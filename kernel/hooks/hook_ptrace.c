// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_ptrace.c -- kretprobe on ptrace.
 *
 * ptrace(request, pid, addr, data) is the debugger syscall. Emitted for
 * every call, success or failure, and only every the register arguments are
 * captured -- no user memory is copied, so the entry context is tiny and
 * there is no userspace marshalling to go wrong in the atomic path.
 *
 * Why it exists: PTRACE_TRACEME on a process whose parent never asked for
 * it is the classic process-hollowing / debugger-anti-analysis probe;
 * PTRACE_POKEDATA/POKETEXT are how an in-memory payload is written into a
 * tracee; PTRACE_SETREGS is how execution is redirected mid-image. The
 * request word and the target are the event.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include "hook_common.h"

struct ptrace_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u32	request;	/* arg0 (di) */
	s32	target_pid;	/* arg1 (si) */
	u64	addr;		/* arg2 (dx) */
	u64	data;		/* arg3 (r10) */
	bool	probed;	/* hook_probe_enter() succeeded; ret must leave() */
	bool	armed;
};

static_assert(sizeof(struct ptrace_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "ptrace entry ctx must stay within kretprobe data budget");

static struct kretprobe ptrace_krp;

static int ptrace_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ptrace_ctx *ctx = (struct ptrace_ctx *)ri->data;

	ctx->armed = 0;
	ctx->probed = hook_probe_enter();
	if (!ctx->probed)
		return 0;
	if (!hook_filter_gate(SENTINEL_SC_PTRACE))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->request = (u64)hook_reg_arg(regs, 0);
	ctx->target_pid = (u64)hook_reg_arg(regs, 1);
	ctx->addr = (u64)hook_reg_arg(regs, 2);
	ctx->data = (u64)hook_reg_arg(regs, 3);
	ctx->armed = true;
	return 0;
}

static int ptrace_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct ptrace_ctx *ctx = (struct ptrace_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_ptrace *ev;

	(void)regs;

	if (!ctx->probed)
		return 0;
	hook_probe_leave();
	if (!ctx->armed)
		return 0;

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_PTRACE;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(struct sentinel_ev_ptrace);

	ev = (struct sentinel_ev_ptrace *)cap->payload;
	ev->request = ctx->request;
	ev->target_pid = ctx->target_pid;
	ev->addr = ctx->addr;
	ev->data = ctx->data;

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int ptrace_hook_enable(void)
{
	ptrace_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("ptrace");
	ptrace_krp.entry_handler = ptrace_entry;
	ptrace_krp.handler = ptrace_ret;
	ptrace_krp.data_size = sizeof(struct ptrace_ctx);
	ptrace_krp.maxactive = 16;
	return register_kretprobe(&ptrace_krp);
}

static void ptrace_hook_disable(void)
{
	unregister_kretprobe(&ptrace_krp);
}

const struct sentinel_hook_ops sentinel_hook_ptrace_ops = {
	.name		= "ptrace",
	.enable		= ptrace_hook_enable,
	.disable	= ptrace_hook_disable,
};
