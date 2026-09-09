// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_mmap_exec.c -- kretprobe on mmap.
 *
 * The signal this hook exists for: anonymous mappings with PROT_EXEC, the
 * W^X-violation case kernel developers explicitly warn about. Executable
 * *file* mappings (dynamic libs, the linker, MAP_EXECUTABLE leftovers) are
 * routine and are NOT captured -- only MAP_ANONYMOUS + PROT_EXEC, with the
 * PROT_WRITE bit carried raw so consumers can distinguish rwx from r-x.
 *
 * Entry gates on the capture filter, remembers the request; ret emits only
 * on success (mapped address == return value).
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include "hook_common.h"

struct mmap_exec_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u64	req_addr;
	u64	length;
	u32	prot;
	u32	flags;
	int	fd;
	u64	offset;
	bool	probed;	/* hook_probe_enter() succeeded; ret must leave() */
	bool	armed;
};

static_assert(sizeof(struct mmap_exec_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "reentrancy/entry ctx must stay within kretprobe data budget");

static struct kretprobe mmap_exec_krp;

static int mmap_exec_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mmap_exec_ctx *ctx = (struct mmap_exec_ctx *)ri->data;

	ctx->armed = false;
	ctx->probed = hook_probe_enter();
	if (!ctx->probed)
		return 0;
	if (!hook_filter_gate(SENTINEL_SC_MMAP))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->req_addr = (u64)hook_reg_arg(regs, 0);
	ctx->length = (u64)hook_reg_arg(regs, 1);
	ctx->prot = (u64)hook_reg_arg(regs, 2);
	ctx->flags = (u64)hook_reg_arg(regs, 3);
	ctx->fd = (int)hook_reg_arg(regs, 4);
	ctx->offset = (u64)hook_reg_arg(regs, 5);
	ctx->armed = (ctx->prot & PROT_EXEC) &&
		     (ctx->flags & MAP_ANONYMOUS);
	return 0;
}

static int mmap_exec_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mmap_exec_ctx *ctx = (struct mmap_exec_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_mmap_exec *ev;
	long retval;

	if (!ctx->probed)
		return 0;
	hook_probe_leave();
	if (!ctx->armed)
		return 0;
	retval = (long)regs_return_value(regs);
	/* Success: a valid mapping >= PAGE_SIZE. Negative/zero = error. */
	if (retval < (long)PAGE_SIZE)
		return 0;

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_MMAP_EXEC;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(struct sentinel_ev_mmap_exec);

	ev = (struct sentinel_ev_mmap_exec *)cap->payload;
	ev->mapped_addr = (u64)retval;
	ev->req_addr = ctx->req_addr;
	ev->length = ctx->length;
	ev->prot = ctx->prot;
	ev->flags = ctx->flags;
	ev->fd = ctx->fd;
	ev->offset = ctx->offset;

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int mmap_exec_enable(void)
{
	mmap_exec_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("mmap");
	mmap_exec_krp.entry_handler = mmap_exec_entry;
	mmap_exec_krp.handler = mmap_exec_ret;
	mmap_exec_krp.data_size = sizeof(struct mmap_exec_ctx);
	mmap_exec_krp.maxactive = 16;
	return register_kretprobe(&mmap_exec_krp);
}

static void mmap_exec_disable(void)
{
	unregister_kretprobe(&mmap_exec_krp);
}

const struct sentinel_hook_ops sentinel_hook_mmap_exec_ops = {
	.name		= "mmap_exec",
	.enable		= mmap_exec_enable,
	.disable	= mmap_exec_disable,
};
