// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_mprotect.c -- kretprobe on mprotect.
 *
 * mprotect(addr, len, prot) is the runtime path that turns a non-executable
 * mapping executable (a JIT making its code pages runnable) or that adds
 * PROT_WRITE to an executable one (the textbook W^X violation). Unlike the
 * earlier hooks nothing is copied from userspace: the three register
 * arguments are the entire event, so the entry context is tiny and the
 * capture cost sits entirely in the ret path, which the filter gate makes
 * skippable before any work.
 *
 * The ret handler emits regardless of the syscall outcome: a *failed*
 * mprotect(PROT_EXEC) is at least as interesting to an activity monitor as
 * a successful one, mirroring the openat/connect convention.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include "hook_common.h"

struct mprotect_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u64	addr;
	u64	len;
	u32	prot;
	bool	probed;	/* hook_probe_enter() succeeded; ret must leave() */
	bool	armed;
};

static_assert(sizeof(struct mprotect_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "mprotect entry ctx must stay within kretprobe data budget");

static struct kretprobe mprotect_krp;

static int mprotect_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mprotect_ctx *ctx = (struct mprotect_ctx *)ri->data;

	ctx->armed = 0;
	ctx->probed = hook_probe_enter();
	if (!ctx->probed)
		return 0;
	if (!hook_filter_gate(SENTINEL_SC_MPROTECT))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->addr = (u64)hook_reg_arg(regs, 0);
	ctx->len = (u64)hook_reg_arg(regs, 1);
	ctx->prot = (u64)hook_reg_arg(regs, 2);
	ctx->armed = !!(ctx->prot & PROT_EXEC);
	return 0;
}

static int mprotect_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mprotect_ctx *ctx = (struct mprotect_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_mprotect *ev;

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
	cap->event_type = SENTINEL_EV_MPROTECT;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(struct sentinel_ev_mprotect);

	ev = (struct sentinel_ev_mprotect *)cap->payload;
	ev->addr = ctx->addr;
	ev->len = ctx->len;
	ev->prot = ctx->prot;

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int mprotect_enable(void)
{
	mprotect_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("mprotect");
	mprotect_krp.entry_handler = mprotect_entry;
	mprotect_krp.handler = mprotect_ret;
	mprotect_krp.data_size = sizeof(struct mprotect_ctx);
	mprotect_krp.maxactive = 16;
	return register_kretprobe(&mprotect_krp);
}

static void mprotect_disable(void)
{
	unregister_kretprobe(&mprotect_krp);
}

const struct sentinel_hook_ops sentinel_hook_mprotect_ops = {
	.name		= "mprotect",
	.enable		= mprotect_enable,
	.disable	= mprotect_disable,
};
