// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_openat.c -- kretprobe on openat (x86_64 / aarch64 wrapper).
 *
 * Entry: capture context + bounded filename copy (arg1) + dfd (arg0) +
 * flags (arg2). Ret: enqueue regardless of outcome -- failed opens are just
 * as relevant to an activity monitor as successful ones.
 */
#include <linux/kprobes.h>
#include <linux/sched.h>
#include "hook_common.h"

struct openat_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	int	dfd;
	int	flags;
	char	filename[SENTINEL_PATH_MAX];
	int	probed;
	int	armed;
};

static_assert(sizeof(struct openat_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "openat entry ctx must stay within kretprobe data budget");

static struct kretprobe openat_krp;

static int openat_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct openat_ctx *ctx = (struct openat_ctx *)ri->data;
	const char __user *filename = (const char __user *)hook_reg_arg(regs, 1);

	ctx->armed = 0;
	ctx->probed = hook_probe_enter();
	if (!ctx->probed)
		return 0;
	if (!hook_filter_gate(SENTINEL_SC_OPENAT))
		return 0;

	ctx->armed = 1;
	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->dfd = (int)hook_reg_arg(regs, 0);
	ctx->flags = (int)hook_reg_arg(regs, 2);
	hook_copy_us_str(ctx->filename, sizeof(ctx->filename), filename);
	return 0;
}

static int openat_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct openat_ctx *ctx = (struct openat_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_openat *ev;

	if (!ctx->probed)
		return 0;
	hook_probe_leave();
	if (!ctx->armed)
		return 0;
	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_OPENAT;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(struct sentinel_ev_openat);

	ev = (struct sentinel_ev_openat *)cap->payload;
	ev->dfd = ctx->dfd;
	ev->flags = ctx->flags;
	memcpy(ev->filename, ctx->filename, sizeof(ev->filename));

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int openat_enable(void)
{
	openat_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("openat");
	openat_krp.entry_handler = openat_entry;
	openat_krp.handler = openat_ret;
	openat_krp.data_size = sizeof(struct openat_ctx);
	openat_krp.maxactive = 16;
	return register_kretprobe(&openat_krp);
}

static void openat_disable(void)
{
	unregister_kretprobe(&openat_krp);
}

const struct sentinel_hook_ops sentinel_hook_openat_ops = {
	.name		= "openat",
	.enable		= openat_enable,
	.disable	= openat_disable,
};
