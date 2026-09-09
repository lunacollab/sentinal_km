// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_finit_module.c -- kretprobe on finit_module.
 *
 * finit_module(fd, flags) loads a module from a detached descriptor. The
 * fd is the identity key the daemon correlates against a memfd_create from
 * the same pid: a memfd-fed module image is exactly the fileless driver
 * path a loader stages (package installers seal a memfd, verify it, then
 * feed it to finit_module). Emitted for every call, success or failure --
 * an EPERM'd attempt is signal, not noise -- so the flag word is the whole
 * point of the event even when the load never sticks.
 *
 * The payload is the two register arguments verbatim: nothing is
 * dereferenced, fd is a descriptor number, not an address.
 *
 * Register map: fd=di, flags=si.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include "hook_common.h"

struct finit_module_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	s32	fd;		/* raw arg0 (edi) */
	u32	flags;		/* raw arg1 (esi); MODULE_INIT_* bits */
	bool	probed;
	bool	armed;
};

static_assert(sizeof(struct finit_module_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "finit_module entry ctx must stay within kretprobe data budget");

static struct kretprobe finit_module_krp;

static int finit_module_entry(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct finit_module_ctx *ctx =
		(struct finit_module_ctx *)ri->data;

	ctx->armed = false;
	if (!hook_probe_enter())
		return 0;
	ctx->probed = true;
	if (!hook_filter_gate(SENTINEL_SC_FINIT_MODULE))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->fd = (int)hook_reg_arg(regs, 0);
	ctx->flags = (u32)hook_reg_arg(regs, 1);
	ctx->armed = true;
	return 0;
}

static int finit_module_ret(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct finit_module_ctx *ctx =
		(struct finit_module_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_finit_module *ev;

	if (!ctx->probed)
		return 0;
	hook_probe_leave();

	if (!ctx->armed)
		return 0;

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_FINIT_MODULE;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(*ev);

	ev = (struct sentinel_ev_finit_module *)cap->payload;
	ev->fd = ctx->fd;
	ev->flags = ctx->flags;

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int finit_module_enable(void)
{
	finit_module_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("finit_module");
	finit_module_krp.entry_handler = finit_module_entry;
	finit_module_krp.handler = finit_module_ret;
	finit_module_krp.data_size = sizeof(struct finit_module_ctx);
	finit_module_krp.maxactive = 16;
	return register_kretprobe(&finit_module_krp);
}

static void finit_module_disable(void)
{
	unregister_kretprobe(&finit_module_krp);
}

const struct sentinel_hook_ops sentinel_hook_finit_module_ops = {
	.name		= "finit_module",
	.enable		= finit_module_enable,
	.disable	= finit_module_disable,
};
