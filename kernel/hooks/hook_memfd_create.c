// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_memfd_create.c -- kretprobe on memfd_create.
 *
 * memfd_create(name, flags) hands back an anonymous, tmpfs-backed fd with no
 * path on any filesystem. Combined with execveat(fd, "", AT_EMPTY_PATH) it
 * is the canonical fileless-execution shape (the daemon correlation agent
 * joins the two), and on its own it is how a dropper stages a payload that
 * never touches disk.
 *
 * The name is user-controlled but bounded to 15 chars + NUL (mfd names
 * longer than MFDFS keep only the first 249 bytes; we keep the first 15).
 * It is copied with the nofault helpers -- entry runs preempt-disabled.
 *
 * Emitted on success and failure alike: a failed memfd staging attempt is
 * still an event of interest.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include "hook_common.h"

struct memfd_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u32	flags;		/* arg1 (si); MFD_CLOEXEC, MFD_ALLOW_SEALING */
	char	name[16];	/* arg0 (di), truncated to 15 chars + NUL */
	bool	probed;	/* hook_probe_enter() succeeded; ret must leave() */
	bool	armed;
};

static_assert(sizeof(struct memfd_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "memfd entry ctx must stay within kretprobe data budget");

static struct kretprobe memfd_krp;

static int memfd_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct memfd_ctx *ctx = (struct memfd_ctx *)ri->data;
	const char __user *name = (const char __user *)hook_reg_arg(regs, 0);

	ctx->armed = 0;
	ctx->probed = hook_probe_enter();
	if (!ctx->probed)
		return 0;
	if (!hook_filter_gate(SENTINEL_SC_MEMFD_CREATE))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->flags = (u32)hook_reg_arg(regs, 1);
	hook_copy_us_str(ctx->name, sizeof(ctx->name), name);
	ctx->name[sizeof(ctx->name) - 1] = '\0';
	ctx->armed = true;
	return 0;
}

static int memfd_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct memfd_ctx *ctx = (struct memfd_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_memfd_create *ev;

	if (!ctx->probed)
		return 0;
	hook_probe_leave();
	if (!ctx->armed)
		return 0;

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_MEMFD_CREATE;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(struct sentinel_ev_memfd_create);

	ev = (struct sentinel_ev_memfd_create *)cap->payload;
	memcpy(ev->name, ctx->name, sizeof(ev->name));
	ev->flags = ctx->flags;
	/* The wire identity key: the descriptor handed back on success, the
	 * negative errno on failure. Emitted unconditionally -- a failed
	 * memfd_create is still a memfd attempt, and its fd<0 both says so
	 * and keeps the daemon from ever treating it as an open descriptor. */
	ev->fd = (int)regs_return_value(regs);

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int memfd_enable(void)
{
	memfd_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("memfd_create");
	memfd_krp.entry_handler = memfd_entry;
	memfd_krp.handler = memfd_ret;
	memfd_krp.data_size = sizeof(struct memfd_ctx);
	memfd_krp.maxactive = 16;
	return register_kretprobe(&memfd_krp);
}

static void memfd_disable(void)
{
	unregister_kretprobe(&memfd_krp);
}

const struct sentinel_hook_ops sentinel_hook_memfd_create_ops = {
	.name		= "memfd_create",
	.enable		= memfd_enable,
	.disable	= memfd_disable,
};
