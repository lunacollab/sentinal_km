// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_clone3.c -- kretprobe on clone3, entry-emitted.
 *
 * clone3(uargs, args_size, flags, pidfd, child_tid, parent_tid, tls) is the
 * namespace-minting syscall: CLONE_NEWUSER / CLONE_NEWNS / CLONE_NEWPID here
 * are how a container or a sandbox-escape stage begins. The event is emitted
 * on entry, before the kernel has decided anything, so it fires for failed
 * attempts too -- a denied CLONE_NEWUSER probe is signal, not noise.
 *
 * Only two struct clone_args members are of interest (flags, exit_signal)
 * and they are read with bounded, no-fault copies bounded by args_size:
 * nothing user-addressable is dereferenced beyond that. args_size is the
 * caller's own size; a value below 8 degenerates to "no flags readable",
 * which the daemon renders as zeros, not a malformed event.
 *
 * Register map (2 fixed args + 5 clone_args members): uargs=di,
 * args_size=si, flags=dx, pidfd=r10, child_tid=r8, parent_tid=r9, tls=stack.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include "hook_common.h"

#define CLONE_ARGS_OFF_FLAGS	0	/* .flags: first u64 */
#define CLONE_ARGS_OFF_EXIT	32	/* .exit_signal: u64 at byte 32 */
#define CLONE_ARGS_END_FLAGS	8	/* reads a u64 at offset 0 */
#define CLONE_ARGS_END_EXIT	40	/* reads a u64 at offset 32 */

struct clone3_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u64	flags;		/* clone_args.flags */
	u64	exit_signal;	/* clone_args.exit_signal */
	u64	args_size;	/* raw arg1 (bounded locally) */
	u64	pidfd_ptr;	/* raw arg3 (never dereferenced) */
	bool	probed;
	bool	armed;
};

static_assert(sizeof(struct clone3_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "clone3 entry ctx must stay within kretprobe data budget");

static struct kretprobe clone3_krp;

/*
 * Copy a 64-bit field from clone_args at byte offset off, honoring the
 * caller's args_size so a short struct reads conservatively as zero.
 */
static u64 clone3_field(u64 ubadge, u64 off)
{
	u64 v = 0;

	if (hook_copy_from_user_nofault(&v, (const void __user *)ubadge + off,
					sizeof(v)) != sizeof(v))
		v = 0;
	return v;
}

static int clone3_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct clone3_ctx *ctx = (struct clone3_ctx *)ri->data;
	u64 uargs = hook_reg_arg(regs, 0);
	u64 args_size = hook_reg_arg(regs, 1);

	ctx->armed = false;
	if (!hook_probe_enter())
		return 0;
	ctx->probed = true;
	if (!hook_filter_gate(SENTINEL_SC_CLONE3))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();

	ctx->args_size = args_size;
	ctx->pidfd_ptr = hook_reg_arg(regs, 2);
	/* Cap the reads by what the caller actually supplied; a zero or
	 * bogus size reads nothing and the daemon sees clean zeros.
	 */
	if (args_size >= CLONE_ARGS_END_FLAGS && uargs)
		ctx->flags = clone3_field(uargs, CLONE_ARGS_OFF_FLAGS);
	if (args_size >= CLONE_ARGS_END_EXIT && uargs)
		ctx->exit_signal = clone3_field(uargs, CLONE_ARGS_OFF_EXIT);
	ctx->armed = true;
	return 0;
}

static int clone3_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct clone3_ctx *ctx = (struct clone3_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_clone3 *ev;

	if (!ctx->probed)
		return 0;
	hook_probe_leave();

	if (!ctx->armed)
		return 0;

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_CLONE3;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(*ev);

	ev = (struct sentinel_ev_clone3 *)cap->payload;
	ev->flags = ctx->flags;
	ev->args_size = (u32)ctx->args_size;
	ev->exit_signal = (u32)ctx->exit_signal;
	ev->pidfd_ptr = ctx->pidfd_ptr;

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int clone3_enable(void)
{
	clone3_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("clone3");
	clone3_krp.entry_handler = clone3_entry;
	clone3_krp.handler = clone3_ret;
	clone3_krp.data_size = sizeof(struct clone3_ctx);
	clone3_krp.maxactive = 16;
	return register_kretprobe(&clone3_krp);
}

static void clone3_disable(void)
{
	unregister_kretprobe(&clone3_krp);
}

const struct sentinel_hook_ops sentinel_hook_clone3_ops = {
	.name		= "clone3",
	.enable		= clone3_enable,
	.disable	= clone3_disable,
};
