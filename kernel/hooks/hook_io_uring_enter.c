// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_io_uring_enter.c -- kretprobe on io_uring_enter with a
 * ret-side completion pairing.
 *
 * io_uring_enter(fd, to_submit, min_complete, flags, sig) is the submission
 * and completion rendezvous of an io_uring ring, i.e. how a workload drives
 * the kernel's async I/O. The interesting observables are not the raw
 * arguments but the two numbers that bracket the call:
 *
 *   submitted -- how many SQEs the kernel actually admitted. On success the
 *                kernel's contract is that retval counts submitted workers;
 *                on failure it returns -submitted. Both decode into a plain
 *                count here.
 *   completed -- how many CQEs the caller was going to wait for. The kernel
 *                exposes no per-call drain counter, so the honest proxy is
 *                min_complete when IORING_ENTER_GETEVENTS asked for it,
 *                else 0. The daemon labels it accordingly.
 *
 * The entry handler stashes the raw register set; the ret handler folds in
 * the pair from retval. Same stash discipline as hook_execveat.c.
 *
 * Register map: fd=di, to_submit=si, min_complete=dx, flags=r10, sig=r8.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/bits.h>
#include "hook_common.h"

#define IORING_ENTER_GETEVENTS	BIT(0)

struct io_uring_enter_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u32	fd;		/* raw arg0 */
	u32	to_submit;	/* raw arg1 */
	u32	min_complete;	/* raw arg2 */
	u32	flags;		/* raw arg3 (r10) */
	u64	sig_ptr;	/* raw arg4 (r8; never dereferenced) */
	bool	probed;
	bool	armed;
};

static_assert(sizeof(struct io_uring_enter_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "io_uring_enter entry ctx must stay within kretprobe data budget");

static struct kretprobe io_uring_enter_krp;

static int io_uring_enter_entry(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct io_uring_enter_ctx *ctx =
		(struct io_uring_enter_ctx *)ri->data;

	ctx->armed = false;
	if (!hook_probe_enter())
		return 0;
	ctx->probed = true;
	if (!hook_filter_gate(SENTINEL_SC_IO_URING_ENTER))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->fd = (int)hook_reg_arg(regs, 0);
	ctx->to_submit = (u32)hook_reg_arg(regs, 1);
	ctx->min_complete = (u32)hook_reg_arg(regs, 2);
	ctx->flags = (u32)hook_reg_arg(regs, 3);
	ctx->sig_ptr = hook_reg_arg(regs, 4);
	ctx->armed = true;
	return 0;
}

static int io_uring_enter_ret(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct io_uring_enter_ctx *ctx =
		(struct io_uring_enter_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_io_uring_enter *ev;
	long retval = regs_return_value(regs);

	if (!ctx->probed)
		return 0;
	hook_probe_leave();

	if (!ctx->armed)
		return 0;

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_IO_URING_ENTER;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(*ev);

	ev = (struct sentinel_ev_io_uring_enter *)cap->payload;
	ev->fd = ctx->fd;
	ev->to_submit = ctx->to_submit;
	ev->min_complete = ctx->min_complete;
	ev->flags = ctx->flags;
	ev->sig_ptr = ctx->sig_ptr;
	/* Success: retval is the submit count. Failure: -retval encodes it
	 * when the ring actually rejected some SQEs, 0 otherwise. Clamp to
	 * the offered count so a malicious/broken kernel cannot overflow.
	 */
	ev->submitted = retval >= 0 ? (u32)retval : (u32)-retval;
	if (ev->submitted > ctx->to_submit)
		ev->submitted = ctx->to_submit;
	ev->completed = (ctx->flags & IORING_ENTER_GETEVENTS) ?
			ctx->min_complete : 0;

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int io_uring_enter_enable(void)
{
	io_uring_enter_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("io_uring_enter");
	io_uring_enter_krp.entry_handler = io_uring_enter_entry;
	io_uring_enter_krp.handler = io_uring_enter_ret;
	io_uring_enter_krp.data_size = sizeof(struct io_uring_enter_ctx);
	io_uring_enter_krp.maxactive = 16;
	return register_kretprobe(&io_uring_enter_krp);
}

static void io_uring_enter_disable(void)
{
	unregister_kretprobe(&io_uring_enter_krp);
}

const struct sentinel_hook_ops sentinel_hook_io_uring_enter_ops = {
	.name		= "io_uring_enter",
	.enable		= io_uring_enter_enable,
	.disable	= io_uring_enter_disable,
};
