// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_execve.c -- kretprobe on execve, capture on success only.
 *
 * Entry: record context, a bounded copy of the filename (arg0), and the
 * real argv[] vector (args 1..) as a bounded NUL-separated blob. The walk
 * is bounded three ways: SENTINEL_ARGV_MAX_ARGS entries, 128 bytes per
 * string (truncated), and a hard blob budget. Each string is measured with
 * the exception-table strnlen before copying the exact length, so we never
 * over-copy into the blob and a faulting pointer simply ends the walk.
 *
 * Ret: execve() returning 0 is the only "success" -- the old image is gone
 * and the process now runs the new one. Build the offsets-addressed v2
 * payload and enqueue.
 *
 * All user-memory touches use the _nofault helpers: the entry handler runs
 * preempt-disabled and must not surface a page fault.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include "hook_common.h"

#define SENTINEL_EXECVE_BLOB_MAX	(SENTINEL_ARGV_MAX_ARGS * \
					 SENTINEL_ARGV_STR_MAX)

struct execve_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u16	path_len;	/* bytes of the path blob incl NUL */
	u16	args_len;	/* bytes of the argv blob incl all NULs */
	u16	argc;
	bool	probed;		/* hook_probe_enter() succeeded */
	bool	armed;		/* set when the gate allowed this syscall */
	char	path[SENTINEL_PATH_MAX];
	char	blob[SENTINEL_EXECVE_BLOB_MAX];
};

static_assert(sizeof(struct execve_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "execve entry ctx must stay within kretprobe data budget");

static struct kretprobe execve_krp;

/*
 * Copy one argv entry measured by sentinel_strnlen_user_max(). Returns the
 * number of string bytes consumed (excl NUL), or 0 to stop the walk.
 */
static u16 execve_capture_arg(char *dst, u16 room, const char __user *up)
{
	long sl;

	if (room < 2)
		return 0;
	/*
	 * strnlen contract: >room means unterminated within the budget, 0 is
	 * a fault or an empty string -- both end this walk.
	 */
	sl = sentinel_strnlen_user_max(up, room - 1);
	if (sl <= 0 || sl >= room)
		return 0;
	if (hook_copy_from_user_nofault(dst, up, (unsigned long)sl) != sl)
		return 0;
	dst[sl] = '\0';
	return (u16)sl;
}

static int execve_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct execve_ctx *ctx = (struct execve_ctx *)ri->data;
	const char __user *filename =
		(const char __user *)hook_reg_arg(regs, 0);
	const char __user *us_argv =
		(const char __user *)hook_reg_arg(regs, 1);
	unsigned long up;
	long n;
	u16 off = 0;
	int i;

	ctx->armed = false;
	if (!hook_probe_enter())
		return 0;
	ctx->probed = true;
	if (!hook_filter_gate(SENTINEL_SC_EXECVE))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();

	n = hook_copy_us_str(ctx->path, sizeof(ctx->path), filename);
	ctx->path_len = (u16)(n > 0 ? n + 1 : 1); /* include NUL */

	ctx->argc = 0;
	ctx->args_len = 0;
	for (i = 0; i < SENTINEL_ARGV_MAX_ARGS; i++) {
		if (hook_copy_from_user_nofault(&up, us_argv + i * sizeof(up),
						sizeof(up)) != sizeof(up))
			break;
		if (up == 0)
			break;
		n = execve_capture_arg(ctx->blob + off,
				       SENTINEL_EXECVE_BLOB_MAX - off,
				       (const char __user *)up);
		if (n == 0)
			break;
		off += (u16)(n + 1);
		ctx->argc++;
	}
	ctx->args_len = off;
	ctx->armed = true;
	return 0;
}

static int execve_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct execve_ctx *ctx = (struct execve_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_execve *ev;
	u16 path_off = SENTINEL_EXECVE_PATH_OFF;
	u16 args_off, total;
	long retval = regs_return_value(regs);

	/* The entry handler ran first; on success it leaves() itself. When
	 * it bailed (too deep), probed stays false and so does armed. */
	if (!ctx->probed)
		return 0;
	hook_probe_leave();

	if (!ctx->armed || retval != 0)
		return 0;

	args_off = path_off + ctx->path_len;
	total = args_off + ctx->args_len;
	if (total > SENTINEL_MAX_PAYLOAD)
		return 0;

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_EXECVE;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = total;

	ev = (struct sentinel_ev_execve *)cap->payload;
	ev->path_off = path_off;
	ev->args_off = args_off;
	ev->argc = ctx->argc;
	memcpy(cap->payload + path_off, ctx->path, ctx->path_len);
	memcpy(cap->payload + args_off, ctx->blob, ctx->args_len);

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int execve_enable(void)
{
	execve_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("execve");
	execve_krp.entry_handler = execve_entry;
	execve_krp.handler = execve_ret;
	execve_krp.data_size = sizeof(struct execve_ctx);
	execve_krp.maxactive = 16;
	return register_kretprobe(&execve_krp);
}

static void execve_disable(void)
{
	unregister_kretprobe(&execve_krp);
}

const struct sentinel_hook_ops sentinel_hook_execve_ops = {
	.name		= "execve",
	.enable		= execve_enable,
	.disable	= execve_disable,
};
