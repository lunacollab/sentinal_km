// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_execveat.c -- kretprobe on execveat, capture on success.
 *
 * execveat(dirfd, filename, argv, envp, flags) is execve relative to an fd.
 * Two shapes matter here:
 *
 *   - execveat(fd, "", AT_EMPTY_PATH) on a memfd -- the anonymous, on-disk
 *     fileless execution path. The daemon correlation agent flags the event
 *     when the fd's memfd_create preceded it (accept only empty-path here:
 *     a path-based execveat is just execve with a dirfd).
 *   - AT_SYMLINK_NOFOLLOW exec against a symlink, a launcher shortcut that a
 *     plain execve would mask.
 *
 * Register map (5 args): dirfd=di, filename=si, argv=dx, envp=r10, flags=r8.
 * The argv walk and the offset-addressed blob are byte-identical to
 * hook_execve.c; only the fixed prefix differs (2+2+2+4+4 = 14 bytes plus
 * the dirfd/flags words).
 *
 * Ret: emit only when execveat() returns 0 -- same rule as execve: a failed
 * image load never leaves the process.
 */
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include "hook_common.h"

#define SENTINEL_EXECVEAT_BLOB_MAX	(SENTINEL_ARGV_MAX_ARGS * \
					 SENTINEL_ARGV_STR_MAX)

struct execveat_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	u16	path_len;	/* bytes of the path blob incl NUL */
	u16	args_len;	/* bytes of the argv blob incl all NULs */
	u16	argc;
	s32	dirfd;		/* arg0 (di); AT_FDCWD == -100 */
	u32	flags;		/* arg4 (r8); AT_EMPTY_PATH etc. */
	bool	probed;		/* hook_probe_enter() succeeded */
	bool	armed;		/* set when the gate allowed this syscall */
	char	path[SENTINEL_PATH_MAX];
	char	blob[SENTINEL_EXECVEAT_BLOB_MAX];
};

static_assert(sizeof(struct execveat_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "execveat entry ctx must stay within kretprobe data budget");

static struct kretprobe execveat_krp;

/*
 * Copy one argv entry measured by sentinel_strnlen_user_max(). Returns the
 * number of string bytes consumed (excl NUL), or 0 to stop the walk.
 */
static u16 execveat_capture_arg(char *dst, u16 room, const char __user *up)
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

static int execveat_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct execveat_ctx *ctx = (struct execveat_ctx *)ri->data;
	const char __user *filename =
		(const char __user *)hook_reg_arg(regs, 1);
	const char __user *us_argv =
		(const char __user *)hook_reg_arg(regs, 2);
	unsigned long up;
	long n;
	u16 off = 0;
	int i;

	ctx->armed = false;
	if (!hook_probe_enter())
		return 0;
	ctx->probed = true;
	if (!hook_filter_gate(SENTINEL_SC_EXECVEAT))
		return 0;

	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->dirfd = (int)hook_reg_arg(regs, 0);
	ctx->flags = (u32)hook_reg_arg(regs, 4);

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
		n = execveat_capture_arg(ctx->blob + off,
					 SENTINEL_EXECVEAT_BLOB_MAX - off,
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

static int execveat_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct execveat_ctx *ctx = (struct execveat_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_execveat *ev;
	u16 path_off = SENTINEL_EXECVEAT_PATH_OFF;
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
	cap->event_type = SENTINEL_EV_EXECVEAT;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = total;

	ev = (struct sentinel_ev_execveat *)cap->payload;
	ev->path_off = path_off;
	ev->args_off = args_off;
	ev->argc = ctx->argc;
	ev->dirfd = ctx->dirfd;
	ev->flags = ctx->flags;
	memcpy(cap->payload + path_off, ctx->path, ctx->path_len);
	memcpy(cap->payload + args_off, ctx->blob, ctx->args_len);

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int execveat_enable(void)
{
	execveat_krp.kp.symbol_name = SENTINEL_SC_WRAPPER("execveat");
	execveat_krp.entry_handler = execveat_entry;
	execveat_krp.handler = execveat_ret;
	execveat_krp.data_size = sizeof(struct execveat_ctx);
	execveat_krp.maxactive = 16;
	return register_kretprobe(&execveat_krp);
}

static void execveat_disable(void)
{
	unregister_kretprobe(&execveat_krp);
}

const struct sentinel_hook_ops sentinel_hook_execveat_ops = {
	.name		= "execveat",
	.enable		= execveat_enable,
	.disable	= execveat_disable,
};
