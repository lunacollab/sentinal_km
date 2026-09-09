// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_common.h -- helpers shared by all syscall hooks.
 *
 * Syscall numbers are per-architecture unistd values, re-keyed below
 * (x86_64 and, since P1.3, aarch64); they exist so the in-kernel filter
 * bitmap (sentinel_filter) can gate capture by syscall number without
 * re-deriving anything from the wire protocol.
 *
 * The symbol naming (__x64_sys_* / __arm64_sys_*) is architecture specific
 * and changes across kernel versions -- see docs/KERNEL_COMPAT.md.
 */
#ifndef _HOOK_COMMON_H
#define _HOOK_COMMON_H

#include <linux/types.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/build_bug.h>

#include "../core/sentinel_filter.h"
#include "../core/sentinel_registry.h"
#include "../core/sentinel_probe.h"
#include "../ipc/sentinel_genl.h"
#include "../ipc/sentinel_ring.h"
#include "../ipc/sentinel_proto.h"

#ifdef CONFIG_ARM64
/* aarch64 unistd values. */
enum {
	SENTINEL_SC_MMAP	= 222,
	SENTINEL_SC_MPROTECT	= 226,
	SENTINEL_SC_CONNECT	= 203,
	SENTINEL_SC_EXECVE	= 221,
	SENTINEL_SC_PTRACE	= 117,
	SENTINEL_SC_FINIT_MODULE = 273,
	SENTINEL_SC_OPENAT	= 56,
	SENTINEL_SC_MEMFD_CREATE = 219,
	SENTINEL_SC_EXECVEAT	= 281,
	SENTINEL_SC_IO_URING_ENTER = 426,
	SENTINEL_SC_CLONE3	= 435,
};
#else
/* x86_64 unistd values of the hooked syscalls. */
enum {
	SENTINEL_SC_MMAP	= 9,
	SENTINEL_SC_MPROTECT	= 10,
	SENTINEL_SC_CONNECT	= 42,
	SENTINEL_SC_EXECVE	= 59,
	SENTINEL_SC_PTRACE	= 101,
	SENTINEL_SC_FINIT_MODULE = 313,
	SENTINEL_SC_OPENAT	= 257,
	SENTINEL_SC_MEMFD_CREATE = 319,
	SENTINEL_SC_EXECVEAT	= 322,
	SENTINEL_SC_IO_URING_ENTER = 426,
	SENTINEL_SC_CLONE3	= 435,
};
#endif
/* arm64 differs only in the syscall numbers; io_uring_enter (426) and
 * clone3 (435) coincide across both arches.
 */

/*
 * kprobe wrapper symbol for a syscall on this architecture. The kernel
 * prefixes the per-arch SYSCALL_DEFINE wrappers __x64_sys_* (x86_64) and
 * __arm64_sys_* (aarch64); picking the right one is what lets the same
 * probe tables load on both arches.
 */
#ifdef CONFIG_ARM64
#define SENTINEL_SC_WRAPPER(sym)	"__arm64_sys_" sym
#else
#define SENTINEL_SC_WRAPPER(sym)	"__x64_sys_" sym
#endif

/*
 * Syscall-argument registers, abstracted so kprobe handlers compile on both
 * x86_64 (di/si/dx/r10/r8/r9) and aarch64 (pt_regs->regs[0..5]). The
 * __*_sys_* wrappers receive a pointer to the syscall pt_regs as their first
 * function argument; the kprobe's regs are the wrapper-call registers, not
 * the syscall argument registers themselves.
 */
#ifdef CONFIG_X86_64
static inline unsigned long hook_reg_arg(struct pt_regs *regs, unsigned int n)
{
	struct pt_regs *syscall_regs = (struct pt_regs *)regs->di;

	if (!syscall_regs)
		return 0;
	switch (n) {
	case 0:
		return syscall_regs->di;
	case 1:
		return syscall_regs->si;
	case 2:
		return syscall_regs->dx;
	case 3:
		return syscall_regs->r10;	/* arg 4; rcx holds retaddr */
	case 4:
		return syscall_regs->r8;
	case 5:
		return syscall_regs->r9;
	default:
		return 0;
	}
}
#else
static inline unsigned long hook_reg_arg(struct pt_regs *regs, unsigned int n)
{
	struct pt_regs *syscall_regs = (struct pt_regs *)regs->regs[0];

	if (!syscall_regs)
		return 0;
	if (n < 6)
		return syscall_regs->regs[n];
	return 0;
}
#endif

/* Per-instance data budget for kretprobe entry contexts (data_size). Keeps
 * maxactive=16 a modest kmalloc. Tuned upward only with the docs updated. */
#define SENTINEL_KTASK_DATA_MAX		4096

/* Largest bitmap index is still < SENTINEL_SC_MAX (see sentinel_filter.h).
 * The highest hooked syscall is clone3 at 435, well inside the 1024-bit
 * mask -- the wire v8 mask rewrite exists precisely so the daemon can
 * express numbers above 63. */
static_assert(SENTINEL_SC_CLONE3 < SENTINEL_SC_MAX, "bitmap too small");

/* The wire buffer must fit every payload struct we emit (see proto.h). */
static_assert(SENTINEL_MAX_PAYLOAD >= sizeof(struct sentinel_ev_openat));
static_assert(SENTINEL_MAX_PAYLOAD >= sizeof(struct sentinel_ev_connect));
static_assert(SENTINEL_MAX_PAYLOAD >= sizeof(struct sentinel_ev_mmap_exec));
static_assert(SENTINEL_MAX_PAYLOAD >= sizeof(struct sentinel_ev_mprotect));
static_assert(SENTINEL_MAX_PAYLOAD >= sizeof(struct sentinel_ev_memfd_create));
static_assert(SENTINEL_MAX_PAYLOAD >= sizeof(struct sentinel_ev_ptrace));

static_assert(SENTINEL_MAX_PAYLOAD >= sizeof(struct sentinel_ev_clone3));
static_assert(SENTINEL_MAX_PAYLOAD >=
	      sizeof(struct sentinel_ev_io_uring_enter));
static_assert(SENTINEL_MAX_PAYLOAD >=
	      sizeof(struct sentinel_ev_finit_module));
static_assert(SENTINEL_MAX_PAYLOAD >= SENTINEL_EXECVE_PAYLOAD_MAX);
static_assert(SENTINEL_MAX_PAYLOAD >=
	      SENTINEL_EXECVEAT_PATH_OFF + SENTINEL_PATH_MAX +
	      SENTINEL_ARGV_MAX_ARGS * SENTINEL_ARGV_STR_MAX);
static_assert(SENTINEL_EXECVE_PATH_OFF == sizeof(struct sentinel_ev_execve));
static_assert(SENTINEL_EXECVEAT_PATH_OFF ==
	      sizeof(struct sentinel_ev_execveat));

/*
 * Version-independent nofault user-string copy (see hook_copy.c).
 * Returns count copied (excluding NUL) or a negative errno.
 */
long hook_strncpy_from_user(char *dst, const char __user *src, long count);

/* No-fault fixed-size copy; returns bytes copied or a negative errno. */
long hook_copy_from_user_nofault(void *dst, const void __user *src,
				 unsigned long n);

/*
 * Bounded user string length, exception-table assisted, safe in the kprobe
 * pre-handler. Returns the string length excluding NUL, max+1 when no NUL
 * is found within max bytes, or 0 on fault (mirrors strnlen_user()).
 */
long sentinel_strnlen_user_max(const char __user *s, long max);

#ifdef CONFIG_X86_64
/* arch/x86_64/sentinel_memchr_zero.S: offset of the first NUL in buf[0..n),
 * or n when none. Only touches kernel memory; fed by the nofault copy in
 * hook_copy.c. Falls back to a byte loop on other arches. */
long sentinel_memchr_zero(const void *buf, long n);
#endif

/* Resolve the nofault helpers at init. Call once from module init. */
int hook_init_copy_helper(void);

/* Init-time selftest battery for the copy/strnlen primitives. Returns 0 on
 * success; any failure should refuse the module load. */
int hook_run_copy_selftest(void);

/* Capture the common execution context (timestamp + pid) into a capture
 * struct. The event_type must already be set by the caller. */
static inline void hook_capture_context(struct sentinel_capture *cap)
{
	cap->timestamp_ns = ktime_get_real_fast_ns();
	cap->pid = task_pid_nr(current);
	cap->cpu = raw_smp_processor_id();
}

/*
 * Fill the process-context quartet (ppid / uid / gid) and the exec base name
 * (comm) into a capture. Called from the kretprobe handler, so for
 * execve/execveat the comm reflects the image that actually ran. The real
 * parent pointer is RCU-guarded and stable for the caller's lifetime; uid
 * and gid are the real IDs, munged into the init namespace so the daemon
 * sees plain integers.
 *
 * Consumers must treat comm as a fixed 16-byte field, not a C string.
 */
static inline void hook_capture_identity(struct sentinel_capture *cap)
{
	/* task_tgid_nr() has no const qualification on its argument. */
	struct task_struct *parent;

	parent = rcu_dereference(current->real_parent);
	cap->ppid = task_tgid_nr(parent);
	cap->uid = from_kuid_munged(&init_user_ns, current_uid());
	cap->gid = from_kgid_munged(&init_user_ns, current_gid());
	memcpy(cap->comm, current->comm, sizeof(cap->comm));
}

/* Bounded copy of a userspace string, version-independent. dst_len includes
 * space for the trailing NUL. Returns number of bytes copied, 0 on
 * failure/empty. */
static inline size_t hook_copy_us_str(char *dst, size_t dst_len,
				      const char __user *src)
{
	long n;

	if (!dst_len)
		return 0;
	n = hook_strncpy_from_user(dst, src, dst_len);
	if (n < 0)
		n = 0;
	/* The underlying helper guarantees NUL-termination on success;
	 * defensively enforce it. */
	if (n >= dst_len)
		dst[dst_len - 1] = '\0';
	return n;
}

/*
 * Gate: does the in-kernel filter allow capturing syscall number nr for the
 * current task right now? Called from kprobe pre-handlers (atomic context).
 * Returns 1 when recording is allowed.
 */
static inline int hook_filter_gate(unsigned int sc_nr)
{
	return sentinel_filter_allows(sc_nr, task_pid_nr(current),
				      from_kuid_munged(&init_user_ns,
						       current_uid()));
}

/* Push a completed capture into the per-CPU ring. Caller supplies the ret
 * handler; preemption is already disabled there. */
static inline void hook_enqueue(struct sentinel_capture *cap)
{
	sentinel_ring_push(cap);
}

#endif /* _HOOK_COMMON_H */
