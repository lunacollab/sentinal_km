// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_filter.h -- in-kernel capture gate.
 *
 * Four orthogonal switches, checked in the kprobe pre-handler so the cost
 * of an event (string copies, ring push, multicast/ringmap emit) is skipped
 * entirely when the event is filtered out:
 *
 *   enable    - global kill switch, backed by a static key so the disabled
 *               fast path is a single patched branch and never even reads the
 *               shared bitmap (module param trace_enable, sysfs "enable")
 *   allow[]   - syscall-number bitmap (module param trace_mask, sysfs "filter")
 *   pidset    - pid allowlist, RCU-protected, empty means "all"
 *               (module param trace_pids, sysfs "filter_pids")
 *   uidset    - uid allowlist, RCU-protected, empty means "all" (v6)
 *               (module param trace_uids, sysfs "filter_uids")
 *
 * The pid and uid allowlists are AND-ed at evaluation time: an event passes
 * only when every non-empty list contains its value, so each additional
 * list narrows capture. Both are read with RCU and copied to nothing -- the
 * kprobe pre-handler must never allocate.
 *
 * The bitmap is indexed by x86_64 syscall number (see hook_common.h).
 * Default is "everything allowed" so the module is useful out of the box.
 */
#ifndef _SENTINEL_FILTER_H
#define _SENTINEL_FILTER_H

#include <linux/jump_label.h>
#include <linux/types.h>

#define SENTINEL_SC_MAX		1024

#define SENTINEL_FILTER_PIDS_MAX	64
#define SENTINEL_FILTER_UIDS_MAX	64

/*
 * Master gate. A module-private static key; static_branch_unlikely() against
 * it is the cheapest possible no-op when recording is off (single NOP -- no
 * data read, no branch), and still a single predictable branch when on.
 * Writers latch it via sentinel_filter_set_enabled(); the key update is
 * text-poke, never torn, so readers on other CPUs observe a whole transition.
 */
DECLARE_STATIC_KEY_FALSE(sentinel_master_gate);

/*
 * Decide whether a capture for syscall nr 'sc_nr' of task 'pid' (tgid) with
 * init-ns-munged real uid 'uid' is allowed. Runs in atomic context (kprobe
 * pre-handler) -- it must never sleep, lock, or allocate. Returns 1 to
 * record, 0 to skip.
 */
int sentinel_filter_allows(unsigned int sc_nr, int pid, u32 uid);

/* Eager gate: 1 when any probe is recording at all. Cheaper than a call
 * when the caller would otherwise build a capture unconditionally. */
int sentinel_filter_enabled(void);

/* Global kill switch (process context). */
void sentinel_filter_set_enabled(bool on);

/* Module-param + sysfs plumbing. All process context.
 * *_store interprets the sysfs/sysctl write syntax:
 *   mask:  "all" | "none" | "set NR" | "clr NR" | hex bitmap
 *   pids:  "add PID" | "del PID"         (csv goes through *_parse)
 *   uids:  "add UID" | "del UID"         (csv goes through *_parse)
 */
int sentinel_filter_parse_mask(const char *hex);
int sentinel_filter_set_nr(unsigned int nr, bool on);
void sentinel_filter_reset(bool all_on);
int sentinel_filter_mask_store(const char *s, size_t len);
int sentinel_filter_pids_parse(const char *csv);
int sentinel_filter_pid_add(int pid);
int sentinel_filter_pid_del(int pid);
int sentinel_filter_pids_store(const char *s, size_t len);
void sentinel_filter_pids_clear(void);
int sentinel_filter_uids_parse(const char *csv);
int sentinel_filter_uid_add(u32 uid);
int sentinel_filter_uid_del(u32 uid);
int sentinel_filter_uids_store(const char *s, size_t len);
void sentinel_filter_uids_clear(void);

/* genl control plane: the syscall allow bitmap, carried since wire v8 as the
 * same hex-text syntax the sysfs "filter" knob uses, over the full
 * SENTINEL_MASK_BITS of address space (numbers above 63 -- clone3, io_uring,
 * finit_module). Process context. The kernel remains the single serializer
 * of the /sys/kernel/sentinel_km/filter and genl representations.
 */

/* sysfs show helpers; return the bytes written to buf. */
int sentinel_filter_sysfs_mask(char *buf, size_t len);
int sentinel_filter_sysfs_pids(char *buf, size_t len);
int sentinel_filter_sysfs_uids(char *buf, size_t len);

int sentinel_filter_init(void);
void sentinel_filter_exit(void);

#endif /* _SENTINEL_FILTER_H */
