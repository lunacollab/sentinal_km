/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
/*
 * sentinel_proto.h -- wire protocol definitions shared between the kernel
 *                     module and the userspace daemon.
 *
 * This is the single file that MUST compile identically on both sides:
 *   - kernel:   as a normal kernel header (#include <linux/types.h>)
 *   - userspace: as-is; the daemon Makefile adds -I../kernel/ipc.
 *
 * ABI rules (untouched): any layout change below is a breaking change and
 * MUST bump SENTINEL_PROTO_VERSION. The daemon rejects any event whose
 * proto_version does not match exactly.
 *
 * Byte offset tables for every structure live in docs/WIRE_PROTOCOL.md.
 */
#ifndef _SENTINEL_PROTO_H
#define _SENTINEL_PROTO_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/build_bug.h>
#define SENTINEL_PACKED		__packed
#else
#include <linux/types.h>
/* The daemon compiles this header with a plain C compiler that has no
 * concept of the kernel's <linux/build_bug.h>. C11 (or later) spells
 * static_assert via <assert.h>; fall back to the keyword directly. */
#ifndef static_assert
#define static_assert(cond, msg)	_Static_assert(cond, msg)
#endif
#define SENTINEL_PACKED		__attribute__((packed))
#endif

#define SENTINEL_PROTO_VERSION	8

/* Exec base name captured in the common header (v6). Sized to
 * TASK_COMM_LEN exactly; consumers must treat it as a fixed-length field,
 * not a C string. */
#define SENTINEL_TASK_COMM_MAX	16

/* Generic netlink multicast group index (offset within family mcgrps[]). */
#define SENTINEL_GENL_MCGRP_EVENT	0

/* Generic netlink commands. Events broadcast over the multicast group carry
 * SENTINEL_CMD_EVENT; doit commands are requests from userspace. */
enum sentinel_genl_cmd {
	SENTINEL_CMD_EVENT = 0,		/* multicast event (never a request) */
	SENTINEL_CMD_STATS,		/* reply-only: filter + ring counters */
	SENTINEL_CMD_SETMASK,		/* in: SENTINEL_ATTR_MASK (u64) */
	SENTINEL_CMD_SETPIDS,		/* in: SENTINEL_ATTR_PIDS (nul-string) */
	SENTINEL_CMD_ENABLE,		/* in: SENTINEL_ATTR_ENABLE (u8) */
	SENTINEL_CMD_SETUIDS,		/* in: SENTINEL_ATTR_UIDS (nul-string) */
	SENTINEL_CMD__MAX,
};

/* Generic netlink attributes: 1-2 ride every multicast message; >=3 belong to
 * doit command requests/replies only and never appear in an event. */
enum {
	SENTINEL_ATTR_EVENT = 1,	/* struct sentinel_event_hdr */
	SENTINEL_ATTR_PAYLOAD,		/* event-specific payload */
	SENTINEL_ATTR_MASK,		/* syscall bitmap as hex text (v8) */
	SENTINEL_ATTR_PIDS,		/* nul-string pid allowlist (CSV) */
	SENTINEL_ATTR_ENABLE,		/* u8: capture kill switch */
	SENTINEL_ATTR_STATS_PUSHED,	/* u64: ring enqueues */
	SENTINEL_ATTR_STATS_DROPPED,	/* u64: ring overflow drops */
	SENTINEL_ATTR_STATS_RINGMAP_DROPPED, /* u64: mmap ring drops */
	SENTINEL_ATTR_STATS_BAILED,	/* u64: reentrancy bails */
	SENTINEL_ATTR_STATS_REQUEUED,	/* u64: deferred-flush re-queues */
	SENTINEL_ATTR_STATS_DRAIN_NS,	/* u64: accumulated drain time (ns) */
	SENTINEL_ATTR_STATS_SENT,	/* u64: multicast datagrams sent */
	SENTINEL_ATTR_UIDS,		/* nul-string uid allowlist (CSV) */
	SENTINEL_ATTR__MAX,
};

/* The in-kernel syscall filter bitmap is 1024 bits. Before wire v8 the mask
 * travelled as a u64 and could only express syscalls 0-63 -- fine while the
 * hooked set stopped at 322, but clone3 (435), io_uring_enter (426) and
 * finit_module (313) live above 63. From v8 on the mask is carried as the
 * exact same hex-text syntax the kernel's own sysfs "filter" knob uses, with
 * SENTINEL_MASK_BITS bits of address space. The kernel is the only parser of
 * that text, so the daemon never re-derives bitmap semantics.
 */
#define SENTINEL_MASK_BITS		1024
#define SENTINEL_MASK_BYTES		(SENTINEL_MASK_BITS / 8)

/* Upper bound for the SENTINEL_ATTR_PIDS / SENTINEL_ATTR_UIDS csv string in
 * genl requests. */
#define SENTINEL_GENL_PIDS_MAX		256
#define SENTINEL_GENL_UIDS_MAX		256

enum sentinel_event_type {
	SENTINEL_EV_EXECVE	= 1,
	SENTINEL_EV_OPENAT	= 2,
	SENTINEL_EV_CONNECT	= 3,
	SENTINEL_EV_MMAP_EXEC	= 4,
	SENTINEL_EV_MPROTECT	= 5,
	SENTINEL_EV_EXECVEAT	= 6,
	SENTINEL_EV_MEMFD_CREATE = 7,
	SENTINEL_EV_PTRACE	= 8,
	SENTINEL_EV_CLONE3	= 9,
	SENTINEL_EV_IO_URING_ENTER = 10,
	SENTINEL_EV_FINIT_MODULE = 11,
	SENTINEL_EV__MAX,
};

/*
 * Common header prepended to every event. Fixed 52 bytes, packed.
 * payload_len is the size of the event-specific payload that follows this
 * header (never the total message size).
 *
 * v7 moved the reserved pad bytes to a trailing crc32: the CRC-32C over the
 * 48 bytes at offsets 0..47 plus the packed payload that follows the
 * header. The daemon verification ladder treats a CRC mismatch as a dropped
 * malformed record, never repaired. Both transports (netlink pairs and the
 * mmap ring) carry the same field over the same bytes.
 *
 * v6 added the process-context quartet -- ppid, uid, gid -- and the exec
 * base name (comm). They are captured in the kretprobe handler, so for
 * execve/execveat the comm reflects the image that actually ran. uid/gid
 * are real IDs munged into the init namespace.
 */
struct sentinel_event_hdr {
	__u8	proto_version;
	__u8	event_type;
	__u16	payload_len;
	__u32	pid;
	__u32	ppid;		/* parent tgid at capture time */
	__u32	uid;		/* real uid, init-ns munged */
	__u32	gid;		/* real gid, init-ns munged */
	__u64	timestamp_ns;
	__u16	cpu;
	__u8	comm[SENTINEL_TASK_COMM_MAX];	/* exec base name (v6) */
	__u16	reserved;	/* zeroed; pad to 48 */
	__u32	crc32;		/* CRC-32C over [0..48) + payload (v7) */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_event_hdr) == 52,
	      "sentinel_event_hdr must be 52 bytes in v7");

/* Byte offset of the crc32 field: everything before it (48 bytes) plus the
 * payload is what the CRC covers. crc32 must stay the trailing field. The
 * sizeof-derived spell keeps the check free of offsetof() so the header
 * compiles identically in the kernel and in userspace. */
#define SENTINEL_EVENT_HDR_CRC_OFF	(sizeof(struct sentinel_event_hdr) - \
					 sizeof(__u32))

#define SENTINEL_EVENT_HDR_LEN		sizeof(struct sentinel_event_hdr)

/*
 * Size limits.
 *
 * SENTINEL_MAX_PAYLOAD bounds every on-wire payload. It must be >= the
 * worst-case execve payload (fixed header + path[256] + 16 arg[128]).
 * The daemon refuses any payload_len above it, so a corrupted kernel can
 * never make the consumer allocate or walk out of bounds.
 */
#define SENTINEL_PATH_MAX	256
#define SENTINEL_ARGV_MAX_ARGS	16
#define SENTINEL_ARGV_STR_MAX	128
#define SENTINEL_MAX_PAYLOAD	4096

/*
 * Execve payload, v2: variable-length string blob addressed by three u16
 * offsets instead of a fixed struct.
 *
 * Compile-time check on both sides:
 *   SENTINEL_EXECVE_FIXED_SIZE == sizeof(struct sentinel_ev_execve) == 6
 *
 * Payload layout:
 *   [0..5]                        struct sentinel_ev_execve (fixed part)
 *   [path_off .. args_off)        path, NUL-terminated
 *   [args_off .. payload_len)     argv blob: argc NUL-terminated strings
 *
 * Every offset is validated by the daemon against payload_len before use.
 */
#define SENTINEL_EXECVE_PATH_OFF	sizeof(struct sentinel_ev_execve)

struct sentinel_ev_execve {
	__u16	path_off;
	__u16	args_off;
	__u16	argc;
} SENTINEL_PACKED;

/* Absolute worst-case execve payload (6 + path + 16*128 = 2310). */
#define SENTINEL_EXECVE_PAYLOAD_MAX	(SENTINEL_EXECVE_PATH_OFF + \
					 SENTINEL_PATH_MAX + \
					 SENTINEL_ARGV_MAX_ARGS * SENTINEL_ARGV_STR_MAX)

struct sentinel_ev_openat {
	char	filename[SENTINEL_PATH_MAX];
	int	dfd;
	int	flags;
} SENTINEL_PACKED;

#define SENTINEL_CONNECT_ADDR_MAX	128

struct sentinel_ev_connect {
	int	sockfd;
	__u8	addr_family;
	__u16	port_be;
	__u8	addr[SENTINEL_CONNECT_ADDR_MAX];
} SENTINEL_PACKED;

/*
 * Executable anonymous mapping (mmap with PROT_EXEC|MAP_ANONYMOUS).
 * W^X violation monitoring: file-backed executable mappings are normal
 * (dynamic linkers), anonymous executable ones are the interesting signal.
 */
struct sentinel_ev_mmap_exec {
	__u64	mapped_addr;	/* return value on success (the mapping) */
	__u64	req_addr;	/* requested address (arg0) */
	__u64	length;		/* mapping size (arg1) */
	__u32	prot;		/* raw arg2 (PROT_EXEC & PROT_WRITE) */
	__u32	flags;		/* raw arg3 (contains MAP_ANONYMOUS) */
	__s32	fd;		/* raw arg4; -1 for anon */
	__u64	offset;		/* raw arg5; mmap file offset */
} SENTINEL_PACKED;

/* Compile-time check: v4 mmap struct must be 44 bytes (all packed:
 * 6*8 + 4 + 4 + 4 + 8 = 44). */
static_assert(sizeof(struct sentinel_ev_mmap_exec) == 44,
	      "sentinel_ev_mmap_exec must be 44 bytes in v7");

/*
 * mprotect transition (mprotect(addr, len, prot)). The signal is a region
 * being flipped to PROT_EXEC -- a JIT making memory executable, or W^X
 * being violated by adding PROT_WRITE to an executable mapping. No user
 * memory is copied; the three register arguments are the whole event.
 */
struct sentinel_ev_mprotect {
	__u64	addr;		/* start of the affected range (arg0) */
	__u64	len;		/* range length in bytes (arg1) */
	__u32	prot;		/* raw arg2 (PROT_EXEC / PROT_WRITE bits) */
	__u32	reserved;	/* zeroed */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_ev_mprotect) == 24,
	      "sentinel_ev_mprotect must be 24 bytes in v7");

/*
 * execveat(dirfd, argv, envp, flags): same offset-addressed argv blob as
 * execve (see struct sentinel_ev_execve), plus the dirfd and AT_* flags of
 * the syscall. path_off must equal sizeof(this struct) so the blob starts
 * immediately after the fixed part; 2+2+2+4+4 = 14 bytes, packed.
 */
#define SENTINEL_EXECVEAT_PATH_OFF	sizeof(struct sentinel_ev_execveat)

struct sentinel_ev_execveat {
	__u16	path_off;
	__u16	args_off;
	__u16	argc;
	__s32	dirfd;		/* arg0; AT_FDCWD == -100 */
	__u32	flags;		/* arg3; AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_ev_execveat) == 14,
	      "sentinel_ev_execveat must be 14 bytes in v7");

/*
 * memfd_create(name, flags): a memfd is anonymous, tmpfs-backed memory whose
 * only path is a bare fd. The name is copied from userspace (argv-bounding
 * applies: MFDFS truncate to 249 bytes; we store the first 15 chars + NUL).
 * v7 adds the returned fd as the identity key for the daemon's fileless
 * correlation: execveat("", dirfd=fd, AT_EMPTY_PATH) matching the same fd.
 */
struct sentinel_ev_memfd_create {
	__u8	name[16];	/* NUL-terminated, truncated */
	__u32	flags;		/* arg1; MFD_CLOEXEC, MFD_ALLOW_SEALING */
	__s32	fd;		/* v7: fput value, fd or negative errno */
	__u32	reserved;	/* zeroed */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_ev_memfd_create) == 28,
	      "sentinel_ev_memfd_create must be 28 bytes in v7");

/*
 * ptrace(request, pid, addr, data): the debugger syscall itself. Emitted for
 * every call, success or failure -- the request word is the interesting part
 * (PTRACE_TRACEME from a non-debugger parent is a process-hollowing
 * precursor). No user memory is copied; the four register arguments are the
 * whole event.
 */
struct sentinel_ev_ptrace {
	__u32	request;	/* arg0; PTRACE_* constants */
	__s32	target_pid;	/* arg1; tracee pid */
	__u64	addr;		/* arg2; address or NULL */
	__u64	data;		/* arg3/poke word, register set or NULL */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_ev_ptrace) == 24,
	      "sentinel_ev_ptrace must be 24 bytes in v7");

/*
 * clone3(flags, uargs, args_size): the userns/namespace-mint syscall.
 * Entry-emitted unconditionally with a bounded no-fault copy of two struct
 * clone_args fields; nothing user-accessible is dereferenced beyond that.
 * The daemon decodes the CLONE_NEW* bits in flags.
 */
struct sentinel_ev_clone3 {
	__u64	flags;		/* clone_args.flags (raw arg; CLONE_NEWUSER etc.) */
	__u32	args_size;	/* arg1 (the caller's sizeof(struct clone_args); 0 if NULL) */
	__u32	exit_signal;	/* clone_args.exit_signal; 0 if args_size too short */
	__u64	pidfd_ptr;	/* arg2 (void __user *; never dereferenced) */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_ev_clone3) == 24,
	      "sentinel_ev_clone3 must be 24 bytes in v7");

/*
 * io_uring_enter(fd, to_submit, min_complete, flags, sig): async-submission
 * visibility. Captured in the ret handler so the completion pairing is part
 * of the same snapshot:
 *
 *   submitted  -- SQEs actually admitted: retval when the call succeeded
 *                 (the kernel's contract is that the negative of retval is
 *                 the number submitted on failure), 0 on entry-time error.
 *   completed  -- CQEs the caller asked us to wait for: min_complete when
 *                 IORING_ENTER_GETEVENTS was requested, else 0. The kernel
 *                 exposes no per-call drain counter, so this is the honest
 *                 upper bound of events waited on, not a count.
 *
 * The register set is the whole event; nothing is dereferenced (sig is a
 * pointer captured raw).
 */
struct sentinel_ev_io_uring_enter {
	__u32	fd;		/* raw arg0 (s32; the io_uring instance) */
	__u32	to_submit;	/* raw arg1 (SQEs offered) */
	__u32	min_complete;	/* raw arg2 (CQEs awaited) */
	__u32	flags;		/* raw arg3 (IORING_ENTER_*) */
	__u64	sig_ptr;	/* raw arg4 (sigset_t __user *; never dereferenced) */
	__u32	submitted;	/* v8: bounded retval (see above) */
	__u32	completed;	/* v8: GETEVENTS ? min_complete : 0 */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_ev_io_uring_enter) == 32,
	      "sentinel_ev_io_uring_enter must be 32 bytes in v8");

/*
 * finit_module(fd, flags): a module image loaded from a detached descriptor
 * -- the fileless driver-load path. Emitted for every call, success or
 * failure: an EPERM'd attempt is at least as interesting as a clean load.
 * fd is the identity key for the daemon's image correlation (a memfd fd
 * created earlier in the same pid). The payload is the two register
 * arguments verbatim; nothing is dereferenced (fd is a descriptor number,
 * never an address into user memory).
 */
struct sentinel_ev_finit_module {
	__s32	fd;		/* raw arg0; identifier of the module image */
	__u32	flags;		/* raw arg1; MODULE_INIT_* bits */
} SENTINEL_PACKED;

static_assert(sizeof(struct sentinel_ev_finit_module) == 8,
	      "sentinel_ev_finit_module must be 8 bytes in v8");

/* ------------------------------------------------------------------ */
/* mmap ring export (zero-copy path).                                 */
/* ------------------------------------------------------------------ */

/* Record stored in the mmap ring. head/tail indices are byte offsets. */
#define SENTINEL_RING_REC_HDR_SIZE	sizeof(struct sentinel_ring_rec)

struct sentinel_ring_rec {
	__u32	rec_len;	/* sizeof(rec) + payload_len for this record */
	struct sentinel_event_hdr hdr;
	/* hdr.payload_len payload bytes follow; rec_len == sizeof(rec) +
	 * payload_len (56 + payload_len in v7) */
} SENTINEL_PACKED;

#define SENTINEL_RINGMAP_MAGIC		0x53454e52	/* "SENR" */

/* The mmap ring's data capacity is runtime-configurable since P2.3: page 0
 * is the meta block, the data ring follows it and may span more than the
 * default 4 KiB data pages. Sizes are expressed in KiB of data; a power of
 * two so mask==capacity-1 stays a pure &.
 */
#define SENTINEL_RINGMAP_DEFAULT_KIB	16	/* 1 meta + 4 data pages */
#define SENTINEL_RINGMAP_MIN_KIB	4
#define SENTINEL_RINGMAP_MAX_KIB	1024
#define SENTINEL_RINGMAP_META_SIZE	4096

#define SENTINEL_RINGMAP_DEFAULT_CAPACITY \
	(SENTINEL_RINGMAP_DEFAULT_KIB * 1024)

/* Default export page count (1 meta + 4 data pages). Capacity is runtime-
 * configurable, so this counts pages only at the default size.
 */
#define SENTINEL_RINGMAP_PAGES \
	(SENTINEL_RINGMAP_DEFAULT_KIB / 4 + 1)

/*
 * Page 0 of the mapping. Layout is fixed:
 *   page 0      -> struct sentinel_ringmap_meta
 *   the rest    -> data ring, `capacity` bytes, a power of two (mask wraps
 *                  via &). The mapping size is SENTINEL_RINGMAP_META_SIZE +
 *                  capacity; with the default 16 KiB that is the historical
 *                  5-page export.
 *
 * epoch is a one-up incarnation counter: it is bumped on every open() and
 * on every accepted resize. Consumers record it at open() so a mapping that
 * outlives a module reload or a resize can be identified as stale, and the
 * first incarnation is never 0.
 *
 * Memory ordering: producer stores head with release semantics; consumer
 * stores tail with release semantics; both read the peer with acquire.
 * Only one consumer is allowed (a second open returns -EBUSY), enforced by
 * the kernel; the dual-consumer refusal harness asserts this contract.
 */
struct sentinel_ringmap_meta {
	__u32	magic;
	__u32	mask;		/* ring capacity - 1 (bytes) */
	__u32	capacity;	/* ring capacity (bytes) */
	__u32	epoch;		/* incarnation counter, > 0 */
	__u32	head;		/* producer write index (absolute) */
	__u32	tail;		/* consumer read index (absolute) */
	__u32	drop_count;	/* records dropped on overflow */
} SENTINEL_PACKED;

#endif /* _SENTINEL_PROTO_H */
