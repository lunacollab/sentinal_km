// SPDX-License-Identifier: Apache-2.0
/*
 * correlate.h -- daemon-side event correlation agent.
 *
 * Folds the raw syscall stream into process-level facts and annotates the
 * consumer-visible output:
 *
 *   - every successful exec/execveat records the pid's image
 *     {path, argv0, timestamp} in a bounded table;
 *   - mmap/mprotect flipping a mapping to PROT_WRITE|PROT_EXEC inside a
 *     process whose image is known is tagged "EXEC-TRANS" (W^X violation /
 *     self-modifying code inside a real binary);
 *   - execveat(dirfd, "", AT_EMPTY_PATH) whose dirfd matches an fd the pid
 *     minted with memfd_create is tagged fileless (anonymous, diskless
 *     execution). A match is (pid, fd, empty-path, within-window); since v7
 *     the wire carries the returned fd, so this is an identity correlation --
 *     the old pid+time guess is gone.
 *
 * The kernel does not participate: everything here is consumer-side
 * inference over events it already streams, so no extra wire protocol is
 * needed -- the events themselves are the input.
 *
 * The tables are open-addressed and age-evicted (capacity-bounded, oldest
 * sequence number evicted on collision) so a long-running daemon leaks no
 * state. Pid recycling is an accepted ambiguity -- a newer exec on the same
 * pid simply replaces the old image.
 */
#ifndef _CORRELATE_H
#define _CORRELATE_H

#include <stdbool.h>
#include <stdint.h>

#include "sentinel_proto.h"

/* Capacity of the per-pid image / memfd tables. Must stay a power of two;
 * the hash uses a mask. */
#define SENTINEL_CORR_EXEC_TABLE	1024
#define SENTINEL_CORR_MEMFD_TABLE	1024

/* How long a memfd_create stays "live" for a later execveat() correlation. */
#define SENTINEL_CORR_MEMFD_WINDOW_NS	30000000000ULL	/* 30 s */

/* execveat arg4: AT_EMPTY_PATH (0x1000). Defined locally so userspace need
 * not depend on a specific <linux/fcntl.h>. */
#define SENTINEL_AT_EMPTY_PATH		0x1000

/* Identity of one process image, as observed on the wire. */
struct correlate_exec {
	char path[SENTINEL_PATH_MAX];
	char argv0[SENTINEL_ARGV_STR_MAX];
};

/*
 * pid == 0 marks an empty slot (pid 0 is never an event source).
 * The memfd slot also remembers the descriptor that was handed out, so the
 * fileless heuristic keys on (pid, fd) identity rather than a bare
 * pid+time window: execveat(dirfd, "", AT_EMPTY_PATH) is only tagged
 * fileless when dirfd equals an fd this pid minted via memfd_create.
 * A failed memfd (fd < 0) is never installed.
 */
struct correlate_exec_slot {
	unsigned int	pid;
	uint64_t	seq;	/* recency, bumped on every insert */
	struct correlate_exec exec;
};

struct correlate_memfd_slot {
	unsigned int	pid;
	uint64_t	seq;
	int		fd;	/* the descriptor, >= 0 (v7 identity key) */
	uint64_t	ts;	/* memfd_create timestamp_ns */
};

struct correlate_state {
	struct correlate_exec_slot	exec_slots[SENTINEL_CORR_EXEC_TABLE];
	struct correlate_memfd_slot	memfd_slots[SENTINEL_CORR_MEMFD_TABLE];
	uint64_t	seq;	/* global monotonic recency counter */
	bool		enabled;/* --no-correlate disables everything */
};

/* Annotations derived for the event currently being printed. */
struct correlate_annot {
	bool		fileless;	/* execveat(AT_EMPTY_PATH) on a memfd */
	bool		exec_trans;	/* W|X flip inside a known image */
	const struct correlate_exec *exec; /* known image, if any */
};

/* Zero the state and set enabled. Disabled observes are no-ops. */
void correlate_init(struct correlate_state *c, bool enabled);

/*
 * Fold one validated event into the state and fill out. Called from the
 * dispatcher before printing; safe to call for every event type. Never
 * fails and never allocates.
 */
void correlate_observe(struct correlate_state *c,
		       const struct sentinel_event_hdr *hdr,
		       const void *payload, struct correlate_annot *out);

#endif /* _CORRELATE_H */
