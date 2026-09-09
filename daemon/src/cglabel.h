// SPDX-License-Identifier: Apache-2.0
/*
 * cglabel.h -- container label resolver.
 *
 * Resolves a task's cgroup membership (via /proc/<pid>/cgroup) into a short,
 * stable "container label" that the printers can append to an event. This is
 * a best-effort, consumer-side nicety: no kernel participation and no extra
 * wire protocol -- the pid on an event is the only input.
 *
 * The mapping is cached in a small bounded table keyed by pid, so a
 * long-running daemon does not re-read procfs on every event or leak state.
 * Pid recycling is an accepted ambiguity, same as the correlator. The cache
 * does not use RCU: the daemon observes a single consumer thread, so a plain
 * hashtable read/write is race-free.
 */
#ifndef _CGLABEL_H
#define _CGLABEL_H

#include <stddef.h>
#include <stdint.h>

/* Capacity of the pid->label cache; must stay a power of two (mask hash). */
#define SENTINEL_CGLABEL_TABLE	512

/* Longest label we emit, including NUL. */
#define SENTINEL_CGLABEL_MAX	64

struct cglabel {
	unsigned int	pid;	/* 0 == free slot */
	char		label[SENTINEL_CGLABEL_MAX];
};

struct cglabel_state {
	struct cglabel	slots[SENTINEL_CGLABEL_TABLE];
};

/* Zero the state. */
void cglabel_init(struct cglabel_state *s);

/*
 * Resolve pid to a container label. Returns a pointer to a NUL-terminated
 * static string owned by the cache (valid until the next call that mutates
 * the cache) or NULL when the pid is not in a recognized container. read
 * errors, permission denials and non-container cgroups all yield NULL and
 * must not disturb the caller's hot path.
 */
const char *cglabel_resolve(struct cglabel_state *s, unsigned int pid);

#endif /* _CGLABEL_H */
