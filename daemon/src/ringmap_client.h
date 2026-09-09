// SPDX-License-Identifier: Apache-2.0
#ifndef _RINGMAP_CLIENT_H
#define _RINGMAP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "sentinel_proto.h"

struct ringmap_client {
	int fd;
	void *map;		/* meta page + data ring (capacity from meta) */
	struct sentinel_ringmap_meta *meta;
	size_t map_size;	/* bytes actually mapped */
	uint32_t capacity;	/* data ring capacity (bytes) */
	uint32_t epoch;		/* incarnation the mapping belongs to */
};

/*
 * Open and mmap the ring device (default /dev/sentinel_ring). Capacity is
 * discovered from the meta page, so any runtime ringmap_size is supported.
 * Refuses a second consumer with -EBUSY; returns 0 or a negative errno.
 */
int ringmap_open(struct ringmap_client *c, const char *path);

/*
 * Check the mapping for readiness (magic, capacity power of two, epoch).
 * Returns 0 or -1.
 */
int ringmap_validate(const struct ringmap_client *c);

/*
 * Copy the next complete record into out (cap bytes) and advance the tail.
 * Returns the record length, 0 when the ring is empty, or a negative errno
 * (-ENOSPC when a record would not fit, -EBADMSG on a corrupt record).
 */
ssize_t ringmap_next(struct ringmap_client *c, void *out, size_t cap);

/*
 * Block up to timeout_ms for the ring to become non-empty (poll). Returns
 * 1 when data is ready, 0 on timeout, negative errno on error.
 */
int ringmap_wait(const struct ringmap_client *c, int timeout_ms);

void ringmap_close(struct ringmap_client *c);

/* Re-open handshake accessors: the epoch this mapping belongs to and its
 * data capacity. A mapping whose epoch no longer matches a freshly probed
 * device (e.g. after a module reload) is a stale incarnation. */
uint32_t ringmap_epoch(const struct ringmap_client *c);
uint32_t ringmap_capacity(const struct ringmap_client *c);

/*
 * read(2)-based alternative to mmap: open the ring device without mapping
 * it. Records are delivered one per successful read() via the backend's
 * .read fop. Blocking by default; set nonblock to get -EAGAIN when empty.
 * Returns the fd, or a negative errno.
 */
int ringmap_ro_open(const char *path, int nonblock);

/*
 * poll() the fd until data (or timeout). Returns 1, 0 on timeout, or a
 * negative errno.
 */
int ringmap_ro_wait(int fd, int timeout_ms);

/*
 * Read the next complete record. Returns rec_len (>0), or a negative errno
 * (-EAGAIN when the ring is empty and nonblock is set).
 */
ssize_t ringmap_ro_read(int fd, void *out, size_t cap);

#endif /* _RINGMAP_CLIENT_H */
