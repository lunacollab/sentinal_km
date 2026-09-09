// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_ringmap.h -- zero-copy mmap export of the event stream.
 *
 * A misc character device (/dev/sentinel_ring) wraps a byte ring of power-
 * of-two capacity: page 0 is struct sentinel_ringmap_meta, the rest is the
 * data ring. Capacity is runtime-configurable (module param / sysfs knob);
 * the ring drain workers are the single producer and append whole records
 * under a spinlock; exactly one user can hold the mapping (a second open
 * returns -EBUSY) and reads head/advances tail. meta.epoch is bumped on
 * every open and accepted resize, forming the re-open handshake.
 *
 * The wire format of a record is struct sentinel_ring_rec (see proto.h),
 * so the same validation/parsing code handles both the netlink path and
 * this one.
 */
#ifndef _SENTINEL_RINGMAP_H
#define _SENTINEL_RINGMAP_H

#include <linux/types.h>

#include "sentinel_genl.h"

/* Append one capture to the ring, if a consumer is attached. Process
 * context (drain worker). Never blocks, never allocates. */
void sentinel_ringmap_emit(struct sentinel_capture *cap);

/* Total records dropped on mmap ring overflow (never "recovered"). */
u64 sentinel_ringmap_drop_total(void);

/* mmap-ring overflow drops attributable to one event type
 * (sentinel_ringmap_drop_total() is the sum over types).
 */
u64 sentinel_ringmap_dropped_by_type(unsigned int type);

/* Current data-ring capacity in KiB (the value the next open uses). */
unsigned int sentinel_ringmap_capacity(void);

/* Retarget the data-ring capacity in KiB for the next open. Requires the
 * device to be idle (no open consumer) and a power-of-two in range. The
 * next open records a fresh meta.epoch incarnation.
 */
int sentinel_ringmap_resize(unsigned int kib);

int sentinel_ringmap_init(void);
void sentinel_ringmap_exit(void);

#endif /* _SENTINEL_RINGMAP_H */
