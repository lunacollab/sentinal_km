// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_ring.h -- per-CPU event ring interface.
 *
 * The kprobe handlers run in atomic context (preemption disabled, cannot
 * sleep, cannot GFP_KERNEL-allocate). They push a verbatim copy of a fully
 * populated struct sentinel_capture into this CPU's ring. The per-CPU drain
 * worker, scheduled from the ret path, later relocates each capture into
 * process context and hands it to sentinel_genl_emit().
 *
 * Capacity is runtime-configurable (module param "ring_size", sysfs knob of
 * the same name). Each CPU's slots live in a separately allocated ring arena
 * that producers and workers reach through an RCU-protected pointer, so a
 * resize swaps in a fresh arena after the door is closed (recording off,
 * workqueue flushed, grace period elapsed) and frees the old one only after
 * a second grace period. Head/tail are plain masked indices owned by the
 * single producer / single consumer per CPU; on overflow the new entry is
 * dropped and a global counter is bumped -- the producer path is never
 * blocked.
 */
#ifndef _SENTINEL_RING_H
#define _SENTINEL_RING_H

#include <linux/types.h>

#include "sentinel_genl.h"

/* Ring capacity bounds, slots per CPU. Each slot is a 4 KiB
 * struct sentinel_capture, so 256 slots ~= 1 MiB per CPU at the default and
 * the ceiling (4096) ~= 16 MiB per CPU -- the operator's explicit choice. */
#define SENTINEL_RING_DEFAULT		256
#define SENTINEL_RING_MIN		64
#define SENTINEL_RING_MAX		4096

struct sentinel_ring_slot {
	struct sentinel_capture capture;
};

/* Slots carry their own capacity so one pointer load plus a single read of
 * nmask give producers and workers coherent bounds with no second-guessing. */
struct sentinel_ring_arena {
	unsigned int	nmask;		/* capacity - 1 */
	struct sentinel_ring_slot slots[];	/* capacity slots */
};

/* Copy cap into the calling CPU's ring. Atomic-context safe; caller must
 * have preemption disabled (guaranteed inside kprobe handlers). Returns 0,
 * -ENOSPC on overflow (dropped), -EINVAL on a malformed capture. */
int sentinel_ring_push(struct sentinel_capture *cap);

/*
 * Capture objects are pooled: sizeof(struct sentinel_capture) is 4KB and the
 * kretprobe ret handlers run in the middle of the syscall exit path, where a
 * full 4KB stack frame is legal but wasteful. Retrieve one (GFP_ATOMIC,
 * returns NULL on OOM) and return it after enqueueing.
 */
struct sentinel_capture *sentinel_capture_alloc_gfp_atomic(void);
void sentinel_capture_free(struct sentinel_capture *cap);

/* Total events dropped due to overflow (never "recovered"). */
u64 sentinel_ring_dropped_total(void);

/* Online-ring overflow drops attributable to one event type
 * (sentinel_ring_dropped_total() is the sum over types).
 */
u64 sentinel_ring_dropped_by_type(unsigned int type);

/* Total events successfully enqueued. */
u64 sentinel_ring_pushed_total(void);

/* Deferred-flush re-queues (drain worker race recovery). */
u64 sentinel_ring_requeued_total(void);

/* Accumulated emit time across all drain workers (ns). */
u64 sentinel_ring_drain_ns_total(void);

/* Wait for all pending drain workers to finish. Process context. Called
 * from module exit after all probes are down and before ring teardown. */
void sentinel_ring_flush(void);

/* Live ring capacity in slots per CPU (the value shown by sysfs). */
unsigned int sentinel_ring_capacity(void);

/*
 * Resize every per-CPU ring to 'slots' (power of two, SENTINEL_RING_MIN ..
 * SENTINEL_RING_MAX). Process context; serialized against concurrent
 * resizes. Stops recording for the duration of the swap and re-enables it
 * on return (restoring the caller's prior gate state). Events already in a
 * ring are relocated, never dropped. Returns 0 or a negative errno.
 */
int sentinel_ring_resize(unsigned int slots);

int sentinel_ring_init(void);
void sentinel_ring_exit(void);

#endif /* _SENTINEL_RING_H */
