// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_ring.c -- per-CPU event ring implementation.
 *
 * Design
 * ------
 * The plan's Phase 3 backpressure strategy ("single consumer kthread
 * draining into genl") serializes every sender behind one lock. For Phase
 * 1-3 we instead run one worker per CPU: each CPU owns its ring and its
 * worker, giving a lock-free hot path (single reader, single writer per
 * CPU) with no global serialization point on the send path, while keeping
 * the "never block the producer" invariant.
 *
 * The workqueue must be BOUND (not WQ_UNBOUND): queue_work_on(cpu) then
 * schedules the worker on that exact CPU, so each worker only ever reads
 * its own CPU's copy while the matching producer writes it. An unbound
 * pool could migrate the worker to another CPU and reintroduce a race.
 *
 * All access inside the kprobe handlers runs with preemption disabled, so a
 * producer touches only its own CPU's copy; the matching drain worker is
 * queued to that same CPU, so it also touches only its own copy.
 *
 * Ring lifetime is guarded by the module refcount: handlers only exist while
 * the module is loaded, and sentinel_exit() flushes the workqueue after
 * unregistering every probe, so no worker outlives ring_cpus.
 *
 * Capacity is runtime-configurable. Each CPU's slots live in a separately
 * allocated struct sentinel_ring_arena reached through an RCU pointer, so a
 * resize can swap in a fresh arena sized to the new capacity. The resize
 * protocol (sentinel_ring_resize):
 *
 *   1. allocate the new arenas up front (GFP_KERNEL, in range, power of two);
 *   2. pull the master static key (recording stops; no new captures);
 *   3. synchronize_rcu() -- no probe handler is mid-push (handlers run with
 *      preemption disabled, which closes the data path), so no worker that
 *      wants the old arenas is still unborn;
 *   4. flush the workqueue -- every worker queued by an in-flight handler
 *      drains; with head frozen the deferred-flush handshake cannot
 *      re-queue, so the queue is empty for good;
 *   5. relocate any undrained events (a worker can park tail when the sink
 *      is failing), swap the arena pointers, re-queue the drains;
 *   6. synchronize_rcu() again, then free the old arenas.
 *
 * Deferred-flush handshake
 * -----------------------
 * The pending flag is a lock-free "one drain outstanding" ownership token:
 *
 *   producer: push slot, head++ ; if we own the token (cmpxchg 0 -> 1 on an
 *             uncontended flag) queue the worker.
 *   worker:   drain everything, then return the token (release: cmpxchg
 *             1 -> 0). A producer that pushed *during* the drain saw a taken
 *             token and did not queue, so before dropping ownership the
 *             worker re-checks head/tail and, if work appeared, races for
 *             the token again (cmpxchg 0 -> 1) and re-queues itself.
 *
 * The two cmpxchgs make exactly one side win: a late push either queues
 * before the worker releases (worker's re-acquire then fails) or after
 * (worker re-acquires and re-queues). There is no lost-wakeup window and
 * no double queue -- the plain flag+snapshot pattern this replaces could
 * both misplace an event (tail overwrote an unstored slot) and double-send.
 *
 * head/tail on a given CPU are only ever read or written by that CPU's own
 * producer and worker (same-CPU handoff), so plain READ_ONCE/WRITE_ONCE
 * ordering is sound; the cross-section of concern is the token, which is
 * why it is atomic.
 */
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/timekeeping.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/log2.h>
#include <linux/overflow.h>
#include <linux/module.h>

#include "sentinel_ring.h"
#include "sentinel_ringmap.h"
#include "sentinel_genl.h"
#include "../core/sentinel_filter.h"

struct sentinel_ring_cpu {
	/*
	 * Producer line: written only by this CPU's probe path (preempt-
	 * disabled kprobe handler) and read by the drain worker to snapshot
	 * the drain range. Parked on its own cache line so the worker's
	 * per-record tail advance cannot bounce the line that carries the
	 * producer's volatile head write.
	 */
	unsigned int	head ____cacheline_aligned_in_smp;
	atomic_t	pending;	/* deferred-flush ownership token */
	u64		dropped;	/* producer overflow drops */
	/* Overflow drops split by event type (index cap->event_type). Same
	 * single-writer rule as dropped: touched only by this CPU's producer
	 * in atomic context, read unsynchronized by the stats path.
	 */
	u64		dropped_by_type[SENTINEL_EV__MAX];

	/*
	 * Consumer line: written only by the drain worker, read once per
	 * push by the producer to test fullness.
	 */
	unsigned int	tail ____cacheline_aligned_in_smp;
	u64		requeued;	/* deferred-flush re-queues */
	u64		drain_ns;	/* accumulated emit time */
	struct work_struct drain_work;

	/* The event arena itself; written by the store path, read by the
	 * emit path, both on this CPU. Swapped (never mutated in place) by
	 * the resize path. */
	struct sentinel_ring_arena __rcu *arena ____cacheline_aligned_in_smp;
} ____cacheline_aligned_in_smp;

static struct sentinel_ring_cpu __percpu *ring_cpus;
static struct workqueue_struct *sentinel_ring_wq;
static struct kmem_cache *cap_cache;

static atomic64_t pushed_total = ATOMIC64_INIT(0);

/* Live capacity, slots per CPU. Written only under ring_lock, read by
 * sysfs show and by the init path. */
static unsigned int ring_capacity = SENTINEL_RING_DEFAULT;
static DEFINE_MUTEX(ring_lock);

static unsigned int ring_size = SENTINEL_RING_DEFAULT;
module_param(ring_size, uint, 0444);
MODULE_PARM_DESC(ring_size,
	"per-CPU ring capacity in slots (power of two, 64..4096); default 256");

static void ring_drain_worker(struct work_struct *work);

/* ------------------------------------------------------------------ */
/* arena helpers                                                      */
/* ------------------------------------------------------------------ */

static struct sentinel_ring_arena *ring_arena_alloc(unsigned int slots)
{
	struct sentinel_ring_arena *arena;

	arena = kzalloc(struct_size(arena, slots, slots), GFP_KERNEL);
	if (arena)
		arena->nmask = slots - 1;
	return arena;
}

static struct sentinel_ring_arena *ring_arena_get(
	const struct sentinel_ring_cpu *cpu_state)
{
	return rcu_dereference(cpu_state->arena);
}

struct sentinel_capture *sentinel_capture_alloc_gfp_atomic(void)
{
	return kmem_cache_alloc(cap_cache, GFP_ATOMIC);
}
EXPORT_SYMBOL_GPL(sentinel_capture_alloc_gfp_atomic);

void sentinel_capture_free(struct sentinel_capture *cap)
{
	kmem_cache_free(cap_cache, cap);
}
EXPORT_SYMBOL_GPL(sentinel_capture_free);

static void ring_drain_worker(struct work_struct *work)
{
	struct sentinel_ring_cpu *cpu_state =
		container_of(work, struct sentinel_ring_cpu, drain_work);
	struct sentinel_ring_arena *arena;
	struct sentinel_genl_batch batch;
	unsigned int head, i, mask;
	bool sent_ok = true;
	u64 start = ktime_get_ns();

	memset(&batch, 0, sizeof(batch));

	/* The arena cannot change while this worker runs: the resize path
	 * flushes the workqueue before swapping the pointer and re-enables
	 * recording only after the swap, so a fresh worker always sees the
	 * post-swap arena. */
	arena = ring_arena_get(cpu_state);
	mask = READ_ONCE(arena->nmask);

	/* Consume everything published so far, then re-check: the producer
	 * may have pushed in the window between the last head read and the
	 * token release below. tail is advanced to the snapshot head so the
	 * ring folds to empty after each pass -- but only once the batch
	 * cleared the door. A persistent send failure parks tail where it is
	 * and the next drain retries those events instead of dropping them
	 * on the floor of a consumed ring.
	 */
	do {
		head = READ_ONCE(cpu_state->head);

		for (i = cpu_state->tail; i != head; i = (i + 1) & mask) {
			sentinel_genl_batch_emit(&batch,
						 &arena->slots[i].capture);
			sentinel_ringmap_emit(&arena->slots[i].capture);
		}
		if (sentinel_genl_batch_flush(&batch) != 0)
			sent_ok = false;
		if (sent_ok)
			WRITE_ONCE(cpu_state->tail, head);
	} while (READ_ONCE(cpu_state->head) != head);

	/* Release ownership; then re-acquire if a push landed after the last
	 * head read (it saw the token taken and never queued). Exactly one
	 * of the two cmpxchgs below wins, so no event is stranded and none
	 * is double-sent.
	 */
	if (atomic_cmpxchg(&cpu_state->pending, 1, 0) != 1)
		return;
	if (READ_ONCE(cpu_state->head) != head &&
	    atomic_cmpxchg(&cpu_state->pending, 0, 1) == 0) {
		cpu_state->requeued++;
		queue_work_on(smp_processor_id(), sentinel_ring_wq,
			      &cpu_state->drain_work);
	}
	cpu_state->drain_ns += ktime_get_ns() - start;
}

int sentinel_ring_push(struct sentinel_capture *cap)
{
	struct sentinel_ring_cpu *cpu_state;
	struct sentinel_ring_arena *arena;
	unsigned int next, mask;

	if (WARN_ON_ONCE(cap->payload_len > sizeof(cap->payload)))
		return -EINVAL;
	/* Handlers run with preemption disabled; assert rather than silently
	 * re-enable, because that would break the per-CPU ownership
	 * invariant the whole ring relies on.
	 */
	if (WARN_ON_ONCE(preemptible()))
		return -EPERM;

	cpu_state = raw_cpu_ptr(ring_cpus);
	arena = ring_arena_get(cpu_state);
	mask = READ_ONCE(arena->nmask);

	next = (cpu_state->head + 1) & mask;
	if (next == cpu_state->tail) {
		cpu_state->dropped++;
		if (cap->event_type < SENTINEL_EV__MAX)
			cpu_state->dropped_by_type[cap->event_type]++;
		return -ENOSPC;
	}

	sentinel_capture_store(&arena->slots[cpu_state->head].capture, cap,
			       SENTINEL_CAPTURE_HDR_SIZE + cap->payload_len);
	WRITE_ONCE(cpu_state->head, next);
	atomic64_inc(&pushed_total);

	/* Take the deferred-flush token. If we already own it a drain is
	 * guaranteed to reach this slot (the worker drains to a live head).
	 */
	if (!atomic_cmpxchg(&cpu_state->pending, 0, 1))
		queue_work_on(smp_processor_id(), sentinel_ring_wq,
			      &cpu_state->drain_work);
	return 0;
}
EXPORT_SYMBOL_GPL(sentinel_ring_push);

/* ------------------------------------------------------------------ */
/* resize                                                             */
/* ------------------------------------------------------------------ */

static int ring_size_valid(unsigned int slots)
{
	return is_power_of_2(slots) &&
	       slots >= SENTINEL_RING_MIN && slots <= SENTINEL_RING_MAX;
}

/*
 * Swap every per-CPU arena for one with 'slots' capacity. Undrained events
 * are relocated so a resize never silently drops an already-captured event;
 * the hidden cost is that recording is paused for the swap (two grace
 * periods plus a workqueue flush) -- milliseconds at most.
 */
int sentinel_ring_resize(unsigned int slots)
{
	struct sentinel_ring_arena **held = NULL, *old, *arena, *new_arena;
	struct sentinel_ring_cpu *cpu_state;
	unsigned int i, pos, mask;
	bool was_enabled;
	int cpu, err = 0;

	if (!ring_size_valid(slots))
		return -EINVAL;

	mutex_lock(&ring_lock);
	if (slots == READ_ONCE(ring_capacity))
		goto out;

	held = kcalloc(nr_cpu_ids, sizeof(*held), GFP_KERNEL);
	if (!held) {
		err = -ENOMEM;
		goto out;
	}
	for_each_possible_cpu(cpu) {
		arena = ring_arena_alloc(slots);
		if (!arena) {
			err = -ENOMEM;
			goto out_holdings;
		}
		held[cpu] = arena;
	}

	/* Close the door: no new captures, no in-flight probe handler, and no
	 * worker that can touch the old arenas after the swap below.
	 * Ordering is load-bearing: the grace period first (a handler that
	 * entered before the gate dropped finishes, and its queued worker
	 * therefore exists), then one flush drains every such worker. With
	 * recording off, head is frozen, so the deferred-flush handshake can
	 * no longer re-queue -- the flush empties the queue for good.
	 */
	was_enabled = sentinel_filter_enabled();
	sentinel_filter_set_enabled(false);
	synchronize_rcu();
	flush_workqueue(sentinel_ring_wq);

	for_each_possible_cpu(cpu) {
		cpu_state = per_cpu_ptr(ring_cpus, cpu);
		old = rcu_dereference_protected(cpu_state->arena,
						lockdep_is_held(&ring_lock));
		new_arena = held[cpu];
		held[cpu] = NULL;

		/* Relocate anything the drain parked (send failures leave
		 * tail short of head). The producer is stopped, so the ring
		 * is frozen: tail..head is the full undrained span.
		 */
		pos = 0;
		mask = READ_ONCE(old->nmask);
		for (i = cpu_state->tail; i != cpu_state->head;
		     i = (i + 1) & mask)
			new_arena->slots[pos++].capture = old->slots[i].capture;
		cpu_state->tail = 0;
		cpu_state->head = pos;

		rcu_assign_pointer(cpu_state->arena, new_arena);
		held[cpu] = old;	/* free after the grace below */

		/* Drain the relocated events without waiting for a fresh
		 * push to arm the token. */
		if (pos &&
		    !atomic_cmpxchg(&cpu_state->pending, 0, 1))
			queue_work_on(cpu, sentinel_ring_wq,
				      &cpu_state->drain_work);
	}

	synchronize_rcu();
	WRITE_ONCE(ring_capacity, slots);

	if (was_enabled)
		sentinel_filter_set_enabled(true);

	/* Graces elapsed since the swap: the old arenas are unreachable. */
	for_each_possible_cpu(cpu) {
		old = held[cpu];
		if (old)
			kfree(old);
	}
	kfree(held);
	mutex_unlock(&ring_lock);
	return 0;

out_holdings:
	for_each_possible_cpu(cpu) {
		if (held[cpu])
			kfree(held[cpu]);
	}
	kfree(held);
out:
	mutex_unlock(&ring_lock);
	return err;
}

unsigned int sentinel_ring_capacity(void)
{
	return READ_ONCE(ring_capacity);
}

/* ------------------------------------------------------------------ */
/* stats                                                              */
/* ------------------------------------------------------------------ */

static u64 ring_percpu_sum(u64 (*get)(const struct sentinel_ring_cpu *))
{
	u64 total = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		total += get(per_cpu_ptr(ring_cpus, cpu));
	return total;
}

static u64 ring_percpu_sum_by(u64 (*get)(const struct sentinel_ring_cpu *,
					 unsigned int),
			      unsigned int arg)
{
	u64 total = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		total += get(per_cpu_ptr(ring_cpus, cpu), arg);
	return total;
}

static u64 ring_get_dropped(const struct sentinel_ring_cpu *c)
{
	return c->dropped;
}

static u64 ring_get_dropped_type(const struct sentinel_ring_cpu *c,
				 unsigned int type)
{
	return c->dropped_by_type[type];
}

static u64 ring_get_requeued(const struct sentinel_ring_cpu *c)
{
	return c->requeued;
}

static u64 ring_get_drain_ns(const struct sentinel_ring_cpu *c)
{
	return c->drain_ns;
}

u64 sentinel_ring_dropped_total(void)
{
	return ring_percpu_sum(ring_get_dropped);
}

/* Per-type share of the online-ring overflow drops (caller bounds type). */
u64 sentinel_ring_dropped_by_type(unsigned int type)
{
	return ring_percpu_sum_by(ring_get_dropped_type, type);
}

u64 sentinel_ring_pushed_total(void)
{
	return atomic64_read(&pushed_total);
}

u64 sentinel_ring_requeued_total(void)
{
	return ring_percpu_sum(ring_get_requeued);
}

u64 sentinel_ring_drain_ns_total(void)
{
	return ring_percpu_sum(ring_get_drain_ns);
}

void sentinel_ring_flush(void)
{
	if (sentinel_ring_wq)
		flush_workqueue(sentinel_ring_wq);
}

int sentinel_ring_init(void)
{
	struct sentinel_ring_arena *arena;
	int cpu;

	if (!ring_size_valid(ring_size)) {
		pr_err("sentinel_km: bad ring_size=%u (power of two, %u..%u)\n",
		       ring_size, SENTINEL_RING_MIN, SENTINEL_RING_MAX);
		return -EINVAL;
	}

	ring_cpus = alloc_percpu(struct sentinel_ring_cpu);
	if (!ring_cpus)
		return -ENOMEM;

	cap_cache = kmem_cache_create("sentinel_cap",
				      sizeof(struct sentinel_capture), 0, 0,
				      NULL);
	if (!cap_cache)
		goto err_cache;

	sentinel_ring_wq = alloc_workqueue("sentinel_ring", 0, 0);
	if (!sentinel_ring_wq)
		goto err_wq;

	for_each_possible_cpu(cpu) {
		struct sentinel_ring_cpu *c = per_cpu_ptr(ring_cpus, cpu);

		arena = ring_arena_alloc(ring_size);
		if (!arena)
			goto err_arena;
		rcu_assign_pointer(c->arena, arena);
		INIT_WORK(&c->drain_work, ring_drain_worker);
	}
	WRITE_ONCE(ring_capacity, ring_size);
	return 0;

err_arena:
	for_each_possible_cpu(cpu) {
		struct sentinel_ring_cpu *c = per_cpu_ptr(ring_cpus, cpu);

		if (c->arena)
			kfree(rcu_dereference_protected(c->arena, true));
	}
	destroy_workqueue(sentinel_ring_wq);
	sentinel_ring_wq = NULL;
err_wq:
	kmem_cache_destroy(cap_cache);
	cap_cache = NULL;
err_cache:
	free_percpu(ring_cpus);
	ring_cpus = NULL;
	return -ENOMEM;
}

void sentinel_ring_exit(void)
{
	int cpu;

	if (sentinel_ring_wq) {
		destroy_workqueue(sentinel_ring_wq);
		sentinel_ring_wq = NULL;
	}
	kmem_cache_destroy(cap_cache);	/* NULL-safe */
	cap_cache = NULL;
	if (ring_cpus) {
		for_each_possible_cpu(cpu) {
			struct sentinel_ring_cpu *c = per_cpu_ptr(ring_cpus, cpu);

			kfree(rcu_dereference_protected(c->arena, true));
		}
		free_percpu(ring_cpus);
		ring_cpus = NULL;
	}
}
