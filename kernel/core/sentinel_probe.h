/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SENTINEL_PROBE_H
#define _SENTINEL_PROBE_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/sched.h>

#define SENTINEL_PROBE_MAX_DEPTH	8

struct sentinel_probe_state {
	unsigned int depth;
};

DECLARE_PER_CPU(struct sentinel_probe_state, sentinel_probe_state);

void __sentinel_probe_bailed_inc(void);

static inline bool __must_check hook_probe_enter(void)
{
	struct sentinel_probe_state *s = this_cpu_ptr(&sentinel_probe_state);

	/*
	 * Refuse to capture outside process context. in_interrupt() covers
	 * NMI/hardirq/softirq -- kprobes may fire there, and recording the
	 * interrupted task is both meaningless and unsafe (the identity and
	 * user-copy reads below assume a real current with ->mm). Kernel
	 * threads have ->mm == NULL; their activity is kernel-initiated and
	 * outside the monitor's contract. Both are counted as bails so a
	 * hostile workload cannot hide a flood in "nothing happened".
	 */
	if (unlikely(in_interrupt() || !current->mm)) {
		__sentinel_probe_bailed_inc();
		return false;
	}
	s->depth++;
	if (unlikely(s->depth > SENTINEL_PROBE_MAX_DEPTH)) {
		__sentinel_probe_bailed_inc();
		s->depth--;
		return false;
	}
	return true;
}

static inline void hook_probe_leave(void)
{
	this_cpu_dec(sentinel_probe_state.depth);
}

u64 sentinel_probe_bailed_total(void);

#endif /* _SENTINEL_PROBE_H */
