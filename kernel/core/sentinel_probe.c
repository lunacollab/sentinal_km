// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_probe.c -- per-CPU reentrancy guard and bail counter.
 *
 * hook_probe_enter()/hook_probe_leave() are static-inline in the header
 * (called from atomic-context kprobe handlers). This file owns the backing
 * storage for the per-CPU depth and the global atomic bailed counter that
 * the genl CMD_STATS command exposes to userspace. A bail is either
 * reentrancy (depth over the cap) or an unsuitable context (interrupt /
 * kernel thread with no ->mm); both mean the event was refused, not lost.
 */
#include <linux/percpu.h>
#include <linux/atomic.h>

#include "sentinel_probe.h"

DEFINE_PER_CPU(struct sentinel_probe_state, sentinel_probe_state);

static atomic64_t probe_bailed = ATOMIC64_INIT(0);

void __sentinel_probe_bailed_inc(void)
{
	atomic64_inc(&probe_bailed);
}

u64 sentinel_probe_bailed_total(void)
{
	return atomic64_read(&probe_bailed);
}
