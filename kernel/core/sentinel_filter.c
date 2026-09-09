// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_filter.c -- in-kernel capture gate.
 *
 * Readers run in the kprobe pre-handler (atomic: no sleep, no locks beyond
 * RCU read-side). Writers run in process context (module init / sysfs) and
 * serialize on filter_lock.
 *
 * Synchronization:
 *   - the master gate is a static key (see sentinel_filter.h): the disabled
 *     fast path is a patched NOP, so a fully-idle capture costs nothing;
 *     the allow bitmap is read with test_bit at the hot-path gate and
 *     written in process context; an aligned unsigned long bitmap shared
 *     mismatch is impossible because writers assign fields before the kill
 *     switch is flipped back on / under the same mutex that re-enables
 *     recording.
 *   - filter_pids / filter_uids are small arrays published by RCU pointer
 *     swap; writers build a fresh set, publish, then kfree_rcu the old one.
 *     Reads happen under one rcu_read_lock covering both.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/bitmap.h>
#include <linux/mutex.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>

#include "sentinel_filter.h"
#include "../ipc/sentinel_proto.h"

#define SENTINEL_FILTER_RETRY		4

/* The kernel-side bitmap width is the wire's mask width (sentinel_proto.h):
 * a drift here would silently truncate --apply mask= settings above bit 63,
 * which wire v8 exists to allow.
 */
static_assert(SENTINEL_SC_MAX == SENTINEL_MASK_BITS,
	      "filter bitmap width must match the wire mask width");

struct sentinel_pidset {
	int	pids[SENTINEL_FILTER_PIDS_MAX];
	int	n;
};

struct sentinel_uidset {
	u32	uids[SENTINEL_FILTER_UIDS_MAX];
	int	n;
};

static struct {
	unsigned long allow[BITS_TO_LONGS(SENTINEL_SC_MAX)];
} sstate;

static struct sentinel_pidset __rcu *filter_pids;
static struct sentinel_uidset __rcu *filter_uids;
static DEFINE_MUTEX(filter_lock);

/* Master gate (defined here, consumed by every hook's hot path via
 * DECLARE_STATIC_KEY_FALSE). Starts patched to "off". */
DEFINE_STATIC_KEY_FALSE(sentinel_master_gate);

/* ------------------------------------------------------------------ */
/* module params                                                       */
/* ------------------------------------------------------------------ */

static char *trace_mask;
module_param(trace_mask, charp, 0444);
MODULE_PARM_DESC(trace_mask,
	"hex syscall bitmap (bit N = allow syscall N); default all-ones");

static char *trace_pids;
module_param(trace_pids, charp, 0444);
MODULE_PARM_DESC(trace_pids, "comma-separated pid allowlist; empty = all");

static char *trace_uids;
module_param(trace_uids, charp, 0444);
MODULE_PARM_DESC(trace_uids, "comma-separated uid allowlist; empty = all");

static bool trace_enable = true;
module_param(trace_enable, bool, 0644);
MODULE_PARM_DESC(trace_enable, "global recording kill switch; default 1");

/* ------------------------------------------------------------------ */
/* hot path                                                            */
/* ------------------------------------------------------------------ */

int sentinel_filter_allows(unsigned int sc_nr, int pid, u32 uid)
{
	const struct sentinel_uidset *uset;
	const struct sentinel_pidset *set;
	int i;

	if (!static_branch_unlikely(&sentinel_master_gate))
		return 0;
	if (sc_nr >= SENTINEL_SC_MAX)
		return 0;
	if (!test_bit(sc_nr, sstate.allow))
		return 0;

	/* RCU read-side is valid with preemption disabled (kprobe
	 * pre-handler). Writers publish a fresh set and kfree_rcu the old.
	 * pid and uid lists are AND-ed: each non-empty list must match.
	 */
	rcu_read_lock();
	set = rcu_dereference(filter_pids);
	if (set && set->n) {
		for (i = 0; i < set->n; i++)
			if (set->pids[i] == pid)
				break;
		if (i == set->n) {
			rcu_read_unlock();
			return 0;
		}
	}
	uset = rcu_dereference(filter_uids);
	if (uset && uset->n) {
		for (i = 0; i < uset->n; i++)
			if (uset->uids[i] == uid)
				break;
		if (i == uset->n) {
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();
	return 1;
}

int sentinel_filter_enabled(void)
{
	return static_branch_unlikely(&sentinel_master_gate);
}

void sentinel_filter_set_enabled(bool on)
{
	if (on)
		static_branch_enable(&sentinel_master_gate);
	else
		static_branch_disable(&sentinel_master_gate);
}

/* ------------------------------------------------------------------ */
/* sysfs / sysctl store interpreters (process context)                */
/* ------------------------------------------------------------------ */

int sentinel_filter_parse_mask(const char *hex)
{
	unsigned long tmp[BITS_TO_LONGS(SENTINEL_SC_MAX)];
	int ret;

	mutex_lock(&filter_lock);
	ret = bitmap_parse(hex, strlen(hex), tmp, SENTINEL_SC_MAX);
	if (!ret)
		memcpy(sstate.allow, tmp, sizeof(tmp));
	mutex_unlock(&filter_lock);
	return ret ? -EINVAL : 0;
}

int sentinel_filter_set_nr(unsigned int nr, bool on)
{
	int ret = 0;

	if (nr >= SENTINEL_SC_MAX)
		return -ERANGE;
	mutex_lock(&filter_lock);
	if (on)
		set_bit(nr, sstate.allow);
	else
		clear_bit(nr, sstate.allow);
	mutex_unlock(&filter_lock);
	return ret;
}

void sentinel_filter_reset(bool all_on)
{
	mutex_lock(&filter_lock);
	if (all_on)
		bitmap_fill(sstate.allow, SENTINEL_SC_MAX);
	else
		bitmap_zero(sstate.allow, SENTINEL_SC_MAX);
	mutex_unlock(&filter_lock);
}

/* ------------------------------------------------------------------ */
/* sysfs / sysctl store interpreters (process context)                */
/* ------------------------------------------------------------------ */

/* Copy a write payload into a stack buffer and NUL-terminate it, so the
 * sscanf-based interpreters below never read past the caller's count. */
static int sntl_write_copy(const char *s, size_t len, char *dst, size_t dst_sz)
{
	size_t n;

	if (len >= dst_sz)
		return -E2BIG;
	n = len;
	memcpy(dst, s, n);
	dst[n] = '\0';
	return 0;
}

int sentinel_filter_mask_store(const char *s, size_t len)
{
	char buf[512];
	char cmd[16];
	unsigned int nr;
	int ret;

	ret = sntl_write_copy(s, len, buf, sizeof(buf));
	if (ret)
		return ret;

	/* Commands leave the hex parser alone by construction: neither word
	 * can parse as a bitmap. */
	if (sscanf(buf, "%15s %u", cmd, &nr) == 2) {
		if (!strcmp(cmd, "set"))
			return sentinel_filter_set_nr(nr, true) ?
				-EINVAL : (int)len;
		if (!strcmp(cmd, "clr"))
			return sentinel_filter_set_nr(nr, false) ?
				-EINVAL : (int)len;
		return -EINVAL;
	}
	if (sscanf(buf, "%15s", cmd) != 1)
		return -EINVAL;
	if (!strcmp(cmd, "all")) {
		sentinel_filter_reset(true);
		return (int)len;
	}
	if (!strcmp(cmd, "none")) {
		sentinel_filter_reset(false);
		return (int)len;
	}
	ret = sentinel_filter_parse_mask(buf);
	if (ret)
		return ret;
	return (int)len;
}

int sentinel_filter_pids_store(const char *s, size_t len)
{
	char buf[256];
	char cmd[16];
	int pid, ret;

	ret = sntl_write_copy(s, len, buf, sizeof(buf));
	if (ret)
		return ret;

	if (sscanf(buf, "%15s %d", cmd, &pid) != 2)
		return -EINVAL;
	if (!strcmp(cmd, "add")) {
		ret = sentinel_filter_pid_add(pid);
		return ret ? ret : (int)len;
	}
	if (!strcmp(cmd, "del")) {
		ret = sentinel_filter_pid_del(pid);
		return ret ? ret : (int)len;
	}
	return -EINVAL;
}

int sentinel_filter_uids_store(const char *s, size_t len)
{
	char buf[256];
	char cmd[16];
	unsigned int uid;
	int ret;

	ret = sntl_write_copy(s, len, buf, sizeof(buf));
	if (ret)
		return ret;

	if (sscanf(buf, "%15s %u", cmd, &uid) != 2)
		return -EINVAL;
	if (!strcmp(cmd, "add")) {
		ret = sentinel_filter_uid_add(uid);
		return ret ? ret : (int)len;
	}
	if (!strcmp(cmd, "del")) {
		ret = sentinel_filter_uid_del(uid);
		return ret ? ret : (int)len;
	}
	return -EINVAL;
}

/* ------------------------------------------------------------------ */
/* pidset plumbing (process context, RCU publish)                      */
/* ------------------------------------------------------------------ */

static struct sentinel_pidset *pidset_dupornew(void)
{
	const struct sentinel_pidset *old = rcu_access_pointer(filter_pids);

	if (old)
		return kmemdup(old, sizeof(*old), GFP_KERNEL);
	return kzalloc(sizeof(struct sentinel_pidset), GFP_KERNEL);
}

/* Publish 'next', then free the previous set after readers are gone. */
static void pidset_publish(struct sentinel_pidset *next)
{
	struct sentinel_pidset *old =
		rcu_dereference_protected(filter_pids, lockdep_is_held(&filter_lock));

	rcu_assign_pointer(filter_pids, next);
	synchronize_rcu();
	kfree(old);
}

int sentinel_filter_pid_add(int pid)
{
	struct sentinel_pidset *next;
	int i, ret = 0;

	mutex_lock(&filter_lock);
	next = pidset_dupornew();
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < next->n; i++) {
		if (next->pids[i] == pid) {
			kfree(next);
			goto out;
		}
	}
	if (next->n >= SENTINEL_FILTER_PIDS_MAX) {
		kfree(next);
		ret = -ENOSPC;
		goto out;
	}
	next->pids[next->n++] = pid;
	pidset_publish(next);
out:
	mutex_unlock(&filter_lock);
	return ret;
}

int sentinel_filter_pid_del(int pid)
{
	struct sentinel_pidset *next;
	int i, ret = 0;

	mutex_lock(&filter_lock);
	next = pidset_dupornew();
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < next->n; i++) {
		if (next->pids[i] == pid) {
			next->pids[i] = next->pids[next->n - 1];
			next->n--;
			break;
		}
	}
	if (i == next->n) {
		kfree(next);
		goto out;
	}
	if (next->n)
		pidset_publish(next);
	else
		pidset_publish(kzalloc(sizeof(*next), GFP_KERNEL));
out:
	mutex_unlock(&filter_lock);
	return ret;
}

void sentinel_filter_pids_clear(void)
{
	struct sentinel_pidset *next;

	mutex_lock(&filter_lock);
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (next)
		pidset_publish(next);
	mutex_unlock(&filter_lock);
}

int sentinel_filter_pids_parse(const char *csv)
{
	struct sentinel_pidset *next, *old;
	char *copy, *tok;
	int pid;
	int ret = 0;

	mutex_lock(&filter_lock);
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	if (csv && *csv) {
		copy = kstrdup(csv, GFP_KERNEL);
		if (!copy) {
			ret = -ENOMEM;
			kfree(next);
			goto out;
		}
		for (tok = strsep(&copy, ","); tok; tok = strsep(&copy, ",")) {
			if (!*tok)
				continue;
			if (kstrtoint(tok, 10, &pid) || pid <= 0) {
				ret = -EINVAL;
				break;
			}
			if (next->n >= SENTINEL_FILTER_PIDS_MAX) {
				ret = -ENOSPC;
				break;
			}
			next->pids[next->n++] = pid;
		}
		kfree(copy);
		if (ret)
			goto out_free_next;
	}
	old = rcu_dereference_protected(filter_pids, lockdep_is_held(&filter_lock));
	rcu_assign_pointer(filter_pids, next);
	synchronize_rcu();
	kfree(old);
out:
	mutex_unlock(&filter_lock);
	return ret;
out_free_next:
	kfree(next);
	goto out;
}

int sentinel_filter_sysfs_mask(char *buf, size_t len)
{
	int n;

	mutex_lock(&filter_lock);
	n = bitmap_print_to_pagebuf(false, buf, sstate.allow, SENTINEL_SC_MAX);
	mutex_unlock(&filter_lock);
	return min_t(size_t, n, len - 1);
}

int sentinel_filter_sysfs_pids(char *buf, size_t len)
{
	const struct sentinel_pidset *set;
	int i, n = 0;

	mutex_lock(&filter_lock);
	set = rcu_dereference_protected(filter_pids, lockdep_is_held(&filter_lock));
	if (set && set->n)
		for (i = 0; i < set->n; i++)
			n += scnprintf(buf + n, len - n, "%d%c", set->pids[i],
				       i + 1 < set->n ? ',' : '\n');
	else
		n = scnprintf(buf, len, "(all)\n");
	mutex_unlock(&filter_lock);
	return n;
}

/* ------------------------------------------------------------------ */
/* uidset plumbing (process context, RCU publish)                      */
/* ------------------------------------------------------------------ */

static struct sentinel_uidset *uidset_dupornew(void)
{
	const struct sentinel_uidset *old = rcu_access_pointer(filter_uids);

	if (old)
		return kmemdup(old, sizeof(*old), GFP_KERNEL);
	return kzalloc(sizeof(struct sentinel_uidset), GFP_KERNEL);
}

static void uidset_publish(struct sentinel_uidset *next)
{
	struct sentinel_uidset *old =
		rcu_dereference_protected(filter_uids, lockdep_is_held(&filter_lock));

	rcu_assign_pointer(filter_uids, next);
	synchronize_rcu();
	kfree(old);
}

int sentinel_filter_uid_add(u32 uid)
{
	struct sentinel_uidset *next;
	int i, ret = 0;

	mutex_lock(&filter_lock);
	next = uidset_dupornew();
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < next->n; i++) {
		if (next->uids[i] == uid) {
			kfree(next);
			goto out;
		}
	}
	if (next->n >= SENTINEL_FILTER_UIDS_MAX) {
		kfree(next);
		ret = -ENOSPC;
		goto out;
	}
	next->uids[next->n++] = uid;
	uidset_publish(next);
out:
	mutex_unlock(&filter_lock);
	return ret;
}

int sentinel_filter_uid_del(u32 uid)
{
	struct sentinel_uidset *next;
	int i, ret = 0;

	mutex_lock(&filter_lock);
	next = uidset_dupornew();
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < next->n; i++) {
		if (next->uids[i] == uid) {
			next->uids[i] = next->uids[next->n - 1];
			next->n--;
			break;
		}
	}
	if (i == next->n) {
		kfree(next);
		goto out;
	}
	uidset_publish(next);
out:
	mutex_unlock(&filter_lock);
	return ret;
}

void sentinel_filter_uids_clear(void)
{
	struct sentinel_uidset *next;

	mutex_lock(&filter_lock);
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (next)
		uidset_publish(next);
	mutex_unlock(&filter_lock);
}

/* Like the pids version, but accepts values up to UID_MAX (u32); uid 0 is a
 * legitimate allowlist entry (root), so unlike pids there is no > 0 rule. */
int sentinel_filter_uids_parse(const char *csv)
{
	struct sentinel_uidset *next, *old;
	char *copy, *tok;
	int ret = 0;

	mutex_lock(&filter_lock);
	next = kzalloc(sizeof(*next), GFP_KERNEL);
	if (!next) {
		ret = -ENOMEM;
		goto out;
	}
	if (csv && *csv) {
		copy = kstrdup(csv, GFP_KERNEL);
		if (!copy) {
			ret = -ENOMEM;
			kfree(next);
			goto out;
		}
		for (tok = strsep(&copy, ","); tok; tok = strsep(&copy, ",")) {
			unsigned int uid;

			if (!*tok)
				continue;
			if (kstrtouint(tok, 10, &uid)) {
				ret = -EINVAL;
				break;
			}
			if (next->n >= SENTINEL_FILTER_UIDS_MAX) {
				ret = -ENOSPC;
				break;
			}
			next->uids[next->n++] = uid;
		}
		kfree(copy);
		if (ret)
			goto out_free_next;
	}
	old = rcu_dereference_protected(filter_uids, lockdep_is_held(&filter_lock));
	rcu_assign_pointer(filter_uids, next);
	synchronize_rcu();
	kfree(old);
out:
	mutex_unlock(&filter_lock);
	return ret;
out_free_next:
	kfree(next);
	goto out;
}

int sentinel_filter_sysfs_uids(char *buf, size_t len)
{
	const struct sentinel_uidset *set;
	int i, n = 0;

	mutex_lock(&filter_lock);
	set = rcu_dereference_protected(filter_uids, lockdep_is_held(&filter_lock));
	if (set && set->n)
		for (i = 0; i < set->n; i++)
			n += scnprintf(buf + n, len - n, "%u%c", set->uids[i],
				       i + 1 < set->n ? ',' : '\n');
	else
		n = scnprintf(buf, len, "(all)\n");
	mutex_unlock(&filter_lock);
	return n;
}

/* ------------------------------------------------------------------ */
/* init / exit                                                         */
/* ------------------------------------------------------------------ */

int sentinel_filter_init(void)
{
	bitmap_fill(sstate.allow, SENTINEL_SC_MAX);

	if (trace_mask && sentinel_filter_parse_mask(trace_mask)) {
		pr_err("sentinel_km: bad trace_mask \"%s\"\n", trace_mask);
		return -EINVAL;
	}
	if (trace_pids && sentinel_filter_pids_parse(trace_pids)) {
		pr_err("sentinel_km: bad trace_pids \"%s\"\n", trace_pids);
		return -EINVAL;
	}
	if (trace_uids && sentinel_filter_uids_parse(trace_uids)) {
		pr_err("sentinel_km: bad trace_uids \"%s\"\n", trace_uids);
		return -EINVAL;
	}
	sentinel_filter_set_enabled(trace_enable);
	return 0;
}

void sentinel_filter_exit(void)
{
	sentinel_filter_set_enabled(false);
	sentinel_filter_pids_clear();
	sentinel_filter_uids_clear();
}
