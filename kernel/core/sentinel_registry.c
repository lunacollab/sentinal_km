// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_registry.c -- RCU-protected hook registry.
 *
 * The registry is deliberately small: hooks are added once at module init and
 * removed once at exit, so the protecting structures (a global lock for
 * writers, RCU for readers) never become a bottleneck. Its four-step teardown
 * order -- unregister probe -> synchronize_rcu() -> remove from list -> free
 * -- is what makes module unload safe against a callback that is mid-flight
 * on another CPU.
 *
 * See docs/ARCHITECTURE.md for the full ordering rationale.
 */
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/module.h>

#include "sentinel_registry.h"

static DEFINE_SPINLOCK(sentinel_registry_lock);
static LIST_HEAD(sentinel_hooks);

static void hook_remove_locked(struct sentinel_hook *hook)
{
	list_del_rcu(&hook->node);
}

int sentinel_hook_register(struct sentinel_hook *hook)
{
	struct sentinel_hook *existing;
	unsigned long flags;

	INIT_LIST_HEAD(&hook->node);
	hook->enabled = false;

	spin_lock_irqsave(&sentinel_registry_lock, flags);
	/* Duplicate names are a programming error; reject loudly. */
	list_for_each_entry(existing, &sentinel_hooks, node) {
		if (!strcmp(existing->ops->name, hook->ops->name)) {
			spin_unlock_irqrestore(&sentinel_registry_lock, flags);
			pr_err("sentinel_km: duplicate hook '%s'\n",
			       hook->ops->name);
			return -EEXIST;
		}
	}
	list_add_tail(&hook->node, &sentinel_hooks);
	spin_unlock_irqrestore(&sentinel_registry_lock, flags);
	return 0;
}

int sentinel_hook_enable(struct sentinel_hook *hook)
{
	int ret = 0;

	if (!hook->ops->enable)
		return 0;
	ret = hook->ops->enable();
	if (ret == 0)
		WRITE_ONCE(hook->enabled, true);
	return ret;
}

void sentinel_hook_disable(struct sentinel_hook *hook)
{
	if (!hook->enabled)
		return;
	if (hook->ops->disable)
		hook->ops->disable();
	WRITE_ONCE(hook->enabled, false);
}

void sentinel_hook_unregister(struct sentinel_hook *hook)
{
	unsigned long flags;

	if (!hook)
		return;

	/* 1: stop the probe from firing (worst case: a handler is already
	 * inside rcu_read_lock; it will finish and then see its hook as
	 * disabled).
	 */
	if (hook->enabled && hook->ops->disable)
		hook->ops->disable();
	hook->enabled = false;

	/* 2 & 3: drop from the list under the lock, then wait for any
	 * in-flight rcu_read_lock() readers (queue_work users) to exit.
	 */
	spin_lock_irqsave(&sentinel_registry_lock, flags);
	hook_remove_locked(hook);
	spin_unlock_irqrestore(&sentinel_registry_lock, flags);
	synchronize_rcu();
}

int sentinel_registry_init(void)
{
	return 0;
}

void sentinel_registry_exit(void)
{
	/* All hooks must already be unregistered (see sentinel_main). */
	WARN_ON_ONCE(!list_empty(&sentinel_hooks));
}
