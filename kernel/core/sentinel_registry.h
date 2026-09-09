// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_registry.h -- RCU-protected hook registry.
 *
 * A hook is a named probe (single kprobe or kretprobe pair) that the module
 * can register/unregister dynamically. The list is read on the hot path
 * (every syscall) and mutated only at load/unload, which is the textbook
 * RCU use case. Readers hold rcu_read_lock(); writers take an exclusive
 * spinlock and call synchronize_rcu() before freeing.
 */
#ifndef _SENTINEL_REGISTRY_H
#define _SENTINEL_REGISTRY_H

struct sentinel_hook;

/* Lifecycle callbacks supplied by a concrete hook implementation. Hooks are
 * static singletons; enable/disable take no arguments and return 0 on
 * success. Invoked in process context, module refcount held. */
struct sentinel_hook_ops {
	const char *name;
	int (*enable)(void);
	void (*disable)(void);
};

struct sentinel_hook {
	const struct sentinel_hook_ops *ops;
	struct list_head node;
	bool enabled;
};

/* Register a hook (takes ownership of the struct until removed). */
int sentinel_hook_register(struct sentinel_hook *hook);

/* Disable + unregister + release the hook. Caller must not hold the
 * registry lock. Safe to call multiple times (idempotent). */
void sentinel_hook_unregister(struct sentinel_hook *hook);

/* Enable/disable an already-registered hook. */
int sentinel_hook_enable(struct sentinel_hook *hook);
void sentinel_hook_disable(struct sentinel_hook *hook);

int sentinel_registry_init(void);
void sentinel_registry_exit(void);

#endif /* _SENTINEL_REGISTRY_H */
