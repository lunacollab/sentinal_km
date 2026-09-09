// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_main.c -- module init/exit, hook wiring, sysfs knobs.
 *
 * Unload order (must not be reordered):
 *   1. disable + unregister every hook (kretprobe unregister)
 *   2. synchronize_rcu()            -- no reader is mid-handler
 *   3. flush_workqueue()            -- no drain worker is mid-send
 *   4. destroy_workqueue()
 *   5. sentinel_ring_exit()         -- free percpu ring storage
 *   6. ringmap unmount              -- no more mmap records
 *   7. genl_unregister_family()     -- no more packets to the socket
 *
 * Within unregister, sentinel_hook_unregister already does disable + RCU
 * grace period. flush_workqueue comes after all hooks are down so no new
 * captures can be pushed.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sysctl.h>
#include <linux/version.h>

#include "sentinel_filter.h"
#include "sentinel_registry.h"
#include "../hooks/sentinel_hooks.h"
#include "../hooks/hook_common.h"
#include "../ipc/sentinel_proto.h"
#include "../ipc/sentinel_genl.h"
#include "../ipc/sentinel_ring.h"
#include "../ipc/sentinel_ringmap.h"

/* ------------------------------------------------------------------ */
/* Hook instances (static; lifetime == module lifetime)                */
/* ------------------------------------------------------------------ */
static struct sentinel_hook hook_execve = {
	.ops = &sentinel_hook_execve_ops,
};
static struct sentinel_hook hook_openat = {
	.ops = &sentinel_hook_openat_ops,
};
static struct sentinel_hook hook_connect = {
	.ops = &sentinel_hook_connect_ops,
};

#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
static struct sentinel_hook hook_mmap_exec = {
	.ops = &sentinel_hook_mmap_exec_ops,
};
static struct sentinel_hook hook_mprotect = {
	.ops = &sentinel_hook_mprotect_ops,
};
static struct sentinel_hook hook_ptrace = {
	.ops = &sentinel_hook_ptrace_ops,
};
static struct sentinel_hook hook_memfd_create = {
	.ops = &sentinel_hook_memfd_create_ops,
};
static struct sentinel_hook hook_execveat = {
	.ops = &sentinel_hook_execveat_ops,
};
static struct sentinel_hook hook_clone3 = {
	.ops = &sentinel_hook_clone3_ops,
};
static struct sentinel_hook hook_io_uring_enter = {
	.ops = &sentinel_hook_io_uring_enter_ops,
};
static struct sentinel_hook hook_finit_module = {
	.ops = &sentinel_hook_finit_module_ops,
};
#endif

static struct sentinel_hook *hooks_to_install[] = {
	&hook_execve,
	&hook_openat,
	&hook_connect,
#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
	&hook_mmap_exec,
	&hook_mprotect,
	&hook_ptrace,
	&hook_memfd_create,
	&hook_execveat,
	&hook_clone3,
	&hook_io_uring_enter,
	&hook_finit_module,
#endif
};

/* ------------------------------------------------------------------ */
/* sysfs knobs                                                         */
/* ------------------------------------------------------------------ */
static struct kobject *sentinel_kobj;

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	/* 11 event types, each pair "<type>=<count> " worst-cases ~14 chars. */
	char pairs[192];
	int off = 0;
	unsigned int type;

	/* Per-type overflow share: online rings + mmap ring, "<type>=<n>" for
	 * every type that has dropped something. Numeric ids keep the file
	 * parser-free, matching the syscall mask convention.
	 */
	for (type = 1; type < SENTINEL_EV__MAX; type++) {
		u64 n = sentinel_ring_dropped_by_type(type) +
			sentinel_ringmap_dropped_by_type(type);

		if (n)
			off += snprintf(pairs + off, sizeof(pairs) - off,
					"%u=%llu ", type,
					(unsigned long long)n);
	}
	if (!off)
		snprintf(pairs, sizeof(pairs), "(none)");

	return sysfs_emit(buf,
			  "pushed   = %llu\n"
			  "dropped  = %llu\n"
			  "sent     = %llu\n"
			  "requeued = %llu\n"
			  "drain_ns = %llu\n"
			  "drops_by_type = %s\n",
			  (unsigned long long)sentinel_ring_pushed_total(),
			  (unsigned long long)sentinel_ring_dropped_total(),
			  (unsigned long long)sentinel_genl_sent_total(),
			  (unsigned long long)sentinel_ring_requeued_total(),
			  (unsigned long long)sentinel_ring_drain_ns_total(),
			  pairs);
}
static struct kobj_attribute stats_attr = __ATTR_RO(stats);

static ssize_t version_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	return sysfs_emit(buf, "%u\n", SENTINEL_PROTO_VERSION);
}
static struct kobj_attribute version_attr = __ATTR_RO(version);

static ssize_t enable_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	return sysfs_emit(buf, "%d\n", sentinel_filter_enabled());
}

static ssize_t enable_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	bool on;
	int ret;

	ret = kstrtobool(buf, &on);
	if (ret)
		return ret;
	sentinel_filter_set_enabled(on);
	return count;
}
static struct kobj_attribute enable_attr = __ATTR_RW(enable);

/*
 * filter: show/round-trip a hex syscall bitmap, or accept the keywords
 * "all" / "none" and "set NR" / "clr NR". Interpretation lives in
 * sentinel_filter.c so the sysctl tree shares it.
 */
static ssize_t filter_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	return sentinel_filter_sysfs_mask(buf, PAGE_SIZE);
}

static ssize_t filter_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	return sentinel_filter_mask_store(buf, count);
}
static struct kobj_attribute filter_attr = __ATTR_RW(filter);

static ssize_t filter_pids_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sentinel_filter_sysfs_pids(buf, PAGE_SIZE);
}

static ssize_t filter_pids_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	return sentinel_filter_pids_store(buf, count);
}
static struct kobj_attribute filter_pids_attr = __ATTR_RW(filter_pids);

static ssize_t filter_uids_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sentinel_filter_sysfs_uids(buf, PAGE_SIZE);
}

static ssize_t filter_uids_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	return sentinel_filter_uids_store(buf, count);
}
static struct kobj_attribute filter_uids_attr = __ATTR_RW(filter_uids);

static ssize_t ring_size_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", sentinel_ring_capacity());
}

static ssize_t ring_size_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	unsigned int slots;
	int ret;

	ret = kstrtouint(buf, 0, &slots);
	if (ret)
		return ret;
	ret = sentinel_ring_resize(slots);
	if (ret)
		return ret;
	return count;
}
static struct kobj_attribute ring_size_attr = __ATTR_RW(ring_size);

/*
 * ringmap_size: data capacity (KiB, power of two) the mmap ring uses for
 * its next open. A resize is refused while a consumer holds the mapping
 * (-EBUSY). Mirror of the per-CPU ring_size knob; the ringmap holds its
 * own capacity.
 */
static ssize_t ringmap_size_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", sentinel_ringmap_capacity());
}

static ssize_t ringmap_size_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	unsigned int kib;
	int ret;

	ret = kstrtouint(buf, 0, &kib);
	if (ret)
		return ret;
	ret = sentinel_ringmap_resize(kib);
	if (ret)
		return ret;
	return count;
}

static struct kobj_attribute ringmap_size_attr = __ATTR_RW(ringmap_size);

static struct attribute *sentinel_attrs[] = {
	&stats_attr.attr,
	&version_attr.attr,
	&enable_attr.attr,
	&filter_attr.attr,
	&filter_pids_attr.attr,
	&filter_uids_attr.attr,
	&ring_size_attr.attr,
	&ringmap_size_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(sentinel);

/* ------------------------------------------------------------------ */
/* sysctl mirror (/proc/sys/kernel/sentinel)                           */
/*                                                                     */
/* Two structures are mirrored here exactly:
 *   - enable, filter, filter_pids: pre-existing knobs, now reachable by
 *     the standard /proc/sys path as well as sysfs;
 *   - filter_uids: the v6 allowlist.
 * Each entry owns a module-lifetime buffer. Reads regenerate the buffer
 * from the live filter state then delegate to proc_dostring so the sysctl
 * core returns a proper null setup; writes land in table->data and then
 * flow through the same interpreters as the sysfs store handlers, so the
 * two interfaces can never drift apart.
 * ------------------------------------------------------------------ */
#define SENTINEL_SYSCTL_BUF 512

static int sentinel_ctl_enable_val;
static char sentinel_ctl_mask_buf[SENTINEL_SYSCTL_BUF];
static char sentinel_ctl_pids_buf[SENTINEL_SYSCTL_BUF];
static char sentinel_ctl_uids_buf[SENTINEL_SYSCTL_BUF];

static void sentinel_sysctl_refresh_enable(void)
{
	sentinel_ctl_enable_val = sentinel_filter_enabled() ? 1 : 0;
}

static void sentinel_sysctl_refresh_mask(void)
{
	int n;

	n = sentinel_filter_sysfs_mask(sentinel_ctl_mask_buf,
				       SENTINEL_SYSCTL_BUF - 1);
	sentinel_ctl_mask_buf[n] = '\0';
}

static void sentinel_sysctl_refresh_pids(void)
{
	char tmp[SENTINEL_SYSCTL_BUF];
	int n;

	n = sentinel_filter_sysfs_pids(tmp, sizeof(tmp));
	snprintf(sentinel_ctl_pids_buf, sizeof(sentinel_ctl_pids_buf), "%.*s",
		 n, tmp);
}

static void sentinel_sysctl_refresh_uids(void)
{
	char tmp[SENTINEL_SYSCTL_BUF];
	int n;

	n = sentinel_filter_sysfs_uids(tmp, sizeof(tmp));
	snprintf(sentinel_ctl_uids_buf, sizeof(sentinel_ctl_uids_buf), "%.*s",
		 n, tmp);
}

static void sentinel_sysctl_refresh_all(void)
{
	sentinel_sysctl_refresh_enable();
	sentinel_sysctl_refresh_mask();
	sentinel_sysctl_refresh_pids();
	sentinel_sysctl_refresh_uids();
}

/* proc_dostring needs a \0-terminated "string" in table->data; all our
 * buffers are zeroed at load and refreshed (regenerated) on every read, so
 * passing table->data to the shared *store interpreters below is safe. */
/* Kernel 6.11 constified the ctl_table argument of proc_handlers (and the
 * proc_dostring/proc_dointvec helpers); older kernels use a mutable table.
 * Follow the house pattern from docs/KERNEL_COMPAT.md and pick the
 * signature the headers we build against actually provide. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
typedef const struct ctl_table sentinel_ctl_table;
#else
typedef struct ctl_table sentinel_ctl_table;
#endif

static int sentinel_sysctl_enable(sentinel_ctl_table *table, int write,
				  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, *v = table->data;

	if (!write)
		*v = sentinel_filter_enabled() ? 1 : 0;
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0 && write)
		sentinel_filter_set_enabled(!!*v);
	return ret;
}

static int sentinel_sysctl_mask(sentinel_ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	if (write) {
		ret = proc_dostring(table, write, buffer, lenp, ppos);
		if (ret)
			return ret;
		return sentinel_filter_mask_store(table->data, strlen(table->data));
	}
	sentinel_sysctl_refresh_mask();
	return proc_dostring(table, write, buffer, lenp, ppos);
}

static int sentinel_sysctl_pids(sentinel_ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	if (write) {
		ret = proc_dostring(table, write, buffer, lenp, ppos);
		if (ret)
			return ret;
		return sentinel_filter_pids_store(table->data, strlen(table->data));
	}
	sentinel_sysctl_refresh_pids();
	return proc_dostring(table, write, buffer, lenp, ppos);
}

static int sentinel_sysctl_uids(sentinel_ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;

	if (write) {
		ret = proc_dostring(table, write, buffer, lenp, ppos);
		if (ret)
			return ret;
		return sentinel_filter_uids_store(table->data, strlen(table->data));
	}
	sentinel_sysctl_refresh_uids();
	return proc_dostring(table, write, buffer, lenp, ppos);
}

static struct ctl_table sentinel_sysctl_table[] = {
	{
		.procname	= "enable",
		.data		= &sentinel_ctl_enable_val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sentinel_sysctl_enable,
	},
	{
		.procname	= "filter",
		.data		= sentinel_ctl_mask_buf,
		.maxlen		= sizeof(sentinel_ctl_mask_buf),
		.mode		= 0644,
		.proc_handler	= sentinel_sysctl_mask,
	},
	{
		.procname	= "filter_pids",
		.data		= sentinel_ctl_pids_buf,
		.maxlen		= sizeof(sentinel_ctl_pids_buf),
		.mode		= 0644,
		.proc_handler	= sentinel_sysctl_pids,
	},
	{
		.procname	= "filter_uids",
		.data		= sentinel_ctl_uids_buf,
		.maxlen		= sizeof(sentinel_ctl_uids_buf),
		.mode		= 0644,
		.proc_handler	= sentinel_sysctl_uids,
	},
	{}
};

static struct ctl_table_header *sentinel_sysctl_header;

/* selftest=0 skips the init-time copy/selftest battery (some deployments
 * refuse any work before load). */
static bool selftest = true;
module_param(selftest, bool, 0644);
MODULE_PARM_DESC(selftest, "run the copy/strnlen selftest battery at init");

/* ------------------------------------------------------------------ */
/* init / exit                                                         */
/* ------------------------------------------------------------------ */
static int __init sentinel_init(void)
{
	int ret, i;

	ret = hook_init_copy_helper();
	if (ret)
		goto err_copy;

	ret = sentinel_crc_init();
	if (ret)
		goto err_copy;

	if (selftest) {
		ret = hook_run_copy_selftest();
		if (ret) {
			pr_err("sentinel_km: selftest failed (%d); refusing to load\n",
			       ret);
			goto err_copy;
		}
		ret = sentinel_capture_selftest();
		if (ret) {
			pr_err("sentinel_km: capture_store selftest failed (%d); refusing to load\n",
			       ret);
			goto err_copy;
		}
		ret = sentinel_crc_selftest();
		if (ret) {
			pr_err("sentinel_km: crc32c selftest failed (%d); refusing to load\n",
			       ret);
			goto err_copy;
		}
	}

	ret = sentinel_filter_init();
	if (ret)
		goto err_filter;

	ret = sentinel_ringmap_init();
	if (ret)
		goto err_ringmap;
	ret = sentinel_ring_init();
	if (ret)
		goto err_ring;
	ret = sentinel_genl_register();
	if (ret)
		goto err_genl;

	ret = sentinel_registry_init();
	if (ret)
		goto err_registry;

	for (i = 0; i < ARRAY_SIZE(hooks_to_install); i++) {
		ret = sentinel_hook_register(hooks_to_install[i]);
		if (ret)
			goto err_hooks;
		ret = sentinel_hook_enable(hooks_to_install[i]);
		if (ret) {
			sentinel_hook_unregister(hooks_to_install[i]);
			goto err_hooks;
		}
	}

	sentinel_kobj = kobject_create_and_add("sentinel_km", kernel_kobj);
	if (!sentinel_kobj) {
		pr_err("sentinel_km: sysfs kobject create failed\n");
		goto err_hooks;
	}
	ret = sysfs_create_groups(sentinel_kobj, sentinel_groups);
	if (ret) {
		kobject_put(sentinel_kobj);
		sentinel_kobj = NULL;
		pr_err("sentinel_km: sysfs groups failed (%d)\n", ret);
		goto err_hooks;
	}

	sentinel_sysctl_refresh_all();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
	sentinel_sysctl_header = register_sysctl_sz("kernel/sentinel",
						sentinel_sysctl_table,
						ARRAY_SIZE(sentinel_sysctl_table) - 1);
#else
	sentinel_sysctl_header = register_sysctl("kernel/sentinel",
						sentinel_sysctl_table);
#endif
	if (!sentinel_sysctl_header) {
		sysfs_remove_groups(sentinel_kobj, sentinel_groups);
		kobject_put(sentinel_kobj);
		sentinel_kobj = NULL;
		pr_err("sentinel_km: sysctl register failed\n");
		ret = -ENOMEM;
		goto err_hooks;
	}

	pr_info("sentinel_km: loaded, proto v%u, hooks=%zu\n",
		SENTINEL_PROTO_VERSION, ARRAY_SIZE(hooks_to_install));
	return 0;

err_hooks:
	for (i = ARRAY_SIZE(hooks_to_install) - 1; i >= 0; i--)
		sentinel_hook_unregister(hooks_to_install[i]);
	sentinel_registry_exit();
err_registry:
	sentinel_genl_unregister();
err_genl:
	sentinel_ring_exit();
err_ring:
	sentinel_ringmap_exit();
err_ringmap:
	sentinel_filter_exit();
err_filter:
err_copy:
	return ret;
}

static void __exit sentinel_exit(void)
{
	int i;

	if (sentinel_kobj) {
		sysfs_remove_groups(sentinel_kobj, sentinel_groups);
		kobject_put(sentinel_kobj);
	}

	if (sentinel_sysctl_header)
		unregister_sysctl_table(sentinel_sysctl_header);

	/* 1. stop all probes */
	for (i = ARRAY_SIZE(hooks_to_install) - 1; i >= 0; i--)
		sentinel_hook_unregister(hooks_to_install[i]);
	sentinel_registry_exit();

	/* 2. RCU grace already elapsed per unregister; flush pending drains */
	sentinel_ring_flush();
	sentinel_ring_exit();
	sentinel_ringmap_exit();

	/* 3. family teardown last: no more messages can be emitted */
	sentinel_genl_unregister();

	sentinel_filter_exit();
	pr_info("sentinel_km: unloaded\n");
}

module_init(sentinel_init);
module_exit(sentinel_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sentinel-org");
MODULE_DESCRIPTION("kprobe-based syscall activity monitor (v6: argv, mmap, mprotect, execveat, memfd, ptrace; v8: clone3, io_uring_enter, finit_module)");
MODULE_VERSION("0.4.0");
