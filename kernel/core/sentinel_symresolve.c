// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_symresolve.c -- resolve unexported kernel symbols.
 *
 * kallsyms_lookup_name() has not been exported to modules since Linux 5.7
 * (commit 0bd476e6c671). The sanctioned workaround is to place a throwaway
 * kprobe on the target symbol name; after register_kprobe() the resolved
 * address is available in kp.addr. We unregister immediately.
 *
 * This is used ONLY to reach kernel-internal symbols we have no other
 * exported handle for. All syscall entry points we probe are registered by
 * name directly through register_kprobe()/register_kretprobe(), so they
 * never pass through here.
 */
#include <linux/kprobes.h>
#include <linux/module.h>

#include "sentinel_symresolve.h"

unsigned long sentinel_resolve_symbol(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}
EXPORT_SYMBOL_GPL(sentinel_resolve_symbol);
