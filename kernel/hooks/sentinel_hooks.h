// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_hooks.h -- concrete hook ops exposed from the hooks/ tree.
 *
 * Each hook *.c exports exactly one const ops table. sentinel_main.c wires
 * these into static struct sentinel_hook instances.
 */
#ifndef _SENTINEL_HOOKS_H
#define _SENTINEL_HOOKS_H

#include "../core/sentinel_registry.h"

extern const struct sentinel_hook_ops sentinel_hook_execve_ops;
extern const struct sentinel_hook_ops sentinel_hook_openat_ops;
extern const struct sentinel_hook_ops sentinel_hook_connect_ops;
#if defined(CONFIG_X86_64) || defined(CONFIG_ARM64)
extern const struct sentinel_hook_ops sentinel_hook_mmap_exec_ops;
extern const struct sentinel_hook_ops sentinel_hook_mprotect_ops;
extern const struct sentinel_hook_ops sentinel_hook_ptrace_ops;
extern const struct sentinel_hook_ops sentinel_hook_memfd_create_ops;
extern const struct sentinel_hook_ops sentinel_hook_execveat_ops;
extern const struct sentinel_hook_ops sentinel_hook_clone3_ops;
extern const struct sentinel_hook_ops sentinel_hook_io_uring_enter_ops;
extern const struct sentinel_hook_ops sentinel_hook_finit_module_ops;
#endif

#endif /* _SENTINEL_HOOKS_H */
