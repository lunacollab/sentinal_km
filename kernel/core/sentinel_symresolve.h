// SPDX-License-Identifier: GPL-2.0-only
#ifndef _SENTINEL_SYMRESOLVE_H
#define _SENTINEL_SYMRESOLVE_H

/*
 * Resolve the address of an unexported kernel symbol by name.
 * Returns 0 if the symbol could not be resolved.
 * Caller must not be in atomic context.
 */
unsigned long sentinel_resolve_symbol(const char *name);

#endif /* _SENTINEL_SYMRESOLVE_H */
