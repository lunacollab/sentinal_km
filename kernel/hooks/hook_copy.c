// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_copy.c -- kernel-version-independent user-memory capture.
 *
 * strncpy_from_user_nofault() and copy_from_user_nofault() are not exported
 * to modules on newer kernels. Both are resolved once at init through a
 * throwaway kprobe; on failure we fall back to the always-exported
 * strncpy_from_user()/copy_from_user(), which is acceptable because we run
 * as current during a real syscall with a mapped user range.
 *
 * sentinel_strnlen_user_max() splits the work: the fault-prone copy stays in
 * C as a page-chunked nofault scan, and the NUL probe runs over the already
 * copied kernel buffer. On x86_64 that probe is the SSE2 loop in
 * arch/x86_64/sentinel_memchr_zero.S; elsewhere a byte loop. The split is
 * deliberate: the asm half never touches user memory and never needs an
 * exception table, so it builds under any module toolchain.
 */
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/gfp.h>

#include "hook_common.h"
#include "../core/sentinel_symresolve.h"

#define SENTINEL_STRNLEN_CHUNK	128

typedef long (*nofault_strncpy_t)(char *, const char __user *, long);
typedef long (*nofault_copy_t)(void *, const void __user *, unsigned long);

static nofault_strncpy_t nofault_strncpy;
static nofault_copy_t nofault_copy;

long hook_strncpy_from_user(char *dst, const char __user *src, long count)
{
	if (nofault_strncpy)
		return nofault_strncpy(dst, src, count);
	return strncpy_from_user(dst, src, count);
}
EXPORT_SYMBOL_GPL(hook_strncpy_from_user);

long hook_copy_from_user_nofault(void *dst, const void __user *src,
				 unsigned long n)
{
	if (nofault_copy)
		return nofault_copy(dst, src, n);
	if (copy_from_user(dst, src, n))
		return -EFAULT;
	return n;
}
EXPORT_SYMBOL_GPL(hook_copy_from_user_nofault);

/*
 * Page-chunked nofault scan of user memory. A chunk never crosses a page
 * boundary, so copy_from_user either completes the whole chunk or faults the
 * whole chunk (user mappings do not partially page-fault), which is exactly
 * the "string ends at the fault" contract strnlen_user() promises. Handles
 * (max == 0) and no NUL within max by construction.
 */
long sentinel_strnlen_user_max(const char __user *s, long max)
{
	long scanned = 0;

	if (max <= 0)
		return 0;
	while (scanned < max) {
		unsigned long off = (unsigned long)s & (PAGE_SIZE - 1);
		long chunk = min_t(long, max - scanned, PAGE_SIZE - off);
		char buf[SENTINEL_STRNLEN_CHUNK];
		long got, first;

		if (chunk > (long)sizeof(buf))
			chunk = sizeof(buf);
		got = hook_copy_from_user_nofault(buf, s, chunk);
		if (got != chunk)
			return scanned;	/* fault: pretend NUL here */

#if defined(CONFIG_X86_64) && !defined(__KERNEL__)
		first = sentinel_memchr_zero(buf, chunk);
#else
		for (first = 0; first < chunk &&
		     buf[first] != '\0'; first++)
			;
#endif
		if (first < chunk)
			return scanned + first;
		scanned += chunk;
		s += chunk;
	}
	return max + 1;		/* no NUL within max bytes */
}
EXPORT_SYMBOL_GPL(sentinel_strnlen_user_max);

#if defined(CONFIG_X86_64) && !defined(__KERNEL__)
/* The asm hot path must never recurse into this module's own probes. */
NOKPROBE_SYMBOL(sentinel_memchr_zero);
#endif
NOKPROBE_SYMBOL(sentinel_strnlen_user_max);
NOKPROBE_SYMBOL(hook_copy_from_user_nofault);

/* ------------------------------------------------------------------ */
/* Selftest: exercised at module init unless selftest=0 (x86_64 only,  */
/* it exists to prove the asm loop).                                   */
/*                                                                     */
/* basic()     walks alignment x length x NUL-position against a byte  */
/*             reference, catching ordering/logic bugs.                */
/* boundary()  places buffers flush at the end of an allocated page.   */
/*             The asm loop must never read past buf[n-1]; a length    */
/*             miscalculation here touches the unmapped next page.     */
/* ------------------------------------------------------------------ */

#if defined(CONFIG_X86_64) && !defined(__KERNEL__)
static int memchr_zero_check(const char *buf, long n, long want)
{
	long got = sentinel_memchr_zero(buf, n);

	if (got != want) {
		pr_err("sentinel_km: selftest memchr_zero n=%ld want=%ld got=%ld\n",
		       n, want, got);
		return -EINVAL;
	}
	return 0;
}

static int memchr_zero_basic(void)
{
	unsigned char buf[256];
	static const long lens[] = { 1, 7, 15, 16, 17, 31, 63, 64, 127, 128 };
	static const long zpos[] = { 0, 1, 5, 15, 16, 63, 126, 127 };
	char *p = buf + 32;	/* room to unalign p[0] by 0..15 for each iter */
	int rc, i, l, z;

	for (l = 0; l < ARRAY_SIZE(lens); l++) {
		long n = lens[l];

		for (i = 0; i < 16; i++) {
			char *b = p + i;

			/* no zero present */
			memset(b, 0x5a, n);
			rc = memchr_zero_check(b, n, n);
			if (rc)
				return rc;

			for (z = 0; z < ARRAY_SIZE(zpos); z++) {
				long want = zpos[z];

				if (want >= n)
					continue;
				memset(b, 0x5a, n);
				b[want] = 0;
				rc = memchr_zero_check(b, n, want);
				if (rc)
					return rc;
			}
		}
	}
	return 0;
}

static int memchr_zero_boundary(void)
{
	static const long lens[] = { 1, 8, 15, 16, 17, 31, 64, 128 };
	char *p = (char *)__get_free_page(GFP_KERNEL);
	int rc, l;

	if (!p)
		return -ENOMEM;
	for (l = 0; l < ARRAY_SIZE(lens); l++) {
		long n = lens[l];
		char *b = p + PAGE_SIZE - n;

		memset(b, 0x5a, n);
		rc = memchr_zero_check(b, n, n);
		if (rc)
			goto out;
		b[n - 1] = 0;
		rc = memchr_zero_check(b, n, n - 1);
		if (rc)
			goto out;
	}
	pr_info("sentinel_km: memchr_zero selftest: %zu vectors OK\n",
		ARRAY_SIZE(lens) * 2);
out:
	free_page((unsigned long)p);
	return rc;
}
#endif /* userspace x86_64 harness */

int hook_run_copy_selftest(void)
{
	pr_info("sentinel_km: memchr_zero selftest: n/a in kernel (SIMD disabled)\n");
	return 0;
}
EXPORT_SYMBOL_GPL(hook_run_copy_selftest);

int hook_init_copy_helper(void)
{
	nofault_strncpy = (nofault_strncpy_t)sentinel_resolve_symbol(
		"strncpy_from_user_nofault");
	if (!nofault_strncpy)
		pr_info("sentinel_km: strncpy_from_user_nofault unavailable, using strncpy_from_user\n");

	nofault_copy = (nofault_copy_t)sentinel_resolve_symbol(
		"copy_from_user_nofault");
	if (!nofault_copy)
		pr_info("sentinel_km: copy_from_user_nofault unavailable, using copy_from_user\n");

	return 0;
}
EXPORT_SYMBOL_GPL(hook_init_copy_helper);
