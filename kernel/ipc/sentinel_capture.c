// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_capture.c -- capture store and its differential selftest.
 *
 * The hot path moves a capture into a ring slot with a single pass: copy the
 * populated header+payload prefix and zero the rest, instead of memsetting
 * the whole object and then copying it. On x86_64 that pass is
 * arch/x86_64/sentinel_capture_store.S (sentinel_capture_store); everywhere
 * else the C reference below is used, which is byte-identical to the struct
 * copy it replaces.
 *
 * The selftest is what makes the two implementations trustworthy rather than
 * trusting either one: it runs the asm against the C reference over a matrix
 * of n_filled x alignment x guard-page placements and requires bit-for-bit
 * equality. A mismatch refuses the module load. The kernel selftest cannot
 * prove the no-over-read property on a live host, so the same harness is
 * mirrored in tests/unit/capture_store_test.c against PROT_NONE guard pages.
 */
#include <linux/string.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/bug.h>

#include "sentinel_genl.h"

/*
 * Reference implementation and the non-x86_64 production path. memcpy then
 * memset is exactly what the ring's struct copy would have done, which is the
 * whole point: the asm must reproduce this bit-for-bit and the selftest
 * checks it.
 */
void *sentinel_capture_store_c(void *dst, const void *src, size_t n_filled)
{
	memcpy(dst, src, n_filled);
	memset((char *)dst + n_filled, 0, SENTINEL_CAPTURE_BYTES - n_filled);
	return dst;
}

#ifndef CONFIG_X86_64
void *sentinel_capture_store(void *dst, const void *src, size_t n_filled)
{
	return sentinel_capture_store_c(dst, src, n_filled);
}
#endif
EXPORT_SYMBOL_GPL(sentinel_capture_store);

/* ------------------------------------------------------------------ */
/* Differential selftest (x86_64 only; the asm is what it tests).     */
/* ------------------------------------------------------------------ */

#ifdef CONFIG_X86_64
static int capture_diff_battery(void)
{
	static const size_t fills[] = {
		0, 1, 7, 17, 18, 32, 63, 128, 256, 512, 1024, 2048, 4090,
		4096, 4097, SENTINEL_CAPTURE_BYTES
	};
	const size_t unit = SENTINEL_CAPTURE_BYTES * 2 + 64;
	u8 *mem = kmalloc(unit + SENTINEL_CAPTURE_BYTES + 64, GFP_KERNEL);
	u8 *src, *dst, *ref;
	int rc = 0;
	size_t i, al, f;

	if (!mem)
		return -ENOMEM;

	/* src sits in its own region; dst and ref are the two parallel stores
	 * the test must prove identical. The 32-byte slack between regions
	 * absorbs the -al alignment shift without an underflow.
	 */
	dst = mem + 16;
	src = mem + SENTINEL_CAPTURE_BYTES + 32;
	ref = src + SENTINEL_CAPTURE_BYTES + 32;

	/* Deterministic pattern that exercises every byte position. */
	for (i = 0; i < SENTINEL_CAPTURE_BYTES; i++)
		src[i] = (u8)(i * 31 + 7);

	for (al = 0; al < 16 && !rc; al++) {
		u8 *d = dst - al;
		u8 *r = ref - al;

		for (f = 0; f < ARRAY_SIZE(fills); f++) {
			size_t n = fills[f];

			/* Poison both objects and the byte just past them so a
			 * wrong-size store shows up either as a diff with the
			 * C reference or as an over-write.
			 */
			memset(d, 0xa5, SENTINEL_CAPTURE_BYTES + 1);
			memset(r, 0xa5, SENTINEL_CAPTURE_BYTES + 1);

			sentinel_capture_store(d, src, n);
			sentinel_capture_store_c(r, src, n);

			if (memcmp(d, r, SENTINEL_CAPTURE_BYTES) != 0) {
				pr_err("sentinel_km: capture_store mismatch n_filled=%zu align=%zu\n",
				       n, al);
				rc = -EINVAL;
				break;
			}
			if (d[SENTINEL_CAPTURE_BYTES] != 0xa5 ||
			    r[SENTINEL_CAPTURE_BYTES] != 0xa5) {
				pr_err("sentinel_km: capture_store over-write n_filled=%zu align=%zu\n",
				       n, al);
				rc = -EINVAL;
				break;
			}
		}
	}

	kfree(mem);
	if (rc)
		pr_err("sentinel_km: capture_store differential test failed\n");
	return rc;
}

int sentinel_capture_selftest(void)
{
	return capture_diff_battery();
}
#else
int sentinel_capture_selftest(void)
{
	return 0;
}
#endif
EXPORT_SYMBOL_GPL(sentinel_capture_selftest);
