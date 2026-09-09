/*
 * capture_store_test.c -- userspace harness for arch/x86_64/
 * sentinel_capture_store.S. Compiles the exact asm through sym_shim.h and
 * checks, against a memcpy+memset reference on normal heap buffers, that the
 * store is bit-identical, and then, against PROT_NONE guard pages, that it
 * never reads past src+n_filled or writes past dst+SENTINEL_CAPTURE_BYTES.
 *
 * The kernel selftest (kernel/ipc/sentinel_capture.c) cannot prove the no
 * over-read / no over-write property without a live host; a guard page here
 * turns any such miscalculation into a SIGSEGV instead of an oops.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Must match SENTINEL_CAPTURE_BYTES in kernel/ipc/sentinel_genl.h; the asm
 * compiled through sym_shim.h pins the same constant on its side, so a
 * drift fails the battery below instead of corrupting a ring slot. */
#define SENTINEL_CAPTURE_BYTES	4141

/* Provided by the assembled sentinel_capture_store.S. */
extern void *sentinel_capture_store(void *dst, const void *src, size_t n);

static void ref_store(void *dst, const void *src, size_t n)
{
	memcpy(dst, src, n);
	memset((char *)dst + n, 0, SENTINEL_CAPTURE_BYTES - n);
}

static int heap_battery(void)
{
	static const size_t fills[] = {
		0, 1, 7, 17, 18, 32, 63, 128, 256, 512, 1024, 2048, 4090,
		4096, 4097, SENTINEL_CAPTURE_BYTES
	};
	/* One allocation per role. A shifted pointer into a shared buffer that
	 * GCC also clips for the next sub-buffer makes the object size < the
	 * poison write below and trips _FORTIFY_SOURCE, though the asm itself
	 * is in bounds -- so keep each object separate and generous. */
	unsigned char *src = malloc(SENTINEL_CAPTURE_BYTES);
	unsigned char *a = malloc(SENTINEL_CAPTURE_BYTES + 16);
	unsigned char *b = malloc(SENTINEL_CAPTURE_BYTES + 16);
	unsigned char *d, *r;
	size_t al, fi;
	int fails = 0;
	size_t i;

	if (!src || !a || !b) {
		perror("malloc");
		exit(1);
	}
	for (i = 0; i < SENTINEL_CAPTURE_BYTES; i++)
		src[i] = (unsigned char)(i * 31 + 7);

	for (al = 0; al < 16; al++) {
		d = a + (16 - al);
		r = b + (16 - al);

		for (fi = 0; fi < sizeof(fills) / sizeof(fills[0]); fi++) {
			size_t n = fills[fi];

			sentinel_capture_store(d, src, n);
			ref_store(r, src, n);

			if (memcmp(d, r, SENTINEL_CAPTURE_BYTES) != 0) {
				fprintf(stderr, "FAIL: n=%zu align=%zu (bit diff)\n",
					n, al);
				fails++;
			}
		}
	}

	free(src);
	free(a);
	free(b);
	return fails;
}

/*
 * Guard-page battery: the source ends flush against a PROT_NONE boundary and
 * the destination flush against another. A read past src+n_filled or a write
 * past dst+SENTINEL_CAPTURE_BYTES faults here instead of corrupting memory.
 *
 * Layout (5 pages, one PROT_NONE each side of the two objects):
 *   P0 writable ...... src tail (ends at P1)
 *   P1 PROT_NONE ..... guards a read past src+n-1
 *   P2/P3 writable ... dst body (4141 bytes, ends exactly at P4)
 *   P4 PROT_NONE ..... guards a write past dst+CAPTURE_BYTES-1
 */
static int guard_page_battery(void)
{
	static const size_t fills[] = { 17, 128, 2048 };
	long ps = sysconf(_SC_PAGESIZE);
	unsigned char *base;
	size_t fi;
	int fails = 0;

	base = mmap(NULL, (size_t)(5 * ps), PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	if (mprotect(base + ps, ps, PROT_NONE) != 0 ||
	    mprotect(base + 4 * ps, ps, PROT_NONE) != 0) {
		perror("mprotect");
		exit(1);
	}

	for (fi = 0; fi < sizeof(fills) / sizeof(fills[0]); fi++) {
		size_t n = fills[fi];
		unsigned char *src = base + ps - n;   /* ends at the P1 guard */
		unsigned char *dst = base + 4 * ps - SENTINEL_CAPTURE_BYTES;

		memset(src, 0x5a, n);			/* starts at P0 */
		memset(dst, 0xa5, SENTINEL_CAPTURE_BYTES);
		sentinel_capture_store(dst, src, n);

		if (memcmp(dst, src, n) != 0) {
			fprintf(stderr, "FAIL: guard n=%zu prefix mismatch\n", n);
			fails++;
		}
		for (size_t off = n; off < SENTINEL_CAPTURE_BYTES; off++)
			if (dst[off] != 0) {
				fprintf(stderr, "FAIL: guard n=%zu tail nonzero @%zu\n",
					n, off);
				fails++;
				break;
			}
	}

	munmap(base, (size_t)(5 * ps));
	return fails;
}

int main(void)
{
	int fails = 0;

	fails += heap_battery();
	fails += guard_page_battery();

	if (fails) {
		fprintf(stderr, "capture_store_test: %d failures\n", fails);
		return 1;
	}
	printf("capture_store_test: OK\n");
	return 0;
}
