/*
 * memchr_zero_test.c -- userspace harness for arch/x86_64/
 * sentinel_memchr_zero.S. Compiles the exact asm instructions through
 * sym_shim.h and checks two properties the kernel selftest cannot prove
 * without risking a live host:
 *
 *   1. logical correctness against a byte reference across alignment x
 *      length x NUL-position combinations;
 *   2. no over-read past buf[n-1] -- buffers are placed flush against a
 *      PROT_NONE guard page, so a miscalculated load faults (SIGSEGV) here
 *      instead of oopsing the machine.
 *
 * The daemon build already depends on nothing beyond the C library and
 * kernel UAPI headers, matching this test.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Provided by the assembled sentinel_memchr_zero.S. */
extern long sentinel_memchr_zero(const void *buf, long n);

static long ref_memchr_zero(const char *buf, long n)
{
	long i;

	for (i = 0; i < n; i++)
		if (buf[i] == '\0')
			return i;
	return n;
}

static int check(const char *buf, long n, long want)
{
	long got = sentinel_memchr_zero(buf, n);
	long ref = ref_memchr_zero(buf, n);
	if (got != want || ref != want) {
		fprintf(stderr, "FAIL: n=%ld want=%ld asm=%ld ref=%ld\n",
			n, want, got, ref);
		return 1;
	}
	return 0;
}

/* Logical battery over heap buffers (kernel buffer notion). */
static int logical_battery(void)
{
	static const long lens[] = { 1, 7, 15, 16, 17, 31, 63, 64, 127, 128,
				     256, 1024, 4096 };
	static const long zpos[] = { 0, 1, 5, 15, 16, 63, 126, 127, 255,
				     1024, 4095 };
	unsigned char buf[4160];
	char *p = (char *)buf + 32;
	long n;
	int i, z, fails = 0;

	for (i = 0; i < (int)(sizeof(lens) / sizeof(lens[0])); i++) {
		n = lens[i];

		for (int a = 0; a < 16; a++) {
			char *b = p + a;

			memset(b, 0x5a, (size_t)n);
			fails += check(b, n, n);

			for (z = 0; z < (int)(sizeof(zpos) / sizeof(zpos[0])); z++) {
				long want = zpos[z];

				if (want >= n)
					continue;
				memset(b, 0x5a, (size_t)n);
				b[want] = 0;
				fails += check(b, n, want);
			}
		}
	}
	return fails;
}

/* Guard-page battery: buffer end sits exactly on a PROT_NONE boundary.
 * Any over-read in the asm loop faults here instead of a live kernel. */
static int guard_page_battery(void)
{
	static const long lens[] = { 1, 8, 15, 16, 17, 31, 64, 128, 256,
				     1024, 2048, 4096 };
	long ps = (long)sysconf(_SC_PAGESIZE);
	char *base;
	int fails = 0;
	size_t l;

	base = mmap(NULL, (size_t)(2 * ps), PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	if (mprotect(base + ps, (size_t)ps, PROT_NONE) != 0) {
		perror("mprotect");
		exit(1);
	}

	for (l = 0; l < sizeof(lens) / sizeof(lens[0]); l++) {
		long n = lens[l];
		char *b = base + ps - n;

		memset(b, 0x5a, (size_t)n);
		fails += check(b, n, n);
		b[n - 1] = 0;
		fails += check(b, n, n - 1);
	}

	munmap(base, (size_t)(2 * ps));
	return fails;
}

int main(void)
{
	int fails = 0;

	fails += logical_battery();
	fails += guard_page_battery();

	if (fails) {
		fprintf(stderr, "memchr_zero_test: %d failures\n", fails);
		return 1;
	}
	printf("memchr_zero_test: OK\n");
	return 0;
}
