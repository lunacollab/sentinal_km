// SPDX-License-Identifier: Apache-2.0
/*
 * crc_asm_test.c -- differential harness for arch/x86_64/sentinel_crc32c.S.
 *
 * The kernel refuses to load unless its init battery proves the SSE4.2 asm
 * equals the table reference (sentinel_crc_selftest). This harness runs the
 * same comparison in userspace, where the length/alignment matrix can be
 * pushed far larger at ASan/UBSan cost rather than load time, and adds a
 * split-window composition check (the packetization-independence the wire
 * CRC relies on). Skipped (exit 77) on CPUs without SSE4.2, mirroring
 * boot_cpu_has().
 *
 * Compile with sym_shim.h for the kernel SYM_* names; the .S raises its own
 * ISA level via the .arch sse4_2 directive:
 *   cc -include tests/unit/sym_shim.h crc_asm_test.c sentinel_crc.c \
 *      kernel/arch/x86_64/sentinel_crc32c.S
 */
#include <assert.h>
#include <cpuid.h>
#include <stdio.h>
#include <string.h>

#include "sentinel_crc.h"
#include "sentinel_proto.h"

extern unsigned int sentinel_crc32c_seed(unsigned int crc, const void *p,
					 unsigned long len);

static unsigned long rng_state = 0x9e3779b97f4a7c15UL;

static unsigned long rng_next(void)
{
	/* xorshift64*: cheap, deterministic, exercises every bit position. */
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return rng_state * 0x2545f4914f6cdd1dUL;
}

static int have_sse4_2(void)
{
	unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

	if (__get_cpuid_max(1, NULL) < 1)
		return 0;
	__get_cpuid(1, &eax, &ebx, &ecx, &edx);
	return (ecx >> 20) & 1;
}

#define BUF_SZ		4096
#define ITERS		8192

static void differential_matrix(void *bufp)
{
	unsigned char (*buf)[BUF_SZ + 16] = bufp;
	unsigned long i, len, off;

	/* Exhaustive length sweep from the fixed vector, the same ground
	 * the kernel selftest covers at load time. */
	for (len = 0; len <= 519; len++) {
		unsigned int t = sentinel_crc32c(*buf, len);
		unsigned int a = sentinel_crc32c_seed(0xffffffffU, *buf, len) ^
				 0xffffffffU;

		assert(a == t);
	}

	/* Random lengths and byte alignments against the table reference. */
	for (i = 0; i < ITERS; i++) {
		len = rng_next() % (BUF_SZ + 1);
		off = rng_next() % 16;
		assert((sentinel_crc32c_seed(0xffffffffU, *buf + off, len) ^
			0xffffffffU) == sentinel_crc32c(*buf + off, len));
	}

	/* Splitting a buffer in two and seeding the second half with the
	 * first must equal one pass -- exactly the window composition that
	 * sentinel_crc_payload() builds for the wire frame. */
	for (i = 0; i < 256; i++) {
		unsigned int seed, once;

		len = 256 + rng_next() % (BUF_SZ - 255);
		seed = sentinel_crc32c_seed(0xffffffffU, *buf, len);
		once = sentinel_crc32c_seed(seed, *buf + len, BUF_SZ - len) ^
		       0xffffffffU;
		assert(once == sentinel_crc32c(*buf, BUF_SZ));
	}
}

int main(void)
{
	static unsigned char buf[BUF_SZ + 16];
	unsigned long i;

	if (!have_sse4_2()) {
		puts("crc_asm_test: SKIP (no SSE4.2)");
		return 77;
	}
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (unsigned char)rng_next();
	differential_matrix(&buf);
	puts("crc_asm_test: OK");
	return 0;
}
