// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/x86_64/sentinel_crc32c.S -- SSE4.2 CRC-32C (Castagnoli) stream fold.
 *
 * __u32 sentinel_crc32c_seed(__u32 crc, const void *p, unsigned long len)
 *
 *   args (SysV AMD64): edi=crc, rsi=p, rdx=len
 *   Folds len bytes at p into the running CRC-32C accumulation and returns
 *   it WITHOUT the terminal complement. A caller that owns part of a window
 *  (the wire CRC covers the 48 header bytes before crc32 plus the payload
 *   in one running fold) seeds with the prior value and keeps folding;
 *   sentinel_crc32c() is this function over the full span plus a final xor:
 *
 *     __u32 sentinel_crc32c(void *p, unsigned long n) {
 *         return ~sentinel_crc32c_seed(0xffffffffU, p, n);
 *     }
 *
 *   The mapping to the table reference in sentinel_crc.c is one-to-one:
 *   each crc32q/crc32l/crc32w/crc32b consumes 8/4/2/1 bytes and updates the
 *   accumulator exactly as the reflected sub-byte reference loop does, so
 *   processing order is packetization-independent. Both paths are proven
 *   equal at module init (sentinel_crc_selftest()) over a length matrix and
 *   again in userspace under ASan by tests/unit/crc_asm_test.c.
 *
 *   Shape mirrors sentinel_memchr_zero.S: a 4*qword block loop (32 bytes
 *   per trip) for the bulk, then 16- and 8-byte degrades, then a 4/2/1 byte
 *   scalar tail. No .fixup and no __ex_table -- this only touches kernel
 *   memory that is valid by construction.
 */
#ifdef __KERNEL__
#include <linux/linkage.h>
#endif

#if defined(CONFIG_MITIGATION_RETHUNK) || defined(CONFIG_RETHUNK)
#define SENTINEL_RET	jmp __x86_return_thunk
#else
#define SENTINEL_RET	ret
#endif

/* crc32* is not part of the SSE2 baseline every x86_64 toolchain assumes;
 * raise the ISA level for this object only. corei7 (Nehalem) covers the
 * crc32 instruction on binutils and on gcc's integrated assembler alike. */
	.arch	corei7

SYM_FUNC_START(sentinel_crc32c_seed)
	mov	%edi, %eax		/* accumulator (lower 32 bits) */
	mov	%rsi, %rdi		/* p */
	mov	%rdx, %rcx		/* len */
	test	%rcx, %rcx
	jz	.Ldone

	/* Bulk: 4*qword blocks while at least 32 bytes remain. */
	cmp	$32, %rcx
	jb	.Lbulk_blocks
.Lbulk:
	crc32q	(%rdi), %rax
	crc32q	8(%rdi), %rax
	crc32q	16(%rdi), %rax
	crc32q	24(%rdi), %rax
	add	$32, %rdi
	sub	$32, %rcx
	cmp	$32, %rcx
	jae	.Lbulk

.Lbulk_blocks:
	/* 16..31: two qwords in one go, leaving at most 15. */
	cmp	$16, %rcx
	jb	.Leight
	crc32q	(%rdi), %rax
	crc32q	8(%rdi), %rax
	add	$16, %rdi
	sub	$16, %rcx
.Leight:
	/* 8..15: one qword, leaving at most 7 (the scalar tail covers it). */
	cmp	$8, %rcx
	jb	.Ltail
	crc32q	(%rdi), %rax
	add	$8, %rdi
	sub	$8, %rcx

.Ltail:
	cmp	$4, %rcx
	jb	.Ltwo
	crc32l	(%rdi), %eax
	add	$4, %rdi
	sub	$4, %rcx
.Ltwo:
	cmp	$2, %rcx
	jb	.Lone
	crc32w	(%rdi), %eax
	add	$2, %rdi
	sub	$2, %rcx
.Lone:
	test	%ecx, %ecx
	jz	.Ldone
	crc32b	(%rdi), %eax
.Ldone:
	SENTINEL_RET
SYM_FUNC_END(sentinel_crc32c_seed)