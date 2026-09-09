// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/x86_64/sentinel_memchr_zero.S -- SSE2 NUL scan over kernel memory.
 *
 * Returns the byte offset of the first zero byte in buf[0..n), or n when no
 * zero byte is present. Callers feed it buffers already copied with
 * copy_from_user_nofault(), so the scan itself is fault-free by construction:
 * every vector load is taken only while at least 16 bytes remain in the
 * window, and the scalar tail walks byte by byte, so no load ever crosses
 * buf[n-1]. There is deliberately no __ex_table and no .fixup section -- see
 * docs/KERNEL_COMPAT.md for why an exception table version cannot ship as an
 * out-of-tree module on the 6.x/7.x CONFIG_STACK_VALIDATION toolchains.
 *
 * Layout of the scan:
 *   - a scalar prologue walks up to 15 bytes to bring %rdi to 16-byte
 *     alignment, which lets the body use movdqa (never movdqu);
 *   - the body unrolls two 16-byte loads per iteration to amortise the
 *     per-iteration branch, dropping to a single block (and then a byte
 *     tail) as the remaining count shrinks;
 *   - the scalar tail scans the final <16 bytes one at a time.
 *
 * Non-x86_64 builds exclude this object via kernel/Kbuild and hook_copy.c
 * falls back to a byte loop. The __KERNEL__ guard keeps the kernel's
 * linkage.h out of the userspace test harness (tests/unit), which supplies
 * SYM_* through -include so the exact instructions are also exercised in
 * userland against guard pages.
 */
#ifdef __KERNEL__
#include <linux/linkage.h>
#endif

#if defined(CONFIG_MITIGATION_RETHUNK) || defined(CONFIG_RETHUNK)
#define SENTINEL_RET	jmp __x86_return_thunk
#else
#define SENTINEL_RET	ret
#endif

SYM_FUNC_START(sentinel_memchr_zero)
	mov	%rsi, %rcx		/* remaining = n */
	xor	%edx, %edx		/* scanned = 0 */
	test	%rcx, %rcx
	jz	.Lnozero

	pxor	%xmm0, %xmm0		/* comparison vector: all zero */

	/*
	 * Alignment prologue. Bufs are arbitrary user copies, so skip to the
	 * first 16-byte boundary up to min(skip, n) bytes. After this either
	 * the vector body runs on an aligned pointer or the remaining count
	 * has dropped below a block and we head to the scalar tail.
	 */
	mov	%rdi, %rax
	neg	%rax
	and	$15, %rax		/* 16-align(rdi) - rdi, in 0..15 */
	cmp	%rax, %rcx
	cmovb	%rcx, %rax		/* never skip more than n */
.Lalign:
	test	%rax, %rax
	jz	.Lmain
	cmpb	$0, (%rdi)
	je	.Lfound_scalar		/* old %rdx still holds scanned */
	inc	%rdi
	inc	%rdx
	dec	%rax
	dec	%rcx			/* remaining shrinks in lockstep */
	jmp	.Lalign

.Lmain:
	/* Two 16-byte blocks per trip while at least 32 bytes remain. */
	cmp	$32, %rcx
	jb	.Ltail
	movdqa	(%rdi), %xmm1
	pcmpeqb	%xmm0, %xmm1
	pmovmskb %xmm1, %eax
	test	%eax, %eax
	jnz	.Lfound0
	movdqa	16(%rdi), %xmm1
	pcmpeqb	%xmm0, %xmm1
	pmovmskb %xmm1, %eax
	test	%eax, %eax
	jnz	.Lfound1
	add	$32, %rdx
	add	$32, %rdi
	sub	$32, %rcx
	jmp	.Lmain

.Ltail:
	/* One 16-byte block while at least 16 remain. */
	cmp	$16, %rcx
	jb	.Ltail_bytes
	movdqa	(%rdi), %xmm1
	pcmpeqb	%xmm0, %xmm1
	pmovmskb %xmm1, %eax
	test	%eax, %eax
	jnz	.Lfound0
	add	$16, %rdx
	add	$16, %rdi
	sub	$16, %rcx

.Ltail_bytes:
	test	%rcx, %rcx
	jz	.Lnozero
	cmpb	$0, (%rdi)
	je	.Lfound_scalar
	inc	%rdi
	inc	%rdx
	dec	%rcx
	jmp	.Ltail_bytes

.Lfound_scalar:
	mov	%edx, %eax
	SENTINEL_RET
.Lfound0:
	bsf	%eax, %eax		/* first NUL within the first block */
	add	%edx, %eax
	SENTINEL_RET
.Lfound1:
	bsf	%eax, %eax
	add	$16, %eax
	add	%edx, %eax
	SENTINEL_RET
.Lnozero:
	mov	%rsi, %rax		/* no NUL within n */
	SENTINEL_RET
SYM_FUNC_END(sentinel_memchr_zero)
