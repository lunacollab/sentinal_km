// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/x86_64/sentinel_capture_store.S -- single-pass capture store.
 *
 * Moves the populated prefix of a capture (the fixed header plus however
 * many payload bytes the hook actually wrote) into a ring slot and zeroes
 * the remainder. The ring's old `= *cap` copied the whole 4141-byte object
 * including its near-constant zero tail; storing only the populated prefix
 * and zero-filling the rest keeps the write traffic proportional to the
 * event, not to the object size.
 *
 * The caller is required to pass n_filled <= SENTINEL_CAPTURE_BYTES. It is
 * not checked here on purpose: a clamp could silently truncate a capture the
 * caller believes it stored, hiding a real bug instead of failing the module
 * at init, where the differential selftest (kernel/ipc/sentinel_capture.c)
 * would catch the mismatch with the C reference. Writing beyond the object is
 * impossible because the zero count is the fixed difference to
 * SENTINEL_CAPTURE_BYTES, never negative.
 *
 * Form: for an arbitrary-length, arbitrary-aligned hot object the CPU's
 * fast-string path (ERMS/FSRM rep movsb / rep stosb) is both correct for
 * every alignment and competitive with a hand-unrolled SSE loop, so we take
 * it: two short instructions with no alignment bookkeeping to get wrong.
 *
 * Called with preemption disabled from the kprobe ret path; it never touches
 * user memory, carries no exception table, and does not recurse into the
 * module's own probes.
 */
#ifdef __KERNEL__
#include <linux/linkage.h>
#endif

#if defined(CONFIG_MITIGATION_RETHUNK) || defined(CONFIG_RETHUNK)
#define SENTINEL_RET	jmp __x86_return_thunk
#else
#define SENTINEL_RET	ret
#endif

/* Must match SENTINEL_CAPTURE_BYTES in kernel/ipc/sentinel_genl.h. The
 * static_assert there pins the C side; this asm pins the constant itself. */
#define SENTINEL_CAPTURE_BYTES	4141

SYM_FUNC_START(sentinel_capture_store)
	mov	%rdi, %r8		/* preserve dst; r8 is caller-saved */
	mov	%rdx, %rcx		/* n_filled bytes to move */

	rep	movsb			/* copy the populated prefix */

	mov	$SENTINEL_CAPTURE_BYTES, %rax
	sub	%rdx, %rax		/* bytes left to zero */
	mov	%rax, %rcx
	xor	%eax, %eax
	rep	stosb			/* zero the tail of the slot */

	mov	%r8, %rax		/* return the original dst */
	SENTINEL_RET
SYM_FUNC_END(sentinel_capture_store)
