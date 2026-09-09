// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/x86_64/sentinel_fixup_probe.S -- research artifact, NOT built into
 * the module (no Kbuild reference). It captures, in source form, the reason
 * sentinel_memchr_zero.S carries no exception table.
 *
 * This is the canonical arch/x86 fixup idiom (_ASM_EXTABLE): the faulting
 * instruction in .text and its handler in .fixup, the table entry encoding
 * the two 32-bit relative offsets. It assembles *in-tree* on every supported
 * kernel, but not as an out-of-tree module object on the 6.x/7.x
 * CONFIG_STACK_VALIDATION toolchain:
 *
 *   - gas cannot compute ".long 2f - 1f" with 1f in .text and 2f in .fixup
 *     ("Error: can't resolve .fixup - .Linsn"), so the cross-section form
 *     fails outright;
 *   - pulling the fixup into .text makes gas fold the difference to a
 *     constant, and objtool then rejects the entry because it carries no
 *     relocation ("objtool: __ex_table+0x4: can't find new reloc").
 *
 * `make -C kernel probe-fixup` (from kernel/) reassembles this snippet
 * against the current toolchain and prints PASS/FAIL as build-matrix
 * evidence. sentinel_memchr_zero.S sidesteps the whole class by never
 * touching user memory, which removes the need for fixups entirely.
 */
.text
.globl sentinel_fixup_probe
.type sentinel_fixup_probe, @function
sentinel_fixup_probe:
	mov	$0x0, %eax
1:	mov	(%rdi), %eax		/* would fault on an unmapped page */
	ret
.pushsection .fixup, "ax"
2:	mov	$-1, %eax		/* sentinel error code */
	ret
.popsection
.pushsection __ex_table, "a"
	.align 8
	.long 1b - ., 2b - 1b		/* gas/objtool barrier, see above */
.popsection
.size sentinel_fixup_probe, .-sentinel_fixup_probe