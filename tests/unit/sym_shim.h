/*
 * sym_shim.h -- SYM_* macros for compiling kernel arch asm in the userspace
 * test harness. Excluded by #ifdef __KERNEL__ from the kernel build; the
 * daemon test Makefile passes -include tests/unit/sym_shim.h.
 */
#ifndef _SYM_SHIM_H
#define _SYM_SHIM_H

#define SYM_FUNC_START(name)				\
	.text;						\
	.globl name;					\
	.type name, @function;				\
	name:

#define SYM_FUNC_END(name)	.size name, .-name

#endif /* _SYM_SHIM_H */
