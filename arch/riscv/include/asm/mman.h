/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MMAN_H__
#define __ASM_MMAN_H__

#include <linux/compiler.h>
#include <linux/types.h>
#include <uapi/asm/mman.h>

/*
 * Major architectures (x86, aarch64, riscv) have shadow stack now. x86 and
 * arm64 choose to use VM_SHADOW_STACK (which actually is VM_HIGH_ARCH_5) vma
 * flag, however that restrict it to 64bit implementation only. risc-v shadow
 * stack encodings in page tables is PTE.R=0, PTE.W=1, PTE.D=1 which used to be
 * reserved until now. risc-v is choosing to encode presence of only VM_WRITE in
 * vma flags as shadow stack vma. However this means that existing users of mmap
 * (and do_mmap) who were relying on passing only PROT_WRITE (or VM_WRITE from
 * kernel driver) but still getting read and write mappings, should still work.
 * x86 and arm64 followed the direction of a new system call `map_shadow_stack`.
 * risc-v would like to converge on that so that shadow stacks flows are as much
 * arch agnostic. Thus a conscious decision to define PROT_XXX definition for
 * shadow stack here (and not exposed to uapi)
 */
#define PROT_SHADOWSTACK	0x40

static inline unsigned long arch_calc_vm_prot_bits(unsigned long prot,
	unsigned long pkey __always_unused)
{
	unsigned long ret = 0;

	if (cpu_supports_shadow_stack())
		ret = (prot & PROT_SHADOWSTACK) ? (VM_SHADOW_STACK | VM_WRITE) : 0;
	/*
	 * If PROT_WRITE was specified, force it to VM_READ | VM_WRITE.
	 * Only VM_WRITE means shadow stack.
	 */
	if (prot & PROT_WRITE)
		ret = (VM_READ | VM_WRITE);
	return ret;
}
#define arch_calc_vm_prot_bits(prot, pkey) arch_calc_vm_prot_bits(prot, pkey)

#endif /* ! __ASM_MMAN_H__ */
