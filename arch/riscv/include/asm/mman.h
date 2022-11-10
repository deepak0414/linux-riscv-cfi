/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MMAN_H__
#define __ASM_MMAN_H__

#include <linux/compiler.h>
#include <linux/types.h>
#include <uapi/asm/mman.h>

static inline unsigned long arch_calc_vm_prot_bits(unsigned long prot,
	unsigned long pkey __always_unused)
{
	unsigned long ret = 0;

        ret = (prot & PROT_SHADOWSTACK)?VM_WRITE:0;

	return ret;
}
#define arch_calc_vm_prot_bits(prot, pkey) arch_calc_vm_prot_bits(prot, pkey)

#endif /* ! __ASM_MMAN_H__ */