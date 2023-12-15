// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Rivos, Inc.
 * Deepak Gupta <debug@rivosinc.com>
 */

#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/uaccess.h>
#include <linux/sizes.h>
#include <linux/user.h>
#include <linux/syscalls.h>
#include <linux/prctl.h>
#include <asm/csr.h>
#include <asm/usercfi.h>

#define SHSTK_ENTRY_SIZE sizeof(void *)

/*
 * TODO: Writes on shadow stack can either be `sspush` or `ssamoswap`. `sspush` can happen
 * implicitly on current shadow stack pointed to by CSR_SSP. `ssamoswap` takes pointer to
 * shadow stack. We plan to use `ssamoswap` to perform writes on shadow stack.
 * Figure out best way to implement ssamoswap. ssamoswap is another variant of amoswap using
 * existing atomic xchg primitives. As of now we don't perform write. User mode can do it.
 */
static inline int write_user_shstk(unsigned long *addr, unsigned long val)
{
	return 0;
}

/*
 * Create a restore token on the shadow stack.  A token is always XLEN wide
 * and aligned to XLEN.
 */
static int create_rstor_token(unsigned long ssp, unsigned long *token_addr)
{
	unsigned long addr;

	/* Token must be aligned */
	if (!IS_ALIGNED(ssp, SHSTK_ENTRY_SIZE))
		return -EINVAL;

	/* On RISC-V we're constructing token to be function of address itself */
	addr = ssp - SHSTK_ENTRY_SIZE;

	if (write_user_shstk((unsigned long __user *)addr, (unsigned long) ssp))
		return -EFAULT;

	if (token_addr)
		*token_addr = addr;

	return 0;
}

static unsigned long allocate_shadow_stack(unsigned long addr, unsigned long size,
				unsigned long token_offset,
				bool set_tok)
{
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	struct mm_struct *mm = current->mm;
	unsigned long addr, populate, size;

	if (addr)
		flags |= MAP_FIXED_NOREPLACE;

	mmap_write_lock(mm);
	addr = do_mmap(NULL, addr, size, PROT_SHADOWSTACK, flags,
				VM_SHADOW_STACK, 0, &populate, NULL);
	mmap_write_unlock(mm);

	if (!set_tok || IS_ERR_VALUE(addr))
		goto out;

	if (create_rstor_token(addr + token_offset, NULL)) {
		vm_munmap(addr, size);
		return -EINVAL;
	}

out:
	return addr;
}

SYSCALL_DEFINE3(map_shadow_stack, unsigned long, addr, unsigned long, size, unsigned int, flags)
{
	bool set_tok = flags & SHADOW_STACK_SET_TOKEN;
	unsigned long aligned_size = 0;

	if (!cpu_supports_shadow_stack())
		return -EOPNOTSUPP;

	/* Anything other than set token should result in invalid param */
	if (flags & ~SHADOW_STACK_SET_TOKEN)
		return -EINVAL;

	/*
	 * Unlike other architectures, on RISC-V, SSP pointer is held in CSR_SSP and is available
	 * CSR in all modes. CSR accesses are performed using 12bit index programmed in instruction
	 * itself. This provides static property on register programming and writes to CSR can't
	 * be unintentional from programmer's perspective. As long as programmer has guarded areas
	 * which perform writes to CSR_SSP properly, shadow stack pivoting is not possible. Since
	 * CSR_SSP is writeable by user mode, it itself can setup a shadow stack token subsequent
	 * to allocation. Although in order to provide portablity with other architecture (because
	 * `map_shadow_stack` is arch agnostic syscall), RISC-V will follow expectation of a token
	 * flag in flags and if provided in flags, setup a token at the base.
	 */

	/* If there isn't space for a token */
	if (set_tok && size < SHSTK_ENTRY_SIZE)
		return -ENOSPC;

	if (addr && (addr % PAGE_SIZE))
		return -EINVAL;

	aligned_size = PAGE_ALIGN(size);
	if (aligned_size < size)
		return -EOVERFLOW;

	return allocate_shadow_stack(addr, aligned_size, size, set_tok);
}
