/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2017 SiFive, Inc.
 *
 * This file was copied from arch/arm64/include/uapi/asm/ucontext.h
 */
#ifndef _UAPI_ASM_RISCV_UCONTEXT_H
#define _UAPI_ASM_RISCV_UCONTEXT_H

#include <linux/types.h>

struct ucontext {
	unsigned long	  uc_flags;
	struct ucontext	 *uc_link;
	stack_t		  uc_stack;
	sigset_t	  uc_sigmask;
	/* There's some padding here to allow sigset_t to be expanded in the
	 * future.  Though this is unlikely, other architectures put uc_sigmask
	 * at the end of this structure and explicitly state it can be
	 * expanded, so we didn't want to box ourselves in here. */
	__u8		  __unused[1024 / 8 - sizeof(sigset_t)
#ifdef CONFIG_USER_SHADOW_STACK
				   - sizeof(unsigned long)
#endif
				  ];
	/*
	 * Zisslpcfi will need state in ucontext to save and restore across
	 * makecontext/setcontext. Such one state is shadow stack pointer. We may need
	 * to save label (of the target function) as well (but that's to be decided).
	 * Stealing 8 (64bit) / 4 (32bit) bytes from padding (__unused) reserved
	 * for expanding sigset_t. We could've expanded the size of ucontext. But
	 * shadow stack is something which by default would be enabled via ELF.
	 * ucontext expansion makes more sense for situations like vector where
	 * app is willingly opting in to get special functionality. Opt-in allows
	 * for enlightening in ucontext restore. Second reason is shadow stack
	 * doesn't need a lot of state and only shadow stack pointer. Tax on
	 * ecosystem due to a small size change (8 bytes) of ucontext is more than
	 * simply keeping the size same and shoving the ss pointer in here. Please
	 * note that shadow stack pointer is pointing to a shadow stack address.
	 * Shadow stack address has shadow stack restore token using which shadow
	 * stack should be restored.
	 * Please note that we're keeping uc_ss_ptr at that this location so that
	 * every other offsets are same and thus works for compatibility.
	 */
#ifdef CONFIG_USER_SHADOW_STACK
	unsigned long uc_ss_ptr;
#endif
	/* We can't put uc_sigmask at the end of this structure because we need
	 * to be able to expand sigcontext in the future.  For example, the
	 * vector ISA extension will almost certainly add ISA state.  We want
	 * to ensure all user-visible ISA state can be saved and restored via a
	 * ucontext, so we're putting this at the end in order to allow for
	 * infinite extensibility.  Since we know this will be extended and we
	 * assume sigset_t won't be extended an extreme amount, we're
	 * prioritizing this. */
	struct sigcontext uc_mcontext;
};

#endif /* _UAPI_ASM_RISCV_UCONTEXT_H */
