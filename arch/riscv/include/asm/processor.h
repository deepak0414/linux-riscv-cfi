/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PROCESSOR_H
#define _ASM_RISCV_PROCESSOR_H

#include <linux/const.h>

#include <vdso/processor.h>

#include <asm/ptrace.h>

/*
 * This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	PAGE_ALIGN(TASK_SIZE / 3)

#define STACK_TOP		TASK_SIZE
#ifdef CONFIG_64BIT
#define STACK_TOP_MAX		TASK_SIZE_64
#else
#define STACK_TOP_MAX		TASK_SIZE
#endif
#define STACK_ALIGN		16

#ifndef __ASSEMBLY__

struct task_struct;
struct pt_regs;

/* CPU-specific state of a task */
struct thread_struct {
	/* Callee-saved registers */
	unsigned long ra;
	unsigned long sp;	/* Kernel mode stack */
	unsigned long s[12];	/* s[0]: frame pointer */
	struct __riscv_d_ext_state fstate;
	unsigned long bad_cause;
};

#ifdef CONFIG_RISCV_CFI

#define FCFI_LOWER_LABEL_SIZE 9
#define FCFI_MID_LABEL_SIZE   8
#define FCFI_UP_LABEL_SIZE    8

#define FCFI_LABEL_SIZE (FCFI_LOWER_LABEL_SIZE + FCFI_MID_LABEL_SIZE + FCFI_UP_LABEL_SIZE)
struct cfi_status {
	unsigned long rsvd1 : 4;
	unsigned long fcfi_en : 1;
	unsigned long bcfi_en : 1;
#ifdef CONFIG_RISCV_M_MODE
	unsigned long elp : 1;
	unsigned long elp_s : 1;
#else
	unsigned long elp_m : 1;
	unsigned long elp : 1;
#endif

	unsigned long rsvd2 : 24;
	unsigned long lp_label : FCFI_LABEL_SIZE;
	unsigned long rsvd3 : ((sizeof(unsigned long)*8) - 32 - FCFI_LABEL_SIZE);
};
#endif
/* Whitelist the fstate from the task_struct for hardened usercopy */
static inline void arch_thread_struct_whitelist(unsigned long *offset,
						unsigned long *size)
{
	*offset = offsetof(struct thread_struct, fstate);
	*size = sizeof_field(struct thread_struct, fstate);
}

#define INIT_THREAD {					\
	.sp = sizeof(init_stack) + (long)&init_stack,	\
}

#define task_pt_regs(tsk)						\
	((struct pt_regs *)(task_stack_page(tsk) + THREAD_SIZE		\
			    - ALIGN(sizeof(struct pt_regs), STACK_ALIGN)))

#define KSTK_EIP(tsk)		(task_pt_regs(tsk)->epc)
#define KSTK_ESP(tsk)		(task_pt_regs(tsk)->sp)


/* Do necessary setup to start up a newly executed thread. */
extern void start_thread(struct pt_regs *regs,
			unsigned long pc, unsigned long sp);

extern unsigned long __get_wchan(struct task_struct *p);


static inline void wait_for_interrupt(void)
{
	__asm__ __volatile__ ("wfi");
}

struct device_node;
int riscv_of_processor_hartid(struct device_node *node, unsigned long *hartid);
int riscv_of_parent_hartid(struct device_node *node, unsigned long *hartid);

extern void riscv_fill_hwcap(void);
extern int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src);
static inline bool arch_supports_shadow_stack(void)
{
	return __riscv_isa_extension_available(NULL, RISCV_ISA_EXT_ZCFI);
}

static inline bool arch_supports_cfi(void)
{
	return __riscv_isa_extension_available(NULL, RISCV_ISA_EXT_ZCFI);
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_PROCESSOR_H */
