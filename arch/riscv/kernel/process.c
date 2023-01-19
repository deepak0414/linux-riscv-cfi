// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Chen Liqin <liqin.chen@sunplusct.com>
 *  Lennox Wu <lennox.wu@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/tick.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>

#include <asm/unistd.h>
#include <asm/processor.h>
#include <asm/csr.h>
#include <asm/stacktrace.h>
#include <asm/string.h>
#include <asm/switch_to.h>
#include <asm/thread_info.h>
#include <asm/cpuidle.h>
#include <linux/mman.h>

register unsigned long gp_in_global __asm__("gp");

#if defined(CONFIG_STACKPROTECTOR) && !defined(CONFIG_STACKPROTECTOR_PER_TASK)
#include <linux/stackprotector.h>
unsigned long __stack_chk_guard __read_mostly;
EXPORT_SYMBOL(__stack_chk_guard);
#endif

extern asmlinkage void ret_from_fork(void);
extern asmlinkage void ret_from_kernel_thread(void);

void arch_cpu_idle(void)
{
	cpu_do_idle();
	raw_local_irq_enable();
}

void __show_regs(struct pt_regs *regs)
{
	show_regs_print_info(KERN_DEFAULT);

	if (!user_mode(regs)) {
		pr_cont("epc : %pS\n", (void *)regs->epc);
		pr_cont(" ra : %pS\n", (void *)regs->ra);
	}

	pr_cont("epc : " REG_FMT " ra : " REG_FMT " sp : " REG_FMT "\n",
		regs->epc, regs->ra, regs->sp);
	pr_cont(" gp : " REG_FMT " tp : " REG_FMT " t0 : " REG_FMT "\n",
		regs->gp, regs->tp, regs->t0);
	pr_cont(" t1 : " REG_FMT " t2 : " REG_FMT " s0 : " REG_FMT "\n",
		regs->t1, regs->t2, regs->s0);
	pr_cont(" s1 : " REG_FMT " a0 : " REG_FMT " a1 : " REG_FMT "\n",
		regs->s1, regs->a0, regs->a1);
	pr_cont(" a2 : " REG_FMT " a3 : " REG_FMT " a4 : " REG_FMT "\n",
		regs->a2, regs->a3, regs->a4);
	pr_cont(" a5 : " REG_FMT " a6 : " REG_FMT " a7 : " REG_FMT "\n",
		regs->a5, regs->a6, regs->a7);
	pr_cont(" s2 : " REG_FMT " s3 : " REG_FMT " s4 : " REG_FMT "\n",
		regs->s2, regs->s3, regs->s4);
	pr_cont(" s5 : " REG_FMT " s6 : " REG_FMT " s7 : " REG_FMT "\n",
		regs->s5, regs->s6, regs->s7);
	pr_cont(" s8 : " REG_FMT " s9 : " REG_FMT " s10: " REG_FMT "\n",
		regs->s8, regs->s9, regs->s10);
	pr_cont(" s11: " REG_FMT " t3 : " REG_FMT " t4 : " REG_FMT "\n",
		regs->s11, regs->t3, regs->t4);
	pr_cont(" t5 : " REG_FMT " t6 : " REG_FMT "\n",
		regs->t5, regs->t6);

	pr_cont("status: " REG_FMT " badaddr: " REG_FMT " cause: " REG_FMT "\n",
		regs->status, regs->badaddr, regs->cause);
}
void show_regs(struct pt_regs *regs)
{
	__show_regs(regs);
	if (!user_mode(regs))
		dump_backtrace(regs, NULL, KERN_DEFAULT);
}

#ifdef CONFIG_COMPAT
static bool compat_mode_supported __read_mostly;

bool compat_elf_check_arch(Elf32_Ehdr *hdr)
{
	return compat_mode_supported &&
	       hdr->e_machine == EM_RISCV &&
	       hdr->e_ident[EI_CLASS] == ELFCLASS32;
}

static int __init compat_mode_detect(void)
{
	unsigned long tmp = csr_read(CSR_STATUS);

	csr_write(CSR_STATUS, (tmp & ~SR_UXL) | SR_UXL_32);
	compat_mode_supported =
			(csr_read(CSR_STATUS) & SR_UXL) == SR_UXL_32;

	csr_write(CSR_STATUS, tmp);

	pr_info("riscv: ELF compat mode %s",
			compat_mode_supported ? "supported" : "unsupported");

	return 0;
}
early_initcall(compat_mode_detect);
#endif

void start_thread(struct pt_regs *regs, unsigned long pc,
	unsigned long sp)
{
	regs->status = SR_PIE;
	if (has_fpu()) {
		regs->status |= SR_FS_INITIAL;
		/*
		 * Restore the initial value to the FP register
		 * before starting the user program.
		 */
		fstate_restore(current, regs);
	}
	regs->epc = pc;
	regs->sp = sp;

#ifdef CONFIG_64BIT
	regs->status &= ~SR_UXL;

	if (is_compat_task())
		regs->status |= SR_UXL_32;
	else
		regs->status |= SR_UXL_64;
#endif
#ifdef CONFIG_USER_SHADOW_STACK
	if (current_thread_info()->user_cfi_state.ufcfi_en)
		regs->status |= SR_UFCFIEN;
#endif
#ifdef CONFIG_USER_INDIRECT_BR_LP
	if (current_thread_info()->user_cfi_state.ubcfi_en)
		regs->status |= SR_UBCFIEN;
#endif
}

void flush_thread(void)
{
#ifdef CONFIG_FPU
	/*
	 * Reset FPU state and context
	 *	frm: round to nearest, ties to even (IEEE default)
	 *	fflags: accrued exceptions cleared
	 */
	fstate_off(current, task_pt_regs(current));
	memset(&current->thread.fstate, 0, sizeof(current->thread.fstate));
#endif
}

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	fstate_save(src, task_pt_regs(src));
	*dst = *src;
	return 0;
}

int copy_thread(struct task_struct *p, const struct kernel_clone_args *args)
{
	unsigned long clone_flags = args->flags;
	unsigned long usp = args->stack;
	unsigned long tls = args->tls;
	struct pt_regs *childregs = task_pt_regs(p);

	/* p->thread holds context to be restored by __switch_to() */
	if (unlikely(args->fn)) {
		/* Kernel thread */
		memset(childregs, 0, sizeof(struct pt_regs));
		childregs->gp = gp_in_global;
		/* Supervisor/Machine, irqs on: */
		childregs->status = SR_PP | SR_PIE;

		p->thread.ra = (unsigned long)ret_from_kernel_thread;
		p->thread.s[0] = (unsigned long)args->fn;
		p->thread.s[1] = (unsigned long)args->fn_arg;
	} else {
		*childregs = *(current_pt_regs());
		if (usp) /* User fork */
			childregs->sp = usp;
		if (clone_flags & CLONE_SETTLS)
			childregs->tp = tls;
		childregs->a0 = 0; /* Return value of fork() */
		p->thread.ra = (unsigned long)ret_from_fork;
	}
	p->thread.sp = (unsigned long)childregs; /* kernel sp */
	return 0;
}


int allocate_shadow_stack(unsigned long *shadow_stack_base, unsigned long *shdw_size)
{
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	struct mm_struct *mm = current->mm;
	unsigned long addr, populate, size;
	*shadow_stack = 0;

	if (!shdw_size)
		return -EINVAL;

	size = *shdw_size;

	/* If size is 0, then try to calculate yourself */
	if (size == 0)
		size = round_up(min_t(unsigned long long, rlimit(RLIMIT_STACK), SZ_4G), PAGE_SIZE);
	mmap_write_lock(mm);
	addr = do_mmap(NULL, 0, size, PROT_SHADOWSTACK, flags, 0,
		       &populate, NULL);
	mmap_write_unlock(mm);
	if (IS_ERR_VALUE(addr))
		return PTR_ERR((void *)addr);
	*shadow_stack_base = addr;
	*shdw_size = size;
	return 0;
}

#if defined(CONFIG_USER_SHADOW_STACK) || defined(CONFIG_USER_INDIRECT_BR_LP)
/* gets called from load_elf_binary(). This'll setup shadow stack and forward cfi enable */
int arch_elf_setup_cfi_state(const struct arch_elf_state *state)
{
	int ret = 0;
	unsigned long shadow_stack_base = 0;
	unsigned long shadow_stk_size = 0;
	struct thread_info *info = NULL;

	info = current_thread_info();
	/* setup back cfi state */
	/* setup cfi state only if implementation supports it */
	if (arch_supports_shadow_stack() && (state->flags & RISCV_ELF_BCFI)) {
		info->user_cfi_state.ubcfi_en = 1;
		ret = allocate_shadow_stack(&shadow_stack_base, &shadow_stk_size);
		if (ret)
			return ret;

		info->user_cfi_state.user_shdw_stk = (shadow_stack_base + shadow_stk_size);
		info->user_cfi_state.shdw_stk_base = shadow_stack_base;
		info->user_cfi_state.audit_mode = 1;
	}
	/* setup forward cfi state */
	if (arch_supports_indirect_br_lp_instr() && (state->flags & RISCV_ELF_FCFI)) {
		info->user_cfi_state.ufcfi_en = 1;
		info->user_cfi_state.lp_label = 0;
		info->user_cfi_state.audit_mode = 1;
	}

	return ret;
}
#endif

#ifdef CONFIG_USER_SHADOW_STACK
int arch_get_shadow_stack_status(struct task_struct *t, unsigned long __user *status)
{
	unsigned long bcfi_status = 0;
	struct thread_info *info = NULL;

	if (!arch_supports_shadow_stack())
		return -EINVAL;

	info = current_thread_info();
	bcfi_status |= info->user_cfi_state.ubcfi_locked ? (1UL << 0) : 0;
	bcfi_status |= info->user_cfi_state.ubcfi_en ? ((1UL << 1) |
		       (info->user_cfi_state.user_shdw_stk)) : 0;

	return copy_to_user(status, &bcfi_status, sizeof(bcfi_status)) ? -EFAULT : 0;
}

int arch_set_shadow_stack_status(struct task_struct *t, unsigned long __user *status)
{
	unsigned long bcfi_status = 0;
	struct thread_info *info = NULL;
	unsigned long shdw_stk = 0;

	if (!arch_supports_shadow_stack())
		return -EINVAL;

	info = current_thread_info();
	/* bcfi status is locked and further can't be modified by user */
	if (info->user_cfi_state.ubcfi_locked)
		return -EINVAL;

	if (copy_from_user(&bcfi_status, status, sizeof(bcfi_status)))
		return -EFAULT;
	/* clear two least significant bits. Always assume min 4 byte alignment */
	shdw_stk = (long) (bcfi_status & (~3));

	if (shdw_stk >= TASK_SIZE)
		return -EINVAL;

	info->user_cfi_state.ubcfi_en = (bcfi_status & (1UL << 1)) ? 1 : 0;
	info->user_cfi_state.ubcfi_locked = (bcfi_status & (1UL << 0)) ? 1 : 0;
	info->user_cfi_state.user_shdw_stk = (long) shdw_stk;

	return 0;
}
#endif

#ifdef CONFIG_USER_INDIRECT_BR_LP
int arch_get_indir_br_lp_status(struct task_struct *t, unsigned long __user *status)
{
	unsigned long fcfi_status = 0;
	struct thread_info *info = NULL;

	if (!arch_supports_indirect_br_lp_instr())
		return -EINVAL;

	info = current_thread_info();
	fcfi_status |= info->user_cfi_state.ufcfi_locked ? (1UL << 0) : 0;
	fcfi_status |= info->user_cfi_state.ufcfi_en ? (1UL << 1) : 0;

	return copy_to_user(status, &fcfi_status, sizeof(fcfi_status)) ? -EFAULT : 0;
}

int arch_set_indir_br_lp_status(struct task_struct *t, unsigned long __user *status)
{
	unsigned long fcfi_status = 0;
	struct thread_info *info = NULL;

	if (!arch_supports_indirect_br_lp_instr())
		return -EINVAL;

	info = current_thread_info();
	/* bcfi status is locked and further can't be modified by user */
	if (info->user_cfi_state.ufcfi_locked)
		return -EINVAL;

	if (copy_from_user(&fcfi_status, status, sizeof(fcfi_status)))
		return -EFAULT;

	info->user_cfi_state.ufcfi_en = (fcfi_status & (1UL << 1)) ? 1 : 0;
	info->user_cfi_state.ufcfi_locked = (fcfi_status & (1UL << 0)) ? 1 : 0;

	return 0;
}
#endif
