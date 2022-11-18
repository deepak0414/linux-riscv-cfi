// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/kdebug.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/kexec.h>

#include <asm/asm-prototypes.h>
#include <asm/bug.h>
#include <asm/csr.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>

int show_unhandled_signals = 1;

static DEFINE_SPINLOCK(die_lock);

void die(struct pt_regs *regs, const char *str)
{
	static int die_counter;
	int ret;
	long cause;

	oops_enter();

	spin_lock_irq(&die_lock);
	console_verbose();
	bust_spinlocks(1);

	pr_emerg("%s [#%d]\n", str, ++die_counter);
	print_modules();
	if (regs)
		show_regs(regs);

	cause = regs ? regs->cause : -1;
	ret = notify_die(DIE_OOPS, str, regs, 0, cause, SIGSEGV);

	if (kexec_should_crash(current))
		crash_kexec(regs);

	bust_spinlocks(0);
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irq(&die_lock);
	oops_exit();

	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");
	if (ret != NOTIFY_STOP)
		make_task_dead(SIGSEGV);
}

void do_trap(struct pt_regs *regs, int signo, int code, unsigned long addr)
{
	struct task_struct *tsk = current;

	if (show_unhandled_signals && unhandled_signal(tsk, signo)
	    && printk_ratelimit()) {
		pr_info("%s[%d]: unhandled signal %d code 0x%x at 0x" REG_FMT,
			tsk->comm, task_pid_nr(tsk), signo, code, addr);
		print_vma_addr(KERN_CONT " in ", instruction_pointer(regs));
		pr_cont("\n");
		__show_regs(regs);
	}

	force_sig_fault(signo, code, (void __user *)addr);
}

static void do_trap_error(struct pt_regs *regs, int signo, int code,
	unsigned long addr, const char *str)
{
	current->thread.bad_cause = regs->cause;

	if (user_mode(regs)) {
		do_trap(regs, signo, code, addr);
	} else {
		if (!fixup_exception(regs))
			die(regs, str);
	}
}

/* TODO/THINK: Should I move this to separate module considering this is CFI specific? */
#ifdef CONFIG_RISCV_CFI
#define SS_CHECKRA  0x8A12C073
#define SS_PUSH_POP 0x81C04073
#define SS_AMOSWAP  0x82004073

#define LP_C_LL     0x83004073
#define LP_C_ML     0x86804073
#define LP_C_UL     0x8B804073

bool is_ss_load_insn(unsigned long insn)
{
	if ((insn & SS_PUSH_POP) == SS_PUSH_POP)
		return true;
	/*
	* SS_AMOSWAP overlaps with LP_S_LL.
	* But LP_S_LL can never raise access fault
	*/
	if ((insn & SS_AMOSWAP) == SS_AMOSWAP)
		return true;

	return false;
}

bool is_ss_store_insn(unsigned long insn)
{
	if ((insn & SS_PUSH_POP) == SS_PUSH_POP)
		return true;
	/*
	* SS_AMOSWAP overlaps with LP_S_LL.
	* But LP_S_LL can never raise access fault
	*/
	if ((insn & SS_AMOSWAP) == SS_AMOSWAP)
		return true;

	return false;
}

bool is_cfi_violation_insn(unsigned long insn)
{
	struct task_struct *task = current;

	if (insn == SS_CHECKRA) {
		pr_warn("cfi violation (sschkra): comm = %s, task = %p\n", task->comm, task);
		return true;
	}
	if ((insn & LP_C_LL) == LP_C_LL) {
		pr_warn("cfi violation (lpcll): comm = %s, task = %p\n", task->comm, task);
		return true;
	}
	if ((insn & LP_C_ML) == LP_C_ML) {
		pr_warn("cfi violation (lpcml): comm = %s, task = %p\n", task->comm, task);
		return true;
	}
	if ((insn & LP_C_UL) == LP_C_UL) {
		pr_warn("cfi violation (lpcul): comm = %s, task = %p\n", task->comm, task);
		return true;
	}

	return false;
}

int handle_illegal_instruction(struct pt_regs *regs)
{
	/* stval should hold faulting opcode */
	unsigned long insn = csr_read(stval);
	struct thread_info *info = NULL;
	struct task_struct *task = current;

	if (arch_supports_cfi()) {
		info = current_thread_info();
		/* If fcfi enabled and  ELP = 1, suppress ELP (audit mode)  and resume */
		if (info->user_cfi_state.fcfi_en && info->user_cfi_state.elp) {
			pr_warn("cfi violation (elp): comm = %s, task = %p\n", task->comm, task);
			info->user_cfi_state.elp = 0;
			return 0;
		}
		/* if faulting opcode is sscheckra/lpcll/lpcml/lpcll, advance PC and resume */
		if (is_cfi_violation_insn(insn)) {
			regs->epc += 4;
			return 0;
		}
	}

	return 1;
}

ulong get_instruction(ulong epc)
{
	ulong *epc_ptr = (ulong *) epc;
	ulong insn = 0;
	__enable_user_access();
	insn = *epc_ptr;
	__disable_user_access();
	return insn;
}
extern asmlinkage void do_page_fault(struct pt_regs *regs);
/*
 * If CFI enabled then following then load access fault can occur if
 * -- ssload (sspop/ssamoswap) happens on non-shadow stack memory.
 *    This is a valid case when we want to do COW on SS memory on `fork`.
 *    SS memory is marked as readonly and subsequent sspop or sspush will lead to
 *    load/store access fault. We need to decode instruction. If it's sspop or sspush
 *    Page fault handler is invoked.
*/
int handle_load_access_fault(struct pt_regs *regs)
{
	ulong insn = get_instruction(regs->epc);

	if (is_ss_load_insn(insn)) {
		regs->cause = EXC_SS_ACCESS_PAGE_FAULT;
		do_page_fault(regs);
		return 0;
	}

	return 1;
}

/*
 * If CFI enabled then following then store access fault can occur if
 * -- ssstore (sspush/ssamoswap) happens on non-shadow stack memory
 * -- regular store happens on shadow stack memory
*/
int handle_store_access_fault(struct pt_regs *regs)
{
	ulong insn = get_instruction(regs->epc);

	/*
	* if a shadow stack store insn, change cause to
	* synthetic SS_ACCESS_PAGE_FAULT
	*/
	if (is_ss_store_insn(insn)) {
		regs->cause = EXC_SS_ACCESS_PAGE_FAULT;
		do_page_fault(regs);
		return 0;
	}

	/*
	* Reaching here means it was a regular store.
	* A regular access fault anyways had been delivering SIGSEV
	* A regular store to shadow stack anyways is also a SIGSEV
	*/

	return 1;
}
#endif

#if defined(CONFIG_XIP_KERNEL) && defined(CONFIG_RISCV_ALTERNATIVE)
#define __trap_section		__section(".xip.traps")
#else
#define __trap_section
#endif
#define DO_ERROR_INFO(name, signo, code, str)				\
asmlinkage __visible __trap_section void name(struct pt_regs *regs)	\
{									\
	do_trap_error(regs, signo, code, regs->epc, "Oops - " str);	\
}

DO_ERROR_INFO(do_trap_unknown,
	SIGILL, ILL_ILLTRP, "unknown exception");
DO_ERROR_INFO(do_trap_insn_misaligned,
	SIGBUS, BUS_ADRALN, "instruction address misaligned");
DO_ERROR_INFO(do_trap_insn_fault,
	SIGSEGV, SEGV_ACCERR, "instruction access fault");
#ifdef CONFIG_RISCV_CFI
/*
 * If CFI enabled then following instructions leads to illegal instruction fault
 * -- sscheckra: x1 and x5 mismatch
 * -- ELP = 1, Any instruction other than lpcll will fault
 * -- lpcll will fault if lower label don't match with LPLR.LL
 * -- lpcml will fault if lower label don't match with LPLR.ML
 * -- lpcul will fault if lower label don't match with LPLR.UL
*/
asmlinkage void __trap_section do_trap_insn_illegal(struct pt_regs *regs)
{
	if (!handle_illegal_instruction(regs))
		return;
	do_trap_error(regs, SIGILL, ILL_ILLOPC, regs->epc,
		      "illegal instruction");
}

asmlinkage void __trap_section do_trap_load_fault(struct pt_regs *regs)
{
	if (!handle_load_access_fault(regs))
		return;
	do_trap_error(regs, SIGSEGV, SEGV_ACCERR, regs->epc,
		      "load access fault");
}
#else
DO_ERROR_INFO(do_trap_insn_illegal,
	SIGILL, ILL_ILLOPC, "illegal instruction");
DO_ERROR_INFO(do_trap_load_fault,
	SIGSEGV, SEGV_ACCERR, "load access fault");
#endif
#ifndef CONFIG_RISCV_M_MODE
DO_ERROR_INFO(do_trap_load_misaligned,
	SIGBUS, BUS_ADRALN, "Oops - load address misaligned");
DO_ERROR_INFO(do_trap_store_misaligned,
	SIGBUS, BUS_ADRALN, "Oops - store (or AMO) address misaligned");
#else
int handle_misaligned_load(struct pt_regs *regs);
int handle_misaligned_store(struct pt_regs *regs);

asmlinkage void __trap_section do_trap_load_misaligned(struct pt_regs *regs)
{
	if (!handle_misaligned_load(regs))
		return;
	do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
		      "Oops - load address misaligned");
}

asmlinkage void __trap_section do_trap_store_misaligned(struct pt_regs *regs)
{
	if (!handle_misaligned_store(regs))
		return;
	do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
		      "Oops - store (or AMO) address misaligned");
}
#endif
#ifdef CONFIG_RISCV_CFI
asmlinkage void __trap_section do_trap_store_fault(struct pt_regs *regs)
{
	if (!handle_store_access_fault(regs))
		return;
	do_trap_error(regs, SIGSEGV, SEGV_ACCERR, regs->epc,
		      "store (or AMO) access fault");
}
#else
DO_ERROR_INFO(do_trap_store_fault,
	SIGSEGV, SEGV_ACCERR, "store (or AMO) access fault");
#endif
DO_ERROR_INFO(do_trap_ecall_u,
	SIGILL, ILL_ILLTRP, "environment call from U-mode");
DO_ERROR_INFO(do_trap_ecall_s,
	SIGILL, ILL_ILLTRP, "environment call from S-mode");
DO_ERROR_INFO(do_trap_ecall_m,
	SIGILL, ILL_ILLTRP, "environment call from M-mode");

static inline unsigned long get_break_insn_length(unsigned long pc)
{
	bug_insn_t insn;

	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;

	return GET_INSN_LENGTH(insn);
}

asmlinkage __visible __trap_section void do_trap_break(struct pt_regs *regs)
{
#ifdef CONFIG_KPROBES
	if (kprobe_single_step_handler(regs))
		return;

	if (kprobe_breakpoint_handler(regs))
		return;
#endif
#ifdef CONFIG_UPROBES
	if (uprobe_single_step_handler(regs))
		return;

	if (uprobe_breakpoint_handler(regs))
		return;
#endif
	current->thread.bad_cause = regs->cause;

	if (user_mode(regs))
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->epc);
#ifdef CONFIG_KGDB
	else if (notify_die(DIE_TRAP, "EBREAK", regs, 0, regs->cause, SIGTRAP)
								== NOTIFY_STOP)
		return;
#endif
	else if (report_bug(regs->epc, regs) == BUG_TRAP_TYPE_WARN)
		regs->epc += get_break_insn_length(regs->epc);
	else
		die(regs, "Kernel BUG");
}
NOKPROBE_SYMBOL(do_trap_break);

#ifdef CONFIG_GENERIC_BUG
int is_valid_bugaddr(unsigned long pc)
{
	bug_insn_t insn;

	if (pc < VMALLOC_START)
		return 0;
	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;
	if ((insn & __INSN_LENGTH_MASK) == __INSN_LENGTH_32)
		return (insn == __BUG_INSN_32);
	else
		return ((insn & __COMPRESSED_INSN_MASK) == __BUG_INSN_16);
}
#endif /* CONFIG_GENERIC_BUG */

#ifdef CONFIG_VMAP_STACK
static DEFINE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)],
		overflow_stack)__aligned(16);
/*
 * shadow stack, handled_ kernel_ stack_ overflow(in kernel/entry.S) is used
 * to get per-cpu overflow stack(get_overflow_stack).
 */
long shadow_stack[SHADOW_OVERFLOW_STACK_SIZE/sizeof(long)];
asmlinkage unsigned long get_overflow_stack(void)
{
	return (unsigned long)this_cpu_ptr(overflow_stack) +
		OVERFLOW_STACK_SIZE;
}

asmlinkage void handle_bad_stack(struct pt_regs *regs)
{
	unsigned long tsk_stk = (unsigned long)current->stack;
	unsigned long ovf_stk = (unsigned long)this_cpu_ptr(overflow_stack);

	console_verbose();

	pr_emerg("Insufficient stack space to handle exception!\n");
	pr_emerg("Task stack:     [0x%016lx..0x%016lx]\n",
			tsk_stk, tsk_stk + THREAD_SIZE);
	pr_emerg("Overflow stack: [0x%016lx..0x%016lx]\n",
			ovf_stk, ovf_stk + OVERFLOW_STACK_SIZE);

	__show_regs(regs);
	panic("Kernel stack overflow");

	for (;;)
		wait_for_interrupt();
}
#endif
