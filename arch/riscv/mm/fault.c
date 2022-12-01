// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Lennox Wu <lennox.wu@sunplusct.com>
 *  Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 */


#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/kfence.h>

#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#include "../kernel/head.h"

static void die_kernel_fault(const char *msg, unsigned long addr,
		struct pt_regs *regs)
{
	bust_spinlocks(1);

	pr_alert("Unable to handle kernel %s at virtual address " REG_FMT "\n", msg,
		addr);

	bust_spinlocks(0);
	die(regs, "Oops");
	make_task_dead(SIGKILL);
}

static inline void no_context(struct pt_regs *regs, unsigned long addr)
{
	const char *msg;

	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs))
		return;

	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice.
	 */
	if (addr < PAGE_SIZE)
		msg = "NULL pointer dereference";
	else {
		if (kfence_handle_page_fault(addr, regs->cause == EXC_STORE_PAGE_FAULT, regs))
			return;

		msg = "paging request";
	}

	die_kernel_fault(msg, addr, regs);
}

static inline void mm_fault_error(struct pt_regs *regs, unsigned long addr, vm_fault_t fault)
{
	if (fault & VM_FAULT_OOM) {
		/*
		 * We ran out of memory, call the OOM killer, and return the userspace
		 * (which will retry the fault, or kill us if we got oom-killed).
		 */
		if (!user_mode(regs)) {
			no_context(regs, addr);
			return;
		}
		pagefault_out_of_memory();
		return;
	} else if (fault & VM_FAULT_SIGBUS) {
		/* Kernel mode? Handle exceptions or die */
		if (!user_mode(regs)) {
			no_context(regs, addr);
			return;
		}
		do_trap(regs, SIGBUS, BUS_ADRERR, addr);
		return;
	}
	BUG();
}

static inline void bad_area(struct pt_regs *regs, struct mm_struct *mm, int code, unsigned long addr)
{
	/*
	 * Something tried to access memory that isn't in our memory map.
	 * Fix it, but check if it's kernel or user first.
	 */
	mmap_read_unlock(mm);
	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs)) {
		do_trap(regs, SIGSEGV, code, addr);
		return;
	}

	no_context(regs, addr);
}

static inline void vmalloc_fault(struct pt_regs *regs, int code, unsigned long addr)
{
	pgd_t *pgd, *pgd_k;
	pud_t *pud_k;
	p4d_t *p4d_k;
	pmd_t *pmd_k;
	pte_t *pte_k;
	int index;
	unsigned long pfn;

	/* User mode accesses just cause a SIGSEGV */
	if (user_mode(regs))
		return do_trap(regs, SIGSEGV, code, addr);

	/*
	 * Synchronize this task's top level page-table
	 * with the 'reference' page table.
	 *
	 * Do _not_ use "tsk->active_mm->pgd" here.
	 * We might be inside an interrupt in the middle
	 * of a task switch.
	 */
	index = pgd_index(addr);
	pfn = csr_read(CSR_SATP) & SATP_PPN;
	pgd = (pgd_t *)pfn_to_virt(pfn) + index;
	pgd_k = init_mm.pgd + index;

	if (!pgd_present(*pgd_k)) {
		no_context(regs, addr);
		return;
	}
	set_pgd(pgd, *pgd_k);

	p4d_k = p4d_offset(pgd_k, addr);
	if (!p4d_present(*p4d_k)) {
		no_context(regs, addr);
		return;
	}

	pud_k = pud_offset(p4d_k, addr);
	if (!pud_present(*pud_k)) {
		no_context(regs, addr);
		return;
	}

	/*
	 * Since the vmalloc area is global, it is unnecessary
	 * to copy individual PTEs
	 */
	pmd_k = pmd_offset(pud_k, addr);
	if (!pmd_present(*pmd_k)) {
		no_context(regs, addr);
		return;
	}

	/*
	 * Make sure the actual PTE exists as well to
	 * catch kernel vmalloc-area accesses to non-mapped
	 * addresses. If we don't do this, this will just
	 * silently loop forever.
	 */
	pte_k = pte_offset_kernel(pmd_k, addr);
	if (!pte_present(*pte_k)) {
		no_context(regs, addr);
		return;
	}

	/*
	 * The kernel assumes that TLBs don't cache invalid
	 * entries, but in RISC-V, SFENCE.VMA specifies an
	 * ordering constraint, not a cache flush; it is
	 * necessary even after writing invalid entries.
	 */
	local_flush_tlb_page(addr);
}

static inline bool access_error(unsigned long cause, struct vm_area_struct *vma)
{
	unsigned long prot = 0, shdw_stk_mask = 0;

	switch (cause) {
	case EXC_INST_PAGE_FAULT:
		if (!(vma->vm_flags & VM_EXEC)) {
			return true;
		}
		break;
	case EXC_LOAD_PAGE_FAULT:
		/* Write implies read */
		if (!(vma->vm_flags & (VM_READ | VM_WRITE))) {
			return true;
		}
		break;
	case EXC_STORE_PAGE_FAULT:
		if (!(vma->vm_flags & VM_WRITE)) {
			return true;
		}
		break;
		/*
		 * If a ss access page fault. vma must have only VM_WRITE.
		 * TODO: Should we've VM_READ too, technically page is readable.
		 * page prot should be 0b010.
		*/
	case EXC_SS_ACCESS_PAGE_FAULT:
		prot = pgprot_val(vma->vm_page_prot);
		shdw_stk_mask = pgprot_val(PAGE_SHADOWSTACK) | pgprot_val(PAGE_READ) | pgprot_val(PAGE_EXEC);
		if (((vma->vm_flags & (VM_WRITE | VM_READ | VM_EXEC)) != VM_WRITE) ||
		    ((prot & shdw_stk_mask) != shdw_stk_mask)) {
			return true;
		}
		break;
	default:
		panic("%s: unhandled cause %lu", __func__, cause);
	}
	return false;
}


unsigned int opcode_break = 0x81C04073;
char app_name_fault_info[] = "shadowstack";
int pid_fault_info = -1;
#define PRINT_LOAD_PF_INFO 1
#define PRINT_STORE_PF_INFO 2
#define PRINT_INSTR_PF_INFO 4
unsigned long pf_cause_filter = (PRINT_LOAD_PF_INFO | PRINT_STORE_PF_INFO);

void dump_fault_info(struct pt_regs *regs, struct vm_area_struct *vma, unsigned long cause)
{
	struct task_struct *tsk;
	int print_fault_info = 0, task_match = 0, pid_match = 0, cause_filter_match = 0;
	int insn = 0;
	int *epc_ptr = NULL;

	tsk = current;

	if (!memcmp(tsk->comm, app_name_fault_info, sizeof(app_name_fault_info))) {
		task_match = 1;
	}

	if ((pid_fault_info != -1) &&
	    (pid_fault_info == tsk->pid)) {
		pid_match = 1;
	}

	switch (cause) {
		case EXC_LOAD_PAGE_FAULT:
			cause_filter_match = (pf_cause_filter & PRINT_LOAD_PF_INFO)?1:0;
			break;
		case EXC_STORE_PAGE_FAULT:
			cause_filter_match = (pf_cause_filter & PRINT_STORE_PF_INFO)?1:0;
			break;
		case EXC_INST_PAGE_FAULT:
			cause_filter_match = (pf_cause_filter & PRINT_INSTR_PF_INFO)?1:0;
			break;
		default:
			cause_filter_match = 0;
			break;
	}
	print_fault_info = (cause_filter_match  & (pid_match | task_match));

	if (print_fault_info) {
		epc_ptr = (int *) regs->epc;
		insn = 0;
		__enable_user_access();
		insn = *epc_ptr;
		__disable_user_access();
		printk("page_fault: comm %s, pid %d, cause %ld, addr %lx, vma flags %lx, prot bits %lx\n", 
			tsk->comm, tsk->pid, cause, regs->badaddr, vma->vm_flags, vma->vm_page_prot.pgprot);
	}
}

/*
 * This routine handles page faults.  It determines the address and the
 * problem, and then passes it off to one of the appropriate routines.
 */
asmlinkage void do_page_fault(struct pt_regs *regs)
{
	struct task_struct *tsk;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	unsigned long addr, cause;
	unsigned int flags = FAULT_FLAG_DEFAULT;
	int insn;
	int code = SEGV_MAPERR;
	vm_fault_t fault;
	int *epc_ptr = NULL;

	cause = regs->cause;
	addr = regs->badaddr;

	tsk = current;
	mm = tsk->mm;

	if (kprobe_page_fault(regs, cause))
		return;

	/*
	 * Fault-in kernel-space virtual memory on-demand.
	 * The 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 */
	if (unlikely((addr >= VMALLOC_START) && (addr < VMALLOC_END))) {
		vmalloc_fault(regs, code, addr);
		return;
	}

#ifdef CONFIG_64BIT
	/*
	 * Modules in 64bit kernels lie in their own virtual region which is not
	 * in the vmalloc region, but dealing with page faults in this region
	 * or the vmalloc region amounts to doing the same thing: checking that
	 * the mapping exists in init_mm.pgd and updating user page table, so
	 * just use vmalloc_fault.
	 */
	if (unlikely(addr >= MODULES_VADDR && addr < MODULES_END)) {
		vmalloc_fault(regs, code, addr);
		return;
	}
#endif
	/* Enable interrupts if they were enabled in the parent context. */
	if (likely(regs->status & SR_PIE))
		local_irq_enable();

	/*
	 * If we're in an interrupt, have no user context, or are running
	 * in an atomic region, then we must not take the fault.
	 */
	if (unlikely(faulthandler_disabled() || !mm)) {
		tsk->thread.bad_cause = cause;
		no_context(regs, addr);
		return;
	}

	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;

	if (!user_mode(regs) && addr < TASK_SIZE &&
			unlikely(!(regs->status & SR_SUM)))
		die_kernel_fault("access to user memory without uaccess routines",
				addr, regs);

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);

	/*
	* TODO: Shall we assert that vm_page_prot should be 010 if
	* cause == EXC_SS_ACCESS_PAGE_FAULT. This'll ensure that
	* arbitrary sspush/sspop/ssamoswap don't on regular memory don't pass through from here
	*/
	if (cause == EXC_STORE_PAGE_FAULT
#ifdef CONFIG_RISCV_CFI
	    || cause == EXC_SS_ACCESS_PAGE_FAULT
#endif
	    )
		flags |= FAULT_FLAG_WRITE;
	else if (cause == EXC_INST_PAGE_FAULT)
		flags |= FAULT_FLAG_INSTRUCTION;
retry:
	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (unlikely(!vma)) {
		tsk->thread.bad_cause = cause;
		bad_area(regs, mm, code, addr);
		return;
	}

	dump_fault_info(regs, vma, cause);

	if (likely(vma->vm_start <= addr))
		goto good_area;
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		tsk->thread.bad_cause = cause;
		bad_area(regs, mm, code, addr);
		return;
	}
	if (unlikely(expand_stack(vma, addr))) {
		tsk->thread.bad_cause = cause;
		bad_area(regs, mm, code, addr);
		return;
	}

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it.
	 */
good_area:
	code = SEGV_ACCERR;

	if (unlikely(access_error(cause, vma))) {
		tsk->thread.bad_cause = cause;
		bad_area(regs, mm, code, addr);
		return;
	}

	/*
	 * If for any reason at all we could not handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	fault = handle_mm_fault(vma, addr, flags, regs);

	/*
	 * If we need to retry but a fatal signal is pending, handle the
	 * signal first. We do not need to release the mmap_lock because it
	 * would already be released in __lock_page_or_retry in mm/filemap.c.
	 */
	if (fault_signal_pending(fault, regs))
		return;

	/* The fault is fully completed (including releasing mmap lock) */
	if (fault & VM_FAULT_COMPLETED)
		return;

	if (unlikely(fault & VM_FAULT_RETRY)) {
		flags |= FAULT_FLAG_TRIED;

		/*
		 * No need to mmap_read_unlock(mm) as we would
		 * have already released it in __lock_page_or_retry
		 * in mm/filemap.c.
		 */
		goto retry;
	}

	mmap_read_unlock(mm);

	if (unlikely(fault & VM_FAULT_ERROR)) {
		tsk->thread.bad_cause = cause;
		mm_fault_error(regs, addr, fault);
		return;
	}
	return;
}
NOKPROBE_SYMBOL(do_page_fault);
