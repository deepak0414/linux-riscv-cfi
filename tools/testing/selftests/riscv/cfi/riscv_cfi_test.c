// SPDX-License-Identifier: GPL-2.0-only

#include "../../kselftest.h"
#include <signal.h>
#include <asm/ucontext.h>
#include <linux/prctl.h>
#include "cfi_rv_test.h"

/* do not optimize cfi related test functions */
#pragma GCC push_options
#pragma GCC optimize("O0")

#define SEGV_CPERR 10 /* control protection fault */

void sigsegv_handler(int signum, siginfo_t *si, void *uc)
{
	struct ucontext *ctx = (struct ucontext *) uc;

	if (si->si_code == SEGV_CPERR) {
		printf("Control flow violation happened somewhere\n");
		printf("pc where violation happened %lx\n", ctx->uc_mcontext.gregs[0]);
		exit(-1);
	}

	/* null pointer deref */
	if (si->si_addr == BAD_POINTER)
		exit(CHILD_EXIT_CODE_NULL_PTR_DEREF);

	/* shadow stack write case */
	exit(CHILD_EXIT_CODE_SSWRITE);
}

int lpad_enable(void)
{
	int ret = 0;

	ret = my_syscall5(__NR_prctl, PR_SET_INDIR_BR_LP_STATUS, PR_INDIR_BR_LP_ENABLE, 0, 0, 0);

	return ret;
}

bool register_signal_handler(void)
{
	struct sigaction sa = {};

	sa.sa_sigaction = sigsegv_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL)) {
		printf("registering signal handler for landing pad violation failed\n");
		return false;
	}

	return true;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	unsigned long lpad_status = 0;

	ksft_print_header();

	ksft_set_plan(RISCV_CFI_SELFTEST_COUNT);

	ksft_print_msg("starting risc-v tests\n");

	/*
	 * Landing pad test. Not a lot of kernel changes to support landing
	 * pad for user mode except lighting up a bit in senvcfg via a prctl
	 * Enable landing pad through out the execution of test binary
	 */
	ret = my_syscall5(__NR_prctl, PR_GET_INDIR_BR_LP_STATUS, &lpad_status, 0, 0, 0);
	if (ret)
		ksft_exit_skip("Get landing pad status failed with %d\n", ret);

	ret = lpad_enable();

	if (ret)
		ksft_exit_skip("Enabling landing pad failed with %d\n", ret);

	if (!register_signal_handler())
		ksft_exit_skip("registering signal handler for SIGSEGV failed\n");

	ksft_print_msg("landing pad enabled for binary\n");
	ksft_print_msg("starting risc-v shadow stack tests\n");
	execute_shadow_stack_tests();

	ksft_finished();
}

#pragma GCC pop_options
