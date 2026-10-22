/*
 * rndr_intercept_test.c - Verify KVM UNDEF injection for monitored processes
 *                         on arm64 (RNDR/RNDRRS).
 *
 * Registers itself with rr_entropy_monitor, executes MRS Xn, RNDR and
 * MRS Xn, RNDRRS from EL0, and confirms each is intercepted as SIGILL
 * (from the KVM-injected UNDEF) rather than returning emulated entropy.
 * Pass-through (post-deregister) is verified separately: after deregister
 * the read should complete with NZCV.Z=0 and a value.
 *
 * The RNDR/RNDRRS sysreg trap reaches KVM via the EL3->EL2 forwarding path
 * (TF-A RNG_TRAP_FORWARD_TO_EL2); the per-process patch then injects UNDEF
 * when the current TTBR0_EL1 is registered, or emulates otherwise.
 *
 * Registers itself via /dev/rr-entropy-monitor (a process may always
 * register itself, so no elevated privilege is needed).
 *
 * Uses the Sn_n_Cm_Cm_n encoding form so no -march=armv8.5-a is needed.
 */
#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "rr_entropy_monitor.h"

static sigjmp_buf *current_escape;
static volatile int got_sigill;

static void sigill_handler(int sig)
{
	got_sigill++;
	if (current_escape)
		siglongjmp(*current_escape, 1);
	signal(SIGILL, SIG_DFL);
	raise(SIGILL);
}

/*
 * Execute one RNDR or RNDRRS read.  Returns 1 if intercepted (SIGILL),
 * 0 if it completed.  On completion, *ok holds NZCV.Z==0 (success) and
 * *val the returned value.
 */
static int test_insn(const char *name, int is_rndrrs, int expect_intercept,
		     uint64_t *val_out, int *ok_out)
{
	sigjmp_buf escape;
	uint64_t val = 0;
	uint32_t ok = 0;
	int intercepted;

	got_sigill = 0;
	current_escape = &escape;

	if (sigsetjmp(escape, 1) == 0) {
		if (is_rndrrs)
			asm volatile("mrs %0, S3_3_C2_C4_1\n\t"  /* RNDRRS */
				     "cset %w1, ne\n"
				     : "=r"(val), "=r"(ok) : : "cc");
		else
			asm volatile("mrs %0, S3_3_C2_C4_0\n\t"  /* RNDR */
				     "cset %w1, ne\n"
				     : "=r"(val), "=r"(ok) : : "cc");
		intercepted = 0;
	} else {
		intercepted = 1;
	}

	current_escape = NULL;
	if (val_out)
		*val_out = val;
	if (ok_out)
		*ok_out = (int)ok;

	if (intercepted)
		printf("  %-8s %s (intercepted -> SIGILL)\n",
		       name, expect_intercept ? "PASS" : "FAIL");
	else
		printf("  %-8s %s (completed: ok=%d val=0x%016llx)\n",
		       name, expect_intercept ? "FAIL" : "PASS",
		       (int)ok, (unsigned long long)val);

	return intercepted;
}

static int rrmon_ioctl(unsigned long cmd)
{
	int32_t pid = getpid();
	int fd, ret = 0;

	fd = open(RRMON_DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", RRMON_DEVICE_PATH,
			strerror(errno));
		return -1;
	}
	if (ioctl(fd, cmd, &pid) < 0) {
		fprintf(stderr, "ioctl %s: %s\n",
			cmd == RRMON_IOC_REGISTER ? "register" : "deregister",
			strerror(errno));
		ret = -1;
	}
	close(fd);
	return ret;
}

int main(void)
{
	struct sigaction sa = { .sa_handler = sigill_handler, .sa_flags = 0 };
	uint64_t v;
	int ok, fail = 0;

	sigaction(SIGILL, &sa, NULL);
	printf("rndr_intercept_test: pid %d\n", getpid());

	/* --- monitored: expect interception --- */
	if (rrmon_ioctl(RRMON_IOC_REGISTER) != 0)
		return 1;
	printf("registered; expect SIGILL:\n");
	fail += !test_insn("RNDR", 0, 1, NULL, NULL);
	fail += !test_insn("RNDRRS", 1, 1, NULL, NULL);

	/* --- deregistered: expect pass-through (emulated read) --- */
	if (rrmon_ioctl(RRMON_IOC_DEREGISTER) != 0)
		fail++;
	printf("deregistered; expect normal completion:\n");
	fail += test_insn("RNDR", 0, 0, &v, &ok);
	fail += test_insn("RNDRRS", 1, 0, &v, &ok);

	printf("\n%s\n", fail ? "FAIL" : "PASS");
	return fail ? 1 : 0;
}
