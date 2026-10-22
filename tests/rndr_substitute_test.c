/*
 * rndr_substitute_test.c - Demonstrate deterministic replay of RNDR/RNDRRS
 *                          on arm64 via SIGILL-time value substitution.
 *
 * Companion to rndr_intercept_test.c (which only proves the SIGILL
 * arrives). This test closes the loop: a SIGILL handler decodes the
 * trapped MRS at PC, substitutes the next value from a fixed "recorded
 * log" into the destination register, sets NZCV to success, and resumes
 * after the instruction — exactly what a record-and-replay supervisor
 * (rr's role on x86) does with the interception point. Running the
 * program twice must produce bit-identical output; a recorded execution
 * downstream of hardware entropy is thereby replayable.
 *
 * Interception path: EL0 MRS -> SCR_EL3.TRNDR trap to EL3 -> TF-A
 * forwards to NS-EL2 -> KVM injects UNDEF for this (registered) process
 * -> guest kernel delivers SIGILL -> handler substitutes.
 *
 * Registers itself via /dev/rr-entropy-monitor (a process may always
 * register itself, so no elevated privilege is needed for this test).
 * Uses the Sn_n_Cm_Cm_n encoding form so no -march=armv8.5-a is needed.
 */
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/ioctl.h>

#include "rr_entropy_monitor.h"

/*
 * MRS Xt, S3_3_C2_C4_0 (RNDR)   = 0xd53b2400 | Rt
 * MRS Xt, S3_3_C2_C4_1 (RNDRRS) = 0xd53b2420 | Rt
 */
#define INSN_MASK    0xffffffe0u
#define INSN_RNDR    0xd53b2400u
#define INSN_RNDRRS  0xd53b2420u

#define PSTATE_NZCV  (0xfull << 28)

/*
 * The "recorded log": the values a recorder would have captured from a
 * previous execution. Fixed at compile time, so every run of this
 * program replays the same entropy stream.
 */
static const uint64_t recorded_log[] = {
	0x524e44525f303030ull, 0x524e44525f303031ull,
	0x524e44525f303032ull, 0x524e44525f303033ull,
	0x524e44525f303034ull, 0x524e44525f303035ull,
	0x524e44525f303036ull, 0x524e44525f303037ull,
};
#define LOG_LEN (sizeof(recorded_log) / sizeof(recorded_log[0]))

static volatile unsigned log_pos;
static volatile unsigned substituted;
static volatile unsigned bad_insn;

static void sigill_substitute(int sig, siginfo_t *si, void *ucv)
{
	ucontext_t *uc = ucv;
	uint64_t pc = uc->uc_mcontext.pc;
	uint32_t insn = *(uint32_t *)pc;
	unsigned rt = insn & 0x1f;
	uint32_t op = insn & INSN_MASK;

	if (op != INSN_RNDR && op != INSN_RNDRRS) {
		/* Not ours: re-raise fatally. */
		bad_insn = insn;
		signal(SIGILL, SIG_DFL);
		return;
	}

	if (rt != 31)	/* Rt=31 encodes XZR: substitution is a no-op */
		uc->uc_mcontext.regs[rt] =
			recorded_log[log_pos % LOG_LEN];
	log_pos++;
	substituted++;

	/* Architected success indication: NZCV = 0b0000. */
	uc->uc_mcontext.pstate &= ~PSTATE_NZCV;

	uc->uc_mcontext.pc = pc + 4;	/* skip the MRS */
}

static int read_rndr(int is_rndrrs, uint64_t *val)
{
	uint64_t v = 0;
	uint32_t ok = 0;

	if (is_rndrrs)
		asm volatile("mrs %0, S3_3_C2_C4_1\n\t"  /* RNDRRS */
			     "cset %w1, ne\n"
			     : "=r"(v), "=r"(ok) : : "cc");
	else
		asm volatile("mrs %0, S3_3_C2_C4_0\n\t"  /* RNDR */
			     "cset %w1, ne\n"
			     : "=r"(v), "=r"(ok) : : "cc");
	*val = v;
	return (int)ok;	/* 1 = NZCV.Z==0 = success */
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
	struct sigaction sa = {
		.sa_sigaction = sigill_substitute,
		.sa_flags = SA_SIGINFO,
	};
	uint64_t digest = 0xcbf29ce484222325ull;	/* FNV-1a basis */
	int fail = 0;
	unsigned i;

	sigaction(SIGILL, &sa, NULL);

	/*
	 * Note: no pid or timestamp in the output — the whole point is
	 * that two runs print identical bytes.
	 */
	printf("rndr_substitute_test: replaying %u recorded values\n",
	       (unsigned)LOG_LEN);

	if (rrmon_ioctl(RRMON_IOC_REGISTER) != 0)
		return 1;

	for (i = 0; i < LOG_LEN; i++) {
		uint64_t v;
		int ok = read_rndr(i & 1, &v);	/* alternate RNDR/RNDRRS */
		int match = (v == recorded_log[i]);

		/* Fold into a digest: downstream computation on the
		 * replayed entropy must also be deterministic. */
		digest = (digest ^ v) * 0x100000001b3ull;

		printf("  %-8s #%u: ok=%d val=0x%016llx %s\n",
		       (i & 1) ? "RNDRRS" : "RNDR", i, ok,
		       (unsigned long long)v,
		       match ? "(== recorded)" : "(MISMATCH)");
		fail += !match || !ok;
	}

	if (rrmon_ioctl(RRMON_IOC_DEREGISTER) != 0)
		fail++;

	if (substituted != LOG_LEN) {
		printf("expected %u substitutions, got %u%s\n",
		       (unsigned)LOG_LEN, substituted,
		       substituted == 0 ?
		       " (not intercepted at all?)" : "");
		fail++;
	}
	if (bad_insn) {
		printf("handler saw foreign insn 0x%08x\n", bad_insn);
		fail++;
	}

	printf("digest: 0x%016llx\n", (unsigned long long)digest);
	printf("%s\n", fail ? "FAIL" : "PASS");
	return fail ? 1 : 0;
}
