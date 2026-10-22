/*
 * rndr_rr.c - A "poor man's rr" for hardware entropy instructions on
 *             arm64: a ptrace-based record/replay supervisor for
 *             RNDR/RNDRRS.
 *
 * Where rndr_substitute_test.c substitutes values from inside the same
 * process (an in-process SIGILL handler), this program is a *separate*
 * supervisor that ptraces an ENTIRELY UNMODIFIED tracee. It records the
 * entropy a live execution consumes and replays it into a later run,
 * with the record/replay division of labour a real recorder has:
 *
 *   record:  run the tracee; each RNDR/RNDRRS it executes traps to the
 *            supervisor as SIGILL. The supervisor reads a fresh value
 *            from its OWN (unmonitored) entropy source, appends it to a
 *            log, injects it into the tracee's destination register,
 *            sets the architected success flags, steps past the MRS,
 *            and continues. The tracee observes real entropy and never
 *            knows it was mediated.
 *
 *   replay:  identical, except the injected values come from the log
 *            instead of a live source. A recorded run and its replay
 *            produce bit-identical results; two record runs differ.
 *
 * Because the tracee needs no SIGILL handler and no cooperation, any
 * ordinary binary that issues RNDR/RNDRRS is replayable.
 *
 * Two substrates, one code path:
 *   - Full stack (QEMU virt + TF-A + KVM): the tracee's EL0 reads trap
 *     to EL3, forward to EL2, and KVM injects UNDEF -> SIGILL *because
 *     the supervisor registered the tracee* with the monitor module
 *     (pass --monitor). The supervisor's own reads are unregistered, so
 *     they are emulated by the hypervisor and yield real entropy.
 *   - Bare hardware without FEAT_RNG (e.g. Cortex-A76): RNDR is simply
 *     UNDEFINED, so the tracee SIGILLs with no module at all, and the
 *     supervisor falls back to getrandom() for record-side entropy.
 *     This lets the whole ptrace/decode/substitute/replay path be
 *     exercised off the full stack.
 *
 * SCOPE (state plainly in the paper): single-threaded tracee only —
 * multi-threaded read ordering is the hard problem this does not solve,
 * as on x86 rr — and entropy instructions only; no syscall/signal
 * record. It is the entropy-interception primitive turned into a real,
 * if minimal, record/replay tool, not a general recorder.
 *
 * Build:   cc -O2 -o rndr_rr rndr_rr.c
 * Usage:   rndr_rr record [--monitor] <log> -- <program> [args...]
 *          rndr_rr replay          <log> -- <program> [args...]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <elf.h>

#include "rr_entropy_monitor.h"

/*
 * MRS Xt, S3_3_C2_C4_0 (RNDR)   = 0xd53b2400 | Rt
 * MRS Xt, S3_3_C2_C4_1 (RNDRRS) = 0xd53b2420 | Rt
 */
#define INSN_MASK    0xffffffe0u
#define INSN_RNDR    0xd53b2400u
#define INSN_RNDRRS  0xd53b2420u

#define PSTATE_NZCV  (0xfull << 28)
#define PSTATE_Z     (1ull   << 30)

/* ---- supervisor-side entropy source ------------------------------- */

static int have_rndr;
static sigjmp_buf probe_jb;

static void probe_ill(int sig)
{
	(void)sig;
	siglongjmp(probe_jb, 1);
}

/* Detect at startup whether this CPU/context can execute RNDR itself. */
static void entropy_probe(void)
{
	struct sigaction sa = { .sa_handler = probe_ill }, old;

	sigaction(SIGILL, &sa, &old);
	if (sigsetjmp(probe_jb, 1) == 0) {
		uint64_t v;
		asm volatile("mrs %0, S3_3_C2_C4_0" : "=r"(v));  /* RNDR */
		have_rndr = 1;
	} else {
		have_rndr = 0;
	}
	sigaction(SIGILL, &old, NULL);
}

/* Return 1 on success (Z==0), 0 on failure; *val gets the value. */
static int host_entropy(int is_rndrrs, uint64_t *val)
{
	if (have_rndr) {
		uint64_t v;
		uint32_t ok;

		if (is_rndrrs)
			asm volatile("mrs %0, S3_3_C2_C4_1\n\t"
				     "cset %w1, ne\n"
				     : "=r"(v), "=r"(ok) : : "cc");
		else
			asm volatile("mrs %0, S3_3_C2_C4_0\n\t"
				     "cset %w1, ne\n"
				     : "=r"(v), "=r"(ok) : : "cc");
		*val = v;
		return (int)ok;
	}
	/* No FEAT_RNG here: stand in with the kernel CSPRNG. */
	if (getrandom(val, sizeof(*val), 0) != (ssize_t)sizeof(*val)) {
		*val = 0;
		return 0;
	}
	return 1;
}

/* ---- log I/O ------------------------------------------------------- */

static FILE *log_fp;

static void log_open_write(const char *path)
{
	log_fp = fopen(path, "w");
	if (!log_fp) {
		fprintf(stderr, "rndr_rr: open %s for write: %s\n",
			path, strerror(errno));
		exit(1);
	}
	fprintf(log_fp, "# rndr_rr entropy log v1\n");
	fprintf(log_fp, "# idx insn ok value\n");
}

static void log_open_read(const char *path)
{
	log_fp = fopen(path, "r");
	if (!log_fp) {
		fprintf(stderr, "rndr_rr: open %s for read: %s\n",
			path, strerror(errno));
		exit(1);
	}
}

static void log_write(unsigned idx, int is_rndrrs, int ok, uint64_t val)
{
	fprintf(log_fp, "%u %s %d 0x%016llx\n", idx,
		is_rndrrs ? "RNDRRS" : "RNDR", ok,
		(unsigned long long)val);
}

/*
 * Read the next log record. Returns 1 on success, 0 on EOF.
 * On success fills *is_rndrrs/*ok/*val.
 */
static int log_read(int *is_rndrrs, int *ok, uint64_t *val)
{
	char line[128];

	while (fgets(line, sizeof(line), log_fp)) {
		char insn[16];
		unsigned idx;
		int o;
		unsigned long long v;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (sscanf(line, "%u %15s %d 0x%llx", &idx, insn, &o, &v) != 4)
			continue;
		*is_rndrrs = (strcmp(insn, "RNDRRS") == 0);
		*ok = o;
		*val = (uint64_t)v;
		return 1;
	}
	return 0;
}

/* ---- ptrace register access --------------------------------------- */

static int get_regs(pid_t pid, struct user_regs_struct *r)
{
	struct iovec iov = { .iov_base = r, .iov_len = sizeof(*r) };

	return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int set_regs(pid_t pid, struct user_regs_struct *r)
{
	struct iovec iov = { .iov_base = r, .iov_len = sizeof(*r) };

	return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

/* Fetch the 32-bit instruction at the tracee's PC. */
static int peek_insn(pid_t pid, uint64_t pc, uint32_t *insn)
{
	struct iovec local = { .iov_base = insn, .iov_len = 4 };
	struct iovec remote = { .iov_base = (void *)pc, .iov_len = 4 };

	return process_vm_readv(pid, &local, 1, &remote, 1, 0) == 4 ? 0 : -1;
}

/* ---- monitor-module registration (full-stack mode) ---------------- */

static int write_pid(unsigned long cmd, pid_t pid)
{
	int32_t arg = (int32_t)pid;
	int fd, ret = 0;

	fd = open(RRMON_DEVICE_PATH, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "rndr_rr: open %s: %s\n", RRMON_DEVICE_PATH,
			strerror(errno));
		return -1;
	}
	if (ioctl(fd, cmd, &arg) < 0) {
		/* ESRCH on deregister just means the module already dropped
		 * the entry when the tracee exited -- not an error. */
		if (!(cmd == RRMON_IOC_DEREGISTER && errno == ESRCH)) {
			fprintf(stderr, "rndr_rr: ioctl %s(%d): %s\n",
				cmd == RRMON_IOC_REGISTER ? "register"
							  : "deregister",
				pid, strerror(errno));
			ret = -1;
		}
	}
	close(fd);
	return ret;
}

/* ---- main supervisor loop ----------------------------------------- */

static int do_record;		/* 1 record, 0 replay */
static int use_monitor;		/* register tracee with the module */

static uint64_t stream_digest = 0xcbf29ce484222325ull;	/* FNV-1a basis */
static unsigned reads_seen;
static unsigned divergences;

/* Handle one RNDR/RNDRRS trap. Returns 0 to continue the tracee. */
static void handle_entropy_trap(pid_t pid, struct user_regs_struct *r,
				uint32_t insn)
{
	unsigned rt = insn & 0x1f;
	int is_rndrrs = (insn & INSN_MASK) == INSN_RNDRRS;
	uint64_t val = 0;
	int ok;

	if (do_record) {
		ok = host_entropy(is_rndrrs, &val);
		log_write(reads_seen, is_rndrrs, ok, val);
	} else {
		int log_is_rndrrs, log_ok;
		uint64_t log_val;

		if (!log_read(&log_is_rndrrs, &log_ok, &log_val)) {
			fprintf(stderr,
				"rndr_rr: DIVERGENCE: tracee read #%u but log "
				"is exhausted\n", reads_seen);
			divergences++;
			ok = 0;			/* deliver a failing read */
			val = 0;
		} else {
			if (log_is_rndrrs != is_rndrrs) {
				fprintf(stderr,
					"rndr_rr: DIVERGENCE at #%u: log has %s, "
					"tracee executed %s\n", reads_seen,
					log_is_rndrrs ? "RNDRRS" : "RNDR",
					is_rndrrs ? "RNDRRS" : "RNDR");
				divergences++;
			}
			ok = log_ok;
			val = log_val;
		}
	}

	/* Rt==31 is XZR: the read still happens, but writes nothing. */
	if (rt != 31)
		r->regs[rt] = val;

	/* Architected flags: success => NZCV=0; failure => Z set. */
	r->pstate &= ~PSTATE_NZCV;
	if (!ok)
		r->pstate |= PSTATE_Z;

	r->pc += 4;			/* step past the MRS */
	set_regs(pid, r);

	stream_digest = (stream_digest ^ val) * 0x100000001b3ull;
	reads_seen++;
}

int main(int argc, char **argv)
{
	int argi = 1;
	const char *logpath;
	char **child_argv;
	pid_t pid;
	int status;

	if (argc < 2) {
usage:
		fprintf(stderr,
			"usage: %s record [--monitor] <log> -- <prog> [args]\n"
			"       %s replay [--monitor] <log> -- <prog> [args]\n"
			"  --monitor: register the tracee with rr-entropy-monitor.\n"
			"  Required on both record AND replay wherever RNDR works\n"
			"  natively (e.g. on the full stack, where unmonitored reads\n"
			"  are hypervisor-emulated and never reach the supervisor).\n",
			argv[0], argv[0]);
		return 2;
	}

	if (!strcmp(argv[argi], "record"))
		do_record = 1;
	else if (!strcmp(argv[argi], "replay"))
		do_record = 0;
	else
		goto usage;
	argi++;

	if (argi < argc && !strcmp(argv[argi], "--monitor")) {
		use_monitor = 1;
		argi++;
	}

	if (argi >= argc)
		goto usage;
	logpath = argv[argi++];

	if (argi >= argc || strcmp(argv[argi], "--"))
		goto usage;
	argi++;			/* skip "--" */

	if (argi >= argc)
		goto usage;
	child_argv = &argv[argi];

	entropy_probe();
	if (do_record) {
		log_open_write(logpath);
		fprintf(stderr, "rndr_rr: record; entropy source = %s\n",
			have_rndr ? "RNDR (host)" : "getrandom() fallback");
	} else {
		log_open_read(logpath);
		fprintf(stderr, "rndr_rr: replay from %s\n", logpath);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}
	if (pid == 0) {
		/* tracee: opt into tracing, then exec the unmodified program */
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(child_argv[0], child_argv);
		fprintf(stderr, "rndr_rr: exec %s: %s\n",
			child_argv[0], strerror(errno));
		_exit(127);
	}

	/* supervisor */
	if (waitpid(pid, &status, 0) < 0) {	/* initial exec stop */
		perror("waitpid");
		return 1;
	}
	ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)PTRACE_O_EXITKILL);

	if (use_monitor && write_pid(RRMON_IOC_REGISTER, pid) != 0)
		fprintf(stderr, "rndr_rr: warning: could not register tracee; "
			"reads may not be intercepted\n");

	ptrace(PTRACE_CONT, pid, NULL, NULL);

	for (;;) {
		int sig;

		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			break;
		}
		if (WIFEXITED(status) || WIFSIGNALED(status))
			break;
		if (!WIFSTOPPED(status))
			continue;

		sig = WSTOPSIG(status);
		if (sig == SIGILL) {
			struct user_regs_struct regs;
			uint32_t insn = 0;

			if (get_regs(pid, &regs) != 0) {
				perror("GETREGSET");
				ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig);
				continue;
			}
			if (peek_insn(pid, regs.pc, &insn) == 0 &&
			    ((insn & INSN_MASK) == INSN_RNDR ||
			     (insn & INSN_MASK) == INSN_RNDRRS)) {
				handle_entropy_trap(pid, &regs, insn);
				ptrace(PTRACE_CONT, pid, NULL, NULL);  /* eat SIGILL */
			} else {
				/* genuine illegal instruction: let it die */
				ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig);
			}
		} else {
			/* pass every other signal through unchanged */
			ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig);
		}
	}

	if (use_monitor)
		write_pid(RRMON_IOC_DEREGISTER, pid);

	/* In replay, leftover log entries mean the tracee read fewer values
	 * than were recorded -- also a divergence. */
	if (!do_record) {
		int a, b;
		uint64_t c;

		if (log_read(&a, &b, &c)) {
			unsigned extra = 1;

			while (log_read(&a, &b, &c))
				extra++;
			fprintf(stderr,
				"rndr_rr: DIVERGENCE: %u recorded value(s) "
				"never consumed\n", extra);
			divergences++;
		}
	}

	fclose(log_fp);

	fprintf(stderr, "rndr_rr: %s complete: %u entropy read(s), "
		"stream digest 0x%016llx",
		do_record ? "record" : "replay", reads_seen,
		(unsigned long long)stream_digest);
	if (!do_record)
		fprintf(stderr, ", %u divergence(s)", divergences);
	fprintf(stderr, "\n");

	if (WIFEXITED(status))
		return divergences ? 1 : WEXITSTATUS(status);
	return 1;
}
