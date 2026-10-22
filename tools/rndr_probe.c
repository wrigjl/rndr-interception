/*
 * rndr_probe.c - Report FEAT_RNG status on an arm64 Linux host.
 * Static build: gcc -O2 -static -o rndr_probe rndr_probe.c
 *
 * Three independent checks:
 *  1. HWCAP2_RNG from getauxval(AT_HWCAP2)
 *  2. ID_AA64ISAR0_EL1.RNDR (bits [63:60]) via the kernel's EL0
 *     MRS emulation (sanitized view)
 *  3. Execute MRS Xn, RNDR / RNDRRS with a SIGILL catch
 */
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/auxv.h>

#ifndef HWCAP2_RNG
#define HWCAP2_RNG (1UL << 16)
#endif

static sigjmp_buf escape;

static void on_sigill(int sig)
{
	siglongjmp(escape, 1);
}

static int try_read(int is_rndrrs, uint64_t *val, int *ok)
{
	uint64_t v = 0;
	uint32_t z = 0;

	if (sigsetjmp(escape, 1) != 0)
		return -1;	/* SIGILL: undefined */
	if (is_rndrrs)
		asm volatile("mrs %0, S3_3_C2_C4_1\n\tcset %w1, ne"
			     : "=r"(v), "=r"(z) : : "cc");
	else
		asm volatile("mrs %0, S3_3_C2_C4_0\n\tcset %w1, ne"
			     : "=r"(v), "=r"(z) : : "cc");
	*val = v;
	*ok = (int)z;
	return 0;
}

int main(void)
{
	uint64_t isar0 = 0, val;
	unsigned long hwcap2 = getauxval(AT_HWCAP2);
	int ok;

	signal(SIGILL, on_sigill);

	printf("HWCAP2_RNG:              %s\n",
	       (hwcap2 & HWCAP2_RNG) ? "set" : "NOT set");

	if (sigsetjmp(escape, 1) == 0) {
		asm volatile("mrs %0, ID_AA64ISAR0_EL1" : "=r"(isar0));
		printf("ID_AA64ISAR0_EL1:        0x%016llx (RNDR field [63:60] = %llu)\n",
		       (unsigned long long)isar0,
		       (unsigned long long)(isar0 >> 60) & 0xf);
	} else {
		printf("ID_AA64ISAR0_EL1:        read SIGILLed (no EL0 emulation?)\n");
	}

	if (try_read(0, &val, &ok) == 0)
		printf("MRS RNDR:                executed, ok=%d val=0x%016llx\n",
		       ok, (unsigned long long)val);
	else
		printf("MRS RNDR:                SIGILL (undefined)\n");

	if (try_read(1, &val, &ok) == 0)
		printf("MRS RNDRRS:              executed, ok=%d val=0x%016llx\n",
		       ok, (unsigned long long)val);
	else
		printf("MRS RNDRRS:              SIGILL (undefined)\n");

	return 0;
}
