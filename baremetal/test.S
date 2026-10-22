/*
 * QEMU FEAT_RNG_TRAP verification test.
 *
 * Starts at EL3 (qemu -bios on -machine virt,secure=on).
 * Sets SCR_EL3.TRNDR, drops to EL2, reads RNDR — should trap.
 * Trap handler at EL3 inspects ESR_EL3 and prints PASS/FAIL via PL011.
 */

#define PL011_DR    0x09000000

.section .text.start, "ax"
.globl _start
_start:
    /* Confirm we started at EL3. */
    mrs  x0, CurrentEL
    lsr  x0, x0, #2
    cmp  x0, #3
    b.ne .Lwrong_el

    /* Stack pointer for EL3. */
    adr  x0, _stack_top
    mov  sp, x0

    /* Install EL3 vector table. */
    adr  x0, vector_table_el3
    msr  VBAR_EL3, x0
    isb

    /*
     * SCR_EL3: RW=1 (AArch64 below), EEL2=1 (enable S-EL2 so we can
     * eret into a Secure EL2 that's allowed to fetch from secure flash
     * where this image lives), TRNDR=1 (the feature we are testing).
     * Note: leaving NS=0 so we stay in secure world; the trap only
     * cares about EL, not security state.
     */
    mrs  x0, SCR_EL3
    orr  x0, x0, #(1 << 10)      /* RW   */
    orr  x0, x0, #(1 << 18)      /* EEL2 */
    mov  x1, #1
    lsl  x1, x1, #40             /* TRNDR */
    orr  x0, x0, x1
    msr  SCR_EL3, x0
    isb

    /* Announce. */
    adr  x0, msg_started
    bl   uart_puts

    /* HCR_EL2.RW=1 so EL1 below would be AArch64 (defensive). */
    mov  x0, #(1 << 31)
    msr  HCR_EL2, x0
    isb

    /* SCTLR_EL2 reset state: keep MMU/caches off (default after reset is fine
     * on QEMU, but make EE/M explicit). */
    mov  x0, #0
    msr  SCTLR_EL2, x0
    isb

    /* SPSR_EL3 = EL2h, all DAIF masked (0x3c9). */
    mov  x0, #0x3c9
    msr  SPSR_EL3, x0

    /* ELR_EL3 = el2_main. */
    adr  x0, el2_main
    msr  ELR_EL3, x0
    eret

.Lwrong_el:
    adr  x0, msg_wrong_el
    bl   uart_puts
    b    halt

el2_main:
    /* Confirm we landed at EL2. */
    mrs  x0, CurrentEL
    lsr  x0, x0, #2
    cmp  x0, #2
    b.ne .Lnot_el2

    adr  x0, msg_at_el2
    bl   uart_puts

    /*
     * While SCR_EL3.TRNDR is set, FEAT_RNG_TRAP forces ID_AA64ISAR0_EL1.RNDR
     * (bits [63:60]) to read as 0b0001 regardless of whether FEAT_RNG is
     * implemented. Reading the ID register itself must not trap.
     */
    adr  x0, msg_pre_isar
    bl   uart_puts
    mrs  x20, ID_AA64ISAR0_EL1
    lsr  x20, x20, #60
    cmp  x20, #1
    b.ne .Lisar_fail
    adr  x0, msg_isar_pass
    bl   uart_puts
    b    .Lisar_done
.Lisar_fail:
    adr  x0, msg_isar_fail
    bl   uart_puts
    mov  x0, x20
    bl   uart_puthex64
    adr  x0, msg_nl
    bl   uart_puts
.Lisar_done:

    /* The moment of truth: MRS Xt, RNDR. Should trap to EL3. */
    adr  x0, msg_pre_rndr
    bl   uart_puts

    .word 0xd53b2400            /* mrs x0, S3_3_C2_C4_0 (RNDR) */

    /* If we reach here, no trap occurred. */
    adr  x0, msg_no_trap
    bl   uart_puts
    b    halt

.Lnot_el2:
    adr  x0, msg_not_el2
    bl   uart_puts
    b    halt

/* ---------------- EL3 vector table ---------------- */
.balign 0x800
vector_table_el3:
    /* Current EL with SP0 */
    .balign 0x80
    b     unexpected_curr_sp0_sync
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected

    /* Current EL with SPx */
    .balign 0x80
    b     unexpected_curr_spx_sync
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected

    /* Lower EL using AArch64 */
    .balign 0x80
    b     sync_lower_aa64
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected

    /* Lower EL using AArch32 */
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected
    .balign 0x80
    b     unexpected

sync_lower_aa64:
    /* Stash ESR_EL3 in x19 (uart_puts clobbers x9-x13). */
    mrs  x19, ESR_EL3
    lsr  x10, x19, #26
    and  x10, x10, #0x3f
    cmp  x10, #0x18           /* sysreg trap */
    b.ne .Lwrong_ec

    adr  x0, msg_pass
    bl   uart_puts

    /* Print the syndrome value in hex. */
    adr  x0, msg_esr
    bl   uart_puts
    mov  x0, x19
    bl   uart_puthex64
    adr  x0, msg_nl
    bl   uart_puts
    b    halt

.Lwrong_ec:
    adr  x0, msg_wrong_ec
    bl   uart_puts
    mov  x0, x19
    bl   uart_puthex64
    adr  x0, msg_nl
    bl   uart_puts
    b    halt

unexpected_curr_sp0_sync:
unexpected_curr_spx_sync:
unexpected:
    adr  x0, msg_unexpected
    bl   uart_puts
    b    halt

/* ---------------- PL011 UART output ---------------- */
/* x0 = NUL-terminated string */
uart_puts:
    ldr  x9, =PL011_DR
1:  ldrb w10, [x0], #1
    cbz  w10, 2f
    strb w10, [x9]
    b    1b
2:  ret

/* x0 = 64-bit value to print as "0x" + 16 hex digits */
uart_puthex64:
    mov  x11, x0
    ldr  x9, =PL011_DR
    mov  w10, #'0'
    strb w10, [x9]
    mov  w10, #'x'
    strb w10, [x9]
    mov  x12, #60
1:  lsr  x13, x11, x12
    and  x13, x13, #0xf
    cmp  x13, #10
    b.lt 2f
    add  w13, w13, #('a' - 10)
    b    3f
2:  add  w13, w13, #'0'
3:  strb w13, [x9]
    subs x12, x12, #4
    b.ge 1b
    ret

halt:
    wfe
    b    halt

/* ---------------- strings ---------------- */
.section .rodata
msg_started:     .asciz "EL3: started, SCR_EL3.TRNDR set\n"
msg_at_el2:      .asciz "EL2: arrived after eret\n"
msg_pre_isar:    .asciz "EL2: reading ID_AA64ISAR0_EL1.RNDR\n"
msg_isar_pass:   .asciz "PASS: ID_AA64ISAR0_EL1.RNDR reads 1 under TRNDR\n"
msg_isar_fail:   .asciz "FAIL: ID_AA64ISAR0_EL1.RNDR not 1; field = "
msg_pre_rndr:    .asciz "EL2: executing MRS x0, RNDR\n"
msg_no_trap:     .asciz "FAIL: RNDR did not trap to EL3\n"
msg_not_el2:     .asciz "FAIL: eret did not land in EL2\n"
msg_wrong_el:    .asciz "FAIL: did not start at EL3\n"
msg_unexpected:  .asciz "FAIL: unexpected exception vector hit\n"
msg_pass:        .asciz "PASS: RNDR trapped to EL3 (EC=0x18)\n"
msg_esr:         .asciz "ESR_EL3 = "
msg_wrong_ec:    .asciz "FAIL: trap with unexpected EC; ESR_EL3 = "
msg_nl:          .asciz "\n"

/* ---------------- stack ---------------- */
.section .bss
.balign 16
.skip 4096
_stack_top:
