# rr.soft RNDR/RNDRRS substitution engine

`0003-arm-rndr-rndrrs-substitution-engine-rr-soft.diff` applies to
**rr.soft** (github.com/sidkshatriya/rr.soft, branch
`software-counters-mode`, commit `c93b2769`). It is the recorder-side
half of the paper's closing §IV result: with the guest module loaded and
this patch applied, `rr record -W` captures live RNDR/RNDRRS values from
a tracee and `rr replay -W` reproduces them bit-identically.

What it does (5 files, ~120 insertions):

- `util.cc`/`util.h`: decode `MRS Xn, RNDR` (`insn & 0xffffffe0 ==
  0xd53b2400`) and `RNDRRS` (`0xd53b2420`); register/deregister the
  tracee with `/dev/rr-entropy-monitor` (ioctl ABI mirrors
  `guest-module/rr_entropy_monitor.h`).
- `record_signal.cc`: on the module-induced SIGILL, write the recorder's
  random value into Xn, set NZCV to success, advance PC, and record an
  `INSTRUCTION_TRAP` event (the same event stock rr uses for RDTSC/CPUID).
- `RecordSession.cc` / `ReplaySession.cc`: register the tracee on both
  record and replay. Replay registration is required: an unregistered
  replay tracee receives working hypervisor-emulated RNDR and the
  supervisor never sees the trap.

No stock-rr change is needed for the interception path itself; the
patch only teaches the recorder what to do with the SIGILL.
