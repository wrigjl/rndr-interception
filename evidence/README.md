# Demonstration evidence (paper §IV) — captured 2026-08-12

Single uninterrupted session (fresh boot → captures → graceful
shutdown) on the stock QEMU `v11.1.0` release binary, the day after
the release shipped. The console log is free of lockup/BUG/WARNING
patterns (the final `ERROR: QEMU System Power off: with GPIO` is
TF-A's normal PSCI poweroff message).

## Sanitization note

For the double-blind submission the logs were mechanically renamed in
place (the archived version keeps them as the reviewers saw them):
hostnames (→ `el2host`, `guestvm`), login usernames (→ `user`), the
kernel builder string (→ `builder@buildhost`), absolute host paths
(→ `<workdir>`), a local kernel version suffix (→ `6.12.88-rr`), a
local dmesg tag (→ `rng-trap:`, matching what the patches in this
repository print), and the guest module's historical page-table-base
field name in dmesg (→ `pgd_base`, matching `guest-module/`). No lines
were added or removed; all timestamps, syndrome values, and entropy
values are untouched.

## Environment (provenance)

| Layer | Component | Version |
|---|---|---|
| Emulator | `qemu-system-aarch64` | **tagged `v11.1.0` release, stock** (first release with FEAT_RNG_TRAP) |
| EL3 firmware | TF-A mainline @ `5260112e6` + `patches/tfa/0001` | `PLAT=qemu ENABLE_FEAT_RNG_TRAP=1 RNG_TRAP_FORWARD_TO_EL2=1 ENABLE_FEAT_FPMR=2 DEBUG=1` |
| EL2 host (`el2host`) | Linux `6.12.88-rr` | 6.12.88 + `patches/kvm/` |
| EL1/EL0 guest (`guestvm`) | Debian 13, stock cloud kernel `6.12.96+deb13-cloud-arm64` | deliberately unpatched; only `guest-module/` loaded |
| Machine config | outer QEMU | `-M virt,secure=on,virtualization=on -accel tcg -cpu max -smp 4 -m 4G` |

Chain: guest EL0 `MRS Xn, RNDR/RNDRRS` → `SCR_EL3.TRNDR` trap to EL3 →
TF-A forwards to NS-EL2 → KVM injects SIGILL if the process's TTBR0 is
registered (monitored), emulates otherwise.

## Files

- `el2host-console-20260812.log` — outer serial console, boot →
  shutdown. TF-A boot banner; `kvm [1]: rng-trap: dispatch hook stub
  present (patch 0001)` at t≈2 s; t≈1206 s `kvm: rng-trap: RNDR trap
  forwarded from EL3 caught` — fired by the guest's UEFI (AAVMF)
  reading RNDR during inner-VM boot: an unmodified firmware read
  traversing the full chain.
- `baremetal-esr-el3-20260812.log` — EL3-layer evidence (`baremetal/`
  harness on the same QEMU binary): `ID_AA64ISAR0_EL1.RNDR` reads 1
  under TRNDR; `ESR_EL3 = 0x6230c809` (EC=0x18, RNDR encoding, read,
  Rt=0).
- `el2host-kvm-trace-20260812.log` (event lines) /
  `el2host-kvm-trace-full-20260812.log` (raw ftrace) — EL2-layer
  evidence during `rndr_intercept_test`: exactly four trapped reads,
  `kvm_handle_sys_reg: HSR 0x6230c889` (RNDR) / `0x6232c889` (RNDRRS)
  and the matching `kvm_sys_access` decodes. First pair = monitored
  process (→ SIGILL), second pair = after deregistration (→ emulated).
  The ISS differs from the bare-metal `ESR_EL3` only in Rt (the
  compiler's destination-register choice).
- `guestvm-test-20260812.log` — EL0-layer evidence,
  `rndr_intercept_test`: registered → RNDR and RNDRRS both SIGILL
  (PASS); deregistered → both complete ok=1 with fresh entropy. The
  deregistered values differ from every prior capture — that is the
  nondeterminism being removed.
- `guestvm-substitute-test-20260812.log` — the replay-mechanism claim:
  a SIGILL handler substitutes 8 values from a fixed recorded log;
  FNV-1a digest `0x3f5cc68f032e2bfd` (identical across captures —
  deterministic by construction); two runs bit-identical (matching
  md5s).
- `guestvm-rndr-rr-20260812.log` — live record → replay
  (`tests/rndr_rr.c`, `--monitor` on both phases): record reads real
  hypervisor-emulated entropy ("entropy source = RNDR (host)"), an
  independent second record differs, and replay reproduces record 1
  bit-identically (matching stream digest, 0 divergences).
- `guestvm-rrsoft-20260812.log` — supplementary: the same
  record/replay property under rr.soft (`rr record -W` /
  `rr replay -W`, the software-counters mode of the public rr fork).
  Two recordings, each replay bit-identical to its own recording,
  recordings differ; guest dmesg shows the module registering each
  tracee (with exec re-keying) and deregistering on exit.
- `mac-m4-feat-rng-20260726.log`, `ec2-graviton2-rndr-20260726.log`,
  `ec2-graviton3-rndr-20260726.log`, `rpi5-rndr-20260726.log` —
  substrate-survey rows for the paper's Table 1 (capture-date
  independent; see each log's header). Probe: `tools/rndr_probe.c`.
