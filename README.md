# Artifact: Upstreaming Replay Support for Hardware Entropy on Arm

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23581742.svg)](https://doi.org/10.5281/zenodo.23581742)

Archived release: v1.0.0, DOI 10.5281/zenodo.23581742 (concept DOI for
all versions: 10.5281/zenodo.23581741).

Artifact for the CSET 2026 paper "Three Months to Flip One Bit:
Upstreaming Replay Support for Hardware Entropy on ARM" (Jason L. Wright
and Thomas L. Baldwin, Idaho State University). The reviewer bundle was
anonymized; this archived version restores attribution and adds the
rr.soft substitution patch (`patches/rr/`). Content is otherwise the
bundle the reviewers saw.

The paper's platform components need no artifact — they are upstream:
FEAT_RNG_TRAP emulation ships in the QEMU 11.1.0 release (2026-08-11),
and the EL3 trap handler for the QEMU `virt` platform is in Trusted
Firmware-A mainline. All evidence below was captured on the stock
v11.1.0 release binary.
This repository holds everything else: the research-side patches, the
guest module, the test harnesses, and the raw demonstration evidence
behind the paper's Section IV.

## Layout

| Path | Contents |
|---|---|
| `patches/tfa/` | EL3→NS-EL2 trap forwarder for TF-A (applies to mainline; see REPRODUCING.md for the pinned base) |
| `patches/kvm/` | Linux/KVM per-process dispatch series for 6.12.88 (`series` gives the order) |
| `patches/rr/` | RNDR/RNDRRS substitution engine for rr.soft (software-counter rr fork), behind the supplementary record/replay result |
| `guest-module/` | `rr_entropy_monitor.ko` source: registers monitored processes' TTBR0 with KVM over a vendor hypercall |
| `tests/` | `rndr_intercept_test.c` (dispatch split), `rndr_substitute_test.c` (the replay/substitution harness), `rndr_rr.c` (ptrace record/replay supervisor) |
| `baremetal/` | EL3-level bare-metal harness (observes the raw trap syndrome under TRNDR) |
| `tools/` | `rndr_probe.c`, the substrate-survey probe used for the paper's Table 1 |
| `evidence/` | Raw captured logs for every Section IV claim, with provenance (`evidence/README.md`) |
| `scripts/` | Outer-VM launcher matching the captured configuration |

## Claim → evidence map

Step numbers refer to the paper's Figure 1.

| Paper claim (§IV) | Fig. 1 step | Evidence | Reproduce with |
|---|---|---|---|
| Trap arrives at EL3, syndrome `0x6230c809`; `ID_AA64ISAR0_EL1.RNDR` reads 1 under TRNDR | 1 | `evidence/baremetal-esr-el3-20260812.log` | `baremetal/` |
| Forwarded trap arrives at EL2 as if taken directly (`0x6230c889`/`0x6232c889`; ISS differs from EL3's only in Rt, which varies with the compiler's register choice) | 2 | `evidence/el2host-kvm-trace-20260812.log` (+ `-full`) | KVM tracepoints during test run |
| Registered process gets SIGILL; deregistered completes with entropy; others unaffected | 0, 3a, 3b | `evidence/guestvm-test-20260812.log` | `tests/rndr_intercept_test.c` |
| Recorded values substituted; two runs bit-identical | 3a | `evidence/guestvm-substitute-test-20260812.log` | `tests/rndr_substitute_test.c` (run twice, `cmp`) |
| Live record → replay: record captures real hypervisor-emulated entropy, replay is bit-identical (digest match, 0 divergences), independent records differ | 0→3a | `evidence/guestvm-rndr-rr-20260812.log` | `tests/rndr_rr.c` (record/replay, `--monitor` on both) |
| Unmodified UEFI boot read traverses the full chain | 1→2→3b | `evidence/el2host-console-20260812.log` (t≈1206 s) | boot the stack, watch dmesg |
| Substrate survey (Graviton2/3, Apple M4, Raspberry Pi 5) | — | `evidence/ec2-*.log`, `evidence/mac-m4-*.log`, `evidence/rpi5-*.log` | `tools/rndr_probe.c` |

Live recorder (§IV closing paragraph): `evidence/guestvm-rrsoft-20260812.log` —
record/replay of a monitored program under rr.soft (`rr record -W` /
`rr replay -W`, software-counter mode of the public rr fork
github.com/sidkshatriya/rr.soft) with `patches/rr/0003` applied: each
replay is bit-identical to its recording, independent recordings differ,
and the guest dmesg shows the module registering the tracee (with exec
re-keying) for each run. See REPRODUCING.md § rr.soft.

## Version pinning

All pins are on public upstream history; the capture is from a single
uninterrupted session on 2026-08-12:

- **QEMU**: the tagged **`v11.1.0` release**, stock — the first release
  shipping FEAT_RNG_TRAP emulation. No QEMU patches are needed.
- **TF-A**: mainline (`integration`) @ `5260112e6` (contains the QEMU
  platform RNG-trap handler and its CI coverage) plus
  `patches/tfa/0001`. **Planned**: re-verify against the next tagged
  TF-A release, expected to be the first release containing the QEMU
  platform handler.
- **Linux (EL2 host)**: 6.12.88 plus `patches/kvm/`.
- **Guest**: stock Debian 13 (cloud kernel `6.12.96+deb13-cloud-arm64`),
  deliberately unpatched; only `guest-module/` is loaded. (A glibc
  distribution is required by the rr-based tests; musl distros work for
  the intercept/substitute tests only.)

## License

BSD-2-Clause (see `LICENSE`), copyright Jason L. Wright and Thomas L.
Baldwin. Archived on Zenodo as DOI 10.5281/zenodo.23581742.
