# Reproducing the demonstration

The stack has four layers built from three trees plus this repository.
Everything below runs under whole-system TCG emulation; no Arm hardware
is required. A capable x86-64 or arm64 host with ~20 GB free disk is
enough; the outer VM is slow under TCG (minutes to boot), which is
expected.

## 0. Versions

| Layer | Tree | Version |
|---|---|---|
| Emulator | qemu.org | `v11.1.0` release (the first with FEAT_RNG_TRAP) |
| EL3 firmware | trustedfirmware.org TF-A | mainline ≥ `5260112e6` + `patches/tfa/0001` |
| EL2 host kernel | kernel.org | 6.12.88 + `patches/kvm/` (order per `series`) |
| EL1/EL0 guest | Debian 13 aarch64 | stock cloud kernel, unmodified (glibc needed for the rr-based tests; a musl distro can run the intercept/substitute tests) |

## 1. Build QEMU

```sh
./configure --target-list=aarch64-softmmu
ninja -C build qemu-system-aarch64
```

## 2. Build TF-A with the forwarder

```sh
git apply patches/tfa/0001-bl31-forward-rng-traps-to-ns-el2.patch
make PLAT=qemu ENABLE_FEAT_RNG_TRAP=1 RNG_TRAP_FORWARD_TO_EL2=1 \
     ENABLE_FEAT_FPMR=2 \
     DEBUG=1 CROSS_COMPILE=aarch64-linux-gnu- all
# concatenate per TF-A's QEMU docs into qemu_fw.bios
```

With `RNG_TRAP_FORWARD_TO_EL2=0` the build is upstream behavior
(EL3-local emulation) — useful as a control.

**`ENABLE_FEAT_FPMR=2` is required with QEMU ≥ 11.1.0**: `-cpu max`
now advertises FEAT_FPMR, and a Linux guest kernel will execute
`MSR FPMR` early in boot. Without this flag EL3 leaves
`SCR_EL3.EnFPM=0`, that write is UNDEFINED, and the EL2 kernel panics
("Oops - Undefined instruction" in `task_fpsimd_load`, ~5 s in). The
`=2` setting is runtime-detected, so the same firmware also boots CPU
models without FPMR.

## 3. EL3-only check (no OS needed)

Build `baremetal/` (a freestanding BL33) and boot it under
`qemu-system-aarch64 -M virt,secure=on,virtualization=on -cpu max`
with the TF-A image. Expected output: `ID_AA64ISAR0_EL1.RNDR = 1`
under TRNDR and `ESR_EL3 = 0x6230c809` (EC 0x18, RNDR, read, Rt=0) —
compare `evidence/baremetal-esr-el3-20260812.log`.

## 4. EL2 host kernel

Apply `patches/kvm/` to Linux 6.12.88 in `series` order (quilt-style),
build an arm64 kernel with KVM enabled, and install it in a disk image
for the outer VM. On boot the kernel logs
`rng-trap: dispatch hook stub present (patch 0001)`.

## 5. Boot the stack

`scripts/run-outer-vm.sh` holds the exact outer-QEMU invocation used
for the captures (TF-A as `-bios`, `-M virt,secure=on,virtualization=on
-accel tcg -cpu max`). Inside the outer VM, create a KVM guest from a
stock Debian 13 cloud image (AAVMF/UEFI boot). During the guest's UEFI
boot the host logs `kvm: rng-trap: RNDR trap forwarded from EL3 caught`
— that is an unmodified firmware read traversing the full chain
(`evidence/el2host-console-20260812.log`, t≈1206 s).

Note: Debian's *cloud* kernel flavor has no 9p filesystem support, so
copy files into the guest over ssh/scp rather than a virtfs share.

## 6. Guest module and tests

In the guest:

```sh
make -C guest-module KDIR=/lib/modules/$(uname -r)/build
insmod guest-module/rr_entropy_monitor.ko    # creates /dev/rr-entropy-monitor
cc -O2 -I guest-module -o rndr_intercept_test  tests/rndr_intercept_test.c
cc -O2 -I guest-module -o rndr_substitute_test tests/rndr_substitute_test.c
cc -O2 -I guest-module -o rndr_rr              tests/rndr_rr.c
```

The module is controlled through ioctls on `/dev/rr-entropy-monitor`
(UAPI in `guest-module/rr_entropy_monitor.h`); a process may always
register itself, so the tests need no privilege beyond the insmod.

- `rndr_intercept_test`: while its PID is registered, RNDR and RNDRRS
  raise SIGILL; after deregistering, both complete with fresh entropy
  and ok=1. Expect exit 0; compare `evidence/guestvm-test-20260812.log`.
  Optionally watch the trap syndromes from the EL2 host with the
  `kvm_handle_sys_reg` / `kvm_sys_access` tracepoints
  (`evidence/el2host-kvm-trace-20260812.log`). The ISS matches the
  EL3-level syndrome except Rt (the compiler's register choice).
- `rndr_substitute_test`: installs a SIGILL handler that substitutes
  values from a fixed 8-entry recorded log and resumes. All 8 reads
  return the recorded values; the FNV-1a digest is
  `0x3f5cc68f032e2bfd`; **two consecutive runs are bit-identical**
  (`cmp` their outputs). Compare
  `evidence/guestvm-substitute-test-20260812.log`. The same binary
  without registration yields different values every run — the
  nondeterminism being removed.
- `rndr_rr`: a minimal ptrace record/replay supervisor for the
  entropy instructions. Record twice, replay the first:

  ```sh
  ./rndr_rr record --monitor r1.log -- <prog-that-reads-RNDR>
  ./rndr_rr record --monitor r2.log -- <prog-that-reads-RNDR>
  ./rndr_rr replay --monitor r1.log -- <prog-that-reads-RNDR>
  ```

  Expected: the replay output is bit-identical to the first record
  (matching stream digest, `0 divergence(s)`) while the two records
  differ. `--monitor` is required on record AND replay here: on this
  stack an unregistered process's RNDR is served by the hypervisor,
  so without registration the supervisor never sees the reads.
  Compare `evidence/guestvm-rndr-rr-20260812.log`.

## 7. Substrate survey (optional)

`tools/rndr_probe.c` builds statically anywhere aarch64 and reports
HWCAP2_RNG, `ID_AA64ISAR0_EL1.RNDR`, and the SIGILL/success behavior of
both instructions from EL0 — the probe behind the paper's Table 1
(`evidence/ec2-graviton{2,3}-rndr-20260726.log`,
`evidence/mac-m4-feat-rng-20260726.log`,
`evidence/rpi5-rndr-20260726.log`).

## rr.soft record/replay (paper §IV, closing paragraph)

Stock `rr` needs a count-accurate PMU that TCG does not provide; rr.soft
counts instructions in software (`-W`). In the guest:

```sh
git clone -b software-counters-mode https://github.com/sidkshatriya/rr.soft
cd rr.soft && git checkout c93b2769
git apply <artifact>/patches/rr/0003-arm-rndr-rndrrs-substitution-engine-rr-soft.diff
# build per rr.soft's README (clang plugin + rocksdb + capnp + zydis);
# a glibc distribution is required.
sysctl kernel.perf_event_paranoid=1     # context-switch event only, no PMU
insmod guest-module/rr_entropy_monitor.ko
rr record -W -o r1 -- <prog-that-reads-RNDR>
rr record -W -o r2 -- <prog-that-reads-RNDR>
rr replay -W -a r1                      # bit-identical to r1's recording
```

The recorder registers the tracee with the module itself (dmesg shows
the registration and exec re-key). Compare
`evidence/guestvm-rrsoft-20260812.log`.
