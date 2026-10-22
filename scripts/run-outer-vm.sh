#!/bin/sh
# Outer VM: the whole-system-emulation substrate for the demonstration.
# QEMU virt machine with EL3 (secure=on) and EL2 (virtualization=on),
# TCG, -cpu max; TF-A (built with RNG_TRAP_FORWARD_TO_EL2=1) as BIOS.
# This matches the invocation recorded at the top of
# evidence/el2host-console-20260726.log.
#
# Environment:
#   QEMU  - path to qemu-system-aarch64 (>= v11.1.0 or master >= 20553466cc)
#   BIOS  - TF-A qemu_fw.bios (see REPRODUCING.md step 2)
#   DISK  - qcow2 root disk with the patched 6.12.88 EL2 host kernel
#   INITRD- host initrd (optional, direct-kernel setups)

QEMU=${QEMU:-qemu-system-aarch64}
BIOS=${BIOS:-qemu_fw.bios}
DISK=${DISK:-disk.qcow2}

exec "$QEMU" \
    -machine virt,virtualization=on,secure=on \
    -accel tcg -cpu max -smp 4 -m 4G -nographic \
    -bios "$BIOS" \
    -drive if=virtio,format=qcow2,file="$DISK" \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0
