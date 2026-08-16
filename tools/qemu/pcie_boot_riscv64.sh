#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot, RISC-V 64 with a PCI Express endpoint attached: require the
# clean success exit (status 33) AND that the kernel's ECAM walk found the
# endpoint and placed its BAR.
#
# The other RISC-V boots exercise virtio-mmio, which the device tree names
# directly — the machine tells the kernel where each transport is. PCI does
# not work that way: the device tree names only the host bridge, and what is
# behind it is discoverable only by reading config space. So this is the first
# boot where the kernel finds a device nothing told it about.
#
# The flags that matter:
#   * `-device virtio-blk-pci` puts a real endpoint on the bus. Without it the
#     walk finds only the host bridge, which proves the arithmetic but not that
#     anything was discovered — the plain smoke boot covers that case and says
#     so.
#   * its `-drive` is a *separate* image from the virtio-mmio disk, because
#     QEMU takes a write lock per image and two devices cannot share one.
#   * `-cpu rva23s64` as everywhere on this port: the tick needs Sstc.
#
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/hardware/02-hardware-description-and-discovery.md ("PCIe")

set -u

MARKER='pcie: OK — walked ECAM and found 2 function(s); 1af4:'
KERNEL="${1:?usage: pcie_boot_riscv64.sh <kernel-elf> <disk-image>}"
DISK="${2:?usage: pcie_boot_riscv64.sh <kernel-elf> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-riscv64-pcie.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/pcie-disk-riscv64.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 120s qemu-system-riscv64 \
    -M virt -cpu rva23s64 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -global virtio-mmio.force-legacy=false \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=pcidisk" \
    -device virtio-blk-pci,drive=pcidisk \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot
status=$?

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

[ "$status" -eq 33 ] || fail "QEMU exited $status (expected 33)"
grep -qF "$MARKER" "$SERIAL_LOG" ||
    fail "the ECAM walk did not report the attached endpoint"

echo "PASS: clean exit 33 and the ECAM walk found the PCI endpoint"
