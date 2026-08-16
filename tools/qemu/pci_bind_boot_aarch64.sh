#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot, AArch64 with an IOMMU and a PCI mass-storage endpoint behind it:
# require the clean success exit (status 33) AND that a device the kernel
# enumerated was bound by class to two drivers in turn, each leased the same
# device-visible addresses.
#
# This is where two halves of the design meet for the first time. Binding by
# class needs an identity the kernel recorded, because config space is not
# per-device and so no capability to it can be handed out. A DMA lease needs an
# IOMMU. Until now the first had only ever run on a machine without the second.
#
# The flags that matter:
#   * `iommu=smmuv3` puts an SMMUv3 in front of the PCIe root complex. Without
#     it the bind still happens and the boot reports, honestly, that the lease
#     is not proven here.
#   * `-device virtio-blk-pci` is a **mass-storage** function (class 0x01), the
#     only class this machine offers that the manager maps to `Block`. `edu`
#     cannot stand in: it is an unclassified device, and the manager refuses to
#     bind what it cannot classify.
#   * **no `-device edu`** — deliberately. The SMMU used to be brought up only
#     when `edu` was attached; this boot is what proves it no longer is.
#
# Normative: docs/drivers/01-driver-framework.md ("DMA Safety", "Binding"),
# docs/hardware/02-hardware-description-and-discovery.md ("PCIe")

set -u

MARKER='pci-bind: OK — the manager matched this device against a binding manifest'
# The last thing between a granted window and a ring-3 virtio-pci driver: a
# driver holding only a window had no way to find anything in it, because a
# virtio-pci function says where its structures are in config space and config
# space is not per-device. The kernel reads it and reports the offsets; this is
# the driver using them.
STRUCTURES_MARKER="found its device's common configuration structure"
LEASE_MARKER='both were leased the same device-visible addresses'
WINDOW_MARKER='past the first page, and the same bytes the kernel reads at that physical address'
# The binding tree (M97): the manager holds the *bus*, not the device, and asks
# the kernel what is behind it. Its own marker, because a manager that fell back
# to being handed its inventory would bind exactly as well and prove one less
# thing — the failure is silent by construction.
DERIVED_MARKER='it was given the **bus** it sits on and derived the device from it (true)'
# What that bus costs the device behind it, on real hardware (D143): a
# `pcie-root-port` gives each function its own configuration and its own BARs,
# so nothing relays and the honest answer is zero. The manifest says so, and the
# endpoint binds against an entry whose budget a relaying hub would blow — which
# is the same declaration doing the work in both directions.
PATH_COST_MARKER='per-child queue separation, so a transfer crosses no extra process'
# PCI as a bus driver (D151). Three markers, because the claims are separable:
# that a ring-3 program walked the bus at all, that the functions in the
# resource graph were put there by it rather than by the kernel, and that a
# driver reached its own configuration space and nothing adjacent.
PCI_BUS_MARKER='pci-bus: OK'
PCI_BUS_DECLARED_MARKER='was put there by an unprivileged process'
PCI_BUS_CONFIG_MARKER='mapped its OWN configuration space'

KERNEL="${1:?usage: pci_bind_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: pci_bind_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64-pci-bind.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/pci-bind-disk-aarch64.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 120s qemu-system-aarch64 \
    -M virt,iommu=smmuv3,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=pcidisk" \
    -device pcie-root-port,id=rp0,slot=0 \
    -device virtio-blk-pci,bus=rp0,drive=pcidisk \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

[ "$status" -eq 33 ] || fail "QEMU exited $status (expected 33)"
grep -qF "$MARKER" "$SERIAL_LOG" || fail "no PCI device was bound through the manifest"
grep -qF "$STRUCTURES_MARKER" "$SERIAL_LOG" ||
    fail "the driver was not told where its device's structures are"
grep -qF "$LEASE_MARKER" "$SERIAL_LOG" ||
    fail "the two drivers were not leased the same addresses"
grep -qF "$DERIVED_MARKER" "$SERIAL_LOG" ||
    fail "the manager was handed its device rather than deriving it from the bus"
grep -qF "$WINDOW_MARKER" "$SERIAL_LOG" ||
    fail "the driver did not read past the first page of its own window"
grep -qF "$PATH_COST_MARKER" "$SERIAL_LOG" ||
    fail "the bus the device sits behind declared no data-path cost"

for marker in "$PCI_BUS_MARKER" "$PCI_BUS_DECLARED_MARKER" "$PCI_BUS_CONFIG_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "PCI was not enumerated from ring 3: '$marker'"
done

echo "PASS: clean exit 33, a ring-3 manager holding a PCIe bus derived the device behind it and bound it by class behind the SMMU with the bus's declared data-path cost applied, and its replacement was leased the addresses the first driver's death released"
