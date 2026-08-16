#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot, AArch64 with a virtio block device on the PCI bus: require the
# clean success exit (status 33) AND that sector 0 was read through the
# **virtio-pci** transport.
#
# Every other virtio boot in this tree drives virtio-mmio, a register block the
# device tree names at a fixed base. A virtio-pci device has no such block: its
# controls live in structures named by vendor capabilities in config space,
# each in some BAR at some offset, with the doorbell at an address computed per
# queue. Reading a sector over it is the proof that the transport seam is real
# — the rings, the descriptor chain and the completion poll below it are the
# same code the mmio path runs.
#
# The flags that matter:
#   * `-device virtio-blk-pci` with its own disk image. QEMU presents it as the
#     **transitional** `1af4:1001`, whose device id is not the modern
#     `0x1040 + type` — a driver that knew only the modern rule would refuse it.
#   * **no `iommu=smmuv3`**, deliberately. With the SMMU up, GBPA aborts, and a
#     device whose stream has no live translation cannot DMA at all; an
#     in-kernel driver holding no lease would hang waiting for a completion the
#     hardware is refusing. That boot reports the skip and this one does the
#     driving.
#
# Normative: Virtual I/O Device (VIRTIO) Version 1.x ("Virtio Over PCI Bus"),
# docs/hardware/02-hardware-description-and-discovery.md ("PCIe")

set -u

MARKER='claim virtio-pci.ok'
# Direct child-queue mapping (M98). A **second** block function, told to present
# more than one request queue. `page-per-vq=on` is what makes each queue's
# doorbell land on a page of its own; without it every queue shares one page, so
# no queue could be granted to a different process however separate its rings
# were. That is why the check fails rather than passes on a shared page — the
# rings would work and the grant would not be possible.
MQ_MARKER='claim virtio-mq.ok'
# The half the controller cannot prove about itself: a ring-3 process holding a
# capability to the controller and nothing else derives the queue behind it and
# submits on it alone. Its own marker, because a check that stopped at the
# controller would show the hardware separates queues and not that the system
# ever hands one over.
CHILD_MARKER='claim queue-child.ok'
KERNEL="${1:?usage: virtio_pci_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: virtio_pci_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64-virtio-pci.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/virtio-pci-disk-aarch64.img"
# The multiqueue function gets its own copy: two devices sharing one backing
# file would have each other's writes appear as the other's reads, and a sector
# read on queue 1 would be evidence of nothing in particular.
MQ_DISK="${TEST_TMPDIR:-/tmp}/virtio-pci-mq-disk-aarch64.img"
cp "$DISK" "$WRITABLE_DISK"
cp "$DISK" "$MQ_DISK"
chmod u+w "$MQ_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=pcidisk" \
    -device virtio-blk-pci,drive=pcidisk \
    -drive "file=$MQ_DISK,if=none,format=raw,id=mqdisk" \
    -device virtio-blk-pci,drive=mqdisk,num-queues=2,page-per-vq=on \
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
grep -qF "$MARKER" "$SERIAL_LOG" ||
    fail "no sector was read over the virtio-pci transport"
grep -qF "$MQ_MARKER" "$SERIAL_LOG" ||
    fail "no multiqueue function served a read on a queue with its own doorbell page"
grep -qF "$CHILD_MARKER" "$SERIAL_LOG" ||
    fail "no ring-3 child derived a queue and submitted on it"

echo "PASS: clean exit 33, a sector was read over the virtio-pci transport, and a ring-3 child holding one page of register window — its queue's doorbell — derived that queue from the controller, published a request and rang its own doorbell"
