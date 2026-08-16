#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 USB boot, AArch64: an xHCI controller with a tree of devices on it.
#
# What this proves that no other boot does is a **bus whose devices have no
# registers**. Everything else here maps a window and drives its device; a USB
# device has nothing to map, so its drivers reach it by asking the process that
# owns the controller to move bytes for them. That is the relaying bus host of
# docs/drivers/01, and it is what finally gives the binding rules' relay-hop
# arithmetic something real to count.
#
# The topology is chosen, not incidental:
#   * usb-storage on a root port  — a disk one relay away, judged by the same
#                                   client program that judges virtio and NVMe;
#   * usb-hub, with usb-kbd behind it — a device two relays away, in a graph
#                                   three levels deep, serving a fourth class
#                                   contract. QEMU names a port behind a hub by
#                                   the path to it (`port=2.1`) rather than by
#                                   the hub's own bus, so the topology is in
#                                   the port number;
#   * usb-audio                   — a device whose class is not on the host's
#                                   allowlist. It enumerates perfectly and is
#                                   declared into the graph with no driver
#                                   bound to it, which is the point.
# Normative: docs/drivers/02-storage-networking-usb-pcie.md ("USB"),
# docs/drivers/01-driver-framework.md ("Bus Topology And Data Paths")

set -u

MARKER='usb: OK'
# The claims, separable and asserted apart.
NO_REGISTERS_MARKER='Its devices have NO REGISTERS'
DEPTH_MARKER='three levels deep'
IDLE_MARKER='answered NO_REPORT rather than failing'
REFUSED_MARKER='One attached device was REFUSED'

KERNEL="${1:?usage: usb_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: usb_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-usb.log"

WRITABLE_DISK="$TMP/usb-disk.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

timeout 300s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -device qemu-xhci,id=xhci \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=usbdisk" \
    -device usb-storage,bus=xhci.0,port=1,drive=usbdisk \
    -device usb-hub,bus=xhci.0,port=2,id=hub \
    -device usb-kbd,bus=xhci.0,port=2.1 \
    -audiodev none,id=silent \
    -device usb-audio,bus=xhci.0,port=3,audiodev=silent \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?

case "$status" in
    33) ;;
    124) fail "boot timed out after 300s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$NO_REGISTERS_MARKER" "$DEPTH_MARKER" "$IDLE_MARKER" "$REFUSED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the USB claim did not hold: '$marker'"
done

echo "PASS: clean exit 33, two class contracts served over devices with no registers, a graph three levels deep, and a device that enumerated and was refused"
