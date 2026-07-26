#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 ring-3 device-host boot, AArch64: boot the Stage 0 kernel with BOTH a
# virtio-blk disk and a virtio-net NIC attached and require the clean success
# exit (status 33) AND the ring-3 host verdict on the serial console. Where
# the per-device boot tests prove each in-kernel driver, this proves the
# **ring-3 device host** end to end: one EL0 process maps both devices by
# capability, self-tests a sector read AND an ARP round-trip from ring 3, and
# serves two client processes over channel IPC. The host check requires both
# devices, so it runs only here (the per-device tests hit its explicit skip
# lines).
# Normative: docs/hardware/04-device-memory-and-unified-memory.md,
# docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='ring3-host: OK'
KERNEL="${1:?usage: ring3_host_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: ring3_host_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-ring3-host-aarch64.log"

# The disk arrives as a read-only build artifact, but QEMU opens the backing
# file read-write. Copy it to a writable scratch path so the device attaches.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/ring3-host-disk.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -global virtio-mmio.force-legacy=false \
    -kernel "$KERNEL" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=n0 \
    -device virtio-net-device,netdev=n0 \
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

case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"

echo "PASS: clean exit 33 and ring-3 host verdict present"
