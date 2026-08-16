#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 NVMe boot, AArch64: boot the Stage 0 kernel with an NVMe controller on
# the PCIe bus and require the clean success exit (status 33) AND the NVMe
# verdict on the serial console.
#
# What this proves that no other boot does: the **block class contract over a
# second transport**. The controller is not virtio, its bring-up shares no code
# with virtio's, and the client that judges it is `blk-client` — the same
# program, byte for byte, that judges the virtio driver. A class contract that
# only ever had one implementation is a class contract nobody has tested.
#
# And a **vector per queue**: each of the driver's two I/O queues is created
# with its own MSI-X vector, routed to its own port, so the driver learns which
# queue completed from where it woke rather than by reading both rings.
# Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
# docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='claim nvme.ok'
# The two claims, separable and asserted apart: that a second transport served
# the block class at all, and that each queue's completions arrived somewhere
# that identifies the queue.
CLASS_MARKER='claim nvme.class-served'
VECTOR_MARKER='claim nvme.vector-per-queue'
# The half a driver and a client agreeing with each other cannot fake, and the
# reason the conformance suite is named here rather than assumed from the OK.
CONFORMANCE_MARKER='claim nvme.conformance-complete'
KERNEL="${1:?usage: nvme_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: nvme_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-nvme-aarch64.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/nvme-disk.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 180s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -global virtio-mmio.force-legacy=false \
    -kernel "$KERNEL" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=nvm" \
    -device nvme,serial=TESSERA0,drive=nvm \
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
    124) fail "boot timed out after 180s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$CLASS_MARKER" "$VECTOR_MARKER" "$CONFORMANCE_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the NVMe claim did not hold: '$marker'"
done

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, an NVMe controller served the block class from ring 3, each queue's completions arrived on its own vector, and the class conformance suite held"
