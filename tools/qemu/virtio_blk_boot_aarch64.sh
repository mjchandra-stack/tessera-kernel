#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 virtio-blk boot, AArch64: boot the Stage 0 kernel with a virtio-blk
# disk attached and require BOTH the clean success exit (status 33) AND the
# virtio-blk verdict on the serial console. Where `smoke_boot_aarch64.sh`
# proves the kernel boots, this proves the in-kernel virtio-blk driver does the
# real modern virtio-mmio handshake and reads sector 0 off a real device.
#
# Differences from `smoke_boot_aarch64.sh`, all forced by needing a device:
#   * A virtio-blk device is attached over the machine's virtio-mmio transport,
#     backed by a deterministic disk whose sector 0 carries the magic the
#     driver verifies.
#   * `virtio-mmio.force-legacy=false` selects the MODERN (version 2) transport;
#     QEMU's virtio-mmio otherwise defaults to the legacy version 1, which the
#     driver deliberately does not speak.
# Normative: docs/hardware/04-device-memory-and-unified-memory.md,
# docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='claim virtio-blk.ok'
# The crash-recovery ladder, both ends of it. A supervisor that only ever
# restarts is a loop; the give-up line is the one that says the policy has a
# bound, and it is the property a healthy machine never demonstrates on its
# own — so it is asserted rather than left to be noticed.
LADDER_MARKER='claim driver-rebind.ok'
GIVEUP_MARKER='claim driver-giveup.ok'
KERNEL="${1:?usage: virtio_blk_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: virtio_blk_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-virtio-aarch64.log"

# The disk arrives as a read-only build artifact, but QEMU opens the backing
# file read-write. Copy it to a writable scratch path so the device attaches.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/virtio-disk.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -global virtio-mmio.force-legacy=false \
    -kernel "$KERNEL" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
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
grep -qF "$LADDER_MARKER" "$SERIAL_LOG" ||
    fail "the driver that was supposed to crash holding its device did not"
grep -qF "$GIVEUP_MARKER" "$SERIAL_LOG" ||
    fail "a host that crashed every time was not given up on"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33 and virtio-blk verdict present"
