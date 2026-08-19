#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3: a file read off a real ext2 volume, through the whole storage stack.
#
# **Two disks, and which is which is the point.** The first is the scratch disk
# every other check uses, and it is written to — the out-of-line round trip
# puts a sector on it, and that write lands where an ext2 superblock would be.
# The second is an ext2 volume `mke2fs` built. The kernel's filesystem check
# registers only the second, so the two never meet.
#
# What passing means: `fs-client` opened `/hello.txt` **by name**, the service
# resolved it through the ext2 directory, the bytes came off the medium through
# the block service and the driver below it, and every one of them matched what
# the image builder wrote. A check that only asserted a status would pass
# against a service answering OK with a zero-filled buffer.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='claim fs.read'
KERNEL="${1:?usage: fs_boot_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
SCRATCH="${2:?usage: fs_boot_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
EXT2="${3:?usage: fs_boot_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-fs-aarch64.log"

# Both disks arrive as read-only build artifacts and QEMU opens its backing
# files read-write, so both are copied to writable scratch paths.
W_SCRATCH="${TEST_TMPDIR:-/tmp}/fs-scratch.img"
W_EXT2="${TEST_TMPDIR:-/tmp}/fs-ext2.img"
cp "$SCRATCH" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"
cp "$EXT2" "$W_EXT2" && chmod u+w "$W_EXT2"

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -global virtio-mmio.force-legacy=false \
    -kernel "$KERNEL" \
    -drive "file=$W_EXT2,if=none,format=raw,id=hd1" \
    -device virtio-blk-device,drive=hd1 \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=n0 \
    -device virtio-net-device,netdev=n0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?

fail() {
    echo "FAIL: $1" >&2
    [ -f "$SERIAL_LOG" ] && sed -n '1,200p' "$SERIAL_LOG" >&2
    exit 1
}

[ "$status" -eq 33 ] || fail "expected clean exit 33, got $status"
grep -qF "$MARKER" "$SERIAL_LOG" || fail "the filesystem read marker is absent"
echo "PASS: clean exit 33, and a file was opened by name on an ext2 volume and read byte-for-byte through the block service and its driver"
