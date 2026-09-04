#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: a file read off a real ext2 volume, through the whole storage
# stack.
#
# **Two disks, and which is which is the point.** The first is the scratch disk
# `smoke_boot.sh` uses, and it is written to — the block class's conformance
# battery puts a sector on it, and that write lands where an ext2 superblock
# would be. The second is an ext2 volume `mke2fs` built. The kernel's block
# check takes the first virtio mass-storage function and its filesystem check
# takes the second, so the order below is load-bearing rather than incidental.
#
# What passing means: `fs-probe` opened `/hello.txt` **by name**, the service
# resolved it through the ext2 directory, the bytes came off the medium through
# the block service and the driver below it, and every one of them matched what
# the image builder wrote. A check that only asserted a status would pass
# against a service answering OK with a zero-filled buffer.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/storage/02-file-io-and-caching.md

set -u

MARKER='claim fs.read'
# And the stack underneath, which this boot exercises against the *scratch*
# disk exactly as `smoke_boot.sh` does. Asserted here too, because a run where
# the block stack quietly stopped working would otherwise leave this script
# reporting only that the filesystem did — and the filesystem check would be
# the one to fail, several layers from the cause.
BLK_MARKER='claim blk.service'
ISO="${1:?usage: fs_boot_x86_64.sh <iso> <scratch-disk> <ext2-disk>}"
SCRATCH="${2:?usage: fs_boot_x86_64.sh <iso> <scratch-disk> <ext2-disk>}"
EXT2="${3:?usage: fs_boot_x86_64.sh <iso> <scratch-disk> <ext2-disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-fs-x86_64.log"

# Both disks arrive as read-only build artifacts and QEMU opens its backing
# files read-write, so both are copied to writable scratch paths.
W_SCRATCH="${TEST_TMPDIR:-/tmp}/fs-scratch-x86_64.img"
W_EXT2="${TEST_TMPDIR:-/tmp}/fs-ext2-x86_64.img"
cp "$SCRATCH" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"
cp "$EXT2" "$W_EXT2" && chmod u+w "$W_EXT2"

# The CPU model is `smoke_boot.sh`'s and for its reasons: `+x2apic` because the
# kernel requires the local APIC's register-set-in-MSRs form, `+smep,+smap`
# because a feature CI never exercises is a feature CI cannot defend.
#
# **The scratch disk is declared first**, so it takes the lower PCI slot and is
# the function the block check binds. Reversing these two lines hands the ext2
# volume to the check that writes a sector to it.
timeout 180s qemu-system-x86_64 \
    -M q35 -m 512M -accel "$ACCEL" \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -cdrom "$ISO" \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk \
    -drive "file=$W_EXT2,if=none,format=raw,id=volume" \
    -device virtio-blk-pci,drive=volume \
    -serial "file:$SERIAL_LOG" \
    -serial null \
    -display none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
status=$?

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# isa-debug-exit: QEMU exits (value << 1) | 1; the kernel writes 0x10 on
# success (=> 33) and 0x20 on failure (=> 65). 124 is the timeout.
case "$status" in
    33) ;;
    124) fail "boot timed out after 180s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -qF "$BLK_MARKER" "$SERIAL_LOG" ||
    fail "the block stack this one sits on did not hold: '$BLK_MARKER'"
grep -qF "$MARKER" "$SERIAL_LOG" ||
    fail "a file was not read off the ext2 volume: '$MARKER'"

# **And the volume is untouched, checked from outside the machine.** This stack
# only reads, so what `mke2fs` built must still be what is there — a filesystem
# service that wrote where it meant to read would leave a volume `e2fsck`
# rejects, and nothing inside the machine would notice.
if command -v e2fsck >/dev/null 2>&1 || [ -x /usr/sbin/e2fsck ]; then
    PATH="/usr/sbin:/sbin:$PATH" e2fsck -fn "$W_EXT2" >/dev/null 2>&1 ||
        fail "e2fsck rejects the volume after the stack read it"
else
    fail "e2fsck is required: it is what judges the volume this check reads"
fi

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, and /hello.txt read byte-for-byte off an ext2 volume through the block service and a ring-3 driver"
