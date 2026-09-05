#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: a file read off a real ext2 volume and two written to it,
# through the whole storage stack.
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
#
# **And then the writes, which this script judges from outside the machine.**
# One went through the service and was not called durable until `Sync` answered;
# the other never became a message at all — the probe stored into its own
# mapping of a file, and what carried those bytes to the medium was the kernel's
# dirty set. Both are searched for in the image after QEMU has exited, and the
# pristine artifact is asserted not to carry them, so finding them means this
# boot put them there.
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
# And the other direction. A volume this stack can only read is one nothing can
# be built on: this says a file was created, written and made durable, and that
# a store into a *mapping* of a file reached the medium as well.
WRITE_MARKER='claim fs.write'
# **And the cache has a ceiling** (D332). The probe walks twelve pages of one
# file twice through a cache that holds eight frames, checking every byte
# against the pattern the image builder wrote. Two claims and both are needed:
# that more pages were supplied than the file has says eviction happened, and
# that every byte was right says eviction dropped the right page. A kernel that
# evicted nothing satisfies the second; one that handed back somebody else's
# frame satisfies the first.
EVICTED_MARKER='claim pagecache.evicted'
PAGES_RIGHT_MARKER='claim pagecache.every-page-right'
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
grep -qF "$WRITE_MARKER" "$SERIAL_LOG" ||
    fail "nothing was written to the ext2 volume: '$WRITE_MARKER'"
for marker in "$EVICTED_MARKER" "$PAGES_RIGHT_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the page cache did not hold its ceiling: '$marker'"
done

# **Durability, checked from outside the machine.** The probe wrote these bytes
# and did not carry on until `Sync` answered, and `Sync` answers only what the
# device said. So after the machine has stopped they must be in the volume — a
# write that reached a cache and no further would not be here. Searching the
# image rather than trusting the guest is the point: the machine that made the
# claim is not the one checking it.
grep -qa 'tessera durable write' "$W_EXT2" ||
    fail "the acknowledged write is not in the volume the machine has stopped using"

# **And the write that was never a message.** The probe stored these bytes into
# its own mapping of the file — the service was told nothing — and then asked
# for a sync. Finding them here means the kernel's dirty set is what the service
# flushed from, because it is the only record those stores left.
grep -qa 'tessera mapped write ok' "$W_EXT2" ||
    fail "a write made through a mapping is not in the volume after a sync"

# And the store made **after** that sync. The page was clean again, so the only
# thing that makes this one visible is the fault the kernel put back when it
# marked the page clean. A kernel that cleaned without re-protecting loses this
# write and nothing else, which is why it is checked separately.
grep -qa 'tessera second mapped ok' "$W_EXT2" ||
    fail "a mapped write made after a sync is lost — the page was not re-protected when it was cleaned"

# **And none of it was there to begin with**, checked against the pristine
# artifact the build produced. Three markers found in a volume that already
# carried them would say nothing at all about this boot.
for marker in 'tessera durable write' 'tessera mapped write ok' 'tessera second mapped ok'; do
    if grep -qa "$marker" "$EXT2"; then
        fail "the pristine volume already carries '$marker' — the build put it there"
    fi
done

# And the volume is still one ext2 recognises. Writing through four layers is
# only worth anything if what comes out the bottom is a filesystem — and this
# is also what says the reads did not scribble: a service that wrote where it
# meant to read leaves a volume `e2fsck` rejects and nothing inside the machine
# notices.
if command -v e2fsck >/dev/null 2>&1 || [ -x /usr/sbin/e2fsck ]; then
    PATH="/usr/sbin:/sbin:$PATH" e2fsck -fn "$W_EXT2" >/dev/null 2>&1 ||
        fail "e2fsck rejects the volume the stack wrote to"
else
    fail "e2fsck is required: it is what judges the volume this check writes"
fi

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, /hello.txt read byte-for-byte off an ext2 volume, an acknowledged write found in the volume after the machine stopped, a mapped write flushed from the page cache, and e2fsck clean"
