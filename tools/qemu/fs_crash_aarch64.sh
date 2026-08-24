#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3: an acknowledged write survives the machine being killed outright.
#
# **The cut is the point.** `fs_boot_aarch64.sh` searches the volume after the
# machine has stopped *cleanly*, which cannot tell a write that reached the
# medium from one a tidy shutdown pushed there on the way out. Here the machine
# is killed with SIGKILL — no exit path, no teardown, nothing given a chance to
# flush — and the bytes must already be in the volume.
#
# The timing needs no guessing. The claim being checked is precisely that the
# bytes leave the machine before `Sync` is answered, so this watches the image
# file from outside and kills QEMU **the instant they appear**. If the claim
# holds, the cut lands after they are on the medium no matter when it lands; if
# it does not, they never appear and the deadline fails the check.
#
# What this does NOT assert is metadata consistency after the cut, and it must
# not: ext2 has no journal, and a machine killed mid-update can leave an inode
# and a bitmap disagreeing. `e2fsck` is therefore deliberately not run here —
# it is run by `fs_boot_aarch64.sh`, on the orderly stop, where it is a claim
# this filesystem can actually make. Asserting it here would be asserting
# something ext2 has never promised.
# Normative: docs/storage/01-storage-stack.md ("Testing")

set -u

KERNEL="${1:?usage: fs_crash_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
SCRATCH="${2:?usage: fs_crash_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
EXT2="${3:?usage: fs_crash_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-fs-crash-aarch64.log"
DURABLE='tessera durable write'

W_SCRATCH="${TEST_TMPDIR:-/tmp}/fs-crash-scratch.img"
W_EXT2="${TEST_TMPDIR:-/tmp}/fs-crash-ext2.img"
cp "$SCRATCH" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"
cp "$EXT2" "$W_EXT2" && chmod u+w "$W_EXT2"

fail() {
    echo "FAIL: $1" >&2
    [ -f "$SERIAL_LOG" ] && sed -n '1,200p' "$SERIAL_LOG" >&2
    exit 1
}

# The volume must not already contain the bytes, or the watch below would fire
# before the machine had written anything and the check would pass on the image
# builder's work. Asserted rather than assumed.
if grep -qa "$DURABLE" "$W_EXT2"; then
    fail "the pristine volume already contains the durable bytes"
fi

# `cortex-a76` rather than the `cortex-a72` this used to run: the kernel turns
# on privileged-access-never (D247), which arrived in ARMv8.1 and which a v8.0
# part like the a72 reports as absent. A check that never exercises the feature
# cannot defend it — the same reason the x86-64 boot asks for `+smep,+smap`.
qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a76 -m 512M -accel "$ACCEL" \
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
    -semihosting-config enable=on,target=native &
qemu=$!

# Watch for the bytes and cut the moment they land. Bounded, because a machine
# that never writes them must fail rather than hang.
seen=false
for _ in $(seq 1 1200); do
    if grep -qa "$DURABLE" "$W_EXT2"; then
        seen=true
        break
    fi
    kill -0 "$qemu" 2>/dev/null || break
    sleep 0.1
done

if [ "$seen" = true ]; then
    kill -9 "$qemu" 2>/dev/null
fi
wait "$qemu" 2>/dev/null
status=$?

[ "$seen" = true ] ||
    fail "the durable bytes never reached the volume (machine exited $status)"

# The machine is gone and was given no chance to tidy up. What is on the medium
# now is what was on it at the instant of the cut.
grep -qa "$DURABLE" "$W_EXT2" ||
    fail "the durable bytes left the volume when the machine was killed"

echo "PASS: an acknowledged write was on the medium before the machine was killed outright (SIGKILL, no shutdown path)"
