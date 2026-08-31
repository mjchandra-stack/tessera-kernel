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
# **And the program that was never in the image.** `//userspace/disk-program` is
# in no store, no accessor and no kernel image — the build puts it on the
# volume and nothing else carries it — so a boot that emits this claim ran
# something it was not shipped with, which is what self-hosting starts as.
EXEC_MARKER='claim fs.exec'
# A program this machine compiled, from a source on the volume, then ran
# (D304). Distinct from `fs.exec`, which is about an image the *build* put on
# the volume: this one is about an image that did not exist when the machine
# started.
COMPILED_MARKER='claim fs.compiled'
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

# `cortex-a76` rather than the `cortex-a72` this used to run: the kernel turns
# on privileged-access-never (D247), which arrived in ARMv8.1 and which a v8.0
# part like the a72 reports as absent. A check that never exercises the feature
# cannot defend it — the same reason the x86-64 boot asks for `+smep,+smap`.
# **The network backend every boot with a NIC must use.** The flow-service
# check runs wherever there is one, and it needs all three: IPv4 and IPv6 named
# explicitly, because `ipv6=on` alone turns IPv4 off (D279), and a TCP peer,
# because `guestfwd` behind a host command is the only deterministic one this
# backend offers (D280). A boot that attached a plainer NIC ran the check
# against a network that could not answer it.
NETDEV='user,id=n0,ipv4=on,ipv6=on,guestfwd=tcp:10.0.2.100:9-cmd:/bin/cat'

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a76 -m 512M -accel "$ACCEL" \
    -global virtio-mmio.force-legacy=false \
    -kernel "$KERNEL" \
    -drive "file=$W_EXT2,if=none,format=raw,id=hd1" \
    -device virtio-blk-device,drive=hd1 \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
    -netdev "$NETDEV" \
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
grep -qF "$EXEC_MARKER" "$SERIAL_LOG" ||
    fail "a program was not run off the volume — the exec marker is absent"
grep -qF "$COMPILED_MARKER" "$SERIAL_LOG" ||
    fail "the machine did not compile a source into a program and run it"

# **And the program it made is on the volume, checked from outside.** The
# machine says it wrote one; this is the image saying so. `built.elf` is in no
# build artifact and on no pristine image — the pristine copy is asserted not
# to have it below, so finding it here means this boot put it there.
PATH="/usr/sbin:/sbin:$PATH" debugfs -R "ls -l /" "$W_EXT2" 2>/dev/null |
    grep -q 'built\.elf' ||
    fail "the program the machine compiled is not on the volume"
if PATH="/usr/sbin:/sbin:$PATH" debugfs -R "ls -l /" "$EXT2" 2>/dev/null |
    grep -q 'built\.elf'; then
    fail "the pristine volume already carries built.elf — the build put it there"
fi

# **Durability, checked from outside the machine.** The client wrote these
# bytes and did not carry on until `Sync` answered, and `Sync` answers only
# what the device said. So after the machine has stopped, they must be in the
# volume — a write that reached a cache and no further would not be here.
# Searching the image rather than trusting the guest is the point: the machine
# that made the claim is not the one checking it.
grep -qa 'tessera durable write' "$W_EXT2" ||
    fail "the acknowledged write is not in the volume the machine has stopped using"

# **And the write that was never a message.** The client stored these bytes
# into its own mapping of the file — the service was told nothing — and then
# asked for a sync. Finding them here means the kernel's dirty set is what the
# service flushed from, because it is the only record those stores left.
grep -qa 'tessera mapped write ok' "$W_EXT2" ||
    fail "a write made through a mapping is not in the volume after a sync"

# And the store made **after** that sync. The page was clean again, so the only
# thing that makes this one visible is the fault the kernel put back when it
# marked the page clean. A kernel that cleaned without re-protecting loses this
# write and nothing else — which is why it is checked separately.
grep -qa 'tessera second mapped ok' "$W_EXT2" ||
    fail "a mapped write made after a sync is lost — the page was not re-protected when it was cleaned"

# And the volume is still one ext2 recognises. Writing through four layers is
# only worth anything if what comes out the bottom is a filesystem.
if command -v e2fsck >/dev/null 2>&1 || [ -x /usr/sbin/e2fsck ]; then
    PATH="/usr/sbin:/sbin:$PATH" e2fsck -fn "$W_EXT2" >/dev/null 2>&1 ||
        fail "e2fsck rejects the volume the stack wrote to"
else
    fail "e2fsck is required: it is what judges the volume this check writes"
fi

# **The program is on the volume and nowhere else.** Checked from outside the
# machine, against the two artifacts themselves: its marker is in the ext2
# image the build wrote and absent from the kernel image that ran it. A boot
# that ran a program it was carrying all along would pass every marker above.
PROGRAM_MARK='tessera program off the volume'
grep -qaF "$PROGRAM_MARK" "$W_EXT2" ||
    fail "the program the check ran is not on the volume it was supposed to come from"
grep -qaF "$PROGRAM_MARK" "$KERNEL" &&
    fail "the program the check ran is inside the kernel image — it was not read off the volume"

echo "PASS: clean exit 33, a file read byte-for-byte through the stack, a program read off the volume and run, a source compiled here into a program this machine then ran, an acknowledged write found in the volume after the machine stopped, a mapped write flushed from the page cache, and e2fsck clean"
