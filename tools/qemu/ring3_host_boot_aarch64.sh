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
#
# It also proves the **block class contract** end to end: one client runs the
# class conformance suite against the live driver, and the driver's write path
# is checked from outside the machine — the sector the client wrote is read
# back out of the disk image after QEMU exits. That last check is the one the
# serial console cannot make: a driver and a client that agreed with each other
# about a write that never reached the medium would produce a perfectly happy
# transcript, and only the file on disk can contradict them.
#
# And it proves the **out-of-line path** (D131): the other client creates a
# memory object, fills a whole 512-byte sector, transfers the buffer to the
# driver, gets it back, and reads the sector into it again. Sector 3 is
# checked here byte for byte — all 512, not a magic at the front, because the
# entire claim of the out-of-line path is that it moves more than the 256-byte
# inline payload can. A run that moved the first eight bytes and zeroes after
# them would pass a magic check and fail this one.
#
# This boot attaches a NIC as well as a disk, so the **network class** check
# runs here too (D150). It is asserted in both places rather than only in the
# NIC-only boot: a check that quietly stopped running in one configuration is
# not something an exit status can distinguish from one that never existed.
# Normative: docs/hardware/04-device-memory-and-unified-memory.md,
# docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='ring3-host: OK'
CONFORMANCE_MARKER='ran the block class'"'"'s conformance suite against the live driver and every rule held'
# The out-of-line claim, in the kernel's own words. Checked separately from the
# disk comparison below: this says the two ring-3 programs believe a whole
# sector moved through a memory object, and the disk says whether it did.
GRANT_MARKER='moved a WHOLE 512-byte sector the other way'
# The zero-copy claim. Checked as its own marker rather than folded into the
# one above, because "a sector moved" and "no CPU copied it" are different
# facts and the first went on being true while the second was false.
ZEROCOPY_MARKER='The driver never mapped that buffer'
# Protected memory (D149). Its own marker, and deliberately the clause naming
# *why*: the interesting claim is not that a request failed but that the only
# thing separating it from the one that succeeded was the classification.
PROTECTED_MARKER='the identical request came back refused'
PROTECTED_REASON_MARKER='no authority for protected memory'
# What the client writes, at the sector it writes it to. Sector 2 is zeroed
# padding on the test disk, so a magic found there came from the driver and
# from nowhere else.
WRITE_MAGIC='TESSERAW'
WRITE_SECTOR_OFFSET=1024
# The out-of-line client's sector, and the pattern it fills: 'TESSERAG' then
# byte i xor 0x5a for the remaining 504 (blk-client's `out_of_line_round_trip`).
GRANT_MAGIC='TESSERAG'
GRANT_SECTOR_OFFSET=1536
# The network class (D150), the first of the class rollout. Three markers,
# because the interesting claims are separable: that a ring-3 driver served the
# contract at all, that the frame reached the client in a buffer the driver gave
# away rather than copied, and that the class conformance suite — the same seven
# rules the block class passes — was reached in full against a second class.
NET_CLASS_MARKER='net-class: OK'
NET_CLASS_PUSH_MARKER='the driver SENT it'
NET_CLASS_CONFORMANCE_MARKER='same seven rules, second class'

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
grep -qF "$CONFORMANCE_MARKER" "$SERIAL_LOG" ||
    fail "the block class conformance suite did not pass against the live driver"
grep -qF "$GRANT_MARKER" "$SERIAL_LOG" ||
    fail "the out-of-line round trip did not run"
grep -qF "$ZEROCOPY_MARKER" "$SERIAL_LOG" ||
    fail "the out-of-line transfer was not zero-copy"
grep -qF "$PROTECTED_MARKER" "$SERIAL_LOG" ||
    fail "protected memory was not refused to an unauthorized device"
grep -qF "$PROTECTED_REASON_MARKER" "$SERIAL_LOG" ||
    fail "the protected-memory refusal did not name the missing authority"

for marker in "$NET_CLASS_MARKER" "$NET_CLASS_PUSH_MARKER" "$NET_CLASS_CONFORMANCE_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the network class was not served from ring 3: '$marker'"
done

# The write path, checked from outside the machine. Everything above this is
# the system agreeing with itself.
written=$(dd if="$WRITABLE_DISK" bs=1 skip="$WRITE_SECTOR_OFFSET" count=8 2>/dev/null)
[ "$written" = "$WRITE_MAGIC" ] ||
    fail "the driver's write did not reach the medium (sector 2 holds '$written', wanted '$WRITE_MAGIC')"

# The out-of-line path, checked the same way and to the byte. Built here
# rather than compared against a stored blob so the expectation is legible:
# what the client wrote is a rule, and a rule can be read.
expected=$(mktemp "${TEST_TMPDIR:-/tmp}/grant-expected.XXXXXX")
{
    printf '%s' "$GRANT_MAGIC"
    for i in $(seq 8 511); do
        printf "$(printf '\\%03o' "$((i % 256 ^ 0x5a))")"
    done
} > "$expected"
actual=$(mktemp "${TEST_TMPDIR:-/tmp}/grant-actual.XXXXXX")
dd if="$WRITABLE_DISK" bs=1 skip="$GRANT_SECTOR_OFFSET" count=512 of="$actual" 2>/dev/null
cmp -s "$expected" "$actual" ||
    fail "the out-of-line write did not reach the medium intact (sector 3 differs from the 512-byte pattern the client wrote: $(cmp "$expected" "$actual" 2>&1 | head -1))"

echo "PASS: clean exit 33, ring-3 host verdict present, the block class conformance suite held against the live driver, the sector the driver wrote is on the disk image, a full 512-byte sector moved through a memory object in both directions, and the same buffer classified protected was refused to the device, and a ring-3 network driver pushed a client a frame nobody asked for"
