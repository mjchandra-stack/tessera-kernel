#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: the block class over an NVMe controller.
#
# **The same contract, a different transport, and the same client judging it.**
# `blk-client` is the program that judges the virtio driver, byte for byte, run
# here with the id that carries both the conformance suite and the out-of-line
# round trip. A class contract that needed a different client per transport
# would not be a class contract.
#
# **And a vector per queue.** An NVMe controller raises a different message for
# each I/O queue so its driver never asks which one completed — it waits where
# that queue's completions land. This boot is what made this port's
# message-signalled vectors a block rather than one.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/drivers/02-storage-networking-usb-pcie.md ("Storage")

set -u

MARKER='claim nvme.ok'
# Separable, and each is a thing the virtio path could not show:
#
#   * `vector-per-queue` — both queues' vectors raised messages, so the driver
#     waited in two places and neither port was silent. A controller answering
#     everything on one vector leaves the other at zero.
#   * `conformance-complete` — the block class's own battery, second transport,
#     every rule reached and held.
VECTOR_MARKER='claim nvme.vector-per-queue'
CONFORMANCE_MARKER='claim nvme.conformance-complete'

ISO="${1:?usage: nvme_boot_x86_64.sh <iso> <disk>}"
DISK="${2:?usage: nvme_boot_x86_64.sh <iso> <disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-nvme-x86_64.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
W_DISK="${TEST_TMPDIR:-/tmp}/nvme-disk-x86_64.img"
W_SCRATCH="${TEST_TMPDIR:-/tmp}/nvme-scratch-x86_64.img"
cp "$DISK" "$W_DISK" && chmod u+w "$W_DISK"
cp "$DISK" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"

# The CPU model is `smoke_boot.sh`'s and for its reasons: `+x2apic` because the
# kernel requires the local APIC's register-set-in-MSRs form, `+smep,+smap`
# because a feature CI never exercises is a feature CI cannot defend.
#
# **The smoke machine plus a controller.** The virtio disk stays: every check
# before this one is the same composition it always is, and the ring-3 bus
# driver is judged against the device set it was written for. The NVMe check
# finds its own function by class and subclass rather than by position, so the
# two never contend — each spawns its own manager, and each registers the
# function it wants.
timeout 180s qemu-system-x86_64 \
    -M q35 -m 512M -accel "$ACCEL" \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -cdrom "$ISO" \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk \
    -drive "file=$W_DISK,if=none,format=raw,id=nvm" \
    -device nvme,serial=TESSERA0,drive=nvm \
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

for marker in "$MARKER" "$VECTOR_MARKER" "$CONFORMANCE_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the ring-3 NVMe stack did not hold: '$marker'"
done

# **And the check did not skip.** A boot that stopped attaching the controller
# would otherwise read as a pass the moment somebody removed a marker.
grep -q "nvme: skipped" "$SERIAL_LOG" &&
    fail "the NVMe check skipped: this boot attaches a controller, so it had one to find"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, an NVMe controller driven from ring 3 serving the block class, and a completion on each queue's own vector"
