#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 smoke boot: boot the Stage 0 image under QEMU and require both the
# clean success exit (isa-debug-exit status 33) AND the alive marker on the
# serial console. TCG by default for determinism; set
# TESSERA_QEMU_ACCEL=kvm (bazel test --config=kvm) for local speed.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3",
# "CI Topology")

set -u

MARKER='claim boot.alive'
# The driver framework on this port: a ring-3 manager binds a real PCI function
# by class to a ring-3 driver that is a compiled program rather than a blob. Its
# own marker, because a check that stopped running is not something an exit
# status can distinguish from one that never existed.
BIND_MARKER='claim driver-bind.ok'
# The half a manager handing over the wrong thing cannot fake: the driver read
# past the first page of its window and agreed with what the kernel reads at
# that physical address.
BIND_WINDOW_MARKER='claim driver-bind.window'
# The verified image store (D146). Two markers, because the interesting half of
# a verifier is the half that says no: the first asserts a container mounted
# against the anchor this kernel is compiled to trust, the second that the same
# code refused an altered one — a check with only the first would pass against
# a `mount` that returned success unconditionally.
#
# Matched as claim keys rather than as a phrase out of the verdict's prose:
# the prose is what the kernel says, not what this asserts, and a reworded
# sentence used to break the check silently.
STORE_MARKER='claim store.ok'
STORE_REFUSAL_MARKER='claim store.refused'
# PCI as a bus driver (D151). Three markers, because the claims are separable:
# that a ring-3 program walked the bus at all, that the functions in the
# resource graph were put there by it rather than by the kernel, and that a
# driver reached its own configuration space and nothing adjacent.
PCI_BUS_MARKER='claim pci-bus.ok'
PCI_BUS_DECLARED_MARKER='claim pci-bus.declared'
PCI_BUS_CONFIG_MARKER='claim pci-bus.own-config'
ISO="${1:?usage: smoke_boot.sh <iso> <disk-image>}"
DISK="${2:?usage: smoke_boot.sh <iso> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/smoke-disk-x86_64.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 120s qemu-system-x86_64 \
    -M q35 -m 512M -accel "$ACCEL" \
    -cdrom "$ISO" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk \
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
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
grep -qF "$BIND_MARKER" "$SERIAL_LOG" ||
    fail "the ring-3 device manager did not bind a PCI device to a ring-3 driver"
grep -qF "$BIND_WINDOW_MARKER" "$SERIAL_LOG" ||
    fail "the driver did not read past the first page of its own window"

for marker in "$STORE_MARKER" "$STORE_REFUSAL_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "marker '$marker' not found in serial output"
done


for marker in "$PCI_BUS_MARKER" "$PCI_BUS_DECLARED_MARKER" "$PCI_BUS_CONFIG_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "PCI was not enumerated from ring 3: '$marker'"
done

echo "PASS: clean exit 33, alive marker present, the image store is verified, and PCI was enumerated by a ring-3 bus driver"
