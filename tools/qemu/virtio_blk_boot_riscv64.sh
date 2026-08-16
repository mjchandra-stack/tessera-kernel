#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot, RISC-V 64 with a virtio-blk disk attached: require the clean
# success exit (status 33) AND the ring-3 driver's verdict on the console.
# Where `smoke_boot_riscv64.sh` proves the kernel boots, this proves a
# *compiled ring-3 program* drives a real device — the driver holds only a
# capability to the transport and a port for its interrupt, and everything it
# does is a syscall.
#
# The flags that matter, none of them incidental:
#   * `-drive`/`-device virtio-blk-device` attaches a deterministic disk whose
#     sector 0 carries the magic the driver reports back.
#   * `virtio-mmio.force-legacy=false` selects the MODERN (version 2)
#     transport. QEMU's virtio-mmio defaults to the legacy one, which this
#     driver deliberately does not speak — without this the driver reports
#     `BadVersion` and the boot fails, which is how this was found.
#   * `-cpu rva23s64` as everywhere on this port: the tick needs Sstc.
#
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='claim blk.ok'
# The crash-recovery ladder, both ends of it — see the AArch64 script for why
# the give-up line is asserted rather than left to be noticed.
LADDER_MARKER='claim driver-rebind.ok'
GIVEUP_MARKER='claim driver-giveup.ok'
KERNEL="${1:?usage: virtio_blk_boot_riscv64.sh <kernel-elf> <disk-image>}"
DISK="${2:?usage: virtio_blk_boot_riscv64.sh <kernel-elf> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-riscv64-blk.log"

# The disk arrives as a read-only build artifact, but QEMU opens the backing
# file read-write; copy it somewhere writable so the run cannot be affected by
# (or affect) the artifact.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/virtio-disk-riscv64.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

timeout 120s qemu-system-riscv64 \
    -M virt -cpu rva23s64 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -global virtio-mmio.force-legacy=false \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot
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

grep -q "$MARKER" "$SERIAL_LOG" ||
    fail "marker '$MARKER' not found — the ring-3 driver did not read the disk"
grep -qF "$LADDER_MARKER" "$SERIAL_LOG" ||
    fail "the driver that was supposed to crash holding its device did not"
grep -qF "$GIVEUP_MARKER" "$SERIAL_LOG" ||
    fail "a host that crashed every time was not given up on"

echo "PASS: clean exit 33 and the ring-3 driver read the disk"
