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

MARKER='TESSERA-STAGE0: KERNEL ALIVE'
ISO="${1:?usage: smoke_boot.sh <iso>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial.log"

timeout 120s qemu-system-x86_64 \
    -M q35 -m 512M -accel "$ACCEL" \
    -cdrom "$ISO" \
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

echo "PASS: clean exit 33 and alive marker present"
