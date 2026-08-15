#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 smoke boot, ARM 32-bit: boot the Stage 0 kernel under QEMU and require
# both the clean success exit (status 33) AND the alive marker on the serial
# console — the same contract the x86-64 and AArch64 scripts enforce, reached
# by a third mechanism.
#
# Differences from the other two scripts, all forced by the machine:
#   * `-kernel` is given the **flat image**, not the ELF. Handed an ELF, QEMU
#     treats the file as bare metal: it jumps to the entry point with every
#     register zero and builds no device tree. Handed a raw binary it takes
#     the Linux path, writing a stub that puts the tree's address in r2 —
#     which is the only way this port gets a memory map.
#   * `-semihosting-config` is not optional, as on AArch64: the exit status
#     comes from a semihosting call, and without the flag it traps as an
#     undefined instruction and the boot hangs after succeeding.
#   * `-cpu cortex-a15` is pinned rather than left to QEMU's default. The port
#     uses LPAE, which `docs/hardware/01` requires over the older short
#     descriptor format, and a CPU model without it is a different machine.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3",
# "CI Topology")

set -u

MARKER='TESSERA-STAGE0: KERNEL ALIVE'
KERNEL="${1:?usage: smoke_boot_arm32.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-arm32.log"

timeout 120s qemu-system-arm \
    -M virt -cpu cortex-a15 -m 256M -accel "$ACCEL" \
    -kernel "$KERNEL" \
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

# Semihosting SYS_EXIT_EXTENDED propagates the kernel's status directly, so the
# port reports 33 on success and 65 on failure to match every other port. 124
# is the timeout.
case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"

echo "PASS: clean exit 33 and alive marker present"
