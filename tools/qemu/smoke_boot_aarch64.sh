#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 smoke boot, AArch64: boot the Stage 0 kernel under QEMU and require
# both the clean success exit (status 33) AND the alive marker on the serial
# console — the same contract `smoke_boot.sh` enforces for x86-64, reached by
# a different mechanism.
#
# Differences from the x86-64 script, all forced by the machine:
#   * `-kernel` loads the ELF directly; there is no bootloader and no ISO.
#   * The `virt` machine has no port I/O and so no `isa-debug-exit` device.
#     The exit status comes from Arm semihosting instead, which is why
#     `-semihosting-config` is not optional: without it the kernel's exit
#     call traps as an undefined instruction and the boot hangs after
#     succeeding.
#   * `gic-version` is pinned rather than left to QEMU's default, so the
#     interrupt controller the port programs does not change under us
#     between QEMU releases.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3",
# "CI Topology")

set -u

MARKER='TESSERA-STAGE0: KERNEL ALIVE'
# The data path's declared cost, checked at binding time (D143). Two block
# devices of one class, matched by one manifest entry with one budget, and the
# only difference between the bind and the refusal is how deep each sits — which
# is `docs/drivers/01`'s claim that a class cannot silently miss its budget
# behind a hub. Its own markers, because a manager that stopped accumulating
# would bind everything and report nothing.
RELAY_MARKER='relay: OK'
RELAY_BUDGET_MARKER='was refused BudgetExceeded'
RELAY_THROUGHPUT_MARKER='was refused ThroughputTooLow'
# A hub the kernel cannot identify is not free. The failure this guards against
# is silent by construction: assuming zero would bind the device and look
# entirely healthy.
RELAY_UNDECLARED_MARKER='refused PathUndeclared rather than bound as though it were direct-attached'
KERNEL="${1:?usage: smoke_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64.log"

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
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

# Semihosting SYS_EXIT propagates the kernel's status directly, so the port
# reports 33 on success and 65 on failure to match the x86-64 convention.
# 124 is the timeout.
case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$RELAY_MARKER" "$RELAY_BUDGET_MARKER" "$RELAY_THROUGHPUT_MARKER" \
              "$RELAY_UNDECLARED_MARKER"; do
    grep -q "$marker" "$SERIAL_LOG" || fail "marker '$marker' not found in serial output"
done

echo "PASS: clean exit 33, alive marker present, and a device's data path is a declared cost"
