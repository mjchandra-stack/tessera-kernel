#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 smoke boot, RISC-V 64: boot the Stage 0 kernel under QEMU and require
# both the clean success exit (status 33) AND the alive marker on the serial
# console — the same contract the x86-64 and AArch64 scripts enforce, reached
# by a third mechanism.
#
# Differences from the other two scripts, all forced by the machine:
#   * `-kernel` loads the ELF and QEMU's default firmware (OpenSBI) starts it
#     in S-mode. There is no bootloader to build and no ISO, and — unlike
#     AArch64 — no image header is needed to make the firmware supply a device
#     tree, because supplying one is part of the SBI boot convention.
#   * The exit status comes from the `virt` machine's SiFive test finisher, a
#     plain MMIO register. Nothing has to be enabled on the command line for
#     it, so there is no counterpart to the AArch64 script's
#     `-semihosting-config`.
#   * `-cpu rva23s64` is pinned rather than left to QEMU's default. The port
#     targets the RVA23 profile and takes its timer tick from Sstc, a
#     supervisor-writable compare register that profile mandates; QEMU's
#     generic default CPU is a different machine, and the port refuses to
#     silently fall back to the firmware timer path on one
#     (docs/lifecycle/04, "No Silent Fallback").
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3",
# "CI Topology")

set -u

MARKER='TESSERA-STAGE0: KERNEL ALIVE'
UMODE_MARKER='umode: kernel unreachable from U-mode'
KERNEL="${1:?usage: smoke_boot_riscv64.sh <kernel-elf>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-riscv64.log"

timeout 120s qemu-system-riscv64 \
    -M virt -cpu rva23s64 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot
status=$?

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# The test finisher exits QEMU with the status the kernel puts in the upper
# half-word, so the port reports 33 on success and 65 on failure to match the
# other two. 124 is the timeout.
case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"

# The privilege boundary is asserted separately from the exit status. The
# kernel already exits 65 if any U-mode check fails, so this does not catch a
# *failing* check — it catches a check that stopped running, which an exit
# status cannot distinguish from one that never existed.
grep -q "$UMODE_MARKER" "$SERIAL_LOG" ||
    fail "marker '$UMODE_MARKER' not found — the U-mode checks did not run"

echo "PASS: clean exit 33, alive marker, and U-mode checks present"
