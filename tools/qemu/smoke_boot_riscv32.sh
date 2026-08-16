#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 smoke boot, RISC-V 32: boot the Stage 0 kernel under QEMU and require
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
#   * No `-cpu` override, unlike the 64-bit script. The RVA profiles are
#     64-bit only, so there is no 32-bit RVA23 model to pin; QEMU's default
#     `rv32` CPU implements Sstc, which is what this port's timer needs and
#     what it refuses to silently fall back from (docs/lifecycle/04, "No
#     Silent Fallback"). If a future QEMU drops Sstc from that model the boot
#     fails on an illegal instruction rather than degrading quietly.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3",
# "CI Topology")

set -u

MARKER='claim boot.alive'
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
KERNEL="${1:?usage: smoke_boot_riscv32.sh <kernel-elf>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-riscv32.log"

timeout 120s qemu-system-riscv32 \
    -M virt -m 256M -accel "$ACCEL" \
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

for marker in "$STORE_MARKER" "$STORE_REFUSAL_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "marker '$marker' not found in serial output"
done

echo "PASS: clean exit 33, alive marker present, and the image store is verified"
