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

MARKER='claim boot.alive'

# The root task, on the port that **completes the matrix** (D263). All five
# machines in this tree run this one program now, from this one source.
#
# Every marker the other four assert, because the claim is that the run is the
# same run: a channel this program made, a capability its parent chose, a child
# that spoke on it, two children runnable at once, a service supervised to a
# clean start and one given up on, and a port it made itself. `roottask.framework`
# is absent here as on RISC-V 32 -- this image carries no manager and no driver,
# and a root task composes what it can rather than pretending.
ROOTTASK_MARKERS=(
    'claim roottask.channel-created'
    # A child told what to work on, and refusing in a vocabulary its parent
    # reads (D302). Both fail apart: `arguments` is the path echoed back
    # intact, `exit-status` is the same program refusing two other legs with
    # two different statuses.
    'claim roottask.arguments'
    'claim roottask.exit-status'
    # Output addressed to a contract rather than to the kernel's console
    # (D303): a third process collected it and the composer matched the bytes.
    'claim roottask.diagnostics'
    'claim roottask.granted'
    'claim roottask.child-spoke'
    'claim roottask.concurrent'
    'claim roottask.supervised'
    'claim roottask.reclaimed'
    'claim roottask.port'
)
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

for marker in "${ROOTTASK_MARKERS[@]}"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the root task did not compose the system here: '$marker'"
done

for marker in "$STORE_MARKER" "$STORE_REFUSAL_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "marker '$marker' not found in serial output"
done

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, alive marker present, and the image store is verified"
