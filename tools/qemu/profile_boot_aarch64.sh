#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot of a *second configuration*: the AArch64 kernel built from
# `config/profiles/aarch64-lean.profile` instead of the default.
#
# Until this existed, "the sizing is configurable" was proved by a refusal —
# `//tools/checks:config_test` showed that a bad profile does not build, and
# nothing showed that a good one does. A surface nobody has built through is
# one whose second value has never been compiled, linked or run
# (build/README.md, D195).
#
# Three claims, and each one fails differently:
#
#   1. The lean machine boots. Same contract as every other port: clean exit
#      33 and the alive marker, from a kernel whose constants and composition
#      both differ from the one every other check runs.
#   2. What the profile turned off is gone *and says so*. The checks for the
#      dropped programs report themselves skipped rather than failing, which is
#      the difference between a machine that was configured smaller and one
#      that is broken.
#   3. The bytes actually left. The lean image must be smaller than the
#      default one — the claim that turning a component off removes its
#      program rather than only the mention of it. This is also what catches a
#      profile name with no file behind it: `select` would take its default arm
#      and build the default kernel under another name, and the two images
#      would come out identical.
#
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='claim boot.alive'
# The kept half. The lean profile drops the multimedia and USB stacks and keeps
# the block path, so a run where *these* went missing would be one where the
# profile removed more than it was asked to.
STORE_MARKER='claim store.ok'
RELAY_MARKER='claim relay.ok'

LEAN="${1:?usage: profile_boot_aarch64.sh <lean-image> <default-image>}"
DEFAULT="${2:?usage: profile_boot_aarch64.sh <lean-image> <default-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64-lean.log"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# Claim 3 first: it needs no boot, and a lean image that is not actually lean
# makes every other assertion here meaningless rather than merely unproven.
lean_size=$(wc -c < "$LEAN")
default_size=$(wc -c < "$DEFAULT")
if [ "$lean_size" -ge "$default_size" ]; then
    echo "FAIL: the lean image is $lean_size bytes and the default is $default_size" >&2
    echo "The profile did not remove anything. Either the components it turns" >&2
    echo "off are still being linked, or --//config:profile did not select it" >&2
    echo "(a profile name with no file falls back to the default)." >&2
    exit 1
fi

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$LEAN" \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?

case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -qF "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"

for marker in "$STORE_MARKER" "$RELAY_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "marker '$marker' not found — the profile dropped more than it was asked to"
done

# Claim 2. Each dropped stack reports itself skipped. Asserted per subsystem
# rather than by counting "skipped" lines: a count would pass if one subsystem
# were skipped twice and another silently ran.
for subsystem in snd gpu usb; do
    grep -q "^\[.*\] $subsystem: skipped" "$SERIAL_LOG" ||
        grep -q "^$subsystem: skipped" "$SERIAL_LOG" ||
        fail "'$subsystem' did not report itself skipped — the profile did not remove it"
done

echo "PASS: a second profile boots (exit 33), the stacks it drops report themselves" \
     "skipped, the block path it keeps still works, and the image is" \
     "$((default_size - lean_size)) bytes smaller"
