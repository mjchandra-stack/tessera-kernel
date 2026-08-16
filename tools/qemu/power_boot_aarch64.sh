#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot, AArch64: require the clean success exit (status 33), that three
# ring-3 processes voted on one power domain and a service resolved them, that
# a domain nobody was using fell out of service and was brought back by a real
# interrupt, and that the whole machine stopped and started again with its
# devices suspended leaves-first.
#
# **This test needs no device and no QEMU flag**, which is the point rather
# than a convenience. The wakeup source is the machine's own real-time clock —
# present on every `virt`, on its own interrupt line, and owned by no driver,
# which is what makes it a wake source rather than a device somebody is using. What is being proven is arbitration: that one voter's
# requirement can be weighed against another's, that the highest demand wins,
# and that a thermal ceiling lowering the answer is *reported* rather than
# applied quietly. None of that is a property of any hardware, and a machine
# option would only obscure which part of the system is under test.
#
# Two lines of the marker are the negative check, and they are in the same
# boot rather than a second one: before the thermal vote the same voters
# resolve to full-active with nothing clamped, and after it to retention with
# `clamped_from` naming full-active. Same processes, same domain, one extra
# message — which is stronger evidence that the ceiling did something than a
# separate run with the thermal voter deleted would be, because nothing else
# about the machine differs between the two.
#
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/power/01-power-management.md

set -u

MARKER='claim power.votes-ok'
CLAMP_MARKER='claim power.clamped'
WAKE_MARKER='claim power.wake-ok'
REFUSED_MARKER='claim power.wake-right-required'
SUSPEND_MARKER='claim power.suspend-ok'
ORDER_MARKER='claim power.suspend-order'
KERNEL="${1:?usage: power_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64-power.log"

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

[ "$status" -eq 33 ] || fail "QEMU exited $status (expected 33)"
grep -qF "$MARKER" "$SERIAL_LOG" || fail "no power vote arbitration was reported"
grep -qF "$CLAMP_MARKER" "$SERIAL_LOG" ||
    fail "a thermal ceiling lowered the answer without saying so"
grep -qF "$WAKE_MARKER" "$SERIAL_LOG" ||
    fail "no runtime idle and wake was reported"
grep -qF "$REFUSED_MARKER" "$SERIAL_LOG" ||
    fail "a capability without Rights::WAKE was able to arm a wakeup source"
grep -qF "$SUSPEND_MARKER" "$SERIAL_LOG" || fail "no system suspend and resume was reported"
grep -qF "$ORDER_MARKER" "$SERIAL_LOG" ||
    fail "a bus was allowed to suspend under a live device"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, three voters arbitrated, the clamp was attributed, an idled domain was woken by a real interrupt, and the machine suspended leaves-first"
