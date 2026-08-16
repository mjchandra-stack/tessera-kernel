#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 GPIO boot, AArch64: a PL061, and a button pressed from outside.
#
# Two things here that no other boot does.
#
# A **platform bus walked from ring 3**. Every device driven here so far was
# found by something privileged: the kernel read the device tree, or enumerated
# PCI, and only then did anything unprivileged get involved. Here a ring-3 bus
# controller maps the machine's own description as its bus capability's window
# — the same relationship pci-bus has to ECAM — walks it, and declares what it
# finds, bounded by the memory window and the interrupt lines that capability
# carries. The kernel's only remaining part is routing the line, which it does
# by asking the graph rather than by knowing what a PL061 is.
#
# An **interrupt no interrupt controller can see**. Eight lines share one
# output, so which of them fired is in a status register and known only to
# whoever read it. The driver hands each watching client a capability to its own
# line, and this script presses the button `virt` wires to line 3 — the
# machine's own device tree says `gpio-keys/poweroff` is `<&pl061 3 0>`, and QMP
# `system_powerdown` is what presses it.
#
# The client watching line 5 must **not** wake. That is the load-bearing half:
# a mechanism that broadcast, or a driver reading the raw status instead of the
# masked one, would wake both, and neither client could tell.
# Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
# ("GPIO And Pin Control")

set -u

MARKER='claim gpio.ok'
ARMED_MARKER='claim gpio.armed'
# The claims, separable and asserted apart.
PLATFORM_MARKER='claim gpio.nothing-privileged'
DESCRIPTION_MARKER='claim gpio.read-devicetree'
GRANT_MARKER='claim gpio.per-line-capability'
OUTSIDE_MARKER='claim gpio.pressed-from-outside'
KERNEL="${1:?usage: gpio_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-gpio.log"
# Short and outside the sandbox tree: a UNIX socket path is bounded at 108
# bytes and a Bazel sandbox path spends most of that on its own.
QMP_DIR="$(mktemp -d /tmp/tsgp.XXXXXX)"
QMP_SOCK="$QMP_DIR/qmp.sock"
: > "$SERIAL_LOG"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
    exit 1
}

qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -qmp "unix:$QMP_SOCK,server=on,wait=off" \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native &
QEMU_PID=$!

# Wait until there is something to hear the press. Pressing before the clients
# hold their interrupt objects would prove nothing about who was woken.
waited=0
until grep -qF "$ARMED_MARKER" "$SERIAL_LOG" 2>/dev/null; do
    kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU exited before arming"
    sleep 0.2
    waited=$((waited + 1))
    [ "$waited" -lt 900 ] || fail "the kernel never armed the GPIO check"
done

[ -S "$QMP_SOCK" ] || fail "QEMU exposed no QMP socket"

# **The press comes from outside the machine.** `system_powerdown` on `virt`
# does not power anything down by itself: it pulses the `gpio-key` device wired
# to PL061 input line 3, and what happens next is entirely the guest's.
printf '%s\n%s\n' \
    '{"execute":"qmp_capabilities"}' \
    '{"execute":"system_powerdown"}' |
    timeout 30s socat - "UNIX-CONNECT:$QMP_SOCK" > "$TMP/qmp.log" 2>&1 ||
    fail "could not drive QMP (is socat installed?)"

grep -q '"error"' "$TMP/qmp.log" &&
    fail "QMP refused the button press: $(cat "$TMP/qmp.log")"

wait "$QEMU_PID"
status=$?
rm -rf "$QMP_DIR"

case "$status" in
    33) ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$PLATFORM_MARKER" "$DESCRIPTION_MARKER" "$GRANT_MARKER" "$OUTSIDE_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the GPIO claim did not hold: '$marker'"
done

echo "PASS: clean exit 33, a ring-3 controller walked the machine's description and declared what it found, and a button pressed from outside woke the one client holding that line's interrupt object"
