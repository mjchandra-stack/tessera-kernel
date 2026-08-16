#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 hotplug boot, AArch64: boot with a virtio-blk-pci device behind a
# PCIe root port, wait for the kernel to say it is holding the device, then
# **pull the device out of the running machine** over QMP and require the
# kernel to notice and revoke every capability naming it.
#
# This is the first script here that talks to QEMU while it runs. Every other
# one starts a machine, waits for it to exit, and reads what it left behind —
# which cannot express "something happened to the hardware halfway through".
# Removal is not a state a machine can be booted into; it is an event, and an
# event needs somebody outside to cause it.
#
# **What makes this a check rather than an assertion.** The kernel's own
# bookkeeping would agree with itself whatever it did. Here QEMU really removes
# the function: its config space stops answering, which is not something the
# kernel can arrange for itself. The kernel's graph agrees with the machine
# only because it acted.
#
# Normative: docs/drivers/01-driver-framework.md ("Device Lifecycle"),
# docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

ARMED_MARKER='claim hotplug.armed'
MARKER='claim hotplug.ok'
KERNEL="${1:?usage: hotplug_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: hotplug_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-hotplug.log"
# **Not under $TMP.** A unix socket path is capped at 108 bytes and Bazel's
# test tmpdir is comfortably longer than that on its own, so the socket gets a
# short directory of its own rather than inheriting one that cannot hold it.
QMP_DIR="$(mktemp -d /tmp/tshp.XXXXXX)"
QMP_SOCK="$QMP_DIR/qmp.sock"

WRITABLE_DISK="$TMP/hotplug-disk-aarch64.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"
: > "$SERIAL_LOG"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# **A switch, not a card.** The topology is
#
#     pcie.0 → pcie-root-port(rp0) → x3130-upstream(up0)
#            → xio3130-downstream(dn0) → virtio-blk-pci
#
# and what gets pulled is `up0`, three levels of bridge deep. Two things make
# that the right shape. The root port cannot itself be unplugged — it sits on
# `pcie.0`, which does not support hotplug — but `up0` is plugged into the root
# port's slot, and that slot does. And unplugging a switch is a **subtree**
# leaving: QEMU's delete recurses into child buses, so the downstream port and
# the endpoint below it go in the same event, and three functions stop
# answering config space at once.
#
# That is what makes this a check of the graph's topology rather than of one
# node: a flat resource graph removes what it was told about and leaves the
# other two behind, resolving and mapping for hardware that is not there.
#
# The kernel gates its check on finding three bridges and a device below them,
# so the machine and the check agree about what kind of run this is without
# either being told.
timeout 180s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=hotdisk" \
    -device pcie-root-port,id=rp0,slot=0 \
    -device x3130-upstream,id=up0,bus=rp0 \
    -device xio3130-downstream,id=dn0,bus=up0,chassis=1,slot=0 \
    -device virtio-blk-pci,bus=dn0,drive=hotdisk,id=victim \
    -qmp "unix:$QMP_SOCK,server=on,wait=off" \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    rm -rf "$QMP_DIR"
}
trap cleanup EXIT

# Wait for the kernel to say it is holding the device. Pulling it before that
# would test nothing: the check has to be watching when the hardware goes.
waited=0
until grep -qF "$ARMED_MARKER" "$SERIAL_LOG" 2>/dev/null; do
    kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU exited before arming"
    sleep 0.2
    waited=$((waited + 1))
    [ "$waited" -lt 600 ] || fail "the kernel never armed the removal check"
done

[ -S "$QMP_SOCK" ] || fail "QEMU exposed no QMP socket"

# Ask for the switch to go.
#
# **This is a request, not an order.** `device_del` on something in a root
# port's slot makes the port raise an eject and *wait* for the guest to
# acknowledge it through the slot control register — the software using the
# hardware is the only thing that knows whether it is mid-transfer. The kernel
# answers at the root port (the slot the switch sits in, not the switch's own),
# and only then does QEMU de-energize the slot and take the whole subtree.
#
# So what this proves is an **eject the guest acknowledged**, not a surprise
# removal — on this bus there is no such thing as the latter.
printf '%s\n%s\n' \
    '{"execute":"qmp_capabilities"}' \
    '{"execute":"device_del","arguments":{"id":"up0"}}' |
    timeout 30s socat - "UNIX-CONNECT:$QMP_SOCK" > "$TMP/qmp.log" 2>&1 ||
    fail "could not drive QMP (is socat installed?)"

grep -q '"error"' "$TMP/qmp.log" &&
    fail "QMP refused the removal: $(cat "$TMP/qmp.log")"

wait "$QEMU_PID"
status=$?
trap - EXIT
rm -rf "$QMP_DIR"

case "$status" in
    33) ;;
    124) fail "boot timed out after 180s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -qF "$MARKER" "$SERIAL_LOG" ||
    fail "the kernel did not notice the switch leaving, or removed it without its subtree"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, and a PCIe switch pulled out of the running machine took its downstream port and the endpoint below it — one removal, three nodes — revoked from a holder that had not asked, while the root port it hung off stayed"
