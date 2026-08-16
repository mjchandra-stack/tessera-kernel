#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 MMC/SD boot, AArch64: an SD host controller with a card in it.
#
# What this proves that no other boot does is a **controller whose children are
# devices**. The card is a device the kernel never enumerated, on a bus the
# kernel does not know, put in the resource graph by a ring-3 driver — and
# holding no registers of its own, because every transfer goes through the
# controller. The block class is then served over it to the same client program
# that judges virtio and NVMe, conformance suite and all.
#
# **This boot has no pair, and cannot have one here.** The obvious companion —
# the same kernel and driver against a slot with nothing in it, differing in one
# thing so that a `NO_MEDIUM` answer is attributable to the card — does not
# exist, because on this emulator it would not differ. `sdhci-pci` reports
# card-present in an empty slot, so the kernel's present-state probe reads true
# with no `sd-card` attached and this script's own verdict is what comes back.
# The driver's medium-gone path is therefore unreachable from any QEMU machine
# available to this tree, and what covers it instead is a mock whose card can be
# taken out: `//kernel/sdhci-mock`, shared by the controller core's tests and by
# `//userspace/sd-host:sd_host_medium_test`, which is the driver's own side —
# `NoCard` becoming the block class's `NO_MEDIUM`, a controller fault staying an
# `IoError`, and a card put back not being served until it is identified again.
# One mock for both, so the tier that produces the refusal and the tier that
# translates it cannot drift into disagreeing about when a card is gone.
#
# What is still only proven off-machine is the join: that the driver reached
# from ring 3, over a channel, through the kernel's own mapping of the
# controller, answers the same way. That needs a card that can leave, and this
# emulator has none.
# Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
# docs/drivers/04-embedded-buses-power-and-timekeeping.md ("Clock Controller")

set -u

MARKER='claim sd.ok'
# The claims, separable and asserted apart.
DECLARED_MARKER='claim sd.declared'
CLOCK_MARKER='claim sd.clock-requested'
KERNEL="${1:?usage: sd_boot_aarch64.sh <kernel-image> <disk-image>}"
DISK="${2:?usage: sd_boot_aarch64.sh <kernel-image> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-sd.log"

WRITABLE_DISK="$TMP/sd-card.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

timeout 180s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=sdcard" \
    -device sdhci-pci,id=sd0 \
    -device sd-card,drive=sdcard,id=card0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?


case "$status" in
    33) ;;
    124) fail "boot timed out after 180s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$DECLARED_MARKER" "$CLOCK_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the SD claim did not hold: '$marker'"
done

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, a card was identified and declared into the resource graph as a device behind its controller, and the block class was served over it"
