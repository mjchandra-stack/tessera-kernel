#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 sound boot, AArch64: a virtio-sound device, one stream kept fed and
# one deliberately abandoned.
#
# What this proves that no other boot does is a **device that is never
# finished**. Everything else here answers a request and stops. A playback
# stream is a standing obligation: the device consumes periods at the rate of
# the sound and plays silence the moment there is nothing to consume, and
# nothing fails while that happens.
#
# Which is why there are two streams: one still holding periods, which must
# report no gap, and one primed the same way and then abandoned, which must
# drain and be *reported* as having gapped. Silence is what a broken audio path
# produces too, so a check that only played a tone would pass against a driver
# that dropped every period on the floor.
#
# What this does NOT prove is that a stream can be kept fed. The emulated
# device consumes faster than a client supplying one period per syscall round
# trip, so neither stream stays ahead of it for long — see D158.
#
# The backend is `none`: a null audiodev consumes at real time and plays
# nowhere, which is exactly what is wanted. What is being tested is the driver,
# not the host's speakers.
# Normative: docs/drivers/03-graphics-display-media-sensors-ai.md ("Audio")

set -u

MARKER='claim snd.ok'
# The claims, separable and asserted apart.
CLEAN_MARKER='claim snd.played-periods'
STARVED_MARKER='claim snd.underrun-reported'
CLASS_MARKER='claim snd.class-served'
KERNEL="${1:?usage: snd_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-snd.log"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

timeout 300s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -audiodev none,id=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?

case "$status" in
    33) ;;
    124) fail "boot timed out after 300s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$CLASS_MARKER" "$CLEAN_MARKER" "$STARVED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the audio claim did not hold: '$marker'"
done

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, the audio class served over a virtio-sound device, a stream with periods queued reported no gap and an abandoned one drained and was reported as having gapped"
