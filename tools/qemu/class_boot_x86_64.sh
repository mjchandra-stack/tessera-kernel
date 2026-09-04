#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: the four device classes that are a manager, a driver and a
# client — display, sound, an SD card and encryption.
#
# **One boot for four classes**, because they are one composition four times:
# each binds a device by class, serves its contract to a client holding a single
# channel endpoint, and none of them routes an interrupt. What differs is the
# function each looks for and the word its client must report, and those are
# what the checks state.
#
# Every client here is the program the other machine runs, reporting the word
# that machine expects — and the SD card is judged by `blk-client`, which is the
# same program that judges virtio, NVMe and USB storage. A class contract that
# needed a different client per transport would not be a class contract.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/drivers/02-storage-networking-usb-pcie.md

set -u

GPU_MARKER='claim gpu.ok'
GPU_DREW_MARKER='claim gpu.drew-every-pixel'
GPU_REFUSED_MARKER='claim gpu.refused-not-clipped'
SND_MARKER='claim snd.ok'
SND_PLAYED_MARKER='claim snd.played-periods'
SND_STARVED_MARKER='claim snd.underrun-reported'
SD_MARKER='claim sd.ok'
CRYPTO_MARKER='claim crypto.ok'
CRYPTO_VECTOR_MARKER='claim crypto.standard-vector'
CRYPTO_KEY_MARKER='claim crypto.key-changes-answer'
CRYPTO_REFUSED_MARKER='claim crypto.refused-not-guessed'

ISO="${1:?usage: class_boot_x86_64.sh <iso> <disk>}"
DISK="${2:?usage: class_boot_x86_64.sh <iso> <disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-class-x86_64.log"

# The disks arrive as read-only build artifacts and QEMU opens them read-write.
W_SD="${TEST_TMPDIR:-/tmp}/class-sd-x86_64.img"
W_SCRATCH="${TEST_TMPDIR:-/tmp}/class-scratch-x86_64.img"
cp "$DISK" "$W_SD" && chmod u+w "$W_SD"
cp "$DISK" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"

# The CPU model is `smoke_boot.sh`'s and for its reasons. The virtio disk stays
# for the reason the NVMe and USB boots keep one: every check before these is
# the composition it always was.
#
# `audiodev none` and `cryptodev builtin` are the backends these two devices
# need to exist at all; neither is asked to make a sound or hold a key.
timeout 300s qemu-system-x86_64 \
    -M q35 -m 512M -accel "$ACCEL" \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -cdrom "$ISO" \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk \
    -device virtio-gpu-pci \
    -audiodev none,id=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -drive "file=$W_SD,if=none,format=raw,id=sdcard" \
    -device sdhci-pci,id=sd0 \
    -device sd-card,drive=sdcard,id=card0 \
    -object cryptodev-backend-builtin,id=cryptodev0 \
    -device virtio-crypto-pci,cryptodev=cryptodev0 \
    -serial "file:$SERIAL_LOG" \
    -serial null \
    -display none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
status=$?

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# isa-debug-exit: QEMU exits (value << 1) | 1; the kernel writes 0x10 on
# success (=> 33) and 0x20 on failure (=> 65). 124 is the timeout.
case "$status" in
    33) ;;
    124) fail "boot timed out after 300s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

for marker in "$GPU_MARKER" "$GPU_DREW_MARKER" "$GPU_REFUSED_MARKER" \
              "$SND_MARKER" "$SND_PLAYED_MARKER" "$SND_STARVED_MARKER" \
              "$SD_MARKER" \
              "$CRYPTO_MARKER" "$CRYPTO_VECTOR_MARKER" "$CRYPTO_KEY_MARKER" \
              "$CRYPTO_REFUSED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "a ring-3 class stack did not hold: '$marker'"
done

# **And none of them skipped.** Every marker above is absent from a boot that
# found no device, and so is this line — a boot that silently stopped attaching
# one would otherwise read as a pass the moment somebody removed a marker.
grep -q ": skipped (this machine has no such device)" "$SERIAL_LOG" &&
    fail "a class check skipped: this boot attaches all four devices"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, and four device classes served from ring 3 — a display, a sound card, an SD card and an encryption device"
