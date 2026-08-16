#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 crypto boot, AArch64: a cipher checked against a published standard.
#
# **The right answer to this one was decided in 2001**, by NIST SP 800-38A. A
# ring-3 client encrypts that document's vector and compares what comes back
# against the ciphertext it says the vector becomes. That is the strongest kind
# of check available anywhere in this tree — stronger than the display's
# screendump, because the screendump proves the guest drew what it meant to and
# this proves the guest was *right*.
#
# It has to be. A cipher's output cannot be inspected: bytes encrypted with the
# wrong key, the wrong mode, or not encrypted at all are indistinguishable from
# correct ones, and every report the driver makes — the session was created, the
# operation completed — is made identically by all of them. Nothing the guest
# says about its own encryption is worth anything on its own.
#
# This script's own contribution is the second half: **it greps the entire
# serial log for the key**. A driver that traced its key material would pass
# every functional check in the machine and fail here, which is the only place
# that mistake is visible.
# Normative: docs/security/02-cryptography-and-key-management.md
# ("Crypto Agility")

set -u

MARKER='crypto: OK'
# The claims, separable and asserted apart.
CLASS_MARKER='served the CRYPTO CLASS over it'
STANDARD_MARKER='THE CIPHERTEXT THE STANDARD PUBLISHES'
KEY_MARKER='CHANGE THE ANSWER'
REFUSED_MARKER='REFUSED RATHER THAN GUESSED AT'

KERNEL="${1:?usage: crypto_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-crypto.log"
: > "$SERIAL_LOG"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

timeout 300s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -object cryptodev-backend-builtin,id=cryptodev0 \
    -device virtio-crypto-pci,cryptodev=cryptodev0 \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?

# **The key check comes first, and runs whatever the boot did.** A leaked key
# matters exactly as much on a boot that failed, and a script that checked the
# exit code first would step over the evidence on its way to reporting
# something less important.
#
# Every rendering a driver might plausibly emit it in: lower- and upper-case
# hex, hex with the separators people put between pairs, the raw bytes, and —
# the one that actually happens on this machine — the 64-bit words a driver
# gets by handing a buffer to the debug sink, which come out little-endian and
# in the wrong order to match the key written left to right.
KEY_HEX='2b7e151628aed2a6abf7158809cf4f3c'
KEY_HEX_UPPER=$(printf '%s' "$KEY_HEX" | tr 'a-f' 'A-F')
KEY_SPACED='2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c'
KEY_COLONS=$(printf '%s' "$KEY_SPACED" | tr ' ' ':')
KEY_WORD_LOW='a6d2ae2816157e2b'
KEY_WORD_HIGH='3c4fcf098815f7ab'
for form in "$KEY_HEX" "$KEY_HEX_UPPER" "$KEY_SPACED" "$KEY_COLONS" \
    "$KEY_WORD_LOW" "$KEY_WORD_HIGH"; do
    grep -qFi "$form" "$SERIAL_LOG" &&
        fail "the key appeared in the serial log as '$form' — a driver that traces key material passes every other check in this machine"
done
# And as the bytes themselves, which is how a buffer written rather than
# formatted would come out.
printf '\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c' > "$TMP/key.bin"
grep -qF -f "$TMP/key.bin" "$SERIAL_LOG" &&
    fail "the key appeared in the serial log as raw bytes"

case "$status" in
    33) ;;
    124) fail "QEMU timed out" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$CLASS_MARKER" "$STANDARD_MARKER" "$KEY_MARKER" "$REFUSED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the crypto claim did not hold: '$marker'"
done

echo "PASS: clean exit 33, a ring-3 driver served the crypto class, the ciphertext is the one NIST SP 800-38A publishes, and the key appears nowhere in what this machine said"
