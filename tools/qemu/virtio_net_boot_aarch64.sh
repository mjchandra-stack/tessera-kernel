#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 virtio-net boot, AArch64: boot the Stage 0 kernel with a virtio-net
# device attached to QEMU's user-mode (SLIRP) network and require BOTH the
# clean success exit (status 33) AND the virtio-net verdict on the serial
# console. The driver transmits an ARP request for the SLIRP gateway (10.0.2.2)
# and verifies the reply, so this proves the in-kernel virtio-net driver's
# transmit AND receive datapaths with a real round-trip.
#
# Differences from `smoke_boot_aarch64.sh`:
#   * A virtio-net device on QEMU's user-mode network backend, which answers
#     ARP for its virtual gateway deterministically (no external host needed).
#   * `virtio-mmio.force-legacy=false` selects the MODERN (version 2) transport,
#     which the driver speaks; QEMU otherwise defaults to legacy version 1.
# Normative: docs/hardware/04-device-memory-and-unified-memory.md,
# docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

set -u

MARKER='virtio-net: OK'
KERNEL="${1:?usage: virtio_net_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-virtio-net-aarch64.log"

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -global virtio-mmio.force-legacy=false \
    -kernel "$KERNEL" \
    -netdev user,id=n0 \
    -device virtio-net-device,netdev=n0 \
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

case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"

echo "PASS: clean exit 33 and virtio-net verdict present"
