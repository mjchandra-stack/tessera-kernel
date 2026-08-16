#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot, AArch64 with a PCI endpoint that can be made to interrupt:
# require the clean success exit (status 33) AND that a device-initiated
# message-signalled interrupt was taken.
#
# Every other interrupt this OS takes comes from a wire the device tree named.
# This one comes from a *message*: the device writes an SPI number to the
# GICv2m doorbell and the GIC raises it. What makes that cheap is that it then
# arrives as an ordinary wired interrupt, so nothing downstream of the GIC had
# to change.
#
# The flags that matter:
#   * `-device edu` is QEMU's minimal PCI endpoint: a single register write
#     makes it send its interrupt. Every other endpoint here needs its
#     transport brought up first, which is a different milestone — so without
#     it the boot reports `msi: skipped` and proves nothing about delivery.
#   * `gic-version=2` because the v2m frame is the GICv2 MSI mechanism; the
#     boot reads the frame's SPI range from its own TYPER rather than assuming.
#
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/hardware/02-hardware-description-and-discovery.md ("PCIe")

set -u

MARKER='claim msi.ok'
KERNEL="${1:?usage: msi_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64-msi.log"

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -device edu \
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
grep -qF "$MARKER" "$SERIAL_LOG" ||
    fail "no device-initiated message-signalled interrupt was reported"

echo "PASS: clean exit 33 and a PCI device's MSI was delivered"
