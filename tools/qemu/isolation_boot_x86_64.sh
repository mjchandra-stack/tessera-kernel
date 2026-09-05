#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: a device that cannot reach memory nobody gave it.
#
# **The DMA-scoping claim on this port.** Until this boot, a driver here
# programmed a device with a physical address and the device was obeyed; the
# only thing keeping a device out of memory it had no business in was the
# driver choosing not to. This machine carries an Intel VT-d remapping unit and
# the `edu` device, and the kernel puts that one function behind a one-page
# address space.
#
# **Both halves are needed and both are asserted.** A transfer *inside* the
# aperture must land, or a unit that aborts everything would pass for one that
# scopes; a transfer *outside* must be refused **and recorded**, or "nothing
# arrived" is indistinguishable from a misconfiguration. The two claims below
# are those two facts, and neither implies the other.
#
# `edu` is the device because its DMA engine is four register writes, so nothing
# has to be brought up first — the same reason the other port picked it for the
# SMMU.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/hardware/04-dma-and-memory-management.md

set -u

SCOPED_MARKER='claim isolation.scoped'
REFUSED_MARKER='claim isolation.refused-outside'

ISO="${1:?usage: isolation_boot_x86_64.sh <iso> <disk>}"
DISK="${2:?usage: isolation_boot_x86_64.sh <iso> <disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-isolation-x86_64.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
W_SCRATCH="${TEST_TMPDIR:-/tmp}/isolation-scratch-x86_64.img"
cp "$DISK" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"

# The CPU model is `smoke_boot.sh`'s and for its reasons: `+x2apic` because the
# kernel requires the local APIC's register-set-in-MSRs form, `+smep,+smap`
# because a feature CI never exercises is a feature CI cannot defend.
#
# **`kernel-irqchip=split` is what lets the unit exist at all** — QEMU refuses
# to attach `intel-iommu` to a machine whose interrupt controller is entirely in
# the kernel — and `intremap=off` says this boot is about DMA remapping and not
# about interrupt remapping, which is a separate facility this kernel does not
# program.
#
# **The virtio disk stays.** Every check before this one is the same
# composition it always is; the isolation check finds `edu` by vendor and device
# id, so the two never contend.
timeout 240s qemu-system-x86_64 \
    -M q35,kernel-irqchip=split -m 512M -accel "$ACCEL" \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -device intel-iommu,intremap=off \
    -cdrom "$ISO" \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk \
    -device edu \
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
    124) fail "boot timed out after 240s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

# **The firmware described a unit, and the kernel found it.** Read out of the
# ACPI tables rather than assumed: a machine that stopped describing one would
# otherwise skip the whole check and read as a pass.
grep -q "acpi: DMAR remapping unit" "$SERIAL_LOG" ||
    fail "no DMAR unit was found, on a machine that attaches one"

for marker in "$SCOPED_MARKER" "$REFUSED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the device was not scoped: '$marker'"
done

# **And the check did not skip.** This boot attaches both the unit and the
# device, so a skip is a bug in finding them rather than an absent machine.
grep -q "isolation: skipped" "$SERIAL_LOG" &&
    fail "the isolation check skipped: this boot attaches a remapping unit and an edu device"

# **And the disk still worked afterwards.** Translation is enabled for the
# length of that one check and switched off again; a boot that left it on would
# abort the next transfer any other device made, and the filesystem check that
# runs immediately after this one is what would notice.
grep -qF 'claim blk.service' "$SERIAL_LOG" ||
    fail "the block stack did not hold on a machine with a remapping unit"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, one PCI function behind a one-page address space — a transfer inside it landed, and one page along was refused and recorded"
