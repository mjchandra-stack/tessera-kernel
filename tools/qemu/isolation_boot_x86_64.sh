#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: a device that cannot reach memory nobody gave it, and cannot
# raise an interrupt nobody gave it either.
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

# **The unit is up for the whole boot** (D339), not for the length of one
# check: every function this machine enumerates is given an entry that passes
# its addresses through, and translation stays on. That is what makes the
# aperture below a fact about the machine rather than about a window somebody
# opened.
ENABLED_MARKER='claim vtd.enabled'
# **And pass-through is real, not merely written.** Made with `edu` itself
# before it is scoped: a transfer naming a physical address lands, and the unit
# records nothing. Without the entry it would be aborted. Kept as its own claim
# even now that the disk goes through the unit too, because it is the one that
# fails in the check rather than four layers away.
PASSTHROUGH_MARKER='claim isolation.passed-through'
SCOPED_MARKER='claim isolation.scoped'
REFUSED_MARKER='claim isolation.refused-outside'
# **And taking it away works.** The lease ends and the device stops reaching the
# address it *was* entitled to — same address, same device, same transfer, and
# the only thing that changed is that the lease is over. Separate from the two
# above because it is the half that says revocation is enforced rather than the
# kernel merely having forgotten.
REVOKED_MARKER='claim isolation.revoked'
# **And the ordinary block stack runs scoped** (D340). Not a check beside the
# system: the same ring-3 driver, service and client the smoke boot runs, with
# the disk behind an address space of its own — every address the driver
# programmed into the device came out of a range the graph owns rather than out
# of physical memory. The driver's code is identical either way, which is what
# the grant saying whether a number is scoped is for.
BLK_SCOPED_MARKER='claim blk.dma-scoped'

# **And the other half of the same boundary** (D343). The tables above say what
# memory a device may reach and have nothing to say about interrupts: on this
# architecture an interrupt is a write into a window the translation tables
# never see, carrying a vector and a destination the *device* supplies. So a
# device behind the tightest aperture on this machine could still raise any
# vector on any CPU. With interrupt remapping on it writes a **handle** instead,
# and which vector that stands for is an entry in a table only the kernel
# writes, carrying the source id of the one function allowed to use it.
IR_ENABLED_MARKER='claim intremap.enabled'
# The five facts, and none of them implies another. The device raises the
# interrupt it was issued, or a unit that blocked everything would pass for one
# that remaps. **The vector that arrives is the table's**: the message named
# none, so a delivery on the vector this kernel chose is the mechanism itself.
# A handle another function was issued is refused — the interrupt-side
# counterpart of an out-of-aperture DMA, and the reason an entry carries a
# source id. A handle past the table and one inside it that was never issued
# are refused too. And the device's own stops working the moment it is taken
# back.
IR_MARKERS=(
    'claim intremap.delivered'
    'claim intremap.chose-vector'
    'claim intremap.refused-foreign'
    'claim intremap.refused-beyond'
    'claim intremap.refused-unissued'
    'claim intremap.revoked'
)

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
# the kernel — and `intremap=on` asks for the second facility the unit has: the
# one that decides which interrupt a device may raise, as against which memory
# it may reach. The kernel reads `ECAP` and programs whichever of the two the
# machine offers, so this line is what makes the claims below reachable rather
# than what turns them on.
#
# **The virtio disk stays, and goes through the unit.** `iommu_platform=on` is
# what makes it: QEMU's virtio devices address memory directly unless they
# negotiate `VIRTIO_F_ACCESS_PLATFORM`, so without it the disk would be behind
# the remapping unit on paper and beside it in fact — and the context entry the
# kernel wrote for it would be a thing nothing on this boot could tell from an
# absent one. With it, the whole ring-3 block stack moving real sectors is
# evidence about those entries.
#
# `disable-legacy=on` goes with it: QEMU refuses `iommu_platform` on a
# transitional device, because the feature does not exist in the legacy
# interface. This kernel's virtio core requires `VIRTIO_F_VERSION_1` anyway, so
# a modern-only device is what it was already driving.
#
# Every check before this one is otherwise the same composition it always is;
# the isolation check finds `edu` by vendor and device id, so the two never
# contend.
timeout 240s qemu-system-x86_64 \
    -M q35,kernel-irqchip=split -m 512M -accel "$ACCEL" \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -device intel-iommu,intremap=on \
    -cdrom "$ISO" \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk,disable-legacy=on,iommu_platform=on \
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

for marker in "$ENABLED_MARKER" "$PASSTHROUGH_MARKER" "$SCOPED_MARKER" \
              "$REFUSED_MARKER" "$REVOKED_MARKER" "$BLK_SCOPED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the device was not scoped: '$marker'"
done

for marker in "$IR_ENABLED_MARKER" "${IR_MARKERS[@]}"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the device's interrupts were not remapped: '$marker'"
done

# **And that check did not skip either.** This boot asks for interrupt
# remapping and attaches a device with an MSI capability, so a skip is a bug in
# finding one of them rather than an absent machine.
grep -q "intremap: skipped" "$SERIAL_LOG" &&
    fail "the interrupt check skipped: this boot asks for interrupt remapping"

# **And the check did not skip.** This boot attaches both the unit and the
# device, so a skip is a bug in finding them rather than an absent machine.
grep -q "isolation: skipped" "$SERIAL_LOG" &&
    fail "the isolation check skipped: this boot attaches a remapping unit and an edu device"

# **And the disk works through the unit.** Translation is on for the whole of
# this boot rather than for the length of one check, and the disk's own
# transactions are translated — so this says the context entry the kernel wrote
# for that function is right, not merely that the boot survived. A bring-up that
# left it out aborts every sector this stack asks for.
grep -qF 'claim blk.service' "$SERIAL_LOG" ||
    fail "the block stack did not hold on a machine with a remapping unit"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, VT-d on for the whole boot with every interrupt behind a handle, the ring-3 block stack driving a scoped disk, one function behind a leased aperture — a transfer inside landed and one page along was refused — and that same function raising the interrupt it was issued while another's handle, an unissued one and its own once withdrawn were all refused and recorded"
