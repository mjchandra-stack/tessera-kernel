#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 boot, AArch64 with an IOMMU and a device that can be made to DMA:
# require the clean success exit (status 33) AND every half of the DMA-safety
# claim — that a device's DMA was translated inside its aperture and refused
# outside it, that a **ring-3 driver's** `dma_alloc` handed back an address
# from that aperture rather than a physical one, and that a refusal is
# *harvested and acted on* rather than only performed by the hardware.
#
# The markers are separate on purpose. The first is a property of the hardware
# and the tables; the second is the property a driver actually gets, and it is
# possible to have the first without the second — that was the state of the
# tree between D119 and this milestone. The fourth is the one nothing else
# implies: the unit refused a transaction and *said so*, through its own
# event-queue interrupt, and policy ended the offending driver's lease. Every
# earlier milestone stopped at the refusal, which means a misbehaving device
# was declined one address at a time forever and nothing above the hardware
# ever knew.
#
# Every earlier milestone handed a driver a physical address and trusted it;
# here the device is given an address space of exactly one page, and the
# hardware refuses the rest.
#
# The flags that matter:
#   * `iommu=smmuv3` puts an SMMUv3 in front of the PCIe root complex. Without
#     it the boot reports `smmu: skipped` and proves nothing.
#   * `-device edu` is the only endpoint here whose DMA engine is a handful of
#     register writes; anything else needs its transport brought up first.
#
# Normative: docs/drivers/01-driver-framework.md ("DMA Safety")

set -u

MARKER='smmu: OK — stream'
SCOPED_MARKER='smmu-dma: OK — ring-3 asked for a DMA buffer and was given an IOVA'
LEASE_MARKER='A DMA lease ends when the capability does'
# "not by polling" is the load-bearing phrase: the record count in that line is
# faults the SMMU's interrupt delivered, so a harvest that silently degraded to
# the polled path would fail the boot check rather than pass it quietly.
# The zero-copy half (D133): a memory object made reachable by a device, and
# then not. Its own marker, because "an address stopped working" is a claim
# only the hardware can settle and the bookkeeping would happily agree either
# way.
ATTACH_MARKER='the same device reached a *memory object*'
# The liveness half (D134): re-attaching one object reuses the address it had,
# so a driver serving a buffer repeatedly does not spend its aperture on how
# long it has been running. Without it the second round is refused.
REUSE_MARKER='survived 6 attach/detach rounds at that same address'
FAULT_MARKER="smmu-fault: OK — the device's refused DMA reached the kernel through the SMMU's own event-queue interrupt"
# Protected memory's second layer (D149). Two markers: that the refusal left no
# translation, and that the address which faulted was one the device is
# *entitled* to — the second is what separates this from the aperture check
# above, where the refused address was outside the lease entirely.
PROTECTED_MARKER='protected-dma: OK'
PROTECTED_INSIDE_MARKER='An address it is entitled to, unmapped because policy stopped the mapping being made'
KERNEL="${1:?usage: smmu_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64-smmu.log"

timeout 120s qemu-system-aarch64 \
    -M virt,iommu=smmuv3,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
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
grep -qF "$MARKER" "$SERIAL_LOG" || fail "the DMA aperture was not proven"
grep -qF "$SCOPED_MARKER" "$SERIAL_LOG" ||
    fail "ring-3 dma_alloc did not hand back an aperture address"
grep -qF "$ATTACH_MARKER" "$SERIAL_LOG" ||
    fail "a memory object was not made reachable by a device and then detached"
grep -qF "$REUSE_MARKER" "$SERIAL_LOG" ||
    fail "re-attaching one object did not reuse its device address"
grep -qF "$LEASE_MARKER" "$SERIAL_LOG" ||
    fail "the DMA lease was not revoked when the capability was reclaimed"
grep -qF "$PROTECTED_MARKER" "$SERIAL_LOG" ||
    fail "the protected-memory refusal left no hardware evidence"
grep -qF "$PROTECTED_INSIDE_MARKER" "$SERIAL_LOG" ||
    fail "the faulting address was not shown to be inside the device's own aperture"
grep -qF "$FAULT_MARKER" "$SERIAL_LOG" ||
    fail "a DMA fault was not harvested through the unit's interrupt and isolated"

echo "PASS: clean exit 33, a device's DMA was scoped to its aperture, a ring-3 driver was given an IOVA from it, the lease was revoked with the capability, a refused transaction was harvested through the unit's own interrupt and isolated its driver, and protected memory refused to an unauthorized device left an address inside that device's own aperture unmapped"
