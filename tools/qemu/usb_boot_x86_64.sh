#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: the USB class — a bus whose devices have no registers.
#
# **Everything else this port drives owns memory.** A virtio function, an NVMe
# controller, a NIC: each is a window a driver maps. A USB device owns none, and
# the two class drivers here map nothing at all — every byte they move crosses
# the host, which is the relaying host `docs/drivers/01` describes.
#
# The device tree below is the point of the boot:
#
#   * `usb-storage` on port 1 — the block class, judged by the same client that
#     judges virtio and NVMe.
#   * `usb-hub` on port 2 with a keyboard behind it — which is what makes the
#     resource graph three levels deep: controller, hub, device.
#   * `usb-audio` on port 3 — attached, working, and **refused**: its class is
#     not on the host's allowlist, so it enumerates and is declared with a class
#     code no manifest entry claims. Visible, and in nobody's hands.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/drivers/02-storage-networking-usb-pcie.md ("USB")

set -u

MARKER='claim usb.ok'
# Separable claims, each about something the other transports cannot show:
#
#   * `no-registers` — the class drivers hold no window and map nothing.
#   * `three-levels` — a hub is a bus with devices behind it, so the graph is
#     three deep where it has only ever been two.
#   * `idle-no-report` — a keyboard with nothing to say answered NO_REPORT
#     rather than failing, which is a different thing from a broken device.
NO_REGISTERS_MARKER='claim usb.no-registers'
DEPTH_MARKER='claim usb.three-levels'
IDLE_MARKER='claim usb.idle-no-report'
#   * `device-refused` — one attached device enumerated perfectly and was
#     declared with a class code no manifest entry claims, so no driver was
#     offered it. The first policy here that turns away something that works.
REFUSED_MARKER='claim usb.device-refused'

# **And the controller runs scoped** (D342). This machine carries an Intel VT-d
# unit, up before the first check and left on. The xHCI controller is the only
# thing on this bus that reaches memory — what is plugged into it has no
# registers and no DMA of its own — so scoping the one function scopes
# everything behind it, and the marker says the addresses its driver programmed
# came out of the graph's aperture rather than out of physical memory.
VTD_MARKER='claim vtd.enabled'
BLK_SCOPED_MARKER='claim blk.dma-scoped'
USB_SCOPED_MARKER='claim usb.dma-scoped'

ISO="${1:?usage: usb_boot_x86_64.sh <iso> <disk>}"
DISK="${2:?usage: usb_boot_x86_64.sh <iso> <disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-usb-x86_64.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
W_USB="${TEST_TMPDIR:-/tmp}/usb-disk-x86_64.img"
W_SCRATCH="${TEST_TMPDIR:-/tmp}/usb-scratch-x86_64.img"
cp "$DISK" "$W_USB" && chmod u+w "$W_USB"
cp "$DISK" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"

# The CPU model is `smoke_boot.sh`'s and for its reasons. The virtio disk stays
# for the reason the NVMe boot keeps one: every check before this is the
# composition it always was, and the USB check finds its controller by class
# rather than by position.
timeout 300s qemu-system-x86_64 \
    -M q35,kernel-irqchip=split -m 512M -accel "$ACCEL" \
    -device intel-iommu,intremap=off \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -cdrom "$ISO" \
    -drive "file=$W_SCRATCH,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk,disable-legacy=on,iommu_platform=on \
    -device qemu-xhci,id=xhci \
    -drive "file=$W_USB,if=none,format=raw,id=usbdisk" \
    -device usb-storage,bus=xhci.0,port=1,drive=usbdisk \
    -device usb-hub,bus=xhci.0,port=2,id=hub \
    -device usb-kbd,bus=xhci.0,port=2.1 \
    -audiodev none,id=silent \
    -device usb-audio,bus=xhci.0,port=3,audiodev=silent \
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

for marker in "$MARKER" "$NO_REGISTERS_MARKER" "$DEPTH_MARKER" "$IDLE_MARKER" \
              "$REFUSED_MARKER" "$VTD_MARKER" "$BLK_SCOPED_MARKER" \
              "$USB_SCOPED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the ring-3 USB stack did not hold: '$marker'"
done

# **And the check did not skip.** A boot that stopped attaching the controller
# would otherwise read as a pass the moment somebody removed a marker.
grep -q "usb: skipped" "$SERIAL_LOG" &&
    fail "the USB check skipped: this boot attaches a controller, so it had one to find"

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, a USB stack driven from ring 3, a disk and a keyboard behind a hub, and two class drivers that map nothing"
