#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3, x86-64: the network device class, driven from ring 3.
#
# **The block class was proved by a driver that answered questions. This one
# cannot be.** A frame arrives because a machine on the other side of the wire
# sent one, and no client asked for it — so the driver speaks first, with no
# request outstanding and nothing to reply to. What this boot needs that the
# others do not is therefore a network somebody answers on, which is what the
# backend below is: QEMU's user-mode stack replies to ARP for its gateway and
# runs a DHCP server, so a round trip is a real one and the reply is not this
# machine's own.
#
# The NIC is its own boot check rather than an addition to `smoke_boot.sh`, for
# the reason the other port's `virtio_net_boot_aarch64` is: attaching one to
# every boot makes every boot slower and makes a network failure look like a
# storage failure, and the check skips out loud when there is no NIC.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3"),
# docs/drivers/02-storage-networking-usb-pcie.md

set -u

MARKER='claim net-class.ok'
# And the three that are separable from it, because each is a thing that could
# not be done before:
#
#   * `driver-sent` — the driver spoke first. Every message this system had sent
#     until the network class was a reply to somebody's call.
#   * `conformance-complete` — the block class's own battery, second class,
#     every rule *reached* and held rather than merely nothing failing.
#   * `dhcp-offer` — a datagram built in ring 3 out of three headers of its own
#     was accepted by a server that is not part of this system, and travelled in
#     a buffer because it was too large to be a message.
DRIVER_SENT_MARKER='claim net-class.driver-sent'
CONFORMANCE_MARKER='claim net-class.conformance-complete'
DHCP_MARKER='claim net-stack.dhcp-offer'
# And the message that woke the driver. A PCI function has no wire: this boot's
# driver parks on a port the kernel bound to a vector it programmed into the
# function's MSI-X table (D326), so a run where the NIC could not interrupt is
# one where nothing above it ever ran.
BLK_MSI_MARKER='claim blk.msi'
# **And the stack above the driver** — four processes, and the one that
# completed the DHCP exchange holds a single channel endpoint: no device, no
# DMA, no NIC and no Ethernet constant. Three markers, because the claims are
# separable: a port bound, a datagram sent as a payload, and an answer read out
# of what came back — from a server that is not part of this system, which is
# what makes the headers the stack built correct rather than well-formed.
FLOW_BOUND_MARKER='claim flow.bound'
FLOW_SENT_MARKER='claim flow.datagram-sent'
FLOW_OFFER_MARKER='claim flow.offer-received'


# **And every device on this boot runs scoped** (D341). The machine carries an
# Intel VT-d unit, brought up before the first check and left on: each function
# the kernel has nothing to say about passes its addresses through, and each one
# a check binds is put behind an address space of its own before its driver
# starts. What the markers below assert is not that the run succeeded — it does
# either way, because a physical address works on a machine that is not
# translating that device — but that the addresses the driver programmed into
# the device came **out of the graph's aperture**. That is the silent downgrade
# this facility exists to prevent, and the only place it shows.
VTD_MARKER='claim vtd.enabled'
BLK_SCOPED_MARKER='claim blk.dma-scoped'
NET_SCOPED_MARKER='claim net-class.dma-scoped'
FLOW_SCOPED_MARKER='claim flow.dma-scoped'
# **And every interrupt on this boot goes through a handle** (D343). The
# devices above signal by writing into a window the translation tables never
# see, carrying a vector they choose themselves; with remapping on, what they
# write is an index into a table only the kernel owns. Asserted here because a
# boot that quietly stopped remapping them would go on passing every other
# claim on this line.
IR_MARKER='claim intremap.enabled'


ISO="${1:?usage: net_boot_x86_64.sh <iso> <disk>}"
DISK="${2:?usage: net_boot_x86_64.sh <iso> <disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-net-x86_64.log"

# The disk arrives as a read-only build artifact and QEMU opens its backing file
# read-write, so it is copied to a writable scratch path.
W_DISK="${TEST_TMPDIR:-/tmp}/net-scratch-x86_64.img"
cp "$DISK" "$W_DISK" && chmod u+w "$W_DISK"

# **The network backend every boot with a NIC must use**, and all three parts of
# it are load-bearing: IPv4 and IPv6 named explicitly, because `ipv6=on` alone
# turns IPv4 off, and a TCP peer behind a host command, because that is the only
# deterministic one this backend offers.
NETDEV='user,id=n0,ipv4=on,ipv6=on,guestfwd=tcp:10.0.2.100:9-cmd:/bin/cat'

# The CPU model is `smoke_boot.sh`'s and for its reasons: `+x2apic` because the
# kernel requires the local APIC's register-set-in-MSRs form, `+smep,+smap`
# because a feature CI never exercises is a feature CI cannot defend.
timeout 180s qemu-system-x86_64 \
    -M q35,kernel-irqchip=split -m 512M -accel "$ACCEL" \
    -device intel-iommu,intremap=on \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -cdrom "$ISO" \
    -drive "file=$W_DISK,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk,disable-legacy=on,iommu_platform=on \
    -netdev "$NETDEV" \
    -device virtio-net-pci,netdev=n0,disable-legacy=on,iommu_platform=on \
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
    124) fail "boot timed out after 180s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

for marker in "$MARKER" "$DRIVER_SENT_MARKER" "$CONFORMANCE_MARKER" "$DHCP_MARKER" \
              "$BLK_MSI_MARKER" "$FLOW_BOUND_MARKER" "$FLOW_SENT_MARKER" \
              "$FLOW_OFFER_MARKER" "$VTD_MARKER" "$BLK_SCOPED_MARKER" \
              "$NET_SCOPED_MARKER" "$FLOW_SCOPED_MARKER" "$IR_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "the ring-3 network stack did not hold: '$marker'"
done

# **And the check did not skip.** Every marker above is absent from a boot that
# never found a NIC, and so is this line — but a skip prints its own reason, and
# a run that silently stopped attaching the device would otherwise read as a
# pass once somebody removed a marker.
for skipped in "net-class: skipped" "flow-service: skipped"; do
    grep -q "$skipped" "$SERIAL_LOG" &&
        fail "a network check skipped: this boot attaches a NIC, so it had one to find"
done

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, a NIC driven from ring 3, a frame the driver sent unasked, the class conformance suite complete, and a DHCP exchange completed by a program holding one channel"
