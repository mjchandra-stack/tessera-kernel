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

MARKER='claim virtio-net.ok'
# The network class (D150), the first of the class rollout. Three markers,
# because the interesting claims are separable: that a ring-3 driver served the
# contract at all, that the frame reached the client in a buffer the driver gave
# away rather than copied, and that the class conformance suite — the same seven
# rules the block class passes — was reached in full against a second class.
NET_CLASS_MARKER='claim net-class.ok'
NET_CLASS_PUSH_MARKER='claim net-class.driver-sent'
NET_CLASS_CONFORMANCE_MARKER='claim net-class.conformance-complete'
# The first protocol above the link (D272). Separate from the three above
# because it claims something different: those say a ring-3 driver served the
# network class, this says a datagram this system built out of an Ethernet, an
# IPv4 and a UDP header was accepted by QEMU's own DHCP server and answered
# with a lease. The frame is 290 bytes, so it also proves the out-of-line
# transmit path — it could not have travelled inside a message. Nothing in this
# tree judges the checksums: a frame built wrongly is one that is silently
# never answered, which is what makes this worth asserting.
NET_STACK_DHCP_MARKER='claim net-stack.dhcp-offer'
# The network as a service (D275). Four markers, because they are separable
# claims and the last one is not about datagrams at all:
#
#   * `bound` — a program with no device capability asked a stack instance for
#     a local port and got one.
#   * `datagram-sent` — it handed over a DHCP payload and the stack built the
#     Ethernet, IPv4 and UDP headers around it. The client never names a MAC as
#     a frame's source, an ethertype, or a checksum.
#   * `offer-received` — QEMU's DHCP server answered, which is what makes those
#     headers correct rather than merely well-formed.
#   * `authority-refused` — a `Bind` carrying a port capability nobody can
#     resolve was refused. `flow_service.isl` reserves that field against a
#     namespace broker that does not exist yet, and a reserved field is only
#     reserved if something enforces it.
FLOW_BOUND_MARKER='claim flow.bound'
FLOW_SENT_MARKER='claim flow.datagram-sent'
FLOW_OFFER_MARKER='claim flow.offer-received'
FLOW_AUTHORITY_MARKER='claim flow.authority-refused'
KERNEL="${1:?usage: virtio_net_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-virtio-net-aarch64.log"

# `cortex-a76` rather than the `cortex-a72` this used to run: the kernel turns
# on privileged-access-never (D247), which arrived in ARMv8.1 and which a v8.0
# part like the a72 reports as absent. A check that never exercises the feature
# cannot defend it — the same reason the x86-64 boot asks for `+smep,+smap`.
# **Both families, named explicitly, and the `ipv4=on` is load-bearing.**
# Naming only `ipv6=on` makes QEMU turn IPv4 *off* — the guest's ARP goes out
# and nothing ever answers it, which looks exactly like a driver that stopped
# receiving and is not (build/README.md, D279). IPv6 is on because the flow
# check's second leg is a stateless DHCPv6 exchange, which is the only UDP
# service this backend answers over v6.
NETDEV='user,id=n0,ipv4=on,ipv6=on'

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a76 -m 512M -accel "$ACCEL" \
    -global virtio-mmio.force-legacy=false \
    -kernel "$KERNEL" \
    -netdev "$NETDEV" \
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

for marker in "$NET_CLASS_MARKER" "$NET_CLASS_PUSH_MARKER" "$NET_CLASS_CONFORMANCE_MARKER" \
    "$NET_STACK_DHCP_MARKER" "$FLOW_BOUND_MARKER" "$FLOW_SENT_MARKER" \
    "$FLOW_OFFER_MARKER" "$FLOW_AUTHORITY_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the network class was not served from ring 3: '$marker'"
done

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, the virtio-net verdict is present, and a ring-3 driver served the network class to a client — pushing it a frame nobody asked for, in a buffer it gave away"
