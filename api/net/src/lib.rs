// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The protocol layers above the link: Ethernet II, IPv4, UDP, and enough DHCP
//! to ask for a lease and read the answer.
//!
//! **What this closes.** `docs/roadmap/03` ("The Network Is A Service") listed
//! TCP and UDP as absent, with the note that *"the one place a protocol above
//! the link layer is parsed at all is `kernel/virtio/src/arp.rs`, which exists
//! to prove a NIC round trip"*. This is the first thing in the tree that
//! speaks a protocol above the link because something needs it carried, rather
//! than to demonstrate that a NIC works.
//!
//! **Memory-safe, allocation-free, and no kernel in sight**, which is the
//! model `api/ext2` and `kernel/virtio` set: the protocol logic forbids
//! `unsafe`, knows nothing about a driver or a channel, and is exercised on
//! the host. A caller supplies the buffer and the bytes; nothing here reserves
//! anything or talks to a device.
//!
//! **Everything on the wire is hostile input.** A frame is whatever the
//! segment sent, and on an emulated network that is whatever the host sent.
//! Every length is checked before it indexes, every checksum is verified
//! before its datagram is believed, and a structure that does not make sense
//! is refused rather than clamped — this crate is on the fuzz gate's
//! hand-written-parser list for that reason
//! (`tools/checks/src/fuzz_gate.rs`).
//!
//! **What it deliberately does not do**: fragmentation and reassembly, IP
//! options, IPv6, TCP, and any state at all. There is no socket, no lease
//! machine and no retransmission — those belong to the stack service, and
//! `docs/roadmap/03` Phase 3 sequences them after this. What is here is the
//! encoding, which is the part a service should not be writing twice.
//!
//! Normative: docs/network/01-network-stack.md

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

// The tests build frames of a size the crate itself never needs to name, which
// is the one thing here that wants an allocator. The crate proper stays
// `no_std` and allocation-free.
#[cfg(test)]
extern crate std;

pub mod checksum;
pub mod dhcp;
pub mod eth;
pub mod ipv4;
pub mod udp;

/// The largest frame this crate builds: a DHCP DISCOVER with its three
/// headers. Callers size their transmit buffer with it rather than guessing.
pub const MAX_FRAME_LEN: usize =
    eth::HEADER_LEN + ipv4::HEADER_LEN + udp::HEADER_LEN + dhcp::DISCOVER_LEN;

/// Builds a broadcast DHCP DISCOVER as a complete Ethernet frame.
///
/// **One function because the three layers are not independent here.** The
/// IPv4 header states a length the UDP header must agree with, and the UDP
/// checksum covers addresses that live in the IPv4 header — so a caller
/// assembling these in the wrong order gets a frame that is well-formed at
/// every layer and wrong as a datagram. Composing them once is what keeps that
/// from being every caller's problem.
///
/// Returns the frame's length, or `None` if `out` is too small for it.
pub fn build_dhcp_discover(out: &mut [u8], client: eth::Mac, xid: u32) -> Option<usize> {
    let frame_len = MAX_FRAME_LEN;
    let frame = out.get_mut(..frame_len)?;

    let after_eth = eth::write_header(frame, eth::BROADCAST, client, eth::ETHERTYPE_IPV4)?;
    let udp_len = udp::HEADER_LEN + dhcp::DISCOVER_LEN;
    // The IPv4 header is written first because it computes its own checksum
    // over its own bytes, and the UDP checksum below reads the addresses back
    // out of nothing — it is told them directly.
    let after_ip = ipv4::write_header(
        after_eth,
        ipv4::UNSPECIFIED,
        ipv4::BROADCAST,
        ipv4::PROTO_UDP,
        // The identification field matters only for reassembly, which this
        // datagram is too small to need; the transaction id is reused so a
        // capture ties the two together.
        xid as u16,
        udp_len,
    )?;

    let mut payload = [0u8; dhcp::DISCOVER_LEN];
    let payload_len = dhcp::build_discover(&mut payload, client, xid)?;
    let written = udp::write(
        after_ip,
        ipv4::UNSPECIFIED,
        ipv4::BROADCAST,
        dhcp::CLIENT_PORT,
        dhcp::SERVER_PORT,
        payload.get(..payload_len)?,
    )?;
    debug_assert_eq!(written, udp_len);
    Some(frame_len)
}

/// Reads a received frame as a DHCP offer answering `xid`.
///
/// Every layer is checked in turn and any of them may refuse: this is the
/// receive path in one call, so that a caller cannot skip the UDP checksum by
/// forgetting to pass the addresses it covers.
pub fn parse_dhcp_offer(frame: &[u8], client: eth::Mac, xid: u32) -> Option<dhcp::Offer> {
    let ethernet = eth::parse(frame)?;
    if ethernet.ethertype != eth::ETHERTYPE_IPV4 {
        return None;
    }
    // A broadcast offer is what was asked for; a unicast one to this station is
    // equally ours. Anything else is somebody else's traffic on a segment this
    // NIC happens to see.
    if ethernet.dst != eth::BROADCAST && ethernet.dst != client {
        return None;
    }
    let packet = ipv4::parse(ethernet.payload)?;
    if packet.protocol != ipv4::PROTO_UDP {
        return None;
    }
    let datagram = udp::parse(packet.payload, packet.src, packet.dst)?;
    if datagram.src_port != dhcp::SERVER_PORT || datagram.dst_port != dhcp::CLIENT_PORT {
        return None;
    }
    dhcp::parse_offer(datagram.payload, xid)
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
