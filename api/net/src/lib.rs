// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The protocol layers above the link: Ethernet II, IPv4, UDP, and enough DHCP
//! to ask for a lease and read the answer.
//!
//! **What this closes.** `docs/roadmap/03` ("The Network Is A Service") listed
//! TCP and UDP as absent, with the note that *"the one place a protocol above
//! the link layer is parsed at all is `drivers/virtio/src/arp.rs`, which exists
//! to prove a NIC round trip"*. This is the first thing in the tree that
//! speaks a protocol above the link because something needs it carried, rather
//! than to demonstrate that a NIC works.
//!
//! **Memory-safe, allocation-free, and no kernel in sight**, which is the
//! model `api/ext2` and `drivers/virtio` set: the protocol logic forbids
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
pub mod dhcpv6;
pub mod eth;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

/// What the three headers cost before any payload.
pub const HEADERS_LEN: usize = eth::HEADER_LEN + ipv4::HEADER_LEN + udp::HEADER_LEN;

/// The largest frame this crate builds: a DHCP DISCOVER with its three
/// headers. Callers size their transmit buffer with it rather than guessing.
pub const MAX_FRAME_LEN: usize = HEADERS_LEN + dhcp::DISCOVER_LEN;

/// Wraps `payload` in a UDP datagram, an IPv4 datagram and an Ethernet frame.
///
/// **The layering seam.** Everything above this is somebody's protocol —
/// DHCP here, and whatever a flow's client is speaking once there is a stack
/// service — and everything below is these three headers. A stack builds the
/// headers and does not know what it is carrying; a client builds the payload
/// and does not know how it travels. Splitting them here is what lets
/// `flow_service`'s `SendTo` take a payload rather than a frame.
///
/// **One function because the three layers are not independent.** The IPv4
/// header states a length the UDP header must agree with, and the UDP checksum
/// covers addresses that live in the IPv4 header — so a caller assembling
/// these separately gets a frame that is well-formed at every layer and wrong
/// as a datagram.
///
/// Returns the frame's length, or `None` if `out` cannot hold it.
#[allow(clippy::too_many_arguments)]
pub fn build_udp_frame(
    out: &mut [u8],
    src_mac: eth::Mac,
    dst_mac: eth::Mac,
    src_addr: ipv4::Addr,
    dst_addr: ipv4::Addr,
    src_port: u16,
    dst_port: u16,
    identification: u16,
    payload: &[u8],
) -> Option<usize> {
    let frame_len = HEADERS_LEN.checked_add(payload.len())?;
    let frame = out.get_mut(..frame_len)?;
    let after_eth = eth::write_header(frame, dst_mac, src_mac, eth::ETHERTYPE_IPV4)?;
    let udp_len = udp::HEADER_LEN.checked_add(payload.len())?;
    let after_ip = ipv4::write_header(
        after_eth,
        src_addr,
        dst_addr,
        ipv4::PROTO_UDP,
        identification,
        udp_len,
    )?;
    let written = udp::write(
        after_ip,
        udp::Peers::V4 {
            src: src_addr,
            dst: dst_addr,
        },
        src_port,
        dst_port,
        payload,
    )?;
    debug_assert_eq!(written, udp_len);
    Some(frame_len)
}

/// Wraps `payload` in a UDP datagram, an IPv6 datagram and an Ethernet frame.
///
/// **The destination must be multicast**, and that is a limitation with a
/// name rather than an oversight: a unicast IPv6 destination needs Neighbour
/// Discovery to learn its Ethernet address, and this crate implements none.
/// A multicast address needs no discovery because RFC 2464 makes the mapping
/// arithmetic — which is why the one exchange this can carry is one addressed
/// to a group.
#[allow(clippy::too_many_arguments)]
pub fn build_udp6_frame(
    out: &mut [u8],
    src_mac: eth::Mac,
    src_addr: ipv6::Addr,
    dst_addr: ipv6::Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    if !ipv6::is_multicast(&dst_addr) {
        return None;
    }
    let headers = eth::HEADER_LEN + ipv6::HEADER_LEN + udp::HEADER_LEN;
    let frame_len = headers.checked_add(payload.len())?;
    let frame = out.get_mut(..frame_len)?;
    let after_eth = eth::write_header(
        frame,
        ipv6::multicast_mac(&dst_addr),
        src_mac,
        eth::ETHERTYPE_IPV6,
    )?;
    let udp_len = udp::HEADER_LEN.checked_add(payload.len())?;
    let after_ip = ipv6::write_header(after_eth, src_addr, dst_addr, ipv6::NEXT_UDP, udp_len)?;
    let written = udp::write(
        after_ip,
        udp::Peers::V6 {
            src: src_addr,
            dst: dst_addr,
        },
        src_port,
        dst_port,
        payload,
    )?;
    debug_assert_eq!(written, udp_len);
    Some(frame_len)
}

/// Wraps `payload` in an IPv4 header of `protocol` and an Ethernet frame.
///
/// The transport-agnostic half of [`build_udp_frame`], for TCP and anything
/// else that supplies its own already-checksummed segment.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_frame(
    out: &mut [u8],
    src_mac: eth::Mac,
    dst_mac: eth::Mac,
    src_addr: ipv4::Addr,
    dst_addr: ipv4::Addr,
    protocol: u8,
    identification: u16,
    payload: &[u8],
) -> Option<usize> {
    let frame_len = eth::HEADER_LEN
        .checked_add(ipv4::HEADER_LEN)?
        .checked_add(payload.len())?;
    let frame = out.get_mut(..frame_len)?;
    let after_eth = eth::write_header(frame, dst_mac, src_mac, eth::ETHERTYPE_IPV4)?;
    let after_ip = ipv4::write_header(
        after_eth,
        src_addr,
        dst_addr,
        protocol,
        identification,
        payload.len(),
    )?;
    after_ip.get_mut(..payload.len())?.copy_from_slice(payload);
    Some(frame_len)
}

/// Unwraps an IPv4 frame down to its transport payload, without assuming the
/// transport.
///
/// Returns the addresses as well, because every transport checksum above IPv4
/// is computed over them.
pub fn parse_ipv4_frame<'a>(
    frame: &'a [u8],
    our_mac: eth::Mac,
) -> Option<(ipv4::Addr, ipv4::Addr, u8, &'a [u8])> {
    let ethernet = eth::parse(frame)?;
    if ethernet.ethertype != eth::ETHERTYPE_IPV4 {
        return None;
    }
    if ethernet.dst != eth::BROADCAST && ethernet.dst != our_mac {
        return None;
    }
    let packet = ipv4::parse(ethernet.payload)?;
    Some((packet.src, packet.dst, packet.protocol, packet.payload))
}

/// A UDP datagram taken out of a received frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received<'a> {
    pub src_addr: ipv4::Addr,
    pub dst_addr: ipv4::Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Unwraps an IPv6 frame's three headers, verifying every one of them.
///
/// A station accepts multicast and its own unicast; anything else on the
/// segment is somebody else's. `our_addr` is this station's link-local, which
/// is what a reply to a solicited exchange is addressed to.
pub fn parse_udp6_frame<'a>(
    frame: &'a [u8],
    our_mac: eth::Mac,
    our_addr: ipv6::Addr,
) -> Option<Received6<'a>> {
    let ethernet = eth::parse(frame)?;
    if ethernet.ethertype != eth::ETHERTYPE_IPV6 {
        return None;
    }
    // A multicast frame is addressed to a group this station may be in, and a
    // unicast one to this station; the link carries neither exclusively.
    if ethernet.dst[0] != 0x33 && ethernet.dst != our_mac {
        return None;
    }
    let packet = ipv6::parse(ethernet.payload)?;
    if packet.next_header != ipv6::NEXT_UDP {
        return None;
    }
    if packet.dst != our_addr && !ipv6::is_multicast(&packet.dst) {
        return None;
    }
    let datagram = udp::parse(
        packet.payload,
        udp::Peers::V6 {
            src: packet.src,
            dst: packet.dst,
        },
    )?;
    Some(Received6 {
        src_addr: packet.src,
        dst_addr: packet.dst,
        src_port: datagram.src_port,
        dst_port: datagram.dst_port,
        payload: datagram.payload,
    })
}

/// Builds an ICMPv6 message as a complete Ethernet frame, to a named MAC.
///
/// **The one builder that takes a link-layer address**, because Neighbour
/// Discovery is the layer that knows one: an advertisement answers a
/// solicitation by going back to whoever asked, which is a unicast this host
/// can address precisely because the question arrived from it.
pub fn build_icmpv6_frame(
    out: &mut [u8],
    src_mac: eth::Mac,
    dst_mac: eth::Mac,
    src_addr: ipv6::Addr,
    dst_addr: ipv6::Addr,
    message: &[u8],
) -> Option<usize> {
    let frame_len = eth::HEADER_LEN
        .checked_add(ipv6::HEADER_LEN)?
        .checked_add(message.len())?;
    let frame = out.get_mut(..frame_len)?;
    let after_eth = eth::write_header(frame, dst_mac, src_mac, eth::ETHERTYPE_IPV6)?;
    // **Hop limit 255, which Neighbour Discovery requires.** A receiver must
    // discard an ND message carrying anything else (RFC 4861), because a
    // packet that crossed a router cannot still have 255 — that is what stops
    // an off-link station forging a neighbour answer.
    let after_ip = ipv6::write_header_hop(
        after_eth,
        src_addr,
        dst_addr,
        ipv6::NEXT_ICMPV6,
        ipv6::ND_HOP_LIMIT,
        message.len(),
    )?;
    after_ip.get_mut(..message.len())?.copy_from_slice(message);
    Some(frame_len)
}

/// An ICMPv6 message taken out of a received frame, with its checksum verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedIcmp6<'a> {
    pub src_mac: eth::Mac,
    pub src_addr: ipv6::Addr,
    pub dst_addr: ipv6::Addr,
    pub message: &'a [u8],
}

/// Unwraps an ICMPv6 frame, verifying the IPv6 header and the checksum.
pub fn parse_icmpv6_frame(frame: &[u8]) -> Option<ReceivedIcmp6<'_>> {
    let ethernet = eth::parse(frame)?;
    if ethernet.ethertype != eth::ETHERTYPE_IPV6 {
        return None;
    }
    let packet = ipv6::parse(ethernet.payload)?;
    if packet.next_header != ipv6::NEXT_ICMPV6 {
        return None;
    }
    if !icmpv6::verify(packet.payload, packet.src, packet.dst) {
        return None;
    }
    Some(ReceivedIcmp6 {
        src_mac: ethernet.src,
        src_addr: packet.src,
        dst_addr: packet.dst,
        message: packet.payload,
    })
}

/// Answers a Neighbour Solicitation for this station, if that is what `frame`
/// is.
///
/// Returns the advertisement as a complete frame, ready to transmit. `None`
/// means the frame was not a solicitation for this station's address, which is
/// the ordinary case for most of what a link carries.
pub fn answer_neighbour_solicitation(
    frame: &[u8],
    out: &mut [u8],
    our_mac: eth::Mac,
) -> Option<usize> {
    let received = parse_icmpv6_frame(frame)?;
    let target = icmpv6::parse_solicitation(received.message)?;
    let ours = ipv6::link_local_from_mac(our_mac);
    if target != ours {
        return None;
    }
    let mut message = [0u8; icmpv6::ADVERTISEMENT_LEN];
    // The advertisement goes back to the solicitor, from the address it asked
    // about — which is what makes the pseudo-header the peer will check match.
    let len = icmpv6::build_advertisement(&mut message, ours, received.src_addr, ours, our_mac)?;
    build_icmpv6_frame(
        out,
        our_mac,
        received.src_mac,
        ours,
        received.src_addr,
        message.get(..len)?,
    )
}

/// A UDP datagram taken out of a received IPv6 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received6<'a> {
    pub src_addr: ipv6::Addr,
    pub dst_addr: ipv6::Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Unwraps the three headers, verifying every one of them.
///
/// The receive path in one call, so a caller cannot skip the UDP checksum by
/// forgetting to pass the addresses it covers. Refuses, in order: a frame that
/// is not IPv4, one addressed to another station, a bad IPv4 header, a
/// fragment, a protocol that is not UDP, and a bad UDP checksum.
pub fn parse_udp_frame(frame: &[u8], our_mac: eth::Mac) -> Option<Received<'_>> {
    let ethernet = eth::parse(frame)?;
    if ethernet.ethertype != eth::ETHERTYPE_IPV4 {
        return None;
    }
    // Broadcast is for everyone and a unicast to this station is ours;
    // anything else is somebody else's traffic on a segment this NIC sees.
    if ethernet.dst != eth::BROADCAST && ethernet.dst != our_mac {
        return None;
    }
    let packet = ipv4::parse(ethernet.payload)?;
    if packet.protocol != ipv4::PROTO_UDP {
        return None;
    }
    let datagram = udp::parse(
        packet.payload,
        udp::Peers::V4 {
            src: packet.src,
            dst: packet.dst,
        },
    )?;
    Some(Received {
        src_addr: packet.src,
        dst_addr: packet.dst,
        src_port: datagram.src_port,
        dst_port: datagram.dst_port,
        payload: datagram.payload,
    })
}

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
    let mut payload = [0u8; dhcp::DISCOVER_LEN];
    let payload_len = dhcp::build_discover(&mut payload, client, xid)?;
    build_udp_frame(
        out,
        client,
        eth::BROADCAST,
        ipv4::UNSPECIFIED,
        ipv4::BROADCAST,
        dhcp::CLIENT_PORT,
        dhcp::SERVER_PORT,
        // The identification field matters only for reassembly, which this
        // datagram is too small to need; the transaction id is reused so a
        // capture ties the two together.
        xid as u16,
        payload.get(..payload_len)?,
    )
}

/// Builds a DHCPv6 Information-Request as a complete Ethernet frame.
///
/// The source address is the link-local this station forms from its own MAC,
/// which is what makes the exchange possible before anything is configured;
/// the destination is the all-DHCP-servers group, so no neighbour has to be
/// discovered.
pub fn build_dhcpv6_information_request(
    out: &mut [u8],
    client: eth::Mac,
    xid: u32,
) -> Option<usize> {
    let mut payload = [0u8; dhcpv6::INFORMATION_REQUEST_LEN];
    let len = dhcpv6::build_information_request(&mut payload, client, xid)?;
    build_udp6_frame(
        out,
        client,
        ipv6::link_local_from_mac(client),
        ipv6::ALL_DHCP_SERVERS,
        dhcpv6::CLIENT_PORT,
        dhcpv6::SERVER_PORT,
        payload.get(..len)?,
    )
}

/// Reads a received frame as a DHCPv6 Reply answering `xid`.
/// **The source port is not checked, and that is an interoperability finding
/// rather than laxity.** RFC 8415 says a server answers from port 547; QEMU's
/// user-mode backend answers from an ephemeral one (8962 in the run that found
/// this), so a client that required 547 discarded a reply that was otherwise
/// perfect. What correlates a reply to its request is the transaction id,
/// which `dhcpv6::parse_reply` checks — the port never did that job, and
/// requiring it here only refused a peer this stack has to talk to (D279).
pub fn parse_dhcpv6_reply(frame: &[u8], client: eth::Mac, xid: u32) -> Option<dhcpv6::Reply> {
    let datagram = parse_udp6_frame(frame, client, ipv6::link_local_from_mac(client))?;
    if datagram.dst_port != dhcpv6::CLIENT_PORT {
        return None;
    }
    dhcpv6::parse_reply(datagram.payload, xid)
}

/// Reads a received frame as a DHCP offer answering `xid`.
///
/// Every layer is checked in turn and any of them may refuse: this is the
/// receive path in one call, so that a caller cannot skip the UDP checksum by
/// forgetting to pass the addresses it covers.
pub fn parse_dhcp_offer(frame: &[u8], client: eth::Mac, xid: u32) -> Option<dhcp::Offer> {
    let datagram = parse_udp_frame(frame, client)?;
    if datagram.src_port != dhcp::SERVER_PORT || datagram.dst_port != dhcp::CLIENT_PORT {
        return None;
    }
    dhcp::parse_offer(datagram.payload, xid)
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
