// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! IPv6, header only: build one, and read one somebody else built.
//!
//! **Three differences from IPv4 that matter to everything above.** The header
//! carries no checksum of its own, so a corrupt address is caught by the
//! transport's pseudo-header or not at all — which is why the transport
//! checksum is *mandatory* here and optional there. The header is a fixed 40
//! bytes with extensions chained through `next_header` rather than an `ihl` to
//! multiply. And the addresses are sixteen bytes, which is the reason
//! `FlowAddress` had to grow (D278).
//!
//! **No extension headers.** A `next_header` this module does not recognise is
//! reported as it stands and the payload handed on unparsed; nothing here
//! walks a chain. A parser that skipped extensions it did not understand would
//! be guessing at where the transport starts.
//!
//! **No fragmentation.** IPv6 fragments live in an extension header, so this
//! module refuses them by not walking the chain at all rather than by checking
//! a flag.
//!
//! Normative: docs/network/01-network-stack.md

use crate::checksum::Sum;
use crate::eth::Mac;

/// An IPv6 address.
pub type Addr = [u8; 16];

/// The fixed header. Extensions would follow it; this module writes none.
pub const HEADER_LEN: usize = 40;

/// `::`, which is what a host uses before it has an address.
pub const UNSPECIFIED: Addr = [0; 16];

/// `ff02::1`, every node on the link.
pub const ALL_NODES: Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

/// `ff02::2`, every router on the link.
pub const ALL_ROUTERS: Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

/// `ff02::1:2`, the DHCPv6 servers and relay agents on the link.
///
/// **Sixteen bytes written out, which is where this was wrong first.** `::1:2`
/// is the last *two groups*, so the bytes are `..00 01 00 02` and the four
/// before them are zero — an address written a group early looks plausible,
/// maps to a plausible multicast MAC, and round-trips through this crate
/// perfectly. What caught it was a checksum computed outside the crate
/// (D278).
pub const ALL_DHCP_SERVERS: Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02];

/// UDP's next-header value, which is the same number as IPv4's protocol.
pub const NEXT_UDP: u8 = 17;

/// ICMPv6's.
pub const NEXT_ICMPV6: u8 = 58;

/// What this module puts in the hop limit: the conventional default.
const DEFAULT_HOP_LIMIT: u8 = 64;

/// Whether `addr` is a multicast address.
pub fn is_multicast(addr: &Addr) -> bool {
    addr[0] == 0xff
}

/// The Ethernet address an IPv6 multicast address is sent to.
///
/// **`33:33` and the low four bytes** (RFC 2464). This is what lets a host send
/// to a multicast group without resolving anything: there is no neighbour to
/// discover, because the mapping is arithmetic. A unicast destination needs
/// Neighbour Discovery, which this crate does not implement — so every frame it
/// builds for IPv6 goes to a multicast group.
pub fn multicast_mac(addr: &Addr) -> Mac {
    [0x33, 0x33, addr[12], addr[13], addr[14], addr[15]]
}

/// The link-local address a station forms from its MAC.
///
/// **Modified EUI-64** (RFC 4291): `fe80::`, then the MAC with `ff:fe` inserted
/// in the middle and the universal/local bit inverted. Formed rather than
/// configured, and **not** verified by Duplicate Address Detection — a host
/// that skipped DAD is making a claim it has not checked, which is fine on a
/// link with one other station and stated here rather than discovered.
pub fn link_local_from_mac(mac: Mac) -> Addr {
    let mut addr = [0u8; 16];
    addr[0] = 0xfe;
    addr[1] = 0x80;
    addr[8] = mac[0] ^ 0x02;
    addr[9] = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xff;
    addr[12] = 0xfe;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    addr
}

/// Writes a header covering a `payload_len`-byte payload, returning the space
/// the payload goes in.
///
/// No checksum: the header has none. What makes a corrupt address detectable
/// is the transport's pseudo-header, which is why RFC 8200 makes that one
/// mandatory.
pub fn write_header<'a>(
    out: &'a mut [u8],
    src: Addr,
    dst: Addr,
    next_header: u8,
    payload_len: usize,
) -> Option<&'a mut [u8]> {
    let payload = u16::try_from(payload_len).ok()?;
    let (header, rest) = out.split_at_mut_checked(HEADER_LEN)?;
    let rest = rest.get_mut(..payload_len)?;

    // Version 6, traffic class 0, flow label 0.
    header[0] = 0x60;
    header[1] = 0;
    header[2..4].copy_from_slice(&0u16.to_be_bytes());
    header[4..6].copy_from_slice(&payload.to_be_bytes());
    header[6] = next_header;
    header[7] = DEFAULT_HOP_LIMIT;
    header[8..24].copy_from_slice(&src);
    header[24..40].copy_from_slice(&dst);
    Some(rest)
}

/// A parsed header and the payload it introduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub src: Addr,
    pub dst: Addr,
    /// What follows the fixed header. A value this crate does not handle is
    /// reported rather than skipped.
    pub next_header: u8,
    pub payload: &'a [u8],
}

/// Parses a datagram.
///
/// Refuses a datagram too short for a header, one that is not version 6, and
/// one whose payload length reaches past what was received. **The payload is
/// cut to the length field**, not to the buffer: a NIC pads a short frame, and
/// the padding is not payload — a checksum computed over it fails, and a
/// parser that included it would be checksumming the wire's own filler.
pub fn parse(datagram: &[u8]) -> Option<Packet<'_>> {
    let header = datagram.get(..HEADER_LEN)?;
    if header[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let end = HEADER_LEN.checked_add(payload_len)?;
    if end > datagram.len() {
        return None;
    }
    let mut src: Addr = [0; 16];
    let mut dst: Addr = [0; 16];
    src.copy_from_slice(&header[8..24]);
    dst.copy_from_slice(&header[24..40]);
    Some(Packet {
        src,
        dst,
        next_header: header[6],
        payload: datagram.get(HEADER_LEN..end)?,
    })
}

/// Sums the pseudo-header RFC 8200 puts in front of an upper-layer datagram.
///
/// **Four bytes of length, not two, and three of zeroes before the next
/// header.** The v4 pseudo-header is twelve bytes and this one is forty; a
/// checksum that reused the v4 shape with v6 addresses would be wrong in a way
/// only a real peer would notice, which is exactly the bug the wire catches
/// and a round-trip test does not.
pub fn pseudo_header(src: Addr, dst: Addr, upper_len: u32, next_header: u8) -> Sum {
    Sum::new()
        .add(&src)
        .add(&dst)
        .add_u16((upper_len >> 16) as u16)
        .add_u16((upper_len & 0xffff) as u16)
        .add_u16(0)
        .add_u16(u16::from(next_header))
}
