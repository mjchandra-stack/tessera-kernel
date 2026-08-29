// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! UDP, over IPv4 or IPv6.
//!
//! **The checksum is the whole of the difficulty.** It covers a pseudo-header
//! that is never transmitted — the addresses out of the network header, the
//! protocol number, and the UDP length repeated — which is what binds a
//! datagram to the addresses it was sent between. A receiver that skipped it
//! would accept a datagram delivered to the wrong host by a rewritten header.
//!
//! **One implementation, two families, and the differences are stated as
//! code.** The pseudo-headers are different shapes — twelve bytes against
//! forty, a two-byte length against four — and over IPv6 the checksum is
//! **mandatory**: a zero there is a datagram to refuse, where over IPv4 it
//! means "not computed". That asymmetry is the one thing a shared
//! implementation must not smooth over, because the IPv6 header has no
//! checksum of its own, so skipping the transport's leaves nothing checking
//! the addresses at all.
//!
//! Normative: docs/network/01-network-stack.md

use crate::checksum::Sum;
use crate::ipv4::PROTO_UDP;
use crate::{ipv4, ipv6};

/// Source port, destination port, length, checksum.
pub const HEADER_LEN: usize = 8;

/// The addresses a datagram travels between, in whichever family carries it.
///
/// **Carried as one value rather than two parameters**, because the family
/// decides the pseudo-header's shape *and* whether a zero checksum is legal —
/// two facts that must not be able to disagree. A signature taking four bytes
/// and a flag would let a caller pass v6 addresses and a v4 rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peers {
    V4 { src: ipv4::Addr, dst: ipv4::Addr },
    V6 { src: ipv6::Addr, dst: ipv6::Addr },
}

impl Peers {
    /// The pseudo-header this family puts in front of a `udp_len`-byte
    /// datagram.
    fn pseudo_header(&self, udp_len: u16) -> Sum {
        match self {
            Peers::V4 { src, dst } => Sum::new()
                .add(src)
                .add(dst)
                .add_u16(PROTO_UDP as u16)
                .add_u16(udp_len),
            Peers::V6 { src, dst } => {
                ipv6::pseudo_header(*src, *dst, u32::from(udp_len), ipv6::NEXT_UDP)
            }
        }
    }

    /// Whether a checksum field of zero may be believed.
    ///
    /// True only over IPv4 (RFC 768). Over IPv6 the network header carries no
    /// checksum, so RFC 8200 makes the transport's mandatory and a zero is a
    /// datagram that has to be refused.
    fn zero_checksum_allowed(&self) -> bool {
        matches!(self, Peers::V4 { .. })
    }
}

/// Writes a header and copies `payload` in after it, checksum included.
///
/// Returns the number of bytes written, which is the UDP length the IPv4
/// header above must already have been told about.
pub fn write(
    out: &mut [u8],
    peers: Peers,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    let udp_len = u16::try_from(HEADER_LEN.checked_add(payload.len())?).ok()?;
    let datagram = out.get_mut(..udp_len as usize)?;
    datagram[0..2].copy_from_slice(&src_port.to_be_bytes());
    datagram[2..4].copy_from_slice(&dst_port.to_be_bytes());
    datagram[4..6].copy_from_slice(&udp_len.to_be_bytes());
    datagram[6..8].copy_from_slice(&0u16.to_be_bytes()); // Zeroed while summed.
    datagram[HEADER_LEN..].copy_from_slice(payload);

    let sum = peers.pseudo_header(udp_len).add(datagram).fold();
    // **Zero means "not computed", so a computed zero is sent as all ones.**
    // The two have the same one's-complement value and opposite meanings; a
    // receiver told zero skips the check it was just asked to make.
    let on_wire = if sum == 0 { 0xffff } else { sum };
    datagram[6..8].copy_from_slice(&on_wire.to_be_bytes());
    Some(udp_len as usize)
}

/// A parsed datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parses a datagram carried between `src_addr` and `dst_addr`, verifying the
/// checksum against them.
///
/// A checksum field of zero is accepted unverified over IPv4, which is what
/// RFC 768 says it means, and **refused over IPv6**, where RFC 8200 makes the
/// transport checksum mandatory. Every other value must verify.
pub fn parse(datagram: &[u8], peers: Peers) -> Option<Datagram<'_>> {
    let header = datagram.get(..HEADER_LEN)?;
    let udp_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if udp_len < HEADER_LEN {
        return None;
    }
    // The length field, not the buffer: a padded frame has bytes after the
    // datagram, and summing them fails a checksum that is correct.
    let datagram = datagram.get(..udp_len)?;
    let stated = u16::from_be_bytes([header[6], header[7]]);
    if stated == 0 {
        // "Not computed", which only IPv4 allows.
        if !peers.zero_checksum_allowed() {
            return None;
        }
    } else {
        let sum = peers.pseudo_header(udp_len as u16).add(datagram).fold();
        if sum != 0 {
            return None;
        }
    }
    Some(Datagram {
        src_port: u16::from_be_bytes([header[0], header[1]]),
        dst_port: u16::from_be_bytes([header[2], header[3]]),
        payload: datagram.get(HEADER_LEN..)?,
    })
}
