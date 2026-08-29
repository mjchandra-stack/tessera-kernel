// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! UDP over IPv4.
//!
//! **The checksum is the whole of the difficulty.** It covers a pseudo-header
//! that is never transmitted — the addresses out of the IPv4 header, the
//! protocol number, and the UDP length repeated — which is what binds a
//! datagram to the addresses it was sent between. A receiver that skipped it
//! would accept a datagram delivered to the wrong host by a rewritten header.
//!
//! Normative: docs/network/01-network-stack.md

use crate::checksum::Sum;
use crate::ipv4::{Addr, PROTO_UDP};

/// Source port, destination port, length, checksum.
pub const HEADER_LEN: usize = 8;

/// Sums the pseudo-header RFC 768 puts in front of the datagram.
fn pseudo_header(src: Addr, dst: Addr, udp_len: u16) -> Sum {
    Sum::new()
        .add(&src)
        .add(&dst)
        .add_u16(PROTO_UDP as u16)
        .add_u16(udp_len)
}

/// Writes a header and copies `payload` in after it, checksum included.
///
/// Returns the number of bytes written, which is the UDP length the IPv4
/// header above must already have been told about.
pub fn write<'a>(
    out: &'a mut [u8],
    src_addr: Addr,
    dst_addr: Addr,
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

    let sum = pseudo_header(src_addr, dst_addr, udp_len)
        .add(datagram)
        .fold();
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
/// A checksum field of zero is accepted unverified, which is what RFC 768
/// says it means over IPv4. Every other value must verify.
pub fn parse<'a>(datagram: &'a [u8], src_addr: Addr, dst_addr: Addr) -> Option<Datagram<'a>> {
    let header = datagram.get(..HEADER_LEN)?;
    let udp_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if udp_len < HEADER_LEN {
        return None;
    }
    // The length field, not the buffer: a padded frame has bytes after the
    // datagram, and summing them fails a checksum that is correct.
    let datagram = datagram.get(..udp_len)?;
    let stated = u16::from_be_bytes([header[6], header[7]]);
    if stated != 0 {
        let sum = pseudo_header(src_addr, dst_addr, udp_len as u16)
            .add(datagram)
            .fold();
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
