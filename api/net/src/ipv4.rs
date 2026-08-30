// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! IPv4, header only: build one, and read one somebody else built.
//!
//! **No fragmentation, no options.** Both are refused rather than skipped.
//! A reassembler is a state machine with a memory budget and its own attack
//! surface, and nothing this crate serves yet sends a datagram that needs one;
//! a parser that silently ignored the fragment offset would hand its caller
//! the first fragment as though it were the whole datagram, which is a wrong
//! answer rather than a missing feature.
//!
//! Normative: docs/network/01-network-stack.md

use crate::checksum::Sum;

/// An IPv4 address.
pub type Addr = [u8; 4];

/// The all-ones broadcast, which is where a client with no address sends.
pub const BROADCAST: Addr = [255, 255, 255, 255];

/// The address a host uses before it has one.
pub const UNSPECIFIED: Addr = [0, 0, 0, 0];

/// A header with no options, which is the only kind this module writes.
pub const HEADER_LEN: usize = 20;

/// UDP's protocol number.
pub const PROTO_UDP: u8 = 17;

/// What this module puts in the TTL field: the conventional default.
const DEFAULT_TTL: u8 = 64;

/// Version 4, header length 5 words — the first byte of every header here.
const VERSION_IHL: u8 = 0x45;

/// Writes a header covering a `payload_len`-byte payload, returning the space
/// the payload goes in.
///
/// The checksum is computed over the header as written, so this must be called
/// before the payload is filled in — the header's checksum does not cover it.
pub fn write_header(
    out: &mut [u8],
    src: Addr,
    dst: Addr,
    protocol: u8,
    identification: u16,
    payload_len: usize,
) -> Option<&mut [u8]> {
    let total_len = u16::try_from(HEADER_LEN.checked_add(payload_len)?).ok()?;
    let (header, rest) = out.split_at_mut_checked(HEADER_LEN)?;
    let rest = rest.get_mut(..payload_len)?;

    header[0] = VERSION_IHL;
    header[1] = 0; // DSCP/ECN: no differentiated service is asked for.
    header[2..4].copy_from_slice(&total_len.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6..8].copy_from_slice(&0u16.to_be_bytes()); // No flags, no offset.
    header[8] = DEFAULT_TTL;
    header[9] = protocol;
    header[10..12].copy_from_slice(&0u16.to_be_bytes()); // Zeroed while summed.
    header[12..16].copy_from_slice(&src);
    header[16..20].copy_from_slice(&dst);

    let sum = Sum::new().add(header).fold();
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    Some(rest)
}

/// A parsed header and the payload it introduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub src: Addr,
    pub dst: Addr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

/// Parses a datagram, verifying the header checksum.
///
/// Refuses, in this order: a datagram too short to hold a header, one that is
/// not version 4, one whose header length is below the minimum or beyond the
/// datagram, a bad header checksum, a fragment, and a total length that does
/// not fit inside the bytes actually received.
///
/// **The total-length field is believed only after it is checked against the
/// received length**, and the payload is cut to it rather than to the buffer.
/// A NIC pads a short frame up to the minimum, so the bytes after the datagram
/// are real and are not payload — a UDP checksum computed over them fails, and
/// a DHCP option walk over them reads pad as options.
pub fn parse(datagram: &[u8]) -> Option<Packet<'_>> {
    let first = *datagram.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = (first & 0x0f) as usize * 4;
    if header_len < HEADER_LEN {
        return None;
    }
    let header = datagram.get(..header_len)?;
    if Sum::new().add(header).fold() != 0 {
        return None;
    }
    // Bit 13 is "more fragments"; the low 13 bits are the offset. Either one
    // set means this is a piece of a datagram, and a piece is not a datagram.
    let flags_offset = u16::from_be_bytes([header[6], header[7]]);
    if flags_offset & 0x3fff != 0 {
        return None;
    }
    let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total_len < header_len || total_len > datagram.len() {
        return None;
    }
    let mut src: Addr = [0; 4];
    let mut dst: Addr = [0; 4];
    src.copy_from_slice(&header[12..16]);
    dst.copy_from_slice(&header[16..20]);
    Some(Packet {
        src,
        dst,
        protocol: header[9],
        payload: datagram.get(header_len..total_len)?,
    })
}
