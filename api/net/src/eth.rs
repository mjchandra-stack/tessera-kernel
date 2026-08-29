// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Ethernet II framing: the 14 bytes under everything else here.
//!
//! Normative: docs/network/01-network-stack.md

/// A MAC address.
pub type Mac = [u8; 6];

/// Every station on the segment.
pub const BROADCAST: Mac = [0xff; 6];

/// The header this module writes and reads: destination, source, ethertype.
pub const HEADER_LEN: usize = 14;

/// IPv4 rides on this ethertype.
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// ARP rides on this one. Declared so a receiver can tell the two apart
/// without a second table; this crate parses no ARP (`kernel/virtio::arp`
/// still owns that, build/README.md D271).
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// Writes a header into the front of `out`, returning what follows it.
///
/// Returns `None` if `out` cannot hold a header, rather than writing a partial
/// one: a caller that ignored a short buffer would transmit a frame whose
/// ethertype is payload.
pub fn write_header<'a>(
    out: &'a mut [u8],
    dst: Mac,
    src: Mac,
    ethertype: u16,
) -> Option<&'a mut [u8]> {
    let (header, rest) = out.split_at_mut_checked(HEADER_LEN)?;
    header[0..6].copy_from_slice(&dst);
    header[6..12].copy_from_slice(&src);
    header[12..14].copy_from_slice(&ethertype.to_be_bytes());
    Some(rest)
}

/// A frame's header fields and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Splits a received frame into its header and payload.
///
/// **A frame shorter than a header is refused rather than clamped.** Anything
/// on the wire is whatever the segment sent, and the length is the first field
/// a parser can be wrong about.
pub fn parse(frame: &[u8]) -> Option<Frame<'_>> {
    let (header, payload) = frame.split_at_checked(HEADER_LEN)?;
    let mut dst: Mac = [0; 6];
    let mut src: Mac = [0; 6];
    dst.copy_from_slice(&header[0..6]);
    src.copy_from_slice(&header[6..12]);
    Some(Frame {
        dst,
        src,
        ethertype: u16::from_be_bytes([header[12], header[13]]),
        payload,
    })
}
