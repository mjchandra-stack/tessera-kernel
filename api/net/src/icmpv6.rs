// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! ICMPv6, and the two messages a host cannot be reached without.
//!
//! **Neighbour Discovery is not optional, and finding that out cost a round
//! trip** (D279). IPv6 has no ARP; a peer that wants to send a host a unicast
//! datagram first asks *"who has this address"* with a Neighbour Solicitation
//! and waits for a Neighbour Advertisement naming the link-layer address. A
//! host that never answers is a host nothing can reply to — the DHCPv6
//! exchange sent its request, the server solicited, and the Reply was never
//! sent because there was nowhere to send it. A stack that speaks UDP over
//! IPv6 and not this speaks to nobody.
//!
//! **Solicitation parsing and advertisement building only.** This host answers
//! neighbours; it does not ask. Asking needs a cache with entries that expire
//! and a queue of datagrams waiting on resolution, and nothing here sends a
//! unicast IPv6 datagram to an address it had to learn — every one it sends
//! goes to a multicast group, whose link-layer address is arithmetic.
//!
//! Normative: docs/network/01-network-stack.md

use crate::eth::Mac;
use crate::ipv6::{self, Addr};

/// Neighbour Solicitation.
pub const NEIGHBOUR_SOLICITATION: u8 = 135;
/// Neighbour Advertisement.
pub const NEIGHBOUR_ADVERTISEMENT: u8 = 136;

/// Type, code and checksum.
const HEADER_LEN: usize = 4;

/// An advertisement: header, flags, target, and the target's link-layer
/// address as an option.
pub const ADVERTISEMENT_LEN: usize = HEADER_LEN + 4 + 16 + 8;

/// Set in an advertisement that answers a solicitation.
const FLAG_SOLICITED: u8 = 0x40;
/// Set to say this answer supersedes whatever the peer had cached.
const FLAG_OVERRIDE: u8 = 0x20;

/// The Target Link-Layer Address option (RFC 4861), in units of eight bytes.
const OPTION_TARGET_LL: u8 = 2;

/// Reads a Neighbour Solicitation and returns the address it asks about.
///
/// **Only the target is returned.** A solicitation may carry the sender's own
/// link-layer address as an option, and this host does not cache it: it
/// answers to the Ethernet source the frame arrived from, which is the same
/// information and needs no table to hold.
pub fn parse_solicitation(message: &[u8]) -> Option<Addr> {
    let body = message.get(..24)?;
    if body[0] != NEIGHBOUR_SOLICITATION || body[1] != 0 {
        return None;
    }
    let mut target: Addr = [0; 16];
    target.copy_from_slice(&body[8..24]);
    Some(target)
}

/// Builds a Neighbour Advertisement for `target`, whose link-layer address is
/// `mac`, into `out`.
///
/// The checksum covers the IPv6 pseudo-header, exactly as UDP's does — which
/// is why `src` and `dst` are needed to build a message that carries neither.
pub fn build_advertisement(
    out: &mut [u8],
    src: Addr,
    dst: Addr,
    target: Addr,
    mac: Mac,
) -> Option<usize> {
    let message = out.get_mut(..ADVERTISEMENT_LEN)?;
    message.fill(0);
    message[0] = NEIGHBOUR_ADVERTISEMENT;
    message[1] = 0;
    // 2..4 is the checksum, left zero while it is computed.
    message[4] = FLAG_SOLICITED | FLAG_OVERRIDE;
    message[8..24].copy_from_slice(&target);
    message[24] = OPTION_TARGET_LL;
    message[25] = 1; // one eight-byte unit
    message[26..32].copy_from_slice(&mac);

    let sum = ipv6::pseudo_header(src, dst, ADVERTISEMENT_LEN as u32, ipv6::NEXT_ICMPV6)
        .add(message)
        .fold();
    // **Never zero on the wire.** ICMPv6 has no "not computed" encoding at
    // all, so a folded zero goes out as all ones exactly as UDP's does.
    let on_wire = if sum == 0 { 0xffff } else { sum };
    message[2..4].copy_from_slice(&on_wire.to_be_bytes());
    Some(ADVERTISEMENT_LEN)
}

/// Verifies an ICMPv6 message's checksum against the addresses it arrived on.
pub fn verify(message: &[u8], src: Addr, dst: Addr) -> bool {
    let len = message.len();
    ipv6::pseudo_header(src, dst, len as u32, ipv6::NEXT_ICMPV6)
        .add(message)
        .fold()
        == 0
}
