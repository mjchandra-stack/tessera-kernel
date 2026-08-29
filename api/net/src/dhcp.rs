// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! DHCP, client side: ask for a lease and read what is offered.
//!
//! **Why this is the first thing above UDP.** A round trip needs somebody to
//! answer, and DHCP is the one service the emulated network answers from
//! inside itself — QEMU's user-mode backend runs the server, so the exchange
//! depends on no host daemon, no external address and no name resolution. It
//! also happens to exercise the whole stack under it: a broadcast that ARP
//! cannot help with, a real IPv4 header, and a UDP checksum over a
//! pseudo-header whose source address is still unset.
//!
//! **What this is not.** There is no lease state machine here: no REQUEST, no
//! ACK, no renewal timers, no address assignment. This builds a DISCOVER and
//! reads an OFFER, which is the exchange that proves the layers below carry a
//! datagram both ways. The rest is a service's job, not a parser's.
//!
//! Normative: docs/network/01-network-stack.md

use crate::eth::Mac;
use crate::ipv4::Addr;

/// The client's port. A DHCP server replies here, not to the source port.
pub const CLIENT_PORT: u16 = 68;

/// The server's port.
pub const SERVER_PORT: u16 = 67;

/// BOOTP's fixed area plus the four-byte magic cookie: where options start.
pub const FIXED_LEN: usize = 240;

/// The shortest message this module will build: the fixed area, a message-type
/// option, a parameter request list, and the end marker.
pub const DISCOVER_LEN: usize = FIXED_LEN + 3 + 5 + 1;

/// `BOOTREQUEST`, which every client message is.
const OP_REQUEST: u8 = 1;
/// `BOOTREPLY`, which every server message is.
const OP_REPLY: u8 = 2;
/// Ethernet, 6-byte addresses.
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;

/// `0x63825363`, the four bytes that say the options area is DHCP's and not
/// BOOTP's vendor field.
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Ask the server to broadcast its reply. A client with no address configured
/// cannot receive a unicast one, because the sender would have to ARP for an
/// address nobody has yet.
const FLAG_BROADCAST: u16 = 0x8000;

/// Option codes this module reads or writes.
mod option {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST: u8 = 55;
    pub const END: u8 = 255;
}

/// The message types this exchange uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
}

/// Builds a DISCOVER into `out`, returning its length.
///
/// `xid` is the transaction id the reply must echo. It is the caller's to
/// choose because it is the only thing tying an offer to this request, and
/// this crate has no randomness of its own — the kernel CSPRNG is the only
/// source of it (`docs/lifecycle/04`), and a parser does not get to call one.
pub fn build_discover(out: &mut [u8], client: Mac, xid: u32) -> Option<usize> {
    let message = out.get_mut(..DISCOVER_LEN)?;
    message.fill(0);

    message[0] = OP_REQUEST;
    message[1] = HTYPE_ETHERNET;
    message[2] = HLEN_ETHERNET;
    message[3] = 0; // hops
    message[4..8].copy_from_slice(&xid.to_be_bytes());
    message[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
    message[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes());
    // ciaddr, yiaddr, siaddr, giaddr stay zero: this client has no address and
    // is not being relayed.
    message[28..34].copy_from_slice(&client);
    message[236..240].copy_from_slice(&MAGIC_COOKIE);

    let options = &mut message[FIXED_LEN..];
    options[0] = option::MESSAGE_TYPE;
    options[1] = 1;
    options[2] = MessageType::Discover as u8;
    options[3] = option::PARAMETER_REQUEST;
    options[4] = 3;
    options[5] = option::SUBNET_MASK;
    options[6] = option::ROUTER;
    options[7] = option::DNS;
    options[8] = option::END;
    Some(DISCOVER_LEN)
}

/// What a server offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer {
    /// The address being offered, out of `yiaddr`.
    pub offered: Addr,
    /// The server's own address, out of option 54.
    pub server: Addr,
    /// Option 1, when the server sent one.
    pub subnet_mask: Option<Addr>,
    /// Option 3's first entry, when the server sent one.
    pub router: Option<Addr>,
}

/// Reads an OFFER that answers `xid`.
///
/// **`xid` is checked, not reported.** A reply carrying somebody else's
/// transaction id is not a malformed offer, it is an answer to a question this
/// client did not ask, and returning it would let a caller act on it.
pub fn parse_offer(message: &[u8], xid: u32) -> Option<Offer> {
    let fixed = message.get(..FIXED_LEN)?;
    if fixed[0] != OP_REPLY || fixed[1] != HTYPE_ETHERNET || fixed[2] != HLEN_ETHERNET {
        return None;
    }
    if u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]) != xid {
        return None;
    }
    if fixed[236..240] != MAGIC_COOKIE {
        return None;
    }
    let mut offered: Addr = [0; 4];
    offered.copy_from_slice(&fixed[16..20]);

    let mut message_type = None;
    let mut server = None;
    let mut subnet_mask = None;
    let mut router = None;
    for (code, value) in Options::new(message.get(FIXED_LEN..)?) {
        match code {
            option::MESSAGE_TYPE => message_type = value.first().copied(),
            option::SERVER_ID => server = addr_of(value),
            option::SUBNET_MASK => subnet_mask = addr_of(value),
            // A router option is a *list*; the first entry is the default
            // gateway and the rest are alternates this client has no use for.
            option::ROUTER => router = value.get(..4).and_then(addr_of),
            _ => {}
        }
    }
    if message_type != Some(MessageType::Offer as u8) {
        return None;
    }
    Some(Offer {
        offered,
        // An offer with no server identifier is unusable: option 54 is what a
        // REQUEST has to be addressed to, so a caller could not act on it.
        server: server?,
        subnet_mask,
        router,
    })
}

/// A four-byte option value read as an address.
fn addr_of(value: &[u8]) -> Option<Addr> {
    let mut addr: Addr = [0; 4];
    addr.copy_from_slice(value.get(..4)?);
    Some(addr)
}

/// Walks the `(code, value)` pairs in an options area.
///
/// **This is the hostile walk**, and it is an iterator so that its termination
/// is one thing to reason about rather than one per caller. Three ways to
/// stop: the END marker, running out of bytes, and a length field reaching
/// past the end — the last being the one a fuzzer finds, and the reason the
/// slice is taken with `get` rather than indexed.
struct Options<'a>(&'a [u8]);

impl<'a> Options<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (&code, rest) = self.0.split_first()?;
            if code == option::END {
                self.0 = &[];
                return None;
            }
            if code == option::PAD {
                // Pad carries no length byte, which is what makes this a loop
                // rather than a single read.
                self.0 = rest;
                continue;
            }
            let (&len, rest) = rest.split_first()?;
            let (value, rest) = rest.split_at_checked(len as usize)?;
            self.0 = rest;
            return Some((code, value));
        }
    }
}
