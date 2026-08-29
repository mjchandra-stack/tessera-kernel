// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! DHCPv6, the stateless half: ask what the network knows, and read the answer.
//!
//! **Information-Request and Reply only** (RFC 3736, "Stateless DHCPv6"). There
//! is no SOLICIT, no ADVERTISE and no address assignment here, because IPv6
//! hosts get addresses from Router Advertisement and use DHCPv6 for the rest —
//! and because the stateless exchange is the one a host can complete with a
//! link-local address it formed itself, needing nothing configured first.
//!
//! **Why this is the v6 exchange the wire can prove.** It is the only UDP
//! service QEMU's user-mode backend answers over IPv6, which makes it the v6
//! counterpart of what DHCP is for v4 (`crate::dhcp`): a server inside the
//! emulated network, no host daemon, no name resolution, and an answer or
//! nothing.
//!
//! Normative: docs/network/01-network-stack.md

use crate::eth::Mac;
use crate::ipv6::Addr;

/// The client's port.
pub const CLIENT_PORT: u16 = 546;
/// The server's port.
pub const SERVER_PORT: u16 = 547;

/// Ask what the network knows, holding no address lease.
const INFORMATION_REQUEST: u8 = 11;
/// The server's answer.
const REPLY: u8 = 7;

/// Option codes this module writes or reads.
mod option {
    pub const CLIENT_ID: u16 = 1;
    pub const SERVER_ID: u16 = 2;
    pub const ORO: u16 = 6;
    pub const DNS_SERVERS: u16 = 23;
}

/// DUID-LL: a DUID made of the link-layer address, which is the one a host can
/// form without storage. Type 3, hardware type 1 (Ethernet), then the MAC.
const DUID_LL_LEN: usize = 10;

/// The message this module builds: header, client id, and one option request.
pub const INFORMATION_REQUEST_LEN: usize = 4 + (4 + DUID_LL_LEN) + (4 + 2);

/// Builds an Information-Request into `out`, returning its length.
///
/// `xid` is the 24-bit transaction id the reply must echo; only its low three
/// bytes are used.
pub fn build_information_request(out: &mut [u8], client: Mac, xid: u32) -> Option<usize> {
    let message = out.get_mut(..INFORMATION_REQUEST_LEN)?;
    message.fill(0);
    message[0] = INFORMATION_REQUEST;
    // 24 bits, big-endian, which is why this is three bytes and not a u32.
    message[1] = (xid >> 16) as u8;
    message[2] = (xid >> 8) as u8;
    message[3] = xid as u8;

    let mut at = 4;
    // CLIENTID, carrying a DUID-LL. A server that cannot tell clients apart
    // cannot answer them, and this is the identifier a host has before it has
    // anything else.
    message[at..at + 2].copy_from_slice(&option::CLIENT_ID.to_be_bytes());
    message[at + 2..at + 4].copy_from_slice(&(DUID_LL_LEN as u16).to_be_bytes());
    message[at + 4..at + 6].copy_from_slice(&3u16.to_be_bytes()); // DUID-LL
    message[at + 6..at + 8].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    message[at + 8..at + 14].copy_from_slice(&client);
    at += 4 + DUID_LL_LEN;

    // ORO: ask for the one option this exchange is about.
    message[at..at + 2].copy_from_slice(&option::ORO.to_be_bytes());
    message[at + 2..at + 4].copy_from_slice(&2u16.to_be_bytes());
    message[at + 4..at + 6].copy_from_slice(&option::DNS_SERVERS.to_be_bytes());

    Some(INFORMATION_REQUEST_LEN)
}

/// What a server answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// The first recursive name server it named, when it named one.
    pub dns: Option<Addr>,
    /// Whether the server identified itself, which RFC 8415 requires of a
    /// Reply and which is therefore worth reporting rather than assuming.
    pub has_server_id: bool,
}

/// Reads a Reply that answers `xid`.
///
/// **The transaction id is checked, not reported.** A reply carrying somebody
/// else's is an answer to a question this client did not ask, and returning it
/// would let a caller act on it — the same rule `crate::dhcp` follows, and the
/// reason both take the id rather than handing it back.
pub fn parse_reply(message: &[u8], xid: u32) -> Option<Reply> {
    let header = message.get(..4)?;
    if header[0] != REPLY {
        return None;
    }
    let got = (u32::from(header[1]) << 16) | (u32::from(header[2]) << 8) | u32::from(header[3]);
    if got != xid & 0x00ff_ffff {
        return None;
    }
    let mut dns = None;
    let mut has_server_id = false;
    for (code, value) in Options(message.get(4..)?) {
        match code {
            option::SERVER_ID => has_server_id = true,
            option::DNS_SERVERS => {
                // A list; the first entry is the one a resolver would try.
                if dns.is_none()
                    && let Some(first) = value.get(..16)
                {
                    let mut addr: Addr = [0; 16];
                    addr.copy_from_slice(first);
                    dns = Some(addr);
                }
            }
            _ => {}
        }
    }
    Some(Reply { dns, has_server_id })
}

/// Walks the `(code, value)` pairs of a DHCPv6 options area.
///
/// **Every option carries its length**, unlike DHCPv4 where PAD and END do
/// not — so this is a plain walk with no special cases, and it stops on the
/// two things that can go wrong: running out of bytes, and a length that
/// reaches past the end.
struct Options<'a>(&'a [u8]);

impl<'a> Iterator for Options<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let header = self.0.get(..4)?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        let (value, rest) = self.0.get(4..)?.split_at_checked(len)?;
        self.0 = rest;
        Some((code, value))
    }
}
