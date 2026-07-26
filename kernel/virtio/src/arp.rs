// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A minimal ARP request builder and reply parser — just enough to prove the
//! virtio-net datapath with a real round-trip against QEMU's SLIRP gateway,
//! without pulling in an IP stack. Pure byte logic over Ethernet + ARP frames,
//! so it is `unsafe`-free and host-tested end to end.
//!
//! Wire fields are big-endian (network order).
//!
//! Normative: docs/hardware/04-device-memory-and-unified-memory.md

/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// ARP operation: request.
pub const OP_REQUEST: u16 = 1;
/// ARP operation: reply.
pub const OP_REPLY: u16 = 2;
/// Bytes in an Ethernet + ARP-over-IPv4 frame (14 header + 28 ARP).
pub const FRAME_LEN: usize = 42;

const ETHERTYPE_IPV4: u16 = 0x0800;
const HTYPE_ETHERNET: u16 = 1;

/// Builds a broadcast ARP request asking who owns `target_ip`, from
/// `src_mac`/`src_ip`.
pub fn build_request(src_mac: [u8; 6], src_ip: [u8; 4], target_ip: [u8; 4]) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    // Ethernet header.
    frame[0..6].copy_from_slice(&[0xff; 6]); // destination: broadcast
    frame[6..12].copy_from_slice(&src_mac); // source
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    // ARP payload.
    frame[14..16].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    frame[16..18].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame[18] = 6; // hardware address length
    frame[19] = 4; // protocol address length
    frame[20..22].copy_from_slice(&OP_REQUEST.to_be_bytes());
    frame[22..28].copy_from_slice(&src_mac); // sender hardware address
    frame[28..32].copy_from_slice(&src_ip); // sender protocol address
    // target hardware address (32..38) stays zero — it is what we are asking for
    frame[38..42].copy_from_slice(&target_ip); // target protocol address
    frame
}

/// The sender identity from a parsed ARP reply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reply {
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
}

/// Parses `frame` as an ARP reply, returning the sender's MAC and IP, or `None`
/// if it is too short, not an ARP frame, or not a reply.
pub fn parse_reply(frame: &[u8]) -> Option<Reply> {
    if frame.len() < FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_ARP {
        return None;
    }
    if u16::from_be_bytes([frame[20], frame[21]]) != OP_REPLY {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[22..28]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&frame[28..32]);
    Some(Reply {
        sender_mac,
        sender_ip,
    })
}
