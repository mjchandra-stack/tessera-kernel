// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Host tests for the protocol layers.
//!
//! **The oracles are external where one exists.** A test that builds a header
//! with this crate and parses it with this crate agrees with itself and proves
//! only that the two halves are inverses — it would pass just as happily if
//! both were wrong about the byte order. So the checksum is checked against
//! RFC 1071's own worked example and against a header published with its
//! answer, and only then is the round trip used, for the parts no published
//! example covers.
//!
//! The strongest oracle for this crate is not here at all: it is
//! `//tools/qemu:net_stack_boot_aarch64_test`, where QEMU's DHCP server
//! decides whether the datagram was well-formed. A test can be wrong about
//! this crate and cannot be wrong about what that server accepts.

use std::vec;
use std::vec::Vec;

use crate::checksum::{Sum, checksum};
use crate::{
    build_dhcp_discover, build_udp_frame, dhcp, eth, ipv4, parse_dhcp_offer, parse_udp_frame, udp,
};

const CLIENT_MAC: eth::Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const XID: u32 = 0x3903_F326;

/// RFC 1071 section 3's worked example, with the answer the RFC states.
#[test]
fn rfc1071_worked_example() {
    let bytes = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(checksum(&bytes), 0x220d);
}

/// A published IPv4 header and the checksum published with it. The field is
/// zeroed, summed, and must reproduce the documented value; summed *including*
/// the field it must come out zero, which is what a receiver actually checks.
#[test]
fn known_ipv4_header_checksum() {
    let mut header = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    assert_eq!(checksum(&header), 0xb861);
    header[10..12].copy_from_slice(&0xb861u16.to_be_bytes());
    assert_eq!(checksum(&header), 0);
}

/// The fold has to run twice. A sum whose low half carries out when the high
/// half is folded in needs the second pass, and one pass is the classic
/// off-by-one — this is the input that separates them.
#[test]
fn fold_carries_twice() {
    let sum = Sum::new().add_u16(0xffff).add_u16(0xffff).add_u16(0x0001);
    assert_eq!(sum.fold(), 0xfffe);
}

/// An odd-length span is padded on the right, not on the left.
#[test]
fn odd_length_pads_right() {
    assert_eq!(checksum(&[0x12]), checksum(&[0x12, 0x00]));
    assert_ne!(checksum(&[0x12]), checksum(&[0x00, 0x12]));
}

/// A DISCOVER this crate builds is a frame whose every layer verifies, checked
/// by walking it apart by hand rather than with the parser that mirrors the
/// builder.
#[test]
fn discover_is_well_formed() {
    let mut frame = [0u8; crate::MAX_FRAME_LEN];
    let len = build_dhcp_discover(&mut frame, CLIENT_MAC, XID).expect("builds");
    assert_eq!(len, crate::MAX_FRAME_LEN);

    assert_eq!(&frame[0..6], &eth::BROADCAST);
    assert_eq!(&frame[6..12], &CLIENT_MAC);
    assert_eq!(
        u16::from_be_bytes([frame[12], frame[13]]),
        eth::ETHERTYPE_IPV4
    );

    // The IPv4 header sums to zero with its checksum in place.
    let ip = &frame[eth::HEADER_LEN..eth::HEADER_LEN + ipv4::HEADER_LEN];
    assert_eq!(checksum(ip), 0);
    assert_eq!(ip[9], ipv4::PROTO_UDP);
    assert_eq!(&ip[12..16], &ipv4::UNSPECIFIED);
    assert_eq!(&ip[16..20], &ipv4::BROADCAST);
    // Total length covers the IP header and everything after it.
    assert_eq!(
        u16::from_be_bytes([ip[2], ip[3]]) as usize,
        len - eth::HEADER_LEN
    );

    // The UDP datagram verifies against the pseudo-header.
    let udp_at = eth::HEADER_LEN + ipv4::HEADER_LEN;
    let datagram = udp::parse(&frame[udp_at..], ipv4::UNSPECIFIED, ipv4::BROADCAST)
        .expect("the datagram verifies");
    assert_eq!(datagram.src_port, dhcp::CLIENT_PORT);
    assert_eq!(datagram.dst_port, dhcp::SERVER_PORT);

    // And the payload is a DISCOVER carrying this client's MAC.
    assert_eq!(datagram.payload[0], 1);
    assert_eq!(&datagram.payload[28..34], &CLIENT_MAC);
    assert_eq!(
        u32::from_be_bytes(datagram.payload[4..8].try_into().expect("four bytes")),
        XID
    );
    assert_eq!(&datagram.payload[236..240], &[0x63, 0x82, 0x53, 0x63]);
}

/// Builds the offer QEMU's user-mode backend sends: the lease it always hands
/// out first, from the gateway it always is.
fn slirp_offer(xid: u32, dst: eth::Mac) -> Vec<u8> {
    const SERVER: ipv4::Addr = [10, 0, 2, 2];
    const OFFERED: ipv4::Addr = [10, 0, 2, 15];
    const SERVER_MAC: eth::Mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

    let mut payload = vec![0u8; dhcp::FIXED_LEN];
    payload[0] = 2; // BOOTREPLY
    payload[1] = 1;
    payload[2] = 6;
    payload[4..8].copy_from_slice(&xid.to_be_bytes());
    payload[16..20].copy_from_slice(&OFFERED); // yiaddr
    payload[20..24].copy_from_slice(&SERVER); // siaddr
    payload[28..34].copy_from_slice(&dst);
    payload[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    payload.extend_from_slice(&[53, 1, 2]); // OFFER
    payload.extend_from_slice(&[54, 4, 10, 0, 2, 2]); // server id
    payload.extend_from_slice(&[1, 4, 255, 255, 255, 0]); // subnet mask
    payload.extend_from_slice(&[3, 4, 10, 0, 2, 2]); // router
    payload.push(255);

    let mut frame = vec![0u8; eth::HEADER_LEN + ipv4::HEADER_LEN + udp::HEADER_LEN + payload.len()];
    let after_eth =
        eth::write_header(&mut frame, dst, SERVER_MAC, eth::ETHERTYPE_IPV4).expect("header fits");
    let after_ip = ipv4::write_header(
        after_eth,
        SERVER,
        ipv4::BROADCAST,
        ipv4::PROTO_UDP,
        0,
        udp::HEADER_LEN + payload.len(),
    )
    .expect("header fits");
    udp::write(
        after_ip,
        SERVER,
        ipv4::BROADCAST,
        dhcp::SERVER_PORT,
        dhcp::CLIENT_PORT,
        &payload,
    )
    .expect("datagram fits");
    frame
}

#[test]
fn reads_an_offer() {
    let frame = slirp_offer(XID, eth::BROADCAST);
    let offer = parse_dhcp_offer(&frame, CLIENT_MAC, XID).expect("an offer");
    assert_eq!(offer.offered, [10, 0, 2, 15]);
    assert_eq!(offer.server, [10, 0, 2, 2]);
    assert_eq!(offer.subnet_mask, Some([255, 255, 255, 0]));
    assert_eq!(offer.router, Some([10, 0, 2, 2]));
}

/// An offer answering a different transaction is not this client's.
#[test]
fn refuses_a_foreign_transaction() {
    let frame = slirp_offer(XID ^ 1, eth::BROADCAST);
    assert!(parse_dhcp_offer(&frame, CLIENT_MAC, XID).is_none());
}

/// Traffic addressed to another station on the segment is not ours, even when
/// everything inside it would parse.
#[test]
fn refuses_another_stations_frame() {
    let frame = slirp_offer(XID, [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc]);
    assert!(parse_dhcp_offer(&frame, CLIENT_MAC, XID).is_none());
}

/// One flipped bit anywhere in the datagram fails the UDP checksum. This is
/// the check that makes the checksum load-bearing rather than decorative.
#[test]
fn a_flipped_bit_fails_the_udp_checksum() {
    let good = slirp_offer(XID, eth::BROADCAST);
    let udp_at = eth::HEADER_LEN + ipv4::HEADER_LEN;
    for byte in udp_at..good.len() {
        let mut frame = good.clone();
        frame[byte] ^= 0x01;
        assert!(
            parse_dhcp_offer(&frame, CLIENT_MAC, XID).is_none(),
            "a flip at byte {byte} was accepted"
        );
    }
}

/// A fragment is refused rather than treated as a whole datagram.
#[test]
fn refuses_a_fragment() {
    let mut frame = slirp_offer(XID, eth::BROADCAST);
    let flags_at = eth::HEADER_LEN + 6;
    frame[flags_at..flags_at + 2].copy_from_slice(&0x2000u16.to_be_bytes()); // more-fragments
    let ip_at = eth::HEADER_LEN;
    frame[ip_at + 10..ip_at + 12].copy_from_slice(&0u16.to_be_bytes());
    let sum = checksum(&frame[ip_at..ip_at + ipv4::HEADER_LEN]);
    frame[ip_at + 10..ip_at + 12].copy_from_slice(&sum.to_be_bytes());
    assert!(parse_dhcp_offer(&frame, CLIENT_MAC, XID).is_none());
}

/// Every truncation of a valid frame is refused, and none of them panics.
/// This is the shape the fuzz target generalises.
#[test]
fn every_truncation_is_refused_without_panicking() {
    let frame = slirp_offer(XID, eth::BROADCAST);
    for len in 0..frame.len() {
        assert!(parse_dhcp_offer(&frame[..len], CLIENT_MAC, XID).is_none());
    }
}

/// An option whose length runs past the end of the options area stops the walk
/// instead of reading past it.
#[test]
fn refuses_an_option_overrunning_the_area() {
    let mut payload = vec![0u8; dhcp::FIXED_LEN];
    payload[0] = 2;
    payload[1] = 1;
    payload[2] = 6;
    payload[4..8].copy_from_slice(&XID.to_be_bytes());
    payload[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    payload.extend_from_slice(&[53, 1, 2]);
    payload.extend_from_slice(&[54, 200, 10, 0, 2, 2]); // claims 200 bytes, has 4
    assert!(dhcp::parse_offer(&payload, XID).is_none());
}

/// Pad bytes carry no length and must not be read as though they did.
#[test]
fn walks_past_pad_bytes() {
    let mut payload = vec![0u8; dhcp::FIXED_LEN];
    payload[0] = 2;
    payload[1] = 1;
    payload[2] = 6;
    payload[4..8].copy_from_slice(&XID.to_be_bytes());
    payload[16..20].copy_from_slice(&[10, 0, 2, 15]);
    payload[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    payload.extend_from_slice(&[0, 0, 0]); // pad
    payload.extend_from_slice(&[53, 1, 2]);
    payload.extend_from_slice(&[0]); // pad between options
    payload.extend_from_slice(&[54, 4, 10, 0, 2, 2]);
    payload.push(255);
    let offer = dhcp::parse_offer(&payload, XID).expect("an offer");
    assert_eq!(offer.offered, [10, 0, 2, 15]);
}

/// An options area with no END marker ends when the bytes do.
#[test]
fn unterminated_options_end_with_the_buffer() {
    let mut payload = vec![0u8; dhcp::FIXED_LEN];
    payload[0] = 2;
    payload[1] = 1;
    payload[2] = 6;
    payload[4..8].copy_from_slice(&XID.to_be_bytes());
    payload[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    payload.extend_from_slice(&[53, 1, 2]);
    payload.extend_from_slice(&[54, 4, 10, 0, 2, 2]);
    assert!(dhcp::parse_offer(&payload, XID).is_some());
}

/// A datagram whose UDP length field exceeds what arrived is refused rather
/// than summed over memory that is not payload.
#[test]
fn refuses_an_overlong_udp_length() {
    let mut frame = slirp_offer(XID, eth::BROADCAST);
    let udp_at = eth::HEADER_LEN + ipv4::HEADER_LEN;
    frame[udp_at + 4..udp_at + 6].copy_from_slice(&0xffffu16.to_be_bytes());
    assert!(parse_dhcp_offer(&frame, CLIENT_MAC, XID).is_none());
}

/// A buffer too small for the frame is refused rather than half-filled.
#[test]
fn refuses_to_build_into_a_short_buffer() {
    let mut frame = [0u8; crate::MAX_FRAME_LEN - 1];
    assert!(build_dhcp_discover(&mut frame, CLIENT_MAC, XID).is_none());
}

/// The layering seam carries a payload that is nobody's protocol.
///
/// **Checked with bytes that are not DHCP**, because every other test here goes
/// through a DHCP helper and would still pass if the general path only worked
/// for the one payload it was written against. This is the function
/// `flow_service`'s `SendTo` is built on.
#[test]
fn a_udp_frame_round_trips_with_an_arbitrary_payload() {
    const SRC: ipv4::Addr = [10, 0, 2, 15];
    const DST: ipv4::Addr = [10, 0, 2, 2];
    const PEER: eth::Mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    let payload: [u8; 5] = *b"hello";

    let mut frame = [0u8; crate::HEADERS_LEN + 5];
    let len = build_udp_frame(
        &mut frame, CLIENT_MAC, PEER, SRC, DST, 5000, 7, 0x1234, &payload,
    )
    .expect("builds");
    assert_eq!(len, crate::HEADERS_LEN + payload.len());

    // Parsed from the peer's side: the frame is addressed to PEER, so it reads
    // it as its own.
    let got = parse_udp_frame(&frame, PEER).expect("parses");
    assert_eq!(got.src_addr, SRC);
    assert_eq!(got.dst_addr, DST);
    assert_eq!(got.src_port, 5000);
    assert_eq!(got.dst_port, 7);
    assert_eq!(got.payload, &payload);
}

/// An odd-length payload is the case the checksum pads, and the one a
/// DHCP-shaped test never reaches — every DHCP message here is even.
#[test]
fn an_odd_length_payload_still_verifies() {
    const SRC: ipv4::Addr = [10, 0, 2, 15];
    const DST: ipv4::Addr = [10, 0, 2, 2];
    const PEER: eth::Mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    for len in 1..=9usize {
        let payload: Vec<u8> = (0..len as u8)
            .map(|b| b.wrapping_mul(37).wrapping_add(1))
            .collect();
        let mut frame = vec![0u8; crate::HEADERS_LEN + len];
        build_udp_frame(&mut frame, CLIENT_MAC, PEER, SRC, DST, 5000, 7, 0, &payload)
            .expect("builds");
        let got = parse_udp_frame(&frame, PEER).expect("a datagram of len {len}");
        assert_eq!(got.payload, &payload[..], "payload of {len} bytes");
    }
}

/// A frame for another station is refused even when everything inside it is
/// well-formed.
#[test]
fn the_general_parse_refuses_another_stations_frame() {
    const SRC: ipv4::Addr = [10, 0, 2, 15];
    const DST: ipv4::Addr = [10, 0, 2, 2];
    const PEER: eth::Mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    let mut frame = [0u8; crate::HEADERS_LEN + 4];
    build_udp_frame(&mut frame, CLIENT_MAC, PEER, SRC, DST, 1, 2, 0, b"abcd").expect("builds");
    assert!(parse_udp_frame(&frame, [0xaa; 6]).is_none());
}
