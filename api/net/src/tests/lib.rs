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
    build_dhcp_discover, build_dhcpv6_information_request, build_udp_frame, build_udp6_frame, dhcp,
    dhcpv6, eth, ipv4, ipv6, parse_dhcp_offer, parse_dhcpv6_reply, parse_udp_frame,
    parse_udp6_frame, tcp, udp,
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
    let datagram = udp::parse(
        &frame[udp_at..],
        udp::Peers::V4 {
            src: ipv4::UNSPECIFIED,
            dst: ipv4::BROADCAST,
        },
    )
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
        udp::Peers::V4 {
            src: SERVER,
            dst: ipv4::BROADCAST,
        },
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

// --- IPv6 -------------------------------------------------------------------

/// The link-local address RFC 4291's Modified EUI-64 forms from a MAC,
/// computed independently of this crate.
///
/// **The bit that gets forgotten is the seventh.** The universal/local bit is
/// *inverted*, not set and not cleared, so `52:` becomes `50:` — an
/// implementation that copied the MAC straight in would produce an address
/// that looks right and is not this station's.
#[test]
fn a_link_local_address_is_eui64_with_the_bit_inverted() {
    let got = ipv6::link_local_from_mac(CLIENT_MAC);
    let want: ipv6::Addr = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56,
    ];
    assert_eq!(got, want);
    assert_eq!(got[8], CLIENT_MAC[0] ^ 0x02, "the u/l bit is inverted");
}

/// RFC 2464's multicast mapping: `33:33` and the low four bytes.
#[test]
fn a_multicast_address_maps_to_its_ethernet_address() {
    assert_eq!(
        ipv6::multicast_mac(&ipv6::ALL_DHCP_SERVERS),
        [0x33, 0x33, 0x00, 0x01, 0x00, 0x02]
    );
    assert_eq!(
        ipv6::multicast_mac(&ipv6::ALL_ROUTERS),
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x02]
    );
    assert!(ipv6::is_multicast(&ipv6::ALL_NODES));
    assert!(!ipv6::is_multicast(&ipv6::link_local_from_mac(CLIENT_MAC)));
}

/// The UDP checksum over an IPv6 pseudo-header, against a value computed
/// outside this crate.
///
/// **This is the assertion that catches a v4-shaped pseudo-header.** The two
/// differ in the length field's width and in three bytes of padding, and an
/// implementation that reused the v4 shape with v6 addresses produces a
/// checksum that round-trips against itself perfectly and is rejected by every
/// real peer.
#[test]
fn a_udp6_checksum_matches_an_independent_computation() {
    let src: ipv6::Addr = {
        let mut a = [0u8; 16];
        a[0] = 0xfe;
        a[1] = 0x80;
        a[15] = 0x01;
        a
    };
    let dst = ipv6::ALL_DHCP_SERVERS;
    let mut datagram = [0u8; udp::HEADER_LEN + 5];
    let len = udp::write(
        &mut datagram,
        udp::Peers::V6 { src, dst },
        546,
        547,
        b"hello",
    )
    .expect("writes");
    assert_eq!(len, udp::HEADER_LEN + 5);
    // 0xba35, computed by a separate implementation of RFC 8200 section 8.1.
    assert_eq!(
        u16::from_be_bytes([datagram[6], datagram[7]]),
        0xba35,
        "the v6 pseudo-header is four bytes of length and three of padding"
    );
}

/// Over IPv6 the checksum is mandatory: a zero is refused, where over IPv4 the
/// same field means "not computed" and is accepted.
///
/// The asymmetry is the point. The IPv6 header carries no checksum of its own,
/// so a receiver that accepted a zero would have nothing at all checking the
/// addresses the datagram arrived on.
#[test]
fn a_zero_checksum_is_refused_over_v6_and_accepted_over_v4() {
    let v6 = udp::Peers::V6 {
        src: ipv6::UNSPECIFIED,
        dst: ipv6::ALL_NODES,
    };
    let v4 = udp::Peers::V4 {
        src: ipv4::UNSPECIFIED,
        dst: ipv4::BROADCAST,
    };
    let mut datagram = [0u8; udp::HEADER_LEN + 4];
    udp::write(&mut datagram, v6, 1, 2, b"abcd").expect("writes");
    // Blank the checksum, which is what "not computed" looks like on the wire.
    datagram[6] = 0;
    datagram[7] = 0;
    assert!(udp::parse(&datagram, v6).is_none(), "v6 must refuse");
    assert!(udp::parse(&datagram, v4).is_some(), "v4 must accept");
}

/// A v6 frame this crate builds is one it reads back, with every layer
/// verified by the parser rather than by the builder.
#[test]
fn a_udp6_frame_round_trips() {
    let src = ipv6::link_local_from_mac(CLIENT_MAC);
    let payload: &[u8] = b"solic";
    let mut frame = [0u8; eth::HEADER_LEN + ipv6::HEADER_LEN + udp::HEADER_LEN + 5];
    let len = build_udp6_frame(
        &mut frame,
        CLIENT_MAC,
        src,
        ipv6::ALL_DHCP_SERVERS,
        546,
        547,
        payload,
    )
    .expect("builds");
    assert_eq!(len, frame.len());
    assert_eq!(&frame[0..6], &[0x33, 0x33, 0x00, 0x01, 0x00, 0x02]);
    assert_eq!(
        u16::from_be_bytes([frame[12], frame[13]]),
        eth::ETHERTYPE_IPV6
    );
    // Version 6 in the top nibble, and the payload length covering UDP.
    assert_eq!(frame[eth::HEADER_LEN] >> 4, 6);
    let ip = &frame[eth::HEADER_LEN..];
    assert_eq!(
        u16::from_be_bytes([ip[4], ip[5]]) as usize,
        udp::HEADER_LEN + 5
    );
    assert_eq!(ip[6], ipv6::NEXT_UDP);

    // Read back as the group's member would.
    let got = parse_udp6_frame(&frame[..len], [0x33, 0x33, 0, 1, 0, 2], src).expect("parses");
    assert_eq!(got.src_addr, src);
    assert_eq!(got.dst_addr, ipv6::ALL_DHCP_SERVERS);
    assert_eq!(got.dst_port, 547);
    assert_eq!(got.payload, payload);
}

/// A unicast destination is refused, because resolving it needs Neighbour
/// Discovery this crate does not implement — refused rather than sent to a
/// guessed Ethernet address.
#[test]
fn a_unicast_v6_destination_is_refused() {
    let src = ipv6::link_local_from_mac(CLIENT_MAC);
    let dst = ipv6::link_local_from_mac([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
    let mut frame = [0u8; 128];
    assert!(build_udp6_frame(&mut frame, CLIENT_MAC, src, dst, 546, 547, b"x").is_none());
}

/// Every truncation of a valid v6 frame is refused, and none of them panics.
#[test]
fn every_v6_truncation_is_refused_without_panicking() {
    let src = ipv6::link_local_from_mac(CLIENT_MAC);
    let mut frame = [0u8; eth::HEADER_LEN + ipv6::HEADER_LEN + udp::HEADER_LEN + 4];
    build_udp6_frame(
        &mut frame,
        CLIENT_MAC,
        src,
        ipv6::ALL_DHCP_SERVERS,
        546,
        547,
        b"abcd",
    )
    .expect("builds");
    for len in 0..frame.len() {
        assert!(parse_udp6_frame(&frame[..len], CLIENT_MAC, src).is_none());
    }
}

/// One flipped bit anywhere in the datagram fails the v6 checksum.
#[test]
fn a_flipped_bit_fails_the_udp6_checksum() {
    let src = ipv6::link_local_from_mac(CLIENT_MAC);
    let mut good = [0u8; eth::HEADER_LEN + ipv6::HEADER_LEN + udp::HEADER_LEN + 4];
    build_udp6_frame(
        &mut good,
        CLIENT_MAC,
        src,
        ipv6::ALL_DHCP_SERVERS,
        546,
        547,
        b"abcd",
    )
    .expect("builds");
    let at = eth::HEADER_LEN + ipv6::HEADER_LEN;
    for byte in at..good.len() {
        let mut frame = good;
        frame[byte] ^= 0x01;
        assert!(
            parse_udp6_frame(&frame, CLIENT_MAC, src).is_none(),
            "a flip at byte {byte} was accepted"
        );
    }
}

/// A next-header this crate does not handle is refused rather than read as
/// UDP. Nothing walks an extension chain, so a fragment or a routing header
/// stops here.
#[test]
fn an_unhandled_next_header_is_refused() {
    let src = ipv6::link_local_from_mac(CLIENT_MAC);
    let mut frame = [0u8; eth::HEADER_LEN + ipv6::HEADER_LEN + udp::HEADER_LEN + 4];
    build_udp6_frame(
        &mut frame,
        CLIENT_MAC,
        src,
        ipv6::ALL_DHCP_SERVERS,
        546,
        547,
        b"abcd",
    )
    .expect("builds");
    // 44 is the fragment header; 58 is ICMPv6. Neither is UDP.
    for next in [44u8, 58, 0] {
        let mut altered = frame;
        altered[eth::HEADER_LEN + 6] = next;
        assert!(parse_udp6_frame(&altered, CLIENT_MAC, src).is_none());
    }
}

/// The Information-Request this crate builds is the message RFC 3736
/// describes, checked field by field rather than by round trip.
#[test]
fn an_information_request_is_well_formed() {
    let mut frame = [0u8; 256];
    let len =
        build_dhcpv6_information_request(&mut frame, CLIENT_MAC, 0x00ab_cdef).expect("builds");
    let got = parse_udp6_frame(
        &frame[..len],
        [0x33, 0x33, 0, 1, 0, 2],
        ipv6::link_local_from_mac(CLIENT_MAC),
    )
    .expect("the datagram verifies");
    assert_eq!(got.src_port, 546);
    assert_eq!(got.dst_port, 547);
    assert_eq!(got.dst_addr, ipv6::ALL_DHCP_SERVERS);

    let msg = got.payload;
    assert_eq!(msg[0], 11, "INFORMATION-REQUEST");
    assert_eq!(&msg[1..4], &[0xab, 0xcd, 0xef], "a 24-bit transaction id");
    // CLIENTID carrying a DUID-LL: type 3, Ethernet, then this station's MAC.
    assert_eq!(&msg[4..6], &[0, 1], "option 1, CLIENTID");
    assert_eq!(&msg[6..8], &[0, 10], "a ten-byte DUID");
    assert_eq!(&msg[8..10], &[0, 3], "DUID-LL");
    assert_eq!(&msg[10..12], &[0, 1], "hardware type Ethernet");
    assert_eq!(&msg[12..18], &CLIENT_MAC);
    // ORO asking for the recursive name servers.
    assert_eq!(&msg[18..20], &[0, 6], "option 6, ORO");
    assert_eq!(&msg[20..22], &[0, 2]);
    assert_eq!(&msg[22..24], &[0, 23], "option 23, DNS servers");
}

/// A Reply built the way a server builds one is read back with its DNS server.
#[test]
fn a_reply_is_read_with_its_answer() {
    const SERVER_DNS: ipv6::Addr = [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03];
    let mut msg = vec![7u8, 0xab, 0xcd, 0xef];
    // SERVERID, which RFC 8415 requires of a Reply.
    msg.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1, 0x52, 0x55, 0x0a, 0, 2, 2]);
    // DNS_SERVERS, one address.
    msg.extend_from_slice(&[0, 23, 0, 16]);
    msg.extend_from_slice(&SERVER_DNS);
    let reply = dhcpv6::parse_reply(&msg, 0x00ab_cdef).expect("a reply");
    assert!(reply.has_server_id);
    assert_eq!(reply.dns, Some(SERVER_DNS));
}

/// A Reply answering a different transaction is not this client's.
#[test]
fn a_v6_reply_for_another_transaction_is_refused() {
    let msg = [7u8, 0, 0, 1];
    assert!(dhcpv6::parse_reply(&msg, 0x00ab_cdef).is_none());
}

/// An option whose length runs past the end stops the walk instead of reading
/// past it — the same hostile case the v4 option walk has.
#[test]
fn a_v6_option_overrunning_the_area_is_refused() {
    let mut msg = vec![7u8, 0xab, 0xcd, 0xef];
    msg.extend_from_slice(&[0, 23, 0, 200, 1, 2, 3, 4]); // claims 200, has 4
    let reply = dhcpv6::parse_reply(&msg, 0x00ab_cdef).expect("the header parses");
    assert_eq!(reply.dns, None, "the overrunning option yields nothing");
}

/// Every truncation of a valid Information-Request frame is refused, and none
/// of them panics.
#[test]
fn every_v6_request_truncation_is_refused() {
    let mut frame = [0u8; 256];
    let len =
        build_dhcpv6_information_request(&mut frame, CLIENT_MAC, 0x00ab_cdef).expect("builds");
    for cut in 0..len {
        assert!(parse_dhcpv6_reply(&frame[..cut], CLIENT_MAC, 0x00ab_cdef).is_none());
    }
}

// --- TCP --------------------------------------------------------------------

/// The addresses this section's connection runs between.
fn tcp_peers() -> udp::Peers {
    udp::Peers::V4 {
        src: [10, 0, 2, 15],
        dst: [10, 0, 2, 100],
    }
}

/// The reverse, as the peer sees it.
fn tcp_peers_reversed() -> udp::Peers {
    udp::Peers::V4 {
        src: [10, 0, 2, 100],
        dst: [10, 0, 2, 15],
    }
}

/// A segment's checksum, against a value computed outside this crate.
///
/// **The pseudo-header is the same arithmetic UDP uses with a different
/// protocol number**, and this is what proves the number is actually reaching
/// it: a checksum computed with 17 instead of 6 round-trips through this crate
/// perfectly and is refused by every real peer.
#[test]
fn a_tcp_checksum_matches_an_independent_computation() {
    let mut out = [0u8; tcp::HEADER_LEN + 2];
    let len = tcp::write(
        &mut out,
        tcp_peers(),
        40000,
        9,
        0x1000,
        0x2000,
        tcp::flag::ACK | tcp::flag::PSH,
        b"hi",
    )
    .expect("writes");
    assert_eq!(len, tcp::HEADER_LEN + 2);
    // 0x52a5, computed by a separate implementation of RFC 793's checksum.
    assert_eq!(u16::from_be_bytes([out[16], out[17]]), 0x52a5);
    assert_eq!(out[12] >> 4, 5, "five words of header, no options");
    assert_eq!(out[13], tcp::flag::ACK | tcp::flag::PSH);
}

/// SYN and FIN each occupy a sequence number; payload bytes occupy their own.
///
/// This is the arithmetic every acknowledgement depends on, and getting it
/// wrong hangs the connection on its first handshake rather than failing
/// anywhere legible.
#[test]
fn syn_and_fin_consume_a_sequence_number() {
    let bare = tcp::Segment {
        src_port: 1,
        dst_port: 2,
        seq: 0,
        ack: 0,
        flags: tcp::flag::ACK,
        window: 0,
        payload: b"abcd",
    };
    assert_eq!(bare.sequence_len(), 4);
    let syn = tcp::Segment {
        flags: tcp::flag::SYN,
        payload: &[],
        ..bare
    };
    assert_eq!(syn.sequence_len(), 1);
    let fin = tcp::Segment {
        flags: tcp::flag::FIN,
        payload: b"ab",
        ..bare
    };
    assert_eq!(fin.sequence_len(), 3);
}

/// **A whole connection, driven on the host.** Open, exchange bytes, close —
/// with a peer written here rather than emulated, so the state machine's
/// corners are reachable without a machine at all.
#[test]
fn a_connection_opens_carries_bytes_and_closes() {
    const PEER_ISN: u32 = 0x9000_0000;
    let mut conn = tcp::Connection::connect(40000, 9, 0x1000_0000);
    let mut out = [0u8; 256];
    let mut reply = [0u8; 256];

    // 1. SYN out.
    let len = conn.syn(&mut out, tcp_peers()).expect("syn");
    let syn = tcp::parse(&out[..len], tcp_peers()).expect("parses");
    assert!(syn.has(tcp::flag::SYN) && !syn.has(tcp::flag::ACK));
    assert_eq!(syn.seq, 0x1000_0000);

    // 2. The peer's SYN-ACK, built as the peer would.
    let len = tcp::write(
        &mut reply,
        tcp_peers_reversed(),
        9,
        40000,
        PEER_ISN,
        syn.seq.wrapping_add(1),
        tcp::flag::SYN | tcp::flag::ACK,
        &[],
    )
    .expect("writes");
    let synack = tcp::parse(&reply[..len], tcp_peers_reversed()).expect("parses");
    let (data, ack) = conn.on_segment(&synack, &mut out, tcp_peers());
    assert_eq!(data, 0);
    assert!(ack.is_some(), "the handshake owes an ACK");
    assert_eq!(conn.state, tcp::State::Established);
    assert_eq!(
        conn.rcv_nxt,
        PEER_ISN.wrapping_add(1),
        "the peer's SYN counted"
    );

    // 3. Send two bytes.
    let len = conn.send(&mut out, tcp_peers(), b"hi").expect("sends");
    let sent = tcp::parse(&out[..len], tcp_peers()).expect("parses");
    assert_eq!(sent.payload, b"hi");
    assert!(sent.has(tcp::flag::PSH));

    // 4. The peer echoes them, at its own sequence.
    let len = tcp::write(
        &mut reply,
        tcp_peers_reversed(),
        9,
        40000,
        conn.rcv_nxt,
        conn.snd_nxt,
        tcp::flag::ACK | tcp::flag::PSH,
        b"hi",
    )
    .expect("writes");
    let echoed = tcp::parse(&reply[..len], tcp_peers_reversed()).expect("parses");
    let (data, ack) = conn.on_segment(&echoed, &mut out, tcp_peers());
    assert_eq!(data, 2, "two bytes of new data");
    assert!(ack.is_some(), "data owes an acknowledgement");

    // 5. Close, and take the peer's FIN.
    let len = conn.close(&mut out, tcp_peers()).expect("closes");
    let fin = tcp::parse(&out[..len], tcp_peers()).expect("parses");
    assert!(fin.has(tcp::flag::FIN));
    assert_eq!(conn.state, tcp::State::FinWait);

    let len = tcp::write(
        &mut reply,
        tcp_peers_reversed(),
        9,
        40000,
        conn.rcv_nxt,
        conn.snd_nxt,
        tcp::flag::ACK | tcp::flag::FIN,
        &[],
    )
    .expect("writes");
    let peer_fin = tcp::parse(&reply[..len], tcp_peers_reversed()).expect("parses");
    let (_, _) = conn.on_segment(&peer_fin, &mut out, tcp_peers());
    assert!(conn.peer_finished);
    assert_eq!(conn.state, tcp::State::Done);
}

/// A segment that does not start where this end is expecting is dropped and
/// re-acknowledged, not taken.
///
/// **This is the reassembly queue's absence, asserted.** A real receiver holds
/// the gap; this one refuses it, which is why the module says it needs a
/// lossless link.
#[test]
fn an_out_of_order_segment_is_refused_and_reacknowledged() {
    let mut conn = tcp::Connection::connect(40000, 9, 0x1000_0000);
    conn.state = tcp::State::Established;
    conn.rcv_nxt = 0x9000_0001;
    let mut out = [0u8; 256];
    let mut peer = [0u8; 256];

    // A segment one byte past where this end is.
    let len = tcp::write(
        &mut peer,
        tcp_peers_reversed(),
        9,
        40000,
        conn.rcv_nxt.wrapping_add(1),
        conn.snd_nxt,
        tcp::flag::ACK | tcp::flag::PSH,
        b"late",
    )
    .expect("writes");
    let seg = tcp::parse(&peer[..len], tcp_peers_reversed()).expect("parses");
    let before = conn.rcv_nxt;
    let (data, ack) = conn.on_segment(&seg, &mut out, tcp_peers());
    assert_eq!(data, 0, "nothing is delivered out of order");
    assert_eq!(conn.rcv_nxt, before, "and the sequence does not move");
    assert!(ack.is_some(), "a duplicate acknowledgement goes back");
}

/// A reset takes the connection down rather than being ignored.
#[test]
fn a_reset_ends_the_connection() {
    let mut conn = tcp::Connection::connect(40000, 9, 0x1000_0000);
    let mut out = [0u8; 256];
    let mut peer = [0u8; 256];
    let len = tcp::write(
        &mut peer,
        tcp_peers_reversed(),
        9,
        40000,
        0,
        0,
        tcp::flag::RST,
        &[],
    )
    .expect("writes");
    let seg = tcp::parse(&peer[..len], tcp_peers_reversed()).expect("parses");
    conn.on_segment(&seg, &mut out, tcp_peers());
    assert_eq!(conn.state, tcp::State::Reset);
}

/// A segment for another connection is ignored, even when everything in it
/// verifies.
#[test]
fn a_segment_for_another_connection_is_ignored() {
    let mut conn = tcp::Connection::connect(40000, 9, 0x1000_0000);
    conn.state = tcp::State::Established;
    let mut out = [0u8; 256];
    let mut peer = [0u8; 256];
    let len = tcp::write(
        &mut peer,
        tcp_peers_reversed(),
        // A different source port: somebody else's connection.
        10,
        40000,
        conn.rcv_nxt,
        conn.snd_nxt,
        tcp::flag::ACK,
        b"x",
    )
    .expect("writes");
    let seg = tcp::parse(&peer[..len], tcp_peers_reversed()).expect("parses");
    let (data, ack) = conn.on_segment(&seg, &mut out, tcp_peers());
    assert_eq!(data, 0);
    assert!(ack.is_none());
}

/// A zero checksum is never legal in TCP, unlike UDP over IPv4.
#[test]
fn a_zero_tcp_checksum_is_refused() {
    let mut out = [0u8; tcp::HEADER_LEN];
    tcp::write(&mut out, tcp_peers(), 1, 2, 0, 0, tcp::flag::ACK, &[]).expect("writes");
    out[16] = 0;
    out[17] = 0;
    assert!(tcp::parse(&out, tcp_peers()).is_none());
}

/// Every truncation of a valid segment is refused, and none of them panics.
#[test]
fn every_tcp_truncation_is_refused() {
    let mut out = [0u8; tcp::HEADER_LEN + 4];
    let len =
        tcp::write(&mut out, tcp_peers(), 1, 2, 0, 0, tcp::flag::ACK, b"abcd").expect("writes");
    for cut in 0..len {
        assert!(tcp::parse(&out[..cut], tcp_peers()).is_none());
    }
}

/// A data offset pointing outside the segment is refused rather than used as
/// an index.
#[test]
fn a_bad_data_offset_is_refused() {
    let mut out = [0u8; tcp::HEADER_LEN + 4];
    tcp::write(&mut out, tcp_peers(), 1, 2, 0, 0, tcp::flag::ACK, b"abcd").expect("writes");
    for words in [0u8, 1, 4, 15] {
        let mut seg = out;
        seg[12] = words << 4;
        assert!(tcp::parse(&seg, tcp_peers()).is_none(), "offset {words}");
    }
}
