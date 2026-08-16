// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl_runtime::io`.

use super::*;

#[test]
fn roundtrips_scalars() {
    let mut buf = [0u8; 32];
    let mut w = Writer::new(&mut buf);
    w.write_u32(0x1122_3344).unwrap();
    w.write_i16(-2).unwrap();
    w.write_bool(true).unwrap();
    w.write_zeros(1).unwrap();
    let n = w.position();
    assert_eq!(n, 8);

    let mut r = Reader::new(&buf[..n]);
    assert_eq!(r.read_u32().unwrap(), 0x1122_3344);
    assert_eq!(r.read_i16().unwrap(), -2);
    assert!(r.read_bool().unwrap());
    r.expect_zeros(1).unwrap();
    r.finish().unwrap();
}

#[test]
fn little_endian_layout() {
    let mut buf = [0u8; 4];
    Writer::new(&mut buf).write_u32(0x0403_0201).unwrap();
    assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn short_buffer_is_rejected() {
    let mut buf = [0u8; 2];
    let mut w = Writer::new(&mut buf);
    assert_eq!(w.write_u32(0), Err(WireError::ShortBuffer));
    let mut r = Reader::new(&[0u8; 2]);
    assert_eq!(r.read_u64(), Err(WireError::ShortBuffer));
}

#[test]
fn non_canonical_padding_and_bool_rejected() {
    let mut r = Reader::new(&[0x02]);
    assert_eq!(r.read_bool(), Err(WireError::InvalidBool));
    let mut r = Reader::new(&[0x00, 0x01]);
    assert_eq!(r.expect_zeros(2), Err(WireError::NonCanonicalPadding));
}

#[test]
fn trailing_bytes_rejected() {
    let mut r = Reader::new(&[0u8; 4]);
    r.read_u16().unwrap();
    assert_eq!(r.finish(), Err(WireError::TrailingBytes));
}

#[test]
fn take_returns_a_subslice_and_advances() {
    let mut r = Reader::new(&[1, 2, 3, 4, 5]);
    assert_eq!(r.take(2).unwrap(), &[1, 2]);
    assert_eq!(r.position(), 2);
    // The taken slice can back a sub-reader whose `finish` enforces that
    // the envelope size was minimal — the union-envelope decode path.
    let payload = r.take(3).unwrap();
    let mut sub = Reader::new(payload);
    assert_eq!(sub.read_u16().unwrap(), 0x0403);
    assert_eq!(sub.finish(), Err(WireError::TrailingBytes));
}

#[test]
fn take_past_end_is_short_buffer() {
    let mut r = Reader::new(&[1, 2]);
    assert_eq!(r.take(3), Err(WireError::ShortBuffer));
}

/// **A payload's handle field is an index, and an index has a bound.**
/// `docs/api/03`: *"Handles are indexed references into the message's
/// handle vector"*. A field naming a capability the message did not carry
/// is a decode failure — not something the receiver should find out by
/// using whatever handle number sat at that position.
#[test]
fn a_handle_index_past_the_messages_vector_is_refused() {
    let bytes = 1u32.to_le_bytes();
    let mut r = Reader::in_message(&bytes, 1);
    assert_eq!(r.read_handle(), Err(WireError::HandleIndexOutOfRange));

    // Index 0 of a one-handle message is the handle the message carried.
    let bytes = 0u32.to_le_bytes();
    let mut r = Reader::in_message(&bytes, 1);
    assert_eq!(r.read_handle().unwrap().index(), 0);

    // A message that carried none can name none.
    let bytes = 0u32.to_le_bytes();
    let mut r = Reader::in_message(&bytes, 0);
    assert_eq!(r.read_handle(), Err(WireError::HandleIndexOutOfRange));
}

/// A **syscall argument** carries a raw handle number rather than an index,
/// because the kernel resolves it against the caller's own table. So the
/// unbounded reader accepts what the bounded one refuses, and that is the
/// difference between the two, not an oversight in either.
#[test]
fn a_syscall_argument_handle_is_not_an_index() {
    let bytes = 4096u32.to_le_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.read_handle().unwrap().index(), 4096);
}

/// The bound survives an envelope. A table is the default shape for a
/// service protocol, so a handle field most often sits inside one — and a
/// sub-reader that lost the bound would skip the check on exactly the
/// fields that need it.
#[test]
fn an_envelopes_sub_reader_keeps_the_handle_bound() {
    let outer = [0u8; 0];
    let r = Reader::in_message(&outer, 1);
    let payload = 1u32.to_le_bytes();
    let mut sr = r.sub(&payload);
    assert_eq!(sr.read_handle(), Err(WireError::HandleIndexOutOfRange));
}
