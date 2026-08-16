// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The canonical little-endian wire reader and writer. All multi-byte values
//! are little-endian; padding and reserved bytes are zero; the reader rejects
//! any non-canonical byte (nonzero padding, a bool outside {0,1}, or trailing
//! data) — there is no lenient mode.
//!
//! Generated bindings emit explicit field and padding calls per the layout the
//! ISL compiler computes, so the wire layout lives in the schema/IR and this
//! codec stays a thin, layout-agnostic byte engine.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use crate::HandleRef;
use crate::error::WireError;

/// A cursor writing canonical wire bytes into a caller-provided buffer.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes written so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(WireError::ShortBuffer)?;
        let slot = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(WireError::ShortBuffer)?;
        slot.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    /// Writes `n` zero bytes (inter-field padding, reserved fields, tail pad).
    pub fn write_zeros(&mut self, n: usize) -> Result<(), WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::ShortBuffer)?;
        let slot = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(WireError::ShortBuffer)?;
        slot.fill(0);
        self.pos = end;
        Ok(())
    }

    /// Writes a boolean as a single canonical byte (0 or 1).
    pub fn write_bool(&mut self, v: bool) -> Result<(), WireError> {
        self.write_bytes(&[v as u8])
    }

    /// Writes a handle as its little-endian side-table index (never a value).
    pub fn write_handle(&mut self, h: HandleRef) -> Result<(), WireError> {
        self.write_bytes(&h.index().to_le_bytes())
    }
}

/// A cursor reading canonical wire bytes, rejecting any non-canonical input.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// How many handles the message carrying these bytes attached, when the
    /// bytes came from a message. `None` for a syscall argument — see
    /// [`Reader::new`].
    handles: Option<u32>,
}

impl<'a> Reader<'a> {
    /// Reads bytes that are **not** a message payload — a syscall argument
    /// struct, or a value being decoded on its own.
    ///
    /// A handle field read through this is a **raw handle number**, because
    /// that is what a syscall argument carries: the kernel resolves it against
    /// the calling process's own table, which it already has. A message
    /// payload's handle field is an *index* instead, because the kernel
    /// translated the handles at transfer and the number on the receiving side
    /// is not the number the sender wrote — use [`Reader::in_message`] there.
    ///
    /// Nothing in the wire bytes distinguishes the two, so the decode call
    /// does. That is a smaller guarantee than the schema could give — a type
    /// reachable from a `protocol` method payload is a message and the
    /// compiler could say so — and it is the one that exists today.
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            handles: None,
        }
    }

    /// Reads a **message payload**, whose handle fields are indices into the
    /// message's handle vector (`docs/api/03`: *"Handles are indexed references
    /// into the message's handle vector … Payload bytes never contain handle
    /// values"*).
    ///
    /// `handle_count` is how many handles arrived with the message. An index at
    /// or past it is [`WireError::HandleIndexOutOfRange`] — the field names a
    /// capability the message did not carry, which is a decode failure and not
    /// something a receiver should discover by using whatever handle number
    /// happened to be at that position.
    pub fn in_message(buf: &'a [u8], handle_count: u32) -> Self {
        Self {
            buf,
            pos: 0,
            handles: Some(handle_count),
        }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Consumes the next `n` bytes as a slice, advancing the cursor. The
    /// envelope primitive: a size-prefixed payload (a union variant, and later
    /// a table field) is decoded by taking exactly its `size` bytes and
    /// decoding the inner value from a sub-`Reader` over them, whose `finish`
    /// then enforces that the envelope size was minimal. Errors `ShortBuffer`
    /// if fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::ShortBuffer)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::ShortBuffer)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        self.take(n)
    }

    /// Reads `n` bytes that must all be zero (padding / reserved fields).
    pub fn expect_zeros(&mut self, n: usize) -> Result<(), WireError> {
        let bytes = self.read_bytes(n)?;
        if bytes.iter().any(|&b| b != 0) {
            return Err(WireError::NonCanonicalPadding);
        }
        Ok(())
    }

    /// Reads a boolean; a byte outside {0, 1} is non-canonical.
    pub fn read_bool(&mut self) -> Result<bool, WireError> {
        match self.read_bytes(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidBool),
        }
    }

    /// Reads a handle field: an index into the message's handle vector when
    /// this reader was built with [`Reader::in_message`], and a raw handle
    /// number otherwise.
    pub fn read_handle(&mut self) -> Result<HandleRef, WireError> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.read_bytes(4)?);
        let value = u32::from_le_bytes(a);
        if let Some(count) = self.handles
            && value >= count
        {
            return Err(WireError::HandleIndexOutOfRange);
        }
        Ok(HandleRef::new(value))
    }

    /// A reader over an envelope's payload that **keeps this reader's handle
    /// bound**.
    ///
    /// A table is the default shape for a service protocol, so a handle field
    /// most often sits inside an envelope rather than at the top level. A
    /// sub-reader built with [`Reader::new`] would lose the bound there, and
    /// the index check would silently apply to exactly the fields that need it
    /// least.
    pub fn sub<'b>(&self, payload: &'b [u8]) -> Reader<'b> {
        Reader {
            buf: payload,
            pos: 0,
            handles: self.handles,
        }
    }

    /// Consumes the reader, erroring if any bytes are left over.
    pub fn finish(self) -> Result<(), WireError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// Generates the little-endian read/write method pair for one scalar type.
macro_rules! wire_scalar {
    ($ty:ty, $write:ident, $read:ident, $n:literal) => {
        impl Writer<'_> {
            #[doc = concat!("Writes a little-endian `", stringify!($ty), "`.")]
            pub fn $write(&mut self, v: $ty) -> Result<(), WireError> {
                self.write_bytes(&v.to_le_bytes())
            }
        }
        impl Reader<'_> {
            #[doc = concat!("Reads a little-endian `", stringify!($ty), "`.")]
            pub fn $read(&mut self) -> Result<$ty, WireError> {
                let mut a = [0u8; $n];
                a.copy_from_slice(self.read_bytes($n)?);
                Ok(<$ty>::from_le_bytes(a))
            }
        }
    };
}

wire_scalar!(u8, write_u8, read_u8, 1);
wire_scalar!(u16, write_u16, read_u16, 2);
wire_scalar!(u32, write_u32, read_u32, 4);
wire_scalar!(u64, write_u64, read_u64, 8);
wire_scalar!(i8, write_i8, read_i8, 1);
wire_scalar!(i16, write_i16, read_i16, 2);
wire_scalar!(i32, write_i32, read_i32, 4);
wire_scalar!(i64, write_i64, read_i64, 8);
wire_scalar!(f32, write_f32, read_f32, 4);
wire_scalar!(f64, write_f64, read_f64, 8);

#[cfg(test)]
mod tests {
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
}
