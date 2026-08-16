// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Runtime support for ISL-generated bindings: the canonical little-endian
//! wire codec ([`Reader`]/[`Writer`]), the handle-reference newtype
//! ([`HandleRef`]), the error domain ([`WireError`]), and the
//! encode/decode traits the generated code targets. `no_std` and
//! zero-dependency, so the same codec serves host services and the `no_std`
//! kernel ABI, and the same validate path is shared by the runtime, the
//! conformance suite, and (later) the fuzzer.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

#![no_std]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
extern crate std;

mod bounded;
mod error;
mod io;

pub use bounded::{BoundedString, BoundedVec};
pub use error::WireError;
pub use io::{Reader, Writer};

/// Wire format version this runtime implements.
pub const WIRE_FORMAT_VERSION: u32 = 0;

/// A reference to a handle by its index in the message's kernel-visible handle
/// vector. Handle *values* never appear in payload bytes
/// (docs/api/03-interface-schema-language.md, "Wire Format"); only this index.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandleRef(u32);

impl HandleRef {
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    pub const fn index(self) -> u32 {
        self.0
    }
}

/// What happens to the sender's copy of an out-of-line reference
/// (`docs/api/03`: *"Out-Of-Line memory fields declare an ownership mode —
/// `transfer`, `share`, or `snapshot`"*; semantics in `docs/kernel/04`).
///
/// Generated code names this in a per-field constant, so a program builds its
/// transfer descriptor from what the contract declared rather than from a
/// literal it typed to match.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ownership {
    /// Ownership moves: the sender's handle and its mappings are gone by the
    /// time the receiver sees the message, so post-send mutation is impossible
    /// by construction rather than by agreement.
    Transfer,
    /// Both sides hold the reference and both may map it — which is why the
    /// schema compiler warns when such a field is validated and then used.
    Share,
    /// The receiver gets a copy taken at send. The default when a field
    /// declares no mode.
    Snapshot,
}

/// A value that encodes to canonical wire bytes.
pub trait WireEncode {
    /// Writes the value's canonical encoding through `writer`.
    fn encode(&self, writer: &mut Writer<'_>) -> Result<(), WireError>;

    /// The exact number of bytes [`encode`](WireEncode::encode) writes. Fixed
    /// for the frozen subset; content-dependent for a bounded string or
    /// vector (`4 + len`), which is why a table/union envelope reads this at
    /// encode time rather than baking a constant.
    fn encoded_len(&self) -> usize;
}

/// A value that decodes from canonical wire bytes, rejecting non-canonical
/// input in the process (decode is validation).
pub trait WireDecode: Sized {
    /// Reads and validates one value from `reader`.
    fn decode(reader: &mut Reader<'_>) -> Result<Self, WireError>;
}

// The primitive wire types implement the codec traits so a `BoundedVec<T, N>`
// (and any other generic container) can carry them. Frozen-struct field
// codegen still calls the `Writer`/`Reader` scalar methods directly; these
// impls are what make a *vector of* a primitive expressible.
macro_rules! impl_wire_scalar {
    ($($ty:ty => $write:ident / $read:ident),+ $(,)?) => {$(
        impl WireEncode for $ty {
            fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                w.$write(*self)
            }
            fn encoded_len(&self) -> usize {
                core::mem::size_of::<$ty>()
            }
        }
        impl WireDecode for $ty {
            fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
                r.$read()
            }
        }
    )+};
}

impl_wire_scalar! {
    u8 => write_u8 / read_u8,
    u16 => write_u16 / read_u16,
    u32 => write_u32 / read_u32,
    u64 => write_u64 / read_u64,
    i8 => write_i8 / read_i8,
    i16 => write_i16 / read_i16,
    i32 => write_i32 / read_i32,
    i64 => write_i64 / read_i64,
    f32 => write_f32 / read_f32,
    f64 => write_f64 / read_f64,
}

impl WireEncode for bool {
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_bool(*self)
    }
    fn encoded_len(&self) -> usize {
        1
    }
}

impl WireDecode for bool {
    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        r.read_bool()
    }
}

/// Encodes `value` into `buf`, returning the number of bytes written.
pub fn encode<T: WireEncode>(value: &T, buf: &mut [u8]) -> Result<usize, WireError> {
    let mut writer = Writer::new(buf);
    value.encode(&mut writer)?;
    Ok(writer.position())
}

/// Decodes one value from `buf`, requiring that it consume every byte
/// (canonical, no trailing data).
pub fn decode<T: WireDecode>(buf: &[u8]) -> Result<T, WireError> {
    let mut reader = Reader::new(buf);
    let value = T::decode(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_ref_is_an_index() {
        let h = HandleRef::new(7);
        assert_eq!(h.index(), 7);
    }

    // A hand-written frozen-struct impl, standing in for generated code, to
    // exercise the encode/decode helpers end to end.
    #[derive(Debug, PartialEq)]
    struct Pair {
        a: u32,
        b: bool,
    }

    impl WireEncode for Pair {
        fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.write_u32(self.a)?;
            w.write_bool(self.b)?;
            w.write_zeros(3) // pad to 8
        }
        fn encoded_len(&self) -> usize {
            8
        }
    }

    impl WireDecode for Pair {
        fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
            let a = r.read_u32()?;
            let b = r.read_bool()?;
            r.expect_zeros(3)?;
            Ok(Self { a, b })
        }
    }

    #[test]
    fn helpers_roundtrip_and_enforce_canonical() {
        let mut buf = [0u8; 8];
        let n = encode(
            &Pair {
                a: 0xdead_beef,
                b: true,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 8);
        let p: Pair = decode(&buf).unwrap();
        assert_eq!(p.a, 0xdead_beef);
        assert!(p.b);

        // Non-canonical padding is rejected by decode.
        let mut bad = buf;
        bad[7] = 1;
        assert_eq!(decode::<Pair>(&bad), Err(WireError::NonCanonicalPadding));

        // Trailing bytes are rejected.
        let mut long = [0u8; 9];
        long[..8].copy_from_slice(&buf);
        assert_eq!(decode::<Pair>(&long), Err(WireError::TrailingBytes));
    }
}
