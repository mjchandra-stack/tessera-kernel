// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The wire codec error domain. Decoding is strict and canonical: there is no
//! lenient mode, so every deviation from the one valid encoding is an error
//! (docs/api/03-interface-schema-language.md, "Wire Format": decoders reject
//! non-canonical input).
//!
//! Normative: docs/api/03-interface-schema-language.md

/// Why an encode or decode failed. Discriminants are stable numeric values for
/// this domain; append variants, never renumber.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum WireError {
    /// The buffer ran out before the value was fully read or written.
    ShortBuffer = 1,
    /// A padding or reserved byte was nonzero (non-canonical).
    NonCanonicalPadding = 2,
    /// A boolean byte was neither 0 nor 1.
    InvalidBool = 3,
    /// A strict enum carried a value not defined by the schema.
    BadEnum = 4,
    /// A bits value had bits set that the schema does not define.
    BadBits = 5,
    /// A bounded array, vector, or string exceeded its declared maximum.
    BoundExceeded = 6,
    /// A handle reference indexed past the message's handle count.
    HandleIndexOutOfRange = 7,
    /// Decoding finished with bytes left over (non-canonical trailing data).
    TrailingBytes = 8,
    /// A strict union carried an ordinal not defined by the schema. (A
    /// flexible union preserves an unknown ordinal instead of erroring.)
    BadUnionTag = 9,
    /// A table's present-field envelopes were not strictly ascending by
    /// ordinal (a duplicate or out-of-order field) — a non-canonical
    /// encoding, since a table value has exactly one valid byte layout.
    NonCanonicalTable = 10,
    /// A bounded string's bytes were not valid UTF-8.
    InvalidUtf8 = 11,
    /// A protocol message carried a method ordinal the schema does not define.
    UnknownMethod = 12,
}

impl WireError {
    /// The stable numeric code for this error.
    pub const fn code(self) -> u16 {
        self as u16
    }
}
