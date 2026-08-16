// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Fixed-capacity bounded collections: the wire representation of ISL's
//! `string:N` and `vector<T>:N`.
//!
//! ISL requires every collection to declare a maximum (`docs/api/03`:
//! "unbounded vectors are not expressible"), which is exactly what lets these
//! be `no_std` and allocation-free: the capacity `N` is part of the type, so
//! the value is an inline `{ len, [_; N] }` rather than a heap `String`/`Vec`.
//! The same code therefore serves a host service and the bare-metal kernel.
//!
//! Both encode as `len: u32` (element or byte count, `≤ N`) followed by the
//! content, and both decode canonically: a length past `N` is
//! [`WireError::BoundExceeded`], and a string's bytes must be valid UTF-8
//! ([`WireError::InvalidUtf8`]). The length prefix is minimal by construction —
//! it is the content's true count.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format")

use crate::error::WireError;
use crate::io::{Reader, Writer};
use crate::{WireDecode, WireEncode};

/// A UTF-8 string of at most `N` bytes, stored inline.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BoundedString<const N: usize> {
    len: u32,
    bytes: [u8; N],
}

impl<const N: usize> BoundedString<N> {
    /// The empty string.
    pub const fn new() -> Self {
        Self {
            len: 0,
            bytes: [0u8; N],
        }
    }

    /// Builds from a `&str`, or [`WireError::BoundExceeded`] if it is longer
    /// than `N` bytes. (Not `FromStr`: the error is the wire domain's, and no
    /// `.parse()` ergonomics are wanted.)
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, WireError> {
        let src = s.as_bytes();
        if src.len() > N {
            return Err(WireError::BoundExceeded);
        }
        let mut bytes = [0u8; N];
        bytes[..src.len()].copy_from_slice(src);
        Ok(Self {
            len: src.len() as u32,
            bytes,
        })
    }

    /// The string's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The string as `&str`. Always valid: the bytes were validated as UTF-8
    /// on construction (`from_str`) or decode.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    /// Byte length.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for BoundedString<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::fmt::Debug for BoundedString<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<const N: usize> WireEncode for BoundedString<N> {
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u32(self.len)?;
        for &b in self.as_bytes() {
            w.write_u8(b)?;
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        4 + self.len as usize
    }
}

impl<const N: usize> WireDecode for BoundedString<N> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let len = r.read_u32()? as usize;
        if len > N {
            return Err(WireError::BoundExceeded);
        }
        let src = r.take(len)?;
        // Validation is the whole point: an invalid encoding is rejected, so
        // `as_str` can never fail later.
        if core::str::from_utf8(src).is_err() {
            return Err(WireError::InvalidUtf8);
        }
        let mut bytes = [0u8; N];
        bytes[..len].copy_from_slice(src);
        Ok(Self {
            len: len as u32,
            bytes,
        })
    }
}

/// A vector of at most `N` values of type `T`, stored inline.
///
/// Backed by `[Option<T>; N]` rather than `[T; N]` so it needs only `T: Copy`,
/// not `T: Default` — a generated struct or enum used as an element derives
/// `Copy` but not necessarily `Default`, and `[None; N]` fills the unused tail
/// without one. The leading `..len` slots are always `Some`.
#[derive(Clone, Copy, PartialEq)]
pub struct BoundedVec<T: Copy, const N: usize> {
    len: u32,
    items: [Option<T>; N],
}

impl<T: Copy, const N: usize> BoundedVec<T, N> {
    /// The empty vector.
    pub fn new() -> Self {
        Self {
            len: 0,
            items: [None; N],
        }
    }

    /// Appends `value`, or [`WireError::BoundExceeded`] if the vector is full.
    pub fn push(&mut self, value: T) -> Result<(), WireError> {
        let idx = self.len as usize;
        if idx >= N {
            return Err(WireError::BoundExceeded);
        }
        self.items[idx] = Some(value);
        self.len += 1;
        Ok(())
    }

    /// The element at `index`, if present.
    pub fn get(&self, index: usize) -> Option<T> {
        if index < self.len as usize {
            self.items[index]
        } else {
            None
        }
    }

    /// Iterates the present elements in order.
    pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
        self.items[..self.len as usize].iter().filter_map(|o| *o)
    }

    /// Element count.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the vector is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<T: Copy, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + core::fmt::Debug, const N: usize> core::fmt::Debug for BoundedVec<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: Copy + WireEncode, const N: usize> WireEncode for BoundedVec<T, N> {
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u32(self.len)?;
        for item in self.iter() {
            item.encode(w)?;
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        4 + self.iter().map(|item| item.encoded_len()).sum::<usize>()
    }
}

impl<T: Copy + WireDecode, const N: usize> WireDecode for BoundedVec<T, N> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let count = r.read_u32()? as usize;
        if count > N {
            return Err(WireError::BoundExceeded);
        }
        let mut items = [None; N];
        for slot in items.iter_mut().take(count) {
            *slot = Some(T::decode(r)?);
        }
        Ok(Self {
            len: count as u32,
            items,
        })
    }
}

#[cfg(test)]
#[path = "tests/bounded.rs"]
mod tests;
