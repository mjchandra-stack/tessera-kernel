// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Interface-ID derivation. Each protocol's 64-bit interface ID is the first
//! eight bytes (little-endian) of `SHA-256("fqname@major")`, where `fqname` is
//! the fully-qualified protocol name (`library.Protocol`). The specification
//! leaves the algorithm open; this fixes it (deviation D11). The ID appears in
//! the channel message header (docs/kernel/02) so peers agree on the protocol.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Protocols")

use crate::sha256::sha256;

/// The 64-bit interface ID for a fully-qualified protocol name at `major`.
pub fn interface_id(fqname: &str, major: u64) -> u64 {
    let input = format!("{fqname}@{major}");
    let digest = sha256(input.as_bytes());
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(first8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic_and_version_sensitive() {
        let a = interface_id("t.svc.Echo", 1);
        assert_eq!(a, interface_id("t.svc.Echo", 1), "stable across calls");
        assert_ne!(a, interface_id("t.svc.Echo", 2), "major version matters");
        assert_ne!(a, interface_id("t.svc.Other", 1), "name matters");
    }

    #[test]
    fn matches_a_fixed_vector() {
        // Pins the derivation so an accidental algorithm change is caught:
        // first 8 bytes (little-endian) of SHA-256("t.svc.Echo@1").
        assert_eq!(interface_id("t.svc.Echo", 1), FIXED_ECHO_ID);
    }

    const FIXED_ECHO_ID: u64 = 0x5274_d214_e745_62ab;
}
