// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The rights mask carried by every handle. Rights are the single vocabulary
//! that governs what a holder may do with an object; the one invariant is that
//! rights only ever *narrow* — a duplicate, transfer, or replace may drop bits
//! but never add them, except through a broker that already holds the
//! authority (docs/security/01-security-model.md, "Rights Catalog").
//!
//! Bit positions are ABI: stable, never renumbered, extended only by adding
//! new bits (docs/lifecycle/04-coding-guidelines.md, "Boundaries"). The
//! syscall-boundary view of this same catalog is the `bits Rights` schema in
//! `api/isl/examples/handle_abi.isl`; the two share these values by convention.
//!
//! Normative: docs/security/01-security-model.md ("Rights Catalog"),
//! docs/kernel/01-kernel-model.md ("Handle And Rights System")
//! Budget: none (mask arithmetic)

/// A set of rights, as a bitmask. Bit positions are stable ABI.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Rights(u64);

impl Rights {
    // Core rights, applicable to most object classes (bits 0..=10).
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const MAP: Rights = Rights(1 << 2);
    pub const EXECUTE: Rights = Rights(1 << 3);
    pub const SIGNAL: Rights = Rights(1 << 4);
    pub const WAIT: Rights = Rights(1 << 5);
    pub const DUPLICATE: Rights = Rights(1 << 6);
    pub const TRANSFER: Rights = Rights(1 << 7);
    pub const CONFIGURE: Rights = Rights(1 << 8);
    pub const BIND: Rights = Rights(1 << 9);
    pub const ADMIN: Rights = Rights(1 << 10);

    // Job-class rights (bits 16..=21).
    pub const CREATE_PROCESS: Rights = Rights(1 << 16);
    pub const CREATE_JOB: Rights = Rights(1 << 17);
    pub const SET_POLICY: Rights = Rights(1 << 18);
    pub const SET_LIMITS: Rights = Rights(1 << 19);
    pub const SUSPEND: Rights = Rights(1 << 20);
    pub const KILL: Rights = Rights(1 << 21);

    // Pager/memory-class rights (bits 24..=26).
    pub const SUPPLY: Rights = Rights(1 << 24);
    pub const WRITEBACK: Rights = Rights(1 << 25);
    pub const EVICT: Rights = Rights(1 << 26);

    // Exception-class rights (bits 28..=30).
    pub const EXCEPTION: Rights = Rights(1 << 28);
    pub const READ_STATE: Rights = Rights(1 << 29);
    pub const WRITE_STATE: Rights = Rights(1 << 30);

    // Revocation-scope-class rights (bits 32..=33).
    pub const DERIVE: Rights = Rights(1 << 32);
    pub const REVOKE: Rights = Rights(1 << 33);

    /// The empty set.
    pub const fn none() -> Rights {
        Rights(0)
    }

    /// All eleven core rights.
    pub const fn all_core() -> Rights {
        Rights(0x7ff)
    }

    /// Wraps a raw mask (e.g. decoded from the wire). Unknown bits are
    /// preserved; callers reduce against a known set as needed.
    pub const fn from_bits(bits: u64) -> Rights {
        Rights(bits)
    }

    /// The raw mask.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The union of two rights sets.
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// The intersection of two rights sets — the reduction used when narrowing.
    pub const fn intersection(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// True if `self` includes every right in `other`.
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    /// True if every right in `self` is also in `other` — the never-expand
    /// check: a narrowed set must be a subset of the original.
    pub const fn is_subset_of(self, other: Rights) -> bool {
        self.0 & other.0 == self.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        self.union(rhs)
    }
}

impl core::ops::BitAnd for Rights {
    type Output = Rights;
    fn bitand(self, rhs: Rights) -> Rights {
        self.intersection(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_bit_values_are_stable_abi() {
        // These values are ABI; the ISL `bits Rights` schema mirrors them.
        assert_eq!(Rights::READ.bits(), 0x1);
        assert_eq!(Rights::WRITE.bits(), 0x2);
        assert_eq!(Rights::MAP.bits(), 0x4);
        assert_eq!(Rights::EXECUTE.bits(), 0x8);
        assert_eq!(Rights::DUPLICATE.bits(), 0x40);
        assert_eq!(Rights::TRANSFER.bits(), 0x80);
        assert_eq!(Rights::ADMIN.bits(), 0x400);
        assert_eq!(Rights::all_core().bits(), 0x7ff);
        assert_eq!(Rights::KILL.bits(), 1 << 21);
        assert_eq!(Rights::REVOKE.bits(), 1 << 33);
    }

    #[test]
    fn subset_and_reduction() {
        let rw = Rights::READ | Rights::WRITE;
        assert!(Rights::READ.is_subset_of(rw));
        assert!(rw.contains(Rights::READ));
        assert!(!Rights::READ.contains(rw));
        // Reduction to a subset is allowed.
        let reduced = rw.intersection(Rights::READ);
        assert_eq!(reduced, Rights::READ);
        assert!(reduced.is_subset_of(rw));
    }

    #[test]
    fn expansion_is_detectable() {
        let ro = Rights::READ;
        let rw = Rights::READ | Rights::WRITE;
        // Asking for WRITE that `ro` does not have is not a subset — an
        // expansion, which the handle ops must reject.
        assert!(!rw.is_subset_of(ro));
    }

    #[test]
    fn empty_and_union() {
        assert!(Rights::none().is_empty());
        assert!(Rights::none().is_subset_of(Rights::all_core()));
        assert_eq!(
            (Rights::READ | Rights::WRITE).bits(),
            Rights::READ.bits() | Rights::WRITE.bits()
        );
    }
}
