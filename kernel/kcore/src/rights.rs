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

    // Power-class rights (bit 36).
    //
    /// Register a device's interrupt as a system wakeup source, and hold a
    /// wake hold against the power object.
    ///
    /// **A right of its own rather than an implication of holding a device.**
    /// Every driver holds a device and most of them have an interrupt; if
    /// arming one as a wake source came with the device, the set of things
    /// able to wake this machine would be the driver table, which nobody
    /// chose and nobody can audit. `docs/power/01` asks for that set to be
    /// explicit and profile-policed, and a separate bit is what makes it a
    /// decision somebody took rather than a consequence.
    pub const WAKE: Rights = Rights(1 << 36);

    /// Commit the system to sleep.
    ///
    /// Separate from [`Self::WAKE`] because they are opposite authorities over
    /// the same machine: one says what may interrupt a sleeping system, the
    /// other stops it running at all. A driver host that registers a wakeup
    /// source has no business suspending the machine, and the power manager
    /// holding both is a fact about that one service rather than a consequence
    /// of the bits.
    pub const SLEEP: Rights = Rights(1 << 37);

    // Firmware-class rights (bit 38).
    //
    /// Load a firmware image into this device (`docs/drivers/01`, "Firmware
    /// Loading"; catalog in `docs/security/01`).
    ///
    /// **Not implied by holding the device**, for the reason [`Self::WAKE`] is
    /// not: firmware is code that runs on hardware outside this CPU's
    /// protection, and if the authority to put it there came with the device
    /// then the set of components able to do so would be the driver table.
    ///
    /// It belongs to whatever *mediates* loading rather than to whatever
    /// consumes the result — the driver framework asks, and narrows this bit
    /// away when it hands the device on, so a driver holds the image it was
    /// granted and cannot ask for a different one. That narrowing is the whole
    /// reason the bit is separate: with the two roles sharing one right, "the
    /// framework decides which image this driver gets" would be a convention
    /// rather than something the kernel enforces.
    pub const FIRMWARE: Rights = Rights(1 << 38);

    // Protected-memory rights (bit 39).
    //
    /// Expose memory on the protected handling path to this device
    /// (`docs/security/01`, "Memory Classification" and the Rights Catalog).
    ///
    /// **A right of the device, not of whoever holds the memory**, and that is
    /// the whole design. Which hardware may be trusted with protected content
    /// — a media decoder, a crypto engine — is a property of the platform, and
    /// a model that asked the buffer's owner instead would be asking the party
    /// with the least ability to know. It travels with the device capability
    /// and narrows away on transfer, so the answer is given once rather than
    /// re-decided by every holder.
    pub const PROTECTED_DMA: Rights = Rights(1 << 39);

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
#[path = "tests/rights.rs"]
mod tests;
