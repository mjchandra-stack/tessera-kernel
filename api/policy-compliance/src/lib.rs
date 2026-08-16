// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Security-policy compliance**: whether a driver holds what its manifest
//! said it would, and nothing else.
//!
//! One of the checks `docs/drivers/01` ("Certification") requires. Both halves
//! of it already existed in this tree and had never been put side by side: the
//! binding manifest declares what a driver bound by an entry may reach
//! (`api/binding`'s `grants_configure`, `grants_derive`, its security domain),
//! and the kernel decides what capabilities a driver process actually ends up
//! holding. Nothing compared them.
//!
//! # Why that gap is the interesting one
//!
//! A capability system's failures are not usually refusals — those are loud and
//! immediate. They are **grants nobody meant to make**: a handle installed with
//! one bit more than it needed, a capability that arrived by transfer carrying
//! rights the receiving driver was never entitled to, a manifest that says
//! `grants_configure: false` about a driver whose device handle carries
//! `CONFIGURE` anyway. None of those produces an error. The system works, and
//! works with more authority in the wrong place than anybody chose.
//!
//! So the rule here is **subset, not equality**. A driver holding less than its
//! manifest allows is a driver that did not need everything it was offered,
//! which is fine and common. A driver holding *more* is the failure, whatever
//! the route by which it arrived.
//!
//! # What "more" means
//!
//! Two populations of rights, because they are gated differently:
//!
//! - The **manifest-gated** ones, which an entry names one at a time —
//!   `CONFIGURE` and `DERIVE` today. `api/binding` explains why each is a
//!   decision rather than a consequence: configuration space is where bus
//!   mastering is turned on, and deriving is authority over what the rest of
//!   the system will bind drivers to.
//! - The **baseline**, which any driver may hold because holding it is what
//!   being a driver means — reading and mapping its own device, waiting on its
//!   own interrupt, talking on its own channels. A driver is not more
//!   privileged for having these; it is a driver.
//!
//! Anything outside both is an undeclared right, and the check names it.
//!
//! `no_std`, dependency-free and allocation-free, so the same rules run in a
//! host test and inside a kernel holding the process table.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Certification"),
//! docs/security/01-security-model.md ("Rights Catalog")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// The rights this crate reasons about, as `kcore::rights` numbers them.
///
/// Restated rather than imported, for the reason `api/class-conformance`
/// restates a status as a `u32`: this crate must be able to *hold* a right the
/// kernel's catalog does not define, because a bit nobody declared is exactly
/// what it exists to report. A type that could only contain known rights could
/// not contain the evidence.
pub mod right {
    pub const READ: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const MAP: u64 = 1 << 2;
    pub const SIGNAL: u64 = 1 << 4;
    pub const WAIT: u64 = 1 << 5;
    pub const DUPLICATE: u64 = 1 << 6;
    pub const TRANSFER: u64 = 1 << 7;
    pub const CONFIGURE: u64 = 1 << 8;
    pub const ADMIN: u64 = 1 << 10;
    pub const DERIVE: u64 = 1 << 32;
    pub const REVOKE: u64 = 1 << 33;
    pub const WAKE: u64 = 1 << 36;
    pub const FIRMWARE: u64 = 1 << 38;
    pub const PROTECTED_DMA: u64 = 1 << 39;
}

/// What any driver may hold without a manifest saying anything.
///
/// **Deliberately narrow.** Reading and mapping its device, waiting on and
/// signalling its own channels and ports, handing a capability on, and holding
/// a duplicate of one it already has. Every one of these is what being a driver
/// consists of; a driver is not more privileged for having them.
///
/// What is **not** here is as much the point: `ADMIN`, `REVOKE`, `FIRMWARE`,
/// `WAKE` and `PROTECTED_DMA` are all authority over something other than this
/// driver's own device, and a driver that ends up holding one has been given
/// something nobody's manifest asked for.
pub const BASELINE: u64 = right::READ
    | right::WRITE
    | right::MAP
    | right::SIGNAL
    | right::WAIT
    | right::DUPLICATE
    | right::TRANSFER;

/// The rights a manifest gates one at a time, and the flag that gates each.
pub const MANIFEST_GATED: [(u64, Gate); 2] = [
    (right::CONFIGURE, Gate::Configure),
    (right::DERIVE, Gate::Derive),
];

/// Which manifest flag permits a gated right.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gate {
    /// `ManifestEntry::grants_configure`.
    Configure,
    /// `ManifestEntry::grants_derive`.
    Derive,
}

/// What the manifest entry a driver was bound by declares about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Declared {
    pub configure: bool,
    pub derive: bool,
    /// The security domain the entry runs in, checked against what the system
    /// policy permits before any of this.
    pub domain: u32,
}

impl Declared {
    fn permits(&self, gate: Gate) -> bool {
        match gate {
            Gate::Configure => self.configure,
            Gate::Derive => self.derive,
        }
    }

    /// Every right this entry allows: the baseline plus what it named.
    pub fn allowance(&self) -> u64 {
        let mut allowed = BASELINE;
        for (bit, gate) in MANIFEST_GATED {
            if self.permits(gate) {
                allowed |= bit;
            }
        }
        allowed
    }
}

/// One capability a process actually holds, as the kernel's handle table
/// records it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Held {
    /// The object the handle names, so a failure points at a capability.
    pub object: u32,
    pub rights: u64,
}

/// What the comparison found.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Verdict {
    /// How many capabilities were examined.
    pub examined: u32,
    /// Every right held across all of them.
    pub held: u64,
    /// Rights held that the manifest never allowed.
    pub undeclared: u64,
    /// The object on the first capability that carried one.
    pub offending_object: u32,
}

impl Verdict {
    /// Whether the driver holds only what it was allowed to.
    ///
    /// Requires that something was examined: a driver holding **no**
    /// capabilities passes a subset test trivially, and calling that compliant
    /// would give a clean report to a process nobody looked at — which is the
    /// same empty claim this facility refuses everywhere else.
    pub fn is_compliant(&self) -> bool {
        self.undeclared == 0 && self.examined > 0
    }

    /// Whether the driver held every right its manifest allowed.
    ///
    /// Reported and **not** required. A driver that took less than it was
    /// offered is a driver that did not need it, which is the direction nobody
    /// should complain about — but a manifest that allows far more than any
    /// driver ever holds is a manifest worth revisiting, and that is invisible
    /// unless somebody counts.
    pub fn used_its_whole_allowance(&self, declared: &Declared) -> bool {
        declared.allowance() & !self.held == 0
    }
}

/// Compares what a driver holds against what its manifest declared.
pub fn check(declared: &Declared, held: &[Held]) -> Verdict {
    let allowed = declared.allowance();
    let mut verdict = Verdict {
        examined: held.len() as u32,
        ..Verdict::default()
    };
    for capability in held {
        verdict.held |= capability.rights;
        let extra = capability.rights & !allowed;
        if extra != 0 {
            verdict.undeclared |= extra;
            if verdict.offending_object == 0 {
                verdict.offending_object = capability.object;
            }
        }
    }
    verdict
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
