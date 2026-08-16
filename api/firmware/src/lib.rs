// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Whether a firmware image may be loaded**, and which authority said no.
//!
//! `docs/drivers/01` ("Firmware Loading") asks for six things. Three of them
//! are decisions about a *particular image* rather than about bytes or
//! plumbing, and those three are here: version constraints are checked,
//! security-critical rollback is blocked, and update compatibility is checked
//! before an update commits. The other three are elsewhere by construction —
//! the signature is the store's measurement (`api/image-store`), provenance is
//! a kernel event, and crash telemetry has nothing to capture on any machine
//! this tree runs on.
//!
//! # Two numbers, two authorities, and that is the whole design
//!
//! An image carries a **security version number** and an **image version**, and
//! `docs/security/02` ("Anti-Rollback") is what forces them apart: firmware
//! carries monotonically increasing security version numbers, the platform
//! stores the minimum acceptable one, and *"images below that version are
//! rejected even if correctly signed"*. That is a statement about
//! vulnerability, made by the system, and it is not what a driver means when it
//! says which firmware it understands — that is a statement about capability,
//! made by the driver.
//!
//! So there are two comparisons against two fields:
//!
//! - the **floor** is the system's, over `svn`, and it wins;
//! - the **requirement** is the driver's, over `image_version`, and it is
//!   subordinate.
//!
//! **The floor is checked first**, and the order is the content of the rule
//! rather than a detail of its implementation. An image the driver is perfectly
//! happy with must still be refused when it is below the floor, and reporting
//! the driver's satisfaction first would let a caller conclude the image was
//! fine and go looking for another reason. One number and one comparison would
//! collapse the two questions into one that answers neither.
//!
//! # Why this is a crate and not a kernel module
//!
//! For the reason `api/binding` and `api/power` are: the rule must run on the
//! host, where every ordering of floor, requirement and image can be walked
//! deliberately, and inside a kernel, where none of them can. What the kernel
//! adds is the floor's *value* and the authority to act — never the rule.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Firmware Loading"),
//! docs/security/02-cryptography-and-key-management.md ("Anti-Rollback")
//! Budget: none (two integer comparisons)

#![no_std]
#![forbid(unsafe_code)]

/// What an image says about itself, as its store entry records it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Image {
    /// The monotonic security version `docs/security/02` requires.
    pub svn: u32,
    /// What the artifact's producer calls this release.
    pub image_version: u32,
}

/// What the component asking for an image needs of it.
///
/// A *minimum* and no maximum. A driver refusing a newer image than it has
/// heard of would make every security update a compatibility break, and the
/// version that is too new for a driver to drive is a fact about a contract
/// (`BindReply.contract_version`) rather than about a firmware release.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Requirement {
    pub min_image_version: u32,
}

/// What the system requires of every image, whoever is asking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy {
    /// The lowest security version this system will accept. An image below it
    /// is refused however well it measures and however much a driver wants it.
    pub rollback_floor: u32,
}

/// Why an image was refused.
///
/// Two values, and the difference is which authority spoke. `RollbackBlocked`
/// cannot be fixed by changing any driver — the system has decided that version
/// is not to run again. `VersionTooOld` is a driver and an image that do not
/// match, and either of them moving fixes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Refusal {
    /// Below the system's rollback floor. Correctly measured, and refused.
    RollbackBlocked = 1,
    /// Older than the component asking for it requires.
    VersionTooOld = 2,
}

/// Whether `image` may be loaded for a component needing `need`, on a system
/// whose policy is `policy`.
pub fn admit(image: &Image, need: &Requirement, policy: &Policy) -> Result<(), Refusal> {
    // The floor first, and it is not a style choice. `docs/security/02` says a
    // downgraded image is rejected *even if correctly signed*; an
    // implementation that reported the driver's opinion first would answer a
    // rollback with "your driver is fine with this", which is true and useless.
    if image.svn < policy.rollback_floor {
        return Err(Refusal::RollbackBlocked);
    }
    if image.image_version < need.min_image_version {
        return Err(Refusal::VersionTooOld);
    }
    Ok(())
}

/// Whether every image in `installed` would still be admissible under `need`
/// and `policy` — `docs/drivers/01`'s *"firmware update compatibility is checked
/// before OS update commit"*.
///
/// Returns the index of the first image that would not be, and why. **An index
/// and not a count**: an update refused because "3 images would break" tells an
/// operator nothing they can act on, and the first one is what they have to go
/// and look at.
///
/// The check runs against the *incoming* system's rule, not the current one.
/// That is the entire point of doing it before a commit: the question is
/// whether the machine still works after the update, and asking today's policy
/// would always answer yes.
pub fn update_compatible(
    installed: &[Image],
    need: &Requirement,
    policy: &Policy,
) -> Result<(), (usize, Refusal)> {
    for (index, image) in installed.iter().enumerate() {
        if let Err(refusal) = admit(image, need, policy) {
            return Err((index, refusal));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
