// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The floor this system will not go below**, and the provenance of what it
//! accepted instead.
//!
//! The rule is `//api/firmware`, which is host-tested and knows nothing about
//! this kernel. What is here is what cannot be tested on a host because it is a
//! *decision*: the value of the rollback floor, and the structured record of
//! every image admitted or refused.
//!
//! # Why the floor is a constant here
//!
//! `docs/security/02` ("Anti-Rollback") says the platform stores the minimum
//! acceptable version *in monotonic counters or fuses where hardware provides
//! them*. No machine this tree boots on provides them, and there is no
//! non-volatile store of any kind — so the floor is compiled in, and that is a
//! recorded deviation rather than a design (build/README.md, D148). What it
//! costs is precisely what a fuse would buy: an attacker who can rewrite the
//! kernel image can lower this, and a fuse would mean they could not.
//!
//! What it does *not* cost is the mechanism. The floor's value is the only part
//! that is standing in for hardware; the rule that consults it, the refusal it
//! produces, and the record that refusal leaves are all real.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Firmware Loading"),
//! docs/security/02-cryptography-and-key-management.md ("Anti-Rollback")
//! Budget: none (one measured read of one image)

use tessera_firmware::{Image, Policy, Refusal, Requirement};
use tessera_image_store::StoreError;
use tessera_karch::KError;

use crate::event::{Component, EventKind, Severity, emit};
use crate::isl_binding::firmware::FirmwareRefusal;

/// The lowest firmware security version this system will accept.
///
/// **Update procedure**: raising this retires every image below it, on this
/// machine, for good — which is the point, and why it is a source change
/// somebody reviews rather than a value anything computes. Before raising it,
/// `tessera_firmware::update_compatible` answers whether anything currently
/// installed would be stranded.
pub const ROLLBACK_FLOOR: u32 = 5;

/// The system's firmware policy.
pub const POLICY: Policy = Policy {
    rollback_floor: ROLLBACK_FLOOR,
};

/// The system store's bytes, installed by boot glue.
///
/// A static rather than a field on every syscall's environment, on the
/// `event::set_clock` precedent and for the same reason: it is one immutable
/// region belonging to the image, identical on every port, and threading it
/// through every port's dispatch environment would make five call sites carry a
/// value none of them decides.
///
/// Empty until boot installs it, and empty is not a fallback: a load against no
/// store is refused by the store reader, which is exactly what it would say
/// about any other region that is not one.
static SYSTEM_STORE: crate::sync::SpinLock<Source> = crate::sync::SpinLock::new(Source {
    region: &[],
    anchors: &crate::store::TRUSTED_ANCHORS,
});

/// Where images come from and what vouches for them.
///
/// The anchors travel beside the region only so that a **host test** can put a
/// container it built itself behind them; boot never changes them, and
/// [`set_system_store`] cannot. A kernel whose anchors could be replaced at run
/// time would have moved its root of trust into whatever does the replacing.
#[derive(Clone, Copy)]
struct Source {
    region: &'static [u8],
    anchors: &'static [tessera_image_store::Anchor],
}

/// Installs the region [`load`] reads images from. Call once, at boot.
///
/// Deliberately takes only the region: the anchors are [`crate::store::TRUSTED_ANCHORS`]
/// and stay that way.
pub fn set_system_store(region: &'static [u8]) {
    SYSTEM_STORE.lock().region = region;
}

/// The installed store region.
pub fn system_store() -> &'static [u8] {
    SYSTEM_STORE.lock().region
}

/// Points the loader at a container built by a test, behind anchors that
/// container measures to.
///
/// **`cfg(test)`, so it cannot exist in a kernel that boots.** It is the seam
/// that lets the whole path — measure, admit, fill an object, write a report —
/// run on a host where an image can be given any version deliberately; without
/// it those steps would be reachable only through QEMU.
#[cfg(test)]
pub(crate) fn set_test_store(
    region: &'static [u8],
    anchors: &'static [tessera_image_store::Anchor],
) {
    *SYSTEM_STORE.lock() = Source { region, anchors };
}

/// What a successful admission produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Admitted<'a> {
    pub bytes: &'a [u8],
    pub svn: u32,
    pub image_version: u32,
    pub digest: [u8; 32],
}

/// Why a load did not produce an image.
///
/// Three kinds, and they are three because their fixes are three: the store
/// could not answer (`Store`), policy declined the image it answered with
/// (`Policy`), or the caller named something that is not a name (`BadName`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadError {
    /// The store had no such image, or would not vouch for the one it had.
    Store(StoreError),
    /// The image exists and measured correctly, and policy declined it.
    ///
    /// **Carries the image**, because the version that was refused is the
    /// number somebody has to compare against the floor: a rollback refusal
    /// reporting no version would say a downgrade happened and refuse to say
    /// from what.
    Policy(Refusal, Image),
    /// The requested name is not a name.
    BadName,
}

impl LoadError {
    /// The kernel-domain error this refusal reports to a caller.
    ///
    /// A policy refusal is [`KError::PolicyRefused`] — the caller was entitled
    /// to ask and named something real. A missing image is `InvalidArgument`:
    /// the request describes something that does not exist, which is that
    /// error's documented meaning, and which of those two a caller met changes
    /// what they do next.
    pub fn code(self) -> KError {
        match self {
            LoadError::Policy(..) => KError::PolicyRefused,
            LoadError::Store(_) | LoadError::BadName => KError::InvalidArgument,
        }
    }

    /// The wire value for the report's `refusal` field. `None` for everything
    /// that is not a policy decision — a caller must not read "no such image"
    /// as "the system retired this version".
    /// The image the refusal is about, where there was one.
    pub fn image(self) -> Option<Image> {
        match self {
            LoadError::Policy(_, image) => Some(image),
            LoadError::Store(_) | LoadError::BadName => None,
        }
    }

    pub fn refusal(self) -> FirmwareRefusal {
        match self {
            LoadError::Policy(Refusal::RollbackBlocked, _) => FirmwareRefusal::RollbackBlocked,
            LoadError::Policy(Refusal::VersionTooOld, _) => FirmwareRefusal::VersionTooOld,
            LoadError::Store(_) | LoadError::BadName => FirmwareRefusal::None,
        }
    }
}

/// Measures the named image and admits it against [`POLICY`].
///
/// `region` is the system store's bytes; `device` scopes the record. Returns
/// what was admitted, or why not — and emits the record either way, because
/// `docs/drivers/01` asks for provenance to be *logged* and a log with only
/// successes in it cannot answer why a machine has no firmware on it.
///
/// **The image is measured before it is judged**, and the order is not
/// interchangeable: policy applied to an entry the store would not vouch for
/// would be deciding about bytes nobody has authenticated, and a refusal from
/// it would look like a statement about a real image.
pub fn load(device: u64, name: &str, need: Requirement) -> Result<Admitted<'static>, LoadError> {
    let source = *SYSTEM_STORE.lock();
    let store =
        crate::store::mount_against(source.region, source.anchors).map_err(LoadError::Store)?;
    let blob = store.open(name).map_err(LoadError::Store)?;
    let image = Image {
        svn: blob.svn,
        image_version: blob.image_version,
    };

    if let Err(refusal) = tessera_firmware::admit(&image, &need, &POLICY) {
        let error = LoadError::Policy(refusal, image);
        emit(
            EventKind::FirmwareRefused,
            Severity::Warning,
            Component::Security,
            [
                device,
                error.refusal() as u32 as u64,
                error.code() as u16 as u64,
                u64::from(image.svn),
            ],
        );
        return Err(error);
    }

    let mut lead = [0u8; 8];
    lead.copy_from_slice(&blob.digest[..8]);
    emit(
        EventKind::FirmwareLoaded,
        Severity::Notice,
        Component::Security,
        [
            device,
            u64::from(image.svn),
            u64::from(image.image_version),
            u64::from_be_bytes(lead),
        ],
    );
    Ok(Admitted {
        bytes: blob.bytes,
        svn: blob.svn,
        image_version: blob.image_version,
        digest: blob.digest,
    })
}

/// Records a load that failed before an image was ever measured — a name that
/// is not a name, a store that would not mount, or a device handle that carried
/// no authority.
///
/// Separate from [`load`] because those failures happen *outside* it, and a
/// refusal nobody recorded is the case that makes a machine with no firmware
/// indistinguishable from a machine that was never asked.
pub fn record_refusal(device: u64, error: KError) {
    emit(
        EventKind::FirmwareRefused,
        Severity::Warning,
        Component::Security,
        [device, 0, error as u16 as u64, 0],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor is above zero. A floor of zero is a system that has retired
    /// nothing, which is a legitimate state and *not* this one — and it is a
    /// state reachable by deleting a digit, with no test failing.
    #[test]
    fn the_floor_retires_something() {
        const { assert!(ROLLBACK_FLOOR > 0) };
        assert_eq!(POLICY.rollback_floor, ROLLBACK_FLOOR);
    }

    /// A policy refusal and a missing image report different kernel errors and
    /// different refusal values. Collapsing either pair would make a caller
    /// unable to tell "the system retired this version" from "there is no such
    /// image", which are opposite situations.
    #[test]
    fn the_two_kinds_of_refusal_stay_apart() {
        let refused = Image {
            svn: 2,
            image_version: 3,
        };
        let policy = LoadError::Policy(Refusal::RollbackBlocked, refused);
        let missing = LoadError::Store(StoreError::NotFound);
        assert_eq!(policy.code(), KError::PolicyRefused);
        assert_eq!(missing.code(), KError::InvalidArgument);
        assert_eq!(policy.refusal(), FirmwareRefusal::RollbackBlocked);
        assert_eq!(missing.refusal(), FirmwareRefusal::None);
        // The refused version travels with the refusal: a rollback that would
        // not say what it refused could not be checked against any floor.
        assert_eq!(policy.image(), Some(refused));
        assert_eq!(missing.image(), None);
    }

    /// Both policy refusals survive the trip to the wire distinctly.
    #[test]
    fn both_policy_refusals_reach_the_wire() {
        let blank = Image {
            svn: 0,
            image_version: 0,
        };
        assert_eq!(
            LoadError::Policy(Refusal::VersionTooOld, blank).refusal(),
            FirmwareRefusal::VersionTooOld
        );
        assert_ne!(
            LoadError::Policy(Refusal::VersionTooOld, blank).refusal(),
            LoadError::Policy(Refusal::RollbackBlocked, blank).refusal()
        );
    }
}
