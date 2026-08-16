// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

const FLOOR: Policy = Policy { rollback_floor: 5 };
const NEEDS_V2: Requirement = Requirement {
    min_image_version: 2,
};

fn image(svn: u32, image_version: u32) -> Image {
    Image { svn, image_version }
}

#[test]
fn an_image_meeting_both_is_admitted() {
    assert_eq!(admit(&image(7, 3), &NEEDS_V2, &FLOOR), Ok(()));
    // Exactly at each boundary: a floor and a minimum are both inclusive,
    // and an off-by-one here would refuse the release that was built to be
    // the answer.
    assert_eq!(admit(&image(5, 2), &NEEDS_V2, &FLOOR), Ok(()));
}

#[test]
fn below_the_floor_is_blocked() {
    assert_eq!(
        admit(&image(4, 3), &NEEDS_V2, &FLOOR),
        Err(Refusal::RollbackBlocked)
    );
}

#[test]
fn below_what_the_driver_needs_is_too_old() {
    assert_eq!(
        admit(&image(7, 1), &NEEDS_V2, &FLOOR),
        Err(Refusal::VersionTooOld)
    );
}

/// **The case the whole two-field design exists for.** An image the driver
/// is entirely happy with, refused anyway because the system has retired
/// that security version. With one number this could not be stated, let
/// alone tested.
#[test]
fn the_floor_outranks_a_satisfied_driver() {
    let happy_driver = Requirement {
        min_image_version: 1,
    };
    let image = image(2, 9);
    // The driver's requirement is met, comfortably.
    assert!(image.image_version >= happy_driver.min_image_version);
    assert_eq!(
        admit(&image, &happy_driver, &FLOOR),
        Err(Refusal::RollbackBlocked)
    );
}

/// And when both fail, the floor is what is reported — the refusal that
/// cannot be fixed by changing a driver is the one worth hearing.
#[test]
fn the_floor_is_reported_when_both_would_refuse() {
    assert_eq!(
        admit(&image(1, 1), &NEEDS_V2, &FLOOR),
        Err(Refusal::RollbackBlocked)
    );
}

/// A floor of zero admits everything the driver admits — a system that has
/// retired nothing is not a system that blocks everything.
#[test]
fn a_zero_floor_blocks_nothing() {
    let none = Policy { rollback_floor: 0 };
    assert_eq!(admit(&image(0, 2), &NEEDS_V2, &none), Ok(()));
}

#[test]
fn an_update_that_keeps_every_image_admissible_commits() {
    let installed = [image(7, 3), image(9, 4)];
    assert_eq!(update_compatible(&installed, &NEEDS_V2, &FLOOR), Ok(()));
}

/// The refusal names *which* image, because an operator has to go and look
/// at one.
#[test]
fn an_update_that_would_strand_an_image_is_refused() {
    let installed = [image(7, 3), image(7, 1)];
    let stricter = Requirement {
        min_image_version: 3,
    };
    assert_eq!(
        update_compatible(&installed, &stricter, &FLOOR),
        Err((1, Refusal::VersionTooOld))
    );
}

/// A raised floor is the other way an update strands an installed image,
/// and it is the one that matters: a security update that retires a version
/// still installed on the machine is exactly what this check is for.
#[test]
fn a_raised_floor_strands_an_installed_image() {
    let installed = [image(7, 3), image(2, 3)];
    let raised = Policy { rollback_floor: 6 };
    assert_eq!(
        update_compatible(&installed, &NEEDS_V2, &raised),
        Err((1, Refusal::RollbackBlocked))
    );
}

/// Nothing installed is compatible with anything. A machine with no
/// firmware must not fail an update for want of firmware to check.
#[test]
fn nothing_installed_is_compatible() {
    assert_eq!(update_compatible(&[], &NEEDS_V2, &FLOOR), Ok(()));
}
