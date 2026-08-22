// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::smp`.

use super::*;

#[test]
fn the_parked_count_is_what_was_found_and_not_started() {
    let four = Topology {
        present: Some(4),
        online: 1,
        boot_cpu_hw_id: 0,
    };
    assert_eq!(four.parked(), Some(3));
}

#[test]
fn a_single_cpu_machine_parks_nothing() {
    let one = Topology {
        present: Some(1),
        online: 1,
        boot_cpu_hw_id: 0,
    };
    assert_eq!(one.parked(), Some(0));
}

#[test]
fn an_unreported_count_stays_unknown_rather_than_becoming_one() {
    // The discriminator for the whole module. Defaulting `present` to 1 would
    // make this `Some(0)` — "nothing parked" — which is exactly the silent
    // fallback the report exists to prevent: a four-CPU board whose firmware
    // did not answer would claim to have started everything it found.
    let silent = Topology {
        present: None,
        online: 1,
        boot_cpu_hw_id: 0,
    };
    assert_eq!(silent.parked(), None);
}

#[test]
fn online_exceeding_present_does_not_wrap() {
    // `present` comes from firmware and `online` from the kernel; nothing makes
    // them agree, and an underflow here would report four billion parked CPUs.
    let inconsistent = Topology {
        present: Some(1),
        online: 2,
        boot_cpu_hw_id: 0,
    };
    assert_eq!(inconsistent.parked(), Some(0));
}
