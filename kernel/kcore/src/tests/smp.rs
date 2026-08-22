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
        platform_hw_id: None,
    };
    assert_eq!(four.parked(), Some(3));
}

#[test]
fn a_single_cpu_machine_parks_nothing() {
    let one = Topology {
        present: Some(1),
        online: 1,
        boot_cpu_hw_id: 0,
        platform_hw_id: None,
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
        platform_hw_id: None,
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
        platform_hw_id: None,
    };
    assert_eq!(inconsistent.parked(), Some(0));
}

#[test]
fn the_registry_reports_the_boot_cpu_and_nothing_else() {
    // `survey` is what a port calls; the online half must come from the
    // registry rather than from the caller. Registering once and asking twice
    // is the discriminator against a count that is really a constant.
    let surveyed = survey(Some(4), 0x8_1234, Some(0x8_1234));

    assert_eq!(surveyed.present, Some(4));
    assert_eq!(surveyed.online, 1);
    assert_eq!(surveyed.parked(), Some(3));
    assert_eq!(surveyed.boot_cpu_hw_id, 0x8_1234);
    assert_eq!(surveyed.boot_id_agrees(), Some(true));

    let boot = cpu(crate::percpu::BOOT_CPU).expect("the boot CPU has a slot");
    assert!(boot.online);
    assert_eq!(boot.hw_id, 0x8_1234);

    // Every other slot is still offline — the hardware id was recorded beside
    // slot zero, not used to choose a slot. A registry that indexed by hw_id
    // would have marked slot 0x8_1234 (or wrapped into another one).
    assert_eq!(online_count(), 1);
    for index in 1..crate::percpu::PerCpu::<u8>::capacity() {
        assert!(!cpu(index).expect("in range").online, "cpu {index}");
    }
}

#[test]
fn one_source_for_the_boot_id_is_not_agreement() {
    // The discriminator for the cross-check: a port with nothing to compare
    // against must report "unchecked", not "checked and fine". Folding `None`
    // into `true` would let the claim be earned by a port that never looked.
    let unchecked = Topology {
        present: Some(1),
        online: 1,
        boot_cpu_hw_id: 0x8_1234,
        platform_hw_id: None,
    };
    assert_eq!(unchecked.boot_id_agrees(), None);

    let disagreeing = Topology {
        platform_hw_id: Some(0),
        ..unchecked
    };
    assert_eq!(disagreeing.boot_id_agrees(), Some(false));
}
