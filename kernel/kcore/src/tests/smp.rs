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

/// The registry, the arrival bitmap, and the fake firmware's answer are all
/// process-wide, and the harness runs tests in parallel threads. So the
/// registry and bring-up are deliberately **one** test walking their scenarios
/// in sequence rather than several racing over one static — several would pass
/// most of the time, which is the worst outcome available.
#[test]
fn the_registry_records_the_boot_cpu_then_the_cpus_it_starts() {
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
        assert!(!cpu(index).expect("in range").arrived, "cpu {index}");
    }

    bring_up_scenarios(0x8_1234);
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

/// The bring-up half of the test above, continuing on the registry it left.
fn bring_up_scenarios(boot_hw_id: u64) {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use tessera_karch::CpuStartError;

    /// A firmware stand-in. `ANSWERS` is what the next start returns;
    /// `ARRIVES` says whether the started CPU then reaches kernel code.
    static REFUSE_FROM: AtomicU32 = AtomicU32::new(u32::MAX);
    static ARRIVES: AtomicBool = AtomicBool::new(true);
    static LAST_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);

    struct FakeFirmware;
    impl tessera_karch::CpuBringUp for FakeFirmware {
        // SAFETY: the trait's contract, which a fake meets vacuously — it starts
        // nothing and reserves nothing.
        unsafe fn start(hw_id: u64, index: u32) -> Result<(), CpuStartError> {
            LAST_INDEX.store(index, Ordering::SeqCst);
            if hw_id >= u64::from(REFUSE_FROM.load(Ordering::SeqCst)) {
                return Err(CpuStartError::Denied);
            }
            if ARRIVES.load(Ordering::SeqCst) {
                announce_arrival(index);
            }
            Ok(())
        }
    }

    // The failing scenarios come first, because a dense index is minted once
    // and this walks the same index space three times: a CPU that arrived in an
    // earlier scenario would still be arrived when a later one reused its
    // index, and the "never arrived" case could not be told from a stale bit.

    // A CPU that firmware refuses is counted as attempted and not as started,
    // and the reason survives to the boot line.
    REFUSE_FROM.store(0x101, Ordering::SeqCst);
    // SAFETY: the fake needs no storage, so there is none to reserve.
    let refused = unsafe { start_secondaries::<FakeFirmware>(&[0x100, 0x101], 0x100, Some(2), 16) };
    assert_eq!(
        (refused.attempted, refused.started, refused.arrived),
        (1, 0, 0)
    );
    assert_eq!(refused.first_error, Some(CpuStartError::Denied));
    assert!(!refused.complete());
    REFUSE_FROM.store(u32::MAX, Ordering::SeqCst);

    // A CPU firmware accepts and that never arrives is the case the bound
    // exists for: the wait ends, and the two counts disagree in a way the
    // report can name.
    ARRIVES.store(false, Ordering::SeqCst);
    let silent =
        // SAFETY: the fake needs no storage, so there is none to reserve.
        unsafe { start_secondaries::<FakeFirmware>(&[boot_hw_id, 0x900], boot_hw_id, Some(2), 4) };
    assert_eq!(
        (silent.attempted, silent.started, silent.arrived),
        (1, 1, 0)
    );
    assert_eq!(silent.first_error, Some(CpuStartError::NoArrival));
    assert!(!silent.complete());
    ARRIVES.store(true, Ordering::SeqCst);

    // The discriminator for `complete`. A single-CPU machine attempts nothing,
    // and "nothing failed" is not "bring-up worked" — a kernel that had
    // stopped starting CPUs entirely would otherwise earn the claim.
    let alone =
        // SAFETY: the fake needs no storage, so there is none to reserve.
        unsafe { start_secondaries::<FakeFirmware>(&[boot_hw_id], boot_hw_id, Some(1), 16) };
    assert_eq!(alone.attempted, 0);
    assert!(!alone.complete(), "nothing attempted is not success");
    assert!(report_bring_up(alone).is_empty());

    // Four CPUs, the boot CPU among them and not first in the list — a driver
    // that assumed the boot CPU was entry zero would try to start it.
    let ids = [0x100u64, boot_hw_id, 0x101, 0x102];
    // SAFETY: the fake needs no storage, so there is none to reserve.
    let all = unsafe { start_secondaries::<FakeFirmware>(&ids, boot_hw_id, Some(6), 16) };
    assert_eq!(
        all.attempted, 3,
        "the boot CPU is not one of its own targets"
    );
    assert_eq!(all.started, 3);
    assert_eq!(all.arrived, 3);
    // Six CPUs on the machine, four in the list: the two the port never
    // collected are counted as present-and-not-started just as an index past
    // the ceiling would be.
    assert_eq!(all.beyond_ceiling, 2);
    assert_eq!(all.first_error, None);
    assert!(all.complete());
    assert_eq!(report_bring_up(all), &["smp.started"]);

    // Indices are dense from BOOT_CPU + 1 and follow the list's order, not the
    // hardware ids: the last CPU started is 0x102, and it is index 3.
    assert_eq!(LAST_INDEX.load(Ordering::SeqCst), 3);
    for (index, hw_id) in [(1u32, 0x100u64), (2, 0x101), (3, 0x102)] {
        let state = cpu(index).expect("in range");
        assert!(state.arrived, "cpu {index} arrived");
        assert!(!state.online, "an arrived CPU is not dispatched to (D8)");
        assert_eq!(state.hw_id, hw_id);
    }
    // ...and nothing above became something the scheduler dispatches to.
    assert_eq!(online_count(), 1);

    ipi_scenarios();
}

/// The interrupt half, continuing on the registry the two above left: CPUs 1,
/// 2 and 3 have arrived, which is the three targets the exclusivity check
/// needs to have anything to say.
fn ipi_scenarios() {
    use core::sync::atomic::{AtomicBool, Ordering};
    use tessera_karch::{Ipi, IpiReason};

    /// Whether the fake controller aims at the CPU it was given or wakes every
    /// CPU it can reach. The second is the defect: it is not a controller that
    /// fails to deliver — it delivers, to the target and to everyone else.
    static OVER_DELIVERS: AtomicBool = AtomicBool::new(false);

    fn note_every_secondary() {
        for index in 0..crate::percpu::PerCpu::<u8>::capacity() {
            if index != BOOT_CPU && cpu(index).is_some_and(|state| state.arrived) {
                note_ipi(index);
            }
        }
    }

    struct FakeController;
    impl Ipi for FakeController {
        // SAFETY: the trait's contract, which a fake meets vacuously — it
        // touches no controller and leaves no interrupt active anywhere.
        unsafe fn send(index: u32, _reason: IpiReason) -> bool {
            if OVER_DELIVERS.load(Ordering::SeqCst) {
                note_every_secondary();
            } else {
                note_ipi(index);
            }
            true
        }

        // SAFETY: as `send`.
        unsafe fn send_all_but_self(_reason: IpiReason) {
            note_every_secondary();
        }
    }

    // A controller that aims: three targets, three acknowledgements, and
    // nobody took an interrupt they were not sent.
    // SAFETY: the fake touches no hardware, so there is no interface to
    // initialize.
    let aimed = unsafe { ping_each::<FakeController>(IpiReason::Reschedule, 64) };
    assert_eq!(
        (aimed.targeted, aimed.addressed, aimed.acknowledged),
        (3, 3, 3)
    );
    assert_eq!(aimed.surplus, 0);
    assert!(aimed.complete());
    assert!(aimed.exclusive());

    // The discriminator, and the reason this check exists. A controller that
    // wakes every CPU on every send still delivers to each target in turn, so
    // it acknowledges perfectly and `complete` cannot tell it apart from a
    // working one. Three sends waking three CPUs is nine interrupts where
    // three were sent.
    OVER_DELIVERS.store(true, Ordering::SeqCst);
    // SAFETY: as above.
    let spraying = unsafe { ping_each::<FakeController>(IpiReason::Reschedule, 64) };
    assert!(
        spraying.complete(),
        "the old check passes on this — that is what makes the new one worth having"
    );
    assert_eq!(spraying.surplus, 6);
    assert!(!spraying.exclusive());
    OVER_DELIVERS.store(false, Ordering::SeqCst);

    // A broadcast is expected to reach everybody, so the same nine-for-three
    // arithmetic is not a finding there and the round does not report one.
    // SAFETY: as above.
    let broadcast = unsafe { broadcast_ipi::<FakeController>(IpiReason::Reschedule, 64) };
    assert_eq!((broadcast.targeted, broadcast.acknowledged), (3, 3));
    assert_eq!(broadcast.surplus, 0);
    assert!(broadcast.complete());

    // Only the exclusivity claim is withheld when the targeted round strayed;
    // the other two are separate questions and keep their answers.
    assert_eq!(
        report_ipi(aimed, broadcast),
        &[
            "smp.ipi-targeted",
            "smp.ipi-broadcast",
            "smp.ipi-only-target"
        ]
    );
    assert_eq!(
        report_ipi(spraying, broadcast),
        &["smp.ipi-targeted", "smp.ipi-broadcast"]
    );
}

#[test]
fn one_other_cpu_cannot_show_that_a_send_was_aimed() {
    // Exclusivity is measured by CPUs gaining exactly one interrupt each, and
    // with a single target there is no difference between a send that honours
    // its argument and one that ignores it — both leave that CPU on one. The
    // claim is withheld rather than made vacuously, which is what obliges the
    // boot checks asserting it to run more than two CPUs.
    let pair = IpiRound {
        targeted: 1,
        addressed: 1,
        acknowledged: 1,
        surplus: 0,
    };
    assert!(pair.complete());
    assert!(!pair.exclusive(), "two CPUs cannot demonstrate this");

    assert!(
        IpiRound {
            targeted: 3,
            addressed: 3,
            acknowledged: 3,
            surplus: 0
        }
        .exclusive()
    );
}

#[test]
fn a_send_that_delivers_nothing_is_not_exclusive() {
    // The other vacuity: a port whose `send` returns without writing anything
    // strays nowhere, so a surplus of zero is exactly what it produces. Making
    // exclusivity depend on delivery keeps "it reached only its target" from
    // being earned by "it reached nobody".
    let dead = IpiRound {
        targeted: 3,
        addressed: 3,
        acknowledged: 0,
        surplus: 0,
    };
    assert!(!dead.exclusive());
}

#[test]
fn an_index_nobody_assigned_is_not_an_arrival() {
    // Announcing out of range must be dropped rather than wrapped into a slot,
    // and CPU 0's above all: the boot CPU's own bit standing in for a stray
    // one would make a failed bring-up look complete.
    let ceiling = crate::percpu::PerCpu::<u8>::capacity();
    announce_arrival(ceiling);
    announce_arrival(ceiling + 7);
    assert!(!has_arrived(ceiling));
    assert!(!has_arrived(ceiling + 7));
}
