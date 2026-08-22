// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::percpu`.

use super::*;

#[test]
fn every_slot_starts_at_the_initializer_and_is_independent() {
    let cpus: PerCpu<u64> = PerCpu::new(0);
    assert!(cpus.iter().all(|&v| v == 0));

    // SAFETY: single-threaded test, no other reference to slot 1 is live.
    unsafe { cpus.with_mut(1, |v| *v = 42) };

    assert_eq!(cpus.get(1), Some(&42));
    // The discriminator: a type that shared one cell between CPUs would return
    // 42 here too, and the test above would still pass.
    assert_eq!(cpus.get(0), Some(&0));
    assert_eq!(cpus.get(2), Some(&0));
}

#[test]
fn an_index_beyond_the_ceiling_is_reported_not_wrapped() {
    let cpus: PerCpu<u64> = PerCpu::new(7);
    let past = PerCpu::<u64>::capacity();

    assert_eq!(cpus.get(past), None);
    // SAFETY: single-threaded test; the call is expected to reach no slot.
    assert_eq!(unsafe { cpus.with_mut(past, |v| *v = 1) }, None);
    // Wrapping would have written slot 0 — the failure this refuses.
    assert!(cpus.iter().all(|&v| v == 7));
}

#[test]
fn the_boot_cpu_is_the_index_the_running_cpu_reports() {
    // While one CPU is online these are the same statement, and that is exactly
    // what `current_index` documents. When Phase 2 makes it read a register,
    // this test is what says the boot CPU still comes back as slot zero.
    assert_eq!(current_index(), BOOT_CPU);
    assert_eq!(BOOT_CPU, 0);
    assert!(BOOT_CPU < PerCpu::<u64>::capacity());
}

#[test]
fn iteration_visits_every_slot_in_index_order() {
    let cpus: PerCpu<u32> = PerCpu::new(0);
    for i in 0..PerCpu::<u32>::capacity() {
        // SAFETY: single-threaded test, one slot at a time.
        unsafe { cpus.with_mut(i, |v| *v = i) };
    }
    assert_eq!(cpus.iter().count(), MAX_CPUS);
    assert!(cpus.iter().enumerate().all(|(i, &v)| v == i as u32));
}
