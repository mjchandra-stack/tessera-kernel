// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::epoch`.

use super::*;

/// The counters are process-wide and the harness runs tests in parallel
/// threads, so this is deliberately **one** test walking its scenarios in
/// sequence.
#[test]
fn a_grace_period_waits_for_a_reader_and_not_for_an_absent_cpu() {
    // Only the boot CPU is online in a host test, so a grace period turns on
    // this thread quiescing — which is exactly the shape the check on real
    // hardware has, with more CPUs.
    crate::smp::register_boot_cpu(0);
    attach(crate::percpu::BOOT_CPU);

    // With nothing held, quiescing carries this CPU past a new epoch.
    let first = advance();
    quiesce();
    assert!(grace_reached(first), "a CPU holding nothing is quiescent");

    // **The discriminator.** Inside a read-side section the same call must do
    // nothing: a CPU that could declare itself quiescent while holding a
    // reference would let a writer free memory out from under it, which is the
    // one failure this facility exists to prevent.
    let second = advance();
    {
        let _guard = read();
        quiesce();
        assert!(
            !grace_reached(second),
            "a reader must not be able to declare itself quiescent"
        );
        // Nested sections are one section: leaving the inner one does not end
        // the outer.
        {
            let _inner = read();
            quiesce();
            assert!(!grace_reached(second));
        }
        quiesce();
        assert!(!grace_reached(second), "the outer section still holds");
    }
    // ...and once it is out, it can.
    quiesce();
    assert!(grace_reached(second));

    // A CPU that has never come online is not waited for. It cannot hold a
    // reference, and waiting for it would stall reclamation for ever on any
    // machine with a slot to spare — which is every machine here.
    let third = advance();
    quiesce();
    assert!(grace_reached(third));
    assert_eq!(seen(crate::percpu::PerCpu::<u8>::capacity()), 0);

    // A bounded wait that does not complete is a failure, not a hint: the
    // caller must treat the memory as still reachable.
    let fourth = advance();
    let _guard = read();
    assert!(!wait_for_grace(fourth, 4));
}
