// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::wakeup`.

use super::*;

/// The bitmaps and the taken counters are process-wide and the harness runs
/// tests in parallel threads, so this is deliberately **one** test walking its
/// scenarios in sequence rather than several racing over one static.
#[test]
fn wakeups_are_a_set_that_survives_being_posted_twice() {
    const CPU: u32 = 1;
    // Identities the posts name. Anything but `UNASSIGNED` will do here —
    // what they are for is the far end's check, which
    // `tests/sched.rs` pins; this test is about the set.
    let a = ThreadId(11);
    let b = ThreadId(22);
    let c = ThreadId(33);

    // A slot nobody posted is not pending.
    assert!(!pending(CPU));

    // Two posts of the same slot are one wakeup. This is the property that
    // makes a bitmap correct where a queue would deliver two, and it is what
    // lets any CPU post without checking whether another already did.
    assert!(post(CPU, 3, a));
    assert!(post(CPU, 3, a));
    assert!(pending(CPU));

    let mut seen = [0usize; 4];
    let mut count = 0usize;
    assert_eq!(
        drain(CPU, |slot, id| {
            seen[count] = slot;
            assert_eq!(id, a, "a wakeup carries the identity it was posted for");
            count += 1;
        }),
        1
    );
    assert_eq!(&seen[..1], &[3]);
    assert!(!pending(CPU), "a drained bitmap is empty");

    // Distinct slots are distinct wakeups, and come back in slot order because
    // that is the order the bits are in — not a promise, but worth pinning so a
    // change to the scan is visible.
    assert!(post(CPU, 0, b));
    assert!(post(CPU, MAX_THREADS - 1, c));
    count = 0;
    assert_eq!(
        drain(CPU, |slot, id| {
            assert_eq!(id, if slot == 0 { b } else { c });
            seen[count] = slot;
            count += 1;
        }),
        2
    );
    assert_eq!(&seen[..2], &[0, MAX_THREADS - 1]);

    // The taken counter is what a boot check reads: three wakeups so far.
    assert_eq!(taken(CPU), 3);

    // A CPU or a slot that does not exist takes nothing, rather than wrapping
    // into one that does. A wakeup delivered to the wrong thread is worse than
    // one not delivered.
    assert!(!post(CPU, MAX_THREADS, a));
    assert!(!post(crate::percpu::PerCpu::<u8>::capacity(), 0, a));
    assert!(!pending(CPU));
    assert_eq!(drain(crate::percpu::PerCpu::<u8>::capacity(), |_, _| {}), 0);

    // Draining an empty bitmap is not an error and counts nothing.
    assert_eq!(drain(CPU, |_, _| panic!("nothing was posted")), 0);
    assert_eq!(taken(CPU), 3);
}
