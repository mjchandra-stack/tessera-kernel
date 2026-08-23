// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::preempt`.

use super::*;

/// The counters and both holds are process-wide, so this is deliberately
/// **one** test walking its scenarios in sequence — the same reason
/// `tests/shootdown.rs` gives.
#[test]
fn a_tick_preempts_unless_this_cpu_is_holding_something_a_switch_would_drop() {
    use core::sync::atomic::{AtomicU64, Ordering};

    static SWITCHED: AtomicU64 = AtomicU64::new(0);
    fn switch() {
        SWITCHED.fetch_add(1, Ordering::SeqCst);
    }

    crate::machine_lock::forget();
    forget();
    SWITCHED.store(0, Ordering::SeqCst);

    // Holding nothing: the tick switches.
    assert!(allowed());
    on_tick(switch);
    assert_eq!(SWITCHED.load(Ordering::SeqCst), 1);
    assert_eq!((taken(), deferred()), (1, 0));

    // **Inside the executive, it must not.** `machine_lock`'s owner is a CPU
    // and not a thread, so a switch here hands the hold to whoever runs next —
    // free access to tables this thread is halfway through, and a release of a
    // hold it never took.
    {
        let _held = crate::machine_lock::hold();
        assert!(!allowed());
        on_tick(switch);
    }
    assert_eq!(
        SWITCHED.load(Ordering::SeqCst),
        1,
        "no switch under the lock"
    );
    assert_eq!((taken(), deferred()), (1, 1));

    // ...and the hold going away makes it safe again, which is what stops a
    // deferral being a lost preemption rather than a late one.
    assert!(allowed());
    on_tick(switch);
    assert_eq!(SWITCHED.load(Ordering::SeqCst), 2);

    // **Inside an epoch read section, likewise.** The depth is per-CPU too, and
    // a thread that carried it away would leave this CPU unable to ever declare
    // itself quiescent — one preemption stalling reclamation for the machine.
    {
        let _read = crate::epoch::read();
        assert!(!allowed());
        on_tick(switch);
    }
    assert_eq!(
        SWITCHED.load(Ordering::SeqCst),
        2,
        "no switch inside a read section"
    );
    assert_eq!((taken(), deferred()), (2, 2));

    assert!(allowed(), "the guard is released with the section");
    crate::machine_lock::forget();
    forget();
}
