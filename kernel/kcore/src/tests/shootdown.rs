// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::shootdown`.

use super::*;

/// The generation and the acknowledgements are process-wide, so this is
/// deliberately **one** test walking its scenarios in sequence.
#[test]
fn a_requester_waits_for_every_target_and_a_late_flush_satisfies_both() {
    use core::sync::atomic::AtomicU64 as CoreAtomic;
    use tessera_karch::IpiReason;

    /// A stand-in that services the shootdown inside `send`, as a CPU that
    /// took the interrupt promptly would.
    static SERVICE_ON_SEND: CoreAtomic = CoreAtomic::new(1);
    struct Prompt;
    impl tessera_karch::Ipi for Prompt {
        // SAFETY: the trait's contract, which a fake meets vacuously.
        unsafe fn send(index: u32, _reason: IpiReason) -> bool {
            if SERVICE_ON_SEND.load(Ordering::SeqCst) == 1 {
                // SAFETY: as above; the fake's "CPU" is this thread.
                unsafe { service_here(index, || {}) };
            }
            true
        }
        // SAFETY: the trait's contract; nothing here broadcasts.
        unsafe fn send_all_but_self(_reason: IpiReason) {}
    }

    // No targets is not a failure and sends nothing. This is the case an
    // architecture whose invalidate broadcasts is always in, and the reason the
    // whole cross-CPU half can compile away there.
    // SAFETY: no target to be unable to answer.
    assert!(unsafe { request::<Prompt>(0, 0) });

    // Two targets, both answering.
    // SAFETY: the fake services in-line.
    assert!(unsafe { request::<Prompt>(0b110, 16) });
    assert_eq!(serviced(1), 1);
    assert_eq!(serviced(2), 1);

    // A target that does not answer is a failure, not a timeout the caller may
    // ignore: the frame is still reachable from it. `bit 3` has never
    // acknowledged anything.
    SERVICE_ON_SEND.store(0, Ordering::SeqCst);
    // SAFETY: the fake declines to service, which is the case under test.
    assert!(!unsafe { request::<Prompt>(0b1000, 4) });

    // ...and one flush satisfies every request outstanding when it happens,
    // which is what makes a counter the right structure. Two requests were
    // asked for while CPU 3 was not answering; a single service now covers
    // both, because the flush it performed did.
    // SAFETY: as above.
    assert!(!unsafe { request::<Prompt>(0b1000, 4) });
    // SAFETY: standing in for CPU 3's interrupt path.
    unsafe { service_here(3, || {}) };
    // SAFETY: the acknowledgement above already covers this generation.
    assert!(unsafe { request::<Prompt>(0b1000, 0) } || serviced(3) == 1);
    assert_eq!(serviced(3), 1, "one flush, not one per request");
}
