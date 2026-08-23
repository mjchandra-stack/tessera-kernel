// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::shootdown`.

use super::*;
/// The generation and the acknowledgements are process-wide, so this is
/// deliberately **one** test walking its scenarios in sequence.
#[test]
fn a_requester_waits_for_every_target_and_a_late_flush_satisfies_both() {
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

/// Frames handed back to the allocator while the sender was being called.
///
/// A static because the sender is a `fn(u32) -> bool` — the shape a port
/// installs — and cannot capture the allocator it needs to look at.
static FREED_WHEN_ASKED: CoreAtomic = CoreAtomic::new(u64::MAX);

/// Frames the counting source below has released.
static FREED: CoreAtomic = CoreAtomic::new(0);

use core::sync::atomic::AtomicU64 as CoreAtomic;

/// A frame source that says how many frames have gone back to it, machine-wide.
///
/// `MockFrameSource::free_list_depth` answers the same question, but only to
/// somebody holding the source — and the whole point of the check below is what
/// an installed sender can see, which is a `static` and nothing else.
struct CountingFrames(tessera_karch_mock::MockFrameSource);

impl tessera_karch::FrameSource for CountingFrames {
    fn alloc_frame(&mut self) -> Option<tessera_karch::PhysFrame> {
        self.0.alloc_frame()
    }
    fn retain_frame(&mut self, frame: tessera_karch::PhysFrame) {
        self.0.retain_frame(frame);
    }
    fn free_frame(&mut self, frame: tessera_karch::PhysFrame) {
        FREED.fetch_add(1, Ordering::SeqCst);
        self.0.free_frame(frame);
    }
}

/// Does an ordinary unmap *ask*, and does it ask before the frame is reusable?
///
/// A different question from the one above, which tests the mechanism. This
/// tests the wiring: `crate::vm`'s unmap paths compute a target set and reach
/// the installed sender, which for most of this tree's life they did not —
/// `AddressSpace::invalidate` had exactly one caller and it was a boot check.
///
/// **One test, in this file, for the reason the one above gives.** The sender,
/// the generation and the counters are process-wide; `kcore`'s suite runs tests
/// in parallel threads, so every scenario that touches them walks in sequence
/// here rather than racing from `tests/vm.rs`.
#[test]
fn an_unmap_tells_the_other_cpus_before_the_frame_can_be_reused() {
    use crate::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FRAME_SIZE, PageFlags, VirtAddr};
    use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

    /// Services in-line, as a CPU that took the interrupt promptly would, and
    /// records what the allocator had taken back by the time it was called.
    fn send(index: u32) -> bool {
        FREED_WHEN_ASKED.store(FREED.load(Ordering::SeqCst), Ordering::SeqCst);
        // SAFETY: standing in for the interrupt path of the CPU `index` names;
        // the fake's flush drops nothing because it caches nothing.
        unsafe { service_here(index, || {}) };
        true
    }

    // SAFETY: the fake services every send in-line, so its `Ipi` obligations
    // are met vacuously and no CPU is really interrupted.
    unsafe { install_sender(send, 16) };

    const BASE: u64 = 0x4000_0000;
    let mut frames = CountingFrames(MockFrameSource::new(0x20_0000, 1024));
    let arch = MockAddressSpace::new(&mut frames, 0).expect("space");
    // CPUs 4 and 5 have it active; this thread answers `current_index()` with
    // the boot CPU, so both are remote and neither is folded away.
    let mut vm = AddressSpace::from_arch(arch, Asid(0), 0b11_0000);

    // An unmap that frees nothing still has to ask: the mapping is gone here
    // and live on every other CPU until it is told.
    vm.map_anonymous(
        VirtAddr::new(BASE),
        2 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("map");
    let before = (serviced(4), serviced(5));
    vm.unmap_range(VirtAddr::new(BASE), 2 * FRAME_SIZE)
        .expect("unmap");
    assert_eq!(
        (serviced(4), serviced(5)),
        (before.0 + 1, before.1 + 1),
        "unmap_range asked both CPUs holding the space"
    );

    // ...and one request for the range, not one per page.
    let before = serviced(4);
    vm.map_anonymous(
        VirtAddr::new(BASE),
        4 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("remap");
    vm.unmap_range(VirtAddr::new(BASE), 4 * FRAME_SIZE)
        .expect("unmap");
    assert_eq!(serviced(4), before + 1, "one shootdown for four pages");

    // **The ordering, which is the whole reason the reclaim is batched.** A
    // frame back in the allocator while another CPU can still translate to it
    // is a frame with two owners. The sender records what had been freed when
    // it ran; for the first batch that must be nothing.
    FREED.store(0, Ordering::SeqCst);
    FREED_WHEN_ASKED.store(u64::MAX, Ordering::SeqCst);
    vm.map_anonymous(
        VirtAddr::new(BASE),
        2 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("remap");
    vm.reclaim_range(VirtAddr::new(BASE), 2 * FRAME_SIZE, &mut frames)
        .expect("reclaim");
    assert_eq!(FREED.load(Ordering::SeqCst), 2, "both frames came back");
    assert_eq!(
        FREED_WHEN_ASKED.load(Ordering::SeqCst),
        0,
        "the other CPUs were told before any frame was reusable"
    );

    // A space nobody else has active asks nobody — the case every uniprocessor
    // boot in this tree is in, and the one that has to stay free.
    let arch = MockAddressSpace::new(&mut frames, 0).expect("space");
    let mut alone = AddressSpace::from_arch(arch, Asid(0), 0);
    alone
        .map_anonymous(
            VirtAddr::new(BASE),
            FRAME_SIZE,
            PageFlags::rw(),
            &mut frames,
        )
        .expect("map");
    let before = serviced(4);
    alone
        .unmap_range(VirtAddr::new(BASE), FRAME_SIZE)
        .expect("unmap");
    assert_eq!(serviced(4), before, "nobody to tell, nothing sent");

    // Nothing above went unanswered, which is what the boot line claims.
    assert_eq!(incomplete(), 0);
}
