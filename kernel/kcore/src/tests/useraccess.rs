// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::useraccess`.
//!
//! One test rather than several, and deliberately: the installed pair is
//! process-global, so a test that installs one changes what every later test
//! sees. Splitting these would make them order-dependent, which is worse than
//! long.

use super::*;
use crate::sched::Scheduler;
use crate::thread::Thread;
use crate::vm::{AddressSpace, Asid};
use core::sync::atomic::{AtomicBool, Ordering};
use tessera_karch::VirtAddr;
use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

extern "C" fn never(_: usize) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// The CPU register, as a cell. What is under test is the kernel's discipline
/// around it, not any port's two instructions.
static CPU_BIT: AtomicBool = AtomicBool::new(false);
fn set_bit(on: bool) {
    CPU_BIT.store(on, Ordering::Relaxed);
}
fn get_bit() -> bool {
    CPU_BIT.load(Ordering::Relaxed)
}

#[test]
fn the_permission_is_counted_when_absent_and_carried_when_present() {
    // --- 1. Nothing installed: the window is inert, and says so. ---
    assert!(
        !is_installed(),
        "this is the crate's only installer; a second one makes this test order-dependent",
    );
    let before = unprotected_copies();
    {
        // SAFETY: nothing is dereferenced here; the guard is the subject.
        let _window = unsafe { Window::open() };
        assert!(!get(), "an absent control reports the bit clear");
    }
    assert_eq!(
        unprotected_copies(),
        before + 1,
        "a copy made with no protection is counted, not assumed harmless",
    );

    // --- 2. Installed: the permission rides the thread, not the CPU. ---
    let _ = install(set_bit, get_bit);

    let mut frames = MockFrameSource::new(0x1000_0000, 64);
    let mut vm = AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0))
        .expect("vm");
    let mut sched = Scheduler::<MockContextOps>::new(1, 0);
    let spawn = |id: u64, vm: &mut AddressSpace<MockAddressSpace>| {
        let mut frames = MockFrameSource::new(0x10_0000 + id * 0x10_0000, 64);
        Thread::<MockContextOps>::spawn(
            never,
            id as usize,
            VirtAddr::new(0xffff_e000_0000_0000 + id * 0x10_0000),
            2,
            vm,
            &mut frames,
        )
        .expect("spawn")
    };
    let a = sched.add_thread(spawn(0, &mut vm)).expect("add");
    let _b = sched.add_thread(spawn(1, &mut vm)).expect("add");
    sched.run(); // a runs

    // `a` is mid-copy when it blocks — exactly how a fault on a pager-backed
    // page leaves it: the fault is forwarded over IPC and the copier parks.
    // SAFETY: nothing is dereferenced; the guard is the subject.
    let window = unsafe { Window::open() };
    assert!(get(), "the window is open on this CPU");
    sched.block_current(); // a blocks, the other thread runs

    assert!(
        !get(),
        "the thread running now opened no window and must not inherit one",
    );

    // ...and when `a` runs again it can finish what it started.
    sched.unblock(a);
    sched.handoff_to(a);
    assert!(
        get(),
        "the thread that opened the window resumes able to finish its copy",
    );
    drop(window);
    assert!(!get(), "and closing it closes it");
}
