// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::thread`.

use super::*;
use crate::vm::{AddressSpace, Asid};
use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

const STACK_BASE: u64 = 0xffff_d000_0000_0000;

extern "C" fn never(_arg: usize) -> ! {
    // Never actually executed (the mock context does not call entries);
    // present only to satisfy the spawn signature.
    loop {
        core::hint::spin_loop();
    }
}

fn space() -> AddressSpace<MockAddressSpace> {
    let mut frames = MockFrameSource::new(0x10_0000, 4096);
    AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0))
        .expect("space")
}

#[test]
fn spawn_maps_guarded_stack_and_starts_ready() {
    let mut vm = space();
    let mut frames = MockFrameSource::new(0x20_0000, 4096);
    let thread = Thread::<MockContextOps>::spawn(
        ThreadId(7),
        never,
        0x1234,
        VirtAddr::new(STACK_BASE),
        4,
        &mut vm,
        &mut frames,
    )
    .expect("spawn");

    assert_eq!(thread.id(), ThreadId(7));
    assert_eq!(thread.state(), ThreadState::Ready);
    assert_eq!(thread.stack_bytes(), 4 * FRAME_SIZE);
    // The stack is mapped and the page below it is a guard (unmapped).
    assert_eq!(vm.mapped_bytes(), 4 * FRAME_SIZE);
    assert!(vm.rights_at(VirtAddr::new(STACK_BASE)).is_some());
    assert!(vm.rights_at(thread.guard_page()).is_none());
    // The mock context carries the spawn argument through init.
    assert_eq!(thread.context().arg, 0x1234);
}

#[test]
fn state_transitions() {
    let mut vm = space();
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut thread = Thread::<MockContextOps>::spawn(
        ThreadId(1),
        never,
        0,
        VirtAddr::new(STACK_BASE),
        2,
        &mut vm,
        &mut frames,
    )
    .expect("spawn");
    thread.set_state(ThreadState::Running);
    assert_eq!(thread.state(), ThreadState::Running);
    thread.set_state(ThreadState::Exited);
    assert_eq!(thread.state(), ThreadState::Exited);
}

#[test]
fn zero_page_stack_is_rejected() {
    let mut vm = space();
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    assert_eq!(
        Thread::<MockContextOps>::spawn(
            ThreadId(0),
            never,
            0,
            VirtAddr::new(STACK_BASE),
            0,
            &mut vm,
            &mut frames,
        )
        .map(|_| ())
        .unwrap_err(),
        KError::InvalidMapping
    );
}

#[test]
fn spawn_user_maps_two_stacks_and_records_process() {
    let mut user_vm = space();
    let mut kernel_vm = space();
    let mut frames = MockFrameSource::new(0x30_0000, 64);
    let proc_id = ObjectId::from_raw(3);
    let root = PhysAddr::new(0x5000);
    const USER_STACK: u64 = 0x0000_0010_0000_0000; // low half (user)
    let thread = Thread::<MockContextOps>::spawn_user(
        ThreadId(9),
        VirtAddr::new(0x40_0000), // user entry
        0xabc,                    // arg
        VirtAddr::new(USER_STACK),
        2, // user stack pages
        VirtAddr::new(STACK_BASE),
        2, // kernel stack pages
        proc_id,
        root,
        &mut user_vm,
        &mut kernel_vm,
        &mut frames,
    )
    .expect("spawn_user");

    assert_eq!(thread.state(), ThreadState::Ready);
    assert_eq!(thread.process(), Some(proc_id));
    assert_eq!(thread.space_root(), Some(root));
    assert_eq!(
        thread.kernel_stack_top().as_u64(),
        STACK_BASE + 2 * FRAME_SIZE
    );
    // The ring-3 stack is user-accessible and lives in the process space.
    let user_flags = user_vm
        .rights_at(VirtAddr::new(USER_STACK))
        .expect("user stack mapped");
    assert!(user_flags.is_user());
    // The kernel stack is a global (kernel-only) mapping in the kernel space.
    let kernel_flags = kernel_vm
        .rights_at(VirtAddr::new(STACK_BASE))
        .expect("kernel stack mapped");
    assert!(!kernel_flags.is_user());
    assert!(kernel_vm.rights_at(VirtAddr::new(USER_STACK)).is_none());
}

#[test]
fn spawn_user_rejects_zero_page_stacks() {
    let mut user_vm = space();
    let mut kernel_vm = space();
    let mut frames = MockFrameSource::new(0x30_0000, 64);
    assert_eq!(
        Thread::<MockContextOps>::spawn_user(
            ThreadId(0),
            VirtAddr::new(0x40_0000),
            0,
            VirtAddr::new(0x0000_0010_0000_0000),
            0, // zero user stack pages
            VirtAddr::new(STACK_BASE),
            2,
            ObjectId::from_raw(1),
            PhysAddr::new(0x5000),
            &mut user_vm,
            &mut kernel_vm,
            &mut frames,
        )
        .map(|_| ())
        .unwrap_err(),
        KError::InvalidMapping
    );
}

#[test]
fn exception_slot_is_reserved_empty() {
    let mut vm = space();
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut thread = Thread::<MockContextOps>::spawn(
        ThreadId(2),
        never,
        0,
        VirtAddr::new(STACK_BASE),
        2,
        &mut vm,
        &mut frames,
    )
    .expect("spawn");
    assert!(!thread.exception_slot().valid);
}
