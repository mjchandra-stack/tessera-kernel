// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::process`.

use super::*;
use crate::object::{ObjectTable, ObjectType};
use crate::rights::Rights;
use crate::thread::ThreadId;
use crate::vm::{AddressSpace, Asid};
use tessera_karch::FrameSource as _;
use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

fn space() -> AddressSpace<MockAddressSpace> {
    let mut frames = MockFrameSource::new(0x40_0000, 64);
    AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
        .expect("space")
}

const MEM: ObjectId = ObjectId::from_raw(0x41);
const GRANT_VA: u64 = 0x4000_0000;

/// A process with one page of a memory object mapped and one handle to it.
/// The handle is returned rather than assumed: `install` picks the first
/// free slot and stamps the slot's generation, so its raw value is not a
/// number a test can predict.
fn holder(
    frames: &mut MockFrameSource,
) -> (
    Process<MockAddressSpace>,
    tessera_karch::PhysFrame,
    crate::handle::Handle,
) {
    let mut space = AddressSpace::<MockAddressSpace>::new(frames, 0xffff_8000_0000_0000, Asid(2))
        .expect("space");
    let frame = frames.alloc_frame().expect("frame");
    space
        .map_shared(
            VirtAddr::new(GRANT_VA),
            tessera_karch::PageFlags::rw().user(),
            MEM,
            0,
            &[frame],
            frames,
        )
        .expect("map");
    let mut process = Process::new(ObjectId::from_raw(0x60), space);
    let handle = process
        .handles_mut()
        .install(
            MEM,
            Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
        )
        .expect("install");
    process
        .record_memory_mapping(MEM, GRANT_VA, 1)
        .expect("record");
    (process, frame, handle)
}

/// Revocation drops the mapping's reference, clears both records, and
/// leaves the object owning its frame alone.
#[test]
fn revoking_a_grant_reclaims_the_mapping_and_clears_the_record() {
    let mut frames = MockFrameSource::new(0x40_0000, 256);
    let (mut process, frame, handle) = holder(&mut frames);

    // Still held: nothing happens, which is what keeps a process that
    // duplicated its capability from losing a mapping it is entitled to.
    assert!(!process.revoke_memory_mappings_unless_held(
        MEM,
        WindowRevokeReason::Transferred,
        &mut frames
    ));
    assert_eq!(process.memory_mapping_count(), 1);

    // The capability departs.
    let mut objects = ObjectTable::new();
    let _ = process.handles_mut().close(&mut objects, handle);
    assert!(process.revoke_memory_mappings_unless_held(
        MEM,
        WindowRevokeReason::Transferred,
        &mut frames
    ));
    assert_eq!(process.memory_mapping_count(), 0);
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA))
            .is_none(),
        "the page is gone",
    );

    // The mapping's reference is dropped; the object still owns its frame,
    // so releasing that returns it exactly once.
    let before = frames.free_list_depth();
    frames.free_frame(frame);
    assert_eq!(frames.free_list_depth(), before + 1);
}

/// **The negative test the whole shape turns on.** A revoked mapping whose
/// record survived would still answer `rights_at`, so
/// `validate_user_range` would accept the range and a later `read_user`
/// would run a kernel-mode copy against an unmapped address. Device
/// windows dodge this by being untracked; a memory grant is tracked and
/// has no such protection.
#[test]
fn a_revoked_grant_no_longer_validates_for_a_kernel_copy() {
    let mut frames = MockFrameSource::new(0x40_0000, 256);
    let (mut process, _frame, handle) = holder(&mut frames);
    assert!(
        crate::syscall::validate_user_range(process.space(), GRANT_VA, FRAME_SIZE, true).is_ok(),
        "mapped and writable before",
    );

    let mut objects = ObjectTable::new();
    let _ = process.handles_mut().close(&mut objects, handle);
    process.revoke_memory_mappings_unless_held(MEM, WindowRevokeReason::Transferred, &mut frames);

    assert!(
        crate::syscall::validate_user_range(process.space(), GRANT_VA, FRAME_SIZE, false).is_err(),
        "a revoked range must not validate for a kernel copy",
    );
}

/// A reclaim that fails **keeps** the record. Dropping it — which is what
/// the device-window path does, safely, because a device window is
/// untracked — would leave the address space's own mapping in place with
/// nothing able to revoke it, and `teardown` would then free the same
/// frames a second time.
#[test]
fn a_failed_reclaim_keeps_the_record_rather_than_double_freeing() {
    let mut frames = MockFrameSource::new(0x40_0000, 256);
    let (mut process, _frame, handle) = holder(&mut frames);
    let mut objects = ObjectTable::new();
    let _ = process.handles_mut().close(&mut objects, handle);

    // A record whose extent does not match any live mapping: `reclaim_range`
    // requires an exact base and length, so this is the shape a drifted
    // record takes.
    process.forget_memory_mapping(MEM, GRANT_VA);
    process
        .record_memory_mapping(MEM, GRANT_VA, 4)
        .expect("record a wrong extent");

    assert!(process.revoke_memory_mappings_unless_held(
        MEM,
        WindowRevokeReason::Transferred,
        &mut frames
    ));
    assert_eq!(
        process.memory_mapping_count(),
        1,
        "the record survives a failed reclaim",
    );
}

/// The sweep a departing process's teardown walks, deduplicated: a process
/// holding two mappings of one object names it once.
#[test]
fn mapped_objects_are_reported_once_each() {
    let mut frames = MockFrameSource::new(0x40_0000, 256);
    let (mut process, _frame, _handle) = holder(&mut frames);
    process
        .record_memory_mapping(MEM, GRANT_VA + FRAME_SIZE, 1)
        .expect("second mapping");
    let other = ObjectId::from_raw(0x42);
    process
        .record_memory_mapping(other, GRANT_VA + 0x1000_0000, 1)
        .expect("another object");

    let mut out = [ObjectId::from_raw(0); MAX_MEMORY_MAPPINGS];
    assert_eq!(process.mapped_memory_objects(&mut out), 2);
    assert!(out[..2].contains(&MEM) && out[..2].contains(&other));
}

#[test]
fn a_full_mapping_record_is_refused() {
    let mut frames = MockFrameSource::new(0x40_0000, 256);
    let (mut process, _frame, _handle) = holder(&mut frames);
    for i in 1..MAX_MEMORY_MAPPINGS {
        process
            .record_memory_mapping(MEM, GRANT_VA + i as u64 * FRAME_SIZE, 1)
            .expect("fits");
    }
    assert_eq!(
        process.record_memory_mapping(MEM, 0x9000_0000, 1),
        Err(KError::LimitExceeded),
    );
}

/// **A slot reused by a replacement is a different thread, and the table says
/// so by itself.**
///
/// This test used to demonstrate the opposite. The list held scheduler *slots*,
/// so a reaped thread freed its number for the next spawn while the dead
/// process went on claiming it — and `process_of_thread` answered with
/// whichever process claimed the number first, which was the corpse. Every
/// syscall the replacement made resolved against a dead handle table and a dead
/// address space, and the only symptom was `AccessDenied` on a pointer the
/// caller could see was valid.
///
/// An identity is minted once and never reused, so the shadowing is gone
/// structurally rather than by the supervisor remembering to call
/// `forget_thread`. That call still exists — a bounded list should not fill up
/// with threads that no longer run — but nothing depends on it being made.
#[test]
fn a_recycled_slot_does_not_let_a_dead_process_answer_for_a_live_thread() {
    let mut table = ProcessTable::<MockAddressSpace>::new();
    let dead = table
        .insert(Process::new(ObjectId::from_raw(1), space()))
        .expect("insert dead");
    let live = table
        .insert(Process::new(ObjectId::from_raw(2), space()))
        .expect("insert live");

    // Both threads occupied scheduler slot 7 in turn; they are not the same
    // thread and their identities do not agree.
    let reaped = ThreadId(7);
    let replacement = ThreadId(8);
    table
        .get_mut(dead)
        .expect("dead")
        .add_thread(reaped)
        .expect("add");
    table
        .get_mut(live)
        .expect("live")
        .add_thread(replacement)
        .expect("add");

    assert_eq!(
        table.process_of_thread(replacement).map(|p| p.id()),
        Some(ObjectId::from_raw(2)),
        "the live thread resolves to the live process, with the corpse still \
         claiming the slot it once had",
    );
    // ...and forgetting is still available, and still does what it says.
    table.get_mut(dead).expect("dead").forget_thread(reaped);
    assert!(table.process_of_thread(reaped).is_none());
}

/// **Two CPUs' slot numbers are different threads, and the table can tell.**
///
/// This is the defect the change was for. A scheduler slot is one CPU's own
/// bookkeeping — `Scheduler::index_of` says as much — so a machine-wide table
/// keyed on slot numbers cannot distinguish CPU 0's thread 3 from CPU 1's. It
/// was unreachable only because secondaries took no syscalls; the first one
/// taken anywhere but the boot CPU would have resolved to whichever process
/// claimed that number.
///
/// A `ThreadId` carries its minting CPU in its high bits, so the two are
/// simply different values.
#[test]
fn the_same_slot_on_two_cpus_is_two_threads() {
    let mut table = ProcessTable::<MockAddressSpace>::new();
    let a = table
        .insert(Process::new(ObjectId::from_raw(1), space()))
        .expect("insert a");
    let b = table
        .insert(Process::new(ObjectId::from_raw(2), space()))
        .expect("insert b");

    // Slot 3 on CPU 0 and slot 3 on CPU 1: the same number, minted by
    // different schedulers.
    const SLOT: u64 = 3;
    let on_cpu0 = ThreadId(SLOT);
    let on_cpu1 = ThreadId((1 << ThreadId::CPU_SHIFT) | SLOT);
    assert_ne!(on_cpu0, on_cpu1, "the CPU is part of the identity");
    assert_eq!(on_cpu1.cpu(), 1);

    table.get_mut(a).expect("a").add_thread(on_cpu0).expect("a");
    table.get_mut(b).expect("b").add_thread(on_cpu1).expect("b");

    assert_eq!(
        table.process_of_thread(on_cpu0).map(|p| p.id()),
        Some(ObjectId::from_raw(1)),
    );
    assert_eq!(
        table.process_of_thread(on_cpu1).map(|p| p.id()),
        Some(ObjectId::from_raw(2)),
        "the second CPU's thread resolves to its own process, not the first \
         process that happened to claim the number",
    );
}

#[test]
fn process_lifecycle_and_thread_membership() {
    let mut process = Process::new(ObjectId::from_raw(1), space());
    assert_eq!(process.state(), ProcessState::Created);
    assert!(!process.is_exited());
    process.add_thread(ThreadId(4)).expect("add thread");
    assert!(process.owns_thread(ThreadId(4)));
    assert!(!process.owns_thread(ThreadId(5)));
    process.set_running();
    assert_eq!(process.state(), ProcessState::Running);
    process.exit(7);
    assert_eq!(process.state(), ProcessState::Exited(7));
    assert!(process.is_exited());
}

#[test]
fn table_resolves_process_by_thread() {
    let mut table = ProcessTable::<MockAddressSpace>::new();
    let mut a = Process::new(ObjectId::from_raw(1), space());
    a.add_thread(ThreadId(2)).expect("add");
    let mut b = Process::new(ObjectId::from_raw(2), space());
    b.add_thread(ThreadId(9)).expect("add");
    let ia = table.insert(a).expect("insert a");
    let _ib = table.insert(b).expect("insert b");
    assert_eq!(
        table.process_of_thread(ThreadId(2)).map(|p| p.id()),
        table.get(ia).map(|p| p.id())
    );
    assert!(table.process_of_thread(ThreadId(9)).is_some());
    assert!(table.process_of_thread(ThreadId(100)).is_none());
}

#[test]
fn table_resolves_process_by_id() {
    let mut table = ProcessTable::<MockAddressSpace>::new();
    table
        .insert(Process::new(ObjectId::from_raw(11), space()))
        .expect("insert a");
    table
        .insert(Process::new(ObjectId::from_raw(22), space()))
        .expect("insert b");
    assert_eq!(
        table.process_of_id(ObjectId::from_raw(22)).map(|p| p.id()),
        Some(ObjectId::from_raw(22))
    );
    assert!(table.process_of_id(ObjectId::from_raw(11)).is_some());
    assert!(table.process_of_id(ObjectId::from_raw(99)).is_none());
}

#[test]
fn thread_set_is_bounded() {
    let mut process = Process::new(ObjectId::from_raw(1), space());
    for i in 0..MAX_THREADS_PER_PROCESS {
        process.add_thread(ThreadId(i as u64)).expect("add");
    }
    assert_eq!(process.add_thread(ThreadId(99)), Err(KError::OutOfMemory));
}

#[test]
fn remove_returns_process_and_frees_slot() {
    let mut table = ProcessTable::<MockAddressSpace>::new();
    let i0 = table
        .insert(Process::new(ObjectId::from_raw(1), space()))
        .expect("insert 0");
    let _i1 = table
        .insert(Process::new(ObjectId::from_raw(2), space()))
        .expect("insert 1");

    let removed = table.remove(i0).expect("remove returns the process");
    assert_eq!(removed.id(), ObjectId::from_raw(1));
    assert!(table.get(i0).is_none(), "slot cleared");
    // Removing an empty or stale index is a harmless None.
    assert!(table.remove(i0).is_none());
    assert!(table.remove(999).is_none());
    // The freed slot is reused by the next insert (dense, first-free).
    let reused = table
        .insert(Process::new(ObjectId::from_raw(3), space()))
        .expect("insert reuses freed slot");
    assert_eq!(reused, i0, "first-free slot is the one just removed");
}

#[test]
fn index_of_id_locates_the_removable_slot() {
    let mut table = ProcessTable::<MockAddressSpace>::new();
    table
        .insert(Process::new(ObjectId::from_raw(11), space()))
        .expect("insert a");
    let ib = table
        .insert(Process::new(ObjectId::from_raw(22), space()))
        .expect("insert b");
    assert_eq!(table.index_of_id(ObjectId::from_raw(22)), Some(ib));
    assert_eq!(table.index_of_id(ObjectId::from_raw(99)), None);
    // index_of_id then remove is the exit-site pattern.
    let idx = table.index_of_id(ObjectId::from_raw(22)).expect("found");
    assert_eq!(
        table.remove(idx).map(|p| p.id()),
        Some(ObjectId::from_raw(22))
    );
    assert_eq!(table.index_of_id(ObjectId::from_raw(22)), None);
}

/// Guards the M21/D51 device-capability conservation invariant: a dropped
/// `Process` must not release the object references its handle table holds.
/// `install`/`insert` are refcount-neutral and there is no `Drop for Process`
/// / `HandleTable`, so a device object installed into a driver host stays live
/// at refcount 1 across install → reclaim (drop) → re-install. A `Drop` that
/// released handles, or an `insert` that started retaining, would break restart
/// conservation — this test catches either.
#[test]
fn dropping_a_process_does_not_release_its_handles_objects() {
    let mut objects = ObjectTable::new();
    let dev = objects.create(ObjectType::Device).expect("device object");
    assert_eq!(objects.refcount(dev), Some(1));

    // Model the driver-host restart loop: build a host, install the shared
    // device capability, reclaim the host's own process object, drop the host.
    for _ in 0..3 {
        let proc_obj = objects.create(ObjectType::Process).expect("process object");
        let mut host = Process::new(proc_obj, space());
        host.handles_mut()
            .insert(dev, Rights::READ)
            .expect("install device handle");
        // `install` adopts an existing reference — refcount-neutral.
        assert_eq!(
            objects.refcount(dev),
            Some(1),
            "install must not retain the device"
        );
        // Reclaim releases the host's *own* process object (rc 1 → destroyed)
        // and drops the host; the host's handle table — which still holds the
        // device handle — is forgotten, not released.
        assert_eq!(
            objects.release(proc_obj),
            Ok(true),
            "the host's process object is destroyed"
        );
        drop(host);
        assert!(objects.is_live(dev), "the device survives the host drop");
        assert_eq!(
            objects.refcount(dev),
            Some(1),
            "dropping the host must not release the device"
        );
    }
}
