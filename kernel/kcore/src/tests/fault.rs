// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::fault`.
//!
//! `vm.rs`'s own tests establish that each fault *classifies* correctly; these
//! establish what a port is told to do about it, which is the part every port
//! now shares.

use super::*;
use crate::vm::Asid;
use tessera_karch::{FRAME_SIZE, PageFlags};
use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

/// The fixture base — a **user-half** address, for the reason the `vm`
/// tests' own base gives: everything reserved here carries `user()`.
const BASE: u64 = 0x0000_4000_0000_0000;

fn space() -> AddressSpace<MockAddressSpace> {
    let mut frames = MockFrameSource::new(0x10_0000, 1024);
    AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
        .expect("empty space")
}

#[test]
fn a_lazy_page_is_filled_and_resumes() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    vm.map_anonymous_demand(VirtAddr::new(BASE), 2 * FRAME_SIZE, PageFlags::rw().user())
        .expect("map demand");

    let repair = repair(&mut vm, VirtAddr::new(BASE + 0x80), false, &mut frames);
    assert_eq!(repair, Repair::Filled);
    assert!(repair.resumes());
    // Repaired means resident: the same access a second time is not a fault to
    // repair at all, which is what "resume the instruction" has to mean.
    assert!(vm.arch().translate(VirtAddr::new(BASE)).is_some());
    assert_eq!(
        repair_at(&mut vm, BASE, false, &mut frames),
        Repair::Fatal,
        "a present page faulting again is a violation, not a second fill"
    );
}

#[test]
fn a_copy_on_write_page_is_copied_and_resumes() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let rights = PageFlags::rw().user();
    vm.map_anonymous(VirtAddr::new(BASE), FRAME_SIZE, rights, &mut frames)
        .expect("map anonymous");
    vm.snapshot_cow(
        VirtAddr::new(BASE),
        VirtAddr::new(BASE + 0x10_0000),
        FRAME_SIZE,
        &mut frames,
    )
    .expect("snapshot");

    let repair = repair(&mut vm, VirtAddr::new(BASE), true, &mut frames);
    assert_eq!(repair, Repair::Copied);
    assert!(repair.resumes());
}

#[test]
fn a_non_resident_pager_page_is_handed_back_not_repaired() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let object = ObjectId::from_raw(7);
    vm.map_object(
        VirtAddr::new(BASE),
        2 * FRAME_SIZE,
        PageFlags::rw().user(),
        object,
        0,
    )
    .expect("map_object");

    // The offset is the object's, not the address space's — a caller that
    // forwarded the faulting VA would ask the pager for the wrong page.
    let repair = repair(
        &mut vm,
        VirtAddr::new(BASE + FRAME_SIZE + 0x40),
        false,
        &mut frames,
    );
    assert_eq!(
        repair,
        Repair::NeedsPageIn {
            object,
            offset: FRAME_SIZE
        }
    );
    assert!(
        !repair.resumes(),
        "nothing was repaired: resuming here re-faults for ever"
    );
}

/// **The grant is not made here, and the page is left read-only.** Whether the
/// store may proceed is the object's dirty accounting to decide, and this
/// module cannot reach it — so it reports what is needed and stops. A version
/// that granted first made the accounting unreachable: by the time anyone saw
/// the answer the page was already writable.
#[test]
fn a_write_to_a_clean_pager_page_asks_for_a_dirty_decision() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let object = ObjectId::from_raw(9);
    vm.map_object(
        VirtAddr::new(BASE),
        FRAME_SIZE,
        PageFlags::rw().user(),
        object,
        0,
    )
    .expect("map_object");
    let frame = frames.alloc_frame().expect("frame");
    vm.supply_page(VirtAddr::new(BASE), frame, &mut frames)
        .expect("supply");

    let repair = repair(&mut vm, VirtAddr::new(BASE + 0x40), true, &mut frames);
    assert_eq!(repair, Repair::NeedsDirty { object, offset: 0 });
    assert!(
        !repair.resumes(),
        "nothing is repaired until somebody decides whether the page may be dirtied",
    );
    assert!(
        !vm.arch()
            .translate(VirtAddr::new(BASE))
            .expect("resident")
            .1
            .writable(),
        "the page stays read-only: granting here would decide the question",
    );
}

#[test]
fn an_unmapped_address_is_fatal() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let repair = repair(&mut vm, VirtAddr::new(BASE), false, &mut frames);
    assert_eq!(repair, Repair::Fatal);
    assert!(!repair.resumes());
}

#[test]
fn a_read_of_a_supplied_page_is_fatal_not_a_second_page_in() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let object = ObjectId::from_raw(13);
    vm.map_object(
        VirtAddr::new(BASE),
        FRAME_SIZE,
        PageFlags::rw().user(),
        object,
        0,
    )
    .expect("map_object");
    let frame = frames.alloc_frame().expect("frame");
    vm.supply_page(VirtAddr::new(BASE), frame, &mut frames)
        .expect("supply");

    // A resident page that faults on a *read* is the mapping and the tables
    // disagreeing. Asking the pager for a page it already supplied would loop.
    assert_eq!(repair_at(&mut vm, BASE, false, &mut frames), Repair::Fatal);
}

#[test]
fn a_demand_fill_with_no_frames_left_is_fatal() {
    let mut vm = space();
    vm.map_anonymous_demand(VirtAddr::new(BASE), FRAME_SIZE, PageFlags::rw().user())
        .expect("map demand");
    let mut empty = MockFrameSource::new(0x40_0000, 0);

    // Refused, not silently left unmapped: a caller told "resume" would run
    // the same store into the same absent page, for ever. Out of memory is the
    // one way a repairable fault still fails, so it is the one worth pinning.
    assert_eq!(
        repair(&mut vm, VirtAddr::new(BASE), false, &mut empty),
        Repair::Fatal
    );
    assert!(vm.arch().translate(VirtAddr::new(BASE)).is_none());
}

/// `repair` at a bare address, for the cases that only care about the verdict.
fn repair_at(
    vm: &mut AddressSpace<MockAddressSpace>,
    va: u64,
    write: bool,
    frames: &mut MockFrameSource,
) -> Repair {
    repair(vm, VirtAddr::new(va), write, frames)
}
