// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::vm`.

use super::*;
use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

/// The fixture base. A **user-half** address, because most of what is mapped
/// here carries `user()` and `AddressSpace` refuses such a mapping above
/// `USER_ADDRESS_MAX` — a refusal these tests should not be arranging around,
/// since no port can honour a user page in the kernel half either. Use
/// [`KERNEL_BASE`] where the mapping is the kernel's own.
const BASE: u64 = 0x0000_4000_0000_0000;

/// A higher-half base, for the mappings that are the kernel's.
const KERNEL_BASE: u64 = 0xffff_c000_0000_0000;
/// A stand-in memory-object id for the shared-mapping tests.
const OBJ: ObjectId = ObjectId::from_raw(0x41);

fn space() -> AddressSpace<MockAddressSpace> {
    let mut frames = MockFrameSource::new(0x10_0000, 1024);
    AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
        .expect("empty space")
}

#[test]
fn maps_and_records_rights_then_unmaps() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let rights = PageFlags::rw();
    vm.map_anonymous(VirtAddr::new(BASE), 2 * FRAME_SIZE, rights, &mut frames)
        .expect("map");
    assert_eq!(vm.mapping_count(), 1);
    assert_eq!(vm.mapped_bytes(), 2 * FRAME_SIZE);
    // Rights and backing are recorded and readable inside the range.
    assert_eq!(vm.rights_at(VirtAddr::new(BASE + FRAME_SIZE)), Some(rights));
    assert_eq!(
        vm.backing_at(VirtAddr::new(BASE + FRAME_SIZE)),
        Some(Backing::Anonymous)
    );
    vm.unmap_range(VirtAddr::new(BASE), 2 * FRAME_SIZE)
        .expect("unmap");
    assert_eq!(vm.mapping_count(), 0);
    assert_eq!(vm.mapped_bytes(), 0);
    assert_eq!(vm.rights_at(VirtAddr::new(BASE)), None);
}

#[test]
fn map_device_page_is_untracked() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let device = PhysFrame::from_base(tessera_karch::PhysAddr::new(0x0a00_0000))
        .expect("aligned device page");
    vm.map_device_page(VirtAddr::new(BASE), device, &mut frames)
        .expect("map device page");
    // The arch mapping exists, but the wrapper records nothing: rights_at
    // consults only the tracked table, and teardown will not touch the
    // device physical page.
    assert!(vm.arch().translate(VirtAddr::new(BASE)).is_some());
    assert_eq!(vm.rights_at(VirtAddr::new(BASE)), None);
    assert_eq!(vm.mapping_count(), 0);
    assert_eq!(vm.mapped_bytes(), 0);
}

#[test]
fn copy_in_walks_mapped_pages_and_rejects_holes() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    // Two mapped pages the loader will populate.
    vm.map_anonymous(
        VirtAddr::new(BASE),
        2 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("map");
    // A source spanning a page boundary walks both frames (mock write is a
    // no-op; this exercises the translate/offset/chunk plumbing).
    let src = [0xabu8; FRAME_SIZE as usize + 16];
    assert_eq!(vm.copy_in(VirtAddr::new(BASE), &src), Ok(()));
    // A short source in the first page succeeds.
    assert_eq!(vm.copy_in(VirtAddr::new(BASE), &[1, 2, 3]), Ok(()));
    // Unaligned destination is rejected before any write.
    assert_eq!(
        vm.copy_in(VirtAddr::new(BASE + 1), &[0u8]),
        Err(KError::Unaligned)
    );
    // A source that runs off the end of the mapped region hits an unmapped
    // page and reports it.
    let over = [0u8; 3 * FRAME_SIZE as usize];
    assert_eq!(
        vm.copy_in(VirtAddr::new(BASE), &over),
        Err(KError::NotMapped)
    );
    // Empty source is a no-op success.
    assert_eq!(vm.copy_in(VirtAddr::new(BASE), &[]), Ok(()));
}

#[test]
fn lazy_anon_demand_fills_page_by_page() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let rights = PageFlags::rw().user();
    vm.map_anonymous_demand(VirtAddr::new(BASE), 2 * FRAME_SIZE, rights)
        .expect("reserve");
    // Recorded lazily: no page is present and nothing is resident yet.
    assert_eq!(vm.mapping_count(), 1);
    assert_eq!(vm.mapped_bytes(), 0);
    assert!(vm.arch().flags_at(VirtAddr::new(BASE)).is_none());
    assert_eq!(
        vm.backing_at(VirtAddr::new(BASE)),
        Some(Backing::AnonymousDemand)
    );

    // A fault anywhere in the first page demand-fills exactly that page.
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE + 0x40), true, &mut frames),
        FaultOutcome::Filled
    );
    let flags = vm
        .arch()
        .flags_at(VirtAddr::new(BASE))
        .expect("present after fill");
    assert!(flags.writable() && flags.is_user());
    assert_eq!(vm.mapped_bytes(), FRAME_SIZE);
    // The second page stays absent until its own fault.
    assert!(
        vm.arch()
            .flags_at(VirtAddr::new(BASE + FRAME_SIZE))
            .is_none()
    );
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE + FRAME_SIZE), false, &mut frames),
        FaultOutcome::Filled
    );
    assert!(
        vm.arch()
            .flags_at(VirtAddr::new(BASE + FRAME_SIZE))
            .is_some()
    );
    assert_eq!(vm.mapped_bytes(), 2 * FRAME_SIZE);
}

#[test]
fn cow_snapshot_shares_then_copies_each_side_on_write() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let rights = PageFlags::rw().user();
    const SRC: u64 = BASE;
    const DST: u64 = BASE + 0x1000_0000;
    vm.map_anonymous(VirtAddr::new(SRC), FRAME_SIZE, rights, &mut frames)
        .expect("map source");
    let orig = vm.arch().translate(VirtAddr::new(SRC)).expect("present").0;

    // Snapshot: both sides share `orig` read-only, both Cow.
    vm.snapshot_cow(
        VirtAddr::new(SRC),
        VirtAddr::new(DST),
        FRAME_SIZE,
        &mut frames,
    )
    .expect("snapshot");
    let (sf, sflags) = vm
        .arch()
        .translate(VirtAddr::new(SRC))
        .expect("src present");
    let (df, dflags) = vm
        .arch()
        .translate(VirtAddr::new(DST))
        .expect("dst present");
    assert!(!sflags.writable() && !dflags.writable(), "both read-only");
    assert_eq!(sf.base().as_u64(), orig.base().as_u64());
    assert_eq!(df.base().as_u64(), orig.base().as_u64(), "shared frame");
    assert_eq!(vm.backing_at(VirtAddr::new(SRC)), Some(Backing::Cow));
    assert_eq!(vm.backing_at(VirtAddr::new(DST)), Some(Backing::Cow));

    // Write through the source: copy private, remap writable; `orig` still
    // held by the snapshot, so it is not reclaimed yet.
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(SRC), true, &mut frames),
        FaultOutcome::Copied
    );
    let (sf2, sflags2) = vm
        .arch()
        .translate(VirtAddr::new(SRC))
        .expect("src present");
    assert!(sflags2.writable());
    assert_ne!(sf2.base().as_u64(), orig.base().as_u64(), "private copy");
    assert_eq!(
        vm.arch()
            .translate(VirtAddr::new(DST))
            .expect("dst present")
            .0
            .base()
            .as_u64(),
        orig.base().as_u64(),
        "snapshot still shares the original"
    );
    assert_eq!(frames.free_list_depth(), 0, "original still referenced");

    // Write through the snapshot: the original's last reference drops and it
    // is reclaimed to the free-list.
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(DST), true, &mut frames),
        FaultOutcome::Copied
    );
    assert!(
        vm.arch()
            .translate(VirtAddr::new(DST))
            .expect("dst present")
            .1
            .writable()
    );
    assert_eq!(
        frames.free_list_depth(),
        1,
        "original reclaimed after last sharer copied"
    );
}

#[test]
fn fault_outside_any_mapping_is_unresolvable() {
    let mut frames = MockFrameSource::new(0x20_0000, 16);
    let mut vm = space();
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(0x1_0000_0000), true, &mut frames),
        FaultOutcome::Unresolvable
    );
}

#[test]
fn object_backed_fault_needs_page_in_then_supply_resolves() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let object = ObjectId::from_raw(7);
    let rights = PageFlags::rw().user();
    vm.map_object(VirtAddr::new(BASE), 2 * FRAME_SIZE, rights, object, 0)
        .expect("map_object");
    assert_eq!(
        vm.backing_at(VirtAddr::new(BASE)),
        Some(Backing::Object {
            object,
            base_offset: 0
        })
    );
    // Non-resident second page → a page-in request at the right offset.
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE + FRAME_SIZE + 0x40), false, &mut frames),
        FaultOutcome::NeedsPageIn {
            object,
            offset: FRAME_SIZE
        }
    );
    // Supply the page (pager-provided frame) → resident but **read-only**
    // (software dirty tracking supplies read-only so a write faults), and a
    // read fault is now a genuine protection violation.
    let frame = frames.alloc_frame().expect("frame");
    vm.supply_page(VirtAddr::new(BASE + FRAME_SIZE), frame, &mut frames)
        .expect("supply");
    let flags = vm
        .arch()
        .translate(VirtAddr::new(BASE + FRAME_SIZE))
        .expect("resident")
        .1;
    assert!(!flags.writable() && flags.is_user(), "supplied read-only");
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE + FRAME_SIZE), false, &mut frames),
        FaultOutcome::Unresolvable
    );
}

#[test]
fn writing_a_supplied_object_page_faults_write_to_clean_then_grant_write() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let object = ObjectId::from_raw(9);
    let rights = PageFlags::rw().user();
    vm.map_object(VirtAddr::new(BASE), FRAME_SIZE, rights, object, 0)
        .expect("map_object");
    let frame = frames.alloc_frame().expect("frame");
    vm.supply_page(VirtAddr::new(BASE), frame, &mut frames)
        .expect("supply");

    // A write to the read-only, present, pager-backed page is the software
    // dirty-bit transition — not a hard fault.
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE + 0x40), true, &mut frames),
        FaultOutcome::WriteToClean { object, offset: 0 }
    );
    // The kernel grants write; the page is now writable and a further write
    // no longer faults.
    vm.grant_write(VirtAddr::new(BASE)).expect("grant");
    assert!(
        vm.arch()
            .translate(VirtAddr::new(BASE))
            .expect("resident")
            .1
            .writable()
    );
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE), true, &mut frames),
        FaultOutcome::Unresolvable
    );
    // Re-protecting read-only makes the next write re-dirty (fault again).
    vm.reprotect_ro(VirtAddr::new(BASE)).expect("reprotect");
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE), true, &mut frames),
        FaultOutcome::WriteToClean { object, offset: 0 }
    );
}

#[test]
fn evicting_a_supplied_page_frees_it_and_the_next_access_pages_in() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let object = ObjectId::from_raw(11);
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
    assert_eq!(vm.mapped_bytes(), FRAME_SIZE);
    let before = frames.free_list_depth();

    vm.evict_page(VirtAddr::new(BASE), &mut frames)
        .expect("evict");
    // The frame returned to the allocator and the mapping dropped a page.
    assert_eq!(frames.free_list_depth(), before + 1);
    assert_eq!(vm.mapped_bytes(), 0);
    assert!(vm.arch().translate(VirtAddr::new(BASE)).is_none());
    // The next access re-classifies as a page-in (non-resident again).
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE), false, &mut frames),
        FaultOutcome::NeedsPageIn { object, offset: 0 }
    );
}

#[test]
fn supply_page_rejects_uncovered_address() {
    let mut frames = MockFrameSource::new(0x20_0000, 16);
    let mut vm = space();
    let frame = frames.alloc_frame().expect("frame");
    assert_eq!(
        vm.supply_page(VirtAddr::new(0x1_0000_0000), frame, &mut frames),
        Err(KError::NotMapped)
    );
}

#[test]
fn fault_on_eager_anonymous_is_unresolvable() {
    // Eager pages are always present, so a fault on one is genuine.
    let mut frames = MockFrameSource::new(0x20_0000, 16);
    let mut vm = space();
    vm.map_anonymous(
        VirtAddr::new(BASE),
        FRAME_SIZE,
        PageFlags::rw().user(),
        &mut frames,
    )
    .expect("map");
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE), true, &mut frames),
        FaultOutcome::Unresolvable
    );
}

#[test]
fn rejects_writable_executable() {
    let mut frames = MockFrameSource::new(0x20_0000, 16);
    let mut vm = space();
    let wx = PageFlags::rw().execute(); // read + write + execute
    assert!(wx.is_wx());
    assert_eq!(
        vm.map_anonymous(VirtAddr::new(BASE), FRAME_SIZE, wx, &mut frames),
        Err(KError::WXViolation)
    );
    // Nothing was mapped by the rejected request.
    assert_eq!(vm.mapping_count(), 0);
}

/// A user-visible mapping may not reach above the architecture's user/kernel
/// boundary — and the range is what is checked, not the base.
///
/// The base alone is what a rejected version of this check would test, and it
/// is exactly what the arm this test exists for did test: a request based one
/// page below the boundary passes a base check and maps into the kernel half
/// anyway. A process's top-level table shares the kernel's higher-half entries
/// by value, so that is not a stray mapping in one address space — it is an
/// edit to the tables the whole machine runs on.
#[test]
fn rejects_a_user_mapping_that_reaches_above_the_user_half() {
    const MAX: u64 = <MockAddressSpace as tessera_karch::AddressSpaceOps>::USER_ADDRESS_MAX;
    let user = PageFlags::rw().user();

    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();

    // Wholly above the boundary.
    assert_eq!(
        vm.map_anonymous(VirtAddr::new(MAX), FRAME_SIZE, user, &mut frames),
        Err(KError::InvalidMapping)
    );
    // Based below it and running across it — the case a base-only check lets
    // through.
    assert_eq!(
        vm.map_anonymous(
            VirtAddr::new(MAX - FRAME_SIZE),
            2 * FRAME_SIZE,
            user,
            &mut frames
        ),
        Err(KError::InvalidMapping)
    );
    // And where the range's end wraps rather than exceeds.
    assert_eq!(
        vm.map_anonymous(
            VirtAddr::new(u64::MAX - FRAME_SIZE + 1),
            FRAME_SIZE * 2,
            user,
            &mut frames
        ),
        Err(KError::InvalidMapping)
    );
    assert_eq!(vm.mapping_count(), 0);

    // The last page below the boundary is not out of range, or the check would
    // be off by one and no test above would say so.
    vm.map_anonymous(
        VirtAddr::new(MAX - FRAME_SIZE),
        FRAME_SIZE,
        user,
        &mut frames,
    )
    .expect("the last user page is mappable");
    assert_eq!(vm.mapping_count(), 1);
}

/// The same boundary does **not** apply to a kernel mapping: the higher half is
/// where kernel mappings live, and a check that refused them would refuse the
/// kernel its own address space.
#[test]
fn the_user_bound_does_not_apply_to_kernel_mappings() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    vm.map_anonymous(
        VirtAddr::new(KERNEL_BASE),
        FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("kernel mapping above the user boundary");
    assert_eq!(vm.mapping_count(), 1);
}

/// The lazy and pager-backed reservations carry the same bound as the eager
/// map. They record a mapping without touching a page table, so a request they
/// accepted would install nothing now and everything on the first fault.
#[test]
fn the_user_bound_covers_the_reservations_too() {
    const MAX: u64 = <MockAddressSpace as tessera_karch::AddressSpaceOps>::USER_ADDRESS_MAX;
    let user = PageFlags::rw().user();
    let mut vm = space();

    assert_eq!(
        vm.map_anonymous_demand(VirtAddr::new(MAX - FRAME_SIZE), 2 * FRAME_SIZE, user),
        Err(KError::InvalidMapping)
    );
    assert_eq!(
        vm.map_object(
            VirtAddr::new(MAX - FRAME_SIZE),
            2 * FRAME_SIZE,
            user,
            OBJ,
            0
        ),
        Err(KError::InvalidMapping)
    );
    assert_eq!(vm.mapping_count(), 0);
}

#[test]
fn rejects_unaligned_and_bad_length() {
    let mut frames = MockFrameSource::new(0x20_0000, 16);
    let mut vm = space();
    assert_eq!(
        vm.map_anonymous(
            VirtAddr::new(BASE + 1),
            FRAME_SIZE,
            PageFlags::rw(),
            &mut frames
        ),
        Err(KError::Unaligned)
    );
    assert_eq!(
        vm.map_anonymous(
            VirtAddr::new(BASE),
            FRAME_SIZE - 1,
            PageFlags::rw(),
            &mut frames
        ),
        Err(KError::InvalidMapping)
    );
    assert_eq!(
        vm.map_anonymous(VirtAddr::new(BASE), 0, PageFlags::rw(), &mut frames),
        Err(KError::InvalidMapping)
    );
}

#[test]
fn rejects_overlap() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    vm.map_anonymous(
        VirtAddr::new(BASE),
        2 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("first map");
    // Overlapping the second page must be rejected without side effects.
    assert_eq!(
        vm.map_anonymous(
            VirtAddr::new(BASE + FRAME_SIZE),
            2 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames
        ),
        Err(KError::AlreadyMapped)
    );
    assert_eq!(vm.mapping_count(), 1);
}

#[test]
fn protect_changes_recorded_rights() {
    let mut frames = MockFrameSource::new(0x20_0000, 16);
    let mut vm = space();
    vm.map_anonymous(
        VirtAddr::new(BASE),
        FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("map");
    vm.protect_range(VirtAddr::new(BASE), FRAME_SIZE, PageFlags::ro())
        .expect("protect");
    assert_eq!(vm.rights_at(VirtAddr::new(BASE)), Some(PageFlags::ro()));
}

#[test]
fn out_of_frames_rolls_back() {
    // Only one frame available, but two pages requested: the first page
    // maps, the second fails, and the whole request is rolled back.
    let mut frames = MockFrameSource::new(0x20_0000, 1);
    let mut vm = space();
    assert_eq!(
        vm.map_anonymous(
            VirtAddr::new(BASE),
            2 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames
        ),
        Err(KError::OutOfMemory)
    );
    assert_eq!(vm.mapping_count(), 0);
    assert_eq!(vm.mapped_bytes(), 0);
    // The address space is clean: a later single-page map succeeds.
    let mut more = MockFrameSource::new(0x30_0000, 4);
    vm.map_anonymous(VirtAddr::new(BASE), FRAME_SIZE, PageFlags::rw(), &mut more)
        .expect("clean remap");
}

#[test]
fn teardown_frees_every_leaf_and_returns_to_baseline() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    // Two eager regions (5 pages total) draw real frames; one lazy region
    // that is never faulted draws none but is recorded.
    vm.map_anonymous(
        VirtAddr::new(BASE),
        3 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("map A");
    vm.map_anonymous(
        VirtAddr::new(BASE + 0x1000_0000),
        2 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("map B");
    vm.map_anonymous_demand(
        VirtAddr::new(BASE + 0x2000_0000),
        FRAME_SIZE,
        PageFlags::rw(),
    )
    .expect("map lazy");
    let drawn = frames.handed_out();
    assert_eq!(drawn, 5, "five resident pages drawn");
    assert_eq!(vm.mapping_count(), 3);

    vm.teardown(&mut frames);

    // Every mapping is gone and every resident frame returned to the
    // free-list; the never-faulted lazy region freed nothing but cleared.
    assert_eq!(vm.mapping_count(), 0, "all mappings cleared");
    assert_eq!(vm.mapped_bytes(), 0);
    assert_eq!(frames.free_list_depth(), drawn, "all resident frames freed");
    // The freed frames are reused before any new frame is drawn.
    let mut vm2 = space();
    vm2.map_anonymous(
        VirtAddr::new(BASE),
        drawn as u64 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("remap reuses freed frames");
    assert_eq!(frames.handed_out(), drawn, "reuse, not fresh draws");
    assert_eq!(frames.free_list_depth(), 0);
}

#[test]
fn teardown_of_cow_snapshot_reclaims_shared_frame_once() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let rights = PageFlags::rw().user();
    const SRC: u64 = BASE;
    const DST: u64 = BASE + 0x1000_0000;
    vm.map_anonymous(VirtAddr::new(SRC), FRAME_SIZE, rights, &mut frames)
        .expect("map source");
    vm.snapshot_cow(
        VirtAddr::new(SRC),
        VirtAddr::new(DST),
        FRAME_SIZE,
        &mut frames,
    )
    .expect("snapshot");
    // One physical frame, two read-only Cow mappings sharing it (refcount 2).
    assert_eq!(frames.handed_out(), 1);
    assert_eq!(frames.free_list_depth(), 0);

    vm.teardown(&mut frames);

    // Tearing down both mappings drops both references; the frame is
    // reclaimed exactly once (not double-freed).
    assert_eq!(vm.mapping_count(), 0);
    assert_eq!(frames.free_list_depth(), 1, "shared frame reclaimed once");
}

/// The whole point of a memory object: one set of frames, two address
/// spaces, and every frame reclaimed **exactly once** whatever order the
/// spaces go down in.
///
/// Three references exist while both are mapped — the object's own, and
/// one per mapping — and the accounting is absolute rather than ordered,
/// which is what makes teardown order irrelevant. This test drives the
/// order that would break a design where the object's reference were
/// implicit in the first mapping.
#[test]
fn a_shared_object_is_reclaimed_once_however_the_holders_go_down() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut a = space();
    let mut b = space();
    let rights = PageFlags::rw().user();

    // The object's own frames, drawn once.
    let frame = frames.alloc_frame().expect("frame");
    let owned = [frame];
    assert_eq!(frames.free_list_depth(), 0);

    a.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &owned, &mut frames)
        .expect("map a");
    b.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &owned, &mut frames)
        .expect("map b");

    // A tears down: 3 -> 2. Nothing comes back; B is still using it.
    a.teardown(&mut frames);
    assert_eq!(frames.free_list_depth(), 0, "B still maps it");

    // B tears down: 2 -> 1. Still nothing — the object itself holds the
    // last reference, and only destroying it releases that.
    b.teardown(&mut frames);
    assert_eq!(frames.free_list_depth(), 0, "the object still owns it");

    // The object's own reference, as `MemoryTable::destroy` drops it.
    frames.free_frame(frame);
    assert_eq!(frames.free_list_depth(), 1, "reclaimed exactly once");
}

/// The same three references released in the opposite order — the object
/// destroyed while both mappings are live. A holder closing its handle
/// while somebody else is using the pages is the ordinary case.
#[test]
fn destroying_the_object_first_leaves_the_mappings_alive() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut a = space();
    let mut b = space();
    let rights = PageFlags::rw().user();
    let frame = frames.alloc_frame().expect("frame");
    let owned = [frame];
    a.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &owned, &mut frames)
        .expect("map a");
    b.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &owned, &mut frames)
        .expect("map b");

    frames.free_frame(frame); // the object is destroyed: 3 -> 2
    assert_eq!(frames.free_list_depth(), 0);
    a.teardown(&mut frames); // 2 -> 1
    assert_eq!(frames.free_list_depth(), 0);
    b.teardown(&mut frames); // 1 -> free list
    assert_eq!(frames.free_list_depth(), 1, "reclaimed exactly once");
}

/// **Not zeroed.** The bytes the other holder put there are the payload;
/// carrying `map_anonymous`'s `zero_frame` into this path would erase
/// exactly what is being handed over, and the failure would look like a
/// driver that wrote nothing.
#[test]
fn mapping_a_shared_object_does_not_erase_its_contents() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut a = space();
    let mut b = space();
    let rights = PageFlags::rw().user();
    let frame = frames.alloc_frame().expect("frame");
    let owned = [frame];

    a.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &owned, &mut frames)
        .expect("map a");
    // Both spaces resolve the same virtual address to the same physical
    // frame, which is the whole mechanism.
    b.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &owned, &mut frames)
        .expect("map b");
    assert_eq!(
        a.arch()
            .translate(VirtAddr::new(BASE))
            .map(|(f, _)| f.base()),
        b.arch()
            .translate(VirtAddr::new(BASE))
            .map(|(f, _)| f.base()),
    );
}

/// `record` silently does nothing when the mapping table is full and does
/// not raise the count, so a mapping installed past the bound would exist
/// in the page tables with no record — invisible to `teardown`,
/// unrevocable, and its frames lost for the life of the machine. The
/// check has to come **before** anything is mapped or retained.
#[test]
fn a_full_mapping_table_refuses_before_it_retains_anything() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let rights = PageFlags::rw().user();
    for i in 0..MAX_MAPPINGS {
        vm.map_anonymous(
            VirtAddr::new(BASE + i as u64 * FRAME_SIZE),
            FRAME_SIZE,
            rights,
            &mut frames,
        )
        .expect("fill the table");
    }
    let frame = frames.alloc_frame().expect("frame");
    let owned = [frame];
    let before = frames.free_list_depth();
    let at = VirtAddr::new(BASE + 0x1000_0000);
    assert_eq!(
        vm.map_shared(at, rights, OBJ, 0, &owned, &mut frames),
        Err(KError::OutOfMemory),
    );
    // Nothing mapped, and no reference taken: freeing the object's own
    // reference returns the frame, which it could not do if a stray
    // retain were outstanding.
    assert!(vm.arch().translate(at).is_none());
    frames.free_frame(frame);
    assert_eq!(frames.free_list_depth(), before + 1);
}

/// A partial failure must free every reference it had already taken.
/// `map_anonymous`'s rollback deliberately never frees — a bump-allocated
/// frame it just drew has nowhere to go back to — but here every retain is
/// a reference somebody else's frame is carrying.
#[test]
fn a_partial_shared_mapping_releases_what_it_retained() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let rights = PageFlags::rw().user();
    let owned = [
        frames.alloc_frame().expect("a"),
        frames.alloc_frame().expect("b"),
    ];
    // A second mapping over the first page's address collides part-way
    // through the run, so page 0 maps and page 1 refuses.
    vm.map_anonymous(
        VirtAddr::new(BASE + FRAME_SIZE),
        FRAME_SIZE,
        rights,
        &mut frames,
    )
    .expect("occupy the second page");
    let before = frames.free_list_depth();
    assert!(
        vm.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &owned, &mut frames)
            .is_err(),
    );
    // Both of the object's frames are back to a single reference, so
    // releasing the object's own returns each exactly once.
    frames.free_frame(owned[0]);
    frames.free_frame(owned[1]);
    assert_eq!(frames.free_list_depth(), before + 2);
}

/// A shared mapping is fully resident from the moment it exists, so a
/// fault on one is the record and the tables having drifted — never a
/// page-in request. Sharing `Backing::Object` would have forwarded it to
/// a pager the object does not have.
#[test]
fn a_fault_on_a_shared_mapping_is_unresolvable() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    let rights = PageFlags::rw().user();
    let frame = frames.alloc_frame().expect("frame");
    vm.map_shared(VirtAddr::new(BASE), rights, OBJ, 0, &[frame], &mut frames)
        .expect("map");
    // Present page, read fault: not a dirty-bit transition, not a page-in.
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE), false, &mut frames),
        FaultOutcome::Unresolvable,
    );
    assert_eq!(
        vm.resolve_fault(VirtAddr::new(BASE), true, &mut frames),
        FaultOutcome::Unresolvable,
    );
}

#[test]
fn reclaim_range_frees_only_that_region() {
    let mut frames = MockFrameSource::new(0x20_0000, 1024);
    let mut vm = space();
    const A: u64 = BASE;
    const B: u64 = BASE + 0x1000_0000;
    vm.map_anonymous(
        VirtAddr::new(A),
        2 * FRAME_SIZE,
        PageFlags::rw(),
        &mut frames,
    )
    .expect("map A");
    vm.map_anonymous(VirtAddr::new(B), FRAME_SIZE, PageFlags::rw(), &mut frames)
        .expect("map B");

    // A wrong base/len is not an exact live mapping.
    assert_eq!(
        vm.reclaim_range(VirtAddr::new(A), FRAME_SIZE, &mut frames),
        Err(KError::NotMapped)
    );

    vm.reclaim_range(VirtAddr::new(A), 2 * FRAME_SIZE, &mut frames)
        .expect("reclaim A");
    // A's two frames freed; B untouched and still mapped.
    assert_eq!(frames.free_list_depth(), 2, "only A's frames freed");
    assert_eq!(vm.mapping_count(), 1);
    assert_eq!(vm.rights_at(VirtAddr::new(A)), None, "A gone");
    assert_eq!(
        vm.rights_at(VirtAddr::new(B)),
        Some(PageFlags::rw()),
        "B intact"
    );
}

#[test]
fn a_broadcast_invalidate_leaves_no_cpu_to_tell() {
    // The branch that has to vanish. Whatever the mask says, an architecture
    // whose invalidate reaches the whole domain has nothing left to send — and
    // the constant is what lets the optimizer delete the send.
    assert_eq!(remote_invalidations(true, 0b1111, 0), 0);
    assert_eq!(remote_invalidations(true, u64::MAX, 3), 0);
}

#[test]
fn a_local_invalidate_leaves_every_other_active_cpu() {
    // ...and the branch that must not vanish. The asking CPU is excluded
    // because it has just invalidated; every other CPU with the space active
    // still holds the entry.
    assert_eq!(remote_invalidations(false, 0b1011, 0), 0b1010);
    assert_eq!(remote_invalidations(false, 0b1011, 1), 0b1001);
    assert_eq!(remote_invalidations(false, 0b1011, 3), 0b0011);

    // A space nobody has active needs no message even where nothing broadcasts,
    // which is the case every single-CPU boot in this tree is in.
    assert_eq!(remote_invalidations(false, 0, 0), 0);

    // An index too wide for the mask reports everyone rather than shifting off
    // the end. Over-reporting costs a message; under-reporting costs a stale
    // translation, and only one of those is recoverable.
    assert_eq!(remote_invalidations(false, 0b1011, 64), 0b1011);
    assert_eq!(remote_invalidations(false, 0b1011, u32::MAX), 0b1011);
}

#[test]
fn changing_a_mapping_invalidates_the_page_it_changed() {
    // The mapping code is held to having *asked*. A port's invalidate leaves no
    // trace — an instruction runs and the TLB is different — so the mock
    // records the request, and this is the only place the three call sites can
    // be checked at all.
    use tessera_karch::AddressSpaceOps;
    let mut frames = MockFrameSource::new(0x10_0000, 16);
    let mut space = MockAddressSpace::new(&mut frames, 0).expect("space");
    let page = VirtAddr::new(0x4000);
    let frame = PhysFrame::from_base(PhysAddr::new(0x20_0000)).expect("frame");

    space
        .map(page, frame, PageFlags::rw(), &mut frames)
        .expect("map");
    space.protect(page, PageFlags::ro()).expect("protect");
    space.unmap(page).expect("unmap");

    assert_eq!(space.invalidated(), [page, page, page]);
}

// --- A failed map gives back what it drew ----------------------------------

/// **A map that runs out of frames returns the ones it already took.**
///
/// The rollback unmapped and stopped there, on the stated grounds that the
/// allocator had no free path — true when it was written, untrue since the
/// bounded free list landed. The cost is not one frame: a caller that can make
/// a map fail can make it fail repeatedly, and each attempt kept everything it
/// had drawn, so a bound on how much one request may map became no bound at
/// all on what a sequence of failing requests may consume.
///
/// Counted exactly rather than checked for absence of a leak, because an exact
/// count is the only check that also catches freeing too much.
#[test]
fn a_map_that_runs_out_of_frames_gives_back_what_it_drew() {
    let user = PageFlags::rw().user();
    // Four frames for the leaves, plus room for whatever page-table levels the
    // mock walks through.
    let mut frames = MockFrameSource::new(0x20_0000, 8);
    let mut vm = space();

    // Ask for more pages than there are frames: some map, then the allocator
    // runs dry.
    assert_eq!(
        vm.map_anonymous(VirtAddr::new(BASE), 64 * FRAME_SIZE, user, &mut frames),
        Err(KError::OutOfMemory)
    );

    // Nothing is recorded, nothing is mapped, and every frame the attempt drew
    // for a leaf is back.
    assert_eq!(vm.mapping_count(), 0);
    assert_eq!(vm.mapped_bytes(), 0);
    assert_eq!(vm.arch().translate(VirtAddr::new(BASE)), None);
    assert!(
        frames.free_list_depth() > 0,
        "the frames the failed map took must come back, not vanish for the life \
         of the machine",
    );

    // And the space is usable afterwards: the returned frames are drawn again.
    let before = frames.handed_out();
    vm.map_anonymous(VirtAddr::new(BASE), 2 * FRAME_SIZE, user, &mut frames)
        .expect("the reclaimed frames are available again");
    assert_eq!(
        frames.handed_out(),
        before,
        "a map after the rollback is served from what the rollback returned",
    );
}

/// The frame that was drawn and never mapped comes back too.
///
/// When the port refuses the mapping itself, the frame for *that* page has
/// been allocated and zeroed and never installed — so the rollback, which
/// works by unmapping, cannot reach it. It is the one frame that needs
/// handing back on its own.
///
/// The refusal is arranged with an untracked device mapping: `map_device_page`
/// records nothing, so the overlap check sees a free range and the port is the
/// thing that says no.
#[test]
fn the_frame_drawn_for_the_page_that_failed_comes_back() {
    let mut frames = MockFrameSource::new(0x20_0000, 32);
    let mut vm = space();

    // An arch mapping the tracked table does not know about, two pages in.
    let blocker = VirtAddr::new(BASE + 2 * FRAME_SIZE);
    let device = PhysFrame::from_base(tessera_karch::PhysAddr::new(0x0a00_0000))
        .expect("aligned device page");
    vm.map_device_page(blocker, device, &mut frames)
        .expect("map device page");

    let drawn_before = frames.handed_out();
    assert_eq!(
        vm.map_anonymous(
            VirtAddr::new(BASE),
            4 * FRAME_SIZE,
            PageFlags::rw(),
            &mut frames
        ),
        Err(KError::AlreadyMapped),
        "the port refuses the third page, which the tracked table could not see",
    );

    // Three frames were drawn: two mapped and rolled back, one drawn for the
    // page that failed and never mapped. All three are back.
    assert_eq!(
        frames.free_list_depth(),
        frames.handed_out() - drawn_before,
        "every frame the failed map drew is back on the free list",
    );
    assert_eq!(vm.mapping_count(), 0);
}

/// **A shared mapping cannot be undone by the operation that frees nothing.**
///
/// `map_shared` takes a reference per page; `unmap_range` releases none and
/// drops the mapping record, so the reference stops being reachable at all —
/// teardown walks the records, and there is no longer one to walk. Refusing is
/// what keeps `unmap_range`'s own contract ("hands nothing back") true of every
/// caller, rather than true of the callers that happened to be right.
#[test]
fn a_shared_mapping_refuses_the_unmap_that_frees_nothing() {
    let mut frames = MockFrameSource::new(0x20_0000, 64);
    let mut vm = space();
    let frame = frames.alloc_frame().expect("frame");
    let base = VirtAddr::new(BASE);

    vm.map_shared(
        base,
        PageFlags::none().read().user(),
        OBJ,
        0,
        &[frame],
        &mut frames,
    )
    .expect("map shared");
    let held = frames.references(frame);

    assert_eq!(
        vm.unmap_range(base, FRAME_SIZE),
        Err(KError::WrongType),
        "the undo that gives nothing back is not this mapping's undo",
    );
    assert_eq!(vm.mapping_count(), 1, "and it changed nothing");
    assert_eq!(frames.references(frame), held);

    // The undo that does match gives the reference back.
    vm.reclaim_range(base, FRAME_SIZE, &mut frames)
        .expect("reclaim");
    assert_eq!(vm.mapping_count(), 0);
    assert_eq!(
        frames.references(frame),
        held - 1,
        "reclaim_range releases the reference map_shared took",
    );
}
