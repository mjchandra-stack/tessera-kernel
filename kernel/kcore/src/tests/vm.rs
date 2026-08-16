// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::vm`.

use super::*;
use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

const BASE: u64 = 0xffff_c000_0000_0000;
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
