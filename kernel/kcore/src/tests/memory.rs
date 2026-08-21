// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::memory`.

use super::*;
use crate::vm::Asid;
use tessera_karch_mock::{MockAddressSpace, MockFrameSource};

const OWNER: ObjectId = ObjectId::from_raw(0x60);

fn space(frames: &mut MockFrameSource) -> AddressSpace<MockAddressSpace> {
    AddressSpace::<MockAddressSpace>::new(frames, 0xffff_8000_0000_0000, Asid(1)).expect("space")
}

/// **Strict binding, and a refusal rather than a weakening.** An alignment
/// the allocator cannot meet is answered `no` — the frames it had drawn go
/// back, and the caller learns now. The alternative is an object that does
/// not meet the constraint it stated, whose owner finds out when a device
/// reads the wrong address.
#[test]
fn an_alignment_that_cannot_be_met_is_refused_not_rounded() {
    // Frames start at 0x1000_1000 and step by pages, so nothing this
    // allocator can hand out is aligned to a megabyte.
    let mut alloc = MockFrameSource::new(0x1000_1000, 64);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    let impossible = Placement {
        alignment: 0x10_0000,
        ..Placement::default()
    };
    assert_eq!(
        table.create(OWNER, 1, impossible, &space, &mut alloc),
        Err(KError::OutOfMemory),
    );
    // And the refusal cost nothing: the frames are back, so an ordinary
    // request still succeeds.
    assert!(
        table
            .create(OWNER, 1, Placement::default(), &space, &mut alloc)
            .is_ok(),
        "a refused placement gives its frames back",
    );
}

/// A physically-contiguous object is a run, checked frame by frame. The
/// bump allocator hands out consecutive frames, so this succeeds — and the
/// check is what makes that a guarantee rather than a coincidence of the
/// allocator in use.
#[test]
fn a_physical_run_is_checked_frame_by_frame() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    let run = Placement {
        physically_contiguous: true,
        ..Placement::default()
    };
    let object = table
        .create(OWNER, 3, run, &space, &mut alloc)
        .expect("a run");
    let mut out = [PhysFrame::containing(tessera_karch::PhysAddr::new(0)); MAX_OBJECT_PAGES];
    assert_eq!(table.frames_of(object, &mut out), 3);
    for (page, frame) in out[..3].iter().enumerate() {
        assert_eq!(
            frame.base().as_u64(),
            out[0].base().as_u64() + page as u64 * FRAME_SIZE,
        );
    }
}

/// **Device-visible contiguity is not a constraint on the memory**, and
/// this is the IOMMU-first rule in one assertion: a request for it accepts
/// whatever frames come back, because the contiguity it asks for is the
/// broker's to produce in the mapping. Checking it against physical
/// addresses would be demanding physical contiguity under another name,
/// which is exactly the carveout pressure the rule exists to avoid.
#[test]
fn device_contiguity_asks_nothing_of_the_frames() {
    let scattered = [
        PhysFrame::from_base(tessera_karch::PhysAddr::new(0x9000)),
        PhysFrame::from_base(tessera_karch::PhysAddr::new(0x1000)),
    ];
    let device = Placement {
        device_contiguous: true,
        ..Placement::default()
    };
    assert_eq!(device.satisfied_by(&scattered), Ok(()));
    // The same frames refuse a physical request, which is what makes the
    // two different questions rather than one spelled two ways.
    let physical = Placement {
        physically_contiguous: true,
        ..Placement::default()
    };
    assert_eq!(physical.satisfied_by(&scattered), Err(KError::OutOfMemory));
}

/// An addressing limit is measured against the **last byte** of every
/// frame. A frame that starts below a 32-bit controller's ceiling and ends
/// above it is still memory that controller cannot address.
#[test]
fn an_addressing_limit_counts_the_last_byte() {
    let frames = [PhysFrame::from_base(tessera_karch::PhysAddr::new(0x1000))];
    let just_short = Placement {
        address_limit: 0x1fff,
        ..Placement::default()
    };
    assert_eq!(just_short.satisfied_by(&frames), Ok(()));
    let one_byte_less = Placement {
        address_limit: 0x1ffe,
        ..Placement::default()
    };
    assert_eq!(
        one_byte_less.satisfied_by(&frames),
        Err(KError::OutOfMemory),
    );
}

#[test]
fn creating_an_object_draws_and_records_its_frames() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();

    let object = table
        .create(OWNER, 2, Placement::default(), &space, &mut alloc)
        .expect("create");
    assert!(
        object.raw() >= MEMORY_OBJECT_ID_BASE,
        "minted above the fabricated range"
    );
    assert_eq!(table.pages_of(object), Some(2));
    assert_eq!(table.len_of(object), Some(2 * FRAME_SIZE));
    assert_eq!(table.owner_of(object), Some(OWNER));
    assert_eq!(table.count(), 1);

    let mut out = [PhysFrame::containing(tessera_karch::PhysAddr::new(0)); MAX_OBJECT_PAGES];
    assert_eq!(table.frames_of(object, &mut out), 2);
    assert_ne!(out[0].base().as_u64(), out[1].base().as_u64());
}

/// A capability that is not a memory object answers `None`, which a caller
/// must be able to tell from an object with no pages — a thing that cannot
/// exist, because `create` refuses zero.
#[test]
fn an_unknown_object_has_no_pages_and_zero_is_refused() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    assert_eq!(table.pages_of(ObjectId::from_raw(0x99)), None);
    assert_eq!(
        table.create(OWNER, 0, Placement::default(), &space, &mut alloc),
        Err(KError::InvalidMapping),
    );
    assert_eq!(
        table.create(
            OWNER,
            MAX_OBJECT_PAGES + 1,
            Placement::default(),
            &space,
            &mut alloc
        ),
        Err(KError::InvalidMapping),
    );
}

/// A partial allocation frees what it drew. A bump allocator has no unwind
/// of its own, so frames left here are lost for the life of the machine
/// and invisible to the caller.
#[test]
fn a_partial_allocation_gives_back_every_frame_it_drew() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    // Drain the allocator to fewer frames than the object needs.
    let before = alloc.free_list_depth();
    let _ = before;
    let mut drained = 0;
    while alloc.alloc_frame().is_some() {
        drained += 1;
        if drained > 4096 {
            panic!("allocator never exhausted");
        }
    }
    assert_eq!(
        table.create(OWNER, 2, Placement::default(), &space, &mut alloc),
        Err(KError::OutOfMemory),
    );
    assert_eq!(table.count(), 0, "and nothing was recorded");
}

/// Destroying releases the object's own reference to each frame and
/// forgets it. It does **not** release anybody else's — a frame a mapping
/// still holds stays alive, which is what lets a holder close its handle
/// while another process is using the pages.
#[test]
fn destroying_releases_the_objects_own_reference() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    let object = table
        .create(OWNER, 3, Placement::default(), &space, &mut alloc)
        .expect("create");

    let before = alloc.free_list_depth();
    assert_eq!(table.destroy(object, &mut alloc), 3);
    assert_eq!(
        alloc.free_list_depth(),
        before + 3,
        "every frame came back exactly once",
    );
    assert_eq!(table.pages_of(object), None);
    // Destroying twice is a no-op, so a departure path need not first ask
    // whether the object was still there.
    assert_eq!(table.destroy(object, &mut alloc), 0);
}

#[test]
fn a_full_table_is_refused_and_ids_are_never_reused() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 256);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    let mut minted = [ObjectId::from_raw(0); MAX_MEMORY_OBJECTS];
    for slot in minted.iter_mut() {
        *slot = table
            .create(OWNER, 1, Placement::default(), &space, &mut alloc)
            .expect("fits");
    }
    assert_eq!(
        table.create(OWNER, 1, Placement::default(), &space, &mut alloc),
        Err(KError::OutOfMemory),
    );
    // Every id distinct — an id handed out twice would let a stale handle
    // name a live object.
    for (i, a) in minted.iter().enumerate() {
        for b in minted.iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
    // And a freed slot does not recycle its id.
    table.destroy(minted[0], &mut alloc);
    let next = table
        .create(OWNER, 1, Placement::default(), &space, &mut alloc)
        .expect("reuse slot");
    assert!(!minted.contains(&next));
}

/// Ownership moves on transfer, and the sweep finds what a departing
/// process owns — the question a refcount would answer, answered without
/// one because transfer has a single owner at every instant.
#[test]
fn ownership_moves_and_the_sweep_finds_it() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 256);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    let receiver = ObjectId::from_raw(0x61);
    let object = table
        .create(OWNER, 1, Placement::default(), &space, &mut alloc)
        .expect("create");

    let mut out = [ObjectId::from_raw(0); MAX_MEMORY_OBJECTS];
    assert_eq!(table.objects_owned_by(OWNER, &mut out), 1);
    assert_eq!(out[0], object);
    assert_eq!(table.objects_owned_by(receiver, &mut out), 0);

    assert!(table.set_owner(object, receiver));
    assert_eq!(table.owner_of(object), Some(receiver));
    assert_eq!(
        table.objects_owned_by(OWNER, &mut out),
        0,
        "the sender owns nothing now"
    );
    assert_eq!(table.objects_owned_by(receiver, &mut out), 1);

    // A capability that is not a memory object passes through untouched,
    // which is why the departure paths call this unconditionally.
    assert!(!table.set_owner(ObjectId::from_raw(0x99), receiver));
}

/// **The backstop: frames a device can still reach do not go back to the
/// allocator.** `Executive::memory_destroy` detaches first, so this should
/// never fire — and if it does, leaking is the lesser of the two harms and
/// the event is what keeps it from being silent. Handing those frames out
/// again would let a device write into somebody else's memory.
#[test]
fn destroying_an_attached_object_frees_nothing() {
    let mut frames = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut frames);
    let mut table = MemoryTable::new();
    let object = table
        .create(OWNER, 2, Placement::default(), &space, &mut frames)
        .expect("create");
    table
        .attach(
            object,
            Attachment {
                device: ObjectId::from_raw(21),
                address: 0x8000_0000,
                len: 2 * FRAME_SIZE,
                scoped: true,
            },
        )
        .expect("attach");

    assert_eq!(table.destroy(object, &mut frames), 0, "nothing was freed");
    assert!(table.attachment_of(object).is_some(), "and it still exists");

    // Detached, it goes as it always did.
    assert!(table.detach(object).is_some());
    assert_eq!(table.destroy(object, &mut frames), 2);
}

/// A second attachment is refused rather than replacing the first, which
/// would leave a translation installed that nothing can name and therefore
/// nothing will ever remove.
#[test]
fn an_object_can_be_reachable_by_one_device_at_a_time() {
    let mut frames = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut frames);
    let mut table = MemoryTable::new();
    let object = table
        .create(OWNER, 1, Placement::default(), &space, &mut frames)
        .expect("create");
    let first = Attachment {
        device: ObjectId::from_raw(21),
        address: 0x8000_0000,
        len: FRAME_SIZE,
        scoped: true,
    };
    table.attach(object, first).expect("attach");
    assert_eq!(
        table.attach(
            object,
            Attachment {
                device: ObjectId::from_raw(22),
                address: 0x9000_0000,
                len: FRAME_SIZE,
                scoped: true,
            },
        ),
        Err(KError::AlreadyMapped),
    );
    assert_eq!(table.attachment_of(object), Some(first));
}

/// Every object a device can reach is findable from the device, which is
/// what the lease-end path walks — the one revocation that starts at the
/// device rather than at the object.
#[test]
fn the_objects_a_device_can_reach_are_findable_from_it() {
    let mut frames = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut frames);
    let mut table = MemoryTable::new();
    let device = ObjectId::from_raw(21);
    let a = table
        .create(OWNER, 1, Placement::default(), &space, &mut frames)
        .expect("create");
    let b = table
        .create(OWNER, 1, Placement::default(), &space, &mut frames)
        .expect("create");
    let c = table
        .create(OWNER, 1, Placement::default(), &space, &mut frames)
        .expect("create");
    for (object, at) in [(a, 0x8000_0000u64), (c, 0x8000_2000)] {
        table
            .attach(
                object,
                Attachment {
                    device,
                    address: at,
                    len: FRAME_SIZE,
                    scoped: true,
                },
            )
            .expect("attach");
    }
    let mut out = [ObjectId::from_raw(0); MAX_MEMORY_OBJECTS];
    let found = table.objects_attached_to(device, &mut out);
    assert_eq!(found, 2);
    assert!(out[..found].contains(&a) && out[..found].contains(&c));
    assert!(!out[..found].contains(&b), "b was never attached");
}

/// A class rises and never falls, and re-stating one is not an error.
///
/// The lowering refusal is the load-bearing half: without it anything
/// holding a protected buffer could clear the class and hand the memory to
/// a device, and every check above this one would be decorative.
#[test]
fn a_class_rises_and_never_falls() {
    let mut alloc = MockFrameSource::new(0x1000, 8);
    let mut space = space(&mut alloc);
    let mut table = MemoryTable::new();
    let owner = ObjectId::from_raw(1);
    let object = table
        .create(owner, 1, Placement::default(), &space, &mut alloc)
        .expect("create");

    assert_eq!(table.class_of(object), Some(MemoryClass::Unclassified));
    assert_eq!(table.classify(object, MemoryClass::Protected), Ok(()));
    assert_eq!(table.class_of(object), Some(MemoryClass::Protected));
    // Idempotent.
    assert_eq!(table.classify(object, MemoryClass::Protected), Ok(()));
    // And never down.
    assert_eq!(
        table.classify(object, MemoryClass::Unclassified),
        Err(KError::AccessDenied)
    );
    assert_eq!(table.class_of(object), Some(MemoryClass::Protected));
    table.destroy(object, &mut alloc);
    let _ = &mut space;
}

/// An id that is not a memory object is a type confusion the caller hears
/// about, rather than a classification silently applied to nothing.
#[test]
fn classifying_something_that_is_not_memory_is_refused() {
    let mut table = MemoryTable::new();
    assert_eq!(
        table.classify(ObjectId::from_raw(99), MemoryClass::Protected),
        Err(KError::WrongType)
    );
    assert_eq!(table.class_of(ObjectId::from_raw(99)), None);
}

// --- Service-backed objects: the pages a page cache is made of ---

const PAGER: ObjectId = ObjectId::from_raw(0x61);

/// The whole difference from `create`: an object exists, has a length, and
/// costs nothing. A hundred-page file must not draw a hundred frames to be
/// opened.
#[test]
fn a_paged_object_draws_no_frames_when_it_is_created() {
    let alloc = MockFrameSource::new(0x1000_0000, 64);
    let before = alloc.free_list_depth();
    let mut table = MemoryTable::new();

    let object = table.create_paged(OWNER, 8, PAGER).expect("create_paged");

    assert_eq!(alloc.free_list_depth(), before, "no frame was drawn");
    assert_eq!(table.pages_of(object), Some(8));
    assert_eq!(table.len_of(object), Some(8 * FRAME_SIZE));
    assert_eq!(table.resident_pages(object), 0);
    assert_eq!(table.pager_of(object), Some(PAGER));
}

/// A kernel-backed object has no pager and cannot be supplied — the two kinds
/// are told apart by the same field, so neither can be mistaken for the other.
#[test]
fn a_kernel_backed_object_has_no_pager_and_refuses_supply() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let space = space(&mut alloc);
    let mut table = MemoryTable::new();
    let object = table
        .create(OWNER, 2, Placement::default(), &space, &mut alloc)
        .expect("create");

    assert_eq!(table.pager_of(object), None);
    assert_eq!(table.resident_pages(object), 2, "created fully resident");
    let frame = alloc.alloc_frame().expect("frame");
    assert_eq!(
        table.supply(object, 0, frame),
        Err(KError::InvalidMapping),
        "supplying a page to memory that already has one is not a page-in"
    );
}

#[test]
fn supplying_a_page_makes_exactly_that_page_resident() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let mut table = MemoryTable::new();
    let object = table.create_paged(OWNER, 4, PAGER).expect("create_paged");
    let frame = alloc.alloc_frame().expect("frame");

    table.supply(object, 2, frame).expect("supply");

    assert_eq!(table.frame_at(object, 2), Some(frame));
    assert_eq!(table.resident_pages(object), 1);
    // The others are still absent, which is what makes the holes meaningful.
    for page in [0usize, 1, 3] {
        assert_eq!(table.frame_at(object, page), None, "page {page}");
    }
}

/// Supplying a page twice would drop the first frame's only reference on the
/// floor: the mapping goes on using it while the table forgets it exists.
#[test]
fn supplying_a_page_that_is_already_there_is_refused() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let mut table = MemoryTable::new();
    let object = table.create_paged(OWNER, 2, PAGER).expect("create_paged");
    let first = alloc.alloc_frame().expect("frame");
    let second = alloc.alloc_frame().expect("frame");
    table.supply(object, 0, first).expect("supply");

    assert_eq!(table.supply(object, 0, second), Err(KError::AlreadyMapped));
    assert_eq!(
        table.frame_at(object, 0),
        Some(first),
        "the first one stays"
    );
}

#[test]
fn supplying_past_the_end_is_refused() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let mut table = MemoryTable::new();
    let object = table.create_paged(OWNER, 2, PAGER).expect("create_paged");
    let frame = alloc.alloc_frame().expect("frame");

    assert_eq!(table.supply(object, 2, frame), Err(KError::InvalidArgument));
    assert_eq!(table.frame_at(object, 2), None);
    assert_eq!(table.resident_pages(object), 0);
}

/// Teardown has to cope with the holes: a partly-resident object returns the
/// frames it has and nothing else.
#[test]
fn destroying_a_partly_resident_object_returns_only_what_it_holds() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let mut table = MemoryTable::new();
    let object = table.create_paged(OWNER, 6, PAGER).expect("create_paged");
    for page in [0usize, 3, 5] {
        let frame = alloc.alloc_frame().expect("frame");
        table.supply(object, page, frame).expect("supply");
    }
    let before = alloc.free_list_depth();

    assert_eq!(table.destroy(object, &mut alloc), 3);
    assert_eq!(alloc.free_list_depth(), before + 3);
    assert_eq!(table.pages_of(object), None, "the object is gone");
}

/// **A dirty page is never evicted.** It holds the only copy of a write, and
/// dropping it loses that write with nothing having failed — the one thing a
/// cache must not do. Write-back is what turns a dirty page into one that can
/// be taken.
#[test]
fn a_dirty_page_is_not_evictable() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let mut table = MemoryTable::new();
    let object = table.create_paged(OWNER, 2, PAGER).expect("create_paged");
    for page in 0..2usize {
        let frame = alloc.alloc_frame().expect("frame");
        table.supply(object, page, frame).expect("supply");
    }
    table.mark_dirty(object, 0);

    // The candidate skips it and offers the clean one instead.
    assert_eq!(table.evict_candidate(object), Some(FRAME_SIZE));
    // And taking it directly is refused, which is the check that survives a
    // caller picking its own page.
    assert_eq!(table.evict(object, 0), None);
    assert!(
        table.frame_at(object, 0).is_some(),
        "the page is still there"
    );

    // Written back, it becomes takeable — the bound is on dirty pages, not on
    // pages that were ever written.
    table.mark_clean(object, 0);
    assert!(table.evict(object, 0).is_some());
    assert_eq!(table.frame_at(object, 0), None);
    assert_eq!(table.resident_pages(object), 1);
}

/// With every page dirty there is nothing to evict, and the caller has to write
/// one back first — the reclaim deadlock, stated as a `None`.
#[test]
fn an_all_dirty_object_offers_no_candidate() {
    let mut alloc = MockFrameSource::new(0x1000_0000, 64);
    let mut table = MemoryTable::new();
    let object = table.create_paged(OWNER, 2, PAGER).expect("create_paged");
    for page in 0..2usize {
        let frame = alloc.alloc_frame().expect("frame");
        table.supply(object, page, frame).expect("supply");
        table.mark_dirty(object, page as u64 * FRAME_SIZE);
    }
    assert_eq!(table.evict_candidate(object), None);
    assert_eq!(table.any_evictable(), None);
    // But it is offered for write-back, which is the way out.
    assert_eq!(table.any_dirty(), Some((object, 0)));
}
