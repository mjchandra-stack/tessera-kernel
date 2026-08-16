// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::syscall`.

use super::*;
use crate::object::{ObjectId, ObjectTable, ObjectType};
use crate::vm::{AddressSpace, Asid};
use tessera_karch::{PageFlags, PhysAddr, PhysFrame};
use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

fn user_space_with_mapping(
    base: u64,
    len: u64,
    flags: PageFlags,
) -> AddressSpace<MockAddressSpace> {
    let mut frames = MockFrameSource::new(0x40_0000, 128);
    let mut space =
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
            .expect("space");
    space
        .map_anonymous(VirtAddr::new(base), len, flags, &mut frames)
        .expect("map");
    space
}

/// Closing the last handle to a device takes its register window with it.
/// A capability can leave by being closed just as well as by being handed
/// on, and the window outlives neither.
#[test]
fn closing_the_last_device_handle_revokes_its_window() {
    let (mut process, mut objects, handle, object) = process_with_handle(Rights::READ);
    let mut frames = MockFrameSource::new(0x90_0000, 64);
    let window = VirtAddr::new(0x2000_0000);
    let frame = PhysFrame::from_base(PhysAddr::new(0x0a00_3000)).expect("mmio frame");
    process
        .space_mut()
        .map_device_page(window, frame, &mut frames)
        .expect("map device");
    process
        .record_device_window(object, window.as_u64(), 1)
        .expect("record");
    assert!(process.space().arch().translate(window).is_some());

    let mut exec = crate::exec::Executive::<MockContextOps>::new(1, 0);
    sys_handle_close(&mut process, &mut objects, &mut exec, None, None, handle).expect("close");

    assert!(
        process.space().arch().translate(window).is_none(),
        "a process kept register access after dropping its capability"
    );
    assert_eq!(process.device_window_count(), 0);
}

/// ...but only when the last one goes. A duplicate still names the device,
/// so the authority — and the window — remain.
#[test]
fn closing_one_of_two_device_handles_keeps_the_window() {
    let (mut process, mut objects, handle, object) =
        process_with_handle(Rights::READ | Rights::DUPLICATE);
    let mut frames = MockFrameSource::new(0x90_0000, 64);
    let window = VirtAddr::new(0x2000_0000);
    let frame = PhysFrame::from_base(PhysAddr::new(0x0a00_3000)).expect("mmio frame");
    process
        .space_mut()
        .map_device_page(window, frame, &mut frames)
        .expect("map device");
    process
        .record_device_window(object, window.as_u64(), 1)
        .expect("record");
    process
        .handles_mut()
        .install(object, Rights::READ)
        .expect("duplicate");

    let mut exec = crate::exec::Executive::<MockContextOps>::new(1, 0);
    sys_handle_close(&mut process, &mut objects, &mut exec, None, None, handle).expect("close");

    assert!(process.handles().holds(object));
    assert!(
        process.space().arch().translate(window).is_some(),
        "a process that still holds the capability lost its window"
    );
    assert_eq!(process.device_window_count(), 1);
}

/// Teardown needs no revocation of its own, and this pins the property it
/// relies on: a device window is **untracked**, so the whole-space teardown
/// — which walks only tracked mappings — cannot hand an MMIO frame to the
/// frame allocator. Returning device registers to the pool the kernel
/// serves anonymous memory from would be about the worst outcome available.
#[test]
fn teardown_never_returns_a_device_window_frame_to_the_allocator() {
    let mut frames = MockFrameSource::new(0x40_0000, 128);
    let mut space =
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(3))
            .expect("space");
    let window = VirtAddr::new(0x2000_0000);
    // Physical address well outside anything the allocator owns.
    let frame = PhysFrame::from_base(PhysAddr::new(0x0a00_3000)).expect("mmio frame");
    space
        .map_device_page(window, frame, &mut frames)
        .expect("map device");
    // The window is deliberately absent from the tracked mapping table.
    assert_eq!(space.mapping_count(), 0);

    let before = frames.free_list_depth();
    space.teardown(&mut frames);
    assert_eq!(
        frames.free_list_depth(),
        before,
        "teardown returned an MMIO frame to the allocator"
    );
}

fn process_with_handle(
    rights: Rights,
) -> (Process<MockAddressSpace>, ObjectTable, Handle, ObjectId) {
    let mut frames = MockFrameSource::new(0x80_0000, 64);
    let space = AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(2))
        .expect("space");
    let mut process = Process::new(ObjectId::from_raw(1), space);
    let mut objects = ObjectTable::new();
    let object = objects.create(ObjectType::Channel).expect("create");
    let handle = process
        .handles_mut()
        .insert(object, rights)
        .expect("insert");
    (process, objects, handle, object)
}

// --- error-domain encoding ---

#[test]
fn encodes_success_and_error_domains() {
    assert_eq!(encode_result(Ok(0)), 0);
    assert_eq!(encode_result(Ok(0x1234)), 0x1234);
    // AccessDenied -> security-policy domain (2), code 8.
    assert_eq!(
        encode_result(Err(KError::AccessDenied)),
        -(((ErrorDomain::SecurityPolicy as i64) << 16) | 8)
    );
    // Protocol -> protocol domain (4), code 10.
    assert_eq!(
        encode_result(Err(KError::Protocol)),
        -(((ErrorDomain::Protocol as i64) << 16) | 10)
    );
    // Errors are always negative, successes never.
    assert!(encode_result(Err(KError::OutOfMemory)) < 0);
    assert!(encode_result(Ok(u32::MAX as u64)) >= 0);
}

// --- user-range validation ---

#[test]
fn validates_user_range() {
    const BASE: u64 = 0x0000_0010_0000_0000;
    let space = user_space_with_mapping(BASE, FRAME_SIZE, PageFlags::rw().user());
    // Fully inside, read and write.
    assert!(validate_user_range(&space, BASE, 16, false).is_ok());
    assert!(validate_user_range(&space, BASE, 16, true).is_ok());
    // Zero length is trivially valid.
    assert!(validate_user_range(&space, BASE, 0, false).is_ok());
    // Unmapped just past the page.
    assert_eq!(
        validate_user_range(&space, BASE + FRAME_SIZE, 8, false),
        Err(KError::AccessDenied)
    );
    // A kernel address is never valid.
    assert_eq!(
        validate_user_range(&space, 0xffff_8000_0000_0000, 8, false),
        Err(KError::AccessDenied)
    );
}

#[test]
fn read_only_user_range_rejects_write() {
    const BASE: u64 = 0x0000_0020_0000_0000;
    let space = user_space_with_mapping(BASE, FRAME_SIZE, PageFlags::ro().user());
    assert!(validate_user_range(&space, BASE, 16, false).is_ok());
    assert_eq!(
        validate_user_range(&space, BASE, 16, true),
        Err(KError::AccessDenied)
    );
}

#[test]
fn user_range_rejects_kernel_only_mapping() {
    const BASE: u64 = 0x0000_0030_0000_0000;
    // A global (kernel) mapping is not user-accessible.
    let space = user_space_with_mapping(BASE, FRAME_SIZE, PageFlags::rw().global());
    assert_eq!(
        validate_user_range(&space, BASE, 16, false),
        Err(KError::AccessDenied)
    );
}

// --- @abi arg decode: validate before interpret ---

fn duplicate_args(
    size: u32,
    version: u32,
    flags: u64,
    source: u32,
    reserved: u32,
    rights: u64,
) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&size.to_le_bytes());
    b[4..8].copy_from_slice(&version.to_le_bytes());
    b[8..16].copy_from_slice(&flags.to_le_bytes());
    b[16..20].copy_from_slice(&source.to_le_bytes());
    b[20..24].copy_from_slice(&reserved.to_le_bytes());
    b[24..32].copy_from_slice(&rights.to_le_bytes());
    b
}

#[test]
fn decodes_valid_duplicate_args() {
    let bytes = duplicate_args(32, 1, 0, 0x0005, 0, Rights::READ.bits());
    let (handle, rights) = decode_duplicate_args(&bytes).expect("decode");
    assert_eq!(handle.raw(), 0x0005);
    assert_eq!(rights, Rights::READ);
}

#[test]
fn rejects_malformed_duplicate_args() {
    // Too short.
    assert_eq!(decode_duplicate_args(&[0u8; 8]), Err(KError::Protocol));
    // Wrong size field.
    assert_eq!(
        decode_duplicate_args(&duplicate_args(31, 1, 0, 0, 0, 0)),
        Err(KError::Protocol)
    );
    // Wrong version.
    assert_eq!(
        decode_duplicate_args(&duplicate_args(32, 2, 0, 0, 0, 0)),
        Err(KError::Protocol)
    );
    // Nonzero flags.
    assert_eq!(
        decode_duplicate_args(&duplicate_args(32, 1, 1, 0, 0, 0)),
        Err(KError::Protocol)
    );
    // Nonzero reserved padding.
    assert_eq!(
        decode_duplicate_args(&duplicate_args(32, 1, 0, 0, 0xdead, 0)),
        Err(KError::Protocol)
    );
}

// --- process-lifecycle @abi arg decode (M14) ---

#[test]
fn decodes_process_create_args() {
    let mut b = [0u8; PROCESS_CREATE_ARGS_SIZE];
    b[0..4].copy_from_slice(&(PROCESS_CREATE_ARGS_SIZE as u32).to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[16..20].copy_from_slice(&0x0007u32.to_le_bytes()); // job handle
    assert_eq!(
        decode_process_create_args(&b).expect("decode").raw(),
        0x0007
    );
    // Too short / bad header.
    assert_eq!(decode_process_create_args(&[0u8; 8]), Err(KError::Protocol));
    b[4] = 2; // version = 2
    assert_eq!(decode_process_create_args(&b), Err(KError::Protocol));
}

#[test]
fn decodes_address_space_map_args() {
    let mut b = [0u8; ADDRESS_SPACE_MAP_ARGS_SIZE];
    b[0..4].copy_from_slice(&(ADDRESS_SPACE_MAP_ARGS_SIZE as u32).to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[16..20].copy_from_slice(&0x0003u32.to_le_bytes()); // process handle
    b[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes()); // vaddr
    b[32..40].copy_from_slice(&0x1000u64.to_le_bytes()); // length
    b[40..48].copy_from_slice(&(Rights::READ.bits() | Rights::EXECUTE.bits()).to_le_bytes());
    b[48..56].copy_from_slice(&0x1000_2000u64.to_le_bytes()); // src
    let req = decode_address_space_map_args(&b).expect("decode");
    assert_eq!(req.process.raw(), 0x0003);
    assert_eq!(req.vaddr, 0x40_0000);
    assert_eq!(req.length, 0x1000);
    assert_eq!(req.rights, Rights::READ | Rights::EXECUTE);
    assert_eq!(req.src, 0x1000_2000);
    // Nonzero reserved padding is rejected.
    b[20] = 1;
    assert_eq!(decode_address_space_map_args(&b), Err(KError::Protocol));
}

#[test]
fn decodes_process_start_args() {
    let mut b = [0u8; PROCESS_START_ARGS_SIZE];
    b[0..4].copy_from_slice(&(PROCESS_START_ARGS_SIZE as u32).to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[16..20].copy_from_slice(&0x0003u32.to_le_bytes()); // process handle
    b[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes()); // entry
    b[32..40].copy_from_slice(&0x7000_0000u64.to_le_bytes()); // stack
    b[40..48].copy_from_slice(&0x2au64.to_le_bytes()); // arg
    let req = decode_process_start_args(&b).expect("decode");
    assert_eq!(req.process.raw(), 0x0003);
    assert_eq!(req.entry, 0x40_0000);
    assert_eq!(req.stack, 0x7000_0000);
    assert_eq!(req.arg, 0x2a);
    // Nonzero flags is rejected.
    b[8] = 1;
    assert_eq!(decode_process_start_args(&b), Err(KError::Protocol));
}

#[test]
fn decodes_channel_create_args() {
    let mut b = [0u8; CHANNEL_CREATE_ARGS_SIZE];
    b[0..4].copy_from_slice(&(CHANNEL_CREATE_ARGS_SIZE as u32).to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[16..24].copy_from_slice(&(Rights::READ.bits() | Rights::WRITE.bits()).to_le_bytes());
    b[24..32].copy_from_slice(&Rights::READ.bits().to_le_bytes());
    let (e0, e1) = decode_channel_create_args(&b).expect("decode");
    assert_eq!(e0, Rights::READ | Rights::WRITE);
    assert_eq!(e1, Rights::READ);
    // Too short / bad version rejected.
    assert_eq!(decode_channel_create_args(&[0u8; 8]), Err(KError::Protocol));
    b[4] = 2;
    assert_eq!(decode_channel_create_args(&b), Err(KError::Protocol));
}

#[test]
fn decodes_channel_msg_args() {
    let mut b = [0u8; CHANNEL_MSG_ARGS_SIZE];
    b[0..4].copy_from_slice(&(CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
    b[4..8].copy_from_slice(&4u32.to_le_bytes());
    b[16..24].copy_from_slice(&0xabcdu64.to_le_bytes()); // interface_id
    b[32..36].copy_from_slice(&7u32.to_le_bytes()); // method_id
    b[36..40].copy_from_slice(&0u32.to_le_bytes()); // msg_flags
    b[40..48].copy_from_slice(&0x40_0000u64.to_le_bytes()); // inline_ptr
    b[48..56].copy_from_slice(&4u64.to_le_bytes()); // inline_len
    b[56..64].copy_from_slice(&0x68_0000u64.to_le_bytes()); // handles_ptr
    b[64..72].copy_from_slice(&1u64.to_le_bytes()); // handle_count
    b[72..80].copy_from_slice(&0x70_0000u64.to_le_bytes()); // installed_ptr
    b[80..88].copy_from_slice(&2u64.to_le_bytes()); // installed_cap
    let req = decode_channel_msg_args(&b).expect("decode");
    assert_eq!(req.interface_id, 0xabcd);
    assert_eq!(req.method_id, 7);
    assert_eq!(req.msg_flags, 0);
    assert_eq!(req.inline_ptr, 0x40_0000);
    assert_eq!(req.inline_len, 4);
    assert_eq!(req.handles_ptr, 0x68_0000);
    assert_eq!(req.handle_count, 1);
    assert_eq!(req.installed_ptr, 0x70_0000);
    assert_eq!(req.installed_cap, 2);
    // Too short / bad size / nonzero flags rejected.
    assert_eq!(decode_channel_msg_args(&[0u8; 8]), Err(KError::Protocol));
    b[0] = 0x49; // size = 73
    assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
    b[0] = 0x48;
    b[8] = 1; // nonzero flags
    assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
    // A version-2 producer is the same 88 bytes and differs only in what
    // `handles_ptr` addresses, so nothing but this check tells the two
    // apart — accepting one would read bare u32 handle values as 16-byte
    // transfer descriptors.
    b[8] = 0;
    b[4] = 2;
    assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
    // Version 3 is refused too, even though every v3 descriptor is a
    // byte-identical v4 one today. What is identical is this kernel's mode
    // numbering, not the format — and a gate that opens once a version is
    // "compatible enough" is a gate that has to be re-argued every time
    // the mode set grows.
    b[4] = 3;
    assert_eq!(decode_channel_msg_args(&b), Err(KError::Protocol));
}

#[test]
fn decodes_a_handle_transfer_descriptor() {
    let mut b = [0u8; HANDLE_TRANSFER_SIZE];
    b[0..4].copy_from_slice(&5u32.to_le_bytes()); // handle
    b[8..16].copy_from_slice(&(Rights::READ | Rights::MAP).bits().to_le_bytes());
    let d = decode_handle_transfer(&b).expect("decode");
    assert_eq!(d.handle, 5);
    assert_eq!(d.rights, Rights::READ | Rights::MAP);

    // The rights word is 64 bits wide, so the rights above bit 31 survive
    // the trip — a 32-bit field would have dropped them silently.
    b[8..16].copy_from_slice(&Rights::REVOKE.bits().to_le_bytes());
    assert_eq!(
        decode_handle_transfer(&b).expect("decode").rights,
        Rights::REVOKE
    );

    // Share is a mode the ABI defines and this kernel has not built, so
    // it is `NotSupported` — a different fact from a malformed descriptor,
    // and one that leads somewhere different.
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(decode_handle_transfer(&b), Err(KError::NotSupported));

    // A mode nobody has defined is a misparse, not a feature request.
    b[4..8].copy_from_slice(&9u32.to_le_bytes());
    assert_eq!(decode_handle_transfer(&b), Err(KError::Protocol));
    b[4..8].copy_from_slice(&0u32.to_le_bytes());

    // A short buffer is a protocol error, never a partial read.
    assert_eq!(decode_handle_transfer(&[0u8; 8]), Err(KError::Protocol));
}

// --- device @abi arg decode (D79) ---

fn device_args(size: u32, version: u32, flags: u64, handle: u32, vaddr: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&size.to_le_bytes());
    b[4..8].copy_from_slice(&version.to_le_bytes());
    b[8..16].copy_from_slice(&flags.to_le_bytes());
    b[16..20].copy_from_slice(&handle.to_le_bytes());
    b[24..32].copy_from_slice(&vaddr.to_le_bytes());
    b
}

#[test]
fn decodes_map_device_args() {
    let b = device_args(32, 1, 0, 5, 0x0000_1000_0040_0000);
    let req = decode_map_device_args(&b).expect("decode");
    assert_eq!(req.device.raw(), 5);
    assert_eq!(req.vaddr, 0x0000_1000_0040_0000);
    // Too short / bad size / bad version / nonzero flags / nonzero reserved.
    assert_eq!(decode_map_device_args(&[0u8; 8]), Err(KError::Protocol));
    assert_eq!(
        decode_map_device_args(&device_args(31, 1, 0, 5, 0)),
        Err(KError::Protocol)
    );
    assert_eq!(
        decode_map_device_args(&device_args(32, 2, 0, 5, 0)),
        Err(KError::Protocol)
    );
    assert_eq!(
        decode_map_device_args(&device_args(32, 1, 1, 5, 0)),
        Err(KError::Protocol)
    );
    let mut bad = device_args(32, 1, 0, 5, 0);
    bad[20] = 1; // nonzero reserved
    assert_eq!(decode_map_device_args(&bad), Err(KError::Protocol));
}

#[test]
fn decodes_dma_alloc_args() {
    let b = device_args(32, 1, 0, 0, 0x0000_1000_0050_0000);
    let req = decode_dma_alloc_args(&b).expect("decode");
    assert_eq!(req.device.raw(), 0);
    assert_eq!(req.vaddr, 0x0000_1000_0050_0000);
    assert_eq!(decode_dma_alloc_args(&[0u8; 8]), Err(KError::Protocol));
    assert_eq!(
        decode_dma_alloc_args(&device_args(32, 2, 0, 0, 0)),
        Err(KError::Protocol)
    );
    let mut bad = device_args(32, 1, 0, 0, 0);
    bad[20] = 1; // nonzero reserved
    assert_eq!(decode_dma_alloc_args(&bad), Err(KError::Protocol));
}

#[test]
fn decodes_irq_complete_args() {
    let mut b = [0u8; IRQ_COMPLETE_ARGS_SIZE];
    b[0..4].copy_from_slice(&(IRQ_COMPLETE_ARGS_SIZE as u32).to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[16..20].copy_from_slice(&0u32.to_le_bytes()); // device handle 0
    assert_eq!(decode_irq_complete_args(&b).expect("decode").raw(), 0);
    assert_eq!(decode_irq_complete_args(&[0u8; 8]), Err(KError::Protocol));
    b[4] = 2; // version = 2
    assert_eq!(decode_irq_complete_args(&b), Err(KError::Protocol));
    b[4] = 1;
    b[20] = 1; // nonzero reserved
    assert_eq!(decode_irq_complete_args(&b), Err(KError::Protocol));
}

// --- handle-op dispatch outcomes ---

#[test]
fn duplicate_narrows_and_rejects_expansion() {
    let (mut process, mut objects, handle, object) =
        process_with_handle(Rights::READ | Rights::WRITE | Rights::DUPLICATE);
    // Narrowing succeeds and adds a reference.
    let new_raw =
        sys_handle_duplicate(&mut process, &mut objects, handle, Rights::READ).expect("duplicate");
    assert_eq!(objects.refcount(object), Some(2));
    // The new handle carries exactly the narrowed rights.
    let new = Handle::from_raw(new_raw as u32);
    assert_eq!(
        sys_handle_query_rights(&process, new).expect("query"),
        Rights::READ.bits()
    );
    // Expansion is rejected (AccessDenied), reference count unchanged.
    assert_eq!(
        sys_handle_duplicate(&mut process, &mut objects, handle, Rights::ADMIN),
        Err(KError::AccessDenied)
    );
    assert_eq!(objects.refcount(object), Some(2));
}

#[test]
fn close_drops_reference_and_reports_destruction() {
    let (mut process, mut objects, handle, object) = process_with_handle(Rights::READ);
    // Only reference: closing destroys the object.
    let mut exec = crate::exec::Executive::<MockContextOps>::new(1, 0);
    assert_eq!(
        sys_handle_close(&mut process, &mut objects, &mut exec, None, None, handle),
        Ok(1)
    );
    assert!(!objects.is_live(object));
    // A stale handle no longer resolves.
    assert_eq!(
        sys_handle_query_rights(&process, handle),
        Err(KError::BadHandle)
    );
}
