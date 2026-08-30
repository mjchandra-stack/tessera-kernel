// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::dispatch`.

use super::*;
use crate::isl_binding::port::PortEventRecord;
use crate::object::ObjectId;
use crate::process::Process;
use crate::thread::Thread;
use crate::vm::{AddressSpace, Asid};
use std::boxed::Box;
use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

extern "C" fn never(_: usize) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// A page-aligned host buffer standing in for the caller's user memory:
/// its host address is below the mock `USER_ADDRESS_MAX`, so mapping the
/// same VA range in the mock space makes `validate_user_range` accept it
/// and the raw copy read/write the real bytes.
#[repr(align(4096))]
struct UserPage([u8; 4096]);

// Boxed: a `ProcessTable` is ~16 × (`HandleTable` + space bookkeeping) —
// hundreds of kilobytes the kernel keeps in a static, far too large for a
// test-thread stack once move copies pile up in a debug build.
struct Harness {
    exec: Box<Executive<MockContextOps>>,
    processes: Box<ProcessTable<MockAddressSpace>>,
    frames: MockFrameSource,
    caller: crate::thread::ThreadId,
    /// The port's IOMMU, absent unless a test installs one — the state of
    /// four of the five ports.
    iommu: Option<MockMapper>,
    /// The port's interrupt controller, absent unless a test installs one.
    irqs: Option<MockRouter>,
}

/// An interrupt-controller stand-in, recording every line it was told to
/// stop delivering. A test cannot otherwise tell a route the graph merely
/// forgot from one that was actually masked — which is the whole
/// difference between revocation and bookkeeping.
#[derive(Default)]
struct MockRouter {
    masked: std::vec::Vec<u32>,
}

impl crate::devmgr::InterruptRouter for MockRouter {
    fn mask(&mut self, intid: u32) {
        self.masked.push(intid);
    }
}

/// An IOMMU stand-in: it records what it was asked to install and every
/// lease it began or ended, which is the only way a test can tell an IOVA
/// that was *installed* from a number that merely came back, or a lease
/// that was *torn down* from one the graph merely forgot.
#[derive(Default)]
struct MockMapper {
    installed: std::vec::Vec<(ObjectId, u64, u64, u64)>,
    /// Ranges the mapper was told to stop translating, so a test can see
    /// that a detach reached the hardware rather than only the record.
    removed: std::vec::Vec<(ObjectId, u64, u64)>,
    began: std::vec::Vec<ObjectId>,
    ended: std::vec::Vec<ObjectId>,
    /// Devices this unit is in front of. Empty means an IOMMU that exists
    /// but has nothing behind it — every grant is honestly unscoped.
    behind: std::vec::Vec<ObjectId>,
    /// The range a lease gets, so a test can size exhaustion.
    window: (u64, u64),
    /// A mapper that refuses — hardware whose tables cannot describe the
    /// range, which must not become a physical address handed back.
    refuses: bool,
}

impl MockMapper {
    fn over(device: ObjectId, base: u64, len: u64) -> Self {
        Self {
            behind: std::vec![device],
            window: (base, len),
            ..Self::default()
        }
    }
}

impl DmaMapper for MockMapper {
    fn translates(&self, device: ObjectId) -> bool {
        self.behind.contains(&device)
    }

    fn begin_lease(&mut self, device: ObjectId) -> Result<(u64, u64), KError> {
        if self.refuses {
            return Err(KError::InvalidMapping);
        }
        self.began.push(device);
        Ok(self.window)
    }

    fn map(&mut self, device: ObjectId, iova: u64, phys: u64, len: u64) -> Result<(), KError> {
        if self.refuses {
            return Err(KError::InvalidMapping);
        }
        self.installed.push((device, iova, phys, len));
        Ok(())
    }

    fn unmap(&mut self, device: ObjectId, iova: u64, len: u64) -> Result<(), KError> {
        if self.refuses {
            return Err(KError::InvalidMapping);
        }
        self.removed.push((device, iova, len));
        Ok(())
    }

    fn end_lease(&mut self, device: ObjectId) {
        self.ended.push(device);
        self.installed.retain(|(d, ..)| *d != device);
    }
}

/// One running thread whose process owns `handle 0` on `device_obj` with
/// `rights`, its space mapping the user page at `upage`'s host address.
fn harness(upage: &UserPage, rights: Rights) -> Harness {
    let mut frames = MockFrameSource::new(0x1000_0000, 256);
    let mut exec = Box::new(Executive::<MockContextOps>::new(4, 0, test_clock));
    let device_obj = ObjectId::from_raw(21);
    exec.device_register_mmio(
        device_obj,
        0x0a00_3e00,
        FRAME_SIZE,
        Rights::READ | Rights::MAP | Rights::TRANSFER,
    )
    .expect("register mmio");

    let mut space =
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
            .expect("space");
    let uva = upage.0.as_ptr() as u64;
    assert!(uva + FRAME_SIZE <= MockAddressSpace::USER_ADDRESS_MAX);
    space
        .map_anonymous(
            VirtAddr::new(uva),
            FRAME_SIZE,
            PageFlags::rw().user(),
            &mut frames,
        )
        .expect("map user page");

    let thread = Thread::<MockContextOps>::spawn(
        never,
        0,
        VirtAddr::new(0xffff_e000_0000_0000),
        2,
        &mut space,
        &mut frames,
    )
    .expect("thread");
    let caller_slot = exec.add_thread(thread).expect("add thread");
    let caller = exec
        .scheduler()
        .thread_id(caller_slot)
        .expect("the thread just admitted has an identity");
    exec.run();

    let mut processes = Box::new(ProcessTable::<MockAddressSpace>::new());
    let mut process = Process::new(device_obj, space);
    process.add_thread(caller).expect("own thread");
    process
        .handles_mut()
        .install(device_obj, rights)
        .expect("install");
    processes.insert(process).expect("insert");

    Harness {
        exec,
        processes,
        frames,
        caller,
        iommu: None,
        irqs: None,
    }
}

fn run(h: &mut Harness, number: SyscallNumber, args: [u64; 6]) -> DispatchOutcome {
    let req = SyscallRequest {
        number: number as u64,
        args,
    };
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper),
        irqs: h
            .irqs
            .as_mut()
            .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
    };
    dispatch(&mut env, &req)
}

/// The object id `harness` registers its device under — what the
/// event-reading tests filter on, so records emitted concurrently by other
/// tests cannot be mistaken for theirs.
const HARNESS_DEVICE: u64 = 21;

/// Serializes the tests that *read* the global event ring. Concurrent
/// emission is harmless (every assertion filters by device object), but a
/// concurrent drain would steal the records under test.
static EVENT_RING: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn blank_event() -> crate::event::KernelEvent {
    crate::event::record(
        crate::event::EventKind::EventsDropped,
        crate::event::Severity::Debug,
        crate::event::Component::Observability,
        0,
        crate::trace::TraceContext::NONE,
        [0; 4],
    )
}

/// Takes the ring lock and drains what is already buffered, so the ring has
/// room for the records the test is about to cause — a full ring drops at
/// the source, and an assertion on a dropped record would fail for a reason
/// that has nothing to do with the code under test.
fn event_ring_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = EVENT_RING.lock().unwrap_or_else(|e| e.into_inner());
    let mut sink = [blank_event(); crate::event::EVENT_RING_CAPACITY];
    while crate::event::drain(&mut sink) > 0 {}
    guard
}

/// Every buffered record naming the harness device, in emission order.
fn drained_device_events() -> std::vec::Vec<crate::event::KernelEvent> {
    let mut sink = [blank_event(); crate::event::EVENT_RING_CAPACITY];
    let n = crate::event::drain(&mut sink);
    sink[..n]
        .iter()
        .filter(|e| e.component == crate::event::Component::Driver && e.arg0 == HARNESS_DEVICE)
        .copied()
        .collect()
}

/// Every buffered record the pager emitted, in emission order.
fn drained_pager_events() -> std::vec::Vec<crate::event::KernelEvent> {
    let mut sink = [blank_event(); crate::event::EVENT_RING_CAPACITY];
    let n = crate::event::drain(&mut sink);
    sink[..n]
        .iter()
        .filter(|e| e.component == crate::event::Component::Pager)
        .copied()
        .collect()
}

/// Writes a `HandleTransfer` descriptor into the user page at offset 2048 —
/// the transfer vector the message-building tests point `handles_ptr` at.
/// `rights` is what the capability is to *arrive* with.
fn write_transfer(upage: &mut UserPage, handle: u32, rights: Rights) -> u64 {
    let at = 2048;
    upage.0[at..at + syscall::HANDLE_TRANSFER_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&handle.to_le_bytes());
    upage.0[at + 8..at + 16].copy_from_slice(&rights.bits().to_le_bytes());
    upage.0.as_ptr() as u64 + at as u64
}

fn device_args(upage: &mut UserPage, handle: u32, vaddr: u64) -> u64 {
    upage.0[0..4].copy_from_slice(&32u32.to_le_bytes());
    upage.0[4..8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[8..16].copy_from_slice(&0u64.to_le_bytes());
    upage.0[16..20].copy_from_slice(&handle.to_le_bytes());
    upage.0[20..24].copy_from_slice(&0u32.to_le_bytes());
    upage.0[24..32].copy_from_slice(&vaddr.to_le_bytes());
    upage.0.as_ptr() as u64
}

#[test]
fn null_returns_zero_and_unknown_is_unhandled() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    assert_eq!(
        run(&mut h, SyscallNumber::Null, [0; 6]),
        DispatchOutcome::Return(0)
    );
    let req = SyscallRequest {
        number: 0xffff,
        args: [0; 6],
    };
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(dispatch(&mut env, &req), DispatchOutcome::Unhandled);
}

#[test]
fn port_divergent_arms_are_unhandled() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ);
    assert_eq!(
        run(&mut h, SyscallNumber::DebugWrite, [0; 6]),
        DispatchOutcome::Unhandled
    );
    assert_eq!(
        run(&mut h, SyscallNumber::ProcessExit, [0; 6]),
        DispatchOutcome::Unhandled
    );
}

#[test]
fn map_device_maps_the_containing_page_and_returns_the_offset_va() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let outcome = run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
    // The registered window sits at 0x0a00_3e00 — intra-page offset 0xe00.
    assert_eq!(outcome, DispatchOutcome::Return(0x4000_0e00));
    // The device page is mapped in the arch space but untracked.
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4000_0000))
            .is_some()
    );
    assert_eq!(process.space().rights_at(VirtAddr::new(0x4000_0000)), None);
}

/// Registers the harness device over a different region, for the tests
/// that care how big a window is rather than who holds it.
fn rewindow(h: &mut Harness, base: u64, len: u64) {
    h.exec
        .device_register_mmio(
            ObjectId::from_raw(0x5a),
            base,
            len,
            Rights::READ | Rights::MAP,
        )
        .expect("register");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    process
        .handles_mut()
        .install(ObjectId::from_raw(0x5a), Rights::READ | Rights::MAP)
        .expect("install");
}

/// A window is not a page. A PCI BAR spans several, and a driver handed
/// only the first page of its own device reaches a quarter of it — which is
/// exactly what blocked the ring-3 virtio-pci driver.
#[test]
fn map_device_maps_every_page_of_a_multi_page_window() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);
    let handle = 1; // the second handle this process was given
    let args_ptr = device_args(&mut upage, handle, 0x4100_0000);

    assert_eq!(
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(0x4100_0000)))
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    for page in 0..4 {
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4100_0000 + page * FRAME_SIZE))
                .is_some(),
            "page {page} of the window is not mapped",
        );
    }
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4100_0000 + 4 * FRAME_SIZE))
            .is_none(),
        "and the window stops where it ends",
    );
    // One record for the window, not one per page — see the event summary.
    assert_eq!(process.device_window_count(), 1);
}

/// Builds a `LifecycleTransitionArgs` in the user page.
fn lifecycle_args(
    upage: &mut UserPage,
    handle: u32,
    from: crate::lifecycle::DriverState,
    to: crate::lifecycle::DriverState,
) -> u64 {
    let at = 384;
    let args = crate::isl_binding::lifecycle::LifecycleTransitionArgs {
        size: syscall::LIFECYCLE_TRANSITION_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        device: tessera_isl_runtime::HandleRef::new(handle),
        from,
        to,
        reason: crate::lifecycle::TransitionReason::Enumerated,
        detail: 0xbeef,
    };
    tessera_isl_runtime::encode(
        &args,
        &mut upage.0[at..at + syscall::LIFECYCLE_TRANSITION_ARGS_SIZE],
    )
    .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// A manager declares a transition for a device it holds, and the kernel
/// records it — the syscall that makes `docs/drivers/01`'s "transitions
/// are observable through structured events" true rather than aspirational.
#[test]
fn a_held_devices_lifecycle_transition_is_recorded() {
    use crate::lifecycle::DriverState::*;
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    let args = lifecycle_args(&mut upage, 0, Discovered, Matched);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DriverLifecycle,
            [args, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0),
    );
    assert_eq!(h.exec.lifecycle_of_object(device), Some(Matched));

    let events = drained_device_events();
    let record = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DriverLifecycleTransition)
        .expect("the transition was not recorded");
    assert_eq!(record.arg0, HARNESS_DEVICE, "the device");
    assert_eq!(record.arg1, Discovered as u64);
    assert_eq!(record.arg2, Matched as u64);
    // The manager's uninterpreted detail rides in the envelope's flags.
    assert_eq!(record.flags, 0xbeef);
}

/// A process that does not hold the device cannot narrate its lifecycle.
/// Without `Rights::MAP` a bystander could write a plausible history for
/// hardware it has only heard of, and nothing downstream could tell.
#[test]
fn a_lifecycle_transition_needs_the_device_authority() {
    use crate::lifecycle::DriverState::*;
    let mut upage = UserPage([0; 4096]);
    // READ only: enough to name the device, not enough to speak for it.
    let mut h = harness(&upage, Rights::READ);
    let args = lifecycle_args(&mut upage, 0, Discovered, Matched);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DriverLifecycle,
            [args, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
    assert_eq!(
        h.exec
            .lifecycle_of_object(ObjectId::from_raw(HARNESS_DEVICE as u32)),
        None,
        "and nothing was recorded",
    );
    let _ = drained_device_events();
}

/// A transition the table does not contain is refused, and the recorded
/// state is unchanged — the difference between a record stream and a
/// sequence.
#[test]
fn an_inconsistent_lifecycle_transition_is_refused() {
    use crate::lifecycle::DriverState::*;
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    let open = lifecycle_args(&mut upage, 0, Discovered, Matched);
    run(
        &mut h,
        SyscallNumber::DriverLifecycle,
        [open, 0, 0, 0, 0, 0],
    );

    // Matched -> Active skips Starting and Probing: a legal-looking claim
    // that could not have happened.
    let skip = lifecycle_args(&mut upage, 0, Matched, Active);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DriverLifecycle,
            [skip, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::Protocol))),
    );
    assert_eq!(h.exec.lifecycle_of_object(device), Some(Matched));

    // And so is a transition from a state the device is not in.
    let stale = lifecycle_args(&mut upage, 0, Active, Degraded);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DriverLifecycle,
            [stale, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::Protocol))),
    );
    assert_eq!(h.exec.lifecycle_of_object(device), Some(Matched));

    let events = drained_device_events();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.kind == crate::event::EventKind::DriverLifecycleTransition)
            .count(),
        1,
        "only the one that was accepted",
    );
}

/// A receiver learns which method it was called with.
///
/// Before this the kernel carried `method_id` in the header and dropped it
/// on delivery, which was invisible while every service here had exactly
/// one method — a block driver could only be a block *reader*, because
/// reading was the only thing a request could mean. A class contract has
/// several methods, and "which one" is the first thing a server needs.
#[test]
fn a_receive_reports_the_method_the_message_named() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(51);
    h.exec.bind_endpoint_object(b, ep_obj);
    let handle = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .handles_mut()
        .install(ep_obj, Rights::READ)
        .expect("install");
    let mut message = Message::new(MessageHeader::new(0x99, 7));
    message.set_inline(&[1, 2, 3, 4]).expect("inline");
    h.exec.send(a, message).expect("queued");

    // A descriptor naming method 0 — the value every caller writes when it
    // is not sending.
    let base = upage.0.as_ptr() as u64;
    let args_at = 512usize;
    {
        let args = &mut upage.0[args_at..args_at + syscall::CHANNEL_MSG_ARGS_SIZE];
        args.fill(0);
        args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
        args[4..8].copy_from_slice(&4u32.to_le_bytes());
        args[40..48].copy_from_slice(&(base + 1024).to_le_bytes()); // inline_ptr
        args[48..56].copy_from_slice(&64u64.to_le_bytes()); // inline_len
    }
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecv,
            [base + args_at as u64, u64::from(handle.raw()), 0, 0, 0, 0],
        ),
        DispatchOutcome::Return(4),
    );

    // The descriptor now names the method that arrived, written in place.
    let at = args_at + syscall::CHANNEL_MSG_METHOD_ID_OFFSET as usize;
    assert_eq!(
        u32::from_le_bytes([
            upage.0[at],
            upage.0[at + 1],
            upage.0[at + 2],
            upage.0[at + 3]
        ]),
        7,
    );
}

/// Builds a `MemoryCreateArgs` in the user page and returns its pointer.
fn memory_create_args(upage: &mut UserPage, bytes: u64) -> u64 {
    memory_create_args_placed(upage, bytes, 0, 0)
}

/// The same, with placement constraints.
fn memory_create_args_placed(
    upage: &mut UserPage,
    bytes: u64,
    constraints: u32,
    alignment: u64,
) -> u64 {
    let at = 640;
    let args = crate::isl_binding::memory::MemoryCreateArgs {
        size: syscall::MEMORY_CREATE_ARGS_SIZE as u32,
        version: 2,
        flags: 0,
        bytes,
        constraints: crate::isl_binding::memory::MemoryConstraint(constraints),
        alignment,
        address_limit: 0,
    };
    tessera_isl_runtime::encode(
        &args,
        &mut upage.0[at..at + syscall::MEMORY_CREATE_ARGS_SIZE],
    )
    .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// Builds a `MemoryMapArgs` in the user page and returns its pointer.
fn memory_map_args(upage: &mut UserPage, handle: u32, vaddr: u64, rights: u32) -> u64 {
    let at = 704;
    let args = crate::isl_binding::memory::MemoryMapArgs {
        size: syscall::MEMORY_MAP_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        memory: tessera_isl_runtime::HandleRef::new(handle),
        rights: crate::isl_binding::memory::MapRights(rights),
        vaddr,
    };
    tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::MEMORY_MAP_ARGS_SIZE])
        .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// A VA well clear of the harness's user page and device windows.
const GRANT_VA: u64 = 0x5000_0000;
const MAP_RW: u32 = 0x1 | 0x2;

/// Create, then map: the caller gets pages it can write, and the object
/// knows who owns them.
#[test]
fn a_created_memory_object_maps_into_its_creator() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let args = memory_create_args(&mut upage, FRAME_SIZE);
    let handle = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };

    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(GRANT_VA as i64),
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA))
            .is_some(),
        "the page is mapped",
    );
    assert_eq!(process.memory_mapping_count(), 1);
    // And the kernel can copy into it, which is what makes it usable as a
    // payload buffer rather than only as ring-3 memory.
    assert!(syscall::validate_user_range(process.space(), GRANT_VA, FRAME_SIZE, true).is_ok(),);
}

/// A length above the per-object ceiling is **refused, not clamped**. A
/// caller handed a smaller object than it asked for would overrun it and
/// find out by faulting somewhere unrelated.
#[test]
fn an_oversized_object_is_refused_rather_than_trimmed() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let too_big = (crate::memory::MAX_OBJECT_PAGES as u64 + 1) * FRAME_SIZE;
    let args = memory_create_args(&mut upage, too_big);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::LimitExceeded))),
    );
    // And zero is not a request for nothing, it is a request that cannot
    // be honoured.
    let args = memory_create_args(&mut upage, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping))),
    );
}

/// **Mapping rights are checked against the capability, never silently
/// reduced to it.** A caller that asked for write on a read-only grant and
/// got a read-only mapping would discover the truth by faulting in the
/// middle of a write it believed had succeeded.
#[test]
fn a_mapping_cannot_carry_authority_the_capability_lacks() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let args = memory_create_args(&mut upage, FRAME_SIZE);
    let handle = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    // Narrow the capability to read-only, then ask for a writable mapping.
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .replace_rights(
                crate::handle::Handle::from_raw(handle),
                Rights::READ | Rights::MAP,
            )
            .expect("narrow");
    }
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
    // Read-only is granted, because that the capability does carry.
    let args = memory_map_args(&mut upage, handle, GRANT_VA, 0x1);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(GRANT_VA as i64),
    );
}

/// A handle that is not a memory object is a type confusion the caller
/// should hear about, not a mapping of whatever happens to be nearby.
#[test]
fn mapping_something_that_is_not_a_memory_object_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // Handle 0 is the harness's *device*, which carries READ | MAP — so
    // a read-only request clears the authority checks and reaches the
    // question this is about: it is not a memory object.
    let args = memory_map_args(&mut upage, 0, GRANT_VA, 0x1);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType))),
    );
}

/// **The sentence the mode is named for.** `docs/kernel/04`: *"ownership
/// moves; the sender's handle and mappings are gone on send, so post-send
/// mutation is impossible by construction."* Without the revocation the
/// receiver would be validating a buffer the sender can still rewrite —
/// a time-of-check race by construction rather than by accident.
#[test]
fn transferring_a_buffer_takes_the_senders_mapping_with_it() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let args = memory_create_args(&mut upage, FRAME_SIZE);
    let handle = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]);

    // Hand it on.
    let handles_ptr = write_transfer(
        &mut upage,
        handle,
        Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
    );
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let (_msg, departed) =
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: None,
            irqs: None,
        };
        end_bindings_of_departed(&mut env, &departed);
    }

    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA))
            .is_none(),
        "the sender's page is gone",
    );
    assert_eq!(process.memory_mapping_count(), 0, "and so is the record");
    // The kernel will not copy through the revoked range either — the
    // property a stale tracked record would silently destroy.
    assert!(syscall::validate_user_range(process.space(), GRANT_VA, FRAME_SIZE, false).is_err(),);
}

/// A capability's departure takes the **whole** window with it. Unmapping
/// only the first page would leave a driver reading registers it no longer
/// holds the capability for.
#[test]
fn revocation_unmaps_every_page_of_a_multi_page_window() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);
    let args_ptr = device_args(&mut upage, 1, 0x4100_0000);
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = crate::handle::Handle::from_raw(1);
    let mut objects = crate::object::ObjectTable::new();
    let _ = process.handles_mut().close(&mut objects, handle);
    process.revoke_device_windows_unless_held(
        ObjectId::from_raw(0x5a),
        crate::process::WindowRevokeReason::HandleClosed,
    );

    for page in 0..4 {
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4100_0000 + page * FRAME_SIZE))
                .is_none(),
            "page {page} survived the revocation",
        );
    }
    assert_eq!(process.device_window_count(), 0);
}

/// A window that collides part-way through rolls back to nothing.
///
/// Device pages are deliberately untracked, so the space's overlap check is
/// blind to them and a collision is only discovered when the arch layer
/// refuses the page — part-way in. A half-installed window is worse than
/// none: the caller is told it has no mapping while some pages are live,
/// and the window record does not describe them.
#[test]
fn a_window_that_collides_part_way_leaves_nothing_behind() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);

    // Something already occupies the third page of where the window goes.
    {
        let Harness {
            processes,
            frames,
            caller,
            ..
        } = &mut h;
        let process = processes.process_of_thread(*caller).expect("process");
        process
            .space_mut()
            .map_anonymous(
                VirtAddr::new(0x4100_2000),
                FRAME_SIZE,
                PageFlags::rw().user(),
                frames,
            )
            .expect("occupy");
    }

    let args_ptr = device_args(&mut upage, 1, 0x4100_0000);
    assert_eq!(
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AlreadyMapped)))
    );

    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert_eq!(process.device_window_count(), 0, "the record is gone");
    for page in [0u64, 1] {
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(0x4100_0000 + page * FRAME_SIZE))
                .is_none(),
            "page {page} was installed before the collision and stayed",
        );
    }
    // The occupant is untouched — the rollback took back only its own.
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4100_2000))
            .is_some(),
    );
}

/// A window larger than the kernel will grant is **refused**, not
/// truncated. A driver given part of its device would find out by faulting
/// somewhere it had no reason to expect.
#[test]
fn an_oversized_window_is_refused_rather_than_truncated() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    rewindow(&mut h, 0x0b00_0000, MAX_DEVICE_WINDOW_BYTES + FRAME_SIZE);
    let args_ptr = device_args(&mut upage, 1, 0x4100_0000);

    assert_eq!(
        run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::LimitExceeded)))
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert_eq!(process.device_window_count(), 0, "and nothing was recorded");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4100_0000))
            .is_none(),
        "and nothing was mapped",
    );
}

/// **One record per grant, whatever the window's size.** The event summary
/// reads a device granted twice as a rebind; a four-page window counted
/// once per page would make a single mapping look like four, and the
/// driver-rebind check would pass on evidence that never happened.
#[test]
fn a_multi_page_window_is_one_grant_record_carrying_its_length() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    rewindow(&mut h, 0x0b00_0000, 4 * FRAME_SIZE);
    let args_ptr = device_args(&mut upage, 1, 0x4100_0000);

    let _guard = event_ring_guard();
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    let mut sink = [blank_event(); crate::event::EVENT_RING_CAPACITY];
    let n = crate::event::drain(&mut sink);
    let grants: std::vec::Vec<_> = sink[..n]
        .iter()
        .filter(|e| e.kind == crate::event::EventKind::DeviceWindowMapped && e.arg0 == 0x5a)
        .collect();
    assert_eq!(grants.len(), 1, "one grant, not one per page");
    assert_eq!(grants[0].arg3, 4 * FRAME_SIZE, "carrying the real length");
}

#[test]
fn map_device_records_a_window_so_the_grant_can_be_revoked() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert_eq!(process.device_window_count(), 0);

    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert_eq!(process.device_window_count(), 1);
}

/// Narrowing, through the syscall path a ring-3 sender actually uses: the
/// descriptor names fewer rights than the sender holds, and the message
/// carries exactly those.
#[test]
fn a_transfer_descriptor_narrows_the_rights_that_travel() {
    let mut upage = UserPage([0; 4096]);
    // The sender holds READ|MAP|TRANSFER and grants only READ|MAP — the
    // capability arrives unable to be handed on.
    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);

    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let message =
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
    let transferred = message.0.handles().next().expect("one handle");
    assert_eq!(transferred.rights, Rights::READ | Rights::MAP);
    assert!(!transferred.rights.contains(Rights::TRANSFER));
}

/// A sender cannot mint authority it does not have by asking for it on the
/// way out, and a refused transfer leaves the handle where it was.
#[test]
fn a_transfer_descriptor_cannot_widen_rights() {
    let mut upage = UserPage([0; 4096]);
    let handles_ptr = write_transfer(
        &mut upage,
        0,
        Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::WRITE,
    );
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);

    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    assert_eq!(
        build_message_from_args(&mut h.processes, h.caller, &args, true).err(),
        Some(KError::AccessDenied)
    );
    // The capability did not move.
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(process.handles().rights(Handle::from_raw(0)).is_ok());
}

/// A reserved field with something in it describes a wire format this
/// kernel does not implement, so the message is refused rather than
/// decoded around.
/// Builds a `DmaAttachArgs` in the user page and returns its pointer.
fn attach_args(upage: &mut UserPage, device: u32, memory: u32) -> u64 {
    let at = 768;
    let args = crate::isl_binding::memory::DmaAttachArgs {
        size: syscall::DMA_ATTACH_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        device: tessera_isl_runtime::HandleRef::new(device),
        memory: tessera_isl_runtime::HandleRef::new(memory),
    };
    tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::DMA_ATTACH_ARGS_SIZE])
        .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// Builds a `DmaDetachArgs` in the user page and returns its pointer.
fn detach_args(upage: &mut UserPage, memory: u32) -> u64 {
    let at = 832;
    let args = crate::isl_binding::memory::DmaDetachArgs {
        size: syscall::DMA_DETACH_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        memory: tessera_isl_runtime::HandleRef::new(memory),
        reserved: 0,
    };
    tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::DMA_DETACH_ARGS_SIZE])
        .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// Creates a one-page object and returns its handle.
fn make_object(h: &mut Harness, upage: &mut UserPage) -> u32 {
    let args = memory_create_args(upage, FRAME_SIZE);
    match run(h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    }
}

/// **The milestone's sentence.** A device reaches a buffer the driver
/// never allocated and never mapped, at an address the IOMMU translates —
/// which is what lets a full-sector transfer happen without a CPU copy.
#[test]
fn a_memory_object_becomes_reachable_by_a_device_at_a_translated_address() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);

    let args = attach_args(&mut upage, 0, memory);
    let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u64,
        other => panic!("attach failed: {other:?}"),
    };
    // The address is the device's, not the memory's: translating is
    // precisely the difference between the two.
    let mapper = h.iommu.as_ref().expect("iommu");
    assert_eq!(mapper.installed.len(), 1);
    let (device, iova, phys, len) = mapper.installed[0];
    assert_eq!(device, ObjectId::from_raw(21));
    assert_eq!(iova, address);
    assert_eq!(len, FRAME_SIZE);
    assert_ne!(
        iova, phys,
        "an IOVA that equalled the phys translates nothing"
    );
}

/// Detach unmaps exactly what attach mapped, and the record goes with it.
#[test]
fn detaching_stops_the_device_reaching_it() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    let args = attach_args(&mut upage, 0, memory);
    let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u64,
        other => panic!("attach failed: {other:?}"),
    };

    let args = detach_args(&mut upage, memory);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaDetach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").removed,
        std::vec![(ObjectId::from_raw(21), address, FRAME_SIZE)],
    );
    // Detaching twice is an error, not a comfortable no-op: a driver that
    // hears "fine" for something that did not happen learns nothing.
    let args = detach_args(&mut upage, memory);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaDetach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::NotMapped))),
    );
}

/// A second attach is refused **and the first survives**. Replacing the
/// record would leave a translation installed that nothing can name, and
/// therefore that nothing will ever remove.
#[test]
fn attaching_twice_is_refused_and_leaves_the_first_alone() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    let args = attach_args(&mut upage, 0, memory);
    let first = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u64,
        other => panic!("attach failed: {other:?}"),
    };
    let args = attach_args(&mut upage, 0, memory);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AlreadyMapped))),
    );
    let mapper = h.iommu.as_ref().expect("iommu");
    assert_eq!(mapper.installed.len(), 1, "no second translation");
    assert!(mapper.removed.is_empty(), "and the first was not torn down");
    assert_eq!(
        h.exec
            .memory_attachment_of(ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE))
            .expect("attachment")
            .address,
        first,
    );
}

/// **Handing the buffer on takes the device's reach with it**, without the
/// driver having to remember. A driver that returned a buffer its device
/// was still writing into would hand back memory that is still moving.
#[test]
fn transferring_an_attached_buffer_detaches_it() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    let args = attach_args(&mut upage, 0, memory);
    let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u64,
        other => panic!("attach failed: {other:?}"),
    };

    let handles_ptr = write_transfer(
        &mut upage,
        memory,
        Rights::READ | Rights::WRITE | Rights::MAP | Rights::TRANSFER,
    );
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let (_msg, departed) =
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper),
            irqs: None,
        };
        end_bindings_of_departed(&mut env, &departed);
    }
    assert_eq!(
        h.iommu.as_ref().expect("iommu").removed,
        std::vec![(ObjectId::from_raw(21), address, FRAME_SIZE)],
        "the device stopped reaching it when the capability left",
    );
}

/// **The device's lease ending clears the record without unmapping.** The
/// translations are already gone and the address range belongs to whoever
/// leases next — an `unmap` into it would be reaching into someone else's
/// address space, and a record that survived would make the object look
/// reachable by a device that can now reach nothing.
#[test]
fn a_lease_ending_forgets_the_attachment_without_unmapping() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    let args = attach_args(&mut upage, 0, memory);
    run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]);
    let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
    assert!(h.exec.memory_attachment_of(object).is_some());

    let holder = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .id();
    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    h.exec.end_device_lease(
        holder,
        ObjectId::from_raw(21),
        crate::devmgr::LeaseEndReason::Transferred,
        mapper,
    );

    assert!(
        h.exec.memory_attachment_of(object).is_none(),
        "the record went with the lease",
    );
    assert!(
        h.iommu.as_ref().expect("iommu").removed.is_empty(),
        "and nothing was unmapped into a range that is no longer ours",
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").ended,
        std::vec![ObjectId::from_raw(21)]
    );
}

/// **A multi-page object on a device with no IOMMU is refused.** Physical
/// frames are not contiguous, so there is no single address to return —
/// and returning the first page's would hand the device an address that
/// runs off the end of that page into whatever the allocator put next.
#[test]
fn an_unscoped_attach_of_more_than_one_page_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // No IOMMU installed — the state of four of the five ports.
    let args = memory_create_args(&mut upage, 2 * FRAME_SIZE);
    let memory = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = attach_args(&mut upage, 0, memory);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::NotSupported))),
    );

    // One page is served, and the address is the frame's own.
    let args = memory_create_args(&mut upage, FRAME_SIZE);
    let single = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = attach_args(&mut upage, 0, single);
    assert!(matches!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(v) if v > 0,
    ));
}

/// Attaching needs `MAP` on **both** capabilities. Narrowing it away from
/// the memory is how a client hands out a buffer that may be read and
/// written but not exposed to a device.
#[test]
fn attaching_without_map_on_either_handle_is_denied() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .replace_rights(crate::handle::Handle::from_raw(memory), Rights::READ)
            .expect("narrow");
    }
    let args = attach_args(&mut upage, 0, memory);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
    assert!(h.iommu.as_ref().expect("iommu").installed.is_empty());
}

/// **`Removed` becomes reachable.** It has been a terminal lifecycle state
/// with a full table of transitions into it since the driver framework
/// landed, and until a removal existed nothing could put a device there —
/// a state the design described and the machine could never enter.
#[test]
fn removal_records_the_terminal_state_nothing_could_reach_before() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(21);
    // A device that got as far as serving before it was pulled.
    for (from, to) in [
        (
            crate::lifecycle::DriverState::Discovered,
            crate::lifecycle::DriverState::Matched,
        ),
        (
            crate::lifecycle::DriverState::Matched,
            crate::lifecycle::DriverState::Starting,
        ),
        (
            crate::lifecycle::DriverState::Starting,
            crate::lifecycle::DriverState::Probing,
        ),
        (
            crate::lifecycle::DriverState::Probing,
            crate::lifecycle::DriverState::Active,
        ),
    ] {
        h.exec
            .declare_lifecycle(
                device,
                from,
                to,
                crate::lifecycle::TransitionReason::Unspecified,
                0,
            )
            .expect("transition");
    }

    h.exec.remove_device(
        device,
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        None,
        None,
    );
    assert_eq!(
        h.exec.lifecycle_state_of(device),
        Some(crate::lifecycle::DriverState::Removed),
        "a device pulled while Active is Removed, not still Active",
    );
}

/// **A lease that stops being renewed ends itself**    /// **A lease that stops being renewed ends itself**, through the very path
/// a departure uses — `LeaseEndReason::Expired` is a third caller of
/// `end_one_lease`, not a second teardown. A lease that expired into a
/// different state from one that was given up would be a second way for
/// the machine to be quiet about a device still translating.
#[test]
fn a_lease_nobody_renews_expires_the_way_a_departure_ends() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let device = ObjectId::from_raw(21);
    let args = device_args(&mut upage, 0, 0x4001_0000);
    run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

    let holder = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .id();
    assert!(h.exec.renew_device_lease(device, holder, Some(100)));

    // Before the deadline nothing happens, and that is as much a part of
    // the mechanism as the expiry: a sweep that ended leases early would
    // be indistinguishable from one that worked.
    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    assert_eq!(h.exec.expire_leases(99, mapper), 0);
    assert!(h.exec.lease_holder_of_object(device).is_some());

    // Renewal moves it out of reach again.
    assert!(h.exec.renew_device_lease(device, holder, Some(200)));
    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    assert_eq!(h.exec.expire_leases(150, mapper), 0);
    assert!(h.exec.lease_holder_of_object(device).is_some());

    // And past it, the lease goes exactly as a departure would take it.
    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    assert_eq!(h.exec.expire_leases(200, mapper), 1);
    assert!(h.exec.lease_holder_of_object(device).is_none());
    assert_eq!(
        h.iommu.as_ref().expect("iommu").ended,
        std::vec![device],
        "the hardware teardown is the same one",
    );
}

/// The syscall a driver actually calls: renew from ring 3, and the lease
/// survives a sweep past where it would otherwise have expired.
#[test]
fn a_driver_can_renew_its_own_lease_through_the_syscall() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let device = ObjectId::from_raw(21);
    let args = device_args(&mut upage, 0, 0x4001_0000);
    run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

    let renew = |upage: &mut UserPage, ticks: u64| -> u64 {
        let at = 896;
        let args = crate::isl_binding::memory::DmaRenewArgs {
            size: syscall::DMA_RENEW_ARGS_SIZE as u32,
            version: 1,
            flags: 0,
            device: tessera_isl_runtime::HandleRef::new(0),
            reserved: 0,
            ticks,
        };
        tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::DMA_RENEW_ARGS_SIZE])
            .expect("encode");
        upage.0.as_ptr() as u64 + at as u64
    };

    let ptr = renew(&mut upage, 100);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaRenew, [ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    assert_eq!(h.exec.expire_leases(99, mapper), 0);

    // Renewed again, it outlives the deadline it used to have.
    let ptr = renew(&mut upage, 500);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaRenew, [ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    assert_eq!(h.exec.expire_leases(200, mapper), 0);
    assert!(h.exec.lease_holder_of_object(device).is_some());

    // And past the new one it goes, through the departure path.
    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    assert_eq!(h.exec.expire_leases(500, mapper), 1);
    assert!(h.exec.lease_holder_of_object(device).is_none());

    // Renewing a lease that is gone is refused, not quietly accepted.
    let ptr = renew(&mut upage, 900);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaRenew, [ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::NotMapped))),
    );
}

/// A renewal is the **holder's** statement about its own lease. Anyone
/// else making it would keep alive a lease its owner had stopped wanting,
/// which is the whole thing expiry exists to notice.
#[test]
fn only_the_holder_can_renew_its_lease() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let device = ObjectId::from_raw(21);
    let args = device_args(&mut upage, 0, 0x4001_0000);
    run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

    assert!(
        !h.exec
            .renew_device_lease(device, ObjectId::from_raw(0xfeed), Some(500)),
        "a stranger cannot extend somebody else's lease",
    );
    // And a device with no lease at all has nothing to renew.
    assert!(!h.exec.renew_device_lease(
        ObjectId::from_raw(0x99),
        ObjectId::from_raw(0x99),
        Some(500),
    ));
}

/// A lease with no deadline never expires. Every driver that predates this
/// has one, and giving them all a lifetime they never agreed to would be
/// the mechanism breaking its own users on the way in.
#[test]
fn a_lease_with_no_deadline_outlives_every_sweep() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let args = device_args(&mut upage, 0, 0x4001_0000);
    run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);

    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    assert_eq!(h.exec.expire_leases(u64::MAX, mapper), 0);
    assert!(
        h.exec
            .lease_holder_of_object(ObjectId::from_raw(21))
            .is_some()
    );
}

/// **The departure nobody chose.** Every other route a capability leaves by
/// is something its holder did; this one runs while the holder is alive and
/// using the device. Two processes hold it, and afterwards neither does.
#[test]
fn removing_a_device_takes_it_from_every_holder() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(21);
    // A second process holding the same device — two drivers, or a manager
    // and the driver it granted to.
    let second = {
        let mut frames = MockFrameSource::new(0x2000_0000, 64);
        let space =
            AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_9000_0000_0000, Asid(2))
                .expect("space");
        let mut process = Process::new(ObjectId::from_raw(0x71), space);
        process
            .handles_mut()
            .install(device, Rights::READ | Rights::MAP)
            .expect("install");
        h.processes.insert(process).expect("insert")
    };
    assert!(
        h.processes
            .get_mut(second)
            .expect("p")
            .handles()
            .holds(device)
    );

    let report = h.exec.remove_device(
        device,
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        None,
        None,
    );
    assert!(report.existed);
    assert_eq!(report.holders, 2, "both holders, not just the first");
    assert!(
        !h.processes
            .get_mut(second)
            .expect("p")
            .handles()
            .holds(device),
        "the capability was taken from a living holder",
    );
    let caller = h.processes.process_of_thread(h.caller).expect("process");
    assert!(!caller.handles().holds(device));
}

/// **What makes the capability invalid rather than merely unheld.** The
/// node is gone, so every syscall that reaches a device refuses — and not
/// one of them had to learn a new rule.
#[test]
fn every_device_syscall_refuses_once_the_device_is_removed() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(21);
    // Re-install a handle after the removal, so what is being tested is the
    // *device* being gone rather than the handle being taken.
    h.exec.remove_device(
        device,
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        None,
        None,
    );
    let handle = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(device, Rights::READ | Rights::MAP)
            .expect("install")
            .raw()
    };

    let args = device_args(&mut upage, handle, 0x4002_0000);
    assert_eq!(
        run(&mut h, SyscallNumber::MapDevice, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
    let args = device_args(&mut upage, handle, 0x4003_0000);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
    let memory = make_object(&mut h, &mut upage);
    let args = attach_args(&mut upage, handle, memory);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
}

/// The window is unmapped in the holder that had one — a driver must not
/// keep register access to a device that is no longer in the machine.
#[test]
fn removal_unmaps_the_register_window_it_finds() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let args = device_args(&mut upage, 0, 0x4001_0000);
    assert!(matches!(
        run(&mut h, SyscallNumber::MapDevice, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(v) if v >= 0,
    ));
    assert!(
        h.processes
            .process_of_thread(h.caller)
            .expect("process")
            .space()
            .arch()
            .translate(VirtAddr::new(0x4001_0000))
            .is_some(),
    );

    let report = h.exec.remove_device(
        ObjectId::from_raw(21),
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        None,
        None,
    );
    assert_eq!(report.windows, 1);
    assert!(
        h.processes
            .process_of_thread(h.caller)
            .expect("process")
            .space()
            .arch()
            .translate(VirtAddr::new(0x4001_0000))
            .is_none(),
        "register access went with the device",
    );
}

/// **The lease and the route end before any handle moves**, and the mock is
/// what can tell: a device that has been pulled must stop translating
/// whatever else succeeds.
#[test]
fn removal_ends_the_lease_before_it_touches_a_handle() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let args = device_args(&mut upage, 0, 0x4001_0000);
    run(&mut h, SyscallNumber::DmaAlloc, [args, 0, 0, 0, 0, 0]);
    assert!(
        h.exec
            .lease_holder_of_object(ObjectId::from_raw(21))
            .is_some()
    );

    let mapper = h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper);
    h.exec.remove_device(
        ObjectId::from_raw(21),
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        mapper,
        None,
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").ended,
        std::vec![ObjectId::from_raw(21)],
    );
    assert!(
        h.exec
            .lease_holder_of_object(ObjectId::from_raw(21))
            .is_none()
    );
}

/// Removing something already removed is a no-op, not an error: a bus may
/// report one disappearance twice, and the second report is not a bug in
/// the reporter.
#[test]
fn removing_a_device_twice_is_harmless() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(21);
    assert!(
        h.exec
            .remove_device(
                device,
                crate::lifecycle::TransitionReason::Removed,
                &mut h.processes,
                None,
                None
            )
            .existed
    );
    let second = h.exec.remove_device(
        device,
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        None,
        None,
    );
    assert!(!second.existed);
    assert_eq!(second.holders, 0);
}

/// **A bus controller does not leave alone.** Pulling a switch takes the
/// ports and the endpoints below it in one physical event; a graph that
/// removed only the node named would leave the children resolving,
/// mapping and authorizing DMA for hardware that is not there.
#[test]
fn removing_a_controller_removes_everything_behind_it() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // The harness' device 21 becomes the root port, with a switch's two
    // ports and an endpoint below it — the hotplug machine's topology.
    let bridge = ObjectId::from_raw(21);
    let below = [0x51, 0x52, 0x53].map(ObjectId::from_raw);
    for (index, id) in below.iter().enumerate() {
        h.exec
            .device_register_mmio(
                *id,
                0x0a00_5000 + 0x1000 * index as u64,
                FRAME_SIZE,
                Rights::READ | Rights::MAP,
            )
            .expect("register");
    }
    h.exec.device_set_parent(below[0], bridge).expect("edge");
    h.exec.device_set_parent(below[1], below[0]).expect("edge");
    h.exec.device_set_parent(below[2], below[1]).expect("edge");

    // A driver holding the endpoint at the bottom, which has asked nobody
    // about any of this.
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(below[2], Rights::READ | Rights::MAP)
            .expect("install");
    }

    let report = h.exec.remove_device(
        bridge,
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        None,
        None,
    );
    assert!(report.existed);
    assert_eq!(
        report.subtree, 4,
        "the port, both switch ports, the endpoint"
    );

    // Every node is gone, so every device syscall refuses for all of them
    // — the deepest one included, which is the node a single removal would
    // have left behind.
    for id in [bridge, below[0], below[1], below[2]] {
        assert!(
            h.exec.mmio_of_object(id).is_none(),
            "{id:?} still resolves after its bus was pulled",
        );
    }
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        !process.handles().holds(below[2]),
        "the endpoint's holder was never asked, and holds nothing",
    );
}

/// The other half: a leaf leaving must not take its bus with it. Removal
/// walks down from what was named, never up.
#[test]
fn removing_a_leaf_leaves_its_bus_and_its_siblings_alone() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let bridge = ObjectId::from_raw(21);
    let siblings = [0x61, 0x62].map(ObjectId::from_raw);
    for (index, id) in siblings.iter().enumerate() {
        h.exec
            .device_register_mmio(
                *id,
                0x0a00_7000 + 0x1000 * index as u64,
                FRAME_SIZE,
                Rights::READ | Rights::MAP,
            )
            .expect("register");
        h.exec.device_set_parent(*id, bridge).expect("edge");
    }

    let report = h.exec.remove_device(
        siblings[0],
        crate::lifecycle::TransitionReason::Removed,
        &mut h.processes,
        None,
        None,
    );
    assert_eq!(report.subtree, 1, "one function, not the bus it sat on");
    assert!(
        h.exec.mmio_of_object(bridge).is_some(),
        "the bus is still there"
    );
    assert!(
        h.exec.mmio_of_object(siblings[1]).is_some(),
        "so is its sibling"
    );
    assert!(h.exec.mmio_of_object(siblings[0]).is_none());
}

/// **The bound this milestone exists to remove.** A device address is never
/// reissued within a lease, so before this every request a driver served
/// spent one — and the SMMU machine's lease is two pages. Re-attaching the
/// same object lands where it landed before, so a driver serving one
/// buffer runs as long as it likes.
#[test]
fn reattaching_one_object_reuses_its_address_forever() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // An aperture of exactly two pages — the real one on the SMMU machine.
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        2 * FRAME_SIZE,
    ));
    let memory = make_object(&mut h, &mut upage);

    let mut seen = None;
    for round in 0..8 {
        let args = attach_args(&mut upage, 0, memory);
        let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) if v >= 0 => v as u64,
            other => panic!("attach {round} failed: {other:?}"),
        };
        match seen {
            None => seen = Some(address),
            Some(first) => assert_eq!(address, first, "round {round} moved"),
        }
        let args = detach_args(&mut upage, memory);
        assert_eq!(
            run(&mut h, SyscallNumber::DmaDetach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
        );
    }
    // Eight rounds through a two-page aperture. Every one of them mapped
    // and unmapped for real — the reuse is of the address, not of the
    // translation.
    let mapper = h.iommu.as_ref().expect("iommu");
    assert_eq!(mapper.installed.len(), 8);
    assert_eq!(mapper.removed.len(), 8);
}

/// A **different** object still gets a different address, and the aperture
/// still runs out. That is the rule intact: what is reissued is an address
/// for the memory it already named, never for other memory.
#[test]
fn a_second_object_gets_its_own_address_and_the_aperture_still_ends() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        2 * FRAME_SIZE,
    ));
    let first = make_object(&mut h, &mut upage);
    let second = make_object(&mut h, &mut upage);
    let third = make_object(&mut h, &mut upage);

    let args = attach_args(&mut upage, 0, first);
    let a = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u64,
        other => panic!("attach failed: {other:?}"),
    };
    let args = attach_args(&mut upage, 0, second);
    let b = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u64,
        other => panic!("attach failed: {other:?}"),
    };
    assert_ne!(a, b, "two objects must not share one address");

    // The aperture holds two pages and both are spent. A third object is
    // refused rather than handed one of theirs.
    let args = attach_args(&mut upage, 0, third);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::OutOfMemory))),
    );
}

/// **Closing the last handle to a buffer you own gives the frames back.**
/// Before this the only ways were dying and handing it on, so a resident
/// service's lifetime was measured in how much work it had done.
#[test]
fn closing_an_owned_memory_object_releases_its_frames() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let memory = make_object(&mut h, &mut upage);
    let before = h.frames.free_list_depth();

    assert_eq!(
        run(
            &mut h,
            SyscallNumber::HandleClose,
            [u64::from(memory), 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(1),
    );
    assert_eq!(
        h.frames.free_list_depth(),
        before + 1,
        "the object's frame came back",
    );
    // The handle is gone with it, so a second close is a bad handle rather
    // than a second release.
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::HandleClose,
            [u64::from(memory), 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::BadHandle))),
    );
}

/// Closing **one of two** handles to the same object frees nothing: the
/// process has not given the capability up, it has given up one name for
/// it.
#[test]
fn closing_one_of_two_handles_keeps_the_object() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let memory = make_object(&mut h, &mut upage);
    let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
    let second = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(object, Rights::READ | Rights::MAP)
            .expect("second handle")
            .raw()
    };
    let before = h.frames.free_list_depth();
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::HandleClose,
            [u64::from(memory), 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0),
    );
    assert_eq!(h.frames.free_list_depth(), before, "nothing was released");
    // And the surviving handle still names it.
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::HandleClose,
            [u64::from(second), 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(1),
    );
}

/// **A receiver closing a lent buffer must not free the sender's memory.**
/// Ownership is the single-valued fact that tells the two apart, and this
/// is the case it exists for.
#[test]
fn closing_a_buffer_you_do_not_own_frees_nothing() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let memory = make_object(&mut h, &mut upage);
    let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
    // Somebody else owns it now — the state a driver is in while it holds
    // a client's transferred buffer.
    h.exec
        .memory_set_sole_holder(object, ObjectId::from_raw(0xbeef));

    let before = h.frames.free_list_depth();
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::HandleClose,
            [u64::from(memory), 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0),
    );
    assert_eq!(
        h.frames.free_list_depth(),
        before,
        "the owner's frames are not the closer's to release",
    );
    assert!(
        h.exec.memory_owner_of(object).is_some(),
        "and it still exists"
    );
}

/// **A share arriving records the receiver as a holder** (D286).
///
/// The receive side, driven through `ChannelRecv` rather than by calling the
/// table: the sending side reads the mode, and this end has to act on what the
/// message says rather than on anything it can work out for itself. A build
/// that carried the mode and then did nothing with it passes every other test
/// here — a shared object would look transferred, and the sender's frames
/// would go the moment it closed its own handle.
#[test]
fn a_share_arriving_adds_the_receiver_to_the_holders() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // An object belonging to somebody else, as one that was shared here is.
    let memory = make_object(&mut h, &mut upage);
    let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
    let sender = ObjectId::from_raw(0xbeef);
    assert!(h.exec.memory_set_sole_holder(object, sender));
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .drop_handle(crate::handle::Handle::from_raw(memory))
            .expect("the creator's handle goes, as a sender's would");
    }

    // The message the sender built: the object, marked shared.
    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(0x5a);
    h.exec.bind_endpoint_object(a, ep_obj);
    let mut message = Message::new(MessageHeader::new(0, 0));
    message
        .add_handle(crate::ipc::TransferredHandle {
            object,
            rights: Rights::READ | Rights::MAP,
            shared: true,
        })
        .expect("attach");
    h.exec.send(b, message).expect("queued");
    // **Whatever number the table gives it.** The creator's handle was
    // dropped above, which bumps that slot's generation — so the endpoint does
    // not land at raw 1 the way it does in a fresh table, and assuming it
    // would is the mistake the generation counter exists to make visible.
    let endpoint = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ep_obj, Rights::READ)
            .expect("install ep")
            .raw()
    };

    let args_ptr = call_args(&mut upage, 96);
    assert!(matches!(
        run(
            &mut h,
            SyscallNumber::ChannelRecv,
            [args_ptr, u64::from(endpoint), 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(v) if v >= 0
    ));
    assert_eq!(
        h.exec.memory_holder_count(object),
        Some(2),
        "the sender kept it and this end now holds it too",
    );
    assert!(h.exec.memory_is_held_by(object, sender));
}

/// **A shared object survives its creator closing it, and goes when the last
/// holder does** (D286).
///
/// The whole point of `SHARE`, at the level where it can actually go wrong:
/// the frames must not return to the allocator while a second holder is still
/// reading them, and they must return when nobody is. Run through
/// `HandleClose` rather than against the table directly, because the bug this
/// guards against lives in the close path's decision — it used to compare a
/// single owner, and a comparison is what a second holder makes wrong.
#[test]
fn a_shared_buffer_outlives_its_creator_and_goes_with_the_last_holder() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let memory = make_object(&mut h, &mut upage);
    let object = ObjectId::from_raw(crate::memory::MEMORY_OBJECT_ID_BASE);
    let sharer = ObjectId::from_raw(0xbeef);
    h.exec.memory_add_holder(object, sharer).expect("shared");
    assert_eq!(h.exec.memory_holder_count(object), Some(2));

    // The creator closes its handle. It is a holder, so it lets go — and the
    // frames stay, because somebody else has not.
    let before = h.frames.free_list_depth();
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::HandleClose,
            [u64::from(memory), 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0),
        "nothing was released, which is what a share means",
    );
    assert_eq!(
        h.frames.free_list_depth(),
        before,
        "memory a second holder is still reading does not go back to the pool",
    );
    assert_eq!(h.exec.memory_holder_count(object), Some(1));

    // And when the last holder lets go, the frames do return. Done through the
    // executive because that holder is not a process this harness runs.
    assert!(!h.exec.memory_remove_holder(object, sharer));
    let released = h.exec.memory_destroy(object, &mut h.frames, None);
    assert!(released > 0, "the last holder's release frees the pages");
    assert!(h.exec.memory_owner_of(object).is_none());
}

/// Closing an attached object detaches it first — the frames must not go
/// back to the allocator while a device can still write into them.
#[test]
fn closing_an_attached_object_detaches_before_freeing() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    let args = attach_args(&mut upage, 0, memory);
    let address = match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u64,
        other => panic!("attach failed: {other:?}"),
    };
    let before = h.frames.free_list_depth();

    assert_eq!(
        run(
            &mut h,
            SyscallNumber::HandleClose,
            [u64::from(memory), 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(1),
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").removed,
        std::vec![(ObjectId::from_raw(21), address, FRAME_SIZE)],
        "the device stopped reaching it before the frame moved",
    );
    assert_eq!(
        h.frames.free_list_depth(),
        before + 1,
        "and then the frame moved",
    );
}

/// Closing a **device** capability takes its register window, its DMA
/// lease and its interrupt route out with it — the same three that follow
/// it out on a transfer.
#[test]
fn closing_a_device_ends_what_the_capability_was_holding() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    // Take a lease by asking for a DMA buffer.
    let args_ptr = device_args(&mut upage, 0, 0x4001_0000);
    run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
    assert!(
        h.exec
            .lease_holder_of_object(ObjectId::from_raw(21))
            .is_some()
    );

    assert_eq!(
        run(&mut h, SyscallNumber::HandleClose, [0, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    assert!(
        h.exec
            .lease_holder_of_object(ObjectId::from_raw(21))
            .is_none(),
        "the lease left with the capability",
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").ended,
        std::vec![ObjectId::from_raw(21)],
    );
}

/// **A capability that did not land is reported at its own position.** The
/// report is what a payload's handle index resolves against, so a report
/// that closed the gap over a dropped capability would leave the
/// receiver's slot holding whatever the *previous* message left there —
/// and a field naming that index would resolve to a stale handle number
/// instead of to an error.
#[test]
fn a_dropped_capability_holds_its_place_in_the_installed_report() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ);
    let mut message = crate::ipc::Message::new(crate::ipc::MessageHeader::new(0, 0));
    for object in [ObjectId::from_raw(0x900), ObjectId::from_raw(0x901)] {
        message
            .add_handle(crate::ipc::TransferredHandle {
                object,
                rights: Rights::READ,
                shared: false,
            })
            .expect("attach");
    }
    // Fill the receiver's table so neither capability can be installed.
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        while process
            .handles_mut()
            .install(ObjectId::from_raw(0xf00), Rights::READ)
            .is_ok()
        {}
    }

    let (installed, count) = install_transferred_handles(&mut h.processes, h.caller, &message);
    // Two descriptors, two positions — the count is what the sender sent,
    // not what survived.
    assert_eq!(count, 2);
    assert_eq!(installed[0], HANDLE_NOT_INSTALLED);
    assert_eq!(installed[1], HANDLE_NOT_INSTALLED);
    // And the sentinel is not a handle number anyone could hold: 0 is the
    // first handle a fresh table hands out, so a zero-filled report would
    // read as "you were given handle 0".
    assert_ne!(HANDLE_NOT_INSTALLED, 0);
}

/// **A message over a limit is refused, not trimmed** (`docs/kernel/04`).
/// Truncating is the failure mode that looks like success: the send
/// returns, the receiver answers a shorter request than the one the sender
/// wrote, and the disagreement surfaces as a wrong answer rather than an
/// error.
#[test]
fn an_oversized_message_is_refused_rather_than_truncated() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let base = upage.0.as_ptr() as u64;
    let mut args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: base,
        inline_len: MAX_INLINE_BYTES as u64 + 1,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    assert_eq!(
        build_message_from_args(&mut h.processes, h.caller, &args, false).err(),
        Some(KError::Protocol),
    );
    // Exactly at the limit is a message, not an error — the boundary
    // belongs on the inside.
    args.inline_len = MAX_INLINE_BYTES as u64;
    assert!(build_message_from_args(&mut h.processes, h.caller, &args, false).is_ok());

    // The same for the transfer vector: a fifth handle silently staying
    // home would leave the receiver short of a capability it was promised.
    args.inline_len = 0;
    args.handles_ptr = base + 2048;
    args.handle_count = MAX_MSG_HANDLES as u64 + 1;
    assert_eq!(
        build_message_from_args(&mut h.processes, h.caller, &args, true).err(),
        Some(KError::Protocol),
    );
}

/// **A share leaves the sender holding what it shared** (D286), and a transfer
/// does not.
///
/// The two modes are one bit apart in the descriptor and opposite in what they
/// do to the sender's table, which is why they are asserted against each other
/// here rather than separately: a build that read the bit and then took the
/// handle anyway would pass either test alone.
#[test]
fn a_share_leaves_the_senders_handle_and_a_transfer_takes_it() {
    let args = |handles_ptr| syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };

    // Mode 1 is SHARE.
    let mut upage = UserPage([0; 4096]);
    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP);
    upage.0[2052..2056].copy_from_slice(&1u32.to_le_bytes());
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let message = build_message_from_args(&mut h.processes, h.caller, &args(handles_ptr), true)
        .expect("a share is built")
        .0;
    assert!(
        message.handles().next().is_some_and(|t| t.shared),
        "and the message says so, because the receiver cannot re-derive it",
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process.handles().lookup(Handle::from_raw(0)).is_ok(),
        "the sender still holds what it shared",
    );

    // Mode 0 is TRANSFER, and the same descriptor otherwise.
    let mut upage = UserPage([0; 4096]);
    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let message = build_message_from_args(&mut h.processes, h.caller, &args(handles_ptr), true)
        .expect("a transfer is built")
        .0;
    assert!(message.handles().next().is_some_and(|t| !t.shared));
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert_eq!(
        process.handles().lookup(Handle::from_raw(0)).err(),
        Some(KError::BadHandle),
        "and a transfer takes it",
    );
}

/// Sharing is delegation, so it needs the right that gates delegation.
///
/// **The same rule as a transfer, and it has to be.** A capability granted
/// without `TRANSFER` is one its holder may use and may not pass on; if
/// sharing skipped that check, every non-delegable grant in the system would
/// be delegable by asking for it the other way.
#[test]
fn a_share_without_the_transfer_right_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ);
    upage.0[2052..2056].copy_from_slice(&1u32.to_le_bytes());
    // The sender holds READ and MAP, and no TRANSFER.
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    assert_eq!(
        build_message_from_args(&mut h.processes, h.caller, &args, true).err(),
        Some(KError::AccessDenied),
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(process.handles().lookup(Handle::from_raw(0)).is_ok());
}

/// The point of the bookkeeping: handing a device capability to another
/// process must take the register window with it. Otherwise the sender
/// keeps everything the capability was protecting, and the receiver's
/// exclusive use is exclusive only of *other receivers* — which is how a
/// device manager ends up more privileged than anything it serves.
#[test]
fn transferring_a_device_capability_takes_its_mapping_with_it() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    // The transfer vector has to live in *user* memory the process maps, so
    // it goes in the same page the args do; the device is handle 0.
    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    // The window is live before the transfer.
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4000_0000))
            .is_some()
    );

    // Hand the device capability away.
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let message = build_message_from_args(&mut h.processes, h.caller, &args, true)
        .expect("transfer the device capability");
    assert_eq!(message.0.handles().count(), 1);

    // The mapping is gone with it, and so is the bookkeeping.
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4000_0000))
            .is_none(),
        "the sender kept register access to a device it gave away"
    );
    assert_eq!(process.device_window_count(), 0);
}

/// Where a `DeviceInfoRecord` lands in the user page — clear of the args
/// and of the transfer vector the other tests use.
const RECORD_AT: usize = 3072;

/// Builds a `DeviceInfoArgs` in the user page and returns its pointer.
fn device_info_args(upage: &mut UserPage, handle: u32) -> (u64, u64) {
    let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
    let at = 256;
    upage.0[at..at + syscall::DEVICE_INFO_ARGS_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&(syscall::DEVICE_INFO_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&record_ptr.to_le_bytes());
    (upage.0.as_ptr() as u64 + at as u64, record_ptr)
}

// -----------------------------------------------------------------------
// DeviceChild — a bus controller derives the devices behind it.
// -----------------------------------------------------------------------

/// Builds a `DeviceChildArgs` in the user page and returns
/// `(args_ptr, record_ptr)`.
fn device_child_args(upage: &mut UserPage, handle: u32, index: u32) -> (u64, u64) {
    let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
    let at = 512;
    upage.0[at..at + syscall::DEVICE_CHILD_ARGS_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&(syscall::DEVICE_CHILD_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
    upage.0[at + 20..at + 24].copy_from_slice(&index.to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&record_ptr.to_le_bytes());
    (upage.0.as_ptr() as u64 + at as u64, record_ptr)
}

/// Reads back a `DeviceChildRecord` as `(count, child, rights)`.
fn device_child_record(upage: &UserPage) -> (u32, u32, u64) {
    let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_CHILD_RECORD_SIZE];
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word"));
    let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("long"));
    (word(16), word(20), long(24))
}

// -----------------------------------------------------------------------
// DeviceDeclare / MapConfig — a bus controller populates the graph, and a
// function maps its own slice of configuration space.
// -----------------------------------------------------------------------

/// The bus this harness hands out: a 1 MiB configuration window and a
/// forwarded memory window BARs may be placed in.
const BUS_OBJ: ObjectId = ObjectId::from_raw(70);
const BUS_CONFIG_BASE: u64 = 0x4010_0000;
const BUS_CONFIG_LEN: u64 = 0x10_0000;
const BUS_FORWARD_BASE: u64 = 0x1000_0000;
const BUS_FORWARD_LEN: u64 = 0x0100_0000;

/// **The IOMMU-first rule, and it is a refusal.** A device behind an IOMMU
/// asking for a run of physical memory is over-asking: the broker can give
/// it one contiguous device address over scattered pages for nothing.
/// Accepting would spend memory nothing can defragment and the caller would
/// never learn it had asked for the wrong thing.
#[test]
fn a_physical_run_is_refused_to_a_device_behind_an_iommu() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let args = memory_create_args_placed(&mut upage, FRAME_SIZE, 0x2, 0);
    let buffer = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = attach_args(&mut upage, 0, buffer);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::PolicyRefused))),
        "the device is behind an IOMMU and did not need a run",
    );

    // The same buffer asking for device-visible contiguity instead is what
    // the rule tells it to ask for, and it attaches.
    let args = memory_create_args_placed(&mut upage, FRAME_SIZE, 0x1, 0);
    let buffer = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = attach_args(&mut upage, 0, buffer);
    assert!(
        matches!(
            run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(v) if v >= 0
        ),
        "device-visible contiguity is what the rule asks for",
    );
}

/// And the same request is **honoured** for hardware the graph records as
/// needing it — no scatter-gather and nothing translating for it. Without
/// this half the rule would just be "physical contiguity is never
/// available", which is a different and wrong policy.
#[test]
fn a_physical_run_is_honoured_for_hardware_that_needs_one() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    h.exec
        .device_set_requires_contiguity(ObjectId::from_raw(21), true)
        .expect("record");
    let args = memory_create_args_placed(&mut upage, FRAME_SIZE, 0x2, 0);
    let buffer = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = attach_args(&mut upage, 0, buffer);
    assert!(matches!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(v) if v >= 0
    ),);
}

/// A harness holding a bus at handle 1 with `rights`.
fn bus_harness(upage: &UserPage, rights: Rights) -> Harness {
    let mut h = harness(upage, Rights::READ | Rights::MAP);
    h.exec
        .device_register_mmio(
            BUS_OBJ,
            BUS_CONFIG_BASE,
            BUS_CONFIG_LEN,
            Rights::READ | Rights::MAP | Rights::DERIVE | Rights::CONFIGURE,
        )
        .expect("register bus");
    h.exec
        .device_set_bus_window(
            BUS_OBJ,
            crate::devmgr::BusWindow {
                config_len: BUS_CONFIG_LEN,
                forward_cpu_base: BUS_FORWARD_BASE,
                forward_bus_base: BUS_FORWARD_BASE,
                forward_len: BUS_FORWARD_LEN,
                first_bus: 0,
                last_bus: 0,
                first_intid: BUS_FIRST_INTID,
                intid_count: BUS_INTID_COUNT,
            },
        )
        .expect("bus window");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process.handles_mut().install(BUS_OBJ, rights).expect("bus");
    assert_eq!(handle.raw(), 1);
    h
}

/// Builds a `DeviceDeclareArgs` and returns `(args_ptr, record_ptr)`.
/// The lines the harness's bus forwards. A range rather than a line,
/// because what is being checked is whether a declaration lands inside it.
const BUS_FIRST_INTID: u32 = 40;
const BUS_INTID_COUNT: u32 = 8;

fn declare_args(upage: &mut UserPage, bdf: u32, base: u64, len: u64) -> (u64, u64) {
    let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
    let at = 768;
    let args = crate::isl_binding::device::DeviceDeclareArgs {
        size: syscall::DEVICE_DECLARE_ARGS_SIZE as u32,
        version: 2,
        flags: 0,
        bus: tessera_isl_runtime::HandleRef::new(1),
        bdf,
        register_base: base,
        register_len: len,
        class_code: 0x01_0000,
        vendor: 0x1af4,
        device_id: 0x1001,
        revision: 3,
        record_ptr,
        intid: 0,
        trigger: 0,
    };
    tessera_isl_runtime::encode(
        &args,
        &mut upage.0[at..at + syscall::DEVICE_DECLARE_ARGS_SIZE],
    )
    .expect("encode");
    (upage.0.as_ptr() as u64 + at as u64, record_ptr)
}

/// `declare_args`, naming a bus other than the harness's own handle 1 —
/// which is how a declared device is asked to hold children of its own.
fn declare_args_on(upage: &mut UserPage, bus: u32, bdf: u32, base: u64, len: u64) -> u64 {
    let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
    let at = 768;
    let args = crate::isl_binding::device::DeviceDeclareArgs {
        size: syscall::DEVICE_DECLARE_ARGS_SIZE as u32,
        version: 2,
        flags: 0,
        bus: tessera_isl_runtime::HandleRef::new(bus),
        bdf,
        register_base: base,
        register_len: len,
        class_code: 0x0c_0300,
        vendor: 0x46f4,
        device_id: 0x0002,
        revision: 1,
        record_ptr,
        intid: 0,
        trigger: 0,
    };
    tessera_isl_runtime::encode(
        &args,
        &mut upage.0[at..at + syscall::DEVICE_DECLARE_ARGS_SIZE],
    )
    .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// Reads back a `DeviceDeclareRecord` as `(device, rights)`.
fn declare_record(upage: &UserPage) -> (u32, u64) {
    let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_DECLARE_RECORD_SIZE];
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word"));
    let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("long"));
    (word(16), long(24))
}

/// The whole of what the milestone claims, in one exchange: something
/// outside the kernel added a node to the resource graph, and the graph
/// answers about it exactly as it does about one the kernel walked to find.
#[test]
fn a_bus_controller_declares_a_device_and_the_graph_knows_it() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0x18, BUS_FORWARD_BASE, 0x1000);
    let mut h = bus_harness(
        &upage,
        Rights::READ | Rights::MAP | Rights::DERIVE | Rights::CONFIGURE,
    );
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (device, rights) = declare_record(&upage);
    assert_ne!(device, HANDLE_NOT_INSTALLED);
    assert!(Rights::from_bits(rights).contains(Rights::CONFIGURE));

    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, _) = process
        .handles()
        .lookup(Handle::from_raw(device))
        .expect("the handle names the declared device");
    let identity = h.exec.identity_of_object(object).expect("identity");
    assert_eq!(identity.vendor, 0x1af4);
    assert_eq!(identity.device, 0x1001);
    assert_eq!(identity.bdf, 0x18);
    assert_eq!(identity.revision, 3);
    // The edge, which is what makes the device reachable from the bus by
    // anything that never saw this declaration.
    assert_eq!(h.exec.device_parent_of(object), Some(BUS_OBJ));
    // Its config slot, computed by the kernel from the BDF rather than
    // taken from the caller.
    assert_eq!(
        h.exec.config_of_object(object),
        Some((BUS_CONFIG_BASE + 0x18 * 4096, 4096)),
    );
}

/// Holding a bus is not authority to populate it — the same rule
/// `DeviceChild` applies to reading it.
#[test]
fn declaring_without_derive_is_denied() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0x18, BUS_FORWARD_BASE, 0x1000);
    let mut h = bus_harness(&upage, Rights::READ | Rights::MAP | Rights::CONFIGURE);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// **Containment, and it creates nothing when it refuses.** A controller
/// declaring a window outside what its bus forwards is the attack this
/// check exists for: the alternative is a "device" whose registers are
/// somebody else's memory, mapped by a driver that was told it was a NIC.
#[test]
fn a_register_window_outside_what_the_bus_forwards_is_refused() {
    let mut upage = UserPage([0; 4096]);
    // One byte past the end of the forwarded window.
    let (args, _) = declare_args(
        &mut upage,
        0x18,
        BUS_FORWARD_BASE + BUS_FORWARD_LEN - 0x800,
        0x1000,
    );
    let mut h = bus_harness(
        &upage,
        Rights::READ | Rights::MAP | Rights::DERIVE | Rights::CONFIGURE,
    );
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    // Nothing was created: the bus has no children, so a later `DeviceChild`
    // walk cannot find what the refusal was supposed to prevent.
    let mut children = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
    assert_eq!(h.exec.device_children_of(BUS_OBJ, &mut children), 0);
}

/// The same rule for the other window. A BDF past the configuration space
/// the bus covers names a slot in whatever follows it in physical memory.
#[test]
fn a_config_slot_outside_the_bus_window_is_refused() {
    let mut upage = UserPage([0; 4096]);
    // 0x100 functions of 4 KiB is exactly the 1 MiB window, so 0x100 is the
    // first slot past its end.
    let (args, _) = declare_args(&mut upage, 0x100, BUS_FORWARD_BASE, 0x1000);
    let mut h = bus_harness(
        &upage,
        Rights::READ | Rights::MAP | Rights::DERIVE | Rights::CONFIGURE,
    );
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidArgument)))
    );
}

/// A declaration cannot mint authority the declarer does not hold: a
/// controller granted a bus without `CONFIGURE` cannot hand out functions
/// that carry it.
#[test]
fn a_declared_device_cannot_carry_more_than_its_bus() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0x18, BUS_FORWARD_BASE, 0x1000);
    let mut h = bus_harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (_, rights) = declare_record(&upage);
    assert!(!Rights::from_bits(rights).contains(Rights::CONFIGURE));
}

/// A bus whose children have **no memory of their own**: no configuration
/// space and nothing forwarded. An SD host controller is one — a card is
/// reached through it, so a capability to the card grants nothing to map.
fn windowless_bus_harness(upage: &UserPage, rights: Rights) -> Harness {
    let mut h = harness(upage, Rights::READ | Rights::MAP);
    h.exec
        .device_register_mmio(
            BUS_OBJ,
            0x3000_0000,
            0x1000,
            Rights::READ | Rights::MAP | Rights::DERIVE,
        )
        .expect("register bus");
    h.exec
        .device_set_bus_window(BUS_OBJ, crate::devmgr::BusWindow::default())
        .expect("bus window");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process.handles_mut().install(BUS_OBJ, rights).expect("bus");
    assert_eq!(handle.raw(), 1);
    h
}

/// **A device capability that carries no memory at all.** It is identity and
/// lifecycle and nothing else, which is the honest description of an SD card:
/// every transfer goes through its controller, so there is nothing for the
/// holder to map and no window for the kernel to contain.
///
/// The graph still knows it, which is what matters — a manager can ask what
/// it is, bind a driver to it, and see it leave.
#[test]
fn a_child_with_no_window_is_still_a_device_the_graph_knows() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0, 0, 0);
    let mut h = windowless_bus_harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (device, _) = declare_record(&upage);
    assert_ne!(device, HANDLE_NOT_INSTALLED);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, _) = process
        .handles()
        .lookup(Handle::from_raw(device))
        .expect("the handle names it");

    // The graph knows it, and the manager can ask what it is.
    assert!(h.exec.device_known(object));
    assert_eq!(
        h.exec.identity_of_object(object).map(|id| id.vendor),
        Some(0x1af4),
    );
    assert_eq!(h.exec.device_parent_of(object), Some(BUS_OBJ));
    // And it holds nothing to map: no register window and no config slot.
    assert_eq!(h.exec.mmio_of_object(object), None);
    assert_eq!(h.exec.config_of_object(object), None);
}

/// Encodes a declaration naming an interrupt line.
fn declare_args_with_irq(upage: &mut UserPage, base: u64, len: u64, intid: u32) -> u64 {
    let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
    let at = 768;
    let args = crate::isl_binding::device::DeviceDeclareArgs {
        size: syscall::DEVICE_DECLARE_ARGS_SIZE as u32,
        version: 2,
        flags: 0,
        bus: tessera_isl_runtime::HandleRef::new(1),
        bdf: 0x18,
        register_base: base,
        register_len: len,
        class_code: 0x01_0000,
        vendor: 0x1af4,
        device_id: 0x1001,
        revision: 3,
        record_ptr,
        intid,
        trigger: 0,
    };
    tessera_isl_runtime::encode(
        &args,
        &mut upage.0[at..at + syscall::DEVICE_DECLARE_ARGS_SIZE],
    )
    .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// **A wire is contained the way a window is.** Without this a bus driver
/// could declare a device on somebody else's INTID and have the graph route
/// that line to itself — which is claiming a wire it was not given, and is
/// exactly the mistake the register-window check has always refused for
/// memory.
#[test]
fn a_bus_may_declare_an_interrupt_only_inside_the_range_it_forwards() {
    let mut upage = UserPage([0; 4096]);
    let args = declare_args_with_irq(&mut upage, BUS_FORWARD_BASE, 0x1000, BUS_FIRST_INTID);
    let mut h = bus_harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (device, _) = declare_record(&upage);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, _) = process
        .handles()
        .lookup(Handle::from_raw(device))
        .expect("the device");
    // Recorded, so the line can be routed — which is the whole point of a
    // bus being able to declare it.
    let mut lines = [0u32; 1 + crate::devmgr::MAX_EXTRA_IRQS];
    assert_eq!(h.exec.intids_of_object(object, &mut lines), 1);
    assert_eq!(lines[0], BUS_FIRST_INTID);

    // The line one past the end. Refused, and nothing is declared for it.
    let args = declare_args_with_irq(
        &mut upage,
        BUS_FORWARD_BASE,
        0x1000,
        BUS_FIRST_INTID + BUS_INTID_COUNT,
    );
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    // And one below it, which is the other end of the same range.
    let args = declare_args_with_irq(&mut upage, BUS_FORWARD_BASE, 0x1000, 1);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// **A bus that forwards no wires can still describe devices.** Every bus
/// that existed before the range did keeps exactly the authority it had: a
/// PCI bridge forwards memory and its functions interrupt by message, so a
/// declaration naming a line is refused and one naming none is not.
#[test]
fn a_bus_with_no_interrupt_range_declares_no_interrupt() {
    let mut upage = UserPage([0; 4096]);
    let args = declare_args_with_irq(&mut upage, BUS_FORWARD_BASE, 0x1000, 0);
    let mut h = bus_harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    // The same bus, with the wires taken away — which is what every bus
    // that existed before this range did forwards.
    h.exec
        .device_set_bus_window(
            BUS_OBJ,
            crate::devmgr::BusWindow {
                config_len: BUS_CONFIG_LEN,
                forward_cpu_base: BUS_FORWARD_BASE,
                forward_bus_base: BUS_FORWARD_BASE,
                forward_len: BUS_FORWARD_LEN,
                first_bus: 0,
                last_bus: 0,
                first_intid: 0,
                intid_count: 0,
            },
        )
        .expect("bus window");
    // A device with no wire: ordinary, and the common case.
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    // A device with one: refused, because this bus was given none to give.
    let args = declare_args_with_irq(&mut upage, BUS_FORWARD_BASE, 0x1000, 40);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// **A hub is a bus.** A device declared by a relaying bus can itself hold
/// children, so a tree of relaying hosts is a tree in the graph rather than
/// a flat list — which is what makes the hop count on a device two levels
/// down a two rather than a one.
///
/// Until this, the `DERIVE` that travels down to a declared device was a
/// right with nothing to exercise: the holder could name the hub and not
/// populate it.
#[test]
fn a_windowless_child_can_hold_children_of_its_own() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0, 0, 0);
    let mut h = windowless_bus_harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (hub, hub_rights) = declare_record(&upage);
    assert_ne!(hub, HANDLE_NOT_INSTALLED);
    assert!(Rights::from_bits(hub_rights).contains(Rights::DERIVE));

    // A device behind the hub, declared by naming the hub itself.
    let args = declare_args_on(&mut upage, hub, 0, 0, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (device, _) = declare_record(&upage);
    assert_ne!(device, HANDLE_NOT_INSTALLED);

    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (hub_object, _) = process
        .handles()
        .lookup(Handle::from_raw(hub))
        .expect("the hub");
    let (leaf, _) = process
        .handles()
        .lookup(Handle::from_raw(device))
        .expect("the device");
    // Three levels, and the graph walks all of them.
    assert_eq!(h.exec.device_parent_of(leaf), Some(hub_object));
    assert_eq!(h.exec.device_parent_of(hub_object), Some(BUS_OBJ));
    // And nothing mappable was created at any depth: the bound the hub
    // inherited is the one it passes on.
    assert_eq!(h.exec.mmio_of_object(leaf), None);
    assert_eq!(h.exec.config_of_object(leaf), None);
}

/// The narrowing survives the extra level. A grandchild claiming a register
/// window is refused exactly as a child claiming one is — otherwise a
/// controller could reach a mappable window by declaring one more hop.
#[test]
fn a_window_is_refused_at_every_depth_below_a_bus_that_forwards_nothing() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0, 0, 0);
    let mut h = windowless_bus_harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]);
    let (hub, _) = declare_record(&upage);

    let args = declare_args_on(&mut upage, hub, 0, 0x4000_0000, 0x1000);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// **The narrowing.** A bus that forwards nothing cannot declare a child
/// with a register window — otherwise the no-window case would be a way to
/// describe a bus with nothing to contain a window in, and then put one
/// there anyway.
#[test]
fn a_bus_that_forwards_nothing_cannot_declare_a_window() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0, 0x4000_0000, 0x1000);
    let mut h = windowless_bus_harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    let mut children = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
    assert_eq!(h.exec.device_children_of(BUS_OBJ, &mut children), 0);
}

/// A windowless device has nothing for `MapConfig` to answer with either,
/// and says so rather than mapping something adjacent.
#[test]
fn a_windowless_child_has_no_config_space_to_map() {
    let mut upage = UserPage([0; 4096]);
    let (args, _) = declare_args(&mut upage, 0, 0, 0);
    let mut h = windowless_bus_harness(
        &upage,
        Rights::READ | Rights::MAP | Rights::DERIVE | Rights::CONFIGURE,
    );
    run(&mut h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]);
    let (device, _) = declare_record(&upage);
    let args = map_config_args(&mut upage, device, 0x5000_0000);
    assert_eq!(
        run(&mut h, SyscallNumber::MapConfig, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::NotSupported)))
    );
}

/// Builds a `MapConfigArgs` for `handle` at `vaddr`.
fn map_config_args(upage: &mut UserPage, handle: u32, vaddr: u64) -> u64 {
    let at = 896;
    let args = crate::isl_binding::device::MapConfigArgs {
        size: syscall::MAP_CONFIG_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        device: tessera_isl_runtime::HandleRef::new(handle),
        reserved: 0,
        vaddr,
    };
    tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::MAP_CONFIG_ARGS_SIZE])
        .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// Declares a function and returns the handle it landed on.
fn declare_one(h: &mut Harness, upage: &mut UserPage, bdf: u32) -> u32 {
    let (args, _) = declare_args(upage, bdf, BUS_FORWARD_BASE, 0x1000);
    assert_eq!(
        run(h, SyscallNumber::DeviceDeclare, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    declare_record(upage).0
}

/// **One function wide, and the page after it is not there.** Configuration
/// space is one flat window per host bridge, so this is the whole of what
/// scoping means: the driver of the function in slot 0x18 cannot read the
/// one in slot 0x19 by adding 4096 to a pointer.
#[test]
fn config_space_is_mapped_one_function_wide() {
    let mut upage = UserPage([0; 4096]);
    let mut h = bus_harness(
        &upage,
        Rights::READ | Rights::MAP | Rights::DERIVE | Rights::CONFIGURE,
    );
    let device = declare_one(&mut h, &mut upage, 0x18);
    const AT: u64 = 0x5000_0000;
    let args = map_config_args(&mut upage, device, AT);
    assert_eq!(
        run(&mut h, SyscallNumber::MapConfig, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(AT as i64),
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (frame, _) = process
        .space()
        .arch()
        .translate(VirtAddr::new(AT))
        .expect("the slot is mapped");
    assert_eq!(frame.base().as_u64(), BUS_CONFIG_BASE + 0x18 * 4096);
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(AT + 4096))
            .is_none(),
        "and the next function's slot is not",
    );
}

/// `CONFIGURE` and not `MAP`: a driver may be trusted with a device's
/// registers and not with the register that turns on bus mastering.
#[test]
fn mapping_config_without_the_configure_right_is_denied() {
    let mut upage = UserPage([0; 4096]);
    let mut h = bus_harness(
        &upage,
        Rights::READ | Rights::MAP | Rights::DERIVE | Rights::CONFIGURE,
    );
    let device = declare_one(&mut h, &mut upage, 0x18);
    // Narrow the handle the way a controller hands a function on.
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .replace_rights(Handle::from_raw(device), Rights::READ | Rights::MAP)
            .expect("narrow");
    }
    let args = map_config_args(&mut upage, device, 0x5000_0000);
    assert_eq!(
        run(&mut h, SyscallNumber::MapConfig, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// A device nobody declared has no slot, and says so. Every device the
/// kernel registered itself is one of these — answering plainly beats
/// mapping whatever sits next to its registers.
#[test]
fn a_device_with_no_config_window_says_so() {
    let mut upage = UserPage([0; 4096]);
    let args = map_config_args(&mut upage, 0, 0x5000_0000);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::CONFIGURE);
    assert_eq!(
        run(&mut h, SyscallNumber::MapConfig, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::NotSupported)))
    );
}

// -----------------------------------------------------------------------
// WakeSource / WakeHold — what may wake this machine, and what stops it
// sleeping.
// -----------------------------------------------------------------------

/// Builds a `WakeSourceArgs` in the user page and returns its pointer.
fn wake_source_args(upage: &mut UserPage, handle: u32, arm: u32) -> u64 {
    let at = 768;
    upage.0[at..at + syscall::WAKE_SOURCE_ARGS_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&(syscall::WAKE_SOURCE_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
    upage.0[at + 20..at + 24].copy_from_slice(&arm.to_le_bytes());
    upage.0.as_ptr() as u64 + at as u64
}

/// Builds a `WakeHoldArgs` in the user page and returns its pointer.
fn wake_hold_args(upage: &mut UserPage, handle: u32, op: u32, ticks: u64) -> u64 {
    let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
    let at = 1024;
    upage.0[at..at + syscall::WAKE_HOLD_ARGS_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&(syscall::WAKE_HOLD_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
    upage.0[at + 20..at + 24].copy_from_slice(&op.to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&ticks.to_le_bytes());
    upage.0[at + 32..at + 40].copy_from_slice(&record_ptr.to_le_bytes());
    upage.0.as_ptr() as u64 + at as u64
}

/// Reads back a `WakeHoldRecord` as `(events, held, ticks)`.
fn wake_hold_record(upage: &UserPage) -> (u64, u32, u64) {
    let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::WAKE_HOLD_RECORD_SIZE];
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word"));
    let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("long"));
    (long(16), word(24), long(32))
}

/// The arming, end to end: a capability carrying `WAKE` over a device with
/// an interrupt makes that line able to wake the machine, and the graph is
/// where the answer lives.
#[test]
fn a_capability_with_wake_arms_the_line_it_names() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = wake_source_args(&mut upage, 0, 1);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
    let device = ObjectId::from_raw(21);
    h.exec.device_set_mmio_irq(device, 34).expect("intid");

    assert_eq!(
        run(&mut h, SyscallNumber::WakeSource, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    assert!(h.exec.is_wake_source(device));
    // And the interrupt bridge can find it by the line it arrives on,
    // which is the direction an interrupt actually comes from.
    assert_eq!(h.exec.record_wake(34), Some(device));
    assert_eq!(h.exec.wake_events(), 1);
}

/// Holding a device is not authority to let it wake the machine. Without
/// this, the set of things able to wake a device would be the driver
/// table — which nobody chose and nobody can audit.
#[test]
fn arming_a_wakeup_source_without_the_wake_right_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = wake_source_args(&mut upage, 0, 1);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(21);
    h.exec.device_set_mmio_irq(device, 34).expect("intid");

    assert_eq!(
        run(&mut h, SyscallNumber::WakeSource, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    assert!(!h.exec.is_wake_source(device), "and nothing was armed");
    assert_eq!(h.exec.record_wake(34), None, "so the line wakes nothing");
}

/// A device with no interrupt cannot be a wakeup source. Recorded, it
/// would look exactly like one that has not fired yet, and a machine that
/// suspended trusting it would never come back.
#[test]
fn arming_a_device_that_cannot_interrupt_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = wake_source_args(&mut upage, 0, 1);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);

    assert_eq!(
        run(&mut h, SyscallNumber::WakeSource, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidArgument)))
    );
    assert!(!h.exec.is_wake_source(ObjectId::from_raw(21)));
}

/// Disarming is not removal, and a line that was armed stops waking the
/// machine the moment it is disarmed — which is what makes runtime idle
/// reversible rather than one-way.
#[test]
fn disarming_stops_the_line_waking_the_machine() {
    let mut upage = UserPage([0; 4096]);
    let mut h = {
        let armed = wake_source_args(&mut upage, 0, 1);
        let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
        h.exec
            .device_set_mmio_irq(ObjectId::from_raw(21), 34)
            .expect("intid");
        run(&mut h, SyscallNumber::WakeSource, [armed, 0, 0, 0, 0, 0]);
        h
    };
    assert!(h.exec.is_wake_source(ObjectId::from_raw(21)));

    let disarm = wake_source_args(&mut upage, 0, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::WakeSource, [disarm, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    assert_eq!(h.exec.record_wake(34), None);
    // The counter is untouched by disarming: it counts events, and none
    // happened.
    assert_eq!(h.exec.wake_events(), 0);
}

/// The counter is readable, and a hold is taken and released under the
/// same right — a caller reads the count *in order to* decide whether to
/// hold, so splitting them would put a syscall in the middle of the race.
#[test]
fn a_hold_is_taken_released_and_the_counter_is_readable() {
    let mut upage = UserPage([0; 4096]);
    let mut h = {
        let query = wake_hold_args(&mut upage, 0, 3, 0);
        let mut h = harness(&upage, Rights::READ | Rights::WAKE);
        assert_eq!(
            run(&mut h, SyscallNumber::WakeHold, [query, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0)
        );
        h
    };
    let (events, held, _) = wake_hold_record(&upage);
    assert_eq!((events, held), (0, 0), "nothing has happened yet");

    let acquire = wake_hold_args(&mut upage, 0, 1, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::WakeHold, [acquire, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    assert_eq!(wake_hold_record(&upage).1, 1, "a hold is live");
    assert_eq!(h.exec.wake_holds_held(), 1);

    let release = wake_hold_args(&mut upage, 0, 2, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::WakeHold, [release, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    assert_eq!(wake_hold_record(&upage).1, 0);
    // Releasing one that was never taken is an answer, not an error: a
    // caller unwinding a path it is unsure it took must not have to
    // remember, and nothing is harmed by a hold going away twice.
    assert_eq!(
        run(&mut h, SyscallNumber::WakeHold, [release, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
}

/// A wake hold is a suspend blocker, so taking one must need the same
/// authority as saying what may wake the machine — the two halves of one
/// power authority.
#[test]
fn a_hold_without_the_wake_right_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let acquire = wake_hold_args(&mut upage, 0, 1, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    assert_eq!(
        run(&mut h, SyscallNumber::WakeHold, [acquire, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    assert_eq!(h.exec.wake_holds_held(), 0);
}

/// A wake through the syscall boundary: the counter moves, and the grace
/// hold it takes for itself vetoes a commit — which is what stops an event
/// arriving just after a resume from being swallowed by an immediate
/// re-suspend.
#[test]
fn a_wake_counts_and_holds_the_machine_awake_briefly() {
    let mut upage = UserPage([0; 4096]);
    let arm = wake_source_args(&mut upage, 0, 1);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
    h.exec
        .device_set_mmio_irq(ObjectId::from_raw(21), 34)
        .expect("intid");
    run(&mut h, SyscallNumber::WakeSource, [arm, 0, 0, 0, 0, 0]);

    h.exec.record_wake(34);
    let query = wake_hold_args(&mut upage, 0, 3, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::WakeHold, [query, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (events, held, _) = wake_hold_record(&upage);
    assert_eq!(events, 1, "the wake was counted");
    assert_eq!(held, 1, "and it holds the machine awake for a moment");
    // Attributed to the source rather than to nobody, so a machine that
    // will not sleep can name what is keeping it up.
    assert_eq!(h.exec.wake_hold_holder(), Some(ObjectId::from_raw(21)));
}

/// A line nobody armed is not a wake. Most interrupts on a running machine
/// are ordinary, and counting them would make the counter a number that
/// changes constantly and therefore says nothing.
#[test]
fn an_unarmed_line_is_not_a_wake() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
    h.exec
        .device_set_mmio_irq(ObjectId::from_raw(21), 34)
        .expect("intid");
    assert_eq!(h.exec.record_wake(34), None);
    assert_eq!(h.exec.record_wake(99), None);
    assert_eq!(h.exec.wake_events(), 0);
    assert_eq!(h.exec.wake_holds_held(), 0);
}

// -----------------------------------------------------------------------
// SystemSuspend — the final commit.
// -----------------------------------------------------------------------

/// Builds a `SystemSuspendArgs` in the user page and returns its pointer.
fn suspend_args(upage: &mut UserPage, handle: u32, snapshot: u64) -> u64 {
    let record_ptr = upage.0.as_ptr() as u64 + RECORD_AT as u64;
    let at = 1280;
    upage.0[at..at + syscall::SYSTEM_SUSPEND_ARGS_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&(syscall::SYSTEM_SUSPEND_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&snapshot.to_le_bytes());
    upage.0[at + 32..at + 40].copy_from_slice(&record_ptr.to_le_bytes());
    upage.0.as_ptr() as u64 + at as u64
}

/// Reads back a `SystemSuspendRecord` as `(status, events, source)`.
fn suspend_record(upage: &UserPage) -> (u32, u64, u64) {
    let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::SYSTEM_SUSPEND_RECORD_SIZE];
    let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("word"));
    let long = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("long"));
    (word(16), long(24), long(32))
}

/// **The lost-wakeup race, closed by counting.** A snapshot taken before a
/// wake and presented after it does not match, and the entry aborts —
/// which is the whole mechanism, since whether the event arrived before,
/// during or after the snapshot cannot be established any other way.
#[test]
fn a_stale_snapshot_aborts_the_commit() {
    let mut upage = UserPage([0; 4096]);
    let arm = wake_source_args(&mut upage, 0, 1);
    let mut h = harness(
        &upage,
        Rights::READ | Rights::MAP | Rights::WAKE | Rights::SLEEP,
    );
    h.exec
        .device_set_mmio_irq(ObjectId::from_raw(21), 34)
        .expect("intid");
    run(&mut h, SyscallNumber::WakeSource, [arm, 0, 0, 0, 0, 0]);

    let snapshot = h.exec.wake_events();
    h.exec.record_wake(34);

    let args = suspend_args(&mut upage, 0, snapshot);
    assert_eq!(
        run(&mut h, SyscallNumber::SystemSuspend, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
        "the call answers rather than failing — an abort is an outcome",
    );
    let (status, events, source) = suspend_record(&upage);
    assert_eq!(status, 2, "SuspendOutcome::WAKE_ARRIVED");
    assert_eq!(events, snapshot + 1);
    assert_eq!(source, 0);
}

/// A wake hold vetoes the commit, and the refusal names the holder — a
/// machine that will not sleep must be able to say what is keeping it up.
#[test]
fn a_wake_hold_vetoes_the_commit_and_names_its_holder() {
    let mut upage = UserPage([0; 4096]);
    let acquire = wake_hold_args(&mut upage, 0, 1, 0);
    let mut h = harness(&upage, Rights::READ | Rights::WAKE | Rights::SLEEP);
    run(&mut h, SyscallNumber::WakeHold, [acquire, 0, 0, 0, 0, 0]);

    let args = suspend_args(&mut upage, 0, h.exec.wake_events());
    assert_eq!(
        run(&mut h, SyscallNumber::SystemSuspend, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let (status, _, source) = suspend_record(&upage);
    assert_eq!(status, 3, "SuspendOutcome::VETOED");
    assert_ne!(source, 0, "and it says who");
}

/// Stopping the machine and saying what may interrupt it are opposite
/// authorities: `WAKE` is not enough.
#[test]
fn committing_without_the_sleep_right_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let args = suspend_args(&mut upage, 0, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::WAKE);
    assert_eq!(
        run(&mut h, SyscallNumber::SystemSuspend, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

// -----------------------------------------------------------------------
// Suspend ordering — leaves before parents, enforced against the graph.
// -----------------------------------------------------------------------

/// Brings `device` up to `Active` the way a device manager would.
fn bring_up(h: &mut Harness, device: ObjectId) {
    use crate::lifecycle::{DriverState as S, TransitionReason as R};
    for (from, to) in [
        (S::Discovered, S::Matched),
        (S::Matched, S::Starting),
        (S::Starting, S::Probing),
        (S::Probing, S::Active),
    ] {
        h.exec
            .declare_lifecycle(device, from, to, R::Bound, 0)
            .expect("bring up");
    }
}

/// **Leaves before parents, and the kernel is what says so.** A manager
/// whose walk is wrong would otherwise produce a perfectly legal record of
/// a bus powered down under a live device, and nothing downstream could
/// tell.
#[test]
fn a_bus_cannot_suspend_under_a_live_device() {
    use crate::lifecycle::{DriverState as S, TransitionError, TransitionReason as R};
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let parent = ObjectId::from_raw(21);
    let children = children_behind(&mut h, parent, 1);
    bring_up(&mut h, parent);
    bring_up(&mut h, children[0]);

    assert_eq!(
        h.exec
            .declare_lifecycle(parent, S::Active, S::Suspending, R::Power, 0),
        Err(TransitionError::OutOfOrder {
            neighbour: children[0],
            state: S::Active,
        }),
    );
    // Refused means unchanged: the bus is still in service, so a manager
    // that ignored the answer would not find its own belief confirmed.
    assert_eq!(h.exec.lifecycle_of_object(parent), Some(S::Active));

    // In the right order both go.
    h.exec
        .declare_lifecycle(children[0], S::Active, S::Suspending, R::Power, 0)
        .expect("child suspending");
    h.exec
        .declare_lifecycle(children[0], S::Suspending, S::Suspended, R::Power, 0)
        .expect("child suspended");
    h.exec
        .declare_lifecycle(parent, S::Active, S::Suspending, R::Power, 0)
        .expect("now the bus may go");
}

/// The mirror, which is the half a manager is most likely to get wrong:
/// resume runs parent-first, because a leaf coming up through a bus that is
/// still down would be a driver talking to nothing.
#[test]
fn a_device_cannot_resume_through_a_suspended_bus() {
    use crate::lifecycle::{DriverState as S, TransitionError, TransitionReason as R};
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let parent = ObjectId::from_raw(21);
    let children = children_behind(&mut h, parent, 1);
    bring_up(&mut h, parent);
    bring_up(&mut h, children[0]);
    for device in [children[0], parent] {
        h.exec
            .declare_lifecycle(device, S::Active, S::Suspending, R::Power, 0)
            .expect("suspending");
        h.exec
            .declare_lifecycle(device, S::Suspending, S::Suspended, R::Power, 0)
            .expect("suspended");
    }

    assert_eq!(
        h.exec
            .declare_lifecycle(children[0], S::Suspended, S::Resuming, R::Power, 0),
        Err(TransitionError::OutOfOrder {
            neighbour: parent,
            state: S::Suspended,
        }),
    );
    // Parent first, and then the leaf may follow.
    h.exec
        .declare_lifecycle(parent, S::Suspended, S::Resuming, R::Power, 0)
        .expect("bus resuming");
    h.exec
        .declare_lifecycle(parent, S::Resuming, S::Active, R::Power, 0)
        .expect("bus back");
    h.exec
        .declare_lifecycle(children[0], S::Suspended, S::Resuming, R::Power, 0)
        .expect("now the leaf may follow");
}

/// Registers `count` children behind the harness' device and returns their
/// ids.
fn children_behind(h: &mut Harness, parent: ObjectId, count: usize) -> [ObjectId; 2] {
    let ids = [0x81, 0x82].map(ObjectId::from_raw);
    for id in ids.iter().take(count) {
        h.exec
            .device_register_mmio(
                *id,
                0x0a00_9000 + 0x1000 * (id.raw() as u64 & 0xf),
                FRAME_SIZE,
                Rights::READ | Rights::MAP,
            )
            .expect("register");
        h.exec.device_set_parent(*id, parent).expect("edge");
    }
    ids
}

/// The grant a bus controller could get from nowhere else: the manager does
/// not know what is behind a bus only the controller's capability names.
#[test]
fn a_controller_derives_a_capability_to_the_device_behind_its_bus() {
    let mut upage = UserPage([0; 4096]);
    let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    let parent = ObjectId::from_raw(21);
    let children = children_behind(&mut h, parent, 2);

    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [args_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0)
    );
    let (count, child, rights) = device_child_record(&upage);
    assert_eq!(count, 2, "both devices on the bus");
    assert_ne!(child, HANDLE_NOT_INSTALLED, "a capability was installed");

    // The handle names the first child, and nothing the caller supplied
    // could have chosen it — the id came from the graph's own edges.
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, held) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(child))
        .expect("the derived handle resolves");
    assert_eq!(object, children[0]);

    // **The graph's record for the child, not a narrowing of the bus's.**
    // The child was registered READ|MAP and that is what came back — the
    // parent's TRANSFER is not on it, and MAP would not be there at all if
    // the rights had been inherited from a bus that has no business
    // holding MAP over its own window.
    assert!(held.contains(Rights::MAP), "usable as a device");
    assert!(
        !held.contains(Rights::TRANSFER),
        "the bus's rights are not the child's",
    );
    assert_eq!(rights, held.bits(), "the record echoes what was installed");
}

/// Holding a bus is not by itself authority to hand out what is on it — a
/// controller may be granted a bus to drive without being made its broker.
#[test]
fn deriving_without_the_derive_right_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let parent = ObjectId::from_raw(21);
    children_behind(&mut h, parent, 1);

    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [args_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// A bus with nothing on it is an ordinary bus, and an index past the end
/// is an ordinary answer. Reported as a distinguished handle rather than
/// zero, because zero is a legitimate handle number.
#[test]
fn asking_past_the_end_of_a_bus_answers_rather_than_fails() {
    let mut upage = UserPage([0; 4096]);
    let (args_ptr, _) = device_child_args(&mut upage, 0, 3);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    children_behind(&mut h, ObjectId::from_raw(21), 1);

    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [args_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0)
    );
    let (count, child, _) = device_child_record(&upage);
    assert_eq!(count, 1);
    assert_eq!(child, HANDLE_NOT_INSTALLED);
}

/// A leaf answers zero children — which is how a controller discovers it is
/// not one, without a second syscall to ask.
#[test]
fn a_device_with_nothing_behind_it_answers_a_count_of_zero() {
    let mut upage = UserPage([0; 4096]);
    let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);

    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [args_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0)
    );
    let (count, child, _) = device_child_record(&upage);
    assert_eq!(count, 0);
    assert_eq!(child, HANDLE_NOT_INSTALLED);
}

/// **A controller can walk a subtree that has a switch in it.** Stopping at
/// one level would make the deepest thing a bus controller could reach its
/// immediate children — on the topology this milestone added, the switch's
/// upstream port and nothing beyond it. Containment is the edge, not
/// attenuation.
#[test]
fn a_derived_capability_keeps_walking_down_the_subtree() {
    let mut upage = UserPage([0; 4096]);
    let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    let parent = ObjectId::from_raw(21);
    let children = children_behind(&mut h, parent, 1);
    // A grandchild, so there is something for a second derive to find.
    let grandchild = ObjectId::from_raw(0x8a);
    h.exec
        .device_register_mmio(grandchild, 0x0a00_b000, FRAME_SIZE, Rights::READ)
        .expect("register");
    h.exec
        .device_set_parent(grandchild, children[0])
        .expect("edge");

    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [args_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0)
    );
    let (_, child, _) = device_child_record(&upage);

    // Now ask the *derived* handle for its own child — the grandchild.
    let (second_args, _) = device_child_args(&mut upage, child, 0);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [second_args, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0),
    );
    let (count, deeper, _) = device_child_record(&upage);
    assert_eq!(count, 1);
    assert_ne!(deeper, HANDLE_NOT_INSTALLED);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, _) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(deeper))
        .expect("the grandchild resolves");
    assert_eq!(object, grandchild, "two levels down from where it started");
}

/// And what *does* stop a driver brokering: it never held `DERIVE`. A
/// controller hands a device on over a channel, where rights narrow on
/// transfer (D113), and what arrives cannot walk anywhere.
#[test]
fn a_device_handed_on_without_derive_brokers_nothing() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let parent = ObjectId::from_raw(21);
    children_behind(&mut h, parent, 1);
    // The shape a driver is in: it holds the bus, but was handed it without
    // the authority to hand anything on.
    let (args_ptr, _) = device_child_args(&mut upage, 0, 0);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [args_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// The right bit on some other object must not be a lever on whatever the
/// graph happens to root at that id.
#[test]
fn deriving_from_something_that_is_not_a_device_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::DERIVE);
    let not_a_device = ObjectId::from_raw(0x400);
    let handle = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(not_a_device, Rights::READ | Rights::DERIVE)
            .expect("install")
            .raw()
    };
    let (args_ptr, _) = device_child_args(&mut upage, handle, 0);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceChild,
            [args_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType)))
    );
}

/// A virtio-mmio transport has no identity in the graph — it says what it
/// is in its own registers. `UNKNOWN` is the answer, not an error: a
/// manager's response is to map it and read them.
#[test]
fn a_device_with_no_recorded_identity_answers_unknown() {
    let mut upage = UserPage([0; 4096]);
    let (args_ptr, _) = device_info_args(&mut upage, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    assert_eq!(
        run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    // The record landed in the user page, which is ordinary memory this
    // test owns — reading it back needs no raw pointer.
    let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_INFO_RECORD_SIZE];
    let word =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    assert_eq!(word(0), syscall::DEVICE_INFO_RECORD_SIZE as u32);
    // kind == UNKNOWN (0)
    assert_eq!(word(16), 0);
    // And no layout, which is the honest answer for a device whose
    // structures the kernel never resolved — not zeroes that a driver
    // might read as offsets, but a flag saying there is nothing here.
    assert_eq!(word(44), 0, "layout_valid");
}

/// **Where the device's structures are, handed back to a holder.**
///
/// The last thing between a granted register window and a driver able to
/// use it. A virtio-pci function says where its controls are in config
/// space, and config space is not per-device — no capability to it can be
/// handed out — so a driver holding the right window had no way to find
/// anything in it. The kernel reads it while enumerating, and this is how
/// a capability holder asks.
///
/// The offsets are relative to the granted window and never absolute: the
/// first is usable by a process that mapped a capability, and the second
/// is a fact about the machine no driver should be given.
#[test]
fn a_holder_is_told_where_its_devices_structures_are() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(23);
    h.exec
        .device_register_identified(
            device,
            0x4000_0000,
            FRAME_SIZE,
            Rights::READ | Rights::MAP,
            crate::devmgr::DeviceIdentity {
                revision: 1,
                bus: crate::devmgr::DeviceBus::Pci,
                class_code: 0x01_00_00,
                vendor: 0x1af4,
                device: 0x1042,
                bdf: 0x08,
            },
        )
        .expect("register");
    h.exec
        .device_set_layout(
            device,
            crate::devmgr::DeviceLayout {
                common: 0,
                notify: 0x3000,
                notify_multiplier: 4,
                isr: 0x1000,
                device_config: 0x2000,
            },
        )
        .expect("layout");
    let handle = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(device, Rights::READ)
            .expect("install")
    };
    let (args_ptr, _) = device_info_args(&mut upage, handle.raw());
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );

    let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_INFO_RECORD_SIZE];
    let word =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    assert_eq!(word(36), 1, "the revision — a binding input of its own");
    assert_eq!(word(40), 1, "bus = PCI");
    assert_eq!(word(44), 1, "layout_valid");
    // Offset zero is a real offset. `layout_valid` is what distinguishes
    // a structure at the start of the window from no structure at all,
    // and a driver that inferred otherwise would refuse to drive exactly
    // the devices that work.
    assert_eq!(word(48), 0, "common");
    assert_eq!(word(52), 0x3000, "notify");
    assert_eq!(word(56), 4, "notify multiplier");
    assert_eq!(word(60), 0x1000, "isr");
    assert_eq!(word(64), 0x2000, "device config");
}

/// What the kernel learned enumerating a bus, handed back to a holder.
#[test]
fn an_enumerated_device_reports_the_identity_the_kernel_recorded() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // Register a second device carrying an identity, as a PCI walk does.
    h.exec
        .device_register_identified(
            ObjectId::from_raw(22),
            0x4000_0000,
            FRAME_SIZE,
            Rights::READ | Rights::MAP,
            crate::devmgr::DeviceIdentity {
                revision: 3,
                bus: crate::devmgr::DeviceBus::Pci,
                class_code: 0x01_08_00,
                vendor: 0x1af4,
                device: 0x1042,
                bdf: 0x0100,
            },
        )
        .expect("register");
    let handle = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ObjectId::from_raw(22), Rights::READ)
            .expect("install")
    };
    let (args_ptr, _) = device_info_args(&mut upage, handle.raw());

    assert_eq!(
        run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0)
    );
    let bytes = &upage.0[RECORD_AT..RECORD_AT + syscall::DEVICE_INFO_RECORD_SIZE];
    let word =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    assert_eq!(word(16), 1, "kind == PCI");
    assert_eq!(word(20), 0x01_08_00, "class code");
    assert_eq!(word(24), 0x1af4, "vendor");
    assert_eq!(word(28), 0x1042, "device");
}

/// Asking about something that is not a device is a type error, not a
/// record full of zeros that reads like a real answer.
#[test]
fn asking_about_a_non_device_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let handle = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ObjectId::from_raw(0x99), Rights::READ)
            .expect("install")
    };
    let (args_ptr, _) = device_info_args(&mut upage, handle.raw());
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceInfo, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType)))
    );
}

/// A device with no aperture gets a physical address, and the system is
/// told so. The grant is legitimate — a machine may have no IOMMU — but an
/// unscoped grant must not read like a scoped one.
#[test]
fn an_unscoped_dma_grant_says_that_it_is_unscoped() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4001_0000);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    let _guard = event_ring_guard();
    run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

    let events = drained_device_events();
    assert!(
        events
            .iter()
            .any(|e| e.kind == crate::event::EventKind::DeviceDmaGranted),
        "the grant itself is recorded"
    );
    let unscoped = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceDmaUnscoped)
        .expect("an unscoped grant must say so");
    assert_eq!(unscoped.severity, crate::event::Severity::Warning);
}

/// Puts the harness device behind an IOMMU whose leases run `[base, len)`.
///
/// No lease is created here, and that is the point: a device is *scoped*
/// because of how the machine is wired, and *leased* because a driver asked
/// it for DMA. Pre-installing one would hide every question about when a
/// lease begins.
fn scoped(h: &mut Harness, base: u64, len: u64) {
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(HARNESS_DEVICE as u32),
        base,
        len,
    ));
}

/// The VA the DMA tests ask for their buffer at.
const DMA_TEST_VA: u64 = 0x4001_0000;

/// The same grant for a device that *does* have an aperture carries no
/// such record — otherwise the report would be noise rather than a
/// distinction.
#[test]
fn a_scoped_dma_grant_carries_no_unscoped_report() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 0x1000);

    let _guard = event_ring_guard();
    run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

    let events = drained_device_events();
    assert!(
        !events
            .iter()
            .any(|e| e.kind == crate::event::EventKind::DeviceDmaUnscoped)
    );
    let scoped = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceDmaScoped)
        .expect("a scoped grant says so positively, not by staying silent");
    assert_eq!(scoped.arg1, DMA_TEST_VA, "the user VA");
    assert_eq!(scoped.arg2, 0x8000_0000, "the IOVA the device sees");
    assert_ne!(
        scoped.arg2, scoped.arg3,
        "the device's address is not the physical one — that is what translating means",
    );
}

/// The claim this whole seam exists for: a driver on a device with an
/// aperture is handed an **IOVA**, and it is an IOVA the IOMMU was
/// actually told about. Checking the return value alone would pass for an
/// implementation that allocated an address and installed nothing.
#[test]
fn a_scoped_device_returns_an_iova_the_iommu_was_given() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 0x2000);

    let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
    let DispatchOutcome::Return(iova) = outcome else {
        panic!("dma_alloc not covered");
    };
    assert_eq!(iova, 0x8000_0000, "the first address in the aperture");

    let phys = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .space()
        .arch()
        .translate(VirtAddr::new(DMA_TEST_VA))
        .expect("the buffer is mapped")
        .0
        .base()
        .as_u64();
    assert_eq!(
        h.iommu.as_ref().expect("iommu").installed,
        std::vec![(
            ObjectId::from_raw(HARNESS_DEVICE as u32),
            0x8000_0000,
            phys,
            FRAME_SIZE
        )],
        "the IOVA handed back names the buffer's page, for that device only",
    );
}

/// A device with a **live lease**, reached on a path that has lost its
/// IOMMU, is a refusal. Its translations exist right now, so answering with
/// a physical address would answer a request for a scoped buffer with an
/// unscoped one — and the caller has no way to tell.
#[test]
fn a_leased_device_with_no_iommu_in_hand_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 0x2000);

    // One good grant, so a lease is live.
    let first = device_args(&mut upage, 0, DMA_TEST_VA);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(0x8000_0000)))
    );

    h.iommu = None;
    let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping)))
    );
    assert!(
        h.processes
            .process_of_thread(h.caller)
            .expect("process")
            .space()
            .arch()
            .translate(VirtAddr::new(DMA_TEST_VA + FRAME_SIZE))
            .is_none(),
        "a refusal leaves no buffer behind",
    );
}

/// A device behind nothing is not scoped, and the grant says so rather
/// than refusing — the state of every device on four of the five ports.
#[test]
fn a_device_behind_no_iommu_is_unscoped_not_refused() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // An IOMMU exists, but this device is not behind it.
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(0x99),
        0x8000_0000,
        0x1000,
    ));

    let _guard = event_ring_guard();
    let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
    let DispatchOutcome::Return(addr) = outcome else {
        panic!("dma_alloc not covered");
    };
    assert!(addr > 0, "a physical address, not a refusal");
    assert!(
        drained_device_events()
            .iter()
            .any(|e| e.kind == crate::event::EventKind::DeviceDmaUnscoped)
    );
    assert!(h.iommu.as_ref().expect("iommu").began.is_empty());
}

/// An IOMMU that cannot describe the range refuses too, and the buffer
/// comes back down with it — a driver that retries must not lose a frame
/// per attempt.
#[test]
fn an_iommu_that_refuses_leaves_no_buffer_behind() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 0x1000);
    h.iommu = Some(MockMapper {
        refuses: true,
        ..MockMapper::over(
            ObjectId::from_raw(HARNESS_DEVICE as u32),
            0x8000_0000,
            0x1000,
        )
    });

    let mapped_before = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .space()
        .mapping_count();
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping)))
    );
    assert_eq!(
        h.processes
            .process_of_thread(h.caller)
            .expect("process")
            .space()
            .mapping_count(),
        mapped_before,
        "the page mapped before the refusal was reclaimed",
    );
}

/// A refusal records **no grant**. `DEVICE_DMA_GRANTED` means a driver is
/// holding a buffer, not that one was attempted — an audit that cannot
/// tell those apart counts grants that never happened, and would see a
/// grant here with neither a scoped nor an unscoped record after it.
#[test]
fn a_refused_grant_is_not_recorded_as_a_grant() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper {
        refuses: true,
        ..MockMapper::over(
            ObjectId::from_raw(HARNESS_DEVICE as u32),
            0x8000_0000,
            0x1000,
        )
    });

    let _guard = event_ring_guard();
    run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

    let events = drained_device_events();
    assert!(
        !events
            .iter()
            .any(|e| e.kind == crate::event::EventKind::DeviceDmaGranted),
        "nothing was granted",
    );
}

/// A lease begins on the **first** grant and is reused by the next — one
/// lease per driver, not one per buffer. A mapper told to begin twice would
/// be re-configuring the device's translation under a driver mid-flight.
#[test]
fn the_first_grant_begins_a_lease_and_the_second_reuses_it() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 0x2000);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    assert_eq!(h.exec.lease_holder_of_object(device), None, "none yet");

    let first = device_args(&mut upage, 0, DMA_TEST_VA);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(0x8000_0000)))
    );
    let holder = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .id();
    assert_eq!(h.exec.lease_holder_of_object(device), Some(holder));

    let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(0x8000_1000)))
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").began,
        std::vec![device],
        "one lease, two buffers",
    );
}

/// A second process holding a handle to the same device cannot allocate out
/// of the first's lease. Without this its buffers would vanish when the
/// *other* process gave the device up — a lease that guarantees nothing.
#[test]
fn a_process_that_does_not_hold_the_lease_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 0x2000);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);

    let first = device_args(&mut upage, 0, DMA_TEST_VA);
    run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]);

    // Someone else already holds it.
    h.exec
        .device_set_aperture(
            device,
            ObjectId::from_raw(0xfeed),
            crate::devmgr::DeviceAperture::new(0x8000_0000, 0x2000),
            None,
        )
        .expect("re-hold");

    let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// A dying holder loses its lease, and the mapper is told — the route a
/// register window does not have, because a window dies with the address
/// space and a translation in an IOMMU does not.
#[test]
fn a_dying_holder_loses_its_lease() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, DMA_TEST_VA);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 0x2000);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);

    let _guard = event_ring_guard();
    let Harness {
        exec,
        processes,
        iommu,
        caller,
        ..
    } = &mut h;
    let process = processes.process_of_thread(*caller).expect("process");
    let ended = exec.end_device_leases(process, iommu.as_mut().map(|m| m as &mut dyn DmaMapper));

    assert_eq!(ended, 1);
    assert_eq!(h.iommu.as_ref().expect("iommu").ended, std::vec![device]);
    assert!(
        h.iommu.as_ref().expect("iommu").installed.is_empty(),
        "its translations went with it",
    );
    assert_eq!(h.exec.lease_holder_of_object(device), None);
    let record = drained_device_events()
        .into_iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceDmaLeaseEnded)
        .expect("the end of a lease is recorded");
    assert_eq!(
        record.arg2,
        crate::devmgr::LeaseEndReason::HolderGone as u64
    );
}

/// **The D120 unlock.** A lease that ends returns its addresses, so the
/// next driver starts from the same base rather than from wherever its
/// predecessor stopped. Without the intervening end, a rebound driver
/// would exhaust the window a few restarts in.
#[test]
fn the_next_lease_reuses_the_addresses_the_last_one_spent() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, 2 * FRAME_SIZE);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);

    // Spend the whole lease.
    let a = device_args(&mut upage, 0, DMA_TEST_VA);
    run(&mut h, SyscallNumber::DmaAlloc, [a, 0, 0, 0, 0, 0]);
    let b = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
    run(&mut h, SyscallNumber::DmaAlloc, [b, 0, 0, 0, 0, 0]);
    let c = device_args(&mut upage, 0, DMA_TEST_VA + 2 * FRAME_SIZE);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [c, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::OutOfMemory))),
        "spent",
    );

    {
        let Harness {
            exec,
            processes,
            iommu,
            caller,
            ..
        } = &mut h;
        let process = processes.process_of_thread(*caller).expect("process");
        exec.end_device_leases(process, iommu.as_mut().map(|m| m as &mut dyn DmaMapper));
    }

    let d = device_args(&mut upage, 0, DMA_TEST_VA + 3 * FRAME_SIZE);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [d, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(0x8000_0000))),
        "the new lease reissues the old lease's first address",
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").began,
        std::vec![device, device],
        "and it is a second lease, not a continuation of the first",
    );
}

/// A spent aperture is out of memory, not a licence to hand back a
/// physical address. D120 made "no aperture" and "aperture exhausted"
/// distinguishable in the graph; this is the behaviour that distinction
/// exists for.
#[test]
fn a_spent_aperture_refuses_rather_than_falling_back() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    scoped(&mut h, 0x8000_0000, FRAME_SIZE);

    let first = device_args(&mut upage, 0, DMA_TEST_VA);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [first, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(0x8000_0000)))
    );
    let second = device_args(&mut upage, 0, DMA_TEST_VA + FRAME_SIZE);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAlloc, [second, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::OutOfMemory)))
    );
    assert_eq!(
        h.iommu.as_ref().expect("iommu").installed.len(),
        1,
        "nothing was installed for the refused call",
    );
}

/// A granted register window is a record, not just a return value
/// (docs/drivers/01: lifecycle transitions are observable through
/// structured events). It carries both names for the window — the user VA
/// the driver got and the physical base the capability authorized — so the
/// grant can be audited without trusting the driver's account of it.
#[test]
fn a_granted_device_window_is_recorded() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    let _guard = event_ring_guard();
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    let events = drained_device_events();
    let grant = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceWindowMapped)
        .expect("the grant was not recorded");
    assert_eq!(grant.arg1, 0x4000_0000, "the user VA the driver was given");
    // The harness registers the window at 0x0a00_3e00, which is not page
    // aligned — the record names the *page* that was mapped.
    assert_eq!(grant.arg2, 0x0a00_3000, "the physical page base");
    assert_eq!(grant.arg3, FRAME_SIZE, "the graph's window length");
    assert_eq!(grant.severity, crate::event::Severity::Info);
}

/// A refusal is the capability system working, and it used to leave no
/// kernel record at all — the caller got an errno and the machine forgot.
/// The record names the error as a stable domain value, never a string.
#[test]
fn a_refused_device_mapping_is_recorded_with_its_error() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    // READ without MAP: the handle names the device but carries no
    // authority to map it.
    let mut h = harness(&upage, Rights::READ);

    let _guard = event_ring_guard();
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    let events = drained_device_events();
    let refusal = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceMapRefused)
        .expect("the refusal was not recorded");
    assert_eq!(refusal.arg1, KError::AccessDenied as u64);
    assert_eq!(refusal.arg2, 0x4000_0000, "the VA that was asked for");
    assert_eq!(refusal.severity, crate::event::Severity::Warning);
    // And nothing claimed a grant.
    assert!(
        !events
            .iter()
            .any(|e| e.kind == crate::event::EventKind::DeviceWindowMapped)
    );
}

/// The revocation record says which of the two routes the capability left
/// by — the distinction `revoke_device_windows_unless_held` documents but
/// could not previously report. A transfer and a close are different
/// events with the same effect, and an auditor needs to tell them apart.
#[test]
fn a_revoked_window_records_the_route_the_capability_left_by() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    let _guard = event_ring_guard();
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

    let events = drained_device_events();
    let revoke = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceWindowRevoked)
        .expect("the revocation was not recorded");
    assert_eq!(revoke.arg1, 0x4000_0000, "the VA that came down");
    assert_eq!(
        revoke.arg2,
        crate::process::WindowRevokeReason::Transferred as u64
    );
    assert_eq!(revoke.arg3, 0, "the page came down cleanly");
}

/// Handing the capability on ends the lease with it. The register window
/// and the DMA lease follow the same departure, and the sender must not
/// keep either — otherwise a driver that gave its device away could still
/// reach memory through it.
#[test]
fn transferring_the_capability_ends_the_lease() {
    let mut upage = UserPage([0; 4096]);
    let dma_args = device_args(&mut upage, 0, DMA_TEST_VA);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    scoped(&mut h, 0x8000_0000, 0x2000);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    run(&mut h, SyscallNumber::DmaAlloc, [dma_args, 0, 0, 0, 0, 0]);
    assert!(h.exec.lease_holder_of_object(device).is_some());

    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let (_msg, departed) =
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: h.iommu.as_mut().map(|m| m as &mut dyn DmaMapper),
            irqs: h
                .irqs
                .as_mut()
                .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
        };
        end_bindings_of_departed(&mut env, &departed);
    }

    assert_eq!(h.exec.lease_holder_of_object(device), None);
    assert_eq!(h.iommu.as_ref().expect("iommu").ended, std::vec![device]);
    assert!(h.iommu.as_ref().expect("iommu").installed.is_empty());
}

/// Handing the capability on takes the **interrupt route** with it too.
///
/// This is the third thing that follows a capability out, and the one with
/// the least in common with the other two. A register window dies with the
/// address space; a DMA lease lives in the IOMMU; a route lives in the
/// interrupt controller *and* in the kernel's own port table, and both
/// outlive the sender completely. Left standing, it keeps waking a port
/// whose holder no longer has any authority over the device.
#[test]
fn transferring_the_capability_ends_the_interrupt_route() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    h.irqs = Some(MockRouter::default());
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    h.exec.device_set_mmio_irq(device, 79).expect("irq");
    let port = h.exec.port_create().expect("port");
    let holder = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .id();
    h.exec
        .device_route_irq(device, port, holder)
        .expect("route");
    assert_eq!(h.exec.port_signal(79, crate::exec::IRQ_PORT_SIGNAL, 1), 1);

    let handles_ptr = write_transfer(&mut upage, 0, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let (_msg, departed) =
        build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");
    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: None,
            irqs: h
                .irqs
                .as_mut()
                .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
        };
        end_bindings_of_departed(&mut env, &departed);
    }

    assert_eq!(h.exec.irq_route_of_object(device), None);
    assert_eq!(
        h.irqs.as_ref().expect("router").masked,
        std::vec![79],
        "the controller stopped delivering, not just the graph",
    );
    // And the port no longer receives the line at all.
    assert_eq!(h.exec.port_signal(79, crate::exec::IRQ_PORT_SIGNAL, 1), 0);

    let events = drained_device_events();
    let revoked = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceIrqRevoked)
        .expect("the revocation was not recorded");
    assert_eq!(revoked.arg1, 79);
    assert_eq!(
        revoked.arg2,
        crate::devmgr::RouteEndReason::Transferred as u64
    );
}

/// A dying driver's route goes with it. Nothing else can take it down: the
/// process's handle table is reclaimed in bulk, so by teardown there is
/// nobody left to ask what it was receiving — which is why the graph
/// records the holder rather than deriving it.
#[test]
fn a_dead_holders_interrupt_route_is_swept_up() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.irqs = Some(MockRouter::default());
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    h.exec.device_set_mmio_irq(device, 79).expect("irq");
    let port = h.exec.port_create().expect("port");
    let holder = h
        .processes
        .process_of_thread(h.caller)
        .expect("process")
        .id();
    h.exec
        .device_route_irq(device, port, holder)
        .expect("route");

    let Harness {
        mut exec,
        mut processes,
        mut irqs,
        caller,
        ..
    } = h;
    {
        let process = processes.process_of_thread(caller).expect("process");
        assert_eq!(
            exec.end_device_irq_routes(
                process,
                irqs.as_mut()
                    .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
            ),
            1,
        );
    }
    assert_eq!(exec.irq_route_of_object(device), None);
    assert_eq!(irqs.as_ref().expect("router").masked, std::vec![79]);
    let events = drained_device_events();
    let revoked = events
        .iter()
        .find(|e| e.kind == crate::event::EventKind::DeviceIrqRevoked)
        .expect("the revocation was not recorded");
    assert_eq!(
        revoked.arg2,
        crate::devmgr::RouteEndReason::HolderGone as u64
    );
}

/// A process that duplicated its device capability and gave one copy away
/// still holds the authority, so it keeps the window — and emits nothing,
/// because nothing was revoked. A record here would be a false report of a
/// revocation that did not happen.
#[test]
fn keeping_the_authority_records_no_revocation() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    let handles_ptr = write_transfer(&mut upage, 1, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
    // A second handle to the same device — handle 1, the one transferred.
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let (object, rights) = process
            .handles()
            .lookup(Handle::from_raw(0))
            .expect("device handle");
        let duplicate = process.handles_mut().install(object, rights).expect("dup");
        assert_eq!(duplicate.raw(), 1);
    }

    let _guard = event_ring_guard();
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

    let events = drained_device_events();
    assert!(
        !events
            .iter()
            .any(|e| e.kind == crate::event::EventKind::DeviceWindowRevoked),
        "reported a revocation while the process still held the authority"
    );
}

/// A process that duplicated its device capability and gave one copy away
/// still holds the authority, so it keeps the window. Revocation asks
/// whether the *capability* left the table, not whether a handle did.
#[test]
fn transferring_one_of_two_handles_to_a_device_keeps_the_window() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    // The duplicate lands at handle 1; transfer that one.
    let handles_ptr = write_transfer(&mut upage, 1, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    let device = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let (object, rights) = process
            .handles()
            .lookup(crate::handle::Handle::from_raw(0))
            .expect("device handle");
        let duplicate = process.handles_mut().install(object, rights).expect("dup");
        assert_eq!(duplicate.raw(), 1);
        object
    };

    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process.handles().holds(device),
        "the original handle remains"
    );
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4000_0000))
            .is_some(),
        "a process that still holds the capability lost its window"
    );
    assert_eq!(process.device_window_count(), 1);
}

/// A window that is *not* transferred stays exactly where it was — the
/// revocation must key on the capability that moved, not fire on any
/// transfer at all.
#[test]
fn transferring_something_else_leaves_a_device_window_alone() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    // The device is handle 0, so the unrelated object below lands at 1.
    let handles_ptr = write_transfer(&mut upage, 1, Rights::READ | Rights::TRANSFER);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);

    // Install an unrelated object and transfer *that*.
    let other = ObjectId::from_raw(99);
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(other, Rights::READ | Rights::TRANSFER)
            .expect("install");
        assert_eq!(handle.raw(), 1);
    }
    let args = syscall::ChannelMsgRequest {
        interface_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: 0,
        inline_len: 0,
        handles_ptr,
        handle_count: 1,
        installed_ptr: 0,
        installed_cap: 0,
    };
    build_message_from_args(&mut h.processes, h.caller, &args, true).expect("transfer");

    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(0x4000_0000))
            .is_some()
    );
    assert_eq!(process.device_window_count(), 1);
}

#[test]
fn map_device_without_map_rights_is_denied() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    let mut h = harness(&upage, Rights::READ);
    let outcome = run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

#[test]
fn map_device_rejects_malformed_args_as_protocol() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4000_0000);
    upage.0[4] = 2; // version = 2
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let outcome = run(&mut h, SyscallNumber::MapDevice, [args_ptr, 0, 0, 0, 0, 0]);
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Err(KError::Protocol)))
    );
}

#[test]
fn dma_alloc_returns_the_physical_base_of_a_tracked_page() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0x4001_0000);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
    let DispatchOutcome::Return(value) = outcome else {
        panic!("dma_alloc not covered");
    };
    assert!(value > 0, "expected a physical address, got {value}");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    // Tracked: the wrapper records the mapping, and the returned phys is
    // the mapped frame's base.
    assert_eq!(
        process.space().rights_at(VirtAddr::new(0x4001_0000)),
        Some(PageFlags::rw().user())
    );
    let (frame, _) = process
        .space()
        .arch()
        .translate(VirtAddr::new(0x4001_0000))
        .expect("translated");
    assert_eq!(frame.base().as_u64(), value as u64);
}

#[test]
fn dma_alloc_on_a_non_device_authority_is_denied() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 1, 0x4001_0000);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // Install a second handle on an object with no MMIO window.
    let other = ObjectId::from_raw(99);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(other, Rights::READ | Rights::MAP)
        .expect("install");
    assert_eq!(handle.raw(), 1);
    let outcome = run(&mut h, SyscallNumber::DmaAlloc, [args_ptr, 0, 0, 0, 0, 0]);
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

#[test]
fn channel_ops_reject_a_bad_endpoint_handle() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = device_args(&mut upage, 0, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    // Handle 0 exists but is no endpoint object → BadHandle from the
    // endpoint bridge; handle 7 does not exist → BadHandle from lookup.
    for ep_handle in [0u64, 7] {
        let outcome = run(
            &mut h,
            SyscallNumber::ChannelRecv,
            [args_ptr, ep_handle, 0, 0, 0, 0],
        );
        assert_eq!(
            outcome,
            DispatchOutcome::Return(encode_result(Err(KError::BadHandle)))
        );
    }
}

#[test]
fn channel_recv_copies_the_queued_payload_out_and_truncates() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    // A channel whose far end has a queued 8-byte message; the near end is
    // installed as handle 1 with READ.
    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(50);
    h.exec.bind_endpoint_object(b, ep_obj);
    let mut m = Message::new(MessageHeader::new(0, 0));
    m.set_inline(b"\xfe\xca\x0d\xf0\xfe\xca\x0d\xf0")
        .expect("inline");
    h.exec.send(a, m).expect("send");
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(ep_obj, Rights::READ)
            .expect("install ep");
        assert_eq!(handle.raw(), 1);
    }

    // ChannelMsgArgs at upage[+128]: recv buffer = upage base (len 6 — one
    // shorter than the payload, proving truncation to the caller's buffer).
    let base = upage.0.as_ptr() as u64;
    let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
    args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    args[40..48].copy_from_slice(&base.to_le_bytes()); // inline_ptr
    args[48..56].copy_from_slice(&6u64.to_le_bytes()); // inline_len
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelRecv,
        [base + 128, 1, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(6));
    assert_eq!(&upage.0[..6], b"\xfe\xca\x0d\xf0\xfe\xca");
}

/// **A server with two endpoints needs to be able to look without
/// waiting.** A blocking receive commits it to whichever client speaks
/// first and leaves the other unheard for as long as the first stays quiet
/// — which is not a shortcoming of the server, it is what a blocking
/// receive means.
#[test]
fn a_non_blocking_receive_says_so_rather_than_parking() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    // An empty channel, installed as handle 1.
    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(51);
    h.exec.bind_endpoint_object(b, ep_obj);
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let handle = process
            .handles_mut()
            .install(ep_obj, Rights::READ)
            .expect("install ep");
        assert_eq!(handle.raw(), 1);
    }

    let base = upage.0.as_ptr() as u64;
    {
        let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
        args.fill(0);
        args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
        args[4..8].copy_from_slice(&4u32.to_le_bytes());
        args[36..40].copy_from_slice(&MSG_FLAG_NONBLOCKING.to_le_bytes());
        args[40..48].copy_from_slice(&base.to_le_bytes());
        args[48..56].copy_from_slice(&8u64.to_le_bytes());
    }
    // Nothing queued: an answer, and the caller is still running.
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecv,
            [base + 128, 1, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::WouldBlock)))
    );

    // And with something queued it behaves exactly as the blocking form.
    let mut m = Message::new(MessageHeader::new(0, 0));
    m.set_inline(b"\xfe\xca\x0d\xf0").expect("inline");
    h.exec.send(a, m).expect("send");
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecv,
            [base + 128, 1, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(4)
    );
    assert_eq!(&upage.0[..4], b"\xfe\xca\x0d\xf0");
}

/// A peer that has closed is `PeerClosed`, not `WouldBlock`. A channel that
/// will never speak again is a different fact from one that has not spoken
/// yet, and a server polling a set of endpoints has to be able to stop
/// polling a dead one.
#[test]
fn a_closed_peer_is_not_merely_quiet() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(52);
    h.exec.bind_endpoint_object(b, ep_obj);
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ep_obj, Rights::READ)
            .expect("install ep");
    }
    h.exec.close_endpoint(a).expect("close");

    let base = upage.0.as_ptr() as u64;
    let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
    args.fill(0);
    args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    args[36..40].copy_from_slice(&MSG_FLAG_NONBLOCKING.to_le_bytes());
    args[40..48].copy_from_slice(&base.to_le_bytes());
    args[48..56].copy_from_slice(&8u64.to_le_bytes());
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecv,
            [base + 128, 1, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::PeerClosed)))
    );
}

/// **A server with two clients hears both.** Waiting on one endpoint and
/// polling the other would sleep through anything the other said; polling
/// both and never parking would be a server no other thread runs behind,
/// because the scheduler here is cooperative. So the wait registers on
/// every endpoint, and reports which one answered — the one thing the
/// message itself does not say and the server needs in order to reply.
#[test]
fn a_wait_on_several_endpoints_takes_from_whichever_speaks() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    let (a0, b0) = h.exec.channel_create().expect("channel");
    let (a1, b1) = h.exec.channel_create().expect("channel");
    h.exec.bind_endpoint_object(b0, ObjectId::from_raw(60));
    h.exec.bind_endpoint_object(b1, ObjectId::from_raw(61));
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        assert_eq!(
            process
                .handles_mut()
                .install(ObjectId::from_raw(60), Rights::READ)
                .expect("ep0")
                .raw(),
            1
        );
        assert_eq!(
            process
                .handles_mut()
                .install(ObjectId::from_raw(61), Rights::READ)
                .expect("ep1")
                .raw(),
            2
        );
    }

    // The endpoint handle vector at the page base, and the receive buffer
    // after it.
    let base = upage.0.as_ptr() as u64;
    upage.0[0..4].copy_from_slice(&1u32.to_le_bytes());
    upage.0[4..8].copy_from_slice(&2u32.to_le_bytes());
    {
        let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
        args.fill(0);
        args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
        args[4..8].copy_from_slice(&4u32.to_le_bytes());
        args[40..48].copy_from_slice(&(base + 64).to_le_bytes()); // inline_ptr
        args[48..56].copy_from_slice(&8u64.to_le_bytes()); // inline_len
        args[56..64].copy_from_slice(&base.to_le_bytes()); // handles_ptr
        args[64..72].copy_from_slice(&2u64.to_le_bytes()); // handle_count
    }

    // The *second* endpoint speaks. A server that had parked on the first
    // would still be asleep.
    let mut m = Message::new(MessageHeader::new(0, 7));
    m.set_inline(b"\x02\x00\x00\x00").expect("inline");
    h.exec.send(a1, m).expect("send");
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecvAny,
            [base + 128, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(4)
    );
    assert_eq!(&upage.0[64..68], b"\x02\x00\x00\x00");
    // Which one answered, written back where the server will look for it.
    let flags = u32::from_le_bytes(upage.0[128 + 36..128 + 40].try_into().expect("msg_flags"));
    assert_eq!(flags, 1, "the second endpoint");
    // And the method, as an ordinary receive reports it.
    let method = u32::from_le_bytes(upage.0[128 + 32..128 + 36].try_into().expect("method_id"));
    assert_eq!(method, 7);

    // Now the first, which must report index zero rather than the last
    // value written.
    let mut m = Message::new(MessageHeader::new(0, 9));
    m.set_inline(b"\x01\x00\x00\x00").expect("inline");
    h.exec.send(a0, m).expect("send");
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecvAny,
            [base + 128, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(4)
    );
    let flags = u32::from_le_bytes(upage.0[128 + 36..128 + 40].try_into().expect("msg_flags"));
    assert_eq!(flags, 0);
}

/// An empty or oversized endpoint vector is refused rather than walked.
#[test]
fn a_wait_on_no_endpoints_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let base = upage.0.as_ptr() as u64;
    let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
    args.fill(0);
    args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    args[56..64].copy_from_slice(&base.to_le_bytes());
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecvAny,
            [base + 128, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidArgument)))
    );
    upage.0[128 + 64..128 + 72].copy_from_slice(&((MAX_RECV_ANY + 1) as u64).to_le_bytes());
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelRecvAny,
            [base + 128, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidArgument)))
    );
}

/// Writes a `ChannelMsgArgs` at `upage[+128]` describing the symmetric
/// call buffer at the page base (request source and reply destination).
/// Returns the args pointer.
fn call_args(upage: &mut UserPage, inline_len: u64) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
    args.fill(0);
    args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    args[40..48].copy_from_slice(&base.to_le_bytes()); // inline_ptr
    args[48..56].copy_from_slice(&inline_len.to_le_bytes()); // inline_len
    base + 128
}

/// A call harness: handle 1 = endpoint `a` with WRITE; a reply is staged on
/// `a` (the mock context switch returns immediately, so `call` proceeds
/// straight to taking its reply — the synchronous round-trip collapsed for the
/// host test).
///
/// Staged through `stage_reply_to_next_call` rather than a plain `send`,
/// because `call` matches the reply's transaction id against the one it minted
/// and a one-way message carries no such id. That distinction is the point of
/// the matching, so a harness that papered over it would be a harness that
/// still passed with the matching removed.
fn call_harness(upage: &UserPage, reply: &[u8]) -> Harness {
    let mut h = harness(upage, Rights::READ | Rights::MAP);
    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(51);
    h.exec.bind_endpoint_object(a, ep_obj);
    let mut m = Message::new(MessageHeader::new(0, 0));
    m.set_inline(reply).expect("inline");
    h.exec.stage_reply_from(b, m).expect("stage reply");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(ep_obj, Rights::WRITE)
        .expect("install ep");
    assert_eq!(handle.raw(), 1);
    h
}

#[test]
fn channel_call_copies_the_reply_payload_out() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = call_args(&mut upage, 96);
    let mut h = call_harness(&upage, b"TESSERAV");
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCall,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(8));
    assert_eq!(&upage.0[..8], b"TESSERAV");
}

#[test]
fn channel_call_truncates_the_reply_to_the_buffer() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = call_args(&mut upage, 4);
    let mut h = call_harness(&upage, b"TESSERAV");
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCall,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(4));
    assert_eq!(&upage.0[..4], b"TESS");
    assert_eq!(&upage.0[4..8], &[0u8; 4]);
}

#[test]
fn channel_call_with_an_empty_reply_returns_zero_and_writes_nothing() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = call_args(&mut upage, 96);
    let mut h = call_harness(&upage, b"");
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCall,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(0));
    assert_eq!(&upage.0[..8], &[0u8; 8]);
}

/// **The third register is the deadline, and a passed one refuses the call.**
///
/// A reply is staged and would be returned instantly, so nothing here is slow:
/// what the test discriminates is whether the register reached the executive
/// at all. A dispatcher that dropped it would hand back the reply and pass
/// every other assertion in this file (D283).
#[test]
fn channel_call_refuses_a_deadline_that_has_passed() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = call_args(&mut upage, 96);
    let mut h = call_harness(&upage, b"TESSERAV");
    // `test_clock` starts at zero and advances a nanosecond a read, so 1 is in
    // the past by the time the dispatcher reads it.
    let _ = test_clock();
    let _ = test_clock();
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCall,
        [args_ptr, 1, 1, 0, 0, 0],
    );
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Err(KError::TimedOut)))
    );
    assert_eq!(
        &upage.0[..8],
        &[0u8; 8],
        "a refused call copies no reply out",
    );
}

/// And zero is no deadline, which is what every caller written before the
/// register existed passes without knowing it. The same staged reply comes
/// back, from a clock that is far past any small number.
#[test]
fn channel_call_treats_a_zero_deadline_as_no_deadline() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = call_args(&mut upage, 96);
    let mut h = call_harness(&upage, b"TESSERAV");
    let _ = test_clock();
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCall,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(8));
    assert_eq!(&upage.0[..8], b"TESSERAV");
}

/// A sender harness for `ChannelSend`: handle 1 = endpoint `a` carrying
/// `rights`, and the peer `b` returned so the test can see what arrived.
/// Nothing is pre-queued and nobody is parked — the whole point of this
/// direction is that it needs neither.
fn send_harness(upage: &UserPage, rights: Rights) -> (Harness, EndpointId) {
    let mut h = harness(upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(53);
    h.exec.bind_endpoint_object(a, ep_obj);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process.handles_mut().install(ep_obj, rights).expect("ep");
    assert_eq!(handle.raw(), 1);
    (h, b)
}

/// Writes a `ChannelMsgArgs` at `upage[+128]` for a send: the payload is
/// read from `upage[..len]`, and `handles` — when given — is the transfer
/// vector's address and count.
fn send_args(upage: &mut UserPage, len: u64, handles: Option<(u64, u64)>) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let args = &mut upage.0[128..128 + syscall::CHANNEL_MSG_ARGS_SIZE];
    args.fill(0);
    args[0..4].copy_from_slice(&(syscall::CHANNEL_MSG_ARGS_SIZE as u32).to_le_bytes());
    args[4..8].copy_from_slice(&4u32.to_le_bytes());
    args[40..48].copy_from_slice(&base.to_le_bytes()); // inline_ptr
    args[48..56].copy_from_slice(&len.to_le_bytes()); // inline_len
    if let Some((ptr, count)) = handles {
        args[56..64].copy_from_slice(&ptr.to_le_bytes()); // handles_ptr
        args[64..72].copy_from_slice(&count.to_le_bytes()); // handle_count
    }
    base + 128
}

/// The direction this system did not have: a message with nobody waiting
/// for it. Nothing is blocked on the far end, no call is outstanding, and
/// the payload is there for a later receive.
#[test]
fn channel_send_queues_for_a_receiver_that_has_not_asked_yet() {
    let mut upage = UserPage([0; 4096]);
    upage.0[..8].copy_from_slice(b"ARPREPLY");
    let args_ptr = send_args(&mut upage, 8, None);
    let (mut h, b) = send_harness(&upage, Rights::WRITE);
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelSend,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(8));
    let message = h.exec.receive(b).expect("the peer has it");
    assert_eq!(message.inline(), b"ARPREPLY");
}

/// `WRITE`, and only `WRITE`: this puts a message in somebody else's
/// queue. A handle that may read their replies has no business doing so.
#[test]
fn channel_send_without_write_rights_is_denied() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = send_args(&mut upage, 8, None);
    let (mut h, _b) = send_harness(&upage, Rights::READ);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelSend,
            [args_ptr, 1, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// **What makes an event able to give something away.** A pushed message
/// carries capabilities on the same path a request's do, so the sender's
/// handle and its mapping are gone once it has gone — which is the whole
/// content of the network class's `TRANSFERRED` ownership: a driver that
/// handed a frame over cannot still be holding it.
#[test]
fn channel_send_hands_the_buffer_over_and_leaves_the_sender_none() {
    let mut upage = UserPage([0; 4096]);
    let (mut h, b) = send_harness(&upage, Rights::WRITE);
    let args = memory_create_args(&mut upage, FRAME_SIZE);
    let buffer = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = memory_map_args(&mut upage, buffer, GRANT_VA, MAP_RW);
    run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]);

    let handles_ptr = write_transfer(&mut upage, buffer, Rights::READ | Rights::MAP);
    let args_ptr = send_args(&mut upage, 0, Some((handles_ptr, 1)));
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelSend,
            [args_ptr, 1, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(0)
    );

    let message = h.exec.receive(b).expect("the peer has it");
    assert_eq!(message.handle_count(), 1, "the buffer travelled");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    assert!(
        process.handles().lookup(Handle::from_raw(buffer)).is_err(),
        "the sender's handle went with it",
    );
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA))
            .is_none(),
        "and so did the mapping",
    );
}

/// A receiver that is not keeping up is the sender's problem to hear
/// about, not the kernel's to hide. The queue is left exactly as full as
/// it was — nothing is dropped to make room.
#[test]
fn channel_send_answers_would_block_on_a_full_queue() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = send_args(&mut upage, 8, None);
    let (mut h, b) = send_harness(&upage, Rights::WRITE);
    for _ in 0..crate::ipc::QUEUE_CAP {
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::ChannelSend,
                [args_ptr, 1, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(8)
        );
    }
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelSend,
            [args_ptr, 1, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::WouldBlock)))
    );
    for _ in 0..crate::ipc::QUEUE_CAP {
        assert!(
            h.exec.receive(b).is_ok(),
            "everything queued is still there"
        );
    }
}

/// A server harness for `ChannelReplyRecv`: handle 1 = endpoint `b` (the
/// server side) with READ; `next_request` is pre-queued on `b` from the
/// client end `a`, standing in for the next caller's request (the
/// immediate-dequeue path of `reply_receive` — on hardware the sequential
/// clients exercise the park-and-handoff path instead).
fn reply_recv_harness(upage: &UserPage, next_request: &[u8]) -> (Harness, EndpointId) {
    let mut h = harness(upage, Rights::READ | Rights::MAP);
    let (a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(52);
    h.exec.bind_endpoint_object(b, ep_obj);
    let mut m = Message::new(MessageHeader::new(0, 0));
    m.set_inline(next_request).expect("inline");
    h.exec.send(a, m).expect("queue next request");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(ep_obj, Rights::READ)
        .expect("install ep");
    assert_eq!(handle.raw(), 1);
    (h, a)
}

#[test]
fn channel_reply_recv_sends_the_reply_and_returns_the_next_request() {
    let mut upage = UserPage([0; 4096]);
    // The symmetric buffer starts holding the reply payload.
    upage.0[..8].copy_from_slice(b"TESSERAV");
    let args_ptr = call_args(&mut upage, 96);
    let (mut h, client_end) = reply_recv_harness(&upage, b"\x18\0\0\0\x01\0\0\0");
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelReplyRecv,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    // The queued next request (8 bytes) was copied into the buffer…
    assert_eq!(outcome, DispatchOutcome::Return(8));
    assert_eq!(&upage.0[..8], b"\x18\0\0\0\x01\0\0\0");
    // …and the reply (96 bytes of the buffer, front = the old payload)
    // was delivered to the client end.
    let reply = h.exec.receive(client_end).expect("reply queued");
    assert_eq!(&reply.inline()[..8], b"TESSERAV");
    assert_eq!(reply.inline().len(), 96);
}

#[test]
fn channel_reply_recv_truncates_the_next_request_to_the_buffer() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = call_args(&mut upage, 4);
    let (mut h, _client_end) = reply_recv_harness(&upage, b"TESSERA2");
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelReplyRecv,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(4));
    assert_eq!(&upage.0[..4], b"TESS");
    assert_eq!(&upage.0[4..8], &[0u8; 4]);
}

/// **The first thing `Rights::SIGNAL` gates.** Waiting on a port and
/// waking one are different authorities: a client that could signal its own
/// port could report an edge that never happened, and READ is what a
/// watcher is given.
#[test]
fn signalling_a_port_needs_the_right_to_and_not_merely_the_port() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port = h.exec.port_create().expect("port");
    let port_obj = ObjectId::from_raw(70);
    h.exec.bind_port_object(port, port_obj);
    h.exec
        .port_bind(port, 3, crate::exec::SOFTWARE_PORT_SIGNAL)
        .expect("bind");
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        // A watcher's rights: it may be woken and may not do the waking.
        let watch = process
            .handles_mut()
            .install(port_obj, Rights::READ)
            .expect("install");
        assert_eq!(watch.raw(), 1);
        let raise = process
            .handles_mut()
            .install(port_obj, Rights::SIGNAL)
            .expect("install");
        assert_eq!(raise.raw(), 2);
    }

    assert_eq!(
        run(&mut h, SyscallNumber::PortSignal, [1, 3, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
        "the same port, through the handle that may only wait",
    );
    assert_eq!(
        run(&mut h, SyscallNumber::PortSignal, [2, 3, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    // And it landed: the wait drains it without parking.
    assert_eq!(
        run(&mut h, SyscallNumber::PortWait, [1, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(1),
    );
}

/// **A source the port is not bound to is refused, not delivered to
/// nothing.** What a holder may raise was decided when the port was made;
/// a signal that silently reached nobody would be a driver believing it
/// woke a client it did not.
#[test]
fn a_source_the_port_does_not_carry_is_refused() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port = h.exec.port_create().expect("port");
    let port_obj = ObjectId::from_raw(71);
    h.exec.bind_port_object(port, port_obj);
    h.exec
        .port_bind(port, 3, crate::exec::SOFTWARE_PORT_SIGNAL)
        .expect("bind");
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(port_obj, Rights::SIGNAL)
            .expect("install");
    }
    assert_eq!(
        run(&mut h, SyscallNumber::PortSignal, [1, 5, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::Protocol))),
        "line 5 is not this port's to raise",
    );
}

/// **One port, not every port bound to the source.** A driver that
/// demultiplexed line 3 must not be able to wake everybody waiting on line
/// 5 by naming their source — which is exactly what the broadcast form an
/// interrupt line uses would do.
#[test]
fn a_software_signal_reaches_the_port_named_and_no_other() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let mine = h.exec.port_create().expect("port");
    let theirs = h.exec.port_create().expect("port");
    h.exec.bind_port_object(mine, ObjectId::from_raw(72));
    h.exec.bind_port_object(theirs, ObjectId::from_raw(73));
    // Both bound to the *same* source, which is the case that separates
    // the two forms.
    for port in [mine, theirs] {
        h.exec
            .port_bind(port, 3, crate::exec::SOFTWARE_PORT_SIGNAL)
            .expect("bind");
    }
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ObjectId::from_raw(72), Rights::SIGNAL | Rights::READ)
            .expect("install");
        process
            .handles_mut()
            .install(ObjectId::from_raw(73), Rights::READ)
            .expect("install");
    }
    assert_eq!(
        run(&mut h, SyscallNumber::PortSignal, [1, 3, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    assert_eq!(
        run(&mut h, SyscallNumber::PortWait, [1, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(1),
        "the port that was named",
    );
    // The other one has nothing, and a wait on it would park — so the
    // executive is asked directly rather than through a syscall that
    // blocks.
    assert!(!h.exec.port_asserted(theirs), "and no other");
}

#[test]
fn port_wait_drains_a_pending_event() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port = h.exec.port_create().expect("port");
    let port_obj = ObjectId::from_raw(60);
    h.exec.bind_port_object(port, port_obj);
    h.exec.port_bind(port, 0x30, 1).expect("bind");
    // Pre-signal so the wait drains without parking (the mock collapses
    // the park path anyway; the block/wake pair is covered in exec.rs).
    assert_eq!(h.exec.port_signal(0x30, 1, 3), 1);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(port_obj, Rights::READ)
        .expect("install port");
    assert_eq!(handle.raw(), 1);
    let outcome = run(&mut h, SyscallNumber::PortWait, [1, 0, 0, 0, 0, 0]);
    assert_eq!(outcome, DispatchOutcome::Return(3));
}

#[test]
fn port_wait_writes_the_event_record_naming_the_source() {
    // The select: two bindings on one port, and the drained record must
    // say which of them fired — that is what lets a server map the event
    // back to the endpoint handle it should receive on.
    let upage = UserPage([0; 4096]);
    let event_ptr = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port = h.exec.port_create().expect("port");
    let port_obj = ObjectId::from_raw(60);
    h.exec.bind_port_object(port, port_obj);
    h.exec.port_bind(port, 0x30, 1).expect("bind a");
    h.exec.port_bind(port, 0x31, 2).expect("bind b");
    assert_eq!(h.exec.port_signal(0x31, 2, 1), 1);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(port_obj, Rights::READ)
        .expect("install port");
    let outcome = run(
        &mut h,
        SyscallNumber::PortWait,
        [u64::from(handle.raw()), event_ptr, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(1));
    let field = |off: usize| u64::from_le_bytes(upage.0[off..off + 8].try_into().expect("8"));
    let word = |off: usize| u32::from_le_bytes(upage.0[off..off + 4].try_into().expect("4"));
    assert_eq!(word(0) as usize, PortEventRecord::WIRE_SIZE);
    assert_eq!(word(4), 1, "version");
    assert_eq!(field(16), 0x31, "source names the binding that fired");
    assert_eq!(word(24), 2, "signal");
    assert_eq!(word(28), 1, "pending");
}

#[test]
fn port_wait_without_an_event_pointer_writes_nothing() {
    // The D84 interrupt shape: a single-binding port needs no record, and
    // passing zero must leave user memory untouched.
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port = h.exec.port_create().expect("port");
    let port_obj = ObjectId::from_raw(60);
    h.exec.bind_port_object(port, port_obj);
    h.exec.port_bind(port, 0x30, 1).expect("bind");
    assert_eq!(h.exec.port_signal(0x30, 1, 2), 1);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(port_obj, Rights::READ)
        .expect("install port");
    let outcome = run(
        &mut h,
        SyscallNumber::PortWait,
        [u64::from(handle.raw()), 0, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(2));
    assert_eq!(
        upage.0[..PORT_EVENT_RECORD_SIZE],
        [0u8; PORT_EVENT_RECORD_SIZE]
    );
}

#[test]
fn port_wait_without_read_rights_is_denied() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port = h.exec.port_create().expect("port");
    let port_obj = ObjectId::from_raw(61);
    h.exec.bind_port_object(port, port_obj);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(port_obj, Rights::WRITE)
        .expect("install port");
    assert_eq!(handle.raw(), 1);
    let outcome = run(&mut h, SyscallNumber::PortWait, [1, 0, 0, 0, 0, 0]);
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

#[test]
fn channel_reply_recv_without_read_rights_is_denied() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = call_args(&mut upage, 96);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let (_a, b) = h.exec.channel_create().expect("channel");
    let ep_obj = ObjectId::from_raw(53);
    h.exec.bind_endpoint_object(b, ep_obj);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let handle = process
        .handles_mut()
        .install(ep_obj, Rights::WRITE)
        .expect("install ep");
    assert_eq!(handle.raw(), 1);
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelReplyRecv,
        [args_ptr, 1, 0, 0, 0, 0],
    );
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}
// -----------------------------------------------------------------------
// FirmwareLoad — a verified image, admitted by policy, handed out as an
// object (D148).
// -----------------------------------------------------------------------

/// Builds a store holding three images: one that loads, one below the
/// system's rollback floor, and one below what a caller will ask for.
///
/// Leaked deliberately. The loader holds a `&'static [u8]` because the real
/// store is part of the kernel image and outlives everything; a test that
/// borrowed a local would be proving something about a lifetime the kernel
/// never has.
fn install_test_store() {
    use tessera_image_store::{Anchor, BuildEntry, build_into, measure};

    let good = [0xa1u8; 300];
    let old = [0xb2u8; 120];
    let stale = [0xc3u8; 64];
    let entries = [
        BuildEntry {
            name: "fw-good.bin",
            svn: 9,
            image_version: 4,
            flags: 0,
            bytes: &good,
        },
        BuildEntry {
            name: "fw-old.bin",
            svn: 1,
            image_version: 4,
            flags: 0,
            bytes: &old,
        },
        BuildEntry {
            name: "fw-stale.bin",
            svn: 9,
            image_version: 1,
            flags: 0,
            bytes: &stale,
        },
    ];
    let mut buffer = std::vec![0u8; 4096];
    let len = build_into(&mut buffer, 1, &entries).expect("build");
    buffer.truncate(len);
    let region: &'static [u8] = std::boxed::Box::leak(buffer.into_boxed_slice());
    let anchors: &'static [Anchor] = std::boxed::Box::leak(std::boxed::Box::new([Anchor {
        id: 1,
        digest: measure(region).expect("measure"),
    }]));
    crate::firmware::tests::set_test_store(region, anchors);
}

/// The handle `harness` installs its device at — the first slot of a fresh
/// table, which is what every other test here relies on too.
const DEVICE_HANDLE: u32 = 0;

/// Builds a `FirmwareLoadArgs` in the user page; returns (args, report) ptrs.
fn firmware_args(
    upage: &mut UserPage,
    handle: u32,
    name: &str,
    min_image_version: u32,
) -> (u64, u64) {
    let at = 1536;
    let report_at = 1792;
    let mut field = [0u8; syscall::FIRMWARE_NAME_LEN];
    field[..name.len()].copy_from_slice(name.as_bytes());
    let args = crate::isl_binding::firmware::FirmwareLoadArgs {
        size: syscall::FIRMWARE_LOAD_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        device: tessera_isl_runtime::HandleRef::new(handle),
        min_image_version,
        name: field,
        reserved: 0,
        report_ptr: upage.0.as_ptr() as u64 + report_at as u64,
    };
    tessera_isl_runtime::encode(
        &args,
        &mut upage.0[at..at + syscall::FIRMWARE_LOAD_ARGS_SIZE],
    )
    .expect("encode");
    (
        upage.0.as_ptr() as u64 + at as u64,
        upage.0.as_ptr() as u64 + report_at as u64,
    )
}

/// Reads back the report the kernel wrote.
fn firmware_report(upage: &UserPage) -> crate::isl_binding::firmware::FirmwareReport {
    let at = 1792;
    tessera_isl_runtime::decode(&upage.0[at..at + syscall::FIRMWARE_REPORT_SIZE])
        .expect("decode report")
}

/// The whole path on a host: measured, admitted, filled into an object the
/// caller can name, and reported — including the image's own measurement,
/// which is what provenance means.
#[test]
fn an_admitted_image_arrives_as_an_object() {
    install_test_store();
    let mut upage = UserPage([0u8; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::FIRMWARE);
    let (args, _) = firmware_args(&mut upage, DEVICE_HANDLE, "fw-good.bin", 3);

    let outcome = run(&mut h, SyscallNumber::FirmwareLoad, [args, 0, 0, 0, 0, 0]);
    let DispatchOutcome::Return(raw) = outcome else {
        panic!("unhandled");
    };
    assert!(raw >= 0, "load refused: {raw}");

    let report = firmware_report(&upage);
    assert_eq!(
        report.refusal,
        crate::isl_binding::firmware::FirmwareRefusal::None
    );
    assert_eq!(report.svn, 9);
    assert_eq!(report.image_version, 4);
    assert_eq!(report.length, 300);
    assert_eq!(report.digest, tessera_hash::sha256(&[0xa1u8; 300]));

    // The handle names a memory object holding exactly that many bytes.
    let handle = Handle::from_raw(raw as u32);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, rights) = process.handles().lookup(handle).expect("installed");
    assert_eq!(h.exec.memory_len_of(object), Some(FRAME_SIZE));
    // **Not writable.** A driver that could edit its firmware would make
    // the digest in the provenance record describe bytes that are gone.
    assert!(!rights.contains(Rights::WRITE));
    assert!(rights.contains(Rights::TRANSFER));
}

/// **The right is the whole access decision.** A caller holding the device
/// with everything a driver gets — READ and MAP — and without FIRMWARE is
/// refused, which is exactly the state the manager leaves a driver in.
#[test]
fn a_device_without_the_firmware_right_cannot_load() {
    install_test_store();
    let mut upage = UserPage([0u8; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let (args, _) = firmware_args(&mut upage, DEVICE_HANDLE, "fw-good.bin", 3);
    assert_eq!(
        run(&mut h, SyscallNumber::FirmwareLoad, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// An image below the floor is refused **while measuring perfectly**, and
/// the report says which policy spoke — `docs/security/02`'s "rejected even
/// if correctly signed", reached through the syscall rather than asserted
/// about the rule.
#[test]
fn an_image_below_the_floor_is_blocked_and_says_so() {
    install_test_store();
    let mut upage = UserPage([0u8; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::FIRMWARE);
    let (args, _) = firmware_args(&mut upage, DEVICE_HANDLE, "fw-old.bin", 1);
    assert_eq!(
        run(&mut h, SyscallNumber::FirmwareLoad, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::PolicyRefused)))
    );
    assert_eq!(
        firmware_report(&upage).refusal,
        crate::isl_binding::firmware::FirmwareRefusal::RollbackBlocked
    );
}

/// And an image the floor accepts but the caller does not is a *different*
/// refusal. One code for both would leave a caller unable to tell a version
/// the system retired from one its driver simply does not want.
#[test]
fn an_image_older_than_the_caller_needs_is_a_different_refusal() {
    install_test_store();
    let mut upage = UserPage([0u8; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::FIRMWARE);
    let (args, _) = firmware_args(&mut upage, DEVICE_HANDLE, "fw-stale.bin", 4);
    assert_eq!(
        run(&mut h, SyscallNumber::FirmwareLoad, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::PolicyRefused)))
    );
    assert_eq!(
        firmware_report(&upage).refusal,
        crate::isl_binding::firmware::FirmwareRefusal::VersionTooOld
    );
}

/// A name nothing answers to is `InvalidArgument` and **not** a policy
/// refusal: a machine with no such image and a machine whose image was
/// retired are opposite situations with opposite fixes.
#[test]
fn an_absent_image_is_not_a_policy_refusal() {
    install_test_store();
    let mut upage = UserPage([0u8; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::FIRMWARE);
    let (args, _) = firmware_args(&mut upage, DEVICE_HANDLE, "fw-absent.bin", 1);
    assert_eq!(
        run(&mut h, SyscallNumber::FirmwareLoad, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidArgument)))
    );
    assert_eq!(
        firmware_report(&upage).refusal,
        crate::isl_binding::firmware::FirmwareRefusal::None
    );
}

// -----------------------------------------------------------------------
// Protected memory — classified regions, and the device that may not have
// them (D149).
// -----------------------------------------------------------------------

/// Builds a `MemoryClassifyArgs` in the user page and returns its pointer.
fn classify_args(upage: &mut UserPage, memory: u32, class: u32) -> u64 {
    let at = 2048;
    upage.0[at..at + syscall::MEMORY_CLASSIFY_ARGS_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&(syscall::MEMORY_CLASSIFY_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&memory.to_le_bytes());
    upage.0[at + 20..at + 24].copy_from_slice(&class.to_le_bytes());
    upage.0.as_ptr() as u64 + at as u64
}

const UNCLASSIFIED: u32 = 0;
const PROTECTED: u32 = 1;

/// A classification rises, and **never falls**. Lowering is what would make
/// the whole mechanism advisory: anything holding a protected buffer could
/// clear the class and hand the memory to a device.
#[test]
fn a_classification_rises_and_never_falls() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let memory = make_object(&mut h, &mut upage);

    let raise = classify_args(&mut upage, memory, PROTECTED);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::MemoryClassify,
            [raise, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Ok(0)))
    );
    // Idempotent: saying it twice is not an error, because a caller made to
    // remember whether it had already asked would keep state the kernel has.
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::MemoryClassify,
            [raise, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Ok(0)))
    );

    let lower = classify_args(&mut upage, memory, UNCLASSIFIED);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::MemoryClassify,
            [lower, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// Classifying needs `WRITE` on the memory, not `MAP`: raising a class
/// restricts what may be done with the object from then on, so it is a
/// modification of it rather than an opinion about it.
#[test]
fn classifying_needs_write_on_the_memory() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let memory = make_object(&mut h, &mut upage);
    // Re-install the object read-only, which is what a client handing out a
    // view rather than the buffer would do.
    let readonly = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let (object, _) = process
            .handles()
            .lookup(Handle::from_raw(memory))
            .expect("memory");
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(object, Rights::READ | Rights::MAP)
            .expect("install")
            .raw()
    };
    let args = classify_args(&mut upage, readonly, PROTECTED);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryClassify, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// **The milestone's sentence.** Protected memory does not reach a device
/// that is not authorized for it — and the identical request succeeds for a
/// device that is, so the refusal is the right's doing and not the
/// classification making the buffer unusable.
#[test]
fn protected_memory_reaches_only_an_authorized_device() {
    for (device_rights, expected_ok) in [
        (Rights::READ | Rights::MAP, false),
        (Rights::READ | Rights::MAP | Rights::PROTECTED_DMA, true),
    ] {
        let mut upage = UserPage([0; 4096]);
        let mut h = harness(&upage, device_rights);
        h.iommu = Some(MockMapper::over(
            ObjectId::from_raw(21),
            0x8000_0000,
            0x10_0000,
        ));
        let memory = make_object(&mut h, &mut upage);
        let classify = classify_args(&mut upage, memory, PROTECTED);
        assert_eq!(
            run(
                &mut h,
                SyscallNumber::MemoryClassify,
                [classify, 0, 0, 0, 0, 0]
            ),
            DispatchOutcome::Return(encode_result(Ok(0)))
        );

        let args = attach_args(&mut upage, 0, memory);
        let outcome = run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]);
        match (outcome, expected_ok) {
            (DispatchOutcome::Return(v), true) => assert!(v >= 0, "authorized attach refused"),
            (outcome, false) => assert_eq!(
                outcome,
                DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
            ),
            (outcome, true) => panic!("unexpected {outcome:?}"),
        }
    }
}

/// An unclassified buffer is unaffected: the check is about the class, not
/// about the right, so a device without `PROTECTED_DMA` keeps working
/// exactly as it did.
#[test]
fn an_unclassified_buffer_still_attaches_without_the_right() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    let args = attach_args(&mut upage, 0, memory);
    match run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) => assert!(v >= 0),
        other => panic!("unexpected {other:?}"),
    }
}

/// **A refusal costs nothing.** No translation is installed and no
/// attachment is recorded — which matters because everything past the check
/// draws on the device's aperture, and a refusal that had already consumed
/// address space would let a caller exhaust a device's translations with
/// requests it was never allowed to make.
#[test]
fn a_refused_attach_consumes_no_aperture() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.iommu = Some(MockMapper::over(
        ObjectId::from_raw(21),
        0x8000_0000,
        0x10_0000,
    ));
    let memory = make_object(&mut h, &mut upage);
    let classify = classify_args(&mut upage, memory, PROTECTED);
    run(
        &mut h,
        SyscallNumber::MemoryClassify,
        [classify, 0, 0, 0, 0, 0],
    );

    let args = attach_args(&mut upage, 0, memory);
    assert_eq!(
        run(&mut h, SyscallNumber::DmaAttach, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    assert!(h.iommu.as_ref().expect("iommu").installed.is_empty());
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(Handle::from_raw(memory))
            .expect("memory")
            .0
    };
    assert!(h.exec.memory_attachment_of(object).is_none());
}

/// Builds an `IrqCompleteArgs` in the caller's page and returns its user VA.
/// Layout (LE): size:u32, version:u32, flags:u64, device:handle(u32),
/// reserved:u32.
fn irq_complete_args(upage: &mut UserPage, handle: u32) -> u64 {
    let at = 3072;
    upage.0[at..at + syscall::IRQ_COMPLETE_ARGS_SIZE].fill(0);
    upage.0[at..at + 4].copy_from_slice(&(syscall::IRQ_COMPLETE_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&handle.to_le_bytes());
    upage.0.as_ptr() as u64 + at as u64
}

/// The property the ports diverged on: a multi-queue controller's *every*
/// line comes back, not just its first. A port re-arming one line leaves the
/// other queues masked, and nothing reports the completion that never arrives.
#[test]
fn every_line_of_a_multi_queue_device_is_resolved() {
    let mut upage = UserPage([0; 4096]);
    let args_va = irq_complete_args(&mut upage, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(21);
    h.exec.device_set_mmio_irq(device, 40).expect("first line");
    h.exec.device_add_mmio_irq(device, 41).expect("second line");
    h.exec.device_add_mmio_irq(device, 42).expect("third line");

    let mut lines = [0u32; crate::devmgr::MAX_IRQ_LINES];
    let count = crate::dispatch::resolve_irq_lines(
        &h.exec,
        &mut h.processes,
        h.caller,
        args_va,
        &mut lines,
    )
    .expect("resolved");

    assert_eq!(count, 3, "a three-line device resolved {count} lines");
    assert_eq!(&lines[..count], &[40, 41, 42]);
}

/// The buffer is sized by its type, so the caller that cannot be given a short
/// one is every caller. This is the guard on `intids_of_object` stopping at the
/// end of a buffer, which for a short one is a line silently dropped.
#[test]
fn the_line_buffer_holds_a_full_device() {
    let mut upage = UserPage([0; 4096]);
    let args_va = irq_complete_args(&mut upage, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let device = ObjectId::from_raw(21);
    h.exec.device_set_mmio_irq(device, 40).expect("first line");
    for extra in 0..crate::devmgr::MAX_EXTRA_IRQS {
        h.exec
            .device_add_mmio_irq(device, 41 + extra as u32)
            .expect("extra line");
    }

    let mut lines = [0u32; crate::devmgr::MAX_IRQ_LINES];
    let count = crate::dispatch::resolve_irq_lines(
        &h.exec,
        &mut h.processes,
        h.caller,
        args_va,
        &mut lines,
    )
    .expect("resolved");

    assert_eq!(
        count,
        crate::devmgr::MAX_IRQ_LINES,
        "a device with every line the graph allows resolved {count}"
    );
}

/// The INTID comes from the capability, never from the caller: a handle
/// without `Rights::MAP` resolves nothing, whatever the args say.
#[test]
fn a_device_held_without_map_re_arms_nothing() {
    let mut upage = UserPage([0; 4096]);
    let args_va = irq_complete_args(&mut upage, 0);
    let mut h = harness(&upage, Rights::READ);
    h.exec
        .device_set_mmio_irq(ObjectId::from_raw(21), 40)
        .expect("line");

    let mut lines = [0u32; crate::devmgr::MAX_IRQ_LINES];
    assert_eq!(
        crate::dispatch::resolve_irq_lines(
            &h.exec,
            &mut h.processes,
            h.caller,
            args_va,
            &mut lines,
        ),
        Err(KError::AccessDenied)
    );
}

/// A device with no line wired is refused rather than answered with zero
/// lines: a driver parking on an interrupt the graph never routed waits
/// forever, and the refusal is what says so.
#[test]
fn a_device_with_no_line_wired_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let args_va = irq_complete_args(&mut upage, 0);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    let mut lines = [0u32; crate::devmgr::MAX_IRQ_LINES];
    assert_eq!(
        crate::dispatch::resolve_irq_lines(
            &h.exec,
            &mut h.processes,
            h.caller,
            args_va,
            &mut lines,
        ),
        Err(KError::AccessDenied)
    );
}

// --- Service-backed objects: the page cache reached from ring 3 ---

/// Builds a `MemoryCreatePagedArgs` in the user page and returns its pointer.
fn paged_create_args(upage: &mut UserPage, bytes: u64, pager: u32) -> u64 {
    let at = 768;
    let args = crate::isl_binding::memory::MemoryCreatePagedArgs {
        size: syscall::MEMORY_CREATE_PAGED_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        bytes,
        pager: tessera_isl_runtime::HandleRef::new(pager),
        reserved: 0,
    };
    tessera_isl_runtime::encode(
        &args,
        &mut upage.0[at..at + syscall::MEMORY_CREATE_PAGED_ARGS_SIZE],
    )
    .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// Builds a `PageSupplyArgs` in the user page and returns its pointer.
fn page_supply_args(upage: &mut UserPage, memory: u32, offset: u64, source: u64) -> u64 {
    let at = 832;
    let args = crate::isl_binding::memory::PageSupplyArgs {
        size: syscall::PAGE_SUPPLY_ARGS_SIZE as u32,
        version: 1,
        flags: 0,
        memory: tessera_isl_runtime::HandleRef::new(memory),
        reserved: 0,
        offset,
        source,
    };
    tessera_isl_runtime::encode(&args, &mut upage.0[at..at + syscall::PAGE_SUPPLY_ARGS_SIZE])
        .expect("encode");
    upage.0.as_ptr() as u64 + at as u64
}

/// The rights a process needs to be both the pager and the mapper of one
/// object, which is what these tests need and no real topology has.
fn pager_rights() -> Rights {
    Rights::READ | Rights::WRITE | Rights::MAP | Rights::SUPPLY
}

/// **The whole difference from `MemoryCreate`.** A hundred-page file must be
/// openable without a hundred frames, or a page cache is just an allocation.
#[test]
fn creating_a_paged_object_draws_no_frames() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    let before = h.frames.handed_out();

    let args = paged_create_args(&mut upage, 8 * FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    assert_eq!(h.frames.handed_out(), before, "no frame was drawn");

    // And it maps, with nothing behind it: the mapping exists and every page
    // is absent, which is what makes the first read a page-in rather than a bug.
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    for page in 0..8u64 {
        assert!(
            process
                .space()
                .arch()
                .translate(VirtAddr::new(GRANT_VA + page * FRAME_SIZE))
                .is_none(),
            "page {page} is absent",
        );
    }
}

/// A page already in the cache is installed by the mapping itself. Faulting on
/// it would ask the pager for a page the kernel is holding.
#[test]
fn a_page_supplied_before_the_mapping_is_installed_by_it() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, 2 * FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };

    let args = page_supply_args(&mut upage, handle, 0, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );

    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let flags = process
        .space()
        .arch()
        .translate(VirtAddr::new(GRANT_VA))
        .expect("the supplied page is resident")
        .1;
    // Installed **read-only** even though the mapping asked for write: that is
    // the software dirty bit, and the first store is what reports the page
    // dirty rather than the kernel guessing.
    assert!(!flags.writable(), "supplied read-only");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA + FRAME_SIZE))
            .is_none(),
        "the page nobody supplied is still absent",
    );
}

/// **`SUPPLY`, not `WRITE`.** Answering for what a reader somewhere else sees
/// is a different authority from writing memory you have mapped, and a process
/// holding only the latter must not be able to fill in pages.
#[test]
fn supplying_without_the_supply_right_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    // A second handle to the same object carrying everything *but* SUPPLY —
    // the view a creator hands a consumer.
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, _) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(handle))
        .expect("lookup");
    let narrowed = process
        .handles_mut()
        .install(object, Rights::READ | Rights::WRITE | Rights::MAP)
        .expect("install narrowed");

    let args = page_supply_args(&mut upage, narrowed.raw(), 0, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
}

/// The two kinds of object are not interchangeable in either direction, and
/// both refusals matter: a paged object mapped eagerly would have absent pages
/// treated as drift, and a kernel-backed object mapped lazily would record a
/// pager that will never answer.
#[test]
fn the_two_kinds_of_object_refuse_each_others_verbs() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());

    let args = memory_create_args(&mut upage, FRAME_SIZE);
    let kernel_backed = match run(&mut h, SyscallNumber::MemoryCreate, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let paged = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };

    // MapObject on a kernel-backed object.
    let args = memory_map_args(&mut upage, kernel_backed, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType))),
    );
    // PageSupply into a kernel-backed object: its pages are already there, so
    // there is nothing to supply and doing it would strand a frame.
    //
    // Asked with a handle that *has* `SUPPLY`, because authority is checked
    // before type — a caller with no rights is told `AccessDenied` and learns
    // nothing about what the object is, which is the right order and the
    // reason this needs a handle built for the question.
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (object, _) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(kernel_backed))
        .expect("lookup");
    let supplying = process
        .handles_mut()
        .install(object, Rights::READ | Rights::SUPPLY)
        .expect("install");
    let args = page_supply_args(&mut upage, supplying.raw(), 0, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType))),
    );
    // And without it, the answer says nothing about the object at all.
    let args = page_supply_args(&mut upage, kernel_backed, 0, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied))),
    );
    // And MemoryMap on a paged object, which has no frames to map.
    let args = memory_map_args(&mut upage, paged, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MemoryMap, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType))),
    );
}

/// A page past the end, and a page that is already there. Both would cost a
/// frame: the first has nowhere to go, the second would drop the frame the
/// mapping is using.
#[test]
fn a_supply_that_cannot_land_gives_its_frame_back() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let after_first = h.frames.handed_out() - h.frames.free_list_depth();

    // Past the end.
    let args = page_supply_args(&mut upage, handle, FRAME_SIZE, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidArgument))),
    );
    // The same page twice.
    let args = page_supply_args(&mut upage, handle, 0, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AlreadyMapped))),
    );
    assert_eq!(
        h.frames.handed_out() - h.frames.free_list_depth(),
        after_first,
        "a refused supply costs nothing",
    );
}

/// An offset or a source inside a page rather than at one. Rounding either
/// would copy a page the caller never chose into an object somebody else reads.
#[test]
fn an_unaligned_supply_is_refused_rather_than_rounded() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, 2 * FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };

    let args = page_supply_args(&mut upage, handle, 0x40, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::Unaligned))),
    );
    let args = page_supply_args(&mut upage, handle, 0, source + 0x40);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::Unaligned))),
    );
}

// --- The fault path: what a port is told, and what never blocks ---

/// A demand-mapped page is repaired without anybody being asked for it. The
/// page-in path must not be reached for a fault the kernel can fix itself.
#[test]
fn a_lazy_fault_resolves_without_a_page_request() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .space_mut()
            .map_anonymous_demand(VirtAddr::new(GRANT_VA), FRAME_SIZE, PageFlags::rw().user())
            .expect("map demand");
    }
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA + 0x40), false),
        FaultVerdict::Resume,
    );
    assert_eq!(env.exec.paging_in_flight(), 0, "nobody was asked");
}

/// An address nothing covers is fatal, and no page request is invented for it.
#[test]
fn an_unmapped_fault_asks_nobody() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), false),
        FaultVerdict::Fatal,
    );
    assert_eq!(env.exec.paging_in_flight(), 0);
}

/// **A pager must not wait for itself.** `docs/kernel/03`'s anti-deadlock rule:
/// the kernel breaks a self-paging cycle by faulting the request rather than
/// blocking, because the thread that would have to answer is the one that would
/// be blocked. Here the object's pager *is* the faulting process, which is the
/// shortest cycle there is.
///
/// The forbidden outcome is a hang, so what this really asserts is that the
/// call returns at all — and that it left no in-flight edge behind, which would
/// make the next page-in look like a loop.
#[test]
fn a_process_faulting_on_an_object_it_pages_itself_is_refused_not_blocked() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    // The harness's handle 0 names the process's own object, so an object
    // created with it as pager is paged by the process that is about to fault.
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );

    let _ring = event_ring_guard();
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), false),
        FaultVerdict::Fatal,
    );
    assert_eq!(
        env.exec.paging_in_flight(),
        0,
        "a refused request records no edge",
    );
    // **Refused *as a cycle*, and said so.** Every other way this fault could
    // fail also answers `Fatal`, so without naming the record this test would
    // pass with the guard deleted — which is exactly what it is for.
    let records = drained_pager_events();
    assert!(
        records
            .iter()
            .any(|e| e.kind == crate::event::EventKind::PagerObjectFaulted),
        "the cycle refusal is reported, not silent: {records:?}",
    );
}

/// An object with no pager in the graph cannot be served by anybody, so the
/// fault fails now rather than waiting for something that will never come.
#[test]
fn a_paged_object_nobody_serves_faults_rather_than_waiting() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    // Created straight on the executive, so no binding is recorded — the state
    // a kernel-built object would be in if its check forgot to bind it.
    let pager = ObjectId::from_raw(0x99);
    let object = h
        .exec
        .memory_create_paged(ObjectId::from_raw(0x60), 1, pager)
        .expect("create_paged");
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .space_mut()
            .map_object(
                VirtAddr::new(GRANT_VA),
                FRAME_SIZE,
                PageFlags::rw().user(),
                object,
                0,
            )
            .expect("map_object");
    }
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), false),
        FaultVerdict::Fatal,
    );
    assert_eq!(env.exec.paging_in_flight(), 0);
}

// --- The write fault: recording a page dirty before letting the store land ---

/// A store to a supplied page is recorded dirty **and then** allowed. The order
/// is the whole point: a page made writable before it is recorded is one a
/// write-back can miss, and the write is lost with nothing having gone wrong.
#[test]
fn a_write_to_a_supplied_page_records_it_dirty_then_grants() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    assert_eq!(
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };
    // Supplied read-only, so the page starts clean and a store must fault.
    assert!(!h.exec.memory_is_dirty(object, 0));

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA + 0x40), true),
        FaultVerdict::Resume,
    );
    assert!(
        env.exec.memory_is_dirty(object, 0),
        "the page is recorded dirty",
    );
    assert_eq!(env.exec.memory_dirty_count(object), 1);
    let process = env
        .processes
        .process_of_thread(env.caller)
        .expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA))
            .expect("resident")
            .1
            .writable(),
        "and the store can now land",
    );
}

/// A read of a supplied page leaves it clean. Dirtying on any fault would have
/// every page written back whether or not anybody changed it.
#[test]
fn reading_a_supplied_page_does_not_dirty_it() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]);
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    // A resident page faulting on a read is drift, not a dirty transition.
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), false),
        FaultVerdict::Fatal,
    );
    assert_eq!(env.exec.memory_dirty_count(object), 0);
}

/// **The bound is a bound.** A writer that dirties every page of an object past
/// its ceiling is refused rather than allowed to keep going; a limit that never
/// stopped anybody would be a number in a struct.
#[test]
fn a_writer_past_the_dirty_bound_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    // As many pages as the object may hold, so the bound is reached with pages
    // left over — a bound met only by running out of object proves nothing.
    let pages = crate::memory::MAX_OBJECT_PAGES as u64;
    let args = paged_create_args(&mut upage, pages * FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    for page in 0..pages {
        let args = page_supply_args(&mut upage, handle, page * FRAME_SIZE, source);
        assert_eq!(
            run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
            "supply page {page}",
        );
    }
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    assert_eq!(
        run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(0),
    );
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    let mut granted = 0u64;
    for page in 0..pages {
        let va = VirtAddr::new(GRANT_VA + page * FRAME_SIZE);
        if resolve_user_fault(&mut env, va, true) == FaultVerdict::Resume {
            granted += 1;
        }
    }
    let limit = u64::from(env.exec.memory_dirty_count(object));
    assert_eq!(
        granted, limit,
        "every granted write dirtied exactly one page"
    );
    assert!(
        granted < pages,
        "the bound stopped a writer with pages still clean: {granted} of {pages}",
    );
}

/// A page written back and marked clean can be written again — the bound is a
/// ceiling on *outstanding* dirty pages, not a lifetime budget.
#[test]
fn a_page_cleaned_by_write_back_can_be_dirtied_again() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]);
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };
    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: None,
            irqs: None,
        };
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), true);
    }
    assert_eq!(h.exec.memory_dirty_count(object), 1);

    // A write-back acknowledged: the page is clean, and re-protecting it makes
    // the next store fault again so it can be re-dirtied.
    h.exec.memory_mark_clean(object, 0);
    assert_eq!(h.exec.memory_dirty_count(object), 0);
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .space_mut()
            .reprotect_ro(VirtAddr::new(GRANT_VA))
            .expect("reprotect");
    }
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), true),
        FaultVerdict::Resume,
    );
    assert_eq!(env.exec.memory_dirty_count(object), 1);
}

// --- Reclaim under real memory pressure ---

/// The page cache is a **reserve**, not a claim: when the machine is short of
/// memory the kernel takes cached pages back, whatever they belong to.
///
/// Driven by the allocator rather than by the cache's own ceiling — those are
/// different limits, and a cache well inside its budget can still be the only
/// memory left to reclaim.
#[test]
fn a_short_allocator_gets_cached_pages_back() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, 4 * FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    for page in 0..4u64 {
        let args = page_supply_args(&mut upage, handle, page * FRAME_SIZE, source);
        assert_eq!(
            run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]),
            DispatchOutcome::Return(0),
            "supply page {page}",
        );
    }
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };
    assert_eq!(h.exec.memory_resident_pages(object), 4);

    // Draw the allocator down to the watermark, so the machine is short while
    // the cache is well inside its own budget — the two limits pulled apart.
    let mut held = std::vec::Vec::new();
    while h.frames.frames_available().unwrap_or(0) > RECLAIM_WATERMARK {
        match h.frames.alloc_frame() {
            Some(frame) => held.push(frame),
            None => break,
        }
    }
    assert!(
        h.exec.memory_dirty_count(object) == 0,
        "every cached page is clean, so every one is reclaimable",
    );

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    let freed = reclaim_for_pressure(&mut env);
    assert!(freed > 0, "pages were given back");
    assert!(
        env.exec.memory_resident_pages(object) < 4,
        "and they came out of the cache",
    );
    assert!(
        env.alloc.frames_available().unwrap_or(0) > RECLAIM_WATERMARK,
        "the machine is above the watermark again",
    );
    for frame in held {
        env.alloc.free_frame(frame);
    }
}

/// **A dirty page is not reclaimed for memory pressure**, even when it is the
/// only page there is. Writing it back needs a message to its service, and
/// blocking a thread that was merely trying to allocate is a worse failure than
/// the allocation — so the answer is to stop reclaiming, not to block.
#[test]
fn memory_pressure_never_takes_a_dirty_page() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, 2 * FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    for page in 0..2u64 {
        let args = page_supply_args(&mut upage, handle, page * FRAME_SIZE, source);
        run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);
    }
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };
    // Every page written, so nothing is clean.
    for page in 0..2u64 {
        assert_eq!(
            h.exec.memory_mark_dirty(object, page * FRAME_SIZE),
            crate::pager::DirtyOutcome::Marked,
        );
    }

    let mut held = std::vec::Vec::new();
    while h.frames.frames_available().unwrap_or(0) > RECLAIM_WATERMARK {
        match h.frames.alloc_frame() {
            Some(frame) => held.push(frame),
            None => break,
        }
    }
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    // It stops rather than spinning, and rather than losing a write.
    assert_eq!(reclaim_for_pressure(&mut env), 0);
    assert_eq!(env.exec.memory_resident_pages(object), 2);
    assert_eq!(env.exec.memory_dirty_count(object), 2);
    for frame in held {
        env.alloc.free_frame(frame);
    }
}

/// An allocation that would have failed succeeds, because a cached page was
/// given back for it. The failure-driven half, which needs no forecast: an
/// allocation that failed is not a prediction about memory, it is memory.
#[test]
fn an_allocation_that_would_fail_takes_a_cached_page_instead() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);

    // Drain the allocator completely — not to the watermark, to nothing.
    let mut held = std::vec::Vec::new();
    while let Some(frame) = h.frames.alloc_frame() {
        held.push(frame);
    }
    assert_eq!(h.frames.frames_available(), Some(0), "nothing left at all");

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    let frame = alloc_frame_reclaiming(&mut env);
    assert!(frame.is_some(), "the cached page paid for it");
    let object = {
        let process = env
            .processes
            .process_of_thread(env.caller)
            .expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };
    assert_eq!(env.exec.memory_resident_pages(object), 0);
    if let Some(frame) = frame {
        env.alloc.free_frame(frame);
    }
    for frame in held {
        env.alloc.free_frame(frame);
    }
}

/// A frame source that will not say how much it has left — the trait's default,
/// and the state of any init-only source with no reclaim.
///
/// It exists to reach the one path a source that *can* answer never takes: with
/// no level to read there is no watermark to be under, so nothing is reclaimed
/// in advance and the first sign of trouble is an allocation that failed.
struct SilentFrameSource(MockFrameSource);

impl tessera_karch::FrameSource for SilentFrameSource {
    fn alloc_frame(&mut self) -> Option<tessera_karch::PhysFrame> {
        self.0.alloc_frame()
    }

    fn retain_frame(&mut self, frame: tessera_karch::PhysFrame) {
        self.0.retain_frame(frame);
    }

    fn free_frame(&mut self, frame: tessera_karch::PhysFrame) {
        self.0.free_frame(frame);
    }

    // `frames_available` deliberately left as the default `None`.
}

/// **The failure path, which only a silent source reaches.** With no level to
/// read the kernel cannot reclaim in advance, so the allocation fails first and
/// the cached page is taken then. Every check that uses a source which *can*
/// answer keeps the pool above water and never gets here — which is why this
/// needs a source that cannot.
#[test]
fn a_silent_allocator_still_gets_a_cached_page_back() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };

    // A source with nothing left and nothing to say about it.
    let mut silent = SilentFrameSource(MockFrameSource::new(0x8000_0000, 0));
    assert_eq!(
        tessera_karch::FrameSource::frames_available(&silent),
        None,
        "it does not answer, which is what puts the kernel on the failure path",
    );

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut silent,
        iommu: None,
        irqs: None,
    };
    let frame = alloc_frame_reclaiming(&mut env);
    assert!(frame.is_some(), "the cached page paid for it");
    assert_eq!(
        env.exec.memory_resident_pages(object),
        0,
        "and it came out of the cache",
    );
}

// --- The write-back window: a store that lands while the service is reading ---

/// A store that arrives while a page's write-back is outstanding is seen by the
/// cache, so the reply cannot mark the page clean over the top of it.
///
/// **Driven through the real fault path, not the cache's own API.** What makes
/// the record trustworthy is that a store *has no other way in*: a pager-backed
/// page is supplied read-only, and only `dirty` ever grants the write. This
/// asserts that whole chain — read-only page, write fault, dispatcher, cache —
/// because a detector wired to anything less would sit there recording nothing.
#[test]
fn a_store_while_a_write_back_is_out_is_recorded() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]);
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    // A first store dirties the page and leaves it writable — the state a page
    // is in when something decides to write it back.
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), true),
        FaultVerdict::Resume,
    );
    assert!(env.exec.memory_is_dirty(object, 0));

    // The window opens exactly as `write_back` opens it.
    env.processes.reprotect_object_page(object, 0);
    env.exec.memory_write_back_started(object, 0);
    let process = env
        .processes
        .process_of_thread(env.caller)
        .expect("process");
    assert!(
        !process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA))
            .expect("resident")
            .1
            .writable(),
        "read-only for the request, or the store below would never fault",
    );

    // The service is reading the page; another thread stores into it.
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA + 8), true),
        FaultVerdict::Resume,
    );

    assert!(
        env.exec.memory_write_back_finished(object, 0),
        "the store landed inside the window, so the page is not what was saved",
    );
    assert!(
        env.exec.memory_is_dirty(object, 0),
        "and it stays dirty: the write-back's reply must not clean it",
    );
}

/// An eviction the cache refuses takes nothing away.
///
/// **The refusal is the reachable case, not a defensive one.** Reclaim writes a
/// dirty page back before taking it, and that request blocks — so by the time
/// the eviction runs, the page it decided about can be dirty again. Unmapping
/// before asking would leave a resident page with no mappings and a caller
/// reporting that it freed nothing.
#[test]
fn an_eviction_the_cache_refuses_leaves_the_mapping_alone() {
    let mut upage = UserPage([0; 4096]);
    let source = upage.0.as_ptr() as u64;
    let mut h = harness(&upage, pager_rights());
    let args = paged_create_args(&mut upage, FRAME_SIZE, 0);
    let handle = match run(
        &mut h,
        SyscallNumber::MemoryCreatePaged,
        [args, 0, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(&mut upage, handle, 0, source);
    run(&mut h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);
    let args = memory_map_args(&mut upage, handle, GRANT_VA, MAP_RW);
    run(&mut h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]);
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), true),
        FaultVerdict::Resume,
    );
    assert!(env.exec.memory_is_dirty(object, 0), "the page is dirty now");

    assert!(
        !evict_page(&mut env, object, 0),
        "a dirty page is not evictable",
    );
    assert_eq!(
        env.exec.memory_resident_pages(object),
        1,
        "and it is still the object's",
    );
    let process = env
        .processes
        .process_of_thread(env.caller)
        .expect("process");
    assert!(
        process
            .space()
            .arch()
            .translate(VirtAddr::new(GRANT_VA))
            .is_some(),
        "the mapping was never taken apart for an eviction that did not happen",
    );
}

/// Gives `object`'s pager a channel, so a `write_back` driven here gets as far
/// as asking. Returns the endpoint the kernel will ask on.
fn pager_channel(h: &mut Harness, object: crate::object::ObjectId) -> crate::ipc::EndpointId {
    let (a, _b) = h.exec.channel_create().expect("channel");
    let pager = h.exec.memory_pager_of(object).expect("pager");
    h.exec.bind_endpoint_object(a, pager);
    a
}

/// ...and pre-queues the service's answer on it.
///
/// The kernel asks from the peer end, so the reply is queued from the endpoint
/// the object is bound to. With the mock context switch returning immediately
/// the round-trip collapses, exactly as it does for `call_harness`: what a host
/// test drives is the decision either side of the call, not the parking in
/// between.
fn answering_pager(h: &mut Harness, object: crate::object::ObjectId, persisted: bool) {
    let a = pager_channel(h, object);
    let reply = crate::isl_binding::memory::WriteBackReply {
        size: crate::isl_binding::memory::WriteBackReply::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        persisted,
    };
    let mut inline = [0u8; crate::isl_binding::memory::WriteBackReply::WIRE_SIZE];
    tessera_isl_runtime::encode(&reply, &mut inline).expect("encode reply");
    let mut message = Message::new(MessageHeader::new(PAGER_INTERFACE_ID, 0));
    message.set_inline(&inline).expect("inline");
    h.exec.stage_reply_from(a, message).expect("stage reply");
}

/// Builds a one-page object supplied, mapped read-write, and dirtied by a real
/// store — the state a page is in when something decides to write it back.
fn dirtied_page(h: &mut Harness, upage: &mut UserPage) -> crate::object::ObjectId {
    let source = upage.0.as_ptr() as u64;
    let args = paged_create_args(upage, FRAME_SIZE, 0);
    let handle = match run(h, SyscallNumber::MemoryCreatePaged, [args, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create failed: {other:?}"),
    };
    let args = page_supply_args(upage, handle, 0, source);
    run(h, SyscallNumber::PageSupply, [args, 0, 0, 0, 0, 0]);
    let args = memory_map_args(upage, handle, GRANT_VA, MAP_RW);
    run(h, SyscallNumber::MapObject, [args, 0, 0, 0, 0, 0]);
    let object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles()
            .lookup(crate::handle::Handle::from_raw(handle))
            .expect("lookup")
            .0
    };
    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA), true),
        FaultVerdict::Resume,
    );
    assert!(
        env.exec.memory_is_dirty(object, 0),
        "dirtied by a real store"
    );
    object
}

/// Whether the page mapped at `GRANT_VA` can currently be stored to.
fn grant_is_writable(h: &mut Harness) -> bool {
    let process = h.processes.process_of_thread(h.caller).expect("process");
    process
        .space()
        .arch()
        .translate(VirtAddr::new(GRANT_VA))
        .expect("resident")
        .1
        .writable()
}

/// A write-back takes the write away **before** it asks, not after it is
/// answered.
///
/// The failed write-back is what makes this visible, and it is the honest case
/// to assert on: there is no reply to mark anything clean, so a page still
/// writable here could only have been left that way by a re-protection that
/// waits for one. While the request is out the page must be unwritable, or a
/// store lands in it with nothing to record the store.
#[test]
fn a_write_back_takes_the_write_away_before_it_asks() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    let object = dirtied_page(&mut h, &mut upage);
    pager_channel(&mut h, object);
    assert!(grant_is_writable(&mut h), "the store left it writable");

    {
        // The request goes out and nothing answers it, so this is the page as
        // it stands while a service has it.
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: None,
            irqs: None,
        };
        assert!(
            !write_back(&mut env, object, 0),
            "nobody persisted it, so it is not clean",
        );
    }
    assert!(h.exec.memory_is_dirty(object, 0), "and it stays dirty");
    assert!(
        !grant_is_writable(&mut h),
        "the write went away with the request, not with the reply",
    );
}

/// **A write-back gives back the reference it took on the page.**
///
/// The window a service reads the page through is opened with `map_shared`,
/// which takes a reference per page, and was closed with `unmap_range`, which
/// releases none — and which also drops the mapping record, so the reference
/// was not merely outstanding but unreachable: teardown walks the records and
/// there was no longer one to walk. The page's count rose on every write-back
/// and never came down, so an object that had been written back could not be
/// reclaimed by anything.
///
/// The count is asserted rather than the consequence, because the consequence
/// is a frame that is never reused — which nothing can wait for. Both
/// directions are checked: a leak would leave it above where it started, and
/// closing the window too hard would leave it below, and the second is worse.
#[test]
fn a_write_back_gives_back_the_reference_it_took() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    let object = dirtied_page(&mut h, &mut upage);
    answering_pager(&mut h, object, true);

    let frame = h
        .exec
        .memory_frame_at(object, 0)
        .expect("the object's page");
    let before = h.frames.references(frame);

    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: None,
            irqs: None,
        };
        assert!(write_back(&mut env, object, 0), "the service persisted it");
    }

    assert_eq!(
        h.frames.references(frame),
        before,
        "the window took a reference on the object's page and must give it back",
    );

    // Twice, because a leak of one per write-back is the shape this had: a
    // single round trip could pass on an off-by-one that a second exposes.
    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: None,
            irqs: None,
        };
        let _ = write_back(&mut env, object, 0);
    }
    assert_eq!(
        h.frames.references(frame),
        before,
        "and the count does not climb with the number of write-backs",
    );
}

/// A write-back a service acknowledges leaves the page clean and unwritable —
/// the ordinary case, which the refusals below must not break.
#[test]
fn an_acknowledged_write_back_cleans_the_page() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    let object = dirtied_page(&mut h, &mut upage);
    answering_pager(&mut h, object, true);

    {
        let mut env = DispatchEnv {
            exec: &mut h.exec,
            processes: &mut h.processes,
            caller: h.caller,
            clock: test_clock,
            alloc: &mut h.frames,
            iommu: None,
            irqs: None,
        };
        assert!(write_back(&mut env, object, 0), "the service persisted it");
    }
    assert!(!h.exec.memory_is_dirty(object, 0), "so it is clean");
    assert!(
        !grant_is_writable(&mut h),
        "and the next store faults, so it can be recorded",
    );
}

/// A page stored to while its write-back was outstanding is **not** marked
/// clean by that write-back's reply, however successful the reply was.
///
/// **This is the write the cache would otherwise lose.** The service persisted
/// what it read; the store landed after it read it. A page marked clean here is
/// one the next eviction drops, taking the store with it and leaving nothing
/// that went wrong.
///
/// The store is placed in the window explicitly because the host round-trip is
/// collapsed — but the arrangement is a real one, not a contrivance: a
/// throttled writer and reclaim can both choose the same page, so a second
/// write-back closing over a store the first one saw is exactly this.
#[test]
fn a_write_back_does_not_clean_a_page_that_was_stored_to_while_it_was_out() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, pager_rights());
    let object = dirtied_page(&mut h, &mut upage);
    answering_pager(&mut h, object, true);

    let mut env = DispatchEnv {
        exec: &mut h.exec,
        processes: &mut h.processes,
        caller: h.caller,
        clock: test_clock,
        alloc: &mut h.frames,
        iommu: None,
        irqs: None,
    };
    // A write-back is already outstanding, and the page takes a store while it
    // is — through the fault path, which is the only way in.
    env.processes.reprotect_object_page(object, 0);
    env.exec.memory_write_back_started(object, 0);
    assert_eq!(
        resolve_user_fault(&mut env, VirtAddr::new(GRANT_VA + 16), true),
        FaultVerdict::Resume,
    );

    assert!(
        !write_back(&mut env, object, 0),
        "persisted, but not what the page holds now",
    );
    assert!(
        env.exec.memory_is_dirty(object, 0),
        "so the page stays dirty and the store survives to the next write-back",
    );
}

// --- ChannelCreate and ProcessGrant: a parent composing a child (D249) ---

/// Builds a `ChannelCreateArgs` (version 2) in the user page, returning its
/// address. `record_at` is the offset the record is to be written at.
fn channel_create_args(upage: &mut UserPage, end0: Rights, end1: Rights, record_at: usize) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let at = 512;
    upage.0[at..at + 4]
        .copy_from_slice(&(crate::syscall::CHANNEL_CREATE_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&2u32.to_le_bytes());
    upage.0[at + 16..at + 24].copy_from_slice(&end0.bits().to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&end1.bits().to_le_bytes());
    upage.0[at + 32..at + 40].copy_from_slice(&(base + record_at as u64).to_le_bytes());
    base + at as u64
}

/// Builds a `ProcessGrantArgs` in the user page, returning its address.
fn process_grant_args(upage: &mut UserPage, process: u32, source: u32, rights: Rights) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let at = 1024;
    upage.0[at..at + 4]
        .copy_from_slice(&(crate::syscall::PROCESS_GRANT_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&process.to_le_bytes());
    upage.0[at + 20..at + 24].copy_from_slice(&source.to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&rights.bits().to_le_bytes());
    base + at as u64
}

/// The two handles the record reports, read back out of the user page.
fn created_handles(upage: &UserPage, record_at: usize) -> (u32, u32) {
    let end0 = u32::from_le_bytes(
        upage.0[record_at + 16..record_at + 20]
            .try_into()
            .expect("four bytes"),
    );
    let end1 = u32::from_le_bytes(
        upage.0[record_at + 20..record_at + 24]
            .try_into()
            .expect("four bytes"),
    );
    (end0, end1)
}

/// A created channel lands as two handles in the caller's own table, reported
/// through the record — and the two ends are each other's peer.
///
/// The peer check is the discriminator: two handles to two objects is what a
/// broken create that made two unrelated endpoints would also produce, and it
/// would pass every other assertion here.
#[test]
fn channel_create_installs_both_ends_and_reports_them() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = channel_create_args(&mut upage, Rights::READ | Rights::WRITE, Rights::WRITE, 64);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCreate,
        [args_ptr, 0, 0, 0, 0, 0],
    );
    assert_eq!(outcome, DispatchOutcome::Return(encode_result(Ok(0))));

    let (end0, end1) = created_handles(&upage, 64);
    assert_ne!(end0, end1, "one channel, two distinct handles");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (obj0, rights0) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(end0))
        .expect("end 0 installed");
    let (obj1, rights1) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(end1))
        .expect("end 1 installed");
    assert_eq!(rights0, Rights::READ | Rights::WRITE);
    assert_eq!(rights1, Rights::WRITE);
    assert_ne!(obj0, obj1);
    // Ids come from the ring-3 range, clear of the ones boot glue picks.
    assert!(obj0.raw() >= crate::ipc::CHANNEL_OBJECT_ID_BASE);
    assert!(obj1.raw() >= crate::ipc::CHANNEL_OBJECT_ID_BASE);

    // The two ends are peers: a message sent on one arrives on the other.
    let a = h.exec.endpoint_of_object(obj0).expect("end 0 resolves");
    let b = h.exec.endpoint_of_object(obj1).expect("end 1 resolves");
    let mut m = Message::new(MessageHeader::new(0, 0));
    m.set_inline(b"peer").expect("inline");
    h.exec.send(a, m).expect("send");
    let arrived = h.exec.receive(b).expect("receive");
    assert_eq!(arrived.inline(), b"peer");
}

/// A version-1 caller is refused and nothing is created. It has nowhere to
/// report the second handle, so serving it would leave a peer nobody holds.
#[test]
fn a_version_one_channel_create_creates_nothing() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = channel_create_args(&mut upage, Rights::READ, Rights::WRITE, 64);
    upage.0[512 + 4..512 + 8].copy_from_slice(&1u32.to_le_bytes());
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCreate,
        [args_ptr, 0, 0, 0, 0, 0],
    );
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Err(KError::Protocol)))
    );
    assert_eq!(created_handles(&upage, 64), (0, 0), "nothing was reported");
}

/// A record pointer outside the caller's mappings takes the whole call down
/// and leaves no handles behind — a channel the caller holds two handles to
/// and cannot learn the numbers of is a slot nothing can ever close.
#[test]
fn a_create_that_cannot_report_installs_nothing() {
    let mut upage = UserPage([0; 4096]);
    let args_ptr = channel_create_args(&mut upage, Rights::READ, Rights::WRITE, 64);
    // Point the record at an address this process has not mapped.
    let at = 512;
    upage.0[at + 32..at + 40].copy_from_slice(&0x7fff_0000_0000u64.to_le_bytes());
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let outcome = run(
        &mut h,
        SyscallNumber::ChannelCreate,
        [args_ptr, 0, 0, 0, 0, 0],
    );
    assert!(
        matches!(outcome, DispatchOutcome::Return(v) if v < 0),
        "an unwritable record must fail the call"
    );
    let process = h.processes.process_of_thread(h.caller).expect("process");
    for handle in 1..4 {
        assert!(
            process
                .handles()
                .lookup(crate::handle::Handle::from_raw(handle))
                .is_err(),
            "handle {handle} was left installed after a failed create"
        );
    }
}

/// Adds a created, not-yet-started child process to the table and installs a
/// handle to it in the caller, returning that handle.
fn add_child(h: &mut Harness) -> u32 {
    let child_obj = ObjectId::from_raw(300);
    let mut frames = MockFrameSource::new(0x2000_0000, 64);
    let space = AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(2))
        .expect("child space");
    h.processes
        .insert(Process::new(child_obj, space))
        .expect("insert child");
    let process = h.processes.process_of_thread(h.caller).expect("process");
    process
        .handles_mut()
        .install(child_obj, Rights::READ | Rights::MAP)
        .expect("install child handle")
        .raw()
}

/// The whole of the claim: a parent creates a channel, hands one end to a
/// child that has not started, and the child holds it — at a handle the kernel
/// reports, carrying exactly the rights the parent chose.
#[test]
fn a_parent_grants_a_capability_to_a_child_that_has_not_started() {
    let mut upage = UserPage([0; 4096]);
    // End 1 is created with TRANSFER because it is the end this parent means
    // to give away: handing a capability on is an authority the creator has to
    // hold, and a create is where it decides which end will travel.
    let create_ptr = channel_create_args(
        &mut upage,
        Rights::READ | Rights::WRITE,
        Rights::WRITE | Rights::TRANSFER,
        64,
    );
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ChannelCreate,
            [create_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Ok(0)))
    );
    let (_end0, end1) = created_handles(&upage, 64);
    let granted_object = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        let (object, _) = process
            .handles()
            .lookup(crate::handle::Handle::from_raw(end1))
            .expect("end 1");
        object
    };
    let child_handle = add_child(&mut h);

    let grant_ptr = process_grant_args(&mut upage, child_handle, end1, Rights::WRITE);
    let outcome = run(
        &mut h,
        SyscallNumber::ProcessGrant,
        [grant_ptr, 0, 0, 0, 0, 0],
    );
    let DispatchOutcome::Return(value) = outcome else {
        panic!("grant was not handled");
    };
    assert!(value >= 0, "grant refused: {value}");
    let installed = crate::handle::Handle::from_raw(value as u32);

    let child = h
        .processes
        .process_of_id(ObjectId::from_raw(300))
        .expect("child");
    let (object, rights) = child
        .handles()
        .lookup(installed)
        .expect("the child holds what it was granted");
    assert_eq!(object, granted_object);
    // Narrowed to what the parent chose, not to what the parent held.
    assert_eq!(rights, Rights::WRITE);
}

/// The kernel narrows and never expands: a right the source does not carry is
/// refused rather than trimmed to what it could give.
#[test]
fn a_grant_wider_than_the_source_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let child_handle = add_child(&mut h);
    let source = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ObjectId::from_raw(400), Rights::READ | Rights::TRANSFER)
            .expect("install a read-only, grantable source")
            .raw()
    };
    let grant_ptr = process_grant_args(
        &mut upage,
        child_handle,
        source,
        Rights::READ | Rights::WRITE,
    );
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ProcessGrant,
            [grant_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    let child = h
        .processes
        .process_of_id(ObjectId::from_raw(300))
        .expect("child");
    assert!(
        child
            .handles()
            .lookup(crate::handle::Handle::from_raw(0))
            .is_err(),
        "a refused grant installed something anyway"
    );
}

/// Handing a capability to somebody else is itself an authority. A process
/// holding a device without `TRANSFER` cannot pass it on.
#[test]
fn a_grant_without_transfer_on_the_source_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let child_handle = add_child(&mut h);
    // Handle 0 is the harness's device capability, installed without TRANSFER.
    let grant_ptr = process_grant_args(&mut upage, child_handle, 0, Rights::READ);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ProcessGrant,
            [grant_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// Once a process is running, what it holds is its own business — a parent
/// reaching in then would be an ambient authority over a process it no longer
/// composes.
#[test]
fn a_grant_to_a_running_process_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let child_handle = add_child(&mut h);
    let source = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ObjectId::from_raw(400), Rights::READ | Rights::TRANSFER)
            .expect("install a grantable source")
            .raw()
    };
    h.processes
        .process_of_id(ObjectId::from_raw(300))
        .expect("child")
        .set_running();
    let grant_ptr = process_grant_args(&mut upage, child_handle, source, Rights::READ);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ProcessGrant,
            [grant_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// A handle the caller genuinely holds, naming something that is not a
/// process, is refused. `DispatchEnv` has no object table, so "is this a
/// process" is answered by whether the id names one — and a handle to a device
/// does not.
#[test]
fn a_grant_to_a_handle_that_is_not_a_process_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    let target = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(ObjectId::from_raw(401), Rights::READ | Rights::MAP)
            .expect("install a non-process target")
            .raw()
    };
    let grant_ptr = process_grant_args(&mut upage, target, 0, Rights::READ);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ProcessGrant,
            [grant_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType)))
    );
}

/// Granting to yourself is `HandleDuplicate` with extra steps, and it is the
/// one way a process could satisfy the created-state check with its own
/// process. Refused by name.
#[test]
fn a_grant_to_the_callers_own_process_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::TRANSFER);
    // The harness's process object is also its device object — one value, two
    // roles — so handle 0 names the caller's own process.
    let grant_ptr = process_grant_args(&mut upage, 0, 0, Rights::READ);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ProcessGrant,
            [grant_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// Composing a child's handle table needs the same authority as composing its
/// address space. A parent that may only start a process it was handed is not
/// thereby entitled to decide what that process can reach.
#[test]
fn a_grant_without_map_on_the_target_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let child_obj = ObjectId::from_raw(301);
    let mut frames = MockFrameSource::new(0x3000_0000, 64);
    let space = AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(3))
        .expect("child space");
    h.processes
        .insert(Process::new(child_obj, space))
        .expect("insert child");
    let (child_handle, source) = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        // READ and WRITE but no MAP: enough to start it, not to compose it.
        let child = process
            .handles_mut()
            .install(child_obj, Rights::READ | Rights::WRITE)
            .expect("install child handle")
            .raw();
        let source = process
            .handles_mut()
            .install(ObjectId::from_raw(402), Rights::READ | Rights::TRANSFER)
            .expect("install a grantable source")
            .raw();
        (child, source)
    };
    let grant_ptr = process_grant_args(&mut upage, child_handle, source, Rights::READ);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::ProcessGrant,
            [grant_ptr, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

// --- PortCreate and PortBind: a process making its own event object (D254) ---

/// A created port lands as a handle in the caller's own table, and it is a
/// *port* — something the executive can resolve and wait on.
///
/// The resolve is the discriminator: a handle to a fresh object is what a
/// create that made no port would also produce, and it would pass every other
/// assertion here.
#[test]
fn port_create_installs_a_handle_that_resolves_to_a_port() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);

    let outcome = run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]);
    let DispatchOutcome::Return(value) = outcome else {
        panic!("PortCreate was not handled");
    };
    assert!(value >= 0, "create refused: {value}");
    let handle = crate::handle::Handle::from_raw(value as u32);

    let (object, rights) = {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process.handles().lookup(handle).expect("the port handle")
    };
    // What a holder can do with a port it made: wait, bind, signal, and hand
    // it on to a driver it starts.
    assert!(rights.contains(Rights::READ));
    assert!(rights.contains(Rights::BIND));
    assert!(rights.contains(Rights::SIGNAL));
    assert!(rights.contains(Rights::TRANSFER));
    // Ids come from the ring-3 range, clear of the ones boot glue picks and of
    // the memory and channel ranges.
    assert!(object.raw() >= crate::port::PORT_OBJECT_ID_BASE);
    assert!(
        h.exec.port_of_object(object).is_some(),
        "the handle names no port"
    );
}

/// Two creates are two ports, not one handle twice.
#[test]
fn two_creates_make_two_ports() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let first = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("first create: {other:?}"),
    };
    let second = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("second create: {other:?}"),
    };
    assert_ne!(first, second);
    let process = h.processes.process_of_thread(h.caller).expect("process");
    let (a, _) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(first))
        .expect("first");
    let (b, _) = process
        .handles()
        .lookup(crate::handle::Handle::from_raw(second))
        .expect("second");
    assert_ne!(a, b, "two creates named one port");
}

/// A bound port is woken by the source it was bound to.
///
/// The wake is the assertion, not the call's return: a `PortBind` that recorded
/// nothing also returns zero.
#[test]
fn a_bound_port_is_woken_by_its_source() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port_handle = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create: {other:?}"),
    };
    let source = 0x2a_u64;
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::PortBind,
            // The signal `PortSignal` raises, and binding anything else is how
            // this test first failed: a port bound to one edge is not woken by
            // another, which is the property the bind exists for.
            [
                u64::from(port_handle),
                source,
                u64::from(crate::exec::SOFTWARE_PORT_SIGNAL),
                0,
                0,
                0
            ]
        ),
        DispatchOutcome::Return(encode_result(Ok(0)))
    );
    // Raising that source on that port delivers an event; the count is what a
    // wait would have returned.
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::PortSignal,
            [u64::from(port_handle), source, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Ok(0))),
        "a bound source could not be raised"
    );
}

/// Binding is where a port's authority is checked. A holder without `BIND`
/// decides nothing about what may wake it.
#[test]
fn a_bind_without_the_bind_right_is_refused() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port_handle = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create: {other:?}"),
    };
    {
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .replace_rights(
                crate::handle::Handle::from_raw(port_handle),
                Rights::READ | Rights::SIGNAL,
            )
            .expect("narrow away BIND");
    }
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::PortBind,
            [u64::from(port_handle), 7, 1, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
}

/// A handle the caller holds that names something other than a port is refused
/// rather than bound to whatever the id happens to reach.
#[test]
fn a_bind_on_a_handle_that_is_not_a_port_is_refused() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::BIND);
    // Handle 0 is the harness's device capability, which carries BIND here and
    // is still not a port.
    assert_eq!(
        run(&mut h, SyscallNumber::PortBind, [0, 7, 1, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::WrongType)))
    );
}

/// A signal number too wide for the field is refused, never truncated.
///
/// Binding to signal 1 because 257 was asked for is a wakeup on the wrong edge,
/// and nothing downstream could tell.
#[test]
fn a_signal_number_that_does_not_fit_is_refused() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let port_handle = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("create: {other:?}"),
    };
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::PortBind,
            [u64::from(port_handle), 7, 257, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping)))
    );
}

// --- DeviceIrqBind: a process routing its own device's line (D255) ---

/// Writes a `DeviceIrqBindArgs` into the user page and answers its address.
fn irq_bind_args(upage: &mut UserPage, device: u32, port: u32, intid: u32) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let at = 1536;
    upage.0[at..at + 4]
        .copy_from_slice(&(crate::syscall::DEVICE_IRQ_BIND_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 8..at + 16].copy_from_slice(&0u64.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&device.to_le_bytes());
    upage.0[at + 20..at + 24].copy_from_slice(&port.to_le_bytes());
    upage.0[at + 24..at + 28].copy_from_slice(&intid.to_le_bytes());
    upage.0[at + 28..at + 32].copy_from_slice(&0u32.to_le_bytes());
    base + at as u64
}

/// A harness whose device handle carries `BIND`, with `intid` wired in the
/// graph, and a port the caller created through the syscall it would really
/// use. Answers the device handle and the port handle.
fn irq_bind_harness(upage: &UserPage, intid: u32, device_rights: Rights) -> (Harness, u32, u32) {
    let mut h = harness(upage, device_rights);
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    h.exec.device_set_mmio_irq(device, intid).expect("wire irq");
    let port = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("port create: {other:?}"),
    };
    (h, 0, port)
}

/// The route a ring-3 caller makes **delivers**, and the call reports the line
/// it was made for.
///
/// Two assertions, and the second is the one that discriminates. A
/// `DeviceIrqBind` that recorded a route in the graph and never bound the port
/// would return the same number and pass every check about the graph — and the
/// driver would park for ever on a completion its port never heard about. That
/// is not hypothetical: it is exactly what `device_route_irq_line` was written
/// to prevent after a passthrough version of it did it.
#[test]
fn a_routed_line_wakes_the_port_the_caller_named() {
    let mut upage = UserPage([0; 4096]);
    let (mut h, device_handle, port_handle) =
        irq_bind_harness(&upage, 79, Rights::READ | Rights::MAP | Rights::BIND);

    let args = irq_bind_args(&mut upage, device_handle, port_handle, 0);
    let outcome = run(&mut h, SyscallNumber::DeviceIrqBind, [args, 0, 0, 0, 0, 0]);
    assert_eq!(
        outcome,
        DispatchOutcome::Return(encode_result(Ok(79))),
        "the call must answer the line it routed, so a driver learns its own \
         source rather than being told out of band",
    );

    // The graph recorded it, for the line reported. Who *holds* it is asserted
    // by `a_ring3_made_route_dies_with_its_maker`, which is the only test here
    // whose caller has an identity distinct from the device.
    let route = h
        .exec
        .irq_route_of_object(ObjectId::from_raw(HARNESS_DEVICE as u32))
        .expect("no route was recorded");
    assert_eq!(route.intid, 79);

    // And the line actually reaches that port: one waiter's worth of signal
    // lands, which a graph-only route would not produce.
    assert_eq!(
        h.exec.port_signal(79, crate::exec::IRQ_PORT_SIGNAL, 1),
        1,
        "the route was recorded but the port was never bound to the line",
    );
}

/// Without `BIND` on the **device**, there is no route.
///
/// `MAP` is not enough and that is the design: a bus controller hands a
/// function's registers to a driver it will not also let redirect the line, and
/// it can only draw that line because the rights are separate.
#[test]
fn routing_a_device_without_bind_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let (mut h, device_handle, port_handle) =
        irq_bind_harness(&upage, 79, Rights::READ | Rights::MAP | Rights::TRANSFER);

    let args = irq_bind_args(&mut upage, device_handle, port_handle, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceIrqBind, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    // The refusal is a refusal, not a return value: nothing was recorded and
    // the line reaches nobody.
    assert_eq!(
        h.exec
            .irq_route_of_object(ObjectId::from_raw(HARNESS_DEVICE as u32)),
        None
    );
    assert_eq!(h.exec.port_signal(79, crate::exec::IRQ_PORT_SIGNAL, 1), 0);
}

/// Without `BIND` on the **port**, there is no route either.
///
/// The same right `PortBind` checks, because this is a port bind: a device
/// route that skipped it would be a way to bind a port without the authority to
/// bind it, which is the whole check `PortBind` exists to make.
#[test]
fn routing_to_a_port_without_bind_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let (mut h, device_handle, _created) =
        irq_bind_harness(&upage, 79, Rights::READ | Rights::MAP | Rights::BIND);

    // A second handle on the same port, narrowed to READ. A holder can wait on
    // it and cannot say what may wake it.
    let readonly = {
        let object = {
            let process = h.processes.process_of_thread(h.caller).expect("process");
            let (object, _) = process
                .handles()
                .lookup(crate::handle::Handle::from_raw(_created))
                .expect("the created port");
            object
        };
        let process = h.processes.process_of_thread(h.caller).expect("process");
        process
            .handles_mut()
            .install(object, Rights::READ)
            .expect("install a read-only view")
            .raw()
    };

    let args = irq_bind_args(&mut upage, device_handle, readonly, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceIrqBind, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::AccessDenied)))
    );
    assert_eq!(
        h.exec
            .irq_route_of_object(ObjectId::from_raw(HARNESS_DEVICE as u32)),
        None
    );
}

/// A caller may choose among **its own** device's lines and cannot name
/// somebody else's.
///
/// The line is checked against the graph rather than taken as given, so naming
/// a line this device does not have is refused — which is what stops a holder
/// of one device from redirecting another's interrupts into a port it holds.
#[test]
fn a_line_the_device_does_not_have_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let (mut h, device_handle, port_handle) =
        irq_bind_harness(&upage, 79, Rights::READ | Rights::MAP | Rights::BIND);
    // A second line this device really does have, so the negative below is
    // about *ownership* of the line and not about naming one at all.
    h.exec
        .device_add_mmio_irq(ObjectId::from_raw(HARNESS_DEVICE as u32), 80)
        .expect("a second line");

    let mine = irq_bind_args(&mut upage, device_handle, port_handle, 80);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceIrqBind, [mine, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(80))),
        "a device's own second line must be routable — a multi-queue \
         controller has one per queue",
    );

    let theirs = irq_bind_args(&mut upage, device_handle, port_handle, 81);
    assert_eq!(
        run(
            &mut h,
            SyscallNumber::DeviceIrqBind,
            [theirs, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping)))
    );
    assert_eq!(
        h.exec.port_signal(81, crate::exec::IRQ_PORT_SIGNAL, 1),
        0,
        "a line the graph never gave this device reached the caller's port",
    );
}

/// A device with no line at all is refused rather than routed to line zero.
#[test]
fn a_device_with_no_line_is_refused() {
    let mut upage = UserPage([0; 4096]);
    // No `device_set_mmio_irq`: the graph knows this device and knows no line
    // for it, which is the state of every windowless capability.
    let mut h = harness(&upage, Rights::READ | Rights::MAP | Rights::BIND);
    let port_handle = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("port create: {other:?}"),
    };
    let args = irq_bind_args(&mut upage, 0, port_handle, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceIrqBind, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Err(KError::InvalidMapping)))
    );
}

/// The route a ring-3 caller made is swept up when that caller dies.
///
/// **The reason the holder is the calling process and not the device.** A
/// driver host does not give its interrupts back explicitly, and one that dies
/// without doing so must not leave a line firing into a port nobody holds —
/// the same sweep a departing driver's register windows and DMA leases already
/// go through, now reached by a route user space made for itself.
///
/// **The caller here is a second process, and it has to be.** The harness gives
/// its process the device's own object id, so `process.id()` and the device are
/// one number and a holder recorded as either would pass. Written that way this
/// test held with the holder replaced by the device, which is to say it was not
/// measuring the holder at all.
#[test]
fn a_ring3_made_route_dies_with_its_maker() {
    let mut upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    h.irqs = Some(MockRouter::default());
    let device = ObjectId::from_raw(HARNESS_DEVICE as u32);
    h.exec.device_set_mmio_irq(device, 79).expect("wire irq");

    // A driver of its own: a process whose identity is not the device's, with
    // the same user page mapped so its syscalls can read arguments out of it.
    let driver_obj = ObjectId::from_raw(0x71);
    let driver = {
        let mut space =
            AddressSpace::<MockAddressSpace>::new(&mut h.frames, 0xffff_9000_0000_0000, Asid(2))
                .expect("space");
        space
            .map_anonymous(
                VirtAddr::new(upage.0.as_ptr() as u64),
                FRAME_SIZE,
                PageFlags::rw().user(),
                &mut h.frames,
            )
            .expect("map the args page");
        let thread = Thread::<MockContextOps>::spawn(
            never,
            0,
            VirtAddr::new(0xffff_e000_0001_0000),
            2,
            &mut space,
            &mut h.frames,
        )
        .expect("thread");
        let slot = h.exec.add_thread(thread).expect("add thread");
        let id = h
            .exec
            .scheduler()
            .thread_id(slot)
            .expect("the thread just admitted has an identity");
        let mut process = Process::new(driver_obj, space);
        process.add_thread(id).expect("own thread");
        process
            .handles_mut()
            .install(device, Rights::READ | Rights::MAP | Rights::BIND)
            .expect("install the device");
        h.processes.insert(process).expect("insert");
        id
    };
    h.caller = driver;

    let port_handle = match run(&mut h, SyscallNumber::PortCreate, [0, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) if v >= 0 => v as u32,
        other => panic!("port create: {other:?}"),
    };
    let args = irq_bind_args(&mut upage, 0, port_handle, 0);
    assert_eq!(
        run(&mut h, SyscallNumber::DeviceIrqBind, [args, 0, 0, 0, 0, 0]),
        DispatchOutcome::Return(encode_result(Ok(79)))
    );
    assert_eq!(
        h.exec.irq_route_of_object(device).expect("route").holder,
        driver_obj,
        "the route is held by whoever asked for it",
    );

    let Harness {
        mut exec,
        mut processes,
        mut irqs,
        caller,
        ..
    } = h;
    {
        let process = processes.process_of_thread(caller).expect("process");
        assert_eq!(
            exec.end_device_irq_routes(
                process,
                irqs.as_mut()
                    .map(|r| r as &mut dyn crate::devmgr::InterruptRouter),
            ),
            1,
            "the departing driver's own route was not found by the sweep",
        );
    }
    assert_eq!(exec.irq_route_of_object(device), None);
    assert_eq!(
        irqs.as_ref().expect("router").masked,
        std::vec![79],
        "the controller went on delivering a line whose holder is gone",
    );
}

/// The clock reads, advances, and refuses what it does not answer.
///
/// **The advance is the property worth asserting.** A clock that returned a
/// constant would satisfy every type in the signature and be useless for the
/// one thing a caller wants it for, which is to tell that time passed.
#[test]
fn the_clock_reads_and_advances() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    let first = match run(&mut h, SyscallNumber::ClockRead, [1, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) => v,
        other => panic!("unhandled: {other:?}"),
    };
    let second = match run(&mut h, SyscallNumber::ClockRead, [1, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) => v,
        other => panic!("unhandled: {other:?}"),
    };
    assert!(first >= 0, "a clock read is not an error: {first}");
    assert!(
        second > first,
        "the clock must advance: {first} then {second}"
    );
}

/// `BOOT` is defined and refused, rather than answered with the monotonic
/// value — the two differ across a suspend nothing here accounts for.
#[test]
fn the_boot_clock_is_refused_rather_than_guessed() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    match run(&mut h, SyscallNumber::ClockRead, [2, 0, 0, 0, 0, 0]) {
        DispatchOutcome::Return(v) => assert!(v < 0, "BOOT must refuse, got {v}"),
        other => panic!("unhandled: {other:?}"),
    }
}

/// A clock nobody has defined is an argument error, not a silent zero.
#[test]
fn an_unknown_clock_is_an_argument_error() {
    let upage = UserPage([0; 4096]);
    let mut h = harness(&upage, Rights::READ | Rights::MAP);
    for which in [0u64, 3, u64::MAX] {
        match run(&mut h, SyscallNumber::ClockRead, [which, 0, 0, 0, 0, 0]) {
            DispatchOutcome::Return(v) => assert!(v < 0, "clock {which} must refuse"),
            other => panic!("unhandled: {other:?}"),
        }
    }
}

/// A clock for the tests: monotonic, and it advances.
///
/// **Counted rather than read**, so a test asserting that time moves asserts
/// something about the syscall rather than about how fast the host is. Each
/// call is one nanosecond later than the last, which is the weakest property
/// a monotonic clock has and the one every caller depends on.
fn test_clock() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(0);
    NOW.fetch_add(1, Ordering::SeqCst)
}
