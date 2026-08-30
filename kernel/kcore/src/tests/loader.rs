// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::loader` — the process lifecycle, on the mock port.
//!
//! **These exist because the lifecycle stopped being one port's.** While it
//! lived in `kernel/kernel/src/main.rs` the only thing that could exercise it
//! was that port's boot check, which meant every rule it enforces — the
//! create-process authority, W^X, the double-start refusal, the reclaim — was
//! checked once, on one architecture, through QEMU. Here they are checked
//! against a mock in milliseconds, which is where a rule about authority
//! belongs (build/README.md, D251).
//!
//! **What is not here, and why.** A create that runs out of frames is not
//! tested: the mock builds an address space without drawing one, so a test
//! asserting the refusal would pass against a loader that never checked — it
//! would be measuring the mock. Exhaustion of the *process table* is checked,
//! because that bound is real on every port.

use super::*;
use crate::process::MAX_PROCESSES;
use crate::syscall::encode_result;
use crate::vm::Asid;
use std::boxed::Box;
use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

/// A page-aligned host buffer standing in for the caller's user memory: its
/// host address is below the mock `USER_ADDRESS_MAX`, so mapping the same VA
/// range in the mock space makes `validate_user_range` accept it and the raw
/// copy read the real bytes.
#[repr(align(4096))]
struct UserPage([u8; 4096]);

/// What the mock port lends the loader.
///
/// Deliberately the whole of it: if a test harness needs more than a real port
/// does, the seam is in the wrong place.
struct MockLoader {
    kernel: AddressSpace<MockAddressSpace>,
    frames: MockFrameSource,
    /// Windows handed out, and whether each is in use — the same pool shape a
    /// port keeps, because the reclaim test is about giving one back.
    windows: [(u64, bool); 4],
}

impl MockLoader {
    fn new(kernel: AddressSpace<MockAddressSpace>) -> Self {
        Self {
            kernel,
            frames: MockFrameSource::new(0x4000_0000, 512),
            windows: [
                (0xffff_e100_0000_0000, false),
                (0xffff_e200_0000_0000, false),
                (0xffff_e300_0000_0000, false),
                (0xffff_e400_0000_0000, false),
            ],
        }
    }

    /// Windows currently taken — what a reclaim test asserts fell back to zero.
    fn windows_in_use(&self) -> usize {
        self.windows.iter().filter(|(_, busy)| *busy).count()
    }
}

impl crate::loader::LoaderSupport<MockAddressSpace> for MockLoader {
    fn new_user_space(
        &mut self,
        _alloc: &mut dyn FrameSource,
    ) -> Result<AddressSpace<MockAddressSpace>, KError> {
        AddressSpace::<MockAddressSpace>::new(&mut self.frames, 0xffff_8000_0000_0000, Asid(9))
    }

    fn kernel_space(&mut self) -> &mut AddressSpace<MockAddressSpace> {
        &mut self.kernel
    }

    fn take_kernel_stack(&mut self) -> Option<VirtAddr> {
        for (va, busy) in self.windows.iter_mut() {
            if !*busy {
                *busy = true;
                return Some(VirtAddr::new(*va));
            }
        }
        None
    }

    fn release_kernel_stack(&mut self, window: VirtAddr) {
        for (va, busy) in self.windows.iter_mut() {
            if *va == window.as_u64() {
                *busy = false;
            }
        }
    }

    fn user_stack_pages(&self) -> u64 {
        2
    }

    fn kernel_stack_pages(&self) -> u64 {
        2
    }
}

/// Everything one loader call needs.
struct Fixture {
    support: MockLoader,
    objects: ObjectTable,
    exec: Box<crate::exec::Executive<MockContextOps>>,
    processes: Box<ProcessTable<MockAddressSpace>>,
    frames: MockFrameSource,
    caller: ThreadId,
    /// The job the caller was seeded with, carrying `create-process`.
    job_handle: u32,
}

extern "C" fn never(_: usize) -> ! {
    loop {
        core::hint::spin_loop()
    }
}

fn fixture(upage: &UserPage) -> Fixture {
    let mut frames = MockFrameSource::new(0x1000_0000, 512);
    let mut exec = Box::new(crate::exec::Executive::<MockContextOps>::new(
        4, 0, test_now,
    ));
    let mut space =
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(1))
            .expect("caller space");
    let uva = upage.0.as_ptr() as u64;
    assert!(uva + FRAME_SIZE <= MockAddressSpace::USER_ADDRESS_MAX);
    space
        .map_anonymous(
            VirtAddr::new(uva),
            FRAME_SIZE,
            PageFlags::rw().user(),
            &mut frames,
        )
        .expect("map the caller's argument page");

    let thread = Thread::<MockContextOps>::spawn(
        never,
        0,
        VirtAddr::new(0xffff_f000_0000_0000),
        2,
        &mut space,
        &mut frames,
    )
    .expect("caller thread");
    let slot = exec.add_thread(thread).expect("admit");
    let caller = exec.scheduler().thread_id(slot).expect("identity");
    exec.run();

    let mut objects = ObjectTable::new();
    let caller_obj = objects.create(ObjectType::Process).expect("caller object");
    let job = objects.create(ObjectType::Job).expect("job object");
    let mut process = Process::new(caller_obj, space);
    process.add_thread(caller).expect("own thread");
    process.set_running();
    let job_handle = process
        .handles_mut()
        .install(job, Rights::CREATE_PROCESS)
        .expect("seed the job")
        .raw();
    let mut processes = Box::new(ProcessTable::<MockAddressSpace>::new());
    processes.insert(process).expect("insert caller");

    let kernel = AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0))
        .expect("kernel space");
    Fixture {
        support: MockLoader::new(kernel),
        objects,
        exec,
        processes,
        frames,
        caller,
        job_handle,
    }
}

/// Runs `ProcessCreate` against the fixture.
///
/// A free function that destructures rather than a method: the loader borrows
/// four of the fixture's fields at once, and only a split borrow lets it.
fn call_create(f: &mut Fixture, args_ptr: u64) -> i64 {
    let Fixture {
        support,
        objects,
        processes,
        frames,
        caller,
        ..
    } = f;
    let mut env = crate::loader::LoaderEnv { support, objects };
    crate::loader::create(&mut env, processes, frames, *caller, args_ptr)
}

/// Live processes in the table — what a create is supposed to add one to.
fn process_count(f: &Fixture) -> usize {
    (0..MAX_PROCESSES)
        .filter(|index| f.processes.get(*index).is_some())
        .count()
}

/// Builds a `ProcessCreateArgs` at offset 0 of the user page.
fn create_args(upage: &mut UserPage, job: u32) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let at = 0;
    upage.0[at..at + 4]
        .copy_from_slice(&(crate::syscall::PROCESS_CREATE_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&job.to_le_bytes());
    base + at as u64
}

/// A process is created under a job the caller holds `create-process` on, and
/// the parent is handed map and start authority over what it made.
#[test]
fn create_makes_a_process_under_a_job_the_caller_holds() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let args_ptr = create_args(&mut upage, job);

    let before = process_count(&f);
    let value = call_create(&mut f, args_ptr);
    assert!(value >= 0, "create refused: {value}");

    assert_eq!(process_count(&f), before + 1, "no process was inserted");
    let caller = f.processes.process_of_thread(f.caller).expect("caller");
    let (child_obj, rights) = caller
        .handles()
        .lookup(crate::handle::Handle::from_raw(value as u32))
        .expect("the parent holds a handle to its child");
    assert!(rights.contains(Rights::MAP), "no authority to populate it");
    assert!(rights.contains(Rights::WRITE), "no authority to start it");
    assert_eq!(
        f.objects.object_type(child_obj),
        Some(ObjectType::Process),
        "the handle names something that is not a process"
    );
}

/// **The authority gate, and it is the only one.** A caller holding every other
/// capability in the system and no `create-process` job makes no process.
#[test]
fn create_without_the_job_authority_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    // A handle the caller genuinely holds, on an object that is not a job it
    // may create under.
    let other = f.objects.create(ObjectType::Memory).expect("object");
    let handle = f
        .processes
        .process_of_thread(f.caller)
        .expect("caller")
        .handles_mut()
        .install(other, Rights::READ | Rights::WRITE | Rights::MAP)
        .expect("install")
        .raw();
    let args_ptr = create_args(&mut upage, handle);

    let before = process_count(&f);
    assert_eq!(
        call_create(&mut f, args_ptr),
        encode_result(Err(KError::AccessDenied)),
        "a caller with no create-process authority made a process"
    );
    assert_eq!(process_count(&f), before, "a refused create inserted one");
}

/// A handle that names nothing is refused before anything is built.
#[test]
fn create_with_an_unheld_job_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let args_ptr = create_args(&mut upage, 99);
    let before = process_count(&f);
    assert!(
        call_create(&mut f, args_ptr) < 0,
        "an unheld job handle was accepted"
    );
    assert_eq!(process_count(&f), before);
}

/// The loader draws no frames it does not need: a refused create leaves the
/// allocator where it found it.
#[test]
fn a_refused_create_draws_nothing() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let args_ptr = create_args(&mut upage, 99);
    let before = f.support.frames.handed_out();
    let _ = call_create(&mut f, args_ptr);
    assert_eq!(
        f.support.frames.handed_out(),
        before,
        "a refused create built an address space anyway"
    );
}

/// Every kernel-stack window is handed out once and no more. Two threads on one
/// kernel stack is not a resource shortage, it is corruption, so exhaustion is
/// a refusal.
#[test]
fn kernel_stack_windows_are_never_shared() {
    let kernel = {
        let mut frames = MockFrameSource::new(0x8000_0000, 16);
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0))
            .expect("kernel space")
    };
    let mut support = MockLoader::new(kernel);
    use crate::loader::LoaderSupport;

    let mut taken = std::vec::Vec::new();
    while let Some(window) = support.take_kernel_stack() {
        assert!(
            !taken.contains(&window.as_u64()),
            "window {:#x} was handed out twice",
            window.as_u64()
        );
        taken.push(window.as_u64());
    }
    assert_eq!(taken.len(), 4, "the pool handed out the wrong count");
    assert_eq!(support.windows_in_use(), 4);

    // And giving one back makes exactly one available again — the property a
    // restart loop depends on.
    support.release_kernel_stack(VirtAddr::new(taken[1]));
    assert_eq!(support.windows_in_use(), 3);
    assert_eq!(
        support.take_kernel_stack().map(|v| v.as_u64()),
        Some(taken[1]),
        "the released window was not the one handed back"
    );
    assert!(support.take_kernel_stack().is_none(), "the pool grew");
}

/// The process table's bound is respected: a create past it is refused rather
/// than overwriting a slot.
#[test]
fn create_past_the_process_bound_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let args_ptr = create_args(&mut upage, job);
    let mut made = 0;
    while process_count(&f) < MAX_PROCESSES {
        if call_create(&mut f, args_ptr) < 0 {
            break;
        }
        made += 1;
    }
    assert!(made > 0, "the fixture could not create even one process");
    assert!(
        call_create(&mut f, args_ptr) < 0,
        "a create past the table's bound was accepted"
    );
}

/// Runs `AddressSpaceMap` against the fixture.
fn call_map(f: &mut Fixture, args_ptr: u64) -> i64 {
    let Fixture {
        support,
        objects,
        processes,
        frames,
        caller,
        ..
    } = f;
    let mut env = crate::loader::LoaderEnv { support, objects };
    crate::loader::address_space_map(&mut env, processes, frames, *caller, args_ptr)
}

/// Runs `ProcessStart` against the fixture.
fn call_start(f: &mut Fixture, args_ptr: u64) -> i64 {
    let Fixture {
        support,
        objects,
        exec,
        processes,
        frames,
        caller,
        ..
    } = f;
    let mut env = crate::loader::LoaderEnv { support, objects };
    crate::loader::start(&mut env, exec, processes, frames, *caller, args_ptr)
}

/// Builds an `AddressSpaceMapArgs` at offset 512 of the user page.
fn map_args(upage: &mut UserPage, child: u32, vaddr: u64, len: u64, rights: u64) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let at = 512;
    upage.0[at..at + 4]
        .copy_from_slice(&(crate::syscall::ADDRESS_SPACE_MAP_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&child.to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&vaddr.to_le_bytes());
    upage.0[at + 32..at + 40].copy_from_slice(&len.to_le_bytes());
    upage.0[at + 40..at + 48].copy_from_slice(&rights.to_le_bytes());
    // No source: zero-filled pages, which is what a `.bss` tail is and what a
    // test that is not about copying wants.
    upage.0[at + 48..at + 56].copy_from_slice(&0u64.to_le_bytes());
    base + at as u64
}

/// Builds a `ProcessStartArgs` at offset 1024 of the user page, carrying no
/// startup message.
fn start_args(upage: &mut UserPage, child: u32, entry: u64, stack: u64) -> u64 {
    start_args_with_message(upage, child, entry, stack, 0, 0, 0)
}

/// Builds a `ProcessStartArgs` naming a startup message.
fn start_args_with_message(
    upage: &mut UserPage,
    child: u32,
    entry: u64,
    stack: u64,
    message_ptr: u64,
    message_len: u64,
    message_va: u64,
) -> u64 {
    let base = upage.0.as_ptr() as u64;
    let at = 1024;
    upage.0[at..at + 4]
        .copy_from_slice(&(crate::syscall::PROCESS_START_ARGS_SIZE as u32).to_le_bytes());
    upage.0[at + 4..at + 8].copy_from_slice(&2u32.to_le_bytes());
    upage.0[at + 16..at + 20].copy_from_slice(&child.to_le_bytes());
    upage.0[at + 24..at + 32].copy_from_slice(&entry.to_le_bytes());
    upage.0[at + 32..at + 40].copy_from_slice(&stack.to_le_bytes());
    upage.0[at + 40..at + 48].copy_from_slice(&7u64.to_le_bytes());
    upage.0[at + 48..at + 56].copy_from_slice(&message_ptr.to_le_bytes());
    upage.0[at + 56..at + 64].copy_from_slice(&message_len.to_le_bytes());
    upage.0[at + 64..at + 72].copy_from_slice(&message_va.to_le_bytes());
    base + at as u64
}

/// A child is created, populated and started, and the start takes exactly one
/// kernel-stack window and leaves the child runnable.
#[test]
fn start_makes_a_child_runnable_and_takes_one_window() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let child = call_create(&mut f, create_args(&mut upage, job)) as u32;

    let entry = 0x40_0000;
    // Read + execute, which is what a code segment asks for.
    let map = map_args(&mut upage, child, entry, FRAME_SIZE, 0x9);
    assert!(call_map(&mut f, map) >= 0, "map refused");

    let windows_before = f.support.windows_in_use();
    let start = start_args(&mut upage, child, entry, 0x20_0000);
    assert_eq!(call_start(&mut f, start), encode_result(Ok(0)));
    assert_eq!(
        f.support.windows_in_use(),
        windows_before + 1,
        "a start took the wrong number of kernel-stack windows"
    );

    // The child is Running and owns a thread the scheduler admitted.
    let child_obj = {
        let caller = f.processes.process_of_thread(f.caller).expect("caller");
        caller
            .handles()
            .lookup(crate::handle::Handle::from_raw(child))
            .expect("child handle")
            .0
    };
    let threads = f
        .processes
        .process_of_id(child_obj)
        .expect("child")
        .thread_ids();
    let id = threads.iter().flatten().next().copied().expect("a thread");
    assert!(
        f.exec.scheduler().index_of(id).is_some(),
        "the child's thread is not on this CPU's scheduler"
    );
}

/// A second start is refused. It would spawn a thread into a process that
/// already has one running against the same stack.
#[test]
fn a_second_start_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let child = call_create(&mut f, create_args(&mut upage, job)) as u32;
    let entry = 0x40_0000;
    assert!(call_map(&mut f, map_args(&mut upage, child, entry, FRAME_SIZE, 0x9)) >= 0);
    let start = start_args(&mut upage, child, entry, 0x20_0000);
    assert_eq!(call_start(&mut f, start), encode_result(Ok(0)));

    let windows = f.support.windows_in_use();
    assert_eq!(
        call_start(&mut f, start),
        encode_result(Err(KError::AccessDenied)),
        "a process was started twice"
    );
    assert_eq!(
        f.support.windows_in_use(),
        windows,
        "a refused start kept a kernel-stack window"
    );
}

/// The child's live mappings, for a test that has to tell a refusal from a
/// half-done map.
fn child_mappings(f: &mut Fixture, child: u32) -> usize {
    let child_obj = {
        let caller = f.processes.process_of_thread(f.caller).expect("caller");
        caller
            .handles()
            .lookup(crate::handle::Handle::from_raw(child))
            .expect("child handle")
            .0
    };
    f.processes
        .process_of_id(child_obj)
        .expect("child")
        .space()
        .arch()
        .len()
}

/// **W^X, refused before anything is mapped.**
///
/// The mapping count is the assertion and the error code is not, which took an
/// inversion to discover: `AddressSpace::protect_range` refuses a writable and
/// executable range too, so deleting the loader's own check still produced a
/// refusal — and a test that only read the result passed against a loader that
/// had stopped checking. What that loader actually does is map the pages
/// writable, *then* fail to re-protect them, leaving the child holding a
/// writable mapping at an address the request was refused for.
#[test]
fn a_write_execute_mapping_is_refused_before_anything_is_mapped() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let child = call_create(&mut f, create_args(&mut upage, job)) as u32;
    let before = child_mappings(&mut f, child);
    // READ | WRITE | EXECUTE.
    let map = map_args(&mut upage, child, 0x40_0000, FRAME_SIZE, 0xb);
    assert_eq!(
        call_map(&mut f, map),
        encode_result(Err(KError::WXViolation))
    );
    assert_eq!(
        child_mappings(&mut f, child),
        before,
        "a refused W^X request left pages mapped in the child"
    );
}

/// Populating a child needs `MAP` on the handle naming it. A parent that may
/// only start a process it was handed does not thereby get to fill it.
#[test]
fn a_map_without_map_authority_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let child = call_create(&mut f, create_args(&mut upage, job)) as u32;
    {
        let caller = f.processes.process_of_thread(f.caller).expect("caller");
        caller
            .handles_mut()
            .replace_rights(
                crate::handle::Handle::from_raw(child),
                Rights::READ | Rights::WRITE,
            )
            .expect("narrow away MAP");
    }
    let map = map_args(&mut upage, child, 0x40_0000, FRAME_SIZE, 0x9);
    assert_eq!(
        call_map(&mut f, map),
        encode_result(Err(KError::AccessDenied))
    );
}

/// A destination past the child's user half is out of range, not out of
/// memory — and a caller learns which.
#[test]
fn a_mapping_past_the_user_half_is_refused() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let child = call_create(&mut f, create_args(&mut upage, job)) as u32;
    let map = map_args(
        &mut upage,
        child,
        MockAddressSpace::USER_ADDRESS_MAX,
        FRAME_SIZE,
        0x9,
    );
    assert_eq!(
        call_map(&mut f, map),
        encode_result(Err(KError::InvalidMapping))
    );
}

/// The size of the objects the lifecycle builds on a syscall stack.
///
/// Printed rather than asserted: what a port's kernel stack can hold is the
/// port's, and the number is what a reader needs when a `ProcessCreate` dies in
/// its prologue.
#[test]
fn report_process_size() {
    std::println!(
        "Process = {} bytes, AddressSpace = {} bytes",
        core::mem::size_of::<Process<MockAddressSpace>>(),
        core::mem::size_of::<AddressSpace<MockAddressSpace>>(),
    );
}

// --- The startup message (D261) ---

/// The message the parent asked for lands as a **user-writable, non-executable
/// page in the child**, at the address the parent named.
///
/// **The bytes themselves are boot-proven, not proven here**, and that is the
/// mock's own division: `MockAddressSpace::write_bytes_to_frame` is a no-op
/// because physical frames are not real memory in a host test. What the boot
/// proves is stronger than a memcpy anyway — `grant-probe` *decodes* the
/// message and sends on the endpoint it names, so a message that arrived
/// wrong makes the send fail and `roottask.child-spoke` disappear.
///
/// What is checkable here is the shape: that a page appears in the child's own
/// space at the right address with the right rights. The rights are the
/// discriminating half — a message delivered executable would be a parent
/// handing a child code, which is exactly what the startup message must not be.
#[test]
fn a_startup_message_maps_a_page_in_the_child() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let child = call_create(&mut f, create_args(&mut upage, job)) as u32;

    let entry = 0x40_0000;
    let map = map_args(&mut upage, child, entry, FRAME_SIZE, 0x9);
    assert!(call_map(&mut f, map) >= 0, "map refused");

    const MESSAGE_LEN: u64 = 24;
    let message_ptr = upage.0.as_ptr() as u64 + 2048;
    let message_va = 0x6000_0000;
    let start = start_args_with_message(
        &mut upage,
        child,
        entry,
        0x20_0000,
        message_ptr,
        MESSAGE_LEN,
        message_va,
    );
    assert_eq!(call_start(&mut f, start), encode_result(Ok(0)));

    let rights = child_space(&mut f, child)
        .rights_at(VirtAddr::new(message_va))
        .expect("no page was mapped at the address the parent named");
    assert!(rights.is_user(), "the child cannot read its own message");
    assert!(rights.writable(), "the message page is read-only");
    assert!(
        !rights.executable(),
        "a startup message must not be a way to deliver code",
    );
}

/// A start carrying no message maps nothing extra.
///
/// The negative half, and it is about cost rather than correctness: every
/// program in this tree that wants a plain scalar passes `message_len = 0`, and
/// a delivery that mapped a page anyway would charge each of them a frame it
/// never asked for.
#[test]
fn a_start_without_a_message_maps_nothing() {
    let mut upage = UserPage([0; 4096]);
    let mut f = fixture(&upage);
    let job = f.job_handle;
    let child = call_create(&mut f, create_args(&mut upage, job)) as u32;

    let entry = 0x40_0000;
    let map = map_args(&mut upage, child, entry, FRAME_SIZE, 0x9);
    assert!(call_map(&mut f, map) >= 0, "map refused");
    let before = child_space(&mut f, child).mapping_count();

    let start = start_args(&mut upage, child, entry, 0x20_0000);
    assert_eq!(call_start(&mut f, start), encode_result(Ok(0)));

    // The stack `spawn_user` maps is the only mapping a plain start adds.
    assert_eq!(
        child_space(&mut f, child).mapping_count(),
        before + 1,
        "a start with no message mapped a page",
    );
}

/// The child's address space, by the handle its parent holds it under.
fn child_space(f: &mut Fixture, child: u32) -> &crate::vm::AddressSpace<MockAddressSpace> {
    let object = f
        .processes
        .process_of_thread(f.caller)
        .expect("the caller")
        .handles()
        .lookup(crate::handle::Handle::from_raw(child))
        .expect("the child handle")
        .0;
    f.processes
        .process_of_id(object)
        .expect("the child process")
        .space()
}

/// A clock for the tests: monotonic, advancing a nanosecond a call.
///
/// **Counted rather than read**, so a test about a deadline asserts something
/// about the deadline rather than about how fast the host is. Defined per test
/// module rather than shared: these modules are attached by `#[path]` and have
/// no common parent to hang a helper on.
fn test_now() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(0);
    NOW.fetch_add(1, Ordering::SeqCst)
}
