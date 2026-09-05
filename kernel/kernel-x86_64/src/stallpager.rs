// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A pager that never answers, and the reader that is told so.
//!
//! `docs/kernel/03` requires that a pager which does not respond leaves its
//! consumers observing **faulted ranges rather than indefinite hangs**. A page
//! request that is never answered would otherwise leave the faulting thread
//! blocked for ever, the run unwinding to boot, and nothing delivered to the
//! reader at all — no fault, no error, no record. The thread would simply stop
//! existing as far as anything could tell.
//!
//! Here the pager receives the request and parks in a second receive it will
//! never be woken from. The reader must come back with a **fault**, the object
//! must be left faulted, and the miss must be counted — all three, because each
//! alone can be true for the wrong reason: a reader can fault because the
//! mapping was wrong, an object can be faulted with nobody noticing, and a
//! counter can move without a thread being released.
//!
//! **This is not a timeout.** The kernel does not guess that the pager is late;
//! it observes that nothing is runnable while a page-in is outstanding, which
//! is a fact about the machine rather than a guess about the pager.
//!
//! Split out of `main.rs` by area (build/README.md, D265).
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("External Pager
//! Protocol")

use crate::*;

/// Where the reader maps the object it will never get a page of.
///
/// **Substituted into the blob rather than written twice.** An address the
/// assembly spelled out and the check also named could drift apart, and the
/// failure would be a reader faulting at an address nobody was watching.
const STALL_VA: u64 = 0x0000_0000_5000_0000;

/// Where the object lands in each program, which is not the same number and
/// says what each one holds. The pager is installed its endpoint first, so its
/// object is the second capability it has; the reader holds **nothing else at
/// all**, so its object is the first. Each blob names its own, and the check
/// asserts both rather than assuming the table hands out what it expects.
const PAGER_OBJECT_HANDLE: u32 = 1;
const READER_OBJECT_HANDLE: u32 = 0;

pub(crate) const STALL_PAGER_EP_OBJ: ObjectId = ObjectId::from_raw(0x1c0);
pub(crate) const STALL_KERNEL_EP_OBJ: ObjectId = ObjectId::from_raw(0x1c1);

// The ring-3 PAGER. Takes the page request off its endpoint and then parks in a
// second receive nothing will ever send to: alive, in a legitimate state, and
// never going to answer — which is the case that would otherwise strand the
// reader for ever.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global stall_pager_start
.global stall_pager_end
stall_pager_start:
    lea rdi, [rip + stall_pager_recv_args]
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # SyscallNumber::ChannelRecv
    syscall
    lea rdi, [rip + stall_pager_recv_args]
    xor esi, esi
    mov eax, 13                        # and parks again, for ever
    syscall
    xor edi, edi
    mov eax, 5                         # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
.balign 8
stall_pager_recv_args:
    .long 88                           # ChannelMsgArgs: size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0                            # interface_id (any, on a receive)
    .quad 0                            # txn_id
    .long 0                            # method_id
    .long 0                            # msg_flags (blocking)
    .quad 0x70000000                   # inline_ptr: this program's stack page
    .quad 64                           # inline_len
    .quad 0                            # handles_ptr
    .quad 0                            # handle_count
    .quad 0x70000100                   # installed_ptr
    .quad 1                            # installed_cap
stall_pager_end:
.text
"#
);

// The ring-3 READER. Maps the object and loads from it. The load must not
// return: a reader that got past it read a page that does not exist.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global stall_reader_start
.global stall_reader_end
stall_reader_start:
    lea rdi, [rip + stall_reader_map_args]
    mov eax, 46                        # SyscallNumber::MemoryMapObject
    syscall
    mov rcx, {VA}                      # STALL_VA
    mov rax, [rcx]                     # the load nobody will answer
    mov edi, 1                         # DebugWrite: only reached if it resumed
    xor esi, esi
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
.balign 8
stall_reader_map_args:
    .long 32                           # MemoryMapArgs: size
    .long 1                            # version
    .quad 0                            # flags
    .long 0                            # memory = handle raw 0 (the object)
    .long 1                            # rights = READ
    .quad {VA}                         # vaddr = STALL_VA
stall_reader_end:
.text
"#,
    VA = const STALL_VA,
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` blocks
// above; the extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    static stall_pager_start: u8;
    static stall_pager_end: u8;
    static stall_reader_start: u8;
    static stall_reader_end: u8;
}

/// What the run established.
pub(crate) struct StallOutcome {
    /// The fault the reader was left with, and the vector it arrived on.
    pub(crate) vector: u64,
    /// Page-in misses the supervisor counted, and escalations it did not.
    pub(crate) misses: u32,
    pub(crate) escalations: u32,
}

/// Runs a reader against a pager that will not answer.
pub(crate) fn stallpager_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<StallOutcome, u32> {
    use kcore::rights::Rights;

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    let (pager_side, kernel_side) = exec_ref().channel_create().map_err(|_| 1u32)?;
    exec_ref().bind_endpoint_object(pager_side, STALL_PAGER_EP_OBJ);
    exec_ref().bind_endpoint_object(kernel_side, STALL_KERNEL_EP_OBJ);

    let kstacks = kstack_mark();

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(crate::loader::syscall_handler) };
    crate::syscalls::set_observer(bind_observer);
    set_page_fault_resolver(crate::syscalls::shared_page_fault_resolver);
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    crate::syscalls::publish_frames(frames);

    let pager_len = (&raw const stall_pager_end as usize) - (&raw const stall_pager_start as usize);
    let (mut pager, pager_thread) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        &raw const stall_pager_start,
        pager_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    let reader_len =
        (&raw const stall_reader_end as usize) - (&raw const stall_reader_start as usize);
    let (mut reader, reader_thread) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        &raw const stall_reader_start,
        reader_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );

    // The endpoint the kernel will call the pager on, and nothing else: this
    // program's whole authority is one channel it never answers.
    pager
        .handles_mut()
        .install(STALL_PAGER_EP_OBJ, Rights::READ)
        .map_err(|_| 2u32)?;
    let object = exec_ref()
        .memory_create_paged(pager.id(), 1, STALL_PAGER_EP_OBJ)
        .map_err(|_| 3u32)?;
    exec_ref()
        .paging_bind(object, STALL_PAGER_EP_OBJ)
        .map_err(|_| 4u32)?;
    if pager
        .handles_mut()
        .install(object, Rights::READ | Rights::SUPPLY)
        .map_err(|_| 5u32)?
        .raw()
        != PAGER_OBJECT_HANDLE
    {
        return Err(6);
    }
    if reader
        .handles_mut()
        .install(object, Rights::READ | Rights::MAP)
        .map_err(|_| 7u32)?
        .raw()
        != READER_OBJECT_HANDLE
    {
        return Err(8);
    }

    // Nothing has been supplied, and nothing will be.
    if exec_ref().memory_resident_pages(object) != 0 {
        return Err(9);
    }
    let misses_before = exec_ref().page_in_misses();
    let escalations_before = exec_ref().page_in_escalations();

    pager.set_running();
    reader.set_running();
    let pager_proc = processes_insert(pager).map_err(|_| 10u32)?;
    let reader_proc = processes_insert(reader).map_err(|_| 11u32)?;
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = judge_stall(object, misses_before, escalations_before);

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [reader_thread, pager_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [reader_proc, pager_proc] {
            if let Some(mut gone) = processes.remove(process) {
                exec_ref().release_memory_of(gone.id(), frames, None);
                gone.space_mut().teardown(frames);
            }
        }
    }
    // **The size `chan_build_process` maps**, not the one the class checks
    // use: a release that named the wrong length unmaps nothing, the bump
    // pointer goes back anyway, and the next check maps over a window that is
    // still there — which arrives as `AlreadyMapped` in a demo three checks
    // later.
    kstack_release(kernel_vm, kstacks, USER_KSTACK_PAGES);
    outcome
}

/// Reads what the run left. Four things, and each alone can be true for the
/// wrong reason.
fn judge_stall(
    object: kcore::object::ObjectId,
    misses_before: u32,
    escalations_before: u32,
) -> Result<StallOutcome, u32> {
    // 1. The reader was left a fault rather than left blocked. A reader that
    //    resumed would have reported through `DebugWrite` instead.
    if !BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(20);
    }
    if BIND_REPORT_COUNT.load(Ordering::SeqCst) != 0 {
        return Err(21);
    }
    // 2. The object is faulted, so the next reader is refused immediately
    //    rather than sent to the same silence.
    if !exec_ref().memory_is_faulted(object) {
        return Err(22);
    }
    // 3. And the miss was counted. Without this the first two could both hold
    //    while the kernel had learned nothing.
    let misses = exec_ref().page_in_misses();
    if misses != misses_before + 1 {
        return Err(23);
    }
    // 4. One miss is not yet an escalation: the policy is three, and a check
    //    that let this move would be asserting the wrong threshold.
    let escalations = exec_ref().page_in_escalations();
    if escalations != escalations_before {
        return Err(24);
    }
    // 5. And nothing is left in flight — a page-in that was abandoned rather
    //    than completed would leave the graph holding an edge for ever.
    if exec_ref().paging_in_flight() != 0 {
        return Err(25);
    }
    Ok(StallOutcome {
        vector: BIND_FAULT[0].load(Ordering::SeqCst),
        misses,
        escalations,
    })
}
