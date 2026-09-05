// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A writer runs out of dirty pages, and the service persists one so it can
//! carry on.
//!
//! `docs/kernel/03` says a producer that dirties faster than its pager writes
//! back is **throttled at the write fault** — held until there is room, not
//! refused. Holding needs something to release the hold, and this is it: the
//! writing thread blocks inside its own store while the kernel asks the
//! object's service to persist a page, and resumes when the answer comes.
//!
//! The writer is never the service, which is what makes the hold safe to take
//! inline: a client at the bound is not the thread that answers the write-back.
//!
//! **And the drained page is written again.** Page zero was persisted to make
//! room, so it is clean — and a clean page that is still *writable* takes that
//! store with no fault, which means nothing records it and the write is dropped
//! by the next eviction. That last store is what says the fault was put back.
//!
//! Split out of `main.rs` by area (build/README.md, D265).
//!
//! Normative: docs/kernel/03-paging-faults-and-exceptions.md ("Write-Back And
//! Throttling")

use crate::*;

/// Where the writer maps the object, and how much of it there is. The address
/// is substituted into the blob rather than written twice, for the reason the
/// stalling-pager check gives.
const WB_VA: u64 = 0x0000_0000_5100_0000;
const WB_PAGES: u64 = kcore::memory::MAX_OBJECT_PAGES as u64;

/// Stores the writer makes: one past half the object, which is where the dirty
/// bound is. The store that meets the bound is the one that blocks.
const WB_WRITES: u64 = (kcore::memory::MAX_OBJECT_PAGES as u64 / 2) + 1;

/// What each program reports, folded into the sink by XOR so the run is
/// finished when both have spoken and neither can stand in for the other.
const WB_SERVICE_TAG: u64 = 0x0b_ac_0b_ac_0b_ac_0b_ac;
const WB_WRITER_TAG: u64 = 0x1a_1d_1a_1d_1a_1d_1a_1d;
const WB_SINK_EXPECTED: u64 = WB_SERVICE_TAG ^ WB_WRITER_TAG;

pub(crate) const WB_SERVICE_EP_OBJ: ObjectId = ObjectId::from_raw(0x1d0);
pub(crate) const WB_KERNEL_EP_OBJ: ObjectId = ObjectId::from_raw(0x1d1);

// The ring-3 SERVICE: takes a write-back request, reads the page the kernel
// mapped for it, and answers "persisted".
//
// **A resident server, because more than one page gets written back.** The
// writer dirties past the bound, is released, and then writes the drained page
// again — which meets the bound a second time and needs a second answer. A
// service that answered once would leave the writer's last store refused.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global wb_service_start
.global wb_service_end
wb_service_start:
    # **The reply body goes on the stack, not in this page.** A blob's data
    # labels are link-time addresses and this program runs at `USER_CODE_VA`;
    # an `inline_ptr` naming one would point at whatever is at that address in
    # ring 3, which is nothing. The stack page is a fixed VA this program owns,
    # so the pointer in the args below is a constant and the bytes are written
    # here (build/README.md, D333).
    mov r13, 0x70000400
    mov dword ptr [r13], 24            # WriteBackReply: size
    mov dword ptr [r13 + 4], 1         # version
    mov qword ptr [r13 + 8], 0         # flags
    mov qword ptr [r13 + 16], 1        # persisted = 1
    mov r15, 0x70000220                # where the request's `source` lands
    mov r14, 1                         # report the tag once, on the first pass
3:
    lea rdi, [rip + wb_recv_args]
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # ChannelRecv
    syscall
    # Read the page the kernel mapped for this request, so a window that was
    # never mapped faults here rather than being reported persisted.
    mov rcx, [r15]                     # the request's `source`
    mov rdx, [rcx]
    # Answer: persisted = 1.
    lea rdi, [rip + wb_reply_args]
    xor esi, esi
    mov eax, 27                        # ChannelReplyContinue, never a plain
    syscall                            # reply: this server has more to do
    test r14, r14
    jz 3b
    xor r14, r14
    mov rdi, 0x0bac0bac0bac0bac
    xor esi, esi
    mov eax, 1                         # DebugWrite: the service was here
    syscall
    jmp 3b
.balign 8
wb_recv_args:
    .long 88                           # ChannelMsgArgs: size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0                            # interface_id (any, on a receive)
    .quad 0                            # txn_id
    .long 0                            # method_id
    .long 0                            # msg_flags (blocking)
    .quad 0x70000200                   # inline_ptr: the request buffer
    .quad 64                           # inline_len
    .quad 0                            # handles_ptr
    .quad 0                            # handle_count
    .quad 0x70000300                   # installed_ptr
    .quad 1                            # installed_cap
.balign 8
wb_reply_args:
    .long 88
    .long 4
    .quad 0
    .quad 0
    .quad 0
    .long 0
    .long 0
    .quad 0x70000400                   # inline_ptr: the reply, on the stack
    .quad 24                           # inline_len
    .quad 0
    .quad 0
    .quad 0
    .quad 0
wb_service_end:
.text
"#
);

// The ring-3 WRITER: maps the object read-write and stores one word per page.
// The store that meets the dirty bound blocks inside the instruction until the
// service answers.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global wb_writer_start
.global wb_writer_end
wb_writer_start:
    lea rdi, [rip + wb_map_args]
    mov eax, 46                        # MemoryMapObject
    syscall
    mov rcx, {VA}                      # WB_VA
    mov rdx, {WRITES}
2:
    mov [rcx], rdx
    add rcx, 4096
    dec rdx
    jnz 2b
    # **And write the drained page again.** Page 0 was persisted to make room,
    # so it is clean — and a clean page still writable takes this store with no
    # fault, which means nothing records it and the write is dropped by the next
    # eviction. This is the store that says the fault was put back.
    mov rcx, {VA}
    mov qword ptr [rcx], 0xf00d
    mov rdi, 0x1a1d1a1d1a1d1a1d
    xor esi, esi
    mov eax, 1                         # DebugWrite
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
.balign 8
wb_map_args:
    .long 32                           # MemoryMapArgs: size
    .long 1                            # version
    .quad 0                            # flags
    .long 0                            # memory = handle raw 0 (the object)
    .long 3                            # rights = READ | WRITE
    .quad {VA}                         # vaddr = WB_VA
wb_writer_end:
.text
"#,
    WRITES = const WB_WRITES,
    VA = const WB_VA,
);

// SAFETY: these name the two blobs' bounds, defined by the `global_asm!` blocks
// above; the extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    static wb_service_start: u8;
    static wb_service_end: u8;
    static wb_writer_start: u8;
    static wb_writer_end: u8;
}

/// What the run established.
pub(crate) struct WritebackOutcome {
    /// Dirty pages the object holds when the run ends, which must be the bound:
    /// the writer filled it, one was drained, and the last store filled it again.
    pub(crate) dirty: u32,
    pub(crate) bound: u32,
}

/// Runs a writer against its own service, past the dirty bound.
pub(crate) fn writeback_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<WritebackOutcome, u32> {
    use kcore::rights::Rights;

    // SAFETY: the boot CPU alone; a fresh table and executive for this check.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }
    let (service_side, kernel_side) = exec_ref().channel_create().map_err(|_| 1u32)?;
    exec_ref().bind_endpoint_object(service_side, WB_SERVICE_EP_OBJ);
    exec_ref().bind_endpoint_object(kernel_side, WB_KERNEL_EP_OBJ);

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

    let service_len = (&raw const wb_service_end as usize) - (&raw const wb_service_start as usize);
    let (mut service, service_thread) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        &raw const wb_service_start,
        service_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    let writer_len = (&raw const wb_writer_end as usize) - (&raw const wb_writer_start as usize);
    let (mut writer, writer_thread) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        &raw const wb_writer_start,
        writer_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );

    service
        .handles_mut()
        .install(WB_SERVICE_EP_OBJ, Rights::READ)
        .map_err(|_| 2u32)?;
    // The object, **fully supplied**: this check is about writing, and a
    // page-in in the middle would be a second mechanism under test.
    let object = exec_ref()
        .memory_create_paged(service.id(), WB_PAGES as usize, WB_SERVICE_EP_OBJ)
        .map_err(|_| 3u32)?;
    exec_ref()
        .paging_bind(object, WB_SERVICE_EP_OBJ)
        .map_err(|_| 4u32)?;
    for page in 0..WB_PAGES {
        let frame = frames.alloc().ok_or(5u32)?;
        exec_ref()
            .memory_supply(object, page as usize, frame)
            .map_err(|_| 6u32)?;
    }
    // The service holds `SUPPLY`: it answers for the contents, which is what a
    // write-back is. The writer holds `WRITE`, and is never asked to persist.
    service
        .handles_mut()
        .install(object, Rights::READ | Rights::SUPPLY)
        .map_err(|_| 7u32)?;
    if writer
        .handles_mut()
        .install(object, Rights::READ | Rights::WRITE | Rights::MAP)
        .map_err(|_| 8u32)?
        .raw()
        != 0
    {
        return Err(9);
    }

    service.set_running();
    writer.set_running();
    let service_proc = processes_insert(service).map_err(|_| 10u32)?;
    let writer_proc = processes_insert(writer).map_err(|_| 11u32)?;

    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    crate::syscalls::withdraw_frames();

    let outcome = judge_writeback(object);

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once. The service is still parked in `recv`: a resident server
    // has no exit, and what ended the run is the writer having reported.
    unsafe {
        for thread in [writer_thread, service_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for process in [writer_proc, service_proc] {
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

/// Reads what the run left.
fn judge_writeback(object: kcore::object::ObjectId) -> Result<WritebackOutcome, u32> {
    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(20);
    }
    // **Both programs spoke**, folded by XOR: the writer got through its stores
    // and the service answered at least one write-back. Either alone leaves a
    // different word, so neither can stand in for the other.
    let mut sink = 0u64;
    for slot in &BIND_REPORTS {
        sink ^= slot.load(Ordering::SeqCst);
    }
    if sink != WB_SINK_EXPECTED {
        return Err(21);
    }
    // The object is **at** its bound, not over it: the writer filled it, one
    // page was drained to make room, and the last store filled it again.
    let dirty = exec_ref().memory_dirty_count(object);
    // The bound is half the object, which is where `kcore::memory` throttles.
    let bound = (kcore::memory::MAX_OBJECT_PAGES / 2) as u32;
    if dirty != bound {
        return Err(22);
    }
    Ok(WritebackOutcome { dirty, bound })
}
