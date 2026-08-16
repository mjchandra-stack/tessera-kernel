// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tessera kernel boot glue for x86-64: the only crate that knows which
//! boot protocol is in use. Translates the Limine handoff into
//! `tessera-karch` boot-info types, brings up the early console, and hands
//! control to the kernel core.
//!
//! Boot sequence per docs/architecture/01-system-architecture.md ("Boot
//! Flow") step 4: CPU-local state, memory management, interrupt
//! controllers, timers, early console — built up across this milestone's
//! steps.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md
//! Budget: none (init path)

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod limine;

use core::alloc::Layout;
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicU16, AtomicU64, AtomicUsize, Ordering,
};
use kcore::panic::PanicDisposition;
use tessera_karch::{
    AddressSpaceOps, CpuOps, ExitCode, FRAME_SIZE, FrameSource, KError, MemoryKind, MemoryRegion,
    PageFlags, PhysAddr, PhysFrame, PlatformExit, VirtAddr,
};
use tessera_karch_x86_64::{
    ContextSwitch, Cpu, DebugExit, KernelAddressSpace, KernelSection, SyscallFrame, TrapFrame,
    Uart16550, read_tsc_serialized, set_page_fault_resolver, set_syscall_handler,
    set_user_fault_handler, tsc_invariant,
};
use tessera_kcore as kcore;
use tessera_kcore::bench::Stats;
use tessera_kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
use tessera_kcore::elf;
use tessera_kcore::exec::Executive;
use tessera_kcore::handle::{Handle, HandleTable};
use tessera_kcore::ipc::{EndpointId, Message, MessageHeader, TransferredHandle};
use tessera_kcore::job::{JobLimits, Member, SIGNAL_EMPTY, SIGNAL_MEMBER_EXIT};
use tessera_kcore::kprint;
use tessera_kcore::kprintln;
use tessera_kcore::object::{ObjectId, ObjectTable, ObjectType};
use tessera_kcore::pager::{
    DeadlineOutcome, DirtyOutcome, MAX_CACHED_PAGES, MissOutcome, ObjectCache, PageInResult,
    PageInSupervisor, SelfPagingGraph, WriteBackReservation,
};
use tessera_kcore::process::{Process, ProcessState, ProcessTable};
use tessera_kcore::rights::Rights;
use tessera_kcore::sched::Scheduler;
use tessera_kcore::syscall::{
    self, ADDRESS_SPACE_MAP_ARGS_SIZE, PROCESS_CREATE_ARGS_SIZE, PROCESS_START_ARGS_SIZE,
    SyscallNumber, decode_address_space_map_args, decode_duplicate_args,
    decode_process_create_args, decode_process_start_args, encode_result, read_user,
    sys_handle_close, sys_handle_duplicate, sys_handle_query_rights, validate_user_range,
};
use tessera_kcore::thread::{Thread, ThreadId, ThreadState};
use tessera_kcore::verdict::{DemoId, DemoVerdict, Outcome, record as verdict};
use tessera_kcore::vm::{AddressSpace, Asid, FaultOutcome};

/// The kernel version string, from the crate metadata.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Deliberately executes `ud2` after bring-up to exercise the trap path:
/// the boot must end in a full register dump and a failure exit. Flip only
/// for local verification; CI boots with this off.
const TRAP_SELF_TEST: bool = false;

/// Deliberately overflows a guarded kernel stack to exercise the guard-page
/// path: the overflow must fault onto the per-CPU exception stack and be
/// reported as a kernel stack overflow, then exit with failure. Flip only for
/// local verification; CI boots with this off.
const STACK_GUARD_SELF_TEST: bool = false;

/// Backing storage for the global console. A `static mut` is the honest
/// representation of "one mutable device object created before
/// concurrency exists"; the single `&mut` is taken exactly once, below.
static mut UART: Uart16550 = Uart16550::com1();

/// Normalized boot memory map. Sized generously; the boot path reports
/// loudly if the bootloader hands over more regions than this.
const MAX_MEMORY_REGIONS: usize = 128;
static mut MEMORY_MAP: [MemoryRegion; MAX_MEMORY_REGIONS] = [MemoryRegion {
    base: PhysAddr::new(0),
    len: 0,
    kind: MemoryKind::Reserved,
}; MAX_MEMORY_REGIONS];

/// Initial kernel heap: 1 MiB carved from the first long-enough run of
/// contiguous usable frames, addressed through the HHDM.
const HEAP_FRAMES: u64 = 256;

/// Boot timer rate; the scheduler quantum and run length are measured in
/// these ticks.
const TICK_HZ: u32 = 100;

/// Scratch virtual range the architecture-conformance battery maps and
/// unmaps. Clear of the kernel image, the direct map, the vmap region and
/// every demo's own range.
const CONFORMANCE_SCRATCH: u64 = 0xffff_b000_0000_0000;

/// x86-64 machine code for `extern "C" fn() -> u64` returning
/// `tessera_arch_conformance::SENTINEL`, for the instruction-cache case:
///
/// ```text
///   mov rax, 0x5e17c0de
///   ret
/// ```
///
/// Written as bytes rather than assembled from a symbol on purpose — the case
/// needs instructions that were *stored as data* into a fresh frame, which is
/// exactly what taking a symbol's address would avoid testing.
const SENTINEL_CODE: &[u8] = &[
    0x48, 0xc7, 0xc0, 0xde, 0xc0, 0x17, 0x5e, // mov rax, 0x5e17c0de
    0xc3, // ret
];

// Kernel-image section boundaries, emitted by the linker script.
// SAFETY: the block only declares linker-defined symbols; no code ever reads
// their contents — only `&raw const` addresses are taken, which accesses no
// memory — so the declarations introduce no unsafe operation.
unsafe extern "C" {
    static __requests_start: u8;
    static __requests_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
}

/// The kernel image's sections and the permissions each must carry once the
/// kernel owns its page tables: code executes but never writes, rodata is
/// read-only, and data (with bss) and the bootloader requests region are
/// writable but never executable — the write-XOR-execute split.
fn kernel_sections() -> [KernelSection; 4] {
    [
        // The whole first (writable) segment, up to .text: the bootloader
        // requests region plus the GOT and any other compiler/linker-placed
        // RW-NX data the linker puts before .text. Mapping to `__text_start`
        // (not `__requests_end`) guarantees none of it is left unmapped after
        // the CR3 switch — a GOT that outgrew the requests region faulted.
        KernelSection {
            virt_start: &raw const __requests_start as u64,
            virt_end: &raw const __text_start as u64,
            flags: PageFlags::rw().global(),
        },
        KernelSection {
            virt_start: &raw const __text_start as u64,
            virt_end: &raw const __text_end as u64,
            flags: PageFlags::rx().global(),
        },
        KernelSection {
            virt_start: &raw const __rodata_start as u64,
            virt_end: &raw const __rodata_end as u64,
            flags: PageFlags::ro().global(),
        },
        KernelSection {
            virt_start: &raw const __data_start as u64,
            virt_end: &raw const __data_end as u64,
            flags: PageFlags::rw().global(),
        },
    ]
}

/// Highest physical address the boot map describes, rounded up to a 2 MiB
/// boundary so the direct map's huge pages cover every frame the kernel can
/// touch (RAM, boot structures, and device ranges alike).
fn max_physical_address(map: &[MemoryRegion]) -> u64 {
    let mut max = 0u64;
    for region in map {
        if let Some(end) = region.end()
            && end.as_u64() > max
        {
            max = end.as_u64();
        }
    }
    max.div_ceil(TWO_MIB) * TWO_MIB
}

/// 2 MiB, the direct map's huge-page size.
const TWO_MIB: u64 = 2 * 1024 * 1024;

/// One PML4 slot: 512 GiB of virtual address space.
const SLOT_SIZE: u64 = 1 << 39;

/// The candidate slots for the direct map — canonical higher half, below the
/// kernel VMAP region.
const FIRST_CANDIDATE_SLOT: u64 = 300;
const CANDIDATE_SLOTS: u64 = 80;

/// The PML4 slot a canonical higher-half address falls in.
const fn slot_of(va: u64) -> u64 {
    (va >> 39) & 0x1ff
}

/// The fixed higher-half addresses something else has already been promised.
///
/// **Written as the addresses themselves rather than as slot numbers**, because
/// the numbers are what went wrong. This list had two ranges missing — the
/// conformance scratch range and the far-read window — and both were invisible
/// as long as the entries were bare integers with no way to see which region
/// each stood for. Every fixed higher-half address in this file belongs here,
/// and spelling them as the constants makes a missing one something a reader can
/// look for.
const RESERVED_REGIONS: [u64; 5] = [
    // The bootloader HHDM.
    0xffff_8000_0000_0000,
    // The far-read window the PCI check maps a device BAR into.
    PCI_FAR_READ_VA,
    // The architecture-conformance scratch range.
    CONFORMANCE_SCRATCH,
    // The kernel VMAP region, which the kstack allocator and the filesystem
    // self-test range also sit inside.
    KERNEL_VMAP_BASE,
    // The kernel image, in the last slot.
    0xffff_ff80_0000_0000,
];

/// Picks the direct map's starting slot, given how many slots it will span.
///
/// **The span is the whole point.** The previous version chose one slot as
/// though the map occupied one, and on this machine the boot memory map reaches
/// a terabyte — device ranges, not RAM — so the map covers *two*. A base one
/// slot below a reserved region therefore collided with it, which is a boot
/// that fails roughly once in forty and passes every other time.
///
/// Returns `None` when nothing fits, rather than picking a base that does not:
/// a machine whose direct map cannot be placed clear of everything else is a
/// machine that must say so (docs/lifecycle/04, "No Silent Fallback").
fn direct_map_base_for(entropy: u64, max_phys: u64) -> Option<u64> {
    let span_slots = max_phys.div_ceil(SLOT_SIZE).max(1);
    let fits = |start: u64| {
        RESERVED_REGIONS
            .iter()
            .map(|va| slot_of(*va))
            .all(|reserved| reserved < start || reserved >= start + span_slots)
    };
    let candidates = (0..CANDIDATE_SLOTS)
        .map(|i| FIRST_CANDIDATE_SLOT + i)
        .filter(|slot| fits(*slot));
    let count = candidates.clone().count() as u64;
    if count == 0 {
        return None;
    }
    candidates
        .clone()
        .nth((entropy % count) as usize)
        .map(|slot| 0xffff_0000_0000_0000 | (slot << 39))
}

/// Chooses the kernel direct-map base: a randomized canonical higher-half PML4
/// slot (KASLR) whose whole span is clear of every region already spoken for.
/// Entropy is RDRAND when the CPU offers it, otherwise the timestamp counter —
/// a weak boot-time fallback (documented as deviation D6), not the eventual
/// kernel CSPRNG.
fn choose_direct_map_base(max_phys: u64) -> Option<u64> {
    let entropy = Cpu::hw_random().unwrap_or_else(tessera_karch_x86_64::read_tsc);
    direct_map_base_for(entropy, max_phys)
}

/// Checks the chooser against **every draw it could have made**, not only the
/// one it did.
///
/// A collision here is a boot that fails a small fraction of the time and
/// passes the rest, which is exactly the shape of bug a test suite does not
/// catch and a person eventually stops believing. Walking the whole candidate
/// space costs eighty iterations once per boot and turns it into a fact.
///
/// **It measures the span in bytes, from `max_phys`, and compares addresses.**
/// Sharing the chooser's slot arithmetic would make it agree with whatever the
/// chooser assumed — which is the mistake being fixed, so a check that repeated
/// it would have passed the broken version. The two must disagree about
/// something for one to catch the other.
fn direct_map_choice_is_sound(max_phys: u64) -> bool {
    for draw in 0..CANDIDATE_SLOTS {
        let Some(base) = direct_map_base_for(draw, max_phys) else {
            return false;
        };
        let end = base.saturating_add(max_phys);
        for reserved in RESERVED_REGIONS {
            if reserved >= base && reserved < end {
                return false;
            }
        }
    }
    true
}

/// Keeps the boot stack reachable at the bootloader HHDM base after the direct
/// map is randomized away, by mapping the 2 MiB region containing the current
/// stack pointer plus the region below it (downward-growth headroom) at the
/// HHDM base. The bootloader places the stack in the HHDM, so this preserves
/// the running stack pointer across the CR3 switch.
fn map_boot_stack_compat(
    space: &mut KernelAddressSpace,
    hhdm_offset: u64,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    let rsp = tessera_karch_x86_64::read_stack_pointer();
    if rsp < hhdm_offset {
        panic!("boot stack is not in the bootloader HHDM ({rsp:#x} < {hhdm_offset:#x})");
    }
    let stack_phys = rsp - hhdm_offset;
    let region = stack_phys & !(TWO_MIB - 1);
    let base_phys = region.saturating_sub(TWO_MIB);
    if let Err(e) =
        space.map_direct_2m_range(hhdm_offset + base_phys, base_phys, 2 * TWO_MIB, frames)
    {
        panic!("boot-stack compatibility mapping failed: {e:?}");
    }
}

/// Higher-half base for the kernel's dynamic mappings, in its own top-level
/// slot clear of the direct map and the kernel image.
const KERNEL_VMAP_BASE: u64 = 0xffff_c000_0000_0000;

// --- Demo kernel-stack-window + ASID allocators --------------------------------
//
// Every ring-3/kernel demo thread maps its kernel stack into the shared boot
// `kernel_vm`, and tags its address space with an `Asid`. Rather than hand-pick a
// unique `0xffff_c000_XXXX_0000` window and a unique `Asid(n)` per demo (which
// collided as `AlreadyMapped` when two overlapped — see the module notes), threads
// draw both from these monotonic allocators, so windows and tags are unique by
// construction. This is demo-harness scaffolding: a real kernel allocates thread
// stacks per-process via the VMA/frame machinery, not from one shared window pool.

/// Base of the kstack-window region, chosen well ABOVE every historical
/// hand-picked window (which topped out near `…f800_0000`) so nothing collides.
/// Same higher-half PML4 slot as `KERNEL_VMAP_BASE`, with vast room; `map_anonymous`
/// imposes no upper bound and the arch mapper creates intermediate tables lazily.
const KSTACK_ALLOC_BASE: u64 = 0xffff_c008_0000_0000;
/// Per-window stride. The stack maps at the slot base; the slack above it is an
/// unmapped guard gap. 2 MiB is ≥15× the largest (32-page = 128 KiB) demo stack.
const KSTACK_WINDOW_SLOT: u64 = 0x0020_0000;
static KSTACK_NEXT: AtomicU64 = AtomicU64::new(KSTACK_ALLOC_BASE);
/// Next opaque address-space tag. `Asid(0)` is the boot `kernel_vm`.
static ASID_NEXT: AtomicU16 = AtomicU16::new(1);

/// Reserves the next unique kernel-stack window in the shared `kernel_vm` and
/// returns its base VA (the caller's `spawn_user`/`map_anonymous` maps `pages`
/// there). Provably infallible for a boot — at most a few dozen windows are drawn
/// from a 64-TiB region — so it returns a bare `VirtAddr`; the `assert!` catches a
/// stack that would overrun its slot (a build-time invariant, like the mapper
/// self-check), not a fallible allocation.
fn alloc_kstack(pages: u64) -> VirtAddr {
    assert!(
        pages * FRAME_SIZE <= KSTACK_WINDOW_SLOT,
        "kstack of {pages} pages exceeds the {KSTACK_WINDOW_SLOT:#x}-byte window slot"
    );
    VirtAddr::new(KSTACK_NEXT.fetch_add(KSTACK_WINDOW_SLOT, Ordering::Relaxed))
}

/// Reserves a contiguous block of `slots` kstack windows and returns its base VA
/// as a `u64`. The strided demos (perf, jobs) index `base + i * KSTACK_WINDOW_SLOT`
/// into the block, so slot `i` maps to one stable window regardless of how often
/// it is recomputed — the same deterministic per-slot mapping the old hand-picked
/// `BASE + i*STRIDE` gave, just drawn from the allocator.
fn reserve_kstack_block(slots: u64) -> u64 {
    KSTACK_NEXT.fetch_add(slots * KSTACK_WINDOW_SLOT, Ordering::Relaxed)
}

/// Allocates the next monotonic address-space tag. The value is opaque — it is
/// never programmed as a hardware PCID (CR3 carries only the page-table root), so
/// a never-reused counter is sufficient; uniqueness-among-live-spaces is all that
/// would matter if PCID tagging is introduced later.
fn alloc_asid() -> Asid {
    Asid(ASID_NEXT.fetch_add(1, Ordering::Relaxed))
}

// Restart-loop resources — a relaunched child/driver-host reuses ONE fixed window
// and ASID for every relaunch: the exited instance's window is freed by
// `reclaim_range`, and the next launch re-maps the same VA (the single-fixed-window
// reuse M20 relies on — a fresh allocation per relaunch would re-leak VAs). So
// these are allocated lazily on first launch and memoized, not drawn per launch.

static CHILD_KSTACK_WINDOW: AtomicU64 = AtomicU64::new(0);
static CHILD_ASID_TAG: AtomicU16 = AtomicU16::new(0);
/// The loader/component-manager child's reused kstack window.
fn child_kstack_window() -> u64 {
    match CHILD_KSTACK_WINDOW.load(Ordering::Relaxed) {
        0 => {
            let w = alloc_kstack(USER_KSTACK_PAGES).as_u64();
            CHILD_KSTACK_WINDOW.store(w, Ordering::Relaxed);
            w
        }
        w => w,
    }
}
/// The loader/component-manager child's reused ASID.
fn child_asid() -> Asid {
    match CHILD_ASID_TAG.load(Ordering::Relaxed) {
        0 => {
            let a = alloc_asid();
            CHILD_ASID_TAG.store(a.0, Ordering::Relaxed);
            a
        }
        a => Asid(a),
    }
}

static DRIVER_HOST_KSTACK_WINDOW: AtomicU64 = AtomicU64::new(0);
static DRIVER_HOST_ASID_TAG: AtomicU16 = AtomicU16::new(0);
/// The restartable driver host's reused kstack window.
fn driver_host_kstack_window() -> u64 {
    match DRIVER_HOST_KSTACK_WINDOW.load(Ordering::Relaxed) {
        0 => {
            let w = alloc_kstack(USER_KSTACK_PAGES).as_u64();
            DRIVER_HOST_KSTACK_WINDOW.store(w, Ordering::Relaxed);
            w
        }
        w => w,
    }
}
/// The restartable driver host's reused ASID.
fn driver_host_asid() -> Asid {
    match DRIVER_HOST_ASID_TAG.load(Ordering::Relaxed) {
        0 => {
            let a = alloc_asid();
            DRIVER_HOST_ASID_TAG.store(a.0, Ordering::Relaxed);
            a
        }
        a => Asid(a),
    }
}

/// Exercises the runtime mapper through the `AddressSpace` object: map two
/// anonymous pages, confirm they are zero-filled, write and read them back,
/// then unmap. A mapper or zero-fill defect fails the boot loudly here rather
/// than corrupting memory later — the paging analogue of the heap self-check.
fn mapper_self_check(
    space: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    let base = VirtAddr::new(KERNEL_VMAP_BASE);
    let len = 2 * FRAME_SIZE;
    if let Err(e) = space.map_anonymous(base, len, PageFlags::rw().global(), frames) {
        panic!("mapper self-check: map failed: {e:?}");
    }
    // The kernel space is active, so the mapping is live at `base`.
    // SAFETY: `[base, base + len)` was just mapped read-write in the active
    // kernel space and the mapper zero-filled its frames, so these in-bounds
    // volatile accesses are valid.
    unsafe {
        let ptr = base.as_u64() as *mut u8;
        let last = (len - 1) as usize;
        if ptr.read_volatile() != 0 || ptr.add(last).read_volatile() != 0 {
            panic!("mapper self-check: anonymous memory not zero-filled");
        }
        for i in 0..len as usize {
            ptr.add(i).write_volatile(0x5a);
        }
        if ptr.read_volatile() != 0x5a || ptr.add(last).read_volatile() != 0x5a {
            panic!("mapper self-check: readback mismatch");
        }
    }
    if let Err(e) = space.unmap_range(base, len) {
        panic!("mapper self-check: unmap failed: {e:?}");
    }
}

// --- Guard-page self-test (flag-gated) ---

/// Base of the throwaway guarded stack used by the guard-page self-test.

/// Recurses, consuming ~512 bytes of stack per frame, until the stack
/// overflows into its guard page. The `black_box` uses force a real frame and
/// defeat tail-call elimination so the stack actually grows.
#[inline(never)]
fn consume_stack(depth: u64) -> u64 {
    let mut frame = [depth; 64];
    core::hint::black_box(&mut frame);
    let deeper = consume_stack(depth.wrapping_add(1));
    core::hint::black_box(frame[0]).wrapping_add(deeper)
}

/// Entry point of the overflowing test thread; never returns normally.
extern "C" fn stack_overflow_entry(_arg: usize) -> ! {
    let _ = consume_stack(0);
    panic!("stack-guard self-test: recursion returned without overflowing");
}

/// Spawns a thread on a small guarded stack and runs it; the deliberate
/// overflow must fault onto the exception stack, where `fatal_trap` reports a
/// kernel stack overflow and exits with failure. If control returns, the guard
/// did not fire — a bug — so this panics.
fn run_stack_guard_self_test(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    kprintln!("stack-guard self-test: overflowing a guarded kernel stack");
    let mut scheduler = Scheduler::<ContextSwitch>::new(1, 0);
    let thread = match Thread::<ContextSwitch>::spawn(
        ThreadId(0xffff),
        stack_overflow_entry,
        0,
        alloc_kstack(4),
        4,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("stack-guard self-test: spawn failed: {e:?}"),
    };
    if scheduler.add_thread(thread).is_err() {
        panic!("stack-guard self-test: could not enqueue the thread");
    }
    scheduler.run();
    panic!("stack-guard self-test: overflow did not fault");
}

// --- Handle + rights self-check ---
//
// The object and handle tables are large fixed pools, so they live in .bss
// (never the boot stack). Touched only from this single-threaded boot path.
static mut OBJECTS: ObjectTable = ObjectTable::new();
static mut HANDLES: HandleTable = HandleTable::new();

/// Exercises the capability system on real hardware, asserting each outcome:
/// create an object, take a full-rights handle, duplicate it with narrowed
/// rights, reject a rights-expansion attempt, replace rights, and confirm the
/// object is destroyed only when its last handle closes. A defect fails the
/// boot loudly here.
fn handle_self_check() {
    // SAFETY: `_start` is single-threaded and these statics are touched only
    // here; this is the only reference taken to each.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let handles = unsafe { &mut *&raw mut HANDLES };

    let id = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => panic!("handle self-check: object create failed: {e:?}"),
    };
    let full = match handles.insert(id, Rights::all_core()) {
        Ok(handle) => handle,
        Err(e) => panic!("handle self-check: insert failed: {e:?}"),
    };

    // Duplicate with narrowed rights (read only).
    let read_only = match handles.duplicate(objects, full, Rights::READ) {
        Ok(handle) => handle,
        Err(e) => panic!("handle self-check: duplicate failed: {e:?}"),
    };
    if handles.rights(read_only) != Ok(Rights::READ) {
        panic!("handle self-check: duplicated rights not narrowed");
    }

    // A duplicate that asks for a right the source lacks must be rejected.
    let expansion = handles.duplicate(objects, read_only, Rights::READ | Rights::WRITE);
    if expansion != Err(KError::AccessDenied) {
        panic!("handle self-check: rights expansion was not rejected");
    }

    // Replace rights in place, narrowing only.
    if handles
        .replace_rights(full, Rights::READ | Rights::WRITE)
        .is_err()
    {
        panic!("handle self-check: replace_rights failed");
    }

    // Object lifetime: two handles reference it; it dies at the last close.
    if objects.refcount(id) != Some(2) {
        panic!("handle self-check: unexpected reference count");
    }
    match handles.close(objects, full) {
        Ok(false) => {}
        other => panic!("handle self-check: first close destroyed too early: {other:?}"),
    }
    match handles.close(objects, read_only) {
        Ok(true) => {}
        other => panic!("handle self-check: last close did not destroy: {other:?}"),
    }
    if objects.is_live(id) {
        panic!("handle self-check: object still live after last close");
    }

    kprintln!(
        "handles: rights narrowing + expansion rejected; object destroyed at last close ({} live)",
        objects.live_count()
    );
}

// --- Scheduler demonstration (preemptive) ---
//
// Spawns CPU-bound worker threads that never yield voluntarily, then lets the
// per-CPU scheduler preempt them round-robin off the timer tick. That all
// workers make progress proves the timer genuinely switched between them
// without cooperation. The run stops after a fixed number of ticks by
// switching back to this boot context, so CI terminates.

const WORKERS: usize = 3;
const WORKER_STACK_PAGES: u64 = 4;
const SCHED_QUANTUM_TICKS: u32 = 2;
const SCHED_TICK_LIMIT: u64 = 40;

/// Per-worker progress counters, incremented in the workers' spin loops.
static WORKER_PROGRESS: [AtomicU64; WORKERS] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// The boot CPU's scheduler. Initialized once in `_start` before the timer is
/// enabled; thereafter touched only by the boot path (interrupts disabled) and
/// the timer interrupt (serialized), so no lock is needed on this single core.
static mut SCHEDULER: Option<Scheduler<ContextSwitch>> = None;

/// A CPU-bound worker: spins forever incrementing its progress counter. It is
/// never resumed cooperatively — only the timer preempts it.
extern "C" fn spin_worker(idx: usize) -> ! {
    loop {
        WORKER_PROGRESS[idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// The timer-tick preemption hook: drives one scheduler tick. Registered with
/// the architecture timer path, it runs in interrupt context.
fn preempt_tick() {
    // SAFETY: single core — the scheduler is initialized before the timer is
    // enabled, and only this hook (in the masked timer interrupt) and the boot
    // path (interrupts disabled) ever touch it, so there is no concurrent
    // access.
    unsafe {
        if let Some(scheduler) = (*&raw mut SCHEDULER).as_mut() {
            scheduler.on_tick();
        }
    }
}

/// Spawns the workers, starts preemptive scheduling under the timer, and
/// reports the switch count and per-worker progress once the tick limit
/// returns control here.
fn scheduler_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    // SAFETY: single-threaded boot, before the timer is enabled; this is the
    // only initialization of the scheduler.
    unsafe { SCHEDULER = Some(Scheduler::new(SCHED_QUANTUM_TICKS, SCHED_TICK_LIMIT)) };

    for idx in 0..WORKERS {
        let stack_base = alloc_kstack(WORKER_STACK_PAGES);
        let thread = match Thread::<ContextSwitch>::spawn(
            ThreadId(idx as u64),
            spin_worker,
            idx,
            stack_base,
            WORKER_STACK_PAGES,
            kernel_vm,
            frames,
        ) {
            Ok(thread) => thread,
            Err(e) => panic!("scheduler demo: spawn failed: {e:?}"),
        };
        // SAFETY: single-threaded boot; the timer is not yet enabled, so the
        // scheduler is not concurrently accessed.
        unsafe {
            match (*&raw mut SCHEDULER).as_mut() {
                Some(scheduler) => {
                    if scheduler.add_thread(thread).is_err() {
                        panic!("scheduler demo: thread table full");
                    }
                }
                None => panic!("scheduler demo: scheduler uninitialized"),
            }
        }
    }

    use tessera_karch::{InterruptControl, TimerControl};
    use tessera_karch_x86_64::{Pit, init_pic, set_tick_hook, unexpected_irqs};
    init_pic();
    Pit::start_periodic(TICK_HZ);
    set_tick_hook(preempt_tick);
    Cpu::enable();
    // SAFETY: the scheduler is initialized above; `run` drives preemptive
    // round-robin and returns when the tick limit switches back to this boot
    // context. The timer interrupt is the only other accessor, and it is
    // serialized with this call by the context switches themselves.
    unsafe {
        match (*&raw mut SCHEDULER).as_mut() {
            Some(scheduler) => scheduler.run(),
            None => panic!("scheduler demo: scheduler uninitialized"),
        }
    }
    Cpu::disable();

    // SAFETY: single-threaded again (interrupts disabled, run returned).
    let switches = unsafe {
        match (*&raw const SCHEDULER).as_ref() {
            Some(scheduler) => scheduler.switch_count(),
            None => 0,
        }
    };
    kprintln!(
        "sched: {switches} preemptive switches over {} ticks ({} unexpected IRQs)",
        Pit::ticks(),
        unexpected_irqs()
    );
    kprintln!(
        "sched: worker progress [{}, {}, {}] (all nonzero => timer preemption)",
        WORKER_PROGRESS[0].load(Ordering::Relaxed),
        WORKER_PROGRESS[1].load(Ordering::Relaxed),
        WORKER_PROGRESS[2].load(Ordering::Relaxed),
    );
}

// --- Synchronous IPC round-trip demonstration ---
//
// The riskiest architectural bet: a request/response *call* between two
// components must cost about what a function call costs, which needs the
// synchronous handoff — a direct caller->callee switch and a direct
// callee->caller switch on reply, exactly two context switches, no run-queue
// traffic (docs/architecture/03 "B3"; the two-switch check is
// docs/prototypes/01). A real handoff transfers control, which the mock
// `switch` cannot do, so this property is proven here on hardware; the pure
// logic is host-tested in `kcore`.
//
// The callee is spawned first so it runs first and parks in `receive`; the
// caller then `call`s, handing off directly to the parked callee. With no other
// ready threads, the round trip is exactly two switches. The `Executive` owns
// the scheduler and channel table and lives behind a `static`, re-borrowed per
// operation, because a switch suspends a thread mid-call and a Rust `&mut`
// cannot span it (the same single-core pattern the scheduler uses).

/// Interface/method identifiers for the demo protocol (the ISL expression of
/// this header is `api/isl/examples/channel_msg.isl`).
const IPC_IFACE_ID: u64 = 0x7e55_e2a0_0000_0001;
const IPC_METHOD_PING: u32 = 1;
const IPC_METHOD_PONG: u32 = 2;
const IPC_QUANTUM_TICKS: u32 = 1;
const IPC_STACK_PAGES: u64 = 4;

/// The demo executive (scheduler + channel table). Initialized once in
/// `ipc_roundtrip_demo` before any demo thread runs; thereafter touched only by
/// the boot path and the two demo threads, which are serialized by the handoff
/// (only one runs at a time on this single core).
static mut EXEC: Option<Executive<ContextSwitch>> = None;

/// The demo channel's two endpoint ids: `.0` is the caller's end, `.1` the
/// callee's. Set once before the threads run.
static mut IPC_ENDPOINTS: Option<(EndpointId, EndpointId)> = None;

/// Separate handle tables for the two demo peers, so the transferred handle is
/// taken from the caller's and installed into the callee's — never shared.
static mut IPC_CALLER_HANDLES: HandleTable = HandleTable::new();
static mut IPC_CALLEE_HANDLES: HandleTable = HandleTable::new();

/// Round-trip results, published by the threads and checked back on boot.
static IPC_ROUNDTRIP_SWITCHES: AtomicU64 = AtomicU64::new(0);
static IPC_REPLY_OK: AtomicBool = AtomicBool::new(false);
static IPC_HANDLE_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Correlation-propagation probes taken from inside the synchronous round trip
/// (D59). The mock scheduler cannot show adoption — its `switch` is a no-op, so
/// a callee never actually runs — so the observation is made here, on target,
/// where the handoff is a real context switch: the callee samples its ambient id
/// before parking and again when `receive` returns under the caller's call.
static CORRELATION_CALLEE_OWN: AtomicU64 = AtomicU64::new(0);
static CORRELATION_CALLEE_DURING_CALL: AtomicU64 = AtomicU64::new(0);
static CORRELATION_CALLER: AtomicU64 = AtomicU64::new(0);
/// Scheduler index of the IPC callee, so the restore can be checked after.
static CORRELATION_CALLEE_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
/// The cause a page-in request left with, and the cause it arrived carrying —
/// the on-target proof that causality survives the message boundary (D60).
/// Page-ins are synchronous and one-at-a-time (see `FS_PENDING`), so the faulter
/// slot always names the request the pager is currently serving. Matches are
/// *counted* at serve time rather than compared at the end, because the last
/// page-in of the boot is served by the ring-3 FS path, which never reaches
/// `serve_page_request` — comparing final values would compare two different
/// requests.
static CORRELATION_PAGE_IN_FAULTER: AtomicU64 = AtomicU64::new(0);
static CORRELATION_PAGE_IN_SERVED: AtomicU64 = AtomicU64::new(0);
static CORRELATION_PAGE_IN_REQUESTS: AtomicU64 = AtomicU64::new(0);
static CORRELATION_PAGE_IN_MATCHED: AtomicU64 = AtomicU64::new(0);

/// The callee's id once the call returned. Sampled immediately after the round
/// trip, not at report time: later demos restart services often enough to reuse
/// the callee's scheduler slot, and the slot's *current* occupant would say
/// nothing about this call.
static CORRELATION_CALLEE_RESTORED: AtomicU64 = AtomicU64::new(0);

/// The single owner of the demo executive, re-borrowed per operation.
fn exec_ref() -> &'static mut Executive<ContextSwitch> {
    // SAFETY: single-core cooperative demo; `EXEC` is initialized in
    // `ipc_roundtrip_demo` before any thread runs, and the boot path and the two
    // demo threads never run concurrently (each handoff switches control), so
    // there is never more than one live borrow in flight.
    unsafe {
        match (*&raw mut EXEC).as_mut() {
            Some(exec) => exec,
            None => panic!("ipc demo: executive uninitialized"),
        }
    }
}

/// The demo channel's endpoint ids.
fn ipc_endpoints() -> (EndpointId, EndpointId) {
    // SAFETY: single-core; set once in `ipc_roundtrip_demo` before the threads
    // run, read-only thereafter.
    unsafe {
        match (*&raw const IPC_ENDPOINTS).as_ref() {
            Some(&pair) => pair,
            None => panic!("ipc demo: endpoints uninitialized"),
        }
    }
}

/// Callee: parks in `receive` until the caller's `call` hands off the request,
/// installs the transferred handle into its own table, and `reply`s — which
/// hands control directly back to the caller.
extern "C" fn ipc_callee_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_caller_ep, callee_ep) = ipc_endpoints();
    // SAFETY: single-core demo; this static handle table is touched only here.
    let callee_handles = unsafe { &mut *&raw mut IPC_CALLEE_HANDLES };

    // The callee's own causal id, before it parks (D59).
    CORRELATION_CALLEE_OWN.store(kcore::trace::current().correlation, Ordering::Relaxed);

    let request = match exec.receive(callee_ep) {
        Ok(message) => message,
        Err(e) => panic!("ipc demo: callee receive failed: {e:?}"),
    };

    // Resumed by the caller's handoff: the work done from here until the reply
    // belongs to the *caller's* cause, not the callee's own.
    CORRELATION_CALLEE_DURING_CALL.store(kcore::trace::current().correlation, Ordering::Relaxed);

    // Adopt every transferred handle into the callee's table; the object
    // reference conserved across the transfer kept it alive in flight.
    let mut installed = 0usize;
    for transferred in request.handles() {
        match callee_handles.install(transferred.object, transferred.rights) {
            Ok(_) => installed += 1,
            Err(e) => panic!("ipc demo: handle install failed: {e:?}"),
        }
    }
    IPC_HANDLE_RECEIVED.store(
        installed == 1 && request.inline() == b"ping",
        Ordering::Relaxed,
    );

    let mut reply = Message::new(MessageHeader::new(IPC_IFACE_ID, IPC_METHOD_PONG));
    if reply.set_inline(b"pong").is_err() {
        panic!("ipc demo: reply payload too large");
    }
    if let Err(e) = exec.reply(callee_ep, reply) {
        panic!("ipc demo: callee reply failed: {e:?}");
    }
    // `reply` handed off to the caller; the callee is left blocked and is never
    // resumed in this demo. If it ever were, it would simply park again.
    loop {
        let _ = exec.receive(callee_ep);
    }
}

/// Caller: builds a request carrying a transferred handle, issues a synchronous
/// `call` (measuring the switch count across it — the load-bearing check), then
/// hands control back to boot so the run ends.
extern "C" fn ipc_caller_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (caller_ep, _callee_ep) = ipc_endpoints();
    // SAFETY: single-core demo; these statics are touched only on this boot
    // path (the caller thread and, for `OBJECTS`, the earlier self-check which
    // has already finished and left it empty).
    let caller_handles = unsafe { &mut *&raw mut IPC_CALLER_HANDLES };
    let objects = unsafe { &mut *&raw mut OBJECTS };

    // Create an object and a transferable handle to it, then take the handle for
    // the request — `take` conserves the object reference (no release); the
    // in-flight message carries it to the callee.
    let object = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => panic!("ipc demo: object create failed: {e:?}"),
    };
    let handle = match caller_handles.insert(object, Rights::READ | Rights::TRANSFER) {
        Ok(handle) => handle,
        Err(e) => panic!("ipc demo: handle insert failed: {e:?}"),
    };
    let (transferred_object, transferred_rights) = match caller_handles.take(handle) {
        Ok(pair) => pair,
        Err(e) => panic!("ipc demo: handle take failed: {e:?}"),
    };

    let mut request = Message::new(MessageHeader::new(IPC_IFACE_ID, IPC_METHOD_PING));
    if request.set_inline(b"ping").is_err() {
        panic!("ipc demo: request payload too large");
    }
    if request
        .add_handle(TransferredHandle {
            object: transferred_object,
            rights: transferred_rights,
        })
        .is_err()
    {
        panic!("ipc demo: too many handles on the request");
    }

    // The measurement: a synchronous call must cost exactly two switches —
    // caller->callee to deliver the request, callee->caller to deliver the
    // reply — with no ready-queue traffic in between.
    CORRELATION_CALLER.store(kcore::trace::current().correlation, Ordering::Relaxed);
    let before = exec.switch_count();
    let reply = match exec.call(caller_ep, request) {
        Ok(message) => message,
        Err(e) => panic!("ipc demo: call failed: {e:?}"),
    };
    let after = exec.switch_count();

    IPC_ROUNDTRIP_SWITCHES.store(after - before, Ordering::Relaxed);
    IPC_REPLY_OK.store(reply.inline() == b"pong", Ordering::Relaxed);

    // Hand control back to the boot context; `run` returns and the demo ends.
    exec.scheduler().yield_to_boot();
    // Unreachable: `yield_to_boot` switched away and this thread is never
    // resumed, but the entry signature demands divergence.
    loop {
        core::hint::spin_loop();
    }
}

/// Creates one channel and two kernel threads, runs the cooperative round trip,
/// and asserts it completed in exactly two context switches with the
/// transferred handle delivered. A defect fails the boot loudly here.
fn ipc_roundtrip_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    // SAFETY: single-threaded boot; the only initialization of `EXEC`, before
    // any demo thread runs.
    unsafe { EXEC = Some(Executive::new(IPC_QUANTUM_TICKS, 0)) };
    let exec = exec_ref();

    let (caller_ep, callee_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(e) => panic!("ipc demo: channel create failed: {e:?}"),
    };
    // SAFETY: single-threaded boot; set once before the threads run.
    unsafe { IPC_ENDPOINTS = Some((caller_ep, callee_ep)) };

    // Callee first: it runs first and parks in `receive`, so the caller's `call`
    // hands off directly to it (no run-queue detour).
    let callee = match Thread::<ContextSwitch>::spawn(
        ThreadId(0x1ca_11ee),
        ipc_callee_entry,
        0,
        alloc_kstack(IPC_STACK_PAGES),
        IPC_STACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("ipc demo: callee spawn failed: {e:?}"),
    };
    match exec.add_thread(callee) {
        Ok(idx) => CORRELATION_CALLEE_INDEX.store(idx as u64, Ordering::Relaxed),
        Err(_) => panic!("ipc demo: thread table full (callee)"),
    }
    let caller = match Thread::<ContextSwitch>::spawn(
        ThreadId(0x1ca_11e2),
        ipc_caller_entry,
        0,
        alloc_kstack(IPC_STACK_PAGES),
        IPC_STACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("ipc demo: caller spawn failed: {e:?}"),
    };
    if exec.add_thread(caller).is_err() {
        panic!("ipc demo: thread table full (caller)");
    }

    // Cooperative run (no timer): switches to the callee (parks), then the
    // caller (round trip), and returns when the caller yields back to boot.
    exec.run();

    // The callee's own id must be back now that the call has returned (D59).
    let callee_idx = CORRELATION_CALLEE_INDEX.load(Ordering::Relaxed) as usize;
    CORRELATION_CALLEE_RESTORED.store(
        exec.scheduler().thread_correlation(callee_idx).unwrap_or(0),
        Ordering::Relaxed,
    );

    let switches = IPC_ROUNDTRIP_SWITCHES.load(Ordering::Relaxed);
    if !IPC_REPLY_OK.load(Ordering::Relaxed) {
        panic!("ipc demo: caller did not receive the expected reply");
    }
    if !IPC_HANDLE_RECEIVED.load(Ordering::Relaxed) {
        panic!("ipc demo: transferred handle did not arrive at the callee");
    }
    if switches != 2 {
        panic!("ipc demo: round trip used {switches} switches, expected exactly 2");
    }
    kprintln!(
        "ipc: sync call round trip in {switches} switches (direct handoff); reply \"pong\", 1 handle transferred"
    );
}

// --- User-mode (ring 3) demonstration ---
//
// The isolation bet: run a program in ring 3, in its own address space, that
// reaches the kernel only through the validated SYSCALL boundary — and prove a
// fault in that program is *contained* (the process dies, the kernel lives).
// A hand-assembled position-independent ring-3 blob (below) issues a handful of
// syscalls (debug-write, null, handle duplicate, handle query) and then
// deliberately dereferences a null pointer; the kernel services the syscalls,
// catches the fault via the user-fault handler, terminates the process under
// the default policy, and returns to boot. None of this can happen under the
// host mock (there is no CPU privilege level), so it is proven here on hardware.

/// Ring-3 text base (low half, user space).
const USER_CODE_VA: u64 = 0x0000_0000_0040_0000;
const USER_CODE_PAGES: u64 = 1;
/// Ring-3 stack (low half).
const USER_STACK_BASE: u64 = 0x0000_0000_7000_0000;
const USER_STACK_PAGES: u64 = 4;
/// The user thread's kernel syscall/exception stack. In the kernel VMAP slot
/// (384) whose page tables the user space shares, and clear of the IPC demo's
/// stacks (…5/6000_0000) so the mapping does not collide.
const USER_KSTACK_PAGES: u64 = 4;

/// The root task's kernel syscall/exception stack. A distinct VMAP window in the
/// same shared higher-half slot as the other ring-3 demos' kernel stacks (so its
/// page-table levels propagate into the user space through `new_user`), clear of
/// USER_KSTACK's own pages.

/// The embedded root-task ELF (v0's "initrd" — a Bazel-built ring-3 program
/// linked into the kernel image; a real initrd / Limine module is deferred,
/// D42). Only the Bazel build embeds it; the cargo inner loop builds without it
/// and the loader demo reports it is absent.
#[cfg(has_root_task)]
fn root_task_elf() -> &'static [u8] {
    &root_task_image::ROOT_TASK_ELF
}
#[cfg(not(has_root_task))]
fn root_task_elf() -> &'static [u8] {
    &[]
}

/// The demo scheduler holding the single ring-3 thread. Static so the syscall
/// and fault handlers (which run in kernel entry context) can reach it.
static mut USER_SCHEDULER: Option<Scheduler<ContextSwitch>> = None;
/// The demo process (address space + handle table). Static for the same reason.
static mut USER_PROCESS: Option<Process<KernelAddressSpace>> = None;

/// Round-trip observations, published by the handlers and checked on boot.
static USER_SYSCALLS: AtomicU64 = AtomicU64::new(0);
static USER_RING3_REACHED: AtomicBool = AtomicBool::new(false);
/// New handle from `sys_handle_duplicate`, stored `+1` so 0 means "not set".
static USER_DUP_HANDLE: AtomicU64 = AtomicU64::new(0);
static USER_QUERY_RIGHTS: AtomicU64 = AtomicU64::new(u64::MAX);
static USER_FAULT_CONTAINED: AtomicBool = AtomicBool::new(false);
static USER_FAULT_VECTOR: AtomicU64 = AtomicU64::new(u64::MAX);
static USER_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);

// --- Driver-host restart on crash (fault observation + supervise counters) --
/// Set by `driver_fault_handler` when a supervised driver host faults (a real
/// #PF crash); the supervisor clears it before each launch and checks it after.
static DRIVER_HOST_FAULTED: AtomicBool = AtomicBool::new(false);
/// Real crashes observed across a run — the restart proof (`== countdown`).
static DRIVER_HOST_FAULTS_SEEN: AtomicU64 = AtomicU64::new(0);
/// Host launches across a run — bounds the budget self-test (`== budget` capped).
static DRIVER_HOST_LAUNCHES: AtomicU64 = AtomicU64::new(0);
/// The causal id of the host thread that just crashed, handed from the fault
/// handler to the supervisor. The supervisor runs on the boot context, whose
/// ambient id is boot's own; adopting this makes the crash-recovery records a
/// continuation of the crash's trace instead of an unrelated root
/// (docs/observability/02 — a stage inherits the item's id).
static DRIVER_HOST_CRASH_CORRELATION: AtomicU64 = AtomicU64::new(0);

// --- M14: user-space loader (ring-3 create/populate/start of a child) ---

/// The shared process table for the executive substrate: every ring-3 demo that
/// runs on `EXEC` (the loader/component-manager parent+child, the channel peers,
/// the driver host+client) registers its processes here. A syscall resolves its
/// *caller* by the running thread (`process_of_thread`) and a *process handle* to
/// its target (`process_of_id`), so the live processes share one dispatcher (the
/// handle→process bridge, D42).
static mut PROCESSES: ProcessTable<KernelAddressSpace> = ProcessTable::new();
/// The parent thread parked inside `ProcessStart` awaiting the child it started
/// (the synchronous start handoff, mirroring `Executive::call`/`reply`). `None`
/// when no start is in flight; the child's exit/fault takes it to hand back.
static mut PARENT_WAITER: Option<usize> = None;
/// Raw pointers to the boot kernel address space and frame allocator, so the
/// loader syscalls (which run in trap context, from a ring-3 caller) can create
/// child spaces and map into them. `_start` never returns, so both live for the
/// kernel's lifetime (the `RESOLVER_FRAMES` pattern).
static mut LOADER_KERNEL_VM: *mut AddressSpace<KernelAddressSpace> = core::ptr::null_mut();
static mut LOADER_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> = core::ptr::null_mut();
/// The exit code the most-recently-exited child stashed for its waiting parent
/// (`i32::MIN` = none yet).
static LOADER_CHILD_EXIT: AtomicI32 = AtomicI32::new(i32::MIN);
/// Set once the child process has run in ring 3 and exited (loader round-trip).
static LOADER_CHILD_RAN: AtomicBool = AtomicBool::new(false);
/// The child process handle the parent obtained from `ProcessCreate`, stored
/// `+1` so 0 means "not observed".
static LOADER_CHILD_HANDLE: AtomicU64 = AtomicU64::new(0);
/// Set once the parent has resumed after the child it started exited.
static LOADER_PARENT_RESUMED: AtomicBool = AtomicBool::new(false);
/// Count of children launched under the loader handler — now pure observability
/// (the demo measures launches as the delta over a run). Reset per `cm_run`; no
/// longer a kstack slot, because the kstack is reclaimed and the window reused.
static CM_LAUNCHES: AtomicU64 = AtomicU64::new(0);
/// M19 observation: the number of supervised children that actually ran and
/// exited back to the manager (incremented in `loader_process_exit`'s parent-
/// handback branch), and the sum of their exit codes — together they prove the
/// crash→recover sequence (`3+2+1+0 = 6` over 4 real runs) without a per-launch
/// array. Reset at the M19 demo start (after `loader_demo`'s own child exit).
static CM_CHILD_RUNS: AtomicU64 = AtomicU64::new(0);
static CM_EXIT_SUM: AtomicI64 = AtomicI64::new(0);
/// The child's ring-3 stack size. Its base comes from the parent over the ABI
/// (`ProcessStartArgs::stack` — the root task passes `0x6800_0000`, clear of the
/// parent's `USER_STACK_BASE`); the kernel maps this many pages there.
const CHILD_STACK_PAGES: u64 = 4;
/// The loader parent runs `ProcessCreate` in a syscall, which builds a whole
/// `Process` (its ~26 KiB handle table + address space) by value on this kernel
/// stack. In the unoptimized kernel build (no copy-elision) that spans several
/// stacked frames (`loader_process_create` → `Process::new` → `HandleTable::new`)
/// totalling ~66 KiB, so the parent needs far more than the usual 4-page ring-3
/// kernel stack (the M13 loader built the process on the large boot stack
/// instead). 32 pages (128 KiB) leaves comfortable margin; the child keeps the
/// standard 4-page stack.
const LOADER_PARENT_KSTACK_PAGES: u64 = 32;

// The ring-3 program. Position-independent: it addresses its own data
// RIP-relative and passes the SYSCALL ABI (rax=number; args in rdi/rsi/…). It
// runs at USER_CODE_VA after being copied there. The blob lives in kernel
// rodata; nothing ever executes it at its kernel address.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global user_program_start
.global user_program_end
user_program_start:
    lea rdi, [rip + 3f]        # debug_write(msg, len)
    mov esi, 25               # length of the message at 3: (keep in sync)
    mov eax, 1
    syscall
    xor eax, eax              # null()
    syscall
    lea rdi, [rip + 5f]       # handle_duplicate(&dup_args)
    mov eax, 2
    syscall
    mov edi, eax              # handle_query_rights(new handle)
    mov eax, 3
    syscall
    xor rcx, rcx              # deliberate null read -> #PF, contained
    mov rax, [rcx]
6:
    jmp 6b
3:
    .ascii "hello from ring 3 (cpl=3)"
4:
.balign 8
5:
    .long 32                  # DuplicateArgs: size
    .long 1                   # version
    .quad 0                   # flags
    .long 0                   # source handle (seeded handle, raw 0)
    .long 0                   # reserved
    .quad 1                   # new_rights = READ
user_program_end:
.text
"#
);

// SAFETY: these name the ring-3 blob's bounds, defined by the global_asm block
// above; the extern block only declares them and introduces no unsafe operation.
unsafe extern "C" {
    static user_program_start: u8;
    static user_program_end: u8;
}

/// `sys_debug_write`: validate and copy a user string (via the shared kcore
/// copy layer), then print it. The 128-byte clamp is this port's console
/// policy, applied before the copy so the validated range never exceeds it.
fn user_debug_write(process: &Process<KernelAddressSpace>, ptr: u64, len: u64) -> i64 {
    const MAX: usize = 128;
    let n = core::cmp::min(len as usize, MAX);
    let mut buf = [0u8; MAX];
    if let Err(e) = read_user(process, ptr, &mut buf[..n]) {
        return encode_result(Err(e));
    }
    if let Ok(text) = core::str::from_utf8(&buf[..n]) {
        kprint!("  user[debug_write]: {text}\n");
    }
    encode_result(Ok(n as u64))
}

/// A frame source that never allocates, for dispatch arms that provably need
/// no frames on this port: x86-64 registers no MMIO device objects, so
/// `MapDevice`/`DmaAlloc` fail at capability resolution before any allocation
/// (they were `ENOSYS` before D79 — now they are capability-gated like every
/// other port). A future x86 MMIO path must thread a real allocator instead.
struct NoFrames;

impl FrameSource for NoFrames {
    fn alloc_frame(&mut self) -> Option<PhysFrame> {
        None
    }
}

/// The registered syscall dispatcher: runs in kernel context after the entry
/// stub, on the user thread's kernel stack, with the user address space still
/// active. Resolves the calling process and performs the operation.
fn user_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    USER_RING3_REACHED.store(true, Ordering::Relaxed);
    USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);

    // SAFETY: single-core; `USER_PROCESS` is set before the ring-3 thread runs
    // and touched only on this boot CPU.
    let process = match unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        Some(process) => process,
        None => return syscall::ENOSYS,
    };
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };

    let number = match SyscallNumber::from_u64(frame.number) {
        Some(number) => number,
        None => return syscall::ENOSYS,
    };
    match number {
        SyscallNumber::Null => encode_result(Ok(0)),
        SyscallNumber::DebugWrite => user_debug_write(process, frame.arg0, frame.arg1),
        SyscallNumber::HandleDuplicate => {
            let mut buf = [0u8; 32];
            if let Err(e) = read_user(process, frame.arg0, &mut buf) {
                return encode_result(Err(e));
            }
            let (source, new_rights) = match decode_duplicate_args(&buf) {
                Ok(decoded) => decoded,
                Err(e) => return encode_result(Err(e)),
            };
            let result = sys_handle_duplicate(process, objects, source, new_rights);
            if let Ok(handle) = result {
                USER_DUP_HANDLE.store(handle + 1, Ordering::Relaxed);
            }
            encode_result(result)
        }
        SyscallNumber::HandleQueryRights => {
            let result = sys_handle_query_rights(process, Handle::from_raw(frame.arg0 as u32));
            if let Ok(bits) = result {
                USER_QUERY_RIGHTS.store(bits, Ordering::Relaxed);
            }
            encode_result(result)
        }
        // A closed device capability ends its DMA lease and its interrupt
        // route too. `None` for the IOMMU because this port has none — the
        // lease bookkeeping still runs, so the rule holds by construction
        // rather than by this port happening never to take a lease. The PIC is
        // real: this port's device interrupts do arrive through it.
        SyscallNumber::HandleClose => encode_result(sys_handle_close(
            process,
            objects,
            exec_ref(),
            None,
            Some(&mut PicRouter),
            Handle::from_raw(frame.arg0 as u32),
        )),
        SyscallNumber::ProcessExit => user_process_exit(frame.arg0 as i32),
        // Wait-on-address is exercised by its own demo/handler, not this one.
        SyscallNumber::WaitOnAddress | SyscallNumber::WakeAddress => syscall::ENOSYS,
        // The three-phase process-lifecycle ABI is defined (numbers +
        // process_abi.isl @abi structs, conformance-gated); the in-kernel loader
        // exercises the create/populate/start path directly. The ring-3
        // implementation awaits the object/handle bridge for processes (D42).
        SyscallNumber::ProcessCreate
        | SyscallNumber::AddressSpaceMap
        | SyscallNumber::ProcessStart => syscall::ENOSYS,
        // Channel IPC is exercised by `channel_ipc_demo`'s own handler (M15),
        // not this single-process one.
        SyscallNumber::ChannelCreate
        | SyscallNumber::ChannelSend
        | SyscallNumber::ChannelRecv
        | SyscallNumber::ChannelCall
        | SyscallNumber::ChannelReply => syscall::ENOSYS,
        // Ports and device I/O are exercised by `driver_host_demo`'s own handler
        // (M16), not this single-process one.
        SyscallNumber::PortCreate
        | SyscallNumber::PortBind
        | SyscallNumber::PortWait
        | SyscallNumber::DeviceIoRead
        | SyscallNumber::DeviceIoWrite => syscall::ENOSYS,
        // The ring-3 pager ops are exercised by `fs_service_demo`'s own handler
        // (M18), not this single-process one.
        SyscallNumber::PageServe | SyscallNumber::PageSupply => syscall::ENOSYS,
        // Mapping a device's MMIO window into a ring-3 driver, and allocating a
        // ring-3 DMA buffer, live in the shared kcore dispatcher (D79) on the
        // executive substrate; this single-process demo handler predates that
        // substrate and does not route them.
        SyscallNumber::MapDevice | SyscallNumber::DmaAlloc => syscall::ENOSYS,
        // The server-loop primitive (D82) is exercised by the AArch64 ring-3
        // driver host; x86's channel demos reply via their own local arms.
        SyscallNumber::ChannelReplyRecv => syscall::ENOSYS,
        // Interrupt re-arm (D84) is arch-coupled (a GIC operation) and
        // exercised by the AArch64 ring-3 device host.
        SyscallNumber::IrqComplete => syscall::ENOSYS,
        // Recording a driver-lifecycle transition (D128) belongs to a ring-3
        // device manager, and this port has none: its one device is a COM2
        // port range boot registered, bound by a kernel-driven supervisor
        // rather than brokered by a manager that could have a lifecycle to
        // declare. The ladder this port *does* run — crash, restart, give up —
        // is recorded by `kcore::supervise`, which needs no syscall.
        SyscallNumber::DriverLifecycle => syscall::ENOSYS,
        // The select-loop reply (D85) belongs to the AArch64 device host; the
        // x86 channel demos reply through their own local arms.
        SyscallNumber::ChannelReplyContinue => syscall::ENOSYS,
        // Asking what a device is (D115) answers from the resource graph, and
        // this port's graph holds no normalized identity: its one device is a
        // COM2 port range the boot glue registered, not something enumerated.
        // A ring-3 caller here would get `UNKNOWN`, which is the same answer
        // the shared arm gives — refusing outright is clearer than
        // implementing a path nothing on this port asks for.
        SyscallNumber::DeviceInfo => syscall::ENOSYS,
        // Memory objects (D131) need a frame allocator to create against, and
        // this port hands its dispatcher `NoFrames`: its ring-3 demos run out
        // of blob-mapped pages the boot glue placed, with no allocator alive
        // by the time a syscall arrives. `ENOSYS` says so rather than letting
        // a caller reach an arm that would fail obscurely on the first frame
        // it asked for.
        SyscallNumber::MemoryCreate | SyscallNumber::MemoryMap => syscall::ENOSYS,
        // Attaching a memory object to a device needs a memory object, which
        // this port cannot create (above), and an IOMMU, which this machine
        // does not have. Two reasons rather than one, and either alone would
        // be enough.
        SyscallNumber::DmaAttach | SyscallNumber::DmaDetach => syscall::ENOSYS,
        // Renewing a lease needs a lease, and this port's one device is behind
        // no IOMMU, so it never takes one.
        SyscallNumber::DmaRenew => syscall::ENOSYS,
        // This port's resource graph is flat: its devices are the legacy ones
        // the PIC and PIT sit on, which are not behind anything. A bus with no
        // children to derive is not a mechanism to implement here — and
        // answering "no children" would be indistinguishable from a working
        // implementation of a tree this port does not have.
        SyscallNumber::DeviceChild => syscall::ENOSYS,
        SyscallNumber::WakeSource => syscall::ENOSYS,
        SyscallNumber::WakeHold => syscall::ENOSYS,
        SyscallNumber::SystemSuspend => syscall::ENOSYS,
        // This is the single-process demo dispatcher, which has no device
        // graph to name an image's destination and no manager to hold the
        // authority. The port's driver-framework check routes its syscalls
        // through `kcore::dispatch`, which does implement it.
        SyscallNumber::FirmwareLoad => syscall::ENOSYS,
        // Likewise: this dispatcher has no memory-object table to classify
        // anything in. `kcore::dispatch` implements it, and the port's
        // framework check routes through that.
        SyscallNumber::MemoryClassify => syscall::ENOSYS,
        // Declaring a device and mapping its configuration space belong to a
        // bus controller and to the driver a controller handed a function to.
        // This dispatcher serves a single-process demo whose one device is a
        // COM2 port range with no bus above it and no configuration space at
        // all; the port's bus-driver check routes through `kcore::dispatch`,
        // which implements both.
        SyscallNumber::DeviceDeclare
        | SyscallNumber::MapConfig
        | SyscallNumber::ChannelRecvAny
        | SyscallNumber::PortSignal => syscall::ENOSYS,
    }
}

/// `sys_process_exit`: terminate the process and switch to boot — never returns
/// to ring 3.
fn user_process_exit(code: i32) -> i64 {
    // SAFETY: single-core; statics set before the ring-3 thread runs.
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.exit(code);
    }
    // SAFETY: single-core; USER_SCHEDULER is set before the ring-3 thread runs.
    if let Some(scheduler) = unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        scheduler.yield_to_boot();
    }
    // Unreachable: yield_to_boot switched to boot and this thread never resumes.
    0
}

/// Emits the exception report `docs/kernel/03` requires — "the report contains
/// fault type, faulting address ... and a correlation ID". The id and the thread
/// identity come from the ambient context, which the scheduler published when the
/// faulting thread was switched in, so the report joins the trace of whatever
/// caused the fault (D59).
///
/// Safe to call from the trap path: the ring lock is only ever held by kernel
/// code, and a *ring-3* fault cannot interrupt a kernel lock holder.
fn report_contained_fault(vector: u64, fault_addr: u64) {
    kcore::event::emit(
        kcore::event::EventKind::UserFaultContained,
        kcore::event::Severity::Error,
        kcore::event::Component::Exception,
        [vector, fault_addr, 0, 0],
    );
}

/// The registered ring-3 fault handler: contains the fault under the default
/// policy (terminate the faulting process, D23) and switches to boot. A
/// kernel-mode fault never reaches here — it stays on the fatal path.
fn user_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    USER_FAULT_ADDR.store(tessera_karch_x86_64::read_cr2(), Ordering::Relaxed);
    report_contained_fault(frame.vector, tessera_karch_x86_64::read_cr2());
    // SAFETY: single-core; statics set before the ring-3 thread runs.
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.exit(-1);
    }
    // SAFETY: single-core; USER_SCHEDULER is set before the ring-3 thread runs.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.yield_to_boot(),
        None => DebugExit::exit(ExitCode::Failure),
    }
    // yield_to_boot switched to the boot context; this thread never resumes.
    loop {
        core::hint::spin_loop();
    }
}

// --- M14 loader: caller resolution, syscall handler, exit/fault handback ---

/// The unified ring-3 syscall dispatcher for the executive substrate. Every demo
/// that runs ring-3 processes on `EXEC` installs this one handler; it resolves the
/// caller from `PROCESSES` by the running thread (`chan_current_index`), so a
/// parent and the child/peer it creates share one dispatcher. Ops a given demo
/// never issues simply never fire. It covers, over the one `EXEC`/`PROCESSES`/
/// `OBJECTS` substrate: process lifecycle (`ProcessCreate`/`AddressSpaceMap`/
/// `ProcessStart` — the ring-3 loader, D42), channel IPC (`ChannelRecv`/`Call`/
/// `Reply`, M15), ports (`PortCreate`/`Bind`/`Wait`, M16), and capability-gated
/// device I/O (`DeviceIoRead`/`Write`, M16). Unlike `user_syscall_handler` (a
/// single `USER_PROCESS`), it dispatches by the running thread.
///
/// Each arm borrows the process/object tables *locally* (never a handler-wide
/// borrow): the channel/port ops re-borrow `PROCESSES` internally, and a child's
/// re-entrant `ProcessExit` during `loader_process_start`'s handoff borrows it
/// again — single-core cooperative, so only one such borrow is ever dereferenced
/// at a time (the `exec_ref()` SAFETY note).
fn syscall_handler(frame: &mut SyscallFrame) -> i64 {
    USER_RING3_REACHED.store(true, Ordering::Relaxed);
    USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);

    let Some(caller_idx) = chan_current_index() else {
        return syscall::ENOSYS;
    };
    let number = match SyscallNumber::from_u64(frame.number) {
        Some(number) => number,
        None => return syscall::ENOSYS,
    };
    // Uniform arms go through the shared kcore dispatcher (D79). Only the
    // never-blocking subset delegates here — the channel arms stay local for
    // their demo instrumentation (sinks, switch counts) until the observer
    // seam lands.
    if matches!(
        number,
        SyscallNumber::Null | SyscallNumber::MapDevice | SyscallNumber::DmaAlloc
    ) {
        let req = SyscallRequest {
            number: frame.number,
            args: [
                frame.arg0, frame.arg1, frame.arg2, frame.arg3, frame.arg4, frame.arg5,
            ],
        };
        // SAFETY: single-core; EXEC/PROCESSES are populated before any ring-3
        // thread runs and touched only on this CPU. None of the delegated
        // arms blocks, so no borrow is parked across a handoff.
        let processes = unsafe { &mut *&raw mut PROCESSES };
        let mut router = PicRouter;
        let mut env = DispatchEnv {
            exec: exec_ref(),
            processes,
            caller: caller_idx,
            alloc: &mut NoFrames,
            // No IOMMU is wired on this port, so no device has an aperture and
            // every DMA grant is unscoped — and says so (D121).
            iommu: None,
            // The legacy PIC, which this port's device interrupts arrive
            // through (D87 tracks replacing it). Present rather than `None`
            // because an interrupt route dropped from the graph but left
            // unmasked at the controller is the half-teardown the seam exists
            // to prevent.
            irqs: Some(&mut router),
        };
        if let DispatchOutcome::Return(v) = dispatch(&mut env, &req) {
            return v;
        }
        // Unreachable for the three delegated numbers; fall through to the
        // local arms' ENOSYS default rather than inventing a new path.
    }
    match number {
        SyscallNumber::DebugWrite => {
            // SAFETY: single-core; PROCESSES is populated before the ring-3
            // threads run and touched only on this boot CPU.
            let processes = unsafe { &mut *&raw mut PROCESSES };
            match processes.process_of_thread(caller_idx) {
                Some(process) => {
                    let result = user_debug_write(process, frame.arg0, frame.arg1);
                    CHAN_PRINTS.fetch_add(1, Ordering::Relaxed);
                    result
                }
                None => syscall::ENOSYS,
            }
        }
        SyscallNumber::ProcessExit => chan_process_exit(caller_idx, frame.arg0 as i32),
        // Ring-3 process lifecycle (the loader, D42): create → map+copy → start a
        // child. These borrow the process/object tables for the call's duration.
        SyscallNumber::ProcessCreate => {
            // SAFETY: single-core; PROCESSES/OBJECTS populated before the ring-3
            // thread runs and touched only on this boot CPU.
            let processes = unsafe { &mut *&raw mut PROCESSES };
            let objects = unsafe { &mut *&raw mut OBJECTS };
            loader_process_create(processes, objects, caller_idx, frame.arg0)
        }
        SyscallNumber::AddressSpaceMap => {
            // SAFETY: as for ProcessCreate.
            let processes = unsafe { &mut *&raw mut PROCESSES };
            let objects = unsafe { &mut *&raw mut OBJECTS };
            loader_address_space_map(processes, objects, caller_idx, frame.arg0)
        }
        SyscallNumber::ProcessStart => {
            // SAFETY: as for ProcessCreate.
            let processes = unsafe { &mut *&raw mut PROCESSES };
            let objects = unsafe { &mut *&raw mut OBJECTS };
            loader_process_start(processes, objects, caller_idx, frame.arg0)
        }
        // Channel IPC (M15): client drives Call; server drives Recv then Reply.
        SyscallNumber::ChannelRecv => chan_channel_recv(caller_idx, frame.arg1),
        SyscallNumber::ChannelCall => chan_channel_call(caller_idx, frame.arg0, frame.arg1),
        SyscallNumber::ChannelReply => chan_channel_reply(caller_idx, frame.arg0, frame.arg1),
        // Ports + capability-gated device I/O (M16 driver host).
        SyscallNumber::PortCreate => driver_port_create(caller_idx),
        SyscallNumber::PortBind => {
            driver_port_bind(caller_idx, frame.arg0, frame.arg1, frame.arg2 as u8)
        }
        SyscallNumber::PortWait => driver_port_wait(caller_idx, frame.arg0),
        SyscallNumber::DeviceIoRead => driver_device_io(caller_idx, frame.arg0, frame.arg1, None),
        SyscallNumber::DeviceIoWrite => {
            driver_device_io(caller_idx, frame.arg0, frame.arg1, Some(frame.arg2 as u8))
        }
        _ => syscall::ENOSYS,
    }
}

/// The loader demo's ring-3 fault handler: contains the fault (terminate the
/// faulting process, D23) and — like `loader_process_exit` — hands back to a
/// waiting parent so a faulting child cannot strand it, or switches to boot.
fn loader_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    USER_FAULT_ADDR.store(tessera_karch_x86_64::read_cr2(), Ordering::Relaxed);
    report_contained_fault(frame.vector, tessera_karch_x86_64::read_cr2());
    let caller_idx = chan_current_index();
    // SAFETY: single-core; statics set before the ring-3 thread runs.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if let Some(idx) = caller_idx
        && let Some(process) = processes.process_of_thread(idx)
    {
        process.exit(-1);
    }
    // SAFETY: single-core; PARENT_WAITER only set by `ProcessStart` on this CPU.
    let waiter = unsafe { (*&raw mut PARENT_WAITER).take() };
    // SAFETY: single-core; EXEC is set before the ring-3 thread runs.
    match unsafe { (*&raw mut EXEC).as_mut() } {
        Some(exec) => {
            let scheduler = exec.scheduler();
            match waiter {
                Some(parent) => {
                    LOADER_CHILD_EXIT.store(-1, Ordering::Relaxed);
                    LOADER_CHILD_RAN.store(true, Ordering::Relaxed);
                    scheduler.handoff_to(parent);
                }
                None => scheduler.yield_to_boot(),
            }
        }
        None => DebugExit::exit(ExitCode::Failure),
    }
    // A handback/boot switch left this context; it never resumes.
    loop {
        core::hint::spin_loop();
    }
}

/// Maps the ISL `Rights` bits used by the loader onto neutral `PageFlags`. Every
/// mapped page is user-accessible; read/write/execute follow the requested bits.
/// The kernel rejects a writable+executable result (W^X) at the call site.
fn rights_to_pageflags(rights: Rights) -> PageFlags {
    let mut flags = PageFlags::none().user();
    if rights.contains(Rights::READ) {
        flags = flags.read();
    }
    if rights.contains(Rights::WRITE) {
        flags = flags.write();
    }
    if rights.contains(Rights::EXECUTE) {
        flags = flags.execute();
    }
    flags
}

/// Phase 1 — `ProcessCreate`: create an empty, not-yet-started child process
/// under the caller's `create-process` authority, and install a handle to it in
/// the caller's handle table. Returns the raw child handle. (docs/api/01, "Create
/// process"; `create-process` is a job right, docs/security/01.)
fn loader_process_create(
    processes: &mut ProcessTable<KernelAddressSpace>,
    objects: &mut ObjectTable,
    caller_idx: usize,
    args_ptr: u64,
) -> i64 {
    // Read + validate the args, and check the caller holds the named job handle
    // with CREATE_PROCESS — the create-process authority gate.
    let caller = match processes.process_of_thread(caller_idx) {
        Some(caller) => caller,
        None => return syscall::ENOSYS,
    };
    let mut buf = [0u8; PROCESS_CREATE_ARGS_SIZE];
    if let Err(e) = read_user(caller, args_ptr, &mut buf) {
        return encode_result(Err(e));
    }
    let job = match decode_process_create_args(&buf) {
        Ok(job) => job,
        Err(e) => return encode_result(Err(e)),
    };
    match caller.handles().rights(job) {
        Ok(rights) if rights.contains(Rights::CREATE_PROCESS) => {}
        Ok(_) => return encode_result(Err(KError::AccessDenied)),
        Err(e) => return encode_result(Err(e)),
    }
    // Caller borrow ends; create the child space + process object.
    // SAFETY: single-core; the loader raw pointers name the boot kernel space and
    // allocator, live for the kernel's lifetime.
    let (kernel_vm, frames) = match unsafe { (LOADER_KERNEL_VM.as_mut(), LOADER_FRAMES.as_mut()) } {
        (Some(vm), Some(frames)) => (vm, frames),
        _ => return syscall::ENOSYS,
    };
    let child_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => return encode_result(Err(e)),
    };
    let child_vm = AddressSpace::from_arch(child_arch, child_asid(), 1u64 << Cpu::cpu_id());
    let child_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => return encode_result(Err(e)),
    };
    if processes.insert(Process::new(child_obj, child_vm)).is_err() {
        return encode_result(Err(KError::OutOfMemory));
    }
    // Install a handle to the child in the caller's table (adopts the object's
    // reference from `create`). The parent gets map + start authority over it.
    let caller = match processes.process_of_thread(caller_idx) {
        Some(caller) => caller,
        None => return syscall::ENOSYS,
    };
    let handle = match caller.handles_mut().install(
        child_obj,
        Rights::READ | Rights::WRITE | Rights::MAP | Rights::EXECUTE | Rights::CREATE_PROCESS,
    ) {
        Ok(handle) => handle,
        Err(e) => return encode_result(Err(e)),
    };
    LOADER_CHILD_HANDLE.store(handle.raw() as u64 + 1, Ordering::Relaxed);
    encode_result(Ok(handle.raw() as u64))
}

/// Phase 2 — `AddressSpaceMap`: map `length` bytes at `vaddr` into the target
/// child (resolved from a handle with MAP right) and populate them from the
/// caller's `src` buffer, then apply the final W^X rights. The copy goes through
/// the HHDM (`copy_in`) with the caller space still active — no CR3 switch (D44).
fn loader_address_space_map(
    processes: &mut ProcessTable<KernelAddressSpace>,
    _objects: &mut ObjectTable,
    caller_idx: usize,
    args_ptr: u64,
) -> i64 {
    let caller = match processes.process_of_thread(caller_idx) {
        Some(caller) => caller,
        None => return syscall::ENOSYS,
    };
    let mut buf = [0u8; ADDRESS_SPACE_MAP_ARGS_SIZE];
    if let Err(e) = read_user(caller, args_ptr, &mut buf) {
        return encode_result(Err(e));
    }
    let req = match decode_address_space_map_args(&buf) {
        Ok(req) => req,
        Err(e) => return encode_result(Err(e)),
    };
    // Resolve the target child from the caller's handle (needs MAP).
    let child_obj = match caller.handles().lookup(req.process) {
        Ok((obj, rights)) if rights.contains(Rights::MAP) => obj,
        Ok(_) => return encode_result(Err(KError::AccessDenied)),
        Err(e) => return encode_result(Err(e)),
    };
    // Validate the source buffer is readable in the caller (active) space; its
    // bytes are read through a raw pointer below while that CR3 stays loaded.
    if req.src != 0
        && let Err(e) = validate_user_range(caller.space(), req.src, req.length, false)
    {
        return encode_result(Err(e));
    }
    // Caller borrow ends (child_obj + req are Copy).
    if req.length == 0 {
        return encode_result(Err(KError::InvalidMapping));
    }
    let rights = rights_to_pageflags(req.rights);
    if rights.is_wx() {
        return encode_result(Err(KError::WXViolation));
    }
    // SAFETY: single-core; the loader frame pointer names the boot allocator.
    let frames = match unsafe { LOADER_FRAMES.as_mut() } {
        Some(frames) => frames,
        None => return syscall::ENOSYS,
    };
    let child = match processes.process_of_id(child_obj) {
        Some(child) => child,
        None => return encode_result(Err(KError::BadHandle)),
    };
    let page_len = req.length.div_ceil(FRAME_SIZE) * FRAME_SIZE;
    // Map writable to receive bytes.
    if let Err(e) = child.space_mut().map_anonymous(
        VirtAddr::new(req.vaddr),
        page_len,
        PageFlags::rw().user(),
        frames,
    ) {
        return encode_result(Err(e));
    }
    // Copy the caller's bytes into the child's frames through the HHDM.
    if req.src != 0 {
        // SAFETY: `[src, src+length)` was validated user-readable in the caller's
        // space, which is the active CR3 here, so the read cannot fault.
        let src = unsafe { core::slice::from_raw_parts(req.src as *const u8, req.length as usize) };
        if let Err(e) = child.space().copy_in(VirtAddr::new(req.vaddr), src) {
            return encode_result(Err(e));
        }
    }
    // Re-protect to the final W^X rights (rx for code, rw for data).
    if let Err(e) = child
        .space_mut()
        .protect_range(VirtAddr::new(req.vaddr), page_len, rights)
    {
        return encode_result(Err(e));
    }
    encode_result(Ok(req.length))
}

/// Phase 3 — `ProcessStart`: spawn the child's initial thread at `entry`/`stack`,
/// join it to the shared scheduler, and hand off to it (the synchronous start,
/// like `Executive::call`). Returns the child's exit code once it exits and hands
/// control back (the waiter handback in `loader_process_exit`).
fn loader_process_start(
    processes: &mut ProcessTable<KernelAddressSpace>,
    objects: &mut ObjectTable,
    caller_idx: usize,
    args_ptr: u64,
) -> i64 {
    let caller = match processes.process_of_thread(caller_idx) {
        Some(caller) => caller,
        None => return syscall::ENOSYS,
    };
    let mut buf = [0u8; PROCESS_START_ARGS_SIZE];
    if let Err(e) = read_user(caller, args_ptr, &mut buf) {
        return encode_result(Err(e));
    }
    let req = match decode_process_start_args(&buf) {
        Ok(req) => req,
        Err(e) => return encode_result(Err(e)),
    };
    let child_obj = match caller.handles().lookup(req.process) {
        Ok((obj, rights)) if rights.contains(Rights::CREATE_PROCESS) => obj,
        Ok(_) => return encode_result(Err(KError::AccessDenied)),
        Err(e) => return encode_result(Err(e)),
    };
    // Caller borrow ends.
    // SAFETY: single-core; the loader raw pointers name the boot kernel space and
    // allocator.
    let (kernel_vm, frames) = match unsafe { (LOADER_KERNEL_VM.as_mut(), LOADER_FRAMES.as_mut()) } {
        (Some(vm), Some(frames)) => (vm, frames),
        _ => return syscall::ENOSYS,
    };
    // Spawn + register the child thread while borrowing the child; the borrow
    // ends before the handoff (the hard rule: no live table borrow across a
    // scheduler switch).
    let child_idx = {
        let child = match processes.process_of_id(child_obj) {
            Some(child) => child,
            None => return encode_result(Err(KError::BadHandle)),
        };
        let child_root = child.space().arch().root_phys();
        // A single fixed kstack window, reused every launch: M20 reclaims the
        // prior child's kstack on its exit (below, after the handback), so the
        // window is free before this spawn. Safe because supervision is
        // synchronous — one child alive at a time. `slot` is now only an
        // observability counter (launch count), not an address.
        let slot = CM_LAUNCHES.fetch_add(1, Ordering::Relaxed);
        let child_kstack = child_kstack_window();
        let thread = match Thread::<ContextSwitch>::spawn_user(
            ThreadId(0x_700_7002 + slot),
            VirtAddr::new(req.entry),
            req.arg as usize,
            VirtAddr::new(req.stack),
            CHILD_STACK_PAGES,
            VirtAddr::new(child_kstack),
            USER_KSTACK_PAGES,
            child_obj,
            child_root,
            child.space_mut(),
            kernel_vm,
            frames,
        ) {
            Ok(thread) => thread,
            Err(e) => return encode_result(Err(e)),
        };
        let idx = match exec_ref().add_thread(thread) {
            Ok(idx) => idx,
            Err(_) => return encode_result(Err(KError::OutOfMemory)),
        };
        if child.add_thread(idx).is_err() {
            return encode_result(Err(KError::OutOfMemory));
        }
        child.set_running();
        idx
    };
    // Park this (parent) thread as the child's waiter and hand off to the child.
    // SAFETY: single-core; PARENT_WAITER is read only by the child's exit/fault.
    unsafe { PARENT_WAITER = Some(caller_idx) };
    // No table borrow is live here; `exec_ref()` re-borrows the executive per op.
    exec_ref().scheduler().handoff_to(child_idx);
    // M20 reclaim-on-exit (docs/kernel/05): the child exited/faulted and
    // handed back, so it is now Blocked and switched off its own kernel
    // stack (the parent's CR3 is active). Return its resources to their
    // pools — the teardown D49 deferred — so a supervisor can restart it
    // without leaking. Reap frees the scheduler slot and yields the thread;
    // reclaim_range unmaps + frees its kstack window in the *shared*
    // kernel_vm. This is memory-safe on single-core because the child is
    // off-CPU and the kstack window (a distinct VA from the parent's) is
    // edited through the direct map, not the active CR3; invlpg suffices
    // (SMP would need a TLB shootdown of the window — deferred, D50).
    if let Some(child_thread) = exec_ref().scheduler().reap(child_idx) {
        let _ = kernel_vm.reclaim_range(
            child_thread.kernel_stack_base(),
            child_thread.stack_bytes(),
            frames,
        );
    }
    // Reclaim the child's process slot and tear down its address space (leaf
    // frames + the page-table frames it uniquely owns), then close the parent's
    // handle to the child so the object-table slot is released too — otherwise
    // restart stays bounded by the object/handle tables.
    if let Some(pidx) = processes.index_of_id(child_obj) {
        if let Some(mut child) = processes.remove(pidx) {
            child.space_mut().teardown(frames);
        }
    }
    if let Some(parent) = processes.process_of_thread(caller_idx) {
        let _ = parent.handles_mut().close(objects, req.process);
    }
    // The child exited and handed back here; report its exit code to the parent.
    LOADER_PARENT_RESUMED.store(true, Ordering::Relaxed);
    let code = LOADER_CHILD_EXIT.load(Ordering::Relaxed);
    encode_result(Ok(code as u32 as u64))
}

/// The page range covering `[vaddr, vaddr + mem_size)`, rounded out to whole
/// pages: `(page_base, page_count)`.
fn elf_seg_pages(seg: &elf::Segment) -> (u64, u64) {
    let page_base = seg.vaddr & !(FRAME_SIZE - 1);
    let end = seg.vaddr + seg.mem_size;
    let page_end = (end + FRAME_SIZE - 1) & !(FRAME_SIZE - 1);
    (page_base, (page_end - page_base) / FRAME_SIZE)
}

/// The final page rights for a loaded segment: user + read, plus execute or
/// write per the segment flags. W^X holds by construction — the loader rejects a
/// write+execute segment before calling this.
fn elf_seg_rights(seg: &elf::Segment) -> PageFlags {
    let mut flags = PageFlags::none().read().user();
    if seg.exec {
        flags = flags.execute();
    }
    if seg.write {
        flags = flags.write();
    }
    flags
}

/// The user-space loader demo (M14, closes D42's ring-3 gap): the kernel loads
/// the root-task ELF and runs it in ring 3 as the **parent/loader** (proving the
/// three-phase ELF load, D25), and the root task then drives `ProcessCreate` →
/// `AddressSpaceMap` → `ProcessStart` to create, populate, and start a **child
/// process** from user space — the docs' "kernel maps, user-space loads" model
/// (docs/api/01, "the loader operation"). The parent and child share one
/// scheduler; the parent hands off to the child it starts and resumes when the
/// child exits.
fn loader_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let image = root_task_elf();
    if image.is_empty() {
        return kprintln!("loader: skipped (no embedded ELF image; cargo inner-loop build)");
    }
    let parsed = match elf::parse(image, elf::Machine::X86_64) {
        Ok(parsed) => parsed,
        Err(e) => return kprintln!("loader: FAIL — ELF parse rejected: {e:?}"),
    };
    // W^X: no loaded segment may be writable and executable (docs/kernel/03).
    for seg in parsed.segments() {
        if seg.write && seg.exec {
            return kprintln!("loader: FAIL — W+X segment at {:#x} rejected", seg.vaddr);
        }
    }

    // SAFETY: one-shot registration before this ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(loader_fault_handler);
    USER_RING3_REACHED.store(false, Ordering::Relaxed);
    LOADER_CHILD_RAN.store(false, Ordering::Relaxed);
    LOADER_PARENT_RESUMED.store(false, Ordering::Relaxed);
    LOADER_CHILD_EXIT.store(i32::MIN, Ordering::Relaxed);
    // Publish the boot kernel space + allocator so the loader syscalls (running
    // in trap context) can create child spaces and map into them.
    // SAFETY: single-core; `_start` never returns, so these outlive every use.
    unsafe {
        LOADER_KERNEL_VM = core::ptr::from_mut(kernel_vm);
        LOADER_FRAMES = core::ptr::from_mut(frames);
    }

    // Phase 1 — create the parent (root-task) process and its address space.
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => return kprintln!("loader: FAIL — new_user: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, alloc_asid(), 1u64 << Cpu::cpu_id());
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => return kprintln!("loader: FAIL — process object: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    // Seed the parent with a job handle carrying `create-process` authority — the
    // gate `ProcessCreate` checks (docs/security/01). Deterministically the first
    // handle (raw 0); the root task passes it as the create job.
    let job_obj = match objects.create(ObjectType::Job) {
        Ok(id) => id,
        Err(e) => return kprintln!("loader: FAIL — job object: {e:?}"),
    };
    let job_handle = match process
        .handles_mut()
        .insert(job_obj, Rights::CREATE_PROCESS)
    {
        Ok(handle) => handle,
        Err(e) => return kprintln!("loader: FAIL — seed job handle: {e:?}"),
    };

    // Phase 2a — reserve each PT_LOAD segment's pages writable, to receive bytes.
    let seg_count = parsed.segments().len();
    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        if process
            .space_mut()
            .map_anonymous(
                VirtAddr::new(base),
                pages * FRAME_SIZE,
                PageFlags::rw().user(),
                frames,
            )
            .is_err()
        {
            return kprintln!("loader: FAIL — map segment at {base:#x}");
        }
    }

    // Spawn the parent's initial thread at the ELF entry point.
    let thread = match Thread::<ContextSwitch>::spawn_user(
        ThreadId(0x_700_7001),
        VirtAddr::new(parsed.entry()),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(LOADER_PARENT_KSTACK_PAGES),
        LOADER_PARENT_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => return kprintln!("loader: FAIL — spawn_user: {e:?}"),
    };
    // SAFETY: single-threaded boot; initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let thread_idx = match exec_ref().add_thread(thread) {
        Ok(idx) => idx,
        Err(_) => return kprintln!("loader: FAIL — add_thread"),
    };
    if process.add_thread(thread_idx).is_err() {
        return kprintln!("loader: FAIL — process add_thread");
    }

    // Phase 2b — activate the parent space (from boot context), copy each
    // segment's file bytes, zero its bss tail, then re-protect it to W^X. (The
    // parent is loaded here by the kernel; the *child* is populated by the parent
    // via `AddressSpaceMap` through the HHDM, no CR3 switch.)
    // SAFETY: the user space shares the kernel higher half; boot code, stack, and
    // the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    for seg in parsed.segments() {
        let src = image[seg.file_offset as usize..].as_ptr();
        // SAFETY: `parse` bounds-checked `[file_offset, file_offset+file_size)`
        // against the image; the destination pages are mapped writable in the
        // now-active user space.
        unsafe {
            core::ptr::copy_nonoverlapping(src, seg.vaddr as *mut u8, seg.file_size as usize);
            let bss = (seg.mem_size - seg.file_size) as usize;
            if bss > 0 {
                core::ptr::write_bytes((seg.vaddr + seg.file_size) as *mut u8, 0, bss);
            }
        }
    }
    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        if process
            .space_mut()
            .protect_range(VirtAddr::new(base), pages * FRAME_SIZE, elf_seg_rights(seg))
            .is_err()
        {
            return kprintln!("loader: FAIL — protect segment at {base:#x}");
        }
    }

    // Phase 3 — publish the parent into the process table and start.
    process.set_running();
    let parent_pidx = match processes_insert(process) {
        Ok(idx) => idx,
        Err(e) => return kprintln!("loader: FAIL — process table insert: {e:?}"),
    };
    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    // Verify the full round-trip: parent ran, created + populated + started a
    // child, the child ran in ring 3 and exited 42, and the parent resumed and
    // exited clean.
    let reached = USER_RING3_REACHED.load(Ordering::Relaxed);
    let child_ran = LOADER_CHILD_RAN.load(Ordering::Relaxed);
    let child_exit = LOADER_CHILD_EXIT.load(Ordering::Relaxed);
    let parent_resumed = LOADER_PARENT_RESUMED.load(Ordering::Relaxed);
    // SAFETY: single-core boot; the ring-3 run has returned to boot.
    let parent_clean = matches!(
        unsafe { (*&raw mut PROCESSES).get(parent_pidx) }.map(Process::state),
        Some(ProcessState::Exited(0))
    );
    let pass = reached && child_ran && child_exit == 42 && parent_resumed && parent_clean;
    report(&verdict(
        DemoId::Loader,
        pass,
        [
            parsed.entry(),
            seg_count as u64,
            u64::from(job_handle.raw()),
            child_exit as u64,
            0,
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "loader: FAIL reached={reached} child_ran={child_ran} child_exit={child_exit} parent_resumed={parent_resumed} parent_clean={parent_clean}"
        );
    }
}

/// Inserts `process` into the global loader process table. A thin wrapper so the
/// unsafe static access has one home.
fn processes_insert(process: Process<KernelAddressSpace>) -> Result<usize, KError> {
    // SAFETY: single-core boot; PROCESSES is touched only on this CPU.
    unsafe { (*&raw mut PROCESSES).insert(process) }
}

// --- M19: component manager (a ring-3 service launches + supervises a service) --

/// The manager's writable data page (in its own space): the loader arg structs,
/// the embedded service blob, and the restart-countdown word — separate from the
/// `rx` code page so the manager can patch the child handle + policy arg at run
/// time. Field offsets the manager blob addresses absolutely: create_args@0,
/// map_args@24 (process@40=0x600028), start_args@80 (process@96=0x600060,
/// arg@120=0x600078), service blob@128, countdown@256.
const CM_DATA_VA: u64 = 0x0000_0000_0060_0000;
/// The service's ring-3 stack base (in the child's space), like the root task's.
const CM_CHILD_STACK: u64 = 0x0000_0000_6800_0000;
/// The restart countdown's offset in the data page (a word the manager decrements
/// across launches — robust over the `ProcessStart` block, unlike a register).
/// The budget word follows it (the hard cap on launches, respecting the leak
/// bound). Both are prefilled by the demo and read by the manager blob at the
/// absolute VAs `CM_DATA_VA + 256` / `+ 260`.
const CM_COUNTDOWN_OFF: usize = 256;
const CM_BUDGET_OFF: usize = 260;
/// The exit code the manager reports when it exhausts the restart budget while
/// the service is still crashing (must match the `mov edi, 176` in the blob).
const CM_GIVEUP_CODE: i32 = 176;

// The SERVICE: a tiny PIC blob that exits with the code the manager passed
// (`ProcessStart`'s `arg`, delivered in rdi = ProcessExit's arg0). A non-zero
// code models a crash; 0 models coming up clean.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global cm_service_program_start
.global cm_service_program_end
cm_service_program_start:
    mov eax, 5                         # ProcessExit(rdi = the manager's arg)
    syscall
1:
    jmp 1b
cm_service_program_end:
.text
"#
);

// The COMPONENT MANAGER: loops the three-phase launch, restarting the service
// while it "crashes" (non-zero exit), until either the countdown reaches 0 (the
// service comes up clean → exit 0) or the restart budget is exhausted (still
// crashing → give up, exit CM_GIVEUP_CODE). Both the countdown@0x600100 and the
// budget@0x600104 are prefilled by the demo. Reads the loader arg structs from
// the data page at 0x600000, patches the returned child handle (rax) into
// map_args/start_args and the countdown into start_args.arg. Absolute VAs (Intel
// global_asm! numeric offsets — a bare symbol would assemble as a memory ref).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global cm_manager_program_start
.global cm_manager_program_end
cm_manager_program_start:
1:
    mov ebx, 0x600100                  # store the countdown into start_args.arg
    mov eax, [rbx]
    mov ebx, 0x600078                  # start_args.arg (the service exits with it)
    mov [rbx], eax
    mov edi, 0x600000                  # create_args
    mov eax, 8                         # ProcessCreate -> rax = child handle
    syscall
    mov ebx, 0x600028                  # map_args.process
    mov [rbx], eax
    mov ebx, 0x600060                  # start_args.process
    mov [rbx], eax
    mov edi, 0x600018                  # map_args
    mov eax, 9                         # AddressSpaceMap (map+copy the service code)
    syscall
    mov edi, 0x600050                  # start_args
    mov eax, 10                        # ProcessStart (blocks; rax = service exit code)
    syscall
    mov ebx, 0x600104                  # budget-- (a launch just happened)
    mov ecx, [rbx]
    dec ecx
    mov [rbx], ecx
    test eax, eax                      # service exit code
    jz 2f                              # exit 0 -> came up clean -> success
    test ecx, ecx                      # still crashing: budget left?
    jz 3f                              # budget exhausted -> give up
    mov ebx, 0x600100                  # else decrement the countdown and restart
    mov eax, [rbx]
    dec eax
    mov [rbx], eax
    jmp 1b
2:
    lea rdi, [rip + cm_manager_msg]
    mov esi, 22                        # length (== cm_manager_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit(0) — recovered clean
    syscall
3:
    lea rdi, [rip + cm_giveup_msg]
    mov esi, 20                        # length (== cm_giveup_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    mov edi, 176                       # ProcessExit(CM_GIVEUP_CODE) — gave up
    mov eax, 5
    syscall
4:
    jmp 4b
cm_manager_msg:
    .ascii "cm: service supervised"
cm_giveup_msg:
    .ascii "cm: gave up (budget)"
cm_manager_program_end:
.text
"#
);

// SAFETY: names the M19 blob bounds from the global_asm above; the extern block
// only declares them and performs no unsafe operation.
unsafe extern "C" {
    static cm_service_program_start: u8;
    static cm_service_program_end: u8;
    static cm_manager_program_start: u8;
    static cm_manager_program_end: u8;
}

/// Pre-fills the manager's data page (its space must be active) with the loader
/// arg structs (all fixed fields; the manager patches process + arg at run time)
/// and the embedded service blob. Zero fields rely on `map_anonymous`'s zero-fill.
fn cm_prefill_data_page(service_blob: *const u8, service_len: usize, countdown: u32, budget: u32) {
    let d = CM_DATA_VA as *mut u8;
    // SAFETY: the manager space is active and CM_DATA_VA is a mapped writable page
    // with room for the structs (through offset ~260) and the service blob.
    unsafe {
        // create_args @0: size=24, version=1 (job@16=0, reserved@20=0 zero-filled)
        (d.add(0) as *mut u32).write_unaligned(24);
        (d.add(4) as *mut u32).write_unaligned(1);
        // map_args @24: size=56, version=1, vaddr@48, length@56, rights@64, src@72
        (d.add(24) as *mut u32).write_unaligned(56);
        (d.add(28) as *mut u32).write_unaligned(1);
        (d.add(48) as *mut u64).write_unaligned(USER_CODE_VA); // child code vaddr
        (d.add(56) as *mut u64).write_unaligned(service_len as u64);
        (d.add(64) as *mut u64).write_unaligned((Rights::READ | Rights::EXECUTE).bits());
        (d.add(72) as *mut u64).write_unaligned(CM_DATA_VA + 128); // src = service blob VA
        // start_args @80: size=48, version=1, entry@104, stack@112, arg@120 (patched)
        (d.add(80) as *mut u32).write_unaligned(48);
        (d.add(84) as *mut u32).write_unaligned(1);
        (d.add(104) as *mut u64).write_unaligned(USER_CODE_VA); // child entry
        (d.add(112) as *mut u64).write_unaligned(CM_CHILD_STACK);
        // service blob @128
        core::ptr::copy_nonoverlapping(service_blob, d.add(128), service_len);
        // restart policy: crash countdown + hard launch budget
        (d.add(CM_COUNTDOWN_OFF) as *mut u32).write_unaligned(countdown);
        (d.add(CM_BUDGET_OFF) as *mut u32).write_unaligned(budget);
    }
}

/// What one supervised run produced: the number of launches this run made, how
/// many children actually ran + exited back, the sum of their exit codes, the
/// last child's exit code, the manager's own exit code, and — for the M20 reclaim
/// proof — the net frames drawn from the map during the run (`handed_out_delta`,
/// bounded and *independent of launch count* once children are reclaimed and their
/// frames reused) and any reclaim-overflow events (must be 0).
struct CmOutcome {
    launches: u64,
    runs: u64,
    exit_sum: i64,
    last_exit: i32,
    manager_exit: Option<i32>,
    handed_out_delta: u64,
    reclaim_overflows: u64,
}

/// Builds a component manager (ASID `asid`, kstack `manager_kstack`) with the
/// restart policy `(countdown, budget)`, runs it on a fresh `EXEC` executive, and
/// gathers the outcome. The manager launches the embedded service (the M14 loader
/// syscalls), supervises it via the synchronous `ProcessStart`-returns-exit-code
/// handoff, and restarts it on each "crash" (non-zero exit) until it comes up
/// clean or the budget is spent. With M20 reclaim-on-exit each child's kstack,
/// process/thread slots, address space, and handle are returned on its exit, so
/// `CM_LAUNCHES` is reset here (it is now pure observability) and the run's frame
/// draw stays bounded no matter how many restarts it makes.
fn cm_run(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    countdown: u32,
    budget: u32,
    asid: u16,
    manager_kstack: u64,
) -> Result<CmOutcome, &'static str> {
    // SAFETY: one-shot registration before this run's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(loader_fault_handler);
    CM_LAUNCHES.store(0, Ordering::Relaxed);
    CM_CHILD_RUNS.store(0, Ordering::Relaxed);
    CM_EXIT_SUM.store(0, Ordering::Relaxed);
    LOADER_CHILD_EXIT.store(i32::MIN, Ordering::Relaxed);
    // Frame draw at run start: with reclaim, the run's net draw is the manager's
    // fixed cost plus one live child's peak — not proportional to the launches.
    let handed_before = frames.handed_out();
    let overflows_before = frames.reclaim_overflows();
    // Fresh scheduler + process table (a prior demo/run left slots consumed); the
    // loader syscalls (in trap context) reach the boot space + allocator here.
    // SAFETY: single-core boot; `_start` never returns, so the raw pointers outlive
    // every use; the statics are touched only on this CPU.
    unsafe {
        LOADER_KERNEL_VM = core::ptr::from_mut(kernel_vm);
        LOADER_FRAMES = core::ptr::from_mut(frames);
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
        PARENT_WAITER = None;
    }

    // Build the manager process: fresh space, code page (rw to receive the blob),
    // a writable data page, a 32-page kernel stack, a seeded create-process job.
    let user_arch = kernel_vm.arch().new_user(frames).map_err(|_| "new_user")?;
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, Asid(asid), 1u64 << Cpu::cpu_id());
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = objects
        .create(ObjectType::Process)
        .map_err(|_| "process object")?;
    let mut manager = Process::new(proc_obj, user_vm);
    let job_obj = objects.create(ObjectType::Job).map_err(|_| "job object")?;
    manager
        .handles_mut()
        .insert(job_obj, Rights::CREATE_PROCESS)
        .map_err(|_| "seed job handle")?;
    let user = PageFlags::rw().user();
    manager
        .space_mut()
        .map_anonymous(
            VirtAddr::new(USER_CODE_VA),
            USER_CODE_PAGES * FRAME_SIZE,
            user,
            frames,
        )
        .map_err(|_| "map code page")?;
    manager
        .space_mut()
        .map_anonymous(VirtAddr::new(CM_DATA_VA), FRAME_SIZE, user, frames)
        .map_err(|_| "map data page")?;
    let thread = Thread::<ContextSwitch>::spawn_user(
        ThreadId(0x_c_9a_e2),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        VirtAddr::new(manager_kstack),
        LOADER_PARENT_KSTACK_PAGES,
        proc_obj,
        user_root,
        manager.space_mut(),
        kernel_vm,
        frames,
    )
    .map_err(|_| "spawn_user")?;
    let manager_idx = exec_ref().add_thread(thread).map_err(|_| "add_thread")?;
    manager
        .add_thread(manager_idx)
        .map_err(|_| "process add_thread")?;

    // Activate the manager space, copy its blob to the code page, pre-fill the
    // data page (structs + service blob + policy words), then W^X-protect the code.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { manager.space().activate(Cpu::cpu_id()) };
    let mblob = &raw const cm_manager_program_start as *const u8;
    let mlen = (&raw const cm_manager_program_end as usize)
        - (&raw const cm_manager_program_start as usize);
    // SAFETY: the blob is in kernel rodata; USER_CODE_VA is a writable user page
    // in the now-active manager space with room for it.
    unsafe { core::ptr::copy_nonoverlapping(mblob, USER_CODE_VA as *mut u8, mlen) };
    let sblob = &raw const cm_service_program_start as *const u8;
    let slen = (&raw const cm_service_program_end as usize)
        - (&raw const cm_service_program_start as usize);
    cm_prefill_data_page(sblob, slen, countdown, budget);
    manager
        .space_mut()
        .protect_range(
            VirtAddr::new(USER_CODE_VA),
            USER_CODE_PAGES * FRAME_SIZE,
            PageFlags::rx().user(),
        )
        .map_err(|_| "protect manager code")?;

    manager.set_running();
    let manager_pidx = processes_insert(manager).map_err(|_| "insert manager")?;
    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    // SAFETY: single-core boot; the ring-3 run has returned to boot.
    let manager_exit = match unsafe { (*&raw mut PROCESSES).get(manager_pidx) }.map(Process::state)
    {
        Some(ProcessState::Exited(code)) => Some(code),
        _ => None,
    };
    Ok(CmOutcome {
        launches: CM_LAUNCHES.load(Ordering::Relaxed),
        runs: CM_CHILD_RUNS.load(Ordering::Relaxed),
        exit_sum: CM_EXIT_SUM.load(Ordering::Relaxed),
        last_exit: LOADER_CHILD_EXIT.load(Ordering::Relaxed),
        manager_exit,
        handed_out_delta: frames.handed_out() - handed_before,
        reclaim_overflows: frames.reclaim_overflows() - overflows_before,
    })
}

/// M19: the component manager. A ring-3 manager launches a service (the M14
/// loader syscalls), supervises it (the synchronous `ProcessStart`-returns-exit-
/// code handoff), and restarts it on each "crash" (non-zero exit) until it comes
/// up clean — the roadmap's "Service dependency restart". Recovery path: countdown
/// 3 (service exits 3,2,1,0), budget 6 (never reached — recovery wins first).
fn component_manager_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let outcome = match cm_run(
        kernel_vm,
        frames,
        3,
        6,
        alloc_asid().0,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
    ) {
        Ok(outcome) => outcome,
        Err(msg) => return kprintln!("cm: FAIL — {msg}"),
    };
    // Countdown 3 → the service exits 3,2,1,0 over 4 launches: 4 real child runs
    // (none failed to spawn), exit codes summing to 6, the last exit 0 (came up
    // clean), and the manager itself exited clean. `runs == launches` proves no
    // restart collided at the kstack window (a failed launch never runs a child).
    let pass = outcome.launches == 4
        && outcome.runs == 4
        && outcome.exit_sum == 6
        && outcome.last_exit == 0
        && outcome.manager_exit == Some(0);
    report(&verdict(
        DemoId::ComponentManager,
        pass,
        [
            outcome.launches,
            outcome.runs,
            outcome.exit_sum as u64,
            outcome.last_exit as u64,
            0,
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "cm: FAIL — launches={} runs={} exit_sum={} last_exit={} manager_exit={:?}",
            outcome.launches,
            outcome.runs,
            outcome.exit_sum,
            outcome.last_exit,
            outcome.manager_exit
        );
    }
}

/// M19 negative self-test: the restart budget is a hard cap. A service that keeps
/// crashing (countdown 10, never reaching 0) is restarted only `budget` (4) times,
/// then the manager gives up — it never runs away toward the ~15-launch leak
/// bound. Proves the guard fires: launches == budget, the last child still crashed
/// (non-zero exit), and the manager exited the distinct `CM_GIVEUP_CODE`.
fn cm_budget_selftest(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let outcome = match cm_run(
        kernel_vm,
        frames,
        10,
        4,
        alloc_asid().0,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
    ) {
        Ok(outcome) => outcome,
        Err(msg) => return kprintln!("cm-budget: FAIL — {msg}"),
    };
    // Countdown 10 with budget 4 → the service exits 10,9,8,7 (all crashes) over
    // exactly 4 launches, then the manager gives up: launches == budget == 4, all
    // ran, the last exit is non-zero (still crashing), and the manager reports the
    // give-up code — never exceeding the budget toward the leak bound.
    let pass = outcome.launches == 4
        && outcome.runs == 4
        && outcome.last_exit != 0
        && outcome.manager_exit == Some(CM_GIVEUP_CODE);
    report(&verdict(
        DemoId::ComponentManagerBudget,
        pass,
        [
            outcome.launches,
            outcome.runs,
            outcome.last_exit as u64,
            CM_GIVEUP_CODE as u64,
            0,
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "cm-budget: FAIL — launches={} runs={} last_exit={} manager_exit={:?}",
            outcome.launches,
            outcome.runs,
            outcome.last_exit,
            outcome.manager_exit
        );
    }
}

/// The M20 reclaim proof: a manager restarts a service far past the old
/// ~15-launch leak bound. Countdown 40, budget 64 → the service exits
/// 40,39,…,1,0 over 41 launches, then comes up clean. This is *impossible*
/// without reclaim-on-exit: each launch consumes a process slot and a scheduler
/// thread slot (both `MAX = 16`), so a 17th launch would fail `OutOfMemory` and
/// the manager would never reach a clean exit. Reaching `runs == 41` with the
/// manager exiting clean proves the process/thread slots (and their kernel
/// stacks) are recycled; the bounded `handed_out_delta` (independent of the 41
/// launches) and zero reclaim-overflows prove the frames are too.
const CM_STRESS_LAUNCHES: u64 = 41;
/// Frame draw ceiling for the stress run — the manager's fixed cost plus one
/// live child's peak, generously bounded. Far below `41 × per-child frames`, so
/// clearing it proves the draw is not proportional to the launch count.
const CM_STRESS_FRAME_BOUND: u64 = 128;
fn cm_reclaim_stress(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let outcome = match cm_run(
        kernel_vm,
        frames,
        (CM_STRESS_LAUNCHES - 1) as u32,
        64,
        alloc_asid().0,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
    ) {
        Ok(outcome) => outcome,
        Err(msg) => return kprintln!("cm-reclaim: FAIL — {msg}"),
    };
    let pass = outcome.launches == CM_STRESS_LAUNCHES
        && outcome.runs == CM_STRESS_LAUNCHES
        && outcome.last_exit == 0
        && outcome.manager_exit == Some(0)
        && outcome.reclaim_overflows == 0
        && outcome.handed_out_delta < CM_STRESS_FRAME_BOUND;
    report(&verdict(
        DemoId::ComponentManagerReclaim,
        pass,
        [
            outcome.launches,
            outcome.runs,
            outcome.handed_out_delta,
            outcome.launches,
            0,
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "cm-reclaim: FAIL — launches={} runs={} last_exit={} manager_exit={:?} handed_out_delta={} overflows={}",
            outcome.launches,
            outcome.runs,
            outcome.last_exit,
            outcome.manager_exit,
            outcome.handed_out_delta,
            outcome.reclaim_overflows
        );
    }
}

// --- M15: user-space channel IPC (ring-3 client calls a ring-3 server) --------

/// Observations, published by the channel handlers and checked on boot.
/// Debug-write count (want 2: one per process).
static CHAN_PRINTS: AtomicU64 = AtomicU64::new(0);
/// Set once the server received the client's "ping".
static CHAN_SERVER_SAW_PING: AtomicBool = AtomicBool::new(false);
/// Set once the client received the server's "pong".
static CHAN_CLIENT_SAW_PONG: AtomicBool = AtomicBool::new(false);
/// Set once the server installed the handle the client transferred.
static CHAN_HANDLE_TRANSFERRED: AtomicBool = AtomicBool::new(false);
/// Scheduler switches consumed by the client's `ChannelCall` round trip (want 2).
static CHAN_ROUNDTRIP_SWITCHES: AtomicU64 = AtomicU64::new(u64::MAX);
/// The client's ring-3 exit code (`i32::MIN` = not observed).
static CHAN_CLIENT_EXIT: AtomicI32 = AtomicI32::new(i32::MIN);
/// The client thread's scheduler index, so the exit handler can tell it from the
/// server (`u64::MAX` = unset).
static CHAN_CLIENT_TIDX: AtomicU64 = AtomicU64::new(u64::MAX);

// The ring-3 SERVER. Announces itself, then (Steps 3+) receives a request on its
// endpoint (handle raw 0) and replies. SYSCALL ABI: rax = number, args in
// rdi/rsi. Message lengths are hardcoded immediates kept in sync with the
// `.ascii` below (a symbol used as an immediate assembles as a memory load in
// Intel-syntax global_asm!; only `.quad`/`.long` label differences are real
// constants — the M13 gotcha).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global chan_server_program_start
.global chan_server_program_end
chan_server_program_start:
    lea rdi, [rip + chan_server_msg]   # arg0 = message pointer
    mov esi, 18                        # arg1 = length (== chan_server_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    # Receive the client's request on the endpoint (handle raw 0). Blocks in the
    # kernel until the client's Call hands off here.
    xor edi, edi                       # arg0 unused by Recv
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # SyscallNumber::ChannelRecv
    syscall
    # Reply "pong" and hand off back to the caller (this thread is then Blocked).
    lea rdi, [rip + chan_reply_args]   # arg0 = ChannelMsgArgs (the reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # SyscallNumber::ChannelReply
    syscall
1:
    jmp 1b
chan_server_msg:
    .ascii "chan: server ready"
.balign 8
chan_reply_args:
    .long 88                           # size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0xabcd                       # interface_id
    .quad 0                            # txn_id (kernel stamps)
    .long 1                            # method_id
    .long 0                            # msg_flags
    # inline_ptr: runtime VA of the body. The blob loads at USER_CODE_VA
    # (0x400000), so start-relative offset + that base is the live VA (a label
    # *difference* is a real assemble-time constant; an absolute label would be a
    # kernel VA once relocated — the M13 gotcha).
    .quad 0x400000 + chan_pong_body - chan_server_program_start
    .quad 4                            # inline_len
    .quad 0                            # handles_ptr
    .quad 0                            # handle_count
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
chan_pong_body:
    .ascii "pong"
chan_server_program_end:
.text
"#
);

// The ring-3 CLIENT. Announces itself, then (Step 4+) calls the server and reads
// the reply. Same ABI/length rules as the server blob.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global chan_client_program_start
.global chan_client_program_end
chan_client_program_start:
    lea rdi, [rip + chan_client_msg]   # arg0 = message pointer
    mov esi, 18                        # arg1 = length (== chan_client_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    # Call the server with "ping" on the endpoint (handle raw 0); blocks for the
    # reply, which the kernel verifies handler-side.
    lea rdi, [rip + chan_call_args]    # arg0 = ChannelMsgArgs (the request)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 14                        # SyscallNumber::ChannelCall
    syscall
    xor edi, edi                       # exit code 0
    mov eax, 5                         # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
chan_client_msg:
    .ascii "chan: client ready"
.balign 8
chan_call_args:
    .long 88                           # size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0xabcd                       # interface_id
    .quad 0                            # txn_id (kernel stamps)
    .long 1                            # method_id
    .long 0                            # msg_flags
    .quad 0x400000 + chan_ping_body - chan_client_program_start   # inline_ptr (live VA)
    .quad 4                            # inline_len
    .quad 0x400000 + chan_client_handles - chan_client_program_start  # handles_ptr (live VA)
    .quad 1                            # handle_count (transfer one capability)
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
chan_ping_body:
    .ascii "ping"
.balign 8
chan_client_handles:
    # One HandleTransfer descriptor (channel_msg.isl): handle, mode, rights.
    # Mode 0 is TransferMode::TRANSFER — the sender's copy goes away.
    # This demo is about the transfer itself, so the capability travels with the
    # rights it was granted (READ|TRANSFER) rather than a narrowed set.
    .long 1                            # the transfer object handle (slot 1, raw 1)
    .long 0                            # reserved (must be zero)
    .quad 0x81                         # rights: READ|TRANSFER
chan_client_program_end:
.text
"#
);

// SAFETY: names the two channel-demo blob bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static chan_server_program_start: u8;
    static chan_server_program_end: u8;
    static chan_client_program_start: u8;
    static chan_client_program_end: u8;
}

/// The scheduler index of the thread currently running under the channel demo —
/// how a channel syscall resolves its caller. `None` before the demo's executive
/// starts.
fn chan_current_index() -> Option<usize> {
    // SAFETY: single-core; EXEC is set before any channel ring-3 thread runs and
    // touched only on this boot CPU.
    unsafe { (*&raw mut EXEC).as_mut() }.and_then(|exec| exec.scheduler().current())
}

/// `sys_process_exit` on the executive substrate. Marks the exiting process
/// `Exited` and records the client's code, then either:
///   - if a parent is parked in `ProcessStart` awaiting this child (the
///     loader / component-manager synchronous handoff), hands control back to
///     the parent with the child's exit code (the child is left `Blocked` and
///     never resumes); or
///   - otherwise parks the exiting thread and switches to the next ready thread
///     — or to boot when none remain (ending the run). The channel server is
///     normally left `Blocked` after its reply and does not reach here.
fn chan_process_exit(caller_idx: usize, code: i32) -> i64 {
    // SAFETY: single-core; statics set before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if let Some(process) = processes.process_of_thread(caller_idx) {
        process.exit(code);
    }
    if CHAN_CLIENT_TIDX.load(Ordering::Relaxed) == caller_idx as u64 {
        CHAN_CLIENT_EXIT.store(code, Ordering::Relaxed);
    }
    // SAFETY: single-core; PARENT_WAITER is only set by `ProcessStart` on this CPU.
    let waiter = unsafe { (*&raw mut PARENT_WAITER).take() };
    // Any `PROCESSES` borrow above has ended before we touch the scheduler.
    let scheduler = exec_ref().scheduler();
    match waiter {
        Some(parent) => {
            LOADER_CHILD_EXIT.store(code, Ordering::Relaxed);
            LOADER_CHILD_RAN.store(true, Ordering::Relaxed);
            // M19 supervision counters: a child that hands back to a parent
            // provably ran (unlike a launch that failed to spawn).
            CM_CHILD_RUNS.fetch_add(1, Ordering::Relaxed);
            CM_EXIT_SUM.fetch_add(code as i64, Ordering::Relaxed);
            scheduler.handoff_to(parent);
        }
        None => scheduler.block_current(),
    }
    0
}

/// The legacy PIC as the kernel core's interrupt-revocation seam
/// (`kcore::devmgr::InterruptRouter`).
///
/// Zero-sized: the controller is a pair of fixed I/O ports. It exists as a
/// type solely because the kernel core must not name a PIC — and this port's
/// PIC is itself tracked debt (build/README.md, D87), which the seam makes
/// replaceable without kcore noticing.
struct PicRouter;

impl kcore::devmgr::InterruptRouter for PicRouter {
    fn mask(&mut self, intid: u32) {
        // A PIC line is 0..=15; anything wider names no line this controller
        // has, and masking a truncated value would mask a *different* device's
        // interrupt. Refusing to act on a value that cannot be a line is the
        // only correct answer, and it cannot happen — the graph's INTIDs on
        // this port come from `register_com2_device`.
        if let Ok(line) = u8::try_from(intid) {
            tessera_karch_x86_64::mask_irq(line);
        }
    }
}

// --- Driver-host restart on crash ----------------------------------------
//
// A ring-3 driver host (the M16 service driver) crashes via a REAL CPU fault
// (#PF), the kernel contains it, and a kernel-driven supervisor reclaims the
// crashed host (M20 primitives), revokes + rebinds its device, and restarts it
// per a (countdown, budget) policy until it comes up clean and services the
// client. Closes the Stage-0 exit gate "kill-a-driver-host-under-load recovers"
// (docs/roadmap/01) and the Crash-Recovery ladder (docs/drivers/01, L221-233:
// revoke mappings/interrupts -> mark degraded -> restart host -> restore
// binding). All of it lives here in main.rs, reusing M16's driver/device path
// and M20's reclaim; no kcore change. See build/README.md D51.
//
// Normative: docs/architecture/01-system-architecture.md ("Failure Model":
// "Driver host restart after crash", "Device reset and rebind"),
// docs/drivers/01-driver-framework.md ("Crash Recovery").

/// The driver host + its client: ASIDs and kstack windows (a distinct VMAP
/// window each, clear of every prior demo's — 0x50-0x5c and 0x60 are taken by
/// M16/M17/M18/perf, so use the free 0x5e/0x62 windows). The host window is
/// reused every restart: M20 `reclaim_range` frees it on each crash before the
/// next spawn, and supervision is synchronous (one host alive at a time).
/// Hard cap on host launches (a persistently-crashing host is given up on),
/// well under the object/handle-table bounds; and the distinct give-up code the
/// supervisor reports (176 is the component manager's `CM_GIVEUP_CODE`).
const DRIVER_RESTART_BUDGET: u32 = 8;
const DRIVER_RESTART_GIVEUP_CODE: i32 = 177;
/// The budget the give-up self-test runs against — deliberately smaller than
/// its crash countdown, so the budget is what stops the loop. Named because
/// the ladder's event check derives its expected crash count from it rather
/// than repeating the number.
const DRIVER_RESTART_BUDGET_SELFTEST_BUDGET: u32 = 4;

// The restartable-driver blob: the M16 service driver, gated by a crash countdown passed
// in the ring-3 entry `arg` (rdi). While the countdown is non-zero the host
// null-derefs (a real #PF that routes to `driver_fault_handler`); at zero it runs
// the real device-service path (the code page is rx-only, so `arg`/rdi is the
// only channel for the supervisor's countdown).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global restartable_driver_program_start
.global restartable_driver_program_end
restartable_driver_program_start:
    test rdi, rdi                      # arg = crash countdown (entry arg in rdi)
    jz 2f                              # 0 -> serve path
    xor rcx, rcx                       # crash: deliberate null read -> #PF (RPL 3)
    mov rax, [rcx]                     #   -> driver_fault_handler
2:
    mov eax, 16                        # PortCreate -> port handle (raw 2)
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    xor edi, edi                       # recv: arg0 unused
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # ChannelRecv (blocks for the client)
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> the looped byte
    syscall
    lea rdi, [rip + restartable_driver_reply_args]    # arg0 = ChannelMsgArgs (reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # ChannelReply (-> hands back to the client)
    syscall
1:
    jmp 1b
.balign 8
restartable_driver_reply_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + restartable_driver_pong_body - restartable_driver_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0
    .quad 0
restartable_driver_pong_body:
    .ascii "pong"
restartable_driver_program_end:
.text
"#
);

// SAFETY: names the restartable-driver blob bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static restartable_driver_program_start: u8;
    static restartable_driver_program_end: u8;
}

/// The registered ring-3 fault handler for the driver-host supervisor. Like
/// `user_fault_handler`, but on the EXEC substrate (`EXEC`/`PROCESSES`, not the
/// single-process `USER_SCHEDULER`/`USER_PROCESS`): it contains a driver-host
/// crash (a real #PF), records it for the supervisor, marks the faulting process
/// `Exited`, terminates its thread, and `yield_to_boot`s so the kernel supervisor
/// loop (around `exec_ref().run()`) resumes to reclaim + restart it (D23 default
/// policy: contain and terminate; the kernel survives).
fn driver_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    USER_FAULT_ADDR.store(tessera_karch_x86_64::read_cr2(), Ordering::Relaxed);
    DRIVER_HOST_FAULTED.store(true, Ordering::Relaxed);
    DRIVER_HOST_FAULTS_SEEN.fetch_add(1, Ordering::Relaxed);
    // The dying host's cause, saved for the supervisor. Everything the
    // supervisor then does — contain, reclaim, rebind, restart — is *caused by*
    // this crash, so the ladder's records belong on this thread's trace rather
    // than on a fresh one. It has to be captured here because `yield_to_boot`
    // is about to leave this thread's context behind.
    DRIVER_HOST_CRASH_CORRELATION.store(kcore::trace::current().correlation, Ordering::Relaxed);
    report_contained_fault(frame.vector, tessera_karch_x86_64::read_cr2());
    let idx = chan_current_index();
    if let Some(idx) = idx {
        // SAFETY: single-core; PROCESSES is populated before the ring-3 host runs
        // and touched only on this boot CPU.
        let processes = unsafe { &mut *&raw mut PROCESSES };
        if let Some(process) = processes.process_of_thread(idx) {
            process.exit(-1);
        }
    }
    // Terminate the faulting thread (skipped by `pop_ready`) and yield to boot;
    // the supervisor reaps + reclaims it after `run()` returns. Any `PROCESSES`
    // borrow above has ended before we touch the scheduler.
    if let Some(idx) = idx {
        exec_ref().scheduler().terminate(idx);
    }
    exec_ref().scheduler().yield_to_boot();
    // yield_to_boot switched to the boot context; this thread never resumes.
    loop {
        core::hint::spin_loop();
    }
}

/// Reclaims a crashed (or exited) driver host on the EXEC substrate — the M20
/// reclaim block adapted to `EXEC`/`PROCESSES`: frees the host's scheduler slot +
/// kernel stack (`reap` + `reclaim_range`), its process slot + address space
/// (`remove` + `teardown`), and releases its process object. It MUST NOT close
/// the host's device handle: dropping the host `Process` forgets that handle
/// *without* releasing it (there is no `Process` Drop impl), so the shared Device
/// capability's reference is conserved (rc stays 1) for the rebind into the next
/// host. The caller must re-activate `kernel_vm` first (the crashed host's CR3 is
/// active when the fault handler yields), so the kstack window is edited through
/// the direct map, not the active CR3 (single-core; invlpg suffices — SMP would
/// need a shootdown, deferred D50/D51).
fn reclaim_crashed_driver_host(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    host_tidx: usize,
    proc_obj: ObjectId,
) {
    if let Some(host_thread) = exec_ref().scheduler().reap(host_tidx) {
        let _ = kernel_vm.reclaim_range(
            host_thread.kernel_stack_base(),
            host_thread.stack_bytes(),
            frames,
        );
    }
    // SAFETY: single-core; PROCESSES is populated before the host ran and touched
    // only on this boot CPU. The borrow ends before the OBJECTS access below.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if let Some(pidx) = processes.index_of_id(proc_obj) {
        if let Some(mut host) = processes.remove(pidx) {
            host.space_mut().teardown(frames);
        }
    }
    // SAFETY: single-core; the only live reference to OBJECTS on this boot CPU.
    // Release the process object (bounds the object table across restarts); the
    // device object is deliberately left untouched (conserved for the rebind).
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let _ = objects.release(proc_obj);
}

/// Isolated driver-crash self-test: one driver host, built with a non-zero crash countdown,
/// null-derefs in ring 3; `driver_fault_handler` contains it and the supervisor
/// reclaims it. Proves the fault path + EXEC-substrate reclaim + device-capability
/// conservation, before the full restart loop.
fn driver_crash_reclaim_selftest(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::com2;
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(driver_fault_handler);
    DRIVER_HOST_FAULTED.store(false, Ordering::Relaxed);
    DRIVER_HOST_FAULTS_SEEN.store(0, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(u64::MAX, Ordering::Relaxed);
    USER_FAULT_ADDR.store(u64::MAX, Ordering::Relaxed);
    com2::init_loopback();
    // SAFETY: single-core boot; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("driver-crash: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);

    let handed_before = frames.handed_out();
    let dblob = &raw const restartable_driver_program_start as *const u8;
    let dlen = (&raw const restartable_driver_program_end as usize)
        - (&raw const restartable_driver_program_start as usize);
    let (mut host, tidx) = chan_build_process(
        kernel_vm,
        frames,
        driver_host_asid().0,
        dblob,
        dlen,
        driver_host_kstack_window(),
        ThreadId(0x_d217_e021),
        1, // arg = crash countdown 1 -> null-derefs immediately
    );
    let proc_obj = host.id();
    if host
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("driver-crash: FAIL — install device capability");
    }
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { host.space().activate(Cpu::cpu_id()) };
    host.set_running();
    if processes_insert(host).is_err() {
        return kprintln!("driver-crash: FAIL — insert host process");
    }
    exec_ref().run(); // host null-derefs -> driver_fault_handler -> yield_to_boot
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };
    reclaim_crashed_driver_host(kernel_vm, frames, tidx, proc_obj);

    let faulted = DRIVER_HOST_FAULTED.load(Ordering::Relaxed);
    let vector = USER_FAULT_VECTOR.load(Ordering::Relaxed);
    let addr = USER_FAULT_ADDR.load(Ordering::Relaxed);
    let live = objects.is_live(dev_obj);
    let rc = objects.refcount(dev_obj);
    let net = frames.handed_out() - handed_before;
    let pass = faulted && vector == 14 && addr == 0 && live && rc == Some(1);
    report(&verdict(
        DemoId::DriverCrash,
        pass,
        [net, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "driver-crash: FAIL — faulted={faulted} vector={vector} addr={addr:#x} live={live} rc={rc:?} net={net}"
        );
    }
}

/// What one supervised driver-host run produced: launches + real crashes observed, whether
/// it reached a clean serve or gave up at the budget, the serve results (the M16
/// client round trip), the device capability's post-run liveness/refcount (the
/// conservation proof), and the run's bounded frame draw.
struct DriverRestartOutcome {
    launches: u64,
    faults: u64,
    served: bool,
    gave_up: bool,
    saw_ping: bool,
    saw_pong: bool,
    byte: u64,
    woken: bool,
    client_exit: i32,
    dev_live: bool,
    dev_rc: Option<usize>,
    handed_out_delta: u64,
    reclaim_overflows: u64,
}

/// Builds a fresh driver host from the restartable-driver blob with crash countdown `arg` (in
/// rdi) and **rebinds** the persistent device capability `dev_obj` into it (the
/// Crash-Recovery ladder's "restore binding"). `ep_obj` is the host's channel
/// endpoint on a clean serve attempt (installed at raw 0, device at raw 1);
/// `None` on a crash attempt (device at raw 0 — the host crashes before touching
/// any handle). Returns the host, its scheduler thread index, and its object id.
fn build_driver_host(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    arg: usize,
    dev_obj: ObjectId,
    ep_obj: Option<ObjectId>,
) -> Result<(Process<KernelAddressSpace>, usize, ObjectId), &'static str> {
    let dblob = &raw const restartable_driver_program_start as *const u8;
    let dlen = (&raw const restartable_driver_program_end as usize)
        - (&raw const restartable_driver_program_start as usize);
    let (mut host, tidx) = chan_build_process(
        kernel_vm,
        frames,
        driver_host_asid().0,
        dblob,
        dlen,
        driver_host_kstack_window(),
        ThreadId(0x_d217_e021),
        arg,
    );
    let proc_obj = host.id();
    if let Some(ep) = ep_obj {
        host.handles_mut()
            .install(ep, Rights::READ | Rights::WRITE)
            .map_err(|_| "install endpoint")?;
    }
    // The rebind: re-install the persistent device capability (refcount-neutral,
    // so the shared Device object stays rc=1 across every restart).
    host.handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .map_err(|_| "install device")?;
    Ok((host, tidx, proc_obj))
}

/// The driver-host supervise-restart loop. One `EXEC`/`PROCESSES`/`dev_obj` for the whole
/// run; the driver host is launched with a crash countdown, and each crash is
/// contained (`driver_fault_handler`), reclaimed (`reclaim_crashed_driver_host`), its device
/// binding revoked (implicit on teardown; `mask_irq`), then rebound into a fresh
/// host — until the countdown reaches 0 and the host comes up clean and services a
/// client, or the restart `budget` is spent (give up). `dev_obj` is created once
/// so it outlives every host; its reference is conserved (rc=1) throughout.
fn run_supervised_driver_host(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    countdown: u32,
    budget: u32,
) -> Result<DriverRestartOutcome, &'static str> {
    use tessera_karch_x86_64::{USER_IF_ON_ENTRY, com2, mask_irq, set_device_irq_hook, unmask_irq};
    // SAFETY: one-shot registration before this run's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(driver_fault_handler);
    set_device_irq_hook(com2_driver_bridge_hook);
    DRIVER_HOST_FAULTED.store(false, Ordering::Relaxed);
    DRIVER_HOST_FAULTS_SEEN.store(0, Ordering::Relaxed);
    DRIVER_HOST_LAUNCHES.store(0, Ordering::Relaxed);
    CHAN_SERVER_SAW_PING.store(false, Ordering::Relaxed);
    CHAN_CLIENT_SAW_PONG.store(false, Ordering::Relaxed);
    CHAN_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    CHAN_CLIENT_TIDX.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0);
    // SAFETY: single-core boot; fresh process table + executive for this run.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    // The device object + its DeviceTable node are created ONCE, before the loop,
    // so they outlive every (re)started host — the persistent binding target.
    let dev_obj = objects
        .create(ObjectType::Device)
        .map_err(|_| "device object")?;
    register_com2_device(dev_obj);

    let handed_before = frames.handed_out();
    let overflows_before = frames.reclaim_overflows();
    let mut cd = countdown;
    // The ladder's policy and its three records live in kcore
    // (`supervise::RestartSupervisor`), shared with every other port that runs
    // a supervisor. What stays here is the architecture work it cannot do:
    // building a host, containing its fault, and reclaiming the corpse.
    let mut sup = kcore::supervise::RestartSupervisor::new(budget);
    let mut served = false;

    loop {
        if cd == 0 {
            // CLEAN attempt: the host comes up and services a client (M16 wiring).
            served = true;
            let (driver_ep, client_ep) =
                exec_ref().channel_create().map_err(|_| "channel_create")?;
            let driver_ep_obj = objects
                .create(ObjectType::Channel)
                .map_err(|_| "driver ep object")?;
            let client_ep_obj = objects
                .create(ObjectType::Channel)
                .map_err(|_| "client ep object")?;
            exec_ref().bind_endpoint_object(driver_ep, driver_ep_obj);
            exec_ref().bind_endpoint_object(client_ep, client_ep_obj);
            let (mut host, _tidx, _proc_obj) =
                build_driver_host(kernel_vm, frames, 0, dev_obj, Some(driver_ep_obj))?;
            DRIVER_HOST_LAUNCHES.fetch_add(1, Ordering::Relaxed);
            sup.launched();
            let cblob = &raw const com2_driver_client_program_start as *const u8;
            let clen = (&raw const com2_driver_client_program_end as usize)
                - (&raw const com2_driver_client_program_start as usize);
            let (mut client, client_tidx) = chan_build_process(
                kernel_vm,
                frames,
                alloc_asid().0,
                cblob,
                clen,
                alloc_kstack(USER_KSTACK_PAGES).as_u64(),
                ThreadId(0x_c113_e021),
                0,
            );
            client
                .handles_mut()
                .install(client_ep_obj, Rights::READ | Rights::WRITE)
                .map_err(|_| "install client endpoint")?;
            CHAN_CLIENT_TIDX.store(client_tidx as u64, Ordering::Relaxed);
            // SAFETY: the user space shares the kernel higher-half; the direct map
            // and boot stack stay mapped after the CR3 load.
            unsafe { host.space().activate(Cpu::cpu_id()) };
            host.set_running();
            client.set_running();
            if processes_insert(host).is_err() {
                return Err("insert host");
            }
            if processes_insert(client).is_err() {
                return Err("insert client");
            }
            unmask_irq(COM2_IRQ_LINE);
            USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
            exec_ref().run();
            USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
            mask_irq(COM2_IRQ_LINE);
            // SAFETY: the kernel space maps this code and stack; active at boot.
            unsafe { kernel_vm.activate(Cpu::cpu_id()) };
            break;
        }
        if !sup.may_restart() {
            // Ladder's end: a host that keeps crashing is not restarted for
            // ever. The give-up is the loudest thing the supervisor does and
            // was previously only a console line.
            sup.give_up(DRIVER_RESTART_GIVEUP_CODE as u64);
            break;
        }
        // CRASH attempt: host only, crash countdown `cd` (non-zero → null-deref).
        DRIVER_HOST_FAULTED.store(false, Ordering::Relaxed);
        let (mut host, tidx, proc_obj) =
            build_driver_host(kernel_vm, frames, cd as usize, dev_obj, None)?;
        DRIVER_HOST_LAUNCHES.fetch_add(1, Ordering::Relaxed);
        sup.launched();
        // SAFETY: the host space maps its code/stack; the direct map + boot stack
        // stay mapped after the CR3 load.
        unsafe { host.space().activate(Cpu::cpu_id()) };
        host.set_running();
        if processes_insert(host).is_err() {
            return Err("insert crash host");
        }
        exec_ref().run(); // host null-derefs → driver_fault_handler → yield_to_boot
        // SAFETY: the kernel space maps this code and stack; active at boot. Must
        // precede reclaim (the crashed host's CR3 was active when it yielded).
        unsafe { kernel_vm.activate(Cpu::cpu_id()) };
        // Ladder step 1, recorded: the host faulted and the kernel did not.
        // The vector and address come from the contained-fault handler, so the
        // record says what killed the host rather than merely that one died.
        //
        // Adopt the dead host's cause first. `run()` returned through
        // `yield_to_boot`, which left the ambient context on boot's own id, so
        // without this the ladder would root a fresh trace and nothing would
        // join a restart to the crash that provoked it — the exact failure the
        // envelope assertion in `report_driver_host_ladder` catches.
        kcore::trace::set_current_correlation(
            DRIVER_HOST_CRASH_CORRELATION.load(Ordering::Relaxed),
        );
        sup.crashed(
            USER_FAULT_VECTOR.load(Ordering::Relaxed),
            USER_FAULT_ADDR.load(Ordering::Relaxed),
        );
        mask_irq(COM2_IRQ_LINE); // ladder steps 1-2: revoke interrupts, mark degraded
        // The free-list depth, not `handed_out`: the latter is cumulative
        // ("frames handed out so far") and never decreases, so a delta across a
        // reclaim is always zero. Reclaim pushes the corpse's frames onto the
        // free list, and measuring either side of this one call is what
        // attributes them to this launch rather than to the boot.
        let free_before_reclaim = frames.free_list_depth();
        reclaim_crashed_driver_host(kernel_vm, frames, tidx, proc_obj);
        cd -= 1;
        // Ladder steps 6-7: the corpse is reclaimed and the loop will rebind
        // the conserved device into a fresh host. Frames reclaimed rides along
        // because a restart that leaks is still a restart — the leak has to be
        // visible per launch, not only in a final total.
        sup.restarted(frames.free_list_depth().saturating_sub(free_before_reclaim) as u64);
    }

    Ok(DriverRestartOutcome {
        launches: DRIVER_HOST_LAUNCHES.load(Ordering::Relaxed),
        faults: DRIVER_HOST_FAULTS_SEEN.load(Ordering::Relaxed),
        served,
        gave_up: sup.outcome().gave_up,
        saw_ping: CHAN_SERVER_SAW_PING.load(Ordering::Relaxed),
        saw_pong: CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed),
        byte: COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed),
        woken: COM2_DRIVER_WOKEN.load(Ordering::Relaxed),
        client_exit: CHAN_CLIENT_EXIT.load(Ordering::Relaxed),
        dev_live: objects.is_live(dev_obj),
        dev_rc: objects.refcount(dev_obj),
        handed_out_delta: frames.handed_out() - handed_before,
        reclaim_overflows: frames.reclaim_overflows() - overflows_before,
    })
}

/// The driver-host-restart gate: a driver host **crashes via a real #PF** a fixed number of times,
/// each crash contained + reclaimed + its device rebound, then it comes up clean
/// and services a client. Countdown 2, budget 8 → 2 crashes then a clean serve.
/// Closes the Stage-0 "kill-a-driver-host-under-load recovers" gate (docs/roadmap/01).
fn driver_restart_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let outcome = match run_supervised_driver_host(kernel_vm, frames, 2, DRIVER_RESTART_BUDGET) {
        Ok(o) => o,
        Err(m) => return kprintln!("driver-restart: FAIL — {m}"),
    };
    // 2 real crashes (each reclaimed + rebound), then a 3rd launch comes up clean
    // and completes the M16 client round trip; the device cap is conserved (rc=1)
    // across the whole crash→reclaim→rebind→restart cycle, with no lost frames.
    let pass = outcome.faults == 2
        && outcome.launches == 3
        && outcome.served
        && outcome.saw_ping
        && outcome.saw_pong
        && outcome.byte == 0x5a
        && outcome.woken
        && outcome.client_exit == 0
        && outcome.dev_live
        && outcome.dev_rc == Some(1)
        && outcome.reclaim_overflows == 0;
    report(&verdict(
        DemoId::DriverRestart,
        pass,
        [outcome.faults, outcome.handed_out_delta, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "driver-restart: FAIL — faults={} launches={} served={} ping={} pong={} byte={:#x} woken={} client_exit={} rc={:?} overflows={}",
            outcome.faults,
            outcome.launches,
            outcome.served,
            outcome.saw_ping,
            outcome.saw_pong,
            outcome.byte,
            outcome.woken,
            outcome.client_exit,
            outcome.dev_rc,
            outcome.reclaim_overflows
        );
    }
}

/// Negative self-test: a driver host that keeps crashing is restarted only up
/// to the budget, then the supervisor gives up (it never runs away). Countdown 10
/// (never reaches 0) with budget 4 → exactly 4 crash launches then give-up; the
/// device binding is revoked and its reference is not leaked (rc stays 1).
fn driver_restart_budget_selftest(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    let outcome = match run_supervised_driver_host(
        kernel_vm,
        frames,
        10,
        DRIVER_RESTART_BUDGET_SELFTEST_BUDGET,
    ) {
        Ok(o) => o,
        Err(m) => return kprintln!("driver-restart-budget: FAIL — {m}"),
    };
    let pass = outcome.gave_up
        && !outcome.served
        && outcome.launches == u64::from(DRIVER_RESTART_BUDGET_SELFTEST_BUDGET)
        && outcome.faults == u64::from(DRIVER_RESTART_BUDGET_SELFTEST_BUDGET)
        && outcome.dev_live
        && outcome.dev_rc == Some(1)
        && outcome.reclaim_overflows == 0;
    report(&verdict(
        DemoId::DriverRestartBudget,
        pass,
        [
            outcome.launches,
            DRIVER_RESTART_GIVEUP_CODE as u64,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "driver-restart-budget: FAIL — gave_up={} served={} launches={} faults={} rc={:?} overflows={}",
            outcome.gave_up,
            outcome.served,
            outcome.launches,
            outcome.faults,
            outcome.dev_rc,
            outcome.reclaim_overflows
        );
    }
}

/// Resolves the endpoint a channel syscall targets: looks the endpoint handle up
/// in the caller's table, checks it carries `need`, and maps its object id back
/// to the live `EndpointId` (the handle→endpoint bridge). Returns a `Copy`
/// `EndpointId` and drops every `PROCESSES` borrow, so the caller may hand off
/// without a borrow spanning the switch.
fn chan_resolve_endpoint(
    caller_idx: usize,
    ep_handle: u64,
    need: Rights,
) -> Result<EndpointId, KError> {
    // SAFETY: single-core; PROCESSES is populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    kcore::dispatch::resolve_endpoint(exec_ref(), processes, caller_idx, ep_handle, need)
}

/// `ChannelCall` (client side): build the request from the caller's
/// `ChannelMsgArgs` (inline bytes + any transferred handles), then hand off
/// synchronously to the server and block for the reply. Every `PROCESSES`/handle
/// borrow ends before `exec.call` switches; observations are published after.
fn chan_channel_call(caller_idx: usize, args_ptr: u64, ep_handle: u64) -> i64 {
    let ep = match chan_resolve_endpoint(caller_idx, ep_handle, Rights::WRITE) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    // Build the request under the client's active space, taking any transferred
    // handles from the client's table (which enforces `Rights::TRANSFER`).
    let request = match chan_build_message(caller_idx, args_ptr, true) {
        Ok(msg) => msg,
        Err(e) => return encode_result(Err(e)),
    };
    // Synchronous call: two switches (client→server on the request, server→client
    // on the reply). No table borrow is held across it.
    let before = exec_ref().switch_count();
    let reply = match exec_ref().call(ep, request) {
        Ok(reply) => reply,
        Err(e) => return encode_result(Err(e)),
    };
    let after = exec_ref().switch_count();
    CHAN_CLIENT_SAW_PONG.store(reply.inline() == b"pong", Ordering::Relaxed);
    CHAN_ROUNDTRIP_SWITCHES.store(after.wrapping_sub(before), Ordering::Relaxed);
    // Install any handles the reply transferred (e.g. a capability the callee
    // granted) into the caller's table — mirror of the receive-side loop. The
    // caller's space is active again (the reply handed control back here).
    // SAFETY: single-core; PROCESSES touched only on this CPU.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if let Some(caller) = processes.process_of_thread(caller_idx) {
        let mut installed = 0usize;
        for transferred in reply.handles() {
            if caller
                .handles_mut()
                .install(transferred.object, transferred.rights)
                .is_ok()
            {
                installed += 1;
            }
        }
        if installed > 0 {
            CHAN_HANDLE_TRANSFERRED.store(true, Ordering::Relaxed);
        }
    }
    encode_result(Ok(0))
}

/// `ChannelRecv` (server side): block until a message arrives on the endpoint,
/// then observe it and install any transferred handles into the server's table.
/// The endpoint is resolved (and borrows dropped) before `exec.receive`, which
/// may park the server and switch to the client.
fn chan_channel_recv(caller_idx: usize, ep_handle: u64) -> i64 {
    let ep = match chan_resolve_endpoint(caller_idx, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    let message = match exec_ref().receive(ep) {
        Ok(message) => message,
        Err(e) => return encode_result(Err(e)),
    };
    CHAN_SERVER_SAW_PING.store(message.inline() == b"ping", Ordering::Relaxed);
    // Install each transferred handle into the (re-resolved) server table — the
    // capability crosses the address-space boundary here.
    // SAFETY: single-core; the call above has returned to the server, whose
    // space is active; PROCESSES is touched only on this CPU.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    if let Some(server) = processes.process_of_thread(caller_idx) {
        let mut installed = 0usize;
        for transferred in message.handles() {
            if server
                .handles_mut()
                .install(transferred.object, transferred.rights)
                .is_ok()
            {
                installed += 1;
            }
        }
        if installed > 0 {
            CHAN_HANDLE_TRANSFERRED.store(true, Ordering::Relaxed);
        }
    }
    encode_result(Ok(0))
}

/// `ChannelReply` (server side): build the response from the server's
/// `ChannelMsgArgs` and hand off directly back to the waiting caller. The server
/// is left `Blocked` after the handoff (it does not resume), so the reply's
/// return value never reaches ring 3 — as with a kernel `reply`. The reply may
/// carry transferred handles (`transfer=true`) — the mechanism by which a
/// service (e.g. the device manager) grants a capability to its caller.
fn chan_channel_reply(caller_idx: usize, args_ptr: u64, ep_handle: u64) -> i64 {
    let ep = match chan_resolve_endpoint(caller_idx, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    let response = match chan_build_message(caller_idx, args_ptr, true) {
        Ok(msg) => msg,
        Err(e) => return encode_result(Err(e)),
    };
    match exec_ref().reply(ep, response) {
        Ok(()) => encode_result(Ok(0)),
        Err(e) => encode_result(Err(e)),
    }
}

/// Builds a `Message` from the caller's `ChannelMsgArgs`: validates and copies
/// the args struct, the inline payload, and — when `transfer` — the transfer
/// vector (each handle `take`n from the caller's table, conserving its object
/// reference). All reads run under the caller's active space; the returned
/// message owns the taken references. Every `PROCESSES` borrow ends on return.
fn chan_build_message(caller_idx: usize, args_ptr: u64, transfer: bool) -> Result<Message, KError> {
    // SAFETY: single-core; PROCESSES is populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    let (message, departed) =
        kcore::dispatch::build_channel_message(processes, caller_idx, args_ptr, transfer)?;
    // Departing capabilities also end their DMA leases. Nothing to end here:
    // this port has no IOMMU, so no device is behind one and no lease is ever
    // taken (`DEVICE_DMA_UNSCOPED` on every grant). Discarded explicitly rather
    // than ignored, so the day an IOMMU lands the omission is a compile-time
    // question and not a silent hole.
    let _ = departed;
    Ok(message)
}

/// Builds a ring-3 process from a rodata blob: its own address space, a code page
/// (copied from the blob, then re-protected rx — W^X), a user stack + kernel
/// stack, and an initial thread (added to `EXEC`, recorded in the process).
/// Returns the not-yet-inserted process and its scheduler thread index, and
/// leaves the new space active (the caller re-activates the first-run space
/// before `run`). Panics on any setup failure, like the other ring-3 demos.
#[allow(clippy::too_many_arguments)]
fn chan_build_process(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    asid: u16,
    blob_start: *const u8,
    blob_len: usize,
    kstack_base: u64,
    tid: ThreadId,
    arg: usize,
) -> (Process<KernelAddressSpace>, usize) {
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("chan demo: new_user failed: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, Asid(asid), 1u64 << Cpu::cpu_id());
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => panic!("chan demo: process object failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    if process
        .space_mut()
        .map_anonymous(
            VirtAddr::new(USER_CODE_VA),
            code_len,
            PageFlags::rw().user(),
            frames,
        )
        .is_err()
    {
        panic!("chan demo: map code failed");
    }
    let thread = match Thread::<ContextSwitch>::spawn_user(
        tid,
        VirtAddr::new(USER_CODE_VA),
        arg,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        VirtAddr::new(kstack_base),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("chan demo: spawn_user failed: {e:?}"),
    };
    let tidx = match exec_ref().add_thread(thread) {
        Ok(idx) => idx,
        Err(e) => panic!("chan demo: add_thread failed: {e:?}"),
    };
    if process.add_thread(tidx).is_err() {
        panic!("chan demo: process add_thread failed");
    }

    // Activate the new space to copy the blob into its code page, then re-protect
    // it rx (W^X). All of the blob's data (message, arg structs) is read-only in
    // this rx page — no writable user page is needed.
    // SAFETY: the user space shares the kernel higher-half; boot code, stack, and
    // the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    // SAFETY: the blob is in kernel rodata; USER_CODE_VA is a writable user page
    // in the now-active space with room for it.
    unsafe { core::ptr::copy_nonoverlapping(blob_start, USER_CODE_VA as *mut u8, blob_len) };
    if process
        .space_mut()
        .protect_range(
            VirtAddr::new(USER_CODE_VA),
            code_len,
            PageFlags::rx().user(),
        )
        .is_err()
    {
        panic!("chan demo: protect code failed");
    }
    (process, tidx)
}

/// Channel IPC: a ring-3 CLIENT process calls a ring-3 SERVER process over a
/// channel — inline bytes plus a transferred capability handle — using the
/// kernel's synchronous call/reply handoff (`Executive::call`/`reply`). Proves
/// the "services talk over channels" model across the privilege boundary and two
/// address spaces (docs/kernel/02 "Channels"; the B3 round trip). The channel is
/// created and its endpoints installed here (the bootstrap-channel model; ring-3
/// `ChannelCreate` is deferred, build/README.md D45).
fn channel_ipc_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this demo's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    CHAN_PRINTS.store(0, Ordering::Relaxed);
    CHAN_SERVER_SAW_PING.store(false, Ordering::Relaxed);
    CHAN_CLIENT_SAW_PONG.store(false, Ordering::Relaxed);
    CHAN_HANDLE_TRANSFERRED.store(false, Ordering::Relaxed);
    CHAN_ROUNDTRIP_SWITCHES.store(u64::MAX, Ordering::Relaxed);
    CHAN_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    CHAN_CLIENT_TIDX.store(u64::MAX, Ordering::Relaxed);

    // A fresh process table (so the channel threads' scheduler indices cannot
    // collide with the loader demo's stale entries) and a fresh executive
    // (scheduler + channel table) shared by both ring-3 processes.
    // SAFETY: single-core boot; the loader demo's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }

    // Create the channel and mint an `ObjectType::Channel` object per endpoint,
    // binding each to its `EndpointId` (the handle→endpoint bridge).
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let (server_ep, client_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("chan: FAIL — channel_create: {e:?}"),
    };
    let server_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("chan: FAIL — server endpoint object: {e:?}"),
    };
    let client_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("chan: FAIL — client endpoint object: {e:?}"),
    };
    exec_ref().bind_endpoint_object(server_ep, server_ep_obj);
    exec_ref().bind_endpoint_object(client_ep, client_ep_obj);

    // Build the SERVER first so it is scheduled first (runs, then parks on
    // `receive`), then the CLIENT. Each gets its endpoint handle at slot 0
    // (raw 0), which its blob names directly.
    let server_blob = &raw const chan_server_program_start as *const u8;
    let server_len = (&raw const chan_server_program_end as usize)
        - (&raw const chan_server_program_start as usize);
    let (mut server, _server_tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        server_blob,
        server_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_c8a0_5e2f),
        0,
    );
    if server
        .handles_mut()
        .install(server_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("chan: FAIL — install server endpoint handle");
    }

    let client_blob = &raw const chan_client_program_start as *const u8;
    let client_len = (&raw const chan_client_program_end as usize)
        - (&raw const chan_client_program_start as usize);
    let (mut client, client_tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        client_blob,
        client_len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_c8a0_c11e),
        0,
    );
    if client
        .handles_mut()
        .install(
            client_ep_obj,
            Rights::READ | Rights::WRITE | Rights::TRANSFER,
        )
        .is_err()
    {
        return kprintln!("chan: FAIL — install client endpoint handle");
    }
    // A capability the client transfers to the server over the channel — installed
    // at slot 1 (raw 1) with `TRANSFER`, which the client blob names. Its refcount
    // must stay 1 as it moves client→message→server (the reference is conserved).
    let xfer_obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => return kprintln!("chan: FAIL — transfer object: {e:?}"),
    };
    if client
        .handles_mut()
        .install(xfer_obj, Rights::READ | Rights::TRANSFER)
        .is_err()
    {
        return kprintln!("chan: FAIL — install transfer handle");
    }
    CHAN_CLIENT_TIDX.store(client_tidx as u64, Ordering::Relaxed);

    // Re-activate the server (first-run) space before starting the scheduler, and
    // publish both processes into the table so the handler can resolve callers.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { server.space().activate(Cpu::cpu_id()) };
    server.set_running();
    client.set_running();
    if processes_insert(server).is_err() {
        return kprintln!("chan: FAIL — insert server process");
    }
    if processes_insert(client).is_err() {
        return kprintln!("chan: FAIL — insert client process");
    }

    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let prints = CHAN_PRINTS.load(Ordering::Relaxed);
    let client_exit = CHAN_CLIENT_EXIT.load(Ordering::Relaxed);
    let saw_ping = CHAN_SERVER_SAW_PING.load(Ordering::Relaxed);
    let saw_pong = CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed);
    let switches = CHAN_ROUNDTRIP_SWITCHES.load(Ordering::Relaxed);
    let handle_moved = CHAN_HANDLE_TRANSFERRED.load(Ordering::Relaxed);
    // The transferred capability moved client→message→server: its reference is
    // conserved (refcount stays 1, now owned by the server's table).
    // SAFETY: single-core boot; the ring-3 run has returned to boot.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let xfer_conserved = objects.is_live(xfer_obj) && objects.refcount(xfer_obj) == Some(1);
    let pass = prints == 2
        && client_exit == 0
        && saw_ping
        && saw_pong
        && switches == 2
        && handle_moved
        && xfer_conserved;
    report(&verdict(DemoId::ChannelIpc, pass, [0; 8]));
    if !pass {
        kprintln!(
            "chan: FAIL prints={prints} client_exit={client_exit} saw_ping={saw_ping} saw_pong={saw_pong} switches={switches} handle_moved={handle_moved} xfer_conserved={xfer_conserved}"
        );
    }
}

// --- M16: driver-host substrate (a ring-3 driver owns a real device) ---------

/// COM2's PIC line (IRQ3) — the driver host's device interrupt.
const COM2_IRQ_LINE: u8 = 3;
/// The abstract port source id and signal the COM2 interrupt is delivered under.
const COM2_SOURCE: u64 = 0xc02;
const COM2_SIGNAL: u8 = 1;
/// Count of COM2 device interrupts observed (self-test / bridge).
static COM2_DRIVER_IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
/// The port `source` the boot context drained after the bridge delivered the
/// device interrupt (`u64::MAX` = not observed).
static COM2_DRIVER_BRIDGE_SOURCE: AtomicU64 = AtomicU64::new(u64::MAX);
/// Set once the ring-3 driver's `PortWait` returned (woken by a port signal).
static COM2_DRIVER_WOKEN: AtomicBool = AtomicBool::new(false);
/// The pending count the ring-3 driver's `PortWait` drained (`u64::MAX` = unset).
static COM2_DRIVER_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
/// The byte the ring-3 driver read from the device via `DeviceIoRead`
/// (`u64::MAX` = unset).
static COM2_DRIVER_DEVICE_BYTE: AtomicU64 = AtomicU64::new(u64::MAX);
/// Set once a `DeviceIo` on a non-`Device` handle was correctly denied.
static COM2_DRIVER_DEVICE_DENIED: AtomicBool = AtomicBool::new(false);
/// Set once a `DeviceIo` at an offset outside the granted range was denied (M17
/// — proves the resource-graph (base,len) payload is enforced, not a constant).
static DEVICE_MANAGER_OOR_DENIED: AtomicBool = AtomicBool::new(false);

/// Step 0 device-IRQ hook: just count COM2 interrupts.
fn com2_driver_count_hook(_vector: u64) {
    COM2_DRIVER_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Step 1 device-IRQ hook: bridge the COM2 interrupt to a port event, so a
/// driver waiting on that port wakes. Runs in interrupt context (IF clear); it
/// is the only `EXEC` accessor at that instant (the boot context is spinning,
/// not inside `EXEC`), so `port_signal` cannot alias a live borrow.
fn com2_driver_bridge_hook(_vector: u64) {
    COM2_DRIVER_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    // A device interrupt is a causal origin — this hook is where the outside
    // world becomes work ("whoever converts the outside world into work mints
    // the ID", docs/observability/02), so the port event and everything the woken
    // driver does on its behalf are attributed to a fresh cause rather than to
    // whichever thread the interrupt happened to land on.
    kcore::trace::set_current_correlation(kcore::trace::mint());
    exec_ref().port_signal(COM2_SOURCE, COM2_SIGNAL, 1);
}

/// M16 Step 0: prove a real device interrupt (COM2 IRQ3) can be raised and
/// dispatched to a hook. Bring up COM2 in loopback, unmask IRQ3, enable
/// interrupts, write a byte to THR (which loops to RBR and raises IRQ3), and
/// confirm the device hook ran and the byte looped.
fn com2_driver_step0_selftest() {
    use tessera_karch::InterruptControl;
    use tessera_karch_x86_64::{com2, init_pic, mask_irq, set_device_irq_hook, unmask_irq};

    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    set_device_irq_hook(com2_driver_count_hook);
    // Remap the PICs above the exception vectors (default state overlaps CPU
    // exceptions); start no timer, so IRQ0 stays quiet and only IRQ3 can fire.
    init_pic();
    com2::init_loopback();
    unmask_irq(COM2_IRQ_LINE);

    Cpu::enable();
    com2::write(0, 0x5a); // THR write -> internal loopback -> RX -> IRQ3
    for _ in 0..1_000_000u64 {
        if COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed) > 0 {
            break;
        }
        core::hint::spin_loop();
    }
    Cpu::disable();
    mask_irq(COM2_IRQ_LINE);

    let count = COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed);
    let looped = com2::read(0); // RBR: the looped-back byte
    let pass = count >= 1 && looped == 0x5a;
    report(&verdict(
        DemoId::Com2DriverStep0,
        pass,
        [count, u64::from(looped), 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "m16-step0: FAIL — count={count} rbr={looped:#04x} (COM2 loopback/IRQ3 unavailable; consider the THRE fallback)"
        );
    }
}

/// M16 Step 1: prove the IRQ→port bridge. A real COM2 interrupt, routed through
/// the device hook, calls `Executive::port_signal`, asserting a bound port that
/// the boot context then drains — the event carries the device's source. (Waking
/// a *blocked* drainer is the same `port_signal` path `ports_demo` already
/// proves cross-context; here the novelty is that the caller is an interrupt.)
fn com2_driver_step1_bridge() {
    use tessera_karch::InterruptControl;
    use tessera_karch_x86_64::{com2, mask_irq, set_device_irq_hook, unmask_irq};

    // A fresh executive owning the port the bridge signals.
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();
    let port = match exec.port_create() {
        Ok(port) => port,
        Err(e) => return kprintln!("m16-step1: FAIL — port_create: {e:?}"),
    };
    if let Err(e) = exec.port_bind(port, COM2_SOURCE, COM2_SIGNAL) {
        return kprintln!("m16-step1: FAIL — port_bind: {e:?}");
    }

    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_BRIDGE_SOURCE.store(u64::MAX, Ordering::Relaxed);
    set_device_irq_hook(com2_driver_bridge_hook);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR from Step 0 so RX re-arms
    unmask_irq(COM2_IRQ_LINE);

    Cpu::enable();
    com2::write(0, 0x5a); // real IRQ3 -> com2_driver_bridge_hook -> port_signal
    for _ in 0..1_000_000u64 {
        if COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed) > 0 {
            break;
        }
        core::hint::spin_loop();
    }
    Cpu::disable();
    mask_irq(COM2_IRQ_LINE);

    // Drain the event the interrupt delivered (asserted, so this does not block).
    if let Ok(event) = exec_ref().port_wait(port) {
        COM2_DRIVER_BRIDGE_SOURCE.store(event.source, Ordering::Relaxed);
    }
    let source = COM2_DRIVER_BRIDGE_SOURCE.load(Ordering::Relaxed);
    let pass = source == COM2_SOURCE;
    report(&verdict(
        DemoId::Com2DriverStep1,
        pass,
        [source, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step1: FAIL — drained source={source:#x} (want {COM2_SOURCE:#x})");
    }
}

// The ring-3 DRIVER host (Step 2 form): create + bind a port for the device
// source, then block in PortWait. Woken by a port signal (Step 2: from boot;
// Step 4+: from the real IRQ), it announces itself and exits. The port handle is
// raw 0 (the first handle installed in this process's fresh table).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_program_start
.global com2_driver_program_end
com2_driver_program_start:
    mov eax, 16                        # SyscallNumber::PortCreate -> handle (raw 0)
    syscall
    xor edi, edi                       # arg0 = port handle (raw 0)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # SyscallNumber::PortBind
    syscall
    xor edi, edi                       # arg0 = port handle (raw 0)
    mov eax, 18                        # SyscallNumber::PortWait (blocks)
    syscall
    lea rdi, [rip + com2_driver_msg]    # announce after waking
    mov esi, 17                        # length (== com2_driver_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    xor edi, edi                       # exit code 0
    mov eax, 5                         # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
com2_driver_msg:
    .ascii "m16 driver: woken"
com2_driver_program_end:
.text
"#
);

// SAFETY: names the driver blob's bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static com2_driver_program_start: u8;
    static com2_driver_program_end: u8;
}

/// Resolves the port a driver-host syscall targets: looks the port handle up in
/// the caller's table (needs `READ`), and maps its object id back to the live
/// `PortId` (the handle→port bridge). Returns a `Copy` `PortId` and drops the
/// `PROCESSES` borrow, so the caller may block without a borrow spanning it.
fn driver_resolve_port(caller_idx: usize, port_handle: u64) -> Result<kcore::port::PortId, KError> {
    // SAFETY: single-core; PROCESSES is populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    let process = processes
        .process_of_thread(caller_idx)
        .ok_or(KError::BadHandle)?;
    let (obj, rights) = process
        .handles()
        .lookup(Handle::from_raw(port_handle as u32))?;
    if !rights.contains(Rights::READ) {
        return Err(KError::AccessDenied);
    }
    exec_ref().port_of_object(obj).ok_or(KError::BadHandle)
}

/// `PortCreate`: create a port, mint its `ObjectType::Port` object, bind the two,
/// and install a handle for it in the caller's table. Returns the raw handle.
fn driver_port_create(caller_idx: usize) -> i64 {
    let port = match exec_ref().port_create() {
        Ok(port) => port,
        Err(e) => return encode_result(Err(e)),
    };
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let obj = match objects.create(ObjectType::Port) {
        Ok(id) => id,
        Err(e) => return encode_result(Err(e)),
    };
    exec_ref().bind_port_object(port, obj);
    // SAFETY: single-core; PROCESSES populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    match processes.process_of_thread(caller_idx) {
        Some(process) => match process
            .handles_mut()
            .install(obj, Rights::READ | Rights::WRITE)
        {
            Ok(handle) => encode_result(Ok(u64::from(handle.raw()))),
            Err(e) => encode_result(Err(e)),
        },
        None => syscall::ENOSYS,
    }
}

/// `PortBind`: bind the port named by `port_handle` to `(source, signal)`.
fn driver_port_bind(caller_idx: usize, port_handle: u64, source: u64, signal: u8) -> i64 {
    let port = match driver_resolve_port(caller_idx, port_handle) {
        Ok(port) => port,
        Err(e) => return encode_result(Err(e)),
    };
    encode_result(exec_ref().port_bind(port, source, signal).map(|()| 0))
}

/// `PortWait`: block until an event arrives on the port named by `port_handle`,
/// then return its pending count. The port is resolved (borrows dropped) before
/// `exec.port_wait`, which may park the caller and switch.
fn driver_port_wait(caller_idx: usize, port_handle: u64) -> i64 {
    let port = match driver_resolve_port(caller_idx, port_handle) {
        Ok(port) => port,
        Err(e) => return encode_result(Err(e)),
    };
    match exec_ref().port_wait(port) {
        Ok(event) => {
            COM2_DRIVER_PENDING.store(u64::from(event.pending), Ordering::Relaxed);
            COM2_DRIVER_WOKEN.store(true, Ordering::Relaxed);
            encode_result(Ok(u64::from(event.pending)))
        }
        Err(e) => encode_result(Err(e)),
    }
}

/// `DeviceIoRead`/`DeviceIoWrite`: access a device register through a device-I/O
/// capability. The handle must name an `ObjectType::Device` object and carry the
/// right for the direction (`READ`/`WRITE`); the offset must lie in the device's
/// register span. The device (COM2) is fixed by the kernel in v0. `value` is
/// `Some` for a write, `None` for a read (which returns the byte read).
fn driver_device_io(caller_idx: usize, dev_handle: u64, offset: u64, value: Option<u8>) -> i64 {
    let need = if value.is_some() {
        Rights::WRITE
    } else {
        Rights::READ
    };
    // Resolve the capability's object id, checking the direction right.
    // SAFETY: single-core; PROCESSES populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    let obj = match processes.process_of_thread(caller_idx) {
        Some(process) => match process
            .handles()
            .lookup(Handle::from_raw(dev_handle as u32))
        {
            Ok((obj, rights)) if rights.contains(need) => obj,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        },
        None => return syscall::ENOSYS,
    };
    // Possession alone is not enough: the object must be a device capability.
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    if objects.object_type(obj) != Some(ObjectType::Device) {
        COM2_DRIVER_DEVICE_DENIED.store(true, Ordering::Relaxed);
        return encode_result(Err(KError::AccessDenied));
    }
    // The authority is scoped by the object's resource-graph payload: its I/O
    // range (base, len). An unregistered Device object grants nothing; an offset
    // outside the granted range is rejected — no compile-time device constant.
    let (base, len) = match exec_ref().device_of_object(obj) {
        Some(range) => range,
        None => return encode_result(Err(KError::AccessDenied)),
    };
    if offset >= u64::from(len) {
        DEVICE_MANAGER_OOR_DENIED.store(true, Ordering::Relaxed);
        return encode_result(Err(KError::Protocol));
    }
    let port = base + offset as u16;
    match value {
        Some(byte) => {
            // SAFETY: `port` lies within the granted device's register range
            // (offset < len), so this port write is authorized by the capability.
            unsafe { tessera_karch_x86_64::device_out(port, byte) };
            encode_result(Ok(0))
        }
        None => {
            // SAFETY: `port` lies within the granted device's register range.
            let byte = unsafe { tessera_karch_x86_64::device_in(port) };
            COM2_DRIVER_DEVICE_BYTE.store(u64::from(byte), Ordering::Relaxed);
            encode_result(Ok(u64::from(byte)))
        }
    }
}

/// Registers a freshly-created `Device` object as the COM2 resource-graph node
/// (its I/O port range + IRQ line), so `DeviceIo` through the resulting
/// capability is authorized and scoped by the node's `(base, len)`. Infallible
/// in practice: each demo builds a fresh `Executive`, so the graph has room.
fn register_com2_device(dev_obj: ObjectId) {
    use tessera_karch_x86_64::com2;
    // The graph's authority over COM2: what a capability to it carries when the
    // kernel itself hands it out. A driver host is granted READ|WRITE and not
    // TRANSFER, so the device it drives is one it cannot pass on; this is the
    // root those grants are narrowed from, and what reclaim returns.
    let _ = exec_ref().device_register(
        dev_obj,
        com2::BASE,
        u16::from(com2::SPAN),
        COM2_IRQ_LINE,
        Rights::READ | Rights::WRITE | Rights::TRANSFER,
    );
}

/// M16 Step 2: prove the ring-3 port syscalls + the handle→port bridge. A ring-3
/// driver process `PortCreate`s and `PortBind`s a port, then blocks in
/// `PortWait`; the boot context signals the source (no IRQ yet) and the driver
/// wakes and drains the event. (Step 4 replaces the boot signal with the real
/// device IRQ.)
fn com2_driver_step2_ring3_ports(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    COM2_DRIVER_PENDING.store(u64::MAX, Ordering::Relaxed);

    // SAFETY: single-core boot; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }

    let blob = &raw const com2_driver_program_start as *const u8;
    let len = (&raw const com2_driver_program_end as usize)
        - (&raw const com2_driver_program_start as usize);
    let (mut driver, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_d817_e001),
        0,
    );
    driver.set_running();
    if processes_insert(driver).is_err() {
        return kprintln!("m16-step2: FAIL — insert driver process");
    }

    // First run: the driver sets up its port and parks in PortWait, returning
    // control here. Signal the source to wake it, then run again so it drains.
    exec_ref().run();
    // SAFETY: back to the kernel space for the boot-context signal below.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };
    exec_ref().port_signal(COM2_SOURCE, COM2_SIGNAL, 1);
    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let pending = COM2_DRIVER_PENDING.load(Ordering::Relaxed);
    let pass = woken && pending == 1;
    report(&verdict(
        DemoId::Com2DriverStep2,
        pass,
        [pending, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step2: FAIL — woken={woken} pending={pending}");
    }
}

// A ring-3 blob proving the capability-gated DeviceIo path: write the device's
// THR (loops to RBR), read it back through the capability (handle raw 0), then
// attempt a read through a NON-device handle (raw 1), which the kernel denies.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_devio_program_start
.global com2_driver_devio_program_end
com2_driver_devio_program_start:
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte
    mov eax, 20                        # SyscallNumber::DeviceIoWrite
    syscall
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # SyscallNumber::DeviceIoRead -> looped byte
    syscall
    mov edi, 1                         # arg0 = a NON-device handle (raw 1)
    xor esi, esi
    mov eax, 19                        # DeviceIoRead -> AccessDenied (denied capability)
    syscall
    lea rdi, [rip + com2_driver_devio_msg]
    mov esi, 19                        # length (== com2_driver_devio_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    xor edi, edi
    mov eax, 5                         # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
com2_driver_devio_msg:
    .ascii "m16 device: io done"
com2_driver_devio_program_end:
.text
"#
);

// SAFETY: names the devio blob's bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static com2_driver_devio_program_start: u8;
    static com2_driver_devio_program_end: u8;
}

/// M16 Step 3: prove the capability-gated DeviceIo syscalls. A ring-3 process
/// holding a `Device` capability (handle raw 0) writes the device's THR and
/// reads the looped-back byte through the capability, then a read through a
/// non-`Device` handle (raw 1) is denied — capability possession + type is
/// required, not mere handle validity.
fn com2_driver_step3_deviceio(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::com2;
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_DENIED.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: single-core boot; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }

    let blob = &raw const com2_driver_devio_program_start as *const u8;
    let len = (&raw const com2_driver_devio_program_end as usize)
        - (&raw const com2_driver_devio_program_start as usize);
    let (mut proc, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_d817_e003),
        0,
    );
    // Seed handle raw 0 = a Device capability, raw 1 = a non-device object.
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step3: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);
    if proc
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step3: FAIL — install device capability");
    }
    let test_obj = match objects.create(ObjectType::Test) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step3: FAIL — test object: {e:?}"),
    };
    if proc
        .handles_mut()
        .install(test_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step3: FAIL — install non-device handle");
    }
    proc.set_running();
    if processes_insert(proc).is_err() {
        return kprintln!("m16-step3: FAIL — insert process");
    }

    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let denied = COM2_DRIVER_DEVICE_DENIED.load(Ordering::Relaxed);
    let pass = byte == 0x5a && denied;
    report(&verdict(
        DemoId::Com2DriverStep3,
        pass,
        [byte, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step3: FAIL — byte={byte:#04x} denied={denied}");
    }
}

// A ring-3 driver blob proving the full device-IRQ loop in ring 3: create+bind a
// port, poke the device (DeviceIoWrite THR) which raises IRQ3 — delivered in
// ring 3 (IF set on entry) and bridged to the port — then PortWait (drains the
// asserted event) and DeviceIoRead the looped byte. Device capability is raw 0,
// so PortCreate returns handle raw 1.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_irqdrv_program_start
.global com2_driver_irqdrv_program_end
com2_driver_irqdrv_program_start:
    mov eax, 16                        # PortCreate -> port handle (raw 1)
    syscall
    mov edi, 1                         # arg0 = port handle (raw 1)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 1                         # arg0 = port handle (raw 1)
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> looped byte
    syscall
    lea rdi, [rip + com2_driver_irqdrv_msg]
    mov esi, 18                        # length (== com2_driver_irqdrv_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
com2_driver_irqdrv_msg:
    .ascii "m16 driver: irq ok"
com2_driver_irqdrv_program_end:
.text
"#
);

// SAFETY: names the IRQ-driver blob's bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static com2_driver_irqdrv_program_start: u8;
    static com2_driver_irqdrv_program_end: u8;
}

/// M16 Step 4: prove a real device interrupt is delivered *in ring 3* and drives
/// the driver. The driver thread enters ring 3 with IF set (the gated
/// `USER_IF_ON_ENTRY`); boot stays IF-clear, so `port_signal` from the IRQ hook
/// only ever runs while the driver is in ring 3 (never aliasing a kernel `EXEC`
/// borrow). The driver pokes the device, the resulting IRQ3 is bridged to its
/// port before it reaches `PortWait` (asserted-before-wait, so it never parks),
/// and it reads the looped byte.
fn com2_driver_step4_irq_driver(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::{USER_IF_ON_ENTRY, com2, mask_irq, set_device_irq_hook, unmask_irq};
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    set_device_irq_hook(com2_driver_bridge_hook);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    COM2_DRIVER_PENDING.store(u64::MAX, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: single-core boot; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }

    let blob = &raw const com2_driver_irqdrv_program_start as *const u8;
    let len = (&raw const com2_driver_irqdrv_program_end as usize)
        - (&raw const com2_driver_irqdrv_program_start as usize);
    let (mut driver, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_d817_e004),
        0,
    );
    // Seed the device capability at handle raw 0 (so PortCreate returns raw 1).
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step4: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);
    if driver
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step4: FAIL — install device capability");
    }
    driver.set_running();
    if processes_insert(driver).is_err() {
        return kprintln!("m16-step4: FAIL — insert driver process");
    }

    // Enable the device IRQ line; the driver enters ring 3 IF-set (boot stays
    // IF-clear). The IRQ fires in ring 3 and is bridged to the driver's port.
    unmask_irq(COM2_IRQ_LINE);
    USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    exec_ref().run();
    USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    mask_irq(COM2_IRQ_LINE);
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let irqs = COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed);
    let pass = byte == 0x5a && woken && irqs >= 1;
    report(&verdict(
        DemoId::Com2DriverStep4,
        pass,
        [byte, irqs, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step4: FAIL — byte={byte:#04x} woken={woken} irqs={irqs}");
    }
}

// The M16 CLIENT: a ring-3 process that asks the driver host to service an I/O by
// `ChannelCall` ("ping"), and receives the driver's reply ("pong"). Endpoint
// handle raw 0. Mirrors the M15 channel client.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_client_program_start
.global com2_driver_client_program_end
com2_driver_client_program_start:
    lea rdi, [rip + com2_driver_client_msg]
    mov esi, 16                        # length (== com2_driver_client_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    lea rdi, [rip + com2_driver_call_args]     # arg0 = ChannelMsgArgs (request)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 14                        # ChannelCall (blocks for the reply)
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
com2_driver_client_msg:
    .ascii "m16 client: call"
.balign 8
com2_driver_call_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + com2_driver_ping_body - com2_driver_client_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
com2_driver_ping_body:
    .ascii "ping"
com2_driver_client_program_end:
.text
"#
);

// The M16 SERVICE DRIVER: a single-thread ring-3 driver host. It creates+binds a
// port for its device IRQ, then serves a client request over a channel — and
// between receiving the request and replying, it drives the real device:
// ChannelRecv -> DeviceIoWrite(THR) -> [IRQ3 in ring 3 -> port] -> PortWait ->
// DeviceIoRead(RBR) -> ChannelReply. Seeded handles: endpoint raw 0, device
// capability raw 1; PortCreate returns the port at raw 2.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_svcdrv_program_start
.global com2_driver_svcdrv_program_end
com2_driver_svcdrv_program_start:
    mov eax, 16                        # PortCreate -> port handle (raw 2)
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    xor edi, edi                       # recv: arg0 unused
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # ChannelRecv (blocks for the client)
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> the looped byte
    syscall
    lea rdi, [rip + com2_driver_reply_args]    # arg0 = ChannelMsgArgs (reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # ChannelReply (-> hands back to the client)
    syscall
1:
    jmp 1b
.balign 8
com2_driver_reply_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + com2_driver_pong_body - com2_driver_svcdrv_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
com2_driver_pong_body:
    .ascii "pong"
com2_driver_svcdrv_program_end:
.text
"#
);

// SAFETY: names the Step 5 blob bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static com2_driver_client_program_start: u8;
    static com2_driver_client_program_end: u8;
    static com2_driver_svcdrv_program_start: u8;
    static com2_driver_svcdrv_program_end: u8;
}

/// M16 Step 5: the full loop. A ring-3 CLIENT `ChannelCall`s a ring-3 DRIVER
/// HOST; the driver services the request by driving a real device (poke ->
/// IRQ3-in-ring-3 -> PortWait -> read) and replies over the channel. First real
/// ring-3 device driver servicing a client's I/O request.
fn com2_driver_step5_service(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::{USER_IF_ON_ENTRY, com2, mask_irq, set_device_irq_hook, unmask_irq};
    // SAFETY: one-shot registration before this demo's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    set_device_irq_hook(com2_driver_bridge_hook);
    CHAN_SERVER_SAW_PING.store(false, Ordering::Relaxed);
    CHAN_CLIENT_SAW_PONG.store(false, Ordering::Relaxed);
    CHAN_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    CHAN_CLIENT_TIDX.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: single-core boot; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }

    // The bootstrap channel between the client and the driver.
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let (driver_ep, client_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("m16-step5: FAIL — channel_create: {e:?}"),
    };
    let driver_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step5: FAIL — driver endpoint object: {e:?}"),
    };
    let client_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step5: FAIL — client endpoint object: {e:?}"),
    };
    exec_ref().bind_endpoint_object(driver_ep, driver_ep_obj);
    exec_ref().bind_endpoint_object(client_ep, client_ep_obj);

    // The DRIVER, built (and scheduled) first so it parks in ChannelRecv before
    // the client calls. Seeded: endpoint raw 0, device capability raw 1.
    let dblob = &raw const com2_driver_svcdrv_program_start as *const u8;
    let dlen = (&raw const com2_driver_svcdrv_program_end as usize)
        - (&raw const com2_driver_svcdrv_program_start as usize);
    let (mut driver, _dtidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        dblob,
        dlen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_d817_e005),
        0,
    );
    if driver
        .handles_mut()
        .install(driver_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step5: FAIL — install driver endpoint");
    }
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step5: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);
    if driver
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step5: FAIL — install device capability");
    }

    // The CLIENT, built second. Seeded: endpoint raw 0.
    let cblob = &raw const com2_driver_client_program_start as *const u8;
    let clen = (&raw const com2_driver_client_program_end as usize)
        - (&raw const com2_driver_client_program_start as usize);
    let (mut client, client_tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        cblob,
        clen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_c113_e005),
        0,
    );
    if client
        .handles_mut()
        .install(client_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step5: FAIL — install client endpoint");
    }
    CHAN_CLIENT_TIDX.store(client_tidx as u64, Ordering::Relaxed);

    // Re-activate the driver (first-run) space, publish both, and run with the
    // device IRQ enabled and IF-set ring-3 entry.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { driver.space().activate(Cpu::cpu_id()) };
    driver.set_running();
    client.set_running();
    if processes_insert(driver).is_err() {
        return kprintln!("m16-step5: FAIL — insert driver process");
    }
    if processes_insert(client).is_err() {
        return kprintln!("m16-step5: FAIL — insert client process");
    }

    unmask_irq(COM2_IRQ_LINE);
    USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    exec_ref().run();
    USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    mask_irq(COM2_IRQ_LINE);
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let saw_ping = CHAN_SERVER_SAW_PING.load(Ordering::Relaxed);
    let saw_pong = CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed);
    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let client_exit = CHAN_CLIENT_EXIT.load(Ordering::Relaxed);
    let pass = saw_ping && saw_pong && byte == 0x5a && woken && client_exit == 0;
    report(&verdict(
        DemoId::Com2DriverService,
        pass,
        [byte, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "m16: FAIL — saw_ping={saw_ping} saw_pong={saw_pong} byte={byte:#04x} woken={woken} client_exit={client_exit}"
        );
    }
}

/// Driver host: the M16 milestone. Runs *before* `scheduler_demo` so the timer
/// and its `TICK_HOOK` are still off (only the device IRQ we unmask can fire).
fn driver_host_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    com2_driver_step0_selftest();
    com2_driver_step1_bridge();
    com2_driver_step2_ring3_ports(kernel_vm, frames);
    com2_driver_step3_deviceio(kernel_vm, frames);
    com2_driver_step4_irq_driver(kernel_vm, frames);
    com2_driver_step5_service(kernel_vm, frames);
}

// --- M17: device manager + resource graph (a service grants a device cap) -----

// The DEVICE MANAGER: waits for a driver's request on its endpoint (raw 0) and
// replies granting the device capability (raw 1) — transferred in the reply.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global device_manager_program_start
.global device_manager_program_end
device_manager_program_start:
    xor edi, edi                       # recv: arg0 unused
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # ChannelRecv (blocks for the driver)
    syscall
    lea rdi, [rip + device_manager_grant_args]    # arg0 = ChannelMsgArgs (grant reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # ChannelReply (transfers the device cap)
    syscall
1:
    jmp 1b
.balign 8
device_manager_grant_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_grant_body - device_manager_program_start
    .quad 4
    .quad 0x400000 + device_manager_grant_handles - device_manager_program_start
    .quad 1                            # handle_count = 1 (grant the device cap)
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_grant_body:
    .ascii "com2"
.balign 8
device_manager_grant_handles:
    # One HandleTransfer descriptor (channel_msg.isl): handle, mode, rights.
    # Mode 0 is TransferMode::TRANSFER — the sender's copy goes away.
    # The manager holds READ|WRITE|TRANSFER and grants **READ|WRITE**, dropping
    # TRANSFER: a driver host gets the authority to drive its device and not the
    # authority to hand it to anyone else. Before rights narrowed on transfer
    # this was not expressible — moving a handle requires TRANSFER, so every
    # granted capability necessarily arrived able to be granted onward.
    .long 1                            # the device capability handle (raw 1)
    .long 0                            # reserved (must be zero)
    .quad 0x03                         # rights: READ|WRITE, deliberately no TRANSFER
device_manager_program_end:
.text
"#
);

// The DRIVER HOST: requests its device from the manager, then services a client
// through the granted capability. Seeded handles: manager-endpoint raw 0,
// client-endpoint raw 1. PortCreate returns raw 2; the granted device cap
// installs at raw 3 (next free slot after the ChannelCall reply).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global device_manager_driver_program_start
.global device_manager_driver_program_end
device_manager_driver_program_start:
    mov eax, 16                        # PortCreate -> port handle (raw 2)
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    lea rdi, [rip + device_manager_req_args]      # arg0 = ChannelMsgArgs (request "com2")
    xor esi, esi                       # arg1 = manager endpoint (raw 0)
    mov eax, 14                        # ChannelCall -> reply grants device cap (raw 3)
    syscall
    xor edi, edi                       # recv: arg0 unused
    mov esi, 1                         # arg1 = client endpoint (raw 1)
    mov eax, 13                        # ChannelRecv (blocks for the client)
    syscall
    mov edi, 3                         # arg0 = granted device cap (raw 3)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    mov edi, 3                         # arg0 = granted device cap (raw 3)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> the looped byte
    syscall
    mov edi, 3                         # arg0 = granted device cap (raw 3)
    mov esi, 8                         # arg1 = offset 8 (== len) -> out of range
    mov eax, 19                        # DeviceIoRead -> denied (enforces the range)
    syscall
    lea rdi, [rip + device_manager_drv_reply_args] # arg0 = ChannelMsgArgs (reply "pong")
    mov esi, 1                         # arg1 = client endpoint (raw 1)
    mov eax, 15                        # ChannelReply (-> hands back to the client)
    syscall
1:
    jmp 1b
.balign 8
device_manager_req_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_req_body - device_manager_driver_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_drv_reply_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_pong_body - device_manager_driver_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_req_body:
    .ascii "com2"
device_manager_pong_body:
    .ascii "pong"
device_manager_driver_program_end:
.text
"#
);

// The CLIENT: asks the driver host to service an I/O (`ChannelCall` "ping"),
// receives "pong". Endpoint handle raw 0. Mirrors the M16 client.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global device_manager_client_program_start
.global device_manager_client_program_end
device_manager_client_program_start:
    lea rdi, [rip + device_manager_client_msg]
    mov esi, 16                        # length (== device_manager_client_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    lea rdi, [rip + device_manager_call_args]     # arg0 = ChannelMsgArgs (request)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 14                        # ChannelCall (blocks for the reply)
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
device_manager_client_msg:
    .ascii "m17 client: call"
.balign 8
device_manager_call_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_ping_body - device_manager_client_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_ping_body:
    .ascii "ping"
device_manager_client_program_end:
.text
"#
);

// SAFETY: names the M17 blob bounds from the global_asm above; the extern block
// only declares them and performs no unsafe operation.
unsafe extern "C" {
    static device_manager_program_start: u8;
    static device_manager_program_end: u8;
    static device_manager_driver_program_start: u8;
    static device_manager_driver_program_end: u8;
    static device_manager_client_program_start: u8;
    static device_manager_client_program_end: u8;
}

/// M17: the device manager. A ring-3 **manager** owns a device (COM2) registered
/// in the resource graph and grants its capability, over a channel reply, to a
/// ring-3 **driver host** that requests it; the driver then drives the device
/// (M16's IRQ + DeviceIo path) through the *granted* cap and services a
/// **client**. Proves brokered capability granting and the Device object's real
/// `(base,len)` resource-graph payload (kernel-enforced).
fn device_manager_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::{USER_IF_ON_ENTRY, com2, mask_irq, set_device_irq_hook, unmask_irq};
    // SAFETY: one-shot registration before this demo's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    set_device_irq_hook(com2_driver_bridge_hook);
    CHAN_SERVER_SAW_PING.store(false, Ordering::Relaxed);
    CHAN_CLIENT_SAW_PONG.store(false, Ordering::Relaxed);
    CHAN_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    CHAN_CLIENT_TIDX.store(u64::MAX, Ordering::Relaxed);
    CHAN_HANDLE_TRANSFERRED.store(false, Ordering::Relaxed);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    DEVICE_MANAGER_OOR_DENIED.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: single-core boot; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }

    // Two channels: A = manager <-> driver (grant), B = driver <-> client (I/O).
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let (mgr_ep, drv_mgr_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("m17: FAIL — manager channel: {e:?}"),
    };
    let (drv_cli_ep, cli_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("m17: FAIL — client channel: {e:?}"),
    };
    let mgr_ep_obj = objects.create(ObjectType::Channel);
    let drv_mgr_ep_obj = objects.create(ObjectType::Channel);
    let drv_cli_ep_obj = objects.create(ObjectType::Channel);
    let cli_ep_obj = objects.create(ObjectType::Channel);
    let (mgr_ep_obj, drv_mgr_ep_obj, drv_cli_ep_obj, cli_ep_obj) =
        match (mgr_ep_obj, drv_mgr_ep_obj, drv_cli_ep_obj, cli_ep_obj) {
            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
            _ => return kprintln!("m17: FAIL — endpoint objects"),
        };
    exec_ref().bind_endpoint_object(mgr_ep, mgr_ep_obj);
    exec_ref().bind_endpoint_object(drv_mgr_ep, drv_mgr_ep_obj);
    exec_ref().bind_endpoint_object(drv_cli_ep, drv_cli_ep_obj);
    exec_ref().bind_endpoint_object(cli_ep, cli_ep_obj);

    // The COM2 device object + its resource-graph node, granted to the manager.
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m17: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);

    // The MANAGER, built and scheduled first so it parks in ChannelRecv before
    // the driver requests. Seeded: endpoint raw 0, device cap raw 1 (with
    // TRANSFER, so it can grant it).
    let mblob = &raw const device_manager_program_start as *const u8;
    let mlen = (&raw const device_manager_program_end as usize)
        - (&raw const device_manager_program_start as usize);
    let (mut manager, _mtidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        mblob,
        mlen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_de91_e001),
        0,
    );
    if manager
        .handles_mut()
        .install(mgr_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
        || manager
            .handles_mut()
            .install(dev_obj, Rights::READ | Rights::WRITE | Rights::TRANSFER)
            .is_err()
    {
        return kprintln!("m17: FAIL — seed manager handles");
    }

    // The DRIVER, built second. Seeded: manager-endpoint raw 0, client-endpoint
    // raw 1 (the granted device cap installs at raw 3 at runtime).
    let dblob = &raw const device_manager_driver_program_start as *const u8;
    let dlen = (&raw const device_manager_driver_program_end as usize)
        - (&raw const device_manager_driver_program_start as usize);
    let (mut driver, _dtidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        dblob,
        dlen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_d817_e017),
        0,
    );
    if driver
        .handles_mut()
        .install(drv_mgr_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
        || driver
            .handles_mut()
            .install(drv_cli_ep_obj, Rights::READ | Rights::WRITE)
            .is_err()
    {
        return kprintln!("m17: FAIL — seed driver handles");
    }

    // The CLIENT, built third. Seeded: driver-endpoint raw 0.
    let cblob = &raw const device_manager_client_program_start as *const u8;
    let clen = (&raw const device_manager_client_program_end as usize)
        - (&raw const device_manager_client_program_start as usize);
    let (mut client, client_tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        cblob,
        clen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_c113_e017),
        0,
    );
    if client
        .handles_mut()
        .install(cli_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m17: FAIL — seed client handle");
    }
    CHAN_CLIENT_TIDX.store(client_tidx as u64, Ordering::Relaxed);

    // Re-activate the manager (first-run) space; publish all three; run with the
    // device IRQ enabled and IF-set ring-3 entry.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { manager.space().activate(Cpu::cpu_id()) };
    manager.set_running();
    driver.set_running();
    client.set_running();
    if processes_insert(manager).is_err()
        || processes_insert(driver).is_err()
        || processes_insert(client).is_err()
    {
        return kprintln!("m17: FAIL — insert processes");
    }

    unmask_irq(COM2_IRQ_LINE);
    USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    exec_ref().run();
    USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    mask_irq(COM2_IRQ_LINE);
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    // The granted device object's reference was conserved (manager→message→driver).
    // SAFETY: single-core boot; the ring-3 run has returned to boot.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_conserved = objects.is_live(dev_obj) && objects.refcount(dev_obj) == Some(1);

    let granted = CHAN_HANDLE_TRANSFERRED.load(Ordering::Relaxed);
    let saw_ping = CHAN_SERVER_SAW_PING.load(Ordering::Relaxed);
    let saw_pong = CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed);
    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let client_exit = CHAN_CLIENT_EXIT.load(Ordering::Relaxed);
    let oor_denied = DEVICE_MANAGER_OOR_DENIED.load(Ordering::Relaxed);
    let pass = granted
        && saw_ping
        && saw_pong
        && byte == 0x5a
        && woken
        && client_exit == 0
        && oor_denied
        && dev_conserved;
    report(&verdict(
        DemoId::DeviceManager,
        pass,
        [u64::from(com2::BASE), byte, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "m17: FAIL — granted={granted} saw_ping={saw_ping} saw_pong={saw_pong} byte={byte:#04x} woken={woken} client_exit={client_exit} oor_denied={oor_denied} dev_conserved={dev_conserved}"
        );
    }
}

// --- The driver framework: a real bus, a manager, and a compiled driver (D145) ---

/// Most PCI functions this port records. q35 with one attached device presents
/// a handful; the walk reports what it found and stops at the array's end.
const MAX_PCI_FUNCTIONS: usize = 16;

/// A zeroed function, for the enumeration array.
const PCI_BLANK_FUNCTION: tessera_pci::Function = tessera_pci::Function {
    revision: 0,
    bdf: tessera_pci::Bdf {
        bus: 0,
        device: 0,
        function: 0,
    },
    vendor: 0,
    device: 0,
    class_code: 0,
    header_type: 0,
    bars: [None; tessera_pci::MAX_BARS],
    parent: None,
};

/// The class byte the manager maps onto `DeviceClass::Block`.
const PCI_CLASS_MASS_STORAGE: u32 = 0x01;

/// How far into its window the driver reads, and the kernel reads after it.
///
/// **Past the first page, deliberately.** A driver granted only its device's
/// first page would still pass a check that read at offset zero; this offset is
/// in the third page of the window, so agreeing with the kernel's read at the
/// same physical address means the whole window arrived.
const FAR_WINDOW_OFFSET: u64 = 0x2000;

/// Where this check maps the bound device's window to make that read. A kernel
/// address, mapped for the length of the comparison and taken down after — the
/// driver's own mapping is the one under test.
const PCI_FAR_READ_VA: u64 = 0xffff_a000_0000_0000;

/// Tags a driver's report as "this is what the kernel says the device is", so
/// the check cannot mistake a PCI identity for some other word. Must match
/// `blk-probe`'s constant of the same name.
const PCI_REPORT_TAG: u64 = 0x5043 << 48;

/// The embedded ring-3 programs. Only the Bazel build has them; the cargo inner
/// loop builds without and the check reports that it was skipped.
#[cfg(has_device_manager)]
fn device_manager_elf() -> &'static [u8] {
    &device_manager_image_x86_64::DEVICE_MANAGER_ELF
}
#[cfg(not(has_device_manager))]
fn device_manager_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_device_manager)]
fn pci_bus_elf() -> &'static [u8] {
    &pci_bus_image_x86_64::PCI_BUS_ELF
}
#[cfg(not(has_device_manager))]
fn pci_bus_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_blk_probe)]
fn blk_probe_elf() -> &'static [u8] {
    &blk_probe_image_x86_64::BLK_PROBE_ELF
}
#[cfg(not(has_blk_probe))]
fn blk_probe_elf() -> &'static [u8] {
    &[]
}

/// PCI configuration space through the legacy `0xCF8`/`0xCFC` port pair.
///
/// **This is why `kernel/pci` needed no change to run here.** `ConfigSpace` is
/// two methods over an ECAM-style byte offset, and ECAM's offset encoding is
/// just `bus:device:function:register` shifted — so the same offset a
/// memory-mapped implementation would add to a base is decoded back into the
/// address this port's host bridge wants. No ACAM window has to be found, no
/// ACPI table parsed, and no base hardcoded.
///
/// **Extended configuration space is out of reach here, and this says so
/// rather than aliasing.** The `0xCF8` address register has eight bits of
/// register number, so offsets at or past 0x100 cannot be expressed; wrapping
/// them into the first 256 bytes would answer a capability walk with the wrong
/// register and look entirely successful. Nothing this port reads lives there:
/// `find_capability` already bounds its chain to the 256-byte header.
struct PortConfigSpace;

/// The address and data ports of the mechanism-1 configuration pair.
const PCI_CONFIG_ADDRESS: u16 = 0xcf8;
const PCI_CONFIG_DATA: u16 = 0xcfc;
/// What a read of a register this mechanism cannot reach answers. The same
/// value the bus itself returns for a function that is not there, which is what
/// every caller already treats as "nothing here".
const PCI_CONFIG_UNREACHABLE: u32 = 0xffff_ffff;

impl PortConfigSpace {
    /// The `0xCF8` address word for an ECAM-style `offset`, or `None` when the
    /// offset names extended configuration space.
    fn address(offset: u64) -> Option<u32> {
        let register = offset & 0xfff;
        if register >= 0x100 {
            return None;
        }
        let bus = (offset >> 20) & 0xff;
        let device = (offset >> 15) & 0x1f;
        let function = (offset >> 12) & 0x7;
        Some(
            0x8000_0000
                | (bus as u32) << 16
                | (device as u32) << 11
                | (function as u32) << 8
                | (register as u32 & 0xfc),
        )
    }
}

impl tessera_pci::ConfigSpace for PortConfigSpace {
    fn read32(&self, offset: u64) -> u32 {
        let Some(address) = Self::address(offset) else {
            return PCI_CONFIG_UNREACHABLE;
        };
        // SAFETY: the configuration address/data pair is owned by this kernel
        // and by nothing else — no ring-3 program on this port can reach a port
        // at all, and the boot path is single-threaded, so no interleaved
        // writer can change the latched address between these two accesses.
        unsafe {
            tessera_karch_x86_64::outl(PCI_CONFIG_ADDRESS, address);
            tessera_karch_x86_64::inl(PCI_CONFIG_DATA)
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        let Some(address) = Self::address(offset) else {
            return;
        };
        // SAFETY: as for `read32` — the pair is this kernel's alone and the
        // address stays latched across the two writes.
        unsafe {
            tessera_karch_x86_64::outl(PCI_CONFIG_ADDRESS, address);
            tessera_karch_x86_64::outl(PCI_CONFIG_DATA, value);
        }
    }
}

/// The 32-bit window BARs are placed in on this machine.
///
/// q35 puts its ECAM at `0xb000_0000` and 512 MiB of RAM ends far below this,
/// so the region is bus address space rather than memory — but that is an
/// argument, not a check, which is why [`pci_window_is_clear`] runs before
/// anything is written.
const PCI_WINDOW_BASE: u64 = 0xc000_0000;
const PCI_WINDOW_LEN: u64 = 0x1000_0000;

/// Whether the BAR window overlaps anything the firmware called memory.
///
/// **Firmware has already assigned these BARs and this reassigns them**, which
/// is what `tessera_pci` does on every port — one code path rather than two.
/// The risk that creates is specific: a window chosen badly would have a device
/// decoding over RAM somebody else is using, and the failure would appear
/// arbitrarily later as corruption with no connection to PCI. So the window is
/// checked against the map the bootloader handed us, and enumeration is refused
/// rather than attempted if it overlaps.
fn pci_window_is_clear(map: &[MemoryRegion]) -> bool {
    let end = PCI_WINDOW_BASE + PCI_WINDOW_LEN;
    !map.iter().any(|region| {
        // Only usable RAM matters. A reserved region here is firmware saying
        // "not memory", which is exactly what a device window is.
        region.kind == MemoryKind::Usable
            && region.base.as_u64() < end
            && PCI_WINDOW_BASE < region.base.as_u64() + region.len
    })
}

/// The syscall surface a device manager and a driver need, routed to the shared
/// dispatcher.
///
/// **Every uniform arm delegates and none is reimplemented.** `kcore::dispatch`
/// is where channel IPC, capability transfer, `MapDevice`, `DeviceInfo` and the
/// lifecycle already live for the two ports that run this framework; a local
/// copy here would be a second implementation of semantics that are supposed to
/// be common, and the first divergence would show up as a port-specific bug in
/// a program neither port compiled differently.
///
/// Only the two genuinely local things stay: `DebugWrite`, which is how a
/// program reports into this port's sink, and `ProcessExit`, which has to reach
/// this port's scheduler.
fn driver_bind_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    let Some(caller_idx) = chan_current_index() else {
        return syscall::ENOSYS;
    };
    let Some(number) = SyscallNumber::from_u64(frame.number) else {
        return syscall::ENOSYS;
    };
    match number {
        SyscallNumber::DebugWrite => {
            let slot = BIND_REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
            if slot < BIND_REPORTS.len() {
                BIND_REPORTS[slot].store(frame.arg0, Ordering::SeqCst);
            }
            0
        }
        SyscallNumber::ProcessExit => chan_process_exit(caller_idx, frame.arg0 as i32),
        _ => {
            let req = SyscallRequest {
                number: frame.number,
                args: [
                    frame.arg0, frame.arg1, frame.arg2, frame.arg3, frame.arg4, frame.arg5,
                ],
            };
            // SAFETY: single-core; EXEC/PROCESSES are populated before any
            // ring-3 thread runs and touched only on this CPU. The borrows are
            // built here and dropped at the end of the call, so none is parked
            // across the handoff a blocking channel op performs inside.
            let processes = unsafe { &mut *&raw mut PROCESSES };
            let mut router = PicRouter;
            let mut env = DispatchEnv {
                exec: exec_ref(),
                processes,
                caller: caller_idx,
                // The boot allocator, published for the run. A driver mapping
                // its register window needs page tables built inside the
                // syscall, which is the whole reason the other ports publish
                // theirs too.
                alloc: bind_frames(),
                // No IOMMU on this machine, so every DMA grant would be
                // unscoped — and says so rather than pretending (D121).
                iommu: None,
                irqs: Some(&mut router),
            };
            match dispatch(&mut env, &req) {
                DispatchOutcome::Return(value) => value,
                DispatchOutcome::Unhandled => syscall::ENOSYS,
            }
        }
    }
}

/// A contained user fault inside the bind check: vector, CR2, RIP, thread.
static BIND_FAULT: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static BIND_FAULTED: AtomicBool = AtomicBool::new(false);

/// Contains a ring-3 fault taken inside the bind check.
///
/// **This check needs its own, and the reason is worth stating.** The handler
/// the single-process demos install drives `USER_PROCESS` and `USER_SCHEDULER`
/// — statics belonging to *that* demo's one process and one scheduler. A fault
/// here would find them stale, yield to a scheduler this check never populated,
/// and hang with nothing printed: the worst possible way to learn that a driver
/// touched something it should not have. So this one exits the faulting process
/// in *this* process table and blocks its thread, which returns control to the
/// boot context the same way an ordinary exit does.
fn bind_user_fault_handler(frame: &TrapFrame) -> ! {
    let cr2 = tessera_karch_x86_64::read_cr2();
    let thread = chan_current_index();
    BIND_FAULTED.store(true, Ordering::SeqCst);
    BIND_FAULT[0].store(frame.vector, Ordering::SeqCst);
    BIND_FAULT[1].store(cr2, Ordering::SeqCst);
    BIND_FAULT[2].store(frame.rip, Ordering::SeqCst);
    BIND_FAULT[3].store(thread.map_or(u64::MAX, |t| t as u64), Ordering::SeqCst);
    report_contained_fault(frame.vector, cr2);
    if let Some(caller) = thread {
        // SAFETY: single-core; the tables are this check's own and quiescent
        // apart from the faulting thread, which is off-CPU from here on.
        let processes = unsafe { &mut *&raw mut PROCESSES };
        if let Some(process) = processes.process_of_thread(caller) {
            process.exit(-1);
        }
        exec_ref().scheduler().block_current();
    }
    // Unreachable: `block_current` switched away and this thread never resumes.
    loop {
        core::hint::spin_loop();
    }
}

/// Where the bind check's ring-3 programs report, in the order they report.
///
/// Ordered rather than folded together, for the reason every other port's sink
/// is: the manager and the driver are two programs, and a single word they both
/// wrote into could not distinguish one of them failing from the other never
/// having run.
const MAX_BIND_REPORTS: usize = 4;
static BIND_REPORTS: [AtomicU64; MAX_BIND_REPORTS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static BIND_REPORT_COUNT: AtomicU64 = AtomicU64::new(0);

/// The boot frame allocator, published for the syscall path's lifetime.
static mut BIND_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> = core::ptr::null_mut();

/// The published allocator, or a source that refuses. Never `None`: a syscall
/// arriving with no allocator is a bug in the boot glue, and answering
/// `NoFrames` makes it fail where it happened.
fn bind_frames() -> &'static mut dyn FrameSource {
    // SAFETY: single-core; set before the ring-3 threads run and cleared after
    // the last one is off-CPU.
    let published = unsafe { *(&raw const BIND_FRAMES) };
    if published.is_null() {
        // SAFETY: `NoFrames` is a zero-sized refusing source; the static
        // reference is valid for the program's lifetime.
        return unsafe { &mut *(&raw mut BIND_NO_FRAMES) };
    }
    // SAFETY: the pointer was published from a live borrow that outlives the
    // run, and only this CPU dereferences it.
    unsafe { &mut *published }
}

static mut BIND_NO_FRAMES: NoFrames = NoFrames;

/// Kernel stack pages for a bind-check program. Eight, because a channel
/// operation parks a whole dispatch frame across the handoff.
const BIND_KSTACK_PAGES: u64 = 8;

/// Loads an ELF into a fresh address space and adds its initial thread.
///
/// **The first compiled ring-3 program on this port.** Everything ring 3 here
/// has been a hand-written `global_asm!` blob copied to a fixed address; this is
/// the sequence `loader_demo` performs on the root task, made a function so two
/// programs can use it, and shaped like the helper of the same name on the two
/// ports that already run the framework.
///
/// Returns the thread's scheduler index and the process's table index — two
/// different numbers, and releasing one without the other is the mistake
/// `Process::forget_thread` exists for.
fn spawn_elf_process(
    image: &[u8],
    arg: usize,
    process_obj: ObjectId,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    let parsed = elf::parse(image, elf::Machine::X86_64).map_err(|_| base_err)?;
    // W^X, checked here rather than trusted from the linker script: a segment
    // that is writable and executable is refused however it got that way.
    if parsed.segments().iter().any(|seg| seg.write && seg.exec) {
        return Err(base_err + 1);
    }

    let user_arch = kernel_vm
        .arch()
        .new_user(frames)
        .map_err(|_| base_err + 2)?;
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, alloc_asid(), 1u64 << Cpu::cpu_id());
    let mut process = Process::new(process_obj, user_vm);

    // Reserve every segment writable to receive its bytes; the W^X protections
    // go on after the copy, which is the only order that works when the copy is
    // what makes the text executable.
    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        process
            .space_mut()
            .map_anonymous(
                VirtAddr::new(base),
                pages * FRAME_SIZE,
                PageFlags::rw().user(),
                frames,
            )
            .map_err(|_| base_err + 3)?;
    }

    let thread = Thread::<ContextSwitch>::spawn_user(
        ThreadId(0x_d1_0000 | u64::from(process_obj.raw())),
        VirtAddr::new(parsed.entry()),
        arg,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(BIND_KSTACK_PAGES),
        BIND_KSTACK_PAGES,
        process_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    )
    .map_err(|_| base_err + 4)?;
    let thread_idx = exec_ref().add_thread(thread).map_err(|_| base_err + 5)?;
    process.add_thread(thread_idx).map_err(|_| base_err + 6)?;

    // The copy happens with the target space active: this port has no
    // higher-half alias of another process's user pages, so the bytes go in
    // through the addresses the program will itself run at.
    // SAFETY: the user space shares the kernel higher half, so this boot code,
    // its stack and the direct map stay mapped across the switch.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    for seg in parsed.segments() {
        let src = image[seg.file_offset as usize..].as_ptr();
        // SAFETY: `parse` bounds-checked `[file_offset, file_offset+file_size)`
        // against the image, and the destination pages were mapped writable
        // above in the space that is now active.
        unsafe {
            core::ptr::copy_nonoverlapping(src, seg.vaddr as *mut u8, seg.file_size as usize);
            let bss = (seg.mem_size - seg.file_size) as usize;
            if bss > 0 {
                core::ptr::write_bytes((seg.vaddr + seg.file_size) as *mut u8, 0, bss);
            }
        }
    }
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    for seg in parsed.segments() {
        let (base, pages) = elf_seg_pages(seg);
        process
            .space_mut()
            .protect_range(VirtAddr::new(base), pages * FRAME_SIZE, elf_seg_rights(seg))
            .map_err(|_| base_err + 7)?;
    }

    process.set_running();
    let process_idx = processes_insert(process).map_err(|_| base_err + 8)?;
    Ok((thread_idx, process_idx))
}

/// What the bind check produced.
struct BindOutcome {
    /// The identity the driver reported back.
    reported: u64,
    /// The identity the kernel enumerated, which the above must equal.
    expected: u64,
    /// How many PCI functions the walk found.
    functions: usize,
    /// The window the bound device was granted.
    bar_base: u64,
    bar_len: u64,
}

/// The q35 host bridge's `PCIEXBAR`, at `0:0.0` configuration offset `0x60`.
///
/// **Where this port learns that ECAM exists at all.** It reaches configuration
/// space through the `0xCF8`/`0xCFC` pair, which is why `tessera_pci::Host` here
/// records an ECAM base of zero: the "window" is an encoding, not memory. A
/// ring-3 bus controller cannot use ports — it holds no I/O authority and there
/// is no capability shaped like one — so the memory-mapped window has to be
/// found before anything can be handed over. The chipset says where it put it.
const PCIEXBAR: u16 = 0x60;

/// The ECAM window's physical base, or `None` when the chipset says it is
/// disabled.
///
/// Refused rather than guessed. QEMU's q35 enables it and puts it at
/// `0xb0000000`, but a machine that says otherwise means it, and a controller
/// handed a window nothing decodes would read all-ones and declare a bus with
/// nothing on it — which is indistinguishable from a bus with nothing on it.
fn ecam_base(host: &tessera_pci::Host, cfg: &dyn tessera_pci::ConfigSpace) -> Option<u64> {
    let root = tessera_pci::Bdf::new(0, 0, 0)?;
    let low = host.read(cfg, root, PCIEXBAR).ok()?;
    // Bit 0 enables the window; bits 2:1 size it; the rest is the base.
    if low & 1 == 0 {
        return None;
    }
    // The upper half addresses windows above 4 GiB, which this port's mapping
    // path does not reach. Reported as absent rather than truncated into range.
    if host.read(cfg, root, PCIEXBAR + 4).ok()? != 0 {
        return None;
    }
    Some(u64::from(low & !0xfff))
}

const PCI_BUS_OBJ: ObjectId = ObjectId::from_raw(0xe0);
const PCI_BUS_MANAGER_SERVER_OBJ: ObjectId = ObjectId::from_raw(0xe1);
const PCI_BUS_MANAGER_CLIENT_OBJ: ObjectId = ObjectId::from_raw(0xe2);
const PCI_BUS_MANAGER_PROC_OBJ: ObjectId = ObjectId::from_raw(0xe3);
const PCI_BUS_DRIVER_PROC_OBJ: ObjectId = ObjectId::from_raw(0xe4);
const PCI_BUS_PROBE_PROC_OBJ: ObjectId = ObjectId::from_raw(0xe5);

/// How much configuration space the bus controller is granted: eight buses,
/// which is `kcore::dispatch::MAX_BUS_WINDOW_BYTES`.
const PCI_BUS_CONFIG_LEN: u64 = 0x80_0000;
const PCI_BUS_COUNT: u8 = 8;

/// The startup argument asking `blk-probe` to report what its own configuration
/// space says it is. Must match `CONFIG_REPORT` there.
const BLK_PROBE_CONFIG_REPORT: usize = 1 << 59;

/// What the bus-driver check produced.
struct BusOutcome {
    /// Functions the ring-3 walk found and declared.
    functions: u64,
    /// The vendor/device word the driver read out of its own configuration
    /// space, which must be what the kernel's independent walk found.
    word: u32,
}

/// Proves **PCI enumeration outside the kernel** on this port — the same ring-3
/// program the AArch64 port runs, against a machine whose configuration space
/// the kernel reaches through I/O ports.
///
/// That difference is the point. The kernel walks through `0xCF8`/`0xCFC`; the
/// controller walks through the memory-mapped window the chipset reports; and
/// the two must agree about the same function. Neither can produce the other's
/// answer by echoing it.
fn pci_bus_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<BusOutcome>, u32> {
    use kcore::rights::Rights;

    if pci_bus_elf().is_empty() || blk_probe_elf().is_empty() {
        return Ok(None);
    }
    if !pci_window_is_clear(memory_map) {
        return Err(1);
    }
    let ports = tessera_pci::Host {
        ecam_base: 0,
        ecam_len: 0x1000_0000,
        first_bus: 0,
        last_bus: 0,
    };
    let mut config = PortConfigSpace;
    let Some(ecam) = ecam_base(&ports, &config) else {
        return Ok(None);
    };
    // The kernel's own walk, which the controller's is checked against.
    let window = tessera_pci::Window {
        cpu_base: PCI_WINDOW_BASE,
        bus_base: PCI_WINDOW_BASE,
        len: PCI_WINDOW_LEN,
        is_32bit: true,
    };
    let mut functions = [PCI_BLANK_FUNCTION; MAX_PCI_FUNCTIONS];
    let found =
        tessera_pci::enumerate(&ports, &mut config, window, &mut functions).map_err(|_| 2u32)?;
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.class_code >> 16 == PCI_CLASS_MASS_STORAGE)
    else {
        return Ok(None);
    };
    let word = u32::from(function.vendor) | (u32::from(function.device) << 16);

    // SAFETY: single-core boot; a fresh table and executive for this check, and
    // the previous demo's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }
    // The bridge, as a device whose register window *is* configuration space.
    exec_ref()
        .device_register_mmio(
            PCI_BUS_OBJ,
            ecam,
            PCI_BUS_CONFIG_LEN,
            Rights::READ
                | Rights::WRITE
                | Rights::MAP
                | Rights::DERIVE
                | Rights::CONFIGURE
                | Rights::TRANSFER,
        )
        .map_err(|_| 3u32)?;
    exec_ref()
        .device_set_bus_window(
            PCI_BUS_OBJ,
            kcore::devmgr::BusWindow {
                config_len: PCI_BUS_CONFIG_LEN,
                forward_cpu_base: PCI_WINDOW_BASE,
                forward_bus_base: PCI_WINDOW_BASE,
                forward_len: PCI_WINDOW_LEN,
                first_bus: 0,
                last_bus: PCI_BUS_COUNT - 1,
                // A PCI bridge forwards memory and no wires: its functions interrupt by
                // message, through a different door.
                first_intid: 0,
                intid_count: 0,
            },
        )
        .map_err(|_| 4u32)?;

    let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| 5u32)?;
    exec_ref().bind_endpoint_object(server_ep, PCI_BUS_MANAGER_SERVER_OBJ);
    exec_ref().bind_endpoint_object(client_ep, PCI_BUS_MANAGER_CLIENT_OBJ);

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(driver_bind_syscall_handler) };
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'static> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe { BIND_FRAMES = frames_ptr };

    // The manager holding **nothing**: its startup argument is zero device
    // capabilities, which is the whole point. Everything it ends up with
    // arrives from the bus driver.
    let (manager_thread, manager_proc) = spawn_elf_process(
        device_manager_elf(),
        0,
        PCI_BUS_MANAGER_PROC_OBJ,
        kernel_vm,
        frames,
        10,
    )?;
    // SAFETY: single-core; the process table is quiescent between spawns.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(manager_proc)
            .ok_or(20u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 21u32)?;
    }
    let (driver_thread, driver_proc) = spawn_elf_process(
        pci_bus_elf(),
        0,
        PCI_BUS_DRIVER_PROC_OBJ,
        kernel_vm,
        frames,
        30,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *&raw mut PROCESSES;
        let driver = processes.get_mut(driver_proc).ok_or(40u32)?;
        driver
            .handles_mut()
            .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 41u32)?;
        driver
            .handles_mut()
            .install(
                PCI_BUS_OBJ,
                Rights::READ
                    | Rights::WRITE
                    | Rights::MAP
                    | Rights::DERIVE
                    | Rights::CONFIGURE
                    | Rights::TRANSFER,
            )
            .map_err(|_| 42u32)?;
    }
    let (probe_thread, probe_proc) = spawn_elf_process(
        blk_probe_elf(),
        BLK_PROBE_CONFIG_REPORT,
        PCI_BUS_PROBE_PROC_OBJ,
        kernel_vm,
        frames,
        50,
    )?;
    // SAFETY: as above.
    unsafe {
        (&mut *&raw mut PROCESSES)
            .get_mut(probe_proc)
            .ok_or(60u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 61u32)?;
    }

    // Everything here is cooperative — a send, a call, a reply, an exit — so
    // the scheduler runs to quiescence without a tick to prod it.
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    unsafe { BIND_FRAMES = core::ptr::null_mut() };

    if BIND_FAULTED.load(Ordering::SeqCst) {
        return Err(70);
    }
    let bus_report = BIND_REPORTS[0].load(Ordering::SeqCst);
    let probe_report = BIND_REPORTS[1].load(Ordering::SeqCst);
    if bus_report >> 56 != 0x50 {
        return Err(71);
    }
    let walked = (bus_report >> 8) & 0xff;
    if walked == 0 || bus_report & 0xff != walked {
        return Err(72);
    }
    if probe_report >> 56 != 0x43 {
        return Err(73);
    }
    if probe_report & 0xffff_ffff != u64::from(word) {
        return Err(74);
    }
    if probe_report & (1 << 48) == 0 {
        return Err(75);
    }

    // SAFETY: transient raw access; every thread is off-CPU and each process is
    // released once.
    unsafe {
        for thread in [probe_thread, driver_thread, manager_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for (thread, process) in [
            (probe_thread, probe_proc),
            (driver_thread, driver_proc),
            (manager_thread, manager_proc),
        ] {
            processes.forget_thread(thread);
            if let Some(mut gone) = processes.remove(process) {
                gone.space_mut().teardown(frames);
            }
        }
    }
    Ok(Some(BusOutcome {
        functions: walked,
        word,
    }))
}

/// A ring-3 device manager binds a real PCI function, by class, to a ring-3
/// driver — on x86-64.
///
/// **The framework's own sentence, on the port that reached it last.** Two of
/// five ports have run this since D91 and D111; this one could not, because it
/// had no compiled ring-3 program, no bus to enumerate, and no route from a
/// user program to the syscalls a manager needs. All three are new here and
/// *none of the mechanism is*: `api/binding`, `userspace/device-manager` and
/// `userspace/blk-probe` are the same sources the other two ports compile, and
/// the syscalls go through the same `kcore::dispatch`.
///
/// The device is a real `virtio-blk-pci` function, enumerated through the
/// legacy configuration ports, classified by the kernel from its class code,
/// and registered in the resource graph with that identity — so the manager
/// classifies it without touching it, which is the only way a PCI function can
/// be classified at all: config space is not per-device and no capability to it
/// can be handed out.
fn driver_bind_check(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) -> Result<Option<BindOutcome>, u32> {
    use kcore::rights::Rights;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Ok(None);
    }
    // Refusing beats placing a BAR over somebody's RAM and finding out later.
    if !pci_window_is_clear(memory_map) {
        return Err(1);
    }

    let host = tessera_pci::Host {
        // The offset encoding `PortConfigSpace` decodes, not a window anything
        // maps: this port reaches configuration space through ports, so the
        // "ECAM base" is zero and the length is the space the encoding spans.
        ecam_base: 0,
        ecam_len: 0x1000_0000,
        first_bus: 0,
        last_bus: 0,
    };
    let window = tessera_pci::Window {
        cpu_base: PCI_WINDOW_BASE,
        bus_base: PCI_WINDOW_BASE,
        len: PCI_WINDOW_LEN,
        is_32bit: true,
    };
    let mut config = PortConfigSpace;
    let mut functions = [PCI_BLANK_FUNCTION; MAX_PCI_FUNCTIONS];
    let found =
        tessera_pci::enumerate(&host, &mut config, window, &mut functions).map_err(|_| 2u32)?;

    // The one class this machine offers that the manager maps to `Block`.
    let Some(function) = functions[..found]
        .iter()
        .find(|f| f.class_code >> 16 == PCI_CLASS_MASS_STORAGE)
    else {
        return Ok(None);
    };
    // **The biggest memory BAR, not the lowest-indexed one.** `first_bar` is
    // the first BAR the function implements, and on a virtio-pci function that
    // is the MSI-X table — a single page. A driver granted that reaches a
    // window it cannot find its configuration structures in, and the read past
    // the first page that proves the *whole* window arrived faults instead.
    // AArch64 learned this and resolves the virtio capabilities to pick the
    // right one; this port has no capability walk yet, so it takes the largest,
    // which on every function this machine presents is the same BAR.
    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(3);
    };
    if bar_len <= FAR_WINDOW_OFFSET {
        // Refused rather than checked at offset zero: a window too small to
        // read past its first page cannot show that the whole of it arrived,
        // and quietly moving the read would test one page and claim the rest.
        return Err(4);
    }

    let device_obj = ObjectId::from_raw(0xd0);
    let manager_server_obj = ObjectId::from_raw(0xd1);
    let manager_client_obj = ObjectId::from_raw(0xd2);
    let manager_proc_obj = ObjectId::from_raw(0xd3);
    let driver_proc_obj = ObjectId::from_raw(0xd4);

    // SAFETY: single-core boot; a fresh table and executive for this check, and
    // the previous demo's run has returned to boot.
    unsafe {
        PROCESSES = ProcessTable::new();
        EXEC = Some(Executive::new(1, 0));
    }
    exec_ref()
        .device_register_identified(
            device_obj,
            bar_base,
            bar_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            kcore::devmgr::DeviceIdentity {
                class_code: function.class_code,
                vendor: function.vendor,
                device: function.device,
                bdf: (u16::from(function.bdf.bus) << 8)
                    | (u16::from(function.bdf.device) << 3)
                    | u16::from(function.bdf.function),
                revision: function.revision,
                bus: kcore::devmgr::DeviceBus::Pci,
            },
        )
        .map_err(|_| 4u32)?;

    let (server_ep, client_ep) = exec_ref().channel_create().map_err(|_| 5u32)?;
    exec_ref().bind_endpoint_object(server_ep, manager_server_obj);
    exec_ref().bind_endpoint_object(client_ep, manager_client_obj);

    // SAFETY: one-shot registration before this check's ring-3 threads run.
    unsafe { set_syscall_handler(driver_bind_syscall_handler) };
    set_user_fault_handler(bind_user_fault_handler);
    BIND_FAULTED.store(false, Ordering::SeqCst);
    BIND_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &BIND_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'static> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe { BIND_FRAMES = frames_ptr };

    // The manager, holding the machine's one device. TRANSFER is what makes it
    // a manager rather than a driver that happens to hold something.
    let (manager_thread, manager_proc) = spawn_elf_process(
        device_manager_elf(),
        1,
        manager_proc_obj,
        kernel_vm,
        frames,
        10,
    )?;
    // SAFETY: single-core; the process table is quiescent between spawns.
    unsafe {
        let processes = &mut *&raw mut PROCESSES;
        let manager = processes.get_mut(manager_proc).ok_or(20u32)?;
        // Install order is the ABI: handle 0 is the service endpoint, then the
        // devices from handle 1 up. The program names those numbers.
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 21u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 22u32)?;
    }

    // The driver, holding its endpoint and **no device**. What it ends up
    // holding arrives by transfer or not at all.
    let (driver_thread, driver_proc) =
        spawn_elf_process(blk_probe_elf(), 1, driver_proc_obj, kernel_vm, frames, 30)?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *&raw mut PROCESSES;
        processes
            .get_mut(driver_proc)
            .ok_or(40u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 41u32)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    exec_ref().run();
    // SAFETY: returning to the space this boot path came from before anything
    // below touches the allocator or the tables.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };
    // SAFETY: the run is over; no syscall can reach this pointer again.
    unsafe { BIND_FRAMES = core::ptr::null_mut() };

    if BIND_FAULTED.load(Ordering::SeqCst) {
        kprintln!(
            "driver-bind: contained fault vec={} cr2={:#x} rip={:#x} thread={}",
            BIND_FAULT[0].load(Ordering::SeqCst),
            BIND_FAULT[1].load(Ordering::SeqCst),
            BIND_FAULT[2].load(Ordering::SeqCst),
            BIND_FAULT[3].load(Ordering::SeqCst) as i64,
        );
    }
    let reported = BIND_REPORTS[0].load(Ordering::SeqCst);
    // **What the kernel reads at the same physical address.** The driver
    // reported a word from `FAR_WINDOW_OFFSET` into the window it was granted;
    // reading it here, through a mapping this check makes and takes down, is
    // what turns "the driver returned a number" into "the driver reached its
    // own device". A grant of the wrong region answers with different bytes and
    // a one-page grant faults, and neither can agree with this by accident.
    let far = if bar_len > FAR_WINDOW_OFFSET {
        let pages = FAR_WINDOW_OFFSET / FRAME_SIZE + 1;
        let first = PhysFrame::from_base(PhysAddr::new(bar_base)).ok_or(6u32)?;
        kernel_vm
            .map_device_range(VirtAddr::new(PCI_FAR_READ_VA), first, pages, frames)
            .map_err(|_| 7u32)?;
        // SAFETY: the pages just mapped cover `[bar_base, bar_base + pages*4K)`
        // as device memory, and the read is 4-byte aligned inside them.
        let value = unsafe {
            ((PCI_FAR_READ_VA + FAR_WINDOW_OFFSET) as *const u32).read_volatile() & 0xffff
        };
        kernel_vm.unmap_device_pages(VirtAddr::new(PCI_FAR_READ_VA), pages);
        u64::from(value)
    } else {
        0
    };
    let expected = PCI_REPORT_TAG
        | (far << 32)
        | (u64::from(function.vendor) << 16)
        | u64::from(function.device);

    // SAFETY: transient raw access; both threads are off-CPU and each is
    // released once. Reaping alone is not teardown — it frees the scheduler
    // slot while the dead process still claims the thread index.
    unsafe {
        for thread in [driver_thread, manager_thread] {
            exec_ref().scheduler().reap(thread);
        }
        let processes = &mut *&raw mut PROCESSES;
        for (thread, process) in [(driver_thread, driver_proc), (manager_thread, manager_proc)] {
            processes.forget_thread(thread);
            if let Some(mut gone) = processes.remove(process) {
                gone.space_mut().teardown(frames);
            }
        }
    }

    Ok(Some(BindOutcome {
        reported,
        expected,
        functions: found,
        bar_base,
        bar_len,
    }))
}

/// Builds a ring-3 process from the embedded blob, runs it, and asserts the
/// isolation bet held: ring 3 executed, the syscalls round-tripped, and the
/// deliberate user fault was contained without a kernel panic.
fn user_mode_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) {
    // SAFETY: one-shot registration, before any ring-3 thread runs.
    unsafe { set_syscall_handler(user_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    // A user address space that shares the kernel higher-half (so the kernel is
    // addressable under the user CR3 during syscalls/faults).
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("user demo: new_user failed: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, alloc_asid(), 1u64 << Cpu::cpu_id());

    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => panic!("user demo: process object create failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    // Seed one handle (raw value 0: slot 0, generation 0) for ring 3 to
    // duplicate and query.
    let seeded_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => panic!("user demo: seed object create failed: {e:?}"),
    };
    if process
        .handles_mut()
        .insert(seeded_obj, Rights::READ | Rights::WRITE | Rights::DUPLICATE)
        .is_err()
    {
        panic!("user demo: seed handle insert failed");
    }

    // Map the ring-3 code page writable so we can copy the program into it.
    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    if let Err(e) = process.space_mut().map_anonymous(
        VirtAddr::new(USER_CODE_VA),
        code_len,
        PageFlags::rw().user(),
        frames,
    ) {
        panic!("user demo: map code page failed: {e:?}");
    }

    // Spawn the ring-3 thread (maps its user and kernel stacks).
    let thread = match Thread::<ContextSwitch>::spawn_user(
        ThreadId(0x5e_2000),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("user demo: spawn_user failed: {e:?}"),
    };
    // SAFETY: single-threaded boot; the only initialization of USER_SCHEDULER.
    unsafe { USER_SCHEDULER = Some(Scheduler::new(1, 0)) };
    let thread_idx = match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => match scheduler.add_thread(thread) {
            Ok(idx) => idx,
            Err(e) => panic!("user demo: scheduler thread table full: {e:?}"),
        },
        None => panic!("user demo: scheduler uninitialized"),
    };
    if process.add_thread(thread_idx).is_err() {
        panic!("user demo: process thread set full");
    }

    // Switch to the user address space, copy the program into the writable code
    // page, then lock it to read+execute (W^X). The kernel stays mapped, so
    // boot keeps running after the CR3 load.
    // SAFETY: the user space shares the kernel higher-half; this code, the boot
    // stack, and the direct map remain mapped after activation.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    let code_src = &raw const user_program_start as *const u8;
    let code_bytes =
        (&raw const user_program_end as usize) - (&raw const user_program_start as usize);
    // SAFETY: [user_program_start, user_program_end) is the assembled ring-3
    // blob in kernel rodata; USER_CODE_VA is a writable user page in the now-
    // active space with room for `code_bytes` (< one page).
    unsafe {
        core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes);
    }
    if let Err(e) = process.space_mut().protect_range(
        VirtAddr::new(USER_CODE_VA),
        code_len,
        PageFlags::rx().user(),
    ) {
        panic!("user demo: protect code page failed: {e:?}");
    }

    // Publish the process, mark it running, and run the thread.
    // SAFETY: single-threaded boot; the only initialization of USER_PROCESS.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }

    kprintln!("user: entering ring 3 at {USER_CODE_VA:#x} (own address space)");
    // SAFETY: single-core boot path; USER_SCHEDULER was initialized above.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.run(),
        None => panic!("user demo: scheduler uninitialized"),
    }

    // Back on the boot context (the fault handler switched here). Restore the
    // kernel address space.
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    // Assert the bet held.
    if !USER_RING3_REACHED.load(Ordering::Relaxed) {
        panic!("user demo: no syscall arrived from ring 3");
    }
    let dup = USER_DUP_HANDLE.load(Ordering::Relaxed);
    if dup == 0 {
        panic!("user demo: handle duplicate did not succeed");
    }
    let queried = USER_QUERY_RIGHTS.load(Ordering::Relaxed);
    if queried != Rights::READ.bits() {
        panic!("user demo: queried rights {queried:#x} != READ");
    }
    if !USER_FAULT_CONTAINED.load(Ordering::Relaxed) {
        panic!("user demo: ring-3 fault was not contained");
    }
    // SAFETY: single-core boot path; only this boot CPU touches USER_PROCESS.
    let state = unsafe { (*&raw const USER_PROCESS).as_ref() }.map(Process::state);
    let exited = matches!(state, Some(ProcessState::Exited(_)));
    if !exited {
        panic!("user demo: process not marked Exited after the fault");
    }

    kprintln!(
        "user: {} syscalls serviced (null + debug_write + duplicate->handle {:#x} + query READ)",
        USER_SYSCALLS.load(Ordering::Relaxed),
        dup - 1,
    );
    kprintln!(
        "user: ring-3 fault (vector {}, addr {:#x}) contained; process terminated, kernel alive",
        USER_FAULT_VECTOR.load(Ordering::Relaxed),
        USER_FAULT_ADDR.load(Ordering::Relaxed),
    );
}

// --- Demand paging + copy-on-write demonstration ---
//
// The reclaim bet: a page fault the kernel *resolves and resumes* rather than
// kills. A ring-3 program writes across a lazy anonymous region never populated
// at map time — each new page demand-faults, is zero-filled and mapped, and the
// write retries transparently (budget B8) — then writes to a copy-on-write page
// the kernel snapshotted, which faults, copies private, and resumes (budget
// B9). None of this terminates the program: it runs to a clean exit. The
// copy-on-write snapshot still holds the pre-write bytes while the writable copy
// holds the new ones — isolation. Proven on hardware; the mock cannot fault.

/// Lazy anonymous region the ring-3 program walks (demand-fill, B8).
const USER_LAZY_VA: u64 = 0x0000_0000_5000_0000;
const USER_LAZY_PAGES: u64 = 4;
/// Copy-on-write region: the kernel writes a pattern, snapshots it, then the
/// program writes it (COW copy, B9). The snapshot keeps the original bytes.
const USER_COW_VA: u64 = 0x0000_0000_6000_0000;
const USER_COW_SNAP_VA: u64 = 0x0000_0000_6100_0000;
/// Bytes: the kernel writes `COW_ORIG`, the program overwrites with `COW_NEW`.
const COW_ORIG: u8 = 0xaa;
const COW_NEW: u8 = 0xbb;
/// This demo's user thread kernel stack (clear of the M6 demo's, still mapped).

/// Page-fault resolutions observed, published by the resolver.
static DP_DEMAND_FILLS: AtomicU64 = AtomicU64::new(0);
static DP_COW_COPIES: AtomicU64 = AtomicU64::new(0);

/// Raw pointer to the boot frame allocator, so the fault resolver (which runs in
/// trap context) can allocate/free frames. `_start` never returns, so the
/// allocator it owns lives for the kernel's lifetime.
static mut RESOLVER_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> = core::ptr::null_mut();

// The ring-3 program. Absolute user VAs (it runs at USER_CODE_VA in its own
// space, and the demo maps the regions at fixed addresses). It writes one byte
// to each lazy page, one byte to the copy-on-write page, then exits cleanly.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global dp_program_start
.global dp_program_end
dp_program_start:
    mov rax, 0x50000000       # USER_LAZY_VA
    mov byte ptr [rax], 1     # page 0 -> demand fault
    add rax, 0x1000
    mov byte ptr [rax], 1     # page 1
    add rax, 0x1000
    mov byte ptr [rax], 1     # page 2
    add rax, 0x1000
    mov byte ptr [rax], 1     # page 3
    mov rax, 0x60000000       # USER_COW_VA
    mov byte ptr [rax], 0xbb  # COW_NEW -> copy-on-write fault
    mov eax, 5                # ProcessExit
    xor edi, edi             # code 0
    syscall
1:
    jmp 1b
dp_program_end:
.text
"#
);

// SAFETY: these name the demand-paging blob's bounds, defined by the global_asm
// block above; the extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    static dp_program_start: u8;
    static dp_program_end: u8;
}

/// The registered page-fault resolver: classifies the #PF against the current
/// process's address space and repairs it (demand-fill or copy-on-write),
/// counting each. Returns `true` if resolved (the instruction is resumed) or
/// `false` for an unresolvable fault (which then contains/panics as before).
fn page_fault_resolver(frame: &mut TrapFrame) -> bool {
    let fault_addr = tessera_karch_x86_64::read_cr2();
    let write = (frame.error_code & 0b10) != 0; // #PF error-code bit 1: write
    // SAFETY: single-core; USER_PROCESS is set before the ring-3 thread runs.
    let process = match unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        Some(process) if !process.is_exited() => process,
        _ => return false,
    };
    // SAFETY: single-core; RESOLVER_FRAMES points at the boot frame allocator,
    // which lives for the kernel's lifetime (`_start` never returns).
    let alloc = match unsafe { RESOLVER_FRAMES.as_mut() } {
        Some(alloc) => alloc,
        None => return false,
    };
    let outcome = process
        .space_mut()
        .resolve_fault(VirtAddr::new(fault_addr), write, alloc);
    match outcome {
        FaultOutcome::Filled => {
            DP_DEMAND_FILLS.fetch_add(1, Ordering::Relaxed);
            true
        }
        FaultOutcome::Copied => {
            DP_COW_COPIES.fetch_add(1, Ordering::Relaxed);
            true
        }
        // Pager-backed: forward a page request to the pager over IPC, block the
        // faulting thread, and resume once it supplies the page (budget B10).
        // `process` is no longer borrowed here — the install happens on the
        // pager thread, which re-borrows USER_PROCESS.
        FaultOutcome::NeedsPageIn { object, offset } => forward_page_in(fault_addr, object, offset),
        // A write to a clean pager page: grant write so the store completes. The
        // pager-pressure harness does the full software dirty accounting in its
        // own scenario drivers; this base resolver serves the read-mostly demo.
        FaultOutcome::WriteToClean { .. } => process
            .space_mut()
            .grant_write(VirtAddr::new(fault_addr))
            .is_ok(),
        FaultOutcome::Unresolvable => false,
    }
}

// --- External-pager page-in wiring ---
//
// A fault on a pager-backed page is forwarded, from trap context, as a request
// over an M5 channel to a pager kernel thread, which supplies the page and hands
// control back. The faulting thread and the pager thread share one `Executive`
// (`EXEC`), so `Executive::call` blocks the faulter and hands off directly to
// the pager — carrying the faulter's priority (budget B10's handoff rule) — and
// resumes it when the pager `reply`s. `supply` is an ownership transfer: the
// pager fills a fresh frame and installs it, no copy through a buffer.

/// The in-kernel pager protocol identifiers (a real ISL schema when the pager
/// becomes a user-space service).
const PAGER_IFACE_ID: u64 = 0x7061_6765_7200_0001;
const METHOD_PAGE_IN: u32 = 1;
const METHOD_SUPPLY_ACK: u32 = 2;
/// Page N of a pager-backed object is filled with the byte `PAGER_CONTENT_BASE
/// + N`, so ring 3 reading a distinct value proves the page came from the pager.
const PAGER_CONTENT_BASE: u64 = 0xc0;

/// The pager channel: `.0` is the fault/client end (the resolver calls on it),
/// `.1` the pager end (the pager thread receives on it). Set once in the demo.
static mut PAGER_ENDPOINTS: Option<(EndpointId, EndpointId)> = None;
/// Page-ins served over IPC (the observability hook; B10 path count).
static PAGER_PAGE_INS: AtomicU64 = AtomicU64::new(0);
/// The in-flight page-in fault (VA, object), stashed by `forward_page_in` before
/// it hands off to the pager, for a ring-3 FS pager's `PageSupply` to resolve
/// (M18). One slot — single in-flight fault (synchronous, single-core). Inert
/// for the in-kernel pager (M12), which reads `USER_PROCESS` directly.
static mut FS_PENDING: Option<(u64, ObjectId)> = None;

/// The pager channel's endpoint ids.
fn pager_endpoints() -> (EndpointId, EndpointId) {
    // SAFETY: single-core; set once in `pager_demo` before the threads run.
    unsafe {
        match (*&raw const PAGER_ENDPOINTS).as_ref() {
            Some(&pair) => pair,
            None => panic!("pager: endpoints uninitialized"),
        }
    }
}

/// Forwards a page-in request to the pager and blocks the faulting thread until
/// it supplies the page. Returns `true` once the page is installed (resume) or
/// `false` if the pager path is unavailable or errors (escalate). Runs as the
/// faulting thread, so `Executive::call` blocks *this* thread.
fn forward_page_in(fault_va: u64, object: ObjectId, offset: u64) -> bool {
    // SAFETY: single-core; PAGER_ENDPOINTS is set before ring 3 runs, `None`
    // (so this returns false) during the earlier demos.
    let endpoints = match unsafe { (*&raw const PAGER_ENDPOINTS).as_ref() } {
        Some(&pair) => pair,
        None => return false,
    };
    // SAFETY: single-core; EXEC holds the faulting + pager threads' scheduler.
    let exec = match unsafe { (*&raw mut EXEC).as_mut() } {
        Some(exec) => exec,
        None => return false,
    };
    // The faulting thread is still current here (the resolver runs in trap
    // context, before `call` blocks it), so this is the cause the request must
    // carry — `call` stamps exactly this onto the header (D60).
    CORRELATION_PAGE_IN_FAULTER.store(kcore::trace::current().correlation, Ordering::Relaxed);
    let mut request = Message::new(MessageHeader::new(PAGER_IFACE_ID, METHOD_PAGE_IN));
    let mut inline = [0u8; 20];
    inline[0..8].copy_from_slice(&fault_va.to_le_bytes());
    inline[8..12].copy_from_slice(&object.raw().to_le_bytes());
    inline[12..20].copy_from_slice(&offset.to_le_bytes());
    if request.set_inline(&inline).is_err() {
        return false;
    }
    // Stash the in-flight fault so a ring-3 FS pager's `PageSupply` can resolve it
    // (M18). Inert for the in-kernel pager, which supplies via `USER_PROCESS`.
    // SAFETY: single-core; one in-flight page-in fault at a time (synchronous).
    unsafe { FS_PENDING = Some((fault_va, object)) };
    // Blocks the faulting thread and hands off to the pager (priority carried);
    // returns when the pager replies with the page already installed.
    let started = read_tsc_serialized();
    match exec.call(endpoints.0, request) {
        Ok(_ack) => {
            PAGER_PAGE_INS.fetch_add(1, Ordering::Relaxed);
            // The structured page-in-latency record: the served count and the
            // perf row are summaries; this is the per-page-in event (D33).
            kcore::event::emit(
                kcore::event::EventKind::PagerPageIn,
                kcore::event::Severity::Info,
                kcore::event::Component::Pager,
                [
                    u64::from(object.raw()),
                    offset,
                    read_tsc_serialized().saturating_sub(started),
                    0,
                ],
            );
            true
        }
        Err(_) => false,
    }
}

/// The in-kernel pager kernel thread: receives page requests, produces the
/// page's content, installs it into the faulting process, and replies (handing
/// control back to the faulter). A RAM-backed reference pager — its content is a
/// per-page byte pattern so provenance is verifiable.
extern "C" fn pager_thread_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_client, pager_ep) = pager_endpoints();
    // First request parks us; thereafter reply-and-wait keeps us parked between
    // the many page-in calls (a bare reply would leave us blocked).
    let mut request = match exec.receive(pager_ep) {
        Ok(request) => request,
        Err(_) => loop {
            core::hint::spin_loop();
        },
    };
    loop {
        let supplied = serve_page_request(&request);
        let mut ack = Message::new(MessageHeader::new(PAGER_IFACE_ID, METHOD_SUPPLY_ACK));
        let _ = ack.set_inline(&[supplied as u8]);
        // Reply hands control back to the faulter and re-parks us for the next
        // request; on a supply failure the ack still returns (the faulter then
        // re-faults or is contained).
        request = match exec.reply_receive(pager_ep, ack) {
            Ok(request) => request,
            Err(_) => loop {
                core::hint::spin_loop();
            },
        };
    }
}

/// Serves one page request: decode the fault VA and object offset, produce the
/// page's content (a per-page byte pattern), and install (`supply`) the frame
/// into the faulting process. Returns whether the page was supplied.
fn serve_page_request(request: &Message) -> bool {
    // The cause the request arrived with — `docs/kernel/03`: "The request carries
    // object ID, page range, fault access type, and a correlation ID". It rides
    // the header, so the pager serves the fault under the faulting thread's cause
    // (D60). Recorded for the `correlation` verdict.
    let arrived = request.header().correlation;
    CORRELATION_PAGE_IN_SERVED.store(arrived, Ordering::Relaxed);
    CORRELATION_PAGE_IN_REQUESTS.fetch_add(1, Ordering::Relaxed);
    if arrived != 0 && arrived == CORRELATION_PAGE_IN_FAULTER.load(Ordering::Relaxed) {
        CORRELATION_PAGE_IN_MATCHED.fetch_add(1, Ordering::Relaxed);
    }
    let inline = request.inline();
    if inline.len() < 20 {
        return false;
    }
    let fault_va = u64::from_le_bytes([
        inline[0], inline[1], inline[2], inline[3], inline[4], inline[5], inline[6], inline[7],
    ]);
    let offset = u64::from_le_bytes([
        inline[12], inline[13], inline[14], inline[15], inline[16], inline[17], inline[18],
        inline[19],
    ]);
    let pattern = (PAGER_CONTENT_BASE + offset / FRAME_SIZE) as u8;
    // SAFETY: single-core; RESOLVER_FRAMES and USER_PROCESS are set before the
    // ring-3 thread runs.
    let (frames, process) =
        match unsafe { (RESOLVER_FRAMES.as_mut(), (*&raw mut USER_PROCESS).as_mut()) } {
            (Some(frames), Some(process)) => (frames, process),
            _ => return false,
        };
    let Some(frame) = frames.alloc() else {
        return false;
    };
    let space = process.space_mut();
    // Produce the page's content, then transfer the frame into the mapping (an
    // ownership move, not a copy).
    space.arch().fill_frame(frame, pattern);
    space
        .supply_page(VirtAddr::new(fault_va), frame, frames)
        .is_ok()
}

// --- M18: RAM-backed filesystem service (a ring-3 service supplies pages) ------

/// Supplies a page-in from a ring-3 service's buffer: fills a fresh frame with
/// `src` (the service's file page, read while the *service's* CR3 is active) and
/// installs it (`supply_page` — ownership transfer, read-only) into the faulting
/// client at `fault_va`. Both the frame fill and `supply_page`'s page-table edit
/// go through the HHDM, so this works even though the service's CR3 is loaded.
/// `src` must be exactly one page. This is the M12 `serve_page_request` supply
/// with its byte-pattern generator replaced by "copy the service's page bytes".
fn fs_supply(
    client_space: &mut AddressSpace<KernelAddressSpace>,
    fault_va: u64,
    src: &[u8],
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> bool {
    if src.len() != FRAME_SIZE as usize {
        return false;
    }
    let Some(frame) = frames.alloc() else {
        return false;
    };
    client_space.arch().write_bytes_to_frame(frame, 0, src);
    client_space
        .supply_page(VirtAddr::new(fault_va), frame, frames)
        .is_ok()
}

/// A static source page (filled with the FS content byte) for the Step-0 supply
/// self-check — stands in for a ring-3 service's file buffer.
static FS_SELFTEST_SRC: [u8; 4096] = [FS_CONTENT_BASE as u8; 4096];
/// Scratch VA for the self-check's pager-backed page — a fixed data-page window
/// (not a kernel stack, so outside `alloc_kstack`'s pool), placed clear of the
/// stack-window region.
const FS_SELFTEST_VA: u64 = 0xffff_c000_5c00_0000;

/// M18 Step 0: prove the supply mechanism in isolation. Map a pager-backed page
/// in the (active) boot kernel space, `fs_supply` a known source page into it,
/// and read it back — validates the copy-to-frame + `supply_page` path the ring-3
/// `PageSupply` syscall will use, before any ring-3 complexity.
fn fs_supply_selftest(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: single-threaded boot; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => return kprintln!("fs: supply FAIL — object: {e:?}"),
    };
    if kernel_vm
        .map_object(
            VirtAddr::new(FS_SELFTEST_VA),
            FRAME_SIZE,
            PageFlags::rw(),
            obj,
            0,
        )
        .is_err()
    {
        return kprintln!("fs: supply FAIL — map_object");
    }
    let supplied = fs_supply(kernel_vm, FS_SELFTEST_VA, &FS_SELFTEST_SRC, frames);
    // The boot kernel space is active, so the supplied read-only page is readable.
    // SAFETY: the page was just supplied (present, read-only) at FS_SELFTEST_VA.
    let byte = unsafe { core::ptr::read_volatile(FS_SELFTEST_VA as *const u8) };
    let pass = supplied && u64::from(byte) == FS_CONTENT_BASE;
    report(&verdict(
        DemoId::FsSupply,
        pass,
        [u64::from(byte), 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("fs: supply FAIL — supplied={supplied} byte={byte:#04x}");
    }
}

/// FS content byte base: page N of the FS "file" holds `FS_CONTENT_BASE + N`,
/// distinct from the in-kernel pager's `PAGER_CONTENT_BASE` (0xc0) so a mix-up
/// fails the content check rather than passing silently.
const FS_CONTENT_BASE: u64 = 0xf0;
/// The FS service's file buffer VA in its own address space (its "page cache").
/// A low-half user VA (< 4 GiB) so the service blob can index it with a 32-bit
/// displacement; clear of the service's code (`0x40_0000`) and stack (`0x7000_0000`).
const FS_BUF_VA: u64 = 0x0000_0000_5000_0000;

/// Pages the ring-3 FS service supplied via `PageSupply` (want `PAGER_OBJ_PAGES`
/// — proves every page-in was served from ring 3).
static FS_SUPPLIED: AtomicU64 = AtomicU64::new(0);
/// Set once a `PageSupply` with an out-of-buffer `src_va` was correctly denied.
static FS_BAD_SRC_DENIED: AtomicBool = AtomicBool::new(false);
/// The FS client's ring-3 exit code (`i32::MIN` = not observed).
static FS_CLIENT_EXIT: AtomicI32 = AtomicI32::new(i32::MIN);

/// Decodes the object offset (bytes 12..20) from a page-in request message.
fn fs_request_offset(request: &Message) -> u64 {
    let inline = request.inline();
    if inline.len() < 20 {
        return 0;
    }
    u64::from_le_bytes([
        inline[12], inline[13], inline[14], inline[15], inline[16], inline[17], inline[18],
        inline[19],
    ])
}

/// `PageServe`: the FS service parks on its endpoint for the next page-in
/// request, then returns the faulting object offset so it can locate the page in
/// its buffer. `exec.receive` parks the service (and switches to the faulter);
/// when the faulter's `forward_page_in` calls, the service resumes here.
fn fs_page_serve(caller_idx: usize, ep_handle: u64) -> i64 {
    let ep = match chan_resolve_endpoint(caller_idx, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    match exec_ref().receive(ep) {
        Ok(request) => encode_result(Ok(fs_request_offset(&request))),
        Err(e) => encode_result(Err(e)),
    }
}

/// `PageSupply`: the FS service supplies the pending page-in from its buffer at
/// `src_va`, then replies-and-waits for the next request (returning its offset).
/// The 4 KiB read of `src_va` happens here — while the *service's* CR3 is active
/// (the M14 discipline) — and `supply_page` installs into the faulting client
/// (`USER_PROCESS`) through the HHDM (no CR3 switch), before the reply hands
/// control back to the faulter.
fn fs_page_supply(caller_idx: usize, ep_handle: u64, src_va: u64) -> i64 {
    let ep = match chan_resolve_endpoint(caller_idx, ep_handle, Rights::READ) {
        Ok(ep) => ep,
        Err(e) => return encode_result(Err(e)),
    };
    // SAFETY: single-core; one in-flight page-in fault (synchronous).
    let (fault_va, _object) = match unsafe { *(&raw const FS_PENDING) } {
        Some(pending) => pending,
        None => return encode_result(Err(KError::Protocol)),
    };
    // Validate the service's source page lies in its own readable mappings.
    // SAFETY: single-core; PROCESSES populated before the ring-3 threads run.
    let src_ok = {
        let processes = unsafe { &mut *&raw mut PROCESSES };
        match processes.process_of_thread(caller_idx) {
            Some(service) => {
                validate_user_range(service.space(), src_va, FRAME_SIZE, false).is_ok()
            }
            None => false,
        }
    };
    let supplied = if src_ok {
        // SAFETY: src_va validated as a 4 KiB user-readable range in the active
        // service space; read-only. Copied into a fresh frame + installed into
        // the faulting client below.
        let src = unsafe { core::slice::from_raw_parts(src_va as *const u8, FRAME_SIZE as usize) };
        // SAFETY: single-core; RESOLVER_FRAMES + USER_PROCESS (the faulting
        // client) are set before the ring-3 threads run.
        let frames = unsafe { RESOLVER_FRAMES.as_mut() };
        let client = unsafe { (*&raw mut USER_PROCESS).as_mut() };
        match (frames, client) {
            (Some(frames), Some(client)) => fs_supply(client.space_mut(), fault_va, src, frames),
            _ => false,
        }
    } else {
        FS_BAD_SRC_DENIED.store(true, Ordering::Relaxed);
        false
    };
    if supplied {
        FS_SUPPLIED.fetch_add(1, Ordering::Relaxed);
    }
    // Reply (the page is installed) and wait for the next request. Every borrow
    // above is dropped before this scheduler handoff.
    let mut ack = Message::new(MessageHeader::new(PAGER_IFACE_ID, METHOD_SUPPLY_ACK));
    let _ = ack.set_inline(&[supplied as u8]);
    match exec_ref().reply_receive(ep, ack) {
        Ok(next) => encode_result(Ok(fs_request_offset(&next))),
        Err(e) => encode_result(Err(e)),
    }
}

/// The FS demo's syscall dispatcher. The FS *service* (in `PROCESSES`) drives
/// `PageServe`/`PageSupply`; the *client* is the faulter (`USER_PROCESS`) and only
/// calls `ProcessExit` (its reads fault and route through the page-fault
/// resolver). `ProcessExit` is therefore always the client.
fn fs_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    USER_RING3_REACHED.store(true, Ordering::Relaxed);
    USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
    let number = match SyscallNumber::from_u64(frame.number) {
        Some(number) => number,
        None => return syscall::ENOSYS,
    };
    match number {
        SyscallNumber::Null => encode_result(Ok(0)),
        SyscallNumber::ProcessExit => {
            // The client (faulter) exits; end the run.
            // SAFETY: single-core; statics set before the ring-3 threads run.
            if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
                process.exit(frame.arg0 as i32);
            }
            FS_CLIENT_EXIT.store(frame.arg0 as i32, Ordering::Relaxed);
            // SAFETY: single-core; EXEC holds this demo's threads' scheduler.
            if let Some(exec) = unsafe { (*&raw mut EXEC).as_mut() } {
                exec.scheduler().yield_to_boot();
            }
            0
        }
        SyscallNumber::PageServe => {
            let Some(caller_idx) = chan_current_index() else {
                return syscall::ENOSYS;
            };
            fs_page_serve(caller_idx, frame.arg0)
        }
        SyscallNumber::PageSupply => {
            let Some(caller_idx) = chan_current_index() else {
                return syscall::ENOSYS;
            };
            fs_page_supply(caller_idx, frame.arg0, frame.arg1)
        }
        _ => syscall::ENOSYS,
    }
}

// The ring-3 FS SERVICE: park for a page-in request (returns the fault offset),
// then supply that page from its buffer (`FS_BUF_VA + offset`) and wait for the
// next — a bare serve/supply loop. Endpoint handle raw 0.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global m18_fs_service_program_start
.global m18_fs_service_program_end
m18_fs_service_program_start:
    xor edi, edi                       # arg0 = endpoint handle (raw 0)
    mov eax, 21                        # PageServe -> rax = fault offset
    syscall
    # Negative probe: one deliberately out-of-buffer supply — the kernel denies
    # it (the range is enforced), the faulter re-faults, then we serve it for real.
    mov rsi, 0x60000000                # outside the buffer at FS_BUF_VA (0x50000000)
    xor edi, edi                       # arg0 = endpoint handle (raw 0)
    mov eax, 22                        # PageSupply(bad) -> denied; rax = retried offset
    syscall
1:
    mov rsi, rax                       # arg1 = offset ...
    add rsi, 0x50000000                # ... + FS_BUF_VA = source page VA
    xor edi, edi                       # arg0 = endpoint handle (raw 0)
    mov eax, 22                        # PageSupply(ep, src) -> rax = next offset
    syscall
    jmp 1b
m18_fs_service_program_end:
.text
"#
);

// SAFETY: names the FS-service blob's bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static m18_fs_service_program_start: u8;
    static m18_fs_service_program_end: u8;
}

/// M18: the RAM-backed filesystem service. A ring-3 client maps a pager-backed
/// memory object and reads it; each page fault drives the existing external-pager
/// handoff (`forward_page_in`→`exec.call`) to a ring-3 **FS service**, which
/// supplies the page from its own RAM buffer via `PageServe`/`PageSupply`. The
/// external-pager bet, end to end, with the pager in ring 3.
fn fs_service_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    set_page_fault_resolver(page_fault_resolver);
    // SAFETY: one-shot registration before this demo's ring-3 threads run.
    unsafe { set_syscall_handler(fs_syscall_handler) };
    set_user_fault_handler(pager_user_fault_handler);
    FS_SUPPLIED.store(0, Ordering::Relaxed);
    FS_BAD_SRC_DENIED.store(false, Ordering::Relaxed);
    FS_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    PAGER_PAGE_INS.store(0, Ordering::Relaxed);

    // One executive holds the service + the faulting client, so the page-in
    // `call` blocks the faulter and hands off directly to the service.
    // SAFETY: single-threaded boot; fresh executive + process table for the demo.
    unsafe {
        EXEC = Some(Executive::new(1, 0));
        PROCESSES = ProcessTable::new();
    }
    let (client_ep, service_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("fs: FAIL — channel create: {e:?}"),
    };
    // SAFETY: single-threaded boot; set once before the threads run.
    unsafe { PAGER_ENDPOINTS = Some((client_ep, service_ep)) };
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let service_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("fs: FAIL — endpoint object: {e:?}"),
    };
    exec_ref().bind_endpoint_object(service_ep, service_ep_obj);
    let mem_obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => return kprintln!("fs: FAIL — memory object: {e:?}"),
    };

    // The FS SERVICE, built (and scheduled) first so it parks in `PageServe`
    // before the client faults. Its file buffer is mapped rw and pre-filled with
    // `FS_CONTENT_BASE+N` per page, under its own (now-active) CR3.
    let sblob = &raw const m18_fs_service_program_start as *const u8;
    let slen = (&raw const m18_fs_service_program_end as usize)
        - (&raw const m18_fs_service_program_start as usize);
    let (mut service, _stidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        sblob,
        slen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_f5_5e_e001),
        0,
    );
    if service
        .space_mut()
        .map_anonymous(
            VirtAddr::new(FS_BUF_VA),
            PAGER_OBJ_PAGES * FRAME_SIZE,
            PageFlags::rw().user(),
            frames,
        )
        .is_err()
    {
        return kprintln!("fs: FAIL — map service buffer");
    }
    for n in 0..PAGER_OBJ_PAGES {
        // SAFETY: the service space is active (chan_build_process left it so); the
        // buffer page was just mapped writable in it. Fill the first byte (the
        // client reads one byte per page).
        unsafe { *((FS_BUF_VA + n * FRAME_SIZE) as *mut u8) = (FS_CONTENT_BASE + n) as u8 };
    }
    if service
        .handles_mut()
        .install(service_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("fs: FAIL — install service endpoint");
    }

    // The CLIENT (the faulter = `USER_PROCESS`), built second. Reuses the M12
    // pager client blob; its pager-backed region is the memory object.
    let cblob = &raw const pager_program_start as *const u8;
    let clen = (&raw const pager_program_end as usize) - (&raw const pager_program_start as usize);
    let (mut client, _ctidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        cblob,
        clen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        ThreadId(0x_c113_e018),
        0,
    );
    if client
        .space_mut()
        .map_object(
            VirtAddr::new(PAGER_OBJ_VA),
            PAGER_OBJ_PAGES * FRAME_SIZE,
            PageFlags::rw().user(),
            mem_obj,
            0,
        )
        .is_err()
    {
        return kprintln!("fs: FAIL — map_object client region");
    }

    // Re-activate the service (first-run) space; publish the service into the
    // process table (handler resolves it there) and the client as `USER_PROCESS`
    // (the resolver's faulter). `RESOLVER_FRAMES` for the supply path.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { service.space().activate(Cpu::cpu_id()) };
    service.set_running();
    client.set_running();
    if processes_insert(service).is_err() {
        return kprintln!("fs: FAIL — insert service process");
    }
    // SAFETY: single-threaded boot; publishing the faulting client + allocator.
    unsafe {
        USER_PROCESS = Some(client);
        RESOLVER_FRAMES = core::ptr::from_mut(frames);
    }

    exec_ref().run();

    // Back on boot with the client CR3 active (it ran last): verify each page
    // holds the FS service's content before restoring the kernel space.
    let mut content_ok = true;
    for i in 0..PAGER_OBJ_PAGES {
        // SAFETY: the page is resident (supplied) and user-readable from ring 0.
        let byte =
            unsafe { core::ptr::read_volatile((PAGER_OBJ_VA + i * FRAME_SIZE) as *const u8) };
        if u64::from(byte) != FS_CONTENT_BASE + i {
            content_ok = false;
        }
    }
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let page_ins = PAGER_PAGE_INS.load(Ordering::Relaxed);
    let supplied = FS_SUPPLIED.load(Ordering::Relaxed);
    let client_exit = FS_CLIENT_EXIT.load(Ordering::Relaxed);
    let bad_denied = FS_BAD_SRC_DENIED.load(Ordering::Relaxed);
    // SAFETY: single-threaded boot; the objects table is quiescent post-run.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let obj_conserved = objects.is_live(mem_obj) && objects.refcount(mem_obj) == Some(1);
    // One extra page-in: the out-of-buffer probe was denied, so page 0 re-faulted
    // once before being served for real. `supplied` counts only the good supplies.
    let pass = content_ok
        && page_ins == PAGER_OBJ_PAGES + 1
        && supplied == PAGER_OBJ_PAGES
        && client_exit == 0
        && obj_conserved
        && bad_denied;
    report(&verdict(
        DemoId::FsService,
        pass,
        [supplied, FS_CONTENT_BASE, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "fs: FAIL — content_ok={content_ok} page_ins={page_ins} supplied={supplied} client_exit={client_exit} bad_denied={bad_denied} obj_conserved={obj_conserved}"
        );
    }
}

/// Builds a ring-3 process with a lazy anonymous region and a copy-on-write
/// snapshot, runs it, and asserts every fault resolved-and-resumed (the program
/// exited cleanly) with copy-on-write isolation intact.
fn demand_paging_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // Resolvable faults route to the resolver; unresolvable ones still contain.
    set_page_fault_resolver(page_fault_resolver);
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(user_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("demand-paging demo: new_user failed: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, alloc_asid(), 1u64 << Cpu::cpu_id());

    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => panic!("demand-paging demo: process object failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    let user = PageFlags::rw().user();
    // Code page (writable to copy the program in; locked to rx afterwards).
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
    {
        panic!("demand-paging demo: map code failed: {e:?}");
    }
    // The lazy region — reserved, populated on fault.
    if let Err(e) = process.space_mut().map_anonymous_demand(
        VirtAddr::new(USER_LAZY_VA),
        USER_LAZY_PAGES * FRAME_SIZE,
        user,
    ) {
        panic!("demand-paging demo: reserve lazy region failed: {e:?}");
    }
    // The copy-on-write source — eagerly mapped so the kernel can seed it.
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_COW_VA), FRAME_SIZE, user, frames)
    {
        panic!("demand-paging demo: map COW region failed: {e:?}");
    }

    let thread = match Thread::<ContextSwitch>::spawn_user(
        ThreadId(0x0d_9000),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("demand-paging demo: spawn_user failed: {e:?}"),
    };
    // SAFETY: single-threaded boot; re-initializing the demo scheduler.
    unsafe { USER_SCHEDULER = Some(Scheduler::new(1, 0)) };
    let thread_idx = match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => match scheduler.add_thread(thread) {
            Ok(idx) => idx,
            Err(e) => panic!("demand-paging demo: scheduler full: {e:?}"),
        },
        None => panic!("demand-paging demo: scheduler uninitialized"),
    };
    if process.add_thread(thread_idx).is_err() {
        panic!("demand-paging demo: process thread set full");
    }

    // Activate the user space, copy the program in, lock it to rx, seed the
    // copy-on-write page, and snapshot it.
    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    let code_src = &raw const dp_program_start as *const u8;
    let code_bytes = (&raw const dp_program_end as usize) - (&raw const dp_program_start as usize);
    // SAFETY: [dp_program_start, dp_program_end) is the assembled ring-3 blob in
    // kernel rodata; USER_CODE_VA is a writable user page with room for it.
    unsafe {
        core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes);
    }
    if let Err(e) = process.space_mut().protect_range(
        VirtAddr::new(USER_CODE_VA),
        code_len,
        PageFlags::rx().user(),
    ) {
        panic!("demand-paging demo: protect code failed: {e:?}");
    }
    // Seed the copy-on-write page and snapshot it (both sides now share it RO).
    // SAFETY: the COW page is mapped writable and user-accessible in the active
    // space; a single-byte write is in bounds.
    unsafe { core::ptr::write_volatile(USER_COW_VA as *mut u8, COW_ORIG) };
    if let Err(e) = process.space_mut().snapshot_cow(
        VirtAddr::new(USER_COW_VA),
        VirtAddr::new(USER_COW_SNAP_VA),
        FRAME_SIZE,
        frames,
    ) {
        panic!("demand-paging demo: snapshot_cow failed: {e:?}");
    }

    // Wire the resolver's allocator and publish the process, then run.
    // SAFETY: `frames` lives for the kernel's lifetime (`_start` never returns).
    unsafe { RESOLVER_FRAMES = core::ptr::from_mut(frames) };
    // SAFETY: single-threaded boot; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }

    kprintln!("dpage: entering ring 3; lazy region + COW snapshot armed");
    // SAFETY: single-core boot path; USER_SCHEDULER was initialized above.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.run(),
        None => panic!("demand-paging demo: scheduler uninitialized"),
    }

    // Back on boot, user CR3 still active: read the two copy-on-write pages
    // before restoring the kernel space.
    // SAFETY: the pages are present and user-readable from ring 0; single byte.
    let cow_byte = unsafe { core::ptr::read_volatile(USER_COW_VA as *const u8) };
    // SAFETY: as above.
    let snap_byte = unsafe { core::ptr::read_volatile(USER_COW_SNAP_VA as *const u8) };
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    // Assert the bet held.
    let clean_exit = matches!(
        // SAFETY: single-core boot path; only this CPU touches USER_PROCESS.
        unsafe { (*&raw const USER_PROCESS).as_ref() }.map(Process::state),
        Some(ProcessState::Exited(0))
    );
    let fills = DP_DEMAND_FILLS.load(Ordering::Relaxed);
    let copies = DP_COW_COPIES.load(Ordering::Relaxed);
    if !clean_exit {
        panic!("demand-paging demo: program did not exit cleanly (a fault was not resolved)");
    }
    if fills != USER_LAZY_PAGES {
        panic!("demand-paging demo: {fills} demand-fills, expected {USER_LAZY_PAGES}");
    }
    if copies != 1 {
        panic!("demand-paging demo: {copies} COW copies, expected 1");
    }
    if cow_byte != COW_NEW {
        panic!("demand-paging demo: COW page is {cow_byte:#x}, expected {COW_NEW:#x}");
    }
    if snap_byte != COW_ORIG {
        panic!(
            "demand-paging demo: snapshot is {snap_byte:#x}, expected {COW_ORIG:#x} (isolation)"
        );
    }
    if frames.reclaim_overflows() != 0 {
        panic!("demand-paging demo: frame reclaim overflowed");
    }

    kprintln!(
        "dpage: {fills} demand-fills + {copies} COW copy resolved-and-resumed; program exited clean",
    );
    kprintln!(
        "dpage: COW isolation held (write {COW_NEW:#x} private; snapshot still {COW_ORIG:#x})"
    );
}

// --- External-pager page-in demonstration ---
//
// The pager bet: a fault on service-backed memory served by a pager over IPC. A
// ring-3 program reads across a region backed by a memory object; each page is
// not resident, so the fault is forwarded (from trap context, as the faulting
// thread) over an M5 channel to a pager kernel thread, which supplies a page and
// hands control back — the read then resumes transparently. The pager fills each
// page with a distinct byte so the demo proves the content came from the pager,
// not a zero fill. Boot-proven; the mock has no ring transition or scheduler
// switch to exercise this.

/// The M8 user thread's kernel stack and the pager thread's kernel stack (in the
/// shared kernel VMAP slot, clear of the earlier demos' stacks).
/// The object-backed (pager) region the ring-3 program reads.
const PAGER_OBJ_VA: u64 = 0x0000_0000_8000_0000;
const PAGER_OBJ_PAGES: u64 = 4;

// The ring-3 program: read one byte from each page of the object-backed region
// (each read faults and is served by the pager), then exit clean.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global pager_program_start
.global pager_program_end
pager_program_start:
    mov rax, 0x80000000       # PAGER_OBJ_VA
    mov bl, [rax]             # page 0 read -> #PF -> page-in
    add rax, 0x1000
    mov bl, [rax]             # page 1
    add rax, 0x1000
    mov bl, [rax]             # page 2
    add rax, 0x1000
    mov bl, [rax]             # page 3
    mov eax, 5                # ProcessExit
    xor edi, edi
    syscall
1:
    jmp 1b
pager_program_end:
.text
"#
);

// SAFETY: these name the pager blob's bounds, defined by the global_asm block
// above; the extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    static pager_program_start: u8;
    static pager_program_end: u8;
}

/// The M8 syscall handler: the program's only syscall is `ProcessExit`, which
/// yields the shared `EXEC` scheduler (the M8 user thread runs there, not in
/// `USER_SCHEDULER`).
fn pager_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    match SyscallNumber::from_u64(frame.number) {
        Some(SyscallNumber::ProcessExit) => {
            // SAFETY: single-core; statics set before the ring-3 thread runs.
            if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
                process.exit(frame.arg0 as i32);
            }
            // SAFETY: single-core; EXEC holds the M8 threads' scheduler.
            if let Some(exec) = unsafe { (*&raw mut EXEC).as_mut() } {
                exec.scheduler().yield_to_boot();
            }
            0
        }
        _ => syscall::ENOSYS,
    }
}

/// The M8 ring-3 fault handler: contains a genuine (non-resolvable) fault by
/// terminating the process and yielding the `EXEC` scheduler. Resolvable pager
/// faults never reach here — the resolver forwards and resumes them.
fn pager_user_fault_handler(frame: &TrapFrame) -> ! {
    USER_FAULT_CONTAINED.store(true, Ordering::Relaxed);
    USER_FAULT_VECTOR.store(frame.vector, Ordering::Relaxed);
    // SAFETY: single-core; statics set before the ring-3 thread runs.
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.exit(-1);
    }
    // SAFETY: single-core; EXEC holds the M8 threads' scheduler.
    match unsafe { (*&raw mut EXEC).as_mut() } {
        Some(exec) => exec.scheduler().yield_to_boot(),
        None => DebugExit::exit(ExitCode::Failure),
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Sets up a pager kernel thread and a ring-3 process with a pager-backed
/// region in one `Executive`, runs it, and asserts every object-backed read was
/// served by the pager over IPC with the pager's content delivered to ring 3.
fn pager_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    set_page_fault_resolver(page_fault_resolver);
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(pager_syscall_handler) };
    set_user_fault_handler(pager_user_fault_handler);

    // One executive holds both the pager thread and the ring-3 thread, so the
    // page-in `call` blocks the faulter and hands off directly to the pager.
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();
    let (client_ep, pager_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(e) => panic!("pager demo: channel create failed: {e:?}"),
    };
    // SAFETY: single-threaded boot; set once before the threads run.
    unsafe { PAGER_ENDPOINTS = Some((client_ep, pager_ep)) };

    // Pager thread first, so it parks in `receive` and the faulter's `call`
    // hands off directly to it.
    let pager_thread = match Thread::<ContextSwitch>::spawn(
        ThreadId(0x_9a_6e),
        pager_thread_entry,
        0,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("pager demo: pager thread spawn failed: {e:?}"),
    };
    if exec.add_thread(pager_thread).is_err() {
        panic!("pager demo: scheduler full (pager)");
    }

    // The ring-3 process with a pager-backed region.
    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("pager demo: new_user failed: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, alloc_asid(), 1u64 << Cpu::cpu_id());
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => panic!("pager demo: process object failed: {e:?}"),
    };
    let mem_obj = match objects.create(ObjectType::Memory) {
        Ok(id) => id,
        Err(e) => panic!("pager demo: memory object failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    let user = PageFlags::rw().user();
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
    {
        panic!("pager demo: map code failed: {e:?}");
    }
    // The pager-backed region — nothing resident; pages arrive via `supply`.
    if let Err(e) = process.space_mut().map_object(
        VirtAddr::new(PAGER_OBJ_VA),
        PAGER_OBJ_PAGES * FRAME_SIZE,
        user,
        mem_obj,
        0,
    ) {
        panic!("pager demo: map_object failed: {e:?}");
    }

    let user_thread = match Thread::<ContextSwitch>::spawn_user(
        ThreadId(0x_9a_e2),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("pager demo: spawn_user failed: {e:?}"),
    };
    let user_idx = match exec.add_thread(user_thread) {
        Ok(idx) => idx,
        Err(e) => panic!("pager demo: scheduler full (user): {e:?}"),
    };
    if process.add_thread(user_idx).is_err() {
        panic!("pager demo: process thread set full");
    }

    // Activate the user space, copy the program in, lock it to rx.
    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    let code_src = &raw const pager_program_start as *const u8;
    let code_bytes =
        (&raw const pager_program_end as usize) - (&raw const pager_program_start as usize);
    // SAFETY: [pager_program_start, pager_program_end) is the assembled ring-3
    // blob in kernel rodata; USER_CODE_VA is a writable user page with room.
    unsafe {
        core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes);
    }
    if let Err(e) = process.space_mut().protect_range(
        VirtAddr::new(USER_CODE_VA),
        code_len,
        PageFlags::rx().user(),
    ) {
        panic!("pager demo: protect code failed: {e:?}");
    }

    // Publish the process + frame allocator for the resolver and pager thread.
    // SAFETY: single-threaded boot; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }
    // SAFETY: `frames` lives for the kernel's lifetime (`_start` never returns).
    unsafe { RESOLVER_FRAMES = core::ptr::from_mut(frames) };

    kprintln!("pager: entering ring 3; {PAGER_OBJ_PAGES} pager-backed pages armed");
    exec.run();

    // Back on boot, user CR3 still active: verify each page holds the pager's
    // distinct content before restoring the kernel space.
    let mut content_ok = true;
    for i in 0..PAGER_OBJ_PAGES {
        // SAFETY: the page is resident (supplied) and user-readable from ring 0.
        let byte =
            unsafe { core::ptr::read_volatile((PAGER_OBJ_VA + i * FRAME_SIZE) as *const u8) };
        if byte != (PAGER_CONTENT_BASE + i) as u8 {
            content_ok = false;
        }
    }
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let page_ins = PAGER_PAGE_INS.load(Ordering::Relaxed);
    let clean_exit = matches!(
        // SAFETY: single-core boot path; only this CPU touches USER_PROCESS.
        unsafe { (*&raw const USER_PROCESS).as_ref() }.map(Process::state),
        Some(ProcessState::Exited(0))
    );
    if !clean_exit {
        panic!("pager demo: program did not exit cleanly (a page-in failed)");
    }
    if page_ins != PAGER_OBJ_PAGES {
        panic!("pager demo: {page_ins} page-ins served, expected {PAGER_OBJ_PAGES}");
    }
    if !content_ok {
        panic!("pager demo: a page did not hold the pager's content");
    }

    kprintln!(
        "pager: {page_ins} object-backed pages served by the pager over IPC (priority inherited)"
    );
    kprintln!("pager: ring 3 read the pager's content back; program exited clean");
}

// --- Performance microbenchmark harness (docs/prototypes/01) ---
//
// Measures the primitives M2–M8 built — B1 syscall, B2 handle op, B3 IPC round
// trip, B7 context switch, B8 anon fault, B9 COW fault, B10 pager page-in —
// with serialized invariant-TSC timing and EXACT percentiles from the sorted
// sample set (never a streaming estimator). Per the harness spec, "QEMU/KVM
// runs validate harness correctness only; budget compliance is judged
// exclusively on bare-metal R1" — so these numbers validate the rig and catch
// regressions, but the R1 gate is bare-metal (build/README.md, D34). A budget
// miss is never a boot failure: the harness always reports and returns.

/// Measured samples per benchmark (reduced from the 1M mandate for boot-time
/// feasibility, D35); enough for stable p50/p90/p99.
const PERF_SAMPLES: usize = 1024;
/// Untimed warm-up iterations before measuring (warms I-cache / predictors).
const PERF_WARMUP: usize = 64;

/// Shared sample buffer — one benchmark runs at a time on the boot CPU.
static mut PERF_BUF: [u64; PERF_SAMPLES] = [0; PERF_SAMPLES];
/// A scratch handle table for the B2 benchmark.
static mut PERF_HANDLES: HandleTable = HandleTable::new();

/// Computes and prints one benchmark's statistics (in TSC cycles).
fn perf_report(name: &str, samples: &mut [u64]) {
    match Stats::from_samples(samples) {
        Some(s) => kprintln!(
            "perf: {name:<16} n={} p50={} p90={} p99={} max={} mean={}",
            s.count,
            s.p50,
            s.p90,
            s.p99,
            s.max,
            s.mean,
        ),
        None => kprintln!("perf: {name:<16} no samples"),
    }
}

/// B2 — handle object operation: query the rights of a handle (a handle-table
/// lookup + rights read), the repeatable read-only form of BM-2.
fn perf_bench_handle_op() {
    // SAFETY: single-threaded boot; these statics are used only here, and
    // OBJECTS/PERF_HANDLES are not concurrently accessed.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let handles = unsafe { &mut *&raw mut PERF_HANDLES };
    let buf = unsafe { &mut *&raw mut PERF_BUF };

    let handle = match objects
        .create(ObjectType::Test)
        .and_then(|object| handles.insert(object, Rights::all_core()))
    {
        Ok(handle) => handle,
        Err(_) => return perf_report("B2 handle-op", &mut []),
    };
    for _ in 0..PERF_WARMUP {
        let _ = core::hint::black_box(handles.rights(handle));
    }
    for slot in buf.iter_mut() {
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(handles.rights(handle));
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start);
    }
    perf_report("B2 handle-op", buf);
}

/// B8 — anonymous zero-fill page fault: time `resolve_fault` demand-filling a
/// fresh lazy page each iteration (one frame per fault).
fn perf_bench_anon_fault(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const BASE: u64 = 0x0000_0000_1000_0000;
    let arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(_) => return perf_report("B8 anon-fault", &mut []),
    };
    let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
    let pages = (PERF_WARMUP + PERF_SAMPLES) as u64;
    if space
        .map_anonymous_demand(
            VirtAddr::new(BASE),
            pages * FRAME_SIZE,
            PageFlags::rw().user(),
        )
        .is_err()
    {
        return perf_report("B8 anon-fault", &mut []);
    }
    // `resolve_fault` edits the scratch space's tables through the direct map,
    // so it needs no CR3 switch. Each page is distinct (a lazy fault fills once).
    let mut warm = 0u64;
    for i in 0..pages {
        let va = VirtAddr::new(BASE + i * FRAME_SIZE);
        if i < PERF_WARMUP as u64 {
            let _ = space.resolve_fault(va, false, frames);
            warm = warm.wrapping_add(1);
            continue;
        }
        let slot = (i - PERF_WARMUP as u64) as usize;
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(space.resolve_fault(va, false, frames));
        let end = read_tsc_serialized();
        // SAFETY: single-threaded boot; PERF_BUF used only here.
        unsafe { (*&raw mut PERF_BUF)[slot] = end.wrapping_sub(start) };
    }
    let _ = warm;
    // SAFETY: single-threaded boot; PERF_BUF used only here.
    perf_report("B8 anon-fault", unsafe { &mut *&raw mut PERF_BUF });
}

/// B9 — copy-on-write fault: snapshot an eager region, then time `resolve_fault`
/// copying a shared page private on each write (one frame per copy).
fn perf_bench_cow_fault(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const SRC: u64 = 0x0000_0000_2000_0000;
    const DST: u64 = 0x0000_0000_3000_0000;
    let arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(_) => return perf_report("B9 cow-fault", &mut []),
    };
    let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
    let pages = (PERF_WARMUP + PERF_SAMPLES) as u64;
    let len = pages * FRAME_SIZE;
    let rights = PageFlags::rw().user();
    if space
        .map_anonymous(VirtAddr::new(SRC), len, rights, frames)
        .and_then(|()| space.snapshot_cow(VirtAddr::new(SRC), VirtAddr::new(DST), len, frames))
        .is_err()
    {
        return perf_report("B9 cow-fault", &mut []);
    }
    for i in 0..pages {
        let va = VirtAddr::new(SRC + i * FRAME_SIZE);
        if i < PERF_WARMUP as u64 {
            let _ = space.resolve_fault(va, true, frames);
            continue;
        }
        let slot = (i - PERF_WARMUP as u64) as usize;
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(space.resolve_fault(va, true, frames));
        let end = read_tsc_serialized();
        // SAFETY: single-threaded boot; PERF_BUF used only here.
        unsafe { (*&raw mut PERF_BUF)[slot] = end.wrapping_sub(start) };
    }
    // SAFETY: single-threaded boot; PERF_BUF used only here.
    perf_report("B9 cow-fault", unsafe { &mut *&raw mut PERF_BUF });
}

/// One page-in under a resident cap (the pager-pressure page-in path): if the
/// object cache is at the cap, evict a clean page first (unmap + free), then
/// alloc, fill, and supply the requested page. This is the work whose latency
/// B10 must hold under pressure (`docs/prototypes/02` S1).
fn perf_page_in_once(
    space: &mut AddressSpace<KernelAddressSpace>,
    base: u64,
    cache: &mut ObjectCache,
    offset: u64,
    cap: u32,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // Under pressure (at the cap), reclaim a clean page before bringing one in.
    if cache.resident_count() as u32 >= cap
        && let Some(evict_off) = cache.evict_candidate()
    {
        let _ = space.evict_page(VirtAddr::new(base + evict_off), frames);
        cache.forget(evict_off);
    }
    if let Some(frame) = frames.alloc() {
        let pattern = (0xc0 + (offset / FRAME_SIZE)) as u8;
        space.arch().fill_frame(frame, pattern);
        if space
            .supply_page(VirtAddr::new(base + offset), frame, frames)
            .is_ok()
        {
            let _ = cache.install(offset);
        }
    }
}

/// B10 (S1) — external-pager page-in latency **under pressure**. Times the
/// page-in path at ~50/90/99 % frame utilization: a resident cap models the
/// utilization level, so at high utilization every page-in must first evict a
/// clean page (docs/prototypes/02, "Page-In Latency Under Pressure" — the point
/// is the shape of the curve, no cliff). Kernel-side timing (the IPC handoff is
/// measured by B3); QEMU numbers are correctness/regression only (D34/D41).
fn perf_bench_page_in(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const BASE: u64 = 0x0000_0000_4000_0000;
    // "Physical memory" for the bench, in pages; utilization sets the resident cap.
    const CAPACITY: u32 = MAX_CACHED_PAGES as u32;
    let mut p50s = [0u64; 3];
    for (level, (util, name)) in [
        (50u32, "B10 page-in/50%"),
        (90, "B10 page-in/90%"),
        (99, "B10 page-in/99%"),
    ]
    .into_iter()
    .enumerate()
    {
        let cap = (CAPACITY * util / 100).max(1);
        let arch = match kernel_vm.arch().new_user(frames) {
            Ok(arch) => arch,
            Err(_) => {
                perf_report(name, &mut []);
                continue;
            }
        };
        let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
        let object = ObjectId::from_raw(0x0b10_0000);
        let total = cap as u64 + (PERF_WARMUP + PERF_SAMPLES) as u64 + 1;
        if space
            .map_object(
                VirtAddr::new(BASE),
                total * FRAME_SIZE,
                PageFlags::rw().user(),
                object,
                0,
            )
            .is_err()
        {
            perf_report(name, &mut []);
            continue;
        }
        let mut cache = ObjectCache::new(CAPACITY);
        // Fill memory to the utilization cap (the resident working set).
        for off in 0..cap as u64 {
            perf_page_in_once(&mut space, BASE, &mut cache, off, cap, frames);
        }
        // Time page-ins of successive fresh pages: at the cap each evicts the
        // oldest clean page first (a sliding resident window).
        let mut next = cap as u64;
        for i in 0..(PERF_WARMUP + PERF_SAMPLES) as u64 {
            if (i as usize) < PERF_WARMUP {
                perf_page_in_once(&mut space, BASE, &mut cache, next, cap, frames);
                next += 1;
                continue;
            }
            let slot = i as usize - PERF_WARMUP;
            let start = read_tsc_serialized();
            perf_page_in_once(&mut space, BASE, &mut cache, next, cap, frames);
            let end = read_tsc_serialized();
            // SAFETY: single-threaded boot; PERF_BUF used only here.
            unsafe { (*&raw mut PERF_BUF)[slot] = end.wrapping_sub(start) };
            next += 1;
        }
        // SAFETY: single-threaded boot; PERF_BUF used only here.
        let buf = unsafe { &mut *&raw mut PERF_BUF };
        p50s[level] = match Stats::from_samples(buf) {
            Some(s) => {
                kprintln!(
                    "perf: {name:<16} n={} p50={} p90={} p99={} max={} mean={}",
                    s.count,
                    s.p50,
                    s.p90,
                    s.p99,
                    s.max,
                    s.mean,
                );
                s.p50
            }
            None => {
                kprintln!("perf: {name:<16} no samples");
                0
            }
        };
    }
    // S1 pass shape: page-in latency must not *cliff* as utilization rises —
    // graceful degradation within budget is fine (docs/prototypes/02 S1).
    let lo = p50s.iter().copied().min().unwrap_or(0).max(1);
    let hi = p50s.iter().copied().max().unwrap_or(0);
    kprintln!(
        "perf: B10 validity: page-in p50 {lo}..{hi} across 50/90/99% util ({})",
        if hi <= lo * 2 {
            "no cliff, graceful"
        } else {
            "CLIFF"
        }
    );
}

/// Perf-harness kernel stacks: distinct slots in the VMAP region (clear of the
/// demos' stacks), since each benchmark's abandoned threads keep their mappings.
const PERF_KSTACK_PAGES: u64 = 4;
const PERF_IFACE_ID: u64 = 0x7065_7266_0000_0001;

/// The base of perf-harness kernel-stack slot `i` (slots 0..=8). A contiguous
/// block is reserved from the window allocator on first use; slot `i` is stable.
fn perf_kstack(i: u64) -> u64 {
    static BASE: AtomicU64 = AtomicU64::new(0);
    let mut base = BASE.load(Ordering::Relaxed);
    if base == 0 {
        base = reserve_kstack_block(9);
        BASE.store(base, Ordering::Relaxed);
    }
    base + i * KSTACK_WINDOW_SLOT
}

/// The B3 benchmark channel (`.0` client, `.1` server) and its switch count.
static mut PERF_ENDPOINTS: Option<(EndpointId, EndpointId)> = None;
static PERF_B3_SWITCHES: AtomicU64 = AtomicU64::new(0);

fn perf_endpoints() -> (EndpointId, EndpointId) {
    // SAFETY: single-core; set once in perf_bench_ipc before the threads run.
    unsafe {
        match (*&raw const PERF_ENDPOINTS).as_ref() {
            Some(&pair) => pair,
            None => panic!("perf: endpoints uninitialized"),
        }
    }
}

/// B3 server: park, then reply-and-wait forever (echoes an empty ack).
extern "C" fn perf_b3_server_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_client, server_ep) = perf_endpoints();
    let mut request = match exec.receive(server_ep) {
        Ok(request) => request,
        Err(_) => loop {
            core::hint::spin_loop();
        },
    };
    loop {
        let _ = &request;
        let reply = Message::new(MessageHeader::new(PERF_IFACE_ID, 2));
        request = match exec.reply_receive(server_ep, reply) {
            Ok(request) => request,
            Err(_) => loop {
                core::hint::spin_loop();
            },
        };
    }
}

/// B3 client: time each synchronous `call` round trip, record the switch count
/// for the two-switches-per-round-trip validity check, then hand back to boot.
extern "C" fn perf_b3_client_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (client_ep, _server) = perf_endpoints();
    for _ in 0..PERF_WARMUP {
        let _ = exec.call(
            client_ep,
            Message::new(MessageHeader::new(PERF_IFACE_ID, 1)),
        );
    }
    let before = exec.switch_count();
    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    for slot in buf.iter_mut() {
        let request = Message::new(MessageHeader::new(PERF_IFACE_ID, 1));
        let start = read_tsc_serialized();
        let _ = core::hint::black_box(exec.call(client_ep, request));
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start);
    }
    PERF_B3_SWITCHES.store(exec.switch_count() - before, Ordering::Relaxed);
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B3 — same-core synchronous IPC round trip. A client/server pair in one
/// executive; the client times each `call`. Also asserts the round trip is
/// exactly two context switches (the BM-3 handoff validity check).
fn perf_bench_ipc(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();
    let (client_ep, server_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(_) => return perf_report("B3 ipc-rtt", &mut []),
    };
    // SAFETY: single-threaded boot; set once before the threads run.
    unsafe { PERF_ENDPOINTS = Some((client_ep, server_ep)) };

    // Server first so it parks and the client's `call` hands off directly to it.
    for (entry, kstack) in [
        (
            perf_b3_server_entry as extern "C" fn(usize) -> !,
            perf_kstack(0),
        ),
        (
            perf_b3_client_entry as extern "C" fn(usize) -> !,
            perf_kstack(1),
        ),
    ] {
        let thread = match Thread::<ContextSwitch>::spawn(
            ThreadId(0x_b3_0000 + kstack),
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        ) {
            Ok(thread) => thread,
            Err(_) => return perf_report("B3 ipc-rtt", &mut []),
        };
        if exec.add_thread(thread).is_err() {
            return perf_report("B3 ipc-rtt", &mut []);
        }
    }
    exec.run();

    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    perf_report("B3 ipc-rtt", unsafe { &mut *&raw mut PERF_BUF });
    let switches = PERF_B3_SWITCHES.load(Ordering::Relaxed);
    let expected = 2 * PERF_SAMPLES as u64;
    kprintln!(
        "perf: B3 validity: {switches} switches for {PERF_SAMPLES} round trips (want {expected}, 2/trip) {}",
        if switches == expected {
            "OK"
        } else {
            "MISMATCH"
        }
    );
}

/// The submission timestamp the B11 client writes just before each `call`; the
/// server reads it when the request becomes visible.
static PERF_B11_SUBMIT: AtomicU64 = AtomicU64::new(0);
/// The B11 sample index (advanced by the server as each request is received).
static PERF_B11_IDX: AtomicUsize = AtomicUsize::new(0);

/// B11 server: on each request received, record the submission→visible delta.
extern "C" fn perf_b11_server_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (_client, server_ep) = perf_endpoints();
    let mut request = match exec.receive(server_ep) {
        Ok(request) => request,
        Err(_) => loop {
            core::hint::spin_loop();
        },
    };
    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    loop {
        // The request is now visible to the driver host; record the latency from
        // the client's submission.
        let visible = read_tsc_serialized();
        let submit = PERF_B11_SUBMIT.load(Ordering::Relaxed);
        let idx = PERF_B11_IDX.fetch_add(1, Ordering::Relaxed);
        if idx < PERF_SAMPLES {
            buf[idx] = visible.wrapping_sub(submit);
        }
        let _ = &request;
        let ack = Message::new(MessageHeader::new(PERF_IFACE_ID, 2));
        request = match exec.reply_receive(server_ep, ack) {
            Ok(request) => request,
            Err(_) => loop {
                core::hint::spin_loop();
            },
        };
    }
}

/// B11 client: submit N I/O requests, timestamping each just before the `call`
/// so the server can measure how long until the request is visible to it.
extern "C" fn perf_b11_client_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let (client_ep, _server) = perf_endpoints();
    for _ in 0..PERF_WARMUP {
        PERF_B11_SUBMIT.store(read_tsc_serialized(), Ordering::Relaxed);
        let _ = exec.call(
            client_ep,
            Message::new(MessageHeader::new(PERF_IFACE_ID, 1)),
        );
    }
    // Discard the warmup samples the server recorded.
    PERF_B11_IDX.store(0, Ordering::Relaxed);
    for _ in 0..PERF_SAMPLES {
        PERF_B11_SUBMIT.store(read_tsc_serialized(), Ordering::Relaxed);
        let _ = core::hint::black_box(exec.call(
            client_ep,
            Message::new(MessageHeader::new(PERF_IFACE_ID, 1)),
        ));
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B11 — I/O submission to driver-host visibility (docs/architecture/03 "B11").
/// A client/driver pair in one executive; the client timestamps each submission
/// and the driver records when the request becomes visible. Mirrors the M16
/// client→driver channel path with a kernel-thread rig for a tight measurement
/// (QEMU/TCG numbers are correctness/regression only, D34/D41).
fn perf_bench_b11(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();
    let (client_ep, server_ep) = match exec.channel_create() {
        Ok(pair) => pair,
        Err(_) => return perf_report("B11 io-visible", &mut []),
    };
    // SAFETY: single-threaded boot; set once before the threads run.
    unsafe { PERF_ENDPOINTS = Some((client_ep, server_ep)) };
    PERF_B11_IDX.store(0, Ordering::Relaxed);

    // Server (driver) first so it parks and the client's `call` hands off to it.
    for (entry, kstack) in [
        (
            perf_b11_server_entry as extern "C" fn(usize) -> !,
            perf_kstack(2),
        ),
        (
            perf_b11_client_entry as extern "C" fn(usize) -> !,
            perf_kstack(3),
        ),
    ] {
        let thread = match Thread::<ContextSwitch>::spawn(
            ThreadId(0x_b11_0000 + kstack),
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        ) {
            Ok(thread) => thread,
            Err(_) => return perf_report("B11 io-visible", &mut []),
        };
        if exec.add_thread(thread).is_err() {
            return perf_report("B11 io-visible", &mut []);
        }
    }
    exec.run();

    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    perf_report("B11 io-visible", unsafe { &mut *&raw mut PERF_BUF });
}

/// Null syscalls the B1 ring-3 program times (kept in sync with the blob's
/// counter immediate). Reduced from 1M for boot-time feasibility (D35).
const PERF_B1_SYSCALLS: u64 = 20000;
/// Total ring-3-measured cycles for the B1 batch, reported via the exit syscall.
static PERF_B1_DELTA: AtomicU64 = AtomicU64::new(0);

// The B1 ring-3 program: RDTSC, N null syscalls, RDTSC, report the delta via the
// exit syscall's argument. Self-timed in ring 3 so it captures the full
// SYSCALL/SYSRET round trip (swapgs + entry stub + dispatch + sysret).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global perf_b1_program_start
.global perf_b1_program_end
perf_b1_program_start:
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r14, rax              # start cycle count
    mov r12d, 20000           # N null syscalls (== PERF_B1_SYSCALLS)
1:
    xor eax, eax              # SyscallNumber::Null
    syscall
    dec r12d
    jnz 1b
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r14              # delta = end - start
    mov rdi, rax             # exit arg0 = total cycles
    mov eax, 5               # ProcessExit
    syscall
2:
    jmp 2b
perf_b1_program_end:
.text
"#
);

// SAFETY: names the B1 blob's bounds, defined by the global_asm above; the
// extern block only declares them and does no unsafe operation.
unsafe extern "C" {
    static perf_b1_program_start: u8;
    static perf_b1_program_end: u8;
}

/// The B1 syscall handler: the measured `Null` returns immediately; `ProcessExit`
/// records the ring-3-measured cycle total and yields to boot.
fn perf_b1_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    match SyscallNumber::from_u64(frame.number) {
        Some(SyscallNumber::Null) => 0,
        Some(SyscallNumber::ProcessExit) => {
            PERF_B1_DELTA.store(frame.arg0, Ordering::Relaxed);
            // SAFETY: single-core; statics set before the ring-3 thread runs.
            if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
                process.exit(0);
            }
            // SAFETY: single-core; USER_SCHEDULER holds the B1 thread.
            if let Some(scheduler) = unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
                scheduler.yield_to_boot();
            }
            0
        }
        _ => syscall::ENOSYS,
    }
}

/// B1 — null syscall. A ring-3 program self-times a batch of null syscalls (the
/// full SYSCALL/SYSRET round trip) and reports the total; the kernel reports the
/// mean per syscall (D35: mean over a batch, not per-sample percentiles).
fn perf_bench_syscall(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this benchmark's ring-3 thread runs.
    unsafe { set_syscall_handler(perf_b1_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(_) => return kprintln!("perf: B1 null-syscall   setup failed"),
    };
    let user_root = user_arch.root_phys();
    let user_vm = AddressSpace::from_arch(user_arch, alloc_asid(), 1u64 << Cpu::cpu_id());
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(_) => return kprintln!("perf: B1 null-syscall   setup failed"),
    };
    let mut process = Process::new(proc_obj, user_vm);
    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    let user = PageFlags::rw().user();
    if process
        .space_mut()
        .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
        .is_err()
    {
        return kprintln!("perf: B1 null-syscall   setup failed");
    }
    let thread = match Thread::<ContextSwitch>::spawn_user(
        ThreadId(0x_b1_e2),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        VirtAddr::new(perf_kstack(6)),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(_) => return kprintln!("perf: B1 null-syscall   setup failed"),
    };
    // SAFETY: single-threaded boot; re-initializing the user scheduler.
    unsafe { USER_SCHEDULER = Some(Scheduler::new(1, 0)) };
    let idx = match unsafe { (*&raw mut USER_SCHEDULER).as_mut() }
        .and_then(|s| s.add_thread(thread).ok())
    {
        Some(idx) => idx,
        None => return kprintln!("perf: B1 null-syscall   setup failed"),
    };
    if process.add_thread(idx).is_err() {
        return kprintln!("perf: B1 null-syscall   setup failed");
    }

    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    let code_src = &raw const perf_b1_program_start as *const u8;
    let code_bytes =
        (&raw const perf_b1_program_end as usize) - (&raw const perf_b1_program_start as usize);
    // SAFETY: the blob is in kernel rodata; USER_CODE_VA is a writable user page
    // in the now-active space with room for it.
    unsafe { core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes) };
    if process
        .space_mut()
        .protect_range(
            VirtAddr::new(USER_CODE_VA),
            code_len,
            PageFlags::rx().user(),
        )
        .is_err()
    {
        return kprintln!("perf: B1 null-syscall   setup failed");
    }
    // SAFETY: single-threaded boot; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }
    // SAFETY: single-core boot; USER_SCHEDULER was initialized above.
    match unsafe { (*&raw mut USER_SCHEDULER).as_mut() } {
        Some(scheduler) => scheduler.run(),
        None => return kprintln!("perf: B1 null-syscall   setup failed"),
    }
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let delta = PERF_B1_DELTA.load(Ordering::Relaxed);
    let mean = delta / PERF_B1_SYSCALLS.max(1);
    kprintln!(
        "perf: B1 null-syscall   mean={mean} (over {PERF_B1_SYSCALLS} syscalls, ring-3 self-timed)"
    );
}

/// The two B7 ping-pong threads' scheduler indices.
static PERF_B7_A: AtomicUsize = AtomicUsize::new(0);
static PERF_B7_B: AtomicUsize = AtomicUsize::new(0);

/// B7 driver thread: time each A→B→A round trip (two switches) and record the
/// per-switch cost. Thread B bounces every handoff straight back.
extern "C" fn perf_b7_a_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let b = PERF_B7_B.load(Ordering::Relaxed);
    for _ in 0..PERF_WARMUP {
        exec.scheduler().handoff_to(b);
    }
    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    for slot in buf.iter_mut() {
        let start = read_tsc_serialized();
        exec.scheduler().handoff_to(b); // A→B, B hands straight back: A→B→A
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start) / 2; // round trip is two switches
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B7 bouncer thread: hand every switch straight back to the driver.
extern "C" fn perf_b7_b_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let a = PERF_B7_A.load(Ordering::Relaxed);
    loop {
        exec.scheduler().handoff_to(a);
    }
}

/// B7 — same-core context switch. Two kernel threads ping-pong via directed
/// handoff. `cross` gives each thread a distinct address space so every switch
/// pays a CR3 load (the budgeted cross-address-space cost); otherwise both share
/// the kernel space (the comparison variant that exposes the CR3 delta).
fn perf_bench_ctxsw(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    cross: bool,
    name: &str,
    slot_a: u64,
    slot_b: u64,
) {
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let (root_a, root_b) = if cross {
        // Two scratch spaces (kernel higher-half shared) force per-switch CR3
        // loads. Their page-table frames outlive the values (no free path).
        match (
            kernel_vm.arch().new_user(frames),
            kernel_vm.arch().new_user(frames),
        ) {
            (Ok(a), Ok(b)) => (Some(a.root_phys()), Some(b.root_phys())),
            _ => return perf_report(name, &mut []),
        }
    } else {
        (None, None)
    };
    let exec = exec_ref();
    let mut spawn_bench_thread = |entry: extern "C" fn(usize) -> !, kstack: u64, root| {
        let mut thread = Thread::<ContextSwitch>::spawn(
            ThreadId(0xb7_0000 + kstack),
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        )
        .ok()?;
        thread.set_space_root(root);
        exec.add_thread(thread).ok()
    };
    // Driver (A) first so it runs first and drives the loop.
    let a_idx = match spawn_bench_thread(perf_b7_a_entry, perf_kstack(slot_a), root_a) {
        Some(idx) => idx,
        None => return perf_report(name, &mut []),
    };
    let b_idx = match spawn_bench_thread(perf_b7_b_entry, perf_kstack(slot_b), root_b) {
        Some(idx) => idx,
        None => return perf_report(name, &mut []),
    };
    PERF_B7_A.store(a_idx, Ordering::Relaxed);
    PERF_B7_B.store(b_idx, Ordering::Relaxed);
    exec.run();
    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    perf_report(name, unsafe { &mut *&raw mut PERF_BUF });
}

/// The two B6 ping-pong words. Their values never change — the waiter reads the
/// current value and waits on it, so the compare-true → block path (the real
/// wait-on-address semantic) runs every iteration rather than being bypassed.
static PERF_B6_D_WORD: AtomicU64 = AtomicU64::new(0);
static PERF_B6_P_WORD: AtomicU64 = AtomicU64::new(0);

/// B6 driver thread: time each `wake(peer)` + `wait(self)` round trip. Waking
/// the peer makes it Ready; blocking in our own wait lets the scheduler run it,
/// and it wakes us straight back — one round trip is two wake→wakeup transitions.
extern "C" fn perf_b6_d_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let d_addr = &raw const PERF_B6_D_WORD as u64;
    let p_addr = &raw const PERF_B6_P_WORD as u64;
    for _ in 0..PERF_WARMUP {
        exec.wake(0, p_addr, 1);
        let v = PERF_B6_D_WORD.load(Ordering::Relaxed);
        let _ = exec.wait_on_address(0, d_addr, v, v);
    }
    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    let buf = unsafe { &mut *&raw mut PERF_BUF };
    for slot in buf.iter_mut() {
        let start = read_tsc_serialized();
        exec.wake(0, p_addr, 1); // wake peer (now Ready)
        let v = PERF_B6_D_WORD.load(Ordering::Relaxed);
        let _ = exec.wait_on_address(0, d_addr, v, v); // block; peer wakes us back
        let end = read_tsc_serialized();
        *slot = end.wrapping_sub(start) / 2; // round trip is two transitions
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// B6 peer thread: wake the driver, then wait to be woken — bouncing every
/// round trip straight back.
extern "C" fn perf_b6_p_entry(_arg: usize) -> ! {
    let exec = exec_ref();
    let d_addr = &raw const PERF_B6_D_WORD as u64;
    let p_addr = &raw const PERF_B6_P_WORD as u64;
    loop {
        exec.wake(0, d_addr, 1);
        let v = PERF_B6_P_WORD.load(Ordering::Relaxed);
        let _ = exec.wait_on_address(0, p_addr, v, v);
    }
}

/// B6 — contended wake (wait-on-address). Two kernel threads ping-pong through
/// `wait_on_address`/`wake` on two stable words; time the round trip, report the
/// per-transition cost. This is the kernel-thread wait/wake half — not the
/// ring-3 BM-6 wake-call-entry-to-waiter-running, the owner-aware-lock boosted
/// path, or the cross-core B5 path (build/README.md, D39).
fn perf_bench_waitwake(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    PERF_B6_D_WORD.store(0, Ordering::Relaxed);
    PERF_B6_P_WORD.store(0, Ordering::Relaxed);
    let exec = exec_ref();
    let mut spawn_bench_thread = |entry: extern "C" fn(usize) -> !, kstack: u64| {
        let thread = Thread::<ContextSwitch>::spawn(
            ThreadId(0xb6_0000 + kstack),
            entry,
            0,
            VirtAddr::new(kstack),
            PERF_KSTACK_PAGES,
            kernel_vm,
            frames,
        )
        .ok()?;
        exec.add_thread(thread).ok()
    };
    // Driver first so it runs first and drives the loop. Slots 7/8 are clear of
    // the B3 (0/1) and B7 (2..5) and B1 (6) benchmark stacks.
    if spawn_bench_thread(perf_b6_d_entry, perf_kstack(7)).is_none() {
        return perf_report("B6 wait-wake", &mut []);
    }
    if spawn_bench_thread(perf_b6_p_entry, perf_kstack(8)).is_none() {
        return perf_report("B6 wait-wake", &mut []);
    }
    exec.run();
    // SAFETY: single-core boot; PERF_BUF used by one benchmark at a time.
    perf_report("B6 wait-wake", unsafe { &mut *&raw mut PERF_BUF });
}

// ---- Wait-on-address (futex) ring-3 demo ------------------------------------

/// The futex word's user VA (kept in sync with the blob below). A dedicated
/// writable user page, separate from the read-execute code page.
const WAIT_WORD_VA: u64 = 0x0000_0000_0060_0000;
/// Kernel stacks for the demo's two threads. Distinct VAs in the shared kernel
/// VMAP slot (384); mappings persist across demos, and slot `9…` is clear of
/// the user (`7…`), demand-paging (`8…`), and pager (`a…`/`b…`) demo stacks.

/// The waiting process's address-space root bits, published so the kernel waker
/// keys `wake` on the same `(space, addr)` the ring-3 `wait` enrolled under.
static WAIT_DEMO_SPACE: AtomicU64 = AtomicU64::new(0);
/// Set true when the ring-3 wait returned cleanly (woken, not error).
static WAIT_DEMO_WOKEN: AtomicBool = AtomicBool::new(false);
/// Threads the kernel waker reported waking (want 1).
static WAIT_DEMO_WAKE_COUNT: AtomicU64 = AtomicU64::new(u64::MAX);
/// The ring-3 exit code, stored `+1` so 0 means "not set".
static WAIT_DEMO_EXIT: AtomicU64 = AtomicU64::new(0);

// The ring-3 waiter. Publishes WAIT_EXPECTED into the futex word, waits on it
// (blocking in the kernel), and on wake exits with the wait's result — 0 for a
// clean wake. SYSCALL ABI: rax = number, args in rdi/rsi.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global wait_demo_program_start
.global wait_demo_program_end
wait_demo_program_start:
    mov rdi, 0x600000         # arg0 = futex word VA (keep == WAIT_WORD_VA)
    mov dword ptr [rdi], 1    # *word = 1 (the value we publish and wait on)
    mov esi, 1                # arg1 = expected value (matches the word above)
    mov eax, 6                # SyscallNumber::WaitOnAddress
    syscall                   # block until the kernel wakes us; rax = 0 on wake
    mov rdi, rax              # exit code = wait result (0 on clean wake)
    mov eax, 5                # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
wait_demo_program_end:
.text
"#
);

// SAFETY: names the wait-demo blob's bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    static wait_demo_program_start: u8;
    static wait_demo_program_end: u8;
}

/// The wait-demo syscall dispatcher: `WaitOnAddress` reads the validated user
/// word and parks on the shared executive (blocking *inside* the syscall until
/// the kernel waker wakes the address); `WakeAddress` wakes; `ProcessExit`
/// records the code and yields to boot. Runs in kernel context on the user
/// thread's kernel stack, with the user address space active.
fn wait_syscall_handler(frame: &mut SyscallFrame) -> i64 {
    // SAFETY: single-core; USER_PROCESS is set before the ring-3 thread runs.
    let process = match unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        Some(process) => process,
        None => return syscall::ENOSYS,
    };
    match SyscallNumber::from_u64(frame.number) {
        Some(SyscallNumber::WaitOnAddress) => {
            let mut word = [0u8; 4];
            if let Err(e) = read_user(process, frame.arg0, &mut word) {
                return encode_result(Err(e));
            }
            let observed = u32::from_le_bytes(word) as u64;
            let space = process.space().arch().root_phys().as_u64();
            let result = exec_ref().wait_on_address(space, frame.arg0, observed, frame.arg1);
            if result.is_ok() {
                WAIT_DEMO_WOKEN.store(true, Ordering::Relaxed);
            }
            encode_result(result.map(|()| 0))
        }
        Some(SyscallNumber::WakeAddress) => {
            let space = process.space().arch().root_phys().as_u64();
            let woken = exec_ref().wake(space, frame.arg0, frame.arg1 as u32);
            encode_result(Ok(woken as u64))
        }
        Some(SyscallNumber::ProcessExit) => {
            WAIT_DEMO_EXIT.store(frame.arg0.wrapping_add(1), Ordering::Relaxed);
            process.exit(frame.arg0 as i32);
            exec_ref().scheduler().yield_to_boot();
            0
        }
        _ => syscall::ENOSYS,
    }
}

/// The kernel waker: wakes the ring-3 waiter blocked on the futex word, then
/// parks so the scheduler runs the now-ready waiter (which returns from its wait
/// and exits). Never resumes after parking.
extern "C" fn wait_demo_waker(_arg: usize) -> ! {
    let exec = exec_ref();
    let space = WAIT_DEMO_SPACE.load(Ordering::Relaxed);
    let woken = exec.wake(space, WAIT_WORD_VA, 1);
    WAIT_DEMO_WAKE_COUNT.store(woken as u64, Ordering::Relaxed);
    // Hand the CPU to the just-woken waiter by parking; it is now Ready.
    exec.scheduler().block_current();
    loop {
        core::hint::spin_loop();
    }
}

/// Wait-on-address: a ring-3 thread blocks on a user word via `WaitOnAddress`,
/// a kernel thread wakes the address, and the ring-3 thread resumes and exits
/// cleanly — proving the futex compare-and-block / wake path across the ring
/// boundary (the B6 primitive; docs/kernel/04 "Wait-On-Address"). The waiter
/// blocks *inside* its syscall and is resumed to return to ring 3.
fn wait_on_address_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(wait_syscall_handler) };
    set_user_fault_handler(user_fault_handler);

    let user_arch = match kernel_vm.arch().new_user(frames) {
        Ok(arch) => arch,
        Err(e) => panic!("wait demo: new_user failed: {e:?}"),
    };
    let user_root = user_arch.root_phys();
    WAIT_DEMO_SPACE.store(user_root.as_u64(), Ordering::Relaxed);
    let user_vm = AddressSpace::from_arch(user_arch, alloc_asid(), 1u64 << Cpu::cpu_id());
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let proc_obj = match objects.create(ObjectType::Process) {
        Ok(id) => id,
        Err(e) => panic!("wait demo: object create failed: {e:?}"),
    };
    let mut process = Process::new(proc_obj, user_vm);

    let user = PageFlags::rw().user();
    let code_len = USER_CODE_PAGES * FRAME_SIZE;
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(USER_CODE_VA), code_len, user, frames)
    {
        panic!("wait demo: map code failed: {e:?}");
    }
    // The futex word lives on its own writable page (the code page becomes rx).
    if let Err(e) =
        process
            .space_mut()
            .map_anonymous(VirtAddr::new(WAIT_WORD_VA), FRAME_SIZE, user, frames)
    {
        panic!("wait demo: map word failed: {e:?}");
    }

    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();

    // The ring-3 waiter, added first so it runs first (and blocks) before the
    // kernel waker gets the CPU.
    let waiter = match Thread::<ContextSwitch>::spawn_user(
        ThreadId(0xa170),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_BASE),
        USER_STACK_PAGES,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        proc_obj,
        user_root,
        process.space_mut(),
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("wait demo: spawn_user failed: {e:?}"),
    };
    let waiter_idx = match exec.add_thread(waiter) {
        Ok(idx) => idx,
        Err(e) => panic!("wait demo: add waiter failed: {e:?}"),
    };
    if process.add_thread(waiter_idx).is_err() {
        panic!("wait demo: process add_thread failed");
    }

    // The kernel waker.
    let waker = match Thread::<ContextSwitch>::spawn(
        ThreadId(0xa171),
        wait_demo_waker,
        0,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => panic!("wait demo: spawn waker failed: {e:?}"),
    };
    if exec.add_thread(waker).is_err() {
        panic!("wait demo: add waker failed");
    }

    // SAFETY: the user space shares the kernel higher-half; boot code, stack,
    // and the direct map stay mapped after the CR3 load.
    unsafe { process.space().activate(Cpu::cpu_id()) };
    let code_src = &raw const wait_demo_program_start as *const u8;
    let code_bytes =
        (&raw const wait_demo_program_end as usize) - (&raw const wait_demo_program_start as usize);
    // SAFETY: the blob is in kernel rodata; USER_CODE_VA is a writable user page
    // in the now-active space with room for it.
    unsafe { core::ptr::copy_nonoverlapping(code_src, USER_CODE_VA as *mut u8, code_bytes) };
    if process
        .space_mut()
        .protect_range(
            VirtAddr::new(USER_CODE_VA),
            code_len,
            PageFlags::rx().user(),
        )
        .is_err()
    {
        panic!("wait demo: protect code failed");
    }
    // SAFETY: single-threaded boot; publishing the running process.
    unsafe { USER_PROCESS = Some(process) };
    if let Some(process) = unsafe { (*&raw mut USER_PROCESS).as_mut() } {
        process.set_running();
    }
    exec.run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };

    let woken = WAIT_DEMO_WOKEN.load(Ordering::Relaxed);
    let wake_count = WAIT_DEMO_WAKE_COUNT.load(Ordering::Relaxed);
    let exit = WAIT_DEMO_EXIT.load(Ordering::Relaxed);
    let pass = woken && wake_count == 1 && exit == 1;
    report(&verdict(DemoId::WaitOnAddress, pass, [0; 8]));
    if !pass {
        kprintln!(
            "wait-demo: FAIL woken={woken} wake_count={wake_count} exit_code={}",
            (exit.wrapping_sub(1)) as i64
        );
    }
}

// ---- Ports (async event delivery) kernel demo -------------------------------

/// The demo's abstract event source and signal. In v0 a source is an opaque id
/// (not yet a channel/sync/cancellation binding — build/README.md, D38).
const PORT_DEMO_SOURCE: u64 = 0x5011;
const PORT_DEMO_SIGNAL: u8 = 1;
/// Kernel stacks for the two demo threads (dedicated VMAP slot `d…`, clear of
/// every other demo/benchmark stack).

/// Observations, published by the consumer and checked on boot.
static PORT_DEMO_COALESCED_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
static PORT_DEMO_TRAILING_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
static PORT_DEMO_WOKEN_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
static PORT_DEMO_COALESCE_COUNT: AtomicU64 = AtomicU64::new(u64::MAX);

/// The consumer: creates and binds a port, proves coalescing (three edges before
/// a drain collapse into one event carrying a pending count of 3), proves a
/// trailing edge after the drain is not lost, then blocks on an empty drain to
/// be woken by the producer's cross-thread signal.
extern "C" fn port_demo_consumer(_arg: usize) -> ! {
    let exec = exec_ref();
    let port = match exec.port_create() {
        Ok(port) => port,
        Err(_) => {
            exec.scheduler().yield_to_boot();
            loop {
                core::hint::spin_loop();
            }
        }
    };
    if exec
        .port_bind(port, PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL)
        .is_err()
    {
        exec.scheduler().yield_to_boot();
        loop {
            core::hint::spin_loop();
        }
    }
    // Phase 1 — three edges before a drain coalesce into one event.
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    if let Ok(event) = exec.port_wait(port) {
        PORT_DEMO_COALESCED_PENDING.store(event.pending as u64, Ordering::Relaxed);
    }
    // Phase 2 — a fresh edge after the drain is a separate, un-lost event.
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    if let Ok(event) = exec.port_wait(port) {
        PORT_DEMO_TRAILING_PENDING.store(event.pending as u64, Ordering::Relaxed);
    }
    PORT_DEMO_COALESCE_COUNT.store(exec.port_coalesced(port), Ordering::Relaxed);
    // Phase 3 — block on an empty port; the producer wakes us cross-thread.
    if let Ok(event) = exec.port_wait(port) {
        PORT_DEMO_WOKEN_PENDING.store(event.pending as u64, Ordering::Relaxed);
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// The producer: signals the bound source (waking the blocked consumer), then
/// parks so the woken consumer runs.
extern "C" fn port_demo_producer(_arg: usize) -> ! {
    let exec = exec_ref();
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 5);
    exec.scheduler().block_current();
    loop {
        core::hint::spin_loop();
    }
}

/// Ports: async event delivery that cannot lose events or overflow. A consumer
/// binds a port to a source and proves the load-bearing semantics — coalescing
/// with a pending count, drain-reads-current-state, no lost edge — then a
/// producer thread signals the source and wakes the blocked drainer
/// (docs/kernel/04 "Port Delivery Semantics"). Both are kernel threads, so the
/// demo runs entirely under the kernel address space.
fn ports_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();
    let mut spawn_kernel_thread = |entry: extern "C" fn(usize) -> !, kstack: u64, id: u64| {
        let thread = Thread::<ContextSwitch>::spawn(
            ThreadId(id),
            entry,
            0,
            VirtAddr::new(kstack),
            USER_KSTACK_PAGES,
            kernel_vm,
            frames,
        )
        .ok()?;
        exec.add_thread(thread).ok()
    };
    // Consumer first so it sets up the port and reaches its blocking drain
    // before the producer runs.
    if spawn_kernel_thread(
        port_demo_consumer,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0xc0_0001,
    )
    .is_none()
    {
        return kprintln!("ports-demo: setup failed (consumer)");
    }
    if spawn_kernel_thread(
        port_demo_producer,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0xc0_0002,
    )
    .is_none()
    {
        return kprintln!("ports-demo: setup failed (producer)");
    }
    exec.run();

    let coalesced = PORT_DEMO_COALESCED_PENDING.load(Ordering::Relaxed);
    let trailing = PORT_DEMO_TRAILING_PENDING.load(Ordering::Relaxed);
    let woken = PORT_DEMO_WOKEN_PENDING.load(Ordering::Relaxed);
    let collapses = PORT_DEMO_COALESCE_COUNT.load(Ordering::Relaxed);
    let pass = coalesced == 3 && trailing == 1 && woken == 5 && collapses == 2;
    report(&verdict(
        DemoId::Ports,
        pass,
        [collapses, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "ports-demo: FAIL coalesced={coalesced} trailing={trailing} woken={woken} collapses={collapses}"
        );
    }
}

// ---- Jobs (containment tree) kernel demo ------------------------------------

/// Kernel stacks for the demo's member threads (dedicated VMAP slot `e…`, clear
/// of every other demo/benchmark stack).

fn job_kstack(i: u64) -> u64 {
    static BASE: AtomicU64 = AtomicU64::new(0);
    let mut base = BASE.load(Ordering::Relaxed);
    if base == 0 {
        base = reserve_kstack_block(4);
        BASE.store(base, Ordering::Relaxed);
    }
    base + i * KSTACK_WINDOW_SLOT
}

/// A member process's thread: it never runs in this demo (the scheduler is never
/// started); it exists so a kill has a real thread to terminate.
extern "C" fn job_member_entry(_arg: usize) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Creates a member process object + a parked thread and places it in `job`.
/// On any failure (including the member-count cap) the thread is terminated and
/// the object released, so a rejected create leaks nothing.
#[allow(clippy::too_many_arguments)]
fn job_spawn_member(
    exec: &mut Executive<ContextSwitch>,
    objects: &mut ObjectTable,
    job: tessera_kcore::job::JobId,
    kstack: u64,
    thread_id: u64,
    rights: Rights,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<(ObjectId, usize), KError> {
    let proc = objects.create(ObjectType::Process)?;
    let thread = match Thread::<ContextSwitch>::spawn(
        ThreadId(thread_id),
        job_member_entry,
        0,
        VirtAddr::new(kstack),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => {
            let _ = objects.release(proc);
            return Err(e);
        }
    };
    let idx = match exec.add_thread(thread) {
        Ok(idx) => idx,
        Err(e) => {
            let _ = objects.release(proc);
            return Err(e);
        }
    };
    match exec.job_add_process(
        job,
        Member {
            process: proc,
            thread: idx,
        },
        rights,
    ) {
        Ok(()) => Ok((proc, idx)),
        Err(e) => {
            exec.scheduler().terminate(idx);
            let _ = objects.release(proc);
            Err(e)
        }
    }
}

/// Jobs: the containment tree. Builds root + a tighter child job, enforces the
/// tighten-only limit rule and the member-count ceiling and the `KILL` right,
/// then kills the whole subtree innermost-first — terminating every member
/// thread, reclaiming each member object, and signalling the root job's state
/// port (member-exit + emptiness) for a supervisor to drain
/// (docs/kernel/05). All operations run in boot context on data structures;
/// the member threads are spawned parked and never scheduled.
fn jobs_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();
    // SAFETY: single-threaded boot path; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };

    let full = Rights::from_bits(
        Rights::CREATE_JOB.bits() | Rights::CREATE_PROCESS.bits() | Rights::KILL.bits(),
    );

    // Root job with a member-process cap of 2.
    let root_obj = match objects.create(ObjectType::Job) {
        Ok(obj) => obj,
        Err(_) => return kprintln!("jobs-demo: setup failed (root object)"),
    };
    let root = match exec.job_create_root(root_obj, JobLimits::new(2)) {
        Ok(job) => job,
        Err(_) => return kprintln!("jobs-demo: setup failed (root)"),
    };

    // Tighten-only: a child looser than its parent's ceiling is rejected.
    let loose_obj = match objects.create(ObjectType::Job) {
        Ok(obj) => obj,
        Err(_) => return kprintln!("jobs-demo: setup failed (object)"),
    };
    let tighten_rejected = matches!(
        exec.job_create_child(root, loose_obj, JobLimits::new(3), full),
        Err(KError::LimitExceeded)
    );
    let _ = objects.release(loose_obj); // reclaim the unused object

    // A child job with a tighter cap of 1.
    let child_obj = match objects.create(ObjectType::Job) {
        Ok(obj) => obj,
        Err(_) => return kprintln!("jobs-demo: setup failed (child object)"),
    };
    let child = match exec.job_create_child(root, child_obj, JobLimits::new(1), full) {
        Ok(job) => job,
        Err(_) => return kprintln!("jobs-demo: setup failed (child)"),
    };

    // Members: P1, P2 fill root's cap of 2; P3 is rejected; P4 goes in the child.
    let p1 = job_spawn_member(
        exec,
        objects,
        root,
        job_kstack(0),
        0xd0_0001,
        full,
        kernel_vm,
        frames,
    );
    let p2 = job_spawn_member(
        exec,
        objects,
        root,
        job_kstack(1),
        0xd0_0002,
        full,
        kernel_vm,
        frames,
    );
    let p3 = job_spawn_member(
        exec,
        objects,
        root,
        job_kstack(2),
        0xd0_0003,
        full,
        kernel_vm,
        frames,
    );
    let p4 = job_spawn_member(
        exec,
        objects,
        child,
        job_kstack(3),
        0xd0_0004,
        full,
        kernel_vm,
        frames,
    );

    let limit_rejected = matches!(p3, Err(KError::LimitExceeded));
    let (p1, p2, p4) = match (p1, p2, p4) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return kprintln!("jobs-demo: setup failed (members)"),
    };
    let member_threads = [p1.1, p2.1, p4.1];

    // The capability gate: a kill without the `KILL` right is denied.
    let mut sink = [None; 8];
    let rights_rejected = matches!(
        exec.job_kill(root, Rights::none(), &mut sink),
        Err(KError::AccessDenied)
    );

    // A supervisor port bound to the root job's state source.
    let source = match exec.job(root) {
        Some(job) => job.state_source(),
        None => return kprintln!("jobs-demo: setup failed (source)"),
    };
    let port = match exec.port_create() {
        Ok(port) => port,
        Err(_) => return kprintln!("jobs-demo: setup failed (port)"),
    };
    if exec.port_bind(port, source, SIGNAL_MEMBER_EXIT).is_err()
        || exec.port_bind(port, source, SIGNAL_EMPTY).is_err()
    {
        return kprintln!("jobs-demo: setup failed (bind)");
    }

    // Kill the whole subtree, innermost-first (child's member before root's).
    let mut killed = [None; 8];
    let n = match exec.job_kill(root, full, &mut killed) {
        Ok(n) => n,
        Err(_) => return kprintln!("jobs-demo: kill failed"),
    };

    // Supervisor reclaim: release each killed member's object.
    let mut released = 0;
    for slot in killed.iter().take(n) {
        if let Some(proc) = slot
            && objects.release(*proc).is_ok()
        {
            released += 1;
        }
    }

    // Every member thread must be terminated.
    let all_exited = member_threads
        .iter()
        .all(|&idx| exec.scheduler().thread_state(idx) == Some(ThreadState::Exited));

    // Drain the state port: root's two member-exits coalesce, then emptiness.
    let member_exit = exec.port_wait(port).ok().map(|e| (e.signal, e.pending));
    let empty = exec.port_wait(port).ok().map(|e| e.signal);

    let ok = tighten_rejected
        && limit_rejected
        && rights_rejected
        && n == 3
        && released == 3
        && all_exited
        && member_exit == Some((SIGNAL_MEMBER_EXIT, 2))
        && empty == Some(SIGNAL_EMPTY);
    report(&verdict(
        DemoId::Jobs,
        ok,
        [n as u64, released as u64, 0, 0, 0, 0, 0, 0],
    ));
    if !ok {
        kprintln!(
            "jobs-demo: FAIL tighten={tighten_rejected} limit={limit_rejected} rights={rights_rejected} killed={n} released={released} exited={all_exited} exit={member_exit:?} empty={empty:?}"
        );
    }
}

// ---- Pager-pressure scenario demos (docs/prototypes/02) ---------------------

/// The scratch pager-backed object's base VA for the pressure scenarios.
const PAGER_PRESSURE_VA: u64 = 0x0000_0000_5000_0000;
/// Kernel stack for the S6 pager thread (dedicated VMAP slot `f…`).

/// Builds a scratch object-backed space of `pages` pages, all supplied
/// (read-only) and clean — the resident working set the scenarios operate on.
fn pager_scratch(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    pages: u64,
) -> Option<AddressSpace<KernelAddressSpace>> {
    let arch = kernel_vm.arch().new_user(frames).ok()?;
    let mut space = AddressSpace::from_arch(arch, alloc_asid(), 0);
    let object = ObjectId::from_raw(0x5017_0000);
    space
        .map_object(
            VirtAddr::new(PAGER_PRESSURE_VA),
            pages * FRAME_SIZE,
            PageFlags::rw().user(),
            object,
            0,
        )
        .ok()?;
    for off in 0..pages {
        let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
        let frame = frames.alloc()?;
        space.arch().fill_frame(frame, 0);
        space.supply_page(va, frame, frames).ok()?;
    }
    Some(space)
}

/// Writes page `off`: the software dirty-bit path. A write to the read-only
/// resident page faults `WriteToClean`; the kernel records it dirty (throttling
/// at the object's dirty bound) and, when within the bound, grants write.
fn pager_write(
    space: &mut AddressSpace<KernelAddressSpace>,
    cache: &mut ObjectCache,
    off: u64,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> DirtyOutcome {
    let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
    match space.resolve_fault(va, true, frames) {
        FaultOutcome::WriteToClean { offset, .. } => {
            let outcome = cache.mark_dirty(offset);
            if outcome == DirtyOutcome::Marked {
                let _ = space.grant_write(va);
            }
            outcome
        }
        // Already writable (already dirtied) or a genuine fault.
        _ => DirtyOutcome::Throttle,
    }
}

/// Writes page `off` back: re-protects the page read-only so the snapshot is
/// stable and the next write re-faults, then — only after the (synchronous, v0)
/// pager acknowledgment — marks the page clean.
fn pager_writeback(
    space: &mut AddressSpace<KernelAddressSpace>,
    cache: &mut ObjectCache,
    off: u64,
) {
    let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
    let _ = space.reprotect_ro(va);
    // The pager persists the stable snapshot and acknowledges; only then:
    cache.mark_clean(off * FRAME_SIZE);
}

/// S2 — dirty flood. A writer dirties pages faster than write-back; the write
/// **throttles at the write fault** once the object's dirty bound is hit, dirty
/// stays bounded, and a write-back drains room for the throttled writer to
/// proceed (docs/prototypes/02 S2; docs/kernel/03 "Dirty throttling").
fn pager_throttle_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 8;
    const LIMIT: u32 = 3;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S2 dirty-flood: setup failed");
    };
    let mut cache = ObjectCache::new(LIMIT);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // Flood: the first LIMIT distinct pages dirty; the next throttles.
    let mut throttled_at = None;
    for off in 0..PAGES {
        if pager_write(&mut space, &mut cache, off, frames) == DirtyOutcome::Throttle {
            throttled_at = Some(off);
            break;
        }
    }
    let throttle_ok = throttled_at == Some(LIMIT as u64) && cache.dirty_count() == LIMIT;
    // Drain one page-back (ack → clean), then the throttled writer proceeds.
    pager_writeback(&mut space, &mut cache, 0);
    let retry = pager_write(&mut space, &mut cache, throttled_at.unwrap_or(0), frames);
    let drained_ok = retry == DirtyOutcome::Marked && cache.dirty_count() == LIMIT;
    let pass = throttle_ok && drained_ok;
    report(&verdict(
        DemoId::PagerDirtyFlood,
        pass,
        [u64::from(LIMIT), 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("S2 dirty-flood: FAIL throttle={throttle_ok} drained={drained_ok}");
    }
}

/// S8 — coordinated flush query. Dirty a scattered set of pages, then assert the
/// dirty-range query returns **exactly** those pages — dirty-tracking
/// correctness on the software dirty-bit configuration (docs/prototypes/02 S8).
fn pager_dirty_query_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 8;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S8 dirty-query: setup failed");
    };
    let mut cache = ObjectCache::new(64);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // Dirty a scattered subset.
    let dirtied = [1u64, 3, 4, 7];
    let mut all_marked = true;
    for &p in &dirtied {
        if pager_write(&mut space, &mut cache, p, frames) != DirtyOutcome::Marked {
            all_marked = false;
        }
    }
    let mut buf = [0u64; PAGES as usize];
    let n = cache.dirty_offsets(&mut buf);
    let expected = [FRAME_SIZE, 3 * FRAME_SIZE, 4 * FRAME_SIZE, 7 * FRAME_SIZE];
    let exact = n == expected.len() && buf[..n] == expected;
    let pass = all_marked && exact;
    report(&verdict(DemoId::PagerDirtyQuery, pass, [0; 8]));
    if !pass {
        kprintln!("S8 dirty-query: FAIL n={n} marked={all_marked} exact={exact}");
    }
}

/// S4 — durability ordering. Write dirty pages back and prove **no page is
/// marked clean before its (synchronous, v0) pager acknowledgment**, and that
/// the snapshot is stable — once write-back is issued the page is read-only, so
/// a write re-faults rather than silently mutating the in-flight snapshot
/// (docs/prototypes/02 S4; docs/kernel/03 "Durability ordering").
fn pager_durability_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 4;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S4 durability: setup failed");
    };
    let mut cache = ObjectCache::new(64);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    for off in 0..PAGES {
        let _ = pager_write(&mut space, &mut cache, off, frames);
    }
    let mut clean_before_ack = false;
    let mut snapshot_stable = true;
    let mut cleaned_after_ack = 0u32;
    for off in 0..PAGES {
        let va = VirtAddr::new(PAGER_PRESSURE_VA + off * FRAME_SIZE);
        // Issue write-back: re-protect read-only so the snapshot cannot change.
        let _ = space.reprotect_ro(va);
        // A write now must re-fault (the page is read-only) — the snapshot is
        // stable, not a concurrently-mutating page.
        if !matches!(
            space.resolve_fault(va, true, frames),
            FaultOutcome::WriteToClean { .. }
        ) {
            snapshot_stable = false;
        }
        // Before the ack the page must still be dirty (not prematurely cleaned).
        if !cache.is_dirty(off * FRAME_SIZE) {
            clean_before_ack = true;
        }
        // ... the pager persists the stable snapshot and acknowledges ...
        // Only after the ack: mark clean.
        cache.mark_clean(off * FRAME_SIZE);
        cleaned_after_ack += 1;
    }
    let ok = !clean_before_ack
        && snapshot_stable
        && cleaned_after_ack == PAGES as u32
        && cache.dirty_count() == 0;
    report(&verdict(
        DemoId::PagerDurability,
        ok,
        [u64::from(cleaned_after_ack), 0, 0, 0, 0, 0, 0, 0],
    ));
    if !ok {
        kprintln!(
            "S4 durability: FAIL clean_before_ack={clean_before_ack} stable={snapshot_stable} cleaned={cleaned_after_ack}"
        );
    }
}

/// S6 — pager death. Kill the pager while it holds dirty pages with un-acked
/// write-backs: its bound object enters a **faulted** state and a data-integrity
/// event reports **exactly** the lost dirty ranges — no more, no fewer
/// (docs/prototypes/02 S6; docs/kernel/03 "Ownership, Resize, And Revocation").
fn pager_death_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const PAGES: u64 = 6;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S6 pager-death: setup failed");
    };
    let mut cache = ObjectCache::new(64);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // Dirty a scattered subset — in-flight, not yet written back.
    let dirtied = [0u64, 2, 5];
    for &p in &dirtied {
        let _ = pager_write(&mut space, &mut cache, p, frames);
    }

    // Spawn a pager thread and kill it (M11 terminate) — the pager dies holding
    // those dirty pages.
    // SAFETY: single-threaded boot; re-initializing the shared executive.
    unsafe { EXEC = Some(Executive::new(1, 0)) };
    let exec = exec_ref();
    let killed = match Thread::<ContextSwitch>::spawn(
        ThreadId(0xdead_0001),
        job_member_entry,
        0,
        alloc_kstack(USER_KSTACK_PAGES),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    )
    .ok()
    .and_then(|thread| exec.add_thread(thread).ok())
    {
        Some(idx) => {
            exec.scheduler().terminate(idx);
            exec.scheduler().thread_state(idx) == Some(ThreadState::Exited)
        }
        None => false,
    };

    // On pager death the object faults, reporting exactly the lost dirty ranges.
    let mut lost = [0u64; PAGES as usize];
    let n = cache.fault(&mut lost);
    let expected = [0, 2 * FRAME_SIZE, 5 * FRAME_SIZE];
    let exact = n == expected.len() && lost[..n] == expected;
    let pass = killed && exact && cache.is_faulted();
    report(&verdict(DemoId::PagerDeath, pass, [0; 8]));
    if !pass {
        kprintln!(
            "S6 pager-death: FAIL killed={killed} n={n} exact={exact} faulted={}",
            cache.is_faulted()
        );
    }
}

/// S3 — Reclaim Deadlock Probe (docs/prototypes/02; docs/kernel/03 "Write-Back
/// Under Memory Pressure"). At hard memory pressure a write-back needs a frame to
/// drain a dirty page — so reclaim can advance — but ordinary allocation would
/// block: the reclaim-needs-memory deadlock. A declared write-back reservation
/// keeps the write-back path progressing; an over-allocation past the reservation
/// fails cleanly (the object's range is faulted), and nothing hangs.
fn pager_reclaim_deadlock_demo(
    kernel_vm: &AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    const CAPACITY: u32 = 8;
    const RESERVED: u32 = 2;
    const PAGES: u64 = 2;
    let Some(mut space) = pager_scratch(kernel_vm, frames, PAGES) else {
        return kprintln!("S3 reclaim-deadlock: setup failed");
    };
    let mut cache = ObjectCache::new(4);
    for off in 0..PAGES {
        let _ = cache.install(off * FRAME_SIZE);
    }
    // A dirty page whose write-back is what must make progress under pressure.
    let _ = pager_write(&mut space, &mut cache, 0, frames);

    let mut res = WriteBackReservation::new(CAPACITY, RESERVED);
    // Drive the ordinary (fault/page-in) path to hard memory pressure.
    let mut ordinary = 0u32;
    while res.alloc_ordinary().is_some() {
        ordinary += 1;
    }
    let blocked = res.at_pressure() && res.alloc_ordinary().is_none();
    // Under pressure the reserved write-back path still makes progress; draining
    // the dirty page frees an ordinary frame so reclaim advances.
    let wb_progress = res.alloc_writeback().is_some();
    res.free_ordinary();
    let reclaim_progressed = res.alloc_ordinary().is_some();

    // A write-back that over-allocates past the reservation fails cleanly — the
    // object's dirty range is faulted rather than the kernel hanging.
    while res.alloc_writeback().is_some() {}
    let overalloc_failed = res.alloc_writeback().is_none();
    let mut lost = [0u64; PAGES as usize];
    let n = cache.fault(&mut lost);
    let clean_fail = overalloc_failed && n == 1 && lost[0] == 0 && cache.is_faulted();

    let pass = ordinary == CAPACITY - RESERVED
        && blocked
        && wb_progress
        && reclaim_progressed
        && clean_fail;
    report(&verdict(
        DemoId::PagerReclaimDeadlock,
        pass,
        [u64::from(ordinary), u64::from(RESERVED), 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "S3 reclaim-deadlock: FAIL ordinary={ordinary} blocked={blocked} wb={wb_progress} reclaim={reclaim_progressed} clean_fail={clean_fail}"
        );
    }
}

/// S5 — Self-Paging Cycle (docs/prototypes/02; docs/kernel/03 "Anti-Deadlock
/// Rules"). Pager A's working set is backed by an object paged by pager B and vice
/// versa; forced to fault together they would deadlock. The kernel detects the
/// cycle in the waits-for graph and breaks it by faulting the request (resolution
/// by error, not hang). Also exercises the degenerate single self-paging pager.
fn pager_self_paging_cycle_demo() {
    const PAGER_A: u32 = 0xA;
    const PAGER_B: u32 = 0xB;
    const OBJ_X: u64 = 0x100; // pager A's working set, paged by B
    const OBJ_Y: u64 = 0x200; // pager B's working set, paged by A

    // Mutual: A backed by B, B backed by A; both fault in their own handlers.
    let mut graph = SelfPagingGraph::new();
    let bound = graph.bind(OBJ_X, PAGER_B).is_ok() && graph.bind(OBJ_Y, PAGER_A).is_ok();
    let a_served = graph.request_page_in(PAGER_A, OBJ_X) == PageInResult::Served;
    let b_cycle = graph.request_page_in(PAGER_B, OBJ_Y) == PageInResult::Cycle;
    // Break the cycle by faulting the request: seal the object that could not be
    // served (the anti-deadlock resolution — an error, never a block).
    let mut cycled = ObjectCache::new(1);
    let _ = cycled.install(0);
    let mut lost = [0u64; 1];
    let _ = cycled.fault(&mut lost);
    let mutual_ok = bound && a_served && b_cycle && cycled.is_faulted() && graph.in_flight() == 1;

    // Degenerate: a single pager whose working set is the object it itself pages.
    let mut solo = SelfPagingGraph::new();
    let solo_ok = solo.bind(OBJ_X, PAGER_A).is_ok()
        && solo.request_page_in(PAGER_A, OBJ_X) == PageInResult::Cycle;

    let pass = mutual_ok && solo_ok;
    report(&verdict(DemoId::PagerSelfPagingCycle, pass, [0; 8]));
    if !pass {
        kprintln!("S5 self-paging-cycle: FAIL mutual={mutual_ok} solo={solo_ok}");
    }
}

/// S7 — Deadline Misses and Supervision (docs/prototypes/02; docs/kernel/03
/// "Page-In Flow", L78-83). A pager delays responses past its policy deadline; the
/// faulting thread must get a bounded fault error (the range faulted), never an
/// indefinite block, and repeated misses escalate through supervision (restart),
/// with each miss and escalation observable as a counted event.
fn pager_deadline_supervision_demo() {
    const DEADLINE: u64 = 10; // ticks a page-in may take
    const ESCALATE_AFTER: u32 = 3; // misses before a supervised restart
    const REQUESTS: u32 = 6; // slow requests, all past deadline

    let mut sup = PageInSupervisor::new(DEADLINE, ESCALATE_AFTER);
    // A request answered within the deadline is not faulted (the deadline is a real
    // discriminator, not always-expire).
    let on_time_pending = sup.check(0, DEADLINE) == DeadlineOutcome::Pending;

    let mut bounded_faults = 0u32;
    let mut escalations = 0u32;
    for i in 0..REQUESTS {
        let started = u64::from(i) * 100;
        // The kernel gives up at deadline plus a bounded margin — not indefinite.
        let now = started + DEADLINE + 1;
        if sup.check(started, now) == DeadlineOutcome::Expired {
            // Deliver a bounded fault error: fault the object's range (not a hang).
            let mut obj = ObjectCache::new(1);
            let _ = obj.install(0);
            let mut lost = [0u64; 1];
            let _ = obj.fault(&mut lost);
            if obj.is_faulted() {
                bounded_faults += 1;
            }
            if sup.record_miss() == MissOutcome::Escalate {
                escalations += 1;
            }
        }
    }

    // 6 misses, escalating every 3 → 2 supervised restarts.
    let ok = on_time_pending
        && bounded_faults == REQUESTS
        && sup.misses() == REQUESTS
        && escalations == REQUESTS / ESCALATE_AFTER
        && sup.escalations() == escalations;
    report(&verdict(
        DemoId::PagerDeadlineSupervision,
        ok,
        [
            u64::from(REQUESTS),
            u64::from(escalations),
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    ));
    if !ok {
        kprintln!(
            "S7 deadline-supervision: FAIL on_time={on_time_pending} faults={bounded_faults} misses={} esc={escalations}",
            sup.misses()
        );
    }
}

// --- Demo verdicts: the record is primary, the line is a rendering -----------
//
// `docs/observability/01`: "Plain text rendering is generated from structured
// records." Each demo builds a `DemoVerdict` (`kcore::verdict`) and calls
// [`report`], which renders the verdict line from that record. A failing demo
// keeps its own diagnostic print — it dumps the whole predicate, far wider than a
// fixed payload — and is counted here so the boot's exit code reflects it,
// closing the hole where every demo could print FAIL and the boot still exited
// success (build/README.md, D58).

/// Demos whose verdict came back `Outcome::Fail`. Gates the boot's exit code.
static DEMOS_FAILED: AtomicU64 = AtomicU64::new(0);

/// Renders a demo's verdict line from its record. A failing verdict renders
/// nothing (the demo already printed its diagnostic dump) and is counted.
fn report(v: &DemoVerdict) {
    if v.outcome != Outcome::Pass {
        DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    match v.demo {
        DemoId::Loader => {
            let (seg_count, child_exit) = (v.arg1, v.arg3 as i32);
            kprintln!(
                "loader: OK — root task (ELF, entry {:#x}, {seg_count} PT_LOAD, W^X, job handle {}) created a child, mapped + populated its code (W^X), started it in ring 3; child exited {child_exit}, parent resumed and exited clean",
                v.arg0,
                v.arg2
            );
        }
        DemoId::ComponentManager => kprintln!(
            "cm: OK — component manager launched a service {} times ({} ran), restarting it on each crash (exit codes summing {}) until it came up clean (last exit {}); manager exited clean",
            v.arg0,
            v.arg1,
            v.arg2 as i64,
            v.arg3 as i32
        ),
        DemoId::ComponentManagerBudget => kprintln!(
            "cm-budget: OK — a service that kept crashing was restarted only {} times (budget cap, {} ran; last exit {} still crashing), then the manager gave up (exit {})",
            v.arg0,
            v.arg1,
            v.arg2 as i32,
            v.arg3 as i32
        ),
        DemoId::ComponentManagerReclaim => kprintln!(
            "cm-reclaim: OK — reclaimed across {} restarts ({} ran, clean); only {} frames drawn (bounded, not {}×), no reclaim overflow — process/thread slots + frames returned to baseline, unbounded restart",
            v.arg0,
            v.arg1,
            v.arg2,
            v.arg3
        ),
        DemoId::DriverCrash => {
            let net = v.arg0 as i64;
            kprintln!(
                "driver-crash: OK — driver host crashed (real #PF at 0x0, vector 14), contained + reclaimed; device cap conserved (rc=1); host frames net {net}"
            );
        }
        DemoId::DriverRestart => kprintln!(
            "driver-restart: OK — driver host crashed (real #PF) {} times, each contained + reclaimed + device rebound (cap conserved rc=1), then restarted clean and serviced the client (byte 0x5a); {} frames drawn, no reclaim overflow",
            v.arg0,
            v.arg1
        ),
        DemoId::DriverRestartBudget => kprintln!(
            "driver-restart-budget: OK — a driver host that kept crashing was restarted only {} times (budget cap), then the supervisor gave up (code {}); device cap not leaked (rc=1)",
            v.arg0,
            v.arg1 as i32
        ),
        DemoId::ChannelIpc => kprintln!(
            "chan: OK — ring-3 client called a ring-3 server over a channel (inline \"ping\"->\"pong\", 1 handle transferred), two switches, both in ring 3; client exited clean"
        ),
        DemoId::Com2DriverStep0 => {
            let (count, looped) = (v.arg0, v.arg1);
            kprintln!(
                "m16-step0: OK — COM2 loopback raised IRQ3 (count={count}, rbr={looped:#04x})"
            );
        }
        DemoId::Com2DriverStep1 => {
            let source = v.arg0;
            kprintln!(
                "m16-step1: OK — real IRQ3 drove port_signal; boot drained a port event (source={source:#x})"
            );
        }
        DemoId::Com2DriverStep2 => {
            let pending = v.arg0;
            kprintln!(
                "m16-step2: OK — ring-3 driver created+bound a port and woke on a signal (pending={pending})"
            );
        }
        DemoId::Com2DriverStep3 => {
            let byte = v.arg0;
            kprintln!(
                "m16-step3: OK — ring-3 driver read the device through its capability (byte={byte:#04x}); a non-device handle was denied"
            );
        }
        DemoId::Com2DriverStep4 => {
            let (byte, irqs) = (v.arg0, v.arg1);
            kprintln!(
                "m16-step4: OK — a real IRQ3 was delivered in ring 3, woke the driver's PortWait, and it read the device (byte={byte:#04x}, irqs={irqs})"
            );
        }
        DemoId::Com2DriverService => {
            let byte = v.arg0;
            kprintln!(
                "m16: OK — ring-3 driver host serviced a client I/O request over a real IRQ3 (COM2 loopback): client called, driver drove the device (byte {byte:#04x}) and replied, client got it and exited clean"
            );
        }
        DemoId::DeviceManager => {
            let byte = v.arg1;
            kprintln!(
                "m17: OK — device manager granted a Device capability (base {:#x}) to a driver host over a channel; the driver drove the device (byte {byte:#04x}) and serviced a client, the granted range was enforced, and the capability's reference was conserved",
                v.arg0
            );
        }
        DemoId::FsSupply => {
            let byte = v.arg0;
            kprintln!(
                "fs: supply OK — copied a service-buffer page into a pager-backed mapping (byte {byte:#04x})"
            );
        }
        DemoId::FsService => {
            let (supplied, content_base) = (v.arg0, v.arg1);
            kprintln!(
                "fs: OK — ring-3 filesystem service supplied {supplied} pages to a client over the external pager (content {content_base:#x}+i, all from ring 3); an out-of-buffer supply was denied, client exited clean, object reference conserved"
            );
        }
        DemoId::WaitOnAddress => kprintln!(
            "wait-demo: OK — ring-3 blocked on a futex word, kernel woke 1, wait returned, clean exit 0"
        ),
        DemoId::Ports => {
            let collapses = v.arg0;
            kprintln!(
                "ports-demo: OK — 3 edges coalesced (pending=3, {collapses} collapses), trailing edge=1 not lost, cross-thread signal woke the drainer (pending=5)"
            );
        }
        DemoId::Jobs => {
            let (n, released) = (v.arg0, v.arg1);
            kprintln!(
                "jobs-demo: OK — tighten-only + member-cap(2) + KILL-right enforced; kill terminated {n} members innermost-first, reclaimed {released} objects, state port drained member-exit(pending=2) + emptiness"
            );
        }
        DemoId::PagerDirtyFlood => {
            let limit = v.arg0;
            kprintln!(
                "S2 dirty-flood: OK — throttled at the write fault after {limit} dirty pages (bounded); a write-back drained one and the writer proceeded"
            );
        }
        DemoId::PagerDirtyQuery => kprintln!(
            "S8 dirty-query: OK — dirtied 4 scattered pages; the dirty-range query returned exactly them"
        ),
        DemoId::PagerDurability => {
            let cleaned_after_ack = v.arg0;
            kprintln!(
                "S4 durability: OK — every page stayed dirty until its pager ack then went clean ({cleaned_after_ack} write-backs, stable snapshots, no clean-before-ack)"
            );
        }
        DemoId::PagerDeath => kprintln!(
            "S6 pager-death: OK — pager killed holding 3 dirty pages; object faulted, data-integrity event reported exactly the lost ranges"
        ),
        DemoId::PagerReclaimDeadlock => {
            let (ordinary, reserved) = (v.arg0, v.arg1);
            kprintln!(
                "S3 reclaim-deadlock: OK — at hard pressure ({ordinary} ordinary frames used, {reserved} reserved) ordinary alloc blocked but a reserved write-back drained a page so reclaim progressed; an over-reservation write-back failed cleanly (range faulted), no hang"
            );
        }
        DemoId::PagerSelfPagingCycle => kprintln!(
            "S5 self-paging-cycle: OK — pager A↔B mutual backing forced to fault: the cycle was detected and the request faulted (not blocked); the degenerate single self-paging pager was broken the same way, no hang"
        ),
        DemoId::PagerDeadlineSupervision => {
            let (requests, escalations) = (v.arg0, v.arg1);
            kprintln!(
                "S7 deadline-supervision: OK — a pager missed its page-in deadline {requests} times: each faulting request got a bounded fault error (range faulted, not hung), and repeated misses escalated to {escalations} supervised restarts, all as events"
            );
        }
        DemoId::ObservabilityEvents => {
            let (n, page_ins, misses, escalations, faulted, wire, cap, dropped) = (
                v.arg0, v.arg1, v.arg2, v.arg3, v.arg4, v.arg5, v.arg6, v.arg7,
            );
            kprintln!(
                "events: OK — drained {n} structured events ({page_ins} page-in, {misses} deadline-miss, {escalations} supervision-escalate, {faulted} object-faulted), each {wire}-byte record round-tripped through its ISL binding; ring bounded at {cap} ({dropped} dropped at the source, reported by one meta-event)"
            );
        }
        DemoId::Correlation => {
            let (stamped, caller, restored, links, parent, faults, served) =
                (v.arg0, v.arg1, v.arg2, v.arg3, v.arg4, v.arg5, v.arg6);
            kprintln!(
                "correlation: OK — {stamped} events carried a live 128-bit id (epoch:seq) and their thread identity; a synchronous call propagated the caller's id {caller} to the callee for the call's duration and restored the callee's own {restored} on return; {links} fan-out link events named a parent distinct from their own fresh id (sample parent {parent}); {faults} contained ring-3 faults reported with the faulting thread's id; a page-in request crossed the message boundary still carrying its faulting thread's cause {served}"
            );
        }
        DemoId::DriverHostLadder => {
            let (crashed, restarted, gave_up, frames) = (v.arg0, v.arg1, v.arg2, v.arg3);
            kprintln!(
                "driver-ladder: OK — the supervisor's own records tell the crash-recovery story: {crashed} contained ring-3 crashes, each answered by exactly one reclaim-and-rebind ({restarted} restarts returning {frames} frames from the corpses), and {gave_up} give-up when a host exhausted its restart budget — severity escalating error → notice → critical"
            );
        }
        // Emitted only by the ports that run the ring-3 driver framework
        // (AArch64, RISC-V 64), which render their own line; x86-64's driver
        // host predates `MapDevice` and reaches its device by port I/O.
        DemoId::DeviceEvents => {}
        DemoId::DriverBind => {
            let (functions, bar_base, bar_len, identity) = (v.arg0, v.arg1, v.arg2, v.arg3);
            kprintln!(
                "driver-bind: OK — {functions} PCI functions enumerated; a ring-3 manager bound the mass-storage one by class to a ring-3 driver, which mapped its own {bar_len:#x} window at {bar_base:#x} and read {:#x} from {FAR_WINDOW_OFFSET:#x} into it — the bytes the kernel reads at that physical address",
                identity >> 32,
            );
        }
        // The architecture-conformance battery renders its own lines from its
        // own records, because it is shared with every other port and its
        // prose belongs to it rather than to this harness. Its failures are
        // counted above like any other verdict.
        DemoId::ArchMapTranslate
        | DemoId::ArchWxRefused
        | DemoId::ArchRemapRejected
        | DemoId::ArchProtect
        | DemoId::ArchUnmap
        | DemoId::ArchFrameOps
        | DemoId::ArchDirectMap
        | DemoId::ArchIcacheCoherence
        | DemoId::ArchContextSwitch => {}
    }
}

/// Correlation-id propagation (docs/observability/02, "Correlation IDs,
/// Normatively"; build/README.md D59). Events were causally anonymous until now —
/// timestamped and typed, but with nothing tying a page-in to the fault that
/// caused it. This proves the four properties the design names, against the
/// events the *preceding* demos actually emitted:
///
/// 1. every record carries a live 128-bit id (the boot epoch plus an
///    origin-minted sequence) and the identity of the thread that emitted it;
/// 2. a synchronous call propagated the caller's id to the callee "for the
///    duration of handling" and restored the callee's own afterwards, so a server
///    does not misattribute its later work to its last caller;
/// 3. spawning fans out — each branch minted a *fresh* id and emitted a link
///    event naming its parent, so traces form a tree;
/// 4. a contained ring-3 fault reported with the faulting thread's id.
///
/// Runs last, so the ring holds the link and fault events from the restart-heavy
/// supervision demos rather than a synthetic sequence.
fn correlation_demo() {
    use kcore::event::{self, Component, EventKind, Severity};
    const CAP: usize = event::EVENT_RING_CAPACITY;

    let epoch = kcore::trace::epoch();
    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut drained = [blank; CAP];
    let n = event::drain(&mut drained);

    // 1. Stamping: a live id, and the epoch agreeing on every record.
    let mut stamped = 0u64;
    let mut identified = 0u64;
    let mut epoch_ok = n > 0;
    for e in &drained[..n] {
        if e.correlation_lo != 0 {
            stamped += 1;
        }
        if e.thread_id != 0 {
            identified += 1;
        }
        if e.correlation_hi != epoch {
            epoch_ok = false;
        }
    }

    // 3. Fan-out: link events naming a real parent.
    let mut links = 0u64;
    let mut parent = 0u64;
    for e in drained[..n]
        .iter()
        .filter(|e| e.kind == EventKind::CorrelationLink)
    {
        // arg0 is the parent; the envelope carries the fresh child id. A branch
        // that shared its parent's id instead of minting would show them equal.
        if e.arg0 != 0 && e.correlation_lo != e.arg0 {
            links += 1;
            parent = e.arg0;
        }
    }

    // 4. Exception reports carrying the faulting thread's id.
    let faults = drained[..n]
        .iter()
        .filter(|e| e.kind == EventKind::UserFaultContained && e.correlation_lo != 0)
        .count() as u64;

    // 4b. The driver-host crash-recovery ladder, reported from the same drain.
    // It has to be this one: `observability_demo` runs *before* the supervision
    // demos, so this is the only drain that ever sees their records, and a
    // check of its own placed here would consume them instead.
    report_driver_host_ladder(&drained[..n]);

    // 2. Propagation across the synchronous call, sampled inside the round trip.
    let caller = CORRELATION_CALLER.load(Ordering::Relaxed);
    let during = CORRELATION_CALLEE_DURING_CALL.load(Ordering::Relaxed);
    let own = CORRELATION_CALLEE_OWN.load(Ordering::Relaxed);
    let restored = CORRELATION_CALLEE_RESTORED.load(Ordering::Relaxed);
    // The ids must be genuinely distinct, or "adopted" and "own" would be
    // indistinguishable and the check would pass vacuously.
    let distinct = caller != 0 && own != 0 && caller != own;
    let propagated = distinct && during == caller;
    let restored_ok = distinct && restored == own;

    // 5. Across a message boundary: the page-in request left the faulting thread
    //    with a cause and arrived at the pager still carrying it (D60) — the
    //    `docs/kernel/03` clause that the request carries a correlation id.
    let served = CORRELATION_PAGE_IN_SERVED.load(Ordering::Relaxed);
    let requests = CORRELATION_PAGE_IN_REQUESTS.load(Ordering::Relaxed);
    let matched = CORRELATION_PAGE_IN_MATCHED.load(Ordering::Relaxed);
    // Every request the in-kernel pager served arrived under the cause its
    // faulting thread sent it with — not merely the last one.
    let crossed = requests > 0 && matched == requests;

    let pass = epoch != 0
        && epoch_ok
        && stamped > 0
        && identified > 0
        && propagated
        && restored_ok
        && links > 0
        && faults > 0
        && crossed;
    report(&verdict(
        DemoId::Correlation,
        pass,
        [stamped, caller, restored, links, parent, faults, served, 0],
    ));
    if !pass {
        kprintln!(
            "correlation: FAIL — epoch={epoch:#x} epoch_ok={epoch_ok} drained={n} stamped={stamped} identified={identified} caller={caller:#x} during={during:#x} own={own:#x} restored={restored:#x} links={links} faults={faults} served={served:#x} matched={matched}/{requests}"
        );
    }
}

/// The driver-host crash-recovery ladder as the supervisor recorded it
/// (docs/drivers/01, "Crash Recovery"; build/README.md D112). The restart
/// demos already assert their own outcome from atomics they control; this
/// asserts the *records*, which is the thing a log service would have to work
/// from and which nobody was checking.
///
/// The counts are what the two supervised runs above must produce:
/// `driver_restart_budget_selftest` crashes 4 times against a budget of 4 and
/// then gives up; `driver_restart_demo` crashes twice and comes up clean. Each
/// contained crash is followed by exactly one reclaim-and-rebind, so crashes
/// and restarts must agree — a restart without a crash, or a crash the
/// supervisor never answered, is the interesting failure.
fn report_driver_host_ladder(drained: &[kcore::event::KernelEvent]) {
    // The reading itself is shared with every other port that runs a
    // supervisor (`kcore::event::summarize_driver_ladder`), and is host-tested
    // there against runs a boot cannot produce on purpose — a restart with no
    // crash behind it, a give-up filed at the wrong severity. What stays here
    // is the only part that is this boot's: how many crashes these two
    // supervised runs were driven to.
    let expected_crashes = u32::from(DRIVER_RESTART_BUDGET_SELFTEST_BUDGET) + 2;
    let s = kcore::event::summarize_driver_ladder(drained, kcore::trace::epoch());
    let pass = s.describes_a_contained_ladder(expected_crashes) && s.gave_up == 1;
    report(&verdict(
        DemoId::DriverHostLadder,
        pass,
        [
            u64::from(s.crashed),
            u64::from(s.restarted),
            u64::from(s.gave_up),
            s.reclaimed_frames,
            u64::from(expected_crashes),
            0,
            0,
            0,
        ],
    ));
    if !pass {
        kprintln!(
            "driver-ladder: FAIL crashed={} (expected {expected_crashes}) restarted={} gave_up={} frames={} component={} severities={} stamped={}",
            s.crashed,
            s.restarted,
            s.gave_up,
            s.reclaimed_frames,
            s.component_ok,
            s.severities_ok,
            s.stamped_ok,
        );
    }
}

/// Structured observability events (docs/observability/01, "Structured Logging";
/// build/README.md D57). Drains the ring the kernel mechanisms emitted into
/// during the preceding demos — page-in latencies, pager deadline misses and
/// supervision escalations, object-faulted data-integrity records, reclaim
/// overflows — proves every record is wire-valid against its ISL schema, and
/// shows the bound: a flood drops at the source, counts, and reports itself with
/// an `EVENTS_DROPPED` meta-event so the silencing is visible.
fn observability_demo() {
    use kcore::event::{self, Component, EventKind, KernelEvent, Severity};
    const CAP: usize = event::EVENT_RING_CAPACITY;
    const WIRE: usize = KernelEvent::WIRE_SIZE;

    // A blank record to initialize the drain buffer (overwritten by `drain`).
    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );

    // 1. What the mechanisms emitted while the earlier demos ran.
    let mut drained = [blank; CAP];
    let n = event::drain(&mut drained);
    let (mut page_ins, mut misses, mut escalations, mut faulted) = (0u32, 0u32, 0u32, 0u32);
    for e in &drained[..n] {
        match e.kind {
            EventKind::PagerPageIn => page_ins += 1,
            EventKind::PagerDeadlineMiss => misses += 1,
            EventKind::PagerSupervisionEscalate => escalations += 1,
            EventKind::PagerObjectFaulted => faulted += 1,
            _ => {}
        }
    }

    // 2. Every emitted record is wire-valid against the generated ISL binding:
    //    encode to the golden size, decode back, compare.
    let mut wire_ok = n > 0;
    for e in &drained[..n] {
        let mut bytes = [0u8; WIRE];
        let encoded = tessera_isl_runtime::encode(e, &mut bytes).unwrap_or(0);
        let decoded: Option<KernelEvent> = tessera_isl_runtime::decode(&bytes).ok();
        if encoded != WIRE || decoded != Some(*e) {
            wire_ok = false;
        }
    }
    // The envelope every record carries (docs/observability/01's field set).
    let envelope_ok = drained[..n]
        .iter()
        .all(|e| e.size == WIRE as u32 && e.version == event::EVENT_SCHEMA_VERSION);

    // 3. The bound: overflow the ring, then confirm the drops were counted and
    //    the next emission with room reports them once as a meta-event.
    for _ in 0..(CAP as u32 + 8) {
        event::emit(
            EventKind::PagerPageIn,
            Severity::Debug,
            Component::Pager,
            [0; 4],
        );
    }
    let dropped = event::dropped();
    // Drain to make room, then one more emission carries the drop notice.
    let mut flood = [blank; CAP];
    let flooded = event::drain(&mut flood);
    event::emit(
        EventKind::PagerPageIn,
        Severity::Debug,
        Component::Pager,
        [0; 4],
    );
    let mut tail = [blank; CAP];
    let tail_n = event::drain(&mut tail);
    let notice = tail[..tail_n]
        .iter()
        .find(|e| e.kind == EventKind::EventsDropped);
    let bound_ok = dropped == 8
        && flooded == CAP
        && notice.is_some_and(|e| e.arg0 == 8 && e.severity == Severity::Warning)
        && event::dropped() == 0;

    let pass = n > 0
        && page_ins > 0
        && misses == 6
        && escalations == 2
        && faulted > 0
        && wire_ok
        && envelope_ok
        && bound_ok;
    report(&verdict(
        DemoId::ObservabilityEvents,
        pass,
        [
            n as u64,
            u64::from(page_ins),
            u64::from(misses),
            u64::from(escalations),
            u64::from(faulted),
            WIRE as u64,
            CAP as u64,
            dropped,
        ],
    ));
    if !pass {
        kprintln!(
            "events: FAIL n={n} page_ins={page_ins} misses={misses} esc={escalations} faulted={faulted} wire={wire_ok} envelope={envelope_ok} bound={bound_ok} dropped={dropped}"
        );
    }
}

/// Runs the microbenchmark suite and reports each result over serial. Always
/// returns so the boot reaches the alive marker; a budget miss is informational.
fn perf_harness(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    kprintln!(
        "perf: microbenchmarks, {PERF_SAMPLES} samples, TSC {} (QEMU/TCG cycles — not R1 compliance)",
        if tsc_invariant() {
            "invariant"
        } else {
            "non-invariant"
        }
    );
    perf_bench_handle_op();
    perf_bench_anon_fault(kernel_vm, frames);
    perf_bench_cow_fault(kernel_vm, frames);
    perf_bench_page_in(kernel_vm, frames);
    perf_bench_ipc(kernel_vm, frames);
    perf_bench_b11(kernel_vm, frames);
    perf_bench_syscall(kernel_vm, frames);
    perf_bench_ctxsw(kernel_vm, frames, false, "B7 ctx-sw/same", 2, 3);
    perf_bench_ctxsw(kernel_vm, frames, true, "B7 ctx-sw/cross", 4, 5);
    perf_bench_waitwake(kernel_vm, frames);
    // The cross-AS benchmark leaves a scratch CR3 active; restore the kernel
    // space so the alive marker and exit run under it.
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(Cpu::cpu_id()) };
}

/// Entry point. Limine enters here in 64-bit long mode, higher half, with
/// the HHDM active and interrupts masked.
// SAFETY: the bootloader transfers control to the unmangled `_start`
// symbol; nothing else in the image defines it, and it never returns.
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    // SAFETY: `_start` runs exactly once, single-threaded, before any
    // other code; this is the only reference ever taken to UART.
    let uart = unsafe { &mut *&raw mut UART };
    uart.init();
    let dropped = kcore::console::init_global(uart);
    // Timestamp source for structured events; the kernel core is
    // architecture-independent, so the cycle counter arrives as a hook.
    kcore::event::set_clock(Cpu::counter_serialized);
    // Boot is a causal origin — "boot itself" (docs/observability/02) — and the
    // first one, so it also installs the epoch that forms the high half of every
    // id minted this boot. The epoch is seeded from the TSC purely so ids from
    // different boots do not collide; correlation ids are not secrets and no
    // semantics depend on their unpredictability (build/README.md, D59).
    kcore::trace::set_epoch(Cpu::counter_serialized());
    kcore::trace::set_current_correlation(kcore::trace::mint());

    kprintln!("Tessera {VERSION} (Stage 0 skeleton, x86-64)");
    kprintln!("early console: COM1 @ 115200");
    if dropped > 0 {
        kprintln!("early console: {dropped} write(s) dropped before init");
    }

    // CPU tables next: from here on, a fault produces a register dump
    // instead of a silent triple fault.
    // SAFETY: once, on the boot CPU, interrupts still disabled.
    unsafe { tessera_karch_x86_64::init_bsp_tables() };
    tessera_karch_x86_64::set_trap_handler(fatal_trap);
    kprintln!(
        "cpu{}: GDT/TSS (+ring-3 segs), IDT, per-CPU block, SYSCALL/SYSRET loaded",
        Cpu::cpu_id()
    );

    if TRAP_SELF_TEST {
        kprintln!("trap self-test: executing ud2");
        // SAFETY: deliberately undefined instruction; the trap handler
        // never returns here.
        unsafe { core::arch::asm!("ud2") };
    }

    if !limine::base_revision_supported() {
        panic!("bootloader does not support requested Limine base revision");
    }

    let hhdm_offset = match limine::hhdm_offset() {
        Some(offset) => {
            kprintln!("hhdm: offset {offset:#x}");
            offset
        }
        None => panic!("bootloader provided no HHDM response"),
    };

    // Memory: normalize the boot map, bring up frame allocation, donate a
    // contiguous run to the kernel heap, and prove it end to end.
    // SAFETY: `_start` runs once, single-threaded; this is the only
    // reference ever taken to MEMORY_MAP.
    let map_storage = unsafe { &mut *&raw mut MEMORY_MAP };
    let (filled, reported) = match limine::normalize_memory_map(map_storage) {
        Some(counts) => counts,
        None => panic!("bootloader provided no memory map"),
    };
    if reported > filled {
        kprintln!(
            "memmap: WARNING: {} region(s) dropped (capacity {MAX_MEMORY_REGIONS})",
            reported - filled
        );
    }
    let memory_map: &[MemoryRegion] = &map_storage[..filled];
    let mut frames = kcore::pmem::BumpFrameAllocator::new(memory_map);
    let usable_frames = frames.total_usable_frames();
    kprintln!(
        "memmap: {filled} regions, {usable_frames} usable frames ({} MiB usable)",
        usable_frames * FRAME_SIZE / (1024 * 1024)
    );

    // Kernel page tables: build our own and drop the bootloader's. The kernel
    // image is mapped write-XOR-execute, and the direct map is placed at a
    // KASLR-randomized higher-half base rather than the fixed bootloader HHDM.
    // The boot stack's region is kept mapped at the HHDM base as a
    // compatibility window so this thread's (HHDM) stack survives the switch;
    // table edits and the heap re-derive their pointers from the new base.
    let (kernel_phys_base, kernel_virt_base) = match limine::executable_address() {
        Some(bases) => bases,
        None => panic!("bootloader provided no executable-address response"),
    };
    let max_phys = max_physical_address(memory_map);
    if !direct_map_choice_is_sound(max_phys) {
        panic!("direct-map KASLR cannot place a {max_phys:#x} span clear of every reserved slot");
    }
    let direct_map_base = match choose_direct_map_base(max_phys) {
        Some(base) => base,
        None => panic!("direct-map KASLR found no slot for a {max_phys:#x} span"),
    };
    let sections = kernel_sections();
    let mut kernel_space = match tessera_karch_x86_64::build_kernel_address_space(
        &mut frames,
        hhdm_offset,     // access base: the HHDM, active while we build
        direct_map_base, // where the new tables map physical memory (randomized)
        kernel_phys_base,
        kernel_virt_base,
        &sections,
        max_phys,
    ) {
        Ok(space) => space,
        Err(e) => panic!("kernel page-table construction failed: {e:?}"),
    };
    if direct_map_base != hhdm_offset {
        map_boot_stack_compat(&mut kernel_space, hhdm_offset, &mut frames);
    }
    let kernel_cr3 = kernel_space.root_phys();
    // SAFETY: one-time on the boot CPU before the first CR3 load; enables the
    // NX and global-page features the new mappings rely on.
    unsafe { tessera_karch_x86_64::enable_paging_features() };
    // SAFETY: `kernel_space` maps this code (kernel image), the boot stack
    // (HHDM compatibility window), and all kernel statics at their current
    // virtual addresses, so the CR3 load switches tables without faulting.
    unsafe { kernel_space.activate() };
    // Physical memory is now reachable only through the kernel's own direct
    // map; redirect table edits there.
    // SAFETY: the kernel tables (now active) map all physical memory at
    // `direct_map_base`.
    unsafe { kernel_space.set_access_base(direct_map_base) };
    kprintln!(
        "paging: kernel CR3 {:#x}, direct-map base {direct_map_base:#x} (KASLR), mapped to {max_phys:#x}",
        kernel_cr3.as_u64()
    );

    // Wrap the kernel tables in an AddressSpace object (the BSP is already
    // running on them) and prove the runtime mapper end to end: map an
    // anonymous region, confirm it is zero-filled, write and read it back,
    // then unmap it.
    let mut kernel_vm = AddressSpace::from_arch(kernel_space, Asid(0), 1u64 << Cpu::cpu_id());
    mapper_self_check(&mut kernel_vm, &mut frames);
    kprintln!("vmem: kernel address space ready (mapper self-check passed)");

    if STACK_GUARD_SELF_TEST {
        run_stack_guard_self_test(&mut kernel_vm, &mut frames);
    }

    let heap_phys = match frames.alloc_contiguous(HEAP_FRAMES) {
        Some(base) => base,
        None => panic!("no contiguous {HEAP_FRAMES}-frame run for the kernel heap"),
    };
    let heap_size = (HEAP_FRAMES * FRAME_SIZE) as usize;
    // Re-derived from the randomized direct-map base, not the bootloader HHDM.
    let heap_virt = match NonNull::new((direct_map_base + heap_phys.as_u64()) as *mut u8) {
        Some(ptr) => ptr,
        None => panic!("heap virtual address is null"),
    };
    // SAFETY: the frames were just handed out exclusively for the heap, and
    // the kernel direct map makes them writable at `heap_virt` for the
    // kernel's lifetime.
    unsafe { kcore::heap::KERNEL_HEAP.lock().init(heap_virt, heap_size) };
    heap_self_check();
    kprintln!(
        "heap: {} KiB at phys {:#x} (self-check passed)",
        heap_size / 1024,
        heap_phys.as_u64()
    );

    // The verified image store, before anything that might want to read from
    // it. Nothing here needs a device, a bus or a process — the container is in
    // this kernel's own image — so it runs first among the checks, which is
    // also the order `docs/security/01` ("Boot Security") describes: what the
    // system will trust is established before it is used.
    if system_store().is_empty() {
        kprintln!("store: skipped — no system store embedded (cargo inner loop)");
    } else {
        let mut scratch = [0u8; STORE_SCRATCH];
        match kcore::store::self_check(system_store(), &mut scratch) {
            Ok(r) => kprintln!(
                "store: OK — mounted a {} B store of {} blob(s) whose directory measured to the anchor this kernel is compiled to trust, and read firmware.bin ({} B, {:#018x}...); a byte changed in that blob is refused at open and one changed in the directory refuses the whole container",
                r.bytes,
                r.entries,
                r.firmware_len,
                r.firmware_lead
            ),
            Err(error) => {
                kprintln!("store: FATAL: check failed ({})", error.code());
                DebugExit::exit(ExitCode::Failure)
            }
        }
    }

    // The architecture-conformance battery: the same porting-layer checks the
    // AArch64 port runs, so "x86-64 implements the layer" is a result rather
    // than the oldest port's privilege (docs/hardware/01, "Porting Rules" 5).
    let arch_conformance = tessera_arch_conformance::run::<ContextSwitch, _>(
        &mut tessera_arch_conformance::Platform {
            space: kernel_vm.arch_mut(),
            frames: &mut frames,
            direct_map_base,
            scratch: VirtAddr::new(CONFORMANCE_SCRATCH),
            sentinel_code: SENTINEL_CODE,
        },
    );
    kprintln!(
        "arch: {} passed, {} failed",
        arch_conformance.passed,
        arch_conformance.failed
    );
    // The battery renders its own verdicts, so they never pass through
    // `report`. Its failures must still reach the exit gate, or a port could
    // fail the porting-layer contract and still exit 33 (build/README.md,
    // D58: a failing demo fails the build).
    DEMOS_FAILED.fetch_add(u64::from(arch_conformance.failed), Ordering::Relaxed);

    // Capabilities: exercise the handle + rights system end to end — create an
    // object, take handles, narrow rights, reject an expansion, and watch the
    // object die when its last handle closes.
    handle_self_check();

    // IPC: the synchronous-handoff bet. Two kernel threads and one channel; a
    // caller `call`s a callee that `receive`s and `reply`s, and the round trip
    // must cost exactly two context switches with a handle transferred across.
    ipc_roundtrip_demo(&mut kernel_vm, &mut frames);

    // Root task: load and run a *real ELF* (parsed, not a copied blob) via the
    // three-phase create → populate(load PT_LOAD, W^X) → start path — the loader
    // bet (D25).
    loader_demo(&mut kernel_vm, &mut frames);

    // Channel IPC: a ring-3 client calls a ring-3 server over a channel (inline
    // bytes + a transferred handle) via the synchronous call/reply handoff — the
    // user-space-services substrate (M15).
    channel_ipc_demo(&mut kernel_vm, &mut frames);

    // User mode: the isolation bet. Run a program in ring 3 in its own address
    // space that reaches the kernel only through the SYSCALL boundary, and prove
    // a fault in it is contained (the process dies, the kernel lives).
    user_mode_demo(&mut kernel_vm, &mut frames);

    // Demand paging: a ring-3 program that faults on lazy anonymous pages and a
    // copy-on-write snapshot, and whose faults are resolved and resumed rather
    // than fatal — the reclaim bet.
    demand_paging_demo(&mut kernel_vm, &mut frames);

    // External pager: a ring-3 program reads pager-backed memory whose pages a
    // pager kernel thread supplies over IPC — the page-in bet.
    pager_demo(&mut kernel_vm, &mut frames);

    // Wait-on-address: a ring-3 thread blocks on a futex word inside its syscall
    // and a kernel thread wakes it across the ring boundary — the B6 primitive.
    wait_on_address_demo(&mut kernel_vm, &mut frames);

    // Ports: async event delivery that coalesces edges into one event carrying a
    // pending count and never loses an edge — a consumer drains, a producer
    // signals and wakes it across threads.
    ports_demo(&mut kernel_vm, &mut frames);

    // Jobs: the containment tree. Build root + a tighter child, enforce the
    // tighten-only limit / member cap / KILL right, then kill the subtree
    // innermost-first and drain the state port — the teardown bet.
    jobs_demo(&mut kernel_vm, &mut frames);

    // Pager under pressure: the write-back / dirty-tracking / eviction bets
    // (docs/prototypes/02). Dirty throttling (S2), dirty-range query (S8),
    // durability ordering (S4), and pager death (S6).
    pager_throttle_demo(&kernel_vm, &mut frames);
    pager_dirty_query_demo(&kernel_vm, &mut frames);
    pager_durability_demo(&kernel_vm, &mut frames);
    pager_death_demo(&mut kernel_vm, &mut frames);
    pager_reclaim_deadlock_demo(&kernel_vm, &mut frames);
    pager_self_paging_cycle_demo();
    pager_deadline_supervision_demo();
    observability_demo();

    // Driver host: a ring-3 driver owns a real device (COM2, IRQ3), receives its
    // interrupt as a port event, and services a client's I/O over a channel —
    // the driver-host I/O bet (M16). Runs before `scheduler_demo` so the timer
    // and its `TICK_HOOK` are still off.
    driver_host_demo(&mut kernel_vm, &mut frames);

    // Device manager: a ring-3 service owns a device resource-graph node and
    // grants its capability to a driver host over a channel; the driver drives
    // the device through the granted cap and services a client (M17). Also before
    // `scheduler_demo` (its driver takes the device IRQ in ring 3).
    device_manager_demo(&mut kernel_vm, &mut frames);

    // The driver framework proper (D145): a real PCI function, a ring-3 manager
    // that classifies it from the graph and binds it by class, and a ring-3
    // driver that is a compiled program rather than a blob. Runs after the demo
    // above because it replaces the process table and executive, and before the
    // scheduler demo for the same reason that one does.
    match driver_bind_check(&mut kernel_vm, &mut frames, memory_map) {
        Ok(Some(outcome)) => report(&verdict(
            DemoId::DriverBind,
            outcome.reported == outcome.expected,
            [
                outcome.functions as u64,
                outcome.bar_base,
                outcome.bar_len,
                outcome.reported,
                outcome.expected,
                0,
                0,
                0,
            ],
        )),
        Ok(None) => kprintln!(
            "driver-bind: skipped (no embedded manager/driver ELF, or no mass-storage function attached)"
        ),
        Err(which) => {
            kprintln!(
                "driver-bind: FAIL — check {which} failed (report {:#x}, count {})",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **Enumeration, done again and from outside.** The walk above was the
    // kernel's, through the legacy configuration ports; this hands a ring-3
    // program the memory-mapped window the chipset reports and lets it do the
    // same work with the same crate. The two reach configuration space by
    // different means and must agree about the same function.
    match pci_bus_check(&mut kernel_vm, &mut frames, memory_map) {
        Ok(Some(outcome)) => kprintln!(
            "pci-bus: OK — a ring-3 program held the host bridge and nothing else, walked it through the memory-mapped window this chipset reports and DECLARED the {} function(s) it found: every PCI device in the resource graph was put there by an unprivileged process. It offered them to the device manager as capabilities rather than as claims, the manager took hardware it had never seen, and a driver bound one by class. That driver mapped its OWN configuration space — 4 KiB scoped to one function, on a right separate from the one that maps its registers — and read {:04x}:{:04x} out of it. The kernel reaches config space through the 0xCF8 port pair and found the same thing, so neither walk produced the other's answer by echoing it",
            outcome.functions,
            outcome.word & 0xffff,
            outcome.word >> 16,
        ),
        Ok(None) => kprintln!(
            "pci-bus: skipped (no embedded bus-driver ELF, no mass-storage function, or the chipset reports no ECAM window)"
        ),
        Err(which) => {
            kprintln!(
                "pci-bus: FAIL — check {which} failed (reports {:#x} {:#x})",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORTS[1].load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // RAM-backed filesystem service: a ring-3 service supplies pages to the
    // external pager — a client maps a pager-backed object, faults, and the
    // ring-3 FS service supplies the page from its own buffer (M18).
    fs_supply_selftest(&mut kernel_vm, &mut frames);
    fs_service_demo(&mut kernel_vm, &mut frames);

    // Component manager: a ring-3 manager launches a service (the M14 loader
    // syscalls), supervises it via the synchronous ProcessStart-returns-exit-code
    // handoff, and restarts it on each "crash" (non-zero exit) until it comes up
    // clean — the roadmap's "Service dependency restart" (M19). The negative
    // self-test proves the restart budget caps a service that keeps crashing.
    cm_budget_selftest(&mut kernel_vm, &mut frames);
    component_manager_demo(&mut kernel_vm, &mut frames);
    // Reclaim-on-exit (M20): the manager restarts a service far past the old
    // ~15-launch leak bound, proving each exited child's process/thread slots,
    // kernel stack, address space, and handle are returned to their pools.
    cm_reclaim_stress(&mut kernel_vm, &mut frames);
    // Driver-host restart on crash: a ring-3 driver host crashes via a real
    // #PF; the kernel contains it and a supervisor reclaims + rebinds + restarts it
    // per a (countdown, budget) policy until it comes up clean and serves a client
    // — the Stage-0 "kill-a-driver-host-under-load recovers" gate. Runs before
    // scheduler_demo (IRQ3 in ring-3 needs the timer/TICK_HOOK off, like M16/M17).
    driver_crash_reclaim_selftest(&mut kernel_vm, &mut frames);
    driver_restart_budget_selftest(&mut kernel_vm, &mut frames);
    driver_restart_demo(&mut kernel_vm, &mut frames);

    // Threads and scheduling: spawn CPU-bound worker threads on guard-paged
    // stacks and let the timer preempt them round-robin. This is the first use
    // of the timer, which now drives preemption rather than a bare tick count.
    scheduler_demo(&mut kernel_vm, &mut frames);

    // Performance: measure the primitives against their budgets (rig + numbers;
    // R1 compliance is bare-metal, so this never fails the boot).
    perf_harness(&mut kernel_vm, &mut frames);

    // Correlation ids: the events the demos above emitted are causally joinable —
    // stamped with a live id and thread identity, propagated across a synchronous
    // call, and linked parent-to-child on fan-out (D59). Last, so the ring holds
    // the restart demos' link and fault events.
    correlation_demo();

    // The verdict records decide the exit status: before this, every demo could
    // print FAIL and the boot still exited success, so CI could not catch a
    // regression (build/README.md, D58).
    let failed = DEMOS_FAILED.load(Ordering::Relaxed);
    if failed > 0 {
        kprintln!("TESSERA-STAGE0: {failed} demo(s) FAILED");
    }
    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    // Clean exit for CI; on hardware without the exit device this halts
    // forever instead.
    DebugExit::exit(if failed > 0 {
        ExitCode::Failure
    } else {
        ExitCode::Success
    })
}

/// Allocates, writes, reads back, and frees through the freshly donated
/// heap — a mapping or allocator defect fails the boot loudly here rather
/// than corrupting something later.
fn heap_self_check() {
    let mut heap = kcore::heap::KERNEL_HEAP.lock();
    let layout = match Layout::from_size_align(4096, 64) {
        Ok(layout) => layout,
        Err(_) => panic!("heap self-check layout invalid"),
    };
    let ptr = match heap.try_alloc(layout) {
        Ok(ptr) => ptr,
        Err(_) => panic!("heap self-check allocation failed"),
    };
    // SAFETY: `ptr` is a fresh exclusive allocation of `layout.size()`
    // bytes; writing and reading it back stays in bounds.
    unsafe {
        core::ptr::write_bytes(ptr.as_ptr(), 0xa5, layout.size());
        if ptr.as_ptr().read_volatile() != 0xa5
            || ptr.as_ptr().add(layout.size() - 1).read_volatile() != 0xa5
        {
            panic!("heap self-check readback mismatch");
        }
        heap.dealloc(ptr, layout);
    }
    if heap.used() != 0 {
        panic!(
            "heap self-check leak: {} bytes still accounted",
            heap.used()
        );
    }
}

/// Fatal-trap handler: full register dump over serial, then a failure
/// exit. Unhandled exceptions are kernel bugs in this milestone — there is
/// no recovery path until the pager exists.
fn fatal_trap(frame: &TrapFrame) -> ! {
    if kcore::panic::enter() == PanicDisposition::ExitImmediately {
        // Trap while already reporting: the reporting path is suspect.
        DebugExit::exit(ExitCode::Failure);
    }
    // SAFETY: fatal path on the only running CPU, interrupts masked by the
    // interrupt gate — no console-lock holder can still be running.
    unsafe { kcore::console::unlock_for_panic() };
    let vector = frame.vector;
    kprintln!();
    kprintln!(
        "!!! EXCEPTION: vector {vector} ({}), error code {:#x}",
        tessera_karch_x86_64::vector_name(vector),
        frame.error_code,
    );
    // A page fault whose address sits within a page of the faulting stack
    // pointer is a kernel stack overflow into the guard page — the exception
    // stack (IST) is why this reports instead of triple-faulting.
    if vector == 14 {
        let fault_addr = tessera_karch_x86_64::read_cr2();
        if frame.rsp.abs_diff(fault_addr) < FRAME_SIZE {
            kprintln!("    KERNEL STACK OVERFLOW: guard-page fault at {fault_addr:#018x}");
        }
    }
    kprintln!(
        "    RIP={:#018x} CS={:#06x} RFLAGS={:#010x}",
        frame.rip,
        frame.cs,
        frame.rflags,
    );
    kprintln!(
        "    RSP={:#018x} SS={:#06x} CR2={:#018x} CR3={:#018x}",
        frame.rsp,
        frame.ss,
        tessera_karch_x86_64::read_cr2(),
        tessera_karch_x86_64::read_cr3(),
    );
    kprintln!(
        "    RAX={:#018x} RBX={:#018x} RCX={:#018x} RDX={:#018x}",
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
    );
    kprintln!(
        "    RSI={:#018x} RDI={:#018x} RBP={:#018x} R8 ={:#018x}",
        frame.rsi,
        frame.rdi,
        frame.rbp,
        frame.r8,
    );
    kprintln!(
        "    R9 ={:#018x} R10={:#018x} R11={:#018x} R12={:#018x}",
        frame.r9,
        frame.r10,
        frame.r11,
        frame.r12,
    );
    kprintln!(
        "    R13={:#018x} R14={:#018x} R15={:#018x}",
        frame.r13,
        frame.r14,
        frame.r15,
    );
    DebugExit::exit(ExitCode::Failure)
}

/// Panics are bugs (docs/lifecycle/04-coding-guidelines.md, "Failure
/// Discipline"): report once, exit with failure; a nested panic skips
/// reporting entirely.
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    match kcore::panic::enter() {
        PanicDisposition::ExitImmediately => DebugExit::exit(ExitCode::Failure),
        PanicDisposition::Report => {
            // SAFETY: panic path on the only running CPU; interrupts are
            // not yet enabled anywhere in this milestone.
            unsafe {
                kcore::panic::report_global(format_args!("{}", info.message()), info.location());
            }
            DebugExit::exit(ExitCode::Failure)
        }
    }
}

/// The system image's verified store, where the build embedded one. Only the
/// Bazel build assembles it (`//store:system_store_image`); the cargo inner
/// loop builds without it and the check reports it absent, exactly as the
/// ring-3 images do.
#[cfg(has_system_store)]
fn system_store() -> &'static [u8] {
    &system_store_image::SYSTEM_STORE
}
#[cfg(not(has_system_store))]
fn system_store() -> &'static [u8] {
    &[]
}

/// Room for a working copy of the store. Sized for the container the build
/// produces with headroom; a store that outgrew it is refused loudly rather
/// than silently checked in part. Its size is this port's business — the check
/// itself is `kcore::store::self_check`, driven identically by every port.
const STORE_SCRATCH: usize = 8192;
