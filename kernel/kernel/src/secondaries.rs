// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Taking the application processors off the bootloader's memory and parking
//! them on the kernel's, x86-64.
//!
//! # Why this exists before there is any SMP
//!
//! Asking the bootloader how many CPUs the machine has is not a read. The
//! protocol answers that question by *starting* every application processor
//! into a wait loop of its own, and that loop's code sits in memory the same
//! boot protocol reports as **usable** — because a kernel that asks for the
//! list is expected to take the CPUs, after which the memory is genuinely free.
//!
//! This kernel starts no CPU (build/README.md, D8), so without this module it
//! would ask for the list, hand that memory to the frame allocator, and write
//! its own page tables over an instruction stream another core is executing.
//! That is not a theoretical hazard: it is what happened, and the symptom was a
//! triple fault on a core with a null IDT and the bootloader's `CR3`, tens of
//! thousands of instructions after the boot appeared to have gone fine.
//!
//! So the count is not free, and this is its price.
//!
//! # Three stages, because the destination does not exist yet
//!
//! The frames that overwrite the wait loop are spent *building* the kernel's
//! page tables, so by the time there is a kernel `CR3` to move a core onto, the
//! damage is done. Parking therefore happens first, in two stages:
//!
//! 1. [`park_all`], before the first frame is allocated. Each core is sent to
//!    the stub below, which lives in kernel text — memory the allocator never
//!    hands out — and waits there. It is still on the bootloader's page tables,
//!    which is survivable because those live in bootloader-reclaimable memory
//!    and this kernel allocates only from usable.
//! 2. [`adopt_tables`], once the kernel's root exists. Each core loads it,
//!    takes a stack of its own, and calls into Rust to say which CPU it is.
//!    After this nothing the cores touch belongs to the bootloader, and that
//!    invariant stops being an unstated dependency on which memory kind the
//!    allocator happens to use.
//! 3. [`ApplicationProcessors::start`], when the kernel decides a CPU is to
//!    take an index. Each core is waiting on a cell of its own; writing that
//!    cell releases it into [`init_cpu_tables`] and then into an idle halt.
//!
//! # Why the third stage is not another `goto_address`
//!
//! The bootloader's per-CPU entry pointer is a one-shot: writing it is what
//! took the core out of the wait loop, and by the time the kernel wants to
//! *start* a CPU that core has long since left. So the release is the kernel's
//! own — a store to a cell the core is already spinning on, in memory the
//! kernel owns, needing no firmware call at all. That is the whole of the
//! difference from the AArch64 port, where a CPU that has not been started may
//! be powered down and only firmware can wake it.
//!
//! # How a core says which one it is
//!
//! It reads its own local-controller id (`CpuOps::hw_id`, CPUID) and publishes
//! it into the slot it claimed on arrival. The slot came from an atomic
//! increment, so it is arrival order and nothing else — sparse identifiers
//! cannot index an array, which is the same reason the kernel's dense index is
//! assigned rather than read. Matching a start request against those published
//! identifiers is what makes "start the CPU firmware calls 3" a well-formed
//! request on a port whose CPUs were already running.
//!
//! The bootloader also listed those identifiers, and this keeps that list
//! separately: two statements of the same set, from firmware and from the CPUs
//! themselves, and a start request that cannot be matched says so rather than
//! starting whichever core happened to be first.
//!
//! # The stub
//!
//! It is entered with the bootloader's address space active, so it must be
//! mapped in both — it is, because the kernel image is mapped at its link
//! address by the bootloader and by the kernel's own tables, and every
//! reference below is `rip`-relative. It uses no stack: no call, no push. The
//! bootloader gave it one, and that stack is in the memory being reclaimed.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 0"),
//! docs/kernel/08-multicore-scalability.md
//! Budget: none (boot path)

use crate::limine;
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_karch::{CpuBringUp, CpuOps, CpuStartError, InterruptControl};
use tessera_karch_x86_64::{CPU_TABLE_SLOTS, Cpu, init_cpu_tables};

/// How long the boot CPU waits for a released core to announce itself.
///
/// A spin count rather than a time, because there is no tick yet and what it
/// bounds is not a duration anyone cares about — only the difference between
/// reporting an absent CPU and hanging on it. Generous enough that an emulated
/// core under a loaded host is not called absent, short enough that a boot
/// which loses every core still finishes.
pub const ARRIVAL_SPINS: u64 = 200_000_000;

/// Stack bytes each parked core takes once it is on the kernel's tables.
///
/// Small on purpose: a parked core calls three functions and halts. It must
/// stay a power of two the stub can form by shifting.
const PARK_STACK_BYTES: usize = 16 * 1024;

/// The alignment is the point of the wrapper, as it is for the AArch64 port's
/// secondary stacks: a `u8` array is byte-aligned, and the ABI requires a
/// 16-byte-aligned stack pointer at every call.
#[repr(align(16))]
// The field is read by the entry stub and by nothing else, which is what makes
// it dead to the compiler and load-bearing to the machine.
#[allow(dead_code)]
struct ParkStacks([[u8; PARK_STACK_BYTES]; CPU_TABLE_SLOTS]);

// SAFETY: the stub reaches this array by name from `global_asm!`, so the symbol
// must survive; nothing else in the image defines it, and nothing in Rust reads
// it — which is what makes it dead to the compiler and load-bearing to the
// machine.
#[unsafe(no_mangle)]
#[allow(dead_code)]
static mut PARK_STACKS: ParkStacks = ParkStacks([[0; PARK_STACK_BYTES]; CPU_TABLE_SLOTS]);

/// What one parked core has said about itself, and what the kernel has told it
/// to become.
struct ParkedCpu {
    /// The core's own local-controller id, published by the core.
    hw_id: AtomicU64,
    /// The dense index the core is to take, plus one; zero while it is still
    /// waiting. Plus one because zero is a real index and this cell must have a
    /// value that means "nothing yet".
    release: AtomicU64,
    /// The descriptor-table base this core has loaded, read back out of its own
    /// hardware after it took its tables. Zero until then.
    gdt_base: AtomicU64,
}

impl ParkedCpu {
    #[allow(clippy::declare_interior_mutable_const)]
    const WAITING: Self = Self {
        hw_id: AtomicU64::new(0),
        release: AtomicU64::new(0),
        gdt_base: AtomicU64::new(0),
    };
}

static PARKED: [ParkedCpu; CPU_TABLE_SLOTS] = [const { ParkedCpu::WAITING }; CPU_TABLE_SLOTS];

/// The local-controller ids the *bootloader* listed, boot CPU first, captured
/// while its response memory was still intact.
static LISTED: [AtomicU64; CPU_TABLE_SLOTS] = [const { AtomicU64::new(u64::MAX) }; CPU_TABLE_SLOTS];
static LISTED_COUNT: AtomicU64 = AtomicU64::new(0);

/// The kernel `CR3` the stub installs, or zero while there is not one yet.
/// Read by each parked core through the same virtual address in both address
/// spaces.
// SAFETY: the stub reaches this static by name from `global_asm!`, so it must keep
// the symbol the assembly refers to; nothing else in the image defines it.
#[unsafe(no_mangle)]
static SECONDARY_KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

/// Incremented by each core once it is executing kernel text (stage 1).
// SAFETY: as above — named by the `global_asm!` stub, defined nowhere else.
#[unsafe(no_mangle)]
static SECONDARIES_PARKED: AtomicU64 = AtomicU64::new(0);

/// Incremented by each core once it is on the kernel's page tables **and has
/// said which CPU it is** (stage 2).
///
/// The two are one event on purpose. A core that had adopted the tables but not
/// yet published its identifier would be invisible to a start request aimed at
/// it, and the boot CPU would report a CPU it could not find on a machine where
/// nothing was wrong — a race that resolves itself is the worst kind to leave
/// in a boot path.
static SECONDARIES_ADOPTED: AtomicU64 = AtomicU64::new(0);

// SAFETY: this declares a symbol defined by the `global_asm!` block below. Its
// only use is as the address written into a bootloader `goto_address` field,
// which is exactly the signature the protocol specifies.
unsafe extern "C" {
    fn secondary_park_stub(info: *mut core::ffi::c_void) -> !;
}

core::arch::global_asm!(
    r#"
.section .text.secondary_park
.globl secondary_park_stub
secondary_park_stub:
    // Interrupts off before anything else: this core has no IDT of its own and
    // any vector it took would be the bootloader's, or nothing at all.
    cli

    // Stage 1. Claim a slot and announce arrival in one operation: the value
    // this core reads back is its slot, and the value left behind is the count
    // the boot CPU waits on. The boot CPU counts these before it allocates a
    // single frame, so reaching here is what makes the bootloader's usable
    // memory safe to spend.
    mov rbx, 1
    lock xadd qword ptr [rip + SECONDARIES_PARKED], rbx

    // Wait for a kernel root to exist. Zero means the boot CPU has not built
    // one yet. This spins rather than halts because there is no interrupt
    // coming to end it — the boot CPU signals by store, not by IPI, which it
    // has no way to send yet (build/README.md, D87).
1:
    pause
    mov rax, qword ptr [rip + SECONDARY_KERNEL_CR3]
    test rax, rax
    jz 1b

    // Stage 2. Onto the kernel's page tables. Every byte touched from here —
    // this code, the stack below — is mapped at the same address by both,
    // which is what makes the switch survivable mid-instruction-stream.
    mov cr3, rax

    // A core with no slot has no stack, and a stack is the one thing it cannot
    // do without. Halt where it stands rather than index past the array.
    cmp rbx, {slots}
    jae 3f

    // This core's stack, and then into Rust, which does everything else.
    lea rax, [rip + PARK_STACKS]
    mov rcx, rbx
    inc rcx
    shl rcx, {stack_shift}
    add rax, rcx
    mov rsp, rax
    mov edi, ebx
    call x86_secondary_park

    // `x86_secondary_park` is `-> !`; if it ever returns, stop rather than run
    // on through whatever follows in memory.
3:
    hlt
    jmp 3b
"#,
    slots = const CPU_TABLE_SLOTS,
    stack_shift = const PARK_STACK_BYTES.trailing_zeros(),
);

const _: () = assert!(
    PARK_STACK_BYTES.is_power_of_two(),
    "the stub forms a stack offset by shifting"
);

/// The port's descriptor tables must cover every CPU the kernel core will
/// index. The two numbers are declared in different places for a reason —
/// `CPU_TABLE_SLOTS` is the port's, `MAX_CPUS` is the configuration's, and the
/// porting layer does not read kernel configuration — so this crate, which is
/// the one that sees both, is where they are made to agree. Raising `MAX_CPUS`
/// past the port breaks the build here rather than producing a CPU with no
/// task-state segment.
const _: () = assert!(
    CPU_TABLE_SLOTS >= tessera_kcore::percpu::MAX_CPUS,
    "config MAX_CPUS exceeds the x86-64 port's descriptor-table slots"
);

/// Where a parked core lands once it is on the kernel's tables, with a stack of
/// its own and nothing else.
///
/// It says which CPU it is, waits to be given an index, takes its descriptor
/// tables and per-CPU block, announces its arrival, and halts.
///
/// **It does not print.** The console is one device with no lock discipline
/// that survives a second writer, and this kernel dispatches to one CPU
/// (build/README.md, D8). Everything this core has to say, it says through two
/// atomics.
///
/// # Safety
///
/// Called once per core, by the entry stub, with `slot` the slot that core
/// claimed and a stack of its own already loaded.
#[unsafe(no_mangle)]
unsafe extern "C" fn x86_secondary_park(slot: u32) -> ! {
    let parked = &PARKED[slot as usize];
    parked.hw_id.store(Cpu::hw_id(), Ordering::Relaxed);
    // Release, and after the identifier: the boot CPU reads this counter and
    // then reads the identifiers, so the identifier must not be able to arrive
    // second.
    SECONDARIES_ADOPTED.fetch_add(1, Ordering::Release);

    let index = loop {
        let released = parked.release.load(Ordering::Acquire);
        if released != 0 {
            break (released - 1) as u32;
        }
        core::hint::spin_loop();
    };

    // Its own GDT, task-state segment, fault stacks, per-CPU block and syscall
    // MSRs. Until this line the core has been running on the bootloader's
    // descriptor tables, which is survivable only because it has done nothing
    // that needs its own.
    // SAFETY: this core, once, with interrupts masked since the stub's first
    // instruction; the index was minted by `kcore::smp` and is held by no other
    // CPU.
    unsafe { init_cpu_tables(index) };

    // Its own local interrupt controller. The I/O controller and the reference
    // clock are the machine's and were done once on the boot CPU; this is the
    // half that exists per CPU, exactly as the other port's controller splits.
    // SAFETY: this core, once, with interrupts masked since the stub's first
    // instruction and the table loaded on the line above.
    unsafe { tessera_karch_x86_64::init_cpu_interrupts(index) };

    // What this core actually loaded, for the boot CPU to compare against every
    // other core's. Ordered before the arrival announcement so a reader that
    // sees the arrival sees this too.
    parked
        .gdt_base
        .store(tessera_karch_x86_64::loaded_gdt_base(), Ordering::Release);

    tessera_kcore::smp::announce_arrival(index);

    // Nothing dispatches here (D8), but it can now be interrupted, so
    // interrupts come off the mask — the difference between a core that is
    // parked and one that is merely idle. Last, after the tables, the
    // controller and the announcement, because an interrupt arriving before any
    // of those has nowhere to go.
    Cpu::enable();

    // Its own periodic tick. Nothing dispatches to this core, so nothing is
    // preempted by it — what it establishes is that the tick is per CPU, which
    // is what a second scheduler will need and what the legacy timer this port
    // used until recently could never have provided.
    <tessera_karch_x86_64::ApicTimer as tessera_karch::TimerControl>::start_periodic_this_cpu(
        crate::TICK_HZ,
    );

    // Halt rather than spin: a halted core costs
    // a host nothing under emulation and no power on hardware. With interrupts
    // masked `hlt` wakes only for an NMI, so the loop is what keeps it halted
    // rather than decoration.
    loop {
        Cpu::halt_until_interrupt();
    }
}

/// This port's bring-up mechanism: releasing a core that is already running
/// this kernel's code and waiting to be told what it is.
pub struct ApplicationProcessors;

impl CpuBringUp for ApplicationProcessors {
    // SAFETY: the trait's contract. This port's share of it is the stack, which
    // the core took before it ever reached Rust, and the descriptor-table slot,
    // which the bound below proves exists.
    unsafe fn start(hw_id: u64, index: u32) -> Result<(), CpuStartError> {
        if index as usize >= CPU_TABLE_SLOTS {
            return Err(CpuStartError::UnknownCpu);
        }
        let arrived = SECONDARIES_ADOPTED.load(Ordering::Acquire) as usize;
        for parked in PARKED.iter().take(arrived.min(CPU_TABLE_SLOTS)) {
            if parked.hw_id.load(Ordering::Relaxed) != hw_id {
                continue;
            }
            // Swap rather than store, so a second request for the same CPU is
            // refused instead of silently redirecting a core that has already
            // been released and may already be running under the first index.
            if parked.release.swap(u64::from(index) + 1, Ordering::Release) != 0 {
                return Err(CpuStartError::AlreadyOn);
            }
            return Ok(());
        }
        Err(CpuStartError::UnknownCpu)
    }
}

/// Whether every CPU that arrived loaded a descriptor table of its own.
///
/// The boot CPU's is included, because the interesting failure is not "two
/// application processors share" but "everyone still shares the one table the
/// boot CPU built" — which is what this port did until the tables became
/// per-CPU, and which nothing else here would notice.
///
/// `None` when no core arrived: there is nothing to compare, and answering
/// `true` would let the check pass on a kernel that started none.
pub fn tables_are_distinct() -> Option<bool> {
    let arrived = (SECONDARIES_ADOPTED.load(Ordering::Acquire) as usize).min(CPU_TABLE_SLOTS);
    if arrived == 0 {
        return None;
    }
    let mut seen = [0u64; CPU_TABLE_SLOTS + 1];
    seen[0] = tessera_karch_x86_64::loaded_gdt_base();
    let mut count = 1usize;
    for parked in PARKED.iter().take(arrived) {
        let base = parked.gdt_base.load(Ordering::Acquire);
        // A core that was never released never took tables; it is not a
        // duplicate, it is simply absent, and the arrival count says so.
        if base == 0 {
            continue;
        }
        if seen[..count].contains(&base) {
            return Some(false);
        }
        seen[count] = base;
        count += 1;
    }
    Some(count > 1)
}

/// The local-controller ids the bootloader listed, boot CPU first.
///
/// This is the platform's statement of which CPUs exist, kept because the
/// response it came from is in memory the kernel reclaims. It is deliberately
/// not the same source as the identifiers the cores publish about themselves:
/// bring-up matches a request against the latter, and a request that came from
/// the former and matches nothing is a disagreement worth seeing.
pub fn listed_cpus(out: &mut [u64]) -> usize {
    let count = (LISTED_COUNT.load(Ordering::Acquire) as usize).min(out.len());
    for (slot, id) in out.iter_mut().enumerate().take(count) {
        *id = LISTED[slot].load(Ordering::Relaxed);
    }
    count
}

/// Stage 1: moves every application processor out of the bootloader's wait loop
/// and into kernel text.
///
/// Returns how many were parked, or `None` if the bootloader reported no CPU
/// list. Blocks until every one has acknowledged: returning earlier would hand
/// the caller a licence to allocate memory that is still executing, which is
/// the whole hazard this module exists to close.
///
/// # Safety
///
/// Call once, on the boot CPU, **before the first frame is allocated** — the
/// bootloader's response memory must still be intact.
pub unsafe fn park_all() -> Option<usize> {
    // The bootloader's list, recorded before its memory is reclaimed. The boot
    // CPU goes first because the list has no order of its own and something has
    // to; `kcore::smp` assigns indices from it, and having the CPU that already
    // holds index zero appear first keeps the assignment from depending on
    // which CPU the firmware happened to enumerate first.
    let (_, boot_lapic_id) = limine::cpu_count()?;
    LISTED[0].store(u64::from(boot_lapic_id), Ordering::Relaxed);
    let mut listed = 1usize;

    // SAFETY: the caller's contract — nothing has been reclaimed yet.
    let found = unsafe {
        limine::for_each_application_processor(|info| {
            if listed < CPU_TABLE_SLOTS {
                LISTED[listed].store(u64::from(info.lapic_id), Ordering::Relaxed);
                listed += 1;
            }
            info.goto_address
                .store(secondary_park_stub as *mut _, Ordering::Release);
        })?
    };
    LISTED_COUNT.store(listed as u64, Ordering::Release);

    // No timeout, deliberately: a core that does not arrive is one still
    // running in memory about to be overwritten, and a boot that stops here is
    // strictly better than one that continues.
    while (SECONDARIES_PARKED.load(Ordering::Acquire) as usize) < found {
        core::hint::spin_loop();
    }
    Some(found)
}

/// Stage 2: publishes the kernel's page-table root and waits for every parked
/// core to adopt it.
///
/// # Safety
///
/// `kernel_cr3` must be a live top-level root that maps this kernel's text and
/// data at their link addresses. Call once, on the boot CPU, after
/// [`park_all`] returned `Some(parked)`.
pub unsafe fn adopt_tables(kernel_cr3: u64, parked: usize) {
    // Returning once every core has both adopted the root and named itself, so
    // a start request issued after this can always be matched.
    SECONDARY_KERNEL_CR3.store(kernel_cr3, Ordering::Release);
    while (SECONDARIES_ADOPTED.load(Ordering::Acquire) as usize) < parked {
        core::hint::spin_loop();
    }
}

/// What a CPU does when another interrupts it.
///
/// Counts it, and nothing else. The reason this kernel can send —
/// `IpiReason::Reschedule` — asks the target to look at its run queue, and no
/// CPU here has one (build/README.md, D8). Counting is what makes delivery
/// observable from the CPU that sent it, which is the whole of what this
/// milestone claims.
pub fn ipi_hook(_vector: u64) {
    let index = tessera_kcore::percpu::current_index();
    tessera_kcore::smp::note_ipi(index);

    // ...and take whatever was posted for this CPU. The interrupt is only the
    // prompt; the wakeups are the bits, and a CPU that took the prompt without
    // draining would leave them for a tick that may never come.
    tessera_kcore::wakeup::drain(index, |_slot| {
        // Nothing to hand the slot to yet: this CPU has no run queue
        // (build/README.md, D8). Taking the wakeup off the bitmap is what the
        // check observes, and Phase 3's scheduler is what will consume it.
    });
}
