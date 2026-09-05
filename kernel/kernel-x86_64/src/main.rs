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
// **`deref_addrof` is a false positive on this crate's one way of reaching a
// `static mut`.** `(*(&raw mut STATIC)).method()` names a place through a raw
// pointer, which is what edition 2024 requires: the fix clippy suggests —
// `STATIC.method()` — autorefs the static and fails to compile with
// `error: creating a mutable reference to mutable static`, denied by
// `static_mut_refs`. Measured, not assumed: applying the suggestion to one site
// in `smmu.rs` produced exactly that error. 445 findings across the five ports
// were this lint, which is most of what the arch-lint baseline was carrying
// (build/README.md, D297).
#![allow(clippy::deref_addrof)]

mod limine;
mod secondaries;

// The checks and the substrate they run on, split out of this file by area
// (build/README.md, D265): what the machine is asked to prove, one module per
// subject. Grouped below the way `kernel-aarch64` groups its own (D196).
//
// **Every module opens with `use crate::*` and is re-exported here**, so the
// namespace is as flat as it was when this was one file. Claiming these are
// boundaries would be false; what they buy is a name and a header per area.

// The primitives the rest of the boot assumes, and the resources it hands out.
mod kstack;
pub(crate) use crate::kstack::*;

mod selfcheck;
pub(crate) use crate::selfcheck::*;

mod smp;
pub(crate) use crate::smp::*;

// The substrate ring 3 runs on.
mod ipc;
pub(crate) use crate::ipc::*;

mod loader;

// This port's one syscall implementation and the seam a check watches it
// through: sixteen handlers over eight functions became one dispatcher and an
// observer (build/README.md, D299).
mod syscalls;
pub(crate) use crate::loader::*;

mod sched;
pub(crate) use crate::sched::*;

mod user;
pub(crate) use crate::user::*;

// Services, and the framework that binds them to devices.
mod channel;
pub(crate) use crate::channel::*;

mod devmgr;
pub(crate) use crate::devmgr::*;

mod fs;
pub(crate) use crate::fs::*;

mod host;
pub(crate) use crate::host::*;

mod cargs;
mod cheap;
mod cparent;
mod cprog;
mod csay;
mod pci_bus;
pub(crate) use crate::pci_bus::*;

mod blk;
/// The four classes that are a manager, a driver and a client (D330).
mod classes;
/// The flow service: the network reached by asking, over that driver (D327).
mod flow;
/// Message-signalled interrupts: arming a function's entry, bridging the
/// vector to a port, and the idle loop a woken driver needs (D326, D327).
mod msi;
/// The network device class, driven from ring 3 (D327).
mod net;
/// The block class over a second transport, a vector per queue (D328).
mod nvme;
/// Power: what a machine resolves when more than one program has an opinion
/// about a device's state (D334).
mod power;
/// A device's data path as a declared cost, and the budget that refuses one
/// that is too far (D331).
mod relay;
/// A pager that never answers, and the reader that is told so (D333).
mod stallpager;
/// The USB class: a bus whose devices have no registers (D329).
mod usb;
/// A writer at the dirty bound, released by a write-back (D333).
mod writeback;
pub(crate) use crate::blk::*;
pub(crate) use crate::classes::*;
pub(crate) use crate::flow::*;
pub(crate) use crate::net::*;
pub(crate) use crate::nvme::*;
pub(crate) use crate::power::*;
pub(crate) use crate::relay::*;
pub(crate) use crate::stallpager::*;
pub(crate) use crate::usb::*;
pub(crate) use crate::writeback::*;

mod ext2;
pub(crate) use crate::ext2::*;

mod restart;
pub(crate) use crate::restart::*;

// Memory: the faults the kernel answers rather than kills.
mod dpage;
pub(crate) use crate::dpage::*;

mod pagein;
pub(crate) use crate::pagein::*;

mod pressure;
pub(crate) use crate::pressure::*;

// Primitives a program waits on.
mod jobs;
pub(crate) use crate::jobs::*;

mod ports;
pub(crate) use crate::ports::*;

mod waitaddr;
pub(crate) use crate::waitaddr::*;

// What the run says about itself, and what it cost. The verdict *renderer*
// is not here: it is the boot's own narration, and stays beside `_start` with
// the trap and panic path — the other output every area reaches through.
mod correlation;
pub(crate) use crate::correlation::*;

mod observability;
pub(crate) use crate::observability::*;

mod perf;
pub(crate) use crate::perf::*;

use core::alloc::Layout;
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicU64, AtomicUsize, Ordering};
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
use tessera_kcore::dispatch::DispatchOutcome;
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
use tessera_kcore::syscall::{self, SyscallNumber, encode_result, read_user, validate_user_range};
use tessera_kcore::thread::{Thread, ThreadState};
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
const RESERVED_REGIONS: [u64; 6] = [
    // The bootloader HHDM.
    0xffff_8000_0000_0000,
    // The interrupt controller and reference clock register blocks.
    INTERRUPT_MMIO_BASE,
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

/// Where the I/O interrupt controller and the reference clock are mapped.
///
/// Two 4 KiB pages, uncached, in a slot of their own. **Not through the direct
/// map**, which reaches them — it covers every physical address the boot map
/// mentions, and on this machine that is a terabyte — but reaches them as
/// cacheable 2 MiB pages. Device registers read through a cacheable mapping
/// work under an emulator and are a fault on hardware, and the granularity of
/// the direct map means the two pages cannot be corrected in place.
const INTERRUPT_MMIO_BASE: u64 = 0xffff_9000_0000_0000;
const IOAPIC_VA: u64 = INTERRUPT_MMIO_BASE;
const HPET_VA: u64 = INTERRUPT_MMIO_BASE + FRAME_SIZE;

/// Their physical addresses, which on this chipset are fixed.
///
/// The architectural way to learn them is the firmware's ACPI tables, and this
/// port does not parse ACPI. These are the addresses `q35` puts them at, in the
/// same spirit as [`PCI_WINDOW_BASE`] above: a statement about the machine this
/// port targets, written where it can be seen, rather than a number buried in a
/// driver. A machine that put them elsewhere would fail the checks below rather
/// than misbehave — both blocks are identified by a register that says what
/// they are.
const IOAPIC_PHYS: u64 = 0xfec0_0000;
const HPET_PHYS: u64 = 0xfed0_0000;

/// Where each secondary's worker thread's stack is mapped. High half, one slot
/// per CPU, inside the kernel VMAP region that `RESERVED_REGIONS` already
/// covers.
/// Slot zero belongs to no secondary — the handoff starts at core 1 — so it is
/// where the boot core's own cross-call thread goes.
const SECONDARY_THREAD_STACKS: u64 = KERNEL_VMAP_BASE + 0x4000_0000;
const SECONDARY_THREAD_STACK_BYTES: u64 = 4 * FRAME_SIZE;

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
            // loader: OK — root task (ELF, entry {:#x}, {seg_count} PT_LOAD,
            // W^X, job handle {}) created a child, mapped + populated its code
            // (W^X), started it in ring 3; child exited {child_exit}, parent
            // resumed and exited clean
            kprintln!(
                "loader: OK — arg0={:#x}, seg count={seg_count}, arg2={}, child exit={child_exit}",
                v.arg0,
                v.arg2
            );
        }
        // The three component-manager demos are gone: supervision, the budget
        // cap and reclaim-across-restarts are the root task's now, reported
        // under `DemoId::Loader` (build/README.md, D250). Their ids stay
        // because `demo_verdict.isl` ordinals are append-only and never reused;
        // nothing emits one, so reaching here is a defect rather than a
        // verdict, and it says so instead of rendering a line that would read
        // as a passing demo.
        DemoId::ComponentManager | DemoId::ComponentManagerBudget => {
            kprintln!("cm: FAIL — a retired demo id was emitted")
        }
        DemoId::ComponentManagerReclaim => {
            kprintln!("cm-reclaim: FAIL — a retired demo id was emitted")
        }
        DemoId::DriverCrash => {
            let net = v.arg0 as i64;
            kprintln!(
                "driver-crash: OK — host crashed (#PF at 0x0, vec 14), contained + reclaimed; cap conserved (rc=1); frames net {net}"
            );
        }
        // driver-restart: OK — driver host crashed (real #PF) {} times, each
        // contained + reclaimed + device rebound (cap conserved rc=1), then
        // restarted clean and serviced the client (byte 0x5a); {} frames
        // drawn, no reclaim overflow
        DemoId::DriverRestart => kprintln!("driver-restart: OK — arg0={}, arg1={}", v.arg0, v.arg1),
        // driver-restart-budget: OK — a driver host that kept crashing was
        // restarted only {} times (budget cap), then the supervisor gave up
        // (code {}); device cap not leaked (rc=1)
        DemoId::DriverRestartBudget => kprintln!(
            "driver-restart-budget: OK — arg0={}, arg1asi32={}",
            v.arg0,
            v.arg1 as i32
        ),
        // chan: OK — ring-3 client called a ring-3 server over a channel
        // (inline \"ping\"->\"pong\", 1 handle transferred), two switches,
        // both in ring 3; client exited clean
        DemoId::ChannelIpc => kprintln!("chan: OK"),
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
                "m16-step4: OK — a real IRQ3 reached ring 3, woke the driver's PortWait, and the device was read (byte={byte:#04x}, irqs={irqs})"
            );
        }
        DemoId::Com2DriverService => {
            let byte = v.arg0;
            // m16: OK — ring-3 driver host serviced a client I/O request over
            // a real IRQ3 (COM2 loopback): client called, driver drove the
            // device (byte {byte:#04x}) and replied, client got it and exited
            // clean
            kprintln!("m16: OK — byte={byte:#04x}");
        }
        DemoId::DeviceManager => {
            let byte = v.arg1;
            // m17: OK — device manager granted a Device capability (base
            // {:#x}) to a driver host over a channel; the driver drove the
            // device (byte {byte:#04x}) and serviced a client, the granted
            // range was enforced, and the capability's reference was conserved
            kprintln!("m17: OK — arg0={:#x}, byte={byte:#04x}", v.arg0);
        }
        DemoId::FsSupply => {
            let byte = v.arg0;
            kprintln!(
                "fs: supply OK — copied a service-buffer page into a pager-backed mapping (byte {byte:#04x})"
            );
        }
        DemoId::FsService => {
            let (supplied, content_base) = (v.arg0, v.arg1);
            // fs: OK — ring-3 filesystem service supplied {supplied} pages to
            // a client over the external pager (content {content_base:#x}+i,
            // all from ring 3); an out-of-buffer supply was denied, client
            // exited clean, object reference conserved
            kprintln!("fs: OK — supplied={supplied}, content base={content_base:#x}");
        }
        DemoId::WaitOnAddress => kprintln!(
            "wait-demo: OK — ring-3 blocked on a futex word, kernel woke 1, wait returned, clean exit 0"
        ),
        DemoId::Ports => {
            let collapses = v.arg0;
            kprintln!(
                "ports-demo: OK — 3 edges coalesced (pending=3, {collapses} collapses), trailing edge kept, cross-thread signal woke drainer"
            );
        }
        DemoId::Jobs => {
            let (n, released) = (v.arg0, v.arg1);
            // jobs-demo: OK — tighten-only + member-cap(2) + KILL-right
            // enforced; kill terminated {n} members innermost-first, reclaimed
            // {released} objects, state port drained member-exit(pending=2) +
            // emptiness
            kprintln!("jobs-demo: OK — n={n}, released={released}");
        }
        DemoId::PagerDirtyFlood => {
            let limit = v.arg0;
            kprintln!(
                "S2 dirty-flood: OK — throttled at the write fault after {limit} dirty pages; a write-back drained one and the writer went on"
            );
        }
        DemoId::PagerDirtyQuery => kprintln!(
            "S8 dirty-query: OK — dirtied 4 scattered pages; the dirty-range query returned exactly them"
        ),
        DemoId::PagerDurability => {
            let cleaned_after_ack = v.arg0;
            // S4 durability: OK — every page stayed dirty until its pager ack
            // then went clean ({cleaned_after_ack} write-backs, stable
            // snapshots, no clean-before-ack)
            kprintln!("S4 durability: OK — cleaned after ack={cleaned_after_ack}");
        }
        DemoId::PagerDeath => kprintln!(
            "S6 pager-death: OK — pager killed holding 3 dirty pages; object faulted, integrity event named the lost ranges"
        ),
        DemoId::PagerReclaimDeadlock => {
            let (ordinary, reserved) = (v.arg0, v.arg1);
            // S3 reclaim-deadlock: OK — at hard pressure ({ordinary} ordinary
            // frames used, {reserved} reserved) ordinary alloc blocked but a
            // reserved write-back drained a page so reclaim progressed; an
            // over-reservation write-back failed cleanly (range faulted), no
            // hang
            kprintln!("S3 reclaim-deadlock: OK — ordinary={ordinary}, reserved={reserved}");
        }
        // S5 self-paging-cycle: OK — pager A↔B mutual backing forced to fault:
        // the cycle was detected and the request faulted (not blocked); the
        // degenerate single self-paging pager was broken the same way, no hang
        DemoId::PagerSelfPagingCycle => kprintln!("S5 self-paging-cycle: OK"),
        DemoId::PagerDeadlineSupervision => {
            let (requests, escalations) = (v.arg0, v.arg1);
            // S7 deadline-supervision: OK — a pager missed its page-in
            // deadline {requests} times: each faulting request got a bounded
            // fault error (range faulted, not hung), and repeated misses
            // escalated to {escalations} supervised restarts, all as events
            kprintln!(
                "S7 deadline-supervision: OK — requests={requests}, escalations={escalations}"
            );
        }
        DemoId::ObservabilityEvents => {
            let (n, page_ins, misses, escalations, faulted, wire, cap, dropped) = (
                v.arg0, v.arg1, v.arg2, v.arg3, v.arg4, v.arg5, v.arg6, v.arg7,
            );
            // events: OK — drained {n} structured events ({page_ins} page-in,
            // {misses} deadline-miss, {escalations} supervision-escalate,
            // {faulted} object-faulted), each {wire}-byte record round-tripped
            // through its ISL binding; ring bounded at {cap} ({dropped}
            // dropped at the source, reported by one meta-event)
            kprintln!(
                "events: OK — n={n}, page ins={page_ins}, misses={misses}, escalations={escalations}, faulted={faulted}, wire={wire}, cap={cap}, dropped={dropped}"
            );
        }
        DemoId::Correlation => {
            let (stamped, caller, restored, links, parent, faults, served) =
                (v.arg0, v.arg1, v.arg2, v.arg3, v.arg4, v.arg5, v.arg6);
            // correlation: OK — {stamped} events carried a live 128-bit id
            // (epoch:seq) and their thread identity; a synchronous call
            // propagated the caller's id {caller} to the callee for the call's
            // duration and restored the callee's own {restored} on return;
            // {links} fan-out link events named a parent distinct from their
            // own fresh id (sample parent {parent}); {faults} contained ring-3
            // faults reported with the faulting thread's id; a page-in request
            // crossed the message boundary still carrying its faulting
            // thread's cause {served}
            kprintln!(
                "correlation: OK — stamped={stamped}, caller={caller}, restored={restored}, links={links}, parent={parent}, faults={faults}, served={served}"
            );
        }
        DemoId::DriverHostLadder => {
            let (crashed, restarted, gave_up, frames) = (v.arg0, v.arg1, v.arg2, v.arg3);
            // driver-ladder: OK — the supervisor's own records tell the crash-
            // recovery story: {crashed} contained ring-3 crashes, each
            // answered by exactly one reclaim-and-rebind ({restarted} restarts
            // returning {frames} frames from the corpses), and {gave_up} give-
            // up when a host exhausted its restart budget — severity
            // escalating error → notice → critical
            kprintln!(
                "driver-ladder: OK — crashed={crashed}, restarted={restarted}, frames={frames}, gave up={gave_up}"
            );
        }
        // Emitted only by the ports that run the ring-3 driver framework
        // (AArch64, RISC-V 64), which render their own line; x86-64's driver
        // host predates `MapDevice` and reaches its device by port I/O.
        DemoId::DeviceEvents => {}
        // Retired: the bind is the root task's now, reported under
        // `DemoId::Loader` (build/README.md, D256). The id stays because
        // `demo_verdict.isl` ordinals are append-only and never reused; nothing
        // emits one, so reaching here is a defect rather than a verdict.
        DemoId::DriverBind => {
            kprintln!("driver-bind: FAIL — a retired demo id was emitted")
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
        | DemoId::ArchContextSwitch
        | DemoId::ArchCpuLocal => {}
    }
}

/// Entry point. Limine enters here in 64-bit long mode, higher half, with
/// the HHDM active and interrupts masked.
// SAFETY: the bootloader transfers control to the unmangled `_start`
// symbol; nothing else in the image defines it, and it never returns.
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    early_console();
    // CPU tables next: from here on, a fault produces a register dump
    // instead of a silent triple fault.
    // SAFETY: once, on the boot CPU, interrupts still disabled.
    unsafe { tessera_karch_x86_64::init_bsp_tables() };

    // The dense index the core reads now comes from this architecture's
    // per-CPU register rather than from the fact that there is one CPU.
    //
    // **After `init_bsp_tables`, not beside the other boot-installed hooks.**
    // This port keeps the index in the `GS` block, so the block has to exist
    // first; installing it earlier writes through a `GS` base of zero, which is
    // a fault before the console has flushed a line. AArch64 has no such
    // ordering because `TPIDR_EL1` needs nothing set up — which is why the
    // placement is the port's to choose and not the core's.
    // SAFETY: boot CPU, once, with the per-CPU block now installed, and before
    // any other CPU is started.
    unsafe { kcore::percpu::install_index_source::<Cpu>() };
    tessera_karch_x86_64::set_trap_handler(fatal_trap);
    kprintln!(
        "cpu{}: GDT/TSS (+ring-3 segs), IDT, per-CPU block, SYSCALL/SYSRET loaded",
        kcore::percpu::current_index()
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
    // SAFETY: `_start` runs once, on the boot CPU; this is the only
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

    // What the machine has, against what this kernel starts on it. Asking the
    // bootloader for its CPU list is what leaves the others parked in its wait
    // loop; nothing here writes an entry pointer, so the count is a statement
    // of what D8 declines to start rather than a step toward starting it.
    //
    // The id comes from the CPU itself, and the bootloader's is passed
    // alongside rather than instead. They are the same number by two routes —
    // CPUID here, the boot protocol's `bsp_lapic_id` there — and on a machine
    // with one CPU both are zero, so a wrong read of either is invisible until
    // something is addressed by it. Handing over both is what makes the
    // agreement checkable now rather than at the first IPI.
    let mp = limine::cpu_count();
    let topology = kcore::smp::survey(
        mp.map(|(count, _)| count),
        Cpu::hw_id(),
        mp.map(|(_, bsp)| u64::from(bsp)),
    );
    kcore::verdict::claims(kcore::smp::report(topology));

    // Stage 1 of parking, and it must be here: the bootloader started these
    // cores to answer the count above, their wait loop is in *usable* memory,
    // and the next thing this function does is allocate from it.
    // SAFETY: boot CPU, once, and no frame has been allocated yet — the
    // bootloader's response memory is intact.
    let parked = unsafe { secondaries::park_all() };
    if let Some(count) = parked
        && count > 0
    {
        kprintln!("smp: {count} application processor(s) parked in kernel text");
    }

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

    // The interrupt path, on the local and I/O APICs. This is the earliest it
    // can happen: both controllers are reached through mappings, and the
    // mappings need the kernel's own tables, which exist as of the line above.
    //
    // The legacy pair is masked here and never written again (build/README.md,
    // D87). Two things forced that rather than merely justifying it: a legacy
    // tick is one timer for a whole machine where preemption needs one per CPU,
    // and the 8259 cannot say which CPU an interrupt is for — the question SMP
    // is made of is one it has no field to express.
    for (virt, phys) in [(IOAPIC_VA, IOAPIC_PHYS), (HPET_VA, HPET_PHYS)] {
        let frame = match PhysFrame::from_base(PhysAddr::new(phys)) {
            Some(frame) => frame,
            None => panic!("interrupt controller address {phys:#x} is not frame-aligned"),
        };
        if let Err(error) = kernel_space.map(
            VirtAddr::new(virt),
            frame,
            PageFlags::rw().device().global(),
            &mut frames,
        ) {
            panic!(
                "interrupt controller at {phys:#x} not mapped (kerror {})",
                error.code()
            );
        }
    }
    // SAFETY: the boot CPU, once, with interrupts masked, the IDT loaded, and
    // both register blocks mapped above for the life of the kernel.
    match unsafe { tessera_karch_x86_64::init_interrupts(IOAPIC_VA, HPET_VA) } {
        Ok(hz) => kprintln!(
            "irq: local APIC (x2APIC) + I/O APIC, legacy 8259/8253 masked; local timer {} kHz",
            hz / 1000
        ),
        Err(error) => {
            kprintln!("irq: FATAL: interrupt path not available ({error:?})");
            DebugExit::exit(ExitCode::Failure)
        }
    }
    kcore::verdict::claims(&["irq.apic"]);
    tessera_karch_x86_64::set_ipi_hook(secondaries::ipi_hook);

    bring_up_secondaries(topology, parked, kernel_cr3);
    let mut kernel_vm = AddressSpace::from_arch(
        kernel_space,
        Asid(0),
        1u64 << kcore::percpu::current_index(),
    );
    // Every CPU on this machine runs on this space, so the set of CPUs an unmap
    // in it must reach is the set of online CPUs. That cannot come from the
    // mask the line above seeds: a secondary adopts the kernel tables in its
    // entry stub, before any `AddressSpace` object exists to call `activate`
    // on, so the mask names the boot CPU and no other — it *under*-reports,
    // which loses a shootdown rather than wasting one.
    //
    // Before the self-check on the next line, not after: that check unmaps, and
    // an unmap this space cannot name its CPUs for is exactly the case this is
    // here to prevent.
    kernel_vm.mark_active_everywhere();
    mapper_self_check(&mut kernel_vm, &mut frames);
    kprintln!("vmem: kernel address space ready (mapper self-check passed)");

    // Give each of them a thread to run. The boot CPU owns the address space
    // and the allocator, so it is the only CPU that can build one — which is
    // why a secondary's first thread arrives rather than being created there.
    //
    // It happens here rather than beside the other cross-CPU checks because it
    // needs the mapper, and the mapper is this line above.
    let handed = {
        let mut given = 0usize;
        let space = &mut kernel_vm;
        for index in 1..kcore::percpu::PerCpu::<u8>::capacity() {
            if !kcore::smp::cpu(index).is_some_and(|state| state.arrived) {
                continue;
            }
            let base = VirtAddr::new(
                SECONDARY_THREAD_STACKS + u64::from(index) * SECONDARY_THREAD_STACK_BYTES,
            );
            let Ok(thread) = kcore::thread::Thread::spawn(
                secondaries::secondary_worker,
                index as usize,
                base,
                SECONDARY_THREAD_STACK_BYTES / FRAME_SIZE,
                space,
                &mut frames,
            ) else {
                continue;
            };
            // SAFETY: the boot CPU, once per index, and that core is idling in
            // its run loop waiting for exactly this.
            if unsafe { secondaries::SECONDARY_HANDOFF.give(index, thread) } {
                given += 1;
            }
        }
        given
    };
    if handed > 0 {
        kcore::verdict::claims(kcore::smp::report_second_cpu(
            kcore::smp::second_cpu_ran(handed, secondaries::work_done, secondaries::ARRIVAL_SPINS),
            topology.present,
        ));
        // ...and did it come off the executive's own run queue for that CPU,
        // rather than off a scheduler the executive has never heard of? The
        // counter above cannot tell — a thread that ran prints the same number
        // either way — so the question is asked of the scheduler each core
        // published, which is the one thing the two cases disagree about.
        kcore::verdict::claims(kcore::secondary::report_executive_run(
            kcore::secondary::dispatched_from_executive(exec_ref()),
        ));

        // ...and can one of them be the *callee* of a synchronous call made
        // here? That is the executive's remote-wake path end to end: a `call`
        // that finds its callee parked on another core posts a wakeup instead
        // of handing off, and the `reply` comes back the same way. Both
        // directions cross, which is what the count in the line below is for.
        kcore::verdict::claims(kcore::cross_call::report(cross_cpu_call(
            &mut kernel_vm,
            &mut frames,
        )));

        // ...and can a secondary take a thread off the CPU that never asked to
        // leave it? Every check above runs threads that block, so all of them
        // pass on a kernel that preempts nothing; this one does not.
        kcore::verdict::claims(kcore::preempt::report_secondary_preempted(
            check_secondary_preemption(&mut kernel_vm, &mut frames),
        ));
    }

    // Does an unmap on this CPU reach the others? On this port the invalidate
    // is local (`INVALIDATE_IS_BROADCAST` is false), so `invalidate` hands back
    // a set of CPUs still holding the translation and the shootdown is what
    // empties it. The space was marked as one every CPU runs on above, where
    // the reason for it belongs.
    // SAFETY: the boot CPU, after bring-up, with the kernel space every CPU is
    // running on and the allocator that built it.
    match unsafe { shootdown_reaches_other_cpus(&mut kernel_vm, &mut frames) } {
        Some(true) => {
            kprintln!("smp: an unmap here reached another CPU (invalidate + shootdown)");
            kcore::verdict::claims(&["smp.shootdown"]);
        }
        Some(false) => kprintln!("smp: an unmap here did NOT reach another CPU"),
        None => {}
    }

    if STACK_GUARD_SELF_TEST {
        run_stack_guard_self_test(&mut kernel_vm, &mut frames);
    }

    kernel_heap(&mut frames, direct_map_base);
    verify_store();
    arch_conformance(&mut kernel_vm, &mut frames, direct_map_base);
    run_demos(&mut kernel_vm, &mut frames, memory_map);
    let failed = DEMOS_FAILED.load(Ordering::Relaxed);
    if failed > 0 {
        kprintln!("TESSERA-STAGE0: {failed} demo(s) FAILED");
    }
    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    // Last, so it counts every path taken this boot rather than the ones
    // that happened to run before it.
    kcore::verdict::claims(kcore::exec::occupancy::report());
    kcore::verdict::claims(kcore::machine_lock::report());
    // Every unmap and every rights narrowing that had another CPU to tell,
    // and how many of them went unanswered. Zero is the claim; a non-zero
    // count is a CPU that may still translate to memory this one stopped
    // protecting, which no later line would otherwise mention.
    kcore::verdict::claims(kcore::shootdown::report());
    // ...and how many ticks took a thread off its CPU, against how many found
    // the CPU holding something a switch would not carry.
    kcore::preempt::report();
    kcore::verdict::claims(&["boot.alive"]);
    // Clean exit for CI; on hardware without the exit device this halts
    // forever instead.
    DebugExit::exit(if failed > 0 {
        ExitCode::Failure
    } else {
        ExitCode::Success
    })
}

/// The console and the clock, before anything that might need to report a
/// failure through them.
///
fn early_console() {
    // SAFETY: `_start` runs exactly once, on the boot CPU, before any
    // other code; this is the only reference ever taken to UART.
    let uart = unsafe { &mut *&raw mut UART };
    uart.init();
    // Before the first lock of any kind — the console's own — so that a
    // non-zero count below means a lock was reached earlier than this, not
    // merely earlier than the tick.
    let unprotected = kcore::sync::install_interrupt_control::<Cpu>();
    let dropped = kcore::console::init_global(uart);
    // Timestamp source for structured events; the kernel core is
    // architecture-independent, so the cycle counter arrives as a hook.
    let unstamped = kcore::event::set_clock(Cpu::counter_serialized);
    if unstamped > 0 {
        kprintln!("event: {unstamped} record(s) emitted before the clock was installed");
    }

    if unprotected > 0 {
        kprintln!("sync: {unprotected} critical section(s) before interrupt control");
    }
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
}

/// The other CPUs: adopted onto the kernel's tables, released, and then asked
/// the questions that only have answers on a machine with more than one — a
/// targeted interrupt, a broadcast, a grace period, a wakeup that crosses, and
/// a tick of their own.
///
/// Takes what it needs and returns nothing: every claim it makes, it makes
/// from inside. That is what lets it be a phase rather than a passage.
fn bring_up_secondaries(
    topology: kcore::smp::Topology,
    parked: Option<usize>,
    kernel_cr3: PhysAddr,
) {
    // Stage 2: the parked cores leave the bootloader's page tables for these.
    // After this nothing any core touches belongs to the bootloader.
    if let Some(count) = parked
        && count > 0
    {
        // SAFETY: `kernel_cr3` is the root this CPU is running on, so it maps
        // the kernel's text and data at their link addresses; `park_all` ran
        // above and returned this count.
        unsafe { secondaries::adopt_tables(kernel_cr3.as_u64(), count) };
        kprintln!("smp: {count} parked processor(s) now on the kernel's page tables, identified");
    }

    // The executive, **before** any other CPU is released, because from here on
    // a released CPU dispatches out of its own half of it (build/README.md
    // D236) and one that arrived first would find nothing. It used to be built
    // lazily by whichever check needed it first, which was fine while the boot
    // CPU was the only CPU that reached it.
    //
    // This is also what keeps the boot's demos from wiping a running
    // secondary's run queue: every later call restarts the executive that
    // exists rather than taking the branch that builds one (D235), and only
    // that branch touches another CPU's half.
    // SAFETY: the boot CPU, with nothing else released and no borrow live.
    unsafe { exec_restart(IPC_QUANTUM_TICKS) };

    // ...and this port's way of interrupting another core, for the executive to
    // prompt one it has posted a wakeup for. Installed rather than named,
    // because `kcore::exec` is generic over a context switch and nothing else
    // (`kcore::wakeup`).
    // SAFETY: the boot core, once, with the local controllers up.
    unsafe { secondaries::install_wakeup_prompt() };

    // ...and the tick that preempts a thread on a core that is not this one.
    // Installed before any core is released, so a secondary's first tick after
    // it reaches its run loop already has somewhere to go.
    // SAFETY: the boot core, once, with no secondary released yet.
    unsafe { secondaries::install_secondary_tick() };

    // ...and its way of telling a core to drop a translation, for the unmap
    // paths in `kcore::vm` to reach the same way. Installed here, before any
    // core is released, so that no unmap can happen in a window where a core is
    // running and nothing can be said to it.
    // SAFETY: the boot core, once, with the local controllers up and no
    // secondary started yet.
    unsafe { secondaries::install_shootdown_sender() };

    // The channel the cross-CPU call will use, opened **before** any core is
    // released: the first secondary to reach its worker claims the server side
    // and reads these endpoints straight away, and one that found nothing
    // would simply not serve — a boot that passes with the check silently
    // skipped.
    kcore::cross_call::open(exec_ref());

    // Stage 3: give each of them an index. They take their own descriptor
    // tables, task-state segment, fault stacks and per-CPU block, announce
    // themselves, and halt. Nothing dispatches to them (D8) — what this
    // establishes is that every CPU on the machine is running this kernel's
    // code with an identity of its own, which is what a scheduler will need
    // before it can be given a second one.
    let mut listed_storage = [0u64; tessera_karch_x86_64::CPU_TABLE_SLOTS];
    let listed_count = secondaries::listed_cpus(&mut listed_storage);
    let listed = &listed_storage[..listed_count];
    // SAFETY: each core took its stack before it reached Rust and its
    // descriptor-table slot is proved to exist by the index bound in `start`;
    // `Cpu::hw_id()` is this CPU's own, read from CPUID.
    let bring_up = unsafe {
        kcore::smp::start_secondaries::<secondaries::ApplicationProcessors>(
            listed,
            Cpu::hw_id(),
            topology.present,
            secondaries::ARRIVAL_SPINS,
        )
    };
    kcore::verdict::claims(kcore::smp::report_bring_up(bring_up));

    // Can this kernel interrupt a CPU it started? Two rounds, because a
    // targeted send and a broadcast are different fields of the same register:
    // the first turns the kernel's dense index into the controller's own
    // identifier and the second uses a shorthand that skips that entirely.
    // SAFETY: every arrived CPU enabled its own controller and recorded its
    // identifier before announcing itself, so each can take what it is sent.
    let (targeted, broadcast) = unsafe {
        (
            kcore::smp::ping_each::<tessera_karch_x86_64::InterCpu>(
                tessera_karch::IpiReason::Reschedule,
                secondaries::ARRIVAL_SPINS,
            ),
            kcore::smp::broadcast_ipi::<tessera_karch_x86_64::InterCpu>(
                tessera_karch::IpiReason::Reschedule,
                secondaries::ARRIVAL_SPINS,
            ),
        )
    };
    kcore::verdict::claims(kcore::smp::report_ipi(targeted, broadcast));

    // ...and can a writer here know when none of them can still be looking at
    // something? That is the epoch facility `docs/kernel/08` mandates, and the
    // grace period below completes only because each of those CPUs reaches a
    // point in its own loop where it holds nothing and says so.
    kcore::verdict::claims(kcore::smp::report_grace(kcore::smp::grace_period(
        kcore::smp::GRACE_SPINS,
    )));

    // ...and does a wakeup posted here reach one of them? This is Phase 3's
    // first mechanism and D17's exit path: a bit set by this CPU, an interrupt
    // to prompt the other, and the other taking it off its own bitmap from its
    // own interrupt path. The only part missing is a run queue at the far end
    // to hand the slot to.
    // SAFETY: every arrived CPU enabled its own controller before announcing
    // itself, so each can take the prompt.
    kcore::verdict::claims(kcore::smp::report_wakeups(unsafe {
        kcore::smp::wake_each::<tessera_karch_x86_64::InterCpu>(0, secondaries::ARRIVAL_SPINS)
    }));

    // ...and is each of them ticking on a timer of its own? The counter is per
    // CPU because the timer is: a machine-wide count would advance on this
    // CPU's tick alone, so a secondary whose timer never started would look
    // exactly like one whose did — which is the state this port was in while
    // its tick was one legacy device for the whole machine.
    kcore::verdict::claims(kcore::smp::report_ticks(kcore::smp::ticks_advanced::<
        tessera_karch_x86_64::ApicTimer,
    >(secondaries::ARRIVAL_SPINS)));

    // ...and that each of them took a descriptor table of its own. Arrival
    // already proves a CPU loaded *a* table — a bad descriptor triple-faults it
    // before it can report anything — but not that two did not load the same
    // one, which is the defect the per-CPU split exists to prevent and the
    // state this port was in until now.
    match secondaries::tables_are_distinct() {
        Some(true) => {
            kprintln!("smp: every CPU loaded its own GDT/TSS");
            kcore::verdict::claims(&["smp.own-tables"]);
        }
        Some(false) => kprintln!("smp: two CPUs loaded the same GDT — the TSS is shared"),
        None => {}
    }

    // ...and that each of them turned execution prevention on.
    //
    // `CR4` is per CPU, so "this kernel has SMEP" is a claim about a *count*
    // rather than about a bit: a kernel that set it in its boot path alone
    // would leave every other CPU able to execute a user page, and no CPU can
    // read another's `CR4` to notice. Each turns it on inside its own
    // `init_cpu_tables` and the arrivals are counted there.
    //
    // Asked here, after the tables check, because that is the first point at
    // which every arrived CPU has demonstrably been through `init_cpu_tables`
    // — it is the same fact the descriptor-table base proves, read from the
    // other side. Asking earlier raced the CPUs it was counting, and said
    // "4 of 1".
    //
    // Reported when absent as well as when present: a CPU model without the
    // feature is a fact about the machine, and a kernel that said nothing
    // about it would read exactly like one that had stopped enabling it
    // (docs/lifecycle/04, "No Silent Fallback").
    // The user-access control, installed once for the machine: the `CR4` bit
    // is per CPU and set above, but `EFLAGS.AC` is manipulated by whichever CPU
    // is running the copy, so the pair `kcore` calls is one pair.
    //
    // Installed here rather than earlier because what it returns is the number
    // of user copies made before it existed, and that number is only worth
    // reading once the boot has done some.
    // Access prevention: the pair goes in only when the port turned the `CR4`
    // bit on, because `STAC`/`CLAC` raise `#UD` without it. While the port has
    // it off, every user copy is counted instead — the boot says how much is
    // going unchecked rather than going quiet.
    if tessera_karch_x86_64::access_prevention_enabled() {
        let unprotected = kcore::useraccess::install(
            |allowed| {
                // SAFETY: the window's contract is the caller's — every user
                // pointer the kernel follows is validated first. This only
                // moves `EFLAGS.AC`.
                unsafe { tessera_karch_x86_64::set_user_access(allowed) }
            },
            tessera_karch_x86_64::user_access,
        );
        kprintln!("smap: OK — access prevention on, {unprotected} copies made before it");
        kcore::verdict::claims(&["smap.installed"]);
    } else if tessera_karch_x86_64::smap_supported() {
        kprintln!(
            "smap: off — the CPU has it and the boot glue is not audited yet (D247); \
             the carrier is in and every user copy is counted"
        );
    } else {
        kprintln!("smap: absent — this CPU model does not implement it");
    }

    let with_tables = bring_up.arrived as u64 + 1;
    let protected = tessera_karch_x86_64::execution_prevention_cpus();
    if !tessera_karch_x86_64::smep_supported() {
        kprintln!("smep: absent — this CPU model does not implement it");
    } else if protected == with_tables {
        kprintln!("smep: OK — execution prevention on all {with_tables} CPU(s)");
        kcore::verdict::claims(&["smep.all-cpus"]);
    } else {
        kprintln!("smep: FAIL — {protected} of {with_tables} CPU(s) enabled it");
    }

    // Wrap the kernel tables in an AddressSpace object (the BSP is already
    // running on them) and prove the runtime mapper end to end: map an
    // anonymous region, confirm it is zero-filled, write and read it back,
    // then unmap it.
}

/// The kernel heap, in one contiguous run of frames reached through the
/// direct map.
fn kernel_heap(frames: &mut kcore::pmem::BumpFrameAllocator<'static>, direct_map_base: u64) {
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
}

/// The verified image store, before anything that might want to read from it.
fn verify_store() {
    if system_store().is_empty() {
        kprintln!("store: skipped — no system store embedded (cargo inner loop)");
    } else {
        let mut scratch = [0u8; STORE_SCRATCH];
        match kcore::store::self_check(system_store(), &mut scratch) {
            Ok(r) => {
                // The directory measured to the anchor this kernel is compiled to
                // trust, and firmware.bin was read through it. A byte changed in
                // that blob is refused at open, and one changed in the directory
                // refuses the whole container: `store.ok` and `store.refused`.
                kprintln!(
                    "store: OK — {} B, {} blob(s), firmware.bin {} B {:#018x}",
                    r.bytes,
                    r.entries,
                    r.firmware_len,
                    r.firmware_lead
                );
                kcore::verdict::claims(&["store.ok", "store.refused"]);
                // **And the kernel installs its own copy** (D331). The other port's
                // image carries no container at all — every one it sees is read off a
                // medium by a component, and a boot with no device has no store. This
                // image carries one, so what makes it reachable to the firmware check
                // below is the kernel handing itself the region it just measured. The
                // kernel-internal path, not the syscall: a kernel installing its own
                // copy and a component offering one are different acts, and only the
                // second is latched as a claim about a medium.
                kcore::firmware::set_system_store(system_store());
            }
            Err(error) => {
                kprintln!("store: FATAL: check failed ({})", error.code());
                DebugExit::exit(ExitCode::Failure)
            }
        }
    }

    // The architecture-conformance battery: the same porting-layer checks the
    // AArch64 port runs, so "x86-64 implements the layer" is a result rather
    // than the oldest port's privilege (docs/hardware/01, "Porting Rules" 5).
    // Not in the battery: only the ports that implement `CpuLocal` can run it.
}

/// The porting-layer battery every port runs. Its verdicts, not this crate's
/// opinion of them, decide whether the port passed.
fn arch_conformance(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    direct_map_base: u64,
) {
    // SAFETY: boot CPU, and nothing else reads the index while it is probed.
    let cpu_local_ok = unsafe { tessera_arch_conformance::cpu_local::<Cpu>() };
    let arch_conformance = tessera_arch_conformance::run::<ContextSwitch, _>(
        &mut tessera_arch_conformance::Platform {
            space: kernel_vm.arch_mut(),
            frames,
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
    // The per-CPU index case reaches the same gate for the same reason.
    DEMOS_FAILED.fetch_add(u64::from(!cpu_local_ok), Ordering::Relaxed);

    // Capabilities: exercise the handle + rights system end to end — create an
    // object, take handles, narrow rights, reject an expansion, and watch the
    // object die when its last handle closes.
}

/// What this machine is asked to prove, in the order it proves it.
///
/// A list of calls rather than a passage of `_start`, so that adding a check
/// is adding a line here and reading the boot is reading this function.
fn run_demos(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    memory_map: &[MemoryRegion],
) {
    handle_self_check();

    // IPC: the synchronous-handoff bet. Two kernel threads and one channel; a
    // caller `call`s a callee that `receive`s and `reply`s, and the round trip
    // must cost exactly two context switches with a handle transferred across.
    ipc_roundtrip_demo(kernel_vm, frames);

    // Channel IPC: a ring-3 client calls a ring-3 server over a channel (inline
    // bytes + a transferred handle) via the synchronous call/reply handoff — the
    // user-space-services substrate (M15).
    channel_ipc_demo(kernel_vm, frames);

    // User mode: the isolation bet. Run a program in ring 3 in its own address
    // space that reaches the kernel only through the SYSCALL boundary, and prove
    // a fault in it is contained (the process dies, the kernel lives).
    user_mode_demo(kernel_vm, frames);

    // Demand paging: a ring-3 program that faults on lazy anonymous pages and a
    // copy-on-write snapshot, and whose faults are resolved and resumed rather
    // than fatal — the reclaim bet.
    demand_paging_demo(kernel_vm, frames);

    // External pager: a ring-3 program reads pager-backed memory whose pages a
    // pager kernel thread supplies over IPC — the page-in bet.
    pager_demo(kernel_vm, frames);

    // Wait-on-address: a ring-3 thread blocks on a futex word inside its syscall
    // and a kernel thread wakes it across the ring boundary — the B6 primitive.
    wait_on_address_demo(kernel_vm, frames);

    // Ports: async event delivery that coalesces edges into one event carrying a
    // pending count and never loses an edge — a consumer drains, a producer
    // signals and wakes it across threads.
    ports_demo(kernel_vm, frames);

    // Jobs: the containment tree. Build root + a tighter child, enforce the
    // tighten-only limit / member cap / KILL right, then kill the subtree
    // innermost-first and drain the state port — the teardown bet.
    jobs_demo(kernel_vm, frames);

    // Pager under pressure: the write-back / dirty-tracking / eviction bets
    // (docs/prototypes/02). Dirty throttling (S2), dirty-range query (S8),
    // durability ordering (S4), and pager death (S6).
    pager_throttle_demo(kernel_vm, frames);
    pager_dirty_query_demo(kernel_vm, frames);
    pager_durability_demo(kernel_vm, frames);
    pager_death_demo(kernel_vm, frames);
    pager_reclaim_deadlock_demo(kernel_vm, frames);
    pager_self_paging_cycle_demo();
    pager_deadline_supervision_demo();
    observability_demo();

    // Driver host: a ring-3 driver owns a real device (COM2, IRQ3), receives its
    // interrupt as a port event, and services a client's I/O over a channel —
    // the driver-host I/O bet (M16). Runs before `scheduler_demo` so the timer
    // and its `TICK_HOOK` are still off.
    driver_host_demo(kernel_vm, frames);

    // Device manager: a ring-3 service owns a device resource-graph node and
    // grants its capability to a driver host over a channel; the driver drives
    // the device through the granted cap and services a client (M17). Also before
    // `scheduler_demo` (its driver takes the device IRQ in ring 3).
    device_manager_demo(kernel_vm, frames);

    // The driver framework used to be composed here, as `driver_bind_check`:
    // 234 lines of boot glue that enumerated PCI, created a channel, spawned a
    // manager and a driver, and reached into both their handle tables. The root
    // task does all of that now, over the same real PCI function, and what is
    // left in the kernel is the part no capability could replace — reading
    // configuration space and naming what was found (build/README.md, D256).

    // **Enumeration, done again and from outside.** The walk above was the
    // kernel's, through the legacy configuration ports; this hands a ring-3
    // program the memory-mapped window the chipset reports and lets it do the
    // same work with the same crate. The two reach configuration space by
    // different means and must agree about the same function.
    match pci_bus_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // pci-bus: OK — a ring-3 program held the host bridge and nothing
            // else, walked it through the memory-mapped window this chipset
            // reports and DECLARED the {} function(s) it found: every PCI
            // device in the resource graph was put there by an unprivileged
            // process. It offered them to the device manager as capabilities
            // rather than as claims, the manager took hardware it had never
            // seen, and a driver bound one by class. That driver mapped its
            // OWN configuration space — 4 KiB scoped to one function, on a
            // right separate from the one that maps its registers — and read
            // {:04x}:{:04x} out of it. The kernel reaches config space through
            // the 0xCF8 port pair and found the same thing, so neither walk
            // produced the other's answer by echoing it
            kprintln!(
                "pci-bus: OK — {} function(s) declared from ring 3; config {:04x}:{:04x}",
                outcome.functions,
                outcome.word & 0xffff,
                outcome.word >> 16,
            );
            kcore::verdict::claims(&["pci-bus.ok", "pci-bus.declared", "pci-bus.own-config"]);
        }
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
    fs_supply_selftest(kernel_vm, frames);
    fs_service_demo(kernel_vm, frames);

    // **A ring-3 program written in C** (`docs/roadmap/04` Phase 4, D306).
    // **Last, and that placement is a finding rather than a preference.** It
    // reuses the bus check's observer and fault handler, and running it before
    // `loader_demo` failed that check — the root task's run is judged on
    // conjuncts that a second executive run in front of it disturbs. A check
    // that borrows another's machinery has to go after everything that reads
    // it, which is the cost of not restarting the executive per check the way
    // AArch64 does.
    match cprog::c_program_check(kernel_vm, frames) {
        Ok(Some(report)) => {
            // c-lang: OK — a program compiled from C by the host toolchain,
            // entered at a crt0 that called `int main(void)` and exited with
            // what it returned. Its syscall numbers came from the generated ABI
            // headers, and the value it reported is arithmetic it performed
            // rather than a constant in its image.
            kprintln!("c-lang: OK — report {report:#x}");
            kcore::verdict::claims(&["c-lang.ran", "c-lang.abi-headers"]);
        }
        Ok(None) => kprintln!("c-lang: skipped (no embedded C program in this image)"),
        Err(which) => {
            kprintln!("c-lang: FAIL — check {which} failed");
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **The first thing above the language: a C program that allocates**
    // (`docs/roadmap/04` Phase 4, D316). Immediately after `cprog` because it
    // borrows the same observer and fault handler, for the reason that check's
    // placement records — and because if the language check has just failed,
    // this one's failure says nothing new.
    match cheap::c_heap_check(kernel_vm, frames) {
        Ok(Some(report)) => {
            // c-heap: OK — `malloc` and `free` from //userspace/libc, over this
            // system's memory objects. The claims are addresses: a block larger
            // than one object can be, the same address returned after a free,
            // and the heap's base again once three adjacent ranges were given
            // back. The value is a mix over bytes that made the round trip
            // through allocated memory.
            kprintln!("c-heap: OK — report {report:#x}");
            kcore::verdict::claims(&["c-heap.allocated", "c-heap.reused", "c-heap.coalesced"]);
        }
        Ok(None) => kprintln!("c-heap: skipped (no embedded C heap program in this image)"),
        Err(which) => {
            kprintln!("c-heap: FAIL — check {which} failed");
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **A C program told what to work on** (`docs/roadmap/04` Phase 4, D317):
    // `crt0` turns the `StartupArgs` its parent left into `argc` and `argv`.
    // After the heap check for the same reason that one follows `cprog` — it
    // borrows the same observer and fault handler, and a failure here says
    // nothing new if the language or the runtime below it has already failed.
    match cargs::c_args_check(kernel_vm, frames) {
        Ok(Some((first, second))) => {
            // c-args: OK — one image, two runs, two different answers folded
            // from argument strings that appear nowhere in it. The startup
            // message was built here through the generated binding and decoded
            // there through the generated header, so the two halves agree about
            // what a byte at an offset means without either being told.
            kprintln!("c-args: OK — reports {first:#x} and {second:#x}");
            kcore::verdict::claims(&["c-args.received", "c-args.varies"]);
        }
        Ok(None) => kprintln!("c-args: skipped (no embedded C argument program in this image)"),
        Err(which) => {
            kprintln!("c-args: FAIL — check {which} failed");
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **A C program that says something a person can read** (D318). The buffer
    // form of `DebugWrite` this port has always implemented, reached from C for
    // the first time — and what gave `<string.h>` its first two callers, since
    // printing an argument means measuring a string nobody gave a length for.
    match csay::c_say_check(kernel_vm, frames) {
        Ok(Some(wrote)) => {
            // c-say: OK — the console took the line. The text itself is
            // asserted by the boot script, which can read the serial log this
            // cannot; what is checked here is the count the syscall answered
            // with, so the two halves are looking at the same call.
            kprintln!("c-say: OK — console took {wrote} bytes");
            kcore::verdict::claims(&["c-say.wrote"]);
        }
        Ok(None) => kprintln!("c-say: skipped (no embedded C console program in this image)"),
        Err(which) => {
            kprintln!("c-say: FAIL — check {which} failed");
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }
    // **And the block class on that bus.** The check above proves a ring-3
    // program can find a mass-storage function and reach the registers it was
    // granted; this proves one can bring the device *up* and read the disk.
    // **Last, and that placement is the same finding `c-lang` recorded one
    // check below.** It borrows the bus check's observer and fault handler and
    // restarts the executive for itself, and a run of it in front of
    // `loader_demo` moved that check's frame draw past its bound — the root
    // task's verdict counts the fresh frames its own run takes, and a check
    // that emptied the free list before it starts changes that number without
    // changing anything about the root task. A check that borrows another's
    // machinery has to go after everything that reads it.
    match blk_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // blk: OK — a compiled ring-3 driver holding one channel endpoint
            // and nothing else asked a device manager for a BLOCK device, was
            // handed a virtio-pci function by class, and brought it up: the
            // modern handshake to DRIVER_OK, a queue it configured out of pages
            // DmaAlloc gave it, a request posted and a completion collected.
            // Its controls are in the BAR the function's own vendor
            // capabilities name — not the lowest-numbered one, which on this
            // device is the MSI-X table — and the driver was told where they
            // are as offsets, because configuration space is not per-device and
            // no capability to it can be handed out. The capacity below is the
            // driver's read of the device configuration structure and the magic
            // is the first eight bytes of sector 0.
            kprintln!(
                "blk: OK — {} caps, BAR {:#x}+{:#x}, {} sectors, sector0 {:#018x}, {}/{} served",
                outcome.capabilities,
                outcome.bar_base,
                outcome.bar_len,
                outcome.capacity,
                outcome.magic,
                outcome.at_service,
                outcome.at_driver,
            );
            // blk: woken — and this is what the driver did *not* have until
            // now. A PCI function has no wire: it signals by writing a message
            // to an address that names a local controller and a vector that
            // names an entry in this kernel's table, neither of which a ring-3
            // program may choose. Boot programmed the function's first MSI-X
            // entry, recorded that vector as the device's line in the resource
            // graph, and bound a port to it; the driver was told only that a
            // port exists, and parked on it instead of watching the used ring.
            kprintln!(
                "blk: woken — {} message(s) on vector {}, delivered to the driver's port",
                outcome.msi,
                tessera_karch_x86_64::MSI_VECTOR_BASE,
            );
            kcore::verdict::claims(&[
                "blk.bound",
                "blk.transport",
                "blk.read",
                // And it was woken by the device rather than watching for it
                // (D326): the completion arrived as a message the function
                // wrote, on a vector boot programmed and a port the graph
                // routed.
                "blk.msi",
                // And the layer above it (D323): a program holding no device
                // answered the same contract the driver does, a client that
                // cannot tell the two apart got the medium's bytes through it,
                // and the requests reached the driver rather than stopping in
                // the middle.
                "blk.service",
                // Every rule of the block class held against that stack.
                "blk.conformance",
            ]);
        }
        Ok(None) => kprintln!(
            "blk: skipped (this image carries no block stack, no virtio mass-storage function, or its structures did not resolve)"
        ),
        Err(which) => {
            // Two lines rather than one: six programs' worth of values is past
            // the console's width bound, and which of them is wrong is the
            // whole of what a reader needs.
            kprintln!(
                "blk: FAIL — check {which} (driver {:#x} {:#x} {:#x})",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORTS[1].load(Ordering::SeqCst),
                BIND_REPORTS[2].load(Ordering::SeqCst),
            );
            kprintln!(
                "blk: FAIL — client {:#x}, {} reports, {}/{} served",
                BIND_REPORTS[3].load(Ordering::SeqCst),
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
                BLK_SERVICE_RECEIVES.load(Ordering::SeqCst),
                BLK_DRIVER_RECEIVES.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And a NIC, driven from ring 3** (D327), when the machine has one. The
    // block class was proved by a driver that answered questions; this one
    // cannot be, because a frame arrives when somebody else sends one and no
    // client asked for it. Placed here for the reason the filesystem check
    // below documents: it is the other large producer of events, and the check
    // that drains the ring stands immediately after it.
    match net_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // net-class: OK — a ring-3 driver bound a NIC by class and served
            // the network contract to a client holding no device at all. The
            // frame the client got back was one nobody replied to: the NIC
            // interrupted the driver — with a *message*, on this machine — and
            // the driver sent it, no call outstanding. Taking the link down was
            // announced, a transmit while it was down came back LINK_DOWN
            // rather than an I/O error, bringing it up was announced again, the
            // class conformance suite reached and held every rule, and a DHCP
            // server answered a datagram the client built itself and handed
            // over in a buffer.
            kprintln!(
                "net-class: OK — report={:#x}, BAR {:#x}, {} caps, {} message(s), {} route(s)",
                outcome.report,
                outcome.bar_base,
                outcome.capabilities,
                outcome.msi,
                outcome.routes_ended,
            );
            kcore::verdict::claims(&[
                "net-class.ok",
                "net-class.driver-sent",
                "net-class.conformance-complete",
                // Separable, and about a different layer: the three above say a
                // ring-3 driver served the network class, this says a datagram
                // built in ring 3 was accepted by a server that is not part of
                // this system — and carried in a buffer, because it was too
                // large to be a message.
                "net-stack.dhcp-offer",
            ]);
        }
        Ok(None) => {
            kprintln!("net-class: skipped (this machine has no NIC, or carries no net stack)")
        }
        Err(which) => {
            kprintln!(
                "net-class: FAIL — check {which} (report {:#x}, wanted {:#x}, {} reports)",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                crate::net::NET_CLIENT_EXPECTED,
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **The same NIC, used again by a taller stack** (D327). Its own check
    // because the class check owns the driver's client endpoint and a driver
    // serves one: extending it would have meant proxying the conformance legs
    // through the stack instance, which changes what those claims mean in order
    // to test something else.
    match flow_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // flow-service: OK — four processes, and the one that completed the
            // DHCP exchange held a single channel endpoint: no device, no DMA,
            // no NIC and no Ethernet constant. The stack instance below it
            // built the Ethernet, IPv4 and UDP headers and knows nothing of
            // what they carry; the driver below that knows virtio and not what
            // a datagram is. A server outside this system answered, which is
            // what makes those headers correct rather than merely well-formed.
            kprintln!(
                "flow-service: OK — report={:#x}, {} message(s) while the datagrams were in flight",
                outcome.report,
                outcome.msi,
            );
            kcore::verdict::claims(&["flow.bound", "flow.datagram-sent", "flow.offer-received"]);
        }
        Ok(None) => {
            kprintln!("flow-service: skipped (this machine has no NIC, or carries no stack)")
        }
        Err(which) => {
            kprintln!(
                "flow-service: FAIL — check {which} (reports {:#x} {:#x}, wanted {:#x})",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORTS[1].load(Ordering::SeqCst),
                crate::flow::FLOW_CLIENT_EXPECTED,
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And the block class over a second transport** (D328), when the machine
    // has an NVMe controller. The client that judges it is the one that judges
    // the virtio driver, byte for byte: a class contract belongs to the class
    // and not to the transport under it.
    match nvme_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // nvme: OK — a controller brought up entirely from ring 3, serving
            // the same contract the virtio driver does, judged by the same
            // client with the same conformance suite. Each I/O queue's
            // completions arrived on its own vector and its own port, which is
            // why both counts below are non-zero: the driver never asks which
            // queue finished, it waits where that queue's completions land.
            kprintln!(
                "nvme: OK — report={:#x}, BAR {:#x}, {}/{} completion(s) per queue vector",
                outcome.report,
                outcome.bar_base,
                outcome.per_vector[0],
                outcome.per_vector[1],
            );
            kcore::verdict::claims(&[
                "nvme.ok",
                "nvme.vector-per-queue",
                "nvme.conformance-complete",
            ]);
        }
        Ok(None) => kprintln!("nvme: skipped (this machine has no NVMe controller)"),
        Err(which) => {
            kprintln!(
                "nvme: FAIL — check {which} (report {:#x}, wanted {:#x}, {} reports)",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                crate::nvme::NVME_CLIENT_EXPECTED,
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And a bus whose devices have no registers** (D329), when the machine
    // has an xHCI controller. Everything else this port drives owns memory; a
    // USB device owns none, and the drivers that serve it map nothing at all.
    match usb_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // usb: OK — a ring-3 host bound the controller, walked the root
            // ports and a hub, addressed what it found and declared every
            // device into the graph, hubs as buses with devices behind them.
            // Two class drivers served block and input off devices they cannot
            // touch, and the clients that judged them are the ones that judge
            // every other transport.
            kprintln!(
                "usb: OK — BAR {:#x}, block={:#x}, input={:#x}",
                outcome.bar_base,
                outcome.block,
                outcome.input,
            );
            // usb: graph — the shape the host declared, read back from the
            // graph rather than from the host's own account of it. Three
            // levels, and one more device than there are drivers that reported:
            // the refused one is attached, enumerated and in nobody's hands.
            kprintln!(
                "usb: graph — {} on the root ports, {} behind a hub, 2 served",
                outcome.on_root,
                outcome.behind_hub,
            );
            kcore::verdict::claims(&[
                "usb.ok",
                "usb.no-registers",
                "usb.three-levels",
                "usb.idle-no-report",
                // Declared, working, and offered to nobody: more devices in
                // the graph than drivers that reported.
                "usb.device-refused",
            ]);
        }
        Ok(None) => kprintln!("usb: skipped (this machine has no xHCI controller)"),
        Err(which) => {
            kprintln!(
                "usb: FAIL — check {which} ({} reports: {:#x} {:#x} {:#x})",
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORTS[1].load(Ordering::SeqCst),
                BIND_REPORTS[2].load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And the four classes that are a manager, a driver and a client**
    // (D330), each when the machine has the device for it. What differs
    // between them is the function they look for, the two programs they run,
    // and the word the client must report; the composition is one runner.
    // **One at a time, and the checks are run inside the loop.** Building an
    // array of results first runs all four before the first is judged, which
    // makes every failure print whichever report the *last* one left — the
    // reports are a shared sink, and a check reads it while it is still its own.
    for name in ["gpu", "snd", "sd", "crypto"] {
        let outcome = match name {
            "gpu" => gpu_check(kernel_vm, frames, memory_map),
            "snd" => snd_check(kernel_vm, frames, memory_map),
            "sd" => sd_check(kernel_vm, frames, memory_map),
            _ => crypto_check(kernel_vm, frames, memory_map),
        };
        match outcome {
            Ok(Some(outcome)) => {
                // <class>: OK — a ring-3 driver bound the device by class and
                // served its contract to a client holding one channel endpoint
                // and no device at all. The report is the same word the other
                // port expects of the same program.
                kprintln!(
                    "{name}: OK — report={:#x}, BAR {:#x}",
                    outcome.report,
                    outcome.bar_base,
                );
                match name {
                    "gpu" => kcore::verdict::claims(&[
                        "gpu.ok",
                        "gpu.class-served",
                        "gpu.drew-every-pixel",
                        "gpu.refused-not-clipped",
                    ]),
                    "snd" => kcore::verdict::claims(&[
                        "snd.ok",
                        "snd.class-served",
                        "snd.played-periods",
                        "snd.underrun-reported",
                    ]),
                    "sd" => kcore::verdict::claims(&["sd.ok", "sd.declared"]),
                    _ => kcore::verdict::claims(&[
                        "crypto.ok",
                        "crypto.class-served",
                        "crypto.standard-vector",
                        "crypto.key-changes-answer",
                        "crypto.refused-not-guessed",
                    ]),
                }
            }
            Ok(None) => kprintln!("{name}: skipped (this machine has no such device)"),
            Err(which) => {
                kprintln!(
                    "{name}: FAIL — check {which} (report {:#x}, {} reports)",
                    BIND_REPORTS[0].load(Ordering::SeqCst),
                    BIND_REPORT_COUNT.load(Ordering::SeqCst),
                );
                DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // **And a path that costs too much is refused** (D331). Not one line of
    // the mechanism is per-port: the arbiter, the manifest and the probe are
    // the same sources the other machines run. What is here is a topology built
    // out of devices that do not exist, because what is checked is what the
    // graph says about a path rather than what is at the end of one.
    match relay_check(kernel_vm, frames) {
        Ok(Some((declared, undeclared))) => {
            // relay: OK — one manifest entry with one budget, asked about two
            // devices of the same class differing only in depth: the near one
            // bound and the far one — one hub further down — was refused
            // BudgetExceeded, so a class cannot silently miss its budget behind
            // a hub. The network device sits well inside its latency budget and
            // was refused ThroughputTooLow, because a shorter path is no help
            // when the remaining hop is the narrow one. And a hub the kernel
            // cannot identify is not free: the manifest claims nothing about
            // it, so the device behind it was refused PathUndeclared rather
            // than bound as though it were direct-attached.
            kprintln!(
                "relay: OK — budget {}us; near hop {}us {}Mb; far {}us refused; {:#x}/{:#x}",
                BLOCK_PATH_BUDGET_US,
                (declared >> 16) & 0xffff,
                (declared >> 48) & 0xffff,
                RELAY_NEAR_COST_US + RELAY_FAR_COST_US,
                declared,
                undeclared,
            );
            kcore::verdict::claims(&[
                "relay.ok",
                "relay.budget-exceeded",
                "relay.throughput-too-low",
                "relay.path-undeclared",
            ]);
        }
        Ok(None) => kprintln!("relay: skipped (this image carries no manager or probe)"),
        Err(which) => {
            kprintln!(
                "relay: FAIL — check {which} (reports {:#x}, {:#x}, count {})",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORTS[1].load(Ordering::SeqCst),
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And firmware, mediated by the driver framework** (D331): a manager
    // holding the right fetches a verified image and hands it to a driver
    // beside its device, and the refusals in between are the point.
    match firmware_check(kernel_vm, frames) {
        Ok(Some(report)) => {
            // What the *kernel* measures for the same image, independently of
            // the driver that reports measuring it. Compared below: neither
            // side can satisfy this by trusting the other.
            let digest = kcore::store::mount(kcore::firmware::system_store())
                .ok()
                .and_then(|store| store.open(kcore::store::SYSTEM_FIRMWARE).ok())
                .map(|blob| {
                    u32::from_le_bytes([
                        blob.digest[0],
                        blob.digest[1],
                        blob.digest[2],
                        blob.digest[3],
                    ])
                })
                .unwrap_or(0);
            if report.driver == firmware_report_expected(digest) && report.update_would_strand {
                // firmware: OK — a manager holding the firmware right fetched a
                // verified image and handed it to a driver beside its device;
                // the driver measured what it received to the same digest the
                // kernel measures from the store. An image below the rollback
                // floor was refused while measuring perfectly, one below what
                // the entry needs was refused differently, the driver's own
                // load was refused because the right did not travel with the
                // device, and a stricter driver set would strand an installed
                // image.
                kprintln!(
                    "firmware: OK — svn={} ver={} digest={:#010x} refusals={:#x} driver={:#x}",
                    FIRMWARE_GOOD_SVN,
                    FIRMWARE_GOOD_VERSION,
                    digest,
                    report.refusals,
                    report.driver,
                );
                kcore::verdict::claims(&[
                    "firmware.ok",
                    "firmware.measured",
                    "firmware.rollback-refused",
                    "firmware.right-required",
                ]);
            } else {
                kprintln!(
                    "firmware: FAIL — driver={:#x} wanted={:#x} strand={}",
                    report.driver,
                    firmware_report_expected(digest),
                    report.update_would_strand,
                );
                DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(None) => kprintln!("firmware: skipped (this image carries no store, manager or probe)"),
        Err(which) => {
            kprintln!(
                "firmware: FAIL — check {which} (reports {:#x}, {:#x}, count {})",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORTS[1].load(Ordering::SeqCst),
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And a runner that will not certify what it did not check** (D331).
    // Every other check here ends by reporting that something worked; this one
    // ends by reporting what was never asked.
    match certify_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // certification: OK — a ring-3 certifier ran the two of the eleven
            // checks a peer can make against a driver and both held; it then
            // refused to certify on them, naming the checks nobody ran, and the
            // same rules refused a forged record and a stale contract version
            // in ring 3. Not proven here: anything about the checks nobody
            // asked, and that the ones that passed are enough — they are not,
            // which is the point.
            kprintln!("certification: OK — report={:#x}", outcome.report);
            kcore::verdict::claims(&[
                "cert.ok",
                "cert.not-certified",
                "cert.nine-ran",
                "cert.refused",
                "cert.two-unasked",
            ]);
        }
        Ok(None) => kprintln!("certification: skipped (no crypto device or certifier)"),
        Err(which) => {
            kprintln!(
                "certification: FAIL — check {which} (report {:#x}, wanted {:#x})",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                CERTIFIER_EXPECTED,
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And a pager that never answers** (D333). `docs/kernel/03` requires
    // that a pager which does not respond leaves its consumers observing
    // faulted ranges rather than indefinite hangs — and the second half of that
    // is the one a check has to earn, because a thread blocked for ever on a
    // request nobody will answer is invisible rather than wrong.
    match stallpager_check(kernel_vm, frames) {
        Ok(outcome) => {
            // stall-pager: OK — the pager took the request and parked in a
            // receive nothing will ever send to; the reader came back with a
            // fault instead of waiting, the object was left faulted so the next
            // reader is refused rather than sent to the same silence, the miss
            // was counted, and one miss is not yet an escalation.
            kprintln!(
                "stall-pager: OK — reader faulted (vector {}), object faulted, {} miss(es), {} escalation(s)",
                outcome.vector,
                outcome.misses,
                outcome.escalations,
            );
            kcore::verdict::claims(&["stall-pager.ok"]);
        }
        Err(which) => {
            kprintln!("stall-pager: FAIL — check {which}");
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And a writer that runs out of dirty pages** (D333): held at the store
    // until its own service persists one, rather than refused.
    match writeback_check(kernel_vm, frames) {
        Ok(outcome) => {
            // writeback: OK — the writer dirtied one page past the bound and
            // blocked inside that store while the kernel asked the object's
            // service to persist a page; the service answered and the writer
            // went on. Then it wrote the drained page again — clean, and still
            // faulting, which is what says the kernel put the fault back when
            // it marked the page clean. The object sits at its bound.
            kprintln!(
                "writeback: OK — {} dirty page(s) at a bound of {}",
                outcome.dirty,
                outcome.bound,
            );
            kcore::verdict::claims(&["writeback.throttled", "writeback.drained"]);
        }
        Err(which) => {
            kprintln!("writeback: FAIL — check {which}");
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And what the machine resolves when three programs disagree** (D334).
    // The device does not exist: what is being checked is the resolution and
    // the transcript it leaves, not anything behind a register window.
    match power_check(kernel_vm, frames) {
        Ok(Some(outcome)) => {
            // power-votes: OK — three voters were each told what the machine
            // resolved rather than what they asked for. The second asked for
            // full activity and got it with nothing clamped, so the third's
            // clamp is a decision rather than a constant; and the device the
            // manager drove ended `Suspended`, having passed through the states
            // a transition is defined to pass through.
            kprintln!(
                "power-votes: OK — replies {:#x}/{:#x}/{:#x}, manager {:#x}, {} event(s) drained",
                outcome.replies[0],
                outcome.replies[1],
                outcome.replies[2],
                outcome.manager,
                outcome.drained,
            );
            kcore::verdict::claims(&["power.votes-ok", "power.clamped"]);
        }
        Ok(None) => kprintln!("power-votes: skipped (this image carries no power manager)"),
        Err(which) => {
            kprintln!(
                "power-votes: FAIL — check {which} ({} reports: {:#x} {:#x} {:#x} {:#x})",
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
                BIND_REPORTS[0].load(Ordering::SeqCst),
                BIND_REPORTS[1].load(Ordering::SeqCst),
                BIND_REPORTS[2].load(Ordering::SeqCst),
                BIND_REPORTS[3].load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And a machine that idles and is woken by a real device** (D335). The
    // wake source here is the mc146818 alarm — two ports of the ISA address
    // space rather than the page the other port maps — and what that changes is
    // only how the kernel touches it: the graph node, the route, the right and
    // the arming are the same story.
    match wake_check(kernel_vm, frames) {
        Ok(Some(outcome)) => {
            // power-wake: OK — the manager idled a domain, parked on the port
            // its RTC's line was routed to, and was woken by an alarm this
            // kernel armed. It counted the wake, saw the grace hold, idled the
            // domain, was refused when it tried to arm the same device through
            // a capability without the right, and left the device in service.
            kprintln!(
                "power-wake: OK — report={:#x}, {} interrupt(s) taken at the line",
                outcome.reported,
                outcome.deliveries,
            );
            kcore::verdict::claims(&["power.wake-ok", "power.wake-right-required"]);
        }
        Ok(None) => kprintln!("power-wake: skipped (this image carries no power manager)"),
        Err(which) => {
            kprintln!(
                "power-wake: FAIL — check {which} (report {:#x}, {} interrupt(s))",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                crate::power::WAKE_DELIVERIES.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And the whole machine stopping and starting again** (D336), ordered by
    // the device tree. The wake above idled one domain; this stops everything,
    // and the ordering is enforced rather than followed — the manager asks in
    // the wrong order twice on purpose and the kernel refuses both times.
    match suspend_check(kernel_vm, frames) {
        Ok(Some(outcome)) => {
            // power-suspend: OK — suspending the bus under a live device was
            // refused and so was resuming the device through a bus still down;
            // in the right order both went. The commit slept until the RTC woke
            // it and the record named the source; the same snapshot presented
            // again aborted because that very wake had moved the counter, and a
            // wake hold refused a commit whose snapshot was fresh.
            kprintln!(
                "power-suspend: OK — events={}, bus state={:?}, device state={:?}, reported={:#x}",
                outcome.events,
                outcome.bus_state,
                outcome.device_state,
                outcome.reported,
            );
            kcore::verdict::claims(&["power.suspend-ok", "power.suspend-order"]);
        }
        Ok(None) => kprintln!("power-suspend: skipped (this image carries no power manager)"),
        Err(which) => {
            kprintln!(
                "power-suspend: FAIL — check {which} (report {:#x}, {} interrupt(s))",
                BIND_REPORTS[0].load(Ordering::SeqCst),
                crate::power::WAKE_DELIVERIES.load(Ordering::SeqCst),
            );
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // **And a file off a real ext2 volume** (D324), when the machine has a
    // second disk to hold one. The stack under it is the one above with a
    // filesystem on top; what it needed was the out-of-line path, because a
    // channel message's inline payload cannot carry a sector and nothing built
    // on a 64-byte read can find a superblock.
    match ext2_check(kernel_vm, frames, memory_map) {
        Ok(Some(outcome)) => {
            // fs: OK — a program holding one channel and no device asked for
            // `/hello.txt` **by name**; a filesystem service resolved it
            // through the ext2 directory on a volume `mke2fs` built, read the
            // inode's blocks through the block service and the driver below it,
            // and every byte matched what the image builder wrote. A path the
            // volume does not carry came back NOT_FOUND rather than as an I/O
            // error, which is what says the lookup is a lookup
            kprintln!(
                "ext2: OK — /hello.txt off {} sectors at BAR {:#x}, {}/{} sectors moved",
                outcome.capacity,
                outcome.bar_base,
                outcome.at_block,
                outcome.at_driver,
            );
            // ext2: wrote — and this half is the one an outside observer
            // checks. The boot script greps the volume once the machine has
            // stopped, for what was written through the service and for what
            // was stored straight into a mapping of the file; this is what the
            // kernel saw of the second, which leaves no message at all.
            kprintln!(
                "ext2: wrote — {} page(s) supplied into a mapping, {} dirty page(s) reported, {} event(s) drained",
                outcome.supplied,
                outcome.dirtied,
                outcome.events,
            );
            // ext2: cache — and this is the ceiling doing its work. The probe
            // walked more pages of one file than the cache holds frames for,
            // and every byte it read was the one the image builder wrote; more
            // supplies than pages walked is a page dropped behind the reader
            // and fetched again, which is eviction rather than refusal.
            kprintln!(
                "ext2: cache — {} page(s) walked twice, {} supply(s), ceiling {} frame(s)",
                outcome.big_pages,
                outcome.supplied,
                kcore::exec::CACHE_FRAME_BUDGET,
            );
            kcore::verdict::claims(&["pagecache.evicted", "pagecache.every-page-right"]);
            kcore::verdict::claims(&["fs.read", "fs.write"]);
        }
        Ok(None) => {
            kprintln!("ext2: skipped (this machine has one disk, or carries no ext2 stack)")
        }
        Err(which) => {
            kprintln!(
                "ext2: FAIL — check {which} (probe {:#x}, {} reports, {}/{} sectors)",
                BIND_REPORTS[3].load(Ordering::SeqCst),
                BIND_REPORT_COUNT.load(Ordering::SeqCst),
                BLK_SERVICE_RECEIVES.load(Ordering::SeqCst),
                BLK_DRIVER_RECEIVES.load(Ordering::SeqCst),
            );
            // **And where, when a program faulted.** Five processes deep, "one
            // of them died" is not a diagnosis: the vector, the address it
            // touched and the instruction that touched it are what say which
            // layer and which line.
            if BIND_FAULTED.load(Ordering::SeqCst) {
                kprintln!(
                    "ext2: FAIL — vec {} at {:#x}, rip {:#x}, thread {}",
                    BIND_FAULT[0].load(Ordering::SeqCst),
                    BIND_FAULT[1].load(Ordering::SeqCst),
                    BIND_FAULT[2].load(Ordering::SeqCst),
                    BIND_FAULT[3].load(Ordering::SeqCst),
                );
            }
            DEMOS_FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // The root task: it loads a real ELF through create → populate(W^X) →
    // grant → start (D25, D249), then supervises a service to a clean start
    // over 41 launches — which is also the reclaim proof, since a process slot
    // and a thread slot are capped at 16 — and gives up on one that never comes
    // up. Component management is its job, not a demo's, and the three demos
    // that made those claims from kernel-side assembly are gone (D250).
    //
    // **Late in the boot on purpose**, where those demos ran — and now behind
    // the filesystem check as well. It is the only thing here that spawns
    // threads *from inside a thread*, so it is the only producer of
    // correlation-link events with a parent, and `correlation_demo` below reads
    // them out of a ring of `EVENT_RING_CAPACITY` that anything later evicts.
    // The check above emits several hundred records in a single run and drains
    // what it left behind; standing after it is what puts these links in a ring
    // with room for them, and standing in front of it is what silently cost the
    // supervision checks their crash and fault records (build/README.md, D325).
    loader_demo(kernel_vm, frames, memory_map);

    // Driver-host restart on crash: a ring-3 driver host crashes via a real
    // #PF; the kernel contains it and a supervisor reclaims + rebinds + restarts it
    // per a (countdown, budget) policy until it comes up clean and serves a client
    // — the Stage-0 "kill-a-driver-host-under-load recovers" gate. Runs before
    // scheduler_demo (IRQ3 in ring-3 needs the timer/TICK_HOOK off, like M16/M17).
    driver_crash_reclaim_selftest(kernel_vm, frames);
    driver_restart_budget_selftest(kernel_vm, frames);
    driver_restart_demo(kernel_vm, frames);

    // Threads and scheduling: spawn CPU-bound worker threads on guard-paged
    // stacks and let the timer preempt them round-robin. This is the first use
    // of the timer, which now drives preemption rather than a bare tick count.
    scheduler_demo(kernel_vm, frames);

    // Performance: measure the primitives against their budgets (rig + numbers;
    // R1 compliance is bare-metal, so this never fails the boot).
    perf_harness(kernel_vm, frames);

    // Correlation ids: the events the demos above emitted are causally joinable —
    // stamped with a live id and thread identity, propagated across a synchronous
    // call, and linked parent-to-child on fan-out (D59). Last, so the ring holds
    // the restart demos' link and fault events.
    correlation_demo();

    // The verdict records decide the exit status: before this, every demo could
    // print FAIL and the boot still exited success, so CI could not catch a
    // regression (build/README.md, D58).
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
