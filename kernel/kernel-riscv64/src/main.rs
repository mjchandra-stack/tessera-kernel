// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tessera kernel boot glue for RISC-V 64: the only RISC-V crate that knows
//! how the machine was entered. Normalizes the firmware handoff into
//! `tessera-karch` types, brings up the early console, and hands control to
//! the kernel core.
//!
//! Entry contract. QEMU's `-kernel` loads this ELF and starts the machine in
//! **M-mode** running OpenSBI, which initializes the platform and then drops
//! to **S-mode** at the image's entry point with the hart id in `a0` and the
//! device-tree blob address in `a1`. Translation is off — `satp` is in Bare
//! mode — so the kernel runs at its physical link address from the first
//! instruction.
//!
//! That firmware step is the structural difference from the other two ports,
//! and it cuts both ways. It hands us a device tree without the header
//! gymnastics AArch64 needs to make the loader build one, and it has already
//! set up the physical memory protection and delegated exceptions to S-mode.
//! It also means part of the machine belongs to something else: the first
//! 2 MiB of RAM is OpenSBI's, and the boot memory map must carve it out —
//! which it does not do by special-casing an address, but by reading the
//! reservations the firmware published in the tree it handed us.
//!
//! This crate is deliberately small and must stay so. The demonstrations live
//! in `tessera-arch-conformance`, which every port runs, so the boot glues
//! cannot drift into three different kernels.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md ("Boot Flow"),
//! docs/hardware/01-platform-and-cpu-support.md ("Porting Rules")
//! Budget: none (init path)

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
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

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use tessera_devicetree::{DeviceTree, FdtError, HEADER_LEN, MmioDevice};
use tessera_karch::{
    BootInfo, ExitCode, FRAME_SIZE, MemoryKind, MemoryRegion, PageFlags, PhysAddr, PlatformExit,
    VirtAddr, normalize_memory_map,
};
use tessera_karch_riscv64::{
    Context, ContextSwitch, Cpu, DIRECT_MAP_BASE, EXCEPTION_ECALL_FROM_USER, KernelSection,
    Ns16550a, SupervisorTimer, TestFinisherExit, TrapFrame, build_kernel_space, exception_name,
};
mod roottask;

// The checks, split out of this file by area (build/README.md, D266): what the
// machine is asked to prove, one module per subject. The same arrangement
// `kernel-aarch64` got in D196 and `kernel/kernel` in D265.
//
// **Every module opens with `use crate::*` and is re-exported here**, so the
// namespace is as flat as it was when this was one file. Claiming these are
// boundaries would be false; what they buy is a name and a header per area.

// What the firmware says the machine is, and the timer that proves it ticks.
mod discovery;
pub(crate) use crate::discovery::*;

mod timer;
pub(crate) use crate::timer::*;

// Getting to U-mode, and giving each program its own address space.
mod process;
pub(crate) use crate::process::*;

mod space;
pub(crate) use crate::space::*;

mod umode;
pub(crate) use crate::umode::*;

// What a program can be given: a message, a device, a buffer, an interrupt.
mod device;
pub(crate) use crate::device::*;

mod exec;
pub(crate) use crate::exec::*;

mod grant;
pub(crate) use crate::grant::*;

mod irq;
pub(crate) use crate::irq::*;

// The driver framework: a real driver, bound by class, supervised, and revoked.
mod blk;
pub(crate) use crate::blk::*;

mod rebind;
pub(crate) use crate::rebind::*;

mod relay;
pub(crate) use crate::relay::*;

mod restart;
pub(crate) use crate::restart::*;

use tessera_kcore as kcore;
use tessera_kcore::kprintln;
use tessera_kcore::panic::PanicDisposition;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capacity of the boot memory map. Sized generously; the boot path reports
/// loudly rather than booting on a truncated map.
const MAX_MEMORY_REGIONS: usize = 64;

// Kernel-image boundaries, emitted by the linker script.
// SAFETY: the block only declares linker-defined symbols; no code ever reads
// their contents — only `&raw const` addresses are taken, which accesses no
// memory — so the declarations introduce no unsafe operation.
unsafe extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
}

/// What a U-mode test blob does to the word it is handed, at this port's
/// register width — which is why it is not shared: the rotation is over a
/// u64, and the two widths are different functions with one name.
fn user_transform(value: u64) -> u64 {
    value.rotate_left(8)
}

/// The kernel image's regions and the permissions each must carry once the
/// kernel owns its page tables: code executes but never writes, rodata is
/// read-only, and data (with .bss and the boot stack) is writable but never
/// executable — the write-XOR-execute split the image's own segments already
/// declare, now enforced by the hardware.
fn kernel_sections() -> [KernelSection; 3] {
    [
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

/// Physical range the `virt` machine puts its devices in — everything below
/// the base of RAM. It covers the test finisher at 0x0010_0000, the CLINT at
/// 0x0200_0000, the PLIC at 0x0c00_0000, the UART at 0x1000_0000, the
/// virtio-mmio transports above it, and the PCIe ECAM window at 0x3000_0000.
const DEVICE_RANGE: (u64, u64) = (0, 0x8000_0000);

/// Scratch virtual range the conformance battery maps and unmaps. Above the
/// top of RAM on this machine and therefore mapped by nothing, but inside the
/// same 1 GiB slot RAM occupies, so the battery exercises real three-level
/// walks rather than landing in an empty root slot.
const CONFORMANCE_SCRATCH: u64 = 0xb000_0000;

/// Tick rate the timer check programs.
const TICK_HZ: u32 = 100;

/// RISC-V machine code for `extern "C" fn() -> u64` returning
/// [`tessera_arch_conformance::SENTINEL`], for the instruction-cache case:
///
/// ```text
///   lui  a0, 0x5e17c
///   addi a0, a0, 0xde
///   ret
/// ```
///
/// Written as bytes rather than assembled from a symbol on purpose — the case
/// needs instructions that were *stored as data* into a fresh frame, which is
/// exactly the situation a symbol's address would let us avoid testing. This
/// is also the one architecture of the three where the case can genuinely
/// fail on hardware: RISC-V does not promise the instruction cache observes
/// stores, so the `fence.i` in `sync_instruction_cache` is what makes these
/// three instructions fetchable.
const SENTINEL_CODE: &[u8] = &[
    0x37, 0xc5, 0x17, 0x5e, // lui  a0, 0x5e17c
    0x13, 0x05, 0xe5, 0x0d, // addi a0, a0, 0xde
    0x67, 0x80, 0x00, 0x00, // ret
];

/// Backing storage for the global console. A `static mut` is the honest
/// representation of "one mutable device object created before concurrency
/// exists"; the single `&mut` is taken exactly once, in `kernel_main`.
/// The console, named through the direct map. Rust does not run until the
/// entry stub has turned translation on and jumped into the upper half, so the
/// device's physical address is never the right one here.
static mut UART: Ns16550a = Ns16550a::at(DIRECT_MAP_BASE as usize + Ns16550a::VIRT_BASE);

// Entry stub. Runs in S-mode with translation off, before any Rust invariant
// holds: there is no stack and `.bss` is whatever the loader left.
//
// Ordering is forced by those facts. Interrupts are masked before any state
// is touched; the firmware handoff is parked in callee-saved registers
// because everything below is free to clobber the argument registers; `.bss`
// is zeroed before the stack is established (the zeroing pass is
// register-only, and the boot stack lives inside `.bss`, so nothing may be on
// it yet); and only then is Rust entered.
core::arch::global_asm!(
    r#"
.section .text._start
.globl _start
_start:
    // Mask and clear every supervisor interrupt for the duration of bring-up.
    csrw    sie, zero
    csrw    sip, zero
    csrci   sstatus, 2

    // Firmware handoff: a0 is this hart's id, a1 the device-tree blob.
    // The hart id lives in tp for the rest of the kernel's life, which is
    // where `CpuOps::hw_id` reads it from — `mhartid` is an M-mode CSR and
    // unreadable here.
    mv      tp, a0
    mv      s0, a1

    // Every `la` below is PC-relative (-Ccode-model=medium), so although this
    // image is linked in the upper half, each symbol it names resolves to that
    // symbol's *physical* address while translation is still off. That is the
    // property the whole low-half prologue rests on.
    //
    // Anchor the global pointer, with relaxation disabled across the load so
    // the instruction that establishes gp is not itself rewritten to use it.
.option push
.option norelax
    la      gp, __global_pointer$
.option pop

    // Clear .bss. Register-only: the boot stack is inside it.
    la      t0, __bss_start
    la      t1, __bss_end
1:
    bgeu    t0, t1, 2f
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       1b

2:
    la      sp, __boot_stack_top

    // Fill the boot root table with 1 GiB gigapages covering the low 4 GiB
    // twice: once identity, so the instruction after `satp` still fetches, and
    // once at the direct-map base, which is where everything lives from the
    // jump below onwards. A PTE is (phys >> 12) << 10 with V|R|W|X|G|A|D set.
    la      t0, boot_root
    li      t1, 512
    mv      t2, t0
3:
    sd      zero, 0(t2)
    addi    t2, t2, 8
    addi    t1, t1, -1
    bnez    t1, 3b

    li      t3, 0
4:
    slli    t4, t3, 30              // phys = i << 30
    srli    t5, t4, 12
    slli    t5, t5, 10
    ori     t5, t5, 0xef            // V|R|W|X|G|A|D
    slli    t6, t3, 3
    add     t2, t0, t6
    sd      t5, 0(t2)               // identity: root[i]
    addi    t6, t3, 256             // the upper half begins at root[256]
    slli    t6, t6, 3
    add     t2, t0, t6
    sd      t5, 0(t2)               // direct map: root[256 + i]
    addi    t3, t3, 1
    li      t6, 4
    blt     t3, t6, 4b

    // satp = Sv39 | (root >> 12)
    srli    t1, t0, 12
    li      t2, 8
    slli    t2, t2, 60
    or      t1, t1, t2
    sfence.vma
    csrw    satp, t1
    sfence.vma

    // Into the upper half. `la` is PC-relative, so 5f is this code's physical
    // address; the base is -1 << 38, the lowest address whose top 26 bits are
    // ones. The stack moves in the same breath — the frame belongs to whichever
    // alias is executing. Nothing computed before this point may be reused
    // after it, which is why Rust has not run yet: a trait object's vtable is a
    // link-time absolute address, and every one of them is high.
    li      t1, -1
    slli    t1, t1, 38
    la      t0, 5f
    add     t0, t0, t1
    add     sp, sp, t1
    jr      t0
5:
    mv      a0, s0
    call    kernel_main

    // kernel_main is `-> !`; if it ever returns, stop rather than run on
    // through whatever follows in memory.
3:
    wfi
    j       3b
"#
);

/// Rust entry point, called by the stub above with the device-tree blob
/// address. Runs in S-mode with translation off and interrupts masked.
///
/// The boot, in the order it happens. Each phase below is a function rather
/// than a paragraph of this one, so that what a phase needs and what it
/// produces are in its signature instead of in eight hundred lines of shared
/// scope. The order is unchanged: `docs/architecture/01` ("Boot Flow") step 4
/// is the first six calls, and everything after is what this machine is asked
/// to prove.
///
/// # Safety
///
/// Called exactly once, by `_start`, on the boot hart, with a valid stack and
/// zeroed `.bss`. `dtb` is whatever the firmware supplied and is not trusted
/// beyond being a number: the reader validates the blob's magic and
/// bounds-checks every access inside it.
#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb: u64) -> ! {
    early_console();

    // The firmware handed over a *physical* address; everything is reached
    // through the direct map from here on.
    let dtb = dtb + DIRECT_MAP_BASE;
    let mut storage = [EMPTY_REGION; MAX_MEMORY_REGIONS];
    let memory_map = read_memory_map(dtb, &mut storage);
    let mut frames = kcore::pmem::BumpFrameAllocator::new(memory_map);
    let mut kernel_space = enable_translation(&mut frames, memory_map);
    install_traps();
    verify_store();

    check_timer();
    check_arch_conformance(&mut kernel_space, &mut frames);
    check_bus(dtb, &kernel_space, &mut frames);
    check_ring3(dtb, &mut kernel_space, &mut frames);
    check_relay(&kernel_space, &mut frames);
    check_root_task(&kernel_space, &mut frames);

    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    kcore::verdict::claims(&["boot.alive"]);
    TestFinisherExit::exit(ExitCode::Success)
}

/// The console, the clock and the two backstops, before anything that might
/// need to report a failure through them.
fn early_console() {
    // The entry stub enabled Sv39 and jumped high before any Rust ran, so the
    // direct map is already live and this is true from the first instruction
    // here — but the platform devices this crate does not construct itself
    // (the PLIC, the test finisher) name themselves by physical address and
    // have to be told the window. Done before the console, because the panic
    // path exits through the finisher.
    //
    // SAFETY: `DIRECT_MAP_BASE` is the base of the direct map the entry stub
    // installed and `build_kernel_space` re-establishes; it covers the `virt`
    // machine's device range read-write for the life of the kernel.
    unsafe { tessera_karch_riscv64::set_device_access_base(DIRECT_MAP_BASE as usize) };

    // SAFETY: `kernel_main` runs exactly once, on the boot CPU, before any
    // other code; this is the only reference ever taken to UART.
    let uart = unsafe { &mut *&raw mut UART };
    uart.init();
    // Before the first lock of any kind — the console's own — so that a
    // non-zero count below means a lock was reached earlier than this, not
    // merely earlier than the tick.
    let unprotected = kcore::sync::install_interrupt_control::<Cpu>();
    let dropped = kcore::console::init_global(uart);

    // Timestamp source for structured events, and the per-boot correlation
    // epoch. Both arrive as porting-layer readings rather than by any
    // architecture's name for its counter.
    let unstamped = kcore::event::set_clock(<Cpu as tessera_karch::CpuOps>::counter_serialized);
    if unstamped > 0 {
        kprintln!("event: {unstamped} record(s) emitted before the clock was installed");
    }

    if unprotected > 0 {
        kprintln!("sync: {unprotected} critical section(s) before interrupt control");
    }

    // Access prevention: `sstatus.SUM` clear by default, set only inside a
    // window. This port used to set it once per demo and leave it — eight
    // calls, each removing the hardware backstop for the whole run rather than
    // for the copy that needed it.
    // SAFETY: the boot hart, once, during its own bring-up.
    let sum_off = unsafe { tessera_karch_riscv64::enable_access_prevention() };
    if sum_off {
        let unwindowed = kcore::useraccess::install(
            |allowed| {
                // SAFETY: the window's contract is the caller's — every user
                // pointer the kernel follows is validated first. This only
                // moves `sstatus.SUM`.
                unsafe { tessera_karch_riscv64::set_user_access(allowed) }
            },
            tessera_karch_riscv64::user_access,
        );
        kprintln!("sum: OK — access prevention on, {unwindowed} copies made before it");
        kcore::verdict::claims(&["sum.installed"]);
    } else {
        kprintln!("sum: off — this port has not turned access prevention on");
    }
    kcore::trace::set_epoch(<Cpu as tessera_karch::CpuOps>::counter_serialized());
    kcore::trace::set_current_correlation(kcore::trace::mint());

    kprintln!("Tessera {VERSION} (Stage 0 skeleton, RISC-V 64)");
    kprintln!("early console: NS16550A @ 115200");
    if dropped > 0 {
        kprintln!("early console: {dropped} write(s) dropped before init");
    }
}

/// The memory map, read from the device tree and reported.
///
/// Borrows `storage` from the caller because the frame allocator built from
/// the result outlives this call: the regions have to live as long as the
/// allocator that walks them.
fn read_memory_map(dtb: u64, storage: &mut [MemoryRegion]) -> &[MemoryRegion] {
    let memory_map = match boot_memory_map(dtb, storage) {
        Ok(map) => map,
        Err(error) => {
            // The memory map is not optional and there is no second source
            // for it. Reporting the code and stopping beats booting onto a
            // map we could not read (docs/lifecycle/04, "No Silent
            // Fallback").
            kprintln!(
                "boot: FATAL: device tree unreadable (fdt error {})",
                error as u16
            );
            TestFinisherExit::exit(ExitCode::Failure)
        }
    };

    let usable: u64 = memory_map
        .iter()
        .filter(|region| region.kind == MemoryKind::Usable)
        .map(|region| region.len)
        .sum();
    kprintln!(
        "memmap: {} regions, {} usable frames ({} MiB usable)",
        memory_map.len(),
        usable / FRAME_SIZE,
        usable / (1024 * 1024)
    );
    for region in memory_map {
        kprintln!(
            "memmap:   {:#018x}..{:#018x} {}",
            region.base.as_u64(),
            region.base.as_u64() + region.len,
            kind_name(region.kind)
        );
    }

    memory_map
}

/// Sv39 on, the kernel in the upper half, and the low half proved empty.
///
/// Returns the space it activated. The `satp` write is the moment translation
/// stops being a formality, so what this returns is the first object in the
/// boot that other phases have to be given rather than assume.
fn enable_translation(
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    memory_map: &[MemoryRegion],
) -> tessera_karch_riscv64::KernelAddressSpace {
    let ram_start = memory_map.first().map(|r| r.base.as_u64()).unwrap_or(0);
    let ram_end = memory_map
        .last()
        .map(|region| region.base.as_u64() + region.len)
        .unwrap_or(0);

    // Build the kernel's real tables and turn translation on. Unlike AArch64
    // there is no coarse boot-table step: the tables are built with a working
    // stack and console, and `satp` goes from Bare to Sv39 exactly once.
    let (kernel_space, image_pages) = match build_kernel_space(
        frames,
        &kernel_sections(),
        (ram_start, ram_end),
        DEVICE_RANGE,
    ) {
        Ok(built) => built,
        Err(error) => {
            kprintln!(
                "paging: FATAL: kernel tables not built (kerror {})",
                error.code()
            );
            TestFinisherExit::exit(ExitCode::Failure)
        }
    };

    // The real tables replace the stub's coarse ones. Both carry the same
    // direct map, so this frame, this stack and this code all keep their
    // addresses across the switch; what changes is that the kernel image now
    // has per-section permissions and the low half is empty.
    // SAFETY: the boot CPU alone; the tables were built for exactly this.
    unsafe {
        use tessera_karch::AddressSpaceOps;
        kernel_space.activate()
    };
    let mut kernel_space = kernel_space;

    // The tables were built with a zero access window, because the stub's
    // identity gigapages were what made a freshly allocated table frame
    // reachable at all. Those are gone as of the line above — the new root has
    // nothing in the low half — so every later walk has to reach a table
    // through the direct map instead. Moving the window is the switch from
    // "translation is a formality" to "the kernel lives somewhere".
    // SAFETY: the tables just activated map all of RAM at `DIRECT_MAP_BASE`
    // read-write, which is exactly the window being declared.
    unsafe { kernel_space.set_access_base(DIRECT_MAP_BASE) };

    kprintln!(
        "paging: Sv39 on, kernel upper-half at {:#018x}, {} MiB direct-mapped, W^X image ({image_pages} pages)",
        &raw const __kernel_start as u64,
        (ram_end - ram_start) / (1024 * 1024)
    );

    // What the split is *for*, asserted rather than assumed. The kernel's own
    // load address, read as a virtual address, must now translate to nothing:
    // the low half is empty, which is what leaves it available to a per-process
    // `satp` root. The high alias of the same frame must still resolve, or the
    // kernel would not be running. Checking both directions distinguishes a
    // real split from a kernel that merely moved.
    {
        use tessera_karch::AddressSpaceOps;
        let phys_as_virt = VirtAddr::new(&raw const __kernel_start as u64 - DIRECT_MAP_BASE);
        let high = VirtAddr::new(&raw const __kernel_start as u64);
        match (
            kernel_space.translate(phys_as_virt),
            kernel_space.translate(high),
        ) {
            (None, Some(_)) => kprintln!(
                "paging: low half empty below {:#018x} — free for per-process roots",
                DIRECT_MAP_BASE
            ),
            _ => {
                kprintln!("paging: FATAL: the low half is not empty, the split is not real");
                TestFinisherExit::exit(ExitCode::Failure)
            }
        }
    }

    let _boot = BootInfo {
        hhdm_offset: DIRECT_MAP_BASE,
        memory_map,
    };

    kernel_space
}

/// Exceptions report instead of trapping to whatever `stvec` held, and the
/// interrupt controller comes up behind them.
fn install_traps() {
    // Exceptions now report instead of trapping to whatever `stvec` held, and
    // the periodic tick exists. Vectors are installed before the interrupt
    // controller, so a fault raised while bringing the PLIC up is still
    // reported.
    // SAFETY: boot hart, interrupts still masked, and the kernel's text is
    // mapped executable at its current address by the tables activated above.
    unsafe { tessera_karch_riscv64::init_vectors() };
    tessera_karch_riscv64::set_trap_handler(fatal_trap);
    // SAFETY: the PLIC is identity-mapped device memory (DEVICE_RANGE), this
    // is the boot hart, and interrupts are still masked.
    unsafe { tessera_karch_riscv64::init_plic() };
}

/// The verified image store, before anything that might want to read from it.
fn verify_store() {
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
            }
            Err(error) => {
                kprintln!("store: FATAL: check failed ({})", error.code());
                TestFinisherExit::exit(ExitCode::Failure)
            }
        }
    }
}

/// The periodic tick, end to end.
fn check_timer() {
    match timer_check() {
        Ok(observed) => kprintln!("timer: {observed} ticks at {TICK_HZ} Hz, Sstc delivering"),
        Err(which) => {
            kprintln!("timer: FATAL: tick check {which} failed");
            TestFinisherExit::exit(ExitCode::Failure)
        }
    }
}

/// The porting-layer battery every port runs. Its verdicts, not this crate's
/// opinion of them, decide whether the port passed.
fn check_arch_conformance(
    kernel_space: &mut tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) {
    let summary = tessera_arch_conformance::run::<ContextSwitch, _>(
        &mut tessera_arch_conformance::Platform {
            space: kernel_space,
            frames,
            direct_map_base: DIRECT_MAP_BASE,
            scratch: VirtAddr::new(CONFORMANCE_SCRATCH),
            sentinel_code: SENTINEL_CODE,
        },
    );
    kprintln!("arch: {} passed, {} failed", summary.passed, summary.failed);
    if summary.failed > 0 {
        kprintln!(
            "TESSERA-STAGE0: {} conformance case(s) FAILED",
            summary.failed
        );
        TestFinisherExit::exit(ExitCode::Failure)
    }
}

/// PCI enumeration, before any of the ring-3 checks: it is discovery, and what
/// it finds is what a later milestone binds by class.
fn check_bus(
    dtb: u64,
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) {
    const BLANK: tessera_pci::Function = tessera_pci::Function {
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
    let mut functions = [BLANK; MAX_PCI_FUNCTIONS];
    match pcie_enumerate(dtb, &mut functions) {
        Some(Ok(count)) => {
            let endpoint = functions[..count].iter().find(|f| f.first_bar().is_some());
            match endpoint {
                Some(f) => {
                    let (bar, len) = f.first_bar().unwrap_or_default();
                    // pcie: OK — walked ECAM and found {count}
                    // function(s); {:04x}:{:04x} at {:02x}:{:02x}.{} class
                    // {:#08x} took a {len:#x} BAR at {bar:#x}, placed by
                    // this kernel because the machine leaves BARs
                    // unassigned
                    kprintln!(
                        "pcie: OK — {count} function(s); {:04x}:{:04x} at {:02x}:{:02x}.{} class {:#08x}, BAR {len:#x} at {bar:#x}",
                        f.vendor,
                        f.device,
                        f.bdf.bus,
                        f.bdf.device,
                        f.bdf.function,
                        f.class_code
                    );
                    kcore::verdict::claims(&["pcie.ok"]);

                    // Bind it by class. The manager cannot read config
                    // space, so the only way it can know this is a block
                    // device is the identity the kernel recorded while
                    // enumerating — which is the whole point of the graph
                    // carrying one.
                    let identity = kcore::devmgr::DeviceIdentity {
                        class_code: f.class_code,
                        vendor: f.vendor,
                        device: f.device,
                        bdf: (u16::from(f.bdf.bus) << 8)
                            | (u16::from(f.bdf.device) << 3)
                            | u16::from(f.bdf.function),
                        revision: f.revision,
                        bus: kcore::devmgr::DeviceBus::Pci,
                    };
                    // The region a driver actually needs, at its real
                    // size — and the word it must read from beyond the
                    // first page of it, which the kernel reads here at the
                    // same physical address. A one-page grant faults there.
                    let (bar, bar_len) = virtio_pci_bar(dtb, f).unwrap_or((bar, len));
                    let far = if bar_len > FAR_WINDOW_OFFSET {
                        // SAFETY: the BAR is placed by this kernel inside
                        // `DEVICE_RANGE`, and is therefore reachable at
                        // `DIRECT_MAP_BASE + phys` like every other device
                        // on this port; the offset is inside the BAR.
                        u64::from(
                            unsafe {
                                tessera_karch_riscv64::mmio_read32(
                                    DIRECT_MAP_BASE as usize + (bar + FAR_WINDOW_OFFSET) as usize,
                                )
                            } & 0xffff,
                        )
                    } else {
                        0
                    };
                    let expected = 0x5043u64 << 48
                        | (far << 32)
                        | (u64::from(f.vendor) << 16)
                        | u64::from(f.device);
                    match driver_rebind_check(kernel_space, frames, bar, bar_len, Some(identity)) {
                        Ok((first, second)) if first == expected && second == expected => {
                            // pci-bind: OK — the manager classified a
                            // device it cannot read (class {:#04x} from
                            // the graph, not from a register) and bound it
                            // to two drivers in turn; each reported back
                            // {first:#x} — the vendor/device the kernel
                            // enumerated
                            kprintln!(
                                "pci-bind: OK — class code={:#04x}, first={first:#x}",
                                f.class_code >> 16
                            );
                        }
                        Ok((first, second)) => {
                            kprintln!(
                                "pci-bind: FATAL: drivers reported {first:#x} and {second:#x}, expected {expected:#x}"
                            );
                            TestFinisherExit::exit(ExitCode::Failure)
                        }
                        Err(which) => {
                            kprintln!("pci-bind: FATAL: check {which} failed");
                            TestFinisherExit::exit(ExitCode::Failure)
                        }
                    }
                }
                None => kprintln!(
                    "pcie: OK — walked ECAM and found {count} function(s), none with a memory BAR to place"
                ),
            }
        }
        Some(Err(e)) => {
            kprintln!("pcie: FATAL: enumeration failed: {e:?}");
            TestFinisherExit::exit(ExitCode::Failure)
        }
        None => kprintln!("pcie: skipped — no PCI host bridge in the device tree"),
    }
}

/// Reports a check that failed the way every arm of this battery reports it,
/// and ends the run.
///
/// **Ending it is the port's business rather than the check's**
/// (`kernel/boot-checks`: "a check here reports and returns; it never exits"),
/// and this is the one place on this port that does it for the ladder below.
fn or_die<T>(name: &str, result: Result<T, u32>) -> T {
    match result {
        Ok(value) => value,
        Err(which) => {
            kprintln!("{name}: FATAL: check {which} failed");
            TestFinisherExit::exit(ExitCode::Failure)
        }
    }
}

/// The ring-3 ladder, in the order it runs: U-mode, then a space of its own,
/// then the kcore substrate, then a message across a channel, then a device,
/// then that device given away, then its interrupt, then a compiled driver,
/// then the framework that replaces one.
///
/// **A sequence, where it used to be a staircase.** Each step ran inside the
/// previous step's `Ok` arm — fifteen levels of indentation by the last one —
/// because each step's value feeds the next. The nesting bought nothing: every
/// failure arm printed and ended the run, which is what `or_die` does in one
/// line. What is left branching is what a *machine* does not have, which is a
/// different question and now the only `match` here.
fn check_ring3(
    dtb: u64,
    kernel_space: &mut tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) {
    let code = or_die("umode", umode_check(kernel_space, frames));
    or_die("process", process_space_check(kernel_space, frames, code));

    let logged = or_die("kcore-umode", kcore_process_check(kernel_space, frames));
    kprintln!(
        "kcore-umode: OK — a kcore Process/Thread ran in U-mode under its own Sv39 root (log {logged:#x})"
    );

    // ipc: OK — two U-mode processes exchanged a message over a channel:
    // server saw {request:#x}, client got {reply:#x} back ({switches}
    // switches, via kcore::dispatch)
    let (request, reply, switches) = or_die("ipc", ipc_check(kernel_space, frames));
    kprintln!("ipc: OK — request={request:#x}, reply={reply:#x}, switches={switches}");

    let mut windows = [MmioDevice {
        base: 0,
        size: 0,
        intid: None,
        trigger: None,
    }; MAX_MMIO_DEVICES];
    let found = virtio_mmio_windows(dtb, &mut windows);

    // Virtio is optional on a machine. Saying so beats passing quietly
    // (docs/lifecycle/04). Everything below needs a transport, so this is the
    // one early return rather than a wrapper around the rest.
    let Some(window) = windows[..found]
        .iter()
        .find(|w| virtio_identity(w.base).0 == tessera_virtio::MAGIC)
    else {
        kprintln!(
            "mmio: skipped — no virtio-mmio transport on this machine ({found} window(s) in the device tree)"
        );
        return;
    };

    let (packed, dma_phys) = or_die("mmio", device_check(kernel_space, frames, window.base));
    kprintln!(
        "mmio: OK — ring-3 mapped virtio MMIO at {:#x} by capability, read magic {:#x} device-id {}",
        window.base,
        packed & 0xffff_ffff,
        packed >> 32
    );
    kprintln!(
        "dma: OK — ring-3 got a DMA page: its user VA {USER_DMA_VA:#x} is phys {dma_phys:#x}, sentinel verified through the direct map"
    );

    // grant: OK — a device capability crossed a channel: the driver was told
    // handle {handle}, read magic {:#x} through it, and the manager no longer
    // holds it
    let (handle, packed) = or_die("grant", grant_check(kernel_space, frames, window.base));
    kprintln!(
        "grant: OK — handle={handle}, packed={:#x}",
        packed & 0xffff_ffff
    );

    match rtc_device(dtb) {
        Some(rtc) => {
            let (line, delivered) = or_die("irq", irq_check(kernel_space, frames, rtc));
            kprintln!(
                "irq: OK — a ring-3 driver parked on its device, woken {delivered}x on line {line} (mask-on-deliver, IrqComplete re-arm)"
            )
        }
        None => kprintln!("irq: skipped — this machine has no real-time clock to interrupt with"),
    }

    // The block driver and the framework both need a *backed* transport, which
    // only exists when a disk is attached.
    let blk = windows[..found]
        .iter()
        .find(|w| virtio_identity(w.base).1 == tessera_virtio::DEVICE_ID_BLOCK);

    match blk {
        Some(blk) => {
            let magic = or_die("blk", blk_driver_check(kernel_space, frames, *blk));
            kprintln!(
                "blk: OK — a compiled ring-3 driver read sector 0 at {:#x}, got {magic:#018x}, woken by its device",
                blk.base
            );
            kcore::verdict::claims(&["blk.ok"]);
        }
        None => kprintln!("blk: skipped — no virtio block device attached to this machine"),
    }

    // The framework: a device bound by class, and a driver replaced without
    // the supervisor ever naming the device.
    let Some(blk) = blk else {
        kprintln!("driver-rebind: skipped — no virtio block device attached to this machine");
        kprintln!("device-events: skipped — no virtio block device attached to this machine");
        return;
    };

    // driver-rebind: OK — a driver crashed holding the transport (a real
    // contained user fault, not a tidy exit), the kernel reclaimed what it
    // held, and two more drivers bound the same transport by class, reporting
    // {first:#x} then {second:#x}
    let (first, second) = or_die(
        "driver-rebind",
        driver_rebind_check(kernel_space, frames, blk.base, blk.size, None),
    );
    kprintln!("driver-rebind: OK — first={first:#x}, second={second:#x}");
    kcore::verdict::claims(&["driver-rebind.ok"]);

    // The ladder's other end: a host that never comes back is given up on
    // rather than respawned for ever. Run before the records are read, so both
    // supervisors' records are in the same drain.
    //
    // driver-giveup: OK — a host that crashed every time was restarted exactly
    // {launches} times, its budget, and then the supervisor stopped. A
    // recovery policy has an end; without one it is a machine that respawns a
    // broken driver until something else breaks
    let launches = or_die(
        "driver-giveup",
        driver_giveup_check(kernel_space, frames, blk.base, blk.size),
    );
    kprintln!("driver-giveup: OK — launches={launches}");
    kcore::verdict::claims(&["driver-giveup.ok"]);

    // Same runs, read back from the records the kernel emitted while they
    // happened.
    if !tessera_boot_checks::device_events(REBIND_DEVICE_OBJECT) {
        TestFinisherExit::exit(ExitCode::Failure)
    }
}

/// What a device's data path costs. It needs no hardware: the topology is
/// graph nodes, and the whole of what is being tested — the manifest, the
/// arbiter, the accumulation and the budget — is the same source AArch64
/// compiles.
fn check_relay(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) {
    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
        kprintln!(
            "relay: skipped (no embedded device-manager/blk-probe ELF; a profile turned it off, or the cargo inner loop)"
        );
    } else {
        match relay_check(kernel_space, frames) {
            Ok((declared, undeclared)) => {
                // relay: OK — what a device's data path costs is declared,
                // accumulated over the graph's own parent edges, and checked
                // before anything binds. One manifest entry, one budget of
                // {}us, and two block devices differing only in depth: the
                // near one bound at {} relay hop costing {}us on a path
                // carrying {}Mbit/s, and the far one — same class, same entry,
                // one hub further down at {}us — was refused BudgetExceeded,
                // so a class cannot silently miss its budget behind a hub. The
                // network device sits well inside its latency budget and was
                // refused ThroughputTooLow, because a shorter path is no help
                // when the remaining hop is the narrow one. And a hub the
                // kernel cannot identify is not free: the manifest claims
                // nothing about it, so the device behind it was refused
                // PathUndeclared rather than bound as though it were direct-
                // attached. Not one line of the mechanism is per-port (reports
                // {:#x}, {:#x})
                kprintln!(
                    "relay: OK — budget {}us; near {} hop {}us {}Mb; far {}us refused; declared {:#x}, undeclared {:#x}",
                    BLOCK_PATH_BUDGET_US,
                    (declared >> 8) & 0xff,
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
            Err(which) => {
                kprintln!(
                    "relay: FATAL: check {which} failed (reports {:#x}, {:#x}, count {})",
                    REPORTS[0].load(Ordering::SeqCst),
                    REPORTS[1].load(Ordering::SeqCst),
                    REPORT_COUNT.load(Ordering::SeqCst),
                );
                TestFinisherExit::exit(ExitCode::Failure)
            }
        }
    }
}

/// The root task: the kernel seeds one job and one bus, starts one process,
/// and everything after that is user space's. The third port to run it, and
/// the third caller of `kcore::loader` (build/README.md, D257).
fn check_root_task(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) {
    match roottask::root_task_check(kernel_space, frames) {
        Ok(None) => kprintln!(
            "roottask: skipped (no embedded root-task ELF; a profile turned it off, or the cargo inner loop)"
        ),
        Ok(Some(report)) => {
            // The low byte is the bind's status and the next is how many relay
            // hops the path cost — zero and one for the device directly behind
            // the bus. Both, rather than a tag bit: `blk-probe` packs its
            // answer into the same word it returns a failure code in, and a bit
            // test on that word reads a failure as a success (D253).
            let bound = report.driver_report & 0xff == 0 && (report.driver_report >> 8) & 0xff == 1;
            let ok =
                report.exit == 0 && report.launches == roottask::EXPECTED_ROOT_LAUNCHES && bound;
            if ok {
                kprintln!(
                    "roottask: OK — launches={} driver={:#x}",
                    report.launches,
                    report.driver_report
                );
                kcore::verdict::claims(&[
                    "roottask.channel-created",
                    // **A child told what to work on** (D302, `docs/roadmap/04`
                    // Phase 1). One program run three ways: it echoed back the
                    // exact path its parent put in `StartupArgs`, and refused
                    // the other two legs.
                    "roottask.arguments",
                    // And it refused them *differently* — `USAGE` for no
                    // arguments, `NOT_FOUND` for a path it will not resolve —
                    // in `ExitStatus`'s vocabulary rather than in numbers of
                    // its own, so the parent acted on which failure it was.
                    "roottask.exit-status",
                    "roottask.granted",
                    "roottask.child-spoke",
                    "roottask.concurrent",
                    "roottask.supervised",
                    "roottask.reclaimed",
                    "roottask.port",
                    "roottask.framework",
                ]);
            } else {
                kprintln!(
                    "roottask: FATAL: launches={} exit={} driver={:#x}",
                    report.launches,
                    report.exit,
                    report.driver_report
                );
                TestFinisherExit::exit(ExitCode::Failure)
            }
        }
        Err(which) => {
            kprintln!("roottask: FATAL: check {which} failed");
            TestFinisherExit::exit(ExitCode::Failure)
        }
    }
}

/// Reports a fatal exception and ends the run. Without this a fault would
/// return through `sret` into the instruction that caused it and loop
/// forever, which is a hang rather than a diagnosis.
fn fatal_trap(frame: &tessera_karch_riscv64::TrapFrame) -> ! {
    kprintln!(
        "TRAP: {} (scause={:#018x}{})",
        tessera_karch_riscv64::exception_name(frame.scause),
        frame.scause,
        if tessera_karch_riscv64::is_write_fault(frame.scause) {
            ", write"
        } else {
            ""
        }
    );
    kprintln!(
        "TRAP: stval={:#018x} sepc={:#018x} sstatus={:#018x} ra={:#018x}",
        frame.stval,
        frame.sepc,
        frame.sstatus,
        frame.ra
    );
    TestFinisherExit::exit(ExitCode::Failure)
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    match kcore::panic::enter() {
        PanicDisposition::ExitImmediately => TestFinisherExit::exit(ExitCode::Failure),
        PanicDisposition::Report => {
            // SAFETY: panic path on the only running hart; interrupts are
            // masked for the whole of this milestone.
            unsafe {
                kcore::panic::report_global(format_args!("{}", info.message()), info.location());
            }
            TestFinisherExit::exit(ExitCode::Failure)
        }
    }
}
// ---------------------------------------------------------------------------
// The driver framework: a device is bound by class, and survives its driver
// ---------------------------------------------------------------------------

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
