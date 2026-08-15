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

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_devicetree::{DeviceTree, FdtError, HEADER_LEN};
use tessera_karch::{
    BootInfo, ExitCode, FRAME_SIZE, MemoryKind, MemoryRegion, PageFlags, PhysAddr, PlatformExit,
    VirtAddr, normalize_memory_map,
};
use tessera_karch_riscv64::{
    ContextSwitch, Cpu, DIRECT_MAP_BASE, KernelSection, Ns16550a, SupervisorTimer,
    TestFinisherExit, build_kernel_space,
};
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
static mut UART: Ns16550a = Ns16550a::virt();

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
    // where `CpuOps::cpu_id` reads it from — `mhartid` is an M-mode CSR and
    // unreadable here.
    mv      tp, a0
    mv      s0, a1

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
/// # Safety
///
/// Called exactly once, by `_start`, on the boot hart, with a valid stack and
/// zeroed `.bss`. `dtb` is whatever the firmware supplied and is not trusted
/// beyond being a number: the reader validates the blob's magic and
/// bounds-checks every access inside it.
#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb: u64) -> ! {
    // SAFETY: `kernel_main` runs exactly once, single-threaded, before any
    // other code; this is the only reference ever taken to UART.
    let uart = unsafe { &mut *&raw mut UART };
    uart.init();
    let dropped = kcore::console::init_global(uart);

    // Timestamp source for structured events, and the per-boot correlation
    // epoch. Both arrive as porting-layer readings rather than by any
    // architecture's name for its counter.
    kcore::event::set_clock(<Cpu as tessera_karch::CpuOps>::counter_serialized);
    kcore::trace::set_epoch(<Cpu as tessera_karch::CpuOps>::counter_serialized());
    kcore::trace::set_current_correlation(kcore::trace::mint());

    kprintln!("Tessera {VERSION} (Stage 0 skeleton, RISC-V 64)");
    kprintln!("early console: NS16550A @ 115200");
    if dropped > 0 {
        kprintln!("early console: {dropped} write(s) dropped before init");
    }

    let mut storage = [EMPTY_REGION; MAX_MEMORY_REGIONS];
    let memory_map = match boot_memory_map(dtb, &mut storage) {
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

    let ram_start = memory_map.first().map(|r| r.base.as_u64()).unwrap_or(0);
    let ram_end = memory_map
        .last()
        .map(|region| region.base.as_u64() + region.len)
        .unwrap_or(0);
    let mut frames = kcore::pmem::BumpFrameAllocator::new(memory_map);

    // Build the kernel's real tables and turn translation on. Unlike AArch64
    // there is no coarse boot-table step: the tables are built with a working
    // stack and console, and `satp` goes from Bare to Sv39 exactly once.
    let (kernel_space, image_pages) = match build_kernel_space(
        &mut frames,
        DIRECT_MAP_BASE,
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

    // SAFETY: the space maps this code, this stack, and the console's device
    // registers at the addresses they already occupy — the image identity-
    // mapped at its per-section permissions, RAM direct-mapped, and the
    // device range below it — so the instruction after the switch still
    // fetches and the next `kprintln!` still reaches the wire.
    unsafe {
        use tessera_karch::AddressSpaceOps;
        kernel_space.activate()
    };
    kprintln!(
        "paging: Sv39 on, {} MiB RAM direct-mapped at {:#018x}, W^X kernel image ({image_pages} pages)",
        (ram_end - ram_start) / (1024 * 1024),
        DIRECT_MAP_BASE + ram_start
    );
    let mut kernel_space = kernel_space;

    let _boot = BootInfo {
        hhdm_offset: DIRECT_MAP_BASE,
        memory_map,
    };

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

    match timer_check() {
        Ok(observed) => kprintln!("timer: {observed} ticks at {TICK_HZ} Hz, Sstc delivering"),
        Err(which) => {
            kprintln!("timer: FATAL: tick check {which} failed");
            TestFinisherExit::exit(ExitCode::Failure)
        }
    }

    // The porting-layer battery every port runs. Its verdicts, not this
    // crate's opinion of them, decide whether the port passed.
    let summary = tessera_arch_conformance::run::<ContextSwitch, _>(
        &mut tessera_arch_conformance::Platform {
            space: &mut kernel_space,
            frames: &mut frames,
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

    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    TestFinisherExit::exit(ExitCode::Success)
}

/// Short label for a memory kind, for the boot map dump.
const fn kind_name(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Usable => "usable",
        MemoryKind::BootloaderReclaimable => "boot-reclaimable",
        MemoryKind::KernelAndModules => "kernel",
        MemoryKind::Framebuffer => "framebuffer",
        MemoryKind::AcpiReclaimable => "acpi-reclaimable",
        MemoryKind::AcpiNvs => "acpi-nvs",
        MemoryKind::Reserved => "reserved",
        MemoryKind::Bad => "bad",
    }
}

const EMPTY_REGION: MemoryRegion = MemoryRegion {
    base: PhysAddr::new(0),
    len: 0,
    kind: MemoryKind::Reserved,
};

/// Reads the firmware's device tree and returns the sorted, non-overlapping
/// physical memory map [`BootInfo`] requires.
///
/// Four sources contribute, and they overlap by nature: the tree's RAM banks
/// cover everything, while the kernel image, the device tree blob itself, and
/// the firmware's own reservations sit inside them. On this machine that last
/// source is not a formality — OpenSBI is resident in the first 2 MiB of RAM
/// and stays there, so a map that missed its reservation would hand the frame
/// allocator the firmware the kernel is still calling into. They are gathered
/// unresolved and handed to [`normalize_memory_map`], which settles the
/// overlaps by precedence.
fn boot_memory_map(dtb: u64, storage: &mut [MemoryRegion]) -> Result<&[MemoryRegion], FdtError> {
    // The blob's own length lives inside it, so the header is read first and
    // the rest only once its extent is known.
    //
    // SAFETY: `dtb` is the firmware handoff address. The SBI boot convention
    // guarantees it points at a device tree blob in memory the kernel owns,
    // and with translation off every physical address is readable. Nothing is
    // trusted about the *contents*: `total_size` validates the magic and
    // rejects an implausible length before the larger slice is formed, and
    // the reader bounds-checks every access inside it.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header)?;
    // SAFETY: as above, now bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };

    let tree = DeviceTree::parse(blob)?;

    let mut gathered = [EMPTY_REGION; MAX_MEMORY_REGIONS];
    let mut count = tree.memory_regions(&mut gathered)?;
    count += tree.reserved_regions(&mut gathered[count..])?;

    for region in [
        // The image the firmware just loaded us from. It is linked at its
        // physical address, so the symbols are the physical extent.
        MemoryRegion {
            base: PhysAddr::new(&raw const __kernel_start as u64),
            len: &raw const __kernel_end as u64 - &raw const __kernel_start as u64,
            kind: MemoryKind::KernelAndModules,
        },
        // The device tree itself, reclaimable once discovery has consumed
        // it — which has not happened yet, so it stays reserved for now.
        MemoryRegion {
            base: PhysAddr::new(dtb),
            len: tree.len() as u64,
            kind: MemoryKind::BootloaderReclaimable,
        },
    ] {
        *gathered.get_mut(count).ok_or(FdtError::TooManyRegions)? = region;
        count += 1;
    }

    let mut edges = [0u64; MAX_MEMORY_REGIONS * 2];
    let filled = normalize_memory_map(&gathered[..count], &mut edges, storage)
        .map_err(|_| FdtError::TooManyRegions)?;
    Ok(&storage[..filled])
}

static OBSERVED_TICKS: AtomicU64 = AtomicU64::new(0);

fn on_tick() {
    OBSERVED_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Starts the tick, waits for interrupts to actually arrive, and stops it.
///
/// Programming a timer proves nothing on its own: the interrupt has to make
/// it past `sie`, past `sstatus.SIE`, through the trap vector and the cause
/// decode before the hook runs. This waits on the hook's own count, so only
/// end-to-end delivery satisfies it.
fn timer_check() -> Result<u64, u32> {
    use tessera_karch::{InterruptControl, TimerControl};

    tessera_karch_riscv64::set_tick_hook(on_tick);
    SupervisorTimer::start_periodic(TICK_HZ);
    Cpu::enable();

    // Bounded wait: spin on the counter rather than trusting the timer, so a
    // controller that never delivers fails the check instead of hanging the
    // boot. The bound is counter ticks, read from the same counter the timer
    // compares against, so it is a real time limit and not a spin count.
    const WANTED: u64 = 3;
    let deadline = tessera_karch_riscv64::read_counter() + tessera_karch_riscv64::TIMEBASE_HZ * 2;
    while OBSERVED_TICKS.load(Ordering::Relaxed) < WANTED {
        if tessera_karch_riscv64::read_counter() > deadline {
            Cpu::disable();
            tessera_karch_riscv64::stop_timer();
            return Err(1);
        }
        core::hint::spin_loop();
    }

    Cpu::disable();
    tessera_karch_riscv64::stop_timer();

    // The architecture's own tick count and the hook's must agree; a mismatch
    // means ticks were delivered that the hook never saw.
    let counted = SupervisorTimer::ticks();
    let observed = OBSERVED_TICKS.load(Ordering::Relaxed);
    if counted != observed {
        return Err(2);
    }
    if tessera_karch_riscv64::unexpected_irqs() != 0 {
        return Err(3);
    }
    Ok(observed)
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
