// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tessera kernel boot glue for RISC-V 32: the only RISC-V crate that knows
//! how the machine was entered. Normalizes the firmware handoff into
//! `tessera-karch` types, brings up the early console, and hands control to
//! the kernel core.
//!
//! Entry contract. QEMU's `-kernel` loads this ELF and starts the machine in
//! **M-mode** running OpenSBI, which initializes the platform and then drops
//! to **S-mode** at the image's entry point with the hart id in `a0` and the
//! device-tree blob address in `a1`. Translation is off — `satp` is in Bare
//! mode — so the kernel runs at its physical link address from the first
//! instruction. That address is **0x8040_0000**, not the 64-bit machine's
//! 0x8020_0000: QEMU rounds a 32-bit kernel's start up to 4 MiB, which is
//! also Sv32's superpage size.
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
use core::sync::atomic::Ordering;
use tessera_devicetree::{DeviceTree, FdtError, HEADER_LEN};
use tessera_karch::atomic::AtomicU64;
use tessera_karch::{
    BootInfo, ExitCode, FRAME_SIZE, MemoryKind, MemoryRegion, PageFlags, PhysAddr, PlatformExit,
    VirtAddr, normalize_memory_map,
};
use tessera_karch_riscv32::{
    Context, ContextSwitch, Cpu, DIRECT_MAP_BASE, EXCEPTION_ECALL_FROM_USER, KernelSection,
    Ns16550a, SupervisorTimer, TestFinisherExit, TrapFrame, build_kernel_space, exception_name,
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

/// What a U-mode test blob does to the word it is handed, at this port's
/// register width — which is why it is not shared: the rotation is over a
/// u32, and the two widths are different functions with one name.
fn user_transform(value: u32) -> u32 {
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
            virt_start: &raw const __text_start as usize as u64,
            virt_end: &raw const __text_end as usize as u64,
            flags: PageFlags::rx().global(),
        },
        KernelSection {
            virt_start: &raw const __rodata_start as usize as u64,
            virt_end: &raw const __rodata_end as usize as u64,
            flags: PageFlags::ro().global(),
        },
        KernelSection {
            virt_start: &raw const __data_start as usize as u64,
            virt_end: &raw const __data_end as usize as u64,
            flags: PageFlags::rw().global(),
        },
    ]
}

/// Physical range the `virt` machine puts its devices in: the test finisher at
/// 0x0010_0000, the real-time clock at 0x0010_1000, the CLINT at 0x0200_0000,
/// the PLIC at 0x0c00_0000, the UART at 0x1000_0000, and the virtio-mmio
/// transports above it.
///
/// It used to be *everything* below RAM — a flat 2 GiB. That was harmless
/// while the range was identity-mapped and nothing else claimed the space, but
/// it cannot survive the move into the kernel half: 2 GiB placed at a
/// kernel-half base runs off the end of a 32-bit address space. Naming what
/// the machine actually has is both smaller and more honest; the PCIe ECAM
/// window at 0x3000_0000 is deliberately outside it, because nothing drives
/// PCIe on this port and mapping a window no one uses is not a service.
const DEVICE_RANGE: (u64, u64) = (0, 0x1100_0000);

/// Where those registers are reached in the kernel half.
///
/// The 64-bit port needed a whole relocation to get a higher half (D97); this
/// one needs only this constant. RAM begins at 2 GiB on this machine, which is
/// exactly [`USER_ADDRESS_MAX`](tessera_karch::AddressSpaceOps::USER_ADDRESS_MAX),
/// so the kernel image and the direct map are already above the boundary and
/// the direct map's offset is zero. The devices were the only thing left in
/// the user half, and this is where they go instead: clear of RAM
/// (0x8000_0000 upward on the reference machine) and clear of the top of the
/// address space.
const DEVICE_WINDOW_BASE: u64 = 0xc000_0000;

/// Scratch virtual range the conformance battery maps and unmaps. Above the
/// top of RAM on this machine and therefore mapped by nothing, but inside the
/// same 1 GiB slot RAM occupies, so the battery exercises real three-level
/// walks rather than landing in an empty root slot.
const CONFORMANCE_SCRATCH: u64 = 0x9000_0000;

/// Tick rate the timer check programs.
const TICK_HZ: u32 = 100;

/// RISC-V 32 machine code for `extern "C" fn() -> u64` returning
/// [`tessera_arch_conformance::SENTINEL`], for the instruction-cache case:
///
/// ```text
///   lui  a0, 0x5e17c
///   addi a0, a0, 0xde
///   li   a1, 0
///   ret
/// ```
///
/// The `li a1, 0` is the word-size difference made concrete. A `u64` return
/// value does not fit one register here, so the RISC-V 32 ABI splits it across
/// the `a0`/`a1` pair — low half then high — and a callee owes the caller
/// both. The 64-bit port's three instructions become four.
///
/// Measured, because the tempting claim is stronger than the truth: the
/// battery **does** observe the high half — returning a non-zero `a1` fails
/// the case — but simply *omitting* this instruction still passes, because
/// `a1` happens to hold zero at that call site under QEMU today. The
/// instruction is here because the ABI requires it, not because this test
/// would catch its absence, and that distinction is worth keeping visible: a
/// sentinel with a non-zero high half would be a stronger check, and is the
/// obvious improvement if this case ever needs to earn its keep on hardware.
///
/// Written as bytes rather than assembled from a symbol on purpose — the case
/// needs instructions that were *stored as data* into a fresh frame.
const SENTINEL_CODE: &[u8] = &[
    0x37, 0xc5, 0x17, 0x5e, // lui  a0, 0x5e17c
    0x13, 0x05, 0xe5, 0x0d, // addi a0, a0, 0xde
    0x93, 0x05, 0x00, 0x00, // li   a1, 0
    0x67, 0x80, 0x00, 0x00, // ret
];

/// Backing storage for the global console. A `static mut` is the honest
/// representation of "one mutable device object created before concurrency
/// exists"; the single `&mut` is taken exactly once, in `kernel_main`.
static mut UART: Ns16550a = Ns16550a::virt();

/// The same UART, at the address it has *after* the tables are activated.
///
/// Two statics rather than one mutable base, because the console is genuinely
/// two different things at two moments: before the switch there is no
/// translation and the only address that works is the physical one; after it,
/// that address is in the user half and deliberately unmapped. A second sink
/// installed at the switch says exactly that, and needs no second `&mut` to
/// an object the console already owns.
static mut UART_WINDOW: Ns16550a = Ns16550a::at(DEVICE_WINDOW_BASE as usize + Ns16550a::VIRT_BASE);

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
    sw      zero, 0(t0)
    addi    t0, t0, 4
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
/// `dtb` is `usize`, not `u64`, and that is load-bearing rather than tidy.
/// The firmware hands the blob address over in a **single register**; an
/// `extern "C"` parameter declared `u64` is passed in the `a0`/`a1` *pair* on
/// this ABI, so the kernel would read a real low half beside whatever `a1`
/// happened to hold and carry a corrupt address into the device-tree reader.
/// The 64-bit port can spell it `u64` because there the two are the same
/// thing; here they are not.
///
/// # Safety
///
/// Called exactly once, by `_start`, on the boot hart, with a valid stack and
/// zeroed `.bss`. `dtb` is whatever the firmware supplied and is not trusted
/// beyond being a number: the reader validates the blob's magic and
/// bounds-checks every access inside it.
#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb: usize) -> ! {
    // SAFETY: `kernel_main` runs exactly once, single-threaded, before any
    // other code; this is the only reference ever taken to UART.
    let uart = unsafe { &mut *&raw mut UART };
    uart.init();
    let dropped = kcore::console::init_global(uart);

    // Timestamp source for structured events, and the per-boot correlation
    // epoch. Both arrive as porting-layer readings rather than by any
    // architecture's name for its counter.
    let unstamped = kcore::event::set_clock(<Cpu as tessera_karch::CpuOps>::counter_serialized);
    if unstamped > 0 {
        kprintln!("event: {unstamped} record(s) emitted before the clock was installed");
    }
    kcore::trace::set_epoch(<Cpu as tessera_karch::CpuOps>::counter_serialized());
    kcore::trace::set_current_correlation(kcore::trace::mint());

    kprintln!("Tessera {VERSION} (Stage 0 skeleton, RISC-V 32)");
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
    // stack and console, and `satp` goes from Bare to Sv32 exactly once.
    let (kernel_space, image_pages) = match build_kernel_space(
        &mut frames,
        DIRECT_MAP_BASE,
        &kernel_sections(),
        (ram_start, ram_end),
        DEVICE_RANGE,
        DEVICE_WINDOW_BASE,
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

    // SAFETY: the space maps this code and this stack at the addresses they
    // already occupy — the image at its per-section permissions and RAM direct
    // mapped, both above 2 GiB — so the instruction after the switch still
    // fetches. What it does *not* map is the console at its physical address,
    // which is why the next two statements come before the next `kprintln!`.
    unsafe {
        use tessera_karch::AddressSpaceOps;
        kernel_space.activate()
    };
    // The devices moved with the switch. Both halves of that have to be told:
    // the console, which holds its own base, and the fixed-address platform
    // devices this crate does not construct — the PLIC and the test finisher,
    // which name themselves physically and are reached through the window.
    // Done before anything can print or panic, because the panic path exits
    // through the finisher.
    // SAFETY: `DEVICE_WINDOW_BASE` is the base of the mapping just activated
    // over the whole device range, read-write for the life of the kernel.
    unsafe { tessera_karch_riscv32::set_device_access_base(DEVICE_WINDOW_BASE as usize) };
    // SAFETY: single-threaded boot; this is the only reference ever taken to
    // `UART_WINDOW`, and it replaces a sink that named an address the tables
    // above no longer map.
    let dropped_across_switch = kcore::console::init_global(unsafe { &mut *&raw mut UART_WINDOW });

    kprintln!(
        "paging: Sv32 on, {} MiB RAM direct-mapped at {:#018x}, W^X kernel image ({image_pages} pages)",
        (ram_end - ram_start) / (1024 * 1024),
        DIRECT_MAP_BASE + ram_start
    );
    // What the move was *for*, asserted rather than announced. The devices
    // were the only thing in the user half, so their physical addresses must
    // now translate to nothing while the window resolves — both directions,
    // because a device that had simply become unreachable would pass a
    // one-sided check just as well as one that moved.
    {
        use tessera_karch::AddressSpaceOps;
        let (device_base, device_len) = DEVICE_RANGE;
        let probes = [
            Ns16550a::VIRT_BASE as u64,
            device_base,
            device_base + device_len - FRAME_SIZE,
        ];
        let moved = probes.iter().all(|&phys| {
            kernel_space.translate(VirtAddr::new(phys)).is_none()
                && kernel_space
                    .translate(VirtAddr::new(DEVICE_WINDOW_BASE + phys))
                    .is_some()
        });
        if !moved {
            kprintln!("paging: FATAL: the device range is still in the user half");
            TestFinisherExit::exit(ExitCode::Failure)
        }
        kprintln!(
            "paging: user half empty below {:#010x} — devices reached at {DEVICE_WINDOW_BASE:#010x}",
            <tessera_karch_riscv32::KernelAddressSpace as AddressSpaceOps>::USER_ADDRESS_MAX
        );
    }

    if dropped_across_switch > 0 {
        // Nothing should be dropped here: the two `init_global` calls are
        // adjacent to the switch with no print between them. Saying so beats
        // assuming it.
        kprintln!("early console: {dropped_across_switch} write(s) dropped across the switch");
    }
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
    unsafe { tessera_karch_riscv32::init_vectors() };
    tessera_karch_riscv32::set_trap_handler(fatal_trap);
    // SAFETY: the PLIC is identity-mapped device memory (DEVICE_RANGE), this
    // is the boot hart, and interrupts are still masked.
    unsafe { tessera_karch_riscv32::init_plic() };

    // The verified image store, before anything that might want to read from
    // it. Nothing here needs a device, a bus or a process — the container is in
    // this kernel's own image — so it runs first among the checks, which is
    // also the order `docs/security/01` ("Boot Security") describes: what the
    // system will trust is established before it is used.
    //
    // **On this port it is also the first time the format is read on a 32-bit
    // target.** `//kernel/width-conformance` compiles the reader for one; this
    // runs it, over a container whose every offset and length is a `u64`.
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

    match umode_check(&mut kernel_space, &mut frames) {
        Ok(code) => match process_space_check(&kernel_space, &mut frames, code) {
            Ok(()) => {}
            Err(which) => {
                kprintln!("process: FATAL: check {which} failed");
                TestFinisherExit::exit(ExitCode::Failure)
            }
        },
        Err(which) => {
            kprintln!("umode: FATAL: check {which} failed");
            TestFinisherExit::exit(ExitCode::Failure)
        }
    }

    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    kcore::verdict::claims(&["boot.alive"]);
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
fn boot_memory_map(dtb: usize, storage: &mut [MemoryRegion]) -> Result<&[MemoryRegion], FdtError> {
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
            base: PhysAddr::new(&raw const __kernel_start as usize as u64),
            len: (&raw const __kernel_end as usize - &raw const __kernel_start as usize) as u64,
            kind: MemoryKind::KernelAndModules,
        },
        // The device tree itself, reclaimable once discovery has consumed
        // it — which has not happened yet, so it stays reserved for now.
        MemoryRegion {
            base: PhysAddr::new(dtb as u64),
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

    tessera_karch_riscv32::set_tick_hook(on_tick);
    SupervisorTimer::start_periodic(TICK_HZ);
    Cpu::enable();

    // Bounded wait: spin on the counter rather than trusting the timer, so a
    // controller that never delivers fails the check instead of hanging the
    // boot. The bound is counter ticks, read from the same counter the timer
    // compares against, so it is a real time limit and not a spin count.
    const WANTED: u64 = 3;
    let deadline = tessera_karch_riscv32::read_counter() + tessera_karch_riscv32::TIMEBASE_HZ * 2;
    while OBSERVED_TICKS.load(Ordering::Relaxed) < WANTED {
        if tessera_karch_riscv32::read_counter() > deadline {
            Cpu::disable();
            tessera_karch_riscv32::stop_timer();
            return Err(1);
        }
        core::hint::spin_loop();
    }

    Cpu::disable();
    tessera_karch_riscv32::stop_timer();

    // The architecture's own tick count and the hook's must agree; a mismatch
    // means ticks were delivered that the hook never saw.
    let counted = SupervisorTimer::ticks();
    let observed = OBSERVED_TICKS.load(Ordering::Relaxed);
    if counted != observed {
        return Err(2);
    }
    if tessera_karch_riscv32::unexpected_irqs() != 0 {
        return Err(3);
    }
    Ok(observed)
}

/// Reports a fatal exception and ends the run. Without this a fault would
/// return through `sret` into the instruction that caused it and loop
/// forever, which is a hang rather than a diagnosis.
fn fatal_trap(frame: &tessera_karch_riscv32::TrapFrame) -> ! {
    kprintln!(
        "TRAP: {} (scause={:#018x}{})",
        tessera_karch_riscv32::exception_name(frame.scause),
        frame.scause,
        if tessera_karch_riscv32::is_write_fault(frame.scause) {
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
// U-mode: the port's first unprivileged execution
// ---------------------------------------------------------------------------

/// Where the user program is mapped. Low in the user half, which D106 emptied
/// — the whole of `[0, 2 GiB)` is now unclaimed, and these are chosen only to
/// be obviously not kernel addresses.
const USER_CODE_VA: u64 = 0x1000_0000;
/// The user stack, deliberately not adjacent to the code page: a stack that
/// overflowed into executable memory would be a mapping bug this layout cannot
/// express.
const USER_STACK_VA: u64 = 0x2000_0000;
/// A data page every process maps at the *same* address and fills differently.
/// Identical addresses holding different bytes is what per-process translation
/// means; anything else would be reachable by agreeing on a layout.
const USER_DATA_VA: u64 = 0x3000_0000;
/// A page only one process maps at all.
const USER_PRIVATE_VA: u64 = 0x4000_0000;

/// The value the user program hands the kernel, and the rotation handed back.
/// Distinctive enough that finding it in a register is not a coincidence, and
/// asymmetric so a round trip proves direction.
const USER_MAGIC: u32 = 0x5e17_c0de;

/// The two calls the user program can make. Not an ABI — this port is not yet
/// on kcore's syscall substrate — just the smallest pair that proves a syscall
/// carries a value in and out, and that the second one is reached.
const SYS_LOG: u32 = 0;
const SYS_EXIT: u32 = 1;

/// Selectors the program's `arg` chooses between.
const CHECK_SYSCALL: usize = 0;
const CHECK_WRITE_TO_CODE: usize = 1;
const CHECK_READ_KERNEL: usize = 2;
const CHECK_READ_DATA: usize = 3;
const CHECK_READ_PRIVATE: usize = 4;

/// Architectural causes the containment checks expect.
const EXCEPTION_LOAD_PAGE_FAULT: u32 = 13;
const EXCEPTION_STORE_PAGE_FAULT: u32 = 15;

/// Size of the user thread's kernel stack.
const USER_KSTACK_BYTES: usize = 8192;

/// The kernel stack the user thread's traps land on. The checks run one at a
/// time and each abandons its predecessor, so one stack serves all three.
#[repr(align(16))]
struct UserKernelStack([u8; USER_KSTACK_BYTES]);
static mut USER_KSTACK: UserKernelStack = UserKernelStack([0; USER_KSTACK_BYTES]);

/// Where the kernel resumes when a user thread stops being one — by exiting,
/// or by faulting. The thread is abandoned mid-trap, on its own kernel stack,
/// which is exactly what containment means here.
static mut KERNEL_RETURN: Context = Context::zeroed();
/// Scratch the abandoned thread's state is saved into and never read from.
static mut ABANDONED: Context = Context::zeroed();

/// What the last user thread did. Read only after control is back in the
/// kernel, so `Relaxed` carries no ordering weight it has not earned.
static USER_EXIT_VALUE: AtomicU64 = AtomicU64::new(0);
static USER_TRAP_CAUSE: AtomicU64 = AtomicU64::new(0);
static USER_TRAP_ADDRESS: AtomicU64 = AtomicU64::new(0);
static USER_SYSCALLS: AtomicU64 = AtomicU64::new(0);

// The user program. Three behaviours selected by `a0`, all position-
// independent: `auipc` reads the *runtime* PC, which is a user virtual
// address, so the blob never needs to know where it was mapped and never
// refers to a kernel-linked symbol.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl user_blob_start
user_blob_start:
    li      t0, 1
    beq     a0, t0, 10f
    li      t0, 2
    beq     a0, t0, 20f
    li      t0, 3
    beq     a0, t0, 30f
    li      t0, 4
    beq     a0, t0, 40f

    // Syscall check: hand the kernel a value, get one back, park it on the
    // user stack, and hand it to a second syscall. Two calls, because one
    // proves entry and only the second proves the kernel put U-mode back where
    // it found it. The stack round trip makes the stack mapping and the `sp`
    // the trampoline installed load-bearing, and the clobber in between means
    // a stale register cannot stand in for either.
    li      a7, 0
    li      a0, 0x5e17c0de
    ecall
    addi    sp, sp, -16
    sw      a0, 0(sp)
    li      a0, 0
    lw      a0, 0(sp)
    addi    sp, sp, 16
    li      a7, 1
    ecall
    unimp

10: // W^X: store into the page this instruction was fetched from.
    auipc   t0, 0
    sw      zero, 0(t0)
    unimp

20: // The privilege boundary: read the base of the kernel's half.
    li      t0, 0x80000000
    lw      t1, 0(t0)
    unimp

30: // Read this process's own data page and exit with what was there. The
    // address is a constant, identical in every process — which is the point.
    li      t0, 0x30000000
    lw      a0, 0(t0)
    li      a7, 1
    ecall
    unimp

40: // Read the page only one of the processes has.
    li      t0, 0x40000000
    lw      a0, 0(t0)
    li      a7, 1
    ecall
    unimp
.globl user_blob_end
user_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined by the `global_asm!`
// block above; the declaration itself performs no operation.
unsafe extern "C" {
    static user_blob_start: u8;
    static user_blob_end: u8;
}

/// Handles every exception taken from U-mode: two syscalls, and everything
/// else as a contained fault.
fn user_trap(frame: &mut TrapFrame) {
    if frame.scause == EXCEPTION_ECALL_FROM_USER {
        USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
        match frame.a7 {
            SYS_LOG => {
                frame.a0 = user_transform(frame.a0);
                // `ecall` leaves `sepc` on the instruction itself. Resuming
                // without advancing it would re-execute the syscall forever —
                // the architecture leaves this to the handler deliberately, so
                // that one can restart an instruction when it wants to.
                frame.sepc += 4;
                return;
            }
            SYS_EXIT => {
                USER_EXIT_VALUE.store(u64::from(frame.a0), Ordering::Relaxed);
                leave_user()
            }
            _ => {
                USER_TRAP_CAUSE.store(u64::MAX, Ordering::Relaxed);
                leave_user()
            }
        }
    }

    USER_TRAP_CAUSE.store(u64::from(frame.scause), Ordering::Relaxed);
    USER_TRAP_ADDRESS.store(u64::from(frame.stval), Ordering::Relaxed);
    leave_user()
}

/// Abandons the running user thread and resumes the kernel.
fn leave_user() -> ! {
    use tessera_karch::ContextOps;
    // SAFETY: single-threaded boot. `KERNEL_RETURN` was written by the
    // `switch` in `run_user` that started this thread, so it names a live
    // kernel stack frame; `ABANDONED` is write-only scratch. This switch does
    // not return, because nothing ever switches back into `ABANDONED`.
    unsafe { ContextSwitch::switch(&raw mut ABANDONED, &raw const KERNEL_RETURN) };
    // Not reachable: the switch above never comes back.
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// Runs the user program once, with `arg` selecting its behaviour, and returns
/// when it has stopped being a user program.
///
/// # Safety
///
/// The user code and stack must be mapped user-accessible in the active
/// address space, and no other user thread may be running.
unsafe fn run_user(arg: usize) {
    use tessera_karch::{ContextOps, UserContextOps};
    USER_EXIT_VALUE.store(0, Ordering::Relaxed);
    USER_TRAP_CAUSE.store(0, Ordering::Relaxed);
    USER_TRAP_ADDRESS.store(0, Ordering::Relaxed);

    let kstack_top =
        (&raw const USER_KSTACK) as u64 + core::mem::size_of::<UserKernelStack>() as u64;
    // SAFETY: `USER_KSTACK` is a live, 16-byte-aligned static owned by this
    // path alone, and the caller guarantees the user mappings. `init_user`
    // writes only the initial frame below its top.
    let user = unsafe {
        ContextSwitch::init_user(
            VirtAddr::new(kstack_top),
            VirtAddr::new(USER_CODE_VA),
            VirtAddr::new(USER_STACK_VA + FRAME_SIZE),
            arg,
        )
    };
    // SAFETY: `KERNEL_RETURN` is this boot path's own continuation and `user`
    // was just built by `init_user`. Control comes back here when the user
    // thread exits or faults.
    unsafe { ContextSwitch::switch(&raw mut KERNEL_RETURN, &user) };
}

/// The port's first ring-3 execution, asserted rather than announced.
///
/// Three properties, each depending on the one before it: that U-mode can be
/// entered and returned from at all, that the page table's `U` bit means what
/// it says in the executable direction, and that it means what it says in the
/// kernel direction. A port that could enter U-mode but not contain it would
/// pass the first alone.
fn umode_check(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
) -> Result<tessera_karch::PhysFrame, u32> {
    // SAFETY: both are linker-provided bounds of the read-only blob above, and
    // the region between them is initialised, immutable and never freed.
    let blob = unsafe {
        core::slice::from_raw_parts(
            &raw const user_blob_start,
            (&raw const user_blob_end as usize) - (&raw const user_blob_start as usize),
        )
    };
    if blob.is_empty() || blob.len() as u64 > FRAME_SIZE {
        return Err(1);
    }

    let code = frames.alloc_frame().ok_or(2u32)?;
    space.zero_frame(code);
    space.write_bytes_to_frame(code, 0, blob);
    space
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 3u32)?;
    space.sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    let stack = frames.alloc_frame().ok_or(4u32)?;
    space.zero_frame(stack);
    space
        .map(
            VirtAddr::new(USER_STACK_VA),
            stack,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 5u32)?;

    // The kernel is about to follow user pointers only in the sense that the
    // program's own stack round trip happens in *its* address space — but the
    // permission is the kernel's to grant either way, and granting it here
    // keeps this port's posture identical to the other four.
    // SAFETY: nothing in this check dereferences a user pointer from the
    // kernel; the permission is set so that the syscall paths a later
    // milestone adds behave as they do on the 64-bit port.
    unsafe { tessera_karch_riscv32::allow_user_memory_access() };
    tessera_karch_riscv32::set_user_trap_hook(user_trap);

    // 1. Enter U-mode, make two syscalls, exit.
    // SAFETY: the code and stack pages are mapped user-accessible above, and
    // no other user thread exists.
    unsafe { run_user(CHECK_SYSCALL) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(6);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != u64::from(user_transform(USER_MAGIC)) {
        return Err(7);
    }
    if USER_SYSCALLS.load(Ordering::Relaxed) != 2 {
        return Err(8);
    }
    kprintln!(
        "umode: entered U-mode and returned — syscall round-tripped {:#x} as {:#x}",
        USER_MAGIC,
        user_transform(USER_MAGIC)
    );

    // 2. W^X at the unprivileged level: the code page is read-execute, so the
    //    program's store into it must fault rather than land.
    // SAFETY: as above.
    unsafe { run_user(CHECK_WRITE_TO_CODE) };
    let cause = USER_TRAP_CAUSE.load(Ordering::Relaxed);
    if cause != u64::from(EXCEPTION_STORE_PAGE_FAULT) {
        return Err(9);
    }
    // The program stores through `auipc`, so the faulting address is the
    // storing instruction's own — inside the code page, not its base.
    let fault = USER_TRAP_ADDRESS.load(Ordering::Relaxed);
    if fault & !(FRAME_SIZE - 1) != USER_CODE_VA {
        return Err(10);
    }
    kprintln!(
        "umode: W^X held — a store into the code page took a {} at {:#x}",
        exception_name(cause as u32),
        fault
    );

    // 3. The privilege boundary itself: every kernel page is mapped without
    //    `U`, so a user load from one must fault. This is the check D106's
    //    empty user half exists to make meaningful — the kernel is not merely
    //    elsewhere, it is unreachable.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_KERNEL) };
    let cause = USER_TRAP_CAUSE.load(Ordering::Relaxed);
    if cause != u64::from(EXCEPTION_LOAD_PAGE_FAULT) {
        return Err(11);
    }
    let boundary =
        <tessera_karch_riscv32::KernelAddressSpace as tessera_karch::AddressSpaceOps>::USER_ADDRESS_MAX;
    if USER_TRAP_ADDRESS.load(Ordering::Relaxed) != boundary {
        return Err(12);
    }
    kprintln!(
        "umode: kernel unreachable from U-mode — a load of {:#010x} took a {}",
        boundary,
        exception_name(cause as u32)
    );
    kcore::verdict::claims(&["umode.ok"]);

    Ok(code)
}

// ---------------------------------------------------------------------------
// Per-process address spaces
// ---------------------------------------------------------------------------

/// What each process finds at [`USER_DATA_VA`]. Two values, one address —
/// 32-bit here, because the program reads the word with `lw`.
const PROCESS_A_DATA: u32 = 0xa1a1_0001;
const PROCESS_B_DATA: u32 = 0xb2b2_0002;
/// What process A finds at [`USER_PRIVATE_VA`], which B does not map at all.
const PROCESS_A_PRIVATE: u32 = 0x0dd1_0003;

/// ASIDs. Non-zero and distinct, and both inside Sv32's **9-bit** field — a
/// smaller pool than Sv39's 16 bits for exactly the same job, which is a
/// difference this port has to respect rather than inherit.
const PROCESS_A_ASID: u16 = 1;
const PROCESS_B_ASID: u16 = 2;

/// Table frames the two spaces return at teardown, exactly.
///
/// Exact rather than a lower bound, for the reason D99 recorded: a teardown
/// that walked past the user half would free the *shared* kernel tables too,
/// and that is silent until something reuses one. Derivation: Sv32 has two
/// levels and each root entry covers 4 MiB, so a space needs its root plus one
/// leaf table per distinct 4 MiB region it maps. A maps four addresses in four
/// regions (1 + 4 = 5); B maps three (1 + 3 = 4).
const PROCESS_TEARDOWN_FRAMES: usize = 5 + 4;

/// Maps the user program and a fresh stack into `space`, sharing `code`.
fn map_user_image(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
    code: tessera_karch::PhysFrame,
    fail: u32,
) -> Result<(), u32> {
    space
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| fail)?;
    space.sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);
    let stack = frames.alloc_frame().ok_or(fail + 1)?;
    space.zero_frame(stack);
    space
        .map(
            VirtAddr::new(USER_STACK_VA),
            stack,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| fail + 1)
}

/// Two processes, each with its own Sv32 root, running the same program.
///
/// The claim is narrow and checkable: the same virtual address means different
/// memory in each, the kernel is reachable from both without being reachable
/// *by* either, and tearing one down leaves the other and the kernel intact.
///
/// `code` is the frame the program's instructions already live in. Both
/// processes map it, deliberately — sharing a frame is what makes the
/// isolation on show a property of the page tables rather than of the memory
/// happening to differ.
fn process_space_check(
    kernel_space: &tessera_karch_riscv32::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    code: tessera_karch::PhysFrame,
) -> Result<(), u32> {
    use tessera_karch::AddressSpaceOps;

    let mut process_a = kernel_space
        .new_user(frames, PROCESS_A_ASID)
        .map_err(|_| 1u32)?;
    map_user_image(&mut process_a, frames, code, 2)?;
    tessera_boot_checks::map_user_bytes(
        &mut process_a,
        frames,
        USER_DATA_VA,
        &PROCESS_A_DATA.to_le_bytes(),
        4,
    )?;
    tessera_boot_checks::map_user_bytes(
        &mut process_a,
        frames,
        USER_PRIVATE_VA,
        &PROCESS_A_PRIVATE.to_le_bytes(),
        5,
    )?;

    let mut process_b = kernel_space
        .new_user(frames, PROCESS_B_ASID)
        .map_err(|_| 6u32)?;
    map_user_image(&mut process_b, frames, code, 7)?;
    tessera_boot_checks::map_user_bytes(
        &mut process_b,
        frames,
        USER_DATA_VA,
        &PROCESS_B_DATA.to_le_bytes(),
        9,
    )?;

    // 1. A reads its own data page. Reaching this line at all is already the
    //    kernel-half check: the instruction after `activate` is kernel text,
    //    and the trap the program's `ecall` takes is kernel text too, so a
    //    space that had not adopted the kernel's half would never get here to
    //    fail a comparison.
    // SAFETY: `process_a` maps this kernel's text, stacks and device window by
    // construction (`new_user` copies them), so execution continues.
    unsafe { process_a.activate() };
    // SAFETY: the program and its stack are mapped user-accessible in the
    // now-active space, and no other user thread is running.
    unsafe { run_user(CHECK_READ_DATA) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(10);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != u64::from(PROCESS_A_DATA) {
        return Err(11);
    }

    // 2. B reads *the same address* and must find its own value. A stale
    //    translation, a shared table, or an ASID collision all show up here.
    // SAFETY: as above, for `process_b`.
    unsafe { process_b.activate() };
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_DATA) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(12);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != u64::from(PROCESS_B_DATA) {
        return Err(13);
    }
    kprintln!(
        "process: two Sv32 roots — {USER_DATA_VA:#010x} = {PROCESS_A_DATA:#010x}/asid {PROCESS_A_ASID}, {PROCESS_B_DATA:#010x}/asid {PROCESS_B_ASID}"
    );

    // 3. B has no mapping where A has one. Checked in both directions, because
    //    "B faults" alone would also be satisfied by an address neither maps.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_PRIVATE) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != u64::from(EXCEPTION_LOAD_PAGE_FAULT) {
        return Err(14);
    }
    if USER_TRAP_ADDRESS.load(Ordering::Relaxed) != USER_PRIVATE_VA {
        return Err(15);
    }
    // SAFETY: as above, back in `process_a`.
    unsafe { process_a.activate() };
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_PRIVATE) };
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != u64::from(PROCESS_A_PRIVATE) {
        return Err(16);
    }
    kprintln!(
        "process: {USER_PRIVATE_VA:#010x} is A's alone — B took a {} there, A read {PROCESS_A_PRIVATE:#010x}",
        exception_name(EXCEPTION_LOAD_PAGE_FAULT)
    );

    // 4. Teardown. Back to the kernel's own space first — freeing the tables
    //    of the space you are running in would be a different kind of demo.
    // SAFETY: the kernel space maps everything this path touches; it is the
    // space the boot path was running in before any process existed.
    unsafe { kernel_space.activate() };
    let before = frames.free_list_depth();
    process_a.free_tables(frames);
    process_b.free_tables(frames);
    let reclaimed = frames.free_list_depth() - before;
    if reclaimed != PROCESS_TEARDOWN_FRAMES {
        return Err(17);
    }
    // The kernel's own mappings are shared *by pointer* with both spaces just
    // torn down. If teardown had walked past the user half, this translation
    // would be gone — and so would the kernel.
    if kernel_space
        .translate(VirtAddr::new(
            DEVICE_WINDOW_BASE + Ns16550a::VIRT_BASE as u64,
        ))
        .is_none()
    {
        return Err(18);
    }
    kprintln!(
        "process: teardown reclaimed {reclaimed} table frames and left the shared kernel half intact"
    );

    Ok(())
}

/// The system image's verified store, where the build embedded one. Only the
/// Bazel build assembles it (`//store:system_store_image`); the cargo inner
/// loop builds without it and the check reports it absent, exactly as the
/// ring-3 images do on the ports that have them.
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
