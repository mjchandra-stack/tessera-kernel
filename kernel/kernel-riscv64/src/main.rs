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
    // where `CpuOps::cpu_id` reads it from — `mhartid` is an M-mode CSR and
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
/// # Safety
///
/// Called exactly once, by `_start`, on the boot hart, with a valid stack and
/// zeroed `.bss`. `dtb` is whatever the firmware supplied and is not trusted
/// beyond being a number: the reader validates the blob's magic and
/// bounds-checks every access inside it.
#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb: u64) -> ! {
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

    // The firmware handed over a *physical* address; everything is reached
    // through the direct map from here on.
    let dtb = dtb + DIRECT_MAP_BASE;
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
    // SAFETY: single-threaded boot; the tables were built for exactly this.
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
        "paging: Sv39 on, kernel in the upper half at {:#018x}, {} MiB RAM direct-mapped, W^X kernel image ({image_pages} pages)",
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

    // PCI enumeration, before any of the ring-3 checks: it is discovery, and
    // what it finds is what a later milestone binds by class.
    {
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
                        let (bar, len) = match f.first_bar() {
                            Some(bar) => bar,
                            None => (0, 0),
                        };
                        kprintln!(
                            "pcie: OK — walked ECAM and found {count} function(s); {:04x}:{:04x} at {:02x}:{:02x}.{} class {:#08x} took a {len:#x} BAR at {bar:#x}, placed by this kernel because the machine leaves BARs unassigned",
                            f.vendor,
                            f.device,
                            f.bdf.bus,
                            f.bdf.device,
                            f.bdf.function,
                            f.class_code
                        );

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
                                        DIRECT_MAP_BASE as usize
                                            + (bar + FAR_WINDOW_OFFSET) as usize,
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
                        match driver_rebind_check(
                            &kernel_space,
                            &mut frames,
                            bar,
                            bar_len,
                            Some(identity),
                        ) {
                            Ok((first, second)) if first == expected && second == expected => {
                                kprintln!(
                                    "pci-bind: OK — the manager classified a device it cannot read (class {:#04x} from the graph, not from a register) and bound it to two drivers in turn; each reported back {first:#x} — the vendor/device the kernel enumerated",
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

    match umode_check(&mut kernel_space, &mut frames) {
        Ok(code) => {
            match process_space_check(&kernel_space, &mut frames, code) {
                Ok(()) => match kcore_process_check(&kernel_space, &mut frames) {
                    Ok(logged) => {
                        kprintln!(
                            "kcore-umode: OK — a kcore Process/Thread ran in U-mode under its own Sv39 root, scheduled by kcore::Scheduler (log {logged:#x})"
                        );
                        match ipc_check(&kernel_space, &mut frames) {
                            Ok((request, reply, switches)) => {
                                kprintln!(
                                    "ipc: OK — two U-mode processes exchanged a message over a channel: server saw {request:#x}, client got {reply:#x} back ({switches} switches, via kcore::dispatch)"
                                );
                                let mut windows = [MmioDevice {
                                    base: 0,
                                    size: 0,
                                    intid: None,
                                    trigger: None,
                                };
                                    MAX_MMIO_DEVICES];
                                let found = virtio_mmio_windows(dtb, &mut windows);
                                match windows[..found]
                                    .iter()
                                    .find(|w| virtio_identity(w.base).0 == tessera_virtio::MAGIC)
                                {
                                    Some(window) => {
                                        match device_check(&kernel_space, &mut frames, window.base)
                                        {
                                            Ok((packed, dma_phys)) => {
                                                kprintln!(
                                                    "mmio: OK — ring-3 mapped virtio MMIO at {:#x} by capability, read magic {:#x} device-id {}",
                                                    window.base,
                                                    packed & 0xffff_ffff,
                                                    packed >> 32
                                                );
                                                kprintln!(
                                                    "dma: OK — ring-3 got a DMA page: its user VA {USER_DMA_VA:#x} is phys {dma_phys:#x}, sentinel verified through the direct map"
                                                );
                                                match grant_check(
                                                    &kernel_space,
                                                    &mut frames,
                                                    window.base,
                                                ) {
                                                    Ok((handle, packed)) => {
                                                        kprintln!(
                                                            "grant: OK — a device capability crossed a channel: the driver was told handle {handle}, read magic {:#x} through it, and the manager no longer holds it",
                                                            packed & 0xffff_ffff
                                                        );
                                                        match rtc_device(dtb) {
                                                            Some(rtc) => {
                                                                match irq_check(
                                                                    &kernel_space,
                                                                    &mut frames,
                                                                    rtc,
                                                                ) {
                                                                    Ok((line, delivered)) => {
                                                                        kprintln!(
                                                                            "irq: OK — a ring-3 driver parked on its device and was woken by it {delivered} times on line {line} (mask-on-deliver, re-armed by IrqComplete)"
                                                                        )
                                                                    }
                                                                    Err(which) => {
                                                                        kprintln!(
                                                                            "irq: FATAL: check {which} failed"
                                                                        );
                                                                        TestFinisherExit::exit(
                                                                            ExitCode::Failure,
                                                                        )
                                                                    }
                                                                }
                                                            }
                                                            None => kprintln!(
                                                                "irq: skipped — this machine has no real-time clock to interrupt with"
                                                            ),
                                                        }
                                                        // The block driver needs a
                                                        // *backed* transport, which
                                                        // only exists when a disk
                                                        // is attached.
                                                        match windows[..found].iter().find(|w| {
                                                            virtio_identity(w.base).1
                                                                == tessera_virtio::DEVICE_ID_BLOCK
                                                        }) {
                                                            Some(blk) => {
                                                                match blk_driver_check(
                                                                    &kernel_space,
                                                                    &mut frames,
                                                                    *blk,
                                                                ) {
                                                                    Ok(magic) => kprintln!(
                                                                        "blk: OK — a compiled ring-3 driver read sector 0 of the disk at {:#x} and got {magic:#018x}, woken by the device",
                                                                        blk.base
                                                                    ),
                                                                    Err(which) => {
                                                                        kprintln!(
                                                                            "blk: FATAL: check {which} failed"
                                                                        );
                                                                        TestFinisherExit::exit(
                                                                            ExitCode::Failure,
                                                                        )
                                                                    }
                                                                }
                                                            }
                                                            None => kprintln!(
                                                                "blk: skipped — no virtio block device attached to this machine"
                                                            ),
                                                        }

                                                        // The framework: a device bound by class, and a driver
                                                        // replaced without the supervisor ever naming the device.
                                                        match windows[..found].iter().find(|w| {
                                                        virtio_identity(w.base).1 == tessera_virtio::DEVICE_ID_BLOCK
                                                    }) {
                                                        Some(blk) => {
                                                            match driver_rebind_check(&kernel_space, &mut frames, blk.base, blk.size, None) {
                                                                Ok((first, second)) => {
                                                                    kprintln!(
                                                                        "driver-rebind: OK — a driver crashed holding the transport (a real contained user fault, not a tidy exit), the kernel reclaimed what it held, and two more drivers bound the same transport by class, reporting {first:#x} then {second:#x}"
                                                                    );
                                                                    // The ladder's other end: a host that
                                                                    // never comes back is given up on
                                                                    // rather than respawned for ever. Run
                                                                    // before the records are read, so both
                                                                    // supervisors' records are in the same
                                                                    // drain.
                                                                    match driver_giveup_check(&kernel_space, &mut frames, blk.base, blk.size) {
                                                                        Ok(launches) => kprintln!(
                                                                            "driver-giveup: OK — a host that crashed every time was restarted exactly {launches} times, its budget, and then the supervisor stopped. A recovery policy has an end; without one it is a machine that respawns a broken driver until something else breaks"
                                                                        ),
                                                                        Err(which) => {
                                                                            kprintln!("driver-giveup: FATAL: check {which} failed");
                                                                            TestFinisherExit::exit(ExitCode::Failure)
                                                                        }
                                                                    }
                                                                    // Same runs, read back from the records
                                                                    // the kernel emitted while they happened.
                                                                    device_events_check(REBIND_DEVICE_OBJECT);
                                                                }
                                                                Err(which) => {
                                                                    kprintln!("driver-rebind: FATAL: check {which} failed");
                                                                    TestFinisherExit::exit(ExitCode::Failure)
                                                                }
                                                            }
                                                        }
                                                        None => {
                                                            kprintln!(
                                                                "driver-rebind: skipped — no virtio block device attached to this machine"
                                                            );
                                                            kprintln!(
                                                                "device-events: skipped — no virtio block device attached to this machine"
                                                            );
                                                        }
                                                    }
                                                    }
                                                    Err(which) => {
                                                        kprintln!(
                                                            "grant: FATAL: check {which} failed"
                                                        );
                                                        TestFinisherExit::exit(ExitCode::Failure)
                                                    }
                                                }
                                            }
                                            Err(which) => {
                                                kprintln!("mmio: FATAL: check {which} failed");
                                                TestFinisherExit::exit(ExitCode::Failure)
                                            }
                                        }
                                    }
                                    // Virtio is optional on a machine. Saying so
                                    // beats passing quietly (docs/lifecycle/04).
                                    None => kprintln!(
                                        "mmio: skipped — no virtio-mmio transport on this machine ({found} window(s) in the device tree)"
                                    ),
                                }
                            }
                            Err(which) => {
                                kprintln!("ipc: FATAL: check {which} failed");
                                TestFinisherExit::exit(ExitCode::Failure)
                            }
                        }
                    }
                    Err(which) => {
                        kprintln!("kcore-umode: FATAL: check {which} failed");
                        TestFinisherExit::exit(ExitCode::Failure)
                    }
                },
                Err(which) => {
                    kprintln!("process: FATAL: check {which} failed");
                    TestFinisherExit::exit(ExitCode::Failure)
                }
            }
        }
        Err(which) => {
            kprintln!("umode: FATAL: check {which} failed");
            TestFinisherExit::exit(ExitCode::Failure)
        }
    }

    // What a device's data path costs, on the second architecture to run the
    // driver framework. It needs no hardware: the topology is graph nodes, and
    // the whole of what is being tested — the manifest, the arbiter, the
    // accumulation and the budget — is the same source AArch64 compiles.
    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        kprintln!("relay: skipped (no embedded device-manager/blk-probe ELF; cargo inner-loop build)");
    } else {
        match relay_check(&kernel_space, &mut frames) {
            Ok((declared, undeclared)) => kprintln!(
                "relay: OK — what a device's data path costs is declared, accumulated over the graph's own parent edges, and checked before anything binds. One manifest entry, one budget of {}us, and two block devices differing only in depth: the near one bound at {} relay hop costing {}us on a path carrying {}Mbit/s, and the far one — same class, same entry, one hub further down at {}us — was refused BudgetExceeded, so a class cannot silently miss its budget behind a hub. The network device sits well inside its latency budget and was refused ThroughputTooLow, because a shorter path is no help when the remaining hop is the narrow one. And a hub the kernel cannot identify is not free: the manifest claims nothing about it, so the device behind it was refused PathUndeclared rather than bound as though it were direct-attached. Not one line of the mechanism is per-port (reports {:#x}, {:#x})",
                BLOCK_PATH_BUDGET_US,
                (declared >> 8) & 0xff,
                (declared >> 16) & 0xffff,
                (declared >> 48) & 0xffff,
                RELAY_NEAR_COST_US + RELAY_FAR_COST_US,
                declared,
                undeclared,
            ),
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
/// Capacity of the virtio-mmio window table. The `virt` machine presents a
/// fixed bank of transport slots whether or not anything is attached to them.
const MAX_MMIO_DEVICES: usize = 32;

/// Fills `out` with the machine's virtio-mmio register windows, returning how
/// many were found.
///
/// Best-effort: virtio is optional on a machine, so a tree this cannot read
/// yields zero windows rather than failing the boot — the caller states that
/// it found none instead of passing quietly.
///
/// Unlike the AArch64 twin this needs no "before the table switch" caveat: the
/// entry stub's direct map covers the blob for the kernel's whole life, so
/// `dtb` here is the same already-offset address the memory map was read from.
fn virtio_mmio_windows(dtb: u64, out: &mut [MmioDevice]) -> usize {
    // SAFETY: as `boot_memory_map` — `dtb` is the firmware handoff address
    // reached through the direct map; `total_size` validates the magic and
    // length before the larger slice is formed, and the reader bounds-checks
    // every access within it.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let Ok(total) = tessera_devicetree::total_size(header) else {
        return 0;
    };
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    let Ok(tree) = DeviceTree::parse(blob) else {
        return 0;
    };
    tree.virtio_mmio_regions(out).unwrap_or(0)
}

/// Reads a virtio-mmio transport's identity registers through the kernel's
/// direct map, returning `(magic, device_id)`.
///
/// The kernel reads them for two reasons: to refuse to hand out a capability
/// to a window that is not a virtio transport at all, and so that what a
/// ring-3 program later reports through its *own* mapping can be compared
/// against what the kernel saw through a completely different path.
fn virtio_identity(base: u64) -> (u32, u32) {
    let window = DIRECT_MAP_BASE as usize + base as usize;
    // SAFETY: `base` is a virtio-mmio window the device tree reported, which
    // lies inside `DEVICE_RANGE` and is therefore mapped read-write at
    // `DIRECT_MAP_BASE + base` by `build_kernel_space`. Both offsets are
    // defined 4-byte-aligned registers within the transport's 0x200 slot, and
    // reading either has no device-side effect.
    unsafe {
        (
            tessera_karch_riscv64::mmio_read32(window + tessera_virtio::reg::MAGIC_VALUE),
            tessera_karch_riscv64::mmio_read32(window + tessera_virtio::reg::DEVICE_ID),
        )
    }
}

/// The machine's PCI host bridge, if it has one.
fn pci_host(dtb: u64) -> Option<tessera_devicetree::PciHost> {
    // SAFETY: as `boot_memory_map` — `dtb` is the firmware handoff address
    // reached through the direct map, and `total_size` validates the blob's
    // magic and length before the larger slice is formed.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    DeviceTree::parse(blob).ok()?.pci_host().ok()?
}

/// Config space reached through the kernel's direct map.
///
/// The `unsafe` the `tessera-pci` crate forbids lives here, and it rests on
/// two facts checked before this is built: the ECAM window the device tree
/// reported lies inside `DEVICE_RANGE`, so it is mapped read-write at
/// `DIRECT_MAP_BASE + phys`; and the crate bounds every offset it passes
/// against the window length it was given, so an offset can never leave it.
struct EcamWindow {
    base: u64,
}

impl tessera_pci::ConfigSpace for EcamWindow {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `base + offset` is inside the ECAM window (the caller bounds
        // the offset) and therefore inside the direct-mapped device range. A
        // config-space read has no device-side effect.
        unsafe {
            tessera_karch_riscv64::mmio_read32(
                DIRECT_MAP_BASE as usize + self.base as usize + offset as usize,
            )
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read32`. Writes here program BARs and the command
        // register of a device the kernel is enumerating before anything else
        // can hold a capability to it.
        unsafe {
            tessera_karch_riscv64::mmio_write32(
                DIRECT_MAP_BASE as usize + self.base as usize + offset as usize,
                value,
            );
        }
    }
}

/// Functions one walk may report — the `virt` machine's bus is sparse, and a
/// bound that is too small is an error rather than a short answer.
const MAX_PCI_FUNCTIONS: usize = 16;

/// Enumerates the PCI bus and reports what it found.
///
/// **The kernel walks config space, and that is a departure worth naming.**
/// The framework's rule is that enumeration needs access, which is why the
/// device manager is a program rather than a table (D91). PCI is the case
/// where that cannot hold: config space is not per-device, so a capability to
/// it would be authority over every function behind the bridge at once, and
/// `MapDevice` grants a single page against a window of megabytes. The kernel
/// therefore reads it and normalizes what it finds into the resource graph —
/// which is what `docs/architecture/02` already says the device manager
/// How far into a device's window the ring-3 driver reads to show it was
/// granted the whole thing. Must match `FAR_OFFSET` in `userspace/blk-probe`.
const FAR_WINDOW_OFFSET: u64 = 0x2000;

/// The BAR a virtio-pci function keeps its configuration structures in, and
/// its extent.
///
/// **Not `first_bar`.** That is the lowest-indexed assigned BAR, which on a
/// virtio-pci function is the MSI-X table; the structures a driver needs live
/// in whichever BAR the device's own vendor capabilities name. Granting a
/// driver the first one hands it the wrong region however completely it is
/// mapped. `None` for a function that publishes no virtio capabilities, whose
/// caller then falls back to the first BAR.
fn virtio_pci_bar(dtb: u64, function: &tessera_pci::Function) -> Option<(u64, u64)> {
    let host = pci_host(dtb)?;
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let cfg = EcamWindow {
        base: host.ecam_base,
    };
    let mut at = None;
    while let Ok(Some(offset)) =
        tessera_pci::find_capability_from(&bridge, &cfg, function.bdf, tessera_pci::CAP_VENDOR, at)
    {
        at = Some(offset);
        let word = |i: u16| bridge.read(&cfg, function.bdf, offset + i * 4).unwrap_or(0);
        let cap = tessera_virtio::pci::decode_cap([word(0), word(1), word(2), word(3)]);
        if cap.cfg_type != tessera_virtio::pci::cfg_type::COMMON {
            continue;
        }
        let (base, len) = function.bars.get(cap.bar as usize).copied().flatten()?;
        // The device's own numbers, checked before they are trusted.
        if u64::from(cap.offset) + u64::from(cap.length) > len {
            return None;
        }
        return Some((base, len));
    }
    None
}

/// consumes ("It receives facts from ... PCIe enumeration").
///
/// Returns the functions found, or `None` when the machine has no bridge.
fn pcie_enumerate(
    dtb: u64,
    out: &mut [tessera_pci::Function],
) -> Option<Result<usize, tessera_pci::Error>> {
    let host = pci_host(dtb)?;
    // The window must be inside the range the kernel direct-maps as device
    // memory, or `EcamWindow`'s safety argument does not hold. Refusing beats
    // reading whatever is mapped there instead.
    if host.ecam_base < DEVICE_RANGE.0
        || host
            .ecam_base
            .saturating_add(host.ecam_len)
            .saturating_sub(1)
            >= DEVICE_RANGE.1
    {
        return Some(Err(tessera_pci::Error::OutsideEcam));
    }
    let memory = host.memory?;
    let window = tessera_pci::Window {
        cpu_base: memory.cpu_base,
        bus_base: memory.bus_base,
        len: memory.len,
        is_32bit: true,
    };
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    Some(tessera_pci::enumerate(&bridge, &mut config, window, out))
}

/// The machine's real-time clock, if it has one.
fn rtc_device(dtb: u64) -> Option<tessera_devicetree::MmioDevice> {
    // SAFETY: as `boot_memory_map` — `dtb` is the firmware handoff address
    // reached through the direct map, and `total_size` validates the blob's
    // magic and length before the larger slice is formed.
    let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(dtb as *const u8, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(RTC_COMPATIBLE)
        .ok()
        .flatten()
}

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
        // The image the firmware loaded. Its symbols are **virtual** now that
        // the kernel is linked in the upper half, and a memory map describes
        // physical memory — so each is converted back. Recording a virtual
        // address here hands the frame allocator a region that is not memory,
        // which is how this was caught.
        MemoryRegion {
            base: PhysAddr::new(&raw const __kernel_start as u64 - DIRECT_MAP_BASE),
            len: &raw const __kernel_end as u64 - &raw const __kernel_start as u64,
            kind: MemoryKind::KernelAndModules,
        },
        // The device tree itself, reclaimable once discovery has consumed
        // it — which has not happened yet, so it stays reserved for now.
        MemoryRegion {
            base: PhysAddr::new(dtb as u64 - DIRECT_MAP_BASE),
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
    <SupervisorTimer as tessera_karch::TimerControl>::start_periodic(TICK_HZ);
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

// ---------------------------------------------------------------------------
// U-mode: the port's first unprivileged execution
// ---------------------------------------------------------------------------

/// Where the user program is mapped. Anywhere in the low half would do — the
/// point of the higher-half split is that the whole of `[0, 2^38)` is now
/// unclaimed — so this is chosen only to be obviously not a kernel address.
const USER_CODE_VA: u64 = 0x1000_0000;
/// The user stack, one page, deliberately not adjacent to the code page: a
/// stack that overflowed into executable memory would be a mapping bug this
/// layout cannot express.
const USER_STACK_VA: u64 = 0x2000_0000;
/// A data page every process maps at the *same* address and fills differently.
/// Identical addresses holding different bytes is what per-process translation
/// means; anything else would be reachable by agreeing on a layout.
const USER_DATA_VA: u64 = 0x3000_0000;
/// A page only one process maps at all.
const USER_PRIVATE_VA: u64 = 0x4000_0000;

/// The value the user program hands the kernel, and the rotation the kernel
/// hands back. Distinctive enough that finding it in a register is not a
/// coincidence, and asymmetric so that a round trip proves direction.
const USER_MAGIC: u64 = 0x5e17_c0de;
fn user_transform(value: u64) -> u64 {
    value.rotate_left(8)
}

/// The two calls the user program can make. Not an ABI — this port is not yet
/// on kcore's syscall substrate — just the smallest pair that proves a syscall
/// carries a value in and a value out, and that the second one is reached.
const SYS_LOG: u64 = 0;
const SYS_EXIT: u64 = 1;

/// Selectors the program's `arg` chooses between.
const CHECK_SYSCALL: usize = 0;
const CHECK_WRITE_TO_CODE: usize = 1;
const CHECK_READ_KERNEL: usize = 2;
const CHECK_READ_DATA: usize = 3;
const CHECK_READ_PRIVATE: usize = 4;

/// Architectural causes the containment checks expect.
const EXCEPTION_LOAD_PAGE_FAULT: u64 = 13;
const EXCEPTION_STORE_PAGE_FAULT: u64 = 15;

/// Size of the user thread's kernel stack.
const USER_KSTACK_BYTES: usize = 8192;

/// The kernel stack the user thread's traps land on. One per user thread; the
/// checks run one at a time and each abandons its predecessor, so one stack
/// serves all three.
#[repr(align(16))]
struct UserKernelStack([u8; USER_KSTACK_BYTES]);
static mut USER_KSTACK: UserKernelStack = UserKernelStack([0; USER_KSTACK_BYTES]);

/// Where the kernel resumes when a user thread stops being one — by exiting,
/// or by faulting. The user thread is abandoned mid-trap, on its own kernel
/// stack, which is exactly what containment means here.
static mut KERNEL_RETURN: Context = Context::zeroed();
/// Scratch the abandoned thread's state is saved into and never read from.
/// `switch` has nowhere else to put it.
static mut ABANDONED: Context = Context::zeroed();

/// What the last user thread did. Read only after control is back in the
/// kernel, so `Relaxed` carries no ordering weight it needs to earn.
static USER_EXIT_VALUE: AtomicU64 = AtomicU64::new(0);
static USER_TRAP_CAUSE: AtomicU64 = AtomicU64::new(0);
static USER_TRAP_ADDRESS: AtomicU64 = AtomicU64::new(0);
static USER_SYSCALLS: AtomicU64 = AtomicU64::new(0);

// The user program. Three behaviours selected by `a0`, all of them
// position-independent — `auipc` reads the *runtime* PC, which is a user
// virtual address, so the blob never needs to know where it was mapped and
// never refers to a kernel-linked symbol.
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
    // proves entry and only the second proves the kernel put U-mode back
    // where it found it. The stack round trip is not decoration — it is what
    // makes the stack mapping and the `sp` the trampoline installed
    // load-bearing, and the clobber in between means a stale register cannot
    // stand in for either.
    li      a7, 0
    li      a0, 0x5e17c0de
    ecall
    addi    sp, sp, -16
    sd      a0, 0(sp)
    li      a0, 0
    ld      a0, 0(sp)
    addi    sp, sp, 16
    li      a7, 1
    ecall
    unimp

10: // W^X: store into the page this instruction was fetched from.
    auipc   t0, 0
    sd      zero, 0(t0)
    unimp

20: // The privilege boundary: read the base of the kernel's direct map.
    li      t0, -1
    slli    t0, t0, 38
    ld      t1, 0(t0)
    unimp

30: // Read this process's own data page and exit with what was there. The
    // address is a constant, identical in every process — which is the point.
    li      t0, 0x30000000
    ld      a0, 0(t0)
    li      a7, 1
    ecall
    unimp

40: // Read the page only one of the processes has.
    li      t0, 0x40000000
    ld      a0, 0(t0)
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
///
/// Returning resumes U-mode. Not returning — which is what `leave_user` does —
/// gives the kernel back control on the stack it started the user thread from.
fn user_trap(frame: &mut TrapFrame) {
    if frame.scause == EXCEPTION_ECALL_FROM_USER {
        USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
        match frame.a7 {
            SYS_LOG => {
                frame.a0 = user_transform(frame.a0);
                // `ecall` leaves `sepc` on the instruction itself. Resuming
                // without advancing it would re-execute the syscall forever —
                // the architecture does not do this for us, deliberately, so
                // that a handler can restart an instruction when it wants to.
                frame.sepc += 4;
                return;
            }
            SYS_EXIT => {
                USER_EXIT_VALUE.store(frame.a0, Ordering::Relaxed);
                leave_user()
            }
            _ => {
                USER_TRAP_CAUSE.store(u64::MAX, Ordering::Relaxed);
                leave_user()
            }
        }
    }

    USER_TRAP_CAUSE.store(frame.scause, Ordering::Relaxed);
    USER_TRAP_ADDRESS.store(frame.stval, Ordering::Relaxed);
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

/// The user program's bytes, as the linker laid them down.
fn user_blob() -> &'static [u8] {
    // SAFETY: both are linker-provided bounds of the read-only blob above, and
    // the region between them is initialised, immutable and never freed.
    unsafe {
        core::slice::from_raw_parts(
            &raw const user_blob_start,
            (&raw const user_blob_end as usize) - (&raw const user_blob_start as usize),
        )
    }
}

/// Maps the user program and a fresh stack into `space`.
///
/// `code` lets a caller hand in a frame another space is already using, which
/// is not an optimisation but the point being made: two processes running the
/// same program share its *frames* and share nothing else. Isolation is a
/// property of the tables.
fn map_user_image(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
    code: Option<tessera_karch::PhysFrame>,
) -> Result<tessera_karch::PhysFrame, u32> {
    let code = match code {
        Some(frame) => frame,
        None => {
            let blob = user_blob();
            if blob.is_empty() || blob.len() as u64 > FRAME_SIZE {
                return Err(1);
            }
            let frame = frames.alloc_frame().ok_or(2u32)?;
            space.zero_frame(frame);
            space.write_bytes_to_frame(frame, 0, blob);
            frame
        }
    };
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
    Ok(code)
}

/// Maps one page at `virt` in `space` holding `value` in its first word.
fn map_user_word(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
    virt: u64,
    value: u64,
    fail: u32,
) -> Result<(), u32> {
    let frame = frames.alloc_frame().ok_or(fail)?;
    space.zero_frame(frame);
    space.write_bytes_to_frame(frame, 0, &value.to_le_bytes());
    space
        .map(VirtAddr::new(virt), frame, PageFlags::rw().user(), frames)
        .map_err(|_| fail)
}

/// The port's first ring-3 execution, asserted rather than announced.
///
/// Three properties, in the order that each depends on the one before it: that
/// U-mode can be entered and returned from at all, that the page table's `U`
/// bit means what it says in the executable direction, and that it means what
/// it says in the kernel direction. A port that could enter U-mode but could
/// not contain it would pass the first alone.
fn umode_check(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
) -> Result<tessera_karch::PhysFrame, u32> {
    let code = map_user_image(space, frames, None)?;

    tessera_karch_riscv64::set_user_trap_hook(user_trap);

    // 1. Enter U-mode, make two syscalls, exit. The value that comes back is
    //    the kernel's transform of the one the program sent, so a zero or an
    //    echo would both fail.
    // SAFETY: the code and stack pages are mapped user-accessible above, and
    // no other user thread exists.
    unsafe { run_user(CHECK_SYSCALL) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(6);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != user_transform(USER_MAGIC) {
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

    // 2. W^X at the unprivileged level: the code page is mapped read-execute,
    //    so the program's store into it must fault rather than land.
    // SAFETY: as above.
    unsafe { run_user(CHECK_WRITE_TO_CODE) };
    let cause = USER_TRAP_CAUSE.load(Ordering::Relaxed);
    if cause != EXCEPTION_STORE_PAGE_FAULT {
        return Err(9);
    }
    // The program stores through `auipc`, so the faulting address is the
    // storing instruction's own address — somewhere inside the code page, not
    // its base. Checking the page is the claim being made.
    let fault = USER_TRAP_ADDRESS.load(Ordering::Relaxed);
    if fault & !(FRAME_SIZE - 1) != USER_CODE_VA {
        return Err(10);
    }
    kprintln!(
        "umode: W^X held — a store into the code page took a {} at {:#x}",
        exception_name(cause),
        fault
    );

    // 3. The privilege boundary itself: every kernel page is mapped without
    //    `U`, so a user load from one must fault. This is the check the higher
    //    half exists to make meaningful — the kernel is not merely elsewhere,
    //    it is unreachable.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_KERNEL) };
    let cause = USER_TRAP_CAUSE.load(Ordering::Relaxed);
    if cause != EXCEPTION_LOAD_PAGE_FAULT {
        return Err(11);
    }
    if USER_TRAP_ADDRESS.load(Ordering::Relaxed) != DIRECT_MAP_BASE {
        return Err(12);
    }
    kprintln!(
        "umode: kernel unreachable from U-mode — a load of {:#018x} took a {}",
        DIRECT_MAP_BASE,
        exception_name(cause)
    );

    Ok(code)
}

// ---------------------------------------------------------------------------
// Per-process address spaces
// ---------------------------------------------------------------------------

/// What each process finds at [`USER_DATA_VA`]. Two values, one address.
const PROCESS_A_DATA: u64 = 0xa1a1_a1a1_0000_0001;
const PROCESS_B_DATA: u64 = 0xb2b2_b2b2_0000_0002;
/// What process A finds at [`USER_PRIVATE_VA`], which B does not map at all.
const PROCESS_A_PRIVATE: u64 = 0x0dd1_0dd1_0000_0003;

/// ASIDs. Non-zero and distinct: zero means the kernel space, and two live
/// spaces sharing one would read each other's cached translations.
const PROCESS_A_ASID: u16 = 1;
const PROCESS_B_ASID: u16 = 2;

/// Two processes, each with its own Sv39 root, running the same program.
///
/// The claim is narrow and checkable: the same virtual address means different
/// memory in each, the kernel is reachable from both without being reachable
/// *by* either, and tearing one down leaves the other and the kernel intact.
///
/// `code` is the frame the program's instructions already live in. Both
/// processes map it, which is deliberate — sharing a frame is what makes the
/// isolation being demonstrated a property of the page tables rather than of
/// the memory happening to be different.
fn process_space_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    code: tessera_karch::PhysFrame,
) -> Result<(), u32> {
    use tessera_karch::AddressSpaceOps;

    let mut process_a = kernel_space
        .new_user(frames, PROCESS_A_ASID)
        .map_err(|_| 1u32)?;
    map_user_image(&mut process_a, frames, Some(code))?;
    map_user_word(&mut process_a, frames, USER_DATA_VA, PROCESS_A_DATA, 6)?;
    map_user_word(
        &mut process_a,
        frames,
        USER_PRIVATE_VA,
        PROCESS_A_PRIVATE,
        7,
    )?;

    let mut process_b = kernel_space
        .new_user(frames, PROCESS_B_ASID)
        .map_err(|_| 8u32)?;
    map_user_image(&mut process_b, frames, Some(code))?;
    map_user_word(&mut process_b, frames, USER_DATA_VA, PROCESS_B_DATA, 9)?;

    // 1. A reads its own data page. Reaching this line at all is already the
    //    kernel-half check: the instruction after `activate` is kernel text,
    //    and the trap the program's `ecall` takes is kernel text too, so a
    //    space that had not adopted the kernel's upper half would never get
    //    here to fail a comparison.
    // SAFETY: `process_a` maps this kernel's text, stacks and direct map by
    // construction (`new_user` copies them), so execution continues.
    unsafe { process_a.activate() };
    // SAFETY: the program and its stack are mapped user-accessible in the
    // now-active space, and no other user thread is running.
    unsafe { run_user(CHECK_READ_DATA) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(10);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != PROCESS_A_DATA {
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
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != PROCESS_B_DATA {
        return Err(13);
    }
    kprintln!(
        "process: two Sv39 roots — {:#018x} reads {:#018x} in asid {} and {:#018x} in asid {}",
        USER_DATA_VA,
        PROCESS_A_DATA,
        PROCESS_A_ASID,
        PROCESS_B_DATA,
        PROCESS_B_ASID
    );

    // 3. B has no mapping where A has one. Checked in both directions, because
    //    "B faults" alone would also be satisfied by an address neither maps.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_PRIVATE) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != EXCEPTION_LOAD_PAGE_FAULT {
        return Err(14);
    }
    if USER_TRAP_ADDRESS.load(Ordering::Relaxed) != USER_PRIVATE_VA {
        return Err(15);
    }
    // SAFETY: as above, back in `process_a`.
    unsafe { process_a.activate() };
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_PRIVATE) };
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != PROCESS_A_PRIVATE {
        return Err(16);
    }
    kprintln!(
        "process: {:#018x} is A's alone — B took a {} there, A read {:#018x}",
        USER_PRIVATE_VA,
        exception_name(EXCEPTION_LOAD_PAGE_FAULT),
        PROCESS_A_PRIVATE
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
    // Exactly, not at least. "At least" would pass for a teardown that walked
    // the whole root and freed the *shared* kernel tables too — which is not a
    // hypothetical: the first version of this check said `>= 2`, and the
    // negative check that broke `free_tables` on purpose sailed through it,
    // returning 18 frames and exiting 33. Over-freeing is silent precisely
    // because the kernel keeps working until something reuses a frame it still
    // points at.
    //
    // The number is derivable from the layout above rather than observed: A
    // maps four addresses spanning two gigabyte slots (root + 2 level-1 + 4
    // level-0 = 7), B maps three within one (root + 1 + 3 = 5).
    const EXPECTED_TABLE_FRAMES: usize = 7 + 5;
    if reclaimed != EXPECTED_TABLE_FRAMES {
        return Err(17);
    }
    // The kernel's own mappings are shared *by pointer* with both spaces that
    // were just torn down. If teardown had walked past the user half, this
    // translation would be gone — and so would the kernel.
    if kernel_space
        .translate(VirtAddr::new(&raw const __kernel_start as u64))
        .is_none()
    {
        return Err(18);
    }
    kprintln!(
        "process: teardown reclaimed {reclaimed} table frames and left the shared kernel half intact"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// The kcore substrate: a real Process, Thread and Scheduler on this port
// ---------------------------------------------------------------------------

/// Where the kcore thread's kernel stack goes, and the constraint that fixes
/// it — which is a RISC-V problem the AArch64 port does not have.
///
/// The kernel half is copied **by value** into each process root
/// (`new_user`), so a kernel mapping made *after* a process exists is visible
/// to that process only if it needed no new **root** entry. A stack placed in
/// a fresh gigabyte slot would be mapped in the kernel space and absent from
/// every process — and the first trap taken by a user thread would fault on
/// its own kernel stack, with no stack to report it on.
///
/// So this sits in the gigabyte slot the direct map already populates, just
/// above where RAM ends on the reference machine. That is an assumption about
/// the platform, which is why the check *verifies* it from inside the process
/// space rather than trusting the arithmetic — and why a machine with enough
/// RAM to reach this address fails loudly at `map_anonymous` instead of
/// quietly overlapping the direct map.
const KCORE_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb000_0000;
const KCORE_KSTACK_PAGES: u64 = 4;

/// The kcore process's user mappings. Distinct from the D98/D99 addresses so
/// nothing is inherited from a space this check did not build.
const KCORE_USER_CODE_VA: u64 = 0x1100_0000;
const KCORE_USER_STACK_VA: u64 = 0x2100_0000;

/// ASID for the kcore process's space.
const KCORE_PROCESS_ASID: u16 = 3;

/// The value the thread logs through the syscall substrate.
const KCORE_SENTINEL: u64 = 0x7e55_e2a0_0000_0001;

/// The scheduler carrying the kcore U-mode thread. A static so the syscall
/// hook can reach it to end the thread; touched only through raw pointers on
/// the single-threaded boot CPU, never a held `&mut` across a switch.
static mut KCORE_SCHED: Option<kcore::sched::Scheduler<ContextSwitch>> = None;

/// The process table. A static in `.bss` because a `ProcessTable` is far too
/// large to build on a boot stack — the same reason the x86-64 and AArch64
/// kernels hold theirs this way.
static mut KCORE_PROCESSES: kcore::process::ProcessTable<
    tessera_karch_riscv64::KernelAddressSpace,
> = kcore::process::ProcessTable::new();

static KCORE_LOG: AtomicU64 = AtomicU64::new(0);
static KCORE_EXITED: AtomicU64 = AtomicU64::new(0);
static KCORE_FAULT: AtomicU64 = AtomicU64::new(0);

// The program the kcore thread runs: log the value it was started with, then
// exit. Two syscalls, both named by `kcore::syscall::SyscallNumber` rather
// than by this file — which is the difference between this check and D98's.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl kcore_blob_start
kcore_blob_start:
    mv      t0, a0
    li      a7, 1           // SyscallNumber::DebugWrite
    mv      a0, t0
    ecall
    li      a7, 5           // SyscallNumber::ProcessExit
    li      a0, 0
    ecall
    unimp
.globl kcore_blob_end
kcore_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined above.
unsafe extern "C" {
    static kcore_blob_start: u8;
    static kcore_blob_end: u8;
}

/// Decodes a U-mode exception through kcore's syscall vocabulary.
///
/// Deliberately not routed through the shared `kcore::dispatch`: that requires
/// an `Executive`, and what this check is for is the layer below — that a
/// `Scheduler` can carry a `Thread` belonging to a `Process` on this port at
/// all.
fn kcore_user_trap(frame: &mut TrapFrame) {
    use kcore::syscall::{SyscallNumber, encode_result};
    if frame.scause == EXCEPTION_ECALL_FROM_USER {
        match SyscallNumber::from_u64(frame.a7) {
            Some(SyscallNumber::DebugWrite) => {
                KCORE_LOG.store(frame.a0, Ordering::SeqCst);
                frame.a0 = encode_result(Ok(0)) as u64;
                frame.sepc += 4;
                return;
            }
            Some(SyscallNumber::ProcessExit) => {
                KCORE_EXITED.store(1, Ordering::SeqCst);
            }
            _ => {
                KCORE_FAULT.store(u64::MAX, Ordering::SeqCst);
            }
        }
    } else {
        KCORE_FAULT.store(frame.scause, Ordering::SeqCst);
    }
    end_kcore_thread()
}

/// Ends the running kcore thread and returns to the scheduler's boot context —
/// the scheduler's own primitives, not D98's bespoke ping-pong.
fn end_kcore_thread() -> ! {
    // SAFETY: single-threaded boot; `KCORE_SCHED` is initialized before `run`
    // and reached only transiently here. `yield_to_boot` switches to the saved
    // boot context and never returns into this abandoned trap frame.
    unsafe {
        let sched = &raw mut KCORE_SCHED;
        if let Some(s) = (*sched).as_mut() {
            if let Some(current) = s.current() {
                s.terminate(current);
            }
            s.yield_to_boot();
        }
    }
    // Not reachable: `yield_to_boot` does not come back.
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// A real `kcore::Process` holding a `kcore::Thread`, scheduled by
/// `kcore::Scheduler`, entered in U-mode through `prepare_resume`, making a
/// syscall named by `kcore::syscall`, and exiting back to boot.
///
/// D99 proved the port can *hold* two address spaces. This proves the core can
/// *drive* one: from here the port shares the substrate every ring-3 feature
/// on AArch64 was built on, rather than a boot-glue harness that resembles it.
fn kcore_process_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // SAFETY: linker-provided bounds of the read-only blob above.
    let blob = unsafe {
        core::slice::from_raw_parts(
            &raw const kcore_blob_start,
            (&raw const kcore_blob_end as usize) - (&raw const kcore_blob_start as usize),
        )
    };

    let user_arch = kernel_space
        .new_user(frames, KCORE_PROCESS_ASID)
        .map_err(|_| 1u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(KCORE_PROCESS_ASID), 0);

    let code = frames.alloc_frame().ok_or(2u32)?;
    user_space.arch().zero_frame(code);
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(KCORE_USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 3u32)?;
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(KCORE_USER_CODE_VA), FRAME_SIZE);

    // A kcore wrapper *aliasing* the live kernel space, so the thread's kernel
    // stack is mapped into the real tables the trap vector walks — and, because
    // the kernel half is shared by pointer, into every process at once.
    // SAFETY: `kernel_space` is the active kernel space; this alias only maps
    // the kstack below and is never torn down (it owns none of its tables).
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(1),
        VirtAddr::new(KCORE_USER_CODE_VA),
        KCORE_SENTINEL as usize,
        VirtAddr::new(KCORE_USER_STACK_VA),
        1,
        VirtAddr::new(KCORE_KSTACK_VA),
        KCORE_KSTACK_PAGES,
        kcore::object::ObjectId::from_raw(1),
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 4u32)?;

    // The stack was mapped into the *kernel* space after this process's root
    // was copied. On a single-root architecture that is only visible to the
    // process if it needed no new root entry — so it is checked, not assumed.
    // Getting this wrong faults on the first trap, with no stack to report on.
    if user_space
        .arch()
        .translate(VirtAddr::new(KCORE_KSTACK_VA))
        .is_none()
    {
        return Err(5);
    }

    // SAFETY: single-threaded boot; the table is reached only through raw
    // pointers, and no `&mut` into it spans a context switch.
    let proc_idx = unsafe {
        let process =
            kcore::process::Process::new(kcore::object::ObjectId::from_raw(1), user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 6u32)?
    };

    KCORE_LOG.store(0, Ordering::SeqCst);
    KCORE_EXITED.store(0, Ordering::SeqCst);
    KCORE_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: as above — initialized before any access, reached transiently.
    let thread_idx = unsafe {
        (&raw mut KCORE_SCHED).write(Some(kcore::sched::Scheduler::new(1, 0)));
        let sched = (*(&raw mut KCORE_SCHED)).as_mut().ok_or(7u32)?;
        sched.add_thread(thread).map_err(|_| 8u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_idx).map_err(|_| 9u32)?;
        }
    }

    tessera_karch_riscv64::set_user_trap_hook(kcore_user_trap);

    // SAFETY: transient raw access; `run` returns when the thread yields to
    // boot, which the hook does on exit or fault.
    unsafe {
        if let Some(sched) = (*(&raw mut KCORE_SCHED)).as_mut() {
            sched.run();
        }
    }

    // Control came back with the *process* root still in `satp`. Restore the
    // kernel's own space before anything frees the tables under it.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if KCORE_EXITED.load(Ordering::SeqCst) != 1 || KCORE_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(10);
    }
    let logged = KCORE_LOG.load(Ordering::SeqCst);
    if logged != KCORE_SENTINEL {
        return Err(11);
    }

    // Teardown: reap the thread, unmap its kernel stack by hand (the alias
    // owns none of the tables it names and must never be torn down), then
    // remove the process, which reclaims the user space.
    // SAFETY: the thread is Exited and off-CPU, so reaping it is valid.
    unsafe {
        if let Some(sched) = (*(&raw mut KCORE_SCHED)).as_mut() {
            sched.reap(thread_idx);
        }
    }
    for page in 0..KCORE_KSTACK_PAGES {
        if let Ok(frame) = kernel_alias
            .arch_mut()
            .unmap(VirtAddr::new(KCORE_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(logged)
}

// ---------------------------------------------------------------------------
// The Executive: two U-mode processes exchange a message over a channel
// ---------------------------------------------------------------------------

/// The request the client sends, handed to it as its thread argument rather
/// than compiled into the program, so the value that comes back is traceable
/// to something the kernel put there.
const IPC_MAGIC: u64 = 0xf00d_cafe_f00d_cafe;
/// What the server XORs into the request to make the reply. A reply that is
/// merely an echo would be satisfied by a channel that never carried anything.
const IPC_REPLY_XOR: u64 = 0x5a5a_5a5a;

/// The two processes' user mappings. Both use the *same* addresses — they have
/// their own roots, and D99 established what that means.
const IPC_USER_CODE_VA: u64 = 0x1200_0000;
const IPC_USER_STACK_VA: u64 = 0x2200_0000;

/// Kernel stacks, in the gigabyte slot the direct map already populates — the
/// D100 constraint, which every kernel mapping made after a process root is
/// copied has to respect.
const IPC_SERVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb400_0000;
const IPC_CLIENT_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb800_0000;
/// Deeper than D100's: a blocking channel handoff parks a whole dispatch frame
/// on this stack.
const IPC_KSTACK_PAGES: u64 = 4;

const IPC_SERVER_ASID: u16 = 4;
const IPC_CLIENT_ASID: u16 = 5;

/// The executive carrying both threads, their channel, and the scheduler.
static mut KCORE_EXEC: Option<kcore::exec::Executive<ContextSwitch>> = None;

/// The boot allocator, exposed to the dispatch hook for the duration of a
/// check. Null outside it, and a null read is a distinct failure rather than a
/// dereference.
static mut DISPATCH_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> = core::ptr::null_mut();

/// Which scheduler slot each program landed in, so the hook can attribute a
/// report to the thread that made it. Distinguishing *who* logged what is the
/// difference between "a value crossed" and "the value crossed in the right
/// direction".
static IPC_SERVER_THREAD: AtomicU64 = AtomicU64::new(u64::MAX);
static IPC_CLIENT_THREAD: AtomicU64 = AtomicU64::new(u64::MAX);

/// Values reported by `DebugWrite`, in arrival order.
///
/// The IPC check attributes reports by *thread*, which separates two programs
/// making one report each. A single program making several needs the other
/// axis, so both exist: this array is keyed by order, which is a property of
/// the program rather than of the schedule.
const MAX_REPORTS: usize = 4;
static REPORTS: [AtomicU64; MAX_REPORTS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static REPORT_COUNT: AtomicU64 = AtomicU64::new(0);

static IPC_SERVER_SAW: AtomicU64 = AtomicU64::new(0);
static IPC_CLIENT_SAW: AtomicU64 = AtomicU64::new(0);
static IPC_EXITS: AtomicU64 = AtomicU64::new(0);
static USER_FAULT: AtomicU64 = AtomicU64::new(0);
/// The address a contained user fault named (`stval`), and the cause the
/// crashing thread was running under.
///
/// Both are captured at fault time because that is the last moment they exist.
/// The address makes the crash-recovery ladder's first record say *what killed
/// the host* rather than merely which class of thing did; the cause is what
/// joins the restart to the crash, since the supervisor is reached through a
/// yield to boot whose ambient context is boot's own id.
static USER_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
static USER_FAULT_CORRELATION: AtomicU64 = AtomicU64::new(0);

/// Whether a `DebugWrite` from a thread that is neither the IPC check's server
/// nor its client is expected.
///
/// The shared syscall hook flags an unrecognised reporter, which is right for
/// the IPC check — a third thread reporting there would mean the wrong process
/// answered. The driver checks collect reports from every driver they spawn
/// through `REPORTS`, so for them any thread is a legitimate reporter. Those
/// checks used to pass only because they ran *after* the IPC check and its
/// stale thread ids happened to match; saying so explicitly is what lets a
/// driver check run anywhere in the boot, which is how this was found.
static REPORTS_FROM_ANY_THREAD: AtomicBool = AtomicBool::new(false);

/// A `&mut` to the executive through its static. Provably initialized before
/// any thread runs.
fn substrate_exec() -> &'static mut kcore::exec::Executive<ContextSwitch> {
    // SAFETY: single-core cooperative boot; `KCORE_EXEC` is set in `ipc_check`
    // before any thread runs, and every channel handoff switches control, so
    // only one borrow is ever actively in flight.
    unsafe {
        match (*(&raw mut KCORE_EXEC)).as_mut() {
            Some(exec) => exec,
            None => {
                kprintln!("ipc: FATAL: executive used before it was built");
                TestFinisherExit::exit(ExitCode::Failure)
            }
        }
    }
}

/// Ends the running thread and switches to the next ready one — to the boot
/// context only when nothing is runnable. `exit_current`, not
/// terminate-and-yield-to-boot, which would end the whole run at the first
/// exit and abandon a still-ready peer (the D82 lesson, inherited rather than
/// relearned).
fn end_user_thread() {
    substrate_exec().scheduler().exit_current();
}

/// The port's syscall entry: a U-mode `ecall` decoded by the **shared**
/// `kcore::dispatch` (D79), with only the arch-coupled remainder handled here.
/// Shared by every Executive-substrate check on this port — a new syscall
/// needs nothing here, which is the substrate working as intended.
///
/// This is the whole point of the milestone. Nothing below knows what a
/// channel is; `dispatch` does, and it is the same code the other ports call.
/// What is port-local is the register ABI — `a7` names the syscall, `a0`-`a5`
/// carry its arguments, `a0` takes the result — and advancing `sepc`, which
/// this architecture leaves to the handler.
fn user_dispatch_hook(frame: &mut TrapFrame) {
    use kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
    use kcore::syscall::{SyscallNumber, encode_result};

    if frame.scause != EXCEPTION_ECALL_FROM_USER {
        USER_FAULT_ADDR.store(frame.stval, Ordering::SeqCst);
        USER_FAULT_CORRELATION.store(kcore::trace::current().correlation, Ordering::SeqCst);
        USER_FAULT.store(frame.scause, Ordering::SeqCst);
        end_user_thread();
        return;
    }
    let Some(caller) = substrate_exec().scheduler().current() else {
        USER_FAULT.store(0xbad0, Ordering::SeqCst);
        end_user_thread();
        return;
    };
    // SAFETY: transient raw read of the check-scoped allocator pointer.
    let frames = unsafe { *(&raw const DISPATCH_FRAMES) };
    if frames.is_null() {
        // A check forgot to expose the allocator. Fail loudly, never by
        // dereferencing null inside a covered arm.
        USER_FAULT.store(0xbad2, Ordering::SeqCst);
        end_user_thread();
        return;
    }

    let request = SyscallRequest {
        number: frame.a7,
        args: [frame.a0, frame.a1, frame.a2, frame.a3, frame.a4, frame.a5],
    };
    let mut router = PlicRouter;
    // SAFETY: single-core cooperative boot. The statics are initialized by
    // `ipc_check` before `run()`, and `DISPATCH_FRAMES` points at the boot allocator
    // for the check's duration (checked non-null above). A blocking channel op
    // parks this frame — the borrows in `env` included — on the blocked
    // thread's own kernel stack, and nothing dereferences them until the
    // handoff returns here.
    let outcome = unsafe {
        let mut env = DispatchEnv {
            exec: match (*(&raw mut KCORE_EXEC)).as_mut() {
                Some(exec) => exec,
                None => {
                    USER_FAULT.store(0xbad3, Ordering::SeqCst);
                    end_user_thread();
                    return;
                }
            },
            processes: &mut *(&raw mut KCORE_PROCESSES),
            caller,
            alloc: &mut *frames,
            // This machine has no IOMMU — `qemu-system-riscv64 -M virt` has no
            // IOMMU node at all — so no device has an aperture and every DMA
            // grant is unscoped, and says so (D121).
            iommu: None,
            // The interrupt controller, unlike the IOMMU, is not optional on
            // this machine: a departing capability whose route was dropped
            // from the graph but left unmasked at the PLIC is the
            // half-teardown the seam exists to prevent.
            irqs: Some(&mut router),
        };
        dispatch(&mut env, &request)
    };

    match outcome {
        DispatchOutcome::Return(value) => {
            frame.a0 = value as u64;
            frame.sepc += 4;
        }
        DispatchOutcome::Unhandled => match SyscallNumber::from_u64(frame.a7) {
            Some(SyscallNumber::DebugWrite) => {
                let slot = REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
                if slot < MAX_REPORTS {
                    REPORTS[slot].store(frame.a0, Ordering::SeqCst);
                }
                // Overflow is not silently dropped: `REPORT_COUNT` keeps
                // counting past the array, so a check that expected two
                // reports and got three sees three.
                let caller = caller as u64;
                if caller == IPC_SERVER_THREAD.load(Ordering::SeqCst) {
                    IPC_SERVER_SAW.store(frame.a0, Ordering::SeqCst);
                } else if caller == IPC_CLIENT_THREAD.load(Ordering::SeqCst) {
                    IPC_CLIENT_SAW.store(frame.a0, Ordering::SeqCst);
                } else if !REPORTS_FROM_ANY_THREAD.load(Ordering::SeqCst) {
                    USER_FAULT.store(0xbad4, Ordering::SeqCst);
                }
                frame.a0 = encode_result(Ok(0)) as u64;
                frame.sepc += 4;
            }
            Some(SyscallNumber::IrqComplete) => {
                // Arch-coupled: re-arming is an interrupt-controller write, so
                // it stays port-local rather than becoming a dispatch arm.
                frame.a0 = irq_complete(caller, frame.a0) as u64;
                frame.sepc += 4;
            }
            Some(SyscallNumber::ProcessExit) => {
                IPC_EXITS.fetch_add(1, Ordering::SeqCst);
                end_user_thread();
            }
            _ => {
                USER_FAULT.store(0xbad1, Ordering::SeqCst);
                end_user_thread();
            }
        },
    }
}

// The two programs. Both build a `ChannelMsgArgs` (88 bytes, the ISL struct)
// on their own user stack — which `spawn_user` mapped through kcore's wrapper,
// so it is a *tracked* mapping and `validate_user_range` accepts a pointer
// into it. An untracked mapping would be a live page the syscall layer refuses
// to read, which is the intended behaviour and an easy self-inflicted wound.
//
// Register ABI: a7 = syscall number, a0 = args-struct pointer, a1 = endpoint
// handle (0 in both — the first install in a fresh handle table).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4

// Builds ChannelMsgArgs at sp+16 with an 8-byte inline buffer at sp+0.
.macro CHANNEL_ARGS
    li      t0, 88
    sw      t0, 16(sp)          // size
    li      t0, 4
    sw      t0, 20(sp)          // version — 4: v2 added the installed-handle
                                // report, v3 made the outgoing handle vector a
                                // HandleTransfer descriptor carrying the rights
                                // each capability arrives with, v4 gave that
                                // descriptor a TransferMode. All three are the
                                // same 88 bytes, so the kernel can only tell
                                // them apart by this word — it refuses a stale
                                // one rather than reading bare handle values
                                // as 16-byte descriptors.
    sd      zero, 24(sp)        // flags
    sd      zero, 32(sp)        // interface_id
    sd      zero, 40(sp)        // txn_id
    sw      zero, 48(sp)        // method_id
    sw      zero, 52(sp)        // msg_flags
    mv      t0, sp
    sd      t0, 56(sp)          // inline_ptr -> the buffer at sp+0
    li      t0, 8
    sd      t0, 64(sp)          // inline_len
    sd      zero, 72(sp)        // handles_ptr
    sd      zero, 80(sp)        // handle_count
    sd      zero, 88(sp)        // installed_ptr
    sd      zero, 96(sp)        // installed_cap
.endm

.globl ipc_server_blob_start
ipc_server_blob_start:
    addi    sp, sp, -128
    sd      zero, 0(sp)
    CHANNEL_ARGS
    addi    a0, sp, 16
    li      a1, 0
    li      a7, 13              // ChannelRecv — parks here until the client calls
    ecall
    bltz    a0, 91f             // a failed syscall must not look like a quiet
                                // zero in the buffer: report the code instead

    ld      a0, 0(sp)           // report what actually arrived
    li      a7, 1               // DebugWrite
    ecall

    ld      t1, 0(sp)           // reply = request ^ IPC_REPLY_XOR
    li      t2, 0x5a5a5a5a
    xor     t1, t1, t2
    sd      t1, 0(sp)
    addi    a0, sp, 16
    li      a1, 0
    li      a7, 27              // ChannelReplyContinue — reply and keep running.
                                // Plain ChannelReply would leave this thread
                                // blocked-but-unregistered; the project has
                                // paid for that lesson twice.
    ecall
    bltz    a0, 91f

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
91:                             // a0 holds the negative error code
    li      a7, 1               // DebugWrite
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl ipc_server_blob_end
ipc_server_blob_end:

.globl ipc_client_blob_start
ipc_client_blob_start:
    addi    sp, sp, -128
    sd      a0, 0(sp)           // a0 = the magic, handed over as the thread arg
    CHANNEL_ARGS
    addi    a0, sp, 16
    li      a1, 0
    li      a7, 14              // ChannelCall — blocks until the reply lands
    ecall
    bltz    a0, 92f

    ld      a0, 0(sp)           // the buffer is symmetric: request out, reply in
    li      a7, 1               // DebugWrite
    ecall

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
92:                             // a0 holds the negative error code
    li      a7, 1               // DebugWrite
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl ipc_client_blob_end
ipc_client_blob_end:
"#
);

// SAFETY: declares the blobs' bounding symbols, defined above.
unsafe extern "C" {
    static ipc_server_blob_start: u8;
    static ipc_server_blob_end: u8;
    static ipc_client_blob_start: u8;
    static ipc_client_blob_end: u8;
}

/// Builds one IPC process: its own root, its program, a user stack, a kernel
/// stack, and its endpoint installed at handle 0. Returns
/// `(thread_index, process_index)` — teardown needs both.
#[allow(clippy::too_many_arguments)]
fn ipc_spawn_process(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blob: &[u8],
    kstack_va: u64,
    asid: u16,
    endpoint_object: kcore::object::ObjectId,
    arg: usize,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = kernel_space.new_user(frames, asid).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(asid), 0);

    // Mapped through the kcore wrapper rather than the arch space directly, so
    // the mapping is **tracked**: the syscall layer validates a user pointer
    // against this list, and an untracked page is one the kernel refuses to
    // read however live it is.
    user_space
        .map_anonymous(
            VirtAddr::new(IPC_USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| base_err + 1)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(IPC_USER_CODE_VA))
        .map(|(frame, _)| frame)
        .ok_or(base_err + 2)?;
    // Written through the direct map, which is how a read-execute page gets
    // its contents without ever being writable to anyone.
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(IPC_USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `kernel_space` is the active kernel space; this alias exists only
    // to map the kernel stack and is never torn down (it owns no tables).
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(kstack_va),
        VirtAddr::new(IPC_USER_CODE_VA),
        arg,
        VirtAddr::new(IPC_USER_STACK_VA),
        1,
        VirtAddr::new(kstack_va),
        IPC_KSTACK_PAGES,
        endpoint_object,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| base_err + 3)?;

    // The D100 constraint, re-checked per process rather than assumed to hold
    // because it held once.
    if user_space
        .arch()
        .translate(VirtAddr::new(kstack_va))
        .is_none()
    {
        return Err(base_err + 4);
    }

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 5)?
            .add_thread(thread)
            .map_err(|_| base_err + 6)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(endpoint_object, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 7)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_idx).map_err(|_| base_err + 8)?;
            // The first install in a fresh handle table lands at handle 0,
            // which both programs name.
            process
                .handles_mut()
                .install(endpoint_object, Rights::READ | Rights::WRITE)
                .map_err(|_| base_err + 9)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// Two U-mode processes exchange a message over a channel.
///
/// The client `call`s with a magic and blocks; the server `receive`s it,
/// reports what arrived, `reply`s with a transform of it, and exits; the client
/// wakes with the reply in the same buffer it sent from and reports that.
/// Returns `(what the server saw, what the client got back, context switches)`.
///
/// Three things are being proven at once, and only the first is about IPC. The
/// message crosses an address-space boundary. The **scheduler chooses** — until
/// now this port had one runnable thread and could not tell a scheduler from a
/// jump. And the syscall arrives through `kcore::dispatch`, the same dispatcher
/// the other ports call, so this port stops having its own idea of what a
/// syscall is.
fn ipc_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64, u64), u32> {
    use tessera_karch::AddressSpaceOps;

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let (server_ep, client_ep) = substrate_exec().channel_create().map_err(|_| 1u32)?;
    let server_obj = kcore::object::ObjectId::from_raw(20);
    let client_obj = kcore::object::ObjectId::from_raw(21);
    substrate_exec().bind_endpoint_object(server_ep, server_obj);
    substrate_exec().bind_endpoint_object(client_ep, client_obj);

    IPC_SERVER_SAW.store(0, Ordering::SeqCst);
    IPC_CLIENT_SAW.store(0, Ordering::SeqCst);
    IPC_EXITS.store(0, Ordering::SeqCst);
    USER_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: linker-provided bounds of the read-only blobs above.
    let (server_blob, client_blob) = unsafe {
        (
            core::slice::from_raw_parts(
                &raw const ipc_server_blob_start,
                (&raw const ipc_server_blob_end as usize)
                    - (&raw const ipc_server_blob_start as usize),
            ),
            core::slice::from_raw_parts(
                &raw const ipc_client_blob_start,
                (&raw const ipc_client_blob_end as usize)
                    - (&raw const ipc_client_blob_start as usize),
            ),
        )
    };

    // The server is built first so it is scheduled first and is already parked
    // in `receive` when the client calls.
    let (server_idx, server_proc) = ipc_spawn_process(
        kernel_space,
        frames,
        server_blob,
        IPC_SERVER_KSTACK_VA,
        IPC_SERVER_ASID,
        server_obj,
        0,
        10,
    )?;
    let (client_idx, client_proc) = ipc_spawn_process(
        kernel_space,
        frames,
        client_blob,
        IPC_CLIENT_KSTACK_VA,
        IPC_CLIENT_ASID,
        client_obj,
        IPC_MAGIC as usize,
        30,
    )?;
    IPC_SERVER_THREAD.store(server_idx as u64, Ordering::SeqCst);
    IPC_CLIENT_THREAD.store(client_idx as u64, Ordering::SeqCst);

    // `dispatch` needs a live frame source; the channel arms allocate nothing
    // today, but a covered arm that does must not find a null pointer.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    // The kernel is about to follow user pointers: the channel descriptor and
    // its payload live on the caller's stack. Every one of them is validated
    // against the caller's tracked mappings first — this only removes the
    // hardware backstop behind that validation.
    // SAFETY: the sole user-pointer path is `kcore::syscall::read_user` /
    // `write_user`, which validate the whole range before dereferencing it.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);
    let switches_before = substrate_exec().switch_count();
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    let switches = substrate_exec().switch_count() - switches_before;
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };

    // Control returned with a *process* root still in `satp`.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(50);
    }
    let server_saw = IPC_SERVER_SAW.load(Ordering::SeqCst);
    if server_saw != IPC_MAGIC {
        return Err(51);
    }
    let client_saw = IPC_CLIENT_SAW.load(Ordering::SeqCst);
    if client_saw != IPC_MAGIC ^ IPC_REPLY_XOR {
        return Err(52);
    }
    if IPC_EXITS.load(Ordering::SeqCst) != 2 {
        return Err(53);
    }
    // A handoff, a wake and two exits cannot happen without the scheduler
    // actually switching. Asserting it beats inferring it from the values.
    if switches < 2 {
        return Err(54);
    }

    // SAFETY: transient raw access; both threads are Exited and off-CPU, and
    // each process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(server_idx);
        }
        for proc_idx in [client_proc, server_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }
    use tessera_karch::FrameSource;
    // SAFETY: as above — the alias owns no tables and is only used to unmap.
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = kernel_arch;
    for base in [IPC_SERVER_KSTACK_VA, IPC_CLIENT_KSTACK_VA] {
        for page in 0..IPC_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((server_saw, client_saw, switches))
}

// ---------------------------------------------------------------------------
// Capability-gated MMIO and DMA: the two favours a ring-3 driver needs
// ---------------------------------------------------------------------------

/// The device process's mappings. All four sit inside one gigabyte, which the
/// teardown count below depends on and states.
const DEVICE_USER_CODE_VA: u64 = 0x1300_0000;
const DEVICE_USER_STACK_VA: u64 = 0x2300_0000;
/// Where the program asks for the device's registers, and for its DMA buffer.
/// Both are the program's choice, not the kernel's — a driver names its own
/// address space; what it cannot name is the *physical* window behind the
/// first, which is exactly what the capability supplies.
const USER_MMIO_VA: u64 = 0x3300_0000;
const USER_DMA_VA: u64 = 0x3400_0000;
const _: () = assert!(
    USER_MMIO_VA % FRAME_SIZE == 0 && USER_DMA_VA % FRAME_SIZE == 0,
    "both must be page-aligned; the syscalls refuse anything else",
);

/// The device process's kernel stack, in the direct map's gigabyte slot — the
/// D100 constraint on any kernel mapping made after a process root is copied.
const DEVICE_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbc00_0000;
const DEVICE_ASID: u16 = 6;

/// What the ring-3 program writes into its DMA page, and what the kernel then
/// looks for at the physical address the program was told to give the device.
const DMA_SENTINEL: u64 = 0xd1a0_d1a0_0000_0007;

/// Table frames plus tracked leaf frames a fully-populated device process
/// returns at teardown.
///
/// Exact, not a lower bound, and the difference matters here more than
/// anywhere else on this port: the MMIO page is mapped **untracked** by
/// `map_device`, so `teardown` must never see it. A device register block
/// returned to the anonymous-memory pool is a bug that would show up much
/// later as memory that reads back as hardware. A lower bound would not
/// notice, exactly as D99's `>= 2` did not notice `free_tables` freeing the
/// kernel's own tables.
///
/// Derivation: the four user addresses above all lie below 1 GiB, so one root
/// and one level-1 table cover them, and their level-1 indices differ, so
/// each needs its own level-0 table — 1 + 1 + 4 = 6. The tracked leaves are
/// the code page, the user stack page and the DMA page — 3. The device window
/// is not among them.
const DEVICE_TEARDOWN_FRAMES: usize = 6 + 3;

// The ring-3 driver's two favours, in one program.
//
// `MapDeviceArgs` and `DmaAllocArgs` are byte-identical 32-byte structs
// (api/isl/examples/device_abi.isl), so the struct is built once and reissued
// with a different syscall number and `vaddr`. That is a property of the ABI,
// not a shortcut: both syscalls ask the same question — "authorised by this
// device handle, put something at this address".
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl device_blob_start
device_blob_start:
    addi    sp, sp, -32
    li      t0, 32
    sw      t0, 0(sp)           // size
    li      t0, 1
    sw      t0, 4(sp)           // version
    sd      zero, 8(sp)         // flags
    sw      zero, 16(sp)        // device — handle 0, the only one installed
    sw      zero, 20(sp)        // reserved
    li      t0, 0x33000000
    sd      t0, 24(sp)          // vaddr = USER_MMIO_VA
    mv      a0, sp
    li      a7, 23              // MapDevice
    ecall
    bltz    a0, 90f             // a refusal must be reported, never ignored

    // a0 is the register base: the page we asked for plus the window's
    // intra-page offset. Read the transport's identity through our *own*
    // mapping — the kernel read the same two registers through the direct
    // map, and the check compares them.
    lwu     a1, 0(a0)           // MAGIC_VALUE @ 0x000
    lwu     a2, 8(a0)           // DEVICE_ID   @ 0x008
    slli    a2, a2, 32          // lwu, not lw: lw sign-extends on RV64 and a
    or      a0, a1, a2          // register with bit 31 set would arrive wrong
    li      a7, 1               // DebugWrite — report 0
    ecall

    li      t0, 0x34000000
    sd      t0, 24(sp)          // vaddr = USER_DMA_VA
    mv      a0, sp
    li      a7, 24              // DmaAlloc
    ecall
    bltz    a0, 90f

    // a0 is the page's physical address — the name the *device* would use for
    // the memory this program is about to write through its own virtual one.
    mv      t1, a0
    li      t2, 0x34000000
    li      t3, 0xd1a0d1a0
    slli    t3, t3, 32
    addi    t3, t3, 7           // DMA_SENTINEL
    sd      t3, 0(t2)
    mv      a0, t1
    li      a7, 1               // DebugWrite — report 1
    ecall

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
90:                             // a0 holds the negative error code
    li      a7, 1
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl device_blob_end
device_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined above.
unsafe extern "C" {
    static device_blob_start: u8;
    static device_blob_end: u8;
}

/// A ring-3 process is granted a Device capability, maps the device's
/// registers into its own address space, reads them, and allocates a buffer
/// the device could address.
///
/// These are the only two privileged favours a driver needs, and neither one
/// tells the program anything it could have guessed: the physical window lives
/// inside the capability and never crosses the ABI, and the DMA page's
/// physical address is *returned* rather than requested. What the program
/// chooses is only where in its own space each lands.
///
/// Returns `(the packed magic|device-id the program read, the DMA physical
/// address it was given)`.
fn device_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    window: u64,
) -> Result<(u64, u64), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }

    // The window enters the resource graph as a Device object. This is the
    // only place its physical address is named; from here on it travels as a
    // capability, and the program that uses it never learns it.
    let device_obj = kcore::object::ObjectId::from_raw(30);
    substrate_exec()
        .device_register_mmio(
            device_obj,
            window,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 1u32)?;

    // SAFETY: linker-provided bounds of the read-only blob above.
    let blob = unsafe {
        core::slice::from_raw_parts(
            &raw const device_blob_start,
            (&raw const device_blob_end as usize) - (&raw const device_blob_start as usize),
        )
    };

    let user_arch = kernel_space
        .new_user(frames, DEVICE_ASID)
        .map_err(|_| 2u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(DEVICE_ASID), 0);

    user_space
        .map_anonymous(
            VirtAddr::new(DEVICE_USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 3u32)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(DEVICE_USER_CODE_VA))
        .map(|(frame, _)| frame)
        .ok_or(4u32)?;
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(DEVICE_USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down (it owns no tables).
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(DEVICE_KSTACK_VA),
        VirtAddr::new(DEVICE_USER_CODE_VA),
        0,
        VirtAddr::new(DEVICE_USER_STACK_VA),
        1,
        VirtAddr::new(DEVICE_KSTACK_VA),
        IPC_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 5u32)?;
    if user_space
        .arch()
        .translate(VirtAddr::new(DEVICE_KSTACK_VA))
        .is_none()
    {
        return Err(6);
    }

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(7u32)?
            .add_thread(thread)
            .map_err(|_| 8u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 9u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_idx).map_err(|_| 10u32)?;
            // Handle 0: the Device capability, with MAP and nothing else it
            // does not need. READ lets it be looked up; MAP is the right the
            // two syscalls actually check.
            process
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 11u32)?;
        }
    }

    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // SAFETY: the sole user-pointer path is `read_user`/`write_user`, which
    // validate the whole range against the caller's tracked mappings first.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    // The same hook the IPC check installs, unchanged: `MapDevice` and
    // `DmaAlloc` are already arms of `kcore::dispatch`, so a port that reached
    // the substrate gets them without writing a line of syscall code.
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);

    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(20);
    }
    let reports = REPORT_COUNT.load(Ordering::SeqCst);
    if reports != 2 {
        // The program reports a refused syscall's code rather than pressing
        // on, so a short run has already said why in its one report. Printing
        // it turns "the count was wrong" into the actual reason — the
        // difference between a rights failure and a bad address is exactly
        // what a reader needs here.
        if reports == 1 {
            kprintln!(
                "mmio: the program reported {} and stopped",
                REPORTS[0].load(Ordering::SeqCst) as i64
            );
        }
        return Err(21);
    }

    // 1. The identity the program read through its own capability mapping, and
    //    the same two registers as the kernel reads them through the direct
    //    map. Two disjoint paths to one register block.
    let packed = REPORTS[0].load(Ordering::SeqCst);
    let (kernel_magic, kernel_id) = virtio_identity(window);
    if packed & 0xffff_ffff != u64::from(kernel_magic)
        || packed >> 32 != u64::from(kernel_id)
        || kernel_magic != tessera_virtio::MAGIC
    {
        return Err(22);
    }

    // 2. The DMA page. The program wrote a sentinel through its *virtual*
    //    address; the kernel looks for it at the *physical* one the program
    //    was told to hand the device. Finding it is what proves the two names
    //    denote the same memory — which is the entire content of `DmaAlloc`,
    //    and is checked here through a path the program never touched.
    let dma_phys = REPORTS[1].load(Ordering::SeqCst);
    if dma_phys & (FRAME_SIZE - 1) != 0 {
        return Err(23);
    }
    // SAFETY: `dma_phys` was returned by `DmaAlloc`, which allocated it from
    // this allocator, so it is a RAM frame the direct map covers read-write.
    // The read is 8 aligned bytes inside it.
    let seen = unsafe { ((DIRECT_MAP_BASE + dma_phys) as *const u64).read_volatile() };
    if seen != DMA_SENTINEL {
        return Err(24);
    }

    // 3. Teardown, counted exactly — see `DEVICE_TEARDOWN_FRAMES`.
    // SAFETY: transient raw access; the thread is Exited and off-CPU, and the
    // process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
    }
    let before = frames.free_list_depth();
    // SAFETY: as above.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }
    let reclaimed = frames.free_list_depth() - before;
    if reclaimed != DEVICE_TEARDOWN_FRAMES {
        return Err(25);
    }
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for page in 0..IPC_KSTACK_PAGES {
        if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(DEVICE_KSTACK_VA + page * FRAME_SIZE)) {
            frames.free_frame(frame);
        }
    }

    Ok((packed, dma_phys))
}

// ---------------------------------------------------------------------------
// A capability crosses a channel: one process hands a device to another
// ---------------------------------------------------------------------------

/// The two processes' mappings. Both have their own roots, so both use the
/// same addresses — and the grant process's fourth address is where *it* maps
/// the device before giving it away.
const GRANT_USER_CODE_VA: u64 = 0x1400_0000;
const GRANT_USER_STACK_VA: u64 = 0x2400_0000;

const GRANT_MANAGER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbe00_0000;
const GRANT_DRIVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbf00_0000;
const GRANT_MANAGER_ASID: u16 = 7;
const GRANT_DRIVER_ASID: u16 = 8;

/// Handle numbers **boot** installs, which is the only thing either program
/// may assume. The device handle the driver ends up using is deliberately not
/// here: it does not exist until the kernel installs it, and the driver is
/// told the number rather than agreeing on one.
const GRANT_ENDPOINT_HANDLE: u64 = 0;
const GRANT_DEVICE_HANDLE: u32 = 1;

// The manager: receive a request, reply with the device capability attached,
// exit. It never says *what* the device is — the reply body is empty, and the
// entire payload is the transferred handle.
//
// Stack layout: an 8-byte inline buffer at sp+0, ChannelMsgArgs at sp+16
// (88 bytes, so through sp+103), and the outgoing transfer vector — one
// 16-byte `HandleTransfer` descriptor — at sp+104. The descriptor moved out of
// the 8 bytes at sp+8 when it stopped being a bare handle value and started
// carrying the rights the capability arrives with (D113).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl grant_manager_blob_start
grant_manager_blob_start:
    addi    sp, sp, -128
    sd      zero, 0(sp)
    li      t0, 88
    sw      t0, 16(sp)          // size
    li      t0, 4
    sw      t0, 20(sp)          // version
    sd      zero, 24(sp)        // flags
    sd      zero, 32(sp)        // interface_id
    sd      zero, 40(sp)        // txn_id
    sw      zero, 48(sp)        // method_id
    sw      zero, 52(sp)        // msg_flags
    mv      t0, sp
    sd      t0, 56(sp)          // inline_ptr
    li      t0, 8
    sd      t0, 64(sp)          // inline_len
    sd      zero, 72(sp)        // handles_ptr — nothing transferred inbound
    sd      zero, 80(sp)        // handle_count
    sd      zero, 88(sp)        // installed_ptr — expects nothing back
    sd      zero, 96(sp)        // installed_cap

    addi    a0, sp, 16
    li      a1, 0
    li      a7, 13              // ChannelRecv — park until the driver calls
    ecall
    bltz    a0, 91f

    // Attach the device capability to the reply: one HandleTransfer
    // descriptor naming the handle and the rights it is to arrive with. This
    // check is about the transfer mechanism, so the capability travels with
    // the rights boot granted (READ|MAP|TRANSFER) rather than a narrowed set —
    // the framework's own grant is where narrowing is exercised.
    li      t0, 1
    sw      t0, 104(sp)         // handle — the one boot installed at index 1
    sw      zero, 108(sp)       // mode = TransferMode::TRANSFER
    li      t0, 0x85
    sd      t0, 112(sp)         // rights: READ|MAP|TRANSFER
    addi    t0, sp, 104
    sd      t0, 72(sp)          // handles_ptr
    li      t0, 1
    sd      t0, 80(sp)          // handle_count
    sd      zero, 64(sp)        // inline_len = 0: the capability *is* the reply

    addi    a0, sp, 16
    li      a1, 0
    li      a7, 27              // ChannelReplyContinue
    ecall
    bltz    a0, 91f

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
91:
    li      a7, 1               // report the refusal rather than pressing on
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl grant_manager_blob_end
grant_manager_blob_end:

// The driver: ask for a device, be told which handle it arrived as, and use
// it. It holds exactly one handle to begin with — its endpoint — and cannot
// name a device until the kernel installs one and reports the number.
//
// Stack layout: inline buffer at sp+0, the installed-handle report (one u32)
// at sp+8, ChannelMsgArgs at sp+16, MapDeviceArgs at sp+112.
.globl grant_driver_blob_start
grant_driver_blob_start:
    addi    sp, sp, -160
    sd      zero, 0(sp)
    sd      zero, 8(sp)
    li      t0, 88
    sw      t0, 16(sp)
    li      t0, 4
    sw      t0, 20(sp)
    sd      zero, 24(sp)
    sd      zero, 32(sp)
    sd      zero, 40(sp)
    sw      zero, 48(sp)
    sw      zero, 52(sp)
    mv      t0, sp
    sd      t0, 56(sp)          // inline_ptr
    li      t0, 8
    sd      t0, 64(sp)          // inline_len
    sd      zero, 72(sp)        // handles_ptr — transfers nothing outbound
    sd      zero, 80(sp)        // handle_count
    addi    t0, sp, 8
    sd      t0, 88(sp)          // installed_ptr — "tell me what I was given"
    li      t0, 1
    sd      t0, 96(sp)          // installed_cap

    addi    a0, sp, 16
    li      a1, 0
    li      a7, 14              // ChannelCall
    ecall
    bltz    a0, 92f

    lwu     s0, 8(sp)           // the handle the *kernel* chose, not a constant
    mv      a0, s0
    li      a7, 1               // DebugWrite — report 0: which handle arrived
    ecall

    li      t0, 32
    sw      t0, 112(sp)         // MapDeviceArgs.size
    li      t0, 1
    sw      t0, 116(sp)         // version
    sd      zero, 120(sp)       // flags
    sw      s0, 128(sp)         // device — the handle just reported to us
    sw      zero, 132(sp)       // reserved
    li      t0, 0x33000000
    sd      t0, 136(sp)         // vaddr = USER_MMIO_VA
    addi    a0, sp, 112
    li      a7, 23              // MapDevice
    ecall
    bltz    a0, 92f

    lwu     a1, 0(a0)           // MAGIC_VALUE
    lwu     a2, 8(a0)           // DEVICE_ID
    slli    a2, a2, 32
    or      a0, a1, a2
    li      a7, 1               // DebugWrite — report 1: what the device says
    ecall

    li      a0, 0
    li      a7, 5
    ecall
    unimp
92:
    li      a7, 1
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl grant_driver_blob_end
grant_driver_blob_end:
"#
);

// SAFETY: declares the blobs' bounding symbols, defined above.
unsafe extern "C" {
    static grant_manager_blob_start: u8;
    static grant_manager_blob_end: u8;
    static grant_driver_blob_start: u8;
    static grant_driver_blob_end: u8;
}

/// Builds one process for the capability-transfer check: its own root, its
/// program, stacks, and the handles boot grants it. `device` is `Some` only
/// for the manager — the driver's whole point is that it starts without one.
#[allow(clippy::too_many_arguments)]
fn grant_spawn_process(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blob: &[u8],
    kstack_va: u64,
    asid: u16,
    endpoint_object: kcore::object::ObjectId,
    device: Option<kcore::object::ObjectId>,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = kernel_space.new_user(frames, asid).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(asid), 0);

    user_space
        .map_anonymous(
            VirtAddr::new(GRANT_USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| base_err + 1)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(GRANT_USER_CODE_VA))
        .map(|(frame, _)| frame)
        .ok_or(base_err + 2)?;
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(GRANT_USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down (it owns no tables).
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(kstack_va),
        VirtAddr::new(GRANT_USER_CODE_VA),
        0,
        VirtAddr::new(GRANT_USER_STACK_VA),
        1,
        VirtAddr::new(kstack_va),
        IPC_KSTACK_PAGES,
        endpoint_object,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| base_err + 3)?;
    if user_space
        .arch()
        .translate(VirtAddr::new(kstack_va))
        .is_none()
    {
        return Err(base_err + 4);
    }

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 5)?
            .add_thread(thread)
            .map_err(|_| base_err + 6)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(endpoint_object, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 7)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_idx).map_err(|_| base_err + 8)?;
            // Handle 0 in every fresh table: the endpoint.
            process
                .handles_mut()
                .install(endpoint_object, Rights::READ | Rights::WRITE)
                .map_err(|_| base_err + 9)?;
            if device.is_none() {
                // The driver's slot 1 is given a *history* before the device
                // arrives in it: a placeholder capability is installed and
                // taken away again, which bumps the slot's generation.
                //
                // This is not scene-setting. A handle is an index **and** a
                // generation, so the value the driver is about to be told is
                // `(1 << 16) | 1`, not `1` — a number no program could have
                // arrived at by counting install order, and one that a program
                // guessing "the device will be handle 1" fails the generation
                // check on. It is also the ordinary case rather than a
                // contrived one: any table that has ever held a capability in
                // a slot behaves this way, which is precisely why D94 had to
                // add the installed-handle report at all.
                let placeholder = kcore::object::ObjectId::from_raw(43);
                let handle = process
                    .handles_mut()
                    .install(placeholder, Rights::TRANSFER)
                    .map_err(|_| base_err + 12)?;
                process
                    .handles_mut()
                    .take(handle)
                    .map_err(|_| base_err + 13)?;
            }
            if let Some(device) = device {
                // Handle 1, the manager's only: the device. **TRANSFER** is
                // what makes it giveable — handing a capability on is itself
                // a right, and without it `take` refuses (D91 learned this
                // the hard way).
                let handle = process
                    .handles_mut()
                    .install(device, Rights::READ | Rights::MAP | Rights::TRANSFER)
                    .map_err(|_| base_err + 10)?;
                if handle.raw() != GRANT_DEVICE_HANDLE {
                    // The program names this number, so it is checked rather
                    // than assumed to fall out of install order.
                    return Err(base_err + 11);
                }
            }
        }
    }
    Ok((thread_idx, proc_idx))
}

/// One process hands a device capability to another over a channel, and the
/// receiver uses it.
///
/// This is the last mechanism a driver framework needs: until now a device
/// could only be granted by **boot**, which is a shared constant wearing a
/// capability's clothes. Three separate things are proven, and the third is
/// the one that makes it a *transfer* rather than a copy:
///
/// 1. The driver starts with no device and ends up mapping one.
/// 2. It learns the handle number **from the kernel**, in the installed-handle
///    report — it cannot have agreed on one in advance, because the handle did
///    not exist until the receive installed it.
/// 3. The manager no longer holds the capability afterwards. The reference is
///    conserved, so "one driver per device" is arithmetic rather than policy.
///
/// Returns `(the handle the driver was given, the packed magic|device-id it
/// then read through it)`.
fn grant_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    window: u64,
) -> Result<(u64, u64), u32> {
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let device_obj = kcore::object::ObjectId::from_raw(40);
    substrate_exec()
        .device_register_mmio(
            device_obj,
            window,
            FRAME_SIZE,
            kcore::rights::Rights::READ
                | kcore::rights::Rights::MAP
                | kcore::rights::Rights::TRANSFER,
        )
        .map_err(|_| 1u32)?;

    let (server_ep, client_ep) = substrate_exec().channel_create().map_err(|_| 2u32)?;
    let manager_obj = kcore::object::ObjectId::from_raw(41);
    let driver_obj = kcore::object::ObjectId::from_raw(42);
    substrate_exec().bind_endpoint_object(server_ep, manager_obj);
    substrate_exec().bind_endpoint_object(client_ep, driver_obj);

    // SAFETY: linker-provided bounds of the read-only blobs above.
    let (manager_blob, driver_blob) = unsafe {
        (
            core::slice::from_raw_parts(
                &raw const grant_manager_blob_start,
                (&raw const grant_manager_blob_end as usize)
                    - (&raw const grant_manager_blob_start as usize),
            ),
            core::slice::from_raw_parts(
                &raw const grant_driver_blob_start,
                (&raw const grant_driver_blob_end as usize)
                    - (&raw const grant_driver_blob_start as usize),
            ),
        )
    };

    // The manager first, so it is parked in `receive` before the driver calls.
    let (manager_idx, manager_proc) = grant_spawn_process(
        kernel_space,
        frames,
        manager_blob,
        GRANT_MANAGER_KSTACK_VA,
        GRANT_MANAGER_ASID,
        manager_obj,
        Some(device_obj),
        10,
    )?;
    let (driver_idx, driver_proc) = grant_spawn_process(
        kernel_space,
        frames,
        driver_blob,
        GRANT_DRIVER_KSTACK_VA,
        GRANT_DRIVER_ASID,
        driver_obj,
        None,
        30,
    )?;

    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // SAFETY: the sole user-pointer path validates the range first.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);

    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(50);
    }
    let reports = REPORT_COUNT.load(Ordering::SeqCst);
    if reports != 2 {
        if reports == 1 {
            kprintln!(
                "grant: a program reported {} and stopped",
                REPORTS[0].load(Ordering::SeqCst) as i64
            );
        }
        return Err(51);
    }

    // 1. The driver was told a handle number it could not have guessed. Not
    //    its endpoint, and — the sharper part — carrying a **non-zero
    //    generation**, so it is not any value install order alone produces. A
    //    program that assumed "the device will be handle 1" would fail the
    //    generation check in `lookup`, which the negative check confirms.
    let installed = REPORTS[0].load(Ordering::SeqCst);
    if installed == GRANT_ENDPOINT_HANDLE || installed >> 16 == 0 {
        return Err(52);
    }
    // 2. Reading through that handle reached the real device.
    let packed = REPORTS[1].load(Ordering::SeqCst);
    let (kernel_magic, kernel_id) = virtio_identity(window);
    if packed & 0xffff_ffff != u64::from(kernel_magic)
        || packed >> 32 != u64::from(kernel_id)
        || kernel_magic != tessera_virtio::MAGIC
    {
        return Err(53);
    }
    // 3. The capability *moved*. The driver holds it and the manager does not,
    //    which is what makes one-driver-per-device conservation rather than
    //    policy — and is checked on both sides, because "the driver has it"
    //    alone would also be true of a copy.
    // SAFETY: transient raw access to the static process table; the run is
    // over and no thread is on CPU.
    let (driver_holds, manager_holds) = unsafe {
        let table = &*(&raw const KCORE_PROCESSES);
        (
            table
                .get(driver_proc)
                .is_some_and(|p| p.handles().holds(device_obj)),
            table
                .get(manager_proc)
                .is_some_and(|p| p.handles().holds(device_obj)),
        )
    };
    if !driver_holds || manager_holds {
        return Err(54);
    }

    // SAFETY: transient raw access; both threads are Exited and off-CPU, and
    // each process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
        for proc_idx in [driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for base in [GRANT_MANAGER_KSTACK_VA, GRANT_DRIVER_KSTACK_VA] {
        for page in 0..IPC_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((installed, packed))
}

// ---------------------------------------------------------------------------
// Ring-3 interrupt delivery: a driver parks on its device's line
// ---------------------------------------------------------------------------

/// The real-time clock's `compatible`. Chosen as this check's device for a
/// reason that is about capabilities rather than convenience: the kernel owns
/// the UART and drives the timer itself, so either would have put two owners
/// on one device — exactly what the model forbids — while the virtio slots on
/// this machine have no backend and so never interrupt. The RTC is the one
/// interrupt source nothing else here claims.
const RTC_COMPATIBLE: &[u8] = b"google,goldfish-rtc";

/// Goldfish RTC registers. Reading `TIME_LOW` latches the high half, and
/// writing `ALARM_LOW` is what arms the alarm — so the write order below is
/// load-bearing, not stylistic.
mod rtc {
    pub const TIME_LOW: usize = 0x00;
    pub const TIME_HIGH: usize = 0x04;
    pub const ALARM_LOW: usize = 0x08;
    pub const ALARM_HIGH: usize = 0x0c;
    pub const IRQ_ENABLED: usize = 0x10;
    pub const CLEAR_INTERRUPT: usize = 0x1c;
}

/// How far ahead the driver sets each alarm. Long enough that arming cannot
/// race its own `PortWait`, short enough that two rounds cost no visible time.
const RTC_ALARM_DELAY_NS: u64 = 10_000_000;
/// Interrupts the driver waits for. **Two**, and that is the whole design of
/// this check: one interrupt proves delivery, but only a second one proves
/// `IrqComplete` re-armed the line the kernel masked on the first.
const IRQ_ROUNDS: u64 = 2;

const IRQ_USER_CODE_VA: u64 = 0x1500_0000;
const IRQ_USER_STACK_VA: u64 = 0x2500_0000;
const IRQ_USER_MMIO_VA: u64 = 0x3500_0000;
const IRQ_DRIVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbd00_0000;
const IRQ_DRIVER_ASID: u16 = 9;

/// Handles boot installs: the device, then the port it is wired to.
const IRQ_DEVICE_HANDLE: u32 = 0;
const IRQ_PORT_HANDLE: u32 = 1;

/// The PLIC source the bridge below is currently wired to (0 = none). Set
/// strictly around the driver's run, so the bridge can never touch the
/// executive while the boot context is inside it.
static WIRED_INTID: AtomicU32 = AtomicU32::new(0);
/// Interrupts the bridge actually delivered, counted in the kernel so the
/// driver's account of events can be checked against one it did not write.
static IRQ_DELIVERED: AtomicU64 = AtomicU64::new(0);

/// The device-interrupt bridge: kernel side of the mask-on-deliver protocol.
///
/// Runs in interrupt context. It **masks the line** before signalling, which
/// is what makes a level-triggered source safe: the trap path completes the
/// PLIC claim unconditionally, so without masking the same still-asserted
/// device would re-interrupt immediately and forever. The driver acknowledges
/// the device through its own mapped window and then calls `IrqComplete`,
/// which is the only thing that re-enables the line.
fn rtc_irq_hook(source: u32) -> bool {
    let wired = WIRED_INTID.load(Ordering::SeqCst);
    if wired == 0 || source != wired {
        return false;
    }
    // SAFETY: masking a PLIC source is an interrupt-controller register write
    // with no memory-model footprint.
    unsafe { tessera_karch_riscv64::disable_irq(source) };
    IRQ_DELIVERED.fetch_add(1, Ordering::SeqCst);
    substrate_exec().port_signal(u64::from(source), 1, 1);
    true
}

/// virtio-mmio as the kernel core's device-reset seam
/// (`kcore::devmgr::DeviceResetter`) — ladder step 5.
///
/// The same class this port's devices are, and the same reason it can be
/// implemented honestly: a virtio transport is reset by writing zero to its
/// `Status` register, and re-reading the register as zero is the device saying
/// it has dropped every negotiated feature and queue configuration. Anything
/// else is a refusal — see the AArch64 twin for why an `Ok` from a resetter
/// that touched nothing is worse than no reset at all.
struct VirtioMmioResetter;

const VIRTIO_MMIO_MAGIC: u64 = 0x000;
const VIRTIO_MMIO_STATUS: u64 = 0x070;
const VIRTIO_MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

impl kcore::devmgr::DeviceResetter for VirtioMmioResetter {
    fn reset(
        &mut self,
        _device: kcore::object::ObjectId,
        identity: Option<kcore::devmgr::DeviceIdentity>,
        window: Option<(u64, u64)>,
    ) -> Result<(), tessera_karch::KError> {
        use tessera_karch::KError;
        if identity.is_some() {
            return Err(KError::NotSupported);
        }
        let (base, len) = window.ok_or(KError::NotSupported)?;
        if len <= VIRTIO_MMIO_STATUS {
            return Err(KError::InvalidMapping);
        }
        // The graph holds physical addresses; this port reaches them through
        // the direct map, which covers all of RAM and the device range.
        let at = DIRECT_MAP_BASE + base;
        // SAFETY: the window comes from the resource graph, so it is a real
        // device window the direct map covers, and both offsets are inside the
        // length it recorded (checked above).
        let magic =
            unsafe { tessera_karch_riscv64::mmio_read32((at + VIRTIO_MMIO_MAGIC) as usize) };
        if magic != VIRTIO_MMIO_MAGIC_VALUE {
            return Err(KError::NotSupported);
        }
        // SAFETY: as above.
        unsafe { tessera_karch_riscv64::mmio_write32((at + VIRTIO_MMIO_STATUS) as usize, 0) };
        // SAFETY: as above. Read back, or a reset the hardware ignored would
        // be recorded as one that worked.
        let status =
            unsafe { tessera_karch_riscv64::mmio_read32((at + VIRTIO_MMIO_STATUS) as usize) };
        if status != 0 {
            return Err(KError::InvalidMapping);
        }
        Ok(())
    }
}

/// A blank crash dump, for supervisors to fill.
const CRASH_DUMP_TEMPLATE: kcore::supervise::CrashDump = kcore::supervise::CrashDump {
    process: kcore::object::ObjectId::from_raw(0),
    cause: 0,
    address: 0,
    correlation: 0,
    captured: 0,
    trace: [kcore::event::KernelEvent {
        size: 0,
        version: 0,
        flags: 0,
        kind: kcore::event::EventKind::EventsDropped,
        severity: kcore::event::Severity::Info,
        component: kcore::event::Component::Driver,
        classification: kcore::event::Classification::Public,
        timestamp: 0,
        thread_id: 0,
        process_id: 0,
        correlation_lo: 0,
        correlation_hi: 0,
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
    }; kcore::supervise::CRASH_TRACE_TAIL],
};

/// The PLIC as the kernel core's interrupt-revocation seam
/// (`kcore::devmgr::InterruptRouter`).
///
/// Zero-sized: the controller is a fixed set of registers this port already
/// knows how to reach. It exists as a type solely because the kernel core must
/// not name a PLIC.
struct PlicRouter;

impl kcore::devmgr::InterruptRouter for PlicRouter {
    fn mask(&mut self, source: u32) {
        // SAFETY: masking a PLIC source is an interrupt-controller register
        // write with no memory-model footprint, valid from any context.
        unsafe { tessera_karch_riscv64::disable_irq(source) };
    }
}

/// `IrqComplete`: re-enable the line of the device the caller names.
///
/// Port-local rather than a `kcore::dispatch` arm because re-arming is an
/// interrupt-controller write, and the controller is the one thing a port
/// cannot share (D79's class of exception, as on AArch64). The authority is
/// not: the caller must hold a capability to the device with `Rights::MAP`,
/// and the INTID comes from the resource graph rather than from the caller.
fn irq_complete(caller: usize, args_ptr: u64) -> i64 {
    use kcore::rights::Rights;
    use kcore::syscall::{
        IRQ_COMPLETE_ARGS_SIZE, decode_irq_complete_args, encode_result, read_user,
    };
    use tessera_karch::KError;

    let object = {
        // SAFETY: transient raw access to the static process table.
        let processes = unsafe { &mut *(&raw mut KCORE_PROCESSES) };
        let Some(process) = processes.process_of_thread(caller) else {
            return encode_result(Err(KError::AccessDenied));
        };
        let mut abuf = [0u8; IRQ_COMPLETE_ARGS_SIZE];
        if let Err(e) = read_user(process, args_ptr, &mut abuf) {
            return encode_result(Err(e));
        }
        let handle = match decode_irq_complete_args(&abuf) {
            Ok(handle) => handle,
            Err(e) => return encode_result(Err(e)),
        };
        match process.handles().lookup(handle) {
            Ok((object, rights)) => {
                if !rights.contains(Rights::MAP) {
                    return encode_result(Err(KError::AccessDenied));
                }
                object
            }
            Err(e) => return encode_result(Err(e)),
        }
    };
    let Some(intid) = substrate_exec().intid_of_object(object) else {
        return encode_result(Err(KError::AccessDenied));
    };
    // SAFETY: enabling a PLIC source is an interrupt-controller register
    // write; the caller proved authority over the device it belongs to.
    unsafe { tessera_karch_riscv64::enable_irq(intid) };
    encode_result(Ok(0))
}

// The ring-3 driver. Maps its device by capability, then twice over: arm the
// alarm, park on the port until the device interrupts, acknowledge the device,
// and re-arm the line.
//
// Stack: MapDeviceArgs at sp+0, the PortEventRecord the kernel fills at sp+32,
// IrqCompleteArgs at sp+64.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl irq_driver_blob_start
irq_driver_blob_start:
    addi    sp, sp, -128
    li      t0, 32
    sw      t0, 0(sp)           // MapDeviceArgs.size
    li      t0, 1
    sw      t0, 4(sp)           // version
    sd      zero, 8(sp)         // flags
    sw      zero, 16(sp)        // device — handle 0
    sw      zero, 20(sp)        // reserved
    li      t0, 0x35000000
    sd      t0, 24(sp)          // vaddr = IRQ_USER_MMIO_VA
    mv      a0, sp
    li      a7, 23              // MapDevice
    ecall
    bltz    a0, 93f
    mv      s1, a0              // the RTC's register base

    li      s2, 2               // rounds
1:
    // Arm the alarm. Reading TIME_LOW latches the high half, and writing
    // ALARM_LOW is what arms — so this order is required.
    lwu     t0, 0(s1)           // TIME_LOW
    lwu     t1, 4(s1)           // TIME_HIGH
    slli    t1, t1, 32
    or      t0, t0, t1          // now, in nanoseconds
    li      t2, 10000000
    add     t0, t0, t2          // now + RTC_ALARM_DELAY_NS
    li      t3, 1
    sw      t3, 16(s1)          // IRQ_ENABLED = 1
    srli    t1, t0, 32
    sw      t1, 12(s1)          // ALARM_HIGH
    sw      t0, 8(s1)           // ALARM_LOW — arms

    // Park until the device interrupts. Nothing else is runnable, so the
    // kernel's boot context is what waits for the line.
    li      a0, 1               // the port handle
    addi    a1, sp, 32          // where the kernel writes the event record
    li      a7, 18              // PortWait
    ecall
    bltz    a0, 93f

    ld      a0, 48(sp)          // PortEventRecord.source (record + 16)
    li      a7, 1               // DebugWrite — which line woke us
    ecall

    // Acknowledge the device itself, before asking for the line back.
    li      t0, 1
    sw      t0, 28(s1)          // CLEAR_INTERRUPT

    li      t0, 24
    sw      t0, 64(sp)          // IrqCompleteArgs.size
    li      t0, 1
    sw      t0, 68(sp)          // version
    sd      zero, 72(sp)        // flags
    sw      zero, 80(sp)        // device — handle 0
    sw      zero, 84(sp)        // reserved
    addi    a0, sp, 64
    li      a7, 26              // IrqComplete — re-arm the masked line
    ecall
    bltz    a0, 93f

    addi    s2, s2, -1
    bnez    s2, 1b

    li      a0, 0
    li      a7, 5               // ProcessExit
    ecall
    unimp
93:
    li      a7, 1               // report the refusal rather than pressing on
    ecall
    li      a0, 0
    li      a7, 5
    ecall
    unimp
.globl irq_driver_blob_end
irq_driver_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined above.
unsafe extern "C" {
    static irq_driver_blob_start: u8;
    static irq_driver_blob_end: u8;
}

/// A ring-3 driver parks on its device's interrupt and is woken by the device.
///
/// The last mechanism this port was missing. Everything before it let a driver
/// *reach* a device; this lets it stop spinning on one. The protocol is
/// mask-on-deliver: the kernel masks the line before signalling the driver's
/// port, and only the driver's `IrqComplete` — authorised by its capability to
/// the device — puts the line back. That is why the driver waits **twice**: a
/// single interrupt would prove delivery while saying nothing about whether
/// the line was ever restored.
///
/// Returns `(the line the driver was woken on, how many interrupts the kernel
/// delivered)`.
fn irq_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    device: tessera_devicetree::MmioDevice,
) -> Result<(u64, u64), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    let Some(intid) = device.intid else {
        // The device tree did not name a line for this device. Refusing beats
        // guessing one: a wrong number is an interrupt that never arrives.
        return Err(1);
    };

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let device_obj = kcore::object::ObjectId::from_raw(50);
    let port_obj = kcore::object::ObjectId::from_raw(51);
    substrate_exec()
        .device_register_mmio(
            device_obj,
            device.base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 2u32)?;
    // The INTID enters the resource graph beside the window, so `IrqComplete`
    // can find it from the capability. The driver never names a line number.
    substrate_exec()
        .device_set_mmio_irq(device_obj, intid)
        .map_err(|_| 3u32)?;

    // The IRQ→port bridge, recorded in the graph as a **route** rather than
    // installed as a bare port binding. A bare binding is a fact only the boot
    // glue knows, so nothing takes it down when the driver goes: the line
    // keeps firing into a port whose holder no longer exists. Routing it makes
    // the interrupt follow the capability the way the register window already
    // does. The holder is `device_obj`, which is also this check's driver
    // process object (`Process::new(device_obj, ..)` below).
    let port = substrate_exec().port_create().map_err(|_| 4u32)?;
    substrate_exec().bind_port_object(port, port_obj);
    substrate_exec()
        .device_route_irq(device_obj, port, device_obj)
        .map_err(|_| 5u32)?;

    // SAFETY: linker-provided bounds of the read-only blob above.
    let blob = unsafe {
        core::slice::from_raw_parts(
            &raw const irq_driver_blob_start,
            (&raw const irq_driver_blob_end as usize) - (&raw const irq_driver_blob_start as usize),
        )
    };

    let user_arch = kernel_space
        .new_user(frames, IRQ_DRIVER_ASID)
        .map_err(|_| 6u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(IRQ_DRIVER_ASID), 0);
    user_space
        .map_anonymous(
            VirtAddr::new(IRQ_USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 7u32)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(IRQ_USER_CODE_VA))
        .map(|(frame, _)| frame)
        .ok_or(8u32)?;
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(IRQ_USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down.
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(IRQ_DRIVER_KSTACK_VA),
        VirtAddr::new(IRQ_USER_CODE_VA),
        0,
        VirtAddr::new(IRQ_USER_STACK_VA),
        1,
        VirtAddr::new(IRQ_DRIVER_KSTACK_VA),
        IPC_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 9u32)?;

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(10u32)?
            .add_thread(thread)
            .map_err(|_| 11u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 12u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_idx).map_err(|_| 13u32)?;
            let device_handle = process
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 14u32)?;
            let port_handle = process
                .handles_mut()
                .install(port_obj, Rights::READ)
                .map_err(|_| 15u32)?;
            // The program names both numbers, so both are checked rather than
            // assumed to fall out of install order.
            if device_handle.raw() != IRQ_DEVICE_HANDLE || port_handle.raw() != IRQ_PORT_HANDLE {
                return Err(16);
            }
        }
    }

    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);
    IRQ_DELIVERED.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // SAFETY: the sole user-pointer path validates the range first.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);
    tessera_karch_riscv64::set_device_irq_hook(rtc_irq_hook);
    // SAFETY: the PLIC source is the one the device tree named for this
    // device, and the bridge is armed for exactly the window below.
    unsafe { tessera_karch_riscv64::enable_irq(intid) };
    WIRED_INTID.store(intid, Ordering::SeqCst);

    // The pump. The driver runs until it parks on its port, at which point
    // nothing is runnable and `run` returns here — so the kernel's own boot
    // context is what waits for the line.
    //
    // Interrupts are unmasked **only** across the `wfi`, which is the whole
    // discipline: the bridge touches the executive, so it must never fire
    // while this context is inside `run`. In U-mode the architecture delivers
    // supervisor interrupts regardless of `sstatus.SIE`, and that is safe for
    // the opposite reason — the kernel is not in the executive then either.
    //
    // `wfi` returns whether or not an interrupt was taken, so unmasking has to
    // happen every iteration rather than once outside the loop.
    // The periodic tick runs across the pump, and it is load-bearing rather
    // than scenery: `wfi` sleeps until *some* interrupt arrives, so without a
    // heartbeat a device line that never comes back leaves this loop asleep
    // forever and the bound below is never evaluated. The first version of
    // this check had exactly that bug — its negative checks timed out instead
    // of failing, which is the failure mode the bound exists to prevent. It is
    // also what a real system looks like: a driver parked on its device
    // coexists with the scheduler's tick.
    <SupervisorTimer as tessera_karch::TimerControl>::start_periodic(TICK_HZ);
    let mut pumps = 0u64;
    const PUMP_LIMIT: u64 = 200;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if REPORT_COUNT.load(Ordering::SeqCst) >= IRQ_ROUNDS
            || USER_FAULT.load(Ordering::SeqCst) != 0
        {
            break;
        }
        if pumps >= PUMP_LIMIT {
            // Bounded, so a line that never comes back is a verdict rather
            // than a hang — which is the whole reason the bound exists, and
            // is worth getting numerically right: `wfi` returns on the 100 Hz
            // tick whether or not the device interrupted, so the limit is a
            // count of *ticks*, and a large-looking number here is seconds of
            // silence. Two seconds is far longer than the alarm's 10 ms and
            // far shorter than any test timeout.
            break;
        }
        <Cpu as tessera_karch::InterruptControl>::enable();
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
        pumps += 1;
    }

    tessera_karch_riscv64::stop_timer();
    WIRED_INTID.store(0, Ordering::SeqCst);
    // SAFETY: masking the line the check armed, now that nothing serves it.
    unsafe { tessera_karch_riscv64::disable_irq(intid) };
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(20);
    }
    let reports = REPORT_COUNT.load(Ordering::SeqCst);
    if reports != IRQ_ROUNDS {
        if reports == 1 {
            kprintln!(
                "irq: only one wake — the line was masked on delivery and never came back ({})",
                REPORTS[0].load(Ordering::SeqCst) as i64
            );
        }
        return Err(21);
    }
    // Every wake names the line the device tree gave this device. The driver
    // never learned that number any other way — it is in the event record the
    // kernel wrote, not in the program.
    for slot in REPORTS.iter().take(IRQ_ROUNDS as usize) {
        let reported = slot.load(Ordering::SeqCst);
        if reported != u64::from(intid) {
            // Printed as signed, because the program reports a refused
            // syscall's code through the same path — so this line
            // distinguishes "woken on the wrong line" from "a syscall it
            // needed was denied".
            kprintln!("irq: a wake reported {}, not line {intid}", reported as i64);
            return Err(22);
        }
    }
    // And the kernel's own count agrees, which the driver could not have
    // arranged: it is incremented in interrupt context.
    let delivered = IRQ_DELIVERED.load(Ordering::SeqCst);
    if delivered != IRQ_ROUNDS {
        return Err(23);
    }

    // SAFETY: transient raw access; the thread is Exited and off-CPU, and the
    // process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for page in 0..IPC_KSTACK_PAGES {
        if let Ok(frame) =
            kernel_alias.unmap(VirtAddr::new(IRQ_DRIVER_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }

    Ok((u64::from(intid), delivered))
}

// ---------------------------------------------------------------------------
// The real thing: a compiled ring-3 driver reads a disk
// ---------------------------------------------------------------------------

/// The driver's ELF, embedded by the Bazel build. The cargo inner loop builds
/// the kernel without it and the check says so rather than pretending.
#[cfg(has_ring3_driver)]
fn blk_driver_elf() -> &'static [u8] {
    &blk_driver_image::BLK_DRIVER_ELF
}
#[cfg(not(has_ring3_driver))]
fn blk_driver_elf() -> &'static [u8] {
    &[]
}

/// The magic sector 0 of the test disk carries. The driver reports the eight
/// bytes it read; this is what they must be.
const DISK_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");

const BLK_DRIVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xba00_0000;
/// The driver is compiled Rust with a real call stack, not a blob: four pages
/// of user stack, and eight of kernel stack because a blocking `PortWait`
/// parks a whole dispatch frame on it.
const BLK_DRIVER_USER_STACK_PAGES: u64 = 4;
const BLK_DRIVER_KSTACK_PAGES: u64 = 8;
const BLK_DRIVER_USER_STACK_VA: u64 = 0x3000_0000;
const BLK_DRIVER_ASID: u16 = 10;

/// Loads a user ELF into `user_space` and returns its entry point.
///
/// Each segment is mapped writable, filled, then narrowed to what it declared
/// — so a page is never both writable and executable, not even briefly during
/// loading. A segment that asks to be both is refused outright rather than
/// having one of the two quietly dropped.
fn load_user_elf(
    image: &[u8],
    user_space: &mut kcore::vm::AddressSpace<tessera_karch_riscv64::KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<u64, u32> {
    use kcore::elf;
    use tessera_karch::AddressSpaceOps;

    let parsed = elf::parse(image, elf::Machine::RiscV64).map_err(|_| base_err)?;
    for segment in parsed.segments() {
        if segment.write && segment.exec {
            return Err(base_err + 1);
        }
        let vaddr = VirtAddr::new(segment.vaddr);
        if segment.vaddr % FRAME_SIZE != 0
            || segment.vaddr
                >= <tessera_karch_riscv64::KernelAddressSpace as AddressSpaceOps>::USER_ADDRESS_MAX
        {
            return Err(base_err + 2);
        }
        let len = segment.mem_size.div_ceil(FRAME_SIZE) * FRAME_SIZE;
        user_space
            .map_anonymous(vaddr, len, PageFlags::rw().user(), frames)
            .map_err(|_| base_err + 3)?;
        let end = (segment.file_offset + segment.file_size) as usize;
        if end > image.len() {
            return Err(base_err + 4);
        }
        user_space
            .copy_in(vaddr, &image[segment.file_offset as usize..end])
            .map_err(|_| base_err + 5)?;
        let rights = if segment.exec {
            PageFlags::rx().user()
        } else {
            PageFlags::rw().user()
        };
        user_space
            .protect_range(vaddr, len, rights)
            .map_err(|_| base_err + 6)?;
        if segment.exec {
            user_space.arch().sync_instruction_cache(vaddr, len);
        }
    }
    Ok(parsed.entry())
}

/// A compiled ring-3 driver reads sector 0 of a real disk.
///
/// Every previous milestone on this port ran a hand-written blob, which proves
/// a mechanism but not that the mechanisms compose into something a person
/// would write. This runs an ELF built from ordinary Rust that reuses
/// `tessera-virtio` **unchanged** — the same transport core the AArch64 driver
/// and the in-kernel proof use — and its only privileged actions are the
/// syscalls the last five milestones added.
///
/// Returns the eight bytes it read from the disk.
fn blk_driver_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    device: tessera_devicetree::MmioDevice,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    let image = blk_driver_elf();
    if image.is_empty() {
        return Err(1);
    }
    let Some(intid) = device.intid else {
        return Err(2);
    };

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let device_obj = kcore::object::ObjectId::from_raw(60);
    let port_obj = kcore::object::ObjectId::from_raw(61);
    substrate_exec()
        .device_register_mmio(
            device_obj,
            device.base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 3u32)?;
    substrate_exec()
        .device_set_mmio_irq(device_obj, intid)
        .map_err(|_| 4u32)?;
    // A route, not a bare binding — see the identical wiring in the blob-based
    // IRQ check above for why the graph has to know who is receiving this.
    let port = substrate_exec().port_create().map_err(|_| 5u32)?;
    substrate_exec().bind_port_object(port, port_obj);
    substrate_exec()
        .device_route_irq(device_obj, port, device_obj)
        .map_err(|_| 6u32)?;

    let user_arch = kernel_space
        .new_user(frames, BLK_DRIVER_ASID)
        .map_err(|_| 7u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(BLK_DRIVER_ASID), 0);
    let entry = load_user_elf(image, &mut user_space, frames, 10)?;

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down.
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(BLK_DRIVER_KSTACK_VA),
        VirtAddr::new(entry),
        0,
        VirtAddr::new(BLK_DRIVER_USER_STACK_VA),
        BLK_DRIVER_USER_STACK_PAGES,
        VirtAddr::new(BLK_DRIVER_KSTACK_VA),
        BLK_DRIVER_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 20u32)?;

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(21u32)?
            .add_thread(thread)
            .map_err(|_| 22u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 23u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_idx).map_err(|_| 24u32)?;
            // Exactly the authority the driver needs and no more: the device
            // it drives, and the port its interrupt arrives on.
            process
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 25u32)?;
            process
                .handles_mut()
                .install(port_obj, Rights::READ)
                .map_err(|_| 26u32)?;
        }
    }

    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);
    IRQ_DELIVERED.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // SAFETY: the sole user-pointer path validates the range first.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);
    tessera_karch_riscv64::set_device_irq_hook(rtc_irq_hook);
    // SAFETY: the PLIC source is the one the device tree named for this device.
    unsafe { tessera_karch_riscv64::enable_irq(intid) };
    WIRED_INTID.store(intid, Ordering::SeqCst);

    // The same pump as the interrupt check, and for the same reason: the
    // driver parks on its device, so the kernel's boot context is what waits
    // for the line. The tick is what makes the bound below reachable.
    <SupervisorTimer as tessera_karch::TimerControl>::start_periodic(TICK_HZ);
    let mut pumps = 0u64;
    const PUMP_LIMIT: u64 = 500;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if REPORT_COUNT.load(Ordering::SeqCst) > 0 || USER_FAULT.load(Ordering::SeqCst) != 0 {
            break;
        }
        if pumps >= PUMP_LIMIT {
            break;
        }
        <Cpu as tessera_karch::InterruptControl>::enable();
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
        pumps += 1;
    }
    tessera_karch_riscv64::stop_timer();
    WIRED_INTID.store(0, Ordering::SeqCst);
    // SAFETY: masking the line the check armed, now that nothing serves it.
    unsafe { tessera_karch_riscv64::disable_irq(intid) };
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(30);
    }
    if REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(31);
    }
    let reported = REPORTS[0].load(Ordering::SeqCst);
    if reported != DISK_MAGIC {
        // The driver reports a staged failure code rather than a wrong value
        // when something refuses it, so printing it names the stage.
        kprintln!("blk: the driver reported {reported:#018x}, not the disk magic");
        return Err(32);
    }
    // The read was interrupt-driven, not polled: the driver parked and the
    // kernel's own counter saw the device wake it.
    if IRQ_DELIVERED.load(Ordering::SeqCst) == 0 {
        return Err(33);
    }

    // SAFETY: transient raw access; the thread is Exited and off-CPU, and the
    // process is removed and torn down once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for page in 0..BLK_DRIVER_KSTACK_PAGES {
        if let Ok(frame) =
            kernel_alias.unmap(VirtAddr::new(BLK_DRIVER_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }

    Ok(reported)
}

// ---------------------------------------------------------------------------
// The driver framework: a device is bound by class, and survives its driver
// ---------------------------------------------------------------------------

/// The manager's and the probe's ELFs, embedded by the Bazel build.
#[cfg(has_ring3_driver)]
fn device_manager_elf() -> &'static [u8] {
    &device_manager_image_riscv64::DEVICE_MANAGER_ELF
}
#[cfg(not(has_ring3_driver))]
fn device_manager_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_driver)]
fn blk_probe_elf() -> &'static [u8] {
    &blk_probe_image_riscv64::BLK_PROBE_ELF
}
#[cfg(not(has_ring3_driver))]
fn blk_probe_elf() -> &'static [u8] {
    &[]
}

/// The user stack every framework program gets. Clear of its image at
/// 0x1000_0000 and of the probe windows `uabi::layout` puts at 0x3000_0000.
const REBIND_USER_STACK_VA: u64 = 0x2000_0000;
const REBIND_USER_STACK_PAGES: u64 = 4;
/// Kernel stacks, in the direct map's gigabyte slot (the D100 constraint).
/// Eight pages: a channel op parks a whole dispatch frame across the handoff.
const REBIND_MANAGER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb000_0000;
const REBIND_DRIVER1_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb100_0000;
const REBIND_DRIVER2_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb200_0000;
/// The crashing incarnations' window, **reused** across launches: supervision
/// here is synchronous, so one host is alive at a time and each crash's
/// reclaim frees the window before the next spawn takes it.
const REBIND_CRASH_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb300_0000;

/// How many times a persistently crashing host is brought back here, and the
/// deliberately smaller budget the give-up self-test runs against so that the
/// budget — not the driver running out of ways to fail — is what stops it.
const DRIVER_RESTART_BUDGET: u32 = kcore::supervise::DEFAULT_RESTART_BUDGET;
const DRIVER_RESTART_SELFTEST_BUDGET: u32 = 3;
/// This supervisor's give-up identity, so two supervisors giving up in one
/// boot stay distinguishable in the record stream.
const DRIVER_RESTART_GIVEUP_CODE: u64 = 179;

/// The startup-argument bit that asks `blk-probe` to crash once it holds its
/// device (`userspace/blk-probe`'s `CRASH_AFTER_BIND`).
///
/// Duplicated here rather than shared through `uabi` because it is a fact
/// about **one program's** entry contract, not about the ABI.
const BLK_PROBE_CRASH_AFTER_BIND: usize = 1 << 63;

/// Runs one host that is asked to crash, contains it, records the ladder's
/// first and sixth steps, and reclaims the corpse.
///
/// Returns whether the host actually faulted. `false` means it exited or never
/// got there, which the caller must treat as a failure rather than a recovery
/// — a supervisor that reports restarting a host that never crashed is
/// reporting work it did not do.
///
/// **The supervisor names no device.** `reclaim_devices` hands whatever the
/// corpse held back to the manager, which is what makes forgetting impossible
/// rather than merely unlikely.
#[allow(clippy::too_many_arguments)]
fn supervise_one_crash(
    supervisor: &mut kcore::supervise::RestartSupervisor,
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    asid: u16,
    proc_obj: kcore::object::ObjectId,
    device_obj: kcore::object::ObjectId,
    manager_client_obj: kcore::object::ObjectId,
    manager_client_ep: kcore::ipc::EndpointId,
    base_err: u32,
) -> Result<bool, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    USER_FAULT.store(0, Ordering::SeqCst);
    USER_FAULT_ADDR.store(0, Ordering::SeqCst);
    USER_FAULT_CORRELATION.store(0, Ordering::SeqCst);

    let (idx, proc) = spawn_elf_process(
        kernel_space,
        frames,
        blk_probe_elf(),
        REBIND_CRASH_KSTACK_VA,
        asid,
        BLK_PROBE_CRASH_AFTER_BIND,
        proc_obj,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table; the process
    // was just inserted and no thread of it has run.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(proc)
            .ok_or(base_err + 20)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| base_err + 20)?;
    }
    supervisor.launched();
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // Back to the kernel's own root before touching a process's tables — the
    // single-root hazard this file documents at every other `run` return.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    let cause = USER_FAULT.load(Ordering::SeqCst);
    if cause != 0 {
        let correlation = USER_FAULT_CORRELATION.load(Ordering::SeqCst);
        let address = USER_FAULT_ADDR.load(Ordering::SeqCst);
        // Ladder step 1. Adopt the dead host's cause before recording
        // anything, or the ladder roots a fresh trace and the restart cannot
        // be joined to the crash that provoked it.
        kcore::trace::set_current_correlation(correlation);
        supervisor.crashed(cause, address);

        // Ladder step 3: the dump, taken before the corpse is torn down and
        // before the ring fills with teardown records — the trail this is for
        // is the one leading up to the fault.
        let mut dump = CRASH_DUMP_TEMPLATE;
        kcore::supervise::capture_crash_dump(&mut dump, proc_obj, cause, address, correlation);

        // Steps 4 and 5. The supervisor does not know everything the driver
        // held — that is reclaim's job below, and the reason reclaim names
        // nothing — but it was asked to supervise a (driver, device) pair, and
        // these two rungs are about the device half of it.
        // SAFETY: transient raw access to the static executive; every thread
        // is off-CPU here.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.notify_dependents(
                    device_obj,
                    kcore::lifecycle::DriverState::Degraded,
                    kcore::lifecycle::TransitionReason::DriverCrashed,
                );
                let mut resetter = VirtioMmioResetter;
                let _ = exec.reset_device(
                    device_obj,
                    kcore::devmgr::ResetPolicy::OnDegraded,
                    Some(&mut resetter),
                );
            }
        }
    }

    // The free-list depth, not `handed_out`: the latter is cumulative and
    // never decreases, so a delta across a reclaim would always be zero.
    let free_before = frames.free_list_depth();
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(proc) {
                let mut router = PlicRouter;
                exec.reclaim_devices(dead, manager_client_ep, None, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(idx);
        if let Some(mut dead) = processes.remove(proc) {
            dead.space_mut().teardown(frames);
        }
    }

    // The kernel stack the corpse used goes back too, before the next launch
    // asks for the same window. Without this the second crashing incarnation
    // would fail to map its stack over a live mapping — the reason
    // supervision here is synchronous and one window can serve every launch.
    // The frames are freed, not merely unmapped: a leak here would show up in
    // the restart record's reclaimed count, which is exactly what that field
    // exists to make visible.
    use tessera_karch::FrameSource;
    // SAFETY: the alias owns no tables and is used only to unmap; the kernel
    // space is active and every thread of the corpse is off-CPU.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for page in 0..REBIND_KSTACK_PAGES {
        if let Ok(frame) =
            kernel_alias.unmap(VirtAddr::new(REBIND_CRASH_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }

    if cause != 0 {
        supervisor.restarted(frames.free_list_depth().saturating_sub(free_before) as u64);
    }
    // Cleared so the checks after this one do not read a deliberate crash as
    // their own failure.
    USER_FAULT.store(0, Ordering::SeqCst);
    USER_FAULT_ADDR.store(0, Ordering::SeqCst);
    Ok(cause != 0)
}
const REBIND_KSTACK_PAGES: u64 = 8;

/// What each incarnation of the probe reports: the transport's magic, rotated
/// by its incarnation number so the two runs cannot be mistaken for one value
/// written twice.
const REBIND_MAGIC: u64 = 0x7472_6976;

/// Builds one framework process from its ELF: a fresh space, loaded segments,
/// user and kernel stacks, and a thread registered on the shared executive.
/// Installs **no** handles — the caller grants each process exactly its
/// authority, which is the whole point of the exercise.
fn spawn_elf_process(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    image: &[u8],
    kstack_va: u64,
    asid: u16,
    arg: usize,
    process_obj: kcore::object::ObjectId,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = kernel_space.new_user(frames, asid).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(asid), 0);
    let entry = load_user_elf(image, &mut user_space, frames, base_err + 1)?;

    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // the kernel stack and is never torn down.
    let kernel_arch = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    let mut kernel_alias = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(kstack_va),
        VirtAddr::new(entry),
        arg,
        VirtAddr::new(REBIND_USER_STACK_VA),
        REBIND_USER_STACK_PAGES,
        VirtAddr::new(kstack_va),
        REBIND_KSTACK_PAGES,
        process_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| base_err + 8)?;

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 9)?
            .add_thread(thread)
            .map_err(|_| base_err + 9)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(process_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 10)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(process) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            process.add_thread(thread_idx).map_err(|_| base_err + 11)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// The device object the rebind check registers its block transport under.
/// Named because two checks depend on it being the same object: the rebind
/// grants it twice, and the event check asserts that the records say so.
const REBIND_DEVICE_OBJECT: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(70);

/// The driver framework's own records, drained and read back
/// (docs/drivers/01: "Transitions are observable through structured events";
/// build/README.md, D112).
///
/// Everything the rebind check above proves, it proves from values the boot
/// glue itself collected. This proves the same story from the **kernel's
/// records** — which is what a log service will have to work from, and what
/// nothing was checking. The two are independent: the check could pass while
/// the framework emitted nothing at all, which is exactly the state this port
/// was in before.
///
/// `device_obj` is the object the rebind granted twice; naming it makes the
/// central claim checkable rather than atmospheric — the *same* physical
/// transport was granted to a second driver, as the records tell it.
fn device_events_check(device_obj: kcore::object::ObjectId) {
    use kcore::event::{self, Component, EventKind, KernelEvent, Severity};
    const CAP: usize = event::EVENT_RING_CAPACITY;

    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );

    // Drops that happened *while the framework ran* — nothing on this port has
    // ever drained the ring, so this is the first time its occupancy has been
    // looked at. A non-zero count here means records were lost before anything
    // could read them, and the check must say so rather than assert past it.
    let dropped_during_boot = event::dropped();
    let mut drained = [blank; CAP];
    let n = event::drain(&mut drained);
    let summary = event::summarize_device_events(&drained[..n], kcore::trace::epoch());
    // The same records, read as the crash-recovery ladder. Read from *this*
    // drain rather than its own, because the ring is drained once per boot and
    // a second reader would find it empty — and because the two readings
    // describing the same run is the point: the rebind and the recovery that
    // made it necessary are one story.
    let ladder = event::summarize_driver_ladder(&drained[..n], kcore::trace::epoch());

    // The envelope every record must carry. The wire round-trip is not
    // repeated here: it is the same generated binding the x86-64 harness
    // encodes and decodes every boot, and adding an ISL-runtime dependency to
    // two more kernels would buy a second run of the same proof.
    let envelope_ok = drained[..n].iter().all(|e| {
        e.size == KernelEvent::WIRE_SIZE as u32 && e.version == event::EVENT_SCHEMA_VERSION
    });

    // The bound holds on this port too: overflow the ring, confirm the drops
    // are counted at the source, and that the next emission with room reports
    // them once (docs/observability/02, "Flood control").
    for _ in 0..(CAP as u32 + 8) {
        event::emit(
            EventKind::DeviceMapRefused,
            Severity::Debug,
            Component::Driver,
            [0; 4],
        );
    }
    let flood_dropped = event::dropped();
    let mut flood = [blank; CAP];
    let flooded = event::drain(&mut flood);
    event::emit(
        EventKind::DeviceMapRefused,
        Severity::Debug,
        Component::Driver,
        [0; 4],
    );
    let mut tail = [blank; CAP];
    let tail_n = event::drain(&mut tail);
    let bound_ok = flood_dropped == 8
        && flooded == CAP
        && tail[..tail_n]
            .iter()
            .any(|e| e.kind == EventKind::EventsDropped && e.arg0 == 8)
        && event::dropped() == 0;

    // One crash in the rebind check, plus one per launch of the give-up
    // self-test. Derived from the budget rather than written as a number, so
    // changing the budget cannot silently change what this asserts.
    let expected_crashes = 1 + DRIVER_RESTART_SELFTEST_BUDGET;
    let pass = dropped_during_boot == 0
        && envelope_ok
        && summary.describes_a_rebind(device_obj.raw())
        && ladder.describes_a_contained_ladder(expected_crashes)
        // The other four rungs — the ones a supervisor cannot climb alone: a
        // manager marking the device, a dump taken, dependents told, a reset
        // attempted. A system recording only the supervisor's three would be
        // running half a ladder and describing a whole one.
        && ladder.describes_the_full_ladder()
        // One supervisor gave up — the self-test's. The rebind check's did
        // not, and a run where both did would mean recovery never succeeded.
        && ladder.gave_up == 1
        // And the policy that answered the give-up stopped offering the
        // device, which is the enforcement behind quarantine rather than the
        // decision to quarantine.
        && ladder.quarantined == 1
        && bound_ok;

    if pass {
        kprintln!(
            "device-events: OK — the framework's own records tell the same story the check above told from its own counters ({} driver records: {} window-grant, {} window-revoke-on-transfer, {} dma-grant, {} device-reclaim): device {} was granted a register window {} times, which is the rebind — one driver held it, died, and the manager gave the same transport to another. The whole seven-step crash-recovery ladder is in the same records: {} contained crashes, each contained and dumped ({} trace records captured with them), {} device marked degraded by its manager, {} dependent service told, {} reset attempted, {} reclaim-and-rebind that recovered {} frames, and {} supervisor that spent its budget, gave up, and quarantined the device rather than respawning for ever. {} lifecycle transitions were recorded and every one of them followed the last, so the states join up end to end rather than merely each being plausible. Every record carries a live 128-bit cause from this boot's epoch; ring bounded at {} (8 dropped at the source, reported by one meta-event)",
            summary.records,
            summary.mapped,
            summary.revoked_on_transfer,
            summary.dma_granted,
            summary.reclaimed,
            device_obj.raw(),
            summary.grants_of(device_obj.raw()),
            ladder.crashed,
            ladder.crash_dump_records,
            ladder.degraded_marks,
            ladder.dependents_notified,
            ladder.resets,
            ladder.restarted,
            ladder.reclaimed_frames,
            ladder.gave_up,
            ladder.transitions,
            CAP
        );
    } else {
        kprintln!(
            "device-events: FAIL n={n} dropped_during_boot={dropped_during_boot} records={} envelope={} (no_timestamp={} no_correlation={} wrong_epoch={} no_thread={} first_bad_kind={}) wire={envelope_ok} mapped={} revoked={} dma={} grants_of_expected_device={} (want >= 2) unmap_errors={} unmatched_revokes={} grant_overflow={} reclaim_lost={} bound={bound_ok} ladder(crashed={} want={expected_crashes} restarted={} gave_up={} frames={} component={} severities={} stamped={} degraded={} dumps={} dump_records={} notified={} unreachable={} resets={} reset_failed={} quarantined={} transitions={} gaps={})",
            summary.records,
            summary.envelope_ok,
            summary.no_timestamp,
            summary.no_correlation,
            summary.wrong_epoch,
            summary.no_thread,
            summary.envelope_offender,
            summary.mapped,
            summary.revoked_on_transfer,
            summary.dma_granted,
            summary.grants_of(device_obj.raw()),
            summary.unmap_errors,
            summary.unmatched_revokes,
            summary.grant_overflow,
            summary.reclaim_lost,
            ladder.crashed,
            ladder.restarted,
            ladder.gave_up,
            ladder.reclaimed_frames,
            ladder.component_ok,
            ladder.severities_ok,
            ladder.stamped_ok,
            ladder.degraded_marks,
            ladder.crash_dumps,
            ladder.crash_dump_records,
            ladder.dependents_notified,
            ladder.dependents_unreachable,
            ladder.resets,
            ladder.resets_failed,
            ladder.quarantined,
            ladder.transitions,
            ladder.transition_gaps
        );
        TestFinisherExit::exit(ExitCode::Failure)
    }
}

/// Negative self-test: a host that keeps crashing is restarted only up to its
/// budget, and then the supervisor stops.
///
/// **The ladder's most important property is the one a healthy machine never
/// shows.** Every other check here watches recovery succeed; this watches it
/// give up, because a supervisor without a bound is not a recovery policy — it
/// is a machine that respawns a broken driver until something else breaks.
///
/// Returns the launches made.
fn driver_giveup_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    device_base: u64,
    device_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Ok(0);
    }

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    let device_obj = kcore::object::ObjectId::from_raw(29);
    let manager_server_obj = kcore::object::ObjectId::from_raw(77);
    let manager_client_obj = kcore::object::ObjectId::from_raw(78);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(79);
    let crash_proc_obj = kcore::object::ObjectId::from_raw(80);

    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(130u32)?;
        exec.device_register_mmio(
            device_obj,
            device_base,
            device_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 131u32)?;
        let channel = exec.channel_create().map_err(|_| 132u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 132u32)?;
        channel.1
    };

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // SAFETY: the sole user-pointer path validates the range first.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);

    let (manager_idx, manager_proc) = spawn_elf_process(
        kernel_space,
        frames,
        device_manager_elf(),
        REBIND_MANAGER_KSTACK_VA,
        17,
        1,
        manager_proc_obj,
        133,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(140u32)?;
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 141u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 142u32)?;
    }

    let mut supervisor = kcore::supervise::RestartSupervisor::new(DRIVER_RESTART_SELFTEST_BUDGET);
    // The loop the budget has to stop. Its own guard is deliberately generous:
    // a test whose runaway guard is the thing under test proves nothing.
    let mut guard = DRIVER_RESTART_SELFTEST_BUDGET * 4 + 4;
    while supervisor.may_restart() && guard > 0 {
        guard -= 1;
        if !supervise_one_crash(
            &mut supervisor,
            kernel_space,
            frames,
            18,
            crash_proc_obj,
            device_obj,
            manager_client_obj,
            manager_client_ep,
            143,
        )? {
            return Err(148);
        }
    }
    supervisor.give_up(DRIVER_RESTART_GIVEUP_CODE);
    let outcome = supervisor.outcome();

    // **Step 7: the binding is restored or disabled based on failure policy.**
    // The supervisor has decided it has tried enough; this is the system
    // deciding what that means for the device. This check's policy quarantines
    // at its own budget, because "the budget is spent" is exactly when this
    // supervisor has decided — a threshold above the budget could never reach
    // the rung the check exists to demonstrate. The other rungs, including the
    // fallback this tree cannot exercise while there is one driver image per
    // class, are host-tested in `kcore::supervise`.
    let policy = kcore::supervise::FailurePolicy {
        quarantine_after: Some(u64::from(DRIVER_RESTART_SELFTEST_BUDGET)),
        ..kcore::supervise::FailurePolicy::DEFAULT
    };
    let action = policy.after(outcome.faults);
    let quarantined = matches!(action, kcore::supervise::FailureAction::Quarantine);
    // SAFETY: transient raw access; every thread is off-CPU by here.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            if quarantined {
                exec.quarantine_device(device_obj, outcome.faults, action as u64);
            }
            // The lifecycle ends where the policy put it. The manager is not
            // declaring this: it never held the device again — that is what
            // quarantine means — so the kernel closes the record for it,
            // rather than leaving the last thing anyone knows about this
            // device being that its driver crashed.
            let _ = exec.declare_lifecycle(
                device_obj,
                kcore::lifecycle::DriverState::Degraded,
                kcore::lifecycle::DriverState::Failed,
                kcore::lifecycle::TransitionReason::BudgetExhausted,
                outcome.faults,
            );
        }
    }

    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: transient raw access; every thread is off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(manager_idx);
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(manager_idx);
        if let Some(mut gone) = processes.remove(manager_proc) {
            gone.space_mut().teardown(frames);
        }
    }

    // Exactly the budget, no more: the loop was stopped by the policy and not
    // by its own guard, and every launch died.
    if outcome.launches != u64::from(DRIVER_RESTART_SELFTEST_BUDGET)
        || outcome.faults != outcome.launches
        || !outcome.gave_up
    {
        return Err(149);
    }
    // And the policy acted. A quarantine that was decided and not applied
    // looks exactly like one that was never decided — the device is simply
    // never offered again either way, and only the graph can tell them apart.
    // SAFETY: transient raw access; every thread is off-CPU.
    if quarantined
        != unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
            .is_some_and(|exec| exec.is_quarantined(device_obj))
    {
        return Err(150);
    }
    Ok(outcome.launches)
}

// --- The relay path, and what it costs (D144) ---

/// The chain [`relay_check`] builds: two relaying hubs the manifest describes,
/// one it does not, and the devices behind each.
///
/// Graph nodes with real parent edges, as on AArch64 and for the same reason —
/// no reference machine has a relaying hub on it, and the edge the manager
/// walks is the one `pcie_enumerate` records either way.
const RELAY_HUB_NEAR_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc0);
const RELAY_NEAR_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc1);
const RELAY_HUB_FAR_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc2);
const RELAY_FAR_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc3);
const RELAY_FAR_NET_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc4);
const RELAY_HUB_UNKNOWN_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc5);
const RELAY_UNKNOWN_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc6);
const RELAY_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc7);
const RELAY_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc8);
const RELAY_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xc9);
const RELAY_PROBE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xca);
const RELAY_SERVER_2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xcb);
const RELAY_CLIENT_2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xcc);
const RELAY_MANAGER_2_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xcd);
const RELAY_PROBE_2_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xce);

/// Kernel stacks, in the direct map's gigabyte slot (the D100 constraint), and
/// the ASIDs that go with them.
const RELAY_MANAGER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb400_0000;
const RELAY_PROBE_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb500_0000;
const RELAY_MANAGER_2_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb600_0000;
const RELAY_PROBE_2_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb700_0000;
const RELAY_MANAGER_ASID: u16 = 21;
const RELAY_PROBE_ASID: u16 = 22;
const RELAY_MANAGER_2_ASID: u16 = 23;
const RELAY_PROBE_2_ASID: u16 = 24;

/// The startup argument asking `blk-probe` to report what its path costs over
/// three binds. Must match `RELAY_REPORT` there.
const BLK_PROBE_RELAY_REPORT: usize = 1 << 61;

/// PCI class codes, as the graph records them: class in bits 23:16.
const RELAY_CLASS_BRIDGE: u32 = 0x06_04_00;
const RELAY_CLASS_STORAGE: u32 = 0x01_08_00;
const RELAY_CLASS_NETWORK: u32 = 0x02_00_00;
const RELAY_VIRTIO_VENDOR: u16 = 0x1af4;
const RELAY_REDHAT_VENDOR: u16 = 0x1b36;

/// The costs `userspace/device-manager`'s manifest declares for these hubs, and
/// the budget its block entry sets. Restated rather than shared, so the check
/// does not agree with the manager by construction.
const RELAY_NEAR_COST_US: u64 = 10;
const RELAY_NEAR_THROUGHPUT_MBPS: u64 = 1000;
const RELAY_FAR_COST_US: u64 = 25;
const BLOCK_PATH_BUDGET_US: u64 = 30;

/// What the three binds must answer on the described chain, and on the one
/// nothing describes. Identical to the AArch64 expectations, because the
/// manifest, the arbiter and the probe are the same sources — only the boot
/// glue below is per-port.
const RELAY_EXPECTED: u64 = (1 << 8)
    | (RELAY_NEAR_COST_US << 16)
    | (8u64 << 32)
    | (9u64 << 40)
    | (RELAY_NEAR_THROUGHPUT_MBPS << 48);
const RELAY_UNDECLARED_EXPECTED: u64 = 10 | (10u64 << 32) | (1u64 << 40);

/// One spawned program: its scheduler thread and its process, which are not the
/// same index and are both released at the end.
#[derive(Clone, Copy)]
struct RelaySpawn {
    thread: usize,
    process: usize,
}

/// Proves that a device's **data path is a declared cost, checked at binding
/// time**, on a second architecture — `docs/drivers/01`, "Bus Topology And Data
/// Paths".
///
/// **Not one line of the mechanism is per-port**, which is the same thing D111
/// showed for binding itself. The arbiter is `api/binding`, the manifest and
/// the accumulation are `userspace/device-manager`, and the budget is checked
/// by the same `blk-probe` — all compiled for a second target and otherwise
/// untouched. What is here is the boot glue that builds the topology and grants
/// the authority.
///
/// The claim is the doc's: one manifest entry with one budget, asked about two
/// devices of the same class differing **only in depth**, binds the near one
/// and refuses the far one. Throughput refuses separately, because a shorter
/// path is no help when the remaining hop is the narrow one. And a hub the
/// kernel cannot identify is refused rather than assumed free.
fn relay_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64), u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Err(1);
    }

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    let identity = |class_code, vendor, device| kcore::devmgr::DeviceIdentity {
        class_code,
        vendor,
        device,
        bdf: 0,
        revision: 0,
        bus: kcore::devmgr::DeviceBus::Pci,
    };

    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // Devices carry TRANSFER because a manager hands them on; hubs do not,
        // and are windowless besides — a bus's registers are nothing a holder
        // should reach.
        let device_rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
        let hub_rights = Rights::READ | Rights::DERIVE;

        // **Registration order is child order, and it is load-bearing.**
        // `children_of` scans the node pool in slot order, the manager walks
        // depth-first, and it binds the first *held* device of a class — so the
        // near device has to be registered before the hub that leads away from
        // it, or the three answers are about different devices.
        exec.device_register_identified(
            RELAY_HUB_NEAR_OBJ,
            0,
            0,
            hub_rights,
            identity(RELAY_CLASS_BRIDGE, RELAY_REDHAT_VENDOR, 0x0001),
        )
        .map_err(|_| 11u32)?;
        exec.device_register_identified(
            RELAY_NEAR_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 12u32)?;
        exec.device_set_parent(RELAY_NEAR_DEVICE_OBJ, RELAY_HUB_NEAR_OBJ)
            .map_err(|_| 12u32)?;

        exec.device_register_identified(
            RELAY_HUB_FAR_OBJ,
            0,
            0,
            hub_rights,
            identity(RELAY_CLASS_BRIDGE, RELAY_REDHAT_VENDOR, 0x0002),
        )
        .map_err(|_| 11u32)?;
        exec.device_set_parent(RELAY_HUB_FAR_OBJ, RELAY_HUB_NEAR_OBJ)
            .map_err(|_| 12u32)?;
        exec.device_register_identified(
            RELAY_FAR_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 13u32)?;
        exec.device_set_parent(RELAY_FAR_DEVICE_OBJ, RELAY_HUB_FAR_OBJ)
            .map_err(|_| 13u32)?;
        exec.device_register_identified(
            RELAY_FAR_NET_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_NETWORK, RELAY_VIRTIO_VENDOR, 0x1041),
        )
        .map_err(|_| 14u32)?;
        exec.device_set_parent(RELAY_FAR_NET_OBJ, RELAY_HUB_FAR_OBJ)
            .map_err(|_| 14u32)?;

        // **The hub with no identity**, registered the way a device the kernel
        // could not enumerate is: the manager can see something is there and
        // cannot learn what, so the manifest has nothing to say about what
        // passing through it costs.
        exec.device_register_mmio(RELAY_HUB_UNKNOWN_OBJ, 0, 0, hub_rights)
            .map_err(|_| 15u32)?;
        exec.device_register_identified(
            RELAY_UNKNOWN_DEVICE_OBJ,
            0,
            0,
            device_rights,
            identity(RELAY_CLASS_STORAGE, RELAY_VIRTIO_VENDOR, 0x1042),
        )
        .map_err(|_| 15u32)?;
        exec.device_set_parent(RELAY_UNKNOWN_DEVICE_OBJ, RELAY_HUB_UNKNOWN_OBJ)
            .map_err(|_| 15u32)?;

        let channel = exec.channel_create().map_err(|_| 16u32)?;
        exec.bind_endpoint_object(channel.0, RELAY_SERVER_OBJ);
        exec.bind_endpoint_object(channel.1, RELAY_CLIENT_OBJ);
        let channel2 = exec.channel_create().map_err(|_| 16u32)?;
        exec.bind_endpoint_object(channel2.0, RELAY_SERVER_2_OBJ);
        exec.bind_endpoint_object(channel2.1, RELAY_CLIENT_2_OBJ);
    }

    REPORT_COUNT.store(0, Ordering::SeqCst);
    REPORTS_FROM_ANY_THREAD.store(true, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // SAFETY: the sole user-pointer path validates the range first.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);

    let (manager, probe) = relay_pair(
        kernel_space,
        frames,
        RELAY_HUB_NEAR_OBJ,
        RELAY_SERVER_OBJ,
        RELAY_CLIENT_OBJ,
        RELAY_MANAGER_PROC_OBJ,
        RELAY_PROBE_PROC_OBJ,
        RELAY_MANAGER_KSTACK_VA,
        RELAY_PROBE_KSTACK_VA,
        RELAY_MANAGER_ASID,
        RELAY_PROBE_ASID,
        20,
    )?;

    // A second manager rather than a fourth request on the first: a manager
    // hands out the first *held* device of a class, and a refused device stays
    // held — so every later request for that class answers about the same
    // device. Asking a different manager is what makes this a different
    // question, and running the pairs one after the other is what keeps the two
    // reports in a known order.
    let (manager2, probe2) = relay_pair(
        kernel_space,
        frames,
        RELAY_HUB_UNKNOWN_OBJ,
        RELAY_SERVER_2_OBJ,
        RELAY_CLIENT_2_OBJ,
        RELAY_MANAGER_2_PROC_OBJ,
        RELAY_PROBE_2_PROC_OBJ,
        RELAY_MANAGER_2_KSTACK_VA,
        RELAY_PROBE_2_KSTACK_VA,
        RELAY_MANAGER_2_ASID,
        RELAY_PROBE_2_ASID,
        40,
    )?;

    // SAFETY: the teardown below frees tables that are otherwise still mapping
    // this kernel, so the kernel's own space is made current first.
    unsafe { kernel_space.activate() };
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(60);
    }
    if REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(61);
    }
    let declared = REPORTS[0].load(Ordering::SeqCst);
    let undeclared = REPORTS[1].load(Ordering::SeqCst);
    if declared != RELAY_EXPECTED {
        return Err(62);
    }
    if undeclared != RELAY_UNDECLARED_EXPECTED {
        return Err(63);
    }

    // SAFETY: transient raw access; all threads are off-CPU, each released
    // once. Reaping alone is not teardown — it frees the scheduler slot while
    // the dead process still claims the thread index, and the next spawn reuses
    // it, so `forget_thread` follows every reap. Both managers are still
    // blocked in `recv`: a resident server has no exit, and what ended each run
    // is its probe having reported.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            for spawn in [manager, probe, manager2, probe2] {
                exec.scheduler().reap(spawn.thread);
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        for spawn in [manager, probe, manager2, probe2] {
            processes.forget_thread(spawn.thread);
            if let Some(mut gone) = processes.remove(spawn.process) {
                gone.space_mut().teardown(frames);
            }
        }
    }

    use tessera_karch::FrameSource;
    // SAFETY: the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for base in [
        RELAY_MANAGER_KSTACK_VA,
        RELAY_PROBE_KSTACK_VA,
        RELAY_MANAGER_2_KSTACK_VA,
        RELAY_PROBE_2_KSTACK_VA,
    ] {
        for page in 0..REBIND_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((declared, undeclared))
}

/// Spawns one device manager over `root` and one `blk-probe` against it, and
/// runs until nothing is runnable.
///
/// The manager is a resident server and never exits, so what ends the run is
/// the probe having reported. Each pair is run to quiescence before the next is
/// spawned: two managers racing would put their probes' reports in the sink in
/// whichever order the scheduler happened to produce, and the check would be
/// asserting on a coincidence.
#[allow(clippy::too_many_arguments)]
fn relay_pair(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    root: kcore::object::ObjectId,
    server: kcore::object::ObjectId,
    client: kcore::object::ObjectId,
    manager_proc_obj: kcore::object::ObjectId,
    probe_proc_obj: kcore::object::ObjectId,
    manager_kstack: u64,
    probe_kstack: u64,
    manager_asid: u16,
    probe_asid: u16,
    base_err: u32,
) -> Result<(RelaySpawn, RelaySpawn), u32> {
    use kcore::rights::Rights;

    let (manager_idx, manager_proc) = spawn_elf_process(
        kernel_space,
        frames,
        device_manager_elf(),
        manager_kstack,
        manager_asid,
        1,
        manager_proc_obj,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(base_err + 10)?;
        // Install order is the ABI: handle 0 is the service endpoint, then the
        // inventory roots from handle 1 up.
        manager
            .handles_mut()
            .install(server, Rights::READ)
            .map_err(|_| base_err + 10)?;
        // **The bus, and nothing else.** Everything behind it the manager gets
        // from the graph — which is also where the path it accumulates comes
        // from, so the topology it charges for is the topology it walked.
        manager
            .handles_mut()
            .install(root, Rights::READ | Rights::DERIVE)
            .map_err(|_| base_err + 10)?;
    }

    let (probe_idx, probe_proc) = spawn_elf_process(
        kernel_space,
        frames,
        blk_probe_elf(),
        probe_kstack,
        probe_asid,
        BLK_PROBE_RELAY_REPORT,
        probe_proc_obj,
        base_err + 1,
    )?;
    // SAFETY: as above. The probe gets its endpoint and **no device**.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(probe_proc)
            .ok_or(base_err + 11)?
            .handles_mut()
            .install(client, Rights::WRITE)
            .map_err(|_| base_err + 11)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    Ok((
        RelaySpawn {
            thread: manager_idx,
            process: manager_proc,
        },
        RelaySpawn {
            thread: probe_idx,
            process: probe_proc,
        },
    ))
}

/// A driver binds a device by class, dies, and its replacement binds the same
/// physical device.
///
/// This is the driver framework, running on a second architecture with **not
/// one line of its mechanism changed**: the resource graph, the transfer, the
/// window revocation and the reclaim all live in `kcore`, and the manager and
/// the probe are the same sources AArch64 builds. What is new here is the
/// boot glue that grants the authority, and the fact that the programs now
/// compile for two targets.
///
/// Returns what each incarnation reported.
fn driver_rebind_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    device_base: u64,
    device_len: u64,
    identity: Option<kcore::devmgr::DeviceIdentity>,
) -> Result<(u64, u64), u32> {
    use kcore::rights::Rights;
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Err(1);
    }

    // SAFETY: single-threaded boot; written before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    let device_obj = REBIND_DEVICE_OBJECT;
    let manager_server_obj = kcore::object::ObjectId::from_raw(71);
    let manager_client_obj = kcore::object::ObjectId::from_raw(72);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(73);
    let driver1_proc_obj = kcore::object::ObjectId::from_raw(74);
    let driver2_proc_obj = kcore::object::ObjectId::from_raw(75);

    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(2u32)?;
        // A device the kernel enumerated is registered *with what it is*, so
        // the manager can classify it without touching config space; a
        // virtio-mmio transport is registered without, and the manager falls
        // back to reading the transport's own registers.
        match identity {
            Some(identity) => exec.device_register_identified(
                device_obj,
                device_base,
                device_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
                identity,
            ),
            None => exec.device_register_mmio(
                device_obj,
                device_base,
                device_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            ),
        }
        .map_err(|_| 3u32)?;
        let channel = exec.channel_create().map_err(|_| 4u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        // The manager **depends on** this device — ladder step 4's edge in the
        // graph. It holds the inventory, and it is the one thing on this
        // machine that has to hear about a device going wrong whether or not
        // the capability finds its way back.
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 4u32)?;
        channel.1
    };

    REPORT_COUNT.store(0, Ordering::SeqCst);
    REPORTS_FROM_ANY_THREAD.store(true, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    USER_FAULT.store(0, Ordering::SeqCst);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow's lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    // SAFETY: the sole user-pointer path validates the range first.
    unsafe { tessera_karch_riscv64::allow_user_memory_access() };
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);

    // The manager, holding the machine's one device. **TRANSFER** is what
    // makes it a manager rather than a driver that happens to hold something —
    // handing a capability on is itself a right, and D91 paid for learning it.
    let (manager_idx, manager_proc) = spawn_elf_process(
        kernel_space,
        frames,
        device_manager_elf(),
        REBIND_MANAGER_KSTACK_VA,
        11,
        1,
        manager_proc_obj,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(40u32)?;
        // Install order is the ABI: handle 0 is the service endpoint, then the
        // devices from handle 1 up. The program names those numbers.
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 41u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 42u32)?;
    }

    // --- The crash-recovery ladder, before the rebind it makes possible ---
    //
    // Incarnation 0 binds the device and then **faults on purpose**, holding
    // it. A driver that exits tidily exercises teardown, not recovery: it has
    // already given back everything it held. A host killed mid-flight has not,
    // and whether the device comes back from it is the question the ladder
    // answers. The policy and the three records are `kcore::supervise`, shared
    // with the other ports; what is local is the architecture work.
    let mut supervisor = kcore::supervise::RestartSupervisor::new(DRIVER_RESTART_BUDGET);
    if !supervise_one_crash(
        &mut supervisor,
        kernel_space,
        frames,
        16,
        kcore::object::ObjectId::from_raw(76),
        device_obj,
        manager_client_obj,
        manager_client_ep,
        110,
    )? {
        // The driver was supposed to die and did not, so nothing below tests
        // recovery. Failing here beats passing a rebind that recovered from
        // nothing.
        return Err(119);
    }

    // Incarnation 1: binds by class, reads the transport's magic, exits.
    let (driver1_idx, driver1_proc) = spawn_elf_process(
        kernel_space,
        frames,
        blk_probe_elf(),
        REBIND_DRIVER1_KSTACK_VA,
        12,
        1,
        driver1_proc_obj,
        50,
    )?;
    // SAFETY: as above. The driver gets its endpoint and **no device**.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver1_proc)
            .ok_or(70u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 70u32)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // Back to the kernel's own root **before touching a process's tables**.
    //
    // `run` returns with whatever root the last thread ran under still in
    // `satp`, and on a single-root architecture that root is also what maps
    // the kernel — `new_user` copied the kernel's entries into it. Freeing
    // that process's tables while it is active pulls the ground out from
    // under the running kernel: the next `.rodata` load faults, the fault
    // handler faults pushing its own frame, and the machine spirals silently.
    // AArch64 cannot have this bug, because there the kernel is in `TTBR1`
    // and tearing down a `TTBR0` cannot reach it.
    // SAFETY: the kernel space maps everything this path touches.
    unsafe { kernel_space.activate() };

    // A driver that identified its device rather than driving it reports the
    // identity, not the transport's magic — the expectation belongs to the
    // caller, which knows which kind of device it registered.
    let expect_magic = identity.is_none();
    let first = REPORTS[0].load(Ordering::SeqCst);
    if expect_magic && first != REBIND_MAGIC.rotate_left(8) {
        kprintln!("driver-rebind: the first driver reported {}", first as i64);
        return Err(71);
    }

    // The driver is gone. Note what the supervisor does *not* do: it never
    // mentions the device. It does not know which devices this driver held and
    // does not need to — the kernel hands whatever it held back to the manager
    // as part of teardown, so a supervisor cannot cost the machine a device by
    // forgetting. Reaping alone is not teardown: it frees the scheduler slot
    // while the dead process still claims the thread index, and the next spawn
    // reuses it (`Process::forget_thread`).
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver1_idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(driver1_proc) {
                // No IOMMU in scope here: `driver_rebind_check` binds a
                // virtio-mmio device, which no IOMMU on this machine sits in
                // front of. The sweep still runs, so a lease taken by any
                // future device bound here would end with its holder.
                //
                // The PLIC is another matter — an interrupt route outlives
                // this teardown in the controller and in the port table, so
                // the router is real rather than absent.
                let mut router = PlicRouter;
                exec.reclaim_devices(dead, manager_client_ep, None, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(driver1_idx);
        if let Some(mut dead) = processes.remove(driver1_proc) {
            dead.space_mut().teardown(frames);
        }
    }

    // Incarnation 2: the same program, a fresh process, no memory of the first.
    let (driver2_idx, driver2_proc) = spawn_elf_process(
        kernel_space,
        frames,
        blk_probe_elf(),
        REBIND_DRIVER2_KSTACK_VA,
        13,
        2,
        driver2_proc_obj,
        80,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver2_proc)
            .ok_or(100u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 100u32)?;
    }
    // SAFETY: as the first run.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: as after the first run, and for the same reason — the teardown
    // below frees the tables that are otherwise still mapping this kernel.
    unsafe { kernel_space.activate() };

    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };

    if USER_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(101);
    }
    let second = REPORTS[1].load(Ordering::SeqCst);
    if expect_magic && second != REBIND_MAGIC.rotate_left(16) {
        kprintln!(
            "driver-rebind: the second driver reported {}",
            second as i64
        );
        return Err(102);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver2_idx);
            exec.scheduler().reap(manager_idx);
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(driver2_idx);
        processes.forget_thread(manager_idx);
        for idx in [driver2_proc, manager_proc] {
            if let Some(mut gone) = processes.remove(idx) {
                gone.space_mut().teardown(frames);
            }
        }
    }
    use tessera_karch::FrameSource;
    // SAFETY: as above — the alias owns no tables and is used only to unmap.
    let mut kernel_alias = unsafe {
        tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        )
    };
    for base in [
        REBIND_MANAGER_KSTACK_VA,
        REBIND_DRIVER1_KSTACK_VA,
        REBIND_DRIVER2_KSTACK_VA,
    ] {
        for page in 0..REBIND_KSTACK_PAGES {
            if let Ok(frame) = kernel_alias.unmap(VirtAddr::new(base + page * FRAME_SIZE)) {
                frames.free_frame(frame);
            }
        }
    }

    Ok((first, second))
}
