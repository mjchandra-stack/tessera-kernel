// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tessera kernel boot glue for AArch64: the only AArch64 crate that knows
//! how the machine was entered. Normalizes the firmware handoff into
//! `tessera-karch` types, brings up the early console, and hands control to
//! the kernel core.
//!
//! Entry contract. The image is a flat binary carrying the arm64 Linux
//! `Image` header, which QEMU's `-kernel` loads at `RAM_base + text_offset`
//! (0x40000000 + 0x80000 on `virt`) and enters at offset 0 with the MMU off,
//! caches off, and the device-tree blob address in `x0`.
//!
//! The header is not decoration. Handed a bare ELF, QEMU treats the image as
//! non-Linux: it starts the CPU at the ELF entry point with every register
//! zero and does not build or load a device tree at all. The header is what
//! selects the boot protocol that delivers one, and the device tree is this
//! architecture's discovery front end
//! (docs/hardware/02-hardware-description-and-discovery.md).
//!
//! There is no bootloader and therefore no higher-half direct map handed to
//! us: unlike the x86-64 glue, which inherits Limine's HHDM, this port
//! builds its own address space from scratch. That is more work, but it
//! means the AArch64 path exercises `karch::BootInfo` end to end rather than
//! inheriting a ready-made map.
//!
//! This crate is deliberately small and must stay so. The demonstrations
//! live in `tessera-arch-conformance`, which both ports run, so the two boot
//! glues cannot drift into two different kernels.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md ("Boot Flow"),
//! docs/hardware/01-platform-and-cpu-support.md ("Porting Rules")
//! Budget: none (init path)

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use tessera_devicetree::{DeviceTree, FdtError, HEADER_LEN, MmioDevice};
use tessera_karch::{
    BootInfo, ExitCode, FRAME_SIZE, MemoryKind, MemoryRegion, PhysAddr, PlatformExit,
    normalize_memory_map,
};
use tessera_karch::{PageFlags, PhysFrame, VirtAddr};
use tessera_karch_aarch64::{
    ContextSwitch, Cpu, DIRECT_MAP_BASE, KernelAddressSpace, KernelSection, PHYS_MASK, Pl011,
    SemihostingExit, build_high_space, build_low_space, switch_tables,
};
use tessera_kcore as kcore;
use tessera_kcore::kprintln;
use tessera_kcore::panic::PanicDisposition;

mod virtio;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capacity of the boot memory map. Sized generously; the boot path reports
/// loudly rather than booting on a truncated map.
const MAX_MEMORY_REGIONS: usize = 64;

/// The `virt` machine lays out 32 virtio-mmio transport slots.
const MAX_VIRTIO_REGIONS: usize = 32;

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
/// the base of RAM, which covers the PL011 at 0x0900_0000 and the GIC at
/// 0x0800_0000. Identity-mapped so the early console survives the moment the
/// MMU comes on.
const DEVICE_RANGE: (u64, u64) = (0, 0x4000_0000);

/// Scratch virtual range the conformance battery maps and unmaps. A high-half
/// (`TTBR1`, kernel) address — the battery operates on the kernel's own space
/// — well clear of the kernel image and the direct map.
const CONFORMANCE_SCRATCH: u64 = 0xffff_0000_5000_0000;

/// AArch64 machine code for `extern "C" fn() -> u64` returning
/// [`tessera_arch_conformance::SENTINEL`], for the instruction-cache case:
///
/// ```text
///   movz x0, #0xc0de
///   movk x0, #0x5e17, lsl #16
///   ret
/// ```
///
/// Written as bytes rather than assembled from a symbol on purpose — the case
/// needs instructions that were *stored as data* into a fresh frame, which is
/// exactly the situation a symbol's address would let us avoid testing.
const SENTINEL_CODE: &[u8] = &[
    0xc0, 0x1b, 0x98, 0xd2, // movz x0, #0xc0de
    0xe0, 0xc2, 0xab, 0xf2, // movk x0, #0x5e17, lsl #16
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

/// Backing storage for the global console. A `static mut` is the honest
/// representation of "one mutable device object created before concurrency
/// exists"; the single `&mut` is taken exactly once, in `kernel_main`.
static mut UART: Pl011 = Pl011::virt();

// Entry stub. Runs with the MMU off on the boot CPU, before any Rust
// invariant holds: there is no stack, `.bss` is whatever the loader left,
// and the exception level is whatever the machine entered at.
//
// Ordering is forced by those facts. The firmware handoff in `x0` is saved
// first because everything below is free to clobber it; exceptions are
// masked before any state is touched; the exception level is normalized to
// EL1h before `SP` is meaningful; the stack is established before `.bss` is
// zeroed (the zeroing pass is register-only, and the boot stack lives inside
// `.bss`, so nothing may be on it yet); and only then is Rust entered.
core::arch::global_asm!(
    r#"
// The arm64 Linux Image header: 64 bytes at the image base, selecting the
// boot protocol that supplies a device tree. `code0` must be a real
// instruction because the loader enters here, so it branches over the rest.
.section .text.header
.globl _start
_start:
    b       _start_el1              // code0: entry, branches past the header
    .long   0                       // code1
    .quad   0x80000                 // text_offset from the base of RAM
    .quad   __image_size            // image_size (text through .bss)
    .quad   0xa                     // flags: LE, 4 KiB granule, load anywhere
    .quad   0                       // res2
    .quad   0                       // res3
    .quad   0                       // res4
    .ascii  "ARM\x64"               // magic, at offset 0x38
    .long   0                       // res5

.section .text._start
.globl _start_el1
_start_el1:
    // Firmware handoff: x0 holds the device-tree blob. Park it in a
    // callee-saved register before anything below can clobber it.
    mov     x19, x0

    // Mask D/A/I/F for the duration of bring-up.
    msr     daifset, #0xf

    // Normalize the exception level. QEMU enters at EL2 when the machine
    // has virtualization enabled and at EL1 otherwise; the kernel runs at
    // EL1h either way, so drop if needed and fall through if not.
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.ne    1f

    // EL1 is AArch64 (HCR_EL2.RW).
    mov     x0, #(1 << 31)
    msr     hcr_el2, x0

    // Let EL1 reach the physical and virtual counters, with no virtual
    // offset, so the generic timer reads the same time at both levels.
    mrs     x0, cnthctl_el2
    orr     x0, x0, #3
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr

    // EL1 state on arrival: MMU off, caches off, RES1 bits set.
    ldr     x0, =0x30d00800
    msr     sctlr_el1, x0

    // Return into EL1h with all exceptions still masked.
    mov     x0, #0x3c5
    msr     spsr_el2, x0
    adr     x0, 1f
    msr     elr_el2, x0
    eret

1:
    // MMU still off: the running PC is the physical load address, and every
    // linked symbol is in the high half, unmapped until translation is on.
    // So everything here is position-independent — `adrp`+`add` resolves a
    // high-linked symbol to where it physically sits — the property the
    // higher-half kernel is built on.

    // A physical boot stack, just for the call below (nothing is on it while
    // .bss is cleared later, in the high half).
    adrp    x0, __boot_stack_top
    add     x0, x0, #:lo12:__boot_stack_top
    mov     sp, x0

    // Install the coarse boot tables and enable the MMU. The five arguments
    // are the physical addresses of the reserved boot table frames.
    adrp    x0, boot_ttbr0_root
    add     x0, x0, #:lo12:boot_ttbr0_root
    adrp    x1, boot_l1_low
    add     x1, x1, #:lo12:boot_l1_low
    adrp    x2, boot_ttbr1_root
    add     x2, x2, #:lo12:boot_ttbr1_root
    adrp    x3, boot_l1_high_kernel
    add     x3, x3, #:lo12:boot_l1_high_kernel
    adrp    x4, boot_l1_high_direct
    add     x4, x4, #:lo12:boot_l1_high_direct
    bl      aarch64_boot_mmu_up

    // Translation is on; TTBR0 still identity-maps this physical code for one
    // more instant. Branch to the high half — the absolute (high) address of
    // the continuation is now valid, resolved through TTBR1.
    ldr     x0, =_start_high
    br      x0

.globl _start_high
_start_high:
    // Executing in the high half now. Move the stack to its high address and
    // clear .bss (register-only; the boot tables live outside .bss, so this
    // does not touch them).
    ldr     x0, =__boot_stack_top
    mov     sp, x0

    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
2:
    cmp     x0, x1
    b.hs    3f
    str     xzr, [x0], #8
    b       2b

3:
    mov     x0, x19
    bl      kernel_main

    // kernel_main is `-> !`; if it ever returns, stop rather than run on
    // through whatever follows in memory.
4:
    wfi
    b       4b
"#
);

/// Called once from the entry stub, with the MMU off, holding the physical
/// addresses of the five reserved boot page-table frames. Fills them with the
/// coarse cover that reaches the high half and turns the MMU on, after which
/// the stub branches high.
///
/// It only forwards its arguments to two position-independent primitives and
/// touches no static, so — like the `adrp`-based stub that calls it — it is
/// correct while executing at the physical load address before translation is
/// on. (The `unsafe-inventory` records the disassembly check that no absolute
/// relocation slipped in.)
///
/// # Safety
///
/// Called exactly once, on the boot CPU, with the MMU off and the five
/// distinct zeroed reserved table frames named by the arguments.
#[unsafe(no_mangle)]
unsafe extern "C" fn aarch64_boot_mmu_up(
    ttbr0_root: u64,
    l1_low: u64,
    ttbr1_root: u64,
    l1_high_kernel: u64,
    l1_high_direct: u64,
) {
    // SAFETY: the stub passes the five reserved boot table frames once, MMU
    // off; `build_boot_tables` then `enable_mmu_raw` is exactly their contract.
    unsafe {
        tessera_karch_aarch64::build_boot_tables(
            ttbr0_root,
            l1_low,
            ttbr1_root,
            l1_high_kernel,
            l1_high_direct,
        );
        tessera_karch_aarch64::enable_mmu_raw(ttbr0_root, ttbr1_root);
    }
}

/// Rust entry point, called by the stub above with the device-tree blob
/// address. Runs at EL1h with the MMU off and all exceptions masked.
///
/// # Safety
///
/// Called exactly once, by `_start`, on the boot CPU, with a valid stack and
/// zeroed `.bss`. `dtb` is whatever the firmware supplied and is not trusted
/// beyond being a number.
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

    kprintln!("Tessera {VERSION} (Stage 0 skeleton, AArch64)");
    kprintln!("early console: PL011 @ 115200");
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
            SemihostingExit::exit(ExitCode::Failure)
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

    // Discover the virtio-mmio transports while the device tree is still
    // reachable at its physical address — before the high-half switch drops
    // the boot identity of low RAM. Only the register-block bases are kept;
    // they are device addresses, mapped for the life of the kernel.
    let mut virtio_regions = [MmioDevice {
        base: 0,
        size: 0,
        intid: None,
    }; MAX_VIRTIO_REGIONS];
    // SAFETY: pre-switch, `dtb` is mapped by the boot identity; `discover`
    // forms a length-validated slice over the blob and bounds-checks it.
    let virtio_count = unsafe { virtio::discover(dtb, &mut virtio_regions) };

    // The direct map spans RAM as the firmware described it, rather than
    // everything from physical zero: the space below RAM is device registers.
    let ram_start = memory_map.first().map(|r| r.base.as_u64()).unwrap_or(0);
    let ram_end = memory_map
        .last()
        .map(|region| region.base.as_u64() + region.len)
        .unwrap_or(0);
    let mut frames = kcore::pmem::BumpFrameAllocator::new(memory_map);

    // Build the kernel's real split tables and switch to them. The MMU is
    // already on (the entry stub's coarse tables reached this high-half code),
    // so table frames are written through the direct map from the start —
    // there is no identity-then-direct-map handoff. The high-half root carries
    // the kernel image at per-section W^X and the direct map; the low-half
    // root carries the device range (and, later, user pages).
    let mut kernel_space = match build_high_space(
        &mut frames,
        DIRECT_MAP_BASE,
        &kernel_sections(),
        (ram_start, ram_end),
    ) {
        Ok(space) => space,
        Err(error) => {
            kprintln!(
                "paging: FATAL: kernel high-half tables not built (kerror {})",
                error.code()
            );
            SemihostingExit::exit(ExitCode::Failure)
        }
    };
    let mut ttbr0_space = match build_low_space(&mut frames, DIRECT_MAP_BASE, DEVICE_RANGE) {
        Ok(space) => space,
        Err(error) => {
            kprintln!(
                "paging: FATAL: low-half tables not built (kerror {})",
                error.code()
            );
            SemihostingExit::exit(ExitCode::Failure)
        }
    };

    // SAFETY: the high-half root maps this code and stack at the same high
    // addresses the boot high-half root did (both cover the kernel image), so
    // the instruction after the switch still fetches; the low-half root maps
    // the PL011 the console uses. The device tree has already been parsed, so
    // dropping the boot identity of low RAM strands nothing.
    unsafe {
        use tessera_karch::AddressSpaceOps;
        switch_tables(ttbr0_space.root_phys(), kernel_space.root_phys())
    };
    kprintln!(
        "paging: MMU on, kernel high-half (TTBR1), {} MiB RAM direct-mapped at {:#018x}, W^X kernel image",
        (ram_end - ram_start) / (1024 * 1024),
        DIRECT_MAP_BASE + ram_start
    );

    let _boot = BootInfo {
        hhdm_offset: DIRECT_MAP_BASE,
        memory_map,
    };

    // Exceptions now report instead of looping at address zero, and the
    // periodic tick exists. Vectors are installed before the interrupt
    // controller, so a fault raised while bringing the GIC up is still
    // reported.
    // SAFETY: boot CPU, interrupts still masked, and the kernel's text is
    // mapped executable at its current address by the tables activated above.
    unsafe { tessera_karch_aarch64::init_vectors() };
    tessera_karch_aarch64::set_trap_handler(fatal_trap);
    // SAFETY: the GIC is identity-mapped device memory (DEVICE_RANGE), this
    // is the boot CPU, and interrupts are still masked.
    unsafe {
        tessera_karch_aarch64::init_gic();
        tessera_karch_aarch64::enable_irq(tessera_karch_aarch64::TIMER_INTID);
    }

    match timer_check() {
        Ok(observed) => kprintln!("timer: {observed} ticks at {TICK_HZ} Hz, GIC delivering"),
        Err(which) => {
            kprintln!("timer: FATAL: tick check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    // The porting-layer battery both ports run. Its verdicts, not this
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
        SemihostingExit::exit(ExitCode::Failure)
    }

    perf_context_switch(&mut kernel_space, &mut frames);

    match el0_check(&mut kernel_space, &mut ttbr0_space, &mut frames) {
        Ok(log) => kprintln!(
            "el0: OK — entered ring 3, syscall taken (log {log:#x}), W^X enforced, user faults contained"
        ),
        Err(which) => {
            kprintln!("el0: FATAL: EL0 check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    match new_user_check(&ttbr0_space, &mut frames) {
        Ok((a, b)) => kprintln!(
            "new-user: OK — 2 isolated EL0 processes, per-process TTBR0, each read its own memory (a={a:#x} b={b:#x})"
        ),
        Err(which) => {
            kprintln!("new-user: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    match kcore_el0_check(&kernel_space, &ttbr0_space, &mut frames) {
        Ok(log) => kprintln!(
            "kcore-el0: OK — EL0 process scheduled by kcore (Process/Thread/Scheduler), syscall via substrate, exited (log {log:#x})"
        ),
        Err(which) => {
            kprintln!("kcore-el0: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    match ipc_check(&kernel_space, &ttbr0_space, &mut frames) {
        Ok((magic, switches)) => kprintln!(
            "ipc: OK — client→server channel round-trip, request delivered (magic {magic:#x}), {switches} switches"
        ),
        Err(which) => {
            kprintln!("ipc: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    match virtio::block_device_base(&virtio_regions[..virtio_count]) {
        Some(base) => {
            match mmio_map_check(&kernel_space, &ttbr0_space, &mut frames, base) {
                Ok(packed) => kprintln!(
                    "mmio: OK — ring-3 mapped virtio MMIO by capability, read magic {:#x} device-id {}",
                    packed & 0xffff_ffff,
                    packed >> 32
                ),
                Err(which) => {
                    kprintln!("mmio: FATAL: check {which} failed");
                    SemihostingExit::exit(ExitCode::Failure)
                }
            }
            match dma_check(&kernel_space, &ttbr0_space, &mut frames, base) {
                Ok(phys) => kprintln!(
                    "dma: OK — ring-3 allocated a DMA buffer, user VA and phys {phys:#x} alias (magic {DMA_MAGIC:#x})"
                ),
                Err(which) => {
                    kprintln!("dma: FATAL: check {which} failed");
                    SemihostingExit::exit(ExitCode::Failure)
                }
            }
            if device_host_elf().is_empty() || blk_client_elf().is_empty() {
                // Explicit, never silent: only the Bazel build embeds the
                // host/client ELFs (the x86 root-task policy, D42/D80/D81).
                kprintln!(
                    "ring3-host: skipped (no embedded host/client ELF; cargo inner-loop build)"
                );
            } else {
                match virtio::net_device_base(&virtio_regions[..virtio_count]) {
                    // The one host drives BOTH device classes (D83), so the
                    // check needs both attached; the per-device boot tests
                    // attach only their own device and hit the skip lines.
                    None => kprintln!("ring3-host: skipped (no network device attached)"),
                    Some(net_base) => {
                        let blk_intid = virtio_regions[..virtio_count]
                            .iter()
                            .find(|r| r.base == base)
                            .and_then(|r| r.intid);
                        match ring3_host_check(
                            &kernel_space,
                            &ttbr0_space,
                            &mut frames,
                            base,
                            blk_intid,
                            net_base,
                        ) {
                            Ok(()) => kprintln!(
                                "ring3-host: OK — resident EL0 host selected across 2 client channels (4 IRQ-driven reads, ARP from EL0)"
                            ),
                            Err(which) => {
                                kprintln!(
                                    "ring3-host: FATAL: check {which} failed (report {:#x})",
                                    EL0_SINK_LOG.load(Ordering::SeqCst)
                                );
                                SemihostingExit::exit(ExitCode::Failure)
                            }
                        }
                    }
                }
            }
        }
        None => kprintln!("mmio/dma: no block device attached (skipped)"),
    }

    // The framework's restart claim, on its own: a driver dies holding the
    // block device and the next one gets it. Deliberately separate from the
    // host check above — no clients, no interrupts, no select loop, so the
    // handover is the only thing being tested.
    match virtio::block_device_base(&virtio_regions[..virtio_count]) {
        Some(base) => match driver_rebind_check(&kernel_space, &ttbr0_space, &mut frames, base) {
            Ok(()) => kprintln!(
                "driver-rebind: OK — a driver died holding the block device; the manager reclaimed it and bound it to a fresh driver, which drove the same transport"
            ),
            Err(which) => {
                kprintln!(
                    "driver-rebind: FATAL: check {which} failed (report {:#x})",
                    EL0_SINK_LOG.load(Ordering::SeqCst)
                );
                SemihostingExit::exit(ExitCode::Failure)
            }
        },
        None => kprintln!("driver-rebind: no block device attached (skipped)"),
    }

    match virtio::check(&virtio_regions[..virtio_count], &mut frames) {
        Ok(true) => kprintln!("virtio-blk: OK — sector 0 read, magic verified"),
        Ok(false) => kprintln!("virtio-blk: no block device attached (skipped)"),
        Err(which) => {
            kprintln!("virtio-blk: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    match virtio::net_check(&virtio_regions[..virtio_count], &mut frames) {
        Ok(Some(mac)) => kprintln!(
            "virtio-net: OK — MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, ARP reply from 10.0.2.2",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        ),
        Ok(None) => kprintln!("virtio-net: no network device attached (skipped)"),
        Err(which) => {
            kprintln!("virtio-net: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    SemihostingExit::exit(ExitCode::Success)
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
/// cover everything, while the kernel image, the device tree blob itself,
/// the firmware reservation block, and `/reserved-memory` all sit inside
/// them. They are gathered unresolved and handed to
/// [`normalize_memory_map`], which settles the overlaps by precedence — so
/// no caller has to reason about the order they were collected in.
fn boot_memory_map(dtb: u64, storage: &mut [MemoryRegion]) -> Result<&[MemoryRegion], FdtError> {
    // The blob's own length lives inside it, so the header is read first and
    // the rest only once its extent is known.
    //
    // SAFETY: `dtb` is the firmware handoff address. The Image boot protocol
    // guarantees it points at a device tree blob in memory the kernel owns,
    // and with the MMU off every physical address is readable. Nothing is
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
        // The image the firmware just loaded us from. Its symbols are linked
        // in the high half now, so the physical extent — what the memory map
        // must carve out of RAM — is the low 48 bits of those addresses.
        MemoryRegion {
            base: PhysAddr::new(&raw const __kernel_start as u64 & PHYS_MASK),
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

/// Boot timer rate; matches the x86-64 harness so the two are comparable.
const TICK_HZ: u32 = 100;

/// Samples for the context-switch benchmark.
const PERF_SAMPLES: usize = 200;
static mut PERF_BUF: [u64; PERF_SAMPLES] = [0; PERF_SAMPLES];

/// The two ends of the ping-pong the benchmark switches between.
static mut PERF_MAIN_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;
static mut PERF_PONG_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;

/// Measures the context-switch path (budget B7).
///
/// This is the one Stage-0 primitive budget the EL1 port can measure
/// honestly: B1-B11 otherwise need syscalls, IPC and the executive, none of
/// which exist before EL0. The main thread switches to a pong thread that
/// immediately switches straight back, and the counter delta brackets exactly
/// two `ContextSwitch::switch` calls per sample.
///
/// Reported in nanoseconds, not raw counter ticks. `CNTVCT_EL0` runs at the
/// system-counter frequency (~62.5 MHz under QEMU), far coarser than the
/// core clock the TSC tracks, so a raw tick count would be both tiny and
/// incomparable with the x86-64 rig — and under QEMU/TCG every number here is
/// a regression tripwire only, never an R1 measurement (build/README.md,
/// D34/D56).
fn perf_context_switch(
    space: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) {
    use tessera_karch::{AddressSpaceOps, ContextOps, CpuOps, FrameSource};

    // Guarded two-page stack for the pong thread, above the conformance
    // scratch so nothing collides.
    let base = VirtAddr::new(CONFORMANCE_SCRATCH + 0x10_0000);
    const PAGES: u64 = 2;
    for page in 0..PAGES {
        let Some(f) = frames.alloc() else {
            return kprintln!("perf: B7 ctx-switch    setup failed (no frame)");
        };
        let at = VirtAddr::new(base.as_u64() + page * FRAME_SIZE);
        if space.map(at, f, PageFlags::rw().global(), frames).is_err() {
            return kprintln!("perf: B7 ctx-switch    setup failed (map)");
        }
    }
    let top = VirtAddr::new(base.as_u64() + PAGES * FRAME_SIZE);

    // SAFETY: `top` tops the two exclusively-owned pages just mapped, and
    // `perf_pong` never returns.
    let pong = unsafe { ContextSwitch::init(top, perf_pong, 0) };
    // SAFETY: single-threaded boot; these statics are written before the
    // switch that reads them and nothing else touches them.
    unsafe {
        (&raw mut PERF_PONG_CTX).write(Some(pong));
        (&raw mut PERF_MAIN_CTX).write(Some(ContextSwitch::empty()));
    }

    let hz = <Cpu as CpuOps>::counter_hz().unwrap_or(1).max(1);
    // The pong thread needs no stop signal: every sample is a full round trip
    // that returns here, and after the loop the main thread simply stops
    // switching to it. Pong is left suspended at its `switch` call — a saved
    // context on a stack that is never resumed — and its frames are freed
    // below, which is sound precisely because nothing switches into it again.
    for i in 0..PERF_SAMPLES {
        let start = <Cpu as CpuOps>::counter_serialized();
        // SAFETY: `PERF_MAIN_CTX` is valid storage to save into, and
        // `PERF_PONG_CTX` was produced by `init` (or the pong thread's own
        // save on a prior round), so its stack holds a matching frame.
        unsafe {
            let main = &raw mut PERF_MAIN_CTX;
            let pong = &raw const PERF_PONG_CTX;
            if let (Some(main_ref), Some(pong_ref)) = ((*main).as_mut(), (*pong).as_ref()) {
                ContextSwitch::switch(main_ref, pong_ref);
            }
        }
        let end = <Cpu as CpuOps>::counter_serialized();
        // Two switches per round trip; report the per-round-trip time in ns.
        let ticks = end.saturating_sub(start);
        // SAFETY: single-threaded; the buffer is written only here.
        unsafe { (*&raw mut PERF_BUF)[i] = ticks * 1_000_000_000 / hz };
    }

    for page in 0..PAGES {
        let at = VirtAddr::new(base.as_u64() + page * FRAME_SIZE);
        if let Ok(f) = space.unmap(at) {
            frames.free_frame(f);
        }
    }

    // SAFETY: single-threaded; PERF_BUF is not aliased during the report.
    let samples = unsafe { &mut *&raw mut PERF_BUF };
    match kcore::bench::Stats::from_samples(samples) {
        Some(s) => kprintln!(
            "perf: B7 ctx-switch    n={} p50={}ns p90={}ns p99={}ns max={}ns mean={}ns (2 switches/rt, QEMU-only)",
            s.count,
            s.p50,
            s.p90,
            s.p99,
            s.max,
            s.mean
        ),
        None => kprintln!("perf: B7 ctx-switch    no samples"),
    }
}

/// Pong end of the context-switch benchmark: switch straight back to main,
/// forever. The main thread stops driving it after the measured rounds, so
/// this simply suspends at its final switch and is never resumed.
extern "C" fn perf_pong(_arg: usize) -> ! {
    use tessera_karch::ContextOps;
    loop {
        // SAFETY: single-threaded boot; `PERF_PONG_CTX` is this thread's own
        // save slot and `PERF_MAIN_CTX` holds the caller's live context.
        unsafe {
            let mine = &raw mut PERF_PONG_CTX;
            let main = &raw const PERF_MAIN_CTX;
            if let (Some(mine_ref), Some(main_ref)) = ((*mine).as_mut(), (*main).as_ref()) {
                ContextSwitch::switch(mine_ref, main_ref);
            }
        }
    }
}

/// Ticks the hook has observed, so the check can prove delivery rather than
/// merely that the timer was programmed.
static OBSERVED_TICKS: AtomicU64 = AtomicU64::new(0);

fn on_tick() {
    OBSERVED_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Starts the tick, waits for interrupts to actually arrive, and stops it.
///
/// Programming a timer proves nothing on its own: the interrupt has to make
/// it through the GIC's priority mask, the distributor's enable, the CPU
/// interface, and the vector table before the hook runs. This waits on the
/// hook's own count, so only end-to-end delivery satisfies it.
fn timer_check() -> Result<u64, u32> {
    use tessera_karch::{InterruptControl, TimerControl};

    tessera_karch_aarch64::set_tick_hook(on_tick);
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    tessera_karch_aarch64::Cpu::enable();

    // Bounded wait: spin on the counter rather than trusting the timer, so a
    // controller that never delivers fails the check instead of hanging the
    // boot. The bound is counter ticks, read from the same counter the timer
    // compares against, so it is a real time limit and not a spin count.
    const WANTED: u64 = 3;
    let deadline =
        tessera_karch_aarch64::read_counter() + tessera_karch_aarch64::counter_frequency() * 2;
    while OBSERVED_TICKS.load(Ordering::Relaxed) < WANTED {
        if tessera_karch_aarch64::read_counter() > deadline {
            tessera_karch_aarch64::Cpu::disable();
            tessera_karch_aarch64::stop_timer();
            return Err(1);
        }
        core::hint::spin_loop();
    }

    tessera_karch_aarch64::Cpu::disable();
    tessera_karch_aarch64::stop_timer();

    // The architecture's own tick count and the hook's must agree; a
    // mismatch means ticks were delivered that the hook never saw.
    let counted = tessera_karch_aarch64::GenericTimer::ticks();
    let observed = OBSERVED_TICKS.load(Ordering::Relaxed);
    if counted != observed {
        return Err(2);
    }
    if tessera_karch_aarch64::unexpected_irqs() != 0 {
        return Err(3);
    }
    Ok(observed)
}

/// Reports a fatal exception and ends the run. Before this existed a kernel
// --- EL0 (ring 3) bring-up (D70) ---

/// User virtual addresses for the EL0 proof. Both in the low `TTBR0` range
/// with EL0 access, clear of the device range (`< 0x4000_0000`) — the user
/// program's private slice of the low half.
const USER_CODE_VA: u64 = 0x0000_1000_0000_0000;
const USER_STACK_VA: u64 = 0x0000_1000_0010_0000;

/// Kernel stack for the EL0 thread. A high-half (`TTBR1`, kernel) address:
/// the EL1 vector lands on it when EL0 traps, so it must be kernel memory,
/// resident regardless of which low half is active. Clear of the kernel image
/// and the conformance scratch.
const EL0_KSTACK_VA: u64 = 0xffff_0000_6000_0000;
const EL0_KSTACK_PAGES: u64 = 4;

/// Syscall numbers (in `x8`, the AArch64 convention). `SYS_LOG` returns to
/// EL0; any other number, including `SYS_EXIT`, ends the thread — so the
/// handler matches only `SYS_LOG` explicitly.
const SYS_LOG: u64 = 0;
const _SYS_EXIT: u64 = 1;

/// EL0 program: `svc` LOG with the magic already in `x0`, then `svc` EXIT.
/// Position-independent (no absolute addresses), hand-assembled little-endian.
///
/// ```text
///   movz x8, #0      ; SYS_LOG   (x0 already = magic, the entry arg)
///   svc  #0
///   movz x8, #1      ; SYS_EXIT
///   movz x0, #0      ; exit code 0
///   svc  #0
///   b    .           ; unreachable
/// ```
const LOG_EXIT_BLOB: &[u8] = &[
    0x08, 0x00, 0x80, 0xd2, // movz x8, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// EL0 program that stores to its own (read-execute) code page — a W^X
/// violation the hardware must fault. `adr x1, .` takes the code address;
/// `str x0, [x1]` writes it.
const WX_BLOB: &[u8] = &[
    0x01, 0x00, 0x00, 0x10, // adr x1, .
    0x20, 0x00, 0x00, 0xf9, // str x0, [x1]
    0x00, 0x00, 0x00, 0x14, // b .
];

/// EL0 program that reads the kernel address passed in `x0` — a privilege
/// violation (kernel pages are `AP=EL1-only`) the hardware must fault.
const KREAD_BLOB: &[u8] = &[
    0x02, 0x00, 0x40, 0xf9, // ldr x2, [x0]
    0x00, 0x00, 0x00, 0x14, // b .
];

// --- per-process address spaces (D74) ---

/// A user data page each process maps at the *same* virtual address to its
/// *own* frame — the address whose contents differ between processes and so
/// prove per-process isolation. Clear of the code/stack pages above.
const USER_DATA_VA: u64 = 0x0000_1000_0030_0000;

/// Distinct sentinels the two processes store at `USER_DATA_VA`; the isolation
/// proof is that each reads back its own.
const SENTINEL_A: u64 = 0xa1a1_a1a1_a1a1_a1a1;
const SENTINEL_B: u64 = 0xb2b2_b2b2_b2b2_b2b2;

/// EL0 program that reads the u64 at [`USER_DATA_VA`] into `x0` and logs it,
/// then exits. Position-independent (it materializes the fixed user VA rather
/// than depending on where it is loaded), hand-assembled little-endian.
///
/// ```text
///   movz x1, #0x0030, lsl #16   ; x1 = USER_DATA_VA (0x1000_0030_0000)
///   movk x1, #0x1000, lsl #32
///   ldr  x0, [x1]               ; x0 = this space's sentinel
///   movz x8, #0                 ; SYS_LOG
///   svc  #0
///   movz x8, #1                 ; SYS_EXIT
///   movz x0, #0
///   svc  #0
///   b    .
/// ```
const READ_DATA_BLOB: &[u8] = &[
    0x01, 0x06, 0xa0, 0xd2, // movz x1, #0x30, lsl #16
    0x01, 0x00, 0xc2, 0xf2, // movk x1, #0x1000, lsl #32
    0x20, 0x00, 0x40, 0xf9, // ldr x0, [x1]
    0x08, 0x00, 0x80, 0xd2, // movz x8, #0  (SYS_LOG)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1  (SYS_EXIT)
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// Monotonic ASID allocator for per-process spaces. ASID 0 is the shared
/// boot/kernel low space; live processes draw 1, 2, … (no reuse here).
static NEXT_ASID: AtomicU64 = AtomicU64::new(1);

fn alloc_asid() -> u16 {
    NEXT_ASID.fetch_add(1, Ordering::Relaxed) as u16
}

/// Where the harness resumes when the EL0 thread exits or faults, and the
/// throwaway the handler saves into on the way back. The EL0 thread never
/// resumes, so its abandoned kernel-stack frame is harmless.
static mut EL0_RETURN_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;
static mut EL0_SCRATCH_CTX: Option<<ContextSwitch as tessera_karch::ContextOps>::Context> = None;

static EL0_LOG: AtomicU64 = AtomicU64::new(0);
static EL0_EXITED: AtomicBool = AtomicBool::new(false);
/// Syndrome of the last EL0 abort, or 0 if none — an EL0 run either exits
/// cleanly or faults, never both.
static EL0_FAULT_ESR: AtomicU64 = AtomicU64::new(0);
static EL0_FAULT_FAR: AtomicU64 = AtomicU64::new(0);

/// True for a data abort taken from a lower exception level (`ESR` class
/// `0b100100`).
fn is_data_abort_lower(esr: u64) -> bool {
    (esr >> 26) & 0x3f == 0b100100
}

/// The EL0 synchronous-exception handler: a `log` records its argument and
/// returns to EL0; an `exit` or any abort records what happened and switches
/// back to the harness (never returning to EL0).
fn el0_sync_hook(frame: &mut tessera_karch_aarch64::TrapFrame) {
    if tessera_karch_aarch64::is_svc(frame.esr) {
        if frame.x[8] == SYS_LOG {
            EL0_LOG.store(frame.x[0], Ordering::SeqCst);
            frame.x[0] = 0; // syscall return value
            return; // resume EL0 after the svc
        }
        // SYS_EXIT (or an unrecognized number): the thread is done.
        EL0_EXITED.store(true, Ordering::SeqCst);
    } else {
        EL0_FAULT_ESR.store(frame.esr, Ordering::SeqCst);
        EL0_FAULT_FAR.store(frame.far, Ordering::SeqCst);
    }
    el0_switch_back();
}

/// Abandons the EL0 thread and resumes the harness at its saved continuation.
fn el0_switch_back() {
    use tessera_karch::ContextOps;
    // SAFETY: single-threaded boot; both contexts were written by `run_el0`
    // before entering EL0, and this switches to the harness continuation,
    // which never switches back into the scratch context.
    unsafe {
        let scratch = &raw mut EL0_SCRATCH_CTX;
        let ret = &raw const EL0_RETURN_CTX;
        if let (Some(s), Some(r)) = ((*scratch).as_mut(), (*ret).as_ref()) {
            ContextSwitch::switch(s, r);
        }
    }
}

/// Writes `blob` into the user code page, publishes it to the instruction
/// stream, enters EL0 with `arg` in `x0`, and returns when the EL0 thread
/// exits or faults (via [`el0_switch_back`]). `low` is the active low-half
/// (`TTBR0`) space the user code lives in.
fn run_el0(low: &mut KernelAddressSpace, code: PhysFrame, blob: &[u8], arg: usize) {
    use tessera_karch::{AddressSpaceOps, ContextOps, UserContextOps};
    low.write_bytes_to_frame(code, 0, blob);
    low.sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    EL0_EXITED.store(false, Ordering::SeqCst);
    EL0_FAULT_ESR.store(0, Ordering::SeqCst);
    EL0_FAULT_FAR.store(0, Ordering::SeqCst);
    EL0_LOG.store(0, Ordering::SeqCst);

    let user_stack_top = VirtAddr::new(USER_STACK_VA + FRAME_SIZE);
    let kstack_top = VirtAddr::new(EL0_KSTACK_VA + EL0_KSTACK_PAGES * FRAME_SIZE);
    // SAFETY: `kstack_top` tops the EL0 thread's exclusively-owned kernel
    // stack, and `USER_CODE_VA`/`user_stack_top` are the just-mapped user code
    // and stack, EL0-accessible in this (active) address space.
    let user_ctx = unsafe {
        ContextSwitch::init_user(kstack_top, VirtAddr::new(USER_CODE_VA), user_stack_top, arg)
    };

    // SAFETY: single-threaded boot; `EL0_RETURN_CTX`/`EL0_SCRATCH_CTX` are
    // written here before the switch that reads them.
    unsafe {
        (&raw mut EL0_RETURN_CTX).write(Some(ContextSwitch::empty()));
        (&raw mut EL0_SCRATCH_CTX).write(Some(ContextSwitch::empty()));
        let ret = &raw mut EL0_RETURN_CTX;
        if let Some(r) = (*ret).as_mut() {
            // Save the harness into the return context and drop to EL0; control
            // comes back here when the handler switches into that saved context.
            ContextSwitch::switch(r, &user_ctx);
        }
    }
}

/// Proves EL0 works: a user program enters ring 3, makes a syscall carrying a
/// register, its W^X violation faults, and its attempt to read kernel memory
/// faults — all contained, the kernel surviving each. Returns the logged
/// value, or the index of the first failing sub-check.
fn el0_check(
    high: &mut KernelAddressSpace,
    low: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use tessera_karch::AddressSpaceOps;

    // The user program's slice lands in the low half (`TTBR0`): user code (rx,
    // EL0) and user stack (rw, EL0). The EL0 thread's kernel stack is high-half
    // (`TTBR1`) kernel memory — the EL1 vector lands on it when EL0 traps. W^X
    // and the EL0/EL1 permission split are enforced by `map`'s flag handling.
    let code = frames.alloc().ok_or(1u32)?;
    low.map(
        VirtAddr::new(USER_CODE_VA),
        code,
        PageFlags::rx().user(),
        frames,
    )
    .map_err(|_| 2u32)?;
    let ustk = frames.alloc().ok_or(3u32)?;
    low.map(
        VirtAddr::new(USER_STACK_VA),
        ustk,
        PageFlags::rw().user(),
        frames,
    )
    .map_err(|_| 4u32)?;
    for page in 0..EL0_KSTACK_PAGES {
        let f = frames.alloc().ok_or(5u32)?;
        high.map(
            VirtAddr::new(EL0_KSTACK_VA + page * FRAME_SIZE),
            f,
            PageFlags::rw().global(),
            frames,
        )
        .map_err(|_| 6u32)?;
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_sync_hook);

    // 1: enter EL0, log a magic through a syscall, exit cleanly.
    const MAGIC: u64 = 0x5e17_c0de;
    run_el0(low, code, LOG_EXIT_BLOB, MAGIC as usize);
    if !EL0_EXITED.load(Ordering::SeqCst) {
        return Err(10);
    }
    if EL0_FAULT_ESR.load(Ordering::SeqCst) != 0 {
        return Err(11);
    }
    let logged = EL0_LOG.load(Ordering::SeqCst);
    if logged != MAGIC {
        return Err(12);
    }

    // 2: W^X — a store to the read-execute code page must fault, as a
    // write-direction data abort from EL0.
    run_el0(low, code, WX_BLOB, 0);
    let esr = EL0_FAULT_ESR.load(Ordering::SeqCst);
    if esr == 0 || !is_data_abort_lower(esr) || !tessera_karch_aarch64::is_write_fault(esr) {
        return Err(13);
    }

    // 3: the privilege boundary — EL0 reading a kernel address must fault. It
    // now rests on the half split itself: the kernel is only in `TTBR1`, which
    // grants no EL0 access, on top of the `AP=EL1-only` leaf bits. The kernel's
    // own text is the target.
    let kernel_addr = &raw const __text_start as usize;
    run_el0(low, code, KREAD_BLOB, kernel_addr);
    if EL0_FAULT_ESR.load(Ordering::SeqCst) == 0 {
        return Err(14); // EL0 must not be able to read kernel memory
    }

    Ok(logged)
}

/// Builds one process's low-half (`TTBR0`) address space: a fresh root with the
/// global device identity ([`build_low_space`]), its own ASID, and its user
/// code/stack/data pages — the data page seeded with `sentinel`. Returns the
/// space and its code frame (which [`run_el0`] writes the program into).
fn build_process(
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    sentinel: u64,
) -> Result<(KernelAddressSpace, PhysFrame), u32> {
    use tessera_karch::AddressSpaceOps;
    let mut space = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 30u32)?;
    space.set_asid(alloc_asid());

    let code = frames.alloc().ok_or(31u32)?;
    space
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 32u32)?;
    let stack = frames.alloc().ok_or(33u32)?;
    space
        .map(
            VirtAddr::new(USER_STACK_VA),
            stack,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 34u32)?;
    let data = frames.alloc().ok_or(35u32)?;
    space
        .map(
            VirtAddr::new(USER_DATA_VA),
            data,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 36u32)?;
    space.write_bytes_to_frame(data, 0, &sentinel.to_le_bytes());

    Ok((space, code))
}

/// Tears down a finished process space: unmap its user leaves (freeing those
/// frames) then free its page-table frames. The space must already be inactive.
fn free_process(space: &mut KernelAddressSpace, frames: &mut kcore::pmem::BumpFrameAllocator<'_>) {
    use tessera_karch::{AddressSpaceOps, FrameSource};
    for va in [USER_CODE_VA, USER_STACK_VA, USER_DATA_VA] {
        if let Ok(frame) = space.unmap(VirtAddr::new(va)) {
            frames.free_frame(frame);
        }
    }
    space.free_tables(frames);
}

/// Proves per-process address spaces: two EL0 processes run the same program in
/// **different** `TTBR0` spaces, each mapping [`USER_DATA_VA`] to its own frame,
/// and each reads back its own sentinel — so the per-process view is real and
/// isolated (a stale-TLB or shared-root bug would cross them). `high` maps the
/// shared EL0 kernel stack (already installed by [`el0_check`]); `boot_low` is
/// the device-bearing space to restore afterwards. Returns the two logged
/// sentinels, verified to match.
fn new_user_check(
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64), u32> {
    use tessera_karch::AddressSpaceOps;

    // Run one process to completion in its own space, returning its logged
    // value. `activate` swaps `TTBR0` (with the space's ASID) so the program
    // sees only this space's memory.
    let mut run = |sentinel: u64| -> Result<(u64, KernelAddressSpace), u32> {
        let (mut space, code) = build_process(frames, sentinel)?;
        // SAFETY: `space` maps this process's user pages; the kernel it returns
        // into is in TTBR1 (untouched by the TTBR0 swap) and the EL0 kernel
        // stack is the shared high-half one, so the swap is safe.
        unsafe { space.activate() };
        run_el0(&mut space, code, READ_DATA_BLOB, 0);
        if !EL0_EXITED.load(Ordering::SeqCst) || EL0_FAULT_ESR.load(Ordering::SeqCst) != 0 {
            return Err(40);
        }
        Ok((EL0_LOG.load(Ordering::SeqCst), space))
    };

    let (log_a, mut space_a) = run(SENTINEL_A)?;
    let (log_b, mut space_b) = run(SENTINEL_B)?;

    // Restore the device-bearing boot space before touching devices again or
    // freeing the process roots.
    // SAFETY: `boot_low` is the boot low-half space, which maps the device
    // identity the kernel needs; it was active before this check.
    unsafe { boot_low.activate() };
    free_process(&mut space_a, frames);
    free_process(&mut space_b, frames);

    // Each process read its own sentinel at the shared virtual address.
    if log_a != SENTINEL_A || log_b != SENTINEL_B {
        return Err(41);
    }
    Ok((log_a, log_b))
}

// --- EL0 on the kcore substrate (D75) ---

/// Kernel stack for the kcore-scheduled EL0 thread, mapped into the kernel
/// high half by `spawn_user`. Distinct from `EL0_KSTACK_VA` (which `el0_check`
/// already mapped into the same high half) so both coexist.
const KCORE_KSTACK_VA: u64 = 0xffff_0000_7000_0000;

/// Sentinel the kcore EL0 process stores at [`USER_DATA_VA`] in its own space
/// and reads back through the syscall — proving both that it was scheduled and
/// that its `TTBR0` was installed (an un-switched space would fault the read).
const KCORE_SENTINEL: u64 = 0xc0de_5ced_c0de_5ced;

/// EL0 program for the kcore path: read the u64 at [`USER_DATA_VA`], make a
/// `DebugWrite`(1) syscall carrying it, then `ProcessExit`(5). Same shape as
/// [`READ_DATA_BLOB`] but with kcore's syscall numbers in `x8`.
const KCORE_EL0_BLOB: &[u8] = &[
    0x01, 0x06, 0xa0, 0xd2, // movz x1, #0x30, lsl #16
    0x01, 0x00, 0xc2, 0xf2, // movk x1, #0x1000, lsl #32
    0x20, 0x00, 0x40, 0xf9, // ldr x0, [x1]
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1  (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5  (ProcessExit)
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// The scheduler carrying the kcore EL0 thread. A static so the syscall hook
/// can reach it to end the thread; accessed only through raw pointers on the
/// single-threaded boot CPU (the executive-substrate discipline), never a held
/// `&mut` across a context switch.
static mut KCORE_SCHED: Option<kcore::sched::Scheduler<ContextSwitch>> = None;

/// The process table. A static (const-initialized, in `.bss`) because a
/// `ProcessTable` is far too large — 16 processes, each with a 1024-entry
/// handle table — to build on the 64 KiB boot stack (the large-object-on-stack
/// hazard); the x86 kernel holds `PROCESSES` the same way.
static mut KCORE_PROCESSES: kcore::process::ProcessTable<KernelAddressSpace> =
    kcore::process::ProcessTable::new();

static KCORE_EL0_LOG: AtomicU64 = AtomicU64::new(0);
static KCORE_EL0_EXITED: AtomicBool = AtomicBool::new(false);
static KCORE_EL0_FAULT: AtomicU64 = AtomicU64::new(0);

/// The kcore-substrate syscall hook: an EL0 `svc` is decoded through kcore's
/// `SyscallNumber` and handled minimally — `DebugWrite` records its argument
/// and resumes EL0; `ProcessExit` (or any abort) ends the thread and returns
/// to the scheduler's boot context.
///
/// Deliberately NOT routed through the shared `kcore::dispatch` (D79): this
/// check proves the pre-Executive bare-`Scheduler` substrate (D75), and the
/// dispatcher requires an `Executive`. The Executive-substrate checks all use
/// [`el0_dispatch_hook`].
fn kcore_el0_hook(frame: &mut tessera_karch_aarch64::TrapFrame) {
    use kcore::syscall::{SyscallNumber, encode_result};
    if tessera_karch_aarch64::is_svc(frame.esr) {
        match SyscallNumber::from_u64(frame.x[8]) {
            Some(SyscallNumber::DebugWrite) => {
                KCORE_EL0_LOG.store(frame.x[0], Ordering::SeqCst);
                frame.x[0] = encode_result(Ok(0)) as u64;
                return; // resume EL0 after the svc
            }
            Some(SyscallNumber::ProcessExit) => {
                KCORE_EL0_EXITED.store(true, Ordering::SeqCst);
            }
            _ => {}
        }
    } else {
        KCORE_EL0_FAULT.store(frame.esr, Ordering::SeqCst);
    }
    end_kcore_thread();
}

/// Ends the running kcore EL0 thread and switches back to the scheduler's boot
/// context — the scheduler's own primitives, not the bespoke ping-pong.
fn end_kcore_thread() {
    // SAFETY: single-threaded boot; `KCORE_SCHED` was initialized before `run`
    // and is accessed only transiently here. `yield_to_boot` switches to the
    // saved boot context and never returns into this abandoned vector frame.
    unsafe {
        let sched = &raw mut KCORE_SCHED;
        if let Some(s) = (*sched).as_mut() {
            if let Some(cur) = s.current() {
                s.terminate(cur);
            }
            s.yield_to_boot();
        }
    }
}

/// Proves the kcore substrate carries an AArch64 EL0 process: a real
/// `kcore::Process` + `kcore::Thread` scheduled by `kcore::Scheduler`, entered
/// through the scheduler (which loads the process `TTBR0` via `prepare_resume`),
/// making a syscall decoded by `kcore::syscall`, and exiting back to boot.
/// Returns the logged sentinel, verified.
fn kcore_el0_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<u64, u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    // The process address space: a fresh low-half (TTBR0) root with the device
    // identity, wrapped by kcore. Map its code (with the program) and a data
    // page (with the sentinel) before it becomes the process's own.
    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 50u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(3), 0);

    let code = frames.alloc().ok_or(51u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 52u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(code, 0, KCORE_EL0_BLOB);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    let data = frames.alloc().ok_or(53u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_DATA_VA),
            data,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 54u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(data, 0, &KCORE_SENTINEL.to_le_bytes());

    // A kcore wrapper aliasing the live kernel high half, so `spawn_user` maps
    // the thread's kernel stack into the real kernel tables the EL1 vector uses.
    // SAFETY: `high` is the active kernel high-half space; the alias is only
    // used to map the kstack below and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(1),
        VirtAddr::new(USER_CODE_VA),
        KCORE_SENTINEL as usize,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(KCORE_KSTACK_VA),
        EL0_KSTACK_PAGES,
        kcore::object::ObjectId::from_raw(1),
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 55u32)?;

    // A real kcore Process owns the address space, held in the static table.
    // SAFETY: single-threaded boot; the table is reached only through raw
    // pointers here (no held `&mut` spans a context switch).
    let proc_idx = unsafe {
        let process =
            kcore::process::Process::new(kcore::object::ObjectId::from_raw(1), user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 56u32)?
    };

    KCORE_EL0_LOG.store(0, Ordering::SeqCst);
    KCORE_EL0_EXITED.store(false, Ordering::SeqCst);
    KCORE_EL0_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: single-threaded boot; initialized before any access, and the
    // scheduler is reached only through raw pointers here and in the hook.
    let thread_idx = unsafe {
        (&raw mut KCORE_SCHED).write(Some(kcore::sched::Scheduler::new(1, 0)));
        let s = (*(&raw mut KCORE_SCHED)).as_mut().ok_or(57u32)?;
        s.add_thread(thread).map_err(|_| 58u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 59u32)?;
        }
    }

    tessera_karch_aarch64::set_el0_sync_hook(kcore_el0_hook);

    // Run the scheduler: it switches to the thread (loading its TTBR0 via
    // prepare_resume), the thread logs the sentinel and exits, and control
    // returns here when the hook yields to boot.
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(s) = (*(&raw mut KCORE_SCHED)).as_mut() {
            s.run();
        }
    }

    // `yield_to_boot` returned here with the *process* TTBR0 still active;
    // restore the device-bearing boot space before its tables are freed (or
    // before the next console write).
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if !KCORE_EL0_EXITED.load(Ordering::SeqCst) || KCORE_EL0_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(60);
    }
    let logged = KCORE_EL0_LOG.load(Ordering::SeqCst);
    if logged != KCORE_SENTINEL {
        return Err(61);
    }

    // Teardown: reap the thread, free its kernel stack (mapped in the aliased
    // kernel space — unmap the leaves by hand, never tearing the alias down),
    // and remove the process (which reclaims the user space).
    // SAFETY: the thread is Exited and off-CPU, so reap is valid.
    unsafe {
        if let Some(s) = (*(&raw mut KCORE_SCHED)).as_mut() {
            s.reap(thread_idx);
        }
    }
    use tessera_karch::FrameSource;
    for page in 0..EL0_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(KCORE_KSTACK_VA + page * FRAME_SIZE))
        {
            frames.free_frame(frame);
        }
    }
    // Remove the process and reclaim its space — freeing the table slot so a
    // later run's threads do not collide with this one's stale thread index in
    // `process_of_thread` (the boot stack now has room to move the process out).
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(logged)
}

// --- IPC: a channel round-trip between two EL0 processes (D76) ---

/// The request magic the client sends and the server logs back — the proof the
/// message crossed the channel.
const IPC_MAGIC: u64 = 0xf00d_cafe_f00d_cafe;

/// Kernel stacks for the two IPC processes, in the kernel high half, distinct
/// from the other EL0 kstacks so all coexist.
const IPC_SERVER_KSTACK_VA: u64 = 0xffff_0000_8000_0000;
const IPC_CLIENT_KSTACK_VA: u64 = 0xffff_0000_9000_0000;
/// Deeper than the log/exit path: an IPC syscall handler parks on this stack
/// across a context switch (the channel `receive`/`call` block by switching).
const IPC_KSTACK_PAGES: u64 = 8;

/// Client program: build a `ChannelMsgArgs` (88 bytes, the ISL struct — D79,
/// widened by the installed-handle report)
/// on the tracked user stack page at `USER_STACK_VA`, describing the request
/// buffer at `USER_DATA_VA` (kernel-seeded with the magic), then
/// `ChannelCall`(14) and `ProcessExit`(5). Register ABI: x0=args-struct ptr,
/// x1=endpoint handle, x8=number.
const IPC_CLIENT_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x0b, 0x80, 0xd2, // movz x10, #0x58        (size = 88)
    0x4a, 0x00, 0xc0, 0xf2, // movk x10, #0x2, lsl #32     (| version 2 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (interface_id = 0)
    0x3f, 0x0d, 0x00, 0xf9, // str xzr, [x9, #24]     (txn_id = 0, kernel stamps)
    0x3f, 0x11, 0x00, 0xf9, // str xzr, [x9, #32]     (method_id|msg_flags = 0)
    0x0b, 0x06, 0xa0, 0xd2, // movz x11, #0x30, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = USER_DATA_VA)
    0x2b, 0x15, 0x00, 0xf9, // str x11, [x9, #40]     (inline_ptr)
    0x0c, 0x01, 0x80, 0xd2, // movz x12, #8
    0x2c, 0x19, 0x00, 0xf9, // str x12, [x9, #48]     (inline_len = 8)
    0x3f, 0x1d, 0x00, 0xf9, // str xzr, [x9, #56]     (handles_ptr = 0)
    0x3f, 0x21, 0x00, 0xf9, // str xzr, [x9, #64]     (handle_count = 0)
    0x3f, 0x25, 0x00, 0xf9, // str xzr, [x9, #72]     (installed_ptr = 0)
    0x3f, 0x29, 0x00, 0xf9, // str xzr, [x9, #80]     (installed_cap = 0)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x01, 0x00, 0x80, 0xd2, // movz x1, #0            (endpoint handle 0)
    0xc8, 0x01, 0x80, 0xd2, // movz x8, #14           (ChannelCall)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5            (ProcessExit)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// Server program: build the same `ChannelMsgArgs` (its `inline_ptr`/`inline_len`
/// describe the receive buffer at `USER_DATA_VA`), `ChannelRecv`(13), read the
/// delivered magic and `DebugWrite`(1) it, then rewrite the descriptor to an
/// empty payload and `ChannelReply`(15). GPRs survive an svc (the trap frame
/// restores them), so x9/x11 stay live across the calls.
const IPC_SERVER_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x0b, 0x80, 0xd2, // movz x10, #0x58        (size = 88)
    0x4a, 0x00, 0xc0, 0xf2, // movk x10, #0x2, lsl #32     (| version 2 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (interface_id = 0)
    0x3f, 0x0d, 0x00, 0xf9, // str xzr, [x9, #24]     (txn_id = 0)
    0x3f, 0x11, 0x00, 0xf9, // str xzr, [x9, #32]     (method_id|msg_flags = 0)
    0x0b, 0x06, 0xa0, 0xd2, // movz x11, #0x30, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = USER_DATA_VA)
    0x2b, 0x15, 0x00, 0xf9, // str x11, [x9, #40]     (inline_ptr = recv buf)
    0x0c, 0x01, 0x80, 0xd2, // movz x12, #8
    0x2c, 0x19, 0x00, 0xf9, // str x12, [x9, #48]     (inline_len = 8)
    0x3f, 0x1d, 0x00, 0xf9, // str xzr, [x9, #56]     (handles_ptr = 0)
    0x3f, 0x21, 0x00, 0xf9, // str xzr, [x9, #64]     (handle_count = 0)
    0x3f, 0x25, 0x00, 0xf9, // str xzr, [x9, #72]     (installed_ptr = 0)
    0x3f, 0x29, 0x00, 0xf9, // str xzr, [x9, #80]     (installed_cap = 0)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x01, 0x00, 0x80, 0xd2, // movz x1, #0            (endpoint handle 0)
    0xa8, 0x01, 0x80, 0xd2, // movz x8, #13           (ChannelRecv)
    0x01, 0x00, 0x00, 0xd4, // svc #0                 (returns n = 8)
    0x60, 0x01, 0x40, 0xf9, // ldr x0, [x11]          (x0 = delivered magic)
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1            (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x3f, 0x15, 0x00, 0xf9, // str xzr, [x9, #40]     (inline_ptr = 0: empty reply)
    0x3f, 0x19, 0x00, 0xf9, // str xzr, [x9, #48]     (inline_len = 0)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x01, 0x00, 0x80, 0xd2, // movz x1, #0            (endpoint handle 0)
    0xe8, 0x01, 0x80, 0xd2, // movz x8, #15           (ChannelReply)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

/// The executive carrying the IPC processes' threads and their channel. A
/// static reached only through raw pointers on the single-threaded boot CPU;
/// the channel ops re-enter it across a handoff, the executive-substrate
/// discipline (never a held `&mut` spanning a switch that a peer also borrows).
static mut KCORE_EXEC: Option<kcore::exec::Executive<ContextSwitch>> = None;

/// Shared result sinks for every Executive-substrate EL0 check (IPC,
/// MapDevice, DmaAlloc — D79). The checks run sequentially on the single boot
/// CPU; each resets them before `run()` and reads them after.
static EL0_SINK_LOG: AtomicU64 = AtomicU64::new(0);
static EL0_SINK_EXITED: AtomicBool = AtomicBool::new(false);
static EL0_SINK_FAULT: AtomicU64 = AtomicU64::new(0);

/// The boot frame allocator, reachable from the (argument-less) dispatch hook
/// so covered syscalls can build page tables and DMA pages. A raw pointer
/// valid **only** while an Executive-substrate check runs (the allocator lives
/// on `kmain`'s stack); set before the process runs and cleared after.
static mut EL0_DISPATCH_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

/// A `&mut` to the IPC executive, via the raw static. Provably initialized
/// before any thread runs.
fn ipc_exec() -> &'static mut kcore::exec::Executive<ContextSwitch> {
    // SAFETY: single-core cooperative; `KCORE_EXEC` is set in `ipc_check` before
    // any thread runs, and each channel handoff switches control, so only one
    // borrow is ever actively in flight.
    unsafe {
        match (*(&raw mut KCORE_EXEC)).as_mut() {
            Some(exec) => exec,
            None => fatal_no_executive(),
        }
    }
}

#[inline(never)]
fn fatal_no_executive() -> ! {
    kprintln!("ipc: FATAL: executive uninitialized");
    SemihostingExit::exit(ExitCode::Failure)
}

/// The running thread's scheduler index.
fn ipc_current() -> Option<usize> {
    ipc_exec().scheduler().current()
}

/// Ends the running EL0 thread and switches to the next ready thread — or
/// the boot context only when nothing is runnable (`exit_current`, D82: the
/// old terminate-and-yield-to-boot ended the whole run at the FIRST exit,
/// abandoning a still-ready second client).
fn ipc_end_thread() {
    ipc_exec().scheduler().exit_current();
}

/// The GIC INTID whose interrupts the ring-3 host is currently wired to
/// (0 = none). Set strictly around the host check's `run()` — the same
/// unmask-only-around-the-run window the x86 COM2 demo uses — so the bridge
/// below can never race boot-context Executive access.
static RING3_BLK_INTID: AtomicU32 = AtomicU32::new(0);

/// The device-IRQ bridge (D84): claims the ring-3 host's device INTID,
/// masks the line (storm-safe for level-triggered sources — the trap path
/// EOIs unconditionally; the host re-arms via `IrqComplete` after acking the
/// device), and signals the host's port. Runs in interrupt context.
fn virtio_irq_hook(id: u32) -> bool {
    let wired = RING3_BLK_INTID.load(Ordering::SeqCst);
    if wired == 0 || id != wired {
        return false;
    }
    // SAFETY: masking a GIC line is an interrupt-controller register write
    // with no memory-model footprint.
    unsafe { tessera_karch_aarch64::disable_irq(id) };
    // SAFETY: exception entry sets PSTATE.I, so this IRQ can only have
    // preempted EL0 execution or boot code outside the enable window — never
    // a live Executive borrow (kernel dispatch runs with IRQs masked from
    // entry to eret, and boot only enables the line for the duration of the
    // scheduler run it does not otherwise touch the Executive within).
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.port_signal(id as u64, 1, 1);
        }
    }
    true
}

/// `IrqComplete` (D84, port-local): re-enable the interrupt line of the
/// device named by the caller's Device capability, after the driver has
/// acknowledged the device through its own mapped window. Requires
/// `Rights::MAP` (the driver authority) and a wired INTID in the resource
/// graph; the INTID comes solely from the capability, never the caller.
fn irq_complete(caller: usize, args_ptr: u64) -> i64 {
    use kcore::rights::Rights;
    use kcore::syscall::{
        IRQ_COMPLETE_ARGS_SIZE, decode_irq_complete_args, encode_result, read_user,
    };
    use tessera_karch::KError;

    let handle = {
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
    // SAFETY: transient raw read of the static executive.
    let intid =
        unsafe { (*(&raw const KCORE_EXEC)).as_ref() }.and_then(|e| e.intid_of_object(handle));
    let Some(intid) = intid else {
        return encode_result(Err(KError::AccessDenied));
    };
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };
    encode_result(Ok(0))
}

/// The one EL0 syscall hook for every Executive-substrate check (D79):
/// normalizes the trap frame into a `SyscallRequest` (`x8` = number,
/// `x0..x5` = args), routes it through the shared kcore dispatcher, and keeps
/// only the port-divergent arms local — `DebugWrite` records the raw `x0`
/// value in [`EL0_SINK_LOG`], `ProcessExit` sets [`EL0_SINK_EXITED`] and ends
/// the thread. A covered arm's result lands back in `x0`. A channel op may
/// hand off inside `dispatch` and resume here later; a `ChannelReply` leaves
/// the server blocked and this frame parked, never resumed.
fn el0_dispatch_hook(frame: &mut tessera_karch_aarch64::TrapFrame) {
    use kcore::dispatch::{DispatchEnv, DispatchOutcome, SyscallRequest, dispatch};
    use kcore::syscall::{SyscallNumber, encode_result};
    if !tessera_karch_aarch64::is_svc(frame.esr) {
        EL0_SINK_FAULT.store(frame.esr, Ordering::SeqCst);
        ipc_end_thread();
        return;
    }
    let Some(caller) = ipc_current() else {
        EL0_SINK_FAULT.store(0xbad0, Ordering::SeqCst);
        ipc_end_thread();
        return;
    };
    // SAFETY: transient raw read of the check-scoped allocator pointer.
    let frames = unsafe { *(&raw const EL0_DISPATCH_FRAMES) };
    if frames.is_null() {
        // A check forgot to expose the boot allocator — fail loudly (a
        // distinct fault sink), never by dereferencing null in a covered arm.
        EL0_SINK_FAULT.store(0xbad2, Ordering::SeqCst);
        ipc_end_thread();
        return;
    }
    let req = SyscallRequest {
        number: frame.x[8],
        args: [
            frame.x[0], frame.x[1], frame.x[2], frame.x[3], frame.x[4], frame.x[5],
        ],
    };
    // SAFETY: single-core cooperative boot. The statics are initialized by the
    // running check before `run()`; `EL0_DISPATCH_FRAMES` points at the boot
    // allocator for the check's duration (checked non-null above). A blocking
    // channel op parks this frame — env borrows included — on the blocked
    // thread's kernel stack; the parked borrows are never dereferenced until
    // the handoff returns here (the executive-substrate discipline).
    let outcome = unsafe {
        let mut env = DispatchEnv {
            exec: match (*(&raw mut KCORE_EXEC)).as_mut() {
                Some(exec) => exec,
                None => fatal_no_executive(),
            },
            processes: &mut *(&raw mut KCORE_PROCESSES),
            caller,
            alloc: &mut *frames,
        };
        dispatch(&mut env, &req)
    };
    match outcome {
        DispatchOutcome::Return(v) => frame.x[0] = v as u64,
        DispatchOutcome::Unhandled => match SyscallNumber::from_u64(frame.x[8]) {
            Some(SyscallNumber::IrqComplete) => {
                // Arch-coupled (a GIC enable), so port-local like
                // DebugWrite/ProcessExit (D79 class; D84).
                frame.x[0] = irq_complete(caller, frame.x[0]) as u64;
            }
            Some(SyscallNumber::DebugWrite) => {
                // XOR-accumulate so multiple reporters compose (two host
                // clients, D82); single-writer checks are value-identical
                // (each resets the sink to 0 and writes once).
                EL0_SINK_LOG.fetch_xor(frame.x[0], Ordering::SeqCst);
                frame.x[0] = encode_result(Ok(0)) as u64;
            }
            Some(SyscallNumber::ProcessExit) => {
                EL0_SINK_EXITED.store(true, Ordering::SeqCst);
                ipc_end_thread();
            }
            _ => {
                EL0_SINK_FAULT.store(0xbad1, Ordering::SeqCst);
                ipc_end_thread();
            }
        },
    }
}

/// Builds one IPC process: a fresh space with its program at `USER_CODE_VA`, a
/// user stack, a data buffer (seeded with `data`), and its endpoint installed
/// at handle 0. Returns `(thread_index, process_index)` — teardown needs the
/// process index to `remove` it from the table (else its stale thread index
/// collides with a later check's reused scheduler slot in `process_of_thread`).
#[allow(clippy::too_many_arguments)]
fn ipc_spawn_process(
    high: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blob: &[u8],
    kstack_va: u64,
    endpoint_object: kcore::object::ObjectId,
    data: &[u8],
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| base_err)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    // Map through the kcore wrapper (not the arch directly) so the mappings are
    // tracked — `validate_user_range`/`rights_at` consult the wrapper's mapping
    // table, and a syscall reading these buffers must find them there. Then
    // write the program/data into the freshly allocated (zeroed) frames.
    user_space
        .map_anonymous(
            VirtAddr::new(USER_CODE_VA),
            FRAME_SIZE,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| base_err + 1)?;
    let code = user_space
        .arch()
        .translate(VirtAddr::new(USER_CODE_VA))
        .map(|(f, _)| f)
        .ok_or(base_err + 2)?;
    user_space.arch().write_bytes_to_frame(code, 0, blob);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    user_space
        .map_anonymous(
            VirtAddr::new(USER_DATA_VA),
            FRAME_SIZE,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| base_err + 3)?;
    let data_frame = user_space
        .arch()
        .translate(VirtAddr::new(USER_DATA_VA))
        .map(|(f, _)| f)
        .ok_or(base_err + 4)?;
    user_space.arch().write_bytes_to_frame(data_frame, 0, data);

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kstack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(kstack_va),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(kstack_va),
        IPC_KSTACK_PAGES,
        endpoint_object,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| base_err + 5)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 6)?
            .add_thread(thread)
            .map_err(|_| base_err + 7)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(endpoint_object, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| base_err + 8)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| base_err + 9)?;
            // The first install in each fresh handle table lands at handle 0,
            // which the programs name.
            p.handles_mut()
                .install(endpoint_object, Rights::READ | Rights::WRITE)
                .map_err(|_| base_err + 10)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// Proves the kcore IPC substrate on AArch64: two EL0 processes exchange a
/// message over a channel — the client `call`s with a magic, the server
/// `receive`s it, logs it back, and `reply`s, exercising the scheduler's
/// blocking handoff between address spaces. Returns the magic the server saw.
fn ipc_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<(u64, u64), u32> {
    use tessera_karch::AddressSpaceOps;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let (server_ep, client_ep) = ipc_exec().channel_create().map_err(|_| 70u32)?;
    let server_obj = kcore::object::ObjectId::from_raw(10);
    let client_obj = kcore::object::ObjectId::from_raw(11);
    ipc_exec().bind_endpoint_object(server_ep, server_obj);
    ipc_exec().bind_endpoint_object(client_ep, client_obj);

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // The server is built first so it schedules first and parks on `receive`
    // before the client `call`s.
    let (server_idx, server_proc) = ipc_spawn_process(
        high,
        frames,
        IPC_SERVER_BLOB,
        IPC_SERVER_KSTACK_VA,
        server_obj,
        &[0u8; 8],
        71,
    )?;
    let (client_idx, client_proc) = ipc_spawn_process(
        high,
        frames,
        IPC_CLIENT_BLOB,
        IPC_CLIENT_KSTACK_VA,
        client_obj,
        &IPC_MAGIC.to_le_bytes(),
        80,
    )?;

    // Expose the boot allocator to the dispatch hook: the channel arms build
    // nothing today, but dispatch requires a live frame source (page tables
    // for a covered map arm; a null pointer is a distinct 0xbad2 fault).
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the transmute only erases the borrow lifetime; the pointer is
    // used solely while this check runs, strictly inside that borrow.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    let switches_before = ipc_exec().switch_count();
    // SAFETY: transient raw access; `run` returns when the last thread yields.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    let switches = ipc_exec().switch_count() - switches_before;
    // SAFETY: the check is over; the hook can no longer fire on this pointer.
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(90);
    }
    let seen = EL0_SINK_LOG.load(Ordering::SeqCst);
    if seen != IPC_MAGIC {
        return Err(91);
    }

    // Teardown: reap both threads (both off-CPU — client Exited, server Blocked)
    // and remove each process, reclaiming its space. Removing (not just
    // tearing down in place) frees the table slots so a later check's threads do
    // not collide with these stale thread indices in `process_of_thread`.
    // SAFETY: transient raw access; both threads are off-CPU, removed once.
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

    Ok((seen, switches))
}

// --- MapDevice: a ring-3 process maps and reads a device's MMIO registers (D77) ---

/// The user VA the ring-3 driver asks `map_device` to place the virtio window at.
/// A fresh high user address, distinct from the code/stack it already holds. The
/// value is also encoded in `MMIO_PROBE_BLOB` (the `movz`/`movk` of `x11`, the
/// args struct's `vaddr` field); this constant documents it and pins the
/// invariant the syscall enforces.
const USER_MMIO_VA: u64 = 0x0000_1000_0040_0000;
const _: () = assert!(
    USER_MMIO_VA < 0x0000_8000_0000_0000 && USER_MMIO_VA % FRAME_SIZE == 0,
    "USER_MMIO_VA must be a page-aligned user address",
);
/// The MMIO process's kernel stack, distinct from the other EL0 kstacks.
const MMIO_KSTACK_VA: u64 = 0xffff_0000_a000_0000;

/// A ring-3 driver program: build a `MapDeviceArgs` (32 bytes, the ISL struct —
/// D79: device handle 0, vaddr `USER_MMIO_VA`) on the tracked user stack page,
/// `MapDevice`(23), then read the identity registers directly from EL0 (through
/// the register base the syscall returns in x0 — the mapped page VA plus the
/// window's intra-page offset) and `DebugWrite`(1) the packed
/// `MAGIC | (DEVICE_ID << 32)`, then `ProcessExit`(5). Register ABI:
/// x0=args-struct ptr, x8=number; MapDevice returns the register base in x0.
const MMIO_PROBE_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x04, 0x80, 0xd2, // movz x10, #0x20        (size = 32)
    0x2a, 0x00, 0xc0, 0xf2, // movk x10, #0x1, lsl #32     (| version 1 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (device handle 0 | reserved)
    0x0b, 0x08, 0xa0, 0xd2, // movz x11, #0x40, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = USER_MMIO_VA)
    0x2b, 0x0d, 0x00, 0xf9, // str x11, [x9, #24]     (vaddr)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0xe8, 0x02, 0x80, 0xd2, // movz x8, #23           (MapDevice)
    0x01, 0x00, 0x00, 0xd4, // svc #0                 (x0 = register base VA)
    0x02, 0x00, 0x40, 0xb9, // ldr w2, [x0]           (MAGIC   @ +0x000)
    0x03, 0x08, 0x40, 0xb9, // ldr w3, [x0, #8]       (DEVICE_ID @ +0x008)
    0x40, 0x80, 0x03, 0xaa, // orr x0, x2, x3, lsl #32     (pack magic|id<<32)
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1            (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5            (ProcessExit)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

// The `MapDevice` semantics (capability resolution, `Rights::MAP`,
// containing-page mapping of the unaligned window, untracked device page) live
// in the shared kcore dispatcher (`kcore::dispatch`, D79); this check only
// grants the capability and verifies what the ring-3 probe read.

/// Proves a ring-3 process can safely touch device registers: an EL0 process is
/// granted a Device capability whose payload is the virtio-mmio window, maps it
/// into its own address space with `map_device`, and reads the identity
/// registers directly — capability-gated MMIO, the foundation of a ring-3 driver
/// host. Read-only, so the in-kernel `virtio::check` still runs afterward.
/// Returns the packed `MAGIC | (DEVICE_ID << 32)` the driver read.
fn mmio_map_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    mmio_base: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, FrameSource};

    // A fresh executive on the shared static: it owns the scheduler that runs the
    // process and the device resource graph the capability resolves against.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }

    // Register the virtio window as an MMIO Device object in the resource graph.
    let device_obj = kcore::object::ObjectId::from_raw(20);
    // SAFETY: transient raw access to the static executive.
    unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(100u32)?
            .device_register_mmio(device_obj, mmio_base, FRAME_SIZE)
            .map_err(|_| 101u32)?;
    }

    // Build the process: a fresh low-half space with the program at USER_CODE_VA.
    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 102u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let code = frames.alloc().ok_or(103u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 104u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(code, 0, MMIO_PROBE_BLOB);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kstack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(MMIO_KSTACK_VA),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(MMIO_KSTACK_VA),
        EL0_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 105u32)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(106u32)?
            .scheduler()
            .add_thread(thread)
            .map_err(|_| 107u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 108u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 109u32)?;
            // The first install in a fresh handle table lands at handle 0, which
            // the program names — the Device capability, with READ|MAP only.
            p.handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 110u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the hook for the duration of the run only.
    // SAFETY: `frames` outlives the run (it lives in `kmain`'s frame); the raw
    // pointer is cleared before this function returns, so the hook dereferences
    // it only while it is valid. `frames` is not otherwise touched during `run`.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    // The pointer must not outlive this frame; clear it before anything else.
    // SAFETY: single-threaded; the hook is done (the thread yielded to boot).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(111);
    }
    let packed = EL0_SINK_LOG.load(Ordering::SeqCst);
    // The ring-3 read must be the real virtio signature: MAGIC in the low word,
    // the block DeviceID in the high word.
    if packed & 0xffff_ffff != tessera_virtio::MAGIC as u64
        || packed >> 32 != tessera_virtio::DEVICE_ID_BLOCK as u64
    {
        return Err(112);
    }

    // Teardown: reap the thread, free its kernel stack (mapped in the aliased
    // kernel space), and remove the process. The device page is an untracked raw
    // mapping, so teardown frees only the table frames, never the MMIO phys.
    // SAFETY: the thread is Exited and off-CPU, so reap is valid.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
    }
    for page in 0..EL0_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(MMIO_KSTACK_VA + page * FRAME_SIZE))
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

    Ok(packed)
}

// --- DmaAlloc: a ring-3 driver allocates a DMA buffer (D78) ---

/// The user VA the ring-3 driver asks `dma_alloc` to place its DMA buffer at.
const DMA_VA: u64 = 0x0000_1000_0050_0000;
const _: () = assert!(
    DMA_VA < 0x0000_8000_0000_0000 && DMA_VA % FRAME_SIZE == 0,
    "DMA_VA must be a page-aligned user address",
);
/// The DMA process's kernel stack, distinct from the other EL0 kstacks.
const DMA_KSTACK_VA: u64 = 0xffff_0000_b000_0000;
/// The pattern the ring-3 driver writes into its DMA buffer through its user VA;
/// the kernel reads it back through the direct map at the returned physical
/// address (also encoded in `DMA_PROBE_BLOB`'s `movz`/`movk` of x3).
const DMA_MAGIC: u64 = 0xd4a0_cafe_d4a0_cafe;

/// A ring-3 driver program: build a `DmaAllocArgs` (32 bytes, the ISL struct —
/// D79: device handle 0, vaddr `DMA_VA`) on the tracked user stack page,
/// `DmaAlloc`(24), write `DMA_MAGIC` into the buffer through the user VA, then
/// `DebugWrite`(1) the returned physical address and `ProcessExit`(5). Register
/// ABI: x0=args-struct ptr, x8=number; DmaAlloc returns the phys in x0.
const DMA_PROBE_BLOB: &[u8] = &[
    0x09, 0x02, 0xa0, 0xd2, // movz x9, #0x10, lsl #16
    0x09, 0x00, 0xc2, 0xf2, // movk x9, #0x1000, lsl #32   (x9 = USER_STACK_VA)
    0x0a, 0x04, 0x80, 0xd2, // movz x10, #0x20        (size = 32)
    0x2a, 0x00, 0xc0, 0xf2, // movk x10, #0x1, lsl #32     (| version 1 << 32)
    0x2a, 0x01, 0x00, 0xf9, // str x10, [x9]          (size|version)
    0x3f, 0x05, 0x00, 0xf9, // str xzr, [x9, #8]      (flags = 0)
    0x3f, 0x09, 0x00, 0xf9, // str xzr, [x9, #16]     (device handle 0 | reserved)
    0x0b, 0x0a, 0xa0, 0xd2, // movz x11, #0x50, lsl #16
    0x0b, 0x00, 0xc2, 0xf2, // movk x11, #0x1000, lsl #32  (x11 = DMA_VA)
    0x2b, 0x0d, 0x00, 0xf9, // str x11, [x9, #24]     (vaddr)
    0xe0, 0x03, 0x09, 0xaa, // mov x0, x9             (args-struct ptr)
    0x08, 0x03, 0x80, 0xd2, // movz x8, #24           (DmaAlloc)
    0x01, 0x00, 0x00, 0xd4, // svc #0                 (x0 = physical address)
    0xe2, 0x03, 0x00, 0xaa, // mov x2, x0             (save phys)
    0xc3, 0x5f, 0x99, 0xd2, // movz x3, #0xcafe
    0x03, 0x94, 0xba, 0xf2, // movk x3, #0xd4a0, lsl #16
    0xc3, 0x5f, 0xd9, 0xf2, // movk x3, #0xcafe, lsl #32
    0x03, 0x94, 0xfa, 0xf2, // movk x3, #0xd4a0, lsl #48   (x3 = DMA_MAGIC)
    0x63, 0x01, 0x00, 0xf9, // str x3, [x11]          (write magic via user VA)
    0xe0, 0x03, 0x02, 0xaa, // mov x0, x2             (report phys)
    0x28, 0x00, 0x80, 0xd2, // movz x8, #1            (DebugWrite)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x80, 0xd2, // movz x0, #0
    0xa8, 0x00, 0x80, 0xd2, // movz x8, #5            (ProcessExit)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0x00, 0x00, 0x00, 0x14, // b .
];

// The `DmaAlloc` semantics (capability resolution, `Rights::MAP` + real
// device-cap gate, tracked anonymous page, physical-address return) live in
// the shared kcore dispatcher (`kcore::dispatch`, D79); this check only grants
// the capability and verifies the VA/phys aliasing.

/// Proves a ring-3 driver can obtain DMA-capable memory: an EL0 process holding
/// a Device capability allocates a DMA buffer with `dma_alloc`, writes a magic
/// through its user VA, and reports the returned physical address; the kernel
/// then reads that physical address through the direct map and finds the magic —
/// proving the driver's VA and the device-visible physical address alias the
/// same memory (the property virtio's descriptor rings depend on). Returns the
/// physical address the driver was given.
fn dma_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    mmio_base: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    // A fresh executive on the shared static, holding the device authority.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let device_obj = kcore::object::ObjectId::from_raw(21);
    // SAFETY: transient raw access to the static executive.
    unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(120u32)?
            .device_register_mmio(device_obj, mmio_base, FRAME_SIZE)
            .map_err(|_| 121u32)?;
    }

    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 122u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let code = frames.alloc().ok_or(123u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 124u32)?;
    user_space
        .arch()
        .write_bytes_to_frame(code, 0, DMA_PROBE_BLOB);
    user_space
        .arch()
        .sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kstack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(DMA_KSTACK_VA),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(DMA_KSTACK_VA),
        EL0_KSTACK_PAGES,
        device_obj,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 125u32)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(126u32)?
            .scheduler()
            .add_thread(thread)
            .map_err(|_| 127u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(device_obj, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 128u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 129u32)?;
            p.handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP)
                .map_err(|_| 130u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the hook for the run only.
    // SAFETY: `frames` outlives the run; the pointer is cleared before returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (the thread yielded to boot).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(131);
    }
    let phys = EL0_SINK_LOG.load(Ordering::SeqCst);
    if phys == 0 {
        return Err(132);
    }
    // Read the buffer through the direct map at the physical address the driver
    // was given: the magic it wrote through its own user VA must be there,
    // proving the two views alias the same physical memory (same-core, so the
    // normal-memory write is cache-coherent with this read — a real device DMA
    // would additionally need cache maintenance + barriers, as the in-kernel
    // virtio driver does).
    // SAFETY: `phys` is a RAM frame just mapped into the (not-yet-torn-down)
    // process; the direct map covers all RAM, so this aligned read is in bounds.
    let seen = unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + phys) as *const u64) };
    if seen != DMA_MAGIC {
        return Err(133);
    }

    // Teardown: reap the thread, free its kernel stack, and remove the process —
    // reclaiming the DMA buffer (a tracked anonymous mapping, so teardown frees
    // its frame) and its space.
    // SAFETY: the thread is Exited and off-CPU, so reap is valid.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(thread_idx);
        }
    }
    use tessera_karch::FrameSource;
    for page in 0..EL0_KSTACK_PAGES {
        if let Ok(frame) = kernel_space
            .arch_mut()
            .unmap(VirtAddr::new(DMA_KSTACK_VA + page * FRAME_SIZE))
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

    Ok(phys)
}

// --- Ring-3 driver host: the EL0 blk driver serves a client over IPC (D80/D81) ---

/// The embedded ring-3 device-host and blk-client ELFs. Only the Bazel build
/// embeds them (the generated `device_host_image`/`blk_client_image` crates);
/// the cargo inner loop builds without them and the check reports the images
/// absent — mirroring the x86 root task.
#[cfg(has_ring3_host)]
fn device_host_elf() -> &'static [u8] {
    &device_host_image::DEVICE_HOST_ELF
}
#[cfg(not(has_ring3_host))]
fn device_host_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn device_manager_elf() -> &'static [u8] {
    &device_manager_image::DEVICE_MANAGER_ELF
}
#[cfg(not(has_ring3_host))]
fn device_manager_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn blk_probe_elf() -> &'static [u8] {
    &blk_probe_image::BLK_PROBE_ELF
}
#[cfg(not(has_ring3_host))]
fn blk_probe_elf() -> &'static [u8] {
    &[]
}

#[cfg(has_ring3_host)]
fn blk_client_elf() -> &'static [u8] {
    &blk_client_image::BLK_CLIENT_ELF
}
#[cfg(not(has_ring3_host))]
fn blk_client_elf() -> &'static [u8] {
    &[]
}

/// Kernel stacks for the two host processes, distinct from every other EL0
/// kstack window. Both are 8 pages: a channel op parks its whole dispatch
/// frame on the kernel stack across the handoff (the IPC-check precedent).
const RING3_DRIVER_KSTACK_VA: u64 = 0xffff_0000_c000_0000;
const RING3_MANAGER_KSTACK_VA: u64 = 0xffff_0000_f000_0000;
const RING3_CLIENT_A_KSTACK_VA: u64 = 0xffff_0000_d000_0000;
const RING3_CLIENT_B_KSTACK_VA: u64 = 0xffff_0000_e000_0000;
const RING3_HOST_KSTACK_PAGES: u64 = 8;
/// The host programs run real compiled Rust: 4 user stack pages each.
const RING3_HOST_USER_STACK_PAGES: u64 = 4;
/// The clients' success reports: the disk magic rotated by each client's id
/// (1 and 2). The sink XOR-accumulates both plus the driver's net report, so
/// the expected value needs all three — each is load-bearing, and the
/// rotations keep the two clients' magic-dependent reports from cancelling.
const RING3_HOST_MAGIC: u64 = u64::from_le_bytes(*b"TESSERAV");
/// The host's own net report: an "AR" tag over the SLIRP gateway's MAC
/// (52:55:0a:00:02:02 for 10.0.2.2 — deterministic), LE-packed. Matches the
/// device-host program's NET_REPORT_TAG construction.
const RING3_NET_EXPECTED: u64 = (0x4152 << 48) | 0x0202_000a_5552;
const RING3_HOST_EXPECTED: u64 =
    RING3_HOST_MAGIC.rotate_left(8) ^ RING3_HOST_MAGIC.rotate_left(16) ^ RING3_NET_EXPECTED;

/// Loads a user ELF into `user_space` (the loader path the x86 port proved,
/// on AArch64 since D80): per PT_LOAD, reserve writable + zero-filled (which
/// settles .bss), copy the file bytes, then drop to the final rights — W^X
/// per segment — and publish executable segments to the instruction cache.
/// Returns the entry point. Error codes `base_err..base_err+6`.
fn load_user_elf(
    image: &[u8],
    user_space: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<u64, u32> {
    use kcore::elf;
    use tessera_karch::AddressSpaceOps;

    let parsed = elf::parse(image, elf::Machine::AArch64).map_err(|_| base_err)?;
    for seg in parsed.segments() {
        if seg.write && seg.exec {
            return Err(base_err + 1);
        }
        let vaddr = VirtAddr::new(seg.vaddr);
        if seg.vaddr % FRAME_SIZE != 0
            || seg.vaddr >= <KernelAddressSpace as AddressSpaceOps>::USER_ADDRESS_MAX
        {
            return Err(base_err + 2);
        }
        let len = seg.mem_size.div_ceil(FRAME_SIZE) * FRAME_SIZE;
        user_space
            .map_anonymous(vaddr, len, PageFlags::rw().user(), frames)
            .map_err(|_| base_err + 3)?;
        let end = (seg.file_offset + seg.file_size) as usize;
        if end > image.len() {
            return Err(base_err + 4);
        }
        user_space
            .copy_in(vaddr, &image[seg.file_offset as usize..end])
            .map_err(|_| base_err + 5)?;
        let rights = if seg.exec {
            PageFlags::rx().user()
        } else {
            PageFlags::rw().user()
        };
        user_space
            .protect_range(vaddr, len, rights)
            .map_err(|_| base_err + 6)?;
        if seg.exec {
            user_space.arch().sync_instruction_cache(vaddr, len);
        }
    }
    Ok(parsed.entry())
}

/// Builds one host process from its ELF: fresh TTBR0 space, loaded segments,
/// user stack, kernel stack (in the shared `kernel_space` alias so the check
/// can unmap it at teardown), thread + process registered on the shared
/// executive substrate. Installs NO handles — the caller grants each process
/// exactly its authority. Error codes `base_err..base_err+10`.
fn ring3_host_spawn(
    image: &[u8],
    kstack_va: u64,
    arg: usize,
    process_obj: kcore::object::ObjectId,
    kernel_space: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<(usize, usize), u32> {
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let user_arch =
        build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| base_err + 7)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let entry = load_user_elf(image, &mut user_space, frames, base_err)?;

    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        kcore::thread::ThreadId(kstack_va),
        VirtAddr::new(entry),
        arg,
        VirtAddr::new(USER_STACK_VA),
        RING3_HOST_USER_STACK_PAGES,
        VirtAddr::new(kstack_va),
        RING3_HOST_KSTACK_PAGES,
        process_obj,
        user_root,
        &mut user_space,
        kernel_space,
        frames,
    )
    .map_err(|_| base_err + 8)?;

    // SAFETY: transient raw access to the static executive and process table.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(base_err + 9)?
            .scheduler()
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
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| base_err + 10)?;
        }
    }
    Ok((thread_idx, proc_idx))
}

/// Proves the ring-3 driver **host** end-to-end (D81 + the resident serve
/// loop, D82): the blk driver self-tests its device, then serves TWO client
/// processes over one channel through the `ChannelReplyRecv` server loop —
/// each client `ChannelCall`s a `BlockReadRequest` for sectors 0 and 1, the
/// driver performs each virtio read and replies a `BlockReadReply` with the
/// sector's first bytes, and each client verifies its per-sector disk magic
/// crossed process, channel, and device. The payload protocol is a
/// user↔user ISL contract the kernel never decodes.
fn ring3_host_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blk_base: u64,
    blk_intid: Option<u32>,
    net_base: u64,
) -> Result<(), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    // A fresh executive on the shared static: the scheduler, the channel, and
    // the device resource graph.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // The device tree must carry the blk device's interrupt — a missing one
    // is a fatal misconfiguration, never a silent poll downgrade (D84).
    let blk_intid = blk_intid.ok_or(190u32)?;
    let device_obj = kcore::object::ObjectId::from_raw(22);
    let net_device_obj = kcore::object::ObjectId::from_raw(23);
    let irq_port_obj = kcore::object::ObjectId::from_raw(40);
    let service_port_obj = kcore::object::ObjectId::from_raw(41);
    // One channel PER CLIENT (D85): each caller gets its own endpoint and so
    // its own outstanding-caller slot, which is what makes concurrent,
    // interrupt-driven serving correct (the D82 crossing was one shared slot).
    let server_a_obj = kcore::object::ObjectId::from_raw(50);
    let client_a_obj = kcore::object::ObjectId::from_raw(51);
    let server_b_obj = kcore::object::ObjectId::from_raw(52);
    let client_b_obj = kcore::object::ObjectId::from_raw(53);
    // The bind channel: the driver's only inbound authority at startup, and
    // the one thing it is told rather than discovers.
    let manager_proc_obj = kcore::object::ObjectId::from_raw(24);
    let manager_server_obj = kcore::object::ObjectId::from_raw(60);
    let manager_client_obj = kcore::object::ObjectId::from_raw(61);
    // SAFETY: transient raw access to the static executive.
    let (_channel_a, _channel_b) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(156u32)?;
        exec.device_register_mmio(device_obj, blk_base, FRAME_SIZE)
            .map_err(|_| 157u32)?;
        exec.device_register_mmio(net_device_obj, net_base, FRAME_SIZE)
            .map_err(|_| 189u32)?;
        exec.device_set_mmio_irq(device_obj, blk_intid)
            .map_err(|_| 191u32)?;
        // The IRQ→port bridge: the blk INTID (as the abstract source id)
        // delivers signal 1 to the host's interrupt port.
        let irq_port = exec.port_create().map_err(|_| 192u32)?;
        exec.bind_port_object(irq_port, irq_port_obj);
        exec.port_bind(irq_port, blk_intid as u64, 1)
            .map_err(|_| 193u32)?;

        // A per-client channel each, and one SERVICE port bound to both
        // server-side endpoint objects: a message arriving on either raises
        // SIGNAL_MESSAGE on that endpoint's object, so the host's single
        // `PortWait` is a select that names which client to serve (D85).
        let a = exec.channel_create().map_err(|_| 158u32)?;
        exec.bind_endpoint_object(a.0, server_a_obj);
        exec.bind_endpoint_object(a.1, client_a_obj);
        let b = exec.channel_create().map_err(|_| 194u32)?;
        exec.bind_endpoint_object(b.0, server_b_obj);
        exec.bind_endpoint_object(b.1, client_b_obj);

        // The manager's service channel. Not bound to the service port: the
        // driver *calls* the manager at startup and then never hears from it
        // again, so it is not part of the select.
        let m = exec.channel_create().map_err(|_| 199u32)?;
        exec.bind_endpoint_object(m.0, manager_server_obj);
        exec.bind_endpoint_object(m.1, manager_client_obj);

        let service_port = exec.port_create().map_err(|_| 195u32)?;
        exec.bind_port_object(service_port, service_port_obj);
        exec.port_bind(
            service_port,
            u64::from(server_a_obj.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 196u32)?;
        exec.port_bind(
            service_port,
            u64::from(server_b_obj.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 197u32)?;
        (a, b)
    };

    // One kernel-high alias holds both kernel stacks, so teardown can unmap
    // them. SAFETY: `high` is the active kernel high-half; the alias is never
    // torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // The manager spawns first, for the same server-first reason the driver
    // does: it must be parked on `recv` before the driver's bind call. A
    // racing call would queue and park harmlessly either way.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        RING3_MANAGER_KSTACK_VA,
        // Its startup argument is the number of device capabilities installed
        // below — the whole of its bootstrap contract with boot.
        2,
        manager_proc_obj,
        &mut kernel_space,
        frames,
        200,
    )?;
    // The driver spawns next so it parks on `recv` before the clients call
    // (the M38 server-first pattern).
    let (driver_idx, driver_proc) = ring3_host_spawn(
        device_host_elf(),
        RING3_DRIVER_KSTACK_VA,
        0,
        device_obj,
        &mut kernel_space,
        frames,
        160,
    )?;
    // Two clients (ids 1 and 2 → their report rotations), each on its OWN
    // channel. That is what makes concurrent interrupt-driven serving correct:
    // the driver may park on its device interrupt mid-request while the other
    // client calls, and each caller's reply is matched by its own endpoint's
    // outstanding-caller slot rather than one shared one (D82 → D85).
    let (client_a_idx, client_a_proc) = ring3_host_spawn(
        blk_client_elf(),
        RING3_CLIENT_A_KSTACK_VA,
        1,
        client_a_obj,
        &mut kernel_space,
        frames,
        172,
    )?;
    let (client_b_idx, client_b_proc) = ring3_host_spawn(
        blk_client_elf(),
        RING3_CLIENT_B_KSTACK_VA,
        2,
        client_b_obj,
        &mut kernel_space,
        frames,
        198,
    )?;

    // Each process gets exactly its authority, and the device capabilities no
    // longer go to the driver. The **manager** holds every device: its service
    // endpoint at handle 0, then the blk and net capabilities at 1 and 2, with
    // TRANSFER — handing a capability to another process is itself a right,
    // granted here and nowhere else. The driver holds no device at all until
    // it asks for one by class; it starts with the bind channel at handle 0,
    // its interrupt port at 1, the service port at 2, and the two per-client
    // server endpoints at 3 and 4. Client: only its endpoint, at handle 0.
    //
    // Install order is still the bootstrap ABI each program mirrors — what
    // changed is that no entry in it says *which device* anything is.
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(201u32)?;
            manager
                .handles_mut()
                .install(manager_server_obj, Rights::READ)
                .map_err(|_| 201u32)?;
            manager
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
                .map_err(|_| 201u32)?;
            manager
                .handles_mut()
                .install(
                    net_device_obj,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 201u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(183u32)?;
            driver
                .handles_mut()
                .install(manager_client_obj, Rights::WRITE)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(irq_port_obj, Rights::READ)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(service_port_obj, Rights::READ)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(server_a_obj, Rights::READ)
                .map_err(|_| 183u32)?;
            driver
                .handles_mut()
                .install(server_b_obj, Rights::READ)
                .map_err(|_| 183u32)?;
        }
        for (proc_idx, endpoint) in [(client_a_proc, client_a_obj), (client_b_proc, client_b_obj)] {
            let client = processes.get_mut(proc_idx).ok_or(183u32)?;
            client
                .handles_mut()
                .install(endpoint, Rights::WRITE)
                .map_err(|_| 183u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the hook for the run only.
    // SAFETY: `frames` outlives the run; the pointer is cleared before returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // Wire and enable the device interrupt strictly around the run (the x86
    // COM2 discipline): boot code never touches the Executive inside this
    // window, so the interrupt-context port_signal cannot alias a live
    // borrow.
    tessera_karch_aarch64::set_device_irq_hook(virtio_irq_hook);
    RING3_BLK_INTID.store(blk_intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(blk_intid) };
    // The interrupt pump (D84): a device completion is asynchronous, so it
    // can land after every thread has parked (the host on its interrupt
    // port, the clients in their calls) — `run()` then returns with nothing
    // runnable and the wake would be orphaned. The boot context is the idle
    // loop: re-run whenever an interrupt lands (each wait bounded by the
    // periodic tick), until the check completes or the budget is spent.
    // Between runs boot touches only atomics — never the Executive — so the
    // interrupt-context bridge stays alias-free.
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // The boot context masks IRQs at reset and nothing has unmasked them
    // since: only a kernel thread's trampoline (`daifclr, #2`) and an EL0
    // thread's SPSR run with `DAIF.I` clear. So an interrupt taken "while
    // idle" is a contradiction unless boot unmasks here — `wfi` wakes on a
    // pending-but-masked interrupt and returns without ever taking it, and
    // the pump spins its whole budget while the completion sits asserted.
    // (D85: the reason a driver parked with no other thread runnable was
    // never woken; D84 only ever took its one interrupt because a client
    // thread happened to be running when it landed.) Unmasking is re-done
    // every iteration: returning from a thread switch restores the boot
    // context with IRQs masked again.
    let done = || {
        EL0_SINK_EXITED.load(Ordering::SeqCst)
            && EL0_SINK_LOG.load(Ordering::SeqCst) == RING3_HOST_EXPECTED
    };
    let mut pump_budget = 500u32;
    loop {
        // SAFETY: transient raw access; `run` returns when no thread is
        // runnable (parked threads may become Ready from interrupt context).
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if done() || pump_budget == 0 {
            break;
        }
        pump_budget -= 1;
        // Sleep until any interrupt (the device's, or the bounding tick);
        // the handler runs here at EL1 and may ready the host.
        // SAFETY: the boot context owns the CPU here; the only handler that
        // can run is the interrupt bridge, which touches atomics and the
        // port facility, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();
    // Close the interrupt window before anything else touches the Executive.
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(blk_intid) };
    RING3_BLK_INTID.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(184);
    }
    // The accumulated report: both clients' rotated-magic DebugWrites XORed
    // on success; any failure code from any of the three programs perturbs
    // it (surfaced by the FATAL line for diagnosis).
    if EL0_SINK_LOG.load(Ordering::SeqCst) != RING3_HOST_EXPECTED {
        return Err(185);
    }

    // Teardown: reap all three threads (clients Exited, the resident driver
    // parked Blocked inside its reply-receive — reap accepts an off-CPU
    // Blocked thread), free the kernel stacks, and remove the processes
    // (reclaiming segments, stacks, and the DMA buffer — tracked mappings).
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_a_idx);
            exec.scheduler().reap(client_b_idx);
            exec.scheduler().reap(driver_idx);
            // The manager is parked in `recv` on its bind channel, having
            // handed out both devices and heard nothing since.
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        RING3_DRIVER_KSTACK_VA,
        RING3_CLIENT_A_KSTACK_VA,
        RING3_CLIENT_B_KSTACK_VA,
        RING3_MANAGER_KSTACK_VA,
    ] {
        for page in 0..RING3_HOST_KSTACK_PAGES {
            if let Ok(frame) = kernel_space
                .arch_mut()
                .unmap(VirtAddr::new(kstack + page * FRAME_SIZE))
            {
                frames.free_frame(frame);
            }
        }
    }
    // SAFETY: transient raw access; each process is removed and torn down once.
    unsafe {
        for proc_idx in [client_a_proc, client_b_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }

    Ok(())
}

/// fault was a silent hang: with `VBAR_EL1` unset the CPU branched to zero,
/// faulted again, and looped.
fn fatal_trap(frame: &tessera_karch_aarch64::TrapFrame) -> ! {
    kprintln!(
        "TRAP: {} (esr={:#018x}{})",
        tessera_karch_aarch64::exception_class_name(frame.esr),
        frame.esr,
        if tessera_karch_aarch64::is_write_fault(frame.esr) {
            ", write"
        } else {
            ""
        }
    );
    kprintln!(
        "TRAP: far={:#018x} elr={:#018x} spsr={:#018x} sp={:#018x}",
        frame.far,
        frame.elr,
        frame.spsr,
        frame.sp
    );
    SemihostingExit::exit(ExitCode::Failure)
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    match kcore::panic::enter() {
        PanicDisposition::ExitImmediately => SemihostingExit::exit(ExitCode::Failure),
        PanicDisposition::Report => {
            // SAFETY: panic path on the only running CPU; interrupts are
            // masked for the whole of this milestone.
            unsafe {
                kcore::panic::report_global(format_args!("{}", info.message()), info.location());
            }
            SemihostingExit::exit(ExitCode::Failure)
        }
    }
}

/// Kernel stacks for the rebind check's three processes, distinct from every
/// other EL0 window in this file.
const REBIND_MANAGER_KSTACK_VA: u64 = 0xffff_0002_0000_0000;
const REBIND_DRIVER1_KSTACK_VA: u64 = 0xffff_0002_1000_0000;
const REBIND_DRIVER2_KSTACK_VA: u64 = 0xffff_0002_2000_0000;

/// What each incarnation of the block driver reports: the virtio magic rotated
/// by its incarnation number, so two successful runs cannot look like one run
/// counted twice.
const REBIND_EXPECTED: u64 = 0x7472_6976u64.rotate_left(8) ^ 0x7472_6976u64.rotate_left(16);

/// A driver dies; the device it held is handed to its replacement.
///
/// This is deliberately the smallest arrangement that can show it: one device
/// manager, and one minimal block driver run twice. No clients, no interrupts,
/// no select loop — the earlier attempts bolted this onto the resident host's
/// check and the handover was never the only thing in the picture.
///
/// The sequence a supervisor actually performs: run the driver, watch it go,
/// **tear it down completely**, give the device back, start the replacement.
/// The "tear it down completely" step is not bookkeeping — see
/// `Process::forget_thread` for what a half-torn-down process does to the next
/// one that reuses its scheduler slot.
fn driver_rebind_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blk_base: u64,
) -> Result<(), u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Ok(());
    }

    // A fresh executive: this check shares nothing with the ones before it.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    let device_obj = kcore::object::ObjectId::from_raw(26);
    let manager_server_obj = kcore::object::ObjectId::from_raw(62);
    let manager_client_obj = kcore::object::ObjectId::from_raw(63);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(64);
    let driver1_proc_obj = kcore::object::ObjectId::from_raw(65);
    let driver2_proc_obj = kcore::object::ObjectId::from_raw(66);

    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(220u32)?;
        exec.device_register_mmio(device_obj, blk_base, FRAME_SIZE)
            .map_err(|_| 221u32)?;
        let channel = exec.channel_create().map_err(|_| 222u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        channel.1
    };

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kernel stacks and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // Expose the boot allocator to the syscall hook for the run only.
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // The manager, holding the machine's one device. TRANSFER is what makes it
    // a manager rather than a driver that happens to hold something.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        REBIND_MANAGER_KSTACK_VA,
        1,
        manager_proc_obj,
        &mut kernel_space,
        frames,
        223,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(224u32)?;
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 224u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 224u32)?;
    }

    // Incarnation 1: binds the device, reads its identifying register, exits.
    let (driver1_idx, driver1_proc) = ring3_host_spawn(
        blk_probe_elf(),
        REBIND_DRIVER1_KSTACK_VA,
        1,
        driver1_proc_obj,
        &mut kernel_space,
        frames,
        225,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver1_proc)
            .ok_or(226u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 226u32)?;
    }

    // Everything here is cooperative — a call, a reply, an exit — so the
    // scheduler runs to quiescence without a tick to prod it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    let first = EL0_SINK_LOG.load(Ordering::SeqCst);
    if first != 0x7472_6976u64.rotate_left(8) {
        return Err(227);
    }

    // The driver is gone. Tear it down completely — and note what the
    // supervisor does *not* do here: it never mentions the block device. It
    // does not know which devices this driver held, and does not need to. The
    // kernel hands whatever it was holding back to the manager as part of
    // teardown, so a supervisor cannot cost the machine a device by forgetting.
    //
    // Reaping alone is not teardown: it frees the scheduler slot while leaving
    // the dead process claiming the thread index, and the next spawn reuses it
    // — see `Process::forget_thread`.
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver1_idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(driver1_proc) {
                exec.reclaim_devices(dead, manager_client_ep);
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(driver1_idx);
        if let Some(mut dead) = processes.remove(driver1_proc) {
            dead.space_mut().teardown(frames);
        }
    }

    // Incarnation 2: the same program, a fresh process, no memory of the first.
    let (driver2_idx, driver2_proc) = ring3_host_spawn(
        blk_probe_elf(),
        REBIND_DRIVER2_KSTACK_VA,
        2,
        driver2_proc_obj,
        &mut kernel_space,
        frames,
        229,
    )?;
    // SAFETY: as above.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(driver2_proc)
            .ok_or(230u32)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| 230u32)?;
    }

    // SAFETY: as the first run.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(232);
    }
    if EL0_SINK_LOG.load(Ordering::SeqCst) != REBIND_EXPECTED {
        return Err(233);
    }

    // Teardown.
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
    for kstack in [
        REBIND_MANAGER_KSTACK_VA,
        REBIND_DRIVER1_KSTACK_VA,
        REBIND_DRIVER2_KSTACK_VA,
    ] {
        let _ = kernel_space.reclaim_range(
            VirtAddr::new(kstack),
            RING3_HOST_KSTACK_PAGES * FRAME_SIZE,
            frames,
        );
    }
    Ok(())
}
