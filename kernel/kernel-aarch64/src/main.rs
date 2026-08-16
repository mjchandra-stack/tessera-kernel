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
    let unstamped = kcore::event::set_clock(<Cpu as tessera_karch::CpuOps>::counter_serialized);
    if unstamped > 0 {
        kprintln!("event: {unstamped} record(s) emitted before the clock was installed");
    }
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
        trigger: None,
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
    // One device-interrupt entry point for the whole boot, installed here
    // rather than by each check that wants a bridge — see [`device_irq_hook`]
    // for why the IOMMU's fault interrupt cannot be a per-check installation.
    tessera_karch_aarch64::set_device_irq_hook(device_irq_hook);

    // The verified image store, before anything that might want to read from
    // it. Nothing here needs a device, a bus or a process — the container is
    // in this kernel's own image — so it runs first among the checks, which is
    // also the order `docs/security/01` ("Boot Security") describes: what the
    // system will trust is established before it is used.
    if system_store().is_empty() {
        kprintln!("store: skipped — no system store embedded (cargo inner loop)");
    } else {
        // Where the firmware syscall reads images from, installed once and
        // never changed. The anchors it is checked against are not installed —
        // they are `kcore::store::TRUSTED_ANCHORS` and stay compiled in.
        kcore::firmware::set_system_store(system_store());
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
                SemihostingExit::exit(ExitCode::Failure)
            }
        }
    }

    // PCI enumeration. The windows are mapped into the high half first — see
    // `map_pci_windows` for why the low-half device range cannot reach them.
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
        match pci_host(dtb) {
            Some(host) => {
                if let Err(e) = map_pci_windows(&mut kernel_space, &mut frames, &host) {
                    kprintln!("pcie: FATAL: windows not mapped (kerror {})", e.code());
                    SemihostingExit::exit(ExitCode::Failure)
                }
                let mut functions = [BLANK; MAX_PCI_FUNCTIONS];
                match pcie_enumerate(&host, &mut functions) {
                    Ok(count) => {
                        match functions[..count].iter().find(|f| f.first_bar().is_some()) {
                            Some(f) => {
                                let (bar, len) = f.first_bar().unwrap_or((0, 0));
                                kprintln!(
                                    "pcie: OK — {count} fn at ECAM {:#x}; {:04x}:{:04x} {:02x}:{:02x}.{} class {:#08x} BAR {len:#x}@{bar:#x}",
                                    host.ecam_base,
                                    f.vendor,
                                    f.device,
                                    f.bdf.bus,
                                    f.bdf.device,
                                    f.bdf.function,
                                    f.class_code
                                );
                            }
                            None => kprintln!(
                                "pcie: OK — walked ECAM at {:#x} and found {count} function(s), none with a memory BAR to place",
                                host.ecam_base
                            ),
                        }

                        // Message-signalled interrupts. Two separate claims,
                        // and the verdicts keep them apart: `edu` proves a
                        // device *sends* one, and the virtio endpoint proves
                        // MSI-X is *configured* — nothing here makes virtio
                        // send, which needs its transport (a later milestone).
                        // Whether the hotplug check ejected the endpoint every
                        // later check would bind. Set inside the MSI arm and
                        // read after it, because the removal happens there and
                        // the consequences do not.
                        let mut device_removed = false;
                        match v2m_frame(dtb) {
                            Some(mut frame) => {
                                match functions[..count]
                                    .iter()
                                    .find(|f| f.vendor == EDU_VENDOR && f.device == EDU_DEVICE)
                                {
                                    Some(edu) => match msi_check(&host, &mut frame, edu) {
                                        Ok((spi, delivered)) => {
                                            // msi: OK — a PCI device raised a message-
                                            // signalled interrupt: {:04x}:{:04x} wrote
                                            // the v2m doorbell at {:#x}, the GIC took
                                            // SPI {spi} ({delivered} delivery), and it
                                            // arrived as an ordinary wired interrupt
                                            kprintln!(
                                                "msi: OK — vendor={:04x}, device={:04x}, doorbell={:#x}, spi={spi}, delivered={delivered}",
                                                edu.vendor,
                                                edu.device,
                                                frame.doorbell()
                                            );
                                            kcore::verdict::claims(&["msi.ok"]);
                                        }
                                        Err(which) => {
                                            kprintln!(
                                                "msi: FATAL: check {which} failed (v2m {:#x} spis {}..+{} doorbell {:#x} bar {:#x?})",
                                                frame.base,
                                                frame.first_spi,
                                                frame.spi_count,
                                                frame.doorbell(),
                                                edu.first_bar()
                                            );
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                    },
                                    None => kprintln!(
                                        "msi: skipped — no edu device attached to raise one"
                                    ),
                                }
                                msix_configure_check(&host, &mut frame, &functions[..count]);

                                // DMA scoping. Runs after the MSI check
                                // because enabling the SMMU changes what every
                                // PCI device may reach, and the interrupt
                                // proof should not be entangled with it.
                                // One SMMU, brought up once and left running,
                                // and **not** gated on any particular device:
                                // every proof below is the same hardware, and
                                // a machine with an IOMMU has one whether or
                                // not the device that drives DMA is attached.
                                let mut unit: Option<Smmu> = None;
                                match smmu_device(dtb) {
                                    Some(smmu) => match Smmu::bring_up(smmu.base, &mut frames) {
                                        // Stored before anything borrows it:
                                        // `EL0_DISPATCH_IOMMU` is a raw pointer
                                        // to this, and a pointer to a slot that
                                        // is later moved out of would dangle.
                                        Ok(brought_up) => {
                                            unit = Some(brought_up);
                                            // The fault harvest, wired for the
                                            // rest of the boot. The node's
                                            // first `interrupts` entry is the
                                            // event queue's on this machine —
                                            // the queue whose records *are*
                                            // the faults; the other three
                                            // (PRI, command-sync, global
                                            // error) have no consumer here and
                                            // stay masked.
                                            //
                                            // A node with no interrupt is not
                                            // fatal and not silent: the unit
                                            // still refuses transactions and
                                            // the polled harvest still reads
                                            // them, so what is lost is
                                            // promptness, and the line below
                                            // says which of the two this boot
                                            // got.
                                            // SAFETY: `unit` is a boot-stack
                                            // slot nothing moves out of, and
                                            // the pointer is used only by the
                                            // interrupt bridge under the
                                            // discipline `smmu_irq_hook`
                                            // documents.
                                            unsafe {
                                                BOOT_IOMMU = unit
                                                    .as_mut()
                                                    .map_or(core::ptr::null_mut(), |u| {
                                                        u as *mut Smmu
                                                    });
                                            }
                                            match smmu.intid {
                                                Some(intid) => {
                                                    SMMU_EVENTQ_INTID
                                                        .store(intid, Ordering::SeqCst);
                                                    // **Configure the trigger
                                                    // before enabling the
                                                    // line, from what the tree
                                                    // says rather than from a
                                                    // constant.** The unit
                                                    // pulses this source, and
                                                    // a GIC input left
                                                    // configured
                                                    // level-sensitive latches
                                                    // nothing from a pulse —
                                                    // the interrupt is simply
                                                    // never delivered, with no
                                                    // error anywhere to say
                                                    // why. That is the failure
                                                    // this arm exists to make
                                                    // impossible to
                                                    // reintroduce.
                                                    if smmu.trigger
                                                        == Some(
                                                            tessera_devicetree::IrqTrigger::Edge,
                                                        )
                                                    {
                                                        // SAFETY: configuring
                                                        // a GIC line's trigger
                                                        // is an
                                                        // interrupt-controller
                                                        // register write.
                                                        unsafe {
                                                            tessera_karch_aarch64::set_irq_edge_triggered(intid)
                                                        };
                                                    }
                                                    // SAFETY: enabling a GIC
                                                    // line is an
                                                    // interrupt-controller
                                                    // register write.
                                                    unsafe {
                                                        tessera_karch_aarch64::enable_irq(intid)
                                                    };
                                                    kprintln!(
                                                        "smmu: fault reporting armed on INTID {intid} — a refused transaction now raises the unit's event-queue interrupt"
                                                    );
                                                }
                                                None => kprintln!(
                                                    "smmu: fault reporting is poll-only — the SMMUv3 node declares no interrupt"
                                                ),
                                            }
                                        }
                                        Err(which) => {
                                            kprintln!("smmu: FATAL: bring-up {which} failed");
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                    },
                                    None => {
                                        kprintln!("smmu: skipped — no SMMUv3 in the device tree")
                                    }
                                }

                                match (
                                    unit.as_mut(),
                                    functions[..count]
                                        .iter()
                                        .find(|f| f.vendor == EDU_VENDOR && f.device == EDU_DEVICE),
                                ) {
                                    (Some(unit), Some(edu)) => {
                                        if let Err(which) = unit.register_stream(
                                            SMMU_DEVICE_OBJ,
                                            stream_id_of(edu),
                                            &mut frames,
                                        ) {
                                            kprintln!(
                                                "smmu: FATAL: stream registration {which} failed"
                                            );
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                        match smmu_check(unit, SMMU_DEVICE_OBJ, &mut frames, edu) {
                                            Ok((stream, inside, event)) => {
                                                if inside != DMA_PATTERN {
                                                    kprintln!(
                                                        "smmu: FATAL: the in-aperture transfer did not land (read {inside:#x})"
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                                if event.kind != tessera_smmu::event::F_TRANSLATION
                                                    || event.stream != stream
                                                {
                                                    kprintln!(
                                                        "smmu: FATAL: refused for the wrong reason: kind {:#x} stream {:#x} (wanted a translation fault on stream {stream:#x})",
                                                        event.kind,
                                                        event.stream
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                                // smmu: OK — stream {stream:#x} has a one-
                                                // page aperture: the device's DMA to
                                                // {APERTURE_IOVA:#x} landed ({inside:#x}
                                                // arrived in the page behind it), and the
                                                // same DMA to {OUTSIDE_IOVA:#x} was
                                                // refused by hardware — the SMMU logged a
                                                // translation fault for that stream at
                                                // {:#x}. A device now reaches only what it
                                                // was given
                                                kprintln!(
                                                    "smmu: OK — stream={stream:#x}, aperture iova={APERTURE_IOVA:#x}, inside={inside:#x}, outside iova={OUTSIDE_IOVA:#x}, address={:#x}",
                                                    event.address
                                                );
                                                kcore::verdict::claims(&["smmu.ok"]);
                                            }
                                            Err(which) => {
                                                kprintln!("smmu: FATAL: check {which} failed");
                                                SemihostingExit::exit(ExitCode::Failure)
                                            }
                                        }

                                        // The same aperture, now reached
                                        // through the syscall a driver
                                        // actually calls.
                                        match scoped_dma_check(
                                            &kernel_space,
                                            &ttbr0_space,
                                            &mut frames,
                                            unit,
                                            edu,
                                        ) {
                                            Ok(grant) => {
                                                // smmu-dma: OK — ring-3 asked for a DMA
                                                // buffer and was given an IOVA, not a
                                                // physical address: dma_alloc returned
                                                // {:#x} for a page at phys {:#x}, and the
                                                // device reached the driver's own buffer
                                                // through it ({:#x} came back). The same
                                                // device's DMA to {OUTSIDE_IOVA:#x} was
                                                // refused. Then the driver's capability
                                                // was reclaimed, and the same DMA to {:#x}
                                                // — the address that had just worked — was
                                                // refused too: the SMMU logged a
                                                // translation fault for that stream at
                                                // {:#x}. A DMA lease ends when the
                                                // capability does, and the address it
                                                // covered is free to be issued again. And
                                                // the same device reached a *memory
                                                // object* — memory that already existed,
                                                // owned by a process, rather than a page
                                                // allocated for the device — at {:#x},
                                                // brought {:#x} back out of it, survived 6
                                                // attach/detach rounds at that same
                                                // address through a lease only two pages
                                                // wide — an aperture that would have been
                                                // spent on the second round if an address
                                                // were taken afresh each time — and then
                                                // could not reach it at all once it was
                                                // detached: the SMMU faulted for that
                                                // stream at the address that had just
                                                // worked
                                                kprintln!(
                                                    "smmu-dma: OK — iova {:#x} phys {:#x} echoed {:#x}; {OUTSIDE_IOVA:#x} refused",
                                                    grant.iova,
                                                    grant.phys,
                                                    grant.echoed,
                                                );
                                                kprintln!(
                                                    "smmu-dma: OK — after reclaim {:#x} faulted at {:#x}; attached {:#x} echoed {:#x}",
                                                    grant.iova,
                                                    grant.revoked_at,
                                                    grant.attached_at,
                                                    grant.attach_echoed,
                                                );
                                                kcore::verdict::claims(&["smmu.dma-iova", "smmu.lease-ends", "smmu.attach-memory-object", "smmu.reuse-stable"]);
                                            }
                                            Err(which) => {
                                                kprintln!("smmu-dma: FATAL: check {which} failed");
                                                SemihostingExit::exit(ExitCode::Failure)
                                            }
                                        }

                                        // A fault is no longer only refused —
                                        // it is reported and acted on.
                                        match dma_fault_isolation_check(
                                            unit,
                                            SMMU_DEVICE_OBJ,
                                            &mut frames,
                                            edu,
                                        ) {
                                            Ok(isolation) => {
                                                // smmu-fault: OK — the device's refused
                                                // DMA reached the kernel through the
                                                // SMMU's own event-queue interrupt ({}
                                                // record(s), not by polling), was recorded
                                                // as a structured DEVICE_DMA_FAULT on
                                                // stream {:#x} at {:#x}, and policy ended
                                                // the lease held by process {:#x}: the
                                                // same device's DMA to {:#x} — the address
                                                // it was entitled to a moment earlier — is
                                                // now refused too. A DMA fault isolates
                                                // its driver
                                                kprintln!(
                                                    "smmu-fault: OK — by interrupt={}, stream={:#x}, refused at={:#x}, stopped={:#x}, lease base={:#x}",
                                                    isolation.by_interrupt,
                                                    isolation.stream,
                                                    isolation.refused_at,
                                                    isolation.stopped,
                                                    LEASE_BASE,
                                                );
                                                kcore::verdict::claims(&["smmu.fault-ok"]);
                                            }
                                            Err(which) => {
                                                kprintln!(
                                                    "smmu-fault: FATAL: check {which} failed"
                                                );
                                                SemihostingExit::exit(ExitCode::Failure)
                                            }
                                        }

                                        // And what a refusal leaves behind.
                                        match protected_dma_check(unit, &mut frames, edu) {
                                            Ok(p) => {
                                                // protected-dma: OK — the rule that
                                                // refuses protected memory to an
                                                // unauthorized device left no translation
                                                // behind it: the device read its
                                                // unclassified buffer, and the address the
                                                // refused attach would have returned
                                                // ({:#x}, inside the {:#x}+{:#x} aperture
                                                // this device holds) faulted in hardware —
                                                // {} fault(s) delivered by the SMMU's own
                                                // interrupt on stream {:#x}. An address it
                                                // is entitled to, unmapped because policy
                                                // stopped the mapping being made
                                                kprintln!(
                                                    "protected-dma: OK — refused at={:#x}, 0={:#x}, 1={:#x}, by interrupt={}, stream={:#x}",
                                                    p.refused_at,
                                                    p.aperture.0,
                                                    p.aperture.1,
                                                    p.by_interrupt,
                                                    p.stream,
                                                );
                                                kcore::verdict::claims(&["smmu.protected-ok", "smmu.protected-inside"]);
                                            }
                                            Err(which) => {
                                                kprintln!(
                                                    "protected-dma: FATAL: check {which} failed"
                                                );
                                                SemihostingExit::exit(ExitCode::Failure)
                                            }
                                        }
                                    }
                                    // The bring-up above already said so.
                                    (None, _) => {}
                                    (_, None) => {
                                        kprintln!("smmu: skipped — no edu device to drive DMA")
                                    }
                                }

                                // Drive a PCI device, rather than only
                                // identify one. Skipped when an SMMU is
                                // running: with GBPA aborting, a device whose
                                // stream has no live translation cannot DMA at
                                // all, and driving it through an aperture the
                                // kernel holds is the next milestone, not a
                                // silent part of this one.
                                match functions[..count].iter().find(|f| is_virtio_storage(f)) {
                                    _ if unit.is_some() => kprintln!(
                                        "virtio-pci: skipped — the SMMU is enabled, and this in-kernel driver holds no DMA lease"
                                    ),
                                    Some(f) => match virtio_pci_regions(&host, f) {
                                        Some(regions) => {
                                            match virtio::pci_check(&regions, &mut frames) {
                                                Ok(()) => {
                                                    // virtio-pci: OK — sector 0 read over the
                                                    // PCI transport from {:04x}:{:04x}, magic
                                                    // verified; its controls were found
                                                    // through {} vendor capabilities (common
                                                    // cfg at {:#x}, notify multiplier {})
                                                    kprintln!(
                                                        "virtio-pci: OK — vendor={:04x}, device={:04x}, capabilities={}, commondirect map base={:#x}, notify multiplier={}",
                                                        f.vendor,
                                                        f.device,
                                                        regions.capabilities,
                                                        regions.common - DIRECT_MAP_BASE,
                                                        regions.notify_multiplier
                                                    );
                                                    kcore::verdict::claims(&["virtio-pci.ok"]);
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "virtio-pci: FATAL: check {which} failed"
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                        None => {
                                            kprintln!(
                                                "virtio-pci: FATAL: {:04x}:{:04x} is a mass-storage function but carries no usable virtio capabilities",
                                                f.vendor,
                                                f.device
                                            );
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                    },
                                    None => kprintln!(
                                        "virtio-pci: skipped — no PCI mass-storage function attached"
                                    ),
                                }

                                // **Per-child queue separation** (M98). Where
                                // the controller hardware provides it, a
                                // child's queue is mapped straight to the child
                                // and a transfer crosses no extra process
                                // (`docs/drivers/01`, "Bus Topology And Data
                                // Paths"). This is the controller's half: the
                                // bring-up a child cannot do for itself,
                                // because it touches registers belonging to the
                                // whole device rather than to any one queue.
                                //
                                // The multiqueue function is a *second*
                                // mass-storage device, told to present more
                                // than one request queue; the first is the
                                // single-queue one the check above drives.
                                match functions[..count]
                                    .iter()
                                    .filter(|f| is_virtio_storage(f))
                                    .nth(1)
                                {
                                    _ if unit.is_some() => kprintln!(
                                        "virtio-mq: skipped — the SMMU is enabled, and this in-kernel driver holds no DMA lease"
                                    ),
                                    Some(f) => match virtio_pci_regions(&host, f) {
                                        Some(regions) => {
                                            match virtio::pci_mq_check(&regions, &mut frames) {
                                                Ok(mq) if mq.separate_pages => {
                                                    // virtio-mq: OK — {} of the {} request
                                                    // queues this {:04x}:{:04x} implements
                                                    // were put in service, and sector 0 was
                                                    // read on **queue 1** — the queue a child
                                                    // driver would be given — while queue 0's
                                                    // used ring stayed empty, so the transfer
                                                    // went where it was posted and nowhere
                                                    // else ({:#x} came back). Queue 1's
                                                    // doorbell is at {:#x} and queue 0's at
                                                    // {:#x}, {} page(s) apart with a notify
                                                    // multiplier of {}: two queues that can be
                                                    // granted to two processes, because page
                                                    // granularity is the unit of granting and
                                                    // these do not share one
                                                    kprintln!(
                                                        "virtio-mq: OK — {}/{} queues live on {:04x}:{:04x}; sector 0 read on q1 ({:#x})",
                                                        mq.queues,
                                                        mq.num_queues,
                                                        f.vendor,
                                                        f.device,
                                                        mq.magic,
                                                    );
                                                    kprintln!(
                                                        "virtio-mq: OK — doorbells q1 {:#x} q0 {:#x}, {} page(s) apart, multiplier {}",
                                                        mq.q1_doorbell,
                                                        mq.q0_doorbell,
                                                        mq.q1_doorbell.abs_diff(mq.q0_doorbell) / FRAME_SIZE as usize,
                                                        mq.multiplier,
                                                    );
                                                    kcore::verdict::claims(&["virtio-mq.ok"]);
                                                    // And now hand that queue
                                                    // to a process that holds
                                                    // nothing else.
                                                    match queue_child_check(
                                                        &mq,
                                                        &kernel_space,
                                                        &mut frames,
                                                    ) {
                                                        Ok(child) if child.window_pages == 1 => {
                                                            // queue-child: OK — a ring-3 process
                                                            // started holding a capability to the
                                                            // *controller* and nothing else derived
                                                            // the queue behind it, mapped that queue's
                                                            // doorbell page at {:#x}, published a
                                                            // request onto its ring and rang its own
                                                            // doorbell: the device served a read the
                                                            // kernel never notified ({:#x} came back).
                                                            // The child's whole register-window
                                                            // holding is {} page — the doorbell — so
                                                            // it never had the controller's registers,
                                                            // never touched queue 0, and asked no
                                                            // other process to submit for it. A
                                                            // transfer crossed no extra process
                                                            kprintln!(
                                                                "queue-child: OK — reported={:#x}, magic={:#x}, window pages={}",
                                                                child.reported,
                                                                child.magic,
                                                                child.window_pages
                                                            );
                                                            kcore::verdict::claims(&["queue-child.ok"]);
                                                        }
                                                        Ok(child) => {
                                                            kprintln!(
                                                                "queue-child: FATAL: the child holds {} pages of register window, not 1 — it was given more than its queue",
                                                                child.window_pages
                                                            );
                                                            SemihostingExit::exit(ExitCode::Failure)
                                                        }
                                                        Err(which) => {
                                                            kprintln!(
                                                                "queue-child: FATAL: check {which} failed; the child reported {:#x}",
                                                                EL0_REPORTS[0]
                                                                    .load(Ordering::SeqCst)
                                                            );
                                                            SemihostingExit::exit(ExitCode::Failure)
                                                        }
                                                    }
                                                }
                                                Ok(mq) => {
                                                    // The rings are separate and the doorbells are
                                                    // not, so nothing here could be handed to a
                                                    // child however well it works.
                                                    kprintln!(
                                                        "virtio-mq: FATAL: queue 0 and queue 1 share a doorbell page ({:#x} and {:#x}, multiplier {}) — the machine needs page-per-vq=on",
                                                        mq.q0_doorbell,
                                                        mq.q1_doorbell,
                                                        mq.multiplier
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "virtio-mq: FATAL: check {which} failed"
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                        None => kprintln!(
                                            "virtio-mq: skipped — the multiqueue function carries no usable virtio capabilities"
                                        ),
                                    },
                                    None => kprintln!(
                                        "virtio-mq: skipped — no second PCI mass-storage function attached"
                                    ),
                                }

                                // **Removal.** Runs only on a machine that has
                                // a hot-pluggable slot — a PCI-to-PCI bridge,
                                // which is what a `pcie-root-port` is and what
                                // a device must sit behind to be removable at
                                // all on this bus.
                                //
                                // Discovered rather than declared, and that is
                                // the point: the condition for running this
                                // check is exactly the condition that makes
                                // the thing it checks possible. A boot with no
                                // slot would otherwise wait for a removal
                                // nobody was going to perform and fail for a
                                // reason that has nothing to do with the
                                // kernel.
                                let hotplug_slot = functions[..count]
                                    .iter()
                                    .any(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE);
                                // Declared in the outer scope: the bus-driver
                                // check below the MSI arm needs to know whether
                                // the endpoint it would bind is still here.
                                if hotplug_slot {
                                    // A switch is two bridges: an upstream port
                                    // and a downstream one. Requiring both is
                                    // what distinguishes this machine from the
                                    // single-port one the check used to run on,
                                    // where there was no subtree to remove.
                                    let bridges = functions[..count]
                                        .iter()
                                        .filter(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE)
                                        .count();
                                    let victim = functions[..count].iter().any(is_virtio_storage);
                                    if bridges >= 3 && victim {
                                        match pci_removal_check(
                                            &host,
                                            &functions[..count],
                                            &mut frames,
                                            &kernel_space,
                                        ) {
                                            Ok(outcome) => {
                                                device_removed = true;
                                                // hotplug: OK — the switch stopped
                                                // answering config space after {} polls,
                                                // and one call took {} nodes with it: the
                                                // switch, its downstream port and the
                                                // endpoint below it. The graph knows none
                                                // of them ({}), so every syscall that
                                                // reaches one now refuses; {} capabilities
                                                // were invalidated without their holder
                                                // being consulted, and it still holds the
                                                // root port, which is still in the
                                                // machine. A bus controller does not leave
                                                // alone
                                                kprintln!(
                                                    "hotplug: OK — polls={}, subtree={}, still known={}, holders={}",
                                                    outcome.polls,
                                                    outcome.subtree,
                                                    !outcome.still_known,
                                                    outcome.holders
                                                );
                                                kcore::verdict::claims(&["hotplug.ok"]);
                                            }
                                            Err(which) => {
                                                kprintln!("hotplug: FATAL: check {which} failed");
                                                SemihostingExit::exit(ExitCode::Failure)
                                            }
                                        }
                                    } else {
                                        kprintln!(
                                            "hotplug: skipped — no mass-storage function behind a switch on this machine"
                                        )
                                    }
                                }

                                // Bind a PCI function by class, behind the
                                // SMMU. Skipped when the hotplug check has just
                                // pulled the device out of the machine: the
                                // enumeration this walks was taken before the
                                // removal, so the function it names is one
                                // nothing can bind any more. That it *cannot*
                                // is the previous check's finding, not a
                                // failure of this one.
                                if device_removed {
                                    kprintln!(
                                        "pci-bind: skipped — the device was removed by the hotplug check"
                                    );
                                } else {
                                    // The manager cannot read config space, so the
                                    // only way it can know this is a block device
                                    // is the identity the kernel recorded while
                                    // enumerating — which is what the graph carries
                                    // one for. And because the device translates,
                                    // its driver's DMA is leased.
                                    match functions[..count].iter().find(|f| is_virtio_storage(f)) {
                                        Some(f) => {
                                            // **Which BAR, not just how much of
                                            // it.** `first_bar` is the
                                            // lowest-indexed one, which on a
                                            // virtio-pci function is the MSI-X
                                            // table — not the BAR its
                                            // configuration structures live in. A
                                            // driver granted that reaches the
                                            // wrong region however completely it
                                            // maps it, so the device's own
                                            // capabilities decide, and only a
                                            // device that names none falls back to
                                            // the first.
                                            let (bar, bar_len) = virtio_pci_regions(&host, f)
                                                .map(|r| (r.bar_base, r.bar_len))
                                                .or_else(|| f.first_bar())
                                                .unwrap_or((0, 0));
                                            let identity = pci_identity(f);
                                            // **The bus it sits on, as the
                                            // kernel enumerated it.** The
                                            // manager is handed the bridge and
                                            // has to be able to classify it —
                                            // a hub it cannot identify is a hub
                                            // whose data-path cost is unknown,
                                            // and a device behind one is
                                            // refused rather than assumed to be
                                            // direct-attached. Registering the
                                            // bridge windowless but *identified*
                                            // is what lets the manifest say the
                                            // one thing worth saying about a
                                            // root port: that it relays nothing.
                                            let bridge = f
                                                .parent
                                                .and_then(|parent| {
                                                    functions[..count]
                                                        .iter()
                                                        .find(|b| b.bdf == parent)
                                                })
                                                .map(pci_identity);
                                            // What the driver must report: its
                                            // device's identity, plus a word the
                                            // kernel reads **at the same physical
                                            // address** the driver reaches through
                                            // its mapping — from beyond the first
                                            // page. A one-page grant faults there;
                                            // a grant of the wrong region answers
                                            // with different bytes. Neither can
                                            // agree with this by accident.
                                            let far = if bar_len > FAR_WINDOW_OFFSET {
                                                // SAFETY: the BAR is placed by this
                                                // kernel and mapped into the high
                                                // half; the offset is inside it.
                                                let at = DIRECT_MAP_BASE + bar + FAR_WINDOW_OFFSET;
                                                u64::from(
                                                    unsafe { (at as *const u32).read_volatile() }
                                                        & 0xffff,
                                                )
                                            } else {
                                                0
                                            };
                                            let expected = PCI_REPORT_TAG
                                                | (far << 32)
                                                | (u64::from(f.vendor) << 16)
                                                | u64::from(f.device);
                                            let stream = stream_id_of(f);
                                            // The structure offsets, relative to
                                            // the window the driver is granted.
                                            // `virtio_pci_regions` resolves them
                                            // to direct-map addresses for the
                                            // kernel's own use; a driver needs
                                            // them as offsets, because it maps a
                                            // capability rather than physical
                                            // memory.
                                            let layout = virtio_pci_regions(&host, f).map(|r| {
                                                let offset = |addr: u64| {
                                                    (addr - DIRECT_MAP_BASE - r.bar_base) as u32
                                                };
                                                kcore::devmgr::DeviceLayout {
                                                    common: offset(r.common),
                                                    notify: offset(r.notify),
                                                    notify_multiplier: r.notify_multiplier,
                                                    isr: offset(r.isr),
                                                    device_config: 0,
                                                }
                                            });
                                            match driver_rebind_check(
                                                &kernel_space,
                                                &ttbr0_space,
                                                &mut frames,
                                                bar,
                                                bar_len,
                                                Some(identity),
                                                layout,
                                                unit.as_mut().map(|u| (u, stream)),
                                                bridge,
                                            ) {
                                                Ok(reports)
                                                    if reports.first == expected
                                                        && reports.second == expected =>
                                                {
                                                    match reports.leased_at {
                                                        Some(base) => {
                                                            // pci-bind: OK — the manager matched this
                                                            // device against a binding manifest (class
                                                            // {:#04x} from the graph, vendor {:#06x},
                                                            // revision {}, on PCI — five inputs, not
                                                            // one) and bound it to two drivers in
                                                            // turn, each told the services it requires
                                                            // and the channel it updates through. Each
                                                            // was granted its device's whole
                                                            // {bar_len:#x} window and read {far:#x}
                                                            // from {FAR_WINDOW_OFFSET:#x} into it —
                                                            // past the first page, and the same bytes
                                                            // the kernel reads at that physical
                                                            // address — and then found its device's
                                                            // common configuration structure at offset
                                                            // {:#x}, which the kernel read out of
                                                            // config space the driver cannot reach and
                                                            // reported to it: the driver wrote a
                                                            // feature selector there and read it back.
                                                            // Both were behind the SMMU on stream
                                                            // {stream:#x}, and both were leased the
                                                            // same device-visible addresses from
                                                            // {base:#x} — the second driver got back
                                                            // what the first one's death released. The
                                                            // manager was never handed this device: it
                                                            // was given the **bus** it sits on and
                                                            // derived the device from it ({}), so a
                                                            // driver holding one at all is a
                                                            // capability that came out of the graph's
                                                            // own parent/child edges. That bus is a
                                                            // **real root port**, classified from the
                                                            // identity the kernel recorded while
                                                            // enumerating, and the manifest declares
                                                            // what `docs/drivers/01` says about it:
                                                            // per-child queue separation, so a
                                                            // transfer crosses no extra process. The
                                                            // endpoint's path therefore costs nothing,
                                                            // and it bound against an entry that
                                                            // tolerates only 30us of relayed latency —
                                                            // the same entry that refuses a device two
                                                            // hubs down
                                                            kprintln!(
                                                                "pci-bind: OK — class {:#04x} vendor {:#06x} rev {}; BAR {base:#x}+{bar_len:#x}, read {far:#x} at {FAR_WINDOW_OFFSET:#x}; cfg {:#x}; bus {}",
                                                                f.class_code >> 16,
                                                                f.vendor,
                                                                f.revision,
                                                                layout.map_or(0, |l| l.common),
                                                                reports.derived_from_bus,
                                                            );
                                                            kcore::verdict::claims(&["pci-bind.ok", "pci-bind.common-config", "pci-bind.same-lease", "pci-bind.window-beyond-page", "pci-bind.path-cost", "pci-bind.derived-from-bus"]);
                                                        }
                                                        // pci-bind: OK — the manager classified a
                                                        // device it cannot read (class {:#04x})
                                                        // and bound it to two drivers in turn;
                                                        // each was granted its device's whole
                                                        // {bar_len:#x} window and read {far:#x}
                                                        // from {FAR_WINDOW_OFFSET:#x} into it —
                                                        // past the first page, and the same bytes
                                                        // the kernel reads at that physical
                                                        // address. NOT proven here: the DMA lease,
                                                        // because no SMMU is in front of this
                                                        // device
                                                        None => kprintln!(
                                                            "pci-bind: OK — class code={:#04x}, bar len={bar_len:#x}, far={far:#x}, far window offset={FAR_WINDOW_OFFSET:#x}",
                                                            f.class_code >> 16
                                                        ),
                                                    }
                                                }
                                                Ok(reports) => {
                                                    kprintln!(
                                                        "pci-bind: FATAL: drivers reported {:#x} and {:#x}, expected {expected:#x}",
                                                        reports.first,
                                                        reports.second
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "pci-bind: FATAL: check {which} failed"
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                        None => kprintln!(
                                            "pci-bind: skipped — no PCI mass-storage function attached"
                                        ),
                                    }
                                }

                                // The block class over a second transport, with a
                                // vector per queue. Inside the MSI arm because it needs
                                // the v2m frame the arm holds: MSI-X is how an NVMe
                                // controller says which queue finished, and without a
                                // doorbell to program there is nothing to route.
                                if nvme_driver_elf().is_empty() || blk_client_elf().is_empty() {
                                    kprintln!(
                                        "nvme: skipped (no embedded driver/client ELF; cargo inner-loop build)"
                                    );
                                } else {
                                    match functions[..count]
                                        .iter()
                                        .find(|f| f.class_code >> 8 == PCI_CLASS_NVME)
                                    {
                                        None => {
                                            kprintln!("nvme: skipped — no NVMe controller attached")
                                        }
                                        Some(controller) => {
                                            match nvme_check(
                                                &kernel_space,
                                                &ttbr0_space,
                                                &mut frames,
                                                &host,
                                                &mut frame,
                                                controller,
                                            ) {
                                                Ok(_) => {
                                                    // nvme: OK — a ring-3 driver brought an
                                                    // NVMe controller up and served the BLOCK
                                                    // CLASS over it: the same contract the
                                                    // virtio driver serves, judged by the same
                                                    // client program byte for byte, and the
                                                    // class conformance suite came back
                                                    // complete. Nothing in the schema changed
                                                    // to let a second transport in. Each of
                                                    // its two I/O queues was created with its
                                                    // own MSI-X vector, routed to its own
                                                    // port, so the driver learned which queue
                                                    // completed by where it woke rather than
                                                    // by reading both rings — reads went on
                                                    // one queue and writes on the other, so
                                                    // the contract's own traffic exercised
                                                    // both. Both routes died with the driver:
                                                    // the graph knows neither line now, which
                                                    // a sweep that ended one and stopped would
                                                    // have left half true
                                                    kprintln!(
                                                        "nvme: OK"
                                                    );
                                                    kcore::verdict::claims(&["nvme.ok", "nvme.class-served", "nvme.vector-per-queue", "nvme.conformance-complete"]);
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "nvme: FATAL: check {which} failed (report {:#x}, wanted {NVME_CLIENT_EXPECTED:#x})",
                                                        EL0_SINK_LOG.load(Ordering::SeqCst),
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            None => kprintln!("msi: skipped — no GICv2m frame in the device tree"),
                        }

                        // MMC/SD: a controller whose children are cards, a
                        // medium that can be pulled, and a clock that is asked
                        // for rather than written.
                        if sd_host_elf().is_empty() || blk_client_elf().is_empty() {
                            kprintln!(
                                "sd: skipped (no embedded driver/client ELF; cargo inner-loop build)"
                            );
                        } else {
                            match functions[..count]
                                .iter()
                                .find(|f| f.class_code >> 8 == PCI_CLASS_SD_HOST)
                            {
                                None => kprintln!("sd: skipped — no SD host controller attached"),
                                Some(controller) => {
                                    match sd_check(
                                        &kernel_space,
                                        &ttbr0_space,
                                        &mut frames,
                                        controller,
                                    ) {
                                        Ok(_) => {
                                            // sd: OK — a ring-3 driver identified the
                                            // card in an SD host controller, DECLARED
                                            // it into the resource graph as a device
                                            // behind that controller — one the kernel
                                            // never enumerated, holding no registers
                                            // of its own because every transfer goes
                                            // through the controller — and served the
                                            // block class over it to the same client
                                            // program that judges virtio and NVMe,
                                            // conformance suite and all. Its bus clock
                                            // was asked for rather than written: 400
                                            // kHz to identify and faster to transfer,
                                            // through rules that refuse a rate the
                                            // controller never declared. NOT proven
                                            // here: the card leaving, because this
                                            // emulator's sd-bus refuses to unplug one
                                            // and its controller reports a card even
                                            // with an empty slot — the NO_MEDIUM path
                                            // exists and is exercised against a mock
                                            // whose card can be taken out
                                            kprintln!(
                                                "sd: OK"
                                            );
                                            kcore::verdict::claims(&["sd.ok", "sd.declared", "sd.clock-requested"]);
                                        }
                                        Err(which) => {
                                            kprintln!(
                                                "sd: FATAL: check {which} failed (reports {:#x} {:#x})",
                                                EL0_REPORTS[0].load(Ordering::SeqCst),
                                                EL0_REPORTS[1].load(Ordering::SeqCst),
                                            );
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                    }
                                }
                            }
                        }

                        // Sound: a device that is never finished, and a
                        // stream deliberately starved.
                        if snd_driver_elf().is_empty() || snd_client_elf().is_empty() {
                            kprintln!(
                                "snd: skipped (no embedded driver/client ELF; cargo inner-loop build)"
                            );
                        } else {
                            match functions[..count]
                                .iter()
                                .find(|f| f.class_code >> 8 == PCI_CLASS_AUDIO)
                            {
                                None => kprintln!("snd: skipped — no audio device attached"),
                                Some(audio) => {
                                    let resolved = virtio_pci_regions(&host, audio).map(|r| {
                                        let offset = |addr: u64| {
                                            (addr - DIRECT_MAP_BASE - r.bar_base) as u32
                                        };
                                        (
                                            kcore::devmgr::DeviceLayout {
                                                common: offset(r.common),
                                                notify: offset(r.notify),
                                                notify_multiplier: r.notify_multiplier,
                                                isr: offset(r.isr),
                                                device_config: offset(r.device_cfg),
                                            },
                                            r.bar_base,
                                            r.bar_len,
                                        )
                                    });
                                    match resolved {
                                        None => kprintln!(
                                            "snd: skipped — the audio device's virtio structures did not resolve"
                                        ),
                                        Some((layout, bar_base, bar_len)) => {
                                            match snd_check(
                                                &kernel_space,
                                                &ttbr0_space,
                                                &mut frames,
                                                audio,
                                                layout,
                                                bar_base,
                                                bar_len,
                                            ) {
                                                Ok(_) => {
                                                    // snd: OK — a ring-3 driver brought up a
                                                    // virtio-sound device and served the AUDIO
                                                    // CLASS over it; the conformance suite
                                                    // came back complete on a sixth contract.
                                                    // A supplied stream PLAYED THE PERIODS IT
                                                    // WAS GIVEN, and one primed the same way
                                                    // then abandoned DRAINED AND THE DRIVER
                                                    // REPORTED THE UNDERRUN — which nothing
                                                    // else in the machine records, because a
                                                    // device that runs dry plays silence and
                                                    // does not fault. NOT proven: that a
                                                    // stream can be KEPT fed, which needs an
                                                    // out-of-line grant this contract does not
                                                    // have
                                                    kprintln!(
                                                        "snd: OK"
                                                    );
                                                    kcore::verdict::claims(&["snd.ok", "snd.played-periods", "snd.underrun-reported", "snd.class-served"]);
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "snd: FATAL: check {which} failed (report {:#x}, wanted {SND_CLIENT_EXPECTED:#x})",
                                                        EL0_REPORTS[0].load(Ordering::SeqCst),
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Display: the first device whose work is checked from
                        // outside the machine.
                        if gpu_driver_elf().is_empty() || gpu_client_elf().is_empty() {
                            kprintln!(
                                "gpu: skipped (no embedded driver/client ELF; cargo inner-loop build)"
                            );
                        } else {
                            match functions[..count]
                                .iter()
                                .find(|f| f.class_code >> 16 == PCI_CLASS_DISPLAY)
                            {
                                None => kprintln!("gpu: skipped — no display device attached"),
                                Some(display) => {
                                    let resolved = virtio_pci_regions(&host, display).map(|r| {
                                        let offset = |addr: u64| {
                                            (addr - DIRECT_MAP_BASE - r.bar_base) as u32
                                        };
                                        (
                                            kcore::devmgr::DeviceLayout {
                                                common: offset(r.common),
                                                notify: offset(r.notify),
                                                notify_multiplier: r.notify_multiplier,
                                                isr: offset(r.isr),
                                                device_config: offset(r.device_cfg),
                                            },
                                            r.bar_base,
                                            r.bar_len,
                                        )
                                    });
                                    match resolved {
                                        None => kprintln!(
                                            "gpu: skipped — the display device's virtio structures did not resolve"
                                        ),
                                        Some((layout, bar_base, bar_len)) => {
                                            match gpu_check(
                                                &kernel_space,
                                                &ttbr0_space,
                                                &mut frames,
                                                display,
                                                layout,
                                                bar_base,
                                                bar_len,
                                            ) {
                                                Ok(_) => {
                                                    // gpu: OK — a ring-3 driver brought a
                                                    // virtio-gpu device up and served the
                                                    // DISPLAY CLASS over it, and the
                                                    // conformance suite came back complete on
                                                    // a seventh contract. A client DREW EVERY
                                                    // PIXEL of a 64x64 pattern through the
                                                    // contract and asked for it to be SHOWN,
                                                    // and blits past the edge were REFUSED
                                                    // RATHER THAN CLIPPED. What the guest
                                                    // reports here is deliberately the smaller
                                                    // half: a driver that set the device up
                                                    // correctly and drew nothing would report
                                                    // exactly this, so THE PICTURE ITSELF IS
                                                    // CHECKED FROM OUTSIDE — the harness asks
                                                    // QEMU for the framebuffer while this
                                                    // machine waits, and looks at the pixels
                                                    kprintln!(
                                                        "gpu: OK"
                                                    );
                                                    kcore::verdict::claims(&["gpu.ok", "gpu.class-served", "gpu.drew-every-pixel", "gpu.refused-not-clipped", "gpu.checked-from-outside"]);
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "gpu: FATAL: check {which} failed (report {:#x}, wanted {GPU_CLIENT_EXPECTED:#x})",
                                                        EL0_REPORTS[0].load(Ordering::SeqCst),
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Crypto: a device whose right answer was decided
                        // somewhere else.
                        if crypto_driver_elf().is_empty() || crypto_client_elf().is_empty() {
                            kprintln!(
                                "crypto: skipped (no embedded driver/client ELF; cargo inner-loop build)"
                            );
                        } else {
                            match functions[..count].iter().find(|f| {
                                f.vendor == VIRTIO_VENDOR_ID && f.device == VIRTIO_CRYPTO_DEVICE_ID
                            }) {
                                None => kprintln!("crypto: skipped — no crypto device attached"),
                                Some(engine) => {
                                    let resolved = virtio_pci_regions(&host, engine).map(|r| {
                                        let offset = |addr: u64| {
                                            (addr - DIRECT_MAP_BASE - r.bar_base) as u32
                                        };
                                        (
                                            kcore::devmgr::DeviceLayout {
                                                common: offset(r.common),
                                                notify: offset(r.notify),
                                                notify_multiplier: r.notify_multiplier,
                                                isr: offset(r.isr),
                                                device_config: offset(r.device_cfg),
                                            },
                                            r.bar_base,
                                            r.bar_len,
                                        )
                                    });
                                    match resolved {
                                        None => kprintln!(
                                            "crypto: skipped — the crypto device's virtio structures did not resolve"
                                        ),
                                        Some((layout, bar_base, bar_len)) => {
                                            match crypto_check(
                                                &kernel_space,
                                                &ttbr0_space,
                                                &mut frames,
                                                engine,
                                                layout,
                                                bar_base,
                                                bar_len,
                                            ) {
                                                Ok(_) => {
                                                    // crypto: OK — a ring-3 driver brought a
                                                    // virtio-crypto device up and served the
                                                    // CRYPTO CLASS over it, and the
                                                    // conformance suite came back complete on
                                                    // an eighth contract. A client encrypted
                                                    // NIST SP 800-38A's vector and got back
                                                    // THE CIPHERTEXT THE STANDARD PUBLISHES,
                                                    // decrypted it back to the plaintext, and
                                                    // saw a one-bit change of key CHANGE THE
                                                    // ANSWER — which is what proves the key
                                                    // reached the device rather than being
                                                    // taken and dropped. Four things were
                                                    // REFUSED RATHER THAN GUESSED AT: an
                                                    // algorithm this driver will not perform,
                                                    // a length the mode cannot work in, an
                                                    // operation on a destroyed session, and an
                                                    // operation whose algorithm disagreed with
                                                    // its session. A RESET TOOK EVERY SESSION
                                                    // WITH IT, which nothing else in this
                                                    // machine would have noticed being broken.
                                                    // NOT proven here: that any of this is
                                                    // constant-time, or that the key is safe
                                                    // from a driver that wanted to keep it —
                                                    // the key crosses inline and the refusal
                                                    // policy is a compiled constant
                                                    kprintln!(
                                                        "crypto: OK"
                                                    );
                                                    kcore::verdict::claims(&["crypto.ok", "crypto.class-served", "crypto.standard-vector", "crypto.key-changes-answer", "crypto.refused-not-guessed"]);
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "crypto: FATAL: check {which} failed (report {:#x}, wanted {CRYPTO_CLIENT_EXPECTED:#x})",
                                                        EL0_REPORTS[0].load(Ordering::SeqCst),
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Certification: a run of the checks, and the refusal
                        // it produces. Runs against the same kind of device
                        // the crypto check uses, and asks a different
                        // question — not whether this driver works, but how
                        // much of what certification requires was asked at
                        // all.
                        if crypto_driver_elf().is_empty() || certifier_elf().is_empty() {
                            kprintln!(
                                "certification: skipped (no embedded driver/certifier ELF; cargo inner-loop build)"
                            );
                        } else {
                            match functions[..count].iter().find(|f| {
                                f.vendor == VIRTIO_VENDOR_ID && f.device == VIRTIO_CRYPTO_DEVICE_ID
                            }) {
                                None => kprintln!(
                                    "certification: skipped — no device to certify a driver against"
                                ),
                                Some(engine) => {
                                    let resolved = virtio_pci_regions(&host, engine).map(|r| {
                                        let offset = |addr: u64| {
                                            (addr - DIRECT_MAP_BASE - r.bar_base) as u32
                                        };
                                        (
                                            kcore::devmgr::DeviceLayout {
                                                common: offset(r.common),
                                                notify: offset(r.notify),
                                                notify_multiplier: r.notify_multiplier,
                                                isr: offset(r.isr),
                                                device_config: offset(r.device_cfg),
                                            },
                                            r.bar_base,
                                            r.bar_len,
                                        )
                                    });
                                    match resolved {
                                        None => kprintln!(
                                            "certification: skipped — the device's virtio structures did not resolve"
                                        ),
                                        Some((layout, bar_base, bar_len)) => {
                                            // **First, and in its own run.** It
                                            // builds a fresh executive, so it
                                            // cannot share the run whose
                                            // transcript the other checks come
                                            // from — and a client left without
                                            // an answer would destroy that
                                            // transcript anyway.
                                            let recovered = match crash_recovery_check(
                                                &kernel_space,
                                                &ttbr0_space,
                                                &mut frames,
                                                engine,
                                                layout,
                                                bar_base,
                                                bar_len,
                                            ) {
                                                Ok(recovered) => recovered,
                                                Err(which) => {
                                                    kprintln!(
                                                        "certification: FATAL: crash-recovery check {which} failed"
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            };
                                            match certification_check(
                                                &kernel_space,
                                                &ttbr0_space,
                                                &mut frames,
                                                engine,
                                                layout,
                                                bar_base,
                                                bar_len,
                                                &host,
                                                &functions[..count],
                                                recovered,
                                            ) {
                                                Ok(counts) => {
                                                    // certification: OK — a ring-3 certifier
                                                    // ran the checks a peer can make against a
                                                    // driver and THIS DRIVER IS NOT CERTIFIED.
                                                    // NINE CHECKS RAN, EIGHT PASSED AND ONE
                                                    // FAILED. Two came from the certifier: the
                                                    // seven class rules came back complete,
                                                    // and every reply the driver sent declared
                                                    // the shape the reader decoded it as —
                                                    // which is not what the host golden tests
                                                    // ask, and matters because DestroySession
                                                    // answers with a control reply where a
                                                    // data request went, so a client trusting
                                                    // the method rather than the declaration
                                                    // would read a status out of the wrong
                                                    // offset. The third is one THE CERTIFIER
                                                    // COULD NOT HAVE MADE: it holds a channel
                                                    // and no view of the kernel's event ring,
                                                    // so boot validated the {} TRACE RECORDS
                                                    // THIS DRIVER CAUSED against the schema —
                                                    // every one carried a timestamp and a
                                                    // causal id, named a kind the catalog
                                                    // defines, was filed under the component
                                                    // that schema puts it beneath, and left
                                                    // every payload slot the schema does not
                                                    // describe empty, which is the one place a
                                                    // value can travel through a trace without
                                                    // anybody having agreed that it should.
                                                    // The fourth HAPPENED BEFORE THIS MACHINE
                                                    // EXISTED: {} frozen structs were fuzzed
                                                    // over {} inputs while this kernel was
                                                    // being built, by a runner that exits non-
                                                    // zero on a finding and whose output this
                                                    // binary links — so a kernel that fuzzed
                                                    // badly is a kernel that did not build,
                                                    // and the evidence for that check is THIS
                                                    // ARTIFACT EXISTING rather than anything
                                                    // said at boot. The fifth asked WHAT THIS
                                                    // DRIVER ACTUALLY HOLDS: its {}
                                                    // capabilities were read out of its own
                                                    // handle table, not out of what boot
                                                    // remembers installing — the two differ by
                                                    // exactly what is worth finding, a
                                                    // capability that arrived by transfer
                                                    // carrying rights nobody at this end chose
                                                    // — and every right on every one of them
                                                    // is inside what its manifest entry
                                                    // allows. The sixth is THE ONE THIS DRIVER
                                                    // DOES NOT PASS, and it is a failure
                                                    // rather than a check nobody ran: {} of
                                                    // its DMA grants came back as a physical
                                                    // address rather than an address a unit
                                                    // resolves for this device alone, so ITS
                                                    // MEMORY CANNOT BE CONTAINED ON THIS
                                                    // MACHINE and there is nothing for a DMA
                                                    // fault to be raised against. That is the
                                                    // emulator's device model rather than this
                                                    // kernel's doing, and it is recorded as a
                                                    // failure because a check that failed and
                                                    // said why is worth more than one nobody
                                                    // ran. The seventh held the driver to ITS
                                                    // OWN DESCRIBE REPLY about power: every
                                                    // state it advertised was asked for and
                                                    // reached, every state it did not
                                                    // advertise was refused, no reply named a
                                                    // state it never claimed, and — the one
                                                    // nothing else catches — NO REFUSAL MOVED
                                                    // THE DEVICE, which is a change reported
                                                    // as an error and therefore invisible to
                                                    // every client that reads the status and
                                                    // stops. The eighth suspended the device
                                                    // and brought it back, and then MADE IT DO
                                                    // THE SAME WORK AGAIN: a resume that
                                                    // returns success and leaves a dead device
                                                    // replies Ok exactly like one that worked,
                                                    // so nothing about the resume itself can
                                                    // tell them apart — only asking for the
                                                    // identical operation across the round
                                                    // trip, in THE SAME SESSION THAT EXISTED
                                                    // BEFORE IT, and getting the identical
                                                    // answer. The ninth got its own run,
                                                    // because it had to: a driver was told to
                                                    // TAKE A REQUEST AND NEVER ANSWER IT, and
                                                    // a client that never gets an answer would
                                                    // have destroyed the transcript the other
                                                    // eight rest on. The driver faulted while
                                                    // the client was parked awaiting its
                                                    // reply, and THE CLIENT CAME BACK WITH AN
                                                    // ERROR — which it did not before this
                                                    // machine learned to tell a caller that
                                                    // the process it waits on has died,
                                                    // because a call parks until a reply
                                                    // arrives and a dead server sends none. A
                                                    // client still parked reports nothing at
                                                    // all, so its report is the whole
                                                    // evidence. Then it REFUSED TO CERTIFY,
                                                    // naming the TWO CHECKS NOBODY ASKED —
                                                    // hotplug and performance — because a
                                                    // check nobody ran must never look like a
                                                    // check that passed, and the failure that
                                                    // would hide is not a driver bug but a rig
                                                    // that stopped asking. The same rules
                                                    // refused a forged record and a stale
                                                    // contract version HERE IN RING 3.
                                                    // Separately from the certificate, A
                                                    // DEVICE WAS PULLED OUT OF THIS MACHINE
                                                    // WHILE RING 3 WAS RUNNING: a bridge in a
                                                    // hot-pluggable slot, held by nobody,
                                                    // whose eject request the periodic tick
                                                    // answered after looking {} times during
                                                    // the run — the guest's half of hotplug,
                                                    // which until now only ever happened in a
                                                    // boot loop with no thread alive, which is
                                                    // the one situation a driver is never in.
                                                    // The graph then removed it. Making that
                                                    // happen to a driver's OWN device is the
                                                    // next step and not this one. NOT proven
                                                    // here: anything about the two nobody
                                                    // asked, and that the eight that passed
                                                    // are enough — they are not, which is the
                                                    // point
                                                    kprintln!(
                                                        "certification: OK — trace records={}, targets={}, inputs={}, capabilities={}, unscoped grants={}, slot polls={}",
                                                        counts.trace_records,
                                                        fuzz_evidence::TARGETS,
                                                        fuzz_evidence::INPUTS,
                                                        counts.capabilities,
                                                        counts.unscoped_grants,
                                                        counts.slot_polls
                                                    );
                                                    kcore::verdict::claims(&["cert.ok", "cert.not-certified", "cert.nine-ran", "cert.refused", "cert.two-unasked", "cert.unanswered-request", "cert.client-returned-error", "cert.resume-same-work", "cert.session-survived", "cert.refusal-did-not-move", "cert.held-to-describe", "cert.one-failed", "cert.dma-uncontained", "cert.capabilities-read", "cert.fuzz-at-build", "cert.fuzz-evidence-artifact", "cert.kernel-vantage", "cert.trace-records", "cert.forgery-refused-ring3", "cert.device-pulled"]);
                                                    print_certificate(&counts.certificate);
                                                }
                                                Err(which) => {
                                                    kprintln!(
                                                        "certification: FATAL: check {which} failed (report {:#x}, wanted {CERTIFIER_EXPECTED:#x})",
                                                        EL0_REPORTS[0].load(Ordering::SeqCst),
                                                    );
                                                    SemihostingExit::exit(ExitCode::Failure)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // GPIO: a platform device that says what it is in
                        // its own registers, and one interrupt line becoming
                        // eight interrupt objects.
                        if gpio_driver_elf().is_empty()
                            || gpio_client_elf().is_empty()
                            || platform_bus_elf().is_empty()
                        {
                            kprintln!(
                                "gpio: skipped (no embedded driver/client ELF; cargo inner-loop build)"
                            );
                        } else {
                            match pl061_device(dtb).zip(dtb_total_size(dtb)) {
                                Some((_, dtb_len)) => {
                                    match gpio_check(
                                        &kernel_space,
                                        &ttbr0_space,
                                        &mut frames,
                                        dtb,
                                        dtb_len,
                                    ) {
                                        Ok(0) => {
                                            kprintln!(
                                                "gpio: armed and nobody pressed — skipped (the press comes from outside, over QMP; only one boot drives it)"
                                            );
                                            kcore::verdict::claims(&["gpio.not-pressed"]);
                                        }
                                        Ok(_) => {
                                            // gpio: OK — NOTHING PRIVILEGED LOOKED AT
                                            // THIS DEVICE. A ring-3 bus controller
                                            // read the machine's own description — the
                                            // device tree, mapped as its bus
                                            // capability's window exactly as a PCI
                                            // controller maps ECAM — and declared what
                                            // it found: two devices, one console
                                            // withheld because the kernel is printing
                                            // on it, and the transports beyond what
                                            // this bus forwards counted rather than
                                            // dropped. The kernel routed the interrupt
                                            // by asking the graph which line that
                                            // child has, never by knowing what a PL061
                                            // is. The driver that bound it by class
                                            // checked the part's own PrimeCell
                                            // registers before writing a word to it,
                                            // because a description is a claim. It
                                            // then handed each watching client a
                                            // capability to ONE LINE — an interrupt no
                                            // interrupt controller can see, since
                                            // eight lines share one output and which
                                            // of them fired is in a status register. A
                                            // button was pressed from OUTSIDE the
                                            // machine, the client holding line 3 woke,
                                            // and the client holding line 5 did not
                                            kprintln!(
                                                "gpio: OK"
                                            );
                                            kcore::verdict::claims(&["gpio.ok", "gpio.nothing-privileged", "gpio.read-devicetree", "gpio.per-line-capability", "gpio.pressed-from-outside"]);
                                        }
                                        Err(which) => {
                                            kprintln!(
                                                "gpio: FATAL: check {which} failed ({} reports: {:#x} {:#x})",
                                                EL0_REPORT_COUNT.load(Ordering::SeqCst),
                                                EL0_REPORTS[0].load(Ordering::SeqCst),
                                                EL0_REPORTS[1].load(Ordering::SeqCst),
                                            );
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                    }
                                }
                                None => {
                                    kprintln!("gpio: skipped — no PL061 in the device tree")
                                }
                            }
                        }

                        // USB: a bus whose devices have no registers at
                        // all, a tree three levels deep, and a device that
                        // enumerates perfectly and is refused.
                        if usb_host_elf().is_empty()
                            || usb_storage_elf().is_empty()
                            || usb_hid_elf().is_empty()
                            || input_client_elf().is_empty()
                        {
                            kprintln!(
                                "usb: skipped (no embedded host/class-driver ELF; cargo inner-loop build)"
                            );
                        } else {
                            match functions[..count]
                                .iter()
                                .find(|f| f.class_code >> 8 == PCI_CLASS_XHCI)
                            {
                                None => kprintln!("usb: skipped — no USB host controller attached"),
                                Some(controller) => {
                                    match usb_check(
                                        &kernel_space,
                                        &ttbr0_space,
                                        &mut frames,
                                        controller,
                                    ) {
                                        Ok(_) => {
                                            // usb: OK — a ring-3 host bound an xHCI
                                            // controller, walked its ports and a hub,
                                            // and DECLARED every device it found into
                                            // the resource graph: hubs as buses with
                                            // devices behind them, so the graph is
                                            // three levels deep and the relay cost on
                                            // a device two levels down is a sum of
                                            // two. Its devices have NO REGISTERS —
                                            // nothing to map, no window a capability
                                            // could name — so two class drivers served
                                            // the block and input contracts over bytes
                                            // this host moved for them, which is the
                                            // first relaying bus in this tree and the
                                            // first thing Hop::Relay has had to count.
                                            // The disk was judged by the same client
                                            // program that judges virtio, NVMe and SD,
                                            // byte for byte, and an idle keyboard
                                            // answered NO_REPORT rather than failing —
                                            // a fourth class contract held to the same
                                            // seven rules by a suite that knows what
                                            // an ordinal is and does not know what a
                                            // keyboard is. One attached device was
                                            // REFUSED: its class is not on the
                                            // allowlist, so it enumerated perfectly,
                                            // was declared with a class code no
                                            // manifest entry claims, and no driver was
                                            // offered it
                                            kprintln!(
                                                "usb: OK"
                                            );
                                            kcore::verdict::claims(&["usb.ok", "usb.no-registers", "usb.three-levels", "usb.idle-no-report", "usb.device-refused"]);
                                        }
                                        Err(which) => {
                                            kprintln!(
                                                "usb: FATAL: check {which} failed ({} reports: {:#x} {:#x} {:#x} {:#x})",
                                                EL0_REPORT_COUNT.load(Ordering::SeqCst),
                                                EL0_REPORTS[0].load(Ordering::SeqCst),
                                                EL0_REPORTS[1].load(Ordering::SeqCst),
                                                EL0_REPORTS[2].load(Ordering::SeqCst),
                                                EL0_REPORTS[3].load(Ordering::SeqCst),
                                            );
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                    }
                                }
                            }
                        }

                        // **Enumeration, done again and from outside.** The
                        // walk above was the kernel's; this hands the bridge to
                        // a ring-3 program and lets it do the same work with
                        // the same crate, then checks what it declared against
                        // what the kernel independently read.
                        if pci_bus_elf().is_empty() || blk_probe_elf().is_empty() {
                            kprintln!(
                                "pci-bus: skipped (no embedded bus-driver ELF; cargo inner-loop build)"
                            );
                        } else if device_removed {
                            // The hotplug check ejected the endpoint this would
                            // bind. The walk below would still work and find
                            // nothing to drive, which is a different check than
                            // the one this is.
                            kprintln!(
                                "pci-bus: skipped — the device was removed by the hotplug check"
                            );
                        } else {
                            match functions[..count].iter().find(|f| is_virtio_storage(f)) {
                                None => kprintln!(
                                    "pci-bus: skipped — no PCI mass-storage function attached"
                                ),
                                Some(f) => {
                                    // The vendor/device register as the kernel
                                    // read it: vendor low, device high, exactly
                                    // as configuration space lays it out.
                                    let word = u32::from(f.vendor) | (u32::from(f.device) << 16);
                                    match pci_bus_check(
                                        &kernel_space,
                                        &ttbr0_space,
                                        &mut frames,
                                        &host,
                                        word,
                                    ) {
                                        Ok(found) => {
                                            // pci-bus: OK — a ring-3 program held the
                                            // host bridge and nothing else, walked it
                                            // with the same enumerator the kernel
                                            // uses, placed the BARs and DECLARED the
                                            // {found} function(s) it found: every PCI
                                            // device in the resource graph was put
                                            // there by an unprivileged process. It
                                            // offered them to the device manager as
                                            // capabilities rather than as claims, the
                                            // manager took hardware it had never seen,
                                            // and a driver bound one by class. That
                                            // driver then mapped its OWN configuration
                                            // space — 4 KiB scoped to one function, on
                                            // a right separate from the one that maps
                                            // its registers — and read {:04x}:{:04x}
                                            // out of it, which is what the kernel's
                                            // own independent walk found in the same
                                            // register and what the bus driver had
                                            // declared. The graph's word came from
                                            // ring 3 and the hardware agrees with it
                                            kprintln!(
                                                "pci-bus: OK — {found} function(s) declared from ring 3; config {:04x}:{:04x}",
                                                word & 0xffff,
                                                word >> 16,
                                            );
                                            kcore::verdict::claims(&["pci-bus.ok", "pci-bus.declared", "pci-bus.own-config"]);
                                        }
                                        Err(which) => {
                                            kprintln!(
                                                "pci-bus: FATAL: check {which} failed (reports {:#x} {:#x})",
                                                EL0_REPORTS[0].load(Ordering::SeqCst),
                                                EL0_REPORTS[1].load(Ordering::SeqCst),
                                            );
                                            SemihostingExit::exit(ExitCode::Failure)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        kprintln!("pcie: FATAL: enumeration failed: {e:?}");
                        SemihostingExit::exit(ExitCode::Failure)
                    }
                }
            }
            None => kprintln!("pcie: skipped — no PCI host bridge in the device tree"),
        }
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
            "new-user: OK — 2 isolated EL0 processes, per-process TTBR0, own memory (a={a:#x} b={b:#x})"
        ),
        Err(which) => {
            kprintln!("new-user: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    match kcore_el0_check(&kernel_space, &ttbr0_space, &mut frames) {
        Ok(log) => kprintln!(
            "kcore-el0: OK — EL0 process scheduled by kcore, syscall via substrate, exited (log {log:#x})"
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
        Some((base, size)) => {
            match mmio_map_check(&kernel_space, &ttbr0_space, &mut frames, base, size) {
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
            match dma_check(&kernel_space, &ttbr0_space, &mut frames, base, size) {
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
                    Some((net_base, net_size)) => {
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
                            Ok(grant_frames) => {
                                // Its own line, because it is its own claim:
                                // the sentence below is about a driver moving
                                // bytes it never mapped, and this one is about
                                // memory it was not allowed to move at all.
                                // protected: OK — a client classified the very
                                // buffer the driver had just moved for it, and
                                // the identical request came back refused: the
                                // driver asked the kernel to make that memory
                                // reachable by the block device and was told
                                // no, because its device capability carries no
                                // authority for protected memory. Nothing else
                                // about the request changed
                                kprintln!(
                                    "protected: OK"
                                );
                                kcore::verdict::claims(&["ring3-host.protected-refused", "ring3-host.protected-reason"]);
                                // ring3-host: OK — resident EL0 host selected
                                // across 2 client channels (IRQ-driven reads,
                                // a sector written and read back off the
                                // medium, ARP from EL0). One client ran the
                                // block class's conformance suite against the
                                // live driver and every rule held: Describe
                                // reported the contract version and the
                                // features, an advertised optional worked, an
                                // unadvertised one answered NOT_SUPPORTED
                                // rather than something worse, Reset left the
                                // state a reset is defined to leave, and a
                                // vendor-range ordinal was refused because no
                                // namespace was negotiated. The other client
                                // moved a WHOLE 512-byte sector the other way
                                // — through a memory object it created,
                                // transferred to the driver and got back,
                                // twice, which the 256-byte inline payload
                                // cannot carry at all. The driver never mapped
                                // that buffer: it attached the object to the
                                // block device and put the device address
                                // straight into the virtqueue, so the only
                                // thing that touched those bytes was the
                                // device, and a driver holding no mapping of a
                                // buffer cannot have copied it. And it gave
                                // the buffer back before it exited: the exit
                                // sweep found {grant_frames} frames still
                                // owned, because closing the handle had
                                // already released them — which is the
                                // difference between memory returned when a
                                // program says so and memory returned when a
                                // program dies. The driver's device interrupt
                                // route was then revoked with it: the
                                // supervisor named no INTID and no port, the
                                // resource graph did
                                kprintln!(
                                    "ring3-host: OK — grant frames={grant_frames}"
                                );
                                kcore::verdict::claims(&["ring3-host.ok", "ring3-host.conformance-complete", "ring3-host.sector-written", "ring3-host.zero-copy"]);
                            }
                            Err(which) => {
                                // The per-reporter values as well as the XOR:
                                // three programs report here, and a folded
                                // total cannot say which of them failed.
                                kprintln!(
                                    "ring3-host: FATAL: check {which} failed (report {:#x}; reports {:#x} {:#x} {:#x} {:#x}, count {})",
                                    EL0_SINK_LOG.load(Ordering::SeqCst),
                                    EL0_REPORTS[0].load(Ordering::SeqCst),
                                    EL0_REPORTS[1].load(Ordering::SeqCst),
                                    EL0_REPORTS[2].load(Ordering::SeqCst),
                                    EL0_REPORTS[3].load(Ordering::SeqCst),
                                    EL0_REPORT_COUNT.load(Ordering::SeqCst),
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

    // The first class of the rollout, and the first thing on this system to
    // speak without being asked. Its own check because it needs only a NIC:
    // the block host's boot attaches one too, so this runs in both, and after
    // the host check — a virtio transport is handed on the way every driver
    // here hands one on, from reset.
    if net_driver_elf().is_empty() || net_client_elf().is_empty() {
        kprintln!("net-class: skipped (no embedded driver/client ELF; cargo inner-loop build)");
    } else {
        match virtio::net_device_base(&virtio_regions[..virtio_count]) {
            None => kprintln!("net-class: skipped (no network device attached)"),
            Some((net_base, _size)) => {
                let net_intid = virtio_regions[..virtio_count]
                    .iter()
                    .find(|r| r.base == net_base)
                    .and_then(|r| r.intid);
                match net_class_check(
                    &kernel_space,
                    &ttbr0_space,
                    &mut frames,
                    net_base,
                    net_intid,
                ) {
                    Ok(report) => {
                        // net-class: OK — a ring-3 driver bound a NIC by class
                        // and served the network contract to a client holding
                        // no device at all. The frame the client got back was
                        // one nobody replied to: the NIC interrupted the
                        // driver, and the driver SENT it — no call
                        // outstanding, the direction this system did not have.
                        // And it sent the frame away: a memory object it made,
                        // attached to the NIC, never mapped and no longer
                        // holds, with the frame at its first byte because the
                        // transport header went to a page of the driver's own.
                        // The gateway answered {:#x}. Taking the link down was
                        // announced the same way, a transmit while it was down
                        // came back LINK_DOWN rather than an I/O error, and
                        // bringing it up was announced again. The block
                        // class's conformance suite judged all of it — same
                        // seven rules, second class — and every one of them
                        // was reached and held
                        kprintln!(
                            "net-class: OK — report={:#x}",
                            report & 0xffff_ffff_ffff
                        );
                        kcore::verdict::claims(&["net-class.ok", "net-class.driver-sent", "net-class.conformance-complete"]);
                    }
                    Err(which) => {
                        kprintln!(
                            "net-class: FATAL: check {which} failed (report {:#x}, wanted {NET_CLASS_EXPECTED:#x})",
                            EL0_SINK_LOG.load(Ordering::SeqCst),
                        );
                        SemihostingExit::exit(ExitCode::Failure)
                    }
                }
            }
        }
    }

    // The framework's restart claim, on its own: a driver dies holding the
    // block device and the next one gets it. Deliberately separate from the
    // host check above — no clients, no interrupts, no select loop, so the
    // handover is the only thing being tested.
    match virtio::block_device_base(&virtio_regions[..virtio_count]) {
        // A virtio-mmio transport: no identity to classify it by (it says what
        // it is in its own registers) and no IOMMU in front of it.
        Some((base, size)) => {
            match driver_rebind_check(
                &kernel_space,
                &ttbr0_space,
                &mut frames,
                base,
                size,
                None,
                // A virtio-mmio transport's register layout is fixed by its
                // specification, so there is nothing to discover and nothing
                // to tell a driver. `None` is that fact, not a gap.
                None,
                None,
                // A virtio-mmio transport sits on no bus the kernel enumerated,
                // so there is no bridge to hand the manager and it holds the
                // device directly.
                None,
            ) {
                Ok(_) => {
                    // driver-rebind: OK — a driver crashed holding the block
                    // device (a real contained EL0 fault, not a tidy exit);
                    // the kernel reclaimed what it held, the supervisor
                    // recorded the crash and the restart, and the manager
                    // bound the same transport to a fresh driver, which drove
                    // it
                    kprintln!(
                        "driver-rebind: OK"
                    );
                    kcore::verdict::claims(&["driver-rebind.ok"]);
                    // The ladder's other end: a host that never comes back is
                    // given up on rather than respawned for ever. Run before
                    // the records are read, so both supervisors' records are in
                    // the same drain.
                    match driver_giveup_check(&kernel_space, &ttbr0_space, &mut frames, base, size)
                    {
                        Ok(launches) => {
                            // driver-giveup: OK — a host that crashed every
                            // time was restarted exactly {launches} times, its
                            // budget, and then the supervisor stopped. A
                            // recovery policy has an end; without one it is a
                            // machine that respawns a broken driver until
                            // something else breaks
                            kprintln!(
                                "driver-giveup: OK — launches={launches}"
                            );
                            kcore::verdict::claims(&["driver-giveup.ok"]);
                        }
                        Err(which) => {
                            kprintln!("driver-giveup: FATAL: check {which} failed");
                            SemihostingExit::exit(ExitCode::Failure)
                        }
                    }
                    // The same runs, read back from the records the kernel
                    // emitted while they happened.
                    if !tessera_boot_checks::device_events(REBIND_DEVICE_OBJECT) {
                        SemihostingExit::exit(ExitCode::Failure)
                    }
                }
                Err(which) => {
                    kprintln!(
                        "driver-rebind: FATAL: check {which} failed (report {:#x})",
                        EL0_SINK_LOG.load(Ordering::SeqCst)
                    );
                    SemihostingExit::exit(ExitCode::Failure)
                }
            }
        }
        None => {
            kprintln!("driver-rebind: no block device attached (skipped)");
            kprintln!("device-events: no block device attached (skipped)");
        }
    }

    // Power vote arbitration (D140). Needs no device of its own — the thing
    // being proven is that three processes can disagree about a domain and one
    // service resolves it — so it runs unconditionally wherever the ring-3
    // images are embedded.
    if power_manager_elf().is_empty() {
        kprintln!("power-votes: skipped (no embedded power-manager ELF; cargo inner-loop build)");
    } else {
        match power_check(&kernel_space, &ttbr0_space, &mut frames) {
            Ok(outcome) => {
                // power-votes: OK — three processes voted on one power domain
                // and a service weighed them: the driver asked for retention
                // and got it, a user asked for full-active and outranked it
                // ({:#x}), and a thermal zone took it back down to retention
                // and was named for doing so ({:#x}, clamped from full-
                // active). The device is {:?}, driven there through every
                // state a power transition is defined to pass through
                kprintln!(
                    "power-votes: OK — replies1={:#x}, replies2={:#x}, device state={:?}",
                    outcome.replies[1],
                    outcome.replies[2],
                    outcome.device_state,
                );
                kcore::verdict::claims(&["power.votes-ok", "power.clamped"]);
            }
            Err(which) => {
                kprintln!(
                    "power-votes: FATAL: check {which} failed (reports {:#x} {:#x} {:#x} {:#x}, count {})",
                    EL0_REPORTS[0].load(Ordering::SeqCst),
                    EL0_REPORTS[1].load(Ordering::SeqCst),
                    EL0_REPORTS[2].load(Ordering::SeqCst),
                    EL0_REPORTS[3].load(Ordering::SeqCst),
                    EL0_REPORT_COUNT.load(Ordering::SeqCst),
                );
                SemihostingExit::exit(ExitCode::Failure)
            }
        }
    }

    // Runtime idle and the wake capability (D141). Needs a wakeup source that
    // belongs to no driver, which on this machine is the RTC.
    match (power_manager_elf().is_empty(), rtc_device(dtb)) {
        (true, _) => {
            kprintln!("power-wake: skipped (no embedded power-manager ELF; cargo inner-loop build)")
        }
        (false, None) => kprintln!("power-wake: skipped (no RTC in the device tree)"),
        (false, Some(rtc)) => match wake_check(&rtc, &kernel_space, &ttbr0_space, &mut frames) {
            Ok(outcome) => {
                // power-wake: OK — a domain nobody was using dropped out of
                // service, and a real interrupt brought it back: the manager
                // armed the RTC as a wakeup source (a second capability to the
                // same device, without Rights::WAKE, was refused), parked, and
                // the alarm on INTID {} woke it. The kernel counted {} wake
                // event(s) before anything could observe one, the grace hold
                // was there, and the device is {:?} again (report {:#x}); the
                // source is disarmed ({})
                kprintln!(
                    "power-wake: OK — unwrap or={}, events={}, device state={:?}, reported={:#x}, still armed={}",
                    rtc.intid.unwrap_or(0),
                    outcome.events,
                    outcome.device_state,
                    outcome.reported,
                    !outcome.still_armed,
                );
                kcore::verdict::claims(&["power.wake-ok", "power.wake-right-required"]);
            }
            Err(which) => {
                kprintln!(
                    "power-wake: FATAL: check {which} failed (report {:#x}, count {})",
                    EL0_REPORTS[0].load(Ordering::SeqCst),
                    EL0_REPORT_COUNT.load(Ordering::SeqCst),
                );
                SemihostingExit::exit(ExitCode::Failure)
            }
        },
    }

    // System suspend and resume (D142), ordered by the device tree.
    match (power_manager_elf().is_empty(), rtc_device(dtb)) {
        (true, _) => kprintln!(
            "power-suspend: skipped (no embedded power-manager ELF; cargo inner-loop build)"
        ),
        (false, None) => kprintln!("power-suspend: skipped (no RTC in the device tree)"),
        (false, Some(rtc)) => match suspend_check(&rtc, &kernel_space, &ttbr0_space, &mut frames) {
            Ok(outcome) => {
                // power-suspend: OK — the machine stopped and started again,
                // leaves before parents. Suspending the bus under a live
                // device was refused by the kernel, and so was resuming the
                // device through a bus still down; in the right order both
                // went. The commit slept until the RTC woke it and the record
                // named the source; the same snapshot presented again aborted
                // because that very wake had moved the counter ({} event(s)),
                // and a wake hold refused a commit whose snapshot was fresh.
                // Both nodes are {:?}/{:?} (report {:#x})
                kprintln!(
                    "power-suspend: OK — events={}, bus state={:?}, device state={:?}, reported={:#x}",
                    outcome.events,
                    outcome.bus_state,
                    outcome.device_state,
                    outcome.reported,
                );
                kcore::verdict::claims(&["power.suspend-ok", "power.suspend-order"]);
            }
            Err(which) => {
                kprintln!(
                    "power-suspend: FATAL: check {which} failed (report {:#x}, count {})",
                    EL0_REPORTS[0].load(Ordering::SeqCst),
                    EL0_REPORT_COUNT.load(Ordering::SeqCst),
                );
                SemihostingExit::exit(ExitCode::Failure)
            }
        },
    }

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        kprintln!(
            "relay: skipped (no embedded device-manager/blk-probe ELF; cargo inner-loop build)"
        );
    } else {
        match relay_check(&kernel_space, &ttbr0_space, &mut frames) {
            Ok(report) => {
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
                // attached (reports {:#x}, {:#x})
                kprintln!(
                    "relay: OK — budget {}us; near {} hop {}us {}Mb; far {}us refused; declared {:#x}, undeclared {:#x}",
                    BLOCK_PATH_BUDGET_US,
                    (report.declared >> 8) & 0xff,
                    (report.declared >> 16) & 0xffff,
                    (report.declared >> 48) & 0xffff,
                    RELAY_NEAR_COST_US + RELAY_FAR_COST_US,
                    report.declared,
                    report.undeclared,
                );
                kcore::verdict::claims(&["relay.ok", "relay.budget-exceeded", "relay.throughput-too-low", "relay.path-undeclared"]);
            }
            Err(which) => {
                kprintln!(
                    "relay: FATAL: check {which} failed (reports {:#x}, {:#x}, count {})",
                    EL0_REPORTS[0].load(Ordering::SeqCst),
                    EL0_REPORTS[1].load(Ordering::SeqCst),
                    EL0_REPORT_COUNT.load(Ordering::SeqCst),
                );
                SemihostingExit::exit(ExitCode::Failure)
            }
        }
    }

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() || system_store().is_empty() {
        kprintln!(
            "firmware: skipped (no embedded programs or system store; cargo inner-loop build)"
        );
    } else {
        // What the *kernel* measures for the same image, independently of the
        // driver that will report measuring it. Compared below: neither side
        // can satisfy this by trusting the other.
        let kernel_digest = kcore::store::mount(system_store())
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
        match firmware_check(&kernel_space, &ttbr0_space, &mut frames) {
            Ok(report)
                if report.driver == firmware_report_expected(kernel_digest)
                    && report.update_would_strand =>
            {
                // firmware: OK — a manager holding the firmware right fetched
                // a verified image (svn {}, version {}) and handed it to a
                // driver beside its device; the driver measured what it
                // received to {:#010x}, the same bytes the kernel measures
                // from the store. An image below the rollback floor (svn {})
                // was refused while measuring perfectly, one below what the
                // entry needs was refused differently, the driver's own load
                // was refused because the right did not travel with the
                // device, and a stricter driver set would strand an installed
                // image (reports {:#x}, {:#x})
                kprintln!(
                    "firmware: OK — svn={} ver={} digest={:#010x} old_svn={} refusals={:#x} driver={:#x}",
                    FIRMWARE_GOOD_SVN,
                    FIRMWARE_GOOD_VERSION,
                    kernel_digest,
                    FIRMWARE_OLD_SVN,
                    report.refusals,
                    report.driver,
                );
                kcore::verdict::claims(&["firmware.ok", "firmware.measured", "firmware.rollback-refused", "firmware.right-required"]);
            }
            Ok(report) => {
                kprintln!(
                    "firmware: FATAL: driver reported {:#x}, expected {:#x} (refusals {:#x}, update-strand {})",
                    report.driver,
                    firmware_report_expected(kernel_digest),
                    report.refusals,
                    report.update_would_strand,
                );
                SemihostingExit::exit(ExitCode::Failure)
            }
            Err(which) => {
                kprintln!(
                    "firmware: FATAL: check {which} failed (reports {:#x}, {:#x}, count {})",
                    EL0_REPORTS[0].load(Ordering::SeqCst),
                    EL0_REPORTS[1].load(Ordering::SeqCst),
                    EL0_REPORT_COUNT.load(Ordering::SeqCst),
                );
                SemihostingExit::exit(ExitCode::Failure)
            }
        }
    }

    match virtio::check(&virtio_regions[..virtio_count], &mut frames) {
        Ok(true) => {
            kprintln!("virtio-blk: OK — sector 0 read, magic verified");
            kcore::verdict::claims(&["virtio-blk.ok"]);
        }
        Ok(false) => kprintln!("virtio-blk: no block device attached (skipped)"),
        Err(which) => {
            kprintln!("virtio-blk: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    match virtio::net_check(&virtio_regions[..virtio_count], &mut frames) {
        Ok(Some(mac)) => {
            kprintln!(
                "virtio-net: OK — MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, ARP reply from 10.0.2.2",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
            kcore::verdict::claims(&["virtio-net.ok"]);
        }
        Ok(None) => kprintln!("virtio-net: no network device attached (skipped)"),
        Err(which) => {
            kprintln!("virtio-net: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
    }

    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    kcore::verdict::claims(&["boot.alive"]);
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
/// Puts one PCI device behind a stream table with a one-page aperture, and
/// proves the boundary in both directions.
///
/// **This is the DMA-scoping claim.** Until now a driver programmed a device
/// with a physical address and the device was obeyed; the only thing keeping
/// a device out of memory it had no business in was the driver choosing not
/// to. Here the device is given an address space: one page is mapped, and the
/// hardware refuses everything else.
///
/// The proof needs both halves. A transfer *inside* the aperture must land,
/// or an SMMU that aborts everything would pass for one that scopes; a
/// transfer *outside* must not, and the event queue must say so, or "nothing
/// arrived" is indistinguishable from a misconfiguration. `edu` is the device
/// because its DMA engine is four register writes, so nothing has to be
/// brought up first.
///
/// Returns `(stream, inside, outside_event)`.
fn smmu_check(
    smmu: &mut Smmu,
    device: kcore::object::ObjectId,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<(u32, u64, tessera_smmu::Event), u32> {
    use kcore::devmgr::DmaMapper as _;

    let stream = smmu.stream_of(device).ok_or(1u32)?;

    // A lease, then one page of memory for the device to reach inside it —
    // through the same seam `dma_alloc` uses, so this proves the *mechanism*
    // rather than a second one built beside it.
    smmu.begin_lease(device).map_err(|_| 3u32)?;
    let target = frames.alloc().ok_or(2u32)?.base().as_u64();
    zero_frame(target);
    smmu.map(device, APERTURE_IOVA, target, FRAME_SIZE)
        .map_err(|_| 3u32)?;

    let (bar, _) = function.first_bar().ok_or(5u32)?;
    let mut edu = BarWindow { base: bar };

    // Give the device something recognisable to move: put the pattern in the
    // target page and have the device read it into its own buffer, through the
    // aperture. Then clear the page and have it write the pattern back.
    direct_write64(target, 0, DMA_PATTERN);
    edu_dma(&mut edu, APERTURE_IOVA, EDU_BUFFER, 8, EDU_DMA_START);
    direct_write64(target, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        APERTURE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    let inside = direct_read64(target, 0);

    // The same transfer to an address the table does not describe.
    direct_write64(target, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        OUTSIDE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(target, 0) != 0 {
        // It reached the page it must not have reached.
        return Err(6);
    }

    // The SMMU's own account of the refusal. Without it, "nothing arrived" is
    // what a misconfiguration produces too.
    let record = smmu.drain_events().ok_or(7u32)?;

    // Give the lease back. The next one — the ring-3 driver's — then starts
    // from an empty table, which is what makes it a *second* lease rather than
    // a continuation of this one.
    smmu.end_lease(device);
    Ok((stream, inside, record))
}

/// What [`dma_fault_isolation_check`] observed.
struct FaultIsolation {
    /// The stream the refusal named.
    stream: u32,
    /// The address the device was refused.
    refused_at: u64,
    /// How many of this check's faults the **unit's own interrupt** delivered.
    /// Zero would mean the harvest works only when something looks.
    by_interrupt: u32,
    /// The process whose lease the policy ended.
    stopped: u32,
}

/// A blank crash dump, for supervisors to fill.
///
/// A `const` rather than a `Default` because `KernelEvent` is generated code
/// and giving generated types trait impls in a boot glue is how a schema
/// change becomes a compile error in the wrong file.
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

/// How many trace records the last crash dump captured — read by the boot
/// check, because a dump that collected nothing is the failure worth seeing
/// and is invisible from outside the dump itself.
static CRASH_DUMP_RECORDS: AtomicU32 = AtomicU32::new(0);

/// A stand-in driver process for the isolation check.
///
/// The check needs a lease *holder* and deliberately not a running driver: the
/// claim is about what the kernel does when a device misbehaves, and putting
/// an EL0 program behind it would add a second thing that could be wrong
/// without making the claim stronger. `scoped_dma_check` already proves a real
/// ring-3 driver takes a real lease.
const ISOLATION_HOLDER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x51);

/// Proves the second clause of `docs/drivers/01` "DMA Safety": faults *are
/// logged and can trigger driver isolation*.
///
/// Everything before this milestone stopped at the hardware's refusal — the
/// SMMU declined one transaction and the system carried on, none the wiser. A
/// device that keeps asking is a device nobody has taken away anything from.
/// Here the fault reaches the kernel **through the unit's own interrupt**, is
/// recorded as a structured event, and ends the device's lease: it stops
/// reaching the address it was refused *and* the one it was entitled to.
///
/// The three things checked, in the order they can fail:
///
/// 1. The interrupt delivered it. Without this the harvest is a polling loop
///    with extra steps, and a fault between two checks would be invisible.
/// 2. The lease ended. The device was reaching a page a moment earlier through
///    an address the graph had issued; it is not now.
/// 3. The device agrees. The in-aperture address that worked is refused, which
///    is the difference between the translations being torn down and the
///    kernel merely having forgotten them.
fn dma_fault_isolation_check(
    smmu: &mut Smmu,
    device: kcore::object::ObjectId,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<FaultIsolation, u32> {
    use kcore::devmgr::{DeviceAperture, DmaMapper as _, IsolationPolicy};

    let stream = smmu.stream_of(device).ok_or(170u32)?;
    let (bar, bar_len) = function.first_bar().ok_or(171u32)?;

    // A fresh executive holding this device and nothing else, so the events
    // read below are this check's.
    // SAFETY: single-threaded boot; no thread of any earlier check is live.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }

    // A lease, recorded in the graph as a driver's would be. The graph is what
    // isolation consults to find a holder, so a lease installed only in the
    // hardware would be torn down with nobody named — which is precisely the
    // case the `device: None` fault arm reports rather than acts on.
    let (base, len) = smmu.begin_lease(device).map_err(|_| 172u32)?;
    let target = frames.alloc().ok_or(173u32)?.base().as_u64();
    zero_frame(target);
    smmu.map(device, base, target, FRAME_SIZE)
        .map_err(|_| 174u32)?;
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(175u32)?;
        exec.device_register_mmio(device, bar, bar_len, kcore::rights::Rights::READ)
            .map_err(|_| 176u32)?;
        exec.device_set_aperture(
            device,
            ISOLATION_HOLDER_OBJ,
            DeviceAperture::new(base, len.min(FRAME_SIZE)),
            // No deadline: this lease exists for the length of one check.
            None,
        )
        .map_err(|_| 177u32)?;
    }

    let mut edu = BarWindow { base: bar };

    // The device reaches its page, so that losing it later means something.
    direct_write64(target, 0, DMA_PATTERN);
    edu_dma(&mut edu, base, EDU_BUFFER, 8, EDU_DMA_START);
    direct_write64(target, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        base,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(target, 0) != DMA_PATTERN {
        return Err(178);
    }

    // Empty the log, so what is counted below is this check's, and arm the
    // policy. Both are deliberate acts: the harvest has been recording faults
    // since bring-up and isolating none of them, which is the conservative
    // default a machine still coming up wants.
    smmu.drain_events();
    let before = SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst);
    SMMU_ISOLATION_STOP.store(0, Ordering::SeqCst);
    SMMU_FAULT_POLICY.store(IsolationPolicy::EndLeaseAndStop as u32, Ordering::SeqCst);

    // The misbehaviour, and the window in which the unit can report it. The
    // boot context has masked interrupts since reset, so without unmasking
    // here the record would sit in the queue and only the polled reader would
    // ever find it — which is the state this milestone exists to leave behind.
    //
    // Nothing else is enabled on this path but the periodic tick and the
    // SMMU's own line, and neither handler touches the borrow held here:
    // the tick counts, and the fault bridge reaches this same unit through
    // `BOOT_IOMMU` between — never during — the accesses below.
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        OUTSIDE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: unmasking and re-masking at EL1 is a PSTATE write on the boot
    // CPU, which owns the machine here.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
    }
    let mut settle = 200_000u32;
    while SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst) == before && settle > 0 {
        settle -= 1;
        core::hint::spin_loop();
    }
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack));
    }
    SMMU_FAULT_POLICY.store(IsolationPolicy::Report as u32, Ordering::SeqCst);

    let by_interrupt = SMMU_FAULTS_BY_INTERRUPT
        .load(Ordering::SeqCst)
        .saturating_sub(before);
    if by_interrupt == 0 {
        // The unit refused the transaction — every earlier check proves that
        // much — and did not tell anyone. That is the failure this milestone
        // is about, so it is a failure here rather than a fallback to polling.
        return Err(179);
    }

    // The policy acted: the graph no longer names a holder for this device.
    // SAFETY: transient raw access to the static executive.
    if unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
        .ok_or(180u32)?
        .lease_holder_of_object(device)
        .is_some()
    {
        return Err(181);
    }
    let stopped = SMMU_ISOLATION_STOP.load(Ordering::SeqCst);
    if stopped != ISOLATION_HOLDER_OBJ.raw() {
        return Err(182);
    }

    // And the hardware agrees. The address the device was *entitled* to a
    // moment ago is refused now — which is what distinguishes translations
    // torn down from a graph that merely forgot them.
    direct_write64(target, 0, 0);
    smmu.drain_events();
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        base,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(target, 0) != 0 {
        return Err(183);
    }
    let record = smmu.drain_events().ok_or(184u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(185);
    }

    Ok(FaultIsolation {
        stream,
        refused_at: record.address,
        by_interrupt,
        stopped,
    })
}

/// Who holds the lease the protected-memory check takes.
///
/// The *device* is `SMMU_DEVICE_OBJ`, as in every other check here: a stream id
/// belongs to the hardware the unit was told about, and a fresh object id would
/// name a device the SMMU has never heard of.
const PROTECTED_HOLDER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x61);

/// What the protected-memory check produced.
struct ProtectedDma {
    /// The stream the refusal named.
    stream: u32,
    /// The address the device was refused — inside its own aperture.
    refused_at: u64,
    /// The aperture the device holds, so the verdict can say the refused
    /// address was inside it rather than merely somewhere.
    aperture: (u64, u64),
    /// Faults the unit's own interrupt delivered for this check.
    by_interrupt: u32,
}

/// Proves the **second layer** of `docs/security/01`'s memory classification:
/// a device refused protected memory does not reach it, and the hardware is
/// what makes that true rather than the interface.
///
/// The first layer — the refusal itself — is proven by the syscall (host tests)
/// and in ring 3 (`blk-client` classifies the very buffer it just moved and the
/// same request comes back refused). What neither of those can show is what the
/// refusal *left behind*, and that is the question here: a policy that returned
/// an error while installing a translation anyway would pass both.
///
/// So the same rule runs — `kcore::memory::attach_permitted`, against the
/// rights the resource graph recorded for this device — and because it says no,
/// no translation is installed. The device is then driven at the address the
/// attach would have returned, which is **inside its own aperture**: an address
/// this device is entitled to use, unmapped because policy stopped the mapping
/// being made. That is what distinguishes this from D119, where the refused
/// address was outside the aperture and the SMMU was refusing a device reaching
/// somewhere it had no business at all.
fn protected_dma_check(
    smmu: &mut Smmu,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<ProtectedDma, u32> {
    use kcore::devmgr::{DeviceAperture, DmaMapper as _};
    use kcore::memory::{MemoryClass, attach_permitted};
    use kcore::rights::Rights;

    let stream = smmu.stream_of(SMMU_DEVICE_OBJ).ok_or(190u32)?;
    let (bar, bar_len) = function.first_bar().ok_or(191u32)?;

    // A fresh executive holding this device and nothing else, so what is
    // counted below is this check's.
    // SAFETY: single-threaded boot; no thread of any earlier check is live.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }

    let (base, len) = smmu.begin_lease(SMMU_DEVICE_OBJ).map_err(|_| 192u32)?;
    // **Two pages of aperture, and that is the point.** One page would leave
    // the refused attach's address outside the lease, which is the case D119
    // already covers; the refusal has to leave a hole *inside* the range this
    // device is entitled to.
    let aperture_len = len.min(2 * FRAME_SIZE);
    if aperture_len < 2 * FRAME_SIZE {
        return Err(193);
    }

    // The device this check registers is deliberately **not** authorized for
    // protected memory: `PROTECTED_DMA` is absent from the rights the graph
    // records, which is what the rule below reads.
    let device_rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(194u32)?;
        exec.device_register_mmio(SMMU_DEVICE_OBJ, bar, bar_len, device_rights)
            .map_err(|_| 194u32)?;
        exec.device_set_aperture(
            SMMU_DEVICE_OBJ,
            PROTECTED_HOLDER_OBJ,
            DeviceAperture::new(base, aperture_len),
            None,
        )
        .map_err(|_| 195u32)?;
    }

    let mut edu = BarWindow { base: bar };

    // --- An unclassified buffer, which reaches the device ---
    let open_frame = frames.alloc().ok_or(196u32)?.base().as_u64();
    zero_frame(open_frame);
    // SAFETY: transient raw access to the static executive; single-threaded
    // boot, and no thread of any earlier check is live.
    let open_iova = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(197u32)?;
        exec.device_allocate_in_aperture(SMMU_DEVICE_OBJ, FRAME_SIZE)
            .ok_or(197u32)?
    };
    smmu.map(SMMU_DEVICE_OBJ, open_iova, open_frame, FRAME_SIZE)
        .map_err(|_| 198u32)?;
    direct_write64(open_frame, 0, DMA_PATTERN);
    edu_dma(&mut edu, open_iova, EDU_BUFFER, 8, EDU_DMA_START);
    direct_write64(open_frame, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        open_iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(open_frame, 0) != DMA_PATTERN {
        return Err(199);
    }

    // --- And a protected one, which does not ---
    //
    // The rule is asked, and its answer is what stops the mapping. Nothing here
    // decides not to map: `attach_permitted` decides, and it is the same
    // function `DmaAttach` consults.
    if !attach_permitted(MemoryClass::Unclassified, device_rights) {
        // The unclassified case must be permitted, or the round trip above
        // proved nothing about classification.
        return Err(200);
    }
    if attach_permitted(MemoryClass::Protected, device_rights) {
        return Err(201);
    }
    // The address the refused attach would have returned. Taken from the
    // aperture, so it is an address this device is entitled to — and left
    // unmapped, because the rule said no.
    //
    // SAFETY: transient raw access to the static executive; single-threaded
    // boot with no other thread live, as everywhere else in this check.
    let sealed_iova = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(202u32)?;
        exec.device_allocate_in_aperture(SMMU_DEVICE_OBJ, FRAME_SIZE)
            .ok_or(202u32)?
    };
    if sealed_iova < base || sealed_iova >= base + aperture_len {
        return Err(203);
    }

    // --- The device tries anyway, and the hardware refuses it ---
    smmu.drain_events();
    let before = SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        sealed_iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: unmasking and re-masking at EL1 is a PSTATE write on the boot
    // CPU, which owns the machine here.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
    }
    let mut settle = 200_000u32;
    while SMMU_FAULTS_BY_INTERRUPT.load(Ordering::SeqCst) == before && settle > 0 {
        settle -= 1;
        core::hint::spin_loop();
    }
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack));
    }
    let by_interrupt = SMMU_FAULTS_BY_INTERRUPT
        .load(Ordering::SeqCst)
        .saturating_sub(before);
    if by_interrupt == 0 {
        return Err(204);
    }

    // And the buffer the device *was* entitled to still works, so the refusal
    // is scoped to the memory that was classified rather than having broken the
    // device's aperture. The device still holds the pattern in its own buffer —
    // the refused transfer read from there and wrote nowhere — so writing it
    // back is the same round trip that worked before.
    direct_write64(open_frame, 0, 0);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        open_iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    if direct_read64(open_frame, 0) != DMA_PATTERN {
        return Err(205);
    }

    let record = smmu.drain_events().ok_or(206u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(207);
    }

    Ok(ProtectedDma {
        stream,
        refused_at: sealed_iova,
        aperture: (base, aperture_len),
        by_interrupt,
    })
}

/// Runs one `edu` DMA transfer and waits for it to finish.
///
/// **Waits in time, not in iterations.** This device runs its DMA off a timer
/// with a delay measured in milliseconds, and a spin counted in loop
/// iterations expires in whatever wall time those happen to take. That is what
/// made an earlier version conclude the SMMU was refusing transfers it had not
/// been given time to perform (D119).
fn edu_dma(edu: &mut BarWindow, src: u64, dst: u64, count: u64, cmd: u64) {
    // Whole 64-bit writes: the device decodes these registers at their own
    // offsets only, so a split access loses the upper half silently.
    edu.write64(EDU_DMA_SRC, src);
    edu.write64(EDU_DMA_DST, dst);
    edu.write64(EDU_DMA_COUNT, count);
    // The command register ignores a write without the start bit, so this is
    // what actually launches the transfer.
    edu.write64(EDU_DMA_CMD, cmd);
    let hz = <Cpu as tessera_karch::CpuOps>::counter_hz().unwrap_or(62_500_000);
    let deadline = <Cpu as tessera_karch::CpuOps>::counter_serialized() + hz; // one second
    while edu.read64(EDU_DMA_CMD) & EDU_DMA_START != 0
        && <Cpu as tessera_karch::CpuOps>::counter_serialized() < deadline
    {
        core::hint::spin_loop();
    }
}

/// Programs a PCI device's message-signalled interrupt and makes it send one.
///
/// This is the claim the milestone rests on: **a PCI device raised a
/// message-signalled interrupt.** `edu` is used because it can be made to
/// send one from a single register write — every other endpoint on this
/// machine needs its transport brought up first, which is a different
/// milestone. It carries MSI rather than MSI-X, and that is why both are
/// implemented: MSI keeps its address and data in config space, so nothing
/// has to be mapped before the device can be armed.
///
/// The address programmed is the v2m doorbell and the data is an SPI from the
/// frame's own range, so what the device sends arrives as an ordinary wired
/// interrupt — which is why nothing downstream of the GIC had to change.
///
/// Returns `(spi, deliveries)`.
fn msi_check(
    host: &tessera_devicetree::PciHost,
    frame: &mut V2mFrame,
    function: &tessera_pci::Function,
) -> Result<(u32, u32), u32> {
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    let capability =
        tessera_pci::find_capability(&bridge, &config, function.bdf, tessera_pci::CAP_MSI)
            .map_err(|_| 1u32)?
            .ok_or(2u32)?;
    let spi = frame.allocate().ok_or(3u32)?;
    let (bar, _) = function.first_bar().ok_or(4u32)?;

    MSI_SPI.store(spi, Ordering::SeqCst);
    MSI_DELIVERED.store(0, Ordering::SeqCst);

    tessera_pci::msi_program(
        &bridge,
        &mut config,
        function.bdf,
        capability,
        frame.doorbell(),
        spi,
    )
    .map_err(|_| 5u32)?;
    // SAFETY: both are interrupt-controller register writes. The edge
    // configuration must come first: the doorbell raises and drops the SPI in
    // one action, and a level-triggered input has nothing left to latch.
    unsafe {
        tessera_karch_aarch64::set_irq_edge_triggered(spi);
        tessera_karch_aarch64::enable_irq(spi);
    }

    // Make the device send. The write is to its own BAR, which this kernel
    // placed and mapped; everything after it is the machine's doing.
    let mut window = BarWindow { base: bar };
    {
        use tessera_pci::ConfigSpace;
        window.write32(EDU_RAISE, 1);
    }

    // Wait for it, bounded. An interrupt that never arrives must fail the
    // check rather than hang the boot — the trap this port has hit before
    // (D85) is a wait with nothing to end it.
    //
    // **Spinning, deliberately not `wfi`.** This check runs before the
    // periodic tick is started, so `wfi` would have nothing but this very
    // interrupt to wake it — and if the message never arrives it blocks for
    // ever, turning a failing check into a hung boot. That is the trap this
    // port has hit before (D85, D104); a spin makes the budget mean something.
    let mut budget = 2_000_000u32;
    while MSI_DELIVERED.load(Ordering::SeqCst) == 0 && budget > 0 {
        // SAFETY: unmasking is re-done every iteration because returning from
        // an exception restores the boot context with IRQs masked again.
        unsafe {
            core::arch::asm!(
                "msr daifclr, #2",
                "nop",
                "msr daifset, #2",
                options(nomem, nostack)
            );
        }
        budget -= 1;
    }

    // Read the device's own interrupt status *before* acknowledging: the ack
    // clears it, so measuring afterwards says nothing about whether the raise
    // ever landed.
    // The device's own view, read *before* acknowledging — the ack clears it,
    // so measuring afterwards says nothing about whether the raise landed.
    // Checking it separates "the device never asked" from "the message never
    // arrived", which is the split that found the bug behind this check.
    let raised = {
        use tessera_pci::ConfigSpace;
        let raised = window.read32(EDU_IRQ_STATUS);
        window.write32(EDU_ACK, 1);
        raised
    };
    if raised == 0 {
        return Err(7);
    }
    let delivered = MSI_DELIVERED.load(Ordering::SeqCst);
    if delivered == 0 {
        return Err(6);
    }
    Ok((spi, delivered))
}

/// Configures MSI-X on a function that has it, and reports **only that**.
///
/// What is proven here is narrow and the verdict says so: the capability was
/// found, its table located in a BAR this kernel placed, an entry programmed
/// with the same doorbell `edu` uses, and MSI-X enabled — read back from the
/// device. What is **not** proven is the device choosing to send one, because
/// making a virtio endpoint raise MSI-X means feature negotiation, queue
/// setup and vector assignment: the transport, which is the next milestone.
/// Reporting this as "MSI-X works" would be the dishonest version.
fn msix_configure_check(
    host: &tessera_devicetree::PciHost,
    frame: &mut V2mFrame,
    functions: &[tessera_pci::Function],
) {
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    for function in functions {
        let Ok(Some(capability)) =
            tessera_pci::find_capability(&bridge, &config, function.bdf, tessera_pci::CAP_MSIX)
        else {
            continue;
        };
        let Ok(table) =
            tessera_pci::msix_table(&bridge, &config, function.bdf, capability, function)
        else {
            continue;
        };
        let Some((bar, _)) = function.bars[table.bar] else {
            continue;
        };
        let Some(spi) = frame.allocate() else {
            kprintln!("msix: FATAL: the v2m frame has no SPI left to assign");
            SemihostingExit::exit(ExitCode::Failure)
        };
        let mut window = BarWindow {
            base: bar + u64::from(table.offset),
        };
        if tessera_pci::program_msix_entry(&mut window, 0, frame.doorbell(), spi).is_err()
            || tessera_pci::msix_enable(&bridge, &mut config, function.bdf, capability).is_err()
        {
            kprintln!("msix: FATAL: entry not programmed");
            SemihostingExit::exit(ExitCode::Failure)
        }
        // Read the entry back from the device rather than trusting the write.
        let (address, data, control) = {
            use tessera_pci::ConfigSpace;
            (
                u64::from(window.read32(0)) | (u64::from(window.read32(4)) << 32),
                window.read32(8),
                window.read32(12),
            )
        };
        if address != frame.doorbell()
            || data != spi
            || control & tessera_pci::MSIX_VECTOR_MASKED != 0
        {
            kprintln!(
                "msix: FATAL: read back address {address:#x} data {data} control {control:#x}"
            );
            SemihostingExit::exit(ExitCode::Failure)
        }
        // msix: OK — {:04x}:{:04x} has MSI-X with {} vector(s); vector 0 is
        // programmed to the v2m doorbell at {address:#x} with SPI {data} and
        // unmasked, read back from the device. NOT proven: the device sending
        // one, which needs its transport
        kprintln!(
            "msix: OK — vendor={:04x}, device={:04x}, entries={}, address={address:#x}, data={data}",
            function.vendor,
            function.device,
            table.entries
        );
        return;
    }
    kprintln!("msix: skipped — no function on this bus offers MSI-X");
}

/// The machine's PCI host bridge, if it has one.
///
/// **Read through the direct map, not at `dtb` itself.** `dtb` is the physical
/// address the firmware handed over, and every other reader on this port uses
/// it *before* the MMU switch, while the boot stub's identity map still
/// covers RAM. Afterwards the low half maps only `DEVICE_RANGE` — one
/// gigabyte of device registers — and the blob, which lives in RAM above
/// that, is no longer at its physical address. Reading it there is a data
/// abort, which is how this was found.
fn pci_host(dtb: u64) -> Option<tessera_devicetree::PciHost> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: the blob lies in RAM, which the high half direct-maps, so
    // `DIRECT_MAP_BASE + dtb` is readable. Nothing is trusted about the
    // contents: `total_size` validates the magic and rejects an implausible
    // length before the larger slice is formed, and the reader bounds-checks
    // every access inside it.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above, bounded by the blob's self-declared length.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob).ok()?.pci_host().ok()?
}

/// Maps a PCI host bridge's windows into the **high half**, and says why they
/// cannot simply be reached the way every other device on this port is.
///
/// Every device here is reached at its physical address through the low-half
/// identity map of `DEVICE_RANGE` — which is 1 GiB, and this machine puts ECAM
/// at 0x40_1000_0000. Widening the blanket range to reach it would identity-map
/// 256 GiB of nothing. Worse, the low half is `TTBR0`, which a per-process
/// address space *replaces* (D76): a mapping made there stops existing the
/// moment a driver runs. So the windows are mapped where the kernel's own
/// mappings live, at `DIRECT_MAP_BASE + phys`, which survives every process
/// switch — the same place the RISC-V port reaches devices from.
///
/// Both windows are needed and for different reasons: config space is how the
/// bus is enumerated, and the memory window is where the BARs this kernel
/// places actually answer.
fn map_pci_windows(
    space: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    host: &tessera_devicetree::PciHost,
) -> Result<(), tessera_karch::KError> {
    let device = PageFlags::rw().global().device();
    space.map_block_range(
        DIRECT_MAP_BASE + host.ecam_base,
        host.ecam_base,
        host.ecam_len,
        device,
        frames,
    )?;
    if let Some(window) = host.memory {
        // The bridge's window need not be a whole number of 2 MiB blocks —
        // this machine forwards 0x2eff_0000 — and the block mapper refuses a
        // partial one. Rounding **up** maps a little more device space than
        // the bridge forwards, which reads as nothing; rounding down would
        // leave the last BAR placed in the window unmapped, which reads as a
        // fault the first time a driver touches it.
        let len = window.len.next_multiple_of(2 * 1024 * 1024);
        space.map_block_range(
            DIRECT_MAP_BASE + window.cpu_base,
            window.cpu_base,
            len,
            device,
            frames,
        )?;
    }
    Ok(())
}

/// Config space reached through the high-half mapping `map_pci_windows` made.
///
/// The `unsafe` the `tessera-pci` crate forbids lives here, and it rests on
/// two facts: the ECAM window is mapped read-write at `DIRECT_MAP_BASE + phys`
/// before this is built, and the crate bounds every offset it passes against
/// the window length it was given.
struct EcamWindow {
    base: u64,
}

impl tessera_pci::ConfigSpace for EcamWindow {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `base + offset` is inside the mapped ECAM window (the caller
        // bounds the offset). A config-space read has no device-side effect.
        unsafe {
            tessera_karch_aarch64::mmio_read32((DIRECT_MAP_BASE + self.base + offset) as usize)
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read32`. Writes here program BARs and the command
        // register of a device the kernel is enumerating, before anything else
        // can hold a capability to it.
        unsafe {
            tessera_karch_aarch64::mmio_write32(
                (DIRECT_MAP_BASE + self.base + offset) as usize,
                value,
            );
        }
    }
}

/// The GICv2m frame: where a message-signalled interrupt is *sent*.
///
/// GICv2m is why message-signalled interrupts are cheap on this port. The
/// frame is a doorbell: a device writes an SPI number to `SETSPI` and the GIC
/// raises that SPI. So an MSI becomes an **ordinary wired interrupt** the
/// moment it lands, and everything downstream — `enable_irq`, the IRQ→port
/// bridge, the EL0 driver waiting on its port (D84) — is reused unchanged.
/// Nothing here knows it is handling a message.
struct V2mFrame {
    base: u64,
    first_spi: u32,
    spi_count: u32,
    /// SPIs handed out so far, from the low end of the frame's range.
    allocated: u32,
}

/// `SETSPI_NSR`: writing an SPI number here raises it. This is the address a
/// device's MSI message is programmed with.
const V2M_SETSPI: u64 = 0x040;
/// `TYPER`: base SPI in bits 25:16, count in bits 9:0.
const V2M_TYPER: u64 = 0x008;

impl V2mFrame {
    /// Reads the frame's own description of the SPI range it owns.
    ///
    /// Taken from `TYPER` rather than the device tree's `arm,msi-base-spi` and
    /// `arm,msi-num-spis`: both describe the same thing, and the one the
    /// hardware answers with cannot disagree with the hardware.
    fn probe(base: u64) -> Self {
        // SAFETY: `base` is the v2m frame the device tree reported, inside
        // `DEVICE_RANGE` and therefore identity-mapped in the low half; TYPER
        // is a defined read-only register and reading it has no side effect.
        let typer = unsafe { tessera_karch_aarch64::mmio_read32((base + V2M_TYPER) as usize) };
        Self {
            base,
            first_spi: (typer >> 16) & 0x3ff,
            spi_count: typer & 0x3ff,
            allocated: 0,
        }
    }

    /// Takes the next SPI from the frame's range.
    ///
    /// An SPI outside the range belongs to some other device on the machine —
    /// handing one out would arm an interrupt this frame never raises, and the
    /// driver would wait for something that cannot arrive.
    fn allocate(&mut self) -> Option<u32> {
        if self.allocated >= self.spi_count {
            return None;
        }
        let spi = self.first_spi + self.allocated;
        self.allocated += 1;
        Some(spi)
    }

    /// The address a device writes to raise an SPI.
    const fn doorbell(&self) -> u64 {
        self.base + V2M_SETSPI
    }
}

/// The machine's SMMUv3, if it has one.
fn smmu_device(dtb: u64) -> Option<MmioDevice> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM and the reader
    // bounds-checks every access inside its self-declared length.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(b"arm,smmu-v3")
        .ok()?
}

/// The machine's real-time clock, if it has one — this port's wakeup source.
fn rtc_device(dtb: u64) -> Option<MmioDevice> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the reader
    // bounds-checks every access inside its self-declared length.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(PL031_COMPATIBLE)
        .ok()?
}

/// How long the machine's description is, out of its own header.
///
/// The length a bus controller is granted, and taken from the blob rather than
/// assumed: a header says how much of it there is, and a window sized by
/// anything else would either hide part of the machine or hand out memory the
/// firmware never wrote.
fn dtb_total_size(dtb: u64) -> Option<u64> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the header
    // is read before the body to learn how much of it there is.
    let total =
        unsafe { tessera_devicetree::total_size(core::slice::from_raw_parts(at, 64)) }.ok()?;
    Some(total as u64)
}

/// The machine's PL061 GPIO controller, if it has one.
///
/// Found by compatible string, which is all the device tree is asked for: the
/// window and the interrupt. **What the part is is not taken from here** — the
/// tree is a description somebody wrote, and the manager reads the answer out
/// of the device's own identification registers.
fn pl061_device(dtb: u64) -> Option<MmioDevice> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the header
    // is read before the body to learn how much of it there is.
    let total =
        unsafe { tessera_devicetree::total_size(core::slice::from_raw_parts(at, 64)) }.ok()?;
    // SAFETY: as above, now for the length the header declared.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(b"arm,pl061")
        .ok()?
}

/// The machine's GICv2m frame, if it has one.
fn v2m_frame(dtb: u64) -> Option<V2mFrame> {
    let at = (DIRECT_MAP_BASE + dtb) as *const u8;
    // SAFETY: as `pci_host` — the blob is in direct-mapped RAM, and the
    // reader bounds-checks every access inside its self-declared length.
    let header = unsafe { core::slice::from_raw_parts(at, HEADER_LEN) };
    let total = tessera_devicetree::total_size(header).ok()?;
    // SAFETY: as above.
    let blob = unsafe { core::slice::from_raw_parts(at, total) };
    let node = DeviceTree::parse(blob)
        .ok()?
        .first_mmio_device(b"arm,gic-v2m-frame")
        .ok()??;
    Some(V2mFrame::probe(node.base))
}

/// A register window over a BAR the kernel placed, for reaching an MSI-X table
/// or a device's own registers.
///
/// The `ConfigSpace` trait is a 32-bit register window; `tessera-pci` uses it
/// for config space and for an MSI-X table alike, because the two differ in
/// where they are and not in how they are touched.
struct BarWindow {
    base: u64,
}

impl BarWindow {
    /// A 64-bit register write.
    ///
    /// Needed because a device's registers are not all 32 bits wide: `edu`'s
    /// DMA source, destination and count are `dma_addr_t`, and its register
    /// decode has no case for the upper half's offset — so two 32-bit writes
    /// set the low word and drop the high one on the floor, leaving the device
    /// with an address it never agreed to and no complaint about it.
    fn write64(&mut self, offset: u64, value: u64) {
        // SAFETY: as the 32-bit accessor below — a BAR this kernel placed
        // inside the bridge's mapped memory window.
        unsafe {
            ((DIRECT_MAP_BASE + self.base + offset) as *mut u64).write_volatile(value);
        }
    }

    /// A 64-bit register read.
    fn read64(&self, offset: u64) -> u64 {
        // SAFETY: as `write64`.
        unsafe { ((DIRECT_MAP_BASE + self.base + offset) as *const u64).read_volatile() }
    }
}

impl tessera_pci::ConfigSpace for BarWindow {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `base` is a BAR this kernel placed inside the bridge's
        // memory window, which `map_pci_windows` mapped at
        // `DIRECT_MAP_BASE + phys`; `offset` stays inside that BAR.
        unsafe {
            tessera_karch_aarch64::mmio_read32((DIRECT_MAP_BASE + self.base + offset) as usize)
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read32`.
        unsafe {
            tessera_karch_aarch64::mmio_write32(
                (DIRECT_MAP_BASE + self.base + offset) as usize,
                value,
            );
        }
    }
}

/// Set by the MSI hook when the SPI this check armed is taken.
static MSI_SPI: AtomicU32 = AtomicU32::new(0);
static MSI_DELIVERED: AtomicU32 = AtomicU32::new(0);

/// The `edu` device: QEMU's minimal PCI endpoint. Writing `RAISE` makes it
/// send its interrupt; writing `ACK` clears it.
const EDU_VENDOR: u16 = 0x1234;
const EDU_DEVICE: u16 = 0x11e8;
const EDU_RAISE: u64 = 0x60;
const EDU_ACK: u64 = 0x64;
/// The device's own record that it raised — set by `RAISE`, cleared by `ACK`.
const EDU_IRQ_STATUS: u64 = 0x24;

/// The IRQ hook for the SPI a message-signalled interrupt was programmed to
/// raise. Counts it and acknowledges nothing else: this proves the message
/// arrived, and the device's own acknowledgement is the caller's business.
fn msi_irq_hook(id: u32) -> bool {
    if id != MSI_SPI.load(Ordering::SeqCst) || id == 0 {
        return false;
    }
    // SAFETY: masking a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(id) };
    MSI_DELIVERED.fetch_add(1, Ordering::SeqCst);
    true
}

/// The SMMU's registers, reached at their physical address through the
/// low-half identity map — the same way the GIC and the v2m frame are, and
/// unlike ECAM, which sits above `DEVICE_RANGE` and needed its own mapping.
struct SmmuRegisters {
    base: usize,
}

impl tessera_smmu::Registers for SmmuRegisters {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: the SMMU's register page is inside `DEVICE_RANGE` and so is
        // identity-mapped device memory; every offset comes from the register
        // map in `tessera_smmu::reg`.
        unsafe { tessera_karch_aarch64::mmio_read32(self.base + offset) }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        // SAFETY: as `read32`.
        unsafe { tessera_karch_aarch64::mmio_write32(self.base + offset, value) }
    }
    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: as `read32`; the SMMU's 64-bit registers are naturally
        // aligned within the page.
        unsafe { ((self.base + offset) as *const u64).read_volatile() }
    }
    fn write64(&mut self, offset: usize, value: u64) {
        // SAFETY: as `read64`.
        unsafe { ((self.base + offset) as *mut u64).write_volatile(value) }
    }
}

/// A word written through the direct map, for the structures the SMMU walks:
/// stream table, queues, and stage-2 tables all live in frames the boot
/// allocator handed out, and the hardware reads them at their physical
/// addresses while the kernel writes them at their direct-map aliases.
fn direct_write64(phys: u64, offset: u64, value: u64) {
    // SAFETY: `phys` is a frame the boot allocator handed out and `offset`
    // stays inside it, so the direct-map alias is mapped writable RAM.
    unsafe { ((DIRECT_MAP_BASE + phys + offset) as *mut u64).write_volatile(value) }
}

/// The counterpart read. See [`direct_write64`].
fn direct_read64(phys: u64, offset: u64) -> u64 {
    // SAFETY: as `direct_write64`.
    unsafe { ((DIRECT_MAP_BASE + phys + offset) as *const u64).read_volatile() }
}

/// Zeroes a whole frame the hardware is about to walk. An uninitialised
/// structure is a structure of undefined entries, not an empty one.
fn zero_frame(phys: u64) {
    for offset in (0..FRAME_SIZE).step_by(8) {
        direct_write64(phys, offset, 0);
    }
}

/// Streams this SMMU can hold an aperture for at once. One per device behind
/// it; this machine puts one device behind it.
const MAX_SMMU_STREAMS: usize = 4;

/// What one level-3 table describes: 512 entries of one page.
const LEAF_SPAN: u64 = 512 * FRAME_SIZE;

/// A stream's translation, and the device capability it belongs to.
///
/// `object` is what makes this reachable from the kernel core: `dma_alloc`
/// knows the device object a driver named, and knows nothing about stream ids.
struct SmmuStream {
    object: kcore::object::ObjectId,
    stream: u32,
    /// The level-3 table describing `[0, LEAF_SPAN)` for this stream — the
    /// only addresses it can be given, and the reason a lease is bounded.
    leaf: u64,
    /// The live lease's `(base, len)`, if a driver holds one. `None` means the
    /// stream is configured and translates nothing: every address it tries
    /// takes a stage-2 fault, which is both what "no lease" ought to mean and
    /// what makes the refusal observable in the event queue.
    lease: Option<(u64, u64)>,
}

/// The SMMU, brought up once and left running for the life of the boot.
///
/// This is the hardware behind [`kcore::devmgr::DmaMapper`]: the graph records
/// which addresses belong to a device, and this installs them. It is boot glue
/// rather than a crate because everything here is *poking* — the encoding it
/// writes all comes from `tessera_smmu`, which is `forbid(unsafe_code)` and
/// host-tested, and that split is what caught three encoding bugs before
/// hardware saw them (D119).
/// What the fault harvest has seen, and how it found out.
///
/// The log exists because there are now **two** readers of one queue — the
/// unit's interrupt and a boot check that polls — and a queue read by two
/// consumers is a race in which either can swallow the other's record. Making
/// the harvest the only consumer and the log the only reader removes the race
/// rather than timing around it: whichever path drains first, both see the
/// same answer.
#[derive(Clone, Copy, Default)]
struct FaultLog {
    /// The most recent fault, taken by the next reader.
    ///
    /// Written by the interrupt bridge and read by boot code, which is safe to
    /// do as a plain field **only** because every reader synchronises on
    /// [`SMMU_FAULTS_SEEN`] first: the harvest stores that counter after
    /// writing this, so a reader that has observed the counter move has
    /// observed the record too.
    last: Option<tessera_smmu::Event>,
}

/// Faults harvested since boot.
///
/// An atomic, and a static rather than a field, because the writer is an
/// interrupt handler and the readers are boot code spinning on it. A plain
/// counter would be hoisted out of any wait loop that watched it — the loop
/// would read one cached value forever and time out on a fault that had
/// already arrived, which is a false negative that looks exactly like the
/// interrupt never firing.
static SMMU_FAULTS_SEEN: AtomicU32 = AtomicU32::new(0);

/// How many of those arrived because the unit *told* the kernel, rather than
/// because something happened to look.
///
/// Counted apart because it is the whole claim of the runtime harvest. A boot
/// check that polls proves the queue works; only this proves a fault on a
/// system nobody is watching would be seen.
static SMMU_FAULTS_BY_INTERRUPT: AtomicU32 = AtomicU32::new(0);

struct Smmu {
    regs: SmmuRegisters,
    /// The linear stream table: one entry per stream id, all aborting except
    /// those an aperture has been installed for.
    strtab: u64,
    cmdq: u64,
    eventq: u64,
    /// The command queue's producer index, advanced by every command issued.
    prod: tessera_smmu::QueueIndex,
    /// The event queue's consumer index. Kept here rather than re-read per
    /// check, so successive readers each see the *next* fault rather than all
    /// re-reading the first one.
    cons: tessera_smmu::QueueIndex,
    streams: [Option<SmmuStream>; MAX_SMMU_STREAMS],
    /// What the harvest has seen. See [`FaultLog`].
    faults: FaultLog,
}

impl Smmu {
    /// Brings the SMMU up with every stream aborting, and nothing translating.
    ///
    /// Aborting is the safe starting state and the deliberate one: a stream
    /// with no entry must not bypass, or an SMMU with an empty table behaves
    /// exactly like no SMMU at all.
    fn bring_up(base: u64, frames: &mut kcore::pmem::BumpFrameAllocator<'_>) -> Result<Self, u32> {
        use tessera_smmu::Registers as _;

        // Contiguous **and aligned to its own size**, which is what the
        // architecture requires of a linear stream table and what the frame
        // allocator does not promise: `alloc_contiguous` guarantees the run is
        // unbroken and nothing about where it starts. A misaligned base has the
        // unit read the table from a lower address, find no valid entry for any
        // stream, and abort every transaction — which presents as DMA that
        // silently does not land, with the stream table looking perfectly well
        // formed in memory. Twice the frames are taken so an aligned run of the
        // right length is certain to be inside; this is boot-time and the waste
        // is one table.
        let table_bytes = STREAM_TABLE_FRAMES * FRAME_SIZE;
        let run = frames
            .alloc_contiguous(STREAM_TABLE_FRAMES * 2)
            .ok_or(2u32)?
            .as_u64();
        let strtab = run.next_multiple_of(table_bytes);
        let cmdq = frames.alloc().ok_or(2u32)?.base().as_u64();
        let eventq = frames.alloc().ok_or(2u32)?.base().as_u64();
        for frame in 0..STREAM_TABLE_FRAMES {
            zero_frame(strtab + frame * FRAME_SIZE);
        }
        for frame in [cmdq, eventq] {
            zero_frame(frame);
        }
        for entry in 0..(1u64 << STREAM_TABLE_LOG2) {
            let at = entry * tessera_smmu::STE_SIZE as u64;
            for (word, value) in tessera_smmu::stream_table_entry_abort().iter().enumerate() {
                direct_write64(strtab, at + (word as u64) * 8, *value);
            }
        }

        let mut smmu = Self {
            regs: SmmuRegisters {
                base: base as usize,
            },
            strtab,
            cmdq,
            eventq,
            prod: tessera_smmu::QueueIndex::new(QUEUE_LOG2, 0),
            cons: tessera_smmu::QueueIndex::new(QUEUE_LOG2, 0),
            streams: [const { None }; MAX_SMMU_STREAMS],
            faults: FaultLog::default(),
        };

        // Queues and the table go in **before** the SMMU is enabled: between
        // enabling and having a valid table every stream aborts, including any
        // the machine is already using.
        smmu.regs
            .write64(tessera_smmu::reg::CMDQ_BASE, cmdq | u64::from(QUEUE_LOG2));
        smmu.regs.write32(tessera_smmu::reg::CMDQ_PROD, 0);
        smmu.regs.write32(tessera_smmu::reg::CMDQ_CONS, 0);
        smmu.regs.write64(
            tessera_smmu::reg::EVENTQ_BASE,
            eventq | u64::from(QUEUE_LOG2),
        );
        smmu.regs.write32(tessera_smmu::reg::EVENTQ_PROD, 0);
        smmu.regs.write32(tessera_smmu::reg::EVENTQ_CONS, 0);
        smmu.regs.write64(tessera_smmu::reg::STRTAB_BASE, strtab);
        // Linear format, sized to the table just built.
        smmu.regs
            .write32(tessera_smmu::reg::STRTAB_BASE_CFG, STREAM_TABLE_LOG2);
        // A stream with no entry aborts rather than bypassing.
        smmu.regs.write32(
            tessera_smmu::reg::GBPA,
            tessera_smmu::gbpa::UPDATE | tessera_smmu::gbpa::ABORT,
        );
        smmu.regs.write32(
            tessera_smmu::reg::CR0,
            tessera_smmu::cr0::CMDQEN | tessera_smmu::cr0::EVENTQEN,
        );
        // **Ask the unit to speak up.** `EVENTQEN` makes it write records;
        // this makes it raise its own interrupt when it does. Without it the
        // queue still fills and nothing says so, which is a fault harvest that
        // works exactly when someone happens to look — during a boot check,
        // and never afterwards.
        //
        // Only the event queue: the PRI queue and the global-error line have
        // no consumer here, and enabling an interrupt nothing handles would
        // give this machine a line that asserts forever.
        smmu.regs
            .write32(tessera_smmu::reg::IRQ_CTRL, tessera_smmu::irq_ctrl::EVENTQ);

        smmu.issue(tessera_smmu::cmd_cfgi_all());
        smmu.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        smmu.issue(tessera_smmu::cmd_sync());

        smmu.regs.write32(
            tessera_smmu::reg::CR0,
            tessera_smmu::cr0::CMDQEN | tessera_smmu::cr0::EVENTQEN | tessera_smmu::cr0::SMMUEN,
        );
        // The hardware says when an enable took effect; assuming it did is how
        // a configuration race becomes an unexplainable fault later.
        let mut budget = 100_000u32;
        while smmu.regs.read32(tessera_smmu::reg::CR0ACK) & tessera_smmu::cr0::SMMUEN == 0
            && budget > 0
        {
            budget -= 1;
        }
        if budget == 0 {
            return Err(4);
        }
        // The unit acknowledges its interrupt-enable separately from `CR0`,
        // and a unit that never does is one whose faults would be harvested
        // only by polling — a degradation that must be reported rather than
        // discovered later as silence.
        let mut budget = 100_000u32;
        while smmu.regs.read32(tessera_smmu::reg::IRQ_CTRLACK) & tessera_smmu::irq_ctrl::EVENTQ == 0
            && budget > 0
        {
            budget -= 1;
        }
        if budget == 0 {
            return Err(5);
        }
        Ok(smmu)
    }

    /// Records that `object`'s DMA arrives on `stream` and builds the
    /// translation structures it will use, with **nothing mapped in them** —
    /// the device can reach exactly nothing until a lease says otherwise.
    ///
    /// Both levels of the table are allocated **here**, once, which is what
    /// lets [`Smmu::begin_lease`] and [`Smmu::map`] be allocation-free (see
    /// [`kcore::devmgr::DmaMapper`]) — and is why a lease cannot exceed
    /// [`LEAF_SPAN`]. Registering a stream is a fact about the machine's
    /// wiring, so it happens at enumeration; leasing is a fact about a driver,
    /// so it happens when one asks.
    fn register_stream(
        &mut self,
        object: kcore::object::ObjectId,
        stream: u32,
        frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    ) -> Result<(), u32> {
        if stream >= (1 << STREAM_TABLE_LOG2) {
            return Err(1);
        }
        let slot = self.streams.iter().position(Option::is_none).ok_or(8u32)?;
        let root = frames.alloc().ok_or(2u32)?.base().as_u64();
        let leaf = frames.alloc().ok_or(2u32)?.base().as_u64();
        zero_frame(root);
        zero_frame(leaf);

        let (t0sz, start_level) =
            tessera_smmu::t0sz_and_start_level(APERTURE_BITS).map_err(|_| 3u32)?;
        // The root is the level-2 table for a 30-bit address; its first entry
        // covers `[0, LEAF_SPAN)`, which is the whole of this stream's world.
        direct_write64(
            root,
            (tessera_smmu::level_index(0, 2) * 8) as u64,
            tessera_smmu::stage2_table_descriptor(leaf),
        );

        // A VMID per stream, so one stream's TLB entries are not another's.
        let ste = tessera_smmu::stream_table_entry_s2(
            root,
            (slot + 1) as u16,
            t0sz,
            tessera_smmu::start_level_to_sl0(start_level),
        );
        let at = u64::from(stream) * tessera_smmu::STE_SIZE as u64;
        for (word, value) in ste.iter().enumerate() {
            direct_write64(self.strtab, at + (word as u64) * 8, *value);
        }
        self.issue(tessera_smmu::cmd_cfgi_ste(stream));
        self.issue(tessera_smmu::cmd_sync());

        self.streams[slot] = Some(SmmuStream {
            object,
            stream,
            leaf,
            lease: None,
        });
        Ok(())
    }

    /// The stream registered for `object`, if it has one.
    fn stream_mut(&mut self, object: kcore::object::ObjectId) -> Option<&mut SmmuStream> {
        self.streams
            .iter_mut()
            .flatten()
            .find(|s| s.object == object)
    }

    /// The stream id an aperture was installed under for `object`.
    fn stream_of(&self, object: kcore::object::ObjectId) -> Option<u32> {
        self.streams
            .iter()
            .flatten()
            .find(|s| s.object == object)
            .map(|s| s.stream)
    }

    /// Pushes one command and rings the doorbell.
    fn issue(&mut self, command: tessera_smmu::Command) {
        use tessera_smmu::Registers as _;
        let at = u64::from(self.prod.index()) * tessera_smmu::CMD_SIZE as u64;
        direct_write64(self.cmdq, at, command[0]);
        direct_write64(self.cmdq, at + 8, command[1]);
        self.prod = self.prod.next();
        self.regs
            .write32(tessera_smmu::reg::CMDQ_PROD, self.prod.raw);
    }

    /// Consumes every fault the SMMU has logged since the last harvest,
    /// records each into `kcore::event`, applies the standing isolation
    /// policy, and remembers the **last** one for a polling reader.
    ///
    /// Draining rather than stepping one record at a time, because **one
    /// refused transfer does not produce one record**: an 8-byte DMA to an
    /// unmapped address logged three on this machine, so a consumer that
    /// advanced by one per harvest would read the previous transfer's refusal
    /// and call it the current one — which is exactly the false pass this
    /// diagnosed.
    ///
    /// `by_interrupt` says which of the two callers this is. Both exist and
    /// neither is redundant: the interrupt is what makes a fault on a running
    /// system visible, and the polled call is what keeps a boot check working
    /// in the windows where the line is masked. They cannot race for records
    /// because neither reads the queue — the log does, once, here.
    ///
    /// Returns how many records were consumed.
    fn harvest(&mut self, by_interrupt: bool) -> u32 {
        use tessera_smmu::Registers as _;
        // The producer index is readable at a page-0 offset and a page-1 alias
        // depending on the implementation; take whichever moved rather than
        // guessing which one this SMMU answers on.
        let page0 = self.regs.read32(0xa8);
        let page1 = self.regs.read32(tessera_smmu::reg::EVENTQ_PROD);
        let prod =
            tessera_smmu::QueueIndex::new(QUEUE_LOG2, if page0 != 0 { page0 } else { page1 });
        let mut consumed = 0u32;
        while !self.cons.is_empty(prod) {
            let at = u64::from(self.cons.index()) * tessera_smmu::EVENT_SIZE as u64;
            let record = tessera_smmu::decode_event([
                direct_read64(self.eventq, at),
                direct_read64(self.eventq, at + 8),
                direct_read64(self.eventq, at + 16),
                direct_read64(self.eventq, at + 24),
            ]);
            self.cons = self.cons.next();
            consumed += 1;
            self.faults.last = Some(record);
            // The record first, then the counters. A reader that has seen
            // `SMMU_FAULTS_SEEN` move has, by this ordering, also seen the
            // record it counts — which is what makes `last` safe to keep as a
            // plain field across an interrupt.
            if by_interrupt {
                SMMU_FAULTS_BY_INTERRUPT.fetch_add(1, Ordering::SeqCst);
            }
            SMMU_FAULTS_SEEN.fetch_add(1, Ordering::SeqCst);
            self.report(record);
        }
        // Told once, after the loop: `EVENTQ_CONS` is how the unit learns the
        // queue has room again, and writing it per record would be a register
        // access per fault on a path a storm can drive.
        self.regs
            .write32(tessera_smmu::reg::EVENTQ_CONS, self.cons.raw);
        consumed
    }

    /// Hands one decoded record to the kernel core: the log first, then the
    /// standing policy.
    ///
    /// The two are separate calls because they have different preconditions.
    /// Recording needs nothing and therefore always happens — `docs/drivers/01`
    /// says faults "are logged", with no qualifier, and a harvest that skipped
    /// the record when no executive was in scope would lose exactly the faults
    /// that happen between checks. Isolation needs the resource graph, so it
    /// happens when there is one and the absence is a fact about this moment
    /// in boot rather than a silent downgrade.
    fn report(&mut self, record: tessera_smmu::Event) {
        use kcore::devmgr::{DmaFault, DmaFaultKind, IsolationPolicy};
        use tessera_smmu::FaultClass;

        let kind = match record.class() {
            FaultClass::Unmapped => DmaFaultKind::Unmapped,
            FaultClass::Permission => DmaFaultKind::Permission,
            FaultClass::UnknownStream => DmaFaultKind::UnknownStream,
            FaultClass::BadConfiguration => DmaFaultKind::BadConfiguration,
            FaultClass::Other => DmaFaultKind::Unclassified,
        };
        let fault = DmaFault {
            // A stream with no registered device is not a lookup failure to
            // paper over — it is this kernel's own stream table describing
            // something no capability backs, and the record says so.
            device: self
                .streams
                .iter()
                .flatten()
                .find(|s| s.stream == record.stream)
                .map(|s| s.object),
            stream: record.stream,
            address: record.address,
            kind,
        };
        kcore::devmgr::record_dma_fault(&fault);

        let policy = match SMMU_FAULT_POLICY.load(Ordering::SeqCst) {
            p if p == IsolationPolicy::EndLease as u32 => IsolationPolicy::EndLease,
            p if p == IsolationPolicy::EndLeaseAndStop as u32 => IsolationPolicy::EndLeaseAndStop,
            _ => IsolationPolicy::Report,
        };
        if matches!(policy, IsolationPolicy::Report) {
            return;
        }
        // SAFETY: transient raw access to the static executive. This runs
        // either from boot code between scheduler runs, or from the interrupt
        // bridge — which can only preempt EL0 execution or boot code outside
        // an enable window, never a live Executive borrow (the same argument
        // `virtio_irq_hook` rests on). Nothing here blocks or schedules.
        let outcome = unsafe {
            match (*(&raw mut KCORE_EXEC)).as_mut() {
                Some(exec) => exec.isolate_dma_fault(fault, policy, Some(self)),
                // No executive: the fault is recorded and nothing is isolated,
                // because there is no graph saying who holds what. Boot before
                // the first check is genuinely in this state.
                None => return,
            }
        };
        if let Some(holder) = outcome.stop {
            // The policy asked for the holder to be stopped and this port has
            // no supervisor in scope to do it, so the request is published for
            // one rather than dropped: a policy that reports acting without
            // acting is the silent degradation docs/lifecycle/04 forbids.
            SMMU_ISOLATION_STOP.store(holder.raw(), Ordering::SeqCst);
        }
    }

    /// Consumes anything outstanding and returns the most recent fault, or
    /// `None` when none has been harvested since the last reader took one.
    ///
    /// **Takes rather than peeks**, which is what preserves the semantics
    /// every existing caller was written against: drain before a transfer to
    /// clear, drain after it to read that transfer's refusal. It also makes
    /// the polled reader immune to the interrupt beating it to the queue — a
    /// fault harvested by the bridge a moment earlier is still waiting here.
    fn drain_events(&mut self) -> Option<tessera_smmu::Event> {
        self.harvest(false);
        self.faults.last.take()
    }
}

/// The kernel core's DMA seam, implemented by real hardware.
///
/// Everything this refuses is a refusal the caller sees rather than a
/// translation quietly not installed: an unknown device, an unaligned range,
/// or a range past what this stream's one table can describe.
impl kcore::devmgr::DmaMapper for Smmu {
    fn translates(&self, device: kcore::object::ObjectId) -> bool {
        self.streams.iter().flatten().any(|s| s.object == device)
    }

    fn begin_lease(
        &mut self,
        device: kcore::object::ObjectId,
    ) -> Result<(u64, u64), tessera_karch::KError> {
        use tessera_karch::KError;
        let stream = self.stream_mut(device).ok_or(KError::InvalidMapping)?;
        let leaf = stream.leaf;
        stream.lease = Some((LEASE_BASE, LEASE_LEN));
        // **Start from nothing, always.** The previous lease's teardown already
        // cleared this table, so this is redundant on the happy path — and that
        // is the point: reissuing a device-visible address is only safe if the
        // new lease cannot inherit a translation, and belt-and-braces here is
        // cheaper than trusting that every teardown ran.
        zero_frame(leaf);
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
        Ok((LEASE_BASE, LEASE_LEN))
    }

    fn end_lease(&mut self, device: kcore::object::ObjectId) {
        let Some(stream) = self.stream_mut(device) else {
            return;
        };
        let leaf = stream.leaf;
        stream.lease = None;
        // **Empty the table; leave the stream table entry valid.** Setting the
        // entry back to abort would also stop the device, but it would stop it
        // as `C_BAD_STREAMID` — the fault for a stream that was never
        // configured — which reports no address and reads exactly like a
        // misconfiguration. An empty translation table is what "reaches
        // nothing" should mean, and a device that tries anyway takes an
        // ordinary stage-2 translation fault naming the address it wanted.
        // That is the difference between revocation being enforced and
        // revocation being observable, and `docs/drivers/01` asks for both.
        //
        // Setting the entry to abort belongs to *device removal*, which is a
        // different sentence in the same paragraph and not this milestone.
        zero_frame(leaf);
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
    }

    fn map(
        &mut self,
        device: kcore::object::ObjectId,
        iova: u64,
        phys: u64,
        len: u64,
    ) -> Result<(), tessera_karch::KError> {
        use tessera_karch::KError;
        let stream = self
            .streams
            .iter()
            .flatten()
            .find(|s| s.object == device)
            .ok_or(KError::InvalidMapping)?;
        let leaf = stream.leaf;
        // A mapper whose only correctness argument is "my caller checks" is one
        // refactor away from being wrong.
        let (base, span) = stream.lease.ok_or(KError::InvalidMapping)?;
        if len == 0 || len % FRAME_SIZE != 0 || iova % FRAME_SIZE != 0 || phys % FRAME_SIZE != 0 {
            return Err(KError::Unaligned);
        }
        let end = iova.checked_add(len).ok_or(KError::InvalidMapping)?;
        if iova < base || end > base + span || end > LEAF_SPAN {
            return Err(KError::InvalidMapping);
        }
        for page in 0..len / FRAME_SIZE {
            let at = iova + page * FRAME_SIZE;
            direct_write64(
                leaf,
                (tessera_smmu::level_index(at, 3) * 8) as u64,
                tessera_smmu::stage2_page_descriptor(phys + page * FRAME_SIZE),
            );
        }
        // The address was never mapped before — an aperture does not reuse —
        // but the hardware may hold a *negative* translation for it from a
        // fault, so the entry only becomes visible once the TLB is told.
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
        Ok(())
    }

    fn unmap(
        &mut self,
        device: kcore::object::ObjectId,
        iova: u64,
        len: u64,
    ) -> Result<(), tessera_karch::KError> {
        use tessera_karch::KError;
        let stream = self
            .streams
            .iter()
            .flatten()
            .find(|s| s.object == device)
            .ok_or(KError::InvalidMapping)?;
        let leaf = stream.leaf;
        // The same checks as `map`, and for the same reason: a mapper whose
        // only correctness argument is "my caller checks" is one refactor away
        // from being wrong. Here the stakes are the other way round — a range
        // this refuses to clear is one the device can still reach.
        let (base, span) = stream.lease.ok_or(KError::InvalidMapping)?;
        if len == 0 || len % FRAME_SIZE != 0 || iova % FRAME_SIZE != 0 {
            return Err(KError::Unaligned);
        }
        let end = iova.checked_add(len).ok_or(KError::InvalidMapping)?;
        if iova < base || end > base + span || end > LEAF_SPAN {
            return Err(KError::InvalidMapping);
        }
        for page in 0..len / FRAME_SIZE {
            let at = iova + page * FRAME_SIZE;
            // Descriptor zero is invalid — bit 0 clear. The device's next
            // transaction to this address raises a translation fault, which is
            // what "the device can no longer reach it" has to mean.
            direct_write64(leaf, (tessera_smmu::level_index(at, 3) * 8) as u64, 0);
        }
        // **The invalidation is the unmap.** Clearing the descriptor without
        // telling the TLB leaves the old translation live in the hardware for
        // as long as it cares to keep it — the bookkeeping would say detached
        // and the device would still be writing.
        self.issue(tessera_smmu::cmd_tlbi_nsnh_all());
        self.issue(tessera_smmu::cmd_sync());
        Ok(())
    }
}

/// How the aperture is sized. A 30-bit input address makes the stage-2 root a
/// single 512-entry level-2 table — one frame — and puts everything at or
/// above 2 MiB outside the one level-3 table below it, which is what makes
/// "outside the aperture" unambiguous rather than a matter of degree.
const APERTURE_BITS: u32 = 30;
/// Where a lease starts in a device's address space, and how wide it is.
///
/// Not zero, because a device-visible address of 0 is handed to ring 3 as a
/// syscall return value, where every driver in this tree reads 0 as failure.
/// Two pages, so a second allocation has somewhere to go and a third proves
/// exhaustion refuses.
const LEASE_BASE: u64 = 0x1_0000;
const LEASE_LEN: u64 = 2 * FRAME_SIZE;
/// Where the device is told to write, inside the lease.
const APERTURE_IOVA: u64 = LEASE_BASE;
/// An address with no translation: the second 2 MiB, which the root table
/// does not describe at all.
const OUTSIDE_IOVA: u64 = 0x20_0000;
/// Entries in the linear stream table — enough to cover the stream ids this
/// machine's PCI functions get, and small enough to fit one frame.
/// Log2 of the linear stream table's entry count.
///
/// **Sized by the bus numbers, not by the device count.** A PCIe stream id is
/// the requester id — `bus << 8 | device << 3 | function` — because that is what
/// the hardware puts on the bus, not something this kernel gets to choose. So
/// the moment a function sits behind a bridge its stream id is at least 256, and
/// a table sized for the devices on bus 0 refuses it: `register_stream` returns
/// "outside the table", and the failure surfaces as a driver that cannot be
/// given DMA rather than as anything mentioning buses.
///
/// Ten covers buses 0 through 3, which is every machine here — 1024 entries at
/// 64 bytes each, sixteen contiguous frames. A machine deeper than that needs
/// the two-level table the architecture provides, which is the right answer for
/// a real range of bus numbers and more mechanism than any check here would
/// exercise.
const STREAM_TABLE_LOG2: u32 = 10;

/// Frames the stream table occupies, which must be contiguous: the unit indexes
/// it as one array from a single base register.
const STREAM_TABLE_FRAMES: u64 =
    ((1u64 << STREAM_TABLE_LOG2) * tessera_smmu::STE_SIZE as u64).div_ceil(FRAME_SIZE);
/// Entries in each queue.
const QUEUE_LOG2: u32 = 3;
/// The pattern the device is made to move, chosen to be recognisable in a
/// page that is otherwise zero.
const DMA_PATTERN: u64 = 0x5344_4d4d_5556_3300;

/// edu's DMA registers (QEMU `hw/misc/edu.c`).
const EDU_DMA_SRC: u64 = 0x80;
const EDU_DMA_DST: u64 = 0x88;
const EDU_DMA_COUNT: u64 = 0x90;
const EDU_DMA_CMD: u64 = 0x98;
/// The address of edu's own buffer, in its private address space — not
/// something the SMMU translates.
const EDU_BUFFER: u64 = 0x4_0000;
const EDU_DMA_START: u64 = 1 << 0;
/// Direction bit: set means edu's buffer to memory, which is the direction
/// that lets the kernel *observe* whether a transfer landed.
const EDU_DMA_TO_MEMORY: u64 = 1 << 1;

/// Functions one walk may report.
const MAX_PCI_FUNCTIONS: usize = 16;

/// The stream id a PCI function's DMA arrives at the SMMU under.
///
/// It is the function's RID, because this machine's `iommu-map` is the
/// identity map (verified from the device tree). A machine with a non-identity
/// map needs the property parsed; this one would report a different stream in
/// its fault records, which is how it would be caught.
fn stream_id_of(function: &tessera_pci::Function) -> u32 {
    (u32::from(function.bdf.bus) << 8)
        | (u32::from(function.bdf.device) << 3)
        | u32::from(function.bdf.function)
}

/// Resolves a virtio-pci function's configuration structures to direct-map
/// addresses by walking its vendor capabilities.
///
/// A virtio-pci device does not say where its controls are in any register —
/// it says so in **config space**, one vendor-specific capability per
/// structure, each naming a BAR and an offset within it. There are several of
/// them, which is why the walk has to be resumable
/// ([`tessera_pci::find_capability_from`]): stopping at the first match finds
/// whichever structure the device happened to list first and misses the rest.
fn virtio_pci_regions(
    host: &tessera_devicetree::PciHost,
    function: &tessera_pci::Function,
) -> Option<virtio::PciRegions> {
    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let cfg = EcamWindow {
        base: host.ecam_base,
    };
    let device_type = tessera_virtio::pci::device_type(function.device)?;

    let mut regions = virtio::PciRegions {
        common: 0,
        notify: 0,
        notify_multiplier: 0,
        isr: 0,
        device_cfg: 0,
        device_type,
        bar_base: 0,
        bar_len: 0,
        capabilities: 0,
    };
    let mut at = None;
    // Bounded by the capability list itself; `find_capability_from` refuses a
    // chain that loops or runs past the header.
    while let Ok(Some(offset)) =
        tessera_pci::find_capability_from(&bridge, &cfg, function.bdf, tessera_pci::CAP_VENDOR, at)
    {
        at = Some(offset);
        regions.capabilities += 1;
        let word = |i: u16| bridge.read(&cfg, function.bdf, offset + i * 4).unwrap_or(0);
        let cap = tessera_virtio::pci::decode_cap([word(0), word(1), word(2), word(3)]);
        let Some((bar_base, bar_len)) = function.bars.get(cap.bar as usize).copied().flatten()
        else {
            continue; // a structure in a BAR that was not placed is unreachable
        };
        // The device's own numbers, so they are checked before they are trusted.
        if u64::from(cap.offset) + u64::from(cap.length) > bar_len {
            continue;
        }
        let at_addr = DIRECT_MAP_BASE + bar_base + u64::from(cap.offset);
        match cap.cfg_type {
            tessera_virtio::pci::cfg_type::COMMON => {
                regions.common = at_addr;
                // The BAR the controls are in is the one a driver must be
                // granted; the structures are offsets within it.
                regions.bar_base = bar_base;
                regions.bar_len = bar_len;
            }
            tessera_virtio::pci::cfg_type::NOTIFY => {
                regions.notify = at_addr;
                // The multiplier follows the standard capability, and only a
                // notify capability carries it.
                regions.notify_multiplier = word(4);
            }
            tessera_virtio::pci::cfg_type::ISR => regions.isr = at_addr,
            tessera_virtio::pci::cfg_type::DEVICE => regions.device_cfg = at_addr,
            _ => {}
        }
    }
    // Without all three there is no transport to build; saying so beats
    // building one over address zero.
    if regions.common == 0 || regions.notify == 0 || regions.isr == 0 {
        return None;
    }
    Some(regions)
}

/// The PCI base class the manager maps to `DeviceClass::Block`. The kernel
/// needs it only to pick a function worth handing the manager; the
/// classification itself is the manager's, from the identity the graph holds.
const PCI_CLASS_MASS_STORAGE: u32 = 0x01;

/// Whether `f` is a **virtio** mass-storage function.
///
/// The class alone stopped being enough when a second storage transport
/// arrived: an NVMe controller is mass storage too, and every check that went
/// looking for "the block device" by class found whichever the walk listed
/// first. The one that hunts for virtio capabilities then declared a fatal
/// error about a controller that never claimed to have any.
fn is_virtio_storage(f: &tessera_pci::Function) -> bool {
    f.class_code >> 16 == PCI_CLASS_MASS_STORAGE && f.vendor == RELAY_VIRTIO_VENDOR
}
/// The PCI class byte for a network controller.
const PCI_CLASS_NETWORK: u32 = 0x02;
/// Base class 0x06 subclass 0x04 — a PCI-to-PCI bridge, which is what a
/// `pcie-root-port` presents as and what a device sits behind to be removable.
const PCI_CLASS_PCI_BRIDGE: u32 = 0x0604;

/// How far into a device's window the ring-3 driver reads to show it was
/// granted the whole thing. Must match `FAR_OFFSET` in `userspace/blk-probe`.
const FAR_WINDOW_OFFSET: u64 = 0x2000;

/// The tag `blk-probe` folds into a report about a device it was told the
/// identity of rather than read — `"PC"`, so a report cannot be mistaken for a
/// register value. Must match `userspace/blk-probe`.
const PCI_REPORT_TAG: u64 = 0x5043 << 48;

/// The device object the `edu` function is registered under for both DMA
/// checks. One constant because the SMMU keys a stream's translation by object
/// id: the check that registers the stream and the check that leases it must
/// name the same device, and each check builds its own executive.
const SMMU_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(23);

/// The DMA driver process's own object id.
///
/// Distinct from the device it drives, which is not a formality: a lease
/// records its holder, and a process whose id *is* the device object would make
/// every holder comparison in the check true for the wrong reason.
const SCOPED_DMA_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(24);

/// Enumerates the PCI bus. See the RISC-V port's twin for why the **kernel**
/// walks config space rather than the device manager (D114): config space is
/// not per-device, so a capability to it would be authority over every
/// function behind the bridge at once.
/// Object ids for the chain the hotplug check registers, from the root port
/// down: `[root port, switch upstream, switch downstream, endpoint]`.
///
/// Four, because what is pulled here is a **switch** rather than a function,
/// and the whole point is that the graph knows what was behind it. The root
/// port stays in the machine and is registered so that the removal can be shown
/// to stop at the edge of the subtree rather than at the edge of the array.
const HOTPLUG_CHAIN_OBJ: [kcore::object::ObjectId; 4] = [
    kcore::object::ObjectId::from_raw(0x64),
    kcore::object::ObjectId::from_raw(0x66),
    kcore::object::ObjectId::from_raw(0x67),
    kcore::object::ObjectId::from_raw(0x68),
];
/// The process that holds them while the switch is pulled.
const HOTPLUG_HOLDER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x65);

/// How long to wait for the device to be pulled, in config reads. Generous:
/// the harness has to notice a serial marker, connect to QMP and issue a
/// command, and a bound that expired first would make this check fail for
/// reasons that have nothing to do with the kernel.
const HOTPLUG_POLL_LIMIT: u64 = 200_000_000;

/// What the removal check observed.
struct RemovalOutcome {
    /// Config reads before the function stopped answering.
    polls: u64,
    /// Holders the removal took the capability from.
    holders: usize,
    /// Whether the graph could still find the device afterwards.
    still_known: bool,
    /// Nodes the removal took — the switch and everything that was behind it.
    subtree: usize,
}

/// **A device is pulled out from under a holder that is still using it.**
///
/// Everything else in this file that ends a capability's life is something the
/// holder did — it handed the device on, or it died. This is the case the
/// resource graph could describe (`Removed` has been a terminal lifecycle state
/// since the driver framework landed) and nothing could perform.
///
/// The proof has a half only the machine can supply. The kernel's bookkeeping
/// would agree with itself whatever it did, so what makes this a check rather
/// than an assertion is that **QEMU really removes the function**: its config
/// space stops answering, which is how surprise removal is detected on this bus
/// and not something the kernel can arrange for itself.
///
/// **What is pulled here is a switch, not a function** (M97). A bus controller
/// does not leave alone: unplugging the switch takes its downstream port and
/// the endpoint below it in one physical event, and three functions stop
/// answering at once. A graph that removed only the node it was told about
/// would leave the other two resolving, mapping and authorizing DMA for
/// hardware that is not there — the exact condition removal exists to prevent,
/// reintroduced one level down.
///
/// The root port is registered too, and **must survive**. It is still in the
/// machine, and a removal that walked upward as readily as downward would take
/// it — which no amount of counting the nodes that went would reveal.
///
/// `chain` is the enumeration, from which the topology is read off the parent
/// edges rather than guessed from bus numbers.
fn pci_removal_check(
    host: &tessera_devicetree::PciHost,
    chain: &[tessera_pci::Function],
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    kernel_space: &KernelAddressSpace,
) -> Result<RemovalOutcome, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};

    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };

    // **The topology, read off the parent edges the walk recorded.** The root
    // port is the bridge on the host's own bus; the switch is the bridge behind
    // it; the endpoint is whatever mass-storage function is below that. Reading
    // it from the edges rather than from bus numbers is the difference between
    // knowing the tree and re-deriving it from an encoding that happens to be
    // ordered today.
    let root_port = chain
        .iter()
        .find(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE && f.parent.is_none())
        .ok_or(204u32)?;
    let switch = chain
        .iter()
        .find(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE && f.parent == Some(root_port.bdf))
        .ok_or(205u32)?;
    let downstream = chain
        .iter()
        .find(|f| f.class_code >> 8 == PCI_CLASS_PCI_BRIDGE && f.parent == Some(switch.bdf))
        .ok_or(206u32)?;
    let endpoint = chain.iter().find(|f| is_virtio_storage(f)).ok_or(207u32)?;
    // The endpoint must be under the downstream port, or the machine is not the
    // one this check was written for and what it proves is not what it claims.
    if endpoint.parent != Some(downstream.bdf) {
        return Err(208);
    }
    let bdf = switch.bdf;

    // A fresh executive holding the function as a device, and a process holding
    // a capability to it — the state a bound driver is in.
    // A fresh executive; the process table is **not** rebuilt.
    //
    // `KCORE_PROCESSES` is a `static mut` with a const initializer, so it is
    // already a valid empty table living in .bss. Writing a new one over it
    // means constructing a `ProcessTable` **on the stack** and copying — and a
    // table is sixteen `Process`es, each carrying a 1024-entry handle table,
    // which is a couple of hundred kilobytes the boot stack does not have. It
    // overflows, and the fault arrives somewhere with no stack left to report
    // it from, which is why this failed with no diagnosis at all.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 190u32)?;
    let user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);
    // A holder for every node in the chain — the root port included, so the
    // check can tell "the subtree went" from "everything went".
    let holder_index = {
        let mut process = kcore::process::Process::new(HOTPLUG_HOLDER_OBJ, user_space);
        for object in HOTPLUG_CHAIN_OBJ {
            process
                .handles_mut()
                .install(object, Rights::READ | Rights::MAP)
                .map_err(|_| 191u32)?;
        }
        // SAFETY: transient raw access to the static process table.
        unsafe {
            (*(&raw mut KCORE_PROCESSES))
                .insert(process)
                .map_err(|_| 192u32)?
        }
    };
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(193u32)?;
        // The window is nominal — nothing here maps one, and what is being
        // checked is the graph's knowledge of the machine's shape.
        for (index, object) in HOTPLUG_CHAIN_OBJ.iter().enumerate() {
            exec.device_register_mmio(
                *object,
                host.ecam_base + (index as u64) * FRAME_SIZE,
                FRAME_SIZE,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            )
            .map_err(|_| 194u32)?;
        }
        // The edges, root port downward. Registered as a chain because that is
        // what the machine is.
        for pair in HOTPLUG_CHAIN_OBJ.windows(2) {
            exec.device_set_parent(pair[1], pair[0])
                .map_err(|_| 209u32)?;
        }
    }
    let _ = kernel_space;

    // Say so before waiting, because the harness outside is watching for this
    // line and will not pull the device until it sees it.
    kprintln!(
        "hotplug: armed — holding the switch at {:02x}:{:02x}.{} and the {} functions behind it, awaiting removal",
        bdf.bus,
        bdf.device,
        bdf.function,
        HOTPLUG_CHAIN_OBJ.len() - 2
    );
    kcore::verdict::claims(&["hotplug.armed"]);

    // **Poll two things, and the second is the guest's half of hotplug.**
    //
    // A hot-pluggable slot does not simply lose its device. The port raises an
    // eject request and *waits*, because the software using the device is the
    // only thing that knows whether it is in the middle of something — so a
    // guest that never answers is a guest the device never leaves. Answering
    // is what this loop does that the machine cannot do for itself.
    //
    // The other half is watching config space, because acknowledging is a
    // request to de-energize the slot rather than an instruction: what makes
    // the device *gone* is that it stops answering, and only that is worth
    // acting on.
    let mut polls = 0u64;
    let mut answered = false;
    loop {
        match bridge.read(&config, bdf, 0) {
            Ok(0xffff_ffff) | Err(_) => break,
            Ok(_) => {}
        }
        // **At the root port, not at the switch.** A slot's registers belong to
        // the port the card is plugged into, and what is being ejected here is
        // the switch itself — so the port that raises the request is the one
        // above it. Answering at the switch would be asking the thing that is
        // leaving whether it may leave.
        if !answered
            && tessera_pci::eject_requested(&bridge, &config, root_port.bdf).unwrap_or(false)
        {
            tessera_pci::acknowledge_eject(&bridge, &mut config, root_port.bdf)
                .map_err(|_| 202u32)?;
            // Once, not every round: the status bits are cleared by the
            // acknowledgement, so a second pass would find nothing to answer
            // and a *third* request would be a different removal.
            answered = true;
        }
        polls += 1;
        if polls >= HOTPLUG_POLL_LIMIT {
            return Err(195);
        }
        core::hint::spin_loop();
    }
    if !answered {
        // The device left without the slot ever asking. Possible on a bus with
        // surprise removal, and not on this one — so it means the check was
        // watching the wrong port, and its acknowledgement proved nothing.
        return Err(203);
    }

    // **One call, naming the switch.** Nothing tells the kernel what was behind
    // it — the graph already knows, and that is the whole claim.
    let switch_obj = HOTPLUG_CHAIN_OBJ[1];
    let root_obj = HOTPLUG_CHAIN_OBJ[0];
    // SAFETY: transient raw access to the statics; single-threaded, every
    // thread off-CPU (none was ever started).
    let (holders, subtree, still_known, root_survived) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(196u32)?;
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let report = exec.remove_device(
            switch_obj,
            kcore::lifecycle::TransitionReason::Removed,
            processes,
            None,
            None,
        );
        if !report.existed {
            return Err(197);
        }
        (
            report.holders,
            report.subtree,
            HOTPLUG_CHAIN_OBJ[1..]
                .iter()
                .any(|object| exec.mmio_of_object(*object).is_some()),
            exec.mmio_of_object(root_obj).is_some(),
        )
    };
    // Three nodes: the switch, its downstream port, and the endpoint. Two would
    // mean the walk stopped one level short, which is precisely the defect a
    // flat graph has.
    if subtree != HOTPLUG_CHAIN_OBJ.len() - 1 {
        return Err(210);
    }
    // One process held all four, and the removal reached it once per node it
    // took. Counting holders rather than asserting a number keeps this honest
    // if the check ever grows a second holder.
    if holders != subtree {
        return Err(198);
    }
    if still_known {
        // The graph would still hand one of these out. Every device syscall
        // resolves through it, so a node left behind is a capability that goes
        // on working for hardware that is not there.
        return Err(199);
    }
    if !root_survived {
        // **The removal walked upward.** The root port is still in the machine
        // and still answering; taking it would be a subtree teardown that does
        // not know where the subtree ends, and no count of removed nodes would
        // have shown it.
        return Err(211);
    }
    // And the holder lost exactly the subtree, without having been consulted —
    // while keeping the one capability that names hardware still present.
    // SAFETY: as above.
    let (holds_removed, holds_root) = unsafe {
        let process = (*(&raw mut KCORE_PROCESSES))
            .get_mut(holder_index)
            .ok_or(200u32)?;
        (
            HOTPLUG_CHAIN_OBJ[1..]
                .iter()
                .any(|object| process.handles().holds(*object)),
            process.handles().holds(root_obj),
        )
    };
    if holds_removed {
        return Err(201);
    }
    if !holds_root {
        return Err(212);
    }

    Ok(RemovalOutcome {
        polls,
        holders,
        still_known,
        subtree,
    })
}

/// The object ids the queue-child check registers: the controller function, the
/// queue behind it, and the child process.
const MQ_CONTROLLER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x70);
const MQ_QUEUE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x71);
const MQ_CHILD_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x72);
/// The child's kernel-stack window.
const MQ_CHILD_KSTACK_VA: u64 = 0xffff_c000_0090_0000;
/// The startup argument that asks `blk-probe` to run as a queue child. Must
/// match `QUEUE_CHILD` there.
const BLK_PROBE_QUEUE_CHILD: usize = 1 << 62;
/// Where a queue child finds the rings of the queue it was given. Must match
/// `tessera_uabi::layout::QUEUE_RING_VA`, which the kernel cannot depend on:
/// `uabi` is built for the user targets, and this is the same agreement
/// `DEVICE_MMIO_VA` already is.
const QUEUE_RING_VA: u64 = 0x0000_1000_00b0_0000;

/// What the ring-3 child established.
struct QueueChildOutcome {
    /// The doorbell VA the child reported mapping — its own report, not the
    /// kernel's belief about it.
    reported: u64,
    /// Bytes the read the *child* published brought back.
    magic: u64,
    /// Pages of register window the child's process holds. One is the claim:
    /// a queue, and not the controller.
    window_pages: usize,
}

/// **A ring-3 child holds one queue and drives it.**
///
/// The half `pci_mq_check` cannot do: it proves the *hardware* separates
/// queues, and this proves the *system* hands one over. The child is started
/// holding a capability to the controller with `Rights::DERIVE` and nothing
/// else — it derives the queue itself (`DeviceChild`, D136/D137), maps that
/// queue's doorbell page, publishes a request the controller formed, and rings
/// its own doorbell.
///
/// **What it does not hold is the finding.** No capability to the controller's
/// register window, no mapping of queue 0, no channel to another process to
/// submit on its behalf — a transfer from here crosses no extra process
/// (`docs/drivers/01`, "Bus Topology And Data Paths"). The check reads the
/// child's register-window count back to say so as a number rather than as a
/// claim about what the code does.
///
/// The descriptors are the controller's, and deliberately: a chain names
/// buffers by their device-visible addresses, which a child has no way to know.
/// The child does the half that makes a request a request — the available-ring
/// index and the doorbell.
fn queue_child_check(
    outcome: &virtio::MqOutcome,
    high: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<QueueChildOutcome, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if blk_probe_elf().is_empty() {
        return Err(1);
    }
    // A second read, formed but not published — so what completes can only be
    // the child's doing.
    let status_phys = virtio::mq_arm_child_read(outcome, 1, frames).map_err(|e| 10 + e)?;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(20u32)?;
        // The controller: a node the child may derive from and must not map.
        // No `Rights::MAP` on it at all, so "the child never reached the
        // controller's registers" is enforced rather than observed.
        exec.device_register_mmio(MQ_CONTROLLER_OBJ, 0, 0, Rights::READ | Rights::DERIVE)
            .map_err(|_| 21u32)?;
        // The queue: one page, which is the doorbell and nothing else.
        exec.device_register_mmio(
            MQ_QUEUE_OBJ,
            outcome.q1_doorbell_phys,
            FRAME_SIZE,
            Rights::READ | Rights::MAP,
        )
        .map_err(|_| 22u32)?;
        exec.device_set_parent(MQ_QUEUE_OBJ, MQ_CONTROLLER_OBJ)
            .map_err(|_| 23u32)?;
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();

    let (child_idx, child_proc) = ring3_host_spawn(
        blk_probe_elf(),
        MQ_CHILD_KSTACK_VA,
        BLK_PROBE_QUEUE_CHILD,
        MQ_CHILD_OBJ,
        &mut kernel_space,
        frames,
        30,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let child = processes.get_mut(child_proc).ok_or(40u32)?;
        child
            .handles_mut()
            .install(MQ_CONTROLLER_OBJ, Rights::READ | Rights::DERIVE)
            .map_err(|_| 41u32)?;
        // Its queue's rings, mapped rather than allocated: this is memory the
        // *device* reads, placed by whoever brought the controller up, and the
        // child never learns its physical address because a descriptor names
        // buffers and not rings.
        let ring = PhysFrame::containing(tessera_karch::PhysAddr::new(outcome.q1_ring_phys));
        child
            .space_mut()
            .map_shared(
                VirtAddr::new(QUEUE_RING_VA),
                PageFlags::rw().user(),
                MQ_QUEUE_OBJ,
                0,
                &[ring],
                frames,
            )
            .map_err(|_| 42u32)?;
    }

    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    let reported = EL0_REPORTS[0].load(Ordering::SeqCst);
    let _ = child_idx;

    // The device must have served a request nobody in the kernel published.
    if !virtio::mq_poll_used(outcome.q1_used_phys, 2) {
        return Err(50);
    }
    // SAFETY: the status byte of the chain armed above, in a frame this boot
    // allocated and the device has just reported written.
    let ok = unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + status_phys) as *const u8) };
    if ok != 0 {
        return Err(51);
    }
    // SAFETY: the first word of the data frame the device filled.
    let magic =
        unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + outcome.data_phys) as *const u64) };
    // **A different sector than the controller read.** The landing zone was
    // zeroed before the child ran, so stale bytes could not survive — but every
    // sector of this image begins with the same four-byte tag, and a check that
    // compared only those would agree with a read of the wrong sector. This is
    // the one comparison that distinguishes "the child's request was served"
    // from "something was served".
    if magic == outcome.magic {
        return Err(53);
    }

    // SAFETY: transient raw access to the static process table.
    let window_pages = unsafe {
        (*(&raw mut KCORE_PROCESSES))
            .get_mut(child_proc)
            .ok_or(52u32)?
            .device_window_count()
    };

    // **Tear the child down before returning.** The process table is shared
    // across every check in this boot, and a leftover process is not inert: it
    // still owns a thread index and a handle table, so the next check's driver
    // is inserted beside a corpse and its crash ladder counts the wrong
    // incarnations. That is how this first failed — three checks further on,
    // with a message about a driver that would not die.
    //
    // The ring page is deliberately *not* freed with it: it is the queue's, the
    // device still has its address, and it was mapped here rather than
    // allocated here.
    // SAFETY: transient raw access; the process is removed and torn down once.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(child_proc) {
            process.space_mut().teardown(frames);
        }
    }
    // SAFETY: the run is over; clear what was published for it.
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }
    Ok(QueueChildOutcome {
        reported,
        magic,
        window_pages,
    })
}

// --- Power vote arbitration: three voters and a service that weighs them (D140) ---

/// Kernel objects this check creates. Local to its own Executive, which every
/// check builds fresh.
const POWER_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x80);
const POWER_SERVICE_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x81);
/// The manager's endpoint objects, in voter order. **Must match
/// `VOTER_ENDPOINT_OBJECTS` in `userspace/power-manager`**: a port event names
/// the object that was signalled, and a handle table is per-process, so boot
/// and the manager have to agree on the numbering. The same bootstrap
/// agreement `device-host` has for its two client endpoints.
const POWER_SERVER_OBJS: [u32; 3] = [70, 71, 72];
const POWER_CLIENT_OBJS: [u32; 3] = [73, 74, 75];
const POWER_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x90);
const POWER_VOTER_PROC_OBJS: [u32; 3] = [0x91, 0x92, 0x93];

const POWER_MANAGER_KSTACK_VA: u64 = 0xffff_0003_0000_0000;
const POWER_VOTER_KSTACK_VAS: [u64; 3] = [
    0xffff_0003_1000_0000,
    0xffff_0003_2000_0000,
    0xffff_0003_3000_0000,
];

/// Voter-mode bit in the power manager's startup argument. Must match
/// `VOTER_MODE` there.
const POWER_VOTER_MODE: usize = 1 << 63;

/// The startup argument for a voter: which level it asks for, what kind of
/// voter it is, and which report slot rotation it uses.
const fn power_voter_arg(level: u64, class: u64, step: u64) -> usize {
    (POWER_VOTER_MODE as u64 | level | (class << 8) | (step << 16)) as usize
}

/// One voter's expected report, packed the way `resolution_word` packs it.
const fn power_vote_word(step: u32, resolved: u64, from: u64, by: u64, winner: u64) -> u64 {
    (resolved | (from << 8) | (by << 16) | (winner << 24)).rotate_left(8 * step)
}

/// The three votes, in the order they are cast, and what each must be told.
///
/// **The middle two rows are the negative check, and they are in-line rather
/// than in a second boot.** Step 2's reply is `FULL_ACTIVE` with nothing
/// clamped; step 3's is `RETENTION` with `clamped_from = FULL_ACTIVE` and
/// `clamped_by = THERMAL`. Same voters, same domain, same manager — one extra
/// message. That is stronger evidence that the ceiling did something than a
/// separate run with the thermal voter deleted would be, because nothing else
/// about the machine differs between the two lines.
const POWER_STEP_1: u64 = power_vote_word(1, 2, 0, 0, 1);
const POWER_STEP_2: u64 = power_vote_word(2, 4, 0, 0, 2);
const POWER_STEP_3: u64 = power_vote_word(3, 2, 4, 4, 2);
/// The manager's own report: three requests served, the domain left at
/// `RETENTION`, and the device not in service.
const POWER_MANAGER_WORD: u64 = (3u64 | (2u64 << 8)).rotate_left(40);

/// What the run must produce.
struct PowerOutcome {
    /// The three replies, as the voters saw them.
    replies: [u64; 3],
    /// The lifecycle state the kernel has recorded for the device afterwards.
    device_state: kcore::lifecycle::DriverState,
}

/// Proves the first thing in this system that **arbitrates**: three processes
/// vote on one power domain and a service weighs them.
///
/// Every contract here has declared power states and resume latencies since
/// D128, and nothing weighed one voter's requirement against another's — a
/// test client sent `SetPower(IDLE)` and then `SetPower(ACTIVE)` because the
/// two lines were next to each other in a transcript, which is a device
/// changing state rather than a system deciding it should.
///
/// The three voters run one at a time, and that is what makes the transcript a
/// sequence rather than a race: each is spawned, runs to its exit, and only
/// then is the next spawned. The manager stays parked on its port between
/// them, which is also the point — it is a resident service, not a script.
fn power_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<PowerOutcome, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if power_manager_elf().is_empty() {
        return Err(1);
    }

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // The device the manager arbitrates *about*, and a node with **no
        // register window at all** — base and length zero, the same shape the
        // queue-child check's controller has. Narrating a lifecycle requires
        // `Rights::MAP` (D128: the same authority `MapDevice` and
        // `IrqComplete` need, so a process that has merely heard of a device
        // cannot tell its story), so the manager is granted it — and there is
        // still nothing behind it to reach. What the manager can do to this
        // device is say what state it is in; what it cannot do is touch it.
        exec.device_register_mmio(POWER_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
            .map_err(|_| 11u32)?;
        // Boot brings the device up to service the way a device manager would
        // have. Binding is not the power manager's business, and a lifecycle
        // that opened at `Suspending` would be a history nobody lived.
        for (from, to, reason) in [
            (
                DriverState::Discovered,
                DriverState::Matched,
                TransitionReason::Bound,
            ),
            (
                DriverState::Matched,
                DriverState::Starting,
                TransitionReason::Launched,
            ),
            (
                DriverState::Starting,
                DriverState::Probing,
                TransitionReason::Launched,
            ),
            (
                DriverState::Probing,
                DriverState::Active,
                TransitionReason::ProbeSucceeded,
            ),
        ] {
            exec.declare_lifecycle(POWER_DEVICE_OBJ, from, to, reason, 0)
                .map_err(|_| 12u32)?;
        }

        // One channel per voter, and one service port bound to every
        // server-side endpoint: a message on any of them raises
        // `SIGNAL_MESSAGE` on that endpoint's object, so the manager's single
        // `PortWait` is a select that names who spoke. A manager receiving on
        // one endpoint at a time would deadlock the moment a different voter
        // called first.
        let port = exec.port_create().map_err(|_| 13u32)?;
        exec.bind_port_object(port, POWER_SERVICE_PORT_OBJ);
        for index in 0..POWER_SERVER_OBJS.len() {
            let (server, client) = exec.channel_create().map_err(|_| 14u32)?;
            let server_obj = kcore::object::ObjectId::from_raw(POWER_SERVER_OBJS[index]);
            exec.bind_endpoint_object(server, server_obj);
            exec.bind_endpoint_object(
                client,
                kcore::object::ObjectId::from_raw(POWER_CLIENT_OBJS[index]),
            );
            exec.port_bind(
                port,
                u64::from(server_obj.raw()),
                kcore::ipc::SIGNAL_MESSAGE,
            )
            .map_err(|_| 15u32)?;
        }
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();

    // The manager spawns first and parks on its port before anybody calls —
    // the server-first pattern every check here uses.
    let (_manager_idx, manager_proc) = ring3_host_spawn(
        power_manager_elf(),
        POWER_MANAGER_KSTACK_VA,
        // Manager mode: the argument is how many requests to serve. A resident
        // service has no opinion about how long it should live, so the
        // stopping condition is boot's rather than the program's.
        POWER_SERVER_OBJS.len(),
        POWER_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(30u32)?;
        manager
            .handles_mut()
            .install(POWER_SERVICE_PORT_OBJ, Rights::READ)
            .map_err(|_| 31u32)?;
        for object in POWER_SERVER_OBJS {
            manager
                .handles_mut()
                .install(kcore::object::ObjectId::from_raw(object), Rights::READ)
                .map_err(|_| 32u32)?;
        }
        manager
            .handles_mut()
            .install(POWER_DEVICE_OBJ, Rights::READ | Rights::MAP)
            .map_err(|_| 33u32)?;
    }

    // The three voters: a driver asking for what it needs to serve, a user
    // asking for more, and a thermal zone taking it away. Levels and classes
    // are `power_manager.isl`'s.
    const DRIVER_VOTE: usize = power_voter_arg(2, 3, 1);
    const USER_VOTE: usize = power_voter_arg(4, 1, 2);
    const THERMAL_VOTE: usize = power_voter_arg(2, 4, 3);

    let mut voter_procs = [0usize; 3];
    for (index, arg) in [DRIVER_VOTE, USER_VOTE, THERMAL_VOTE]
        .into_iter()
        .enumerate()
    {
        let (_idx, proc_idx) = ring3_host_spawn(
            power_manager_elf(),
            POWER_VOTER_KSTACK_VAS[index],
            arg,
            kcore::object::ObjectId::from_raw(POWER_VOTER_PROC_OBJS[index]),
            &mut kernel_space,
            frames,
            40 + 10 * index as u32,
        )?;
        voter_procs[index] = proc_idx;
        // SAFETY: transient raw access to the static process table.
        unsafe {
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            let voter = processes.get_mut(proc_idx).ok_or(80u32)?;
            voter
                .handles_mut()
                .install(
                    kcore::object::ObjectId::from_raw(POWER_CLIENT_OBJS[index]),
                    Rights::WRITE,
                )
                .map_err(|_| 81u32)?;
        }
        // Run to a standstill before the next voter is spawned. That is what
        // makes the transcript a sequence: three concurrent voters would
        // resolve to the same final level but in an order nobody could
        // predict, and the intermediate replies are exactly what is being
        // checked.
        // SAFETY: transient raw access; `run` returns when nothing is runnable.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
    }

    // **Put the boot low half back before anything else.** A run leaves
    // `TTBR0` holding the last process's space, and this check then frees that
    // space — after which the live translation tables are frames the allocator
    // has handed to somebody else. Nothing fails at the moment it happens;
    // what fails is the next thing to touch a low address, which on this port
    // is the interrupt controller, in a check further down the boot.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // Four reports: one per voter, then the manager's when it stops.
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 4 {
        return Err(90);
    }
    let mut replies = [
        EL0_REPORTS[0].load(Ordering::SeqCst),
        EL0_REPORTS[1].load(Ordering::SeqCst),
        EL0_REPORTS[2].load(Ordering::SeqCst),
    ];
    if replies[0] != POWER_STEP_1 {
        return Err(91);
    }
    if replies[1] != POWER_STEP_2 {
        return Err(92);
    }
    // The third voter and the manager both become runnable on the same reply,
    // so which of them reports first is the scheduler's business and not this
    // check's. Both values are required, in either order — the alternative
    // would be a check that passes or fails on a detail neither program
    // controls. Matched as a pair rather than folded together, so that one
    // report cannot stand in for the other.
    let tail = [replies[2], EL0_REPORTS[3].load(Ordering::SeqCst)];
    let thermal_reply = if tail == [POWER_STEP_3, POWER_MANAGER_WORD] {
        tail[0]
    } else if tail == [POWER_MANAGER_WORD, POWER_STEP_3] {
        tail[1]
    } else {
        return Err(93);
    };

    replies[2] = thermal_reply;

    // **The resolution happened to a device.** The manager drove it through
    // the states a power transition is defined to pass through; the kernel
    // refused none of them and has the state to prove it.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let device_state = unsafe { (*(&raw const KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.lifecycle_of_object(POWER_DEVICE_OBJ))
        .ok_or(94u32)?;
    if device_state != DriverState::Suspended {
        return Err(95);
    }

    // **And it moved three times, not once.** The final state alone would not
    // say so — but the kernel's edge table does: had the manager failed to
    // resume the device after step 2, step 3's `Active -> Suspending` would
    // have been declared from `Suspended`, which is refused, and the manager
    // would have reported a failure instead of its summary. The transcript is
    // enforced rather than counted.

    // Tear every process down before returning. The process table is shared
    // across every check in this boot, and a leftover process still owns a
    // thread index and a handle table — which is how a later check ends up
    // counting the wrong incarnations (D139).
    // SAFETY: transient raw access; every thread is off-CPU.
    unsafe {
        for proc_idx in voter_procs
            .into_iter()
            .chain(core::iter::once(manager_proc))
        {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                process.space_mut().teardown(frames);
            }
        }
    }
    // SAFETY: the run is over; clear what was published for it.
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    Ok(PowerOutcome {
        replies,
        device_state,
    })
}

// --- Runtime idle and a real wake source: the PL031 RTC (D141) ---

/// The `virt` machine's real-time clock. Chosen as this port's wakeup source
/// for the reason D104 chose the goldfish RTC on RISC-V: it is **real, on its
/// own interrupt line, and owned by no driver**. A virtio device only
/// interrupts for a request somebody made, so using one would mean idling with
/// work outstanding — which is not what runtime idle is, and would make the
/// proof describe a situation the policy would never create.
const PL031_COMPATIBLE: &[u8] = b"arm,pl031";
/// Register offsets. The counter, the match register the alarm compares
/// against, the interrupt mask, the masked status, and the write-one-to-clear.
const PL031_DR: u64 = 0x00;
const PL031_MR: u64 = 0x04;
const PL031_IMSC: u64 = 0x10;
const PL031_MIS: u64 = 0x18;
const PL031_ICR: u64 = 0x1c;

/// The RTC's registers, through the high-half mapping [`map_wake_source`]
/// makes.
///
/// The high half rather than the low-half device identity map, and that is
/// forced: the low half is `TTBR0`, which a running EL0 process owns, so an
/// address that worked before a process ran would be that process's memory
/// afterwards. `map_pci_windows` maps its windows high for the same reason.
struct Pl031 {
    base: u64,
}

impl Pl031 {
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: `base` is the RTC's register page, mapped Device-nGnRnE at
        // `DIRECT_MAP_BASE + phys` before this is built, and `offset` is a
        // defined 4-byte-aligned register inside the first 0x20 bytes of it.
        unsafe { tessera_karch_aarch64::mmio_read32((self.base + offset) as usize) }
    }

    fn write(&self, offset: u64, value: u32) {
        // SAFETY: as `read`; nothing else on this machine touches the RTC.
        unsafe {
            tessera_karch_aarch64::mmio_write32((self.base + offset) as usize, value);
        }
    }

    /// Sets the alarm `seconds` from now and unmasks its interrupt.
    ///
    /// The PL031 counts at 1 Hz, so one second is the shortest alarm this
    /// device can express. That is slow for a boot check and it is the price
    /// of the source being real — a faster wake would have to come from a
    /// device somebody owns, which is the thing this deliberately avoids.
    fn arm_alarm(&self, seconds: u32) {
        self.write(PL031_ICR, 1);
        let now = self.read(PL031_DR);
        self.write(PL031_MR, now.wrapping_add(seconds));
        self.write(PL031_IMSC, 1);
    }

    /// Whether the alarm has fired and not yet been acknowledged.
    fn fired(&self) -> bool {
        self.read(PL031_MIS) & 1 != 0
    }

    /// Acknowledges the alarm and masks the line.
    fn disarm(&self) {
        self.write(PL031_IMSC, 0);
        self.write(PL031_ICR, 1);
    }
}

/// Maps the RTC's register page into the high half and answers its VA.
fn map_wake_source(
    space: &mut KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    phys: u64,
) -> Result<u64, tessera_karch::KError> {
    const BLOCK: u64 = 2 * 1024 * 1024;
    let block = phys & !(BLOCK - 1);
    space.map_block_range(
        DIRECT_MAP_BASE + block,
        block,
        BLOCK,
        PageFlags::rw().global().device(),
        frames,
    )?;
    Ok(DIRECT_MAP_BASE + phys)
}

/// The wakeup source's INTID while [`wake_check`] runs (0 = none), on the same
/// enable-only-around-the-run discipline every other bridge here uses.
static POWER_WAKE_INTID: AtomicU32 = AtomicU32::new(0);

/// The wakeup-source bridge: mask the line, **count the wake**, then signal
/// the port.
///
/// The order is the whole point. A wake that is delivered but not counted is
/// exactly the lost wakeup the counter exists to close — delivery can wake a
/// process which then races a suspend entry, while counting first means the
/// number has already moved by the time anything can observe the event at all.
///
/// Masking before either is the storm rule every level-triggered source here
/// obeys: the trap path EOIs unconditionally, and the PL031 keeps its line
/// asserted until its status register is cleared.
fn wake_irq_hook(id: u32) -> bool {
    let wired = POWER_WAKE_INTID.load(Ordering::SeqCst);
    if wired == 0 || id != wired {
        return false;
    }
    // SAFETY: masking a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(id) };
    // SAFETY: as `virtio_irq_hook` — exception entry sets PSTATE.I, so this
    // can only have preempted EL0 or boot code outside the enable window, and
    // never a live Executive borrow.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.record_wake(id);
            exec.port_signal(id as u64, 1, 1);
        }
    }
    true
}

/// Kernel objects [`wake_check`] creates.
const WAKE_RTC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa0);
const WAKE_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa1);
/// The capability the power manager holds to say the machine must not sleep.
///
/// **Not a device and not, yet, an object class of its own.** What the kernel
/// checks when a hold is taken is the *right*, and the hold is attributed to
/// the calling process — so this handle is the gate rather than the subject. A
/// Power object with a table entry would give the gate something to be about;
/// the suspend commit will need one, and inventing it before then would be an
/// object nobody reads.
const WAKE_POWER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa2);
const WAKE_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa3);
const WAKE_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xa4);
const WAKE_MANAGER_KSTACK_VA: u64 = 0xffff_0003_4000_0000;

/// The startup argument that asks the power manager to run its idle-and-wake
/// mode. Must match `WAKE_MODE` there.
const POWER_MANAGER_WAKE_MODE: usize = 1 << 62;

/// What the manager must report: one wake counted, the grace hold seen, the
/// domain idled, the capability without `Rights::WAKE` refused, and the device
/// back in service. One byte each, so a failure names which of the five went
/// wrong rather than only that something did.
const WAKE_EXPECTED: u64 = 1 | (1 << 8) | (1 << 16) | (1 << 24) | (1 << 32);

/// What the run must produce.
struct WakeOutcome {
    /// The manager's packed report.
    reported: u64,
    /// The system wake-event counter afterwards.
    events: u64,
    /// The lifecycle state the kernel has recorded for the idled device.
    device_state: kcore::lifecycle::DriverState,
    /// Whether the RTC is still armed as a wakeup source.
    still_armed: bool,
}

/// Proves runtime idle and the wake capability: a domain nobody is using drops
/// out of service, and a **real interrupt the kernel counted** brings it back.
///
/// D140 built something that arbitrates. What it could not do is let a domain
/// that had fallen to the floor come back on its own — there was nothing that
/// could wake a machine which had stopped, and no way to say which things were
/// allowed to.
///
/// The power manager here touches no register. It holds three capabilities —
/// the RTC with `Rights::WAKE`, a port, and the device whose lifecycle it
/// narrates — and boot owns the RTC itself, arms its alarm, and clears it
/// afterwards. That split is the design rather than a convenience: registering
/// a wakeup source is the manager's business and driving a clock is not.
fn wake_check(
    rtc: &tessera_devicetree::MmioDevice,
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<WakeOutcome, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    if power_manager_elf().is_empty() {
        return Err(1);
    }
    // A wakeup source with no interrupt is not a wakeup source. The device
    // tree is where that is settled, and a missing line is a fatal
    // misconfiguration rather than a silent downgrade to polling (D84).
    let intid = rtc.intid.ok_or(2u32)?;

    // SAFETY: `high` is the active kernel high-half; the alias maps the RTC
    // page and the manager's kernel stack and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let rtc_va = {
        // SAFETY: the same alias, used only to add a Device mapping for a page
        // nothing else in the high half covers.
        let mut arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
        map_wake_source(&mut arch, frames, rtc.base).map_err(|_| 3u32)?
    };
    let clock = Pl031 { base: rtc_va };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // The RTC as a graph node. `WAKE` is on the node's own rights because
        // that is what a kernel-originated hand-out of it carries; a device
        // nobody said may wake this machine could not be armed however it were
        // granted.
        exec.device_register_mmio(
            WAKE_RTC_OBJ,
            rtc.base,
            FRAME_SIZE,
            Rights::READ | Rights::WAKE,
        )
        .map_err(|_| 11u32)?;
        exec.device_set_mmio_irq(WAKE_RTC_OBJ, intid)
            .map_err(|_| 12u32)?;
        // The device that idles: windowless, as in D140, so the capability
        // carries the authority to narrate a lifecycle and nothing else.
        exec.device_register_mmio(WAKE_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
            .map_err(|_| 13u32)?;
        for (from, to, reason) in [
            (
                DriverState::Discovered,
                DriverState::Matched,
                TransitionReason::Bound,
            ),
            (
                DriverState::Matched,
                DriverState::Starting,
                TransitionReason::Launched,
            ),
            (
                DriverState::Starting,
                DriverState::Probing,
                TransitionReason::Launched,
            ),
            (
                DriverState::Probing,
                DriverState::Active,
                TransitionReason::ProbeSucceeded,
            ),
        ] {
            exec.declare_lifecycle(WAKE_DEVICE_OBJ, from, to, reason, 0)
                .map_err(|_| 14u32)?;
        }
        // The route: the RTC's line, delivered to a port the manager holds.
        // Through the graph rather than as a bare port binding, so the wake
        // capability follows the device the way a register window and a DMA
        // lease already do.
        let port = exec.port_create().map_err(|_| 15u32)?;
        exec.bind_port_object(port, WAKE_PORT_OBJ);
        exec.device_route_irq(WAKE_RTC_OBJ, port, WAKE_MANAGER_PROC_OBJ)
            .map_err(|_| 16u32)?;
    }

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);

    let (_manager_idx, manager_proc) = ring3_host_spawn(
        power_manager_elf(),
        WAKE_MANAGER_KSTACK_VA,
        POWER_MANAGER_WAKE_MODE,
        WAKE_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(30u32)?;
        let mut install = |object, rights| {
            manager
                .handles_mut()
                .install(object, rights)
                .map(|_| ())
                .map_err(|_| 31u32)
        };
        install(WAKE_PORT_OBJ, Rights::READ)?;
        install(WAKE_RTC_OBJ, Rights::READ | Rights::WAKE)?;
        install(WAKE_POWER_OBJ, Rights::READ | Rights::WAKE)?;
        install(WAKE_DEVICE_OBJ, Rights::READ | Rights::MAP)?;
        // **The same device, without `WAKE`.** The negative check is a handle
        // rather than a second boot: one capability can arm this line and the
        // other cannot, and the only difference between them is the right.
        install(WAKE_RTC_OBJ, Rights::READ)?;
    }

    // Arm the alarm and let the line through, strictly around the run.
    clock.arm_alarm(1);
    POWER_WAKE_INTID.store(intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);

    // The interrupt pump (D84/D85): the manager parks on its port with nothing
    // else runnable, so `run` returns and the wake would be orphaned without a
    // boot context that waits for it. Unmasking every iteration is required —
    // `wfi` returns from a pending-but-masked interrupt without ever taking
    // it, and returning from a thread switch restores the boot context with
    // IRQs masked again.
    let mut pump_budget = 600u32;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable
        // (a parked thread may become Ready from interrupt context).
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if EL0_SINK_EXITED.load(Ordering::SeqCst) || pump_budget == 0 {
            break;
        }
        pump_budget -= 1;
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches the port facility and the
        // wake counter, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();
    // **Put the boot low half back before anything else.** A run that ends
    // with a thread merely *parked* rather than exited leaves `TTBR0` holding
    // that process's space, so the console's identity mapping — and every
    // other device register the low half carries — is simply not there. Every
    // check that can end that way does this; the ones that cannot get away
    // without it, which is why it is easy to forget and expensive to debug.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    POWER_WAKE_INTID.store(0, Ordering::SeqCst);
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(intid) };
    clock.disarm();

    let reported = EL0_REPORTS[0].load(Ordering::SeqCst);
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(40);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(41);
    }
    if reported != WAKE_EXPECTED {
        return Err(44);
    }

    // SAFETY: transient raw access; every thread is off-CPU by here.
    let (events, device_state, still_armed) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(42u32)?;
        (
            exec.wake_events(),
            exec.lifecycle_of_object(WAKE_DEVICE_OBJ).ok_or(43u32)?,
            exec.is_wake_source(WAKE_RTC_OBJ),
        )
    };

    // Tear the manager down before returning: the process table is shared
    // across every check in this boot, and a leftover process still owns a
    // thread index and a handle table (D139).
    // SAFETY: transient raw access; every thread is off-CPU.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(manager_proc) {
            process.space_mut().teardown(frames);
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    // The kernel's own answers, independent of what the manager said about
    // itself: exactly one wake was counted, the device is back in service, and
    // nothing is left able to wake this machine.
    if events != 1 {
        return Err(45);
    }
    if device_state != DriverState::Active {
        return Err(46);
    }
    if still_armed {
        return Err(47);
    }

    Ok(WakeOutcome {
        reported,
        events,
        device_state,
        still_armed,
    })
}

// --- System suspend and resume, ordered by the device tree (D142) ---

/// Kernel objects [`suspend_check`] creates. The bus and the device behind it
/// are graph nodes with a real parent edge — the same edge `pcie_enumerate`
/// records for a function behind a bridge — and the manager is handed only the
/// bus, so it has to walk the graph to find the rest.
const SUSPEND_BUS_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb0);
const SUSPEND_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb1);
const SUSPEND_RTC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb2);
const SUSPEND_POWER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb3);
const SUSPEND_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb4);
const SUSPEND_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xb5);
const SUSPEND_MANAGER_KSTACK_VA: u64 = 0xffff_0003_5000_0000;

/// The startup argument that asks the power manager to suspend the machine.
/// Must match `SUSPEND_MODE` there.
const POWER_MANAGER_SUSPEND_MODE: usize = 1 << 61;

/// What the manager must report: the wrong-order suspend refused, the
/// wrong-order resume refused, the commit resumed (1) naming a source, the
/// stale snapshot aborted as a wake having arrived (2), the held machine
/// refusing to stop (3), and both devices back in service. One byte each, so a
/// failure names which of the seven went wrong.
const SUSPEND_EXPECTED: u64 =
    1 | (1 << 8) | (1 << 16) | (1 << 24) | (2u64 << 32) | (3u64 << 40) | (1u64 << 48);

/// What the run must produce.
struct SuspendOutcomeReport {
    /// The manager's packed report.
    reported: u64,
    /// The lifecycle states the kernel has recorded afterwards.
    bus_state: kcore::lifecycle::DriverState,
    device_state: kcore::lifecycle::DriverState,
    /// The system wake-event counter.
    events: u64,
}

/// Proves that the whole machine stops and starts again, ordered by Phase 2's
/// dependency graph and committed by the kernel.
///
/// Three things are being shown, and the first is the one that could not have
/// been shown before this phase. **The ordering is enforced**: the manager
/// asks to suspend the bus while the device behind it is still serving, and
/// the kernel refuses — so leaves-before-parents is a property of the machine
/// rather than of whichever loop happens to be walking the tree. The mirror is
/// asked too, because resume runs parent-first and that is the half a manager
/// is most likely to get wrong.
///
/// **The commit is the kernel's.** The manager snapshots the wake-event
/// counter, calls `SystemSuspend`, and does not run again until something
/// wakes the machine — which here is a real alarm on a device nobody owns.
/// Nothing else is runnable while it sleeps, so the CPU reaches its idle loop,
/// which *is* suspend-to-idle.
///
/// **And it refuses when it should.** The same snapshot presented a second
/// time no longer matches, because the wake that ended the sleep moved the
/// counter — a real stale snapshot rather than a fabricated number. A wake
/// hold then refuses a commit whose snapshot is perfectly fresh.
fn suspend_check(
    rtc: &tessera_devicetree::MmioDevice,
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<SuspendOutcomeReport, u32> {
    use kcore::lifecycle::{DriverState, TransitionReason};
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    if power_manager_elf().is_empty() {
        return Err(1);
    }
    let intid = rtc.intid.ok_or(2u32)?;

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);
    let rtc_va = {
        // SAFETY: the same alias, adding a Device mapping for the RTC page.
        // Idempotent: `wake_check` has already made it, and mapping the same
        // block again over the same output is not a change.
        let mut arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
        map_wake_source(&mut arch, frames, rtc.base).unwrap_or(DIRECT_MAP_BASE + rtc.base)
    };
    let clock = Pl031 { base: rtc_va };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // The bus, and the device behind it. Windowless: what is being tested
        // is the tree, and giving these register windows would add a thing to
        // get wrong that has nothing to do with ordering. `DERIVE` on the bus
        // is what lets the manager find the device without being told.
        exec.device_register_mmio(
            SUSPEND_BUS_OBJ,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::DERIVE,
        )
        .map_err(|_| 11u32)?;
        exec.device_register_mmio(SUSPEND_DEVICE_OBJ, 0, 0, Rights::READ | Rights::MAP)
            .map_err(|_| 12u32)?;
        exec.device_set_parent(SUSPEND_DEVICE_OBJ, SUSPEND_BUS_OBJ)
            .map_err(|_| 13u32)?;
        exec.device_register_mmio(
            SUSPEND_RTC_OBJ,
            rtc.base,
            FRAME_SIZE,
            Rights::READ | Rights::WAKE,
        )
        .map_err(|_| 14u32)?;
        exec.device_set_mmio_irq(SUSPEND_RTC_OBJ, intid)
            .map_err(|_| 15u32)?;

        for device in [SUSPEND_BUS_OBJ, SUSPEND_DEVICE_OBJ] {
            for (from, to, reason) in [
                (
                    DriverState::Discovered,
                    DriverState::Matched,
                    TransitionReason::Bound,
                ),
                (
                    DriverState::Matched,
                    DriverState::Starting,
                    TransitionReason::Launched,
                ),
                (
                    DriverState::Starting,
                    DriverState::Probing,
                    TransitionReason::Launched,
                ),
                (
                    DriverState::Probing,
                    DriverState::Active,
                    TransitionReason::ProbeSucceeded,
                ),
            ] {
                exec.declare_lifecycle(device, from, to, reason, 0)
                    .map_err(|_| 16u32)?;
            }
        }

        let port = exec.port_create().map_err(|_| 17u32)?;
        exec.bind_port_object(port, SUSPEND_PORT_OBJ);
        exec.device_route_irq(SUSPEND_RTC_OBJ, port, SUSPEND_MANAGER_PROC_OBJ)
            .map_err(|_| 18u32)?;
    }

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);

    let (_manager_idx, manager_proc) = ring3_host_spawn(
        power_manager_elf(),
        SUSPEND_MANAGER_KSTACK_VA,
        POWER_MANAGER_SUSPEND_MODE,
        SUSPEND_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        20,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(30u32)?;
        let mut install = |object, rights| {
            manager
                .handles_mut()
                .install(object, rights)
                .map(|_| ())
                .map_err(|_| 31u32)
        };
        install(SUSPEND_PORT_OBJ, Rights::READ)?;
        install(SUSPEND_RTC_OBJ, Rights::READ | Rights::WAKE)?;
        // Both power rights on one capability, which is a fact about this one
        // service rather than a property of the bits: saying what may wake the
        // machine and stopping it are separate authorities, and the kernel
        // checks them separately.
        install(
            SUSPEND_POWER_OBJ,
            Rights::READ | Rights::WAKE | Rights::SLEEP,
        )?;
        // **The bus, and nothing else.** What is behind it the manager finds
        // by asking the graph, which is the same graph the ordering is
        // enforced against.
        install(SUSPEND_BUS_OBJ, Rights::READ | Rights::MAP | Rights::DERIVE)?;
    }

    // The alarm has to fire *after* the manager reaches its commit, or the
    // wake it is waiting for will already have happened — which the snapshot
    // comparison would correctly refuse, proving the abort rather than the
    // sleep. One second is the shortest this device can express and the
    // manager reaches the commit in microseconds.
    clock.arm_alarm(1);
    POWER_WAKE_INTID.store(intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);

    let mut pump_budget = 600u32;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable
        // — which during the commit is the machine being asleep.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.scheduler().run();
            }
        }
        if EL0_SINK_EXITED.load(Ordering::SeqCst) || pump_budget == 0 {
            break;
        }
        pump_budget -= 1;
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches the port facility and the
        // wake counter, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    POWER_WAKE_INTID.store(0, Ordering::SeqCst);
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(intid) };
    clock.disarm();

    let reported = EL0_REPORTS[0].load(Ordering::SeqCst);
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 1 {
        return Err(40);
    }
    if !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(41);
    }
    if reported != SUSPEND_EXPECTED {
        return Err(42);
    }

    // SAFETY: transient raw access; every thread is off-CPU by here.
    let (bus_state, device_state, events) = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(43u32)?;
        (
            exec.lifecycle_of_object(SUSPEND_BUS_OBJ).ok_or(44u32)?,
            exec.lifecycle_of_object(SUSPEND_DEVICE_OBJ).ok_or(45u32)?,
            exec.wake_events(),
        )
    };
    // The kernel's own answers: both nodes back in service, and exactly one
    // wake — the one that ended the sleep. A second would mean the two aborts
    // had been ended by something rather than refused.
    if bus_state != DriverState::Active || device_state != DriverState::Active {
        return Err(46);
    }
    if events != 1 {
        return Err(47);
    }

    // SAFETY: transient raw access; every thread is off-CPU.
    unsafe {
        if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(manager_proc) {
            process.space_mut().teardown(frames);
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    Ok(SuspendOutcomeReport {
        reported,
        bus_state,
        device_state,
        events,
    })
}

// --- The relay path, and what it costs (D143) ---

/// The chain [`relay_check`] builds. Two relaying hubs the manifest describes,
/// one it does not, and the devices behind each.
///
/// Graph nodes rather than enumerated hardware, and for the reason D142 built
/// its bus the same way: no reference machine has a relaying hub on it. What is
/// under test is the arithmetic over a parent chain, and these carry the same
/// parent edge `pcie_enumerate` records for a function behind a bridge — the
/// edge the manager walks is the real one either way.
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

const RELAY_MANAGER_KSTACK_VA: u64 = 0xffff_0003_6000_0000;
const RELAY_PROBE_KSTACK_VA: u64 = 0xffff_0003_7000_0000;
const RELAY_MANAGER_2_KSTACK_VA: u64 = 0xffff_0003_8000_0000;
const RELAY_PROBE_2_KSTACK_VA: u64 = 0xffff_0003_9000_0000;

/// The startup argument asking `blk-probe` to report what its path costs over
/// three binds. Must match `RELAY_REPORT` there.
const BLK_PROBE_RELAY_REPORT: usize = 1 << 61;

/// PCI class codes, as the graph records them: class in bits 23:16.
const RELAY_CLASS_BRIDGE: u32 = 0x06_04_00;
const RELAY_CLASS_STORAGE: u32 = 0x01_08_00;
const RELAY_CLASS_NETWORK: u32 = 0x02_00_00;
const RELAY_VIRTIO_VENDOR: u16 = 0x1af4;
const RELAY_REDHAT_VENDOR: u16 = 0x1b36;

/// The costs `userspace/device-manager`'s manifest declares for these two hubs,
/// and the budget its block entry sets.
///
/// **Restated here, not shared.** The manifest is the manager's policy and this
/// is the check's expectation; a single constant would make the check agree
/// with the manager by construction and prove nothing about whether the
/// manager applied it.
const RELAY_NEAR_COST_US: u64 = 10;
const RELAY_NEAR_THROUGHPUT_MBPS: u64 = 1000;
const RELAY_FAR_COST_US: u64 = 25;
const BLOCK_PATH_BUDGET_US: u64 = 30;

/// What the three binds must answer.
///
/// The near device binds: status 0, one hop, its declared cost, its declared
/// throughput. The far one is refused `BudgetExceeded` (8) and the network
/// device `ThroughputTooLow` (9). Every number is one the manifest declared —
/// a hop count of two, or the far hub's cost showing up on the near device,
/// would mean the manager had accumulated something other than the path it
/// walked.
const RELAY_EXPECTED: u64 = (1 << 8)
    | (RELAY_NEAR_COST_US << 16)
    | (8u64 << 32)
    | (9u64 << 40)
    | (RELAY_NEAR_THROUGHPUT_MBPS << 48);

/// What the same three binds must answer behind the hub nothing describes.
///
/// The one device there is refused `PathUndeclared` (10) — twice, because a
/// refused device stays held and the second request is about the same one — and
/// there is no network device at all, which is `NoMatch` (1). No hops, no
/// latency and no throughput are reported, because nothing was bound.
///
/// It is deliberately the *same* probe mode as the described chain. A mode that
/// went on to drive whatever it was given would, if this hub ever became
/// declared, fail by wandering off into a windowless device rather than by
/// reporting a different number — and a negative check that fails for an
/// incidental reason is not evidence about the thing under test.
const RELAY_UNDECLARED_EXPECTED: u64 = 10 | (10u64 << 32) | (1u64 << 40);

/// One spawned program: its scheduler thread and its process, both of which
/// have to be released and which are not the same index.
#[derive(Clone, Copy)]
struct RelaySpawn {
    thread: usize,
    process: usize,
}

/// What the run produced.
struct RelayReport {
    /// The three-bind report from the described chain.
    declared: u64,
    /// The single bind behind the hub nothing describes.
    undeclared: u64,
}

/// Proves that a device's **data path is a declared cost, checked at binding
/// time** — `docs/drivers/01`, "Bus Topology And Data Paths".
///
/// The claim being tested is the doc's last one: that a class "cannot meet its
/// budget on direct-attach and silently miss it behind two hubs without the
/// declaration making that arithmetic visible at binding time". So the same
/// manifest entry, with the same budget, is asked about two devices of the same
/// class that differ **only in depth** — and it binds the near one and refuses
/// the far one. Nothing else about the machine differs between those two
/// answers, which is what makes the refusal the topology's doing.
///
/// Throughput is a separate requirement with a separate refusal, because a
/// shorter path is the fix for one and no help at all for the other. The
/// network device sits at a depth its latency budget tolerates easily and
/// behind a hub too narrow for it.
///
/// And a hub the kernel cannot identify is **not free**. The second half hands
/// a manager a bus with no recorded identity; the manifest claims nothing, so
/// the device behind it is refused rather than bound as though it were
/// direct-attached. That is the case a system assuming zero would get wrong
/// while looking entirely healthy.
fn relay_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<RelayReport, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Err(1);
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // SAFETY: single-threaded boot; initialized before any thread runs.
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
        // should reach, and `DeviceChild` grants the graph's record for the
        // *child* rather than a narrowing of the parent's.
        let device_rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
        let hub_rights = Rights::READ | Rights::DERIVE;
        // **Registration order is child order, and it is load-bearing.**
        // `children_of` scans the node pool in slot order, the manager walks
        // depth-first, and it binds the first *held* device of a class — so the
        // near device has to be registered before the hub that leads away from
        // it. Registering both hubs first sends the walk down the far branch
        // and swaps which device each of the three answers is about.
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

        // **The hub with no identity.** Registered the way a device the kernel
        // could not enumerate is, which is the whole point: the manager can see
        // that something is there and cannot learn what, so the manifest has
        // nothing to say about what passing through it costs.
        exec.device_register_mmio(RELAY_HUB_UNKNOWN_OBJ, 0, 0, Rights::READ | Rights::DERIVE)
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

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);

    // --- The described chain: three binds, one manager, one entry ---
    let (relay_manager, relay_probe) = relay_pair(
        RELAY_HUB_NEAR_OBJ,
        Rights::READ | Rights::DERIVE,
        RELAY_SERVER_OBJ,
        RELAY_CLIENT_OBJ,
        RELAY_MANAGER_PROC_OBJ,
        RELAY_PROBE_PROC_OBJ,
        RELAY_MANAGER_KSTACK_VA,
        RELAY_PROBE_KSTACK_VA,
        1,
        BLK_PROBE_RELAY_REPORT,
        &mut kernel_space,
        frames,
        20,
    )?;

    // --- And the hub nothing describes ---
    //
    // A second manager rather than a fourth request on the first: a manager
    // hands out the first *held* device of a class, and a refused device stays
    // held — so every later request for that class answers about the same
    // device. Asking a different manager is what makes this a different
    // question.
    let (relay_manager_2, relay_probe_2) = relay_pair(
        RELAY_HUB_UNKNOWN_OBJ,
        Rights::READ | Rights::DERIVE,
        RELAY_SERVER_2_OBJ,
        RELAY_CLIENT_2_OBJ,
        RELAY_MANAGER_2_PROC_OBJ,
        RELAY_PROBE_2_PROC_OBJ,
        RELAY_MANAGER_2_KSTACK_VA,
        RELAY_PROBE_2_KSTACK_VA,
        1,
        BLK_PROBE_RELAY_REPORT,
        &mut kernel_space,
        frames,
        40,
    )?;

    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    // A run leaves TTBR0 holding the last process's space, and everything below
    // — including the console this reports through — is a low address.
    unsafe { boot_low.activate() };

    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(60);
    }
    let declared = EL0_REPORTS[0].load(Ordering::SeqCst);
    let undeclared = EL0_REPORTS[1].load(Ordering::SeqCst);
    if declared != RELAY_EXPECTED {
        return Err(61);
    }
    if undeclared != RELAY_UNDECLARED_EXPECTED {
        return Err(62);
    }

    // SAFETY: transient raw access; every thread is off-CPU by here, and each
    // thread and process is released once.
    //
    // **Reaping alone is not teardown.** It frees the scheduler slot while the
    // dead process still claims the thread index, and the next spawn reuses it
    // — so `forget_thread` follows every reap. The managers are still blocked
    // in `recv` when this runs: a resident server has no exit, and what ends
    // the run is the probe having reported.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            for thread in [
                relay_manager.thread,
                relay_probe.thread,
                relay_manager_2.thread,
                relay_probe_2.thread,
            ] {
                exec.scheduler().reap(thread);
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        for pair in [relay_manager, relay_probe, relay_manager_2, relay_probe_2] {
            processes.forget_thread(pair.thread);
            if let Some(mut process) = processes.remove(pair.process) {
                process.space_mut().teardown(frames);
            }
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    Ok(RelayReport {
        declared,
        undeclared,
    })
}

/// Spawns one device manager over `root` and one `blk-probe` against it, and
/// runs until nothing is runnable.
///
/// The manager is a resident server, so it never exits; what ends the run is
/// the probe having reported. That is why each pair is run to quiescence before
/// the next is spawned — two managers racing would put their probes' reports in
/// the sink in whichever order the scheduler happened to produce, and the check
/// would be asserting on a coincidence.
#[allow(clippy::too_many_arguments)]
fn relay_pair(
    root: kcore::object::ObjectId,
    root_rights: kcore::rights::Rights,
    server: kcore::object::ObjectId,
    client: kcore::object::ObjectId,
    manager_proc_obj: kcore::object::ObjectId,
    probe_proc_obj: kcore::object::ObjectId,
    manager_kstack: u64,
    probe_kstack: u64,
    manager_arg: usize,
    probe_arg: usize,
    kernel_space: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<(RelaySpawn, RelaySpawn), u32> {
    use kcore::rights::Rights;

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        manager_kstack,
        manager_arg,
        manager_proc_obj,
        kernel_space,
        frames,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(base_err + 10)?;
        manager
            .handles_mut()
            .install(server, Rights::READ)
            .map_err(|_| base_err + 10)?;
        // **What boot grants the framework, and nothing else.** For a bus that
        // is READ | DERIVE: everything behind it the manager gets from the
        // graph, so the topology it charges for is the topology it walked. For
        // a device it is the device's own rights, `FIRMWARE` included — the
        // authority to put code on hardware is boot's to grant and the
        // manager's to spend, and it does not travel on to a driver.
        manager
            .handles_mut()
            .install(root, root_rights)
            .map_err(|_| base_err + 10)?;
    }

    let (probe_idx, probe_proc) = ring3_host_spawn(
        blk_probe_elf(),
        probe_kstack,
        probe_arg,
        probe_proc_obj,
        kernel_space,
        frames,
        base_err + 1,
    )?;
    // SAFETY: as above.
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

// --- Firmware loading (D148) ---------------------------------------------

const FIRMWARE_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd0);
const FIRMWARE_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd1);
const FIRMWARE_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd2);
const FIRMWARE_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd3);
const FIRMWARE_PROBE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xd4);

/// The virtio product id the firmware-declaring manifest entry names. Restated
/// here rather than shared, like every other value this check expects of the
/// manager's policy.
const FIRMWARE_BLOCK_PRODUCT: u16 = 0x1052;

const FIRMWARE_MANAGER_KSTACK_VA: u64 = 0xffff_0003_a000_0000;
const FIRMWARE_PROBE_KSTACK_VA: u64 = 0xffff_0003_b000_0000;

/// The startup argument asking `device-manager` to report the two refusals
/// before it serves, over one device. Must match `FIRMWARE_PROBE` there.
const DEVICE_MANAGER_FIRMWARE_PROBE: usize = (1 << 60) | 1;
/// The startup argument asking `blk-probe` to report what firmware it was
/// handed. Must match `FIRMWARE_REPORT` there.
const BLK_PROBE_FIRMWARE_REPORT: usize = 1 << 60;

/// What the store's images declare, restated here rather than shared.
///
/// **Restated on purpose**, the way the relay costs are: these are what the
/// build put in the container, and a check that read them from the same place
/// the manager does would agree with it by construction.
/// The version the manifest entry requires, restated. Used here as the
/// *installed* driver set's requirement — what the machine is running today.
const BLOCK_FIRMWARE_MIN_VERSION: u32 = 2;
const FIRMWARE_GOOD_SVN: u64 = 7;
const FIRMWARE_GOOD_VERSION: u64 = 3;
const FIRMWARE_OLD_SVN: u64 = 2;
const FIRMWARE_V1_SVN: u64 = 7;

/// What the manager's two deliberate refusals must answer.
///
/// Low to high: `RollbackBlocked` (1) for the image below the floor,
/// `VersionTooOld` (2) for the one below what the entry needs, then the two
/// security versions the kernel reported for them. **Two different refusals is
/// the evidence** — one code for both would leave a system unable to say
/// whether an image was retired or merely old, and those have different fixes.
const FIRMWARE_REFUSALS_EXPECTED: u64 =
    1 | (2u64 << 4) | (FIRMWARE_OLD_SVN << 32) | (FIRMWARE_V1_SVN << 40);

/// What the driver must report about the image it was handed.
///
/// The low word is the leading four bytes of the digest **the driver measured
/// itself**, which the check compares against what the kernel measures from the
/// same store — the one comparison in this milestone that neither side can
/// satisfy by echoing the other. Then the image version, the security version,
/// and zero for the driver's own attempt to load firmware, which must be
/// refused `AccessDenied`.
fn firmware_report_expected(digest_lead: u32) -> u64 {
    u64::from(digest_lead) | (FIRMWARE_GOOD_VERSION << 32) | (FIRMWARE_GOOD_SVN << 40)
}

/// What the run produced.
struct FirmwareReportPair {
    refusals: u64,
    driver: u64,
    /// Whether the incoming system's stricter driver set would strand an image
    /// already in the store — `docs/drivers/01`'s update-compatibility check.
    update_would_strand: bool,
}

/// Proves **firmware loading, mediated by the driver framework** —
/// `docs/drivers/01`, "Firmware Loading".
///
/// Five claims, and each is a different outcome from one code path:
///
/// 1. A manager holding `Rights::FIRMWARE` fetches a verified image and hands
///    it to a driver beside the device, as a second capability.
/// 2. The driver **measures what it received** and gets the digest the kernel
///    measured from the store — the only check here that neither side can
///    satisfy by trusting the other.
/// 3. An image below the system's rollback floor is refused **while measuring
///    perfectly**: `docs/security/02`'s "rejected even if correctly signed".
/// 4. An image the floor accepts and the manifest entry does not is refused
///    *differently*, because those are two authorities and two fixes.
/// 5. The driver asks for firmware itself and is refused, because the manager
///    narrowed the right away when it handed the device on. Without this the
///    right would be a bit nobody had watched refuse anything.
///
/// And the update-compatibility rule runs over the store's real contents: a
/// driver set requiring a version above what is installed would strand it, and
/// the one that is installed would not.
fn firmware_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<FirmwareReportPair, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() || system_store().is_empty() {
        return Err(1);
    }

    // SAFETY: `high` is the active kernel high-half.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(10u32)?;
        // **FIRMWARE is granted here and nowhere else.** Boot gives it to the
        // manager because the manager is the framework; the manager does not
        // pass it on, and the driver's refusal later is that decision working.
        exec.device_register_identified(
            FIRMWARE_DEVICE_OBJ,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::FIRMWARE,
            kcore::devmgr::DeviceIdentity {
                class_code: RELAY_CLASS_STORAGE,
                vendor: RELAY_VIRTIO_VENDOR,
                // The product id the one firmware-declaring manifest entry
                // names. Every other block device in this tree keeps binding
                // with no firmware at all, which is the normal case.
                device: FIRMWARE_BLOCK_PRODUCT,
                bdf: 0,
                revision: 0,
                bus: kcore::devmgr::DeviceBus::Pci,
            },
        )
        .map_err(|_| 11u32)?;

        let channel = exec.channel_create().map_err(|_| 12u32)?;
        exec.bind_endpoint_object(channel.0, FIRMWARE_SERVER_OBJ);
        exec.bind_endpoint_object(channel.1, FIRMWARE_CLIENT_OBJ);
    }

    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: `frames` outlives the run; the pointer is cleared before return.
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    reset_el0_reports();
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);

    let (manager, probe) = relay_pair(
        FIRMWARE_DEVICE_OBJ,
        // The device itself, with the authority to fetch its firmware. The
        // manager spends it and narrows it away on the transfer.
        Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::FIRMWARE,
        FIRMWARE_SERVER_OBJ,
        FIRMWARE_CLIENT_OBJ,
        FIRMWARE_MANAGER_PROC_OBJ,
        FIRMWARE_PROBE_PROC_OBJ,
        FIRMWARE_MANAGER_KSTACK_VA,
        FIRMWARE_PROBE_KSTACK_VA,
        DEVICE_MANAGER_FIRMWARE_PROBE,
        BLK_PROBE_FIRMWARE_REPORT,
        &mut kernel_space,
        frames,
        20,
    )?;

    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // Two reports: the manager's refusals first (it writes before it serves),
    // then the driver's.
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        return Err(60);
    }
    let refusals = EL0_REPORTS[0].load(Ordering::SeqCst);
    let driver = EL0_REPORTS[1].load(Ordering::SeqCst);

    // SAFETY: transient raw access; every thread is off-CPU by here, and each
    // thread and process is released once. Reaping alone is not teardown — see
    // `relay_check` for why `forget_thread` follows it.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            for thread in [manager.thread, probe.thread] {
                exec.scheduler().reap(thread);
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        for pair in [manager, probe] {
            processes.forget_thread(pair.thread);
            if let Some(mut process) = processes.remove(pair.process) {
                process.space_mut().teardown(frames);
            }
        }
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
    }

    if refusals != FIRMWARE_REFUSALS_EXPECTED {
        return Err(61);
    }

    Ok(FirmwareReportPair {
        refusals,
        driver,
        update_would_strand: firmware_update_would_strand(),
    })
}

/// Runs `docs/drivers/01`'s update-compatibility check over the store's **real**
/// contents.
///
/// The question an update has to answer is whether the machine still works
/// afterwards, so it is asked of the images that are *in use*: an image today's
/// policy already refuses is not stranded by an update, because nothing is
/// running it. Filtering by the current rule first is what makes the answer
/// about the update rather than about the store's contents.
///
/// Two candidate driver sets against that set: the one installed, which still
/// admits everything, and a stricter one requiring a version above what is
/// there, which does not. Both are checked, because a rule that refused
/// everything would look correct with only the second.
///
/// The update is hypothetical — this system has no update mechanism, and that
/// is a recorded deviation — but the images and the rule are real.
fn firmware_update_would_strand() -> bool {
    let Ok(store) = kcore::store::mount(system_store()) else {
        return false;
    };
    let installed = tessera_firmware::Requirement {
        min_image_version: BLOCK_FIRMWARE_MIN_VERSION,
    };
    let incoming = tessera_firmware::Requirement {
        min_image_version: FIRMWARE_GOOD_VERSION as u32 + 1,
    };
    let policy = kcore::firmware::POLICY;

    let mut in_use = [tessera_firmware::Image {
        svn: 0,
        image_version: 0,
    }; 8];
    let mut count = 0;
    for index in 0..store.len().min(in_use.len()) {
        let Ok(entry) = store.entry(index) else {
            continue;
        };
        // Firmware only: the store carries other things, and an answer about a
        // blob no driver loads would be noise.
        if !entry.name().starts_with("firmware") {
            continue;
        }
        let image = tessera_firmware::Image {
            svn: entry.svn,
            image_version: entry.image_version,
        };
        if tessera_firmware::admit(&image, &installed, &policy).is_ok() {
            in_use[count] = image;
            count += 1;
        }
    }
    let in_use = &in_use[..count];
    if in_use.is_empty() {
        return false;
    }
    tessera_firmware::update_compatible(in_use, &installed, &policy).is_ok()
        && tessera_firmware::update_compatible(in_use, &incoming, &policy).is_err()
}

fn pcie_enumerate(
    host: &tessera_devicetree::PciHost,
    out: &mut [tessera_pci::Function],
) -> Result<usize, tessera_pci::Error> {
    let Some(memory) = host.memory else {
        return Err(tessera_pci::Error::WindowExhausted);
    };
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
    tessera_pci::enumerate(&bridge, &mut config, window, out)
}

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
    0x8a, 0x00, 0xc0, 0xf2, // movk x10, #0x4, lsl #32     (| version 4 << 32)
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
    0x8a, 0x00, 0xc0, 0xf2, // movk x10, #0x4, lsl #32     (| version 4 << 32)
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
/// The cause the crashing EL0 thread was running under.
///
/// Captured at fault time because that is the last moment it exists: the
/// thread ends here, and the supervisor that answers the crash reaches it
/// through a yield back to boot, whose ambient context is boot's own id.
/// Without adopting this, every ladder record would root a fresh trace and
/// nothing would join a restart to the crash that provoked it — which is most
/// of what those records are for.
static EL0_SINK_FAULT_CORRELATION: AtomicU64 = AtomicU64::new(0);

/// The address a contained EL0 fault named (`FAR_EL1`).
///
/// Kept beside the syndrome rather than folded into it because the
/// crash-recovery ladder's first record is supposed to say *what killed the
/// host* — and "a data abort" without an address is a class of causes, not a
/// cause. A supervisor reporting only the syndrome would produce identical
/// records for a null dereference and a stray pointer.
static EL0_SINK_FAULT_ADDR: AtomicU64 = AtomicU64::new(0);

/// Reports kept **in order**, for checks that run one program more than once
/// and must tell the runs apart. [`EL0_SINK_LOG`] composes reporters by XOR,
/// which is the right shape for several programs reporting different things at
/// once, and the wrong one for the same program reporting the same thing twice
/// — those cancel. Both axes exist because both cases are real.
const MAX_EL0_REPORTS: usize = 4;
static EL0_REPORTS: [AtomicU64; MAX_EL0_REPORTS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static EL0_REPORT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Clears the ordered reports before a check that reads them.
fn reset_el0_reports() {
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &EL0_REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
}

/// The boot frame allocator, reachable from the (argument-less) dispatch hook
/// so covered syscalls can build page tables and DMA pages. A raw pointer
/// valid **only** while an Executive-substrate check runs (the allocator lives
/// on `kmain`'s stack); set before the process runs and cleared after.
static mut EL0_DISPATCH_FRAMES: *mut kcore::pmem::BumpFrameAllocator<'static> =
    core::ptr::null_mut();

/// The SMMU, reachable from the same argument-less hook, so a `DmaAlloc` for a
/// device with an aperture can install the translation it hands back.
///
/// Null is not a default — it is this machine having no IOMMU, which every
/// boot without `iommu=smmuv3` genuinely is, and which the kernel core reports
/// on each grant (`DEVICE_DMA_UNSCOPED`). The same raw-pointer discipline as
/// [`EL0_DISPATCH_FRAMES`], except that the SMMU outlives one check: it is
/// brought up once and stays enabled, because disabling it between checks
/// would let a device reach memory in the gap.
static mut EL0_DISPATCH_IOMMU: *mut Smmu = core::ptr::null_mut();

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

/// Closes every channel endpoint the running thread's process holds, waking
/// whoever was waiting on the other side.
///
/// **Only for a thread that died, never for one that finished.** Doing this on
/// every thread exit was tried and took eighteen of the twenty-four boot checks
/// down with it: a ring-3 program reaching the end of its work is the ordinary
/// case, its peers are still running and still using those channels, and
/// closing them is a teardown nobody asked for. A crash is the opposite — the
/// peers are waiting on a reply that will never come — and the difference
/// between the two is the whole reason this is called from the fault path
/// alone.
///
/// Read from the process's **own handle table** rather than from a list kept
/// alongside it: a channel it was given late, or one that arrived by transfer,
/// is exactly the one a separate list forgets.
fn close_endpoints_of_current() {
    let Some(thread) = ipc_current() else {
        return;
    };
    const SLOTS: usize = 32;
    let mut audit = [(
        kcore::object::ObjectId::from_raw(0),
        kcore::rights::Rights::none(),
    ); SLOTS];
    // SAFETY: transient raw access to the static process table; a read, and the
    // executive borrow below does not overlap it.
    let count = unsafe {
        (*(&raw mut KCORE_PROCESSES))
            .process_of_thread(thread)
            .map(|process| process.handles().audit(&mut audit))
            .unwrap_or(0)
    };
    let mut held = [kcore::object::ObjectId::from_raw(0); SLOTS];
    for (slot, (object, _)) in held.iter_mut().zip(audit.iter()).take(count) {
        *slot = *object;
    }
    ipc_exec().close_endpoints_of(&held[..count]);
}

/// The GIC INTID whose interrupts the ring-3 driver under test is currently
/// wired to (0 = none) — the block host's, or the network driver's, whichever
/// check is running. Set strictly around a ring-3 check's `run()` — the same
/// unmask-only-around-the-run window the x86 COM2 demo uses — so the bridge
/// below can never race boot-context Executive access.
static RING3_DRIVER_INTID: AtomicU32 = AtomicU32::new(0);

/// A second line the same driver is wired to (0 = none).
///
/// **Because a multi-queue controller has more than one.** Every check before
/// this one drove a device with a single interrupt, so one slot was the whole
/// need; an NVMe controller raises one per queue, and a bridge that claimed
/// only the first would leave the other queue's completions unclaimed and its
/// driver parked forever.
static RING3_DRIVER_INTID_ALT: AtomicU32 = AtomicU32::new(0);

/// The device-IRQ bridge (D84): claims the ring-3 host's device INTID,
/// masks the line (storm-safe for level-triggered sources — the trap path
/// EOIs unconditionally; the host re-arms via `IrqComplete` after acking the
/// device), and signals the host's port. Runs in interrupt context.
fn virtio_irq_hook(id: u32) -> bool {
    let wired = RING3_DRIVER_INTID.load(Ordering::SeqCst);
    let alt = RING3_DRIVER_INTID_ALT.load(Ordering::SeqCst);
    if (wired == 0 || id != wired) && (alt == 0 || id != alt) {
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

/// The SMMU's event-queue INTID, once the device tree has been read (0 = the
/// machine has no SMMU, or its node declares no interrupt).
static SMMU_EVENTQ_INTID: AtomicU32 = AtomicU32::new(0);

/// The isolation policy the fault harvest applies, as an
/// `IsolationPolicy` discriminant.
///
/// A static rather than a constant because it *is* policy: a machine being
/// brought up wants every fault recorded and nothing torn down, and a machine
/// running drivers wants the opposite. Defaulting to `Report` is the
/// conservative end — a boot that never sets it degrades to logging, which is
/// the behaviour this port had before the harvest existed.
static SMMU_FAULT_POLICY: AtomicU32 = AtomicU32::new(kcore::devmgr::IsolationPolicy::Report as u32);

/// A holder the isolation policy asked to have stopped, published for a
/// supervisor to act on (0 = none outstanding). See [`Smmu::report`].
static SMMU_ISOLATION_STOP: AtomicU32 = AtomicU32::new(0);

/// The machine's SMMU, reachable from the interrupt bridge for the whole boot.
///
/// Distinct from [`EL0_DISPATCH_IOMMU`], which is set and cleared around each
/// check that needs a mapper in a syscall. A fault can land at any moment —
/// including between two checks, which is exactly the window a
/// check-scoped pointer would leave unharvested — so this one is set once
/// after bring-up and never cleared, matching the fact that the SMMU itself is
/// enabled once and never disabled.
static mut BOOT_IOMMU: *mut Smmu = core::ptr::null_mut();

/// The SMMU's own interrupt: a fault record has been written to the event
/// queue. Harvests it, which records it and applies the standing policy.
///
/// Runs in interrupt context. Unlike the device bridges below it does **not**
/// mask its line: the SMMU's event-queue interrupt is edge-triggered and
/// pulsed per record on this machine, and the harvest empties the queue, so
/// there is no level left asserting to storm on. Masking it would instead
/// silence every fault after the first.
fn smmu_irq_hook(id: u32) -> bool {
    let wired = SMMU_EVENTQ_INTID.load(Ordering::SeqCst);
    if wired == 0 || id != wired {
        return false;
    }
    // SAFETY: `BOOT_IOMMU` is set once after bring-up and names a slot nothing
    // moves out of. Single-core, and this interrupt can only preempt EL0
    // execution or boot code inside an enable window — kernel dispatch runs
    // with IRQs masked from entry to eret, so the raw access never overlaps a
    // use of the `&mut Smmu` a boot check holds. This is the same discipline
    // `EL0_DISPATCH_IOMMU` already rests on, reaching the same object.
    unsafe {
        if let Some(smmu) = BOOT_IOMMU.as_mut() {
            smmu.harvest(true);
        }
    }
    true
}

/// This port's one device-interrupt entry point.
///
/// A single hook, offered to each consumer in turn, because the IOMMU's
/// interrupt is not like the others: every other bridge here belongs to one
/// check and is disarmed by zeroing its own INTID when that check ends, while
/// the SMMU reports faults about *every* device on the machine and must stay
/// wired for the whole boot. With one hook slot in the arch layer, a check
/// installing its own bridge would have unwired the fault harvest for exactly
/// the window in which drivers are running.
///
/// Each consumer still guards on its own wired INTID, so the order below is
/// not a priority — no two of them can claim the same line.
fn device_irq_hook(id: u32) -> bool {
    smmu_irq_hook(id) || msi_irq_hook(id) || virtio_irq_hook(id) || wake_irq_hook(id)
}

/// virtio-mmio as the kernel core's device-reset seam
/// (`kcore::devmgr::DeviceResetter`) — ladder step 5.
///
/// **Per class, and this port knows exactly one.** A virtio transport is reset
/// by writing zero to its `Status` register: the specification defines that as
/// the device dropping every negotiated feature, every queue configuration and
/// every outstanding buffer, and re-reading the register as zero is the device
/// saying it has done so. That is the whole reset, and it is why virtio is the
/// class this can honestly implement today.
///
/// Anything else is a **refusal**. A PCI function-level reset is a different
/// mechanism entirely (a capability write and a mandated settling time), and
/// returning `Ok` for one would have the ladder record a successful reset of a
/// device nothing touched — the next rung would then be taken on a false
/// premise, which is worse than not resetting at all.
struct VirtioMmioResetter;

/// virtio-mmio register offsets used by the reset.
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
        // A device the kernel enumerated from config space is a PCI function,
        // and this resetter does not speak function-level reset.
        if identity.is_some() {
            return Err(KError::NotSupported);
        }
        let (base, len) = window.ok_or(KError::NotSupported)?;
        if len <= VIRTIO_MMIO_STATUS {
            return Err(KError::InvalidMapping);
        }
        // Confirm it is a virtio transport before writing anything to it.
        // The register map below belongs to virtio and to nothing else, and a
        // zero written at offset 0x70 of some other device is not a reset —
        // it is a poke at a register whose meaning nobody here knows.
        //
        // SAFETY: the window comes from the resource graph, which holds the
        // physical base enumeration found; it is inside `DEVICE_RANGE` and so
        // identity-mapped device memory on this port, and both offsets are
        // inside the length the graph recorded (checked above).
        let magic =
            unsafe { tessera_karch_aarch64::mmio_read32((base + VIRTIO_MMIO_MAGIC) as usize) };
        if magic != VIRTIO_MMIO_MAGIC_VALUE {
            return Err(KError::NotSupported);
        }
        // SAFETY: as above.
        unsafe { tessera_karch_aarch64::mmio_write32((base + VIRTIO_MMIO_STATUS) as usize, 0) };
        // The device says whether it did it. Without reading back, a reset
        // that the hardware ignored would be recorded as one that worked.
        // SAFETY: as above.
        let status =
            unsafe { tessera_karch_aarch64::mmio_read32((base + VIRTIO_MMIO_STATUS) as usize) };
        if status != 0 {
            return Err(KError::InvalidMapping);
        }
        Ok(())
    }
}

/// The GIC as the kernel core's interrupt-revocation seam
/// (`kcore::devmgr::InterruptRouter`).
///
/// Zero-sized: the controller is a fixed set of registers this port already
/// knows how to reach, so there is nothing to carry. It exists as a type
/// solely because the kernel core must not name a GIC — the same reason
/// [`Smmu`] implements `DmaMapper` rather than kcore knowing what an SMMU is.
struct GicRouter;

impl kcore::devmgr::InterruptRouter for GicRouter {
    fn mask(&mut self, intid: u32) {
        // SAFETY: masking a GIC line is an interrupt-controller register write
        // with no memory-model footprint, valid from any context.
        unsafe { tessera_karch_aarch64::disable_irq(intid) };
    }
}

/// `IrqComplete` (D84): re-enable every line of the device the caller names.
///
/// Port-local for the controller write alone — the authority check and the
/// lines themselves are [`kcore::dispatch::resolve_irq_lines`], because which
/// lines a device has is the resource graph's answer and not this port's.
fn irq_complete(caller: usize, args_ptr: u64) -> i64 {
    use kcore::syscall::encode_result;

    let mut lines = [0u32; kcore::devmgr::MAX_IRQ_LINES];
    // SAFETY: transient raw access to the static process table and executive.
    let processes = unsafe { &mut *(&raw mut KCORE_PROCESSES) };
    // SAFETY: transient raw read of the static executive.
    let Some(exec) = (unsafe { (*(&raw const KCORE_EXEC)).as_ref() }) else {
        return encode_result(Err(tessera_karch::KError::AccessDenied));
    };
    let count = match kcore::dispatch::resolve_irq_lines(
        exec, processes, caller, args_ptr, &mut lines,
    ) {
        Ok(count) => count,
        Err(e) => return encode_result(Err(e)),
    };
    for intid in &lines[..count] {
        // SAFETY: enabling a GIC line is an interrupt-controller register
        // write; the caller proved authority over the device it belongs to.
        unsafe { tessera_karch_aarch64::enable_irq(*intid) };
    }
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
        EL0_SINK_FAULT_ADDR.store(frame.far, Ordering::SeqCst);
        EL0_SINK_FAULT_CORRELATION.store(kcore::trace::current().correlation, Ordering::SeqCst);
        EL0_SINK_FAULT.store(frame.esr, Ordering::SeqCst);
        // The thread is not going to reply to anybody. Release what it held
        // before it stops running, so a caller parked on it can discover that
        // rather than wait for an event that can no longer happen.
        close_endpoints_of_current();
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
    let mut router = GicRouter;
    let outcome = unsafe {
        let mut env = DispatchEnv {
            exec: match (*(&raw mut KCORE_EXEC)).as_mut() {
                Some(exec) => exec,
                None => fatal_no_executive(),
            },
            processes: &mut *(&raw mut KCORE_PROCESSES),
            caller,
            alloc: &mut *frames,
            // Always present, unlike the IOMMU: this machine's interrupt
            // controller is not optional, and a departing capability whose
            // route was dropped from the graph but left unmasked at the GIC is
            // the half-teardown the seam exists to prevent.
            irqs: Some(&mut router),
            iommu: {
                let unit = *(&raw const EL0_DISPATCH_IOMMU);
                // Null means no IOMMU on this boot, which is a fact about the
                // machine and reported as one — never a reason to hand a
                // device with an aperture a physical address instead.
                unit.as_mut()
                    .map(|u| u as &mut dyn kcore::devmgr::DmaMapper)
            },
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
                // **And keep them apart, in order.** XOR composes reporters but
                // cannot distinguish them, and two reporters sending the *same*
                // value cancel to zero — which is not a hypothetical: a driver
                // bound to a PCI device reports the identity the kernel
                // enumerated, and its replacement reports the same identity.
                // A check reading only the sink would see 0 and could not tell
                // "ran twice, agreed" from "never ran". Keyed by order, which
                // is a property of the program rather than of the schedule.
                let slot = EL0_REPORT_COUNT.fetch_add(1, Ordering::SeqCst) as usize;
                if slot < MAX_EL0_REPORTS {
                    EL0_REPORTS[slot].store(frame.x[0], Ordering::SeqCst);
                }
                // Overflow is not dropped silently: the count keeps rising past
                // the array, so a check expecting two reports and given three
                // sees three.
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
    mmio_len: u64,
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
            .device_register_mmio(
                device_obj,
                mmio_base,
                mmio_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            )
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
    mmio_len: u64,
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
            .device_register_mmio(
                device_obj,
                mmio_base,
                mmio_len,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            )
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

// --- DmaAlloc through an aperture: the address ring-3 gets is an IOVA ---

/// The DMA process's kernel stack for the scoped check, distinct from every
/// other EL0 kstack window.
const SCOPED_DMA_KSTACK_VA: u64 = 0xffff_0000_b100_0000;

/// What [`scoped_dma_check`] proves, in the three numbers that say it.
struct ScopedGrant {
    /// What `dma_alloc` returned — the address the driver will program into
    /// its device.
    iova: u64,
    /// The physical page behind it. Different from `iova`, which is what
    /// translating means.
    phys: u64,
    /// What the device brought back out of the driver's buffer, reached
    /// through `iova`.
    echoed: u64,
    /// The address the SMMU refused **after** the lease ended — the same
    /// `iova` that worked a moment earlier, which is the whole point.
    revoked_at: u64,
    /// Where the device reached a **memory object** that was attached to it —
    /// memory the driver allocated as an object rather than as a DMA page.
    attached_at: u64,
    /// What the device wrote into that object, read back through the direct
    /// map. Proof the attachment reached the hardware.
    attach_echoed: u64,
}

/// Proves the sentence the whole seam exists for: **a ring-3 driver asks for a
/// DMA buffer and is handed an address that reaches its buffer and nothing
/// else.**
///
/// Every earlier milestone handed a driver a physical address and trusted it.
/// D119 showed hardware could bound a device, but with tables the boot built
/// by hand for an address ring-3 never saw. This closes the gap: the EL0
/// program is the *unchanged* D78 probe — it calls `dma_alloc`, writes a magic
/// through its own user VA, and reports what it got back — and the number it
/// reports is now an IOVA, because its device has an aperture.
///
/// The proof is that the **device** honours it. The kernel makes `edu` read 8
/// bytes from the driver's buffer through the returned address; it comes back
/// carrying the magic ring-3 wrote through its VA, so the IOVA and the user VA
/// name the same page from two sides. Then the same transfer to an address
/// outside the aperture is refused by hardware, with the SMMU naming the
/// stream — otherwise "the device wrote where we said" would be equally true
/// of a device that can write anywhere.
fn scoped_dma_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    smmu: &mut Smmu,
    function: &tessera_pci::Function,
) -> Result<ScopedGrant, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let (bar, bar_len) = function.first_bar().ok_or(140u32)?;
    let stream = smmu.stream_of(SMMU_DEVICE_OBJ).ok_or(141u32)?;

    // A fresh executive holding the device authority — and, this time, the
    // record that the device translates. The aperture starts clear of the page
    // `smmu_check` mapped by hand, because the graph must never hand out an
    // address the boot already used for something else.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(142u32)?;
        exec.device_register_mmio(
            SMMU_DEVICE_OBJ,
            bar,
            bar_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 143u32)?;
        // **No aperture is installed here.** The device is behind an SMMU and
        // the SMMU knows it; the lease is the driver's to take, and taking it
        // is what the check is watching for.
    }

    let user_arch = build_low_space(frames, DIRECT_MAP_BASE, DEVICE_RANGE).map_err(|_| 145u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(alloc_asid()), 0);

    let code = frames.alloc().ok_or(146u32)?;
    user_space
        .arch_mut()
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 147u32)?;
    // The same program as the unscoped check (D78): what changed is the answer
    // it gets, not the question it asks. A driver does not know, and does not
    // need to know, whether the address it was handed is translated.
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
        kcore::thread::ThreadId(SCOPED_DMA_KSTACK_VA),
        VirtAddr::new(USER_CODE_VA),
        0,
        VirtAddr::new(USER_STACK_VA),
        1,
        VirtAddr::new(SCOPED_DMA_KSTACK_VA),
        EL0_KSTACK_PAGES,
        SMMU_DEVICE_OBJ,
        user_root,
        &mut user_space,
        &mut kernel_space,
        frames,
    )
    .map_err(|_| 148u32)?;

    // SAFETY: transient raw access to the static executive.
    let thread_idx = unsafe {
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(149u32)?
            .scheduler()
            .add_thread(thread)
            .map_err(|_| 150u32)?
    };
    // SAFETY: transient raw access to the static process table.
    let proc_idx = unsafe {
        let process = kcore::process::Process::new(SCOPED_DMA_PROC_OBJ, user_space);
        (*(&raw mut KCORE_PROCESSES))
            .insert(process)
            .map_err(|_| 151u32)?
    };
    // SAFETY: transient raw access to the static process table.
    unsafe {
        if let Some(p) = (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) {
            p.add_thread(thread_idx).map_err(|_| 152u32)?;
            p.handles_mut()
                .install(SMMU_DEVICE_OBJ, Rights::READ | Rights::MAP)
                .map_err(|_| 153u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator **and the SMMU** to the hook for the run only.
    // SAFETY: both outlive the run; the pointers are cleared before returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
        EL0_DISPATCH_IOMMU = smmu;
    }

    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when the thread yields to boot.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (the thread yielded to boot).
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
        EL0_DISPATCH_IOMMU = core::ptr::null_mut();
    }

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(154);
    }
    let iova = EL0_SINK_LOG.load(Ordering::SeqCst);

    // What the driver was handed must be an address from *its* lease. A
    // physical address that happened to work would fail here, which is the
    // point: this check exists to catch the fallback, not just the fault.
    //
    // And it must be the lease's **first** address — `smmu_check` spent this
    // same range a moment ago and gave it back, so a driver starting anywhere
    // else would mean the release did not happen and the window is being eaten
    // one driver at a time.
    if iova != LEASE_BASE {
        return Err(155);
    }
    // SAFETY: transient raw access to the static executive.
    if unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.lease_holder_of_object(SMMU_DEVICE_OBJ))
        != Some(SCOPED_DMA_PROC_OBJ)
    {
        return Err(156);
    }
    let phys = {
        // SAFETY: transient raw access to the static process table; the
        // process is still resident (teardown is below).
        let process = unsafe { (*(&raw mut KCORE_PROCESSES)).get_mut(proc_idx) }.ok_or(156u32)?;
        process
            .space()
            .arch()
            .translate(VirtAddr::new(DMA_VA))
            .ok_or(157u32)?
            .0
            .base()
            .as_u64()
    };
    if iova == phys {
        // Not a translation at all — the two names for this memory must differ,
        // or the aperture is decorative.
        return Err(158);
    }

    // Now the device. It reads 8 bytes out of the driver's buffer **through
    // the IOVA the kernel handed ring-3**, and hands them back.
    let mut edu = BarWindow { base: bar };
    edu_dma(&mut edu, iova, EDU_BUFFER, 8, EDU_DMA_START);
    // SAFETY: `phys` is a RAM frame mapped into the (not-yet-torn-down)
    // process; the direct map covers all RAM, so this aligned write is in
    // bounds. Clearing it first is what makes the read-back meaningful — the
    // magic that comes back came from the device, not from being left there.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + phys) as *mut u64, 0) };
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as the write above.
    let echoed = unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + phys) as *const u64) };
    if echoed != DMA_MAGIC {
        return Err(159);
    }

    // And the other half: the same device, the same transfer, to an address it
    // was not given. Without this, "the device reached the buffer" is equally
    // true of a device that can reach everything.
    //
    // Drain first, so the record read afterwards is this transfer's and not an
    // earlier check's.
    smmu.drain_events();
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        OUTSIDE_IOVA,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    let record = smmu.drain_events().ok_or(160u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(161);
    }

    // --- A memory object, attached and then detached ------------------------
    //
    // Everything above is `DmaAlloc`: a page the kernel allocated *for* the
    // device. This is the thing D131 could not do — an object that already
    // exists, owned by a process, made reachable by a device and then not.
    //
    // Driven through the executive rather than through a ring-3 syscall,
    // because the syscall half is covered by unit tests and the half that is
    // not is whether `Smmu::unmap` reaches the hardware. That is what this
    // answers, and only a real SMMU can.
    // SAFETY: transient raw access to the static process table and executive;
    // single-threaded boot, and the process is resident (its thread exited but
    // teardown is below). The two statics are distinct, so the borrows do not
    // alias.
    let (object, object_phys, attached_at) = unsafe {
        let process = (*(&raw mut KCORE_PROCESSES))
            .get_mut(proc_idx)
            .ok_or(165u32)?;
        let owner = process.id();
        // The space is borrowed only so the new frames can be zeroed — see
        // `MemoryTable::create`, where zeroing is structural rather than the
        // caller's to remember.
        let space = process.space();
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(166u32)?;
        let object = exec
            .memory_create(owner, 1, kcore::memory::Placement::default(), space, frames)
            .map_err(|_| 167u32)?;
        let mut object_frames = [PhysFrame::containing(PhysAddr::new(0)); 16];
        if exec.memory_frames_of(object, &mut object_frames) != 1 {
            return Err(168);
        }
        let object_phys = object_frames[0].base().as_u64();
        let at = exec
            .device_allocate_in_aperture(SMMU_DEVICE_OBJ, FRAME_SIZE)
            .ok_or(169u32)?;
        kcore::devmgr::DmaMapper::map(smmu, SMMU_DEVICE_OBJ, at, object_phys, FRAME_SIZE)
            .map_err(|_| 170u32)?;
        exec.memory_attach(
            object,
            kcore::memory::Attachment {
                device: SMMU_DEVICE_OBJ,
                address: at,
                len: FRAME_SIZE,
                scoped: true,
            },
        )
        .map_err(|_| 171u32)?;
        (object, object_phys, at)
    };

    // The device writes into the object through the address it was given.
    // SAFETY: `object_phys` is a RAM frame the kernel just allocated and
    // zeroed; the direct map covers all RAM, so this aligned read is in bounds.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + object_phys) as *mut u64, 0) };
    edu_dma(&mut edu, iova, EDU_BUFFER, 8, EDU_DMA_START);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        attached_at,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as the write above.
    let attach_echoed =
        unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + object_phys) as *const u64) };
    if attach_echoed != DMA_MAGIC {
        return Err(172);
    }

    // **Past the aperture, on purpose.** The lease is two pages and
    // `dma_alloc` already took one, so these rounds have exactly one address
    // between them. Each attaches, is reached, and detaches; without an
    // address remembered across the detach the second round would be refused
    // for want of aperture — which is the bound this loop exists to disprove.
    let mut rounds = 0u32;
    while rounds < 6 {
        // SAFETY: transient raw access to the static executive; single-threaded.
        let at = unsafe {
            let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(178u32)?;
            exec.detach_memory(object, Some(smmu)).ok_or(179u32)?;
            let remembered = exec
                .memory_remembered_address(object, SMMU_DEVICE_OBJ)
                .ok_or(180u32)?;
            kcore::devmgr::DmaMapper::map(
                smmu,
                SMMU_DEVICE_OBJ,
                remembered,
                object_phys,
                FRAME_SIZE,
            )
            .map_err(|_| 181u32)?;
            exec.memory_attach(
                object,
                kcore::memory::Attachment {
                    device: SMMU_DEVICE_OBJ,
                    address: remembered,
                    len: FRAME_SIZE,
                    scoped: true,
                },
            )
            .map_err(|_| 182u32)?;
            remembered
        };
        // The same address every round — a driver serving one buffer does not
        // spend its aperture on how long it has been running.
        if at != attached_at {
            return Err(183);
        }
        rounds += 1;
    }
    // And the device still reaches it on the last round, so the rounds were
    // real attachments rather than bookkeeping that happened to agree.
    // SAFETY: `object_phys` is a resident RAM frame the direct map covers.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + object_phys) as *mut u64, 0) };
    edu_dma(&mut edu, iova, EDU_BUFFER, 8, EDU_DMA_START);
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        attached_at,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as above.
    if unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + object_phys) as *const u64) }
        != DMA_MAGIC
    {
        return Err(184);
    }

    // Detach, and the same address stops resolving. **This is the property the
    // whole mechanism rests on**: a buffer handed back to its owner while the
    // device could still write into it would be memory that is still moving.
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(173u32)?;
        if exec.detach_memory(object, Some(smmu)).is_none() {
            return Err(174);
        }
    }
    // Clear it, so anything found there afterwards came from the device rather
    // than from being left behind by the transfer above.
    // SAFETY: `object_phys` is a resident RAM frame the direct map covers; an
    // aligned 8-byte write in bounds.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + object_phys) as *mut u64, 0) };
    smmu.drain_events();
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        attached_at,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as above.
    if unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + object_phys) as *const u64) } != 0 {
        // The device still reached it. Bookkeeping said detached and the
        // hardware disagreed, which is the one outcome that must never pass.
        return Err(175);
    }
    let record = smmu.drain_events().ok_or(176u32)?;
    if record.kind != tessera_smmu::event::F_TRANSLATION || record.stream != stream {
        return Err(177);
    }

    // --- The lease ends, and the device stops reaching what it was reaching ---
    //
    // **This runs before teardown, and the order is part of the claim.** If the
    // frames went back to the allocator first, a revocation that silently did
    // nothing would let the device write into memory the kernel had already
    // handed to something else — the check would cause the bug it exists to
    // catch, and pass while doing it.
    // SAFETY: transient raw access to the static executive and process table;
    // the thread has exited, so the process is quiescent but still resident.
    let ended = unsafe {
        let process = (*(&raw mut KCORE_PROCESSES))
            .get_mut(proc_idx)
            .ok_or(162u32)?;
        (*(&raw mut KCORE_EXEC))
            .as_mut()
            .ok_or(163u32)?
            .end_device_leases(process, Some(smmu))
    };
    if ended != 1 {
        return Err(164);
    }

    // Clear the page, so what comes back came from the device.
    // SAFETY: as the accesses above — still mapped, still resident.
    unsafe { core::ptr::write_volatile((DIRECT_MAP_BASE + phys) as *mut u64, 0) };
    // Empty the queue, so the refusal read below is this transfer's alone.
    smmu.drain_events();
    // The same device, the same transfer, to the address it was using moments
    // ago and is no longer entitled to.
    edu_dma(
        &mut edu,
        EDU_BUFFER,
        iova,
        8,
        EDU_DMA_START | EDU_DMA_TO_MEMORY,
    );
    // SAFETY: as above.
    if unsafe { core::ptr::read_volatile((DIRECT_MAP_BASE + phys) as *const u64) } != 0 {
        // It still reached the buffer. The lease ended on paper only.
        return Err(165);
    }
    // And the SMMU's account of it, naming the very address that worked before.
    // `next_event` consumes, so this is *this* refusal and not the one above.
    let revoked = smmu.drain_events().ok_or(166u32)?;
    // The fault names the **page**, not necessarily the first byte of it: an
    // 8-byte transfer is split into narrower transactions, so the last record
    // of a refused one sits partway into the page (`iova + 4` here). Requiring
    // the exact base would fail for a reason that has nothing to do with
    // revocation.
    if revoked.kind != tessera_smmu::event::F_TRANSLATION
        || revoked.stream != stream
        || revoked.address & !(FRAME_SIZE - 1) != iova
    {
        return Err(167);
    }

    // Teardown: reap the thread, free its kernel stack, and remove the process,
    // reclaiming the DMA buffer's frame with it — safe to do now, and only now,
    // because the device can no longer name that frame.
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
            .unmap(VirtAddr::new(SCOPED_DMA_KSTACK_VA + page * FRAME_SIZE))
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

    Ok(ScopedGrant {
        iova,
        phys,
        echoed,
        revoked_at: revoked.address,
        attached_at,
        attach_echoed,
    })
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
fn power_manager_elf() -> &'static [u8] {
    &power_manager_image::POWER_MANAGER_ELF
}
#[cfg(not(has_ring3_host))]
fn power_manager_elf() -> &'static [u8] {
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

/// The embedded ring-3 NVMe driver. Only the Bazel build embeds it; the cargo
/// inner loop builds without it and the check reports it absent.
#[cfg(has_ring3_host)]
fn sd_host_elf() -> &'static [u8] {
    &sd_host_image::SD_HOST_ELF
}
#[cfg(not(has_ring3_host))]
fn sd_host_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_nvme)]
fn nvme_driver_elf() -> &'static [u8] {
    &nvme_driver_image::NVME_DRIVER_ELF
}
#[cfg(not(has_nvme))]
fn nvme_driver_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn crypto_driver_elf() -> &'static [u8] {
    &crypto_driver_image::CRYPTO_DRIVER_ELF
}
#[cfg(not(has_ring3_host))]
fn crypto_driver_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn crypto_client_elf() -> &'static [u8] {
    &crypto_client_image::CRYPTO_CLIENT_ELF
}
#[cfg(not(has_ring3_host))]
fn crypto_client_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn certifier_elf() -> &'static [u8] {
    &certifier_image::CERTIFIER_ELF
}
#[cfg(not(has_ring3_host))]
fn certifier_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn gpu_driver_elf() -> &'static [u8] {
    &gpu_driver_image::GPU_DRIVER_ELF
}
#[cfg(not(has_ring3_host))]
fn gpu_driver_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn gpu_client_elf() -> &'static [u8] {
    &gpu_client_image::GPU_CLIENT_ELF
}
#[cfg(not(has_ring3_host))]
fn gpu_client_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn snd_driver_elf() -> &'static [u8] {
    &snd_driver_image::SND_DRIVER_ELF
}
#[cfg(not(has_ring3_host))]
fn snd_driver_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn snd_client_elf() -> &'static [u8] {
    &snd_client_image::SND_CLIENT_ELF
}
#[cfg(not(has_ring3_host))]
fn snd_client_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn platform_bus_elf() -> &'static [u8] {
    &platform_bus_image::PLATFORM_BUS_ELF
}
#[cfg(not(has_ring3_host))]
fn platform_bus_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn gpio_driver_elf() -> &'static [u8] {
    &gpio_driver_image::GPIO_DRIVER_ELF
}
#[cfg(not(has_ring3_host))]
fn gpio_driver_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn gpio_client_elf() -> &'static [u8] {
    &gpio_client_image::GPIO_CLIENT_ELF
}
#[cfg(not(has_ring3_host))]
fn gpio_client_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn usb_host_elf() -> &'static [u8] {
    &usb_host_image::USB_HOST_ELF
}
#[cfg(not(has_ring3_host))]
fn usb_host_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn usb_storage_elf() -> &'static [u8] {
    &usb_storage_image::USB_STORAGE_ELF
}
#[cfg(not(has_ring3_host))]
fn usb_storage_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn usb_hid_elf() -> &'static [u8] {
    &usb_hid_image::USB_HID_ELF
}
#[cfg(not(has_ring3_host))]
fn usb_hid_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn input_client_elf() -> &'static [u8] {
    &input_client_image::INPUT_CLIENT_ELF
}
#[cfg(not(has_ring3_host))]
fn input_client_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn pci_bus_elf() -> &'static [u8] {
    &pci_bus_image::PCI_BUS_ELF
}
#[cfg(not(has_ring3_host))]
fn pci_bus_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn net_driver_elf() -> &'static [u8] {
    &net_driver_image::NET_DRIVER_ELF
}
#[cfg(not(has_ring3_host))]
fn net_driver_elf() -> &'static [u8] {
    &[]
}
#[cfg(has_ring3_host)]
fn net_client_elf() -> &'static [u8] {
    &net_client_image::NET_CLIENT_ELF
}
#[cfg(not(has_ring3_host))]
fn net_client_elf() -> &'static [u8] {
    &[]
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
/// The driver's report that the kernel refused to make a client's buffer
/// reachable by its device — the protected-memory refusal, seen from the side
/// that asked for the attachment. Matches `device-host`'s `ATTACH_REFUSED_TAG`.
///
/// **Exactly one per boot**, because exactly one client classifies its buffer
/// and repeats one request. A second refusal, or none, changes the sink and
/// fails the check — which is what makes this evidence rather than decoration.
const RING3_ATTACH_REFUSED_EXPECTED: u64 = 0x4152_5f52 << 32;
const RING3_HOST_EXPECTED: u64 = RING3_HOST_MAGIC.rotate_left(8)
    ^ RING3_HOST_MAGIC.rotate_left(16)
    ^ RING3_NET_EXPECTED
    ^ RING3_ATTACH_REFUSED_EXPECTED;


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

    let entry = kcore::elf::load_into(image, &mut user_space, frames, kcore::elf::Machine::AArch64, base_err)?;

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
) -> Result<usize, u32> {
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
        exec.device_register_mmio(
            device_obj,
            blk_base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 157u32)?;
        exec.device_register_mmio(
            net_device_obj,
            net_base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 189u32)?;
        exec.device_set_mmio_irq(device_obj, blk_intid)
            .map_err(|_| 191u32)?;
        // The IRQ→port bridge, recorded in the graph as a **route** rather
        // than installed as a bare port binding.
        //
        // The difference is what happens when the driver goes. A bare binding
        // is a fact only the boot glue knows, so nothing takes it down: the
        // line keeps firing into a port whose holder is gone, and the next
        // driver granted this device finds its own interrupts arriving
        // somewhere it cannot reach. Routing it through the graph makes the
        // interrupt follow the capability the way the register window and the
        // DMA lease already do (D93, D123).
        //
        // The holder named here is `device_obj` because that is also the
        // driver's process object in this check — `ring3_host_spawn` is given
        // it as the process id below. One value, two roles, which is a quirk
        // of this check's numbering and not of the mechanism.
        let irq_port = exec.port_create().map_err(|_| 192u32)?;
        exec.bind_port_object(irq_port, irq_port_obj);
        exec.device_route_irq(device_obj, irq_port, device_obj)
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
    RING3_DRIVER_INTID.store(blk_intid, Ordering::SeqCst);
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
    // **The driver's interrupt route ends with the driver, and the kernel is
    // what ends it.** Everything above this line is the D84 bridge working;
    // this is the half that was missing. The supervisor names no INTID and no
    // port — it does not know which interrupts this driver was receiving, and
    // does not need to, exactly as it does not know which devices it held. The
    // graph does.
    //
    // Done before the corpse is torn down, for the reason a DMA lease is: a
    // route lives in the GIC and in the port table, both of which would
    // outlive the process entirely.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let routes_ended = unsafe {
        let mut router = GicRouter;
        match (
            (*(&raw mut KCORE_EXEC)).as_mut(),
            (*(&raw mut KCORE_PROCESSES)).get_mut(driver_proc),
        ) {
            (Some(exec), Some(driver)) => exec.end_device_irq_routes(driver, Some(&mut router)),
            _ => 0,
        }
    };
    if routes_ended != 1 {
        return Err(186);
    }
    // The route is gone and the line is masked by the revocation above, so
    // this is belt-and-braces on a line the driver's departure already closed.
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(blk_intid) };
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    // Nothing routes this device's interrupts any more — the claim, checked
    // rather than assumed, because "the graph forgot" and "the graph was never
    // told" look identical afterwards.
    // SAFETY: transient raw access; every thread is off-CPU.
    if unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.irq_route_of_object(device_obj))
        .is_some()
    {
        return Err(187);
    }
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
    let mut grant_frames_released = 0usize;
    unsafe {
        for proc_idx in [client_a_proc, client_b_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                // **A memory object outlives its creator's handle table.** A
                // process forgets its handles on drop by design (driver
                // restart depends on it), so nothing else would ever release
                // the frames behind a grant that was still held at exit — and
                // an object is exactly the thing whose owner may have died
                // holding it. Runs before teardown, though the refcounting
                // makes either order sound: teardown releases the *mapping's*
                // reference and this releases the object's.
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    // No mapper: this host runs on a machine with no SMMU in
                    // front of its virtio transports, so every attachment here
                    // is unscoped and has no translation to tear down. A
                    // machine that did would hand its `Smmu` in, and passing
                    // `None` there would leave a device reaching freed frames.
                    grant_frames_released += exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }

    Ok(grant_frames_released)
}

// --- The network class, served from ring 3 (D150) --------------------------

const NET_CLASS_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe0);
const NET_CLASS_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe1);
const NET_CLASS_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe2);
const NET_CLASS_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe3);
const NET_CLASS_EVENT_DRIVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe4);
const NET_CLASS_EVENT_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe5);
const NET_CLASS_MANAGER_SERVER_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xe6);
const NET_CLASS_MANAGER_CLIENT_OBJ: kcore::object::ObjectId =
    kcore::object::ObjectId::from_raw(0xe7);
const NET_CLASS_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe8);
const NET_CLASS_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xe9);
const NET_CLASS_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xea);

const NET_CLASS_MANAGER_KSTACK_VA: u64 = 0xffff_0004_a000_0000;
const NET_CLASS_DRIVER_KSTACK_VA: u64 = 0xffff_0004_b000_0000;
const NET_CLASS_CLIENT_KSTACK_VA: u64 = 0xffff_0004_c000_0000;

/// What the client must report, and every bit of it is load-bearing.
///
/// Low 48 bits: the gateway's MAC as the ARP resolved it (`52:55:0a:00:02:02`,
/// SLIRP's), which only a completed round trip through the granted buffer can
/// produce. Then, in order: the frame arrived **in a memory object** rather
/// than copied inline; both link transitions were announced; a transmit while
/// the link was down answered `LINK_DOWN`; and the class conformance suite came
/// back *complete* — every rule reached and held, not merely nothing failed.
/// The top byte tags the reporter.
const NET_CLASS_EXPECTED: u64 = 0x4e0f_0202_000a_5552;

/// Proves the **network device class, served by a ring-3 driver** — the first
/// class in the rollout, and the first thing on this system to speak without
/// being asked.
///
/// Four claims, and the first is the one the block class could never make:
///
/// 1. The driver sends the received frame with `ChannelSend` — no request
///    outstanding, nothing to reply to. It sends because the NIC interrupted
///    it; the client is parked on a channel it never called on.
/// 2. The frame travels **as a memory object the driver gives away**. It
///    created the buffer, attached it to the NIC, never mapped it, and holds no
///    handle to it afterwards — `TRANSFERRED` ownership, which the block class
///    had no use for.
/// 3. `SetPower(STANDBY)` takes the link down and says so; a transmit while it
///    is down answers `LINK_DOWN` rather than an I/O error, because the device
///    is present and configurable; `ACTIVE` brings it back and says so again.
/// 4. The same conformance suite the block class passes, against this one,
///    complete.
fn net_class_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    net_base: u64,
    net_intid: Option<u32>,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    // A receive path that is not interrupt-driven is not this class. A missing
    // interrupt is a fatal misconfiguration, never a silent downgrade to
    // polling — which would leave the unsolicited-send claim untested.
    let net_intid = net_intid.ok_or(420u32)?;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(421u32)?;
        exec.device_register_mmio(
            NET_CLASS_DEVICE_OBJ,
            net_base,
            FRAME_SIZE,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 422u32)?;
        exec.device_set_mmio_irq(NET_CLASS_DEVICE_OBJ, net_intid)
            .map_err(|_| 423u32)?;

        // **One port carries both**, and that is what makes the push
        // unsolicited rather than merely asynchronous. The driver's single
        // `PortWait` is a select over "the NIC has a frame" and "the client
        // asked for something": when it sends, it is not sitting in anybody's
        // call. Two ports would have let it wait for the client and answer.
        let port = exec.port_create().map_err(|_| 424u32)?;
        exec.bind_port_object(port, NET_CLASS_PORT_OBJ);
        exec.device_route_irq(NET_CLASS_DEVICE_OBJ, port, NET_CLASS_DRIVER_PROC_OBJ)
            .map_err(|_| 425u32)?;

        let requests = exec.channel_create().map_err(|_| 426u32)?;
        exec.bind_endpoint_object(requests.0, NET_CLASS_SERVER_OBJ);
        exec.bind_endpoint_object(requests.1, NET_CLASS_CLIENT_OBJ);
        // **A second channel for events, and it is not an optimisation.** A
        // pushed event and a reply share one endpoint's queue, so a client's
        // `ChannelCall` would dequeue whichever came first and read an event as
        // its answer. Separate channels make that impossible rather than
        // unlikely.
        let events = exec.channel_create().map_err(|_| 427u32)?;
        exec.bind_endpoint_object(events.0, NET_CLASS_EVENT_DRIVER_OBJ);
        exec.bind_endpoint_object(events.1, NET_CLASS_EVENT_CLIENT_OBJ);
        // The bind channel. Not on the port: the driver calls the manager once
        // at startup and never hears from it again.
        let manager = exec.channel_create().map_err(|_| 428u32)?;
        exec.bind_endpoint_object(manager.0, NET_CLASS_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, NET_CLASS_MANAGER_CLIENT_OBJ);

        exec.port_bind(
            port,
            u64::from(NET_CLASS_SERVER_OBJ.raw()),
            kcore::ipc::SIGNAL_MESSAGE,
        )
        .map_err(|_| 429u32)?;
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // Server first, in both hops: the manager must be parked on `recv` before
    // the driver's bind call, and the driver on its port before the client's.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        NET_CLASS_MANAGER_KSTACK_VA,
        // One device capability, and no probe modes: this manager exists to
        // hand a NIC to whoever asks for the class.
        1,
        NET_CLASS_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        430,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        net_driver_elf(),
        NET_CLASS_DRIVER_KSTACK_VA,
        0,
        NET_CLASS_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        440,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        net_client_elf(),
        NET_CLASS_CLIENT_KSTACK_VA,
        0,
        NET_CLASS_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        450,
    )?;

    // Each process gets exactly its authority, in the install order each
    // program's bootstrap contract mirrors. The driver holds no device until it
    // asks for one by class; the client holds no device at all, ever.
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(431u32)?;
            manager
                .handles_mut()
                .install(NET_CLASS_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 431u32)?;
            manager
                .handles_mut()
                .install(
                    NET_CLASS_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 431u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(441u32)?;
            driver
                .handles_mut()
                .install(NET_CLASS_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 441u32)?;
            driver
                .handles_mut()
                .install(NET_CLASS_PORT_OBJ, Rights::READ)
                .map_err(|_| 441u32)?;
            driver
                .handles_mut()
                .install(NET_CLASS_SERVER_OBJ, Rights::READ)
                .map_err(|_| 441u32)?;
            // WRITE, because sending is putting a message in somebody else's
            // queue. The driver can never read this channel, which is the same
            // asymmetry that stops a client answering its own events.
            driver
                .handles_mut()
                .install(NET_CLASS_EVENT_DRIVER_OBJ, Rights::WRITE)
                .map_err(|_| 441u32)?;
        }
        {
            let client = processes.get_mut(client_proc).ok_or(451u32)?;
            client
                .handles_mut()
                .install(NET_CLASS_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 451u32)?;
            client
                .handles_mut()
                .install(NET_CLASS_EVENT_CLIENT_OBJ, Rights::READ)
                .map_err(|_| 451u32)?;
        }
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // Expose the boot allocator to the hook for the run only.
    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    RING3_DRIVER_INTID.store(net_intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(net_intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // The interrupt pump (D84/D85), and this class needs it more than the
    // block one did: the frame that wakes the driver arrives long after every
    // thread has parked, and the boot context is the only thing left to take
    // the interrupt. Unmasked every iteration, because returning from a thread
    // switch restores the boot context with `DAIF.I` set again.
    let done = || {
        EL0_SINK_EXITED.load(Ordering::SeqCst)
            && EL0_SINK_LOG.load(Ordering::SeqCst) == NET_CLASS_EXPECTED
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
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches atomics and the port
        // facility, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();

    // The driver's interrupt route ends with the driver, and the kernel is what
    // ends it — the supervisor names no INTID and no port; the graph does.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let routes_ended = unsafe {
        let mut router = GicRouter;
        match (
            (*(&raw mut KCORE_EXEC)).as_mut(),
            (*(&raw mut KCORE_PROCESSES)).get_mut(driver_proc),
        ) {
            (Some(exec), Some(driver)) => exec.end_device_irq_routes(driver, Some(&mut router)),
            _ => 0,
        }
    };
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(net_intid) };
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if routes_ended != 1 {
        return Err(452);
    }
    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(453);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != NET_CLASS_EXPECTED {
        return Err(454);
    }

    // Teardown: the client Exited, the driver and manager parked. Reap, free
    // the kernel stacks, and remove the processes — which releases the receive
    // buffer the driver was holding when the run ended, along with everything
    // else it owned.
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        NET_CLASS_CLIENT_KSTACK_VA,
        NET_CLASS_DRIVER_KSTACK_VA,
        NET_CLASS_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(report)
}

// --- PCI as a bus driver: enumeration in ring 3 (D151) ----------------------

const PCI_BUS_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf0);
const PCI_BUS_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf1);
const PCI_BUS_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf2);
const PCI_BUS_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf3);
const PCI_BUS_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf4);
const PCI_BUS_PROBE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0xf5);

const PCI_BUS_MANAGER_KSTACK_VA: u64 = 0xffff_0005_a000_0000;
const PCI_BUS_DRIVER_KSTACK_VA: u64 = 0xffff_0005_b000_0000;
const PCI_BUS_PROBE_KSTACK_VA: u64 = 0xffff_0005_c000_0000;

/// How much configuration space the bus controller is granted: eight buses.
///
/// **A grant, not a limit it discovers.** The window covers whichever buses the
/// controller is handed, and a machine with more of them hands over more window
/// deliberately rather than a controller quietly reaching further. Eight is
/// what the deepest topology these boots build needs — a root port above an
/// upstream switch above a downstream port, with an endpoint under it — plus
/// room, and `MAX_BUS_WINDOW_BYTES` is the kernel's ceiling on the same number.
const PCI_BUS_CONFIG_LEN: u64 = 0x80_0000;

/// Buses that window covers, counting from the host bridge's first.
const PCI_BUS_COUNT: u8 = 8;

/// The startup argument asking `blk-probe` to report what its own configuration
/// space says it is. Must match `CONFIG_REPORT` there.
const BLK_PROBE_CONFIG_REPORT: usize = 1 << 59;

/// Proves **PCI enumeration outside the kernel** — `docs/drivers/01`, "Bus
/// Topology And Data Paths".
///
/// Four claims, and the first is the one that makes the others worth having:
///
/// 1. A ring-3 program held the host bridge and nothing else, walked it with
///    the same `tessera_pci` the kernel calls, placed the BARs, and **declared**
///    what it found. The devices in the graph afterwards were put there by an
///    unprivileged process.
/// 2. The device manager accepted them as *offers* rather than returns —
///    hardware it had never seen, arriving as a capability, because a body can
///    be forged by any sender and a transferred capability cannot.
/// 3. A driver bound one by class and mapped **its own configuration space**,
///    4 KiB scoped to one function, through `Rights::CONFIGURE`.
/// 4. What it read there agrees with what the graph says — and the graph's word
///    came from the bus driver, so this is the ring-3 walk being checked against
///    the hardware rather than against itself. The kernel's own enumeration,
///    which still runs, is the third opinion the expectation is built from.
fn pci_bus_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    host: &tessera_devicetree::PciHost,
    expected_word: u32,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let Some(memory) = host.memory else {
        return Err(460);
    };
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(461u32)?;
        // The bridge, as a device whose register window *is* configuration
        // space. That is what makes the containment check possible at all: the
        // kernel knows exactly how far the controller's own window reaches, so
        // a slot it declares either lies inside it or does not.
        exec.device_register_mmio(
            PCI_BUS_OBJ,
            host.ecam_base,
            PCI_BUS_CONFIG_LEN,
            Rights::READ
                | Rights::WRITE
                | Rights::MAP
                | Rights::DERIVE
                | Rights::CONFIGURE
                | Rights::TRANSFER,
        )
        .map_err(|_| 462u32)?;
        exec.device_set_bus_window(
            PCI_BUS_OBJ,
            kcore::devmgr::BusWindow {
                config_len: PCI_BUS_CONFIG_LEN,
                forward_cpu_base: memory.cpu_base,
                forward_bus_base: memory.bus_base,
                forward_len: memory.len,
                first_bus: host.first_bus,
                // The window's worth of buses, never more than the bridge
                // itself covers: a controller told it may walk a bus the host
                // bridge does not forward would read config space that answers
                // for nothing.
                last_bus: host
                    .last_bus
                    .min(host.first_bus.saturating_add(PCI_BUS_COUNT - 1)),
                // A PCI bridge forwards memory and no wires: its functions
                // interrupt by message, through a different door.
                first_intid: 0,
                intid_count: 0,
            },
        )
        .map_err(|_| 463u32)?;

        let manager = exec.channel_create().map_err(|_| 464u32)?;
        exec.bind_endpoint_object(manager.0, PCI_BUS_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, PCI_BUS_MANAGER_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // The manager first and holding **nothing**: its startup argument is zero
    // device capabilities, which is the whole point. Everything it ends up with
    // arrives from the bus driver.
    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        PCI_BUS_MANAGER_KSTACK_VA,
        0,
        PCI_BUS_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        470,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        pci_bus_elf(),
        PCI_BUS_DRIVER_KSTACK_VA,
        0,
        PCI_BUS_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        480,
    )?;
    let (probe_idx, probe_proc) = ring3_host_spawn(
        blk_probe_elf(),
        PCI_BUS_PROBE_KSTACK_VA,
        BLK_PROBE_CONFIG_REPORT,
        PCI_BUS_PROBE_PROC_OBJ,
        &mut kernel_space,
        frames,
        490,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(manager_proc)
            .ok_or(471u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_SERVER_OBJ, Rights::READ)
            .map_err(|_| 471u32)?;
        {
            let driver = processes.get_mut(driver_proc).ok_or(481u32)?;
            driver
                .handles_mut()
                .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 481u32)?;
            // **The whole of what a bus controller is given.** READ and WRITE
            // because placing a BAR is a write to configuration space, MAP to
            // reach it at all, DERIVE to populate the bus, and CONFIGURE and
            // TRANSFER so the functions it declares can carry them onward. It
            // is told nothing else about the machine.
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
                .map_err(|_| 481u32)?;
        }
        processes
            .get_mut(probe_proc)
            .ok_or(491u32)?
            .handles_mut()
            .install(PCI_BUS_MANAGER_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 491u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // Everything here is cooperative — a send, a call, a reply, an exit — so
    // the scheduler runs to quiescence without a tick to prod it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(492);
    }
    // **Indexed rather than folded.** Two programs report here and one of them
    // reports a count; an XOR could not say which of them failed, and D124's
    // lesson was that a fold cannot tell "ran twice and agreed" from "never
    // ran".
    let bus_report = EL0_REPORTS[0].load(Ordering::SeqCst);
    let probe_report = EL0_REPORTS[1].load(Ordering::SeqCst);
    if bus_report >> 56 != 0x50 {
        return Err(493);
    }
    let found = (bus_report >> 8) & 0xff;
    let declared = bus_report & 0xff;
    if found == 0 || declared != found {
        return Err(494);
    }
    if probe_report >> 56 != 0x43 {
        return Err(495);
    }
    // What the driver read out of its own configuration space must be what the
    // kernel's independent walk found in the same register.
    if probe_report & 0xffff_ffff != u64::from(expected_word) {
        return Err(496);
    }
    // And the graph must have agreed with it, which is the bus driver's
    // declaration being checked against the hardware.
    if probe_report & (1 << 48) == 0 {
        return Err(497);
    }

    // Teardown: the bus driver and the probe exited; the manager is parked in
    // `recv` holding what it was offered.
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(probe_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        PCI_BUS_PROBE_KSTACK_VA,
        PCI_BUS_DRIVER_KSTACK_VA,
        PCI_BUS_MANAGER_KSTACK_VA,
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
        for proc_idx in [probe_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(found)
}

// --- NVMe: a class contract over a second transport, a vector per queue (D153) ---

const NVME_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x100);
const NVME_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x101);
const NVME_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x102);
const NVME_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x103);
const NVME_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x104);
const NVME_PORT1_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x105);
const NVME_PORT2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x106);
const NVME_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x107);
const NVME_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x108);
const NVME_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x109);

const NVME_MANAGER_KSTACK_VA: u64 = 0xffff_0006_a000_0000;
const NVME_DRIVER_KSTACK_VA: u64 = 0xffff_0006_b000_0000;
const NVME_CLIENT_KSTACK_VA: u64 = 0xffff_0006_c000_0000;

/// The PCI class of an NVM Express controller: mass storage, subclass NVM.
const PCI_CLASS_NVME: u32 = 0x0108;

/// The MSI-X vectors the driver's two I/O queues raise, which are also their
/// queue ids. The pairing is the contract with `userspace/nvme-driver`: it
/// creates queue *n* with vector *n*, and this routes vector *n* to the port it
/// holds at that index.
const NVME_VECTORS: [u16; 2] = [1, 2];

/// What `blk-client` reports when it has read both sectors and the block
/// class's conformance suite came back complete. Its id is 1, and it rotates
/// the disk magic by its id.
const NVME_CLIENT_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8);

/// Proves the **block class contract over a second transport, with a vector per
/// queue** — `docs/drivers/02` ("Storage").
///
/// Three claims:
///
/// 1. An NVMe controller is brought up entirely from ring 3 and serves
///    `tessera.driver.block`. Nothing in the schema changed to accommodate it,
///    and the client that judges it is `blk-client` — the same program, byte for
///    byte, that judges the virtio driver. A class contract belongs to the class
///    and not to the transport under it, and this is what that sentence means.
/// 2. Each I/O queue's completions arrive on **its own MSI-X vector and its own
///    port**. The driver never demultiplexes: it submits on a queue and waits
///    where that queue's interrupts land.
/// 3. The block class's conformance suite comes back *complete* against it —
///    every rule reached and held, judged by the suite that judged virtio.
fn nvme_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    host: &tessera_devicetree::PciHost,
    v2m: &mut V2mFrame,
    function: &tessera_pci::Function,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    let bridge = tessera_pci::Host {
        ecam_base: host.ecam_base,
        ecam_len: host.ecam_len,
        first_bus: host.first_bus,
        last_bus: host.last_bus,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    // The register window: the largest memory BAR, which on this controller is
    // BAR 0 — its registers and, past 0x1000, its doorbells.
    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(500);
    };

    // **Two vectors, two SPIs, two ports.** Programming MSI-X is boot's because
    // the doorbell address is a platform fact a driver must not invent — the
    // same reason a driver is never told where its register window is in
    // physical memory.
    let capability =
        tessera_pci::find_capability(&bridge, &config, function.bdf, tessera_pci::CAP_MSIX)
            .map_err(|_| 501u32)?
            .ok_or(502u32)?;
    let table = tessera_pci::msix_table(&bridge, &config, function.bdf, capability, function)
        .map_err(|_| 503u32)?;
    if u32::from(table.entries) <= u32::from(NVME_VECTORS[1]) {
        // A controller with fewer vectors than queues cannot give each queue
        // its own, and a check that carried on would be proving something else.
        return Err(504);
    }
    let Some((msix_bar, _)) = function.bars[table.bar] else {
        return Err(505);
    };
    let mut msix = BarWindow {
        base: msix_bar + u64::from(table.offset),
    };
    let mut spis = [0u32; 2];
    for (slot, vector) in NVME_VECTORS.iter().enumerate() {
        let spi = v2m.allocate().ok_or(506u32)?;
        spis[slot] = spi;
        tessera_pci::program_msix_entry(&mut msix, usize::from(*vector), v2m.doorbell(), spi)
            .map_err(|_| 507u32)?;
    }
    tessera_pci::msix_enable(&bridge, &mut config, function.bdf, capability).map_err(|_| 508u32)?;

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(510u32)?;
        // **Registered with its identity, not just its window.** A PCI
        // function says what it is in configuration space, which no capability
        // reaches, so the manager classifies it from what the graph recorded.
        // Without this it falls back to probing the device's own registers —
        // which works for a virtio transport that announces itself at offset
        // zero and finds an NVMe controller's capability register instead.
        exec.device_register_identified(
            NVME_DEVICE_OBJ,
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
        .map_err(|_| 511u32)?;
        // Both lines, and then a route each. A device with one line per queue
        // needs both recorded or the second is one nothing can re-arm — and a
        // route each is what makes the port the driver wakes on identify the
        // queue that finished.
        for spi in spis {
            exec.device_add_mmio_irq(NVME_DEVICE_OBJ, spi)
                .map_err(|_| 512u32)?;
        }
        for (slot, object) in [NVME_PORT1_OBJ, NVME_PORT2_OBJ].into_iter().enumerate() {
            let port = exec.port_create().map_err(|_| 513u32)?;
            exec.bind_port_object(port, object);
            exec.device_route_irq_line(NVME_DEVICE_OBJ, spis[slot], port, NVME_DRIVER_PROC_OBJ)
                .map_err(|_| 514u32)?;
        }
        let manager = exec.channel_create().map_err(|_| 515u32)?;
        exec.bind_endpoint_object(manager.0, NVME_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, NVME_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 516u32)?;
        exec.bind_endpoint_object(service.0, NVME_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, NVME_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        NVME_MANAGER_KSTACK_VA,
        1,
        NVME_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        520,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        nvme_driver_elf(),
        NVME_DRIVER_KSTACK_VA,
        0,
        NVME_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        530,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        blk_client_elf(),
        NVME_CLIENT_KSTACK_VA,
        1,
        NVME_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        540,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(521u32)?;
            manager
                .handles_mut()
                .install(NVME_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 521u32)?;
            manager
                .handles_mut()
                .install(
                    NVME_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 521u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(531u32)?;
            driver
                .handles_mut()
                .install(NVME_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 531u32)?;
            driver
                .handles_mut()
                .install(NVME_SERVER_OBJ, Rights::READ)
                .map_err(|_| 531u32)?;
            // A port per queue, in the order the driver's own constants name
            // them. This install order is the whole of its bootstrap contract.
            for object in [NVME_PORT1_OBJ, NVME_PORT2_OBJ] {
                driver
                    .handles_mut()
                    .install(object, Rights::READ)
                    .map_err(|_| 531u32)?;
            }
        }
        processes
            .get_mut(client_proc)
            .ok_or(541u32)?
            .handles_mut()
            .install(NVME_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 541u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    RING3_DRIVER_INTID.store(spis[0], Ordering::SeqCst);
    RING3_DRIVER_INTID_ALT.store(spis[1], Ordering::SeqCst);
    for spi in spis {
        // SAFETY: enabling a GIC line is an interrupt-controller register
        // write. Edge-triggered, because a message-signalled interrupt raises
        // and drops the line in one action and a level input has nothing left
        // to latch.
        unsafe {
            tessera_karch_aarch64::set_irq_edge_triggered(spi);
            tessera_karch_aarch64::enable_irq(spi);
        }
    }
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    let done = || {
        EL0_SINK_EXITED.load(Ordering::SeqCst)
            && EL0_SINK_LOG.load(Ordering::SeqCst) == NVME_CLIENT_EXPECTED
    };
    let mut pump_budget = 2000u32;
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
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches atomics and the port
        // facility, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();

    // The driver's routes end with the driver, and the kernel is what ends
    // them — both of them, which is what a device with a line per queue needs.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let routes_ended = unsafe {
        let mut router = GicRouter;
        match (
            (*(&raw mut KCORE_EXEC)).as_mut(),
            (*(&raw mut KCORE_PROCESSES)).get_mut(driver_proc),
        ) {
            (Some(exec), Some(driver)) => exec.end_device_irq_routes(driver, Some(&mut router)),
            _ => 0,
        }
    };
    for spi in spis {
        // SAFETY: disabling a GIC line is an interrupt-controller register
        // write.
        unsafe { tessera_karch_aarch64::disable_irq(spi) };
    }
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    RING3_DRIVER_INTID_ALT.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if routes_ended != 1 {
        return Err(550);
    }
    // Neither line routes anywhere now. Checked rather than assumed, because
    // "the graph forgot" and "the graph was never told" look identical
    // afterwards — and a device with two lines is exactly where a sweep that
    // ended one and stopped would go unnoticed.
    // SAFETY: transient raw access; every thread is off-CPU.
    if unsafe { (*(&raw const KCORE_EXEC)).as_ref() }
        .and_then(|exec| exec.irq_route_of_object(NVME_DEVICE_OBJ))
        .is_some()
    {
        return Err(551);
    }
    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 || !EL0_SINK_EXITED.load(Ordering::SeqCst) {
        return Err(552);
    }
    let report = EL0_SINK_LOG.load(Ordering::SeqCst);
    if report != NVME_CLIENT_EXPECTED {
        return Err(553);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        NVME_CLIENT_KSTACK_VA,
        NVME_DRIVER_KSTACK_VA,
        NVME_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(report)
}

// --- Sound: a device that is never finished, and a stream deliberately
// starved (D158) ---

const SND_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x180);
const SND_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x181);
const SND_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x182);
const SND_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x183);
const SND_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x184);
const SND_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x185);
const SND_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x186);
const SND_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x187);

const SND_MANAGER_KSTACK_VA: u64 = 0xffff_000a_a000_0000;
const SND_DRIVER_KSTACK_VA: u64 = 0xffff_000a_b000_0000;
const SND_CLIENT_KSTACK_VA: u64 = 0xffff_000a_c000_0000;

/// A multimedia controller, subclass audio. Matched on both bytes: the base
/// byte covers video and telephony as well.
const PCI_CLASS_AUDIO: u32 = 0x0401;

/// What the client reports: the suite came back complete, the fed stream played
/// with no gap, and the abandoned one gapped.
const SND_CLIENT_EXPECTED: u64 = (0xa0 << 56) | (1 << 34) | (1 << 33) | (1 << 32);

/// Proves **a device that is never finished**.
///
/// Everything else this kernel drives answers a request and stops. A playback
/// stream is a standing obligation: the device consumes periods at the rate of
/// the sound and plays silence the moment there is nothing to consume, and
/// nothing fails while it happens.
///
/// Which is why the check has two streams. One is kept fed and must have
/// consumed periods with no gap; the other is started, given one period and
/// abandoned, and must be **reported** as having gapped. Without the second, a
/// driver that dropped every period on the floor would pass — silence is what a
/// broken audio path produces too.
fn snd_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(901u32)?;
        exec.device_register_identified(
            SND_DEVICE_OBJ,
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
        .map_err(|_| 902u32)?;
        // Where its virtio structures are, read out of configuration space
        // during enumeration — a driver holding only a window has no way to
        // find them, because config space is not per-device and no capability
        // to it can be handed out.
        exec.device_set_layout(SND_DEVICE_OBJ, layout)
            .map_err(|_| 903u32)?;

        let manager = exec.channel_create().map_err(|_| 904u32)?;
        exec.bind_endpoint_object(manager.0, SND_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, SND_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 905u32)?;
        exec.bind_endpoint_object(service.0, SND_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, SND_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        SND_MANAGER_KSTACK_VA,
        1,
        SND_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        910,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        snd_driver_elf(),
        SND_DRIVER_KSTACK_VA,
        0,
        SND_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        920,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        snd_client_elf(),
        SND_CLIENT_KSTACK_VA,
        0,
        SND_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        930,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(911u32)?;
            manager
                .handles_mut()
                .install(SND_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 911u32)?;
            manager
                .handles_mut()
                .install(
                    SND_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 911u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(921u32)?;
            driver
                .handles_mut()
                .install(SND_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 921u32)?;
            driver
                .handles_mut()
                .install(SND_SERVER_OBJ, Rights::READ)
                .map_err(|_| 921u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(931u32)?
            .handles_mut()
            .install(SND_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 931u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // **The device consumes at the rate of the sound**, so the client's polling
    // has to be able to make progress while nothing else is runnable. The timer
    // runs so a stream waiting on a period the device has not finished with is
    // interrupted rather than spinning to its bound.
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(940);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Three separable claims, checked apart: the suite came back complete, the
    // fed stream played without a gap, and the abandoned one gapped.
    if report & (1 << 32) == 0 {
        return Err(941);
    }
    if report & (1 << 33) == 0 {
        return Err(942);
    }
    if report & (1 << 34) == 0 {
        return Err(943);
    }
    // The low half carries the fed stream's own numbers, which the verdict
    // does not need and a failure does.
    if report >> 32 != SND_CLIENT_EXPECTED >> 32 {
        return Err(944);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        SND_CLIENT_KSTACK_VA,
        SND_DRIVER_KSTACK_VA,
        SND_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(report)
}

// --- Display: the first device whose work is checked from outside the
// machine (D159) ---

const GPU_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a0);
const GPU_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a1);
const GPU_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a2);
const GPU_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a3);
const GPU_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a4);
const GPU_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a5);
const GPU_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a6);
const GPU_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1a7);

const GPU_MANAGER_KSTACK_VA: u64 = 0xffff_000b_a000_0000;
const GPU_DRIVER_KSTACK_VA: u64 = 0xffff_000b_b000_0000;
const GPU_CLIENT_KSTACK_VA: u64 = 0xffff_000b_c000_0000;

/// A display controller. Matched on the base byte: every subclass of it is a
/// display of some kind, which is not true of the multimedia class beside it.
const PCI_CLASS_DISPLAY: u32 = 0x03;

/// What the client reports: the suite came back complete, every pixel was
/// written and shown, and a blit past the edge was refused rather than clipped.
const GPU_CLIENT_EXPECTED: u64 = (0xd0 << 56) | (1 << 34) | (1 << 33) | (1 << 32);

/// Proves **a device whose work is checked from outside the machine**.
///
/// Every other check here believes the guest, and is right to: the value a
/// driver reports could only have come from its device. A display is different.
/// A driver that created the resource, attached the backing, set the scanout
/// and drew nothing reports exactly what a working one does — so this check
/// asks the guest for very little, arms, and waits while the harness outside
/// asks QEMU for the framebuffer and looks at the pixels.
fn gpu_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1001u32)?;
        exec.device_register_identified(
            GPU_DEVICE_OBJ,
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
        .map_err(|_| 1002u32)?;
        // Where its virtio structures are, read out of configuration space
        // during enumeration — a driver holding only a window has no way to
        // find them, because config space is not per-device and no capability
        // to it can be handed out.
        exec.device_set_layout(GPU_DEVICE_OBJ, layout)
            .map_err(|_| 1003u32)?;

        let manager = exec.channel_create().map_err(|_| 1004u32)?;
        exec.bind_endpoint_object(manager.0, GPU_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, GPU_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1005u32)?;
        exec.bind_endpoint_object(service.0, GPU_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, GPU_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        GPU_MANAGER_KSTACK_VA,
        1,
        GPU_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1010,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        gpu_driver_elf(),
        GPU_DRIVER_KSTACK_VA,
        0,
        GPU_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1020,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        gpu_client_elf(),
        GPU_CLIENT_KSTACK_VA,
        0,
        GPU_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        1030,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1011u32)?;
            manager
                .handles_mut()
                .install(GPU_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1011u32)?;
            manager
                .handles_mut()
                .install(
                    GPU_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1011u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1021u32)?;
            driver
                .handles_mut()
                .install(GPU_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1021u32)?;
            driver
                .handles_mut()
                .install(GPU_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1021u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(1031u32)?
            .handles_mut()
            .install(GPU_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1031u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // The timer runs so the wait after the picture is drawn is a wait rather
    // than a spin, and so a driver parked on a command the device has not
    // finished with is interrupted.
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // **Armed, and then held.** The picture is on the glass now, and it stays
    // there only while this machine is running — so the check says so and waits
    // long enough for the harness outside to ask QEMU for the framebuffer. A
    // boot nobody is watching pays a few seconds; a boot that is watching gets
    // its screendump.
    kprintln!(
        "gpu: armed — a picture is on the glass, waiting for it to be looked at from outside"
    );
    kcore::verdict::claims(&["gpu.armed"]);
    {
        use tessera_karch::{CpuOps, InterruptControl};
        for _ in 0..500u32 {
            <Cpu as InterruptControl>::enable();
            Cpu::halt_until_interrupt();
            <Cpu as InterruptControl>::disable();
        }
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(1040);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Three separable claims, checked apart — and none of them is the one that
    // matters most, which is checked outside this machine entirely.
    if report & (1 << 32) == 0 {
        return Err(1041);
    }
    if report & (1 << 33) == 0 {
        return Err(1042);
    }
    if report & (1 << 34) == 0 {
        return Err(1043);
    }
    // The low half carries the pixel count, which the verdict does not need and
    // a failure does.
    if report >> 32 != GPU_CLIENT_EXPECTED >> 32 {
        return Err(1044);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        GPU_CLIENT_KSTACK_VA,
        GPU_DRIVER_KSTACK_VA,
        GPU_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(report)
}

// --- Crypto: a device whose answer is fixed by a published standard
// (D160) ---

const CRYPTO_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c0);
const CRYPTO_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c1);
const CRYPTO_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c2);
const CRYPTO_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c3);
const CRYPTO_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c4);
const CRYPTO_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c5);
const CRYPTO_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c6);
const CRYPTO_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1c7);

const CRYPTO_MANAGER_KSTACK_VA: u64 = 0xffff_000c_a000_0000;
const CRYPTO_DRIVER_KSTACK_VA: u64 = 0xffff_000c_b000_0000;
const CRYPTO_CLIENT_KSTACK_VA: u64 = 0xffff_000c_c000_0000;

/// What a virtio crypto device is, by vendor and device id.
///
/// **Not a PCI class.** This transport does not declare a useful one — the
/// class byte says "other", which a dozen unrelated devices also say — so it is
/// identified by what it *is* rather than by what kind of thing it claims to
/// be: 0x1040 plus the virtio device id, which is how a modern virtio function
/// names itself.
const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_CRYPTO_DEVICE_ID: u16 = 0x1040 + 20;

/// What the client reports: the suite came back complete, the ciphertext is the
/// one the standard publishes, it decrypts back, the key made a difference, and
/// four things that should have been refused were.
const CRYPTO_CLIENT_EXPECTED: u64 = (0xc0 << 56)
    | (1 << 40)
    | (1 << 39)
    | (1 << 38)
    | (1 << 37)
    | (1 << 36)
    | (1 << 35)
    | (1 << 34)
    | (1 << 33)
    | (1 << 32);

/// Proves **a device whose right answer was decided somewhere else**.
///
/// The display check had to go outside the machine to see whether the work was
/// done. This one does not have to, and for a better reason: the answer is
/// published. A ring-3 client encrypts NIST SP 800-38A's vector and compares
/// what comes back against the ciphertext the standard says it becomes — a
/// value no wrong implementation agrees with by accident, and one that nothing
/// in this machine could have produced without actually doing the work.
fn crypto_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1201u32)?;
        exec.device_register_identified(
            CRYPTO_DEVICE_OBJ,
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
        .map_err(|_| 1202u32)?;
        // Where its virtio structures are, read out of configuration space
        // during enumeration — a driver holding only a window has no way to
        // find them, because config space is not per-device and no capability
        // to it can be handed out.
        exec.device_set_layout(CRYPTO_DEVICE_OBJ, layout)
            .map_err(|_| 1203u32)?;

        let manager = exec.channel_create().map_err(|_| 1204u32)?;
        exec.bind_endpoint_object(manager.0, CRYPTO_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, CRYPTO_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1205u32)?;
        exec.bind_endpoint_object(service.0, CRYPTO_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, CRYPTO_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        CRYPTO_MANAGER_KSTACK_VA,
        1,
        CRYPTO_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1210,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        crypto_driver_elf(),
        CRYPTO_DRIVER_KSTACK_VA,
        0,
        CRYPTO_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1220,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        crypto_client_elf(),
        CRYPTO_CLIENT_KSTACK_VA,
        0,
        CRYPTO_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        1230,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1201u32)?;
            manager
                .handles_mut()
                .install(CRYPTO_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1211u32)?;
            manager
                .handles_mut()
                .install(
                    CRYPTO_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1211u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1221u32)?;
            driver
                .handles_mut()
                .install(CRYPTO_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1221u32)?;
            driver
                .handles_mut()
                .install(CRYPTO_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1221u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(1231u32)?
            .handles_mut()
            .install(CRYPTO_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1231u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // The timer runs so a driver parked on a command the device has not yet
    // finished with is interrupted rather than spinning to its bound.
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(1240);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Eight separable claims, checked apart so a failure names which one.
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    for (bit, which) in [
        (32u32, 1241u32),
        (33, 1242),
        (34, 1243),
        (35, 1244),
        (36, 1245),
        (37, 1246),
        (38, 1247),
        (39, 1248),
        (40, 1250),
    ] {
        if report & (1 << bit) == 0 {
            return Err(which);
        }
    }
    // The low half carries the conformance rule bits, which the verdict does
    // not need and a failure does.
    if report >> 32 != CRYPTO_CLIENT_EXPECTED >> 32 {
        return Err(1249);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        CRYPTO_CLIENT_KSTACK_VA,
        CRYPTO_DRIVER_KSTACK_VA,
        CRYPTO_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(report)
}

// --- Crash recovery: a client parked on a driver that dies (D171) ---

const CRASH_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e0);
const CRASH_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e1);
const CRASH_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e2);
const CRASH_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e3);
const CRASH_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e4);
const CRASH_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e5);
const CRASH_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e6);
const CRASH_CLIENT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1e7);

const CRASH_MANAGER_KSTACK_VA: u64 = 0xffff_000e_a000_0000;
const CRASH_DRIVER_KSTACK_VA: u64 = 0xffff_000e_b000_0000;
const CRASH_CLIENT_KSTACK_VA: u64 = 0xffff_000e_c000_0000;

/// The startup bit that makes the driver take a request and never answer it.
const CRASH_BEFORE_REPLYING: usize = 1 << 63;

/// The stage a ring-3 program reports when a channel call fails, and the tag
/// every `uabi::fail` carries. Together they say the client came back from its
/// call with an error rather than with an answer.
const CLIENT_FAIL_TAG: u64 = 0xdead_0000_0000_0000;
const CLIENT_CHANNEL_STAGE: u64 = 0xc9;

/// **A client parked on a driver that dies.**
///
/// Its own run, and it has to be: a crash that leaves the certifier without an
/// answer destroys the transcript the other checks are built on, so this cannot
/// share the run that produces them. A fresh executive, a driver told to take
/// one request and never reply, and a client that calls it.
///
/// What is being asked is not whether the driver died — that is arranged — but
/// whether **the client came back**. Before `close_endpoints_of`, it did not:
/// the call parked awaiting a reply, the server stopped existing, and nothing
/// connected the two, so the thread stayed blocked and the run ended with it
/// still waiting. A client that never returns reports nothing at all, which is
/// exactly how this reads: the report count is the evidence.
fn crash_recovery_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
) -> Result<bool, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1501u32)?;
        exec.device_register_identified(
            CRASH_DEVICE_OBJ,
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
        .map_err(|_| 1502u32)?;
        exec.device_set_layout(CRASH_DEVICE_OBJ, layout)
            .map_err(|_| 1503u32)?;
        let manager = exec.channel_create().map_err(|_| 1504u32)?;
        exec.bind_endpoint_object(manager.0, CRASH_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, CRASH_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1505u32)?;
        exec.bind_endpoint_object(service.0, CRASH_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, CRASH_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        CRASH_MANAGER_KSTACK_VA,
        1,
        CRASH_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1510,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        crypto_driver_elf(),
        CRASH_DRIVER_KSTACK_VA,
        CRASH_BEFORE_REPLYING,
        CRASH_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1520,
    )?;
    let (client_idx, client_proc) = ring3_host_spawn(
        certifier_elf(),
        CRASH_CLIENT_KSTACK_VA,
        CERTIFIED_DRIVER_ID,
        CRASH_CLIENT_PROC_OBJ,
        &mut kernel_space,
        frames,
        1530,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1501u32)?;
            manager
                .handles_mut()
                .install(CRASH_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1511u32)?;
            manager
                .handles_mut()
                .install(
                    CRASH_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1511u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1521u32)?;
            driver
                .handles_mut()
                .install(CRASH_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1521u32)?;
            driver
                .handles_mut()
                .install(CRASH_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1521u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(1531u32)?
            .handles_mut()
            .install(CRASH_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1531u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable —
    // which, before this milestone, is precisely what a client left blocked
    // forever looked like.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    // The driver was supposed to die. If it did not, the run proved nothing
    // about recovery and must say so rather than passing on a crash that never
    // happened.
    let crashed = EL0_SINK_FAULT.load(Ordering::SeqCst) != 0;
    // And the client was supposed to come back. A client still parked reports
    // nothing at all, so the count is the whole evidence.
    let client_report = EL0_REPORTS[0].load(Ordering::SeqCst);
    let returned = EL0_REPORT_COUNT.load(Ordering::SeqCst) > 0;
    // With an error, and specifically the channel call's. A client that came
    // back claiming success would be worse than one that hung.
    let with_an_error = client_report & 0xffff_0000_0000_0000 == CLIENT_FAIL_TAG
        && (client_report >> 16) & 0xffff == CLIENT_CHANNEL_STAGE;

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        CRASH_CLIENT_KSTACK_VA,
        CRASH_DRIVER_KSTACK_VA,
        CRASH_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }

    if !crashed {
        return Err(1540);
    }
    Ok(returned && with_an_error)
}

// --- Removal while ring 3 is running: the guest's half of hotplug, on the
// periodic tick ---

/// What the slot watch has seen so far.
///
/// Four states rather than a flag, because the two middle ones are different
/// facts and collapsing them would make the check unable to say which half
/// failed: a slot that never asked and a slot that asked and was never answered
/// are an absent request and a broken guest.
mod slot_watch {
    /// Nothing is being watched.
    pub const IDLE: u32 = 0;
    /// A port and the device below it are being watched, and no eject has been
    /// requested yet.
    pub const ARMED: u32 = 1;
    /// The eject was requested and this guest answered it. The device has not
    /// stopped answering config space yet.
    pub const ACKNOWLEDGED: u32 = 2;
    /// Config space stopped answering and the graph was told.
    pub const REMOVED: u32 = 3;
}

static SLOT_WATCH_STATE: AtomicU32 = AtomicU32::new(slot_watch::IDLE);
static SLOT_WATCH_ECAM: AtomicU64 = AtomicU64::new(0);
static SLOT_WATCH_ECAM_LEN: AtomicU64 = AtomicU64::new(0);
/// The host's bus range, `first << 8 | last`.
static SLOT_WATCH_BUSES: AtomicU32 = AtomicU32::new(0);
/// The port whose slot is watched, and the endpoint below it, each packed as
/// `bus << 16 | device << 8 | function`.
static SLOT_WATCH_PORT: AtomicU32 = AtomicU32::new(0);
static SLOT_WATCH_DEVICE: AtomicU32 = AtomicU32::new(0);
/// The graph node the endpoint is, so the removal can name it.
static SLOT_WATCH_OBJECT: AtomicU32 = AtomicU32::new(0);
/// How many ticks looked, so a run in which the hook never fired is
/// distinguishable from one in which it looked and saw nothing.
static SLOT_WATCH_POLLS: AtomicU64 = AtomicU64::new(0);
/// How many graph nodes the removal took.
static SLOT_WATCH_SUBTREE: AtomicU32 = AtomicU32::new(0);

fn pack_bdf(bdf: tessera_pci::Bdf) -> u32 {
    (u32::from(bdf.bus) << 16) | (u32::from(bdf.device) << 8) | u32::from(bdf.function)
}

fn unpack_bdf(packed: u32) -> Option<tessera_pci::Bdf> {
    tessera_pci::Bdf::new(
        ((packed >> 16) & 0xff) as u8,
        ((packed >> 8) & 0xff) as u8,
        (packed & 0xff) as u8,
    )
}

/// Starts watching `port`'s slot for an eject, and `device` for the moment it
/// stops answering.
///
/// Everything the watch needs is copied into integers rather than borrowed.
/// `tessera_pci::Host` and `EcamWindow` are four numbers and one number
/// respectively, so the tick hook rebuilds them instead of holding a reference
/// into a boot stack frame that a later check will reuse.
fn arm_slot_watch(
    host: &tessera_pci::Host,
    port: tessera_pci::Bdf,
    device: tessera_pci::Bdf,
    object: kcore::object::ObjectId,
) {
    SLOT_WATCH_ECAM.store(host.ecam_base, Ordering::SeqCst);
    SLOT_WATCH_ECAM_LEN.store(host.ecam_len, Ordering::SeqCst);
    SLOT_WATCH_BUSES.store(
        (u32::from(host.first_bus) << 8) | u32::from(host.last_bus),
        Ordering::SeqCst,
    );
    SLOT_WATCH_PORT.store(pack_bdf(port), Ordering::SeqCst);
    SLOT_WATCH_DEVICE.store(pack_bdf(device), Ordering::SeqCst);
    SLOT_WATCH_OBJECT.store(object.raw(), Ordering::SeqCst);
    SLOT_WATCH_POLLS.store(0, Ordering::SeqCst);
    SLOT_WATCH_SUBTREE.store(0, Ordering::SeqCst);
    SLOT_WATCH_STATE.store(slot_watch::ARMED, Ordering::SeqCst);
}

fn disarm_slot_watch() {
    SLOT_WATCH_STATE.store(slot_watch::IDLE, Ordering::SeqCst);
}

/// A tick that does nothing, for restoring the state this check found: no hook
/// at all. There is no way to unregister one, and a hook that counted would
/// perturb the check that owns the counter.
fn on_tick_idle() {}

/// The periodic tick, watching a hot-pluggable slot.
///
/// **This exists because a removal cannot happen while ring 3 is running
/// otherwise.** A hot-pluggable slot does not simply lose its device: the port
/// raises an eject request and waits for the guest to answer, because the
/// software using the device is the only thing that knows whether it is
/// mid-transfer. The existing removal check answers in a boot loop, with no
/// thread alive — which is exactly the situation a driver is never in. During
/// `Scheduler::run` the boot CPU is inside the scheduler and nothing polls, so
/// `device_del` on a running machine is a request nobody ever answers and the
/// device stays. That was measured, not assumed.
///
/// The tick is the one thing that already fires during a run, so the guest's
/// half lives here. It does the same two things the boot loop does, in the same
/// order and for the same reasons: answer the request once, then watch config
/// space, because acknowledging is a request to de-energize the slot and what
/// makes a device *gone* is that it stops answering.
fn on_tick_watching_a_slot() {
    // **Deliberately not `OBSERVED_TICKS`.** That counter belongs to
    // `timer_check`, which waits on it and then compares it against the
    // architecture's own tick count — and the architecture's is reset by
    // `start_periodic` while this one never is. A hook that incremented it here
    // would leave that check already past its threshold before its timer had
    // ticked once, so it would compare a fresh hardware count against a stale
    // software one and fail. Found by doing exactly that. This watch counts its
    // own looks, in `SLOT_WATCH_POLLS`.
    let state = SLOT_WATCH_STATE.load(Ordering::SeqCst);
    if state != slot_watch::ARMED && state != slot_watch::ACKNOWLEDGED {
        return;
    }
    let buses = SLOT_WATCH_BUSES.load(Ordering::SeqCst);
    let host = tessera_pci::Host {
        ecam_base: SLOT_WATCH_ECAM.load(Ordering::SeqCst),
        ecam_len: SLOT_WATCH_ECAM_LEN.load(Ordering::SeqCst),
        first_bus: ((buses >> 8) & 0xff) as u8,
        last_bus: (buses & 0xff) as u8,
    };
    let mut config = EcamWindow {
        base: host.ecam_base,
    };
    let (Some(port), Some(device)) = (
        unpack_bdf(SLOT_WATCH_PORT.load(Ordering::SeqCst)),
        unpack_bdf(SLOT_WATCH_DEVICE.load(Ordering::SeqCst)),
    ) else {
        return;
    };
    SLOT_WATCH_POLLS.fetch_add(1, Ordering::SeqCst);

    match host.read(&config, device, 0) {
        // Still there. Answer the eject if one has been raised and this guest
        // has not answered yet — once, because the acknowledgement clears the
        // status bits and a second request would be a different removal.
        Ok(vendor) if vendor != 0xffff_ffff => {
            if state == slot_watch::ARMED
                && tessera_pci::eject_requested(&host, &config, port).unwrap_or(false)
                && tessera_pci::acknowledge_eject(&host, &mut config, port).is_ok()
            {
                SLOT_WATCH_STATE.store(slot_watch::ACKNOWLEDGED, Ordering::SeqCst);
            }
        }
        // Gone. Tell the graph, which is what invalidates the capabilities
        // naming it and wakes whoever was parked on its interrupt.
        _ => {
            let object =
                kcore::object::ObjectId::from_raw(SLOT_WATCH_OBJECT.load(Ordering::SeqCst));
            // SAFETY: transient raw access to the statics. The tick is an IRQ
            // and AArch64 masks interrupts on exception entry, so this cannot
            // preempt `el0_dispatch_hook` — which is the only other holder of
            // these — and the two never overlap. The state is moved to
            // `REMOVED` first, so a tick that arrived during this one would
            // return at the top rather than remove twice.
            unsafe {
                SLOT_WATCH_STATE.store(slot_watch::REMOVED, Ordering::SeqCst);
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    let processes = &mut *(&raw mut KCORE_PROCESSES);
                    let report = exec.remove_device(
                        object,
                        kcore::lifecycle::TransitionReason::Removed,
                        processes,
                        None,
                        None,
                    );
                    SLOT_WATCH_SUBTREE.store(report.subtree as u32, Ordering::SeqCst);
                }
            }
        }
    }
}

// --- Certification: a run of the checks, and the refusal it produces (D161) ---

const CERT_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d0);
const CERT_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d1);
const CERT_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d2);
const CERT_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d3);
const CERT_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d4);
const CERT_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d5);
const CERT_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d6);
const CERT_CERTIFIER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d7);
/// The bridge this check holds only so that something can be pulled out from
/// under a running machine.
const CERT_VICTIM_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x1d8);

/// Ticks to wait for a pull that was asked for from outside.
///
/// Twenty seconds at `TICK_HZ`, which is generous for a request the driving
/// script makes within a second of the armed marker — and short enough that the
/// cases where the pull never lands *fail* rather than crawl. It was two
/// hundred seconds first, and the two inversions that prove this mechanism both
/// took that long to report what they knew in the first tick: a bound sized so
/// nothing could ever hit it makes every negative result expensive.
const SLOT_WATCH_SETTLE: u32 = 2_000;

/// The root port and the bridge below it, if this machine has that shape.
///
/// Read off the bus numbers rather than the parent edges: a root port is a
/// bridge on the host's own first bus, and the switch is a bridge on any bus
/// below it. That is enough here because the topology is one of each — a
/// machine with two would need the edges, and a check that guessed between them
/// would be watching the wrong slot.
fn pullable_switch<'a>(
    first_bus: u8,
    functions: &'a [tessera_pci::Function],
) -> Option<(&'a tessera_pci::Function, &'a tessera_pci::Function)> {
    let bridges = || {
        functions
            .iter()
            .filter(|f| f.class_code >> 8 == RELAY_CLASS_BRIDGE >> 8)
    };
    let port = bridges().find(|f| f.bdf.bus == first_bus)?;
    let switch = bridges().find(|f| f.bdf.bus != first_bus)?;
    Some((port, switch))
}

const CERT_MANAGER_KSTACK_VA: u64 = 0xffff_000d_a000_0000;
const CERT_DRIVER_KSTACK_VA: u64 = 0xffff_000d_b000_0000;
const CERT_CERTIFIER_KSTACK_VA: u64 = 0xffff_000d_c000_0000;

/// **What boot tells the certifier it is certifying.**
///
/// A client observes behaviour and cannot observe identity: whoever answers its
/// channel is "the driver" from the inside, whatever it is, so a certificate a
/// client filled in for itself would be a certificate about nothing in
/// particular. Boot spawned the process and is what knows.
///
/// The low half of the manifest's driver signature. The record's `driver` field
/// is 32 bits and a signature is 64, which is survivable exactly because this
/// field was never the identity — the artifact's measurement is, which is why
/// the record carries a digest at all (build/README.md, D161).
const CERTIFIED_DRIVER_ID: usize = 0x6572_6100;

/// The class and contract version the certificate is about — the crypto class,
/// and the version its `Describe` reply names.
const CERTIFIED_DEVICE_CLASS: u32 = 10;
const CERTIFIED_CONTRACT_VERSION: u32 = 1;

/// The five checks this machine can make: the certifier's two, the two only
/// boot can see, and the one that happened before the machine existed.
const CERTIFIED_CHECKS_RAN: u32 = tessera_certification::Check::AbiConformance.bit()
    | tessera_certification::Check::ClassConformance.bit()
    | tessera_certification::Check::TraceSchema.bit()
    | tessera_certification::Check::SecurityPolicy.bit()
    | tessera_certification::Check::DmaFault.bit()
    | tessera_certification::Check::Power.bit()
    | tessera_certification::Check::SuspendResume.bit()
    | tessera_certification::Check::CrashRecovery.bit()
    | tessera_certification::Check::Fuzz.bit();

/// The one check this machine runs and this driver does not pass.
///
/// **A failure, deliberately, and not a check left unrun.** This rig cannot
/// contain the device under test: QEMU's SMMU does not translate for a
/// virtio-crypto function, on bus zero or behind a root port, so the driver's
/// grants come back as physical addresses. The honest answer to "is this
/// driver's DMA contained" is therefore *no*, and recording it as such is the
/// difference the certificate exists to keep — a check that failed and said why
/// is worth more than a check nobody ran, and collapsing the two would lose the
/// only thing distinguishing an unfit driver from an absent rig
/// (build/README.md, D166).
const CERTIFIED_CHECKS_FAILED: u32 = tessera_certification::Check::DmaFault.bit();

/// What one run of `certification_check` looked at.
///
/// Counts rather than a verdict, because the verdict is in the certificate and
/// the counts are what make it readable: "the records were well formed" and
/// "the driver held only what it was allowed" are both unfalsifiable from a log
/// that does not say how many of each there were.
struct CertificationCounts {
    trace_records: u32,
    capabilities: u32,
    unscoped_grants: u32,
    /// Ticks that looked at the slot while ring 3 was still running.
    slot_polls: u64,
    /// The certificate itself, encoded, so the verdict can leave this machine.
    ///
    /// Everything else here is a number a human reads in a log. This is the
    /// record a later boot on a different machine has to act on, and prose is
    /// not something a signed channel can admit a driver on.
    certificate: [u8; certification::Certificate::WIRE_SIZE],
}

/// Puts the certificate on the wire, as one line of hex.
///
/// **A verdict that cannot leave the machine that reached it is not evidence
/// for anything.** Every other line this boot prints is prose for a person; a
/// signed channel admits a driver on a record, and this is the only form of
/// this run's answer that a later boot on a different machine can act on.
/// Hex on the console because the console is the one channel a boot check
/// already has, and because a reader can see that nothing was added to it.
fn print_certificate(encoded: &[u8; certification::Certificate::WIRE_SIZE]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = [0u8; certification::Certificate::WIRE_SIZE * 2];
    for (index, byte) in encoded.iter().enumerate() {
        hex[index * 2] = DIGITS[usize::from(byte >> 4)];
        hex[index * 2 + 1] = DIGITS[usize::from(byte & 0xf)];
    }
    match core::str::from_utf8(&hex) {
        Ok(text) => kprintln!("certificate: {text}"),
        // Unreachable, every byte being an ASCII hex digit — but a kernel whose
        // verdict silently stopped travelling is worse than one that says the
        // rendering failed.
        Err(_) => kprintln!("certificate: FATAL: the record did not render"),
    }
}

/// Encodes the certificate a run produced, measuring the artifact it is about.
///
/// **The digest is what makes it evidence about bytes.** A certificate naming
/// only a driver is evidence about a name, and a name is what an attacker
/// substituting an image keeps. `api/update-channel` refuses an entry whose
/// image is all zero for exactly that reason, so the measurement is taken here
/// — where the bytes that ran are the bytes in hand — rather than being
/// attached later by whoever is assembling a manifest.
fn encoded_certificate(
    certificate: &tessera_certification::Certificate,
) -> Result<[u8; certification::Certificate::WIRE_SIZE], u32> {
    let digest = tessera_hash::sha256(crypto_driver_image::CRYPTO_DRIVER_ELF.as_slice());
    let record = certification::Certificate {
        size: certification::Certificate::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        driver: certificate.subject().driver,
        device_class: certificate.subject().class,
        contract_version: certificate.subject().contract_version,
        ran: certificate.ran(),
        passed: certificate.passed(),
        digest_algorithm: certification::CertificateDigest::Sha256,
        image: digest,
    };
    let mut out = [0u8; certification::Certificate::WIRE_SIZE];
    match tessera_isl_runtime::encode(&record, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(1455),
    }
}

/// What the binding manifest's crypto entry declares about a driver bound by
/// it, restated here because boot is where the comparison happens and the
/// manifest lives in a ring-3 manager.
///
/// **Restating it is the weak seam and it is stated rather than hidden.** The
/// honest arrangement is for the manager to report the entry it matched, which
/// needs a protocol that does not exist yet (build/README.md, D165). Until then
/// a disagreement between these two lines and the manager's table would make
/// this check compare a driver against a policy nobody applied.
const CERTIFIED_POLICY: tessera_policy_compliance::Declared = tessera_policy_compliance::Declared {
    configure: true,
    derive: false,
    domain: 1,
};

/// What the driver process actually holds, compared against that.
///
/// Read from the **process's own handle table** rather than from boot's memory
/// of what it installed. Those differ by exactly the thing worth finding: a
/// capability that arrived by transfer, from the manager, carrying rights
/// nobody at this end chose.
fn policy_compliance_of(process: usize) -> tessera_policy_compliance::Verdict {
    use tessera_policy_compliance::Held;
    const SLOTS: usize = 32;

    let mut audit = [(
        kcore::object::ObjectId::from_raw(0),
        kcore::rights::Rights::none(),
    ); SLOTS];
    // SAFETY: transient raw access to the static process table; a read, and
    // every thread is off-CPU.
    let count = unsafe {
        (*(&raw const KCORE_PROCESSES))
            .get(process)
            .map(|p| p.handles().audit(&mut audit))
            .unwrap_or(0)
    };
    let mut held = [Held {
        object: 0,
        rights: 0,
    }; SLOTS];
    for (slot, (object, rights)) in held.iter_mut().zip(audit.iter()).take(count) {
        *slot = Held {
            object: object.raw(),
            rights: rights.bits(),
        };
    }
    tessera_policy_compliance::check(&CERTIFIED_POLICY, &held[..count])
}

/// Whether the fuzz record this kernel was compiled with says anything.
///
/// **The outcome itself is entailed by this binary existing.** The evidence
/// record is a genrule output produced by a runner that exits non-zero on a
/// finding, and the kernel links it — so a kernel that fuzzed badly is a kernel
/// that did not build. Recording `Passed` here is reading a fact off the
/// artifact rather than asserting one.
///
/// What is still worth checking is that the record is *substantive*. A stubbed
/// evidence file would compile and link and say nothing, and "the fuzzing ran"
/// over zero targets is the same empty claim this whole facility exists to
/// refuse. So: targets exist, they got more inputs than there were targets, and
/// the run was two-sided — some inputs decoded and some were refused.
fn fuzz_evidence_is_substantive() -> bool {
    fuzz_evidence::TARGETS > 0
        && fuzz_evidence::INPUTS > fuzz_evidence::TARGETS
        && fuzz_evidence::ACCEPTED > 0
        && fuzz_evidence::ACCEPTED < fuzz_evidence::INPUTS
}

/// What this driver's own records say about its DMA.
///
/// **The certification question is prior to fault handling, and is not the same
/// one.** Every SMMU check in this tree proves the hardware refuses what it
/// should; none of them asks whether *this driver's* memory goes through an
/// aperture at all. A driver handed a physical address has no fault to handle,
/// because there is nothing for a fault to be raised against — so a driver
/// "certified for DMA-fault handling" on a machine that cannot contain it has
/// been certified for nothing.
///
/// `kernel_event.isl` already keeps the two apart, deliberately: a scoped grant
/// is a positive record rather than the absence of a warning.
#[derive(Clone, Copy, Default)]
struct DmaSummary {
    /// Grants that returned an IOVA the unit resolves for this device alone.
    scoped: u32,
    /// Grants that returned a physical address, because nothing translates for
    /// this device.
    unscoped: u32,
    /// Transactions the unit refused and attributed to this driver.
    faults: u32,
}

impl DmaSummary {
    /// Whether this driver's DMA is containable, and was contained.
    ///
    /// Requires at least one scoped grant. A driver that never asked for DMA
    /// has not shown that its DMA is scoped, and reading "no unscoped grants"
    /// off a driver that made none is the empty claim this facility refuses
    /// everywhere else.
    fn is_contained(&self) -> bool {
        self.scoped > 0 && self.unscoped == 0 && self.faults == 0
    }
}

/// Validates the trace records this driver caused, as `kernel_event.isl`
/// defines them.
///
/// **`tail` and not `drain`.** The ring is drained once per boot, by
/// `device_events_check`, and a reader that consumed it here would leave that
/// check nothing to read — the records would be judged and then be gone, which
/// is a worse trade than reading them twice.
///
/// Scoped to one process, because the question is what *this driver* emitted.
/// The machine's whole ring would fold in every earlier check's records and
/// answer a question nobody asked about a driver nobody is certifying.
fn trace_schema_of(process: u64) -> (tessera_trace_schema::Verdict, DmaSummary) {
    use kcore::event::{self, Component, EventKind, Severity};
    const SEEN: usize = 64;

    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut seen = [blank; SEEN];
    let n = event::tail(&mut seen);

    let mut records = [tessera_trace_schema::Record::default(); SEEN];
    let mut count = 0;
    for emitted in &seen[..n] {
        if emitted.process_id != process {
            continue;
        }
        records[count] = tessera_trace_schema::Record {
            size: emitted.size,
            version: emitted.version,
            kind: emitted.kind as u32,
            severity: emitted.severity as u32,
            component: emitted.component as u32,
            classification: emitted.classification as u32,
            timestamp: emitted.timestamp,
            process_id: emitted.process_id,
            correlation_lo: emitted.correlation_lo,
            correlation_hi: emitted.correlation_hi,
            args: [emitted.arg0, emitted.arg1, emitted.arg2, emitted.arg3],
        };
        count += 1;
    }

    // The same records read for a different question, from this one pass rather
    // than a second — for the reason `device_events_check` takes both its
    // summaries off one drain: the two readings are about the same run, and a
    // second pass could describe a machine that had moved on.
    let mut dma = DmaSummary::default();
    for record in &records[..count] {
        match record.kind {
            19 => dma.scoped += 1,
            18 => dma.unscoped += 1,
            22 => dma.faults += 1,
            _ => {}
        }
    }
    (tessera_trace_schema::validate(&records[..count]), dma)
}

/// What the certifier reports: the two checks it can make from inside a channel
/// both held, it refused to certify on them, the refusal named nine, and the
/// rules refused a forged record and a stale contract version in ring 3.
const CERTIFIER_EXPECTED: u64 = (0xc1 << 56)
    | (1 << 39)
    | (1 << 38)
    | (1 << 37)
    | (1 << 36)
    | (1 << 35)
    | (1 << 34)
    | (1 << 33)
    | (1 << 32)
    // AbiConformance, ClassConformance, Power and SuspendResume, and nothing
    // else.
    | 0b110
    | (1 << 7)
    | (1 << 4);

/// Proves **a runner that will not certify what it did not check**.
///
/// Every other check in this machine ends by reporting that something worked.
/// This one ends by reporting what was never asked. A ring-3 certifier runs the
/// two of the eleven checks a peer can make against a driver — the seven class
/// rules, and whether the driver's replies declare the shapes the reader
/// assumed — and both hold. It then refuses to issue a certificate, because
/// nine checks need a machine somebody is interfering with from outside, a
/// fuzzing engine, or a measurement rig, and none of those is here.
///
/// **The refusal is the property.** A runner that certified on two passing
/// checks would be hiding a failure that is not a driver bug: a rig that
/// stopped asking. The checks in this tree are scripts registered by hand, and
/// nothing notices a registration going missing except something built to.
fn certification_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
    pci: &tessera_devicetree::PciHost,
    functions: &[tessera_pci::Function],
    recovered: bool,
) -> Result<CertificationCounts, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1301u32)?;
        exec.device_register_identified(
            CERT_DEVICE_OBJ,
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
        .map_err(|_| 1302u32)?;
        exec.device_set_layout(CERT_DEVICE_OBJ, layout)
            .map_err(|_| 1303u32)?;

        let manager = exec.channel_create().map_err(|_| 1304u32)?;
        exec.bind_endpoint_object(manager.0, CERT_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, CERT_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1305u32)?;
        exec.bind_endpoint_object(service.0, CERT_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, CERT_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        CERT_MANAGER_KSTACK_VA,
        1,
        CERT_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1310,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        crypto_driver_elf(),
        CERT_DRIVER_KSTACK_VA,
        0,
        CERT_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1320,
    )?;
    // The certifier is told which driver this run is about, because it cannot
    // find out.
    let (certifier_idx, certifier_proc) = ring3_host_spawn(
        certifier_elf(),
        CERT_CERTIFIER_KSTACK_VA,
        CERTIFIED_DRIVER_ID,
        CERT_CERTIFIER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1330,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1301u32)?;
            manager
                .handles_mut()
                .install(CERT_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1311u32)?;
            manager
                .handles_mut()
                .install(
                    CERT_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1311u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1321u32)?;
            driver
                .handles_mut()
                .install(CERT_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1321u32)?;
            driver
                .handles_mut()
                .install(CERT_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1321u32)?;
        }
        processes
            .get_mut(certifier_proc)
            .ok_or(1331u32)?
            .handles_mut()
            .install(CERT_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1331u32)?;
    }

    // Taken before the run, because the trace check reads it after the process
    // it names has been reaped.
    // SAFETY: transient raw access to the static process table; nothing else
    // holds a reference across this read.
    let driver_pid = unsafe {
        (*(&raw const KCORE_PROCESSES))
            .get(driver_proc)
            .map(|process| process.id().raw() as u64)
    }
    .ok_or(1322u32)?;

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // **Something to pull while ring 3 runs.** A PCI-to-PCI bridge behind a
    // root port, registered in the graph and held by nobody: the certification
    // subject is the crypto driver, and pulling *its* device is the next step
    // rather than this one. What is being shown here is only that a slot can be
    // answered and a device removed from inside a run — with a victim whose
    // going disturbs nothing else, so a failure here is about the mechanism.
    let host = tessera_pci::Host {
        ecam_base: pci.ecam_base,
        ecam_len: pci.ecam_len,
        first_bus: pci.first_bus,
        last_bus: pci.last_bus,
    };
    let watched = pullable_switch(host.first_bus, functions);
    if let Some((port, switch)) = watched {
        // SAFETY: transient raw access to the static executive.
        unsafe {
            let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1307u32)?;
            exec.device_register_identified(
                CERT_VICTIM_OBJ,
                0,
                0,
                Rights::READ,
                kcore::devmgr::DeviceIdentity {
                    class_code: switch.class_code,
                    vendor: switch.vendor,
                    device: switch.device,
                    bdf: (u16::from(switch.bdf.bus) << 8)
                        | (u16::from(switch.bdf.device) << 3)
                        | u16::from(switch.bdf.function),
                    revision: switch.revision,
                    bus: kcore::devmgr::DeviceBus::Pci,
                },
            )
            .map_err(|_| 1308u32)?;
        }
        arm_slot_watch(&host, port.bdf, switch.bdf, CERT_VICTIM_OBJ);
        kprintln!(
            "certification-hotplug: armed — bridge {:02x}:{:02x}.{} in slot {:02x}:{:02x}.{}, awaiting a pull while ring 3 runs",
            switch.bdf.bus,
            switch.bdf.device,
            switch.bdf.function,
            port.bdf.bus,
            port.bdf.device,
            port.bdf.function
        );
        kcore::verdict::claims(&["cert.hotplug-armed"]);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // The tick watches the slot for the whole run. Restored afterwards, so no
    // later check inherits a hook looking at hardware it does not know about.
    tessera_karch_aarch64::set_tick_hook(on_tick_watching_a_slot);
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // How much the tick saw **while ring 3 was still running**, read before
    // anything below can add to it. A removal that only landed afterwards is a
    // different and weaker claim, and the two must not be reported as one.
    let polls_during_run = SLOT_WATCH_POLLS.load(Ordering::SeqCst);

    // The pull is driven from outside and does not wait for this machine's
    // scheduler to run out of work, so the run ending is not the removal
    // failing. The timer is still going and the hook still looks; this gives it
    // a bounded window with interrupts open.
    if watched.is_some() {
        for _ in 0..SLOT_WATCH_SETTLE {
            if SLOT_WATCH_STATE.load(Ordering::SeqCst) == slot_watch::REMOVED {
                break;
            }
            // SAFETY: unmasking and re-masking at EL1 is a PSTATE write on the
            // boot CPU, which owns the machine here. `wfi` returns on the next
            // tick, and a masked one would never arrive at all.
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
                core::arch::asm!("wfi", options(nomem, nostack));
                core::arch::asm!("msr daifset, #2", options(nomem, nostack));
            }
        }
    }

    tessera_karch_aarch64::stop_timer();
    // **Back to doing nothing, not back to `on_tick`.** No hook is installed
    // when this check runs — `timer_check` installs the counting one later, and
    // its counter is never reset — so leaving a counting hook behind would have
    // every ring-3 run after this one increment it, and that check would find
    // its threshold already crossed before its own timer had ticked once.
    tessera_karch_aarch64::set_tick_hook(on_tick_idle);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(1340);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Six separable claims, checked apart so a failure names which one.
    for (bit, which) in [
        (32u32, 1341u32),
        (33, 1342),
        (34, 1343),
        (35, 1344),
        (36, 1345),
        (37, 1346),
        (38, 1347),
        (39, 1349),
    ] {
        if report & (1 << bit) == 0 {
            return Err(which);
        }
    }
    // And exactly those two checks ran. A run that quietly recorded a third
    // would be the failure this whole facility is shaped against, so the mask
    // is compared rather than merely inspected for the two that matter.
    if report & 0xffff != CERTIFIER_EXPECTED & 0xffff {
        return Err(1348);
    }

    // **The check the certifier could not have made.** It holds one channel and
    // no view of the kernel's event ring, so the records this driver caused are
    // not something it could ever read — and a runner that only recorded what
    // one vantage could observe would be capped at that vantage forever. A
    // certificate aggregates outcomes from wherever they can be seen, so this
    // one is assembled here, from the certifier's two and boot's third.
    let (verdict, dma) = trace_schema_of(driver_pid);
    let mut runner = tessera_certification::Runner::new(tessera_certification::Subject {
        driver: CERTIFIED_DRIVER_ID as u32,
        class: CERTIFIED_DEVICE_CLASS,
        contract_version: CERTIFIED_CONTRACT_VERSION,
    });
    runner.record(
        tessera_certification::Check::AbiConformance,
        tessera_certification::Outcome::ran(report & (1 << 32) != 0),
    );
    runner.record(
        tessera_certification::Check::ClassConformance,
        tessera_certification::Outcome::ran(report & (1 << 33) != 0),
    );
    // Also the certifier's: power is a question a peer can ask, because it
    // holds the driver to its own `Describe` reply rather than to a wattmeter.
    runner.record(
        tessera_certification::Check::Power,
        tessera_certification::Outcome::ran(report & (1 << 38) != 0),
    );
    runner.record(
        tessera_certification::Check::SuspendResume,
        tessera_certification::Outcome::ran(report & (1 << 39) != 0),
    );
    runner.record(
        tessera_certification::Check::TraceSchema,
        tessera_certification::Outcome::ran(verdict.is_complete()),
    );
    runner.record(
        tessera_certification::Check::Fuzz,
        tessera_certification::Outcome::ran(fuzz_evidence_is_substantive()),
    );
    let policy = policy_compliance_of(driver_proc);
    runner.record(
        tessera_certification::Check::SecurityPolicy,
        tessera_certification::Outcome::ran(policy.is_compliant()),
    );
    runner.record(
        tessera_certification::Check::DmaFault,
        tessera_certification::Outcome::ran(dma.is_contained()),
    );
    runner.record(
        tessera_certification::Check::CrashRecovery,
        tessera_certification::Outcome::ran(recovered),
    );
    let certificate = runner.certificate();
    // A run that examined nothing must never read as a run that found nothing
    // wrong, so the count is a claim of its own and travels to the verdict line
    // — a reader who cannot see how much was looked at cannot weigh what was
    // found.
    if verdict.examined == 0 {
        return Err(1360);
    }
    if certificate.failures() != CERTIFIED_CHECKS_FAILED {
        // Which kind, so a failure names an event rather than the run.
        return Err(1349 + verdict.offending_kind.min(99));
    }
    if certificate.ran() != CERTIFIED_CHECKS_RAN {
        return Err(1449);
    }
    if certificate.is_certified() || certificate.missing().count_ones() != 2 {
        return Err(1450);
    }
    let encoded = encoded_certificate(&certificate)?;

    // The slot watch, as three separable facts. A machine with no pullable
    // bridge skips them, which a boot on a topology without one legitimately
    // is — and the script that drives the pull is what makes the difference
    // visible rather than this check assuming either way.
    if watched.is_some() {
        // The hook looked while ring 3 was still running. Without this the
        // whole mechanism could be a post-run poll wearing a tick's name.
        if polls_during_run == 0 {
            return Err(1451);
        }
        // The eject was answered by this guest. A device that left without the
        // slot ever asking would mean the watch was on the wrong port.
        if SLOT_WATCH_STATE.load(Ordering::SeqCst) == slot_watch::ARMED {
            return Err(1452);
        }
        if SLOT_WATCH_STATE.load(Ordering::SeqCst) != slot_watch::REMOVED {
            return Err(1453);
        }
        // And the graph acted rather than merely being told.
        if SLOT_WATCH_SUBTREE.load(Ordering::SeqCst) == 0 {
            return Err(1454);
        }
    }
    disarm_slot_watch();

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(certifier_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        CERT_CERTIFIER_KSTACK_VA,
        CERT_DRIVER_KSTACK_VA,
        CERT_MANAGER_KSTACK_VA,
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
        for proc_idx in [certifier_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(CertificationCounts {
        trace_records: verdict.examined,
        capabilities: policy.examined,
        unscoped_grants: dma.unscoped,
        slot_polls: polls_during_run,
        certificate: encoded,
    })
}

// --- GPIO: one interrupt line becoming eight, and a button pressed from
// outside the machine (D156) ---

const GPIO_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x160);
const GPIO_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x161);
const GPIO_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x162);
const GPIO_MANAGER_SERVER2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x163);
const GPIO_MANAGER_CLIENT2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x164);
const GPIO_IRQ_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x165);
const GPIO_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x166);
const GPIO_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x167);
const GPIO_CLIENT_A_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x168);
const GPIO_CLIENT_B_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x169);
/// The two service channels the driver serves, one per client.
const GPIO_SERVICE_A_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16a);
const GPIO_SERVICE_A_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16b);
const GPIO_SERVICE_B_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16c);
const GPIO_SERVICE_B_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16d);
/// One port per line, at consecutive object ids.
const GPIO_LINE_PORT_BASE: u32 = 0x170;
/// The platform bus, and the process that walks it.
const PLATFORM_BUS_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16e);
const PLATFORM_BUS_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16f);
const PLATFORM_BUS_KSTACK_VA: u64 = 0xffff_0009_e000_0000;

/// **What this bus forwards**, and therefore what it may declare devices in.
/// The `virt` machine's peripheral region: the console, the RTC, the GPIO
/// controller and the firmware configuration port. Deliberately not the
/// virtio-mmio transports a megabyte further up — a bus is granted a range and
/// a controller that wanted more would have to be given more, which is the
/// whole point of the range being on the capability.
const PLATFORM_FORWARD_BASE: u64 = 0x0900_0000;
const PLATFORM_FORWARD_LEN: u64 = 0x0004_0000;
/// The interrupt lines it may declare from: the first sixteen shared
/// peripheral interrupts, which is where this machine's peripherals sit.
const PLATFORM_FIRST_INTID: u32 = 32;
const PLATFORM_INTID_COUNT: u32 = 16;

/// The class code the bus controller declares a GPIO controller with — how
/// boot recognises which of the devices it declared is the one to route,
/// without knowing what a PL061 is or where it lives.
const PLATFORM_CLASS_GPIO: u32 = 0x08_8000;

const GPIO_MANAGER_KSTACK_VA: u64 = 0xffff_0009_a000_0000;
const GPIO_DRIVER_KSTACK_VA: u64 = 0xffff_0009_b000_0000;
const GPIO_CLIENT_A_KSTACK_VA: u64 = 0xffff_0009_c000_0000;
const GPIO_CLIENT_B_KSTACK_VA: u64 = 0xffff_0009_d000_0000;

/// The line QEMU's `virt` wires its power button to, and the one client A
/// watches. Read from the machine's own device tree — `gpio-keys/poweroff`
/// names `<&pl061 3 0>` — rather than chosen.
const GPIO_BUTTON_LINE: u32 = 3;
/// The line client B watches, which nothing is wired to. **The load-bearing
/// half of the check**: it must not wake.
const GPIO_QUIET_LINE: u32 = 5;

/// What a client reports: a tag, the line it watched, whether it was granted an
/// interrupt object, and whether that object fired naming its own line.
const GPIO_CLIENT_TAG: u64 = 0x91 << 56;
const GPIO_REPORT_WOKEN: u64 = 1 << 32;
const GPIO_REPORT_GRANTED: u64 = 1 << 33;
const GPIO_A_EXPECTED: u64 =
    GPIO_CLIENT_TAG | ((GPIO_BUTTON_LINE as u64) << 40) | GPIO_REPORT_GRANTED | GPIO_REPORT_WOKEN;

/// Proves **an interrupt object for something no interrupt controller can
/// see**.
///
/// A PL061 has eight lines and one interrupt output. A ring-3 driver binds it
/// — a platform device, on neither PCI nor virtio-mmio, that said what it was
/// through its own PrimeCell registers because there is nowhere else to look —
/// and hands each watching client a capability to *its* line. Two clients watch
/// two lines and park.
///
/// Then a button is pressed from outside the machine, over QMP, and exactly one
/// of them wakes. The one that does not is what makes the demultiplex real: a
/// mechanism that broadcast, or a driver that read the raw status instead of
/// the masked one, would wake both and neither client could tell.
fn gpio_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    dtb: u64,
    dtb_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(801u32)?;
        // **The bus, and its configuration space is the device tree.** Boot
        // grants the blob as the bus capability's window — the same
        // relationship a PCI host bridge has to ECAM — and nothing else about
        // the machine. What is in the tree is the controller's to find.
        exec.device_register_identified(
            PLATFORM_BUS_OBJ,
            dtb,
            dtb_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
            kcore::devmgr::DeviceIdentity {
                // A bridge, which is what a bus is to anything looking at it.
                class_code: 0x06_0000,
                vendor: 0,
                device: 0,
                bdf: 0,
                revision: 0,
                // **And the kind everything behind it inherits.** A device
                // declared here is on the platform bus, which is a binding
                // input in its own right: a driver written for one transport
                // cannot drive a device on another, and the graph saying "PCI"
                // about a device tree node would offer it to the wrong ones.
                bus: kcore::devmgr::DeviceBus::Platform,
            },
        )
        .map_err(|_| 802u32)?;
        exec.device_set_bus_window(
            PLATFORM_BUS_OBJ,
            kcore::devmgr::BusWindow {
                // How much of the blob the controller may read, which is what
                // it is told its own window is.
                config_len: dtb_len,
                forward_cpu_base: PLATFORM_FORWARD_BASE,
                forward_bus_base: PLATFORM_FORWARD_BASE,
                forward_len: PLATFORM_FORWARD_LEN,
                first_bus: 0,
                last_bus: 0,
                // **The wires it may hand out.** A range on the capability, so
                // a controller that declared a device on a line outside it is
                // refused rather than trusted.
                first_intid: PLATFORM_FIRST_INTID,
                intid_count: PLATFORM_INTID_COUNT,
            },
        )
        .map_err(|_| 803u32)?;

        let manager = exec.channel_create().map_err(|_| 804u32)?;
        exec.bind_endpoint_object(manager.0, GPIO_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, GPIO_MANAGER_CLIENT_OBJ);
        let manager2 = exec.channel_create().map_err(|_| 804u32)?;
        exec.bind_endpoint_object(manager2.0, GPIO_MANAGER_SERVER2_OBJ);
        exec.bind_endpoint_object(manager2.1, GPIO_MANAGER_CLIENT2_OBJ);
        let service_a = exec.channel_create().map_err(|_| 805u32)?;
        exec.bind_endpoint_object(service_a.0, GPIO_SERVICE_A_SERVER_OBJ);
        exec.bind_endpoint_object(service_a.1, GPIO_SERVICE_A_CLIENT_OBJ);
        let service_b = exec.channel_create().map_err(|_| 806u32)?;
        exec.bind_endpoint_object(service_b.0, GPIO_SERVICE_B_SERVER_OBJ);
        exec.bind_endpoint_object(service_b.1, GPIO_SERVICE_B_CLIENT_OBJ);

        // The driver's own hardware interrupt.
        let irq_port = exec.port_create().map_err(|_| 807u32)?;
        exec.bind_port_object(irq_port, GPIO_IRQ_PORT_OBJ);

        // **One port per line, bound to that line as its source.** The binding
        // is what a `PortSignal` holder may raise, so what the driver can wake
        // was decided here and not by the number it passes.
        for line in 0..u32::from(tessera_pl061::LINES) {
            let port = exec.port_create().map_err(|_| 808u32)?;
            exec.bind_port_object(
                port,
                kcore::object::ObjectId::from_raw(GPIO_LINE_PORT_BASE + line),
            );
            exec.port_bind(port, u64::from(line), kcore::exec::SOFTWARE_PORT_SIGNAL)
                .map_err(|_| 809u32)?;
        }
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        GPIO_MANAGER_KSTACK_VA,
        // **No devices granted at all.** Everything this manager holds arrives
        // as an offer from the bus controller, which is what "enumeration
        // happens outside the kernel" means when it is finished rather than
        // half done. Two service endpoints, one per caller.
        1 << 56,
        GPIO_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        810,
    )?;
    let (bus_idx, bus_proc) = ring3_host_spawn(
        platform_bus_elf(),
        PLATFORM_BUS_KSTACK_VA,
        0,
        PLATFORM_BUS_PROC_OBJ,
        &mut kernel_space,
        frames,
        860,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        gpio_driver_elf(),
        GPIO_DRIVER_KSTACK_VA,
        0,
        GPIO_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        820,
    )?;
    let (client_a_idx, client_a_proc) = ring3_host_spawn(
        gpio_client_elf(),
        GPIO_CLIENT_A_KSTACK_VA,
        GPIO_BUTTON_LINE as usize,
        GPIO_CLIENT_A_PROC_OBJ,
        &mut kernel_space,
        frames,
        830,
    )?;
    let (client_b_idx, client_b_proc) = ring3_host_spawn(
        gpio_client_elf(),
        GPIO_CLIENT_B_KSTACK_VA,
        GPIO_QUIET_LINE as usize,
        GPIO_CLIENT_B_PROC_OBJ,
        &mut kernel_space,
        frames,
        840,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(811u32)?;
            manager
                .handles_mut()
                .install(GPIO_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 811u32)?;
            manager
                .handles_mut()
                .install(GPIO_MANAGER_SERVER2_OBJ, Rights::READ)
                .map_err(|_| 811u32)?;
        }
        {
            let bus = processes.get_mut(bus_proc).ok_or(861u32)?;
            bus.handles_mut()
                .install(GPIO_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 861u32)?;
            bus.handles_mut()
                .install(
                    PLATFORM_BUS_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
                )
                .map_err(|_| 861u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(821u32)?;
            driver
                .handles_mut()
                .install(GPIO_MANAGER_CLIENT2_OBJ, Rights::WRITE)
                .map_err(|_| 821u32)?;
            driver
                .handles_mut()
                .install(GPIO_SERVICE_A_SERVER_OBJ, Rights::READ)
                .map_err(|_| 821u32)?;
            driver
                .handles_mut()
                .install(GPIO_SERVICE_B_SERVER_OBJ, Rights::READ)
                .map_err(|_| 821u32)?;
            driver
                .handles_mut()
                .install(GPIO_IRQ_PORT_OBJ, Rights::READ)
                .map_err(|_| 821u32)?;
            // **Two handles to each line's port.** One carries `SIGNAL` and
            // stays; the other carries `READ` and `TRANSFER` and is what the
            // driver hands to the client that watches the line. A transfer
            // moves a handle out of the sender's table, so a driver holding one
            // would give away the capability it needs in order to signal.
            for line in 0..u32::from(tessera_pl061::LINES) {
                let object = kcore::object::ObjectId::from_raw(GPIO_LINE_PORT_BASE + line);
                driver
                    .handles_mut()
                    .install(object, Rights::SIGNAL)
                    .map_err(|_| 822u32)?;
            }
            for line in 0..u32::from(tessera_pl061::LINES) {
                let object = kcore::object::ObjectId::from_raw(GPIO_LINE_PORT_BASE + line);
                driver
                    .handles_mut()
                    .install(object, Rights::READ | Rights::TRANSFER)
                    .map_err(|_| 823u32)?;
            }
        }
        processes
            .get_mut(client_a_proc)
            .ok_or(831u32)?
            .handles_mut()
            .install(GPIO_SERVICE_A_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 831u32)?;
        processes
            .get_mut(client_b_proc)
            .ok_or(841u32)?
            .handles_mut()
            .install(GPIO_SERVICE_B_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 841u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);

    // **Enumeration first, and then the route.** The bus controller walks the
    // tree, declares what it found and offers it to the manager, and every
    // program below waits on something that does not exist until it has. So it
    // runs to completion before anything else does — which it can, because
    // `run` returns when nothing is runnable and the manager parks between
    // requests.
    // SAFETY: transient raw access; `run` returns when no thread is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    // What the walk did with the machine it read, checked before the counters
    // are reused for the second act. Two devices declared — the GPIO
    // controller and the real-time clock — one withheld, and the transports a
    // megabyte above what this bus forwards counted as beyond its reach rather
    // than dropped in silence.
    let walked = EL0_REPORTS[0].load(Ordering::SeqCst);
    if walked >> 56 != 0x70 {
        return Err(827);
    }
    if (walked >> 32) & 0xffff != 2 {
        return Err(828);
    }
    if (walked >> 16) & 0xffff != 1 {
        return Err(829);
    }
    if walked & 0xffff == 0 {
        return Err(830);
    }
    // The second act's reports are the ones the verdict is about.
    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // **Routed from the graph, not from knowledge of the device.** This is the
    // one privileged step left, and it is worth being exact about what it
    // knows: boot asks the bus what is behind it, takes the child whose class
    // code says input, and routes whatever line the graph records for it. It
    // never learns what a PL061 is, where it lives, or which SPI it uses — a
    // driver cannot yet ask for its own route, and this is what stands in for
    // that until it can.
    // SAFETY: transient raw access to the static executive.
    let intid = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(824u32)?;
        let mut children = [kcore::object::ObjectId::from_raw(0); kcore::devmgr::MAX_DEVICES];
        let count = exec.device_children_of(PLATFORM_BUS_OBJ, &mut children);
        let mut routed = None;
        for child in &children[..count] {
            let Some(identity) = exec.identity_of_object(*child) else {
                continue;
            };
            if identity.class_code != PLATFORM_CLASS_GPIO {
                continue;
            }
            let mut lines = [0u32; 1 + kcore::devmgr::MAX_EXTRA_IRQS];
            if exec.intids_of_object(*child, &mut lines) == 0 {
                continue;
            }
            let port = exec.port_of_object(GPIO_IRQ_PORT_OBJ).ok_or(824u32)?;
            exec.device_route_irq_line(*child, lines[0], port, GPIO_DRIVER_PROC_OBJ)
                .map_err(|_| 825u32)?;
            routed = Some(lines[0]);
            break;
        }
        // Nothing behind the bus interrupts the way a GPIO controller does, so
        // there is nothing to prove and no line to enable.
        routed.ok_or(826u32)?
    };

    RING3_DRIVER_INTID.store(intid, Ordering::SeqCst);
    // SAFETY: enabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::enable_irq(intid) };
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);

    // The second run takes every thread to where it waits: the clients on their
    // line ports, the driver on its interrupt. Then the check says it is armed
    // — the button is pressed from outside the machine, and it cannot be
    // pressed before there is something to hear it.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // gpio: armed — two clients hold interrupt objects for lines
    // {GPIO_BUTTON_LINE} and {GPIO_QUIET_LINE}, waiting for a button press
    // from outside the machine
    kprintln!(
        "gpio: armed — gpio button line={GPIO_BUTTON_LINE}, gpio quiet line={GPIO_QUIET_LINE}"
    );
    kcore::verdict::claims(&["gpio.armed"]);

    // The interrupt pump (D84/D85): the press is asynchronous and lands after
    // every thread has parked, so `run()` returns with nothing runnable and the
    // wake would be orphaned. Boot is the idle loop, and it must unmask every
    // iteration — `wfi` returns from a pending-but-masked interrupt without
    // ever taking it.
    // **Bounded, because most boots have nobody to press the button.** A
    // PL061 is on every `virt` machine, so this check runs on every aarch64
    // boot — and only the one driven over QMP presses anything. Running out is
    // therefore not a failure: it is "nobody pressed", which the caller reports
    // as a skip. Long enough for a press that is coming, short enough that a
    // boot with none pays a few seconds.
    let done = || EL0_REPORT_COUNT.load(Ordering::SeqCst) > 0;
    let mut pump_budget = 400u32;
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
        // SAFETY: the boot context owns the CPU here; the only handler that can
        // run is the interrupt bridge, which touches atomics and the port
        // facility, never the Executive borrow `run` just released.
        <Cpu as tessera_karch::InterruptControl>::enable();
        Cpu::halt_until_interrupt();
        <Cpu as tessera_karch::InterruptControl>::disable();
    }
    tessera_karch_aarch64::stop_timer();
    // SAFETY: disabling a GIC line is an interrupt-controller register write.
    unsafe { tessera_karch_aarch64::disable_irq(intid) };
    RING3_DRIVER_INTID.store(0, Ordering::SeqCst);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(850);
    }
    // **Exactly one report, and it is the client whose line was pressed.** The
    // other client is still parked, which is the whole claim: a mechanism that
    // broadcast, or a driver reading the raw status instead of the masked one,
    // would have woken both.
    let reports = EL0_REPORT_COUNT.load(Ordering::SeqCst);
    let first = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Nobody pressed anything, which is every boot but the one driven over QMP.
    // Reported as such rather than as a failure: what would be wrong is a press
    // that reached the wrong client, and no press reached nobody.
    let pressed = reports > 0;
    if pressed {
        if first != GPIO_A_EXPECTED {
            return Err(851);
        }
        if reports != 1 {
            return Err(852);
        }
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_b_idx);
            exec.scheduler().reap(client_a_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(bus_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        GPIO_CLIENT_B_KSTACK_VA,
        GPIO_CLIENT_A_KSTACK_VA,
        GPIO_DRIVER_KSTACK_VA,
        PLATFORM_BUS_KSTACK_VA,
        GPIO_MANAGER_KSTACK_VA,
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
        for proc_idx in [
            client_b_proc,
            client_a_proc,
            driver_proc,
            bus_proc,
            manager_proc,
        ] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(if pressed { first } else { 0 })
}

// --- USB: a relaying bus host, a deep tree, and a device that is refused (D155) ---

const USB_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x140);
const USB_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x141);
const USB_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x142);
/// **One service channel per driver that calls.** A channel carries one
/// outstanding call, so two drivers blocked on the same one is a reply going to
/// whichever the kernel wakes first — a driver handed another driver's device.
/// This is the first machine here with more than one driver binding at once.
const USB_MANAGER_SERVER2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14f);
const USB_MANAGER_CLIENT2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x150);
const USB_MANAGER_SERVER3_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x151);
const USB_MANAGER_CLIENT3_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x152);
const USB_HOST_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x143);
const USB_HOST_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x144);
const USB_BLK_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x145);
const USB_BLK_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x146);
const USB_INPUT_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x147);
const USB_INPUT_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x148);
const USB_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x149);
const USB_HOST_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14a);
const USB_STORAGE_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14b);
const USB_HID_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14c);
const USB_BLK_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14d);
const USB_INPUT_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x14e);

const USB_MANAGER_KSTACK_VA: u64 = 0xffff_0008_a000_0000;
const USB_HOST_KSTACK_VA: u64 = 0xffff_0008_b000_0000;
const USB_STORAGE_KSTACK_VA: u64 = 0xffff_0008_c000_0000;
const USB_HID_KSTACK_VA: u64 = 0xffff_0008_d000_0000;
const USB_BLK_KSTACK_VA: u64 = 0xffff_0008_e000_0000;
const USB_INPUT_KSTACK_VA: u64 = 0xffff_0008_f000_0000;

/// A USB host controller on PCI: serial bus controller, subclass USB. Matched
/// on both bytes, because the base byte covers FireWire, SMBus and CAN as well.
const PCI_CLASS_XHCI: u32 = 0x0c03;

/// What `blk-client` reports when it read the disk and the suite came back
/// complete: the disk magic rotated by its id, as on every other transport.
const USB_BLK_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8);

/// What `input-client` reports. The three bits are separable claims and are
/// checked apart: the suite came back complete, an idle keyboard answered
/// `NO_REPORT` rather than failing, and a report was read back through the
/// relay. The low byte is the HID protocol the device declared, which is a
/// keyboard.
const USB_INPUT_EXPECTED: u64 = (0x1d << 56) | (1 << 34) | (1 << 33) | (1 << 32) | 1;

/// Proves **a bus whose devices have no registers**: the relaying host
/// `docs/drivers/01` describes, which nothing in this tree has been.
///
/// Four programs and two contracts. A ring-3 host binds the xHCI controller,
/// walks the root ports and a hub, addresses what it finds, and puts every
/// device in the resource graph — hubs as buses with devices behind them, so
/// the graph is three levels deep where it has only ever been two. Two class
/// drivers then serve `tessera.driver.block` and `tessera.driver.input` off
/// devices they cannot touch: neither maps anything, because there is nothing
/// to map, and every byte they move crosses the host.
///
/// And one attached device is **refused**. Its class is not on the host's
/// allowlist, so it enumerates perfectly and is declared into the graph with a
/// class code no manifest entry claims — visible, and in nobody's hands. That
/// is the first policy here that turns away something that works.
fn usb_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(700);
    };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(701u32)?;
        exec.device_register_identified(
            USB_DEVICE_OBJ,
            bar_base,
            bar_len,
            // DERIVE, because this controller's children are devices and its
            // driver is what puts them in the graph — and its children's
            // children are too, which is what a hub is.
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
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
        .map_err(|_| 702u32)?;
        // A bus that forwards nothing and has no configuration window for its
        // children: a USB device owns no memory, and a declaration naming a
        // register window is refused. The same shape the SD controller has, and
        // the reason a hub declared behind this one can hold devices of its own.
        exec.device_set_bus_window(USB_DEVICE_OBJ, kcore::devmgr::BusWindow::default())
            .map_err(|_| 703u32)?;

        let manager = exec.channel_create().map_err(|_| 704u32)?;
        exec.bind_endpoint_object(manager.0, USB_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, USB_MANAGER_CLIENT_OBJ);
        let manager2 = exec.channel_create().map_err(|_| 704u32)?;
        exec.bind_endpoint_object(manager2.0, USB_MANAGER_SERVER2_OBJ);
        exec.bind_endpoint_object(manager2.1, USB_MANAGER_CLIENT2_OBJ);
        let manager3 = exec.channel_create().map_err(|_| 704u32)?;
        exec.bind_endpoint_object(manager3.0, USB_MANAGER_SERVER3_OBJ);
        exec.bind_endpoint_object(manager3.1, USB_MANAGER_CLIENT3_OBJ);
        let host = exec.channel_create().map_err(|_| 705u32)?;
        exec.bind_endpoint_object(host.0, USB_HOST_SERVER_OBJ);
        exec.bind_endpoint_object(host.1, USB_HOST_CLIENT_OBJ);
        let block = exec.channel_create().map_err(|_| 706u32)?;
        exec.bind_endpoint_object(block.0, USB_BLK_SERVER_OBJ);
        exec.bind_endpoint_object(block.1, USB_BLK_CLIENT_OBJ);
        let input = exec.channel_create().map_err(|_| 707u32)?;
        exec.bind_endpoint_object(input.0, USB_INPUT_SERVER_OBJ);
        exec.bind_endpoint_object(input.1, USB_INPUT_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        USB_MANAGER_KSTACK_VA,
        // One device granted, and two service endpoints beyond the first. The
        // extras are installed *after* the device handles, so the device base
        // is where every other check leaves it.
        1 | (2 << 56),
        USB_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        710,
    )?;
    let (host_idx, host_proc) = ring3_host_spawn(
        usb_host_elf(),
        USB_HOST_KSTACK_VA,
        0,
        USB_HOST_PROC_OBJ,
        &mut kernel_space,
        frames,
        720,
    )?;
    let (storage_idx, storage_proc) = ring3_host_spawn(
        usb_storage_elf(),
        USB_STORAGE_KSTACK_VA,
        0,
        USB_STORAGE_PROC_OBJ,
        &mut kernel_space,
        frames,
        730,
    )?;
    let (hid_idx, hid_proc) = ring3_host_spawn(
        usb_hid_elf(),
        USB_HID_KSTACK_VA,
        0,
        USB_HID_PROC_OBJ,
        &mut kernel_space,
        frames,
        740,
    )?;
    // The same client program that judges virtio, NVMe and SD, with the same
    // argument. Nothing about it knows this disk is reached through two other
    // processes, which is the whole claim.
    let (blk_idx, blk_proc) = ring3_host_spawn(
        blk_client_elf(),
        USB_BLK_KSTACK_VA,
        1,
        USB_BLK_PROC_OBJ,
        &mut kernel_space,
        frames,
        750,
    )?;
    let (input_idx, input_proc) = ring3_host_spawn(
        input_client_elf(),
        USB_INPUT_KSTACK_VA,
        0,
        USB_INPUT_PROC_OBJ,
        &mut kernel_space,
        frames,
        760,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(711u32)?;
            manager
                .handles_mut()
                .install(USB_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 711u32)?;
            manager
                .handles_mut()
                .install(
                    USB_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
                )
                .map_err(|_| 711u32)?;
            manager
                .handles_mut()
                .install(USB_MANAGER_SERVER2_OBJ, Rights::READ)
                .map_err(|_| 711u32)?;
            manager
                .handles_mut()
                .install(USB_MANAGER_SERVER3_OBJ, Rights::READ)
                .map_err(|_| 711u32)?;
        }
        {
            let host = processes.get_mut(host_proc).ok_or(721u32)?;
            host.handles_mut()
                .install(USB_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 721u32)?;
            host.handles_mut()
                .install(USB_HOST_SERVER_OBJ, Rights::READ)
                .map_err(|_| 721u32)?;
        }
        {
            let storage = processes.get_mut(storage_proc).ok_or(731u32)?;
            storage
                .handles_mut()
                .install(USB_MANAGER_CLIENT2_OBJ, Rights::WRITE)
                .map_err(|_| 731u32)?;
            storage
                .handles_mut()
                .install(USB_HOST_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 731u32)?;
            storage
                .handles_mut()
                .install(USB_BLK_SERVER_OBJ, Rights::READ)
                .map_err(|_| 731u32)?;
        }
        {
            let hid = processes.get_mut(hid_proc).ok_or(741u32)?;
            hid.handles_mut()
                .install(USB_MANAGER_CLIENT3_OBJ, Rights::WRITE)
                .map_err(|_| 741u32)?;
            hid.handles_mut()
                .install(USB_HOST_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 741u32)?;
            hid.handles_mut()
                .install(USB_INPUT_SERVER_OBJ, Rights::READ)
                .map_err(|_| 741u32)?;
        }
        processes
            .get_mut(blk_proc)
            .ok_or(751u32)?
            .handles_mut()
            .install(USB_BLK_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 751u32)?;
        processes
            .get_mut(input_proc)
            .ok_or(761u32)?
            .handles_mut()
            .install(USB_INPUT_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 761u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(770);
    }
    // Two clients, two contracts, and both are load-bearing: the block report
    // is byte-identical to what virtio, NVMe and SD produce, and the input one
    // carries three separable claims that are checked apart.
    let mut block = 0u64;
    let mut input = 0u64;
    for report in &EL0_REPORTS {
        let value = report.load(Ordering::SeqCst);
        if value == USB_BLK_EXPECTED {
            block = value;
        } else if value >> 56 == 0x1d {
            input = value;
        }
    }
    if block != USB_BLK_EXPECTED {
        return Err(771);
    }
    if input & (1 << 32) == 0 {
        return Err(772);
    }
    if input & (1 << 33) == 0 {
        return Err(773);
    }
    if input & (1 << 34) == 0 {
        return Err(774);
    }
    if input != USB_INPUT_EXPECTED {
        return Err(775);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(input_idx);
            exec.scheduler().reap(blk_idx);
            exec.scheduler().reap(hid_idx);
            exec.scheduler().reap(storage_idx);
            exec.scheduler().reap(host_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        USB_INPUT_KSTACK_VA,
        USB_BLK_KSTACK_VA,
        USB_HID_KSTACK_VA,
        USB_STORAGE_KSTACK_VA,
        USB_HOST_KSTACK_VA,
        USB_MANAGER_KSTACK_VA,
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
        for proc_idx in [
            input_proc,
            blk_proc,
            hid_proc,
            storage_proc,
            host_proc,
            manager_proc,
        ] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(input)
}

// --- MMC/SD: a controller with card children, and a medium that can go (D154) ---

const SD_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x120);
const SD_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x121);
const SD_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x122);
const SD_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x123);
const SD_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x124);
const SD_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x125);
const SD_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x126);
const SD_CLIENT_A_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x127);
const SD_CLIENT_B_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x128);

const SD_MANAGER_KSTACK_VA: u64 = 0xffff_0007_a000_0000;
const SD_DRIVER_KSTACK_VA: u64 = 0xffff_0007_b000_0000;
const SD_CLIENT_A_KSTACK_VA: u64 = 0xffff_0007_c000_0000;
const SD_CLIENT_B_KSTACK_VA: u64 = 0xffff_0007_d000_0000;

/// An SD host controller on PCI: system peripheral, subclass SD. Matched on
/// both bytes because the base byte is a category shared with interrupt
/// controllers and timers.
const PCI_CLASS_SD_HOST: u32 = 0x0805;

/// The startup argument asking `blk-client` to wait for the medium to go
/// rather than to read something that must succeed. Must match `MEDIUM_GONE`
/// there.
const BLK_CLIENT_MEDIUM_GONE: usize = 1 << 58;

/// What the first client reports: the disk magic rotated by its id.
const SD_CLIENT_EXPECTED: u64 = u64::from_le_bytes(*b"TESSERAV").rotate_left(8);
/// What the second reports when it saw the card leave.
const SD_GONE_EXPECTED: u64 = 0x5344 << 48;

/// Proves **a controller with card children, card-detect hotplug, and a clock
/// that is requested rather than written** — `docs/drivers/04` and the
/// removable half of the block class.
///
/// Runs in two acts, because the interesting one needs the first to have
/// finished:
///
/// 1. With a card in the slot, a ring-3 driver identifies it, **declares it
///    into the resource graph** — a device the kernel has never seen, on a bus
///    it does not know — and serves the block class over it. `blk-client`, the
///    same program that judges virtio and NVMe, reads and runs the conformance
///    suite.
/// 2. Then the check says it is armed and waits. The card is pulled from
///    outside the machine, and a second client loops on **the same request that
///    just succeeded** until the answer becomes `NO_MEDIUM` — a value the block
///    contract has carried since it was written and nothing could ever return,
///    because nothing here was removable.
fn sd_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, CpuOps, TimerControl};

    let Some((bar_base, bar_len)) = function
        .bars
        .iter()
        .flatten()
        .copied()
        .max_by_key(|(_, len)| *len)
    else {
        return Err(600);
    };

    // **Whether there is a card, read here rather than inferred from what the
    // driver reports.** The two boots this check runs under differ in exactly
    // one thing — a card in the slot or not — and a check that learned which
    // from the driver would be asking the thing under test.
    //
    // SAFETY: the PCI memory windows are mapped in the kernel's low half by
    // `map_pci_windows`, and the present-state register is a defined 32-bit
    // register inside this function's BAR.
    let card_present = unsafe {
        ((bar_base + tessera_sdhci::reg::PRESENT_STATE as u64) as *const u32).read_volatile()
            & (1 << 16)
            != 0
    };

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(601u32)?;
        exec.device_register_identified(
            SD_DEVICE_OBJ,
            bar_base,
            bar_len,
            // DERIVE, because this controller's children are devices and its
            // driver is what puts them in the graph. The manager narrows what
            // it hands on; this is what boot gives the manager to spend.
            Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
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
        .map_err(|_| 602u32)?;
        // **A bus that forwards nothing and has no configuration window for its
        // children.** That is what makes a card declarable at all: the kernel
        // records the controller as a bus whose children own no memory, and a
        // declaration naming a register window is refused.
        exec.device_set_bus_window(SD_DEVICE_OBJ, kcore::devmgr::BusWindow::default())
            .map_err(|_| 603u32)?;

        let manager = exec.channel_create().map_err(|_| 604u32)?;
        exec.bind_endpoint_object(manager.0, SD_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, SD_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 605u32)?;
        exec.bind_endpoint_object(service.0, SD_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, SD_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        SD_MANAGER_KSTACK_VA,
        1,
        SD_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        610,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        sd_host_elf(),
        SD_DRIVER_KSTACK_VA,
        0,
        SD_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        620,
    )?;
    // **The same client program either way**, and its argument is the only
    // difference: with a card it reads and runs the conformance suite, and
    // without one it asks for the same sector and requires the answer to be
    // `NO_MEDIUM`. One program, one contract, two machines.
    let (client_idx, client_proc) = ring3_host_spawn(
        blk_client_elf(),
        SD_CLIENT_A_KSTACK_VA,
        if card_present {
            1
        } else {
            BLK_CLIENT_MEDIUM_GONE
        },
        SD_CLIENT_A_PROC_OBJ,
        &mut kernel_space,
        frames,
        630,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(611u32)?;
            manager
                .handles_mut()
                .install(SD_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 611u32)?;
            manager
                .handles_mut()
                .install(
                    SD_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER | Rights::DERIVE,
                )
                .map_err(|_| 611u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(621u32)?;
            driver
                .handles_mut()
                .install(SD_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 621u32)?;
            driver
                .handles_mut()
                .install(SD_SERVER_OBJ, Rights::READ)
                .map_err(|_| 621u32)?;
        }
        processes
            .get_mut(client_proc)
            .ok_or(631u32)?
            .handles_mut()
            .install(SD_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 631u32)?;
    }

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // Cooperative throughout — calls, replies and an exit.
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(640);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    let expected = if card_present {
        SD_CLIENT_EXPECTED
    } else {
        SD_GONE_EXPECTED
    };
    if report != expected {
        return Err(641);
    }

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(client_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        SD_CLIENT_A_KSTACK_VA,
        SD_DRIVER_KSTACK_VA,
        SD_MANAGER_KSTACK_VA,
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
        for proc_idx in [client_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(u64::from(card_present))
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

/// Kernel stacks for the rebind check's processes, distinct from every other
/// EL0 window in this file.
const REBIND_MANAGER_KSTACK_VA: u64 = 0xffff_0002_0000_0000;
const REBIND_DRIVER1_KSTACK_VA: u64 = 0xffff_0002_1000_0000;
const REBIND_DRIVER2_KSTACK_VA: u64 = 0xffff_0002_2000_0000;
/// The crashing incarnations' window, **reused** across launches: supervision
/// here is synchronous, so one host is alive at a time and each crash's
/// reclaim frees the window before the next spawn takes it. The same discipline
/// the x86-64 supervisor has used since D51.
const REBIND_CRASH_KSTACK_VA: u64 = 0xffff_0002_3000_0000;

/// How many times a persistently crashing host is brought back here.
///
/// The kcore default; named locally so the give-up self-test can deliberately
/// run against a *smaller* one and have the budget, rather than its crash
/// countdown, be what stops the loop.
const DRIVER_RESTART_BUDGET: u32 = kcore::supervise::DEFAULT_RESTART_BUDGET;
/// This supervisor's give-up identity, so two supervisors giving up in one
/// boot stay distinguishable in the record stream.
const DRIVER_RESTART_GIVEUP_CODE: u64 = 178;

/// The startup-argument bit that asks `blk-probe` to crash once it holds its
/// device (`userspace/blk-probe`'s `CRASH_AFTER_BIND`).
///
/// Duplicated here rather than shared through `uabi` because it is a fact
/// about **one program's** entry contract, not about the ABI: a second
/// crashing driver would choose its own, and putting it in the shared header
/// would imply every driver understands it.
const BLK_PROBE_CRASH_AFTER_BIND: u64 = 1 << 63;

/// Runs one host that is asked to crash, contains it, records the ladder's
/// first and sixth steps, and reclaims the corpse.
///
/// Returns whether the host actually faulted. `false` means it exited or never
/// got there, which the caller must treat as a failure rather than as a
/// recovery — a supervisor that reports restarting a host that never crashed
/// is reporting work it did not do.
///
/// **The supervisor names no device.** It does not know what this driver held
/// and does not need to: `reclaim_devices` hands whatever it was holding back
/// to the manager, which is what makes forgetting impossible rather than
/// merely unlikely.
#[allow(clippy::too_many_arguments)]
fn supervise_one_crash(
    supervisor: &mut kcore::supervise::RestartSupervisor,
    kstack: u64,
    proc_obj: kcore::object::ObjectId,
    device_obj: kcore::object::ObjectId,
    manager_client_obj: kcore::object::ObjectId,
    manager_client_ep: kcore::ipc::EndpointId,
    kernel_space: &mut kcore::vm::AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    base_err: u32,
) -> Result<bool, u32> {
    use kcore::rights::Rights;

    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_SINK_FAULT_ADDR.store(0, Ordering::SeqCst);
    EL0_SINK_FAULT_CORRELATION.store(0, Ordering::SeqCst);

    let (idx, proc) = ring3_host_spawn(
        blk_probe_elf(),
        kstack,
        BLK_PROBE_CRASH_AFTER_BIND as usize,
        proc_obj,
        kernel_space,
        frames,
        base_err,
    )?;
    // SAFETY: transient raw access to the static process table; the process
    // was just inserted and no thread of it has run.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes
            .get_mut(proc)
            .ok_or(base_err + 1)?
            .handles_mut()
            .install(manager_client_obj, Rights::WRITE)
            .map_err(|_| base_err + 1)?;
    }
    supervisor.launched();
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }

    let syndrome = EL0_SINK_FAULT.load(Ordering::SeqCst);
    if syndrome != 0 {
        let correlation = EL0_SINK_FAULT_CORRELATION.load(Ordering::SeqCst);
        let address = EL0_SINK_FAULT_ADDR.load(Ordering::SeqCst);
        // Ladder step 1. Adopt the dead host's cause before recording
        // anything: `run()` returned through a yield to boot, which left the
        // ambient context on boot's own id, and without this the ladder roots
        // a fresh trace and the restart cannot be joined to the crash.
        kcore::trace::set_current_correlation(correlation);
        supervisor.crashed(syndrome, address);

        // Ladder step 3: the dump, and the tail of the trace the dead host
        // left behind. Taken **before** the corpse is torn down and before the
        // ring fills with teardown records, because the trail this is for is
        // the one leading up to the fault.
        //
        // The dump is a kilobyte and lives here rather than in a static: it is
        // read by the check that follows and by nothing else, and a static
        // would outlive the crash it describes.
        let mut dump = CRASH_DUMP_TEMPLATE;
        kcore::supervise::capture_crash_dump(&mut dump, proc_obj, syndrome, address, correlation);
        CRASH_DUMP_RECORDS.store(dump.captured as u32, Ordering::SeqCst);

        // **Steps 4 and 5 need the binding, and this is where a supervisor
        // does know one.** It does not know everything the driver held — that
        // is reclaim's job below, and the whole reason reclaim names nothing —
        // but it was asked to supervise a (driver, device) pair, and steps 4
        // and 5 are about the device half of it.
        // SAFETY: transient raw access to the static executive; every thread
        // is off-CPU here.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                // Step 4: tell the services that depend on this device.
                exec.notify_dependents(
                    device_obj,
                    kcore::lifecycle::DriverState::Degraded,
                    kcore::lifecycle::TransitionReason::DriverCrashed,
                );
                // Step 5: attempt a reset, if policy allows. A device whose
                // driver died mid-flight has queues the kernel cannot reason
                // about; the next driver should not inherit them.
                //
                // A refusal is recorded and not fatal: a reset that cannot be
                // performed is a rung the ladder could not climb, and the
                // rungs below it still apply.
                let mut resetter = VirtioMmioResetter;
                let _ = exec.reset_device(
                    device_obj,
                    kcore::devmgr::ResetPolicy::OnDegraded,
                    Some(&mut resetter),
                );
            }
        }
    }

    // Reclaim, whether or not it crashed: a host that exited still has to be
    // taken down, and leaving one behind would corrupt the next launch's
    // scheduler slot.
    //
    // The free-list depth, not `handed_out`: the latter is cumulative and
    // never decreases, so a delta across a reclaim would always be zero.
    let free_before = frames.free_list_depth();
    // SAFETY: transient raw access; the thread is off-CPU and removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(idx);
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(proc) {
                let mapper = (!EL0_DISPATCH_IOMMU.is_null())
                    .then(|| &mut *EL0_DISPATCH_IOMMU as &mut dyn kcore::devmgr::DmaMapper);
                let mut router = GicRouter;
                exec.reclaim_devices(dead, manager_client_ep, mapper, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(idx);
        if let Some(mut dead) = processes.remove(proc) {
            dead.space_mut().teardown(frames);
        }
    }
    let _ = kernel_space.reclaim_range(
        VirtAddr::new(kstack),
        RING3_HOST_KSTACK_PAGES * FRAME_SIZE,
        frames,
    );

    if syndrome != 0 {
        supervisor.restarted(frames.free_list_depth().saturating_sub(free_before) as u64);
    }
    // The sinks are cleared so the checks after this one do not read a
    // deliberate crash as their own failure.
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_SINK_FAULT_ADDR.store(0, Ordering::SeqCst);
    Ok(syndrome != 0)
}

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
/// The device object the rebind check registers its block transport under.
/// Named because two checks depend on it being the same object: the rebind
/// grants it twice, and the event check asserts that the records say so.
const REBIND_DEVICE_OBJECT: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(26);

/// The bridge the bound device sits behind, when it sits behind one.
///
/// Registered only when the enumeration actually found a parent. A graph that
/// invented a bus for a function on the root complex would be describing a
/// machine that does not exist, and the manager would derive its device from
/// something that is not there.
const REBIND_BRIDGE_OBJECT: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(27);

/// Negative self-test: a host that keeps crashing is restarted only up to its
/// budget, and then the supervisor stops.
///
/// **The ladder's most important property is the one a healthy machine never
/// shows.** Every other check here watches recovery succeed; this watches it
/// give up, because a supervisor without a bound is not a recovery policy —
/// it is a machine that respawns a broken driver until something else breaks.
///
/// The budget is deliberately smaller than the number of crashes available, so
/// what stops the loop is the budget and not the driver running out of ways to
/// fail. Returns the launches made, or an error code.
fn driver_giveup_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    blk_base: u64,
    blk_len: u64,
) -> Result<u64, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Ok(0);
    }

    // A fresh executive: this check shares nothing with the ones before it.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    let device_obj = kcore::object::ObjectId::from_raw(28);
    let manager_server_obj = kcore::object::ObjectId::from_raw(68);
    let manager_client_obj = kcore::object::ObjectId::from_raw(69);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(70);
    let crash_proc_obj = kcore::object::ObjectId::from_raw(71);

    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(260u32)?;
        exec.device_register_mmio(
            device_obj,
            blk_base,
            blk_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .map_err(|_| 261u32)?;
        let channel = exec.channel_create().map_err(|_| 262u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 262u32)?;
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
    reset_el0_reports();

    let (manager_idx, manager_proc) = ring3_host_spawn(
        device_manager_elf(),
        REBIND_MANAGER_KSTACK_VA,
        1,
        manager_proc_obj,
        &mut kernel_space,
        frames,
        263,
    )?;
    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        let manager = processes.get_mut(manager_proc).ok_or(264u32)?;
        manager
            .handles_mut()
            .install(manager_server_obj, Rights::READ)
            .map_err(|_| 264u32)?;
        manager
            .handles_mut()
            .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
            .map_err(|_| 264u32)?;
    }

    let mut supervisor = kcore::supervise::RestartSupervisor::new(tessera_boot_checks::DRIVER_RESTART_SELFTEST_BUDGET);
    // The loop the budget has to stop. Its own guard is deliberately generous:
    // if `may_restart` never went false, this would spin past the budget and
    // the count below would catch it — a test whose runaway guard is the
    // thing under test proves nothing.
    let mut guard = tessera_boot_checks::DRIVER_RESTART_SELFTEST_BUDGET * 4 + 4;
    while supervisor.may_restart() && guard > 0 {
        guard -= 1;
        if !supervise_one_crash(
            &mut supervisor,
            REBIND_CRASH_KSTACK_VA,
            crash_proc_obj,
            device_obj,
            manager_client_obj,
            manager_client_ep,
            &mut kernel_space,
            frames,
            265,
        )? {
            return Err(268);
        }
    }
    supervisor.give_up(DRIVER_RESTART_GIVEUP_CODE);
    let outcome = supervisor.outcome();

    // Step 7 — the policy the ladder ends on, applied and read back, in
    // `tessera_boot_checks`: none of it is architectural.
    // SAFETY: transient raw access; every thread is off-CPU by here.
    let quarantined = unsafe {
        match (*(&raw mut KCORE_EXEC)).as_mut() {
            Some(exec) => tessera_boot_checks::apply_giveup_policy(exec, device_obj, &outcome),
            None => return Err(268),
        }
    };

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };

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
    let _ = kernel_space.reclaim_range(
        VirtAddr::new(REBIND_MANAGER_KSTACK_VA),
        RING3_HOST_KSTACK_PAGES * FRAME_SIZE,
        frames,
    );

    // SAFETY: transient raw access; every thread is off-CPU.
    let exec = unsafe { (*(&raw const KCORE_EXEC)).as_ref() };
    tessera_boot_checks::driver_giveup_verdict(exec, device_obj, &outcome, quarantined, 269, 270)?;
    Ok(outcome.launches)
}


/// What one run of [`driver_rebind_check`] observed.
struct RebindReports {
    /// What each incarnation reported, kept apart rather than folded.
    first: u64,
    second: u64,
    /// The device-visible base each incarnation's lease started at, when the
    /// device was behind an IOMMU. Both incarnations see the same value —
    /// which is the claim, not a coincidence.
    leased_at: Option<u64>,
    /// Whether the manager reached its device by **deriving it from a bus**
    /// rather than by being handed it.
    ///
    /// Not a report from the manager, and it does not need to be. When the
    /// device sits behind a bridge the kernel installs the *bridge* in the
    /// manager's table and nothing else — so a driver that was bound to the
    /// device at all can only have been given a capability the manager obtained
    /// from `DeviceChild`. There is no other way for one to exist.
    derived_from_bus: bool,
}

/// Reads the live DMA lease for `device` and checks it belongs to `holder`.
///
/// `scoped` says whether there should be one at all: a device behind no IOMMU
/// takes no lease, and finding one would mean the graph recorded something the
/// hardware is not enforcing.
fn observe_lease(
    device: kcore::object::ObjectId,
    holder: kcore::object::ObjectId,
    scoped: bool,
    base_err: u32,
) -> Result<Option<u64>, u32> {
    // SAFETY: transient raw access to the static executive; single-threaded
    // boot, and every thread of this check is off-CPU when this runs.
    let exec = unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }.ok_or(base_err)?;
    let held = exec.lease_holder_of_object(device);
    if !scoped {
        // No IOMMU: no lease, and the grant said so when it was made.
        return if held.is_none() {
            Ok(None)
        } else {
            Err(base_err + 1)
        };
    }
    if held != Some(holder) {
        return Err(base_err + 2);
    }
    let aperture = exec.aperture_of_object(device).ok_or(base_err + 3)?;
    if aperture.base != LEASE_BASE {
        return Err(base_err + 4);
    }
    Ok(Some(aperture.base))
}

/// `identity` is what the kernel learned enumerating the device, when it
/// learned anything: `Some` registers a device the manager can **classify
/// without reading it**, which is the only way a PCI function can be bound
/// (config space is not per-device, so no capability to it can be handed out).
/// `None` is a transport that says what it is in its own registers, and the
/// manager maps it and asks.
///
/// `smmu` is the unit the bound device's DMA passes through, with the stream id
/// its transactions arrive on. `Some` puts the device behind a translation and
/// lets its driver take a **DMA lease**; `None` is a device no IOMMU sits in
/// front of, whose grants are unscoped and say so.
///
/// Returns what each incarnation reported, in order — not folded together. See
/// [`EL0_REPORTS`] for why that distinction is load-bearing here.
/// What the kernel enumerated about one PCI function, in the form the resource
/// graph records identities in.
fn pci_identity(f: &tessera_pci::Function) -> kcore::devmgr::DeviceIdentity {
    kcore::devmgr::DeviceIdentity {
        class_code: f.class_code,
        vendor: f.vendor,
        device: f.device,
        bdf: (u16::from(f.bdf.bus) << 8)
            | (u16::from(f.bdf.device) << 3)
            | u16::from(f.bdf.function),
        revision: f.revision,
        bus: kcore::devmgr::DeviceBus::Pci,
    }
}

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
    blk_len: u64,
    identity: Option<kcore::devmgr::DeviceIdentity>,
    layout: Option<kcore::devmgr::DeviceLayout>,
    smmu: Option<(&mut Smmu, u32)>,
    bridge: Option<kcore::devmgr::DeviceIdentity>,
) -> Result<RebindReports, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::AddressSpaceOps;

    if device_manager_elf().is_empty() || blk_probe_elf().is_empty() {
        return Ok(RebindReports {
            first: 0,
            second: 0,
            leased_at: None,
            derived_from_bus: false,
        });
    }

    // A fresh executive: this check shares nothing with the ones before it.
    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(4, 0)));
    }

    let device_obj = REBIND_DEVICE_OBJECT;
    let manager_server_obj = kcore::object::ObjectId::from_raw(62);
    let manager_client_obj = kcore::object::ObjectId::from_raw(63);
    let manager_proc_obj = kcore::object::ObjectId::from_raw(64);
    let driver1_proc_obj = kcore::object::ObjectId::from_raw(65);
    let driver2_proc_obj = kcore::object::ObjectId::from_raw(66);
    // The crashing incarnations get their own process objects. Reusing one
    // across launches would have a replacement inserted under an id the dead
    // process still claims, which is the `Process::forget_thread` failure in
    // its other form.
    let crash_proc_obj = kcore::object::ObjectId::from_raw(67);

    // The device this check binds, and — when the kernel enumerated one — the
    // identity that lets the manager classify it without reading a register.
    // SAFETY: transient raw access to the static executive.
    let manager_client_ep = unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(220u32)?;
        let rights = Rights::READ | Rights::MAP | Rights::TRANSFER;
        match identity {
            Some(identity) => {
                exec.device_register_identified(device_obj, blk_base, blk_len, rights, identity)
            }
            None => exec.device_register_mmio(device_obj, blk_base, blk_len, rights),
        }
        .map_err(|_| 221u32)?;
        // **Where the device's structures are** — the thing a driver holding
        // only a window cannot discover, because a virtio-pci function says so
        // in config space and config space is not per-device (D126's open
        // item). The kernel read it while enumerating; this is where it
        // becomes something a capability holder can ask for.
        if let Some(layout) = layout {
            exec.device_set_layout(device_obj, layout)
                .map_err(|_| 221u32)?;
        }
        // **The bus, when there is one.** The manager is handed the bridge
        // rather than the device, and derives the device from it — which is
        // what makes it a bus controller's manager rather than one holding an
        // inventory somebody else assembled.
        //
        // The bridge's own rights carry no MAP: a root port's register window
        // is nothing any holder should reach, and the child does not inherit
        // these anyway — `DeviceChild` hands out the graph's record for the
        // child, which is why a bus can be granted less than the devices on it.
        if let Some(bridge) = bridge {
            // Identified, so the manager can classify the hub and ask the
            // manifest what passing through it costs. Windowless still: a root
            // port's registers are nothing any holder should reach.
            exec.device_register_identified(
                REBIND_BRIDGE_OBJECT,
                0,
                0,
                Rights::READ | Rights::DERIVE,
                bridge,
            )
            .map_err(|_| 240u32)?;
            exec.device_set_parent(device_obj, REBIND_BRIDGE_OBJECT)
                .map_err(|_| 240u32)?;
        }
        let channel = exec.channel_create().map_err(|_| 222u32)?;
        exec.bind_endpoint_object(channel.0, manager_server_obj);
        exec.bind_endpoint_object(channel.1, manager_client_obj);
        // The manager **depends on** this device — ladder step 4's edge in the
        // graph. It is a dependent in the ordinary sense: it holds the
        // inventory, it is what a failure invalidates, and it is the one thing
        // on this machine that has to hear about a device going wrong whether
        // or not the capability finds its way back.
        exec.device_add_dependent(device_obj, channel.1)
            .map_err(|_| 222u32)?;
        channel.1
    };

    // SAFETY: `high` is the active kernel high-half; the alias only maps the
    // kernel stacks and is never torn down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    // Put the device behind its stream before anything can ask for DMA, and
    // publish the unit to the syscall hook for the run — the same set-and-clear
    // discipline `scoped_dma_check` uses. Without this a bound device's
    // `dma_alloc` would find no mapper and hand back a physical address.
    let smmu = match smmu {
        Some((unit, stream)) => {
            unit.register_stream(device_obj, stream, frames)
                .map_err(|_| 234u32)?;
            // SAFETY: `unit` outlives the run below; cleared before returning.
            unsafe { EL0_DISPATCH_IOMMU = unit };
            Some(unit)
        }
        None => None,
    };

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
    reset_el0_reports();

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
        // Handle 1 is the manager's inventory root. Behind a bridge that is the
        // **bus**, which the manager walks with `DeviceChild`; on a machine
        // whose function sits on the root complex it is the device itself, and
        // the manager finds a count of zero children and treats it as a leaf.
        // One code path, two machines, and no flag telling it which it is on.
        if bridge.is_some() {
            manager
                .handles_mut()
                .install(REBIND_BRIDGE_OBJECT, Rights::READ | Rights::DERIVE)
                .map_err(|_| 224u32)?;
        } else {
            manager
                .handles_mut()
                .install(device_obj, Rights::READ | Rights::MAP | Rights::TRANSFER)
                .map_err(|_| 224u32)?;
        }
    }

    // --- The crash-recovery ladder, before the rebind it makes possible ---
    //
    // Incarnation 0 binds the device and then **faults on purpose**, holding
    // it. Everything after this point in the check used to begin with a driver
    // that exited tidily, which exercises teardown and not recovery: a corpse
    // that asked to leave has already given back everything it held. A host
    // killed mid-flight has not, and whether the device comes back from it is
    // the whole question the ladder answers.
    //
    // The supervisor's policy and its three records are `kcore::supervise`,
    // shared with the x86-64 port that has run this ladder since D51. What is
    // local is the architecture work: spawning a host, containing its fault,
    // and reclaiming the corpse.
    let mut supervisor = kcore::supervise::RestartSupervisor::new(DRIVER_RESTART_BUDGET);
    let crashed_before = supervise_one_crash(
        &mut supervisor,
        REBIND_CRASH_KSTACK_VA,
        crash_proc_obj,
        device_obj,
        manager_client_obj,
        manager_client_ep,
        &mut kernel_space,
        frames,
        236,
    )?;
    if !crashed_before {
        // The driver was supposed to die and did not, so nothing below is
        // testing recovery. Failing here beats passing a rebind that never
        // recovered from anything.
        return Err(239);
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
    let first = EL0_REPORTS[0].load(Ordering::SeqCst);
    // A transport that identifies itself is expected to have been *driven*, so
    // the magic is the proof. A device the kernel classified is not: this
    // driver speaks no virtio-pci transport, and the identity it echoes is
    // what the caller checks instead.
    if identity.is_none() && first != 0x7472_6976u64.rotate_left(8) {
        return Err(227);
    }

    // The lease incarnation 1 took, before anything tears it down.
    let leased_at = observe_lease(device_obj, driver1_proc_obj, smmu.is_some(), 235)?;

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
                // The device goes back to the manager **and** its DMA lease
                // ends here — the supervisor names neither. It does not know
                // what this driver held, which is the point; the kernel does.
                //
                // **Register windows are not revoked here, and do not need to
                // be.** A window lives in the address space torn down below and
                // dies with it (D93). A DMA lease does not — it lives in the
                // IOMMU and would outlive this process entirely — which is the
                // whole reason this call takes a mapper at all. Reading the
                // lease teardown as covering windows too would have the
                // asymmetry exactly backwards.
                //
                // An interrupt route is the *second* thing on the wrong side of
                // that asymmetry: it lives in the GIC and in the port table,
                // both of which survive this teardown, so it is handed a router
                // for the same reason and by the same argument.
                let mapper = (!EL0_DISPATCH_IOMMU.is_null())
                    .then(|| &mut *EL0_DISPATCH_IOMMU as &mut dyn kcore::devmgr::DmaMapper);
                let mut router = GicRouter;
                exec.reclaim_devices(dead, manager_client_ep, mapper, Some(&mut router));
            }
        }
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        processes.forget_thread(driver1_idx);
        if let Some(mut dead) = processes.remove(driver1_proc) {
            dead.space_mut().teardown(frames);
        }
    }

    // The lease went with the driver. Checking this *between* the incarnations
    // is what makes the next one's lease a second lease rather than the first
    // one still standing.
    if smmu.is_some() {
        // SAFETY: transient raw access; every thread of this check is off-CPU.
        let held = unsafe { (*(&raw mut KCORE_EXEC)).as_ref() }
            .ok_or(240u32)?
            .lease_holder_of_object(device_obj);
        if held.is_some() {
            return Err(241);
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

    // The replacement's lease, taken before the space is torn down — and it
    // must start where the first one did. A second driver handed the *next*
    // addresses instead would mean the window is being spent one restart at a
    // time, which no long-running machine survives.
    let second_lease = observe_lease(device_obj, driver2_proc_obj, smmu.is_some(), 245)?;
    if second_lease != leased_at {
        return Err(250);
    }

    // Restore the device-bearing boot space before touching devices or freeing.
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe {
        EL0_DISPATCH_FRAMES = core::ptr::null_mut();
        EL0_DISPATCH_IOMMU = core::ptr::null_mut();
    }

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(232);
    }
    let second = EL0_REPORTS[1].load(Ordering::SeqCst);
    if EL0_REPORT_COUNT.load(Ordering::SeqCst) != 2 {
        // Two drivers, two reports. More means someone else reported into this
        // check; fewer means an incarnation never got there.
        return Err(234);
    }
    if identity.is_none() && EL0_SINK_LOG.load(Ordering::SeqCst) != REBIND_EXPECTED {
        return Err(233);
    }

    // Teardown.
    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(driver2_idx);
            exec.scheduler().reap(manager_idx);
            // The replacement's lease ends before its frames go back to the
            // allocator, not after: in the gap the device would still name
            // memory the kernel had already handed to something else.
            let processes = &mut *(&raw mut KCORE_PROCESSES);
            if let Some(dead) = processes.get_mut(driver2_proc) {
                exec.end_device_leases(dead, smmu.map(|u| u as &mut dyn kcore::devmgr::DmaMapper));
            }
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
    Ok(RebindReports {
        first,
        second,
        leased_at,
        derived_from_bus: bridge.is_some(),
    })
}
