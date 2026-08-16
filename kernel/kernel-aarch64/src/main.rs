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

// The checks, by what they are about. This file keeps the boot glue, the
// machine's statics and `kernel_main` — which is the composition root, and
// runs what is declared here in order.
//
// The split is organisational and says so: every module still opens with
// `use crate::*`, and the root re-exports each module, so the namespace is the
// one flat namespace it was when all of this was one file. What the modules
// buy is a name and a header per area, not a boundary — tightening the globs
// into named imports is its own change.
//
// `certify`, not `certification`: the ISL bindings crate the checks decode
// against is already `certification`, and a module of that name would shadow
// it inside itself.

// What this machine is.
mod discovery;
pub(crate) use crate::discovery::*;
mod pci;
pub(crate) use crate::pci::*;
mod smmu;
pub(crate) use crate::smmu::*;
mod virtio;
mod virtio_pci;
pub(crate) use crate::virtio_pci::*;

// The substrate ring 3 runs on.
mod el0;
pub(crate) use crate::el0::*;
mod ipc;
pub(crate) use crate::ipc::*;
mod device_access;
pub(crate) use crate::device_access::*;
mod host;
pub(crate) use crate::host::*;

// Properties of the machine itself.
mod isolation;
pub(crate) use crate::isolation::*;
mod perf;
pub(crate) use crate::perf::*;
mod power;
pub(crate) use crate::power::*;
mod relay;
pub(crate) use crate::relay::*;
mod firmware;
pub(crate) use crate::firmware::*;

// One device class each, driven from ring 3.
mod net;
pub(crate) use crate::net::*;
mod pci_bus;
pub(crate) use crate::pci_bus::*;
mod nvme;
pub(crate) use crate::nvme::*;
mod snd;
pub(crate) use crate::snd::*;
mod gpu;
pub(crate) use crate::gpu::*;
mod crypto;
pub(crate) use crate::crypto::*;
mod gpio;
pub(crate) use crate::gpio::*;
mod usb;
pub(crate) use crate::usb::*;
mod sd;
pub(crate) use crate::sd::*;

// A driver dies, and what happens next.
mod recovery;
pub(crate) use crate::recovery::*;
mod restart;
pub(crate) use crate::restart::*;

// What the run is willing to certify.
mod certify;
pub(crate) use crate::certify::*;

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
                                if components::nvme_driver().is_empty() || components::blk_client().is_empty() {
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
                        if components::sd_host().is_empty() || components::blk_client().is_empty() {
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
                        if components::snd_driver().is_empty() || components::snd_client().is_empty() {
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
                        if components::gpu_driver().is_empty() || components::gpu_client().is_empty() {
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
                        if components::crypto_driver().is_empty() || components::crypto_client().is_empty() {
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
                        if components::crypto_driver().is_empty() || components::certifier().is_empty() {
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
                        if components::gpio_driver().is_empty()
                            || components::gpio_client().is_empty()
                            || components::platform_bus().is_empty()
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
                        if components::usb_host().is_empty()
                            || components::usb_storage().is_empty()
                            || components::usb_hid().is_empty()
                            || components::input_client().is_empty()
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
                        if components::pci_bus().is_empty() || components::blk_probe().is_empty() {
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
            if components::device_host().is_empty() || components::blk_client().is_empty() {
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
    if components::net_driver().is_empty() || components::net_client().is_empty() {
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
    if components::power_manager().is_empty() {
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
    match (components::power_manager().is_empty(), rtc_device(dtb)) {
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
    match (components::power_manager().is_empty(), rtc_device(dtb)) {
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

    if components::device_manager().is_empty() || components::blk_probe().is_empty() {
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

    if components::device_manager().is_empty() || components::blk_probe().is_empty() || system_store().is_empty() {
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
