// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tessera kernel boot glue for ARM 32-bit.
//!
//! Entry contract. QEMU writes a small bootloader at the base of RAM which
//! sets `r0 = 0`, `r1 = machine id` and **`r2 = the device-tree address`**,
//! then branches to this image's entry point with the MMU off, caches off,
//! and the CPU in SVC mode with IRQ and FIQ masked.
//!
//! That is a third boot convention across five ports and worth naming, since
//! each one delivers the device tree differently: AArch64 needs a Linux
//! `Image` header at offset 0 before the loader will build a tree at all; the
//! RISC-V ports get one from SBI firmware in `a1`; here a register is simply
//! set by a stub QEMU wrote, with no header and no firmware.
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
use tessera_devicetree::HEADER_LEN;
use tessera_karch::{
    BootInfo, ExitCode, FRAME_SIZE, MemoryKind, PageFlags, PlatformExit, VirtAddr,
};
use tessera_karch_arm32::{
    ContextSwitch, DIRECT_MAP_BASE, KernelSection, Pl011, SemihostingExit, build_kernel_space,
};
use tessera_kcore as kcore;
use tessera_kcore::kprintln;
use tessera_kcore::panic::PanicDisposition;

mod boot;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capacity of the boot memory map. Sized generously; the boot path reports
/// loudly rather than booting on a truncated map.
const MAX_MEMORY_REGIONS: usize = 64;

/// Tick rate the timer check programs.
const TICK_HZ: u32 = 100;

static OBSERVED_TICKS: AtomicU64 = AtomicU64::new(0);

fn on_tick() {
    OBSERVED_TICKS.fetch_add(1, Ordering::Relaxed);
}

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
/// read-only, and data (with .bss and the stacks) is writable but never
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

/// Physical range the `virt` machine puts its devices in — everything below
/// the base of RAM, covering the GICv2 at 0x0800_0000, the PL011 at
/// 0x0900_0000, the virtio-mmio transports above it, and the flash at 0.
const DEVICE_RANGE: (u64, u64) = (0, 0x4000_0000);

/// Scratch virtual range the conformance battery maps and unmaps. Above the
/// top of RAM on this machine and therefore mapped by nothing, but inside the
/// same 1 GiB level-1 slot RAM occupies, so the battery exercises real
/// three-level walks rather than landing in an empty root entry — which, with
/// only four root entries, would be easy to do by accident.
const CONFORMANCE_SCRATCH: u64 = 0x6000_0000;

/// ARM 32-bit machine code for `extern "C" fn() -> u64` returning
/// [`tessera_arch_conformance::SENTINEL`], for the instruction-cache case:
///
/// ```text
///   movw r0, #0xc0de
///   movt r0, #0x5e17
///   mov  r1, #0
///   bx   lr
/// ```
///
/// Four instructions, not three, for the reason the RISC-V 32 port documents:
/// a `u64` return does not fit one register at this width, so the ABI splits
/// it across `r0`/`r1` and the callee owes both halves.
///
/// Written as bytes rather than assembled from a symbol on purpose — the case
/// needs instructions that were *stored as data* into a fresh frame, which is
/// exactly the situation a symbol's address would let us avoid testing. On
/// this architecture the case can genuinely fail: the data and instruction
/// caches are not coherent, so `sync_instruction_cache` is what makes these
/// four instructions fetchable.
const SENTINEL_CODE: &[u8] = &[
    0xde, 0x00, 0x0c, 0xe3, // movw r0, #0xc0de
    0x17, 0x0e, 0x45, 0xe3, // movt r0, #0x5e17
    0x00, 0x10, 0xa0, 0xe3, // mov  r1, #0
    0x1e, 0xff, 0x2f, 0xe1, // bx   lr
];

/// Backing storage for the global console. A `static mut` is the honest
/// representation of "one mutable device object created before concurrency
/// exists"; the single `&mut` is taken exactly once, in `kernel_main`.
static mut UART: Pl011 = Pl011::virt();

// Entry stub. Runs in SVC mode with the MMU off, before any Rust invariant
// holds: there is no stack and `.bss` is whatever the loader left.
//
// Ordering is forced by those facts. Interrupts are masked first; the
// firmware handoff is parked in a callee-saved register because everything
// below is free to clobber the argument registers; `.bss` is zeroed before
// the stack is established (the zeroing pass is register-only, and the boot
// stack lives inside `.bss`); the banked per-mode stacks are installed by
// entering each mode in turn — the one piece of setup with no counterpart on
// any other port, because only ARMv7-A banks the stack pointer per mode; and
// only then is Rust entered.
core::arch::global_asm!(
    r#"
.section .text._start
.globl _start
_start:
    cpsid   if
    mov     r4, r2

    ldr     r0, =__bss_start
    ldr     r1, =__bss_end
1:
    cmp     r0, r1
    bhs     2f
    mov     r2, #0
    str     r2, [r0], #4
    b       1b

2:
    // Banked stacks, one processor mode at a time. Entering a mode with
    // interrupts still masked is safe; each mode's SP is written and then the
    // CPU returns to SVC. 0x12 = IRQ, 0x17 = ABT, 0x13 = SVC.
    mrs     r5, cpsr
    bic     r6, r5, #0x1f
    orr     r6, r6, #0x12
    msr     cpsr_c, r6
    ldr     sp, =__irq_stack_top
    bic     r6, r5, #0x1f
    orr     r6, r6, #0x17
    msr     cpsr_c, r6
    ldr     sp, =__abort_stack_top
    bic     r6, r5, #0x1f
    orr     r6, r6, #0x13
    msr     cpsr_c, r6
    ldr     sp, =__boot_stack_top

    mov     r0, r4
    bl      kernel_main

    // kernel_main is `-> !`; if it ever returns, stop rather than run on.
3:
    wfi
    b       3b
"#
);

/// Rust entry point, called by the stub above with the device-tree address.
///
/// # Safety
///
/// Called exactly once, by `_start`, on the boot CPU, with a valid stack and
/// zeroed `.bss`. `dtb` is `usize` for the reason the RISC-V 32 port
/// documents: the firmware hands the address over in a **single register**,
/// and an `extern "C"` parameter declared `u64` would be passed in a register
/// *pair* on this ABI.
#[unsafe(no_mangle)]
extern "C" fn kernel_main(dtb: usize) -> ! {
    // SAFETY: `kernel_main` runs exactly once, single-threaded, before any
    // other code; this is the only reference ever taken to UART.
    let uart = unsafe { &mut *&raw mut UART };
    uart.init();
    let dropped = kcore::console::init_global(uart);

    kprintln!("Tessera {VERSION} (Stage 0 skeleton, ARM 32-bit)");
    kprintln!("early console: PL011 @ 115200");
    if dropped > 0 {
        kprintln!("early console: {dropped} write(s) dropped before init");
    }
    let mut storage = [boot::EMPTY_REGION; MAX_MEMORY_REGIONS];
    let memory_map = match boot::memory_map(dtb, &mut storage) {
        Ok(map) => map,
        Err(error) => {
            // The memory map is not optional and there is no second source for
            // it. Reporting and stopping beats booting onto a map we could not
            // read (docs/lifecycle/04, "No Silent Fallback").
            kprintln!(
                "boot: FATAL: device tree unreadable (fdt error {}){}",
                error as u16,
                if boot::tree_overlaps_image(dtb, HEADER_LEN) {
                    " — it overlaps the kernel image, so .bss zeroing destroyed it"
                } else {
                    ""
                }
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
            boot::kind_name(region.kind)
        );
    }

    let ram_start = memory_map.first().map(|r| r.base.as_u64()).unwrap_or(0);
    let ram_end = memory_map
        .last()
        .map(|region| region.base.as_u64() + region.len)
        .unwrap_or(0);
    let mut frames = kcore::pmem::BumpFrameAllocator::new(memory_map);

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
            SemihostingExit::exit(ExitCode::Failure)
        }
    };

    // Vectors first, before translation changes under us. The reset vector
    // base is 0, which after the MMU comes on is device memory and therefore
    // unexecutable — so a fault raised *by the enable itself* would vector
    // into a page it cannot fetch and spin on a recursive prefetch abort with
    // nothing on the wire. Installing VBAR while the MMU is still off costs
    // nothing and turns that silent hang into a reported trap.
    // SAFETY: boot CPU, interrupts masked, and the vector table is in this
    // image's text, mapped executable by the tables about to be enabled.
    unsafe { tessera_karch_arm32::init_vectors() };
    tessera_karch_arm32::set_trap_handler(fatal_trap);

    // SAFETY: the space maps this code, this stack, and the console's device
    // registers at the addresses they already occupy — the image identity-
    // mapped at its per-section permissions, RAM direct-mapped, and the device
    // range below it — so the instruction after the enable still fetches and
    // the next `kprintln!` still reaches the wire.
    unsafe { tessera_karch_arm32::enable_mmu(&kernel_space) };
    kprintln!(
        "paging: LPAE on, {} MiB RAM direct-mapped at {:#010x}, W^X kernel image ({image_pages} pages)",
        (ram_end - ram_start) / (1024 * 1024),
        DIRECT_MAP_BASE + ram_start
    );
    let mut kernel_space = kernel_space;

    let _boot = BootInfo {
        hhdm_offset: DIRECT_MAP_BASE,
        memory_map,
    };

    // The periodic tick. The vectors are already in place (above), so a fault
    // raised while bringing the GIC up is reported rather than spun on.
    // SAFETY: the GIC is identity-mapped device memory (DEVICE_RANGE), this is
    // the boot CPU, and interrupts are still masked.
    unsafe {
        tessera_karch_arm32::init_gic();
        tessera_karch_arm32::enable_irq(tessera_karch_arm32::TIMER_INTID);
    }

    match boot::timer_check() {
        Ok(observed) => kprintln!("timer: {observed} ticks at {TICK_HZ} Hz, GIC delivering"),
        Err(which) => {
            kprintln!("timer: FATAL: tick check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
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
        SemihostingExit::exit(ExitCode::Failure)
    }

    kprintln!("TESSERA-STAGE0: KERNEL ALIVE");
    SemihostingExit::exit(ExitCode::Success)
}

/// Reports a fatal exception and ends the run. Without this a fault would
/// branch through whatever `VBAR` pointed at and loop.
fn fatal_trap(frame: &tessera_karch_arm32::TrapFrame) -> ! {
    kprintln!(
        "TRAP: {} (pc={:#010x} spsr={:#010x}{})",
        tessera_karch_arm32::exception_name(frame.kind),
        frame.pc,
        frame.spsr,
        if tessera_karch_arm32::is_write_fault(frame) {
            ", write"
        } else {
            ""
        }
    );
    kprintln!(
        "TRAP: fault address {:#010x} status {:#010x}",
        frame.fault_address,
        frame.fault_status
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
