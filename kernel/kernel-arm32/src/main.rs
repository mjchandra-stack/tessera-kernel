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
    Context, ContextSwitch, DIRECT_MAP_BASE, KernelSection, Pl011, SemihostingExit, TrapFrame,
    UserFrame, build_kernel_space, exception_name,
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

/// Scratch virtual range the conformance battery maps and unmaps.
///
/// A **kernel-half** address: the battery maps it into the kernel's own
/// space, which since the `TTBCR` split is walked out of `TTBR1` and covers
/// only `[2 GiB, 4 GiB)`. It sits above the direct map's image of RAM and
/// inside the same 1 GiB root entry, so the battery exercises real three-level
/// walks rather than landing in an empty root entry — which, with only two
/// entries per root, would be easy to do by accident.
const CONFORMANCE_SCRATCH: u64 = 0xe000_0000;

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

/// The same PL011, at the address it has once the kernel's own tables are in
/// `TTBR1`.
///
/// Two statics rather than one mutable base, for the reason the RISC-V 32 port
/// records (D106): before the switch the only address that works is the
/// physical one, after it that address is in the user half and deliberately
/// unmapped, and a mutable base would need a second `&mut` aliasing the one
/// the console already holds.
static mut UART_WINDOW: Pl011 = Pl011::at(DIRECT_MAP_BASE as usize + Pl011::VIRT_BASE);

// Entry stub. Runs in SVC mode with the MMU off, before any Rust invariant
// holds: there is no stack, `.bss` is whatever the loader left, and — because
// the image is linked in the high half — no linked address is valid yet.
//
// That last fact drives everything. Every symbol this stub needs is loaded
// with `ldr rX, =sym`, which is a PC-relative literal-pool load and therefore
// works while running physically, and then converted to its physical address
// by subtracting KERNEL_VIRT_BASE — a known constant, so no relocation
// machinery is required. Only after translation is on and the stub has
// branched into the high half do linked addresses mean anything, which is why
// the banked per-mode stacks (whose symbols are high) are installed there and
// not before.
//
// Ordering is otherwise forced by the usual facts: interrupts masked first;
// the firmware handoff parked in a callee-saved register because everything
// below may clobber the argument registers; `.bss` zeroed before the stack is
// established, and before the boot roots inside it are filled.
core::arch::global_asm!(
    r#"
.section .text._start
.globl _start
_start:
    cpsid   if
    mov     r4, r2                  // the device tree, for kernel_main

    // Zero .bss, at physical addresses.
    ldr     r0, =__bss_start
    ldr     r1, =__bss_end
    sub     r0, r0, #0x80000000
    sub     r1, r1, #0x80000000
1:
    cmp     r0, r1
    bhs     2f
    mov     r2, #0
    str     r2, [r0], #4
    b       1b

2:
    // Two roots, two entries each: a 2 GiB region of 1 GiB blocks. TTBR0 maps
    // [0, 2 GiB) to itself so this code keeps running across the enable;
    // TTBR1 maps [2 GiB, 4 GiB) down to physical [0, 2 GiB), which is where
    // the kernel is linked. Entry 0 covers the device gigabyte and is Device
    // memory; entry 1 covers RAM and is Normal, cacheable, inner-shareable.
    //   block = 0b01, AttrIndx at [4:2], SH at [9:8], AF at 10.
    ldr     r5, =boot_root0
    sub     r5, r5, #0x80000000
    ldr     r6, =boot_root1
    sub     r6, r6, #0x80000000

    ldr     r0, =0x401               // device block, phys 0
    mov     r1, #0
    strd    r0, r1, [r5]             // TTBR0[0] -> 0x00000000, Device
    strd    r0, r1, [r6]             // TTBR1[0] -> 0x00000000, Device
    ldr     r0, =0x40000705          // normal block, phys 0x40000000
    strd    r0, r1, [r5, #8]         // TTBR0[1] -> identity RAM
    strd    r0, r1, [r6, #8]         // TTBR1[1] -> high alias of RAM

    // MAIR0: attribute 0 Device-nGnRnE, attribute 1 Normal write-back.
    ldr     r0, =0x0000ff00
    mcr     p15, 0, r0, c10, c2, 0
    mov     r0, #0
    mcr     p15, 0, r0, c10, c2, 1
    // TTBCR: EAE (long descriptors), T0SZ = T1SZ = 1 — a 2 GiB/2 GiB split.
    ldr     r0, =0x80010001
    mcr     p15, 0, r0, c2, c0, 2
    isb
    // The roots. Both are 64-bit registers written with a register pair.
    mov     r1, #0
    mcrr    p15, 0, r5, r1, c2       // TTBR0
    mcrr    p15, 1, r6, r1, c2       // TTBR1
    dsb     ish
    mcr     p15, 0, r1, c8, c7, 0    // invalidate the whole TLB
    dsb     ish
    isb

    // Enable the MMU, the data cache and the instruction cache, preserving
    // whatever reserved bits firmware set.
    mrc     p15, 0, r0, c1, c0, 0
    orr     r0, r0, #0x1             // M
    orr     r0, r0, #0x4             // C
    orr     r0, r0, #0x1000          // I
    mcr     p15, 0, r0, c1, c0, 0
    isb

    // Now linked addresses mean something. Branch to one — `bx` to an
    // absolute target rather than a relative branch, because a relative
    // branch would stay in the identity map.
    ldr     r0, =3f
    bx      r0

3:
    // Banked stacks, one processor mode at a time, at their high addresses.
    // Entering a mode with interrupts still masked is safe; each mode's SP is
    // written and then the CPU returns to SVC. 0x12 = IRQ, 0x17 = ABT,
    // 0x13 = SVC. The one piece of setup with no counterpart on any other
    // port, because only ARMv7-A banks the stack pointer per mode.
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
4:
    wfi
    b       4b
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

    // The stub's coarse kernel root is replaced by the real one, built with
    // per-section permissions. Both map this code and this stack at the same
    // high addresses, so the instruction after the switch still fetches.
    // SAFETY: `kernel_space` maps the running code, the active stack and the
    // device range at the addresses they already occupy.
    unsafe { tessera_karch_arm32::install_kernel_space(&kernel_space) };

    // The console moved with the kernel. Its physical alias lives in the user
    // half, which the next statement empties — so this must come first.
    // SAFETY: single-threaded boot; this is the only reference ever taken to
    // `UART_WINDOW`, and it replaces a sink naming an address that is about to
    // stop being mapped.
    let dropped_across_switch = {
        let uart = unsafe { &mut *&raw mut UART_WINDOW };
        uart.init();
        kcore::console::init_global(uart)
    };

    // The platform devices this crate does not construct itself — the GIC —
    // name themselves by physical address and have to be told the window,
    // before anything touches them and before the identity map goes.
    // SAFETY: `DIRECT_MAP_BASE` is the base of the mapping just installed over
    // the whole device range, read-write for the life of the kernel.
    unsafe { tessera_karch_arm32::set_device_access_base(DIRECT_MAP_BASE as usize) };

    // The stub left an identity map in `TTBR0` because the code enabling the
    // MMU was running at a physical address. It is a lie about the user half
    // now, and the boundary this port has is only real if nothing is on the
    // other side of it.
    // SAFETY: everything reached from here on is a high address — the device
    // tree was read before the switch, and the console has just moved.
    unsafe { tessera_karch_arm32::clear_user_root() };

    kprintln!(
        "paging: LPAE on, {} MiB RAM direct-mapped at {:#010x}, W^X kernel image ({image_pages} pages)",
        (ram_end - ram_start) / (1024 * 1024),
        DIRECT_MAP_BASE + ram_start
    );
    // What the split is *for*, asserted rather than announced. A device's
    // physical address must now translate to nothing in the kernel's space
    // while its direct-map alias resolves — both directions, because a device
    // that had merely become unreachable would pass a one-sided check as well
    // as one that moved. The low half is `TTBR0`'s, and `TTBR0` is empty.
    {
        use tessera_karch::AddressSpaceOps;
        let (device_base, device_len) = DEVICE_RANGE;
        let probes = [
            Pl011::VIRT_BASE as u64,
            device_base,
            device_base + device_len - FRAME_SIZE,
        ];
        let moved = probes.iter().all(|&phys| {
            kernel_space.translate(VirtAddr::new(phys)).is_none()
                && kernel_space
                    .translate(VirtAddr::new(DIRECT_MAP_BASE + phys))
                    .is_some()
        });
        if !moved {
            kprintln!("paging: FATAL: the device range is still in the user half");
            SemihostingExit::exit(ExitCode::Failure)
        }
        kprintln!(
            "paging: user half empty below {:#010x} — kernel walked from TTBR1, devices at {DIRECT_MAP_BASE:#010x}",
            <tessera_karch_arm32::KernelAddressSpace as AddressSpaceOps>::USER_ADDRESS_MAX
        );
    }

    if dropped_across_switch > 0 {
        // Nothing should be dropped: the two `init_global` calls bracket the
        // switch with no print between them. Saying so beats assuming it.
        kprintln!("early console: {dropped_across_switch} write(s) dropped across the switch");
    }
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
            Ok(r) => kprintln!(
                "store: OK — mounted a {} B store of {} blob(s) whose directory measured to the anchor this kernel is compiled to trust, and read firmware.bin ({} B, {:#018x}...); a byte changed in that blob is refused at open and one changed in the directory refuses the whole container",
                r.bytes,
                r.entries,
                r.firmware_len,
                r.firmware_lead
            ),
            Err(error) => {
                kprintln!("store: FATAL: check failed ({})", error.code());
                SemihostingExit::exit(ExitCode::Failure)
            }
        }
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

    match umode_check(&kernel_space, &mut frames) {
        Ok(code) => match process_space_check(&kernel_space, &mut frames, code) {
            Ok(()) => {}
            Err(which) => {
                kprintln!("process: FATAL: check {which} failed");
                SemihostingExit::exit(ExitCode::Failure)
            }
        },
        Err(which) => {
            kprintln!("umode: FATAL: check {which} failed");
            SemihostingExit::exit(ExitCode::Failure)
        }
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

// ---------------------------------------------------------------------------
// User mode: the port's first unprivileged execution
// ---------------------------------------------------------------------------

/// Where the user program is mapped.
///
/// This port's arrangement differs from RISC-V 32's in a way worth naming.
/// There RAM begins at `USER_ADDRESS_MAX`, so emptying the user half was
/// enough to put the kernel out of reach by *address*. Here RAM begins at
/// 1 GiB — below the boundary — so the kernel and the user program share the
/// low half, and what separates them is the descriptor's `AP` field: kernel
/// pages are `AP_RW_PL1`, user pages `AP_RW_ALL`. A real boundary in one table,
/// which is exactly the arrangement AArch64's first EL0 milestone used (D70),
/// and the reason the third check below probes a *mapped kernel* address
/// rather than an empty one — an unmapped address would fault for the wrong
/// reason and prove nothing about privilege.
const USER_CODE_VA: u64 = 0x6000_0000;
/// The user stack, not adjacent to the code page.
const USER_STACK_VA: u64 = 0x6100_0000;
/// A data page every process maps at the *same* address and fills differently.
const USER_DATA_VA: u64 = 0x6200_0000;
/// A page only one process maps at all.
const USER_PRIVATE_VA: u64 = 0x6300_0000;
/// The kernel address the program tries to read: the base of RAM, mapped
/// read-write for privileged code only. Checked to be mapped before the
/// program runs, so a machine whose RAM moved fails loudly here instead of
/// silently testing an empty address.
const KERNEL_PROBE_VA: u64 = DIRECT_MAP_BASE;

/// The value the user program hands the kernel, and the rotation handed back.
const USER_MAGIC: u32 = 0x5e17_c0de;
fn user_transform(value: u32) -> u32 {
    value.rotate_left(8)
}

/// The two calls the user program can make, in `r7` — the register ARM's EABI
/// puts a syscall number in. Not an ABI: the smallest pair that proves a
/// syscall carries a value in and out and that the second one is reached.
const SYS_LOG: u32 = 0;
const SYS_EXIT: u32 = 1;

/// Selectors the program's argument chooses between.
const CHECK_SYSCALL: usize = 0;
const CHECK_WRITE_TO_CODE: usize = 1;
const CHECK_READ_KERNEL: usize = 2;
const CHECK_READ_DATA: usize = 3;
const CHECK_READ_PRIVATE: usize = 4;

/// Size of the user thread's kernel stack — its `SP_svc`.
const USER_KSTACK_BYTES: usize = 8192;

/// ASIDs for the user spaces. Non-zero and distinct: zero is the kernel's.
const USER_ASID: u16 = 1;

#[repr(align(8))]
struct UserKernelStack([u8; USER_KSTACK_BYTES]);
static mut USER_KSTACK: UserKernelStack = UserKernelStack([0; USER_KSTACK_BYTES]);

/// Where the kernel resumes when a user thread stops being one.
static mut KERNEL_RETURN: Context = Context::zeroed();
/// Scratch the abandoned thread's state is saved into and never read from.
static mut ABANDONED: Context = Context::zeroed();

static USER_EXIT_VALUE: AtomicU64 = AtomicU64::new(0);
static USER_TRAP_KIND: AtomicU64 = AtomicU64::new(0);
static USER_TRAP_ADDRESS: AtomicU64 = AtomicU64::new(0);
static USER_SYSCALLS: AtomicU64 = AtomicU64::new(0);

// The user program. Three behaviours selected by `r0`, all position-
// independent: `adr` computes a PC-relative address, which is a user virtual
// address, so the blob never needs to know where it was mapped.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl user_blob_start
user_blob_start:
    cmp     r0, #1
    beq     10f
    cmp     r0, #2
    beq     20f
    cmp     r0, #3
    beq     30f
    cmp     r0, #4
    beq     40f

    // Syscall check: hand the kernel a value, get one back, park it on the
    // user stack, and hand it to a second syscall. The stack round trip makes
    // the stack mapping and the SP the trampoline installed load-bearing, and
    // the clobber in between means a stale register cannot stand in for
    // either.
    mov     r7, #0
    movw    r0, #0xc0de
    movt    r0, #0x5e17
    svc     #0
    sub     sp, sp, #8
    str     r0, [sp]
    mov     r0, #0
    ldr     r0, [sp]
    add     sp, sp, #8
    mov     r7, #1
    svc     #0
    udf     #0

10: // W^X: store into the page this instruction was fetched from.
    adr     r0, 10b
    str     r0, [r0]
    udf     #0

20: // The privilege boundary: read a kernel page — mapped in TTBR1, and
    // AP_RW_PL1 besides, so this must fault on permission rather than absence.
    movw    r0, #0x0000
    movt    r0, #0x8000
    ldr     r1, [r0]
    udf     #0

30: // Read this process's own data page and exit with what was there. The
    // address is a constant, identical in every process — which is the point.
    movw    r0, #0x0000
    movt    r0, #0x6200
    ldr     r0, [r0]
    mov     r7, #1
    svc     #0
    udf     #0

40: // Read the page only one of the processes has.
    movw    r0, #0x0000
    movt    r0, #0x6300
    ldr     r0, [r0]
    mov     r7, #1
    svc     #0
    udf     #0
.globl user_blob_end
user_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined above.
unsafe extern "C" {
    static user_blob_start: u8;
    static user_blob_end: u8;
}

/// Handles an `svc` from User mode.
fn user_syscall(frame: &mut UserFrame) {
    USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
    match frame.r[7] {
        SYS_LOG => {
            frame.r[0] = user_transform(frame.r[0]);
            // No `pc` adjustment: ARM's `LR` already points *after* the `svc`,
            // unlike RISC-V's `sepc`, which points at the `ecall`. The
            // difference is the architecture's, and this is where it shows.
        }
        SYS_EXIT => {
            USER_EXIT_VALUE.store(u64::from(frame.r[0]), Ordering::Relaxed);
            leave_user()
        }
        _ => {
            USER_TRAP_KIND.store(u64::MAX, Ordering::Relaxed);
            leave_user()
        }
    }
}

/// Handles an abort taken from User mode: records it and abandons the thread.
fn user_abort(frame: &TrapFrame) {
    USER_TRAP_KIND.store(u64::from(frame.kind), Ordering::Relaxed);
    USER_TRAP_ADDRESS.store(u64::from(frame.fault_address), Ordering::Relaxed);
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
        <tessera_karch_arm32::Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// Runs the user program once, with `arg` selecting its behaviour.
///
/// # Safety
///
/// The user code and stack must be mapped user-accessible in the active
/// address space, and no other user thread may be running.
unsafe fn run_user(arg: usize) {
    use tessera_karch::{ContextOps, UserContextOps};
    USER_EXIT_VALUE.store(0, Ordering::Relaxed);
    USER_TRAP_KIND.store(0, Ordering::Relaxed);
    USER_TRAP_ADDRESS.store(0, Ordering::Relaxed);

    let kstack_top =
        (&raw const USER_KSTACK) as u64 + core::mem::size_of::<UserKernelStack>() as u64;
    // SAFETY: `USER_KSTACK` is a live, 8-byte-aligned static owned by this path
    // alone, and the caller guarantees the user mappings.
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

/// The port's first unprivileged execution, in its own address space.
///
/// Since the `TTBCR` split the kernel is walked out of `TTBR1` and the low
/// half out of `TTBR0`, so the user program cannot be mapped into the kernel's
/// space at all — it needs a space of its own, which is also what makes the
/// boundary worth having. The kernel remains reachable *to the kernel*
/// throughout, because `TTBR1` is not what `activate` changes.
fn umode_check(
    kernel_space: &tessera_karch_arm32::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<tessera_karch::PhysFrame, u32> {
    use tessera_karch::{AddressSpaceOps, FrameSource};
    let mut space_owned = kernel_space
        .new_user(frames, USER_ASID)
        .map_err(|_| 20u32)?;
    let space = &mut space_owned;
    // SAFETY: both are linker-provided bounds of the read-only blob above.
    let blob = unsafe {
        core::slice::from_raw_parts(
            &raw const user_blob_start,
            (&raw const user_blob_end as usize) - (&raw const user_blob_start as usize),
        )
    };
    if blob.is_empty() || blob.len() as u64 > FRAME_SIZE {
        return Err(1);
    }
    // The kernel probe must name a page the kernel actually has, or the third
    // check would pass on an address that is merely absent. It is checked in
    // the *kernel's* space, because that is where it lives — the process space
    // being built here covers only the low half.
    if kernel_space
        .translate(VirtAddr::new(KERNEL_PROBE_VA))
        .is_none()
    {
        return Err(2);
    }

    let code = frames.alloc_frame().ok_or(3u32)?;
    space.zero_frame(code);
    space.write_bytes_to_frame(code, 0, blob);
    space
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 4u32)?;
    space.sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    let stack = frames.alloc_frame().ok_or(5u32)?;
    space.zero_frame(stack);
    space
        .map(
            VirtAddr::new(USER_STACK_VA),
            stack,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 6u32)?;

    tessera_karch_arm32::set_user_syscall_hook(user_syscall);
    tessera_karch_arm32::set_user_abort_hook(user_abort);

    // The process's root goes into `TTBR0`. The kernel keeps running out of
    // `TTBR1` across this, which is the property the split exists for.
    // SAFETY: the space maps the program and its stack; the kernel is
    // untouched by a `TTBR0` change.
    unsafe { space.activate() };

    // 1. Enter User mode, make two syscalls, exit.
    // SAFETY: the code and stack pages are mapped user-accessible above, and
    // no other user thread exists.
    unsafe { run_user(CHECK_SYSCALL) };
    if USER_TRAP_KIND.load(Ordering::Relaxed) != 0 {
        return Err(7);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != u64::from(user_transform(USER_MAGIC)) {
        return Err(8);
    }
    if USER_SYSCALLS.load(Ordering::Relaxed) != 2 {
        return Err(9);
    }
    kprintln!(
        "umode: entered User mode and returned — syscall round-tripped {:#x} as {:#x}",
        USER_MAGIC,
        user_transform(USER_MAGIC)
    );

    // 2. W^X at the unprivileged level.
    // SAFETY: as above.
    unsafe { run_user(CHECK_WRITE_TO_CODE) };
    let kind = USER_TRAP_KIND.load(Ordering::Relaxed);
    if kind != u64::from(tessera_karch_arm32::KIND_DATA_ABORT) {
        return Err(10);
    }
    let fault = USER_TRAP_ADDRESS.load(Ordering::Relaxed);
    if fault & !(FRAME_SIZE - 1) != USER_CODE_VA {
        return Err(11);
    }
    kprintln!(
        "umode: W^X held — a store into the code page took a {} at {:#x}",
        exception_name(kind as u32),
        fault
    );

    // 3. The privilege boundary: the page is mapped, and mapped for privileged
    //    code only, so a user load of it must fault on *permission* rather
    //    than absence.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_KERNEL) };
    let kind = USER_TRAP_KIND.load(Ordering::Relaxed);
    if kind != u64::from(tessera_karch_arm32::KIND_DATA_ABORT) {
        return Err(12);
    }
    if USER_TRAP_ADDRESS.load(Ordering::Relaxed) != KERNEL_PROBE_VA {
        return Err(13);
    }
    kprintln!(
        "umode: kernel unreachable from User mode — a load of {KERNEL_PROBE_VA:#010x}, which *is* mapped, took a {}",
        exception_name(kind as u32)
    );

    // Back to a kernel-only regime before the caller does anything else.
    // SAFETY: nothing low is reachable or needed from here.
    unsafe { tessera_karch_arm32::clear_user_root() };
    Ok(code)
}

// ---------------------------------------------------------------------------
// Per-process TTBR0 roots
// ---------------------------------------------------------------------------

/// What each process finds at [`USER_DATA_VA`]. Two values, one address.
const PROCESS_A_DATA: u32 = 0xa1a1_0001;
const PROCESS_B_DATA: u32 = 0xb2b2_0002;
/// What process A finds at [`USER_PRIVATE_VA`], which B does not map.
const PROCESS_A_PRIVATE: u32 = 0x0dd1_0003;

const PROCESS_A_ASID: u16 = 2;
const PROCESS_B_ASID: u16 = 3;

/// Maps one page at `virt` in `space` holding `value` in its first word.
fn map_user_word(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
    virt: u64,
    value: u32,
    fail: u32,
) -> Result<(), u32> {
    let frame = frames.alloc_frame().ok_or(fail)?;
    space.zero_frame(frame);
    space.write_bytes_to_frame(frame, 0, &value.to_le_bytes());
    space
        .map(VirtAddr::new(virt), frame, PageFlags::rw().user(), frames)
        .map_err(|_| fail)
}

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

/// Two processes, each with its own `TTBR0` root, running the same program.
///
/// The claim is the one the other ports make — the same virtual address means
/// different memory in each — but it is reached differently here, and more
/// simply. With two translation-base registers a process root holds *only*
/// the user half; the kernel is in `TTBR1` and is not in these tables at all.
/// So there is no kernel half copied by value, nothing shared by pointer, and
/// no exact-frame-count guard needed against a teardown that walks too far
/// (D99, D108). Teardown here can free everything the root reaches, because
/// everything it reaches belongs to the process.
fn process_space_check(
    kernel_space: &tessera_karch_arm32::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    code: tessera_karch::PhysFrame,
) -> Result<(), u32> {
    use tessera_karch::AddressSpaceOps;

    let mut process_a = kernel_space
        .new_user(frames, PROCESS_A_ASID)
        .map_err(|_| 1u32)?;
    map_user_image(&mut process_a, frames, code, 2)?;
    map_user_word(&mut process_a, frames, USER_DATA_VA, PROCESS_A_DATA, 4)?;
    map_user_word(
        &mut process_a,
        frames,
        USER_PRIVATE_VA,
        PROCESS_A_PRIVATE,
        5,
    )?;

    let mut process_b = kernel_space
        .new_user(frames, PROCESS_B_ASID)
        .map_err(|_| 6u32)?;
    map_user_image(&mut process_b, frames, code, 7)?;
    map_user_word(&mut process_b, frames, USER_DATA_VA, PROCESS_B_DATA, 9)?;

    // 1. A reads its own data page.
    // SAFETY: `process_a` maps the program and its stack; the kernel is
    // untouched by a `TTBR0` change, so execution continues either way.
    unsafe { process_a.activate() };
    // SAFETY: the program and its stack are mapped user-accessible in the
    // now-active space, and no other user thread is running.
    unsafe { run_user(CHECK_READ_DATA) };
    if USER_TRAP_KIND.load(Ordering::Relaxed) != 0 {
        return Err(10);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != u64::from(PROCESS_A_DATA) {
        return Err(11);
    }

    // 2. B reads *the same address* and must find its own value.
    // SAFETY: as above, for `process_b`.
    unsafe { process_b.activate() };
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_DATA) };
    if USER_TRAP_KIND.load(Ordering::Relaxed) != 0 {
        return Err(12);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != u64::from(PROCESS_B_DATA) {
        return Err(13);
    }
    kprintln!(
        "process: two TTBR0 roots — {USER_DATA_VA:#010x} reads {PROCESS_A_DATA:#010x} in asid {PROCESS_A_ASID} and {PROCESS_B_DATA:#010x} in asid {PROCESS_B_ASID}"
    );

    // 3. B has no mapping where A has one. Checked in both directions, because
    //    "B faults" alone would also hold for an address neither maps.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_PRIVATE) };
    if USER_TRAP_KIND.load(Ordering::Relaxed) != u64::from(tessera_karch_arm32::KIND_DATA_ABORT) {
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
        exception_name(tessera_karch_arm32::KIND_DATA_ABORT)
    );

    // 4. Teardown, then back to a kernel-only regime.
    // SAFETY: nothing low is reachable or needed after this.
    unsafe { tessera_karch_arm32::clear_user_root() };
    let before = frames.free_list_depth();
    process_a.free_tables(frames);
    process_b.free_tables(frames);
    if frames.free_list_depth() <= before {
        return Err(17);
    }
    // The kernel's own mappings live in `TTBR1` and were never in these
    // tables, so tearing a process down cannot reach them. Checked anyway,
    // because "cannot" is a claim about code that just ran.
    if kernel_space
        .translate(VirtAddr::new(KERNEL_PROBE_VA))
        .is_none()
    {
        return Err(18);
    }
    kprintln!(
        "process: teardown reclaimed {} frames; the kernel's TTBR1 tables were never in reach",
        frames.free_list_depth() - before
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
