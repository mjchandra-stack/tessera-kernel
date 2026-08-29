// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Ring-3 interrupt delivery: a driver parks on its device's line.
//!
//! One-cell PLIC interrupts, and the goldfish RTC because it is the only source on
//! this machine nothing else owns. The wfi pump needs a heartbeat or a line that
//! never fires looks the same as one that has not fired yet (D104).
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---------------------------------------------------------------------------
// Ring-3 interrupt delivery: a driver parks on its device's line
// ---------------------------------------------------------------------------

/// The real-time clock's `compatible`. Chosen as this check's device for a
/// reason that is about capabilities rather than convenience: the kernel owns
/// the UART and drives the timer itself, so either would have put two owners
/// on one device — exactly what the model forbids — while the virtio slots on
/// this machine have no backend and so never interrupt. The RTC is the one
/// interrupt source nothing else here claims.
pub(crate) const RTC_COMPATIBLE: &[u8] = b"google,goldfish-rtc";

/// Goldfish RTC registers. Reading `TIME_LOW` latches the high half, and
/// writing `ALARM_LOW` is what arms the alarm — so the write order below is
/// load-bearing, not stylistic.
pub(crate) mod rtc {
    pub const TIME_LOW: usize = 0x00;
    pub const TIME_HIGH: usize = 0x04;
    pub const ALARM_LOW: usize = 0x08;
    pub const ALARM_HIGH: usize = 0x0c;
    pub const IRQ_ENABLED: usize = 0x10;
    pub const CLEAR_INTERRUPT: usize = 0x1c;
}

/// How far ahead the driver sets each alarm. Long enough that arming cannot
/// race its own `PortWait`, short enough that two rounds cost no visible time.
pub(crate) const RTC_ALARM_DELAY_NS: u64 = 10_000_000;
/// Interrupts the driver waits for. **Two**, and that is the whole design of
/// this check: one interrupt proves delivery, but only a second one proves
/// `IrqComplete` re-armed the line the kernel masked on the first.
pub(crate) const IRQ_ROUNDS: u64 = 2;

pub(crate) const IRQ_USER_CODE_VA: u64 = 0x1500_0000;
pub(crate) const IRQ_USER_STACK_VA: u64 = 0x2500_0000;
pub(crate) const IRQ_USER_MMIO_VA: u64 = 0x3500_0000;
pub(crate) const IRQ_DRIVER_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xbd00_0000;
pub(crate) const IRQ_DRIVER_ASID: u16 = 9;

/// Handles boot installs: the device, then the port it is wired to.
pub(crate) const IRQ_DEVICE_HANDLE: u32 = 0;
pub(crate) const IRQ_PORT_HANDLE: u32 = 1;

/// The PLIC source the bridge below is currently wired to (0 = none). Set
/// strictly around the driver's run, so the bridge can never touch the
/// executive while the boot context is inside it.
pub(crate) static WIRED_INTID: AtomicU32 = AtomicU32::new(0);
/// Interrupts the bridge actually delivered, counted in the kernel so the
/// driver's account of events can be checked against one it did not write.
pub(crate) static IRQ_DELIVERED: AtomicU64 = AtomicU64::new(0);

/// The device-interrupt bridge: kernel side of the mask-on-deliver protocol.
///
/// Runs in interrupt context. It **masks the line** before signalling, which
/// is what makes a level-triggered source safe: the trap path completes the
/// PLIC claim unconditionally, so without masking the same still-asserted
/// device would re-interrupt immediately and forever. The driver acknowledges
/// the device through its own mapped window and then calls `IrqComplete`,
/// which is the only thing that re-enables the line.
pub(crate) fn rtc_irq_hook(source: u32) -> bool {
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
pub(crate) struct VirtioMmioResetter;

pub(crate) const VIRTIO_MMIO_MAGIC: u64 = 0x000;
pub(crate) const VIRTIO_MMIO_STATUS: u64 = 0x070;
pub(crate) const VIRTIO_MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

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
pub(crate) const CRASH_DUMP_TEMPLATE: kcore::supervise::CrashDump = kcore::supervise::CrashDump {
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
pub(crate) struct PlicRouter;

impl kcore::devmgr::InterruptRouter for PlicRouter {
    fn mask(&mut self, source: u32) {
        // SAFETY: masking a PLIC source is an interrupt-controller register
        // write with no memory-model footprint, valid from any context.
        unsafe { tessera_karch_riscv64::disable_irq(source) };
    }
}

/// `IrqComplete`: re-enable every line of the device the caller names.
///
/// Port-local for the controller write alone — the authority check and the
/// lines themselves are [`kcore::dispatch::resolve_irq_lines`]. **This port
/// used to re-arm the first line only.** No RISC-V 64 device declares an extra
/// one today, so nothing here was observably wrong; but the graph that records
/// extra lines is `kcore`'s and not a port's, so the first multi-queue
/// controller this port grows would have had a queue go quiet with nothing
/// saying so.
pub(crate) fn irq_complete(caller: kcore::thread::ThreadId, args_ptr: u64) -> i64 {
    use kcore::syscall::encode_result;

    let mut lines = [0u32; kcore::devmgr::MAX_IRQ_LINES];
    // SAFETY: transient raw access to the static process table.
    let processes = unsafe { &mut *(&raw mut KCORE_PROCESSES) };
    let count = match kcore::dispatch::resolve_irq_lines(
        substrate_exec(),
        processes,
        caller,
        args_ptr,
        &mut lines,
    ) {
        Ok(count) => count,
        Err(e) => return encode_result(Err(e)),
    };
    for intid in &lines[..count] {
        // SAFETY: enabling a PLIC source is an interrupt-controller register
        // write; the caller proved authority over the device it belongs to.
        unsafe { tessera_karch_riscv64::enable_irq(*intid) };
    }
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
    pub(crate) static irq_driver_blob_start: u8;
    pub(crate) static irq_driver_blob_end: u8;
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
pub(crate) fn irq_check(
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

    // SAFETY: the boot CPU alone; written before any thread runs.
    unsafe {
        kcore_exec_restart(1);
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
            process
                .add_thread(thread_id_of(thread_idx)?)
                .map_err(|_| 13u32)?;
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
    <SupervisorTimer as tessera_karch::TimerControl>::start_periodic_this_cpu(TICK_HZ);
    let mut pumps = 0u64;
    const PUMP_LIMIT: u64 = 200;
    loop {
        // SAFETY: transient raw access; `run` returns when nothing is runnable.
        unsafe {
            if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                exec.run();
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
