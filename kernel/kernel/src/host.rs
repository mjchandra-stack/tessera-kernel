// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The driver-host substrate: a ring-3 driver owns a real device.
//!
//! COM2 with its own interrupt line, delivered to ring 3 as a port event and
//! answered with a device read the driver's capability had to permit.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- M16: driver-host substrate (a ring-3 driver owns a real device) ---------

/// COM2's PIC line (IRQ3) — the driver host's device interrupt.
pub(crate) const COM2_IRQ_LINE: u8 = 3;
/// The abstract port source id and signal the COM2 interrupt is delivered under.
pub(crate) const COM2_SOURCE: u64 = 0xc02;
pub(crate) const COM2_SIGNAL: u8 = 1;
/// Count of COM2 device interrupts observed (self-test / bridge).
pub(crate) static COM2_DRIVER_IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
/// The port `source` the boot context drained after the bridge delivered the
/// device interrupt (`u64::MAX` = not observed).
pub(crate) static COM2_DRIVER_BRIDGE_SOURCE: AtomicU64 = AtomicU64::new(u64::MAX);
/// Set once the ring-3 driver's `PortWait` returned (woken by a port signal).
pub(crate) static COM2_DRIVER_WOKEN: AtomicBool = AtomicBool::new(false);
/// The pending count the ring-3 driver's `PortWait` drained (`u64::MAX` = unset).
pub(crate) static COM2_DRIVER_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
/// The byte the ring-3 driver read from the device via `DeviceIoRead`
/// (`u64::MAX` = unset).
pub(crate) static COM2_DRIVER_DEVICE_BYTE: AtomicU64 = AtomicU64::new(u64::MAX);
/// Set once a `DeviceIo` on a non-`Device` handle was correctly denied.
pub(crate) static COM2_DRIVER_DEVICE_DENIED: AtomicBool = AtomicBool::new(false);
/// Set once a `DeviceIo` at an offset outside the granted range was denied (M17
/// — proves the resource-graph (base,len) payload is enforced, not a constant).
pub(crate) static DEVICE_MANAGER_OOR_DENIED: AtomicBool = AtomicBool::new(false);

/// Step 0 device-IRQ hook: just count COM2 interrupts.
pub(crate) fn com2_driver_count_hook(_vector: u64) {
    COM2_DRIVER_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Step 1 device-IRQ hook: bridge the COM2 interrupt to a port event, so a
/// driver waiting on that port wakes. Runs in interrupt context (IF clear); it
/// is the only `EXEC` accessor at that instant (the boot context is spinning,
/// not inside `EXEC`), so `port_signal` cannot alias a live borrow.
pub(crate) fn com2_driver_bridge_hook(_vector: u64) {
    COM2_DRIVER_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    // A device interrupt is a causal origin — this hook is where the outside
    // world becomes work ("whoever converts the outside world into work mints
    // the ID", docs/observability/02), so the port event and everything the woken
    // driver does on its behalf are attributed to a fresh cause rather than to
    // whichever thread the interrupt happened to land on.
    kcore::trace::set_current_correlation(kcore::trace::mint());
    exec_ref().port_signal(COM2_SOURCE, COM2_SIGNAL, 1);
}

/// M16 Step 0: prove a real device interrupt (COM2 IRQ3) can be raised and
/// dispatched to a hook. Bring up COM2 in loopback, unmask IRQ3, enable
/// interrupts, write a byte to THR (which loops to RBR and raises IRQ3), and
/// confirm the device hook ran and the byte looped.
pub(crate) fn com2_driver_step0_selftest() {
    use tessera_karch::InterruptControl;
    use tessera_karch_x86_64::{com2, mask_irq, set_device_irq_hook, unmask_irq};

    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    set_device_irq_hook(com2_driver_count_hook);
    // No controller setup here any more: the interrupt path is brought up once
    // in `kernel_main`, and re-initializing it mid-boot would clear the very
    // redirection table the line below is about to program.
    com2::init_loopback();
    unmask_irq(COM2_IRQ_LINE);

    Cpu::enable();
    com2::write(0, 0x5a); // THR write -> internal loopback -> RX -> IRQ3
    for _ in 0..1_000_000u64 {
        if COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed) > 0 {
            break;
        }
        core::hint::spin_loop();
    }
    Cpu::disable();
    mask_irq(COM2_IRQ_LINE);

    let count = COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed);
    let looped = com2::read(0); // RBR: the looped-back byte
    let pass = count >= 1 && looped == 0x5a;
    report(&verdict(
        DemoId::Com2DriverStep0,
        pass,
        [count, u64::from(looped), 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "m16-step0: FAIL — count={count} rbr={looped:#04x} (COM2 loopback/IRQ3 unavailable; consider the THRE fallback)"
        );
    }
}

/// M16 Step 1: prove the IRQ→port bridge. A real COM2 interrupt, routed through
/// the device hook, calls `Executive::port_signal`, asserting a bound port that
/// the boot context then drains — the event carries the device's source. (Waking
/// a *blocked* drainer is the same `port_signal` path `ports_demo` already
/// proves cross-context; here the novelty is that the caller is an interrupt.)
pub(crate) fn com2_driver_step1_bridge() {
    use tessera_karch::InterruptControl;
    use tessera_karch_x86_64::{com2, mask_irq, set_device_irq_hook, unmask_irq};

    // A fresh executive owning the port the bridge signals.
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();
    let port = match exec.port_create() {
        Ok(port) => port,
        Err(e) => return kprintln!("m16-step1: FAIL — port_create: {e:?}"),
    };
    if let Err(e) = exec.port_bind(port, COM2_SOURCE, COM2_SIGNAL) {
        return kprintln!("m16-step1: FAIL — port_bind: {e:?}");
    }

    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_BRIDGE_SOURCE.store(u64::MAX, Ordering::Relaxed);
    set_device_irq_hook(com2_driver_bridge_hook);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR from Step 0 so RX re-arms
    unmask_irq(COM2_IRQ_LINE);

    Cpu::enable();
    com2::write(0, 0x5a); // real IRQ3 -> com2_driver_bridge_hook -> port_signal
    for _ in 0..1_000_000u64 {
        if COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed) > 0 {
            break;
        }
        core::hint::spin_loop();
    }
    Cpu::disable();
    mask_irq(COM2_IRQ_LINE);

    // Drain the event the interrupt delivered (asserted, so this does not block).
    if let Ok(event) = exec_ref().port_wait(port) {
        COM2_DRIVER_BRIDGE_SOURCE.store(event.source, Ordering::Relaxed);
    }
    let source = COM2_DRIVER_BRIDGE_SOURCE.load(Ordering::Relaxed);
    let pass = source == COM2_SOURCE;
    report(&verdict(
        DemoId::Com2DriverStep1,
        pass,
        [source, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step1: FAIL — drained source={source:#x} (want {COM2_SOURCE:#x})");
    }
}

// The ring-3 DRIVER host (Step 2 form): create + bind a port for the device
// source, then block in PortWait. Woken by a port signal (Step 2: from boot;
// Step 4+: from the real IRQ), it announces itself and exits. The port handle is
// raw 0 (the first handle installed in this process's fresh table).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_program_start
.global com2_driver_program_end
com2_driver_program_start:
    mov eax, 16                        # SyscallNumber::PortCreate -> handle (raw 0)
    syscall
    xor edi, edi                       # arg0 = port handle (raw 0)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # SyscallNumber::PortBind
    syscall
    xor edi, edi                       # arg0 = port handle (raw 0)
    xor esi, esi                       # arg1 = 0: the count, no event record
    mov eax, 18                        # SyscallNumber::PortWait (blocks)
    syscall
    lea rdi, [rip + com2_driver_msg]    # announce after waking
    mov esi, 17                        # length (== com2_driver_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    xor edi, edi                       # exit code 0
    mov eax, 5                         # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
com2_driver_msg:
    .ascii "m16 driver: woken"
com2_driver_program_end:
.text
"#
);

// SAFETY: names the driver blob's bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static com2_driver_program_start: u8;
    pub(crate) static com2_driver_program_end: u8;
}

/// Resolves the port a driver-host syscall targets: looks the port handle up in
/// the caller's table (needs `READ`), and maps its object id back to the live
/// `PortId` (the handle→port bridge). Returns a `Copy` `PortId` and drops the
/// `PROCESSES` borrow, so the caller may block without a borrow spanning it.
pub(crate) fn driver_resolve_port(
    caller_idx: kcore::thread::ThreadId,
    port_handle: u64,
) -> Result<kcore::port::PortId, KError> {
    // SAFETY: the boot CPU alone; PROCESSES is populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    let process = processes
        .process_of_thread(caller_idx)
        .ok_or(KError::BadHandle)?;
    let (obj, rights) = process
        .handles()
        .lookup(Handle::from_raw(port_handle as u32))?;
    if !rights.contains(Rights::READ) {
        return Err(KError::AccessDenied);
    }
    exec_ref().port_of_object(obj).ok_or(KError::BadHandle)
}

/// `PortCreate`: create a port, mint its `ObjectType::Port` object, bind the two,
/// and install a handle for it in the caller's table. Returns the raw handle.
pub(crate) fn driver_port_create(caller_idx: kcore::thread::ThreadId) -> i64 {
    let port = match exec_ref().port_create() {
        Ok(port) => port,
        Err(e) => return encode_result(Err(e)),
    };
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let obj = match objects.create(ObjectType::Port) {
        Ok(id) => id,
        Err(e) => return encode_result(Err(e)),
    };
    exec_ref().bind_port_object(port, obj);
    // SAFETY: the boot CPU alone; PROCESSES populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    match processes.process_of_thread(caller_idx) {
        Some(process) => match process
            .handles_mut()
            .install(obj, Rights::READ | Rights::WRITE)
        {
            Ok(handle) => encode_result(Ok(u64::from(handle.raw()))),
            Err(e) => encode_result(Err(e)),
        },
        None => syscall::ENOSYS,
    }
}

/// `PortBind`: bind the port named by `port_handle` to `(source, signal)`.
pub(crate) fn driver_port_bind(
    caller_idx: kcore::thread::ThreadId,
    port_handle: u64,
    source: u64,
    signal: u8,
) -> i64 {
    let port = match driver_resolve_port(caller_idx, port_handle) {
        Ok(port) => port,
        Err(e) => return encode_result(Err(e)),
    };
    encode_result(exec_ref().port_bind(port, source, signal).map(|()| 0))
}

/// `PortWait`: block until an event arrives on the port named by `port_handle`,
/// then return its pending count. The port is resolved (borrows dropped) before
/// `exec.port_wait`, which may park the caller and switch.
pub(crate) fn driver_port_wait(
    caller_idx: kcore::thread::ThreadId,
    port_handle: u64,
    record_ptr: u64,
) -> i64 {
    let port = match driver_resolve_port(caller_idx, port_handle) {
        Ok(port) => port,
        Err(e) => return encode_result(Err(e)),
    };
    // `arg1` is where a `PortEventRecord` goes, **or 0 to want only the
    // count**. This substrate writes no record, so it answers the documented
    // zero case and refuses the other rather than ignoring the register —
    // which is what it did until D298, with one blob leaving `PortBind`'s
    // source id in it and nothing noticing that a kernel honouring the ABI
    // would have written a record to `0xc02`.
    if record_ptr != 0 {
        return encode_result(Err(KError::NotSupported));
    }
    match exec_ref().port_wait(port) {
        Ok(event) => {
            COM2_DRIVER_PENDING.store(u64::from(event.pending), Ordering::Relaxed);
            COM2_DRIVER_WOKEN.store(true, Ordering::Relaxed);
            encode_result(Ok(u64::from(event.pending)))
        }
        Err(e) => encode_result(Err(e)),
    }
}

/// `DeviceIoRead`/`DeviceIoWrite`: access a device register through a device-I/O
/// capability. The handle must name an `ObjectType::Device` object and carry the
/// right for the direction (`READ`/`WRITE`); the offset must lie in the device's
/// register span. The device (COM2) is fixed by the kernel in v0. `value` is
/// `Some` for a write, `None` for a read (which returns the byte read).
pub(crate) fn driver_device_io(
    caller_idx: kcore::thread::ThreadId,
    dev_handle: u64,
    offset: u64,
    value: Option<u8>,
) -> i64 {
    let need = if value.is_some() {
        Rights::WRITE
    } else {
        Rights::READ
    };
    // Resolve the capability's object id, checking the direction right.
    // SAFETY: the boot CPU alone; PROCESSES populated before the ring-3 threads run.
    let processes = unsafe { &mut *&raw mut PROCESSES };
    let obj = match processes.process_of_thread(caller_idx) {
        Some(process) => match process
            .handles()
            .lookup(Handle::from_raw(dev_handle as u32))
        {
            Ok((obj, rights)) if rights.contains(need) => obj,
            Ok(_) => return encode_result(Err(KError::AccessDenied)),
            Err(e) => return encode_result(Err(e)),
        },
        None => return syscall::ENOSYS,
    };
    // Possession alone is not enough: the object must be a device capability.
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    if objects.object_type(obj) != Some(ObjectType::Device) {
        COM2_DRIVER_DEVICE_DENIED.store(true, Ordering::Relaxed);
        return encode_result(Err(KError::AccessDenied));
    }
    // The authority is scoped by the object's resource-graph payload: its I/O
    // range (base, len). An unregistered Device object grants nothing; an offset
    // outside the granted range is rejected — no compile-time device constant.
    let (base, len) = match exec_ref().device_of_object(obj) {
        Some(range) => range,
        None => return encode_result(Err(KError::AccessDenied)),
    };
    if offset >= u64::from(len) {
        DEVICE_MANAGER_OOR_DENIED.store(true, Ordering::Relaxed);
        return encode_result(Err(KError::Protocol));
    }
    let port = base + offset as u16;
    match value {
        Some(byte) => {
            // SAFETY: `port` lies within the granted device's register range
            // (offset < len), so this port write is authorized by the capability.
            unsafe { tessera_karch_x86_64::device_out(port, byte) };
            encode_result(Ok(0))
        }
        None => {
            // SAFETY: `port` lies within the granted device's register range.
            let byte = unsafe { tessera_karch_x86_64::device_in(port) };
            COM2_DRIVER_DEVICE_BYTE.store(u64::from(byte), Ordering::Relaxed);
            encode_result(Ok(u64::from(byte)))
        }
    }
}

/// Registers a freshly-created `Device` object as the COM2 resource-graph node
/// (its I/O port range + IRQ line), so `DeviceIo` through the resulting
/// capability is authorized and scoped by the node's `(base, len)`. Infallible
/// in practice: each demo builds a fresh `Executive`, so the graph has room.
pub(crate) fn register_com2_device(dev_obj: ObjectId) {
    use tessera_karch_x86_64::com2;
    // The graph's authority over COM2: what a capability to it carries when the
    // kernel itself hands it out. A driver host is granted READ|WRITE and not
    // TRANSFER, so the device it drives is one it cannot pass on; this is the
    // root those grants are narrowed from, and what reclaim returns.
    let _ = exec_ref().device_register(
        dev_obj,
        com2::BASE,
        u16::from(com2::SPAN),
        COM2_IRQ_LINE,
        Rights::READ | Rights::WRITE | Rights::TRANSFER,
    );
}

/// M16 Step 2: prove the ring-3 port syscalls + the handle→port bridge. A ring-3
/// driver process `PortCreate`s and `PortBind`s a port, then blocks in
/// `PortWait`; the boot context signals the source (no IRQ yet) and the driver
/// wakes and drains the event. (Step 4 replaces the boot signal with the real
/// device IRQ.)
pub(crate) fn com2_driver_step2_ring3_ports(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    COM2_DRIVER_PENDING.store(u64::MAX, Ordering::Relaxed);

    // SAFETY: the boot CPU alone; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    let blob = &raw const com2_driver_program_start;
    let len = (&raw const com2_driver_program_end as usize)
        - (&raw const com2_driver_program_start as usize);
    let (mut driver, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    driver.set_running();
    if processes_insert(driver).is_err() {
        return kprintln!("m16-step2: FAIL — insert driver process");
    }

    // First run: the driver sets up its port and parks in PortWait, returning
    // control here. Signal the source to wake it, then run again so it drains.
    exec_ref().run();
    // SAFETY: back to the kernel space for the boot-context signal below.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };
    exec_ref().port_signal(COM2_SOURCE, COM2_SIGNAL, 1);
    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let pending = COM2_DRIVER_PENDING.load(Ordering::Relaxed);
    let pass = woken && pending == 1;
    report(&verdict(
        DemoId::Com2DriverStep2,
        pass,
        [pending, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step2: FAIL — woken={woken} pending={pending}");
    }
}

// A ring-3 blob proving the capability-gated DeviceIo path: write the device's
// THR (loops to RBR), read it back through the capability (handle raw 0), then
// attempt a read through a NON-device handle (raw 1), which the kernel denies.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_devio_program_start
.global com2_driver_devio_program_end
com2_driver_devio_program_start:
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte
    mov eax, 20                        # SyscallNumber::DeviceIoWrite
    syscall
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # SyscallNumber::DeviceIoRead -> looped byte
    syscall
    mov edi, 1                         # arg0 = a NON-device handle (raw 1)
    xor esi, esi
    mov eax, 19                        # DeviceIoRead -> AccessDenied (denied capability)
    syscall
    lea rdi, [rip + com2_driver_devio_msg]
    mov esi, 19                        # length (== com2_driver_devio_msg bytes)
    mov eax, 1                         # SyscallNumber::DebugWrite
    syscall
    xor edi, edi
    mov eax, 5                         # SyscallNumber::ProcessExit
    syscall
1:
    jmp 1b
com2_driver_devio_msg:
    .ascii "m16 device: io done"
com2_driver_devio_program_end:
.text
"#
);

// SAFETY: names the devio blob's bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static com2_driver_devio_program_start: u8;
    pub(crate) static com2_driver_devio_program_end: u8;
}

/// M16 Step 3: prove the capability-gated DeviceIo syscalls. A ring-3 process
/// holding a `Device` capability (handle raw 0) writes the device's THR and
/// reads the looped-back byte through the capability, then a read through a
/// non-`Device` handle (raw 1) is denied — capability possession + type is
/// required, not mere handle validity.
pub(crate) fn com2_driver_step3_deviceio(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::com2;
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_DENIED.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: the boot CPU alone; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    let blob = &raw const com2_driver_devio_program_start;
    let len = (&raw const com2_driver_devio_program_end as usize)
        - (&raw const com2_driver_devio_program_start as usize);
    let (mut proc, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    // Seed handle raw 0 = a Device capability, raw 1 = a non-device object.
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step3: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);
    if proc
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step3: FAIL — install device capability");
    }
    let test_obj = match objects.create(ObjectType::Test) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step3: FAIL — test object: {e:?}"),
    };
    if proc
        .handles_mut()
        .install(test_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step3: FAIL — install non-device handle");
    }
    proc.set_running();
    if processes_insert(proc).is_err() {
        return kprintln!("m16-step3: FAIL — insert process");
    }

    exec_ref().run();
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let denied = COM2_DRIVER_DEVICE_DENIED.load(Ordering::Relaxed);
    let pass = byte == 0x5a && denied;
    report(&verdict(
        DemoId::Com2DriverStep3,
        pass,
        [byte, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step3: FAIL — byte={byte:#04x} denied={denied}");
    }
}

// A ring-3 driver blob proving the full device-IRQ loop in ring 3: create+bind a
// port, poke the device (DeviceIoWrite THR) which raises IRQ3 — delivered in
// ring 3 (IF set on entry) and bridged to the port — then PortWait (drains the
// asserted event) and DeviceIoRead the looped byte. Device capability is raw 0,
// so PortCreate returns handle raw 1.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_irqdrv_program_start
.global com2_driver_irqdrv_program_end
com2_driver_irqdrv_program_start:
    mov eax, 16                        # PortCreate -> port handle (raw 1)
    syscall
    mov edi, 1                         # arg0 = port handle (raw 1)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 1                         # arg0 = port handle (raw 1)
    xor esi, esi                       # arg1 = 0: the count, no event record
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    xor edi, edi                       # arg0 = device handle (raw 0)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> looped byte
    syscall
    lea rdi, [rip + com2_driver_irqdrv_msg]
    mov esi, 18                        # length (== com2_driver_irqdrv_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
com2_driver_irqdrv_msg:
    .ascii "m16 driver: irq ok"
com2_driver_irqdrv_program_end:
.text
"#
);

// SAFETY: names the IRQ-driver blob's bounds from the global_asm above; the
// extern block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static com2_driver_irqdrv_program_start: u8;
    pub(crate) static com2_driver_irqdrv_program_end: u8;
}

/// M16 Step 4: prove a real device interrupt is delivered *in ring 3* and drives
/// the driver. The driver thread enters ring 3 with IF set (the gated
/// `USER_IF_ON_ENTRY`); boot stays IF-clear, so `port_signal` from the IRQ hook
/// only ever runs while the driver is in ring 3 (never aliasing a kernel `EXEC`
/// borrow). The driver pokes the device, the resulting IRQ3 is bridged to its
/// port before it reaches `PortWait` (asserted-before-wait, so it never parks),
/// and it reads the looped byte.
pub(crate) fn com2_driver_step4_irq_driver(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::{USER_IF_ON_ENTRY, com2, mask_irq, set_device_irq_hook, unmask_irq};
    // SAFETY: one-shot registration before this demo's ring-3 thread runs.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    set_device_irq_hook(com2_driver_bridge_hook);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    COM2_DRIVER_PENDING.store(u64::MAX, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: the boot CPU alone; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    let blob = &raw const com2_driver_irqdrv_program_start;
    let len = (&raw const com2_driver_irqdrv_program_end as usize)
        - (&raw const com2_driver_irqdrv_program_start as usize);
    let (mut driver, _tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        blob,
        len,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    // Seed the device capability at handle raw 0 (so PortCreate returns raw 1).
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step4: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);
    if driver
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step4: FAIL — install device capability");
    }
    driver.set_running();
    if processes_insert(driver).is_err() {
        return kprintln!("m16-step4: FAIL — insert driver process");
    }

    // Enable the device IRQ line; the driver enters ring 3 IF-set (boot stays
    // IF-clear). The IRQ fires in ring 3 and is bridged to the driver's port.
    unmask_irq(COM2_IRQ_LINE);
    USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    exec_ref().run();
    USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    mask_irq(COM2_IRQ_LINE);
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let irqs = COM2_DRIVER_IRQ_COUNT.load(Ordering::Relaxed);
    let pass = byte == 0x5a && woken && irqs >= 1;
    report(&verdict(
        DemoId::Com2DriverStep4,
        pass,
        [byte, irqs, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!("m16-step4: FAIL — byte={byte:#04x} woken={woken} irqs={irqs}");
    }
}

// The M16 CLIENT: a ring-3 process that asks the driver host to service an I/O by
// `ChannelCall` ("ping"), and receives the driver's reply ("pong"). Endpoint
// handle raw 0. Mirrors the M15 channel client.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_client_program_start
.global com2_driver_client_program_end
com2_driver_client_program_start:
    lea rdi, [rip + com2_driver_client_msg]
    mov esi, 16                        # length (== com2_driver_client_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    lea rdi, [rip + com2_driver_call_args]     # arg0 = ChannelMsgArgs (request)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    xor edx, edx                       # arg2 = no deadline on the reply (D283)
    mov eax, 14                        # ChannelCall (blocks for the reply)
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
com2_driver_client_msg:
    .ascii "m16 client: call"
.balign 8
com2_driver_call_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + com2_driver_ping_body - com2_driver_client_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
com2_driver_ping_body:
    .ascii "ping"
com2_driver_client_program_end:
.text
"#
);

// The M16 SERVICE DRIVER: a single-thread ring-3 driver host. It creates+binds a
// port for its device IRQ, then serves a client request over a channel — and
// between receiving the request and replying, it drives the real device:
// ChannelRecv -> DeviceIoWrite(THR) -> [IRQ3 in ring 3 -> port] -> PortWait ->
// DeviceIoRead(RBR) -> ChannelReply. Seeded handles: endpoint raw 0, device
// capability raw 1; PortCreate returns the port at raw 2.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global com2_driver_svcdrv_program_start
.global com2_driver_svcdrv_program_end
com2_driver_svcdrv_program_start:
    mov eax, 16                        # PortCreate -> port handle (raw 2)
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    lea rdi, [rip + com2_driver_svcdrv_recv_args] # arg0 = ChannelMsgArgs
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # ChannelRecv (blocks for the client)
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    xor esi, esi                       # arg1 = 0: the count, no event record
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    mov edi, 1                         # arg0 = device handle (raw 1)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> the looped byte
    syscall
    lea rdi, [rip + com2_driver_reply_args]    # arg0 = ChannelMsgArgs (reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # ChannelReply (-> hands back to the client)
    syscall
1:
    jmp 1b
.balign 8
com2_driver_reply_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + com2_driver_pong_body - com2_driver_svcdrv_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
com2_driver_pong_body:
    .ascii "pong"
.balign 8
com2_driver_svcdrv_recv_args:
    .long 88                           # ChannelMsgArgs: size
    .long 4                            # version
    .quad 0                            # flags
    .quad 0                            # interface_id (any, on a receive)
    .quad 0                            # txn_id
    .long 0                            # method_id
    .long 0                            # msg_flags (blocking)
    .quad 0                            # inline_ptr — none, because
    .quad 0                            # inline_len = 0: the wakeup, not the bytes
    .quad 0                            # handles_ptr
    .quad 0                            # handle_count
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
com2_driver_svcdrv_program_end:
.text
"#
);

// SAFETY: names the Step 5 blob bounds from the global_asm above; the extern
// block only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static com2_driver_client_program_start: u8;
    pub(crate) static com2_driver_client_program_end: u8;
    pub(crate) static com2_driver_svcdrv_program_start: u8;
    pub(crate) static com2_driver_svcdrv_program_end: u8;
}

/// M16 Step 5: the full loop. A ring-3 CLIENT `ChannelCall`s a ring-3 DRIVER
/// HOST; the driver services the request by driving a real device (poke ->
/// IRQ3-in-ring-3 -> PortWait -> read) and replies over the channel. First real
/// ring-3 device driver servicing a client's I/O request.
pub(crate) fn com2_driver_step5_service(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    use tessera_karch_x86_64::{USER_IF_ON_ENTRY, com2, mask_irq, set_device_irq_hook, unmask_irq};
    // SAFETY: one-shot registration before this demo's ring-3 threads run.
    unsafe { set_syscall_handler(syscall_handler) };
    set_user_fault_handler(user_fault_handler);
    set_device_irq_hook(com2_driver_bridge_hook);
    CHAN_SERVER_SAW_PING.store(false, Ordering::Relaxed);
    CHAN_CLIENT_SAW_PONG.store(false, Ordering::Relaxed);
    CHAN_CLIENT_EXIT.store(i32::MIN, Ordering::Relaxed);
    CHAN_CLIENT_TIDX.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: the boot CPU alone; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    // The bootstrap channel between the client and the driver.
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let (driver_ep, client_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("m16-step5: FAIL — channel_create: {e:?}"),
    };
    let driver_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step5: FAIL — driver endpoint object: {e:?}"),
    };
    let client_ep_obj = match objects.create(ObjectType::Channel) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step5: FAIL — client endpoint object: {e:?}"),
    };
    exec_ref().bind_endpoint_object(driver_ep, driver_ep_obj);
    exec_ref().bind_endpoint_object(client_ep, client_ep_obj);

    // The DRIVER, built (and scheduled) first so it parks in ChannelRecv before
    // the client calls. Seeded: endpoint raw 0, device capability raw 1.
    let dblob = &raw const com2_driver_svcdrv_program_start;
    let dlen = (&raw const com2_driver_svcdrv_program_end as usize)
        - (&raw const com2_driver_svcdrv_program_start as usize);
    let (mut driver, _dtidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        dblob,
        dlen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    if driver
        .handles_mut()
        .install(driver_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step5: FAIL — install driver endpoint");
    }
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m16-step5: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);
    if driver
        .handles_mut()
        .install(dev_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step5: FAIL — install device capability");
    }

    // The CLIENT, built second. Seeded: endpoint raw 0.
    let cblob = &raw const com2_driver_client_program_start;
    let clen = (&raw const com2_driver_client_program_end as usize)
        - (&raw const com2_driver_client_program_start as usize);
    let (mut client, client_tidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        cblob,
        clen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    if client
        .handles_mut()
        .install(client_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m16-step5: FAIL — install client endpoint");
    }
    CHAN_CLIENT_TIDX.store(
        thread_id_of(client_tidx).map_or(u64::MAX, |t| t.0),
        Ordering::Relaxed,
    );

    // Re-activate the driver (first-run) space, publish both, and run with the
    // device IRQ enabled and IF-set ring-3 entry.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { driver.space().activate(kcore::percpu::current_index()) };
    driver.set_running();
    client.set_running();
    if processes_insert(driver).is_err() {
        return kprintln!("m16-step5: FAIL — insert driver process");
    }
    if processes_insert(client).is_err() {
        return kprintln!("m16-step5: FAIL — insert client process");
    }

    unmask_irq(COM2_IRQ_LINE);
    USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    exec_ref().run();
    USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    mask_irq(COM2_IRQ_LINE);
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    let saw_ping = CHAN_SERVER_SAW_PING.load(Ordering::Relaxed);
    let saw_pong = CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed);
    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let client_exit = CHAN_CLIENT_EXIT.load(Ordering::Relaxed);
    let pass = saw_ping && saw_pong && byte == 0x5a && woken && client_exit == 0;
    report(&verdict(
        DemoId::Com2DriverService,
        pass,
        [byte, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "m16: FAIL — saw_ping={saw_ping} saw_pong={saw_pong} byte={byte:#04x} woken={woken} client_exit={client_exit}"
        );
    }
}

/// Driver host: the M16 milestone. Runs *before* `scheduler_demo` so the timer
/// and its `TICK_HOOK` are still off (only the device IRQ we unmask can fire).
pub(crate) fn driver_host_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    com2_driver_step0_selftest();
    com2_driver_step1_bridge();
    com2_driver_step2_ring3_ports(kernel_vm, frames);
    com2_driver_step3_deviceio(kernel_vm, frames);
    com2_driver_step4_irq_driver(kernel_vm, frames);
    com2_driver_step5_service(kernel_vm, frames);
}
