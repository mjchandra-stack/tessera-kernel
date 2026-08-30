// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The device manager: a service grants a device capability.
//!
//! Binding brokered over a channel rather than arranged by the kernel — the
//! manager replies with the capability transferred, and refuses the request that
//! asks for a device outside what it holds.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- M17: device manager + resource graph (a service grants a device cap) -----

// The DEVICE MANAGER: waits for a driver's request on its endpoint (raw 0) and
// replies granting the device capability (raw 1) — transferred in the reply.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global device_manager_program_start
.global device_manager_program_end
device_manager_program_start:
    xor edi, edi                       # recv: arg0 unused
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 13                        # ChannelRecv (blocks for the driver)
    syscall
    lea rdi, [rip + device_manager_grant_args]    # arg0 = ChannelMsgArgs (grant reply)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    mov eax, 15                        # ChannelReply (transfers the device cap)
    syscall
1:
    jmp 1b
.balign 8
device_manager_grant_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_grant_body - device_manager_program_start
    .quad 4
    .quad 0x400000 + device_manager_grant_handles - device_manager_program_start
    .quad 1                            # handle_count = 1 (grant the device cap)
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_grant_body:
    .ascii "com2"
.balign 8
device_manager_grant_handles:
    # One HandleTransfer descriptor (channel_msg.isl): handle, mode, rights.
    # Mode 0 is TransferMode::TRANSFER — the sender's copy goes away.
    # The manager holds READ|WRITE|TRANSFER and grants **READ|WRITE**, dropping
    # TRANSFER: a driver host gets the authority to drive its device and not the
    # authority to hand it to anyone else. Before rights narrowed on transfer
    # this was not expressible — moving a handle requires TRANSFER, so every
    # granted capability necessarily arrived able to be granted onward.
    .long 1                            # the device capability handle (raw 1)
    .long 0                            # reserved (must be zero)
    .quad 0x03                         # rights: READ|WRITE, deliberately no TRANSFER
device_manager_program_end:
.text
"#
);

// The DRIVER HOST: requests its device from the manager, then services a client
// through the granted capability. Seeded handles: manager-endpoint raw 0,
// client-endpoint raw 1. PortCreate returns raw 2; the granted device cap
// installs at raw 3 (next free slot after the ChannelCall reply).
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global device_manager_driver_program_start
.global device_manager_driver_program_end
device_manager_driver_program_start:
    mov eax, 16                        # PortCreate -> port handle (raw 2)
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov rsi, 0xc02                     # arg1 = COM2_SOURCE
    mov edx, 1                         # arg2 = COM2_SIGNAL
    mov eax, 17                        # PortBind
    syscall
    lea rdi, [rip + device_manager_req_args]      # arg0 = ChannelMsgArgs (request "com2")
    xor esi, esi                       # arg1 = manager endpoint (raw 0)
    xor edx, edx                       # arg2 = no deadline on the reply (D283)
    mov eax, 14                        # ChannelCall -> reply grants device cap (raw 3)
    syscall
    xor edi, edi                       # recv: arg0 unused
    mov esi, 1                         # arg1 = client endpoint (raw 1)
    mov eax, 13                        # ChannelRecv (blocks for the client)
    syscall
    mov edi, 3                         # arg0 = granted device cap (raw 3)
    xor esi, esi                       # arg1 = offset 0 (THR)
    mov edx, 0x5a                      # arg2 = byte -> raises IRQ3 in ring 3
    mov eax, 20                        # DeviceIoWrite
    syscall
    mov edi, 2                         # arg0 = port handle (raw 2)
    mov eax, 18                        # PortWait -> drains the IRQ's port event
    syscall
    mov edi, 3                         # arg0 = granted device cap (raw 3)
    xor esi, esi                       # arg1 = offset 0 (RBR)
    mov eax, 19                        # DeviceIoRead -> the looped byte
    syscall
    mov edi, 3                         # arg0 = granted device cap (raw 3)
    mov esi, 8                         # arg1 = offset 8 (== len) -> out of range
    mov eax, 19                        # DeviceIoRead -> denied (enforces the range)
    syscall
    lea rdi, [rip + device_manager_drv_reply_args] # arg0 = ChannelMsgArgs (reply "pong")
    mov esi, 1                         # arg1 = client endpoint (raw 1)
    mov eax, 15                        # ChannelReply (-> hands back to the client)
    syscall
1:
    jmp 1b
.balign 8
device_manager_req_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_req_body - device_manager_driver_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_drv_reply_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_pong_body - device_manager_driver_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_req_body:
    .ascii "com2"
device_manager_pong_body:
    .ascii "pong"
device_manager_driver_program_end:
.text
"#
);

// The CLIENT: asks the driver host to service an I/O (`ChannelCall` "ping"),
// receives "pong". Endpoint handle raw 0. Mirrors the M16 client.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 16
.global device_manager_client_program_start
.global device_manager_client_program_end
device_manager_client_program_start:
    lea rdi, [rip + device_manager_client_msg]
    mov esi, 16                        # length (== device_manager_client_msg bytes)
    mov eax, 1                         # DebugWrite
    syscall
    lea rdi, [rip + device_manager_call_args]     # arg0 = ChannelMsgArgs (request)
    xor esi, esi                       # arg1 = endpoint handle (raw 0)
    xor edx, edx                       # arg2 = no deadline on the reply (D283)
    mov eax, 14                        # ChannelCall (blocks for the reply)
    syscall
    xor edi, edi
    mov eax, 5                         # ProcessExit
    syscall
1:
    jmp 1b
device_manager_client_msg:
    .ascii "m17 client: call"
.balign 8
device_manager_call_args:
    .long 88
    .long 4
    .quad 0
    .quad 0xabcd
    .quad 0
    .long 1
    .long 0
    .quad 0x400000 + device_manager_ping_body - device_manager_client_program_start
    .quad 4
    .quad 0
    .quad 0
    .quad 0                            # installed_ptr (no report wanted)
    .quad 0                            # installed_cap
device_manager_ping_body:
    .ascii "ping"
device_manager_client_program_end:
.text
"#
);

// SAFETY: names the M17 blob bounds from the global_asm above; the extern block
// only declares them and performs no unsafe operation.
unsafe extern "C" {
    pub(crate) static device_manager_program_start: u8;
    pub(crate) static device_manager_program_end: u8;
    pub(crate) static device_manager_driver_program_start: u8;
    pub(crate) static device_manager_driver_program_end: u8;
    pub(crate) static device_manager_client_program_start: u8;
    pub(crate) static device_manager_client_program_end: u8;
}

/// M17: the device manager. A ring-3 **manager** owns a device (COM2) registered
/// in the resource graph and grants its capability, over a channel reply, to a
/// ring-3 **driver host** that requests it; the driver then drives the device
/// (M16's IRQ + DeviceIo path) through the *granted* cap and services a
/// **client**. Proves brokered capability granting and the Device object's real
/// `(base,len)` resource-graph payload (kernel-enforced).
pub(crate) fn device_manager_demo(
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
    CHAN_HANDLE_TRANSFERRED.store(false, Ordering::Relaxed);
    COM2_DRIVER_IRQ_COUNT.store(0, Ordering::Relaxed);
    COM2_DRIVER_DEVICE_BYTE.store(u64::MAX, Ordering::Relaxed);
    COM2_DRIVER_WOKEN.store(false, Ordering::Relaxed);
    DEVICE_MANAGER_OOR_DENIED.store(false, Ordering::Relaxed);
    com2::init_loopback();
    let _ = com2::read(0); // drain any stale RBR

    // SAFETY: the boot CPU alone; fresh process table + executive for this demo.
    unsafe {
        PROCESSES = ProcessTable::new();
        exec_restart(1);
    }

    // Two channels: A = manager <-> driver (grant), B = driver <-> client (I/O).
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let (mgr_ep, drv_mgr_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("m17: FAIL — manager channel: {e:?}"),
    };
    let (drv_cli_ep, cli_ep) = match exec_ref().channel_create() {
        Ok(pair) => pair,
        Err(e) => return kprintln!("m17: FAIL — client channel: {e:?}"),
    };
    let mgr_ep_obj = objects.create(ObjectType::Channel);
    let drv_mgr_ep_obj = objects.create(ObjectType::Channel);
    let drv_cli_ep_obj = objects.create(ObjectType::Channel);
    let cli_ep_obj = objects.create(ObjectType::Channel);
    let (mgr_ep_obj, drv_mgr_ep_obj, drv_cli_ep_obj, cli_ep_obj) =
        match (mgr_ep_obj, drv_mgr_ep_obj, drv_cli_ep_obj, cli_ep_obj) {
            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
            _ => return kprintln!("m17: FAIL — endpoint objects"),
        };
    exec_ref().bind_endpoint_object(mgr_ep, mgr_ep_obj);
    exec_ref().bind_endpoint_object(drv_mgr_ep, drv_mgr_ep_obj);
    exec_ref().bind_endpoint_object(drv_cli_ep, drv_cli_ep_obj);
    exec_ref().bind_endpoint_object(cli_ep, cli_ep_obj);

    // The COM2 device object + its resource-graph node, granted to the manager.
    let dev_obj = match objects.create(ObjectType::Device) {
        Ok(id) => id,
        Err(e) => return kprintln!("m17: FAIL — device object: {e:?}"),
    };
    register_com2_device(dev_obj);

    // The MANAGER, built and scheduled first so it parks in ChannelRecv before
    // the driver requests. Seeded: endpoint raw 0, device cap raw 1 (with
    // TRANSFER, so it can grant it).
    let mblob = &raw const device_manager_program_start;
    let mlen = (&raw const device_manager_program_end as usize)
        - (&raw const device_manager_program_start as usize);
    let (mut manager, _mtidx) = chan_build_process(
        kernel_vm,
        frames,
        alloc_asid().0,
        mblob,
        mlen,
        alloc_kstack(USER_KSTACK_PAGES).as_u64(),
        0,
    );
    if manager
        .handles_mut()
        .install(mgr_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
        || manager
            .handles_mut()
            .install(dev_obj, Rights::READ | Rights::WRITE | Rights::TRANSFER)
            .is_err()
    {
        return kprintln!("m17: FAIL — seed manager handles");
    }

    // The DRIVER, built second. Seeded: manager-endpoint raw 0, client-endpoint
    // raw 1 (the granted device cap installs at raw 3 at runtime).
    let dblob = &raw const device_manager_driver_program_start;
    let dlen = (&raw const device_manager_driver_program_end as usize)
        - (&raw const device_manager_driver_program_start as usize);
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
        .install(drv_mgr_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
        || driver
            .handles_mut()
            .install(drv_cli_ep_obj, Rights::READ | Rights::WRITE)
            .is_err()
    {
        return kprintln!("m17: FAIL — seed driver handles");
    }

    // The CLIENT, built third. Seeded: driver-endpoint raw 0.
    let cblob = &raw const device_manager_client_program_start;
    let clen = (&raw const device_manager_client_program_end as usize)
        - (&raw const device_manager_client_program_start as usize);
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
        .install(cli_ep_obj, Rights::READ | Rights::WRITE)
        .is_err()
    {
        return kprintln!("m17: FAIL — seed client handle");
    }
    CHAN_CLIENT_TIDX.store(
        thread_id_of(client_tidx).map_or(u64::MAX, |t| t.0),
        Ordering::Relaxed,
    );

    // Re-activate the manager (first-run) space; publish all three; run with the
    // device IRQ enabled and IF-set ring-3 entry.
    // SAFETY: the user space shares the kernel higher-half; the direct map and
    // boot stack stay mapped after the CR3 load.
    unsafe { manager.space().activate(kcore::percpu::current_index()) };
    manager.set_running();
    driver.set_running();
    client.set_running();
    if processes_insert(manager).is_err()
        || processes_insert(driver).is_err()
        || processes_insert(client).is_err()
    {
        return kprintln!("m17: FAIL — insert processes");
    }

    unmask_irq(COM2_IRQ_LINE);
    USER_IF_ON_ENTRY.store(true, Ordering::Relaxed);
    exec_ref().run();
    USER_IF_ON_ENTRY.store(false, Ordering::Relaxed);
    mask_irq(COM2_IRQ_LINE);
    // SAFETY: the kernel space maps this code and stack; it was active at boot.
    unsafe { kernel_vm.activate(kcore::percpu::current_index()) };

    // The granted device object's reference was conserved (manager→message→driver).
    // SAFETY: the boot CPU alone; the ring-3 run has returned to boot.
    let objects = unsafe { &mut *&raw mut OBJECTS };
    let dev_conserved = objects.is_live(dev_obj) && objects.refcount(dev_obj) == Some(1);

    let granted = CHAN_HANDLE_TRANSFERRED.load(Ordering::Relaxed);
    let saw_ping = CHAN_SERVER_SAW_PING.load(Ordering::Relaxed);
    let saw_pong = CHAN_CLIENT_SAW_PONG.load(Ordering::Relaxed);
    let byte = COM2_DRIVER_DEVICE_BYTE.load(Ordering::Relaxed);
    let woken = COM2_DRIVER_WOKEN.load(Ordering::Relaxed);
    let client_exit = CHAN_CLIENT_EXIT.load(Ordering::Relaxed);
    let oor_denied = DEVICE_MANAGER_OOR_DENIED.load(Ordering::Relaxed);
    let pass = granted
        && saw_ping
        && saw_pong
        && byte == 0x5a
        && woken
        && client_exit == 0
        && oor_denied
        && dev_conserved;
    report(&verdict(
        DemoId::DeviceManager,
        pass,
        [u64::from(com2::BASE), byte, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        // m17: FAIL — granted={granted} saw_ping={saw_ping}
        // saw_pong={saw_pong} byte={byte:#04x} woken={woken}
        // client_exit={client_exit} oor_denied={oor_denied}
        // dev_conserved={dev_conserved}
        kprintln!(
            "m17: FAIL granted={granted} ping={saw_ping} pong={saw_pong} byte={byte:#04x} woken={woken} exit={client_exit} oor={oor_denied} dev={dev_conserved}"
        );
    }
}
