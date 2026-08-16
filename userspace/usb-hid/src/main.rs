// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **USB HID driver**: a `no_std` Rust program that serves
//! `tessera.driver.input` over a keyboard it cannot touch.
//!
//! **It has no device window and asks for none.** Every other class driver here
//! maps its device and writes registers. This one binds an input device, learns
//! the address the USB host assigned it, and then reaches it entirely through
//! that host — which is what `docs/drivers/01`'s relaying bus host means from
//! the other side. There is no `MapDevice` call in this program, and there is
//! nothing it could map.
//!
//! **Two questions, not one.** `Poll` asks what has happened; `GetReport` asks
//! what is true. They look similar and are not: a client that has just started
//! and wants to know whether a key is already held has no event to wait for,
//! and no amount of polling produces one. `Poll` is a brief interrupt transfer
//! and answers `NO_REPORT` when the room is quiet; `GetReport` is a control
//! request that always completes.
//!
//! **`NO_REPORT` is the point of the class.** A keyboard nobody is typing on is
//! a working keyboard. Every other class here fails when it has nothing to
//! give; this one has to say "nothing, and I am fine" — and a client that could
//! not tell that from a fault would report one every time the room went quiet.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Class Contracts")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use device_abi::{DeviceInfoArgs, DeviceInfoRecord};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use input_device::{
    InputControlReply, InputDescribeReply, InputDeviceIncoming, InputError, InputPowerState,
    InputReportReply,
};
use tessera_isl_runtime::{HandleRef, Reader, WireError, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};
use usb_host::{
    UsbControlRequest, UsbDeviceReply, UsbError, UsbHost, UsbTransferKind, UsbTransferReply,
    UsbTransferRequest,
};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_DEVICE_INFO: u64 = 28;

/// The capabilities boot installs, in order, and where the bound device lands.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const HOST_ENDPOINT_HANDLE: u64 = 1;
const CLIENT_ENDPOINT_HANDLE: u64 = 2;
const DEVICE_HANDLE: u32 = 3;

/// The symmetric request/reply buffer: the largest struct either way is 96.
const MSG_BUF_LEN: usize = 128;

/// Field offsets in an encoded `ChannelMsgArgs` (`channel_msg.isl`).
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;

/// A boot keyboard's report: modifiers, a reserved byte, six keycodes.
const REPORT_LEN: u16 = 8;

/// `UsbTransferRequest.flags` bit 0 — ask whether something has happened rather
/// than waiting until it does.
const TRANSFER_BRIEF: u64 = 0x1;

/// The HID class request that reads the state a device is holding now, and the
/// report type in the high half of its value.
const HID_GET_REPORT: u8 = 0x01;
const HID_REPORT_TYPE_INPUT: u16 = 0x0100;
/// Device to host, class, to an interface.
const IN_CLASS_INTERFACE: u8 = 0xa1;

/// What this driver implements beyond the required set: `GetReport` and not
/// `SetReport`.
///
/// Deliberately one of the two. A driver advertising everything makes the
/// conformance suite's unimplemented-optional rule unreachable, and this one is
/// honest anyway: lighting a keyboard's lamps means writing to the device, and
/// nothing here has a reason to.
const FEATURES: u64 = 0x2;

/// How many times the manager is asked for a device of this class before the
/// driver gives up. Bounded, because a device that is never going to arrive
/// must be reported rather than waited for.
const BIND_TRIES: u32 = 64;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// Reads back a u32 the kernel wrote into one of this program's buffers.
fn kernel_u32(bytes: &[u8], at: usize) -> u32 {
    let mut out = [0u8; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        if at + i >= bytes.len() {
            return 0;
        }
        // SAFETY: a bounds-checked byte of this program's own stack buffer;
        // volatile because the kernel wrote it.
        *slot = unsafe { core::ptr::read_volatile(&bytes[at + i]) };
    }
    u32::from_le_bytes(out)
}

/// Writes a u64 into an encoded descriptor between messages.
fn patch_args(args: &mut [u8; ChannelMsgArgs::WIRE_SIZE], at: usize, value: u64) {
    for (i, byte) in value.to_le_bytes().iter().enumerate() {
        // SAFETY: `at` is a field offset inside this program's own stack
        // buffer, and the widest field written is 8 bytes inside 88.
        unsafe { core::ptr::write_volatile(&mut args[at + i], *byte) };
    }
}

/// Encodes a `ChannelMsgArgs` over a buffer.
fn channel_args(
    buf_ptr: u64,
    buf_len: u64,
    method: u32,
) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: buf_len,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xd0, 0xe)),
    }
}

/// Acquires an input device from the device manager.
fn bind() -> Result<bool, u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Input,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0xd1, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64, 0)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xd1, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0xd1, 0xd)),
    };
    if reply.status != 0 {
        // Not yet, rather than never.
        return Ok(false);
    }
    if reply.class != DeviceClass::Input {
        // The class it was actually handed, so a mis-binding says which rather
        // than only that.
        return Err(fail(0xd1, 0x200 | (reply.class as u64)));
    }
    Ok(true)
}

/// Asks until there is something to be given, or gives up saying so.
///
/// **A driver can start before its device exists.** This one's device is
/// produced by a bus host enumerating a tree, and the two are separate
/// processes with no ordering between them — so "nothing of that class" at
/// startup means "not yet", and a driver that took it for "never" would be a
/// driver whose success depended on which process the scheduler picked first.
///
/// Bounded, and it says which happened: a device that never arrives is
/// reported, not waited for.
fn bind_when_available() -> Result<(), u64> {
    for _ in 0..BIND_TRIES {
        if bind()? {
            return Ok(());
        }
    }
    Err(fail(0xd1, 0x100))
}

/// Asks the kernel what the bound device is.
///
/// **This is how a class driver learns the address to name.** The USB host
/// declared the device with its bus address in the identity field a BDF
/// occupies, and the graph is what carries it here — so the driver is told
/// which device it has by the same mechanism that told it it has one, rather
/// than by a number agreed out of band.
fn device_address() -> Result<u32, u64> {
    let record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    let args = DeviceInfoArgs {
        size: DeviceInfoArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(DEVICE_HANDLE),
        reserved: 0,
        record_ptr: record.as_ptr() as u64,
    };
    let mut buf = [0u8; DeviceInfoArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xd2, 0xe));
    }
    let answered = syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0);
    if answered < 0 {
        return Err(fail(0xd2, (-answered) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceInfoRecord::WIRE_SIZE }>(&record);
    let info: DeviceInfoRecord = match decode(&bytes) {
        Ok(info) => info,
        Err(_) => return Err(fail(0xd2, 0xd)),
    };
    Ok(info.bdf)
}

/// One call to the USB host, over the relay channel.
///
/// The reply lands back in the same buffer, which is the channel's shape and
/// not this driver's choice.
fn call_host(buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Result<(), u64> {
    // **The whole buffer, not the request's length.** A call's `inline_len` is
    // symmetric: it is how many bytes go out *and* how many of the reply come
    // back. Sizing it to the request would clamp every reply to the size of the
    // question — which reads as a device that answered with zeros rather than
    // as a message that was cut off.
    let args = channel_args(buf.as_ptr() as u64, MSG_BUF_LEN as u64, method)?;
    let n = syscall2(SYS_CHANNEL_CALL, args.as_ptr() as u64, HOST_ENDPOINT_HANDLE);
    if n < 0 {
        return Err(fail(0xd3, (-n) as u64));
    }
    Ok(())
}

/// Asks the host what the device at this address is.
fn describe_device(address: u32) -> Result<UsbDeviceReply, u64> {
    let request = usb_host::UsbDeviceRequest {
        size: usb_host::UsbDeviceRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        address,
        reserved: 0,
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    if encode(&request, &mut buf[..usb_host::UsbDeviceRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0xd4, 0xe));
    }
    call_host(&mut buf, UsbHost::DESCRIBE)?;
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&buf);
    match decode::<UsbDeviceReply>(&bytes[..UsbDeviceReply::WIRE_SIZE]) {
        Ok(reply) => Ok(reply),
        Err(_) => Err(fail(0xd4, 0xd)),
    }
}

/// What this driver carries between requests.
struct Driver {
    /// The device's address on its host, which is the only name it has.
    address: u32,
    /// Its interrupt-in endpoint, as the host reported the device described it.
    endpoint: u32,
    /// Which interface the reports come from, for the class requests that name
    /// one.
    interface: u16,
    subclass: u32,
    protocol: u32,
    power: InputPowerState,
}

/// Runs one relayed transfer and returns what came back.
fn transfer(
    driver: &Driver,
    endpoint: u32,
    length: u16,
    brief: bool,
) -> Result<(UsbError, u32, [u8; 64]), u64> {
    let request = UsbTransferRequest {
        size: UsbTransferRequest::WIRE_SIZE as u32,
        version: 1,
        flags: if brief { TRANSFER_BRIEF } else { 0 },
        address: driver.address,
        endpoint,
        kind: UsbTransferKind::Interrupt,
        length: u32::from(length),
        data: [0u8; 64],
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    if encode(&request, &mut buf[..UsbTransferRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0xd5, 0xe));
    }
    call_host(&mut buf, UsbHost::TRANSFER)?;
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&buf);
    match decode::<UsbTransferReply>(&bytes[..UsbTransferReply::WIRE_SIZE]) {
        Ok(reply) => Ok((reply.status, reply.transferred, reply.data)),
        Err(_) => Err(fail(0xd5, 0xd)),
    }
}

/// The HID `GET_REPORT` class request, relayed as a control transfer.
fn get_report(driver: &Driver) -> Result<(UsbError, u32, [u8; 64]), u64> {
    let value = HID_REPORT_TYPE_INPUT.to_le_bytes();
    let index = driver.interface.to_le_bytes();
    let length = REPORT_LEN.to_le_bytes();
    let request = UsbControlRequest {
        size: UsbControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        address: driver.address,
        length: u32::from(REPORT_LEN),
        setup: [
            IN_CLASS_INTERFACE,
            HID_GET_REPORT,
            value[0],
            value[1],
            index[0],
            index[1],
            length[0],
            length[1],
        ],
        data: [0u8; 64],
    };
    let mut buf = [0u8; MSG_BUF_LEN];
    if encode(&request, &mut buf[..UsbControlRequest::WIRE_SIZE]).is_err() {
        return Err(fail(0xd6, 0xe));
    }
    call_host(&mut buf, UsbHost::CONTROL)?;
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&buf);
    match decode::<UsbTransferReply>(&bytes[..UsbTransferReply::WIRE_SIZE]) {
        Ok(reply) => Ok((reply.status, reply.transferred, reply.data)),
        Err(_) => Err(fail(0xd6, 0xd)),
    }
}

/// What a relayed transfer's outcome means to a client of this class.
///
/// The translation is one line and worth naming: `REMOVED` and `UNAUTHORIZED`
/// are facts about the device that this class has its own words for, and a
/// driver that collapsed everything into one error would leave a client unable
/// to tell a keyboard that left from one it was never allowed to have.
fn class_error(status: UsbError) -> InputError {
    match status {
        UsbError::Ok => InputError::Ok,
        UsbError::Removed | UsbError::NoDevice => InputError::Removed,
        UsbError::Unauthorized => InputError::NotSupported,
        UsbError::Stall | UsbError::Protocol => InputError::Protocol,
        UsbError::Degraded => InputError::Degraded,
        _ => InputError::IoError,
    }
}

/// Answers one client request. Returns the reply's encoded length.
fn serve(
    driver: &mut Driver,
    method: u32,
    request: Result<InputDeviceIncoming, WireError>,
    msg_buf: &mut [u8; MSG_BUF_LEN],
) -> Result<usize, u64> {
    let control = |status: InputError, state: InputPowerState, buf: &mut [u8; MSG_BUF_LEN]| {
        let reply = InputControlReply {
            size: InputControlReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status,
            state,
        };
        match encode(&reply, &mut buf[..InputControlReply::WIRE_SIZE]) {
            Ok(_) => Ok(InputControlReply::WIRE_SIZE),
            Err(_) => Err(fail(0xd7, 0xe)),
        }
    };
    let report = |status: InputError, length: u32, bytes: [u8; 64], buf: &mut [u8; MSG_BUF_LEN]| {
        let reply = InputReportReply {
            size: InputReportReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status,
            report_id: 0,
            length,
            reserved: 0,
            report: bytes,
        };
        match encode(&reply, &mut buf[..InputReportReply::WIRE_SIZE]) {
            Ok(_) => Ok(InputReportReply::WIRE_SIZE),
            Err(_) => Err(fail(0xd7, 0xe)),
        }
    };

    if method >= VENDOR_ORDINAL_BASE {
        return control(InputError::Protocol, driver.power, msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control(InputError::Protocol, driver.power, msg_buf);
        }
        // The ordinal that could not be decoded, so a mismatch says which.
        Err(_) => return Err(fail(0xd8, u64::from(method))),
    };

    match request {
        InputDeviceIncoming::Describe(_) => {
            let reply = InputDescribeReply {
                size: InputDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: InputError::Ok,
                features: FEATURES,
                subclass: driver.subclass,
                protocol: driver.protocol,
                max_report_len: u32::from(REPORT_LEN),
                power_states: (1 << InputPowerState::Active as u32)
                    | (1 << InputPowerState::Idle as u32),
                resume_latency_us: 1000,
                vendor: 0,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..InputDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok(InputDescribeReply::WIRE_SIZE),
                Err(_) => Err(fail(0xd7, 0xe)),
            }
        }
        InputDeviceIncoming::Poll(_) => {
            // A brief interrupt transfer: has anything happened, rather than
            // wait until something does.
            let (status, moved, bytes) = transfer(driver, driver.endpoint, REPORT_LEN, true)?;
            if status != UsbError::Ok {
                return report(class_error(status), 0, [0u8; 64], msg_buf);
            }
            if moved == 0 {
                // **The answer this class exists to be able to give.**
                return report(InputError::NoReport, 0, [0u8; 64], msg_buf);
            }
            report(InputError::Ok, moved, bytes, msg_buf)
        }
        InputDeviceIncoming::GetReport(_) => {
            let (status, moved, bytes) = get_report(driver)?;
            if status != UsbError::Ok {
                return report(class_error(status), 0, [0u8; 64], msg_buf);
            }
            report(InputError::Ok, moved, bytes, msg_buf)
        }
        InputDeviceIncoming::SetReport(_) => {
            // Advertised as absent and answered as absent, which is the only
            // pair a client's feature check can rely on.
            control(InputError::NotSupported, driver.power, msg_buf)
        }
        InputDeviceIncoming::Reset(_) => {
            // The contract's reset leaves `ACTIVE` and no report pending. It
            // does not clear what the device holds: a key that is physically
            // down is still down, and claiming otherwise would be claiming
            // authority over the world.
            driver.power = InputPowerState::Active;
            control(InputError::Ok, InputPowerState::Active, msg_buf)
        }
        InputDeviceIncoming::SetPower(ask) => match ask.state {
            InputPowerState::Active | InputPowerState::Idle => {
                driver.power = ask.state;
                control(InputError::Ok, ask.state, msg_buf)
            }
            _ => control(InputError::NotSupported, driver.power, msg_buf),
        },
    }
}

/// The whole program.
fn run() -> u64 {
    if let Err(code) = bind_when_available() {
        return code;
    }
    let address = match device_address() {
        Ok(address) => address,
        Err(code) => return code,
    };
    let described = match describe_device(address) {
        Ok(described) => described,
        Err(code) => return code,
    };
    // A device the host will not drive is one this driver cannot drive either,
    // and it says so at startup rather than on every request.
    if described.status != UsbError::Ok {
        return fail(0xd9, described.status as u64);
    }

    let mut driver = Driver {
        address,
        // The interrupt-in endpoint of a boot keyboard is endpoint one, and it
        // is named here as the device's own descriptor gives it — number in the
        // low bits, direction in the high one. The host refuses any endpoint
        // the device did not describe, so a wrong guess is an error rather than
        // a transfer to somewhere else.
        endpoint: 0x81,
        interface: described.interface as u16,
        subclass: described.subclass,
        protocol: described.protocol,
        power: InputPowerState::Active,
    };

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64, 0) {
        Ok(args) => args,
        Err(code) => return code,
    };
    loop {
        let n = syscall2(
            SYS_CHANNEL_RECV,
            args.as_ptr() as u64,
            CLIENT_ENDPOINT_HANDLE,
        );
        if n < 0 {
            return fail(0xda, (-n) as u64);
        }
        let method = kernel_u32(&args, ARGS_METHOD_ID);
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        let request = InputDeviceIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
        let reply_len = match serve(&mut driver, method, request, &mut msg_buf) {
            Ok(len) => len,
            Err(code) => return code,
        };
        patch_args(&mut args, ARGS_INLINE_LEN, reply_len as u64);
        let replied = syscall2(
            SYS_CHANNEL_REPLY_CONTINUE,
            args.as_ptr() as u64,
            CLIENT_ENDPOINT_HANDLE,
        );
        patch_args(&mut args, ARGS_INLINE_LEN, MSG_BUF_LEN as u64);
        if replied < 0 {
            return fail(0xdb, (-replied) as u64);
        }
    }
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, value, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    exit_reporting(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
