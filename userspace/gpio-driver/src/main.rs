// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **GPIO driver**: a `no_std` Rust program that owns a PL061,
//! serves `tessera.driver.gpio` over it, and turns one hardware interrupt into
//! per-line interrupt objects its clients hold.
//!
//! **This is the first driver here that manufactures an interrupt.** Every
//! other one waits on a line the machine raised and services what the device
//! did. A GPIO controller has eight lines and one interrupt output, so which
//! line fired is a fact the interrupt controller cannot report — it is in a
//! status register, and only whoever read it knows. Demultiplexing it is this
//! program's job, and `PortSignal` is what lets it wake the one client whose
//! line it was.
//!
//! A client that holds line 3's interrupt object waits on that line and on
//! nothing else, and one that does not hold it cannot be woken by line 3 at
//! all. That makes the demultiplex a **grant** rather than a routing decision
//! this driver could get wrong in a client's favour: the worst a bug here can
//! do is fail to wake somebody, not wake the wrong somebody.
//!
//! **Caller identity comes from the channel.** Each client has its own service
//! endpoint, and a line's owner is the endpoint the claim arrived on — not a
//! field in the request, which any sender could fill in with somebody else's
//! name.
//!
//! The transport is `tessera-pl061`, host-tested against a mock. What this file
//! adds is the syscalls and the volatile access to a window the kernel mapped.
//!
//! Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
//! ("GPIO And Pin Control")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use device_abi::{IrqCompleteArgs, MapDeviceArgs};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use gpio_controller::{
    GpioConfigRequest, GpioControlReply, GpioControllerIncoming, GpioDescribeReply, GpioDirection,
    GpioError, GpioEvent, GpioFeature, GpioLevelReply, GpioLineRequest, GpioPowerState,
    GpioTracePoint, GpioTrigger,
};
use tessera_isl_runtime::{HandleRef, Reader, WireError, decode, encode};
use tessera_pl061::{Controller, Direction, Error as PlError, LINES, Registers, Trigger};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_PORT_WAIT: u64 = 18;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_IRQ_COMPLETE: u64 = 26;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_PORT_SIGNAL: u64 = 44;

/// The capabilities boot installs, in order.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
/// The service endpoints, one per client. **One channel per caller**, because a
/// channel carries one outstanding call and two clients blocked on the same one
/// is a reply going to whichever the kernel wakes first.
const FIRST_CLIENT_HANDLE: u64 = 1;
const CLIENTS: usize = 2;
/// Where this driver's own hardware interrupt arrives.
const IRQ_PORT_HANDLE: u64 = 3;
/// The line ports, twice over.
///
/// **Two handles to each port, and there is a reason it is not one.** The
/// driver keeps one carrying `SIGNAL` — the authority to raise the line — and
/// hands the other, carrying only `READ`, to the client that watches it. A
/// transfer *moves* a handle out of the sender's table, so a driver with one
/// handle would give away the very capability it needs in order to signal.
///
/// What a driver would do with a duplicate syscall is mint the narrowed grant
/// itself; ring 3 has no way to duplicate a handle yet, so boot provides both
/// (build/README.md, D156).
const LINE_SIGNAL_BASE: u32 = 4;
const LINE_GRANT_BASE: u32 = LINE_SIGNAL_BASE + LINES as u32;
/// Where the bound controller lands: everything above is installed before it.
const CONTROLLER_HANDLE: u32 = LINE_GRANT_BASE + LINES as u32;

/// Where this program asks for the controller's registers.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// Field offsets in an encoded `ChannelMsgArgs`.
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;
/// `msg_flags` bit 0: take a message if one is queued, and say so if none is.
const MSG_FLAG_NONBLOCKING: u32 = 0x1;

/// What the driver advertises: it drives and it interrupts, and it has no bias
/// or drive strength at all — which a PL061 does not, and which the contract
/// exists to be able to say.
const FEATURES: u64 = 0x1 | 0x2;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// The controller's register window, at the address the kernel mapped it to.
struct UserRegisters {
    base: usize,
}

impl Registers for UserRegisters {
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: `base` is the window `MapDevice` installed in this address
        // space, and every offset the transport core uses is a defined register
        // inside it.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `read32`; this driver exclusively owns the controller,
        // which is a property of the capability being conserved rather than
        // shared.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

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

/// Encodes a `ChannelMsgArgs` over the message buffer.
fn channel_args(
    buf_ptr: u64,
    buf_len: u64,
    flags: u32,
    handles: u64,
    handle_count: u64,
) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: flags,
        inline_ptr: buf_ptr,
        inline_len: buf_len,
        handles_ptr: handles,
        handle_count,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xb0, 0xe)),
    }
}

/// Acquires the GPIO controller from the device manager.
fn bind() -> Result<(), u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Gpio,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0xb1, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64, 0, 0, 0)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xb1, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0xb1, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0xb1, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Gpio {
        return Err(fail(0xb1, 0x200 | (reply.class as u64)));
    }
    Ok(())
}

/// Maps the controller's registers, returning the base.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(CONTROLLER_HANDLE),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xb2, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0xb2, (-base) as u64));
    }
    Ok(base as u64)
}

/// Re-arms the controller's interrupt line after an edge has been handled.
fn irq_complete() -> Result<(), u64> {
    let args = IrqCompleteArgs {
        size: IrqCompleteArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(CONTROLLER_HANDLE),
        reserved: 0,
    };
    let mut buf = [0u8; IrqCompleteArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0xb3, 0xe));
    }
    let done = syscall2(SYS_IRQ_COMPLETE, buf.as_ptr() as u64, 0);
    if done < 0 {
        return Err(fail(0xb3, (-done) as u64));
    }
    Ok(())
}

/// What this driver carries between requests.
struct Driver {
    /// Who holds each line, as the endpoint index its claim arrived on. `None`
    /// for a line nobody has claimed.
    owner: [Option<usize>; LINES as usize],
    /// Whether the line's interrupt object has been handed over and its line
    /// unmasked.
    watched: [bool; LINES as usize],
    /// Whether each client has asked for a line yet.
    ///
    /// **This is what decides which of two things the driver waits on**, and it
    /// exists because it cannot wait on both. A client that has not spoken is
    /// one whose request would go unheard if the driver parked on its
    /// interrupt; a client that has asked for a line is one that is now waiting
    /// on that line rather than on this channel. So the driver waits on its
    /// clients until each has asked, and on the machine afterwards.
    ///
    /// A rule shaped by the mechanism rather than by the problem: what this
    /// wants is a wait that spans a port and a channel, and the kernel has only
    /// the channel half (build/README.md, D156).
    asked: [bool; CLIENTS],
    power: GpioPowerState,
    /// The part number the controller reported about itself.
    part: u32,
}

/// What a transport failure means to a client of this class.
fn class_error(error: PlError) -> GpioError {
    match error {
        PlError::NoSuchLine => GpioError::NoSuchLine,
        PlError::NotAPl061 => GpioError::Degraded,
    }
}

/// The trigger the transport takes for the one the contract names.
///
/// `NONE` is not a trigger: it is a line configured for reading, and turning it
/// into one would arm an interrupt nobody asked for.
fn trigger_of(trigger: GpioTrigger) -> Option<Trigger> {
    match trigger {
        GpioTrigger::None => None,
        GpioTrigger::RisingEdge => Some(Trigger::RisingEdge),
        GpioTrigger::FallingEdge => Some(Trigger::FallingEdge),
        GpioTrigger::BothEdges => Some(Trigger::BothEdges),
        GpioTrigger::HighLevel => Some(Trigger::HighLevel),
        GpioTrigger::LowLevel => Some(Trigger::LowLevel),
    }
}

/// Answers one client's request. `client` is the endpoint it arrived on, which
/// is this driver's only notion of who is asking — a field in the body could be
/// filled in with somebody else's name by anyone who can send.
///
/// Returns the reply's encoded length and, when the reply hands over a line's
/// interrupt object, which handle to transfer with it.
fn serve(
    driver: &mut Driver,
    gpio: &Controller<'_, UserRegisters>,
    client: usize,
    method: u32,
    request: Result<GpioControllerIncoming, WireError>,
    msg_buf: &mut [u8; MSG_BUF_LEN],
) -> Result<(usize, Option<u32>), u64> {
    let control = |status: GpioError, state: GpioPowerState, buf: &mut [u8; MSG_BUF_LEN]| {
        let reply = GpioControlReply {
            size: GpioControlReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status,
            state,
        };
        match encode(&reply, &mut buf[..GpioControlReply::WIRE_SIZE]) {
            Ok(_) => Ok((GpioControlReply::WIRE_SIZE, None)),
            Err(_) => Err(fail(0xb4, 0xe)),
        }
    };

    if method >= VENDOR_ORDINAL_BASE {
        return control(GpioError::Protocol, driver.power, msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control(GpioError::Protocol, driver.power, msg_buf);
        }
        Err(_) => return Err(fail(0xb5, u64::from(method))),
    };

    /// A line the caller must own, or the reason it may not have it.
    fn owned(driver: &Driver, client: usize, line: u32) -> Result<usize, GpioError> {
        let index = usize::try_from(line).map_err(|_| GpioError::NoSuchLine)?;
        if index >= usize::from(LINES) {
            return Err(GpioError::NoSuchLine);
        }
        match driver.owner[index] {
            Some(held) if held == client => Ok(index),
            // A line is not shareable: two holders want it at different levels
            // and no arithmetic resolves that.
            Some(_) => Err(GpioError::LineBusy),
            None => Err(GpioError::LineBusy),
        }
    }

    match request {
        GpioControllerIncoming::Describe(_) => {
            let reply = GpioDescribeReply {
                size: GpioDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: GpioError::Ok,
                features: FEATURES,
                line_count: u32::from(LINES),
                vendor: 0,
                part: driver.part,
                power_states: (1 << GpioPowerState::Active as u32)
                    | (1 << GpioPowerState::Idle as u32),
                resume_latency_us: 1000,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..GpioDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok((GpioDescribeReply::WIRE_SIZE, None)),
                Err(_) => Err(fail(0xb4, 0xe)),
            }
        }
        GpioControllerIncoming::ConfigureLine(ask) => {
            let Ok(index) = usize::try_from(ask.line) else {
                return control(GpioError::NoSuchLine, driver.power, msg_buf);
            };
            if index >= usize::from(LINES) {
                return control(GpioError::NoSuchLine, driver.power, msg_buf);
            }
            // Claiming and configuring are one step, so no window exists in
            // which a line is configured and unowned.
            match driver.owner[index] {
                Some(held) if held != client => {
                    return control(GpioError::LineBusy, driver.power, msg_buf);
                }
                _ => {}
            }
            let line = index as u8;
            let direction = match ask.direction {
                GpioDirection::Input => Direction::Input,
                GpioDirection::Output => Direction::Output,
            };
            if let Err(e) = gpio.set_direction(line, direction) {
                return control(class_error(e), driver.power, msg_buf);
            }
            match trigger_of(ask.trigger) {
                Some(trigger) => {
                    // An output cannot interrupt: it is this driver driving the
                    // line, and an edge it made itself is not news.
                    if direction == Direction::Output {
                        return control(GpioError::WrongDirection, driver.power, msg_buf);
                    }
                    if let Err(e) = gpio.configure_interrupt(line, trigger) {
                        return control(class_error(e), driver.power, msg_buf);
                    }
                }
                None => {
                    let _ = gpio.mask(line);
                }
            }
            driver.owner[index] = Some(client);
            driver.watched[index] = false;
            control(GpioError::Ok, driver.power, msg_buf)
        }
        GpioControllerIncoming::Read(ask) => {
            let (status, level) = match owned(driver, client, ask.line) {
                Ok(index) => match gpio.read(index as u8) {
                    Ok(level) => (GpioError::Ok, u32::from(level)),
                    Err(e) => (class_error(e), 0),
                },
                Err(status) => (status, 0),
            };
            let reply = GpioLevelReply {
                size: GpioLevelReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                line: ask.line,
                level,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..GpioLevelReply::WIRE_SIZE]) {
                Ok(_) => Ok((GpioLevelReply::WIRE_SIZE, None)),
                Err(_) => Err(fail(0xb4, 0xe)),
            }
        }
        GpioControllerIncoming::Write(ask) => {
            let status = match owned(driver, client, ask.line) {
                Ok(index) => match gpio.direction(index as u8) {
                    Ok(Direction::Output) => match gpio.write(index as u8, ask.level != 0) {
                        Ok(()) => GpioError::Ok,
                        Err(e) => class_error(e),
                    },
                    // Writing an input is the one failure a caller can fix
                    // without knowing anything else about the board.
                    Ok(Direction::Input) => GpioError::WrongDirection,
                    Err(e) => class_error(e),
                },
                Err(status) => status,
            };
            control(status, driver.power, msg_buf)
        }
        GpioControllerIncoming::WatchLine(ask) => match owned(driver, client, ask.line) {
            Ok(index) => {
                if gpio.unmask(index as u8).is_err() {
                    return control(GpioError::NoSuchLine, driver.power, msg_buf);
                }
                driver.watched[index] = true;
                if let Some(asked) = driver.asked.get_mut(client) {
                    *asked = true;
                }
                // The reply carries the line's interrupt object. The handle
                // travels in the message's vector and never in these bytes: a
                // body can be forged by any sender and a capability cannot.
                let (len, _) = control(GpioError::Ok, driver.power, msg_buf)?;
                Ok((len, Some(LINE_GRANT_BASE + index as u32)))
            }
            Err(status) => control(status, driver.power, msg_buf),
        },
        GpioControllerIncoming::ReleaseLine(ask) => match owned(driver, client, ask.line) {
            Ok(index) => {
                let line = index as u8;
                let _ = gpio.mask(line);
                gpio.clear(1 << line);
                let _ = gpio.set_direction(line, Direction::Input);
                driver.owner[index] = None;
                driver.watched[index] = false;
                control(GpioError::Ok, driver.power, msg_buf)
            }
            Err(status) => control(status, driver.power, msg_buf),
        },
        GpioControllerIncoming::Reset(_) => {
            // Every line released, masked, acknowledged and pointed back at
            // input — the safe end, because a line left as an output after a
            // reset is a line still driving something.
            for line in 0..LINES {
                let _ = gpio.mask(line);
                let _ = gpio.set_direction(line, Direction::Input);
                driver.owner[usize::from(line)] = None;
                driver.watched[usize::from(line)] = false;
            }
            gpio.clear(0xff);
            driver.power = GpioPowerState::Active;
            control(GpioError::Ok, GpioPowerState::Active, msg_buf)
        }
        GpioControllerIncoming::SetPower(ask) => match ask.state {
            GpioPowerState::Active | GpioPowerState::Idle => {
                driver.power = ask.state;
                control(GpioError::Ok, ask.state, msg_buf)
            }
            _ => control(GpioError::NotSupported, driver.power, msg_buf),
        },
        GpioControllerIncoming::SetElectrical(_) => {
            // Advertised as absent and answered as absent, which is the only
            // pair a client's feature check can rely on. A PL061 has no bias
            // and no drive strength at all.
            control(GpioError::NotSupported, driver.power, msg_buf)
        }
    }
}

/// One hardware interrupt, turned into as many line interrupts as it was.
///
/// **The masked status names them, and nothing else does.** The raw register
/// says what every line is doing including the ones deliberately masked off, so
/// demultiplexing from it would wake watchers for edges nobody asked about.
/// Lines nobody is watching are acknowledged and not signalled: an edge on an
/// unwatched line still has to be cleared, or a level-sensed one would hold the
/// controller's interrupt asserted forever.
fn demultiplex(driver: &Driver, gpio: &Controller<'_, UserRegisters>) -> Result<u32, u64> {
    let pending = gpio.pending();
    // Acknowledged before the clients are woken, so an edge that arrives while
    // they are running is a new one rather than the one just handled.
    gpio.clear(pending);
    let mut delivered = 0;
    for line in 0..LINES {
        if pending & (1 << line) == 0 || !driver.watched[usize::from(line)] {
            continue;
        }
        let signalled = syscall2(
            SYS_PORT_SIGNAL,
            u64::from(LINE_SIGNAL_BASE + u32::from(line)),
            u64::from(line),
        );
        if signalled < 0 {
            return Err(fail(0xb6, (-signalled) as u64));
        }
        delivered += 1;
    }
    Ok(delivered)
}

/// The whole program.
fn run() -> u64 {
    if let Err(code) = bind() {
        return code;
    }
    let base = match map_device(MMIO_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    let registers = UserRegisters {
        base: base as usize,
    };
    // Asked rather than assumed, even though the manager already asked: this
    // driver is the one that will write the registers, and a window that is not
    // what it was told is a window it must not write.
    let part = match tessera_pl061::identify(&registers) {
        Some(part) => part,
        None => return fail(0xb7, 0),
    };
    let gpio = match Controller::probe(&registers) {
        Ok(gpio) => gpio,
        Err(_) => return fail(0xb7, 1),
    };
    // Every line masked and pointed at input before anything is served, because
    // whatever the firmware left behind is not this driver's configuration.
    for line in 0..LINES {
        let _ = gpio.mask(line);
        let _ = gpio.set_direction(line, Direction::Input);
    }
    gpio.clear(0xff);

    let mut driver = Driver {
        owner: [None; LINES as usize],
        watched: [false; LINES as usize],
        asked: [false; CLIENTS],
        power: GpioPowerState::Active,
        part,
    };

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    let mut event = [0u8; 32];
    loop {
        // **Serve everything outstanding, then wait for an edge.** A blocking
        // receive would leave this driver deaf to its own interrupt, and a
        // blocking wait leaves it deaf to its clients — so it takes what is
        // queued without blocking, and parks on the interrupt only when there
        // is nothing to answer. A request arriving while it is parked waits for
        // the next edge; a wait that spans a port and a channel is what would
        // fix that, and this kernel has only the channel half of it.
        let mut served = false;
        for client in 0..CLIENTS {
            let endpoint = FIRST_CLIENT_HANDLE + client as u64;
            let args = match channel_args(
                msg_buf.as_ptr() as u64,
                MSG_BUF_LEN as u64,
                MSG_FLAG_NONBLOCKING,
                0,
                0,
            ) {
                Ok(args) => args,
                Err(code) => return code,
            };
            let n = syscall2(SYS_CHANNEL_RECV, args.as_ptr() as u64, endpoint);
            if n < 0 {
                // Nothing queued on this one, which is an answer.
                continue;
            }
            served = true;
            let method = kernel_u32(&args, ARGS_METHOD_ID);
            let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
            let request =
                GpioControllerIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
            let (reply_len, grant) =
                match serve(&mut driver, &gpio, client, method, request, &mut msg_buf) {
                    Ok(reply) => reply,
                    Err(code) => return code,
                };
            let (handles, count) = match grant {
                Some(handle) => {
                    let descriptor = HandleTransfer {
                        mode: TransferMode::Transfer,
                        // Read and nothing else: a client that could signal its
                        // own line could report an edge that never happened.
                        rights: 0x1,
                        handle,
                    };
                    if encode(&descriptor, &mut transfer).is_err() {
                        return fail(0xb8, 0xe);
                    }
                    (transfer.as_ptr() as u64, 1)
                }
                None => (0, 0),
            };
            let mut reply =
                match channel_args(msg_buf.as_ptr() as u64, reply_len as u64, 0, handles, count) {
                    Ok(args) => args,
                    Err(code) => return code,
                };
            patch_args(&mut reply, ARGS_INLINE_LEN, reply_len as u64);
            let replied = syscall2(SYS_CHANNEL_REPLY_CONTINUE, reply.as_ptr() as u64, endpoint);
            if replied < 0 {
                return fail(0xb9, (-replied) as u64);
            }
        }
        if served {
            continue;
        }

        // **A client that has not spoken yet must not be left unheard.** The
        // poll above sees nothing until the clients have run, and under a
        // cooperative scheduler they cannot run until this driver blocks — so
        // blocking on the channels is what lets them ask at all. Once every
        // client has a line, they are waiting on their lines and this driver
        // waits on the machine.
        if driver.asked.iter().any(|asked| !asked) {
            let args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64, 0, 0, 0) {
                Ok(args) => args,
                Err(code) => return code,
            };
            // Blocking, on the first endpoint whose client has not asked.
            let Some(client) = driver.asked.iter().position(|asked| !asked) else {
                continue;
            };
            let endpoint = FIRST_CLIENT_HANDLE + client as u64;
            let n = syscall2(SYS_CHANNEL_RECV, args.as_ptr() as u64, endpoint);
            if n < 0 {
                return fail(0xbb, (-n) as u64);
            }
            let method = kernel_u32(&args, ARGS_METHOD_ID);
            let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
            let request =
                GpioControllerIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
            let (reply_len, grant) =
                match serve(&mut driver, &gpio, client, method, request, &mut msg_buf) {
                    Ok(reply) => reply,
                    Err(code) => return code,
                };
            let (handles, count) = match grant {
                Some(handle) => {
                    let descriptor = HandleTransfer {
                        mode: TransferMode::Transfer,
                        rights: 0x1,
                        handle,
                    };
                    if encode(&descriptor, &mut transfer).is_err() {
                        return fail(0xb8, 0xe);
                    }
                    (transfer.as_ptr() as u64, 1)
                }
                None => (0, 0),
            };
            let mut reply =
                match channel_args(msg_buf.as_ptr() as u64, reply_len as u64, 0, handles, count) {
                    Ok(args) => args,
                    Err(code) => return code,
                };
            patch_args(&mut reply, ARGS_INLINE_LEN, reply_len as u64);
            let replied = syscall2(SYS_CHANNEL_REPLY_CONTINUE, reply.as_ptr() as u64, endpoint);
            if replied < 0 {
                return fail(0xb9, (-replied) as u64);
            }
            continue;
        }

        let waited = syscall2(SYS_PORT_WAIT, IRQ_PORT_HANDLE, event.as_mut_ptr() as u64);
        if waited < 0 {
            return fail(0xba, (-waited) as u64);
        }
        if let Err(code) = demultiplex(&driver, &gpio) {
            return code;
        }
        if let Err(code) = irq_complete() {
            return code;
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
