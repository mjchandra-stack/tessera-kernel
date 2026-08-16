// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **display driver**: a `no_std` Rust program that brings a
//! virtio-gpu device up and serves `tessera.driver.display` over it.
//!
//! **It is the first driver here whose work can be checked from outside.**
//! Every other one is believed: the value it reports could only have come from
//! its device. A display's output is on the glass, and a driver that created
//! the resource, attached the backing, set the scanout and drew nothing reports
//! exactly what a working one does — so the boot check does not ask this
//! program whether it worked, it asks QEMU for the framebuffer.
//!
//! Which is why `Flush` is its own method and this driver never does it on a
//! client's behalf: **nothing is visible until somebody asks for it to be**.
//!
//! The transport is `tessera-virtio`'s PCI transport, split virtqueue and 2D
//! command encodings, unchanged; what this file adds is the syscalls, the
//! volatile access to a window the kernel mapped, and the pages the device
//! reads its pixels out of.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md
//! ("Display And Graphics")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use device_abi::{DeviceInfoArgs, DeviceInfoRecord, DmaAllocArgs, MapDeviceArgs};
use display_output::{
    DisplayBlitReply, DisplayControlReply, DisplayDescribeReply, DisplayError, DisplayFormat,
    DisplayOutputIncoming, DisplayPowerState,
};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{HandleRef, Reader, WireError, decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};
use tessera_virtio::pci::{PciTransport, Regs};
use tessera_virtio::{Layout, Transport, gpu};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_DEVICE_INFO: u64 = 28;

/// The capabilities boot installs, in order.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;
const DEVICE_HANDLE: u32 = 2;

/// Where this program asks for the device's registers and its DMA pages.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;
const DMA_VA_BASE: u64 = 0x0000_1000_0050_0000;
const PAGE: u64 = 0x1000;

/// Queue entries. A chain is two descriptors and nothing here pipelines, so
/// eight is four commands' worth of room for one at a time.
const QUEUE_SIZE: u16 = 8;

/// The scanout this driver drives, and the resource it puts on it.
const SCANOUT: u32 = 0;
const RESOURCE: u32 = 1;

/// The picture's size.
///
/// **Smaller than the display the device offers, and deliberately.** A
/// framebuffer for the mode QEMU reports is megabytes, which is a thousand
/// separate page grants; what is being proved here is that pixels a client sent
/// reach the glass, and that needs a picture rather than a large one. The
/// scanout is set to exactly this rectangle, so what a screendump returns is
/// this and nothing else.
const WIDTH: u32 = 64;
const HEIGHT: u32 = 64;
const BYTES_PER_PIXEL: u32 = 4;
/// Pages the framebuffer occupies — and the entries its backing list has.
const FB_PAGES: usize = (WIDTH * HEIGHT * BYTES_PER_PIXEL / 0x1000) as usize;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// Field offsets in an encoded `ChannelMsgArgs`.
const ARGS_METHOD_ID: usize = 32;
const ARGS_INLINE_LEN: usize = 48;

/// Pixels one `Blit` carries — sixteen, at four bytes each.
const BLIT_PIXELS: u32 = 16;

/// What this driver advertises: it fills, and it has no cursor plane.
const FEATURES: u64 = 0x1;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// A window the kernel mapped, at some offset into it.
struct Window {
    base: usize,
}

impl Regs for Window {
    fn read8(&self, offset: usize) -> u8 {
        // SAFETY: `base` is inside the window `MapDevice` installed in this
        // address space, and every offset is a defined field of the structure
        // the device's own capabilities placed there.
        unsafe { ((self.base + offset) as *const u8).read_volatile() }
    }
    fn read16(&self, offset: usize) -> u16 {
        // SAFETY: as `read8`.
        unsafe { ((self.base + offset) as *const u16).read_volatile() }
    }
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: as `read8`.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }
    fn write8(&self, offset: usize, value: u8) {
        // SAFETY: as `read8`; this driver exclusively owns the device.
        unsafe { ((self.base + offset) as *mut u8).write_volatile(value) }
    }
    fn write16(&self, offset: usize, value: u16) {
        // SAFETY: as `write8`.
        unsafe { ((self.base + offset) as *mut u16).write_volatile(value) }
    }
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `write8`.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// One page, under both its names.
#[derive(Clone, Copy, Default)]
struct Page {
    va: u64,
    phys: u64,
}

/// Hands a slice over a DMA page to a caller, scoped so no two exist at once.
fn with_page<R>(page: &Page, f: impl FnOnce(&mut [u8]) -> R) -> R {
    // SAFETY: `DmaAlloc` mapped exactly one readable and writable page at
    // `page.va` for this process; nothing else forms a reference to it while
    // `f` runs, and the mapping outlives the call.
    let slice = unsafe { core::slice::from_raw_parts_mut(page.va as *mut u8, PAGE as usize) };
    f(slice)
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
fn channel_args(buf_ptr: u64, buf_len: u64) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
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
        Err(_) => Err(fail(0x80, 0xe)),
    }
}

/// Acquires a display from the device manager.
fn bind() -> Result<(), u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Display,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0x81, 0xe));
    }
    let args = channel_args(message.as_ptr() as u64, message.len() as u64)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0x81, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x81, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0x81, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Display {
        return Err(fail(0x81, 0x200 | (reply.class as u64)));
    }
    Ok(())
}

/// Asks the kernel where this device's virtio structures are.
fn device_layout() -> Result<DeviceInfoRecord, u64> {
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
        return Err(fail(0x82, 0xe));
    }
    if syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0) < 0 {
        return Err(fail(0x82, 1));
    }
    let bytes = read_kernel_filled::<{ DeviceInfoRecord::WIRE_SIZE }>(&record);
    let info: DeviceInfoRecord = match decode(&bytes) {
        Ok(info) => info,
        Err(_) => return Err(fail(0x82, 0xd)),
    };
    if info.layout_valid == 0 {
        return Err(fail(0x82, 0x100));
    }
    Ok(info)
}

/// Maps the device's register window.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(DEVICE_HANDLE),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x83, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x83, (-base) as u64));
    }
    Ok(base as u64)
}

/// Hands out the next page the device can address.
struct Pages {
    next: usize,
}

impl Pages {
    fn take(&mut self) -> Result<Page, u64> {
        let vaddr = DMA_VA_BASE + (self.next as u64) * PAGE;
        let args = DmaAllocArgs {
            size: DmaAllocArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            device: HandleRef::new(DEVICE_HANDLE),
            reserved: 0,
            vaddr,
        };
        let mut buf = [0u8; DmaAllocArgs::WIRE_SIZE];
        if encode(&args, &mut buf).is_err() {
            return Err(fail(0x84, 0xe));
        }
        let phys = syscall2(SYS_DMA_ALLOC, buf.as_ptr() as u64, 0);
        if phys < 0 {
            return Err(fail(0x84, (-phys) as u64));
        }
        self.next += 1;
        Ok(Page {
            va: vaddr,
            phys: phys as u64,
        })
    }
}

/// The control queue and where the driver is in it.
struct Ring {
    page: Page,
    layout: Layout,
    next_desc: u16,
    avail_index: u16,
    used_index: u16,
}

impl Ring {
    /// Puts one two-descriptor chain on the ring: the command the device reads,
    /// then the buffer it writes its answer into.
    fn submit(&mut self, out_phys: u64, out_len: u32, in_phys: u64, in_len: u32) {
        let head = self.next_desc;
        let second = (head + 1) % QUEUE_SIZE;
        let (layout, avail) = (self.layout, self.avail_index);
        with_page(&self.page, |memory| {
            let mut desc = |index: u16, addr: u64, len: u32, flags: u16, next: u16| {
                let at = layout.desc_offset + usize::from(index) * 16;
                memory[at..at + 8].copy_from_slice(&addr.to_le_bytes());
                memory[at + 8..at + 12].copy_from_slice(&len.to_le_bytes());
                memory[at + 12..at + 14].copy_from_slice(&flags.to_le_bytes());
                memory[at + 14..at + 16].copy_from_slice(&next.to_le_bytes());
            };
            desc(head, out_phys, out_len, 0x1, second);
            desc(second, in_phys, in_len, 0x2, 0);
            let slot = layout.avail_offset + 4 + usize::from(avail % QUEUE_SIZE) * 2;
            memory[slot..slot + 2].copy_from_slice(&head.to_le_bytes());
            let at = layout.avail_offset + 2;
            memory[at..at + 2].copy_from_slice(&avail.wrapping_add(1).to_le_bytes());
        });
        self.avail_index = self.avail_index.wrapping_add(1);
        self.next_desc = (second + 1) % QUEUE_SIZE;
    }

    fn completed(&self) -> bool {
        let layout = self.layout;
        let published = with_page(&self.page, |memory| {
            let at = layout.used_offset + 2;
            u16::from_le_bytes([memory[at], memory[at + 1]])
        });
        published != self.used_index
    }

    fn collect(&mut self) {
        self.used_index = self.used_index.wrapping_add(1);
    }
}

/// Everything the driver carries.
struct Driver {
    control: Ring,
    /// The command's request and its response, in one page.
    command: Page,
    /// The framebuffer, page by page. Physically scattered, which is why the
    /// device is told about it as a list.
    framebuffer: [Page; FB_PAGES],
    power: DisplayPowerState,
}

const REQUEST_AT: usize = 0;
const RESPONSE_AT: usize = 2048;
const RESPONSE_LEN: u32 = 1024;

/// Runs one control-queue command and returns the device's response type.
fn command<T: Transport>(driver: &mut Driver, transport: &T, request: &[u8]) -> Result<u32, u64> {
    let page = driver.command;
    with_page(&page, |memory| {
        memory[REQUEST_AT..REQUEST_AT + request.len()].copy_from_slice(request);
        // Zeroed first, so a response read back is one the device wrote rather
        // than the last one it wrote.
        for byte in &mut memory[RESPONSE_AT..RESPONSE_AT + RESPONSE_LEN as usize] {
            *byte = 0;
        }
    });
    driver.control.submit(
        page.phys + REQUEST_AT as u64,
        request.len() as u32,
        page.phys + RESPONSE_AT as u64,
        RESPONSE_LEN,
    );
    transport.notify(gpu::Queue::Control as u16);
    // Bounded: a device that never answers is a device, not a hang.
    for _ in 0..4_000_000u32 {
        if driver.control.completed() {
            driver.control.collect();
            let kind = with_page(&page, |memory| {
                gpu::response_type(&memory[RESPONSE_AT..RESPONSE_AT + gpu::HEADER_LEN])
            });
            return kind.map_err(|_| fail(0x85, 0));
        }
    }
    Err(fail(0x85, 1))
}

/// Writes one pixel into the framebuffer.
///
/// The page it lands in comes from the offset, because the framebuffer is a
/// list of pages the kernel handed out one at a time and nothing says they are
/// next to each other in memory.
fn put_pixel(driver: &Driver, x: u32, y: u32, colour: u32) {
    let offset = ((y * WIDTH + x) * BYTES_PER_PIXEL) as usize;
    let page = offset / PAGE as usize;
    let Some(page) = driver.framebuffer.get(page) else {
        return;
    };
    let within = offset % PAGE as usize;
    with_page(page, |memory| {
        memory[within..within + 4].copy_from_slice(&colour.to_le_bytes());
    });
}

/// Copies the framebuffer into the device's own copy and puts it on the glass.
fn flush<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    rect: gpu::Rect,
) -> Result<DisplayError, u64> {
    let mut request = [0u8; gpu::TRANSFER_LEN];
    // The offset of the rectangle's first row in the backing, which only this
    // program knows because only it knows the stride it wrote at.
    let offset = u64::from(rect.y) * u64::from(WIDTH) * u64::from(BYTES_PER_PIXEL)
        + u64::from(rect.x) * u64::from(BYTES_PER_PIXEL);
    if gpu::transfer_to_host_2d(RESOURCE, rect, offset, WIDTH, HEIGHT, &mut request).is_err() {
        return Ok(DisplayError::OutOfBounds);
    }
    if !gpu::accepted(command(driver, transport, &request)?) {
        return Ok(DisplayError::Degraded);
    }
    let mut request = [0u8; gpu::FLUSH_LEN];
    if gpu::resource_flush(RESOURCE, rect, WIDTH, HEIGHT, &mut request).is_err() {
        return Ok(DisplayError::OutOfBounds);
    }
    if !gpu::accepted(command(driver, transport, &request)?) {
        return Ok(DisplayError::Degraded);
    }
    Ok(DisplayError::Ok)
}

/// Answers one client request. Returns the reply's encoded length.
fn serve<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    method: u32,
    request: Result<DisplayOutputIncoming, WireError>,
    msg_buf: &mut [u8; MSG_BUF_LEN],
) -> Result<usize, u64> {
    let control_reply =
        |status: DisplayError, state: DisplayPowerState, buf: &mut [u8; MSG_BUF_LEN]| {
            let reply = DisplayControlReply {
                size: DisplayControlReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                state,
            };
            match encode(&reply, &mut buf[..DisplayControlReply::WIRE_SIZE]) {
                Ok(_) => Ok(DisplayControlReply::WIRE_SIZE),
                Err(_) => Err(fail(0x86, 0xe)),
            }
        };

    if method >= VENDOR_ORDINAL_BASE {
        return control_reply(DisplayError::Protocol, driver.power, msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control_reply(DisplayError::Protocol, driver.power, msg_buf);
        }
        Err(_) => return Err(fail(0x87, u64::from(method))),
    };

    match request {
        DisplayOutputIncoming::Describe(_) => {
            let reply = DisplayDescribeReply {
                size: DisplayDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: DisplayError::Ok,
                features: FEATURES,
                width: WIDTH,
                height: HEIGHT,
                format: DisplayFormat::B8g8r8a8,
                bytes_per_pixel: BYTES_PER_PIXEL,
                power_states: (1 << DisplayPowerState::Active as u32)
                    | (1 << DisplayPowerState::Idle as u32),
                resume_latency_us: 1000,
                vendor: 0,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..DisplayDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok(DisplayDescribeReply::WIRE_SIZE),
                Err(_) => Err(fail(0x86, 0xe)),
            }
        }
        DisplayOutputIncoming::Blit(ask) => {
            // **Refused rather than clipped.** A client whose run was quietly
            // trimmed would see a picture it did not compose.
            let count = ask.count.min(BLIT_PIXELS);
            let end = u64::from(ask.x) + u64::from(count);
            let status = if ask.y >= HEIGHT || end > u64::from(WIDTH) || count == 0 {
                DisplayError::OutOfBounds
            } else {
                for index in 0..count {
                    let at = (index * BYTES_PER_PIXEL) as usize;
                    let colour = u32::from_le_bytes([
                        ask.pixels[at],
                        ask.pixels[at + 1],
                        ask.pixels[at + 2],
                        ask.pixels[at + 3],
                    ]);
                    put_pixel(driver, ask.x + index, ask.y, colour);
                }
                DisplayError::Ok
            };
            let reply = DisplayBlitReply {
                size: DisplayBlitReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                written: if status == DisplayError::Ok { count } else { 0 },
            };
            match encode(&reply, &mut msg_buf[..DisplayBlitReply::WIRE_SIZE]) {
                Ok(_) => Ok(DisplayBlitReply::WIRE_SIZE),
                Err(_) => Err(fail(0x86, 0xe)),
            }
        }
        DisplayOutputIncoming::Flush(ask) => {
            let rect = gpu::Rect {
                x: ask.x,
                y: ask.y,
                width: ask.width,
                height: ask.height,
            };
            let status = if rect.within(WIDTH, HEIGHT) {
                flush(driver, transport, rect)?
            } else {
                DisplayError::OutOfBounds
            };
            control_reply(status, driver.power, msg_buf)
        }
        DisplayOutputIncoming::Fill(ask) => {
            let rect = gpu::Rect {
                x: ask.x,
                y: ask.y,
                width: ask.width,
                height: ask.height,
            };
            if !rect.within(WIDTH, HEIGHT) {
                return control_reply(DisplayError::OutOfBounds, driver.power, msg_buf);
            }
            for y in rect.y..rect.y + rect.height {
                for x in rect.x..rect.x + rect.width {
                    put_pixel(driver, x, y, ask.colour);
                }
            }
            control_reply(DisplayError::Ok, driver.power, msg_buf)
        }
        DisplayOutputIncoming::Reset(_) => {
            // Cleared **and shown**: a reset that left the last picture on the
            // glass is one the only observer who matters cannot see.
            for y in 0..HEIGHT {
                for x in 0..WIDTH {
                    put_pixel(driver, x, y, 0xff00_0000);
                }
            }
            let rect = gpu::Rect {
                x: 0,
                y: 0,
                width: WIDTH,
                height: HEIGHT,
            };
            let status = flush(driver, transport, rect)?;
            driver.power = DisplayPowerState::Active;
            control_reply(status, DisplayPowerState::Active, msg_buf)
        }
        DisplayOutputIncoming::SetPower(ask) => match ask.state {
            DisplayPowerState::Active | DisplayPowerState::Idle => {
                driver.power = ask.state;
                control_reply(DisplayError::Ok, ask.state, msg_buf)
            }
            _ => control_reply(DisplayError::NotSupported, driver.power, msg_buf),
        },
        DisplayOutputIncoming::SetCursor(_) => {
            // Advertised as absent and answered as absent.
            control_reply(DisplayError::NotSupported, driver.power, msg_buf)
        }
    }
}

/// The whole program.
fn run() -> u64 {
    if let Err(code) = bind() {
        return code;
    }
    let info = match device_layout() {
        Ok(info) => info,
        Err(code) => return code,
    };
    let base = match map_device(MMIO_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    let common = Window {
        base: (base + u64::from(info.common_offset)) as usize,
    };
    let notify = Window {
        base: (base + u64::from(info.notify_offset)) as usize,
    };
    let isr = Window {
        base: (base + u64::from(info.isr_offset)) as usize,
    };
    let device_cfg = Window {
        base: (base + u64::from(info.device_config_offset)) as usize,
    };
    let transport = PciTransport::new(
        &common,
        &notify,
        info.notify_multiplier,
        Some(&isr),
        Some(&device_cfg),
        gpu::DEVICE_ID,
    );
    if transport
        .probe(gpu::DEVICE_ID, tessera_virtio::Error::NotBlockDevice)
        .is_err()
    {
        return fail(0x88, 0);
    }

    let mut pages = Pages { next: 0 };
    let layout = Layout::for_size(QUEUE_SIZE);
    if layout.total > PAGE as usize {
        return fail(0x88, 1);
    }
    transport.begin();
    let low = transport.device_features_low();
    if transport.negotiate(low, 1).is_err() {
        return fail(0x88, 2);
    }
    let state = match transport.set_features_ok() {
        Ok(state) => state,
        Err(_) => return fail(0x88, 3),
    };
    // Both queues, although only the control queue is driven: a device told a
    // queue is absent behaves differently from one told it is empty.
    let mut rings = [const { None }; 2];
    for index in 0..2u32 {
        let page = match pages.take() {
            Ok(page) => page,
            Err(code) => return code,
        };
        with_page(&page, |memory| {
            for byte in memory.iter_mut() {
                *byte = 0;
            }
        });
        if transport
            .configure_queue(
                index,
                QUEUE_SIZE,
                page.phys + layout.desc_offset as u64,
                page.phys + layout.avail_offset as u64,
                page.phys + layout.used_offset as u64,
            )
            .is_err()
        {
            return fail(0x88, 4);
        }
        rings[index as usize] = Some(Ring {
            page,
            layout,
            next_desc: 0,
            avail_index: 0,
            used_index: 0,
        });
    }
    if transport.driver_ok(state).is_err() {
        return fail(0x88, 5);
    }

    let command_page = match pages.take() {
        Ok(page) => page,
        Err(code) => return code,
    };
    let mut framebuffer = [Page::default(); FB_PAGES];
    for page in framebuffer.iter_mut() {
        *page = match pages.take() {
            Ok(page) => page,
            Err(code) => return code,
        };
    }
    let Some(control) = rings[0].take() else {
        return fail(0x88, 6);
    };
    let mut driver = Driver {
        control,
        command: command_page,
        framebuffer,
        power: DisplayPowerState::Active,
    };

    // What the display is, asked before anything is drawn. A driver that
    // guessed would draw off the edge of a display it never asked about.
    let mut request = [0u8; gpu::HEADER_LEN];
    if gpu::get_display_info(&mut request).is_err() {
        return fail(0x89, 0);
    }
    if !gpu::accepted(match command(&mut driver, &transport, &request) {
        Ok(kind) => kind,
        Err(code) => return code,
    }) {
        return fail(0x89, 1);
    }
    let scanout = with_page(&driver.command, |memory| {
        gpu::Scanout::parse_first(&memory[RESPONSE_AT..RESPONSE_AT + gpu::DISPLAY_INFO_LEN])
    });
    let Ok(scanout) = scanout else {
        return fail(0x89, 2);
    };
    // A display with nothing attached is a state and not a fault, and this
    // driver reports it rather than drawing into nothing.
    if !scanout.enabled || scanout.width == 0 {
        return fail(0x89, 0x100);
    }

    // The resource, its backing, and the scanout it goes on.
    let mut request = [0u8; gpu::CREATE_2D_LEN];
    if gpu::resource_create_2d(RESOURCE, WIDTH, HEIGHT, gpu::FORMAT_B8G8R8A8, &mut request).is_err()
    {
        return fail(0x8a, 0);
    }
    if !gpu::accepted(match command(&mut driver, &transport, &request) {
        Ok(kind) => kind,
        Err(code) => return code,
    }) {
        return fail(0x8a, 1);
    }
    // **A list, because the pages are not next to each other.** The kernel
    // handed them out one at a time and nothing promised they are contiguous,
    // which is exactly the case this command exists for.
    let mut entries = [(0u64, 0u32); FB_PAGES];
    for (entry, page) in entries.iter_mut().zip(driver.framebuffer.iter()) {
        *entry = (page.phys, PAGE as u32);
    }
    let mut request = [0u8; gpu::ATTACH_HEADER_LEN + FB_PAGES * gpu::ATTACH_ENTRY_LEN];
    if gpu::resource_attach_backing(RESOURCE, &entries, &mut request).is_err() {
        return fail(0x8a, 2);
    }
    if !gpu::accepted(match command(&mut driver, &transport, &request) {
        Ok(kind) => kind,
        Err(code) => return code,
    }) {
        return fail(0x8a, 3);
    }
    let full = gpu::Rect {
        x: 0,
        y: 0,
        width: WIDTH,
        height: HEIGHT,
    };
    let mut request = [0u8; gpu::SET_SCANOUT_LEN];
    if gpu::set_scanout(SCANOUT, RESOURCE, full, WIDTH, HEIGHT, &mut request).is_err() {
        return fail(0x8a, 4);
    }
    if !gpu::accepted(match command(&mut driver, &transport, &request) {
        Ok(kind) => kind,
        Err(code) => return code,
    }) {
        return fail(0x8a, 5);
    }

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut args = match channel_args(msg_buf.as_ptr() as u64, MSG_BUF_LEN as u64) {
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
            return fail(0x8b, (-n) as u64);
        }
        let method = kernel_u32(&args, ARGS_METHOD_ID);
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        let request = DisplayOutputIncoming::decode(method, &mut Reader::in_message(&bytes, 0));
        let reply_len = match serve(&mut driver, &transport, method, request, &mut msg_buf) {
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
            return fail(0x8c, (-replied) as u64);
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
