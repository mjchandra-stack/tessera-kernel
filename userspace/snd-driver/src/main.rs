// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **audio driver**: a `no_std` Rust program that brings a
//! virtio-sound device up and serves `tessera.driver.audio` over it.
//!
//! **It is the first driver here whose device is never finished.** Every other
//! one answers a request and stops: a sector arrives, a frame goes out, a line
//! is read. A playback stream is a standing obligation — the device consumes
//! periods at the rate of the sound and plays silence the moment there is
//! nothing to consume, and nothing fails while that happens.
//!
//! **So this driver counts.** An underrun has no register: the device does not
//! fault when it runs dry, so the only thing that knows a gap was heard is the
//! program that had nothing ready when a period came back. That accounting is
//! `tessera_virtio::snd::Stream`, host-tested, and reporting it is what `Status`
//! is a required method for.
//!
//! The transport is `tessera-virtio`'s PCI transport and split virtqueue,
//! unchanged; what this file adds is the syscalls, the volatile access to a
//! window the kernel mapped, and the pages the device reads.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md ("Audio")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use audio_output::{
    AudioControlReply, AudioDescribeReply, AudioError, AudioFormat, AudioOutputIncoming,
    AudioPowerState, AudioStatusReply, AudioWriteReply,
};
use device_abi::DeviceInfoRecord;
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{Reader, WireError, decode, encode};
use tessera_sdk::{
    Dma as Page, Endpoint, Error as SdkError, Handle as SdkHandle, Platform as _, machine::Machine,
};
use tessera_uabi::fail;
use tessera_virtio::pci::{PciTransport, Regs};
use tessera_virtio::snd;
use tessera_virtio::{Layout, Transport};


/// The capabilities boot installs, in order.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;
/// Where the bound device lands: two handles are installed above it.
const DEVICE_HANDLE: u32 = 2;

/// Where this program asks for the device's registers and its DMA pages.
const MMIO_VA: u64 = 0x0000_1000_0040_0000;
const DMA_VA_BASE: u64 = 0x0000_1000_0050_0000;
const PAGE: u64 = 0x1000;

/// Queue entries. **Twice the chains, because a chain is two descriptors**: the
/// device reads the request and writes the answer, and a queue sized to the
/// periods rather than to the descriptors would reuse a descriptor the device
/// still holds.
const QUEUE_SIZE: u16 = 16;

/// The streams this driver serves. Two, because the check needs one kept fed
/// and one deliberately starved — and a driver that could only hold one could
/// not tell the difference between them.
const MAX_STREAMS: usize = 2;

/// One period, in bytes — and it is exactly what one `Write` carries.
///
/// **Because the contract's inline payload is what a client can supply per
/// round trip.** A period several writes long means the client needs several
/// syscalls to produce one, and against a device that consumes faster than that
/// the stream drains no matter how attentive the client is — every stream would
/// underrun and the value would stop distinguishing anything. One write, one
/// period is what makes "kept fed" a state a client can actually hold.
///
/// The real answer is to grant the client's own memory rather than copy through
/// a message, which is the out-of-line mechanism the block class has and this
/// contract does not (build/README.md, D158).
const PERIOD_BYTES: u32 = 64;
/// How many the device may hold at once. Half the chains the queue has room
/// for, so a submission never overtakes a descriptor still in flight.
const PERIODS: u32 = 4;

/// The one format and rate this driver sets up. A mixer and rate conversion are
/// a service above this contract, not part of it.
const CHANNELS: u8 = 2;
const RATE_HZ: u32 = 44100;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;


/// What this driver advertises: it pauses, and it has no mixer and no capture.
const FEATURES: u64 = 0x1;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// A window the kernel mapped, at some offset into it.
///
/// One type for all four virtio-pci structures, because they differ only in
/// where they start — which is what the offsets in `DeviceInfoRecord` say.
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
        // SAFETY: as `read8`; this driver exclusively owns the device, which is
        // a property of the capability being conserved rather than shared.
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

/// Hands the transport core a slice over a DMA page.
///
/// The pointer is the platform's rather than this program's: a DMA page is
/// only memory on the machine that mapped it, and going through `with_dma` is
/// what lets `tessera_sdk::dma` watch what a driver does with one.
fn with_page<R>(page: &Page, f: impl FnOnce(&mut [u8]) -> R) -> R {
    Machine.with_dma(page, f)
}

/// Acquires an audio device from the device manager.
fn bind() -> Result<(), u64> {
    let mut message = [0u8; BindReply::WIRE_SIZE];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Audio,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0x71, 0xe));
    }
    let mut answer = [0u8; BindReply::WIRE_SIZE];
    tessera_sdk::bind(
        &mut Machine,
        Endpoint(SdkHandle(MANAGER_ENDPOINT_HANDLE)),
        &message,
        &mut answer,
    )
    .map_err(|_| fail(0x71, 1))?;
    let reply: BindReply = match decode(&answer) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x71, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0x71, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Audio {
        return Err(fail(0x71, 0x200 | (reply.class as u64)));
    }
    Ok(())
}

/// Asks the kernel where this device's virtio structures are.
///
/// A virtio-pci device says so in configuration space, which is not per-device
/// and so cannot be handed to a driver — the kernel read it during enumeration
/// and this is how a holder asks for what it found.
fn device_layout() -> Result<DeviceInfoRecord, u64> {
    let mut record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    Machine
        .device_info(SdkHandle(u64::from(DEVICE_HANDLE)), &mut record)
        .map_err(|_| fail(0x72, 1))?;
    let info: DeviceInfoRecord = match decode(&record) {
        Ok(info) => info,
        Err(_) => return Err(fail(0x72, 0xd)),
    };
    // A device whose structures the kernel did not resolve is one this driver
    // cannot find its way around: reported rather than driven at offset zero.
    if info.layout_valid == 0 {
        return Err(fail(0x72, 0x100));
    }
    Ok(info)
}

/// Maps the device's register window.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    Machine
        .map_device(SdkHandle(u64::from(DEVICE_HANDLE)), vaddr)
        .map_err(|_| fail(0x73, 1))
}

/// Hands out the next page the device can address.
struct Pages {
    next: usize,
}

impl Pages {
    fn take(&mut self) -> Result<Page, u64> {
        let vaddr = DMA_VA_BASE + (self.next as u64) * PAGE;
        let page = Machine
            .dma_alloc(SdkHandle(u64::from(DEVICE_HANDLE)), vaddr)
            .map_err(|_| fail(0x74, 1))?;
        self.next += 1;
        Ok(page)
    }
}

/// One virtqueue: its ring page and where the driver is in it.
struct Ring {
    page: Page,
    layout: Layout,
    index: u16,
    /// The next descriptor to use. The queue never holds more than
    /// `QUEUE_SIZE` entries because nothing here submits without a slot.
    next_desc: u16,
    avail_index: u16,
    used_index: u16,
}

impl Ring {
    /// Puts one two-descriptor chain on the ring: something the device reads,
    /// then something it writes.
    ///
    /// Two rather than one because every message this device takes has an
    /// answer written back — a control status, or the status after a period —
    /// and a single descriptor cannot be both read-only to the device and
    /// written by it.
    fn submit(&mut self, out_phys: u64, out_len: u32, in_phys: u64, in_len: u32) -> u16 {
        let head = self.next_desc;
        let second = (head + 1) % QUEUE_SIZE;
        with_page(&self.page, |memory| {
            let desc =
                |memory: &mut [u8], index: u16, addr: u64, len: u32, flags: u16, next: u16| {
                    let at = self.layout.desc_offset + usize::from(index) * 16;
                    memory[at..at + 8].copy_from_slice(&addr.to_le_bytes());
                    memory[at + 8..at + 12].copy_from_slice(&len.to_le_bytes());
                    memory[at + 12..at + 14].copy_from_slice(&flags.to_le_bytes());
                    memory[at + 14..at + 16].copy_from_slice(&next.to_le_bytes());
                };
            // NEXT on the first, WRITE on the second: the device reads the
            // request and writes the answer.
            desc(memory, head, out_phys, out_len, 0x1, second);
            desc(memory, second, in_phys, in_len, 0x2, 0);
            // The available ring: the head, then the index that publishes it.
            let slot =
                self.layout.avail_offset + 4 + usize::from(self.avail_index % QUEUE_SIZE) * 2;
            memory[slot..slot + 2].copy_from_slice(&head.to_le_bytes());
            self.avail_index = self.avail_index.wrapping_add(1);
            let at = self.layout.avail_offset + 2;
            memory[at..at + 2].copy_from_slice(&self.avail_index.to_le_bytes());
        });
        self.next_desc = (second + 1) % QUEUE_SIZE;
        head
    }

    /// Whether the device has finished anything this driver has not collected.
    fn completed(&self) -> bool {
        let published = with_page(&self.page, |memory| {
            let at = self.layout.used_offset + 2;
            u16::from_le_bytes([memory[at], memory[at + 1]])
        });
        published != self.used_index
    }

    /// Takes one completion, and says **which chain** it was.
    ///
    /// The head matters here in a way it does not for a device with one kind of
    /// work. Two streams share this queue and the used ring says nothing about
    /// which stream a buffer belonged to — so a driver that took completions in
    /// order and attributed them to whichever stream had one outstanding would
    /// credit a fed stream with a starved stream's period, and the underrun
    /// would be reported against the wrong sound.
    fn collect(&mut self) -> u16 {
        let head = with_page(&self.page, |memory| {
            let at = self.layout.used_offset + 4 + usize::from(self.used_index % QUEUE_SIZE) * 8;
            u32::from_le_bytes([memory[at], memory[at + 1], memory[at + 2], memory[at + 3]]) as u16
        });
        self.used_index = self.used_index.wrapping_add(1);
        head
    }
}

/// One playback stream.
struct StreamState {
    /// Whether a client has configured it.
    configured: bool,
    started: bool,
    /// The accounting the class contract's `Status` reports, and the only place
    /// an underrun exists.
    stream: snd::Stream,
    /// Bytes of the period being assembled. A period crosses the contract in
    /// sixty-four-byte writes, so several make one.
    filled: u32,
    /// The page the samples go in, and the header and status beside them.
    buffer: Page,
}

/// Everything the driver carries.
struct Driver {
    control: Ring,
    transmit: Ring,
    /// The control queue's request and response, in one page.
    control_page: Page,
    /// Which stream each outstanding transmit chain belongs to, by its head
    /// descriptor. The used ring does not say, and two streams share the queue.
    transmit_owner: [u8; QUEUE_SIZE as usize],
    streams: [StreamState; MAX_STREAMS],
    power: AudioPowerState,
}

/// Where the pieces of a transmit page live: the header the device reads, the
/// samples after it, and the status it writes at the end.
const XFER_HEADER_AT: usize = 0;
const XFER_SAMPLES_AT: usize = 64;
const XFER_STATUS_AT: usize = 2048;

/// Where the control page's request and response live.
const CONTROL_REQUEST_AT: usize = 0;
const CONTROL_RESPONSE_AT: usize = 256;

/// Runs one control-queue transaction and returns the device's status.
fn control<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    request: &[u8],
    response_len: u32,
) -> Result<u32, u64> {
    with_page(&driver.control_page, |memory| {
        memory[CONTROL_REQUEST_AT..CONTROL_REQUEST_AT + request.len()].copy_from_slice(request);
        // The response is zeroed first, so a status read back is one the device
        // wrote rather than the last one it wrote.
        for byte in &mut memory[CONTROL_RESPONSE_AT..CONTROL_RESPONSE_AT + response_len as usize] {
            *byte = 0;
        }
    });
    let head = driver.control.submit(
        driver.control_page.device_address + CONTROL_REQUEST_AT as u64,
        request.len() as u32,
        driver.control_page.device_address + CONTROL_RESPONSE_AT as u64,
        response_len,
    );
    let _ = head;
    transport.notify(snd::Queue::Control as u16);
    // Bounded: a device that never answers a control request is a device, not
    // a hang.
    for _ in 0..4_000_000u32 {
        if driver.control.completed() {
            let _ = driver.control.collect();
            let status = with_page(&driver.control_page, |memory| {
                snd::control_status(&memory[CONTROL_RESPONSE_AT..CONTROL_RESPONSE_AT + 4])
            });
            return status.map_err(|_| fail(0x75, 0));
        }
    }
    Err(fail(0x75, 1))
}

/// Brings one stream up: parameters, prepare, start.
fn open_stream<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    index: usize,
) -> Result<AudioError, u64> {
    let params = snd::Params {
        stream: index as u32,
        buffer_bytes: PERIOD_BYTES * PERIODS,
        period_bytes: PERIOD_BYTES,
        channels: CHANNELS,
        format: snd::FORMAT_S16,
        rate: snd::RATE_44100,
    };
    let mut request = [0u8; snd::SET_PARAMS_LEN];
    if snd::set_params(&params, &mut request).is_err() {
        return Ok(AudioError::BadFormat);
    }
    if !snd::accepted(control(
        driver,
        transport,
        &request,
        snd::CONTROL_STATUS_LEN as u32,
    )?) {
        return Ok(AudioError::BadFormat);
    }
    // **Prepared, and not started.** Starting is its own method because a
    // stream started empty gaps before the first sample is heard: a client
    // primes the ring first, and it can only do that if configuring has not
    // already set the device running.
    let mut request = [0u8; snd::STREAM_REQUEST_LEN];
    if snd::stream_request(snd::request::PCM_PREPARE, index as u32, &mut request).is_err() {
        return Ok(AudioError::Protocol);
    }
    if !snd::accepted(control(
        driver,
        transport,
        &request,
        snd::CONTROL_STATUS_LEN as u32,
    )?) {
        return Ok(AudioError::Protocol);
    }
    Ok(AudioError::Ok)
}

/// Collects whatever the device has finished with, and tells each stream
/// whether there was another period ready to take its place.
///
/// **This is where an underrun is observed.** The device gave a period back and
/// asked for the next one; if the stream had nothing assembled, a gap was
/// heard, and nothing else in the machine will ever mention it.
fn reap(driver: &mut Driver) {
    while driver.transmit.completed() {
        let head = driver.transmit.collect();
        let Some(owner) = driver
            .transmit_owner
            .get(usize::from(head % QUEUE_SIZE))
            .copied()
        else {
            continue;
        };
        let Some(state) = driver.streams.get_mut(usize::from(owner)) else {
            continue;
        };
        if state.stream.outstanding() == 0 {
            continue;
        }
        // **The question no register can be asked**, and it is about the queue
        // rather than about this instant. While the device still holds a
        // period, or the driver has a whole one assembled, the sound continues
        // — a client that refills on demand has nothing assembled the moment
        // after it submitted, and calling that a gap would report an underrun
        // on every stream that is keeping up perfectly.
        //
        // What is a gap is the device having nothing left: it asked, the queue
        // was empty, and silence went out.
        let still_queued = state.stream.outstanding() > 1;
        let refilled = still_queued || state.filled >= PERIOD_BYTES;
        state.stream.completed(refilled);
    }
}

/// Hands one assembled period to the device.
fn submit_period<T: Transport>(driver: &mut Driver, transport: &T, index: usize) {
    let Some(state) = driver.streams.get_mut(index) else {
        return;
    };
    if state.stream.submitted().is_err() {
        return;
    }
    let buffer = state.buffer;
    state.filled = 0;
    with_page(&buffer, |memory| {
        let _ = snd::xfer_header(index as u32, &mut memory[XFER_HEADER_AT..]);
    });
    let head = driver.transmit.submit(
        buffer.device_address + XFER_HEADER_AT as u64,
        snd::XFER_HEADER_LEN as u32 + PERIOD_BYTES,
        buffer.device_address + XFER_STATUS_AT as u64,
        snd::XFER_STATUS_LEN as u32,
    );
    if let Some(slot) = driver
        .transmit_owner
        .get_mut(usize::from(head % QUEUE_SIZE))
    {
        *slot = index as u8;
    }
    transport.notify(snd::Queue::Transmit as u16);
}

/// Answers one client request. Returns the reply's encoded length.
fn serve<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    method: u32,
    request: Result<AudioOutputIncoming, WireError>,
    msg_buf: &mut [u8],
) -> Result<usize, u64> {
    let control_reply =
        |status: AudioError, state: AudioPowerState, buf: &mut [u8]| {
            let reply = AudioControlReply {
                size: AudioControlReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                state,
            };
            match encode(&reply, &mut buf[..AudioControlReply::WIRE_SIZE]) {
                Ok(_) => Ok(AudioControlReply::WIRE_SIZE),
                Err(_) => Err(fail(0x76, 0xe)),
            }
        };

    if method >= VENDOR_ORDINAL_BASE {
        return control_reply(AudioError::Protocol, driver.power, msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control_reply(AudioError::Protocol, driver.power, msg_buf);
        }
        Err(_) => return Err(fail(0x77, u64::from(method))),
    };

    // Every request is a chance to notice what the device has finished with,
    // because a stream nobody asks about is a stream nobody would hear about.
    reap(driver);

    match request {
        AudioOutputIncoming::Describe(_) => {
            let reply = AudioDescribeReply {
                size: AudioDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: AudioError::Ok,
                features: FEATURES,
                streams: MAX_STREAMS as u32,
                period_bytes: PERIOD_BYTES,
                periods: PERIODS,
                channels_max: u32::from(CHANNELS),
                power_states: (1 << AudioPowerState::Active as u32)
                    | (1 << AudioPowerState::Idle as u32),
                resume_latency_us: 1000,
                vendor: 0,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..AudioDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok(AudioDescribeReply::WIRE_SIZE),
                Err(_) => Err(fail(0x76, 0xe)),
            }
        }
        AudioOutputIncoming::Configure(ask) => {
            let Some(index) = usize::try_from(ask.stream)
                .ok()
                .filter(|i| *i < MAX_STREAMS)
            else {
                return control_reply(AudioError::NoStream, driver.power, msg_buf);
            };
            // Refused rather than converted: a client that asked for one rate
            // and silently got another would hear its audio at the wrong speed
            // and have nothing to check.
            if ask.format != AudioFormat::S16
                || ask.rate != RATE_HZ
                || ask.channels != u32::from(CHANNELS)
            {
                return control_reply(AudioError::BadFormat, driver.power, msg_buf);
            }
            let status = open_stream(driver, transport, index)?;
            if status == AudioError::Ok {
                driver.streams[index].configured = true;
                driver.streams[index].started = false;
                driver.streams[index].stream = snd::Stream::new(PERIODS);
            }
            control_reply(status, driver.power, msg_buf)
        }
        AudioOutputIncoming::Start(ask) => {
            let Some(index) = usize::try_from(ask.stream)
                .ok()
                .filter(|i| *i < MAX_STREAMS)
            else {
                return control_reply(AudioError::NoStream, driver.power, msg_buf);
            };
            if !driver.streams[index].configured {
                return control_reply(AudioError::NoStream, driver.power, msg_buf);
            }
            if driver.streams[index].started {
                return control_reply(AudioError::Ok, driver.power, msg_buf);
            }
            let mut request = [0u8; snd::STREAM_REQUEST_LEN];
            if snd::stream_request(snd::request::PCM_START, index as u32, &mut request).is_err() {
                return control_reply(AudioError::Protocol, driver.power, msg_buf);
            }
            let status = control(driver, transport, &request, snd::CONTROL_STATUS_LEN as u32)?;
            if !snd::accepted(status) {
                return control_reply(AudioError::Protocol, driver.power, msg_buf);
            }
            driver.streams[index].started = true;
            control_reply(AudioError::Ok, driver.power, msg_buf)
        }
        AudioOutputIncoming::Write(ask) => {
            let index = usize::try_from(ask.stream)
                .ok()
                .filter(|i| *i < MAX_STREAMS);
            let (status, accepted, outstanding) = match index {
                None => (AudioError::NoStream, 0, 0),
                Some(index) if !driver.streams[index].configured => (AudioError::NoStream, 0, 0),
                Some(index) => {
                    // **The underrun is reported here and observed elsewhere.**
                    // What is being answered is a write that worked; what is
                    // being reported is what happened before it arrived.
                    let gapped = driver.streams[index].stream.underruns() > 0;
                    let length = (ask.length as usize).min(ask.samples.len());
                    let state = &mut driver.streams[index];
                    let room = (PERIOD_BYTES - state.filled) as usize;
                    let take = length.min(room);
                    let at = XFER_SAMPLES_AT + state.filled as usize;
                    let buffer = state.buffer;
                    with_page(&buffer, |memory| {
                        memory[at..at + take].copy_from_slice(&ask.samples[..take]);
                    });
                    state.filled += take as u32;
                    let full = state.filled >= PERIOD_BYTES;
                    let has_room = state.stream.has_room();
                    if full && has_room {
                        submit_period(driver, transport, index);
                    }
                    let outstanding = driver.streams[index].stream.outstanding();
                    let status = if gapped {
                        AudioError::Underrun
                    } else if take == 0 {
                        // Nothing was taken because the device is holding all it
                        // can. The stream working, and how a client learns to
                        // wait rather than buffer without bound.
                        AudioError::Busy
                    } else {
                        AudioError::Ok
                    };
                    (status, take as u32, outstanding)
                }
            };
            let reply = AudioWriteReply {
                size: AudioWriteReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                accepted,
                outstanding,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..AudioWriteReply::WIRE_SIZE]) {
                Ok(_) => Ok(AudioWriteReply::WIRE_SIZE),
                Err(_) => Err(fail(0x76, 0xe)),
            }
        }
        AudioOutputIncoming::Status(ask) => {
            let index = usize::try_from(ask.stream)
                .ok()
                .filter(|i| *i < MAX_STREAMS);
            let (status, played, underruns, outstanding) = match index {
                Some(index) if driver.streams[index].configured => {
                    let stream = &driver.streams[index].stream;
                    (
                        AudioError::Ok,
                        stream.played(),
                        stream.underruns(),
                        stream.outstanding(),
                    )
                }
                _ => (AudioError::NoStream, 0, 0, 0),
            };
            let reply = AudioStatusReply {
                size: AudioStatusReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                stream: ask.stream,
                played,
                underruns,
                outstanding,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..AudioStatusReply::WIRE_SIZE]) {
                Ok(_) => Ok(AudioStatusReply::WIRE_SIZE),
                Err(_) => Err(fail(0x76, 0xe)),
            }
        }
        AudioOutputIncoming::Stop(ask) => {
            let Some(index) = usize::try_from(ask.stream)
                .ok()
                .filter(|i| *i < MAX_STREAMS)
            else {
                return control_reply(AudioError::NoStream, driver.power, msg_buf);
            };
            let mut request = [0u8; snd::STREAM_REQUEST_LEN];
            let _ = snd::stream_request(snd::request::PCM_STOP, index as u32, &mut request);
            let status = control(driver, transport, &request, snd::CONTROL_STATUS_LEN as u32)?;
            driver.streams[index].started = false;
            control_reply(
                if snd::accepted(status) {
                    AudioError::Ok
                } else {
                    AudioError::Protocol
                },
                driver.power,
                msg_buf,
            )
        }
        AudioOutputIncoming::Reset(_) => {
            // Every stream stopped and unconfigured, and the counts go with
            // them: carrying an underrun forward would report a gap in one
            // sound as having happened during another.
            for index in 0..MAX_STREAMS {
                if driver.streams[index].configured {
                    let mut request = [0u8; snd::STREAM_REQUEST_LEN];
                    let _ =
                        snd::stream_request(snd::request::PCM_RELEASE, index as u32, &mut request);
                    let _ = control(driver, transport, &request, snd::CONTROL_STATUS_LEN as u32)?;
                }
                driver.streams[index].configured = false;
                driver.streams[index].started = false;
                driver.streams[index].filled = 0;
                driver.streams[index].stream = snd::Stream::new(PERIODS);
            }
            driver.power = AudioPowerState::Active;
            control_reply(AudioError::Ok, AudioPowerState::Active, msg_buf)
        }
        AudioOutputIncoming::SetPower(ask) => match ask.state {
            AudioPowerState::Active | AudioPowerState::Idle => {
                driver.power = ask.state;
                control_reply(AudioError::Ok, ask.state, msg_buf)
            }
            _ => control_reply(AudioError::NotSupported, driver.power, msg_buf),
        },
        AudioOutputIncoming::SetVolume(_) => {
            // Advertised as absent and answered as absent, which is the only
            // pair a client's feature check can rely on.
            control_reply(AudioError::NotSupported, driver.power, msg_buf)
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
        snd::DEVICE_ID,
    );
    if transport
        .probe(snd::DEVICE_ID, tessera_virtio::Error::NotSoundDevice)
        .is_err()
    {
        return fail(0x78, 0);
    }
    // What the device says about itself, before it is asked for anything.
    let config = match snd::Config::parse([
        transport.config_u32(0),
        transport.config_u32(4),
        transport.config_u32(8),
    ]) {
        Ok(config) => config,
        Err(_) => return fail(0x78, 1),
    };
    if (config.streams as usize) < MAX_STREAMS {
        return fail(0x78, 0x100 | u64::from(config.streams));
    }

    let mut pages = Pages { next: 0 };
    let layout = Layout::for_size(QUEUE_SIZE);
    if layout.total > PAGE as usize {
        return fail(0x78, 2);
    }

    transport.begin();
    let low = transport.device_features_low();
    if transport.negotiate(low, 1).is_err() {
        return fail(0x78, 3);
    }
    let state = match transport.set_features_ok() {
        Ok(state) => state,
        Err(_) => return fail(0x78, 4),
    };

    // Four queues, and each needs its own ring even though this driver only
    // drives two: a device told a queue is absent behaves differently from one
    // told it is empty, and the specification has no way to say the first.
    let mut rings = [const { None }; 4];
    for index in 0..4u32 {
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
                page.device_address + layout.desc_offset as u64,
                page.device_address + layout.avail_offset as u64,
                page.device_address + layout.used_offset as u64,
            )
            .is_err()
        {
            return fail(0x78, 5);
        }
        rings[index as usize] = Some(Ring {
            page,
            layout,
            index: index as u16,
            next_desc: 0,
            avail_index: 0,
            used_index: 0,
        });
    }
    if transport.driver_ok(state).is_err() {
        return fail(0x78, 6);
    }

    let control_page = match pages.take() {
        Ok(page) => page,
        Err(code) => return code,
    };
    // The SDK does not derive `Default` for a DMA page, because a zeroed one
    // is not a page. This array is filled one stream at a time, so the driver
    // says what it means by an entry it has not filled yet.
    const UNALLOCATED: Page = Page {
        va: 0,
        device_address: 0,
    };
    let mut buffers = [UNALLOCATED; MAX_STREAMS];
    for buffer in buffers.iter_mut() {
        *buffer = match pages.take() {
            Ok(page) => page,
            Err(code) => return code,
        };
    }
    let (Some(control_ring), Some(transmit_ring)) = (rings[0].take(), rings[2].take()) else {
        return fail(0x78, 7);
    };
    let mut driver = Driver {
        control: control_ring,
        transmit: transmit_ring,
        control_page,
        transmit_owner: [0; QUEUE_SIZE as usize],
        streams: [
            StreamState {
                configured: false,
                started: false,
                stream: snd::Stream::new(PERIODS),
                filled: 0,
                buffer: buffers[0],
            },
            StreamState {
                configured: false,
                started: false,
                stream: snd::Stream::new(PERIODS),
                filled: 0,
                buffer: buffers[1],
            },
        ],
        power: AudioPowerState::Active,
    };

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut failure = 0u64;
    // The receive, the reply-and-loop-back, and the volatile read of what the
    // kernel wrote are the SDK's; what an audio request means is this
    // driver's. The reply goes straight into the buffer `serve` will send —
    // there is no second staging copy.
    let served = tessera_sdk::serve(
        &mut Machine,
        Endpoint(SdkHandle(CLIENT_ENDPOINT_HANDLE)),
        &mut msg_buf,
        |method, bytes, out| {
            let request = AudioOutputIncoming::decode(method, &mut Reader::in_message(bytes, 0));
            match serve(&mut driver, &transport, method, request, out) {
                Ok(len) => Ok(len),
                Err(code) => {
                    // A class failure is this driver's, not the platform's, so
                    // it is carried out rather than folded into an SDK error.
                    failure = code;
                    Err(SdkError::NotBound)
                }
            }
        },
    );
    if failure != 0 {
        return failure;
    }
    match served {
        Ok(()) => fail(0x79, 11),
        Err(_) => fail(0x79, 1),
    }
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    Machine.finish(value)
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
