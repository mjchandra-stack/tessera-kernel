// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The virtio-sound protocol: what a stream is asked for, and what one period
//! of audio looks like on the wire.
//!
//! Beside [`Blk`](crate::Blk) and [`Net`](crate::Net), on the same transport
//! and the same split virtqueue. What is different is the *shape of the work*.
//! A block request is finished when its answer arrives and a frame is finished
//! when it is sent; a playback stream is a standing obligation with a deadline,
//! and the device plays silence the moment the driver stops keeping up. Nothing
//! fails while that happens, which is why the accounting matters more here than
//! the error codes do.
//!
//! # Four queues, and which one a message belongs on is part of the message
//!
//! Control, event, transmit, receive — and unlike NVMe's queue pairs they are
//! not interchangeable. A `PCM_START` on the transmit queue is not a slow
//! start, it is samples; so [`Queue`] is returned by the encoders rather than
//! remembered by each caller.
//!
//! # The status is at the end of the buffer, not in the used ring
//!
//! This is the mistake this device invites. One transmit buffer is a header
//! naming the stream, then the samples, then a **status the device writes after
//! them**. The used ring's length covers what the device wrote, which is the
//! status — so a driver that read it as "bytes played" would be reading a
//! length where the audio is and audio where the length is, and would hear
//! something plausible while believing something false.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md ("Audio")
//! Budget: none (driven from ring 3)

use crate::Error;

/// The virtio device id a sound device carries.
pub const DEVICE_ID: u32 = 25;

/// The queues a sound device has, in the order the specification numbers them.
///
/// Returned by the encoders rather than left to the caller, because they are
/// not interchangeable: a control request put on the transmit queue is not a
/// slow request, it is noise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Queue {
    Control = 0,
    Event = 1,
    Transmit = 2,
    /// Capture. Declared because the device has it and a driver that pretended
    /// otherwise would be describing a different device; nothing here drives it
    /// (build/README.md, D158).
    Receive = 3,
}

/// Control request codes.
pub mod request {
    pub const PCM_INFO: u32 = 0x0100;
    pub const PCM_SET_PARAMS: u32 = 0x0101;
    pub const PCM_PREPARE: u32 = 0x0102;
    pub const PCM_RELEASE: u32 = 0x0103;
    pub const PCM_START: u32 = 0x0104;
    pub const PCM_STOP: u32 = 0x0105;
}

/// Status codes a device answers a control request with.
pub mod status {
    pub const OK: u32 = 0x8000;
    pub const BAD_MSG: u32 = 0x8001;
    pub const NOT_SUPPORTED: u32 = 0x8002;
    pub const IO_ERROR: u32 = 0x8003;
}

/// Sample formats, as the specification numbers them. Only the one this tree
/// uses is named; a format is a number on the wire and naming every one would
/// be listing a table nobody reads.
pub const FORMAT_S16: u8 = 5;
/// Rates, likewise: 44.1 kHz, which every backend supports.
pub const RATE_44100: u8 = 7;

/// Bytes in a control request header — the request code and nothing else.
pub const CONTROL_HEADER_LEN: usize = 4;
/// Bytes in a control response header, which is a status.
pub const CONTROL_STATUS_LEN: usize = 4;
/// Bytes in a `PCM_SET_PARAMS` request, header included.
pub const SET_PARAMS_LEN: usize = 24;
/// Bytes in a request that names a stream and nothing else — prepare, start,
/// stop, release.
pub const STREAM_REQUEST_LEN: usize = 8;
/// Bytes one `PCM_INFO` answer occupies, per stream.
pub const PCM_INFO_LEN: usize = 32;
/// Bytes in a transmit buffer's header: the stream it belongs to.
pub const XFER_HEADER_LEN: usize = 8;
/// Bytes in the status the device writes after the samples: a status and the
/// count of bytes it consumed.
pub const XFER_STATUS_LEN: usize = 8;

/// What the device says about itself, out of its configuration space.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Config {
    pub jacks: u32,
    pub streams: u32,
    pub channel_maps: u32,
}

impl Config {
    /// Reads the four configuration words a sound device exposes.
    ///
    /// A device with no streams is refused rather than driven: every request
    /// below names one, and there is no useful thing to do with a sound card
    /// that has none.
    pub fn parse(words: [u32; 3]) -> Result<Config, Error> {
        let config = Config {
            jacks: words[0],
            streams: words[1],
            channel_maps: words[2],
        };
        if config.streams == 0 {
            return Err(Error::NotSoundDevice);
        }
        Ok(config)
    }
}

/// What a stream is being asked to play.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    pub stream: u32,
    /// Bytes the device may hold at once, across all periods.
    pub buffer_bytes: u32,
    /// Bytes in one period — the unit the device consumes and returns.
    pub period_bytes: u32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
}

impl Params {
    /// Whether these parameters describe something playable.
    ///
    /// **A period that does not divide the buffer is refused**, because the
    /// device consumes whole periods: the remainder would be a piece of buffer
    /// that is never played and never returned, and the stream would lose a
    /// little latency budget every time round.
    pub fn check(&self) -> Result<(), Error> {
        if self.period_bytes == 0 || self.buffer_bytes == 0 || self.channels == 0 {
            return Err(Error::BadStreamParams);
        }
        if self.period_bytes > self.buffer_bytes {
            return Err(Error::BadStreamParams);
        }
        if !self.buffer_bytes.is_multiple_of(self.period_bytes) {
            return Err(Error::BadStreamParams);
        }
        Ok(())
    }

    /// How many periods the device can hold at once — what a client must be
    /// told so it can keep exactly that many in flight.
    pub fn periods(&self) -> u32 {
        self.buffer_bytes / self.period_bytes
    }
}

/// Writes a request that names only a stream: prepare, start, stop, release.
pub fn stream_request(code: u32, stream: u32, out: &mut [u8]) -> Result<Queue, Error> {
    if out.len() < STREAM_REQUEST_LEN {
        return Err(Error::BadStreamParams);
    }
    out[0..4].copy_from_slice(&code.to_le_bytes());
    out[4..8].copy_from_slice(&stream.to_le_bytes());
    Ok(Queue::Control)
}

/// Writes a `PCM_SET_PARAMS` request.
///
/// The parameters are checked here rather than by the device, because a device
/// that refuses them answers with one status for every possible reason — and a
/// driver told only "bad message" has to guess which of six numbers it got
/// wrong.
pub fn set_params(params: &Params, out: &mut [u8]) -> Result<Queue, Error> {
    params.check()?;
    if out.len() < SET_PARAMS_LEN {
        return Err(Error::BadStreamParams);
    }
    out[0..4].copy_from_slice(&request::PCM_SET_PARAMS.to_le_bytes());
    out[4..8].copy_from_slice(&params.stream.to_le_bytes());
    out[8..12].copy_from_slice(&params.buffer_bytes.to_le_bytes());
    out[12..16].copy_from_slice(&params.period_bytes.to_le_bytes());
    // Features, and none are asked for: this driver plays a stream and does not
    // ask the device to do anything else with it.
    out[16..20].copy_from_slice(&0u32.to_le_bytes());
    out[20] = params.channels;
    out[21] = params.format;
    out[22] = params.rate;
    out[23] = 0;
    Ok(Queue::Control)
}

/// Reads the status the device answered a control request with.
pub fn control_status(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() < CONTROL_STATUS_LEN {
        return Err(Error::ShortResponse);
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Whether a control status means the request was carried out.
///
/// Its own function because the codes start at 0x8000 and a driver testing for
/// zero would read every success as a failure — which is the opposite of the
/// usual convention and exactly the kind of thing a second reader assumes.
pub fn accepted(status: u32) -> bool {
    status == status::OK
}

/// What one stream is, out of a `PCM_INFO` answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PcmInfo {
    pub features: u32,
    pub formats: u64,
    pub rates: u64,
    /// 0 for playback, 1 for capture.
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,
}

impl PcmInfo {
    /// Reads one stream's description, which follows the response status.
    pub fn parse(bytes: &[u8]) -> Result<PcmInfo, Error> {
        if bytes.len() < PCM_INFO_LEN {
            return Err(Error::ShortResponse);
        }
        // The first eight bytes are the common header every info record
        // carries; what this driver needs starts after it.
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let long = |at: usize| u64::from(word(at)) | (u64::from(word(at + 4)) << 32);
        Ok(PcmInfo {
            features: word(8),
            formats: long(12),
            rates: long(20),
            direction: bytes[28],
            channels_min: bytes[29],
            channels_max: bytes[30],
        })
    }

    /// Whether this stream plays rather than records.
    pub fn is_playback(&self) -> bool {
        self.direction == 0
    }

    /// Whether the device will accept a format and rate on this stream.
    ///
    /// Asked rather than assumed: a stream that does not do what is about to be
    /// set up refuses `PCM_SET_PARAMS` with a status that says only "bad
    /// message", and a driver would have no way to tell an unsupported rate
    /// from a malformed request.
    pub fn supports(&self, format: u8, rate: u8) -> bool {
        self.formats & (1 << u64::from(format)) != 0 && self.rates & (1 << u64::from(rate)) != 0
    }
}

/// Writes the header of one transmit buffer: which stream these samples are
/// for.
pub fn xfer_header(stream: u32, out: &mut [u8]) -> Result<Queue, Error> {
    if out.len() < XFER_HEADER_LEN {
        return Err(Error::BadStreamParams);
    }
    out[0..4].copy_from_slice(&stream.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    Ok(Queue::Transmit)
}

/// What the device wrote after the samples.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct XferStatus {
    pub status: u32,
    /// Bytes the device has *not* consumed of this period.
    pub latency_bytes: u32,
}

impl XferStatus {
    /// Reads the status the device wrote at the end of a transmit buffer.
    ///
    /// **Not the used ring's length.** A used element's length is how many
    /// bytes the device wrote, which here is the status itself — a driver
    /// taking it for bytes played would read eight where a period is a
    /// thousand, and would keep handing over periods while believing it had
    /// barely started.
    pub fn parse(bytes: &[u8]) -> Result<XferStatus, Error> {
        if bytes.len() < XFER_STATUS_LEN {
            return Err(Error::ShortResponse);
        }
        Ok(XferStatus {
            status: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            latency_bytes: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }

    pub fn is_ok(&self) -> bool {
        self.status == status::OK
    }
}

/// A playback stream's own accounting.
///
/// **This is where underrun lives, and it is nowhere else.** The device does not
/// fault when it runs dry — it plays silence and carries on — so no register
/// anywhere says a gap was heard. What says it is this: the driver had nothing
/// to hand over at the moment the device gave a period back and asked for the
/// next one.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stream {
    /// Periods the device may hold at once.
    capacity: u32,
    /// Periods it is holding now.
    outstanding: u32,
    /// Periods it has consumed and returned.
    played: u32,
    /// Times it asked for one and there was none.
    underruns: u32,
}

impl Stream {
    pub fn new(capacity: u32) -> Stream {
        Stream {
            capacity,
            ..Stream::default()
        }
    }

    /// Whether another period can be handed over now.
    pub fn has_room(&self) -> bool {
        self.outstanding < self.capacity
    }

    /// Records a period handed to the device.
    pub fn submitted(&mut self) -> Result<(), Error> {
        if !self.has_room() {
            return Err(Error::StreamFull);
        }
        self.outstanding += 1;
        Ok(())
    }

    /// Records a period the device gave back, and whether the driver had
    /// another to replace it with.
    ///
    /// `refilled` is the caller's answer to "and did you have one ready" — the
    /// question no register can be asked. A stream told `false` has been heard
    /// to gap.
    pub fn completed(&mut self, refilled: bool) {
        self.outstanding = self.outstanding.saturating_sub(1);
        self.played += 1;
        if !refilled {
            self.underruns += 1;
        }
    }

    pub fn played(&self) -> u32 {
        self.played
    }

    pub fn outstanding(&self) -> u32 {
        self.outstanding
    }

    /// How many times this stream ran dry. **Zero is a claim, not an absence**:
    /// a client is told the count either way, so "it played cleanly" and
    /// "nobody was counting" are different answers.
    pub fn underruns(&self) -> u32 {
        self.underruns
    }
}
