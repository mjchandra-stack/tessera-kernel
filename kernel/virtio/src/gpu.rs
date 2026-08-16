// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The virtio-gpu 2D protocol: what a display says it is, and what it takes to
//! put a picture on it.
//!
//! Beside [`snd`](crate::snd), on the same transport and the same split
//! virtqueue. Two things here are not like the device protocols before it.
//!
//! # A resource is memory the device is *told about*
//!
//! Every other device in this tree is handed one page and an address in a
//! register. A GPU resource is created empty and then given its backing as a
//! **list of regions** — the first time anything here describes memory to a
//! device rather than pointing at it. What that buys is a framebuffer larger
//! than a page, and what it costs is that the description has to be right:
//! a device told about memory the driver does not own would read it anyway.
//!
//! # Every command names a rectangle, and nothing checks it
//!
//! A transfer and a flush each name a rectangle within a resource. A rectangle
//! that runs past the resource is the one piece of arithmetic in this protocol
//! that a driver can get wrong **without the device complaining** — it will
//! read whatever follows the backing and put it on the screen. So [`Rect`]
//! checks itself against the resource it is used with, here, where it needs no
//! hardware to test.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md
//! ("Display And Graphics")
//! Budget: none (driven from ring 3)

use crate::Error;

/// The virtio device id a GPU carries.
pub const DEVICE_ID: u32 = 16;

/// The queues a GPU has. Two, and the cursor queue is not driven here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Queue {
    Control = 0,
    /// The cursor plane, which this tree does not use — declared because the
    /// device has it and a driver that configured only one queue would be
    /// describing a different device.
    Cursor = 1,
}

/// Command codes, and the response codes that answer them.
pub mod command {
    pub const GET_DISPLAY_INFO: u32 = 0x0100;
    pub const RESOURCE_CREATE_2D: u32 = 0x0101;
    pub const RESOURCE_UNREF: u32 = 0x0102;
    pub const SET_SCANOUT: u32 = 0x0103;
    pub const RESOURCE_FLUSH: u32 = 0x0104;
    pub const TRANSFER_TO_HOST_2D: u32 = 0x0105;
    pub const RESOURCE_ATTACH_BACKING: u32 = 0x0106;
    pub const RESOURCE_DETACH_BACKING: u32 = 0x0107;
}

/// What a device answers with.
pub mod response {
    /// The command was carried out and the answer carries nothing else.
    pub const OK_NODATA: u32 = 0x1100;
    /// The answer is a display-info structure.
    pub const OK_DISPLAY_INFO: u32 = 0x1101;
    pub const ERR_UNSPEC: u32 = 0x1200;
    pub const ERR_OUT_OF_MEMORY: u32 = 0x1201;
    pub const ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
    pub const ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
}

/// Whether a response code means the command was carried out.
///
/// Its own function because success is a *range* rather than a value — a
/// display-info answer and an empty acknowledgement are both success — and a
/// driver comparing against one of them would read the other as a failure.
pub fn accepted(code: u32) -> bool {
    code == response::OK_NODATA || code == response::OK_DISPLAY_INFO
}

/// Bytes in the header every command and response begins with.
pub const HEADER_LEN: usize = 24;
/// Bytes in a `RESOURCE_CREATE_2D` request, header included.
pub const CREATE_2D_LEN: usize = HEADER_LEN + 16;
/// Bytes in a `SET_SCANOUT` request.
pub const SET_SCANOUT_LEN: usize = HEADER_LEN + 24;
/// Bytes in a `TRANSFER_TO_HOST_2D` request.
pub const TRANSFER_LEN: usize = HEADER_LEN + 32;
/// Bytes in a `RESOURCE_FLUSH` request.
pub const FLUSH_LEN: usize = HEADER_LEN + 24;
/// Bytes in a `RESOURCE_ATTACH_BACKING` request before its entries.
pub const ATTACH_HEADER_LEN: usize = HEADER_LEN + 8;
/// Bytes one backing entry occupies: an address, a length, and padding.
pub const ATTACH_ENTRY_LEN: usize = 16;
/// Bytes a display-info response occupies: the header and sixteen scanouts.
pub const DISPLAY_INFO_LEN: usize = HEADER_LEN + 16 * 24;

/// The pixel format this tree uses: 32-bit, blue-green-red-alpha in memory
/// order, which is what a little-endian host writes as 0xAARRGGBB.
pub const FORMAT_B8G8R8A8: u32 = 1;

/// One scanout, as the device describes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Scanout {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    /// Whether anything is attached to it. **A real state and not a failure**:
    /// a machine with no display is an ordinary machine, and a driver that
    /// could not tell it from a broken device would report a fault for a
    /// monitor nobody plugged in.
    pub enabled: bool,
}

impl Scanout {
    /// Reads the first scanout out of a display-info response.
    ///
    /// The first, because that is the one this tree drives; the answer
    /// describes sixteen and the rest are read by nothing.
    pub fn parse_first(bytes: &[u8]) -> Result<Scanout, Error> {
        if bytes.len() < HEADER_LEN + 24 {
            return Err(Error::ShortResponse);
        }
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Ok(Scanout {
            x: word(HEADER_LEN),
            y: word(HEADER_LEN + 4),
            width: word(HEADER_LEN + 8),
            height: word(HEADER_LEN + 12),
            enabled: word(HEADER_LEN + 16) != 0,
        })
    }

    /// Bytes a framebuffer for this scanout occupies at four bytes a pixel.
    ///
    /// `None` when the arithmetic does not fit, which is a scanout this driver
    /// cannot back rather than one it should try to.
    pub fn framebuffer_bytes(&self) -> Option<u64> {
        u64::from(self.width)
            .checked_mul(u64::from(self.height))?
            .checked_mul(4)
    }
}

/// A rectangle within a resource.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    /// Whether this rectangle lies inside a resource of `width` by `height`.
    ///
    /// **The check the device does not do for you.** A flush or a transfer
    /// naming a rectangle past the resource's edge is not refused by the
    /// hardware: it reads whatever follows the backing and puts it on the
    /// screen. Checked in whole arithmetic, because the sum of an offset and a
    /// width is exactly where a 32-bit wrap turns an obviously wrong rectangle
    /// into a plausible one.
    pub fn within(&self, width: u32, height: u32) -> bool {
        let right = u64::from(self.x) + u64::from(self.width);
        let bottom = u64::from(self.y) + u64::from(self.height);
        self.width > 0
            && self.height > 0
            && right <= u64::from(width)
            && bottom <= u64::from(height)
    }

    fn write(&self, out: &mut [u8], at: usize) {
        out[at..at + 4].copy_from_slice(&self.x.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&self.y.to_le_bytes());
        out[at + 8..at + 12].copy_from_slice(&self.width.to_le_bytes());
        out[at + 12..at + 16].copy_from_slice(&self.height.to_le_bytes());
    }
}

/// Writes the header every command begins with.
fn header(out: &mut [u8], kind: u32) {
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    // No flags, no fence, context zero: this driver issues one command at a
    // time and waits for it, so there is nothing for a fence to order.
    for byte in &mut out[4..HEADER_LEN] {
        *byte = 0;
    }
}

/// Reads the type out of a response header.
pub fn response_type(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::ShortResponse);
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Asks what displays there are.
pub fn get_display_info(out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < HEADER_LEN {
        return Err(Error::BadRect);
    }
    header(out, command::GET_DISPLAY_INFO);
    Ok(HEADER_LEN)
}

/// Creates a 2D resource of `width` by `height`.
pub fn resource_create_2d(
    resource: u32,
    width: u32,
    height: u32,
    format: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    // Resource zero is the value that means "no resource" in `SET_SCANOUT`, so
    // creating one would give the driver a resource it cannot distinguish from
    // having none.
    if out.len() < CREATE_2D_LEN || resource == 0 || width == 0 || height == 0 {
        return Err(Error::BadRect);
    }
    header(out, command::RESOURCE_CREATE_2D);
    out[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&resource.to_le_bytes());
    out[HEADER_LEN + 4..HEADER_LEN + 8].copy_from_slice(&format.to_le_bytes());
    out[HEADER_LEN + 8..HEADER_LEN + 12].copy_from_slice(&width.to_le_bytes());
    out[HEADER_LEN + 12..HEADER_LEN + 16].copy_from_slice(&height.to_le_bytes());
    Ok(CREATE_2D_LEN)
}

/// Tells the device where a resource's pixels live.
///
/// **The first thing in this tree that describes memory to a device rather than
/// pointing at it.** Each entry is an address and a length, and the device will
/// read every byte of every one — so a list with an entry the driver does not
/// own is a device reading memory nobody granted it.
pub fn resource_attach_backing(
    resource: u32,
    entries: &[(u64, u32)],
    out: &mut [u8],
) -> Result<usize, Error> {
    let total = ATTACH_HEADER_LEN + entries.len() * ATTACH_ENTRY_LEN;
    // A backing of no entries is a resource with nowhere to read from, which
    // the device would accept and then read nothing from.
    if out.len() < total || resource == 0 || entries.is_empty() {
        return Err(Error::BadRect);
    }
    header(out, command::RESOURCE_ATTACH_BACKING);
    out[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&resource.to_le_bytes());
    out[HEADER_LEN + 4..HEADER_LEN + 8].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (index, (addr, len)) in entries.iter().enumerate() {
        let at = ATTACH_HEADER_LEN + index * ATTACH_ENTRY_LEN;
        out[at..at + 8].copy_from_slice(&addr.to_le_bytes());
        out[at + 8..at + 12].copy_from_slice(&len.to_le_bytes());
        out[at + 12..at + 16].copy_from_slice(&0u32.to_le_bytes());
    }
    Ok(total)
}

/// Puts a resource on a scanout.
pub fn set_scanout(
    scanout: u32,
    resource: u32,
    rect: Rect,
    width: u32,
    height: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < SET_SCANOUT_LEN || !rect.within(width, height) {
        return Err(Error::BadRect);
    }
    header(out, command::SET_SCANOUT);
    rect.write(out, HEADER_LEN);
    out[HEADER_LEN + 16..HEADER_LEN + 20].copy_from_slice(&scanout.to_le_bytes());
    out[HEADER_LEN + 20..HEADER_LEN + 24].copy_from_slice(&resource.to_le_bytes());
    Ok(SET_SCANOUT_LEN)
}

/// Copies part of a resource's backing into the device's own copy of it.
///
/// `offset` is where in the backing the rectangle's first row starts, and it is
/// the caller's because only the caller knows the stride it wrote at.
pub fn transfer_to_host_2d(
    resource: u32,
    rect: Rect,
    offset: u64,
    width: u32,
    height: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < TRANSFER_LEN || !rect.within(width, height) {
        return Err(Error::BadRect);
    }
    header(out, command::TRANSFER_TO_HOST_2D);
    rect.write(out, HEADER_LEN);
    out[HEADER_LEN + 16..HEADER_LEN + 24].copy_from_slice(&offset.to_le_bytes());
    out[HEADER_LEN + 24..HEADER_LEN + 28].copy_from_slice(&resource.to_le_bytes());
    out[HEADER_LEN + 28..HEADER_LEN + 32].copy_from_slice(&0u32.to_le_bytes());
    Ok(TRANSFER_LEN)
}

/// Puts part of a resource on the glass.
///
/// **Nothing is visible until this.** A transfer moves pixels into the device's
/// copy and changes nothing anybody can see — which is exactly what makes a
/// driver that forgot it look like one that works.
pub fn resource_flush(
    resource: u32,
    rect: Rect,
    width: u32,
    height: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < FLUSH_LEN || !rect.within(width, height) {
        return Err(Error::BadRect);
    }
    header(out, command::RESOURCE_FLUSH);
    rect.write(out, HEADER_LEN);
    out[HEADER_LEN + 16..HEADER_LEN + 20].copy_from_slice(&resource.to_le_bytes());
    out[HEADER_LEN + 20..HEADER_LEN + 24].copy_from_slice(&0u32.to_le_bytes());
    Ok(FLUSH_LEN)
}
