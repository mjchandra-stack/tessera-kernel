// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Reading an ELF, for whoever is going to load it.**
//!
//! The parse alone: what the entry point is, which segments are loadable, and
//! whether the image is one this machine could run at all. Mapping the segments
//! is the caller's, because it is three syscalls and every caller spells its
//! failures differently — what is worth sharing is the part that is easy to get
//! wrong and impossible to test where it lived.
//!
//! **It lived in `userspace/roottask`**, which was the only program that loaded
//! anything, and it could not be tested there: a `no_main` ring-3 binary has no
//! host test target, so a hundred lines of header arithmetic were exercised
//! only by booting a machine. A second loader — the one Phase 2's third bullet
//! needs, running a program off a filesystem — is what makes extracting it
//! right rather than speculative, and the tests below are what it buys
//! (`build/README.md`, D294).
//!
//! **Refused rather than proceeding on the parts it recognised.** The class,
//! the byte order, the type and the machine are all checked before any offset
//! is believed: a loader that maps segments out of a file it has misidentified
//! has already lost.
//!
//! Normative: docs/roadmap/03-composition-and-self-hosting.md ("Phase 2")

#![no_std]
#![deny(clippy::unwrap_used, clippy::expect_used)]
// The tests build fixtures, which needs an allocator; the library itself has
// none and stays `no_std` for the ring-3 programs that link it.
#[cfg(test)]
extern crate std;

/// How many loadable segments a program may have.
///
/// Bounded because there is no allocator here. A program with more is refused,
/// which is a limit a linker script can be written against; truncating would
/// produce a process missing a segment it needs and no way to find out.
pub const MAX_SEGMENTS: usize = 8;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_DATA_LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;

/// Segment permission bits, as the program header spells them.
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// The machine a loaded image must name.
///
/// **A per-architecture fact, and the reason an image for the wrong one is
/// refused rather than mapped**: a loader that mapped it would produce a
/// process faulting on its first instruction with nothing to say why.
#[cfg(target_arch = "x86_64")]
pub const EM_THIS: u16 = 62;
#[cfg(target_arch = "aarch64")]
pub const EM_THIS: u16 = 183;
/// The same number as RISC-V 64: the ELF specification gives RISC-V one machine
/// value for both widths and distinguishes them by the **class** byte, which
/// `layout::CLASS` is what checks (D258).
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
pub const EM_THIS: u16 = 243;
/// ARM 32 has a machine number of its own — AArch64 has another — so unlike the
/// RISC-V pair this value alone identifies the target.
#[cfg(target_arch = "arm")]
pub const EM_THIS: u16 = 40;

/// Where the fields are, at this machine's class.
#[cfg(target_pointer_width = "64")]
pub mod layout {
    pub const CLASS: u8 = 2;
    pub const EHDR: usize = 64;
    pub const PHDR: usize = 56;
    pub const E_ENTRY: usize = 24;
    pub const E_PHOFF: usize = 32;
    pub const E_PHENTSIZE: usize = 54;
    pub const E_PHNUM: usize = 56;
    pub const P_FLAGS: usize = 4;
    pub const P_OFFSET: usize = 8;
    pub const P_VADDR: usize = 16;
    pub const P_FILESZ: usize = 32;
    pub const P_MEMSZ: usize = 40;
}

#[cfg(target_pointer_width = "32")]
pub mod layout {
    pub const CLASS: u8 = 1;
    pub const EHDR: usize = 52;
    pub const PHDR: usize = 32;
    pub const E_ENTRY: usize = 24;
    pub const E_PHOFF: usize = 28;
    pub const E_PHENTSIZE: usize = 42;
    pub const E_PHNUM: usize = 44;
    pub const P_OFFSET: usize = 4;
    pub const P_VADDR: usize = 8;
    pub const P_FILESZ: usize = 16;
    pub const P_MEMSZ: usize = 20;
    pub const P_FLAGS: usize = 24;
}

/// One loadable segment.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Segment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

/// A parsed image: where it starts, and what to map.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Image {
    pub entry: u64,
    segments: [Segment; MAX_SEGMENTS],
    count: usize,
}

impl Image {
    /// The loadable segments, in the order the program header lists them.
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }
}

/// Parses `image`, or `None` if it is not something this machine could run.
///
/// One answer for every refusal, deliberately. A caller has exactly one thing
/// to do with any of them — refuse to load — and a richer error would invite
/// treating some malformed images as more acceptable than others.
pub fn parse(image: &[u8]) -> Option<Image> {
    if image.len() < layout::EHDR
        || image.get(0..4)? != ELF_MAGIC
        || *image.get(4)? != layout::CLASS
        || *image.get(5)? != EI_DATA_LSB
        || le_u16(image, 16)? != ET_EXEC
        || le_u16(image, 18)? != EM_THIS
    {
        return None;
    }
    let entry = le_addr(image, layout::E_ENTRY)?;
    let phoff = le_addr(image, layout::E_PHOFF)? as usize;
    let phentsize = le_u16(image, layout::E_PHENTSIZE)? as usize;
    let phnum = le_u16(image, layout::E_PHNUM)? as usize;
    if phentsize < layout::PHDR {
        return None;
    }

    let mut segments = [Segment::default(); MAX_SEGMENTS];
    let mut count = 0;
    for index in 0..phnum {
        let at = phoff.checked_add(index.checked_mul(phentsize)?)?;
        if le_u32(image, at)? != PT_LOAD {
            continue;
        }
        if count == MAX_SEGMENTS {
            return None;
        }
        let segment = Segment {
            flags: le_u32(image, at + layout::P_FLAGS)?,
            offset: le_addr(image, at + layout::P_OFFSET)?,
            vaddr: le_addr(image, at + layout::P_VADDR)?,
            filesz: le_addr(image, at + layout::P_FILESZ)?,
            memsz: le_addr(image, at + layout::P_MEMSZ)?,
        };
        // A segment claiming more file bytes than it has, or fewer memory bytes
        // than file bytes, is malformed. Checked here so a mapping loop can be
        // arithmetic rather than validation.
        let end = segment.offset.checked_add(segment.filesz)?;
        if end > image.len() as u64 || segment.memsz < segment.filesz {
            return None;
        }
        // W^X, refused rather than downgraded: a program the loader silently
        // made non-writable faults on its own data (`docs/kernel/03`).
        if segment.flags & PF_W != 0 && segment.flags & PF_X != 0 {
            return None;
        }
        // **A segment that describes no memory is dropped rather than
        // recorded**, the same as `kcore::elf` does and for the same reason:
        // `ld` emits a `PT_LOAD` for every `PHDRS` entry the linker script
        // declares, so a program with no statics gets an empty read-write one
        // at address zero. It loads nothing, and a mapping loop handed it asks
        // for zero pages at zero — which is what a ring-3 loader would do with
        // the first C program it was given (`build/README.md`, D317).
        if segment.memsz == 0 {
            continue;
        }
        segments[count] = segment;
        count += 1;
    }
    if count == 0 {
        return None;
    }
    Some(Image {
        entry,
        segments,
        count,
    })
}

/// Rounds up to a whole number of 4 KiB pages — the granularity a mapping is
/// made at, and so where a segment's file bytes stop covering its memory size.
pub fn page_up(value: u64) -> u64 {
    (value + 0xfff) & !0xfff
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
        *bytes.get(at + 2)?,
        *bytes.get(at + 3)?,
    ]))
}

#[cfg(target_pointer_width = "64")]
fn le_addr(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
        *bytes.get(at + 2)?,
        *bytes.get(at + 3)?,
        *bytes.get(at + 4)?,
        *bytes.get(at + 5)?,
        *bytes.get(at + 6)?,
        *bytes.get(at + 7)?,
    ]))
}

#[cfg(target_pointer_width = "32")]
fn le_addr(bytes: &[u8], at: usize) -> Option<u64> {
    le_u32(bytes, at).map(u64::from)
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
