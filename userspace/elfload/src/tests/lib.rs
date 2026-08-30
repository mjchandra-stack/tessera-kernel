// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The first tests this parser has ever had.**
//!
//! It lived in a `no_main` ring-3 binary, where there is no host test target,
//! so every one of its refusals was exercised only by booting a machine that
//! never presented a malformed image — which is to say, not at all. These are
//! the malformed images (D294).

use super::*;

/// Builds a minimal ELF for *this* machine with one PT_LOAD segment, so a test
/// can then break exactly one thing about it.
///
/// Built rather than checked in: a binary fixture cannot carry an SPDX header,
/// and one built here is a function of the constants the parser reads.
fn image(edit: impl FnOnce(&mut [u8])) -> std::vec::Vec<u8> {
    let phoff = layout::EHDR;
    let mut bytes = std::vec![0u8; phoff + layout::PHDR + 0x100];
    bytes[..4].copy_from_slice(&ELF_MAGIC);
    bytes[4] = layout::CLASS;
    bytes[5] = EI_DATA_LSB;
    bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_THIS.to_le_bytes());
    put_addr(&mut bytes, layout::E_ENTRY, 0x1000);
    put_addr(&mut bytes, layout::E_PHOFF, phoff as u64);
    bytes[layout::E_PHENTSIZE..layout::E_PHENTSIZE + 2]
        .copy_from_slice(&(layout::PHDR as u16).to_le_bytes());
    bytes[layout::E_PHNUM..layout::E_PHNUM + 2].copy_from_slice(&1u16.to_le_bytes());

    bytes[phoff..phoff + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[phoff + layout::P_FLAGS..phoff + layout::P_FLAGS + 4]
        .copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    put_addr(&mut bytes, phoff + layout::P_OFFSET, phoff as u64 + layout::PHDR as u64);
    put_addr(&mut bytes, phoff + layout::P_VADDR, 0x1000);
    put_addr(&mut bytes, phoff + layout::P_FILESZ, 0x80);
    put_addr(&mut bytes, phoff + layout::P_MEMSZ, 0x100);
    edit(&mut bytes);
    bytes
}

fn put_addr(bytes: &mut [u8], at: usize, value: u64) {
    #[cfg(target_pointer_width = "64")]
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    #[cfg(target_pointer_width = "32")]
    bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

/// The positive path, so the refusals below are refusals of something that
/// would otherwise have been accepted.
#[test]
fn a_well_formed_image_parses() {
    let bytes = image(|_| {});
    let parsed = parse(&bytes).expect("a well-formed image");
    assert_eq!(parsed.entry, 0x1000);
    assert_eq!(parsed.segments().len(), 1);
    let segment = parsed.segments()[0];
    assert_eq!(segment.vaddr, 0x1000);
    assert_eq!(segment.filesz, 0x80);
    assert_eq!(segment.memsz, 0x100);
}

/// **Every identity field is checked before any offset is believed.**
///
/// A loader that mapped segments out of a file it had misidentified has already
/// lost, and each of these is a different way to be handed the wrong file.
#[test]
fn an_image_that_is_not_this_machines_is_refused() {
    assert!(parse(&image(|b| b[0] = 0)).is_none(), "magic");
    assert!(parse(&image(|b| b[4] ^= 1)).is_none(), "class");
    assert!(parse(&image(|b| b[5] = 2)).is_none(), "byte order");
    assert!(
        parse(&image(|b| b[16..18].copy_from_slice(&1u16.to_le_bytes()))).is_none(),
        "ET_REL is not executable",
    );
    assert!(
        parse(&image(|b| b[18..20].copy_from_slice(&(EM_THIS ^ 1).to_le_bytes()))).is_none(),
        "another machine",
    );
}

/// A segment reaching past the file is refused rather than clamped: what a
/// clamp would map is bytes the image does not have.
#[test]
fn a_segment_past_the_end_is_refused() {
    let phoff = layout::EHDR;
    assert!(
        parse(&image(|b| put_addr(b, phoff + layout::P_FILESZ, 0x10_0000))).is_none(),
        "filesz past the image",
    );
    assert!(
        parse(&image(|b| put_addr(b, phoff + layout::P_OFFSET, 0x10_0000))).is_none(),
        "offset past the image",
    );
}

/// Memory smaller than file is malformed: the bytes would have nowhere to go.
#[test]
fn memsz_below_filesz_is_refused() {
    let phoff = layout::EHDR;
    assert!(parse(&image(|b| put_addr(b, phoff + layout::P_MEMSZ, 0x10))).is_none());
}

/// **W^X is refused, not downgraded.**
///
/// A program the loader silently made non-writable faults on its own data, and
/// one it silently made non-executable faults on its first instruction. Either
/// is a process that dies with nothing to say; the refusal happens here, where
/// there is something to say it about.
#[test]
fn a_writable_executable_segment_is_refused() {
    let phoff = layout::EHDR;
    assert!(
        parse(&image(|b| {
            b[phoff + layout::P_FLAGS..phoff + layout::P_FLAGS + 4]
                .copy_from_slice(&(PF_R | PF_W | PF_X).to_le_bytes())
        }))
        .is_none()
    );
}

/// An image with nothing to load is refused: a process with no segments is one
/// that faults at its entry point.
#[test]
fn an_image_with_no_loadable_segment_is_refused() {
    let phoff = layout::EHDR;
    assert!(parse(&image(|b| b[phoff..phoff + 4].copy_from_slice(&2u32.to_le_bytes()))).is_none());
}

/// Truncation is refused at every stage rather than read past.
#[test]
fn a_truncated_image_is_refused() {
    let bytes = image(|_| {});
    for len in [0, 1, 16, layout::EHDR - 1] {
        assert!(parse(&bytes[..len]).is_none(), "{len} bytes");
    }
}
