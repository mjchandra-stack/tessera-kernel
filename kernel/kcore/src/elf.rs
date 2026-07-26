// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A minimal ELF64 parser for the process loader. The docs put the loader in
//! user space (`docs/api/01`: "user-space loaders populate a new process's
//! address space before start") and never name a format; v0 loads `ET_EXEC`
//! ELF64 in the kernel (build/README.md, D42). This module only *parses* — it
//! validates the header and extracts the `PT_LOAD` segments and entry point,
//! with every field bounds-checked against the image; the actual mapping (with
//! W^X, `docs/kernel/03`) is done by the loader against an `AddressSpace`.
//!
//! Pure and allocation-free — no arch, no frames — so it is host-tested against
//! a golden ELF byte image.
//!
//! Normative: docs/api/01-system-call-interface.md ("Process And Thread"),
//! docs/kernel/03-paging-faults-and-exceptions.md ("Write-XOR-Execute")
//! Budget: none (load path)

/// Loadable segments a single image may carry this milestone (bounded, like
/// every kcore pool).
pub const MAX_SEGMENTS: usize = 8;

// ELF constants (the subset v0 accepts).
const EI_NIDENT: usize = 16;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

/// `e_machine` values this loader can be asked to accept. The caller names
/// the architecture it is prepared to *run*, rather than the loader assuming
/// one: a kernel that hard-codes its own is a kernel that silently accepts
/// the wrong binary the day it is ported.
///
/// Values are the ELF specification's and are ABI; append, never renumber.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Machine {
    X86_64 = 0x3e,
    AArch64 = 0xb7,
}

/// Why an image was rejected — stable, descriptive reasons (a malformed or
/// hostile image must never load).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfError {
    /// Too short to hold the header (or a header it points at).
    Truncated,
    /// Not an ELF (bad `0x7f E L F` magic).
    BadMagic,
    /// Not a 64-bit, little-endian image.
    NotElf64,
    /// Built for a different CPU architecture than the caller asked for.
    WrongMachine,
    /// Not an executable (`ET_EXEC`); v0 does not load `ET_DYN` (D42).
    NotExecutable,
    /// A program-header entry is malformed, or its file range lies outside the
    /// image / its memory size is smaller than its file size.
    BadSegment,
    /// More `PT_LOAD` segments than [`MAX_SEGMENTS`].
    TooManySegments,
}

/// One `PT_LOAD` segment: where its bytes are in the file, where they map, and
/// its permissions. `mem_size >= file_size`; the tail is zero-filled bss.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment {
    pub file_offset: u64,
    pub vaddr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

/// A parsed executable image: its entry point and its loadable segments.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ElfImage {
    entry: u64,
    segments: [Segment; MAX_SEGMENTS],
    count: usize,
}

impl ElfImage {
    /// The virtual entry point (`e_entry`).
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// The loadable segments, in program-header order.
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }
}

fn read_u16(image: &[u8], off: usize) -> Result<u16, ElfError> {
    let bytes = image.get(off..off + 2).ok_or(ElfError::Truncated)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(image: &[u8], off: usize) -> Result<u32, ElfError> {
    let bytes = image.get(off..off + 4).ok_or(ElfError::Truncated)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(image: &[u8], off: usize) -> Result<u64, ElfError> {
    let bytes = image.get(off..off + 8).ok_or(ElfError::Truncated)?;
    let mut v = [0u8; 8];
    v.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(v))
}

/// Parses `image` as an `ET_EXEC` ELF64 for `machine`, returning its entry point and
/// `PT_LOAD` segments, or an [`ElfError`] describing why it was rejected. Every
/// field is bounds-checked against the image; a segment whose file bytes fall
/// outside the image, or whose memory size is smaller than its file size, is
/// rejected.
pub fn parse(image: &[u8], machine: Machine) -> Result<ElfImage, ElfError> {
    if image.len() < EHDR_SIZE {
        return Err(ElfError::Truncated);
    }
    if image[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    // e_ident: class + data encoding.
    if image[4] != ELFCLASS64 || image[5] != ELFDATA2LSB {
        return Err(ElfError::NotElf64);
    }
    let _ = EI_NIDENT;
    if read_u16(image, 16)? != ET_EXEC {
        return Err(ElfError::NotExecutable);
    }
    if read_u16(image, 18)? != machine as u16 {
        return Err(ElfError::WrongMachine);
    }
    let entry = read_u64(image, 24)?;
    let phoff = read_u64(image, 32)? as usize;
    let phentsize = read_u16(image, 54)? as usize;
    let phnum = read_u16(image, 56)? as usize;
    if phentsize < PHDR_SIZE {
        return Err(ElfError::BadSegment);
    }

    let mut segments = [Segment {
        file_offset: 0,
        vaddr: 0,
        file_size: 0,
        mem_size: 0,
        read: false,
        write: false,
        exec: false,
    }; MAX_SEGMENTS];
    let mut count = 0;
    for i in 0..phnum {
        let base = phoff
            .checked_add(i.checked_mul(phentsize).ok_or(ElfError::BadSegment)?)
            .ok_or(ElfError::BadSegment)?;
        if read_u32(image, base)? != PT_LOAD {
            continue;
        }
        let flags = read_u32(image, base + 4)?;
        let file_offset = read_u64(image, base + 8)?;
        let vaddr = read_u64(image, base + 16)?;
        let file_size = read_u64(image, base + 32)?;
        let mem_size = read_u64(image, base + 40)?;
        // The segment's file bytes must lie within the image, and its in-memory
        // size cannot be smaller than what the file provides.
        let file_end = file_offset
            .checked_add(file_size)
            .ok_or(ElfError::BadSegment)?;
        if file_end > image.len() as u64 || mem_size < file_size {
            return Err(ElfError::BadSegment);
        }
        if count >= MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        segments[count] = Segment {
            file_offset,
            vaddr,
            file_size,
            mem_size,
            read: flags & PF_R != 0,
            write: flags & PF_W != 0,
            exec: flags & PF_X != 0,
        };
        count += 1;
    }
    Ok(ElfImage {
        entry,
        segments,
        count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// Builds a minimal valid ELF64 `ET_EXEC` image: a 64-byte header, one
    /// 56-byte `PT_LOAD` program header (R+X), and a little code. The single
    /// segment covers the whole file (`p_offset = 0`) and adds 16 bytes of bss.
    fn golden() -> Vec<u8> {
        const VADDR: u64 = 0x40_0000;
        const ENTRY: u64 = 0x40_0078; // right after the two headers (64 + 56)
        let code: [u8; 8] = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let file_size = (EHDR_SIZE + PHDR_SIZE + code.len()) as u64; // 128
        let mem_size = file_size + 16;

        let mut img = Vec::new();
        // --- Elf64_Ehdr ---
        img.extend_from_slice(&ELF_MAGIC);
        img.push(ELFCLASS64); // EI_CLASS
        img.push(ELFDATA2LSB); // EI_DATA
        img.push(1); // EI_VERSION
        img.extend_from_slice(&[0u8; 9]); // EI_OSABI + pad → 16 bytes total
        img.extend_from_slice(&ET_EXEC.to_le_bytes()); // e_type @16
        img.extend_from_slice(&(Machine::X86_64 as u16).to_le_bytes()); // e_machine @18
        img.extend_from_slice(&1u32.to_le_bytes()); // e_version @20
        img.extend_from_slice(&ENTRY.to_le_bytes()); // e_entry @24
        img.extend_from_slice(&64u64.to_le_bytes()); // e_phoff @32
        img.extend_from_slice(&0u64.to_le_bytes()); // e_shoff @40
        img.extend_from_slice(&0u32.to_le_bytes()); // e_flags @48
        img.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize @52
        img.extend_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize @54
        img.extend_from_slice(&1u16.to_le_bytes()); // e_phnum @56
        img.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize @58
        img.extend_from_slice(&0u16.to_le_bytes()); // e_shnum @60
        img.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx @62
        assert_eq!(img.len(), EHDR_SIZE);
        // --- Elf64_Phdr (PT_LOAD, R+X) ---
        img.extend_from_slice(&PT_LOAD.to_le_bytes()); // p_type @0
        img.extend_from_slice(&(PF_R | PF_X).to_le_bytes()); // p_flags @4
        img.extend_from_slice(&0u64.to_le_bytes()); // p_offset @8
        img.extend_from_slice(&VADDR.to_le_bytes()); // p_vaddr @16
        img.extend_from_slice(&VADDR.to_le_bytes()); // p_paddr @24
        img.extend_from_slice(&file_size.to_le_bytes()); // p_filesz @32
        img.extend_from_slice(&mem_size.to_le_bytes()); // p_memsz @40
        img.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align @48
        assert_eq!(img.len(), EHDR_SIZE + PHDR_SIZE);
        // --- code ---
        img.extend_from_slice(&code);
        img
    }

    #[test]
    fn parses_a_valid_executable() {
        let image = golden();
        let elf = parse(&image, Machine::X86_64).expect("valid ELF");
        assert_eq!(elf.entry(), 0x40_0078);
        assert_eq!(elf.segments().len(), 1);
        let seg = elf.segments()[0];
        assert_eq!(seg.vaddr, 0x40_0000);
        assert_eq!(seg.file_offset, 0);
        assert_eq!(seg.file_size, 128);
        assert_eq!(seg.mem_size, 144); // 16 bytes of bss
        assert!(seg.read && seg.exec && !seg.write); // R+X, W^X honoured
    }

    #[test]
    fn rejects_non_elf() {
        assert_eq!(parse(&[0u8; 64], Machine::X86_64), Err(ElfError::BadMagic));
        assert_eq!(
            parse(b"not an elf", Machine::X86_64),
            Err(ElfError::Truncated)
        );
    }

    #[test]
    fn rejects_wrong_class_machine_and_type() {
        let mut img = golden();
        img[4] = 1; // ELFCLASS32
        assert_eq!(parse(&img, Machine::X86_64), Err(ElfError::NotElf64));

        let mut img = golden();
        img[18] = 0x28; // EM_ARM
        assert_eq!(parse(&img, Machine::X86_64), Err(ElfError::WrongMachine));

        let mut img = golden();
        img[16] = 3; // ET_DYN
        assert_eq!(parse(&img, Machine::X86_64), Err(ElfError::NotExecutable));
    }

    #[test]
    fn rejects_a_segment_past_the_image_end() {
        let mut img = golden();
        // Inflate p_filesz (@ phoff 64 + 32) beyond the image length.
        let huge = 0x10_0000u64.to_le_bytes();
        img[64 + 32..64 + 40].copy_from_slice(&huge);
        assert_eq!(parse(&img, Machine::X86_64), Err(ElfError::BadSegment));
    }

    #[test]
    fn rejects_mem_size_smaller_than_file_size() {
        let mut img = golden();
        // p_memsz (@ phoff 64 + 40) set below p_filesz (128).
        img[64 + 40..64 + 48].copy_from_slice(&64u64.to_le_bytes());
        assert_eq!(parse(&img, Machine::X86_64), Err(ElfError::BadSegment));
    }

    #[test]
    fn non_load_segments_are_skipped() {
        let mut img = golden();
        // Flip the single program header's type to something other than PT_LOAD.
        img[64..68].copy_from_slice(&7u32.to_le_bytes()); // PT_GNU_STACK-ish
        let elf = parse(&img, Machine::X86_64).expect("still a valid header");
        assert_eq!(elf.segments().len(), 0);
    }
}
