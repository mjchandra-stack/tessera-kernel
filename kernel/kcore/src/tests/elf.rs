// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::elf`.

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
