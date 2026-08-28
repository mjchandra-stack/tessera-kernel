// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::elf`.

use super::*;
use std::vec::Vec;
use tessera_karch::{AddressSpaceOps, FRAME_SIZE, MemoryKind, VirtAddr};
use tessera_karch_mock::{MockAddressSpace, synthetic_map};

/// A two-segment image: the first as `golden`'s (R+X), the second a second
/// `PT_LOAD` at `vaddr` with `flags`. Written by hand rather than by a linker
/// because the layout under test — read-only data in its own segment — is one
/// no program in this tree emits yet, which is exactly why the loader got it
/// wrong.
fn two_segment(second_flags: u32, second_vaddr: u64) -> Vec<u8> {
    let mut img = golden();
    // e_phnum 1 -> 2
    img[56..58].copy_from_slice(&2u16.to_le_bytes());
    // The first phdr's file range covered the whole image; keep it to the
    // headers plus code so the appended phdr is not inside it.
    let first_size = (EHDR_SIZE + 2 * PHDR_SIZE + 8) as u64;
    img[64 + 32..64 + 40].copy_from_slice(&first_size.to_le_bytes()); // p_filesz
    img[64 + 40..64 + 48].copy_from_slice(&(first_size + 16).to_le_bytes()); // p_memsz
    // Splice a second phdr in directly after the first, before the code.
    let mut phdr = Vec::new();
    phdr.extend_from_slice(&PT_LOAD.to_le_bytes());
    phdr.extend_from_slice(&second_flags.to_le_bytes());
    phdr.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    phdr.extend_from_slice(&second_vaddr.to_le_bytes()); // p_vaddr
    phdr.extend_from_slice(&second_vaddr.to_le_bytes()); // p_paddr
    phdr.extend_from_slice(&8u64.to_le_bytes()); // p_filesz
    phdr.extend_from_slice(&8u64.to_le_bytes()); // p_memsz
    phdr.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    let at = EHDR_SIZE + PHDR_SIZE;
    for (i, b) in phdr.into_iter().enumerate() {
        img.insert(at + i, b);
    }
    img
}

/// A space and an allocator with room for a handful of pages and their tables.
fn loadable() -> (
    crate::vm::AddressSpace<MockAddressSpace>,
    Vec<tessera_karch::MemoryRegion>,
) {
    let map = synthetic_map(&[(0x100_000, 512 * FRAME_SIZE, MemoryKind::Usable)]);
    (
        crate::vm::AddressSpace::<MockAddressSpace>::new(
            &mut crate::pmem::BumpFrameAllocator::new(&map),
            0xffff_8000_0000_0000,
            crate::vm::Asid(1),
        )
        .expect("space"),
        map,
    )
}

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

// --- What the loader grants ------------------------------------------------

/// **A read-only segment is mapped read-only.**
///
/// The loader chose between `rx` and `rw` on `seg.exec` alone, so every
/// non-executable segment came out writable — and a `PT_LOAD` asking for read
/// and nothing else is `.rodata`. The parsed `write` flag existed only to be
/// checked against `exec` for W^X, and was never consulted for the thing it
/// names.
#[test]
fn a_read_only_segment_is_not_mapped_writable() {
    const RODATA: u64 = 0x50_0000;
    let (mut space, map) = loadable();
    let mut frames = crate::pmem::BumpFrameAllocator::new(&map);
    let image = two_segment(PF_R, RODATA);

    load_into(&image, &mut space, &mut frames, Machine::X86_64, 100).expect("loads");

    let rights = space
        .rights_at(VirtAddr::new(RODATA))
        .expect("the read-only segment is mapped");
    assert!(rights.readable() && rights.is_user());
    assert!(
        !rights.writable(),
        "a segment that asked for read alone must not be writable",
    );
    assert!(!rights.executable());
}

/// The two shapes every image in this tree actually has keep exactly the
/// rights they had. Deriving the grant is a change to what a *separated*
/// read-only segment gets, and must be a change to nothing else.
#[test]
fn the_shapes_the_linker_emits_are_unchanged() {
    const DATA: u64 = 0x50_0000;
    let (mut space, map) = loadable();
    let mut frames = crate::pmem::BumpFrameAllocator::new(&map);
    let image = two_segment(PF_R | PF_W, DATA);

    load_into(&image, &mut space, &mut frames, Machine::X86_64, 100).expect("loads");

    // R+X, as `golden`'s first segment declares.
    let text = space.rights_at(VirtAddr::new(0x40_0000)).expect("text");
    assert!(text.readable() && text.executable() && !text.writable());
    // R+W.
    let data = space.rights_at(VirtAddr::new(DATA)).expect("data");
    assert!(data.readable() && data.writable() && !data.executable());
}

/// A segment asking for no read is refused, not quietly given one. Hardware
/// here has no read-disable bit, so the request cannot be honoured — and
/// granting read anyway would be the loader widening what the image asked for.
#[test]
fn a_segment_that_asks_for_no_read_is_refused() {
    let (mut space, map) = loadable();
    let mut frames = crate::pmem::BumpFrameAllocator::new(&map);
    let image = two_segment(PF_W, 0x50_0000);

    assert_eq!(
        load_into(&image, &mut space, &mut frames, Machine::X86_64, 100),
        Err(107),
    );
}

/// The bound is on the range, not the base — the same off-by-a-range the
/// loader's map syscall had. A segment based one page below the boundary and
/// running past it is what a base-only check lets through.
#[test]
fn a_segment_running_past_the_user_half_is_refused() {
    let max = <MockAddressSpace as AddressSpaceOps>::USER_ADDRESS_MAX;
    let (mut space, map) = loadable();
    let mut frames = crate::pmem::BumpFrameAllocator::new(&map);
    // Based inside the user half, two pages long, ending one page above it.
    // Grow the second segment to two pages: p_memsz lives at the second
    // phdr's offset 40.
    let mut image = two_segment(PF_R, max - FRAME_SIZE);
    let memsz_at = EHDR_SIZE + PHDR_SIZE + 40;
    image[memsz_at..memsz_at + 8].copy_from_slice(&(2 * FRAME_SIZE).to_le_bytes());

    assert_eq!(
        load_into(&image, &mut space, &mut frames, Machine::X86_64, 100),
        Err(102),
    );
}

// --- ELF32, for the 32-bit ports (D258) ---

/// The same one-segment executable, as an ELF32 for RISC-V: a 52-byte header, a
/// 32-byte `PT_LOAD` (R+X), and a little code.
///
/// **Written out rather than derived from `golden`.** The two classes are not
/// the same header narrowed — ELF32 puts `p_flags` *after* the sizes where
/// ELF64 puts it second — and a builder that narrowed fields would produce an
/// image the parser under test agrees with for the same wrong reason.
fn golden32() -> Vec<u8> {
    const VADDR: u32 = 0x1000_0000;
    const ENTRY: u32 = 0x1000_0054; // right after the two headers (52 + 32)
    let code: [u8; 8] = [0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
    let file_size = (52 + 32 + code.len()) as u32;
    let mem_size = file_size + 16;

    let mut img = Vec::new();
    // --- Elf32_Ehdr ---
    img.extend_from_slice(&ELF_MAGIC);
    img.push(1); // EI_CLASS = ELFCLASS32
    img.push(ELFDATA2LSB);
    img.push(1); // EI_VERSION
    img.extend_from_slice(&[0u8; 9]);
    img.extend_from_slice(&ET_EXEC.to_le_bytes()); // e_type @16
    img.extend_from_slice(&0xf3u16.to_le_bytes()); // e_machine @18 — RISC-V
    img.extend_from_slice(&1u32.to_le_bytes()); // e_version @20
    img.extend_from_slice(&ENTRY.to_le_bytes()); // e_entry @24
    img.extend_from_slice(&52u32.to_le_bytes()); // e_phoff @28
    img.extend_from_slice(&0u32.to_le_bytes()); // e_shoff @32
    img.extend_from_slice(&0u32.to_le_bytes()); // e_flags @36
    img.extend_from_slice(&52u16.to_le_bytes()); // e_ehsize @40
    img.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize @42
    img.extend_from_slice(&1u16.to_le_bytes()); // e_phnum @44
    img.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize @46
    img.extend_from_slice(&0u16.to_le_bytes()); // e_shnum @48
    img.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx @50
    assert_eq!(img.len(), 52);
    // --- Elf32_Phdr (PT_LOAD, R+X). Note the field order: flags come last.
    img.extend_from_slice(&PT_LOAD.to_le_bytes()); // p_type @0
    img.extend_from_slice(&0u32.to_le_bytes()); // p_offset @4
    img.extend_from_slice(&VADDR.to_le_bytes()); // p_vaddr @8
    img.extend_from_slice(&VADDR.to_le_bytes()); // p_paddr @12
    img.extend_from_slice(&file_size.to_le_bytes()); // p_filesz @16
    img.extend_from_slice(&mem_size.to_le_bytes()); // p_memsz @20
    img.extend_from_slice(&(PF_R | PF_X).to_le_bytes()); // p_flags @24
    img.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align @28
    assert_eq!(img.len(), 52 + 32);
    img.extend_from_slice(&code);
    img
}

/// An ELF32 parses, and its segment's **permissions** come out right.
///
/// The permissions are the assertion that discriminates. Every other field
/// narrows in place, so a parser that read ELF32 with ELF64 offsets would still
/// get plausible answers for some of them; `p_flags` moves from offset 4 to
/// offset 24, so reading it at the ELF64 place returns the segment's *file
/// offset* — zero here, which is no permissions at all, and a page mapped
/// neither readable nor executable.
#[test]
fn parses_a_32_bit_executable() {
    let image = golden32();
    let elf = parse(&image, Machine::RiscV32).expect("valid ELF32");
    assert_eq!(elf.entry(), 0x1000_0054);
    assert_eq!(elf.segments().len(), 1);
    let seg = &elf.segments()[0];
    assert_eq!(seg.vaddr, 0x1000_0000);
    assert_eq!(seg.file_size, 92);
    assert_eq!(seg.mem_size, 108);
    assert!(seg.read, "p_flags was not read from the ELF32 offset");
    assert!(seg.exec, "p_flags was not read from the ELF32 offset");
    assert!(!seg.write);
}

/// A 64-bit image is refused for a 32-bit target, and a 32-bit image for a
/// 64-bit one.
///
/// **Both directions, because the class check is not a formality.** RISC-V
/// gives both widths the same `e_machine`, so the machine check alone cannot
/// tell them apart — the class byte is the only thing that can, and a loader
/// that took either would read a program header at the wrong width and map
/// whatever it found there.
#[test]
fn an_image_of_the_wrong_class_is_refused() {
    assert_eq!(
        parse(&golden32(), Machine::RiscV64),
        Err(ElfError::NotElf64),
        "a 32-bit image was accepted for a 64-bit target",
    );
    let mut wide = golden();
    // The same machine number a RISC-V image carries, so what refuses this is
    // the class and not the machine.
    wide[18..20].copy_from_slice(&0xf3u16.to_le_bytes());
    assert_eq!(
        parse(&wide, Machine::RiscV32),
        Err(ElfError::NotElf64),
        "a 64-bit image was accepted for a 32-bit target",
    );
}

/// The two RISC-V targets declare the same `e_machine` and different classes —
/// which is the whole reason `Machine::RiscV32` needed a discriminant that is
/// not a machine number.
#[test]
fn both_riscv_targets_share_one_machine_number() {
    let riscv32 = golden32();
    assert_eq!(u16::from_le_bytes([riscv32[18], riscv32[19]]), 0xf3);
    assert_eq!(riscv32[4], 1, "ELFCLASS32");
    assert_ne!(
        Machine::RiscV32 as u16,
        Machine::RiscV64 as u16,
        "the two targets must be distinguishable as values",
    );
}
