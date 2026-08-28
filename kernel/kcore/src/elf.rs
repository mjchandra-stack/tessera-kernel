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
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_SEGMENTS;

// ELF constants (the subset v0 accepts).
const EI_NIDENT: usize = 16;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Where the two ELF classes keep the fields this loader reads.
///
/// **A table rather than two parsers.** The classes differ only in the width of
/// their address-sized fields and therefore in where the later ones start;
/// every check the parser makes — the magic, the type, the machine, the segment
/// bounds — is the same check on both. Two parsers would mean two places for a
/// bounds check to be missing from, and the one that gets less use is the one
/// it would be missing from.
///
/// The program-header layouts are genuinely reordered rather than merely
/// narrowed: ELF32 puts `p_flags` last, after the sizes, where ELF64 puts it
/// second. A parser that assumed narrowing alone would read a segment's flags
/// out of its alignment and map a text segment writable.
struct ElfLayout {
    /// Size of the file header, and of one program-header entry.
    ehdr_size: usize,
    phdr_size: usize,
    /// File-header field offsets: entry point, program-header table offset,
    /// entry size, entry count.
    e_entry: usize,
    e_phoff: usize,
    e_phentsize: usize,
    e_phnum: usize,
    /// Program-header field offsets, from the entry's base.
    p_flags: usize,
    p_offset: usize,
    p_vaddr: usize,
    p_filesz: usize,
    p_memsz: usize,
    /// Whether the address-sized fields are eight bytes rather than four.
    wide: bool,
}

/// The ELF64 header and program-header sizes, for the test builders that
/// assemble an image by hand.
#[cfg(test)]
pub(crate) const EHDR_SIZE: usize = ELF64.ehdr_size;
#[cfg(test)]
pub(crate) const PHDR_SIZE: usize = ELF64.phdr_size;

const ELF32: ElfLayout = ElfLayout {
    ehdr_size: 52,
    phdr_size: 32,
    e_entry: 24,
    e_phoff: 28,
    e_phentsize: 42,
    e_phnum: 44,
    p_offset: 4,
    p_vaddr: 8,
    p_filesz: 16,
    p_memsz: 20,
    p_flags: 24,
    wide: false,
};

const ELF64: ElfLayout = ElfLayout {
    ehdr_size: 64,
    phdr_size: 56,
    e_entry: 24,
    e_phoff: 32,
    e_phentsize: 54,
    e_phnum: 56,
    p_flags: 4,
    p_offset: 8,
    p_vaddr: 16,
    p_filesz: 32,
    p_memsz: 40,
    wide: true,
};

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
    RiscV64 = 0xf3,
    /// RISC-V, 32-bit.
    ///
    /// **Its discriminant is not an `e_machine` value**, and it is the first
    /// variant here that is not. The ELF specification gives RISC-V *one*
    /// machine number and distinguishes the two widths by the **class** byte,
    /// so a variant carrying the number alone could not say which of the two a
    /// caller is prepared to run. `0x01f3` is unassigned and deliberately not
    /// the spec's; [`Self::e_machine`] is what the parser compares against, and
    /// no existing value moved to make room for this one.
    RiscV32 = 0x01f3,
}

impl Machine {
    /// The `e_machine` an image for this target must declare.
    ///
    /// Equal to the discriminant for every variant whose discriminant is a
    /// machine number, which is every one but [`Self::RiscV32`].
    fn e_machine(self) -> u16 {
        match self {
            Self::RiscV32 => Self::RiscV64 as u16,
            other => other as u16,
        }
    }

    /// The ELF class an image for this target must declare.
    fn class(self) -> u8 {
        match self {
            Self::RiscV32 => ELFCLASS32,
            _ => ELFCLASS64,
        }
    }

    /// Where this target's images keep the fields the parser reads.
    fn layout(self) -> &'static ElfLayout {
        match self {
            Self::RiscV32 => &ELF32,
            _ => &ELF64,
        }
    }
}

/// Why an image was rejected — stable, descriptive reasons (a malformed or
/// hostile image must never load).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfError {
    /// Too short to hold the header (or a header it points at).
    Truncated,
    /// Not an ELF (bad `0x7f E L F` magic).
    BadMagic,
    /// Not a little-endian image of the class the caller's machine uses — a
    /// 32-bit image offered to a 64-bit loader, or the reverse.
    ///
    /// **The class is checked against the caller's machine, not against a
    /// constant.** Both are real classes; which one is right is a fact about
    /// who is loading, and a loader that accepted either would map an ELF32
    /// program header as if its fields were twice as wide.
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
    let layout = machine.layout();
    // An address-sized field, read at whichever width this class uses.
    let read_addr = |image: &[u8], at: usize| -> Result<u64, ElfError> {
        if layout.wide {
            read_u64(image, at)
        } else {
            read_u32(image, at).map(u64::from)
        }
    };

    if image.len() < layout.ehdr_size {
        return Err(ElfError::Truncated);
    }
    if image[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    // e_ident: class + data encoding. The class the *caller's machine* uses,
    // because both are real classes and reading one as the other reads a
    // program header's flags out of its alignment.
    if image[4] != machine.class() || image[5] != ELFDATA2LSB {
        return Err(ElfError::NotElf64);
    }
    let _ = (EI_NIDENT, ELFCLASS64);
    if read_u16(image, 16)? != ET_EXEC {
        return Err(ElfError::NotExecutable);
    }
    if read_u16(image, 18)? != machine.e_machine() {
        return Err(ElfError::WrongMachine);
    }
    let entry = read_addr(image, layout.e_entry)?;
    // An image declaring a program-header offset beyond this target's
    // address space is rejected, not truncated into range: a truncated
    // offset would point at a different, plausibly-parseable place in the
    // image and the headers found there would be believed.
    let phoff =
        usize::try_from(read_addr(image, layout.e_phoff)?).map_err(|_| ElfError::BadSegment)?;
    let phentsize = read_u16(image, layout.e_phentsize)? as usize;
    let phnum = read_u16(image, layout.e_phnum)? as usize;
    if phentsize < layout.phdr_size {
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
        let flags = read_u32(image, base + layout.p_flags)?;
        let file_offset = read_addr(image, base + layout.p_offset)?;
        let vaddr = read_addr(image, base + layout.p_vaddr)?;
        let file_size = read_addr(image, base + layout.p_filesz)?;
        let mem_size = read_addr(image, base + layout.p_memsz)?;
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

/// Loads every `PT_LOAD` of `image` into `space`, and returns its entry point.
///
/// Reserve writable and zero-filled — which settles `.bss` — then copy the
/// file bytes, then narrow to what the segment declared. **That order is the
/// only one that works**: the copy is what makes a text segment's bytes
/// executable, so the rights cannot go on before it. A page is therefore never
/// both writable and executable at rest, and a segment that asks to be both is
/// refused outright rather than having one of the two quietly dropped.
///
/// Generic over the porting layer because nothing here is any architecture's:
/// the two ports that had a copy of it differed in the `Machine` they parsed
/// for and in what they called a local.
///
/// Errors are `base_err..=base_err + 7`, so a caller can tell which step
/// refused without this function knowing what a caller's codes mean.
pub fn load_into<A: tessera_karch::AddressSpaceOps>(
    image: &[u8],
    space: &mut crate::vm::AddressSpace<A>,
    frames: &mut crate::pmem::BumpFrameAllocator<'_>,
    machine: Machine,
    base_err: u32,
) -> Result<u64, u32> {
    use tessera_karch::{AddressSpaceOps, FRAME_SIZE, PageFlags, VirtAddr};

    let parsed = parse(image, machine).map_err(|_| base_err)?;
    for seg in parsed.segments() {
        if seg.write && seg.exec {
            return Err(base_err + 1);
        }
        // A segment that asks for no read is refused rather than quietly given
        // one. Hardware here has no read-disable bit — a present page is
        // readable — so the request cannot be honoured, and granting read
        // anyway would be the loader deciding to widen what the image asked
        // for (docs/lifecycle/04, "No Silent Fallback"). No linker in this tree
        // emits one; this is what says so if that changes.
        if !seg.read {
            return Err(base_err + 7);
        }
        let vaddr = VirtAddr::new(seg.vaddr);
        // The whole segment must land in the user half, not just its base. A
        // segment based one page below the boundary and running past it is
        // exactly what a base-only check lets through — the same off-by-a-range
        // the loader's map syscall had.
        let len = seg
            .mem_size
            .div_ceil(FRAME_SIZE)
            .checked_mul(FRAME_SIZE)
            .ok_or(base_err + 2)?;
        let end_va = seg.vaddr.checked_add(len).ok_or(base_err + 2)?;
        if seg.vaddr % FRAME_SIZE != 0
            || seg.vaddr >= <A as AddressSpaceOps>::USER_ADDRESS_MAX
            || end_va > <A as AddressSpaceOps>::USER_ADDRESS_MAX
        {
            return Err(base_err + 2);
        }
        space
            .map_anonymous(vaddr, len, PageFlags::rw().user(), frames)
            .map_err(|_| base_err + 3)?;
        let end = (seg.file_offset + seg.file_size) as usize;
        if end > image.len() {
            return Err(base_err + 4);
        }
        space
            .copy_in(vaddr, &image[seg.file_offset as usize..end])
            .map_err(|_| base_err + 5)?;
        // **The grant is the segment's own, not a guess from one bit of it.**
        // This read `seg.exec` and nothing else, so every non-executable
        // segment came out writable — and a `PT_LOAD` that asks for read alone
        // is `.rodata`, which the program then had a writable page of. The
        // parsed `write` flag existed only to be checked against `exec` for
        // W^X and was never consulted for the thing it names.
        //
        // No image in this tree changes shape: the linker emits `R E` and
        // `RW ` here, which derive to exactly what the old two-way choice
        // produced. What changes is the image that separates its read-only
        // data, which is the ordinary layout everywhere else.
        let mut rights = PageFlags::none().read().user();
        if seg.write {
            rights = rights.write();
        }
        if seg.exec {
            rights = rights.execute();
        }
        space
            .protect_range(vaddr, len, rights)
            .map_err(|_| base_err + 6)?;
        if seg.exec {
            space.arch().sync_instruction_cache(vaddr, len);
        }
    }
    Ok(parsed.entry())
}

#[cfg(test)]
#[path = "tests/elf.rs"]
mod tests;
