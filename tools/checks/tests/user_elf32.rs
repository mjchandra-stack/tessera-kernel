// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The 32-bit ring-3 toolchain, checked against the loader that has to accept
//! what it produces.
//!
//! **Two halves of one claim, and neither is worth much alone.** `kcore::elf`
//! learned the 32-bit class against images this repository assembles by hand
//! (D258), which proves the parser agrees with the ELF specification as this
//! repository reads it; `//userspace/uabi` learned a syscall sequence for a
//! 32-bit machine (D259), which lets the toolchain emit such a program at all.
//! This is the join: the bytes a real compiler and a real linker produced, fed
//! to the real parser.
//!
//! It is a gate rather than a unit test because the thing under test is an
//! agreement between two packages that never reference each other — the build
//! rules and the kernel — and neither can hold it alone.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Endianness And
//! Word Size"), docs/api/01-system-call-interface.md ("The Result Word")

use tessera_kcore::elf::{ElfError, Machine, parse};

/// The built RISC-V 32 program, from the path Bazel puts in the environment.
fn image() -> Vec<u8> {
    let path = std::env::var("TESSERA_RISCV32_PROGRAM")
        .expect("the build must name the 32-bit program under test");
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// The toolchain produced a 32-bit RISC-V executable, and the loader takes it.
#[test]
fn the_kernel_loader_accepts_the_32_bit_toolchains_output() {
    let image = image();
    // The class byte first, so a failure below distinguishes "the linker
    // emitted the wrong thing" from "the parser rejected the right thing".
    assert_eq!(image[4], 1, "the linker did not emit ELFCLASS32");
    assert_eq!(
        u16::from_le_bytes([image[18], image[19]]),
        0xf3,
        "the linker did not emit a RISC-V machine number",
    );

    let elf = parse(&image, Machine::RiscV32).expect("the loader refused the toolchain's output");
    assert_eq!(
        elf.entry(),
        0x1000_0000,
        "the entry point is not the base `user-riscv32.ld` links at",
    );

    // **One `PT_LOAD`, and that is the linker being right rather than this
    // being lax.** The script declares a text and a data segment, and this
    // program has no data and no bss at all — so the data segment is empty and
    // is dropped. What the image does carry beyond it is a `GNU_PROPERTY`
    // note, which the loader skips because it is not `PT_LOAD`; a parser that
    // did not skip it would try to map a segment at virtual address zero.
    assert_eq!(
        elf.segments().len(),
        1,
        "expected exactly the text segment this program has",
    );
    let text = &elf.segments()[0];
    assert_eq!(text.vaddr, 0x1000_0000);
    assert!(text.mem_size >= text.file_size);

    // **The permissions, which are the assertion that discriminates.** Every
    // other field narrows in place between the two ELF classes, so reading
    // this image at the 64-bit offsets still yields plausible numbers; ELF32
    // moves `p_flags` from offset 4 to offset 24, so reading it at the 64-bit
    // place returns the segment's *file offset* — `0x1000` here, which carries
    // neither `PF_R` nor `PF_X` and describes a page that can be neither read
    // nor run.
    assert!(text.read, "`p_flags` was not read from the ELF32 offset");
    assert!(text.exec, "`p_flags` was not read from the ELF32 offset");
    assert!(
        !text.write,
        "the text segment is writable — W^X does not hold"
    );
}

/// And the same bytes are refused for the 64-bit target.
///
/// **The half that says the class check is load-bearing.** RISC-V gives both
/// widths one `e_machine`, so this image passes the machine check for
/// `RiscV64` and must still be refused — by its class and nothing else.
#[test]
fn the_same_image_is_refused_for_the_64_bit_target() {
    assert_eq!(
        parse(&image(), Machine::RiscV64),
        Err(ElfError::NotElf64),
        "a 32-bit image was accepted for the 64-bit target",
    );
}
