// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The language and its back end, checked without a machine.
//!
//! **The interpreter and the code generator are held against each other.** A
//! code generator cannot be checked by running its output here — this is a host
//! test and the output is AArch64 — so what is checked instead is that the
//! instructions it emits decode back to the operations it was given, and that
//! the oracle in `Program::value` agrees with what those instructions would
//! compute. The machine check then runs the real thing against the same number,
//! which is the half this cannot do.

use super::{Error, ErrorKind, IMAGE_VA, MAX_OPS, Op, parse};

/// Decodes the instructions this crate emits, so a test can say what the
/// generated program *does* rather than what the generator claims.
///
/// Deliberately a second implementation: a decoder written from the encoder
/// would agree with it about a wrong encoding, which is the failure the whole
/// point of this test is to catch.
fn interpret(code: &[u32]) -> Option<u64> {
    let mut acc: u64 = 0;
    let mut reported = None;
    let mut x8: u64 = 0;
    for word in code {
        let w = *word;
        if w & 0xffe0_001f == 0xd280_0000 {
            // movz x0, #imm16
            acc = u64::from((w >> 5) & 0xffff);
        } else if w & 0xffe0_001f == 0xd280_0008 {
            // movz x8, #imm16
            x8 = u64::from((w >> 5) & 0xffff);
        } else if w & 0xffc0_03ff == 0x9100_0000 {
            acc = acc.wrapping_add(u64::from((w >> 10) & 0xfff));
        } else if w & 0xffc0_03ff == 0xd100_0000 {
            acc = acc.wrapping_sub(u64::from((w >> 10) & 0xfff));
        } else if w & 0xffc0_0000 == 0xd340_0000 {
            let imms = (w >> 10) & 0x3f;
            acc = acc.wrapping_shl(63 - imms);
        } else if w == 0xd400_0001 {
            if x8 == 1 {
                reported = Some(acc);
            } else if x8 == 5 {
                break;
            }
        } else if w == 0x1400_0000 {
            break;
        } else {
            return None;
        }
    }
    reported
}

fn compile(src: &str) -> super::Program {
    parse(src.as_bytes()).expect("compiles")
}

#[test]
fn the_generated_code_computes_what_the_oracle_says() {
    for src in [
        "load 0x1234\nshl 12\nadd 0x567\nemit\n",
        "load 7\nemit\n",
        "load 0xffff\nshl 48\nemit\n",
        "load 100\nsub 58\nemit\n",
        "load 1\nshl 8\nadd 1\nshl 8\nadd 1\nshl 8\nadd 1\nemit\n",
        "load 0\nsub 1\nemit\n",
    ] {
        let program = compile(src);
        let mut code = [0u32; MAX_OPS + 6];
        let words = program.code(&mut code).expect("emits");
        assert_eq!(
            interpret(&code[..words]),
            Some(program.value()),
            "generated code disagrees with the oracle for {src:?}",
        );
    }
}

#[test]
fn nothing_is_folded() {
    // `load 1 / add 1` is two instructions, not one. Folding would move the
    // arithmetic out of the generated program, which is the thing under test.
    let program = compile("load 1\nadd 1\nemit\n");
    let mut code = [0u32; MAX_OPS + 6];
    let words = program.code(&mut code).expect("emits");
    assert_eq!(words, 2 + 6);
    assert_eq!(program.value(), 2);
}

#[test]
fn a_wider_source_makes_a_different_program() {
    // The property the machine check depends on: change the source, change the
    // bytes. A generator that emitted a template would pass everything above.
    let a = compile("load 1\nemit\n");
    let b = compile("load 2\nemit\n");
    let mut one = [0u8; super::MAX_IMAGE];
    let mut two = [0u8; super::MAX_IMAGE];
    let na = a.emit(&mut one).expect("a");
    let nb = b.emit(&mut two).expect("b");
    assert_eq!(na, nb, "same shape");
    assert_ne!(one[..na], two[..nb], "different bytes");
}

#[test]
fn comments_and_blank_lines_are_not_operations() {
    let program = compile("; a header\n\n  load 5   ; trailing\n\n\temit\n\n");
    assert_eq!(program.ops(), &[Op::Load(5)]);
    assert_eq!(program.value(), 5);
}

#[test]
fn hex_and_decimal_and_underscores_all_read() {
    assert_eq!(compile("load 0x10\nemit\n").value(), 16);
    assert_eq!(compile("load 16\nemit\n").value(), 16);
    assert_eq!(compile("load 0x1_0\nemit\n").value(), 16);
    assert_eq!(compile("load 0X10\nemit\n").value(), 16);
}

#[test]
fn the_emitted_image_is_an_elf_this_machine_would_load() {
    let program = compile("load 0x41\nemit\n");
    let mut image = [0u8; super::MAX_IMAGE];
    let n = program.emit(&mut image).expect("emits");
    assert_eq!(&image[..4], b"\x7fELF");
    assert_eq!(image[4], 2, "64-bit class");
    assert_eq!(image[5], 1, "little-endian");
    assert_eq!(u16::from_le_bytes([image[16], image[17]]), 2, "ET_EXEC");
    assert_eq!(u16::from_le_bytes([image[18], image[19]]), 183, "aarch64");
    assert_eq!(u16::from_le_bytes([image[54], image[55]]), 56, "phentsize");
    assert_eq!(u16::from_le_bytes([image[56], image[57]]), 1, "one segment");
    // The entry is past the headers, and the segment covers the whole file.
    let entry = u64::from_le_bytes(image[24..32].try_into().expect("entry"));
    assert_eq!(entry, IMAGE_VA + 120);
    let filesz = u64::from_le_bytes(image[96..104].try_into().expect("filesz"));
    assert_eq!(filesz as usize, n);
}

/// The fields go where `//userspace/elfload` reads them from.
///
/// **Not `elfload::parse`, and the reason is the point.** That crate compiled
/// for *this* host expects the host's machine number; an image naming AArch64
/// is one it should refuse, and does. What can be checked without an AArch64
/// host is the coupling that actually breaks — that this generator writes each
/// field at the offset the loader reads it from — so the offsets come from
/// `elfload::layout` rather than being spelled again here. The machine check
/// runs the real parse against the real image.
#[test]
fn the_fields_are_where_the_loader_reads_them() {
    use tessera_elfload::layout;
    let program = compile("load 0xc0de\nshl 12\nadd 0xbee\nshl 4\nadd 0xf\nemit\n");
    let mut image = [0u8; super::MAX_IMAGE];
    let n = program.emit(&mut image).expect("emits");

    let u16_at = |at: usize| u16::from_le_bytes([image[at], image[at + 1]]);
    let u64_at = |at: usize| u64::from_le_bytes(image[at..at + 8].try_into().expect("eight bytes"));
    assert_eq!(image[4], layout::CLASS);
    assert_eq!(u16_at(18), 183, "AArch64, which is not this host's EM_THIS");
    assert_eq!(u64_at(layout::E_ENTRY), IMAGE_VA + 120);
    assert_eq!(u64_at(layout::E_PHOFF) as usize, 64);
    assert_eq!(u16_at(layout::E_PHENTSIZE) as usize, layout::PHDR);
    assert_eq!(u16_at(layout::E_PHNUM), 1);

    let ph = 64;
    assert_eq!(u64_at(ph + layout::P_OFFSET), 0);
    assert_eq!(u64_at(ph + layout::P_VADDR), IMAGE_VA);
    assert_eq!(u64_at(ph + layout::P_FILESZ) as usize, n);
    assert_eq!(u64_at(ph + layout::P_MEMSZ) as usize, n);
    let flags = u32::from_le_bytes(
        image[ph + layout::P_FLAGS..ph + layout::P_FLAGS + 4]
            .try_into()
            .expect("four bytes"),
    );
    assert_eq!(
        flags,
        tessera_elfload::PF_R | tessera_elfload::PF_X,
        "readable and executable, not writable",
    );
}

/// And a loader built for another machine refuses it, which is the machine
/// check `elfload` performs before it believes any offset above.
#[test]
fn a_loader_for_a_different_machine_refuses_it() {
    let program = compile("load 1\nemit\n");
    let mut image = [0u8; super::MAX_IMAGE];
    let n = program.emit(&mut image).expect("emits");
    assert!(
        tessera_elfload::parse(&image[..n]).is_none(),
        "this host is not AArch64, so its loader must not accept an AArch64 image",
    );
}

#[test]
fn a_source_that_never_emits_is_refused() {
    assert_eq!(
        parse(b"load 1\n"),
        Err(Error {
            kind: ErrorKind::NoEmit,
            line: 0
        })
    );
}

#[test]
fn anything_after_emit_is_refused_rather_than_ignored() {
    assert_eq!(
        parse(b"load 1\nemit\nadd 1\n"),
        Err(Error {
            kind: ErrorKind::TrailingOps,
            line: 3
        })
    );
}

#[test]
fn the_line_number_is_the_one_a_reader_would_count() {
    assert_eq!(
        parse(b"; a comment\nload 1\nnope 2\nemit\n"),
        Err(Error {
            kind: ErrorKind::UnknownOp,
            line: 3
        })
    );
}

#[test]
fn an_operand_too_wide_for_its_instruction_is_refused() {
    // 12 bits for add and sub, 16 for load, 6 for shl. Each is the width of the
    // immediate field the instruction actually has.
    assert_eq!(
        parse(b"load 1\nadd 0x1000\nemit\n").expect_err("add").kind,
        ErrorKind::BadOperand
    );
    assert_eq!(
        parse(b"load 0x10000\nemit\n").expect_err("load").kind,
        ErrorKind::BadOperand
    );
    assert_eq!(
        parse(b"load 1\nshl 64\nemit\n").expect_err("shl").kind,
        ErrorKind::BadOperand
    );
    // And one that would overflow `u64` on the way in, rather than wrapping.
    assert_eq!(
        parse(b"load 0xffffffffffffffffff\nemit\n")
            .expect_err("overflow")
            .kind,
        ErrorKind::BadOperand
    );
}

#[test]
fn arity_is_checked_both_ways() {
    assert_eq!(
        parse(b"load\nemit\n").expect_err("no operand").kind,
        ErrorKind::WrongArity
    );
    assert_eq!(
        parse(b"load 1\nemit 2\n")
            .expect_err("emit takes none")
            .kind,
        ErrorKind::WrongArity
    );
}

#[test]
fn a_source_with_too_many_operations_is_refused() {
    // `MAX_OPS + 1` operations, built in a fixed array: this crate is `no_std`
    // and its tests are too, which is the same discipline the library is under.
    const LINE: &[u8] = b"add 1\n";
    let mut text = [0u8; (MAX_OPS + 1) * 6 + 5];
    let mut at = 0;
    for _ in 0..=MAX_OPS {
        text[at..at + LINE.len()].copy_from_slice(LINE);
        at += LINE.len();
    }
    text[at..at + 5].copy_from_slice(b"emit\n");
    assert_eq!(
        parse(&text).expect_err("too many").kind,
        ErrorKind::TooManyOps
    );
}

#[test]
fn a_bad_operand_is_not_a_wrapped_one() {
    // The parse refuses; it does not take the low bits and carry on. A compiler
    // that wrapped would emit a program reporting a number nobody wrote.
    assert!(parse(b"load 65536\nemit\n").is_err());
    assert_eq!(compile("load 65535\nemit\n").value(), 65535);
}
