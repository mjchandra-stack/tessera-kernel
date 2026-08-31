// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **A language, and a code generator that turns it into a program.**
//!
//! Deliberately the smallest thing that is not a fixed byte array. The claim
//! `docs/roadmap/04` Phase 2 makes is about the *loop* — a program on this
//! machine produced a program, wrote it to a volume, and the machine ran what
//! came back — and that plan predicted in advance that the phase "will be
//! attempted with too large an input language". So: an accumulator, four
//! operations, and a way to say what the answer was.
//!
//! ```text
//! ; report 0x1234_567
//! load 0x1234
//! shl 12
//! add 0x567
//! emit
//! ```
//!
//! `add` and `sub` take twelve bits because that is the width of the
//! instruction's immediate field, and `load` takes sixteen for the same reason.
//! A wider operand is a source error rather than something to synthesise a
//! second instruction for — which is the language being this small on purpose,
//! and is the first thing that caught a bad example in this very comment.
//!
//! **What makes it a compiler rather than a template.** The value a generated
//! program reports is not in this crate anywhere: it is computed at run time by
//! instructions this crate chose, from a source file it read. A generator that
//! emitted a constant would fail the moment the source changed, which is what
//! its check does to it — and is the same argument D146 made about a store
//! whose only subject was four blobs `mkstore synth --seed` produced.
//!
//! **Nothing is folded.** `load 1 / add 1` could be emitted as `load 2`, and is
//! not: constant folding would move the arithmetic from the generated program
//! into this one, and the generated program is the thing under test. The
//! interpreter in [`Program::value`] exists to say what the emitted code *must*
//! compute, so a host test can hold the two against each other without a
//! machine.
//!
//! Normative: docs/roadmap/04-self-hosting.md ("Phase 2")

#![no_std]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// The most operations one program may have.
///
/// Bounded like every other pool in this tree: a source with more is refused,
/// not truncated, because a program that compiled the first sixty-four lines of
/// a file and reported success would be worse than one that refused.
pub const MAX_OPS: usize = 64;

/// The widest image [`Program::emit`] will produce, headers included.
pub const MAX_IMAGE: usize = 512;

/// One operation on the accumulator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    /// Replace the accumulator with a 16-bit constant.
    Load(u16),
    /// Add a 12-bit constant.
    Add(u16),
    /// Subtract a 12-bit constant.
    Sub(u16),
    /// Shift left by 0..=63.
    Shl(u8),
}

/// Why a source could not be compiled.
///
/// Values rather than a formatted string: a program above this cannot print,
/// and a caller has to be able to say *which* line was wrong
/// (`docs/lifecycle/04`, "Errors are stable-domain values").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Error {
    /// What went wrong.
    pub kind: ErrorKind,
    /// The 1-based line it went wrong on, or 0 for a whole-file complaint.
    pub line: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrorKind {
    /// A word in the first position that names no operation.
    UnknownOp,
    /// An operand that is not a number, or one too wide for its operation.
    BadOperand,
    /// An operation that wants an operand and was given none, or given two.
    WrongArity,
    /// More than [`MAX_OPS`] operations.
    TooManyOps,
    /// The source never said `emit`, so the program it describes reports
    /// nothing and there would be no way to tell it had run.
    NoEmit,
    /// Something after `emit`, which would never execute.
    TrailingOps,
    /// The image did not fit in the buffer it was given.
    ImageTooLarge,
}

/// A parsed source: the operations, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Program {
    ops: [Op; MAX_OPS],
    len: usize,
}

impl Program {
    /// The operations, in order.
    #[must_use]
    pub fn ops(&self) -> &[Op] {
        &self.ops[..self.len]
    }

    /// What a correctly generated program will report.
    ///
    /// **The oracle, and it is not used by the generator.** This interprets the
    /// operations; [`emit`](Self::emit) compiles them. A host test runs both and
    /// requires them to agree, which is the only way to check a code generator
    /// without executing its output — and the machine check then runs the real
    /// thing against the same number.
    ///
    /// Wrapping, because the generated instructions wrap: a 64-bit accumulator
    /// that overflowed differently here than on the machine would make this a
    /// worse oracle than no oracle.
    #[must_use]
    pub fn value(&self) -> u64 {
        let mut acc: u64 = 0;
        for op in self.ops() {
            acc = match *op {
                Op::Load(v) => u64::from(v),
                Op::Add(v) => acc.wrapping_add(u64::from(v)),
                Op::Sub(v) => acc.wrapping_sub(u64::from(v)),
                Op::Shl(n) => acc.wrapping_shl(u32::from(n)),
            };
        }
        acc
    }
}

/// Splits `line` at the first `;` and trims ASCII whitespace from both ends.
fn strip(line: &[u8]) -> &[u8] {
    let end = match line.iter().position(|b| *b == b';') {
        Some(at) => at,
        None => line.len(),
    };
    let mut slice = &line[..end];
    while let [first, rest @ ..] = slice {
        if first.is_ascii_whitespace() {
            slice = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = slice {
        if last.is_ascii_whitespace() {
            slice = rest;
        } else {
            break;
        }
    }
    slice
}

/// Splits a stripped line into its word and its operand, if any.
fn split_word(line: &[u8]) -> (&[u8], Option<&[u8]>) {
    match line.iter().position(|b| b.is_ascii_whitespace()) {
        None => (line, None),
        Some(at) => {
            let rest = strip(&line[at..]);
            if rest.is_empty() {
                (&line[..at], None)
            } else {
                (&line[..at], Some(rest))
            }
        }
    }
}

/// Reads a decimal or `0x`-prefixed operand.
///
/// **Refused rather than wrapped.** A literal too wide for `u64` is a source
/// error, and a parser that silently took its low bits would compile a program
/// that reports a number nobody wrote.
fn number(text: &[u8]) -> Option<u64> {
    let (digits, radix) = if let [b'0', b'x' | b'X', rest @ ..] = text {
        (rest, 16u64)
    } else {
        (text, 10u64)
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for byte in digits {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' if radix == 16 => u64::from(byte - b'a') + 10,
            b'A'..=b'F' if radix == 16 => u64::from(byte - b'A') + 10,
            b'_' => continue,
            _ => return None,
        };
        value = value.checked_mul(radix)?.checked_add(digit)?;
    }
    Some(value)
}

/// Parses `source` into a [`Program`].
pub fn parse(source: &[u8]) -> Result<Program, Error> {
    let mut ops = [Op::Load(0); MAX_OPS];
    let mut len = 0usize;
    let mut saw_emit = false;

    // 1-based, because a line number a reader has to adjust is worse than none.
    for (line_no, line) in (1_u32..).zip(source.split(|b| *b == b'\n')) {
        let line = strip(line);
        if line.is_empty() {
            continue;
        }
        if saw_emit {
            // Anything after `emit` never runs. Said rather than dropped: a
            // compiler that silently ignored half a file is one whose output
            // nobody can reason about.
            return Err(Error {
                kind: ErrorKind::TrailingOps,
                line: line_no,
            });
        }
        let (word, operand) = split_word(line);
        let err = |kind| Error {
            kind,
            line: line_no,
        };

        if word == b"emit" {
            if operand.is_some() {
                return Err(err(ErrorKind::WrongArity));
            }
            saw_emit = true;
            continue;
        }

        let operand = operand.ok_or_else(|| err(ErrorKind::WrongArity))?;
        let value = number(operand).ok_or_else(|| err(ErrorKind::BadOperand))?;
        let op = match word {
            b"load" => Op::Load(u16::try_from(value).map_err(|_| err(ErrorKind::BadOperand))?),
            b"add" | b"sub" => {
                // 12 bits, because that is what the instruction's immediate
                // field holds. A wider operand is a source error rather than
                // something to synthesise a second instruction for — the
                // language is this small on purpose.
                if value > 0xfff {
                    return Err(err(ErrorKind::BadOperand));
                }
                let v = value as u16;
                if word == b"add" {
                    Op::Add(v)
                } else {
                    Op::Sub(v)
                }
            }
            b"shl" => {
                if value > 63 {
                    return Err(err(ErrorKind::BadOperand));
                }
                Op::Shl(value as u8)
            }
            _ => return Err(err(ErrorKind::UnknownOp)),
        };
        if len == MAX_OPS {
            return Err(err(ErrorKind::TooManyOps));
        }
        ops[len] = op;
        len += 1;
    }

    if !saw_emit {
        return Err(Error {
            kind: ErrorKind::NoEmit,
            line: 0,
        });
    }
    Ok(Program { ops, len })
}

// --- The AArch64 back end -------------------------------------------------
//
// One instruction per operation and no peephole anywhere, for the reason the
// module comment gives: the arithmetic belongs to the generated program.

/// `movz Xd, #imm16`, shift 0.
fn movz(rd: u32, imm: u16) -> u32 {
    0xd280_0000 | (u32::from(imm) << 5) | rd
}

/// `add x0, x0, #imm12`.
fn add_imm(imm: u16) -> u32 {
    0x9100_0000 | (u32::from(imm) << 10)
}

/// `sub x0, x0, #imm12`.
fn sub_imm(imm: u16) -> u32 {
    0xd100_0000 | (u32::from(imm) << 10)
}

/// `lsl x0, x0, #sh`, which is `ubfm x0, x0, #(-sh mod 64), #(63-sh)`.
fn lsl_imm(sh: u8) -> u32 {
    let immr = (64 - u32::from(sh)) % 64;
    let imms = 63 - u32::from(sh);
    0xd340_0000 | (immr << 16) | (imms << 10)
}

/// `svc #0`.
const SVC: u32 = 0xd400_0001;
/// `b .` — a branch to itself, so a program whose exit somehow returns spins
/// where a reader can see it rather than running off the end of its own text.
const SPIN: u32 = 0x1400_0000;

/// `DebugWrite`, the one call a generated program makes to say what it computed.
const SYS_DEBUG_WRITE: u16 = 1;
const SYS_PROCESS_EXIT: u16 = 5;

/// Where a generated program is loaded. The same address this port's linker
/// script gives every other user program, because it is the same user half.
pub const IMAGE_VA: u64 = 0x0000_1000_0000_0000;

/// AArch64's ELF machine number.
const EM_AARCH64: u16 = 183;
const EHDR: usize = 64;
const PHDR: usize = 56;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_R: u32 = 4;

impl Program {
    /// The instructions this program compiles to, in order.
    ///
    /// Separate from [`emit`](Self::emit) so a host test can check the code
    /// without reading it back out of an ELF — the encodings are the part that
    /// is easy to get wrong and the container is not.
    pub fn code(&self, out: &mut [u32]) -> Result<usize, Error> {
        let needed = self.len + 6;
        if out.len() < needed {
            return Err(Error {
                kind: ErrorKind::ImageTooLarge,
                line: 0,
            });
        }
        let mut at = 0usize;
        for op in self.ops() {
            out[at] = match *op {
                Op::Load(v) => movz(0, v),
                Op::Add(v) => add_imm(v),
                Op::Sub(v) => sub_imm(v),
                Op::Shl(n) => lsl_imm(n),
            };
            at += 1;
        }
        // Report the accumulator, then exit cleanly. `DebugWrite` clobbers x0
        // with its result, so the exit code is loaded after the call and not
        // before it — a generated program that exited with whatever the console
        // returned would be reporting the kernel's answer as its own.
        out[at] = movz(8, SYS_DEBUG_WRITE);
        out[at + 1] = SVC;
        out[at + 2] = movz(8, SYS_PROCESS_EXIT);
        out[at + 3] = movz(0, 0);
        out[at + 4] = SVC;
        out[at + 5] = SPIN;
        Ok(needed)
    }

    /// Writes a loadable ELF for this program into `out`, returning its length.
    ///
    /// One `PT_LOAD` covering the whole file from offset zero, so the headers
    /// are mapped with the text. That costs 120 bytes of address space and
    /// saves an alignment rule that would otherwise have to be right for the
    /// image to load at all.
    pub fn emit(&self, out: &mut [u8]) -> Result<usize, Error> {
        let too_large = Error {
            kind: ErrorKind::ImageTooLarge,
            line: 0,
        };
        let mut code = [0u32; MAX_OPS + 6];
        let words = self.code(&mut code)?;
        let total = EHDR + PHDR + words * 4;
        if total > out.len() || total > MAX_IMAGE {
            return Err(too_large);
        }
        for byte in out[..total].iter_mut() {
            *byte = 0;
        }

        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2; // 64-bit
        out[5] = 1; // little-endian
        out[6] = 1; // EI_VERSION
        out[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        out[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        let entry = IMAGE_VA + (EHDR + PHDR) as u64;
        out[24..32].copy_from_slice(&entry.to_le_bytes());
        out[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes()); // e_phoff
        out[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
        out[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes()); // e_phentsize
        out[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

        let ph = EHDR;
        out[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        out[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        out[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        out[ph + 16..ph + 24].copy_from_slice(&IMAGE_VA.to_le_bytes()); // p_vaddr
        out[ph + 24..ph + 32].copy_from_slice(&IMAGE_VA.to_le_bytes()); // p_paddr
        out[ph + 32..ph + 40].copy_from_slice(&(total as u64).to_le_bytes()); // p_filesz
        out[ph + 40..ph + 48].copy_from_slice(&(total as u64).to_le_bytes()); // p_memsz
        out[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

        let mut at = EHDR + PHDR;
        for word in &code[..words] {
            out[at..at + 4].copy_from_slice(&word.to_le_bytes());
            at += 4;
        }
        Ok(total)
    }
}

#[cfg(test)]
#[path = "tests/tsm.rs"]
mod tests;
