// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Structure-aware fuzzing of the generated decoders**, driven from the
//! schema that generated them.
//!
//! `docs/lifecycle/02` ("Tier 2") asks for *"structure-aware fuzz targets
//! generated from ISL … parsers and binary interfaces have mandatory fuzz
//! targets that fail CI if absent"*. This is the engine half; `islc --fuzz`
//! emits the targets.
//!
//! # Why generated, and why that is the whole idea
//!
//! A decoder for a frozen struct rejects almost every random byte string, and
//! it rejects them **immediately**, at the first strict-enum field. A byte-level
//! fuzzer therefore spends its entire budget rediscovering facts the compiler
//! already knows — that offset 12 holds one of four values, that offset 24 is a
//! length, that the record is exactly 96 bytes long. It reaches the interesting
//! part of the decoder almost never.
//!
//! The compiler knows every field's offset, width and legal domain, so the
//! mutator here starts from a **record that decodes** and changes one thing at
//! a time. That is what makes the oracle possible, and the oracle is the point:
//! for most mutations this engine knows what the answer *should* be.
//!
//! # The oracle
//!
//! - A field set to a value the schema permits must still decode. A decoder
//!   that refused one would be narrower than the type it implements, and the
//!   producer that sent it would be blameless.
//! - A strict-enum field set outside its domain, or a `bits` field carrying a
//!   bit the schema never declared, must be refused. These are the guards the
//!   whole frozen-struct discipline rests on, and random bytes exercise one
//!   field's and never the rest.
//! - Anything that decodes must **re-encode to the same bytes**. Two byte
//!   strings decoding to one value is how a signature over bytes and a check
//!   over values come apart, which is a security property rather than a
//!   tidiness one.
//! - A buffer shorter than the record must be refused rather than read past.
//!
//! Bit flips are also thrown in, with no expected answer beyond canonicality
//! and not crashing — they are what finds the case nobody modelled.
//!
//! # Determinism
//!
//! Every run is `(target, seed, iteration)` and nothing else: the generator is
//! a plain xorshift and there is no clock, no thread and no environment. A
//! finding reproduces from three numbers, so a failure is a bug report rather
//! than an anecdote.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 2"),
//! docs/api/03-interface-schema-language.md ("Wire Format")

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use tessera_isl_runtime::{WireDecode, WireEncode, decode, encode};

/// A deterministic generator. **Not** a random source in the security sense —
/// `docs/security/02` puts randomness behind the kernel CSPRNG, and this is a
/// test harness that must repeat itself exactly.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Any non-zero state; xorshift is fixed at zero.
        Rng(seed | 1)
    }

    /// The next value in the sequence. Named `step` rather than `next` so it
    /// is never mistaken for an iterator's.
    pub fn step(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.step() % bound as u64) as usize
    }
}

/// What values a field may hold, as the schema declares them.
#[derive(Clone, Copy, Debug)]
pub enum Domain {
    /// Every bit pattern of the field's width is a legal value.
    Any,
    /// A strict enum: exactly these values decode, and nothing else does.
    Enum(&'static [u64]),
    /// A `bits` mask: any subset of the declared bits decodes, and a value with
    /// a bit the schema never declared does not. A second domain rather than
    /// `Any` because the generated decoder really does refuse one
    /// (`WireError::BadBits`), and a fuzzer that never wrote an undeclared bit
    /// would leave that guard untouched.
    Mask(u64),
}

/// One field of a frozen struct, as the schema lays it out.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub name: &'static str,
    pub offset: usize,
    /// Width in bytes: 1, 2, 4 or 8.
    pub size: usize,
    pub domain: Domain,
}

/// What the codec did with one input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// The decoder refused it.
    Rejected,
    /// It decoded, and re-encoding reproduced the bytes exactly.
    Canonical,
    /// It decoded, and re-encoding produced *different* bytes — so two byte
    /// strings name one value.
    NotCanonical,
    /// It decoded and could not be encoded back at all.
    EncodeFailed,
}

/// Runs the codec over `bytes` and reports what happened.
///
/// The generated targets call this with their concrete type; everything else
/// here is type-agnostic.
pub fn probe<T: WireEncode + WireDecode>(bytes: &[u8], wire_size: usize) -> Verdict {
    let Ok(value) = decode::<T>(bytes) else {
        return Verdict::Rejected;
    };
    let mut back = vec![0u8; wire_size];
    match encode(&value, &mut back) {
        Err(_) => Verdict::EncodeFailed,
        Ok(written) if written != wire_size => Verdict::NotCanonical,
        Ok(_) if back != bytes => Verdict::NotCanonical,
        Ok(_) => Verdict::Canonical,
    }
}

/// One fuzz target: a frozen struct, its layout, and a record that decodes.
pub struct Target {
    pub name: &'static str,
    pub wire_size: usize,
    pub fields: &'static [Field],
    /// A canonical encoding of a value whose every field is legal — the
    /// starting point a byte-level fuzzer has no way to construct.
    pub seed: &'static [u8],
    pub probe: fn(&[u8], usize) -> Verdict,
}

/// What the mutator did, so a finding says which oracle was violated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mutation {
    /// Bits flipped at random. No expected verdict beyond canonicality.
    FlipBits,
    /// Every enum field set to some member the schema declares.
    LegalValues,
    /// One enum or bits field set outside its domain.
    IllegalEnum,
    /// The buffer cut short of the record's length.
    Truncated,
}

/// A violated expectation, and everything needed to reproduce it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Finding {
    pub target: &'static str,
    pub field: &'static str,
    pub mutation: Mutation,
    pub verdict: Verdict,
    pub seed: u64,
    pub iteration: u32,
}

/// What a run covered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Coverage {
    pub targets: u32,
    pub inputs: u32,
    /// Inputs the decoder accepted. Reported because a run in which *nothing*
    /// decoded exercised only the guard and none of the decoder behind it —
    /// which is the fuzzing equivalent of a check nobody ran.
    pub accepted: u32,
    /// Inputs it refused.
    pub rejected: u32,
}

/// Fuzzes every target, `iterations` inputs each, and returns what it found.
///
/// The first finding stops that target and is returned; a run is either clean
/// or has a reproducible counterexample, and a list of near-duplicates from one
/// broken field would be neither.
pub fn run(targets: &[Target], iterations: u32, seed: u64) -> (Coverage, Option<Finding>) {
    let mut coverage = Coverage {
        targets: targets.len() as u32,
        ..Coverage::default()
    };
    for target in targets {
        let mut rng = Rng::new(seed ^ fnv(target.name));
        // The seed itself must decode, or the target is describing a record
        // its own schema does not accept and every mutation below starts from
        // nonsense.
        coverage.inputs += 1;
        match (target.probe)(target.seed, target.wire_size) {
            Verdict::Canonical => coverage.accepted += 1,
            verdict => {
                return (
                    coverage,
                    Some(Finding {
                        target: target.name,
                        field: "<seed>",
                        mutation: Mutation::LegalValues,
                        verdict,
                        seed,
                        iteration: 0,
                    }),
                );
            }
        }

        for iteration in 0..iterations {
            let mut bytes = target.seed.to_vec();
            let (mutation, field) = mutate(&mut bytes, target, &mut rng);
            let verdict = (target.probe)(&bytes, target.wire_size);
            coverage.inputs += 1;
            match verdict {
                Verdict::Rejected => coverage.rejected += 1,
                _ => coverage.accepted += 1,
            }
            if judge(mutation, verdict).is_some() {
                return (
                    coverage,
                    Some(Finding {
                        target: target.name,
                        field,
                        mutation,
                        verdict,
                        seed,
                        iteration,
                    }),
                );
            }
        }
    }
    (coverage, None)
}

/// A parser that is **not** a generated codec: bytes in, accepted or refused.
///
/// The compiler knows nothing about a hand-written parser — no field offsets,
/// no domains, no way to build a legal input — so the oracle here is much
/// weaker than the one above, and saying so is the point rather than an
/// apology. What is checked is that the parser **never panics**, on any input,
/// and that its own valid example still parses. In safe Rust that is not
/// nothing: a slice index past the end, an arithmetic overflow, a subtraction
/// that wraps a length, and a loop that never terminates all show up here, and
/// all of them are what a malformed device tree or a corrupt container would
/// otherwise do inside a kernel.
pub struct BlobTarget {
    pub name: &'static str,
    /// A valid input. Also the thing the target is claiming to parse — a
    /// target whose own example is refused is describing nothing.
    pub seed: &'static [u8],
    /// Parses `bytes` and reports whether it accepted them, having also walked
    /// whatever the parse produced. **Must return rather than panic, for every
    /// input.**
    pub parse: fn(&[u8]) -> bool,
}

/// Fuzzes hand-written parsers: bit flips, truncation and extension.
///
/// Mutations here are untargeted because there is nothing to target. That is
/// the cost of a parser the compiler did not write, and it is the argument for
/// generating them where possible.
pub fn run_blobs(
    targets: &[BlobTarget],
    iterations: u32,
    seed: u64,
) -> (Coverage, Option<Finding>) {
    let mut coverage = Coverage {
        targets: targets.len() as u32,
        ..Coverage::default()
    };
    for target in targets {
        let mut rng = Rng::new(seed ^ fnv(target.name));
        coverage.inputs += 1;
        if (target.parse)(target.seed) {
            coverage.accepted += 1;
        } else {
            return (
                coverage,
                Some(Finding {
                    target: target.name,
                    field: "<seed>",
                    mutation: Mutation::LegalValues,
                    verdict: Verdict::Rejected,
                    seed,
                    iteration: 0,
                }),
            );
        }

        for _ in 0..iterations {
            let mut bytes = target.seed.to_vec();
            match rng.step() % 3 {
                0 => bytes.truncate(rng.below(bytes.len().max(1))),
                1 => {
                    let extra = rng.below(64);
                    for _ in 0..extra {
                        bytes.push((rng.step() & 0xff) as u8);
                    }
                    flip(&mut bytes, &mut rng);
                }
                _ => flip(&mut bytes, &mut rng),
            }
            coverage.inputs += 1;
            // The oracle: returning at all is the pass. A panic fails the test
            // where it happens, and a hang fails it by timeout.
            if (target.parse)(&bytes) {
                coverage.accepted += 1;
            } else {
                coverage.rejected += 1;
            }
        }
    }
    (coverage, None)
}

/// Whether `verdict` is what `mutation` should have produced.
///
/// `None` means the oracle is satisfied. Bit flips have no expected verdict
/// except that whatever decodes must be canonical — saying more would be
/// inventing a rule the schema does not state.
fn judge(mutation: Mutation, verdict: Verdict) -> Option<()> {
    match (mutation, verdict) {
        (_, Verdict::NotCanonical | Verdict::EncodeFailed) => Some(()),
        (Mutation::LegalValues, Verdict::Rejected) => Some(()),
        (Mutation::IllegalEnum, Verdict::Canonical) => Some(()),
        (Mutation::Truncated, Verdict::Canonical) => Some(()),
        _ => None,
    }
}

/// Applies one mutation, returning what it did and which field it touched.
fn mutate(bytes: &mut Vec<u8>, target: &Target, rng: &mut Rng) -> (Mutation, &'static str) {
    let enums: Vec<&Field> = target
        .fields
        .iter()
        .filter(|f| matches!(f.domain, Domain::Enum(_) | Domain::Mask(_)))
        .collect();

    match rng.step() % 4 {
        0 if !enums.is_empty() => {
            // Every enum field to some member the schema declares. The whole
            // record stays legal, so it must still decode.
            for field in &enums {
                match field.domain {
                    Domain::Enum(members) if !members.is_empty() => {
                        let pick = members[rng.below(members.len())];
                        write_field(bytes, field, pick);
                    }
                    // Any subset of the declared bits, the empty one included.
                    Domain::Mask(known) => write_field(bytes, field, rng.step() & known),
                    _ => {}
                }
            }
            (Mutation::LegalValues, "<all enums>")
        }
        1 if !enums.is_empty() => {
            let field = enums[rng.below(enums.len())];
            match illegal_value(field) {
                Some(value) => {
                    write_field(bytes, field, value);
                    (Mutation::IllegalEnum, field.name)
                }
                // Every value of the field's width is a legal member, so there
                // is nothing illegal to write. Reported as a bit flip rather
                // than skipped, because a mutation that did nothing must not
                // be judged against the illegal-enum oracle.
                None => {
                    flip(bytes, rng);
                    (Mutation::FlipBits, field.name)
                }
            }
        }
        2 => {
            let cut = rng.below(bytes.len());
            bytes.truncate(cut);
            (Mutation::Truncated, "<length>")
        }
        _ => {
            flip(bytes, rng);
            (Mutation::FlipBits, "<any>")
        }
    }
}

fn flip(bytes: &mut [u8], rng: &mut Rng) {
    if bytes.is_empty() {
        return;
    }
    let flips = 1 + rng.below(3);
    for _ in 0..flips {
        let at = rng.below(bytes.len());
        let bit = rng.below(8);
        bytes[at] ^= 1 << bit;
    }
}

/// The smallest value of the field's width that the enum does not declare, or
/// `None` when every value of that width is a member.
fn illegal_value(field: &Field) -> Option<u64> {
    let width = match field.size {
        1 => u64::from(u8::MAX),
        2 => u64::from(u16::MAX),
        4 => u64::from(u32::MAX),
        _ => u64::MAX,
    };
    match field.domain {
        Domain::Any => None,
        // Walk up from the highest member; a strict enum in this tree is a
        // small set of small numbers, so the first gap is a step or two away.
        Domain::Enum(members) => {
            let highest = members.iter().copied().max().unwrap_or(0);
            (highest.saturating_add(1)..=width).find(|candidate| !members.contains(candidate))
        }
        // The lowest bit the schema never declared, if the field is wide
        // enough to hold one.
        Domain::Mask(known) => {
            let undeclared = !known & width;
            (undeclared != 0).then(|| 1u64 << undeclared.trailing_zeros())
        }
    }
}

fn write_field(bytes: &mut [u8], field: &Field, value: u64) {
    let end = field.offset + field.size;
    if end > bytes.len() {
        return;
    }
    let le = value.to_le_bytes();
    bytes[field.offset..end].copy_from_slice(&le[..field.size]);
}

/// A stable hash, so each target's stream differs and none of them shares the
/// run's seed directly.
fn fnv(name: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
