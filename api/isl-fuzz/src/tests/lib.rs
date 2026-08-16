// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;
use tessera_isl_runtime::{Reader, WireError, Writer};

/// A stand-in for a generated frozen struct: a strict enum at offset 0 and
/// a free `u32` after it.
#[derive(Debug, PartialEq)]
struct Pair {
    kind: u32,
    value: u32,
}

const KINDS: &[u64] = &[1, 2, 3];

impl WireEncode for Pair {
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u32(self.kind)?;
        w.write_u32(self.value)
    }
    fn encoded_len(&self) -> usize {
        8
    }
}

impl WireDecode for Pair {
    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let kind = r.read_u32()?;
        if !KINDS.contains(&u64::from(kind)) {
            return Err(WireError::BadEnum);
        }
        let value = r.read_u32()?;
        Ok(Pair { kind, value })
    }
}

const FIELDS: &[Field] = &[
    Field {
        name: "kind",
        offset: 0,
        size: 4,
        domain: Domain::Enum(KINDS),
    },
    Field {
        name: "value",
        offset: 4,
        size: 4,
        domain: Domain::Any,
    },
];

const SEED: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 0];

fn target() -> Target {
    Target {
        name: "Pair",
        wire_size: 8,
        fields: FIELDS,
        seed: SEED,
        probe: probe::<Pair>,
    }
}

#[test]
fn a_correct_decoder_survives_the_oracle() {
    let (coverage, finding) = run(&[target()], 400, 0x5eed);
    assert_eq!(finding, None, "{finding:?}");
    assert_eq!(coverage.targets, 1);
    assert_eq!(coverage.inputs, 401);
    assert!(
        coverage.accepted > 0 && coverage.rejected > 0,
        "a run that only ever accepted, or only ever refused, exercised one \
         half of the decoder: {coverage:?}",
    );
}

/// **The oracle's point.** A decoder that lets an undeclared enum value
/// through is caught, and caught quickly, because the mutator writes one
/// deliberately rather than waiting for random bytes to land on it.
#[test]
fn a_decoder_that_accepts_an_undeclared_enum_value_is_caught() {
    #[derive(Debug, PartialEq)]
    struct Sloppy(Pair);
    impl WireEncode for Sloppy {
        fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.write_u32(self.0.kind)?;
            w.write_u32(self.0.value)
        }
        fn encoded_len(&self) -> usize {
            8
        }
    }
    impl WireDecode for Sloppy {
        fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
            // No domain check — the bug.
            let kind = r.read_u32()?;
            let value = r.read_u32()?;
            Ok(Sloppy(Pair { kind, value }))
        }
    }

    let sloppy = Target {
        probe: probe::<Sloppy>,
        ..target()
    };
    let (_, finding) = run(&[sloppy], 400, 0x5eed);
    let finding = finding.expect("an undeclared value was accepted and nobody noticed");
    assert_eq!(finding.mutation, Mutation::IllegalEnum);
    assert_eq!(finding.field, "kind");
}

/// A decoder that reads past a short buffer, or answers from whatever
/// follows it, is caught by the truncation mutation.
#[test]
fn a_decoder_that_accepts_a_short_buffer_is_caught() {
    #[derive(Debug, PartialEq)]
    struct Greedy(u32);
    impl WireEncode for Greedy {
        fn encode(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
            w.write_u32(self.0)?;
            w.write_u32(0)
        }
        fn encoded_len(&self) -> usize {
            8
        }
    }
    impl WireDecode for Greedy {
        fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
            // Reads one field and does not insist on the rest.
            Ok(Greedy(r.read_u32().unwrap_or(1)))
        }
    }
    let greedy = Target {
        name: "Greedy",
        fields: &[],
        seed: &[1, 0, 0, 0, 0, 0, 0, 0],
        probe: probe::<Greedy>,
        wire_size: 8,
    };
    let (_, finding) = run(&[greedy], 200, 7);
    assert!(finding.is_some(), "a short buffer decoded to something");
}

/// The generator is the run's only input, so a finding reproduces from the
/// seed and nothing else.
#[test]
fn the_same_seed_produces_the_same_run() {
    let first = run(&[target()], 200, 99);
    let second = run(&[target()], 200, 99);
    assert_eq!(first, second);
    let other = run(&[target()], 200, 100);
    assert_ne!(first.0, other.0, "a different seed explores differently");
}

/// A target whose seed does not decode is a target describing a record its
/// own schema refuses, and every mutation from it starts from nonsense.
#[test]
fn a_seed_that_does_not_decode_is_the_first_finding() {
    let broken = Target {
        seed: &[9, 0, 0, 0, 0, 0, 0, 0],
        ..target()
    };
    let (_, finding) = run(&[broken], 10, 1);
    assert_eq!(finding.map(|f| f.field), Some("<seed>"));
}

#[test]
fn the_first_gap_above_the_members_is_the_illegal_value() {
    assert_eq!(illegal_value(&FIELDS[0]), Some(4));
    assert_eq!(illegal_value(&FIELDS[1]), None, "no domain to leave");
}
