// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The boot harness's demo-verdict record, ISL-generated from
//! `api/isl/examples/demo_verdict.isl`. `docs/observability/01` requires that
//! "plain text rendering is generated from structured records": a demo produces a
//! [`DemoVerdict`], and the harness renders its verdict line from that record
//! rather than printing prose directly (build/README.md, D58).
//!
//! This module is only the vocabulary — the record type and its `DemoId`/
//! `Outcome` discriminators, re-exported so the harness never reaches into the
//! private binding module. The renderer and the pass/fail aggregation live in the
//! harness itself (`kernel/kernel/src/main.rs`), because the verdict prose is the
//! harness's, not the kernel core's.
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md
//! ("Structured Logging")
//! Budget: none (boot reporting only)

pub use crate::isl_binding::verdict::{DemoId, DemoVerdict, Outcome};

use tessera_karch::EarlyConsole;

/// The schema version stamped into every verdict record.
pub const VERDICT_SCHEMA_VERSION: u32 = 1;

/// Builds a verdict record with the mandated envelope filled in. `args` are the
/// values the demo's rendered line interpolates, positionally (the renderer knows
/// each demo's arity and types); unused slots stay zero.
pub fn record(demo: DemoId, pass: bool, args: [u64; 8]) -> DemoVerdict {
    DemoVerdict {
        size: DemoVerdict::WIRE_SIZE as u32,
        version: VERDICT_SCHEMA_VERSION,
        flags: 0,
        demo,
        outcome: if pass { Outcome::Pass } else { Outcome::Fail },
        arg0: args[0],
        arg1: args[1],
        arg2: args[2],
        arg3: args[3],
        arg4: args[4],
        arg5: args[5],
        arg6: args[6],
        arg7: args[7],
    }
}

/// The word every asserted-claim line begins with, so a boot check can match
/// one exactly rather than by a phrase out of the verdict's prose.
pub const CLAIM_PREFIX: &str = "claim ";

/// Emits one line per claim key: `claim <group>.<name>`.
///
/// A boot check asserts *properties*, and until now it did so by grepping a
/// sentence out of a verdict line — which made the prose a test contract, so no
/// line could be shortened without breaking a test, and a reworded sentence
/// broke one silently. A key is the same assertion with a name instead of a
/// paragraph: stable under rewording, matched with `grep -F`, and short enough
/// that a line carrying one stays a line.
///
/// One key per line, deliberately. Packing several into one line would put the
/// boot check back to matching a substring of something longer.
pub fn claims(keys: &[&str]) {
    for key in keys {
        crate::kprintln!("{CLAIM_PREFIX}{key}");
    }
}

/// [`claims`] into any console — the unit-testable path, as `console::write_to`
/// is for `kprint!`.
pub fn write_claims(sink: &mut dyn EarlyConsole, keys: &[&str]) {
    for key in keys {
        crate::console::write_to(sink, format_args!("{CLAIM_PREFIX}{key}\n"));
    }
}

#[cfg(test)]
#[path = "tests/verdict.rs"]
mod tests;
