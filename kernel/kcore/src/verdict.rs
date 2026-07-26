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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_and_outcome_are_filled_in() {
        let pass = record(DemoId::Loader, true, [1, 2, 3, 4, 0, 0, 0, 0]);
        assert_eq!(pass.size, DemoVerdict::WIRE_SIZE as u32);
        assert_eq!(pass.version, VERDICT_SCHEMA_VERSION);
        assert_eq!(pass.demo, DemoId::Loader);
        assert_eq!(pass.outcome, Outcome::Pass);
        assert_eq!((pass.arg0, pass.arg3, pass.arg7), (1, 4, 0));

        let fail = record(DemoId::ObservabilityEvents, false, [0; 8]);
        assert_eq!(fail.outcome, Outcome::Fail);
    }
}
