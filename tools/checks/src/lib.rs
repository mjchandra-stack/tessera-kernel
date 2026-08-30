// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 static gates: SPDX header check, third-party license check, the
//! unsafe-code inventory gate, the mandatory fuzz-target gate, the
//! package-coverage gate that keeps the other four looking at the whole tree,
//! the codegen-flag gate that holds the two build systems to one answer, the
//! log-line length gate, the test-double gate, the deviation-ledger gate that
//! keeps a cited deviation number an address rather than a hope, and the
//! interface-surface gate that keeps the system call surface from drifting
//! away from the schema that describes it, and the boundary gate that holds a
//! user program's only path to the kernel to the ABI, and the ABI gate that
//! holds the published surface to the schemas it was generated from.
//! Runs both under Bazel (`rust_test` over a source filegroup) and cargo.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0"),
//! docs/lifecycle/04-coding-guidelines.md
//! Budget: none (build-time tooling)

pub mod abi;
pub mod boundary;
pub mod config;
pub mod doubles;
pub mod flags;
pub mod fuzz_gate;
pub mod inventory;
pub mod ledger;
pub mod license;
pub mod logging;
pub mod packages;
pub mod scan;
pub mod spdx;
pub mod surface;
pub mod walk;

/// A gate violation: repo-relative path plus a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub reason: String,
}

impl core::fmt::Display for Violation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

/// Fails the calling test with a readable report if any violations exist.
pub fn assert_no_violations(gate: &str, violations: &[Violation]) {
    if violations.is_empty() {
        return;
    }
    let mut report = format!("{gate}: {} violation(s)\n", violations.len());
    for v in violations {
        report.push_str("  ");
        report.push_str(&v.to_string());
        report.push('\n');
    }
    panic!("{report}");
}
