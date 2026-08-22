// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: the deviation ledger parses as one table, its numbers are
//! unique and unbroken, every entry says what would close it, and every `D<n>`
//! cited anywhere in the tree resolves to a row.
//!
//! The ledger is cited from source — `tools/checks/src/config.rs` names D199,
//! `tools/ci/arch-lint-baseline.txt` names D183 — so a deviation number is an
//! address into a document, and nothing checked that the document could still
//! be read. It could not: 65 blank lines had ended the table at D33, eight rows
//! had dropped their exit criterion to an unescaped `|`, and one number was
//! serving two entries.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use tessera_checks::{assert_no_violations, ledger, walk};

#[test]
fn the_deviation_ledger_parses_and_every_citation_resolves() {
    let root = walk::source_root();
    assert!(
        root.join(ledger::LEDGER).is_file(),
        "no ledger at {} — gate misconfigured",
        root.join(ledger::LEDGER).display()
    );
    assert_no_violations("ledger", &ledger::check(&root));
}

#[test]
fn the_gate_is_reading_the_whole_ledger() {
    // A gate that parsed one row and stopped would report clean. The count is
    // the discriminator: this is the ledger, not a table that happens to be
    // shaped like one.
    let root = walk::source_root();
    let content = std::fs::read_to_string(root.join(ledger::LEDGER)).expect("ledger");
    let (entries, violations) = ledger::check_table(ledger::LEDGER, &content);
    assert_eq!(violations, Vec::new());
    assert!(
        entries.len() >= 215,
        "only {} entries parsed; the ledger has more than that, so the table is being cut short",
        entries.len()
    );
}
