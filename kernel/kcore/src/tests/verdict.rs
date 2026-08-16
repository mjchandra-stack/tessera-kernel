// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::verdict`.

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

/// The exact bytes a boot check greps for. If this changes, every script
/// asserting a claim stops matching, so the format is pinned here rather
/// than left to whatever the emitter happens to write.
#[test]
fn a_claim_is_one_prefixed_key_per_line() {
    let mut console = tessera_karch_mock::MockConsole::new();
    write_claims(&mut console, &["store.ok", "store.refused"]);
    assert_eq!(console.text(), "claim store.ok\nclaim store.refused\n");
}

#[test]
fn no_claims_writes_nothing() {
    let mut console = tessera_karch_mock::MockConsole::new();
    write_claims(&mut console, &[]);
    assert_eq!(console.text(), "");
}
