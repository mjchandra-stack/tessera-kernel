// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated demo-verdict bindings (built by the
//! codegen genrule from `examples/demo_verdict.isl`, never committed). Proves a
//! `DemoVerdict` encodes to a fixed golden layout and decodes back — the record
//! each boot demo produces and the harness renders its verdict line from
//! (docs/observability/01: "Plain text rendering is generated from structured
//! records").
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md,
//! docs/api/03-interface-schema-language.md ("Wire Format")

use demo_verdict::{DemoId, DemoVerdict, Outcome};
use tessera_isl_runtime::{decode, encode};

/// Golden encoding of the `DemoVerdict` value below: little-endian, 8-byte
/// aligned, 88 bytes. `demo`/`outcome` pack at offsets 16..24; the eight payload
/// slots are 8-aligned from offset 24.
const GOLDEN: [u8; 88] = [
    0x58, 0, 0, 0, // size = 88
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x02, 0, 0, 0, // demo = ComponentManager (2)
    0x01, 0, 0, 0, // outcome = Pass (1)
    0x04, 0, 0, 0, 0, 0, 0, 0, // arg0 = 4 (launches)
    0x04, 0, 0, 0, 0, 0, 0, 0, // arg1 = 4 (runs)
    0x06, 0, 0, 0, 0, 0, 0, 0, // arg2 = 6 (exit_sum)
    0, 0, 0, 0, 0, 0, 0, 0, // arg3 = 0 (last_exit)
    0, 0, 0, 0, 0, 0, 0, 0, // arg4
    0, 0, 0, 0, 0, 0, 0, 0, // arg5
    0, 0, 0, 0, 0, 0, 0, 0, // arg6
    0, 0, 0, 0, 0, 0, 0, 0, // arg7
];

#[test]
fn demo_verdict_matches_golden_and_round_trips() {
    assert_eq!(DemoVerdict::WIRE_SIZE, 88);
    let value = DemoVerdict {
        size: 88,
        version: 1,
        flags: 0,
        demo: DemoId::ComponentManager,
        outcome: Outcome::Pass,
        arg0: 4,
        arg1: 4,
        arg2: 6,
        arg3: 0,
        arg4: 0,
        arg5: 0,
        arg6: 0,
        arg7: 0,
    };
    let mut buf = [0u8; 88];
    assert_eq!(encode(&value, &mut buf).unwrap(), 88);
    assert_eq!(buf, GOLDEN);

    let decoded: DemoVerdict = decode(&GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn demo_ids_and_outcomes_are_stable() {
    // Append-only ABI: a recorded verdict must stay interpretable, so these
    // values are never renumbered or reused.
    assert_eq!(Outcome::Pass as u32, 1);
    assert_eq!(Outcome::Fail as u32, 2);

    assert_eq!(DemoId::Loader as u32, 1);
    assert_eq!(DemoId::ComponentManager as u32, 2);
    assert_eq!(DemoId::DriverCrash as u32, 5);
    assert_eq!(DemoId::ChannelIpc as u32, 8);
    assert_eq!(DemoId::DeviceManager as u32, 15);
    assert_eq!(DemoId::Jobs as u32, 20);
    assert_eq!(DemoId::PagerDirtyFlood as u32, 21);
    assert_eq!(DemoId::PagerDeadlineSupervision as u32, 27);
    assert_eq!(DemoId::ObservabilityEvents as u32, 28);
}
