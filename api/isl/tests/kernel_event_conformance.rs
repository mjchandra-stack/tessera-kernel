// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated kernel observability-event bindings
//! (built by the codegen genrule from `examples/kernel_event.isl`, never
//! committed). Proves a `KernelEvent` encodes to a fixed golden layout and decodes
//! back — the record the kernel's bounded event ring emits, and the schema a log
//! service will decode (docs/observability/01, "Structured Logging").
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md,
//! docs/api/03-interface-schema-language.md ("Wire Format")

use kernel_event::{Classification, Component, EventKind, KernelEvent, Severity};
use tessera_isl_runtime::{decode, encode};

/// Golden encoding of the `KernelEvent` value below: little-endian, 8-byte
/// aligned, 104 bytes. The four `u32` discriminators pack at offsets 16..32 with
/// no padding; every `u64` is 8-aligned.
const GOLDEN: [u8; 104] = [
    0x68, 0, 0, 0, // size = 104
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x02, 0, 0, 0, // kind = PagerDeadlineMiss (2)
    0x28, 0, 0, 0, // severity = Warning (40)
    0x01, 0, 0, 0, // component = Pager (1)
    0x00, 0, 0, 0, // classification = Public (0)
    0x34, 0x12, 0, 0, 0, 0, 0, 0, // timestamp = 0x1234
    0x07, 0, 0, 0, 0, 0, 0, 0, // thread_id = 7
    0x09, 0, 0, 0, 0, 0, 0, 0, // process_id = 9
    0x11, 0, 0, 0, 0, 0, 0, 0, // correlation_lo = 0x11
    0x22, 0, 0, 0, 0, 0, 0, 0, // correlation_hi = 0x22
    0x64, 0, 0, 0, 0, 0, 0, 0, // arg0 = 100
    0xc8, 0, 0, 0, 0, 0, 0, 0, // arg1 = 200
    0x2c, 0x01, 0, 0, 0, 0, 0, 0, // arg2 = 300
    0x90, 0x01, 0, 0, 0, 0, 0, 0, // arg3 = 400
];

#[test]
fn kernel_event_matches_golden_and_round_trips() {
    assert_eq!(KernelEvent::WIRE_SIZE, 104);
    let value = KernelEvent {
        size: 104,
        version: 1,
        flags: 0,
        kind: EventKind::PagerDeadlineMiss,
        severity: Severity::Warning,
        component: Component::Pager,
        classification: Classification::Public,
        timestamp: 0x1234,
        thread_id: 7,
        process_id: 9,
        correlation_lo: 0x11,
        correlation_hi: 0x22,
        arg0: 100,
        arg1: 200,
        arg2: 300,
        arg3: 400,
    };
    let mut buf = [0u8; 104];
    assert_eq!(encode(&value, &mut buf).unwrap(), 104);
    assert_eq!(buf, GOLDEN);

    let decoded: KernelEvent = decode(&GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn severity_ladder_is_gapped_and_ordered() {
    // The ladder is the project's choice (docs mandate the field, not the levels)
    // and is ABI — gapped by ten so a level can be inserted without renumbering.
    assert_eq!(Severity::Debug as u32, 10);
    assert_eq!(Severity::Info as u32, 20);
    assert_eq!(Severity::Notice as u32, 30);
    assert_eq!(Severity::Warning as u32, 40);
    assert_eq!(Severity::Error as u32, 50);
    assert_eq!(Severity::Critical as u32, 60);
    assert!((Severity::Warning as u32) < (Severity::Error as u32));
}

#[test]
fn event_kind_and_component_ids_are_stable() {
    // Append-only ABI: these values are never renumbered or reused.
    assert_eq!(EventKind::PagerPageIn as u32, 1);
    assert_eq!(EventKind::PagerDeadlineMiss as u32, 2);
    assert_eq!(EventKind::PagerSupervisionEscalate as u32, 3);
    assert_eq!(EventKind::PagerObjectFaulted as u32, 4);
    assert_eq!(EventKind::MemReclaimOverflow as u32, 5);
    assert_eq!(EventKind::EventsDropped as u32, 6);

    assert_eq!(Component::Pager as u32, 1);
    assert_eq!(Component::Memory as u32, 2);
    assert_eq!(Component::Driver as u32, 3);
    assert_eq!(Component::Observability as u32, 6);

    assert_eq!(Classification::Public as u32, 0);
}
