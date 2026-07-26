// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated port event record (built by the
//! codegen genrule from `examples/port_event.isl`, never committed). Proves
//! `PortEventRecord` encodes to a fixed golden layout and decodes back — the
//! kernel writes this struct into a waiter's buffer, so its wire stability is
//! what lets a ring-3 service tell WHICH of its bound sources fired (D85).
//!
//! Normative: docs/api/03-interface-schema-language.md ("Wire Format"),
//! docs/api/01-system-call-interface.md

use port_event::PortEventRecord;
use tessera_isl_runtime::{WireError, decode, encode};

/// Golden encoding of the `PortEventRecord` value below: 32 bytes, LE, no
/// implicit padding (the `signal`/`pending` u32 pair fills the 8-byte slot
/// after `source`). The source is a plausible endpoint object id and the
/// pending count is non-trivial, so the golden covers real values.
const EVENT_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x32, 0, 0, 0, 0, 0, 0, 0, // source = 50 (a server endpoint object)
    0x02, 0, 0, 0, // signal = 2 (SIGNAL_MESSAGE)
    0x03, 0, 0, 0, // pending = 3 coalesced arrivals
];

#[test]
fn port_event_record_matches_golden_and_round_trips() {
    assert_eq!(PortEventRecord::WIRE_SIZE, 32);
    let value = PortEventRecord {
        size: 32,
        version: 1,
        flags: 0,
        source: 50,
        signal: 2,
        pending: 3,
    };
    let mut buf = [0u8; 32];
    assert_eq!(encode(&value, &mut buf).unwrap(), 32);
    assert_eq!(buf, EVENT_GOLDEN);
    assert_eq!(decode::<PortEventRecord>(&EVENT_GOLDEN).unwrap(), value);
}

#[test]
fn a_truncated_buffer_is_rejected() {
    assert_eq!(
        decode::<PortEventRecord>(&EVENT_GOLDEN[..24]),
        Err(WireError::ShortBuffer)
    );
}
