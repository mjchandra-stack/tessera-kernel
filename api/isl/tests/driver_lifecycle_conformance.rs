// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Conformance test for the ISL-generated driver-lifecycle bindings (built by
//! the codegen genrule from `examples/driver_lifecycle.isl`, never committed).
//!
//! Two things are pinned here. The **wire layout** of the transition argument
//! struct and the notice, because a kernel and a ring-3 manager decode them
//! from opposite sides of a syscall boundary. And the **state and reason
//! values**, because those are what a log service reads a recorded lifecycle
//! by: renumbering one would not fail to compile anywhere, it would silently
//! turn every stored record into a different history.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Lifecycle"),
//! docs/api/03-interface-schema-language.md ("Wire Format")

use driver_lifecycle::{DriverState, LifecycleTransitionArgs, ServiceNotice, TransitionReason};
use tessera_isl_runtime::{HandleRef, decode, encode};

/// Golden encoding of the `LifecycleTransitionArgs` value below: 32 bytes, LE.
/// The handle and the three `u32` discriminators pack at 16..32 with no
/// padding, and `detail` is 8-aligned at 32.
const TRANSITION_GOLDEN: [u8; 40] = [
    0x28, 0, 0, 0, // size = 40
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x07, 0, 0, 0, // device = handle 7
    0x05, 0, 0, 0, // from = Active (5)
    0x0a, 0, 0, 0, // to = Degraded (10)
    0x06, 0, 0, 0, // reason = DriverCrashed (6)
    0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0, // detail = 0xdeadbeef
];

#[test]
fn transition_args_match_golden_and_round_trip() {
    assert_eq!(LifecycleTransitionArgs::WIRE_SIZE, 40);
    let value = LifecycleTransitionArgs {
        size: 40,
        version: 1,
        flags: 0,
        device: HandleRef::new(7),
        from: DriverState::Active,
        to: DriverState::Degraded,
        reason: TransitionReason::DriverCrashed,
        detail: 0xdead_beef,
    };
    let mut buf = [0u8; 40];
    assert_eq!(encode(&value, &mut buf).unwrap(), 40);
    assert_eq!(buf, TRANSITION_GOLDEN);

    let decoded: LifecycleTransitionArgs = decode(&TRANSITION_GOLDEN).unwrap();
    assert_eq!(decoded, value);
}

/// Golden encoding of the notice a dependent service receives.
const NOTICE_GOLDEN: [u8; 32] = [
    0x20, 0, 0, 0, // size = 32
    0x01, 0, 0, 0, // version = 1
    0, 0, 0, 0, 0, 0, 0, 0, // flags = 0
    0x1a, 0, 0, 0, // device = 26
    0x0a, 0, 0, 0, // state = Degraded (10)
    0x06, 0, 0, 0, // reason = DriverCrashed (6)
    0, 0, 0, 0, // reserved
];

#[test]
fn service_notice_matches_golden_and_round_trips() {
    assert_eq!(ServiceNotice::WIRE_SIZE, 32);
    let value = ServiceNotice {
        size: 32,
        version: 1,
        flags: 0,
        device: 26,
        state: DriverState::Degraded,
        reason: TransitionReason::DriverCrashed,
        reserved: 0,
    };
    let mut buf = [0u8; 32];
    assert_eq!(encode(&value, &mut buf).unwrap(), 32);
    assert_eq!(buf, NOTICE_GOLDEN);
    assert_eq!(decode::<ServiceNotice>(&NOTICE_GOLDEN).unwrap(), value);
}

/// The thirteen states `docs/drivers/01` lists, at the values a stored record
/// is read by. Append-only ABI: never renumbered, never reused.
#[test]
fn the_thirteen_states_have_stable_ids() {
    assert_eq!(DriverState::Discovered as u32, 1);
    assert_eq!(DriverState::Matched as u32, 2);
    assert_eq!(DriverState::Starting as u32, 3);
    assert_eq!(DriverState::Probing as u32, 4);
    assert_eq!(DriverState::Active as u32, 5);
    assert_eq!(DriverState::Suspending as u32, 6);
    assert_eq!(DriverState::Suspended as u32, 7);
    assert_eq!(DriverState::Resuming as u32, 8);
    assert_eq!(DriverState::Resetting as u32, 9);
    assert_eq!(DriverState::Degraded as u32, 10);
    assert_eq!(DriverState::Stopping as u32, 11);
    assert_eq!(DriverState::Removed as u32, 12);
    assert_eq!(DriverState::Failed as u32, 13);
}

/// Zero is deliberately not a state: it stays available as "no state
/// recorded", so an uninitialised record is distinguishable from a device that
/// was genuinely just discovered.
#[test]
fn zero_is_not_a_state() {
    assert!(
        decode::<ServiceNotice>(&{
            let mut bad = NOTICE_GOLDEN;
            bad[20] = 0; // state = 0
            bad
        })
        .is_err()
    );
}

/// A reason value nothing in the enum names is rejected rather than decoded to
/// whichever variant happens to sit nearby.
#[test]
fn an_unknown_reason_is_refused() {
    let mut bad = NOTICE_GOLDEN;
    bad[24] = 0xfe;
    assert!(decode::<ServiceNotice>(&bad).is_err());
}

#[test]
fn transition_reason_ids_are_stable() {
    assert_eq!(TransitionReason::Unspecified as u32, 0);
    assert_eq!(TransitionReason::Enumerated as u32, 1);
    assert_eq!(TransitionReason::DriverCrashed as u32, 6);
    assert_eq!(TransitionReason::BudgetExhausted as u32, 10);
    assert_eq!(TransitionReason::Quarantined as u32, 11);
    assert_eq!(TransitionReason::FallbackSelected as u32, 13);
    assert_eq!(TransitionReason::Power as u32, 15);
}
