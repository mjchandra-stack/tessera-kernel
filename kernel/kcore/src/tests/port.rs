// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::port`.

use super::*;

const SRC: u64 = 0x5011;
const SIG: u8 = 1;

#[test]
fn port_object_binds_and_resolves() {
    let mut table = PortTable::new();
    let a = table.create().unwrap();
    let b = table.create().unwrap();
    table.set_port_object(a, ObjectId::from_raw(0x11));
    table.set_port_object(b, ObjectId::from_raw(0x22));
    assert_eq!(table.port_of_object(ObjectId::from_raw(0x11)), Some(a));
    assert_eq!(table.port_of_object(ObjectId::from_raw(0x22)), Some(b));
    assert_eq!(table.port_of_object(ObjectId::from_raw(0x99)), None);
}

#[test]
fn edges_before_a_drain_coalesce_into_one_event_with_a_pending_count() {
    let mut port = Port::new();
    port.bind(SRC, SIG).expect("bind");
    // Three edges before any drain collapse into one event.
    assert!(port.deliver(SRC, SIG, 1));
    assert!(port.deliver(SRC, SIG, 1));
    assert!(port.deliver(SRC, SIG, 1));
    assert_eq!(
        port.drain(),
        Some(PortEvent {
            source: SRC,
            signal: SIG,
            pending: 3,
        })
    );
    // Two of the three edges landed on an already-pending slot.
    assert_eq!(port.coalesced(), 2);
    // Drain read current state: nothing is left asserted.
    assert_eq!(port.drain(), None);
}

#[test]
fn a_trailing_edge_after_a_drain_is_not_lost() {
    let mut port = Port::new();
    port.bind(SRC, SIG).expect("bind");
    port.deliver(SRC, SIG, 5);
    assert_eq!(port.drain().map(|e| e.pending), Some(5));
    // A fresh edge after the drain is a new, separate event (not coalesced).
    port.deliver(SRC, SIG, 1);
    assert_eq!(port.drain().map(|e| e.pending), Some(1));
    assert_eq!(port.coalesced(), 0); // no edge ever hit a pending slot
}

#[test]
fn edges_carry_their_count() {
    let mut port = Port::new();
    port.bind(SRC, SIG).expect("bind");
    // A single deliver of several edges is one pending count.
    port.deliver(SRC, SIG, 4);
    assert_eq!(port.drain().map(|e| e.pending), Some(4));
}

#[test]
fn a_signal_to_an_unbound_source_is_a_no_op() {
    let mut port = Port::new();
    port.bind(SRC, SIG).expect("bind");
    assert!(!port.deliver(0xdead, SIG, 1)); // unbound source
    assert!(!port.deliver(SRC, 2, 1)); // bound source, unbound signal
    assert_eq!(port.drain(), None);
}

#[test]
fn distinct_bindings_coalesce_independently() {
    let mut port = Port::new();
    port.bind(SRC, 1).expect("bind sig 1");
    port.bind(SRC, 2).expect("bind sig 2");
    port.deliver(SRC, 1, 2);
    port.deliver(SRC, 2, 3);
    // Each binding drains its own coalesced count (order is slot order).
    let a = port.drain().expect("event a");
    let b = port.drain().expect("event b");
    let mut pendings = [a.pending, b.pending];
    pendings.sort_unstable();
    assert_eq!(pendings, [2, 3]);
    assert_eq!(port.drain(), None);
}

#[test]
fn a_duplicate_bind_is_rejected_and_a_full_port_refuses() {
    let mut port = Port::new();
    port.bind(SRC, SIG).expect("bind");
    // One slot per (source, signal): a second bind of the same pair fails.
    assert_eq!(port.bind(SRC, SIG), Err(KError::Protocol));
    // Fill the remaining slots with distinct signals, then overflow.
    for sig in 1..MAX_BINDINGS as u8 {
        port.bind(SRC, sig + 1).expect("bind distinct");
    }
    assert_eq!(port.bind(SRC, 200), Err(KError::OutOfMemory));
}

/// Unbinding releases the slot, so the pair can be bound again — the
/// difference between a route being gone and a route being quiet. A slot
/// left occupied would refuse the next binding of the same line, which is
/// how a rebound device would find its interrupts unroutable.
#[test]
fn unbind_releases_the_slot_for_a_later_binding() {
    let mut port = Port::new();
    port.bind(SRC, SIG).expect("bind");
    assert!(port.unbind(SRC, SIG));
    // Gone: a second unbind has nothing to release, and a signal on the
    // pair matches nothing.
    assert!(!port.unbind(SRC, SIG));
    assert!(!port.deliver(SRC, SIG, 1));
    // And the slot is free, not merely inert.
    assert!(port.bind(SRC, SIG).is_ok());
}

/// Undrained edges die with the binding, and deliberately: they describe
/// interrupts belonging to a route that no longer exists, and carrying
/// them forward would hand the port's next holder a count from its
/// predecessor's device.
#[test]
fn unbind_discards_what_had_coalesced_onto_the_slot() {
    let mut port = Port::new();
    port.bind(SRC, SIG).expect("bind");
    port.deliver(SRC, SIG, 3);
    assert!(port.unbind(SRC, SIG));
    assert_eq!(port.drain(), None, "nothing asserted survives the unbind");
    // Rebound, the slot starts empty rather than inheriting the three.
    port.bind(SRC, SIG).expect("rebind");
    assert_eq!(port.drain(), None);
    port.deliver(SRC, SIG, 1);
    assert_eq!(port.drain().map(|e| e.pending), Some(1));
}

/// One binding's revocation leaves its neighbours alone. A device giving
/// up its interrupt must not silence another device sharing the port.
#[test]
fn unbinding_one_pair_leaves_the_others_bound() {
    let mut port = Port::new();
    port.bind(SRC, 1).expect("bind 1");
    port.bind(SRC, 2).expect("bind 2");
    assert!(port.unbind(SRC, 1));
    assert!(!port.deliver(SRC, 1, 1));
    assert!(port.deliver(SRC, 2, 1));
    assert_eq!(port.drain().map(|e| e.signal), Some(2));
}

#[test]
fn port_table_allocates_and_resolves() {
    let mut table = PortTable::new();
    let a = table.create().expect("create a");
    let b = table.create().expect("create b");
    assert_ne!(a, b);
    assert!(table.port(a).is_some());
    table.port_mut(b).expect("b").bind(SRC, SIG).expect("bind");
    assert!(table.port(PortId(999)).is_none());
}

#[test]
fn blocked_drainer_is_recorded_and_taken_once() {
    let mut port = Port::new();
    port.set_blocked_drainer(Some(4));
    assert_eq!(port.take_blocked_drainer(), Some(4));
    assert_eq!(port.take_blocked_drainer(), None);
}
