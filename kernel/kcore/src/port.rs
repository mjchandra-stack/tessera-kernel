// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Ports: async event delivery that cannot lose events or overflow, by
//! construction (docs/kernel/04, "Port Delivery Semantics"):
//!
//! - *"Port storage is preallocated per binding: one slot per bound (source,
//!   signal) pair, allocated at bind time. There is no overflow case."*
//! - *"Events coalesce per slot: multiple edges on the same source and signal
//!   before a drain collapse into one event carrying a pending count."*
//! - *"A drain reads current state, so coalescing never hides state."*
//!
//! This module is the pure event-delivery structure — bindings, coalescing, and
//! draining, with no scheduling. The executive (`exec.rs`) layers blocking a
//! drainer and waking it on a signal on top, exactly as it does for channels.
//! A binding's `source` is an abstract id in v0: the concrete channel-readiness,
//! timeline point-reached, cancellation, and peer-death sources — and the async
//! deadline / expired-flag / drop-policy machinery — are deferred
//! (build/README.md, D38). No event is ever silently dropped here.
//!
//! Normative: docs/kernel/04-synchronization-and-ipc-guarantees.md
//! ("Port Delivery Semantics", "Observability")
//! Budget: none (async delivery; the cross-core signal path is B5, deferred)

use crate::object::ObjectId;
use tessera_karch::KError;

/// Ports the table holds.
pub const MAX_PORTS: usize = 32;
/// Bindings (one per `(source, signal)` pair) a single port holds.
pub const MAX_BINDINGS: usize = 8;

/// A raw port identifier: an index into the port table. Like `EndpointId`, this
/// is a kernel-internal reference; the handle/rights bridge is deferred (D38).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortId(pub usize);

/// One preallocated `(source, signal)` slot. `pending` is the coalesced edge
/// count; `asserted` means at least one undrained edge is waiting.
#[derive(Clone, Copy)]
struct Binding {
    source: u64,
    signal: u8,
    pending: u32,
    asserted: bool,
}

/// A drained event: which `(source, signal)` fired and how many edges coalesced
/// into it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortEvent {
    pub source: u64,
    pub signal: u8,
    pub pending: u32,
}

/// A single port: a fixed set of preallocated bindings, a coalescing counter for
/// observability, and at most one blocked drainer (v0 single-receiver).
pub struct Port {
    bindings: [Option<Binding>; MAX_BINDINGS],
    /// Edges that collapsed onto an already-pending slot (observability:
    /// "port coalescing counts", docs/kernel/04).
    coalesced: u64,
    /// The thread parked in a drain with nothing asserted, if any.
    blocked_drainer: Option<usize>,
    /// The `ObjectType::Port` object id this port is handle-addressable by, if a
    /// handle has been minted for it (the handle→port bridge for ring-3 callers).
    object: Option<ObjectId>,
}

impl Port {
    pub const fn new() -> Self {
        Self {
            bindings: [const { None }; MAX_BINDINGS],
            coalesced: 0,
            blocked_drainer: None,
            object: None,
        }
    }

    /// Binds this port to the object id of its `ObjectType::Port` object.
    pub fn set_object(&mut self, id: ObjectId) {
        self.object = Some(id);
    }

    /// The object id bound to this port, if any.
    pub fn object(&self) -> Option<ObjectId> {
        self.object
    }

    /// Preallocates a slot for `(source, signal)`. One slot per pair: a
    /// duplicate bind is a protocol error, and a full port is [`KError::
    /// OutOfMemory`] — never a silent drop later, since delivery never allocates.
    pub fn bind(&mut self, source: u64, signal: u8) -> Result<(), KError> {
        if self.find(source, signal).is_some() {
            return Err(KError::Protocol);
        }
        let slot = self
            .bindings
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.bindings[slot] = Some(Binding {
            source,
            signal,
            pending: 0,
            asserted: false,
        });
        Ok(())
    }

    /// Delivers `edges` edges to the `(source, signal)` binding, coalescing them
    /// onto any already-pending count. Returns `true` if a binding matched
    /// (an unbound source is a no-op for this port). Counts a coalescing event
    /// whenever edges land on an already-pending slot.
    pub fn deliver(&mut self, source: u64, signal: u8, edges: u32) -> bool {
        let Some(idx) = self.find(source, signal) else {
            return false;
        };
        if let Some(binding) = self.bindings[idx].as_mut() {
            if binding.pending > 0 {
                // Edges collapse onto the pending event (no new slot).
                self.coalesced = self.coalesced.saturating_add(1);
            }
            binding.pending = binding.pending.saturating_add(edges);
            binding.asserted = true;
        }
        true
    }

    /// Drains one asserted binding, returning its coalesced event and resetting
    /// the slot. A drain reads *current* state, so coalescing never hides an
    /// edge. Returns `None` if nothing is asserted.
    pub fn drain(&mut self) -> Option<PortEvent> {
        let idx = self
            .bindings
            .iter()
            .position(|b| matches!(b, Some(x) if x.asserted))?;
        let binding = self.bindings[idx].as_mut()?;
        let event = PortEvent {
            source: binding.source,
            signal: binding.signal,
            pending: binding.pending,
        };
        binding.pending = 0;
        binding.asserted = false;
        Some(event)
    }

    /// The coalescing count (observability).
    pub fn coalesced(&self) -> u64 {
        self.coalesced
    }

    /// Records the thread parked draining this port (nothing asserted).
    pub fn set_blocked_drainer(&mut self, thread: Option<usize>) {
        self.blocked_drainer = thread;
    }

    /// Removes and returns the parked drainer, if any (to wake on a signal).
    pub fn take_blocked_drainer(&mut self) -> Option<usize> {
        self.blocked_drainer.take()
    }

    fn find(&self, source: u64, signal: u8) -> Option<usize> {
        self.bindings
            .iter()
            .position(|b| matches!(b, Some(x) if x.source == source && x.signal == signal))
    }
}

impl Default for Port {
    fn default() -> Self {
        Self::new()
    }
}

/// A fixed pool of ports.
pub struct PortTable {
    ports: [Option<Port>; MAX_PORTS],
}

impl PortTable {
    pub const fn new() -> Self {
        Self {
            ports: [const { None }; MAX_PORTS],
        }
    }

    /// Allocates a port, returning its id, or [`KError::OutOfMemory`] if full.
    pub fn create(&mut self) -> Result<PortId, KError> {
        let index = self
            .ports
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.ports[index] = Some(Port::new());
        Ok(PortId(index))
    }

    pub fn port(&self, id: PortId) -> Option<&Port> {
        self.ports.get(id.0).and_then(Option::as_ref)
    }

    pub fn port_mut(&mut self, id: PortId) -> Option<&mut Port> {
        self.ports.get_mut(id.0).and_then(Option::as_mut)
    }

    /// The port at raw index `i`, for the signal fan-out sweep.
    pub fn port_mut_at(&mut self, i: usize) -> Option<&mut Port> {
        self.ports.get_mut(i).and_then(Option::as_mut)
    }

    /// Binds `port` to the object id of its `ObjectType::Port` object, so a
    /// ring-3 handle resolving to `id` maps back to `port`.
    pub fn set_port_object(&mut self, port: PortId, id: ObjectId) {
        if let Some(port) = self.port_mut(port) {
            port.set_object(id);
        }
    }

    /// Resolves an object id back to its bound port — the handle→port bridge
    /// (a linear scan, the `ProcessTable::process_of_id` pattern).
    pub fn port_of_object(&self, id: ObjectId) -> Option<PortId> {
        for (index, slot) in self.ports.iter().enumerate() {
            if let Some(port) = slot
                && port.object() == Some(id)
            {
                return Some(PortId(index));
            }
        }
        None
    }
}

impl Default for PortTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
}
