// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Channel transport: the message and queue data structures, with no
//! scheduling. A channel is two paired endpoints; each endpoint owns a bounded
//! FIFO receive queue. A message carries a header, a bounded inline byte
//! payload, and a *separate* set of transferred handles — handle values never
//! live in the payload bytes (docs/api/03-interface-schema-language.md, "Wire
//! Format"), so transfer stays atomic and future ISL codegen fits.
//!
//! Bounds are enforced, never truncated (docs/kernel/04): an oversize payload
//! or too many handles is a protocol error at construction; a full queue yields
//! `WouldBlock`. The executive (`exec.rs`) layers blocking, handoff, and the
//! transaction/wait bookkeeping on top of these pure structures.
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Channels"),
//! docs/kernel/04-synchronization-and-ipc-guarantees.md
//! Budget: B3 (round-trip), B4 (per transferred handle) — the transport this
//! sits under; unmeasured until the perf rig lands (build/README.md, D20)

use crate::isl_binding::channel::MessageHeader as WireMessageHeader;
use crate::object::ObjectId;
use crate::rights::Rights;
use tessera_karch::KError;

/// Maximum inline payload bytes (matches the B3 ≤ 256 B call size).
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_INLINE_BYTES;

/// Maximum handles transferred per message (matches the B4 ≤ 4 handles case).
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_MSG_HANDLES;

/// Messages a single endpoint may queue.
pub const QUEUE_CAP: usize = 8;
/// Channels the table holds.
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_CHANNELS;

/// The port signal a message arrival raises on the destination endpoint's
/// object (D85). A server binds a port to `(endpoint_object, SIGNAL_MESSAGE)`
/// per client endpoint; the drained event then names which endpoint has work
/// — a select across per-client channels.
pub const SIGNAL_MESSAGE: u8 = 2;

/// The wire-format version stamped into the ISL `MessageHeader` envelope.
/// Version 2 added the 128-bit correlation id (D60); the generated decoder is
/// canonical (it consumes exactly `WIRE_SIZE` bytes), so a version-1 producer is
/// already rejected on size — the bump makes that rejection self-describing.
pub const MESSAGE_HEADER_WIRE_VERSION: u32 = 2;

/// The channel message header — the semantic fields every message carries
/// (docs/kernel/02, "Channels"). This is the **in-memory subset** of the ISL wire
/// header `channel_msg.MessageHeader` (`api/isl/examples/channel_msg.isl`, the
/// wire-layout source of truth): the schema adds a `size`/`version` envelope and a
/// wider `flags` that only matter when a header crosses a byte boundary.
/// [`to_wire`](Self::to_wire) / [`from_wire`](Self::from_wire) convert between the
/// two through the ISL-generated binding, and the
/// `message_header_round_trips_through_the_generated_binding` test machine-checks
/// that the in-memory fields agree with the wire form (no more "by convention").
///
/// `correlation` is the *sequence* half of the mandated 128-bit causal id; the
/// other half is the per-boot epoch, which is global and constant, so `to_wire`
/// fills it from [`crate::trace::epoch`] rather than storing a boot constant in
/// every queued message. This is the same split [`crate::event::record`] uses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MessageHeader {
    pub interface_id: u64,
    pub method_id: u32,
    pub flags: u32,
    pub txn_id: u64,
    /// The cause this message belongs to, stamped by the kernel from the sending
    /// thread's ambient context — never supplied by a sender, so a ring-3 process
    /// cannot forge a cause. 0 means "no cause recorded".
    pub correlation: u64,
}

impl MessageHeader {
    pub const fn new(interface_id: u64, method_id: u32) -> Self {
        Self {
            interface_id,
            method_id,
            flags: 0,
            txn_id: 0,
            // Stamped by the executive on send/call, like `txn_id`. This stays a
            // literal so `new` remains `const`.
            correlation: 0,
        }
    }

    /// The wire form of this header — the ISL-generated `channel_msg.MessageHeader`
    /// (the schema is the wire-layout source of truth). Adds the `size`/`version`
    /// envelope the in-memory subset omits. Used when a channel header crosses a
    /// byte boundary (`WireEncode`).
    pub fn to_wire(&self) -> WireMessageHeader {
        WireMessageHeader {
            size: WireMessageHeader::WIRE_SIZE as u32,
            version: MESSAGE_HEADER_WIRE_VERSION,
            flags: u64::from(self.flags),
            interface_id: self.interface_id,
            txn_id: self.txn_id,
            method_id: self.method_id,
            correlation_lo: self.correlation,
            correlation_hi: crate::trace::epoch(),
        }
    }

    /// Rebuilds the in-memory header from its wire form (`WireDecode`), dropping the
    /// `size`/`version` envelope. The caller validates the envelope as needed.
    ///
    /// `correlation_hi` (the epoch) is dropped the same way: within a boot it is
    /// constant, so the sequence alone identifies the cause. A header from a
    /// *different* boot would therefore lose the distinction — irrelevant while a
    /// message cannot outlive the kernel that queued it (D60).
    /// `flags` is the one field the wire form carries wider than the in-memory
    /// one does, so it is the one that can fail: a header setting a flag bit
    /// above 32 is **rejected** rather than narrowed. Dropping those bits would
    /// hand the rest of the kernel a header whose flags say something the
    /// sender did not (docs/lifecycle/04, "No Silent Fallback").
    pub fn from_wire(wire: &WireMessageHeader) -> Result<Self, KError> {
        Ok(Self {
            interface_id: wire.interface_id,
            method_id: wire.method_id,
            flags: u32::try_from(wire.flags).map_err(|_| KError::Protocol)?,
            txn_id: wire.txn_id,
            correlation: wire.correlation_lo,
        })
    }
}

/// A handle in flight: the object reference conserved from the sender's handle
/// table, plus its rights. The in-flight message owns the reference, keeping the
/// object alive between send and receive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TransferredHandle {
    pub object: ObjectId,
    pub rights: Rights,
}

/// A channel message: header, bounded inline payload, and a separate set of
/// transferred handles.
pub struct Message {
    header: MessageHeader,
    inline: [u8; MAX_INLINE_BYTES],
    inline_len: usize,
    handles: [Option<TransferredHandle>; MAX_MSG_HANDLES],
    handle_count: usize,
}

impl Message {
    pub fn new(header: MessageHeader) -> Self {
        Self {
            header,
            inline: [0; MAX_INLINE_BYTES],
            inline_len: 0,
            handles: [None; MAX_MSG_HANDLES],
            handle_count: 0,
        }
    }

    pub fn header(&self) -> MessageHeader {
        self.header
    }

    /// Stamps the transaction id (the executive assigns it on a call).
    pub fn set_txn(&mut self, txn_id: u64) {
        self.header.txn_id = txn_id;
    }

    /// Stamps the causal id (the executive assigns it from the sending thread on
    /// send/call, so causality survives the message boundary — D60).
    pub fn set_correlation(&mut self, correlation: u64) {
        self.header.correlation = correlation;
    }

    /// Sets the inline payload, rejecting an oversize one with a protocol error.
    pub fn set_inline(&mut self, bytes: &[u8]) -> Result<(), KError> {
        if bytes.len() > MAX_INLINE_BYTES {
            return Err(KError::Protocol);
        }
        self.inline[..bytes.len()].copy_from_slice(bytes);
        self.inline_len = bytes.len();
        Ok(())
    }

    pub fn inline(&self) -> &[u8] {
        &self.inline[..self.inline_len]
    }

    /// Attaches a transferred handle, rejecting more than the per-message limit.
    pub fn add_handle(&mut self, handle: TransferredHandle) -> Result<(), KError> {
        if self.handle_count >= MAX_MSG_HANDLES {
            return Err(KError::Protocol);
        }
        self.handles[self.handle_count] = Some(handle);
        self.handle_count += 1;
        Ok(())
    }

    pub fn handle_count(&self) -> usize {
        self.handle_count
    }

    /// The transferred handles, in attachment order.
    pub fn handles(&self) -> impl Iterator<Item = TransferredHandle> + '_ {
        self.handles.iter().flatten().copied()
    }
}

/// One end of a channel: a bounded FIFO receive queue plus the wait bookkeeping
/// the executive maintains (which thread, if any, is blocked receiving here or
/// blocked in a call awaiting a reply) and the peer-closed flag.
pub struct Endpoint {
    queue: [Option<Message>; QUEUE_CAP],
    head: usize,
    len: usize,
    peer_closed: bool,
    /// Thread index blocked in `receive` on this endpoint (executive-managed).
    blocked_receiver: Option<usize>,
    /// `(thread index, txn)` of a caller blocked in a call awaiting the reply
    /// that will arrive on this endpoint (executive-managed).
    pending_caller: Option<(usize, u64)>,
}

impl Endpoint {
    const fn new() -> Self {
        Self {
            queue: [const { None }; QUEUE_CAP],
            head: 0,
            len: 0,
            peer_closed: false,
            blocked_receiver: None,
            pending_caller: None,
        }
    }

    /// Appends a message to the FIFO queue, or `WouldBlock` if it is full.
    pub fn enqueue(&mut self, message: Message) -> Result<(), KError> {
        if self.len >= QUEUE_CAP {
            return Err(KError::WouldBlock);
        }
        let tail = (self.head + self.len) % QUEUE_CAP;
        self.queue[tail] = Some(message);
        self.len += 1;
        Ok(())
    }

    /// Removes the front message, or `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<Message> {
        if self.len == 0 {
            return None;
        }
        let message = self.queue[self.head].take();
        self.head = (self.head + 1) % QUEUE_CAP;
        self.len -= 1;
        message
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn queued(&self) -> usize {
        self.len
    }

    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    fn mark_peer_closed(&mut self) {
        self.peer_closed = true;
    }

    pub fn blocked_receiver(&self) -> Option<usize> {
        self.blocked_receiver
    }

    pub fn set_blocked_receiver(&mut self, thread: Option<usize>) {
        self.blocked_receiver = thread;
    }

    pub fn pending_caller(&self) -> Option<(usize, u64)> {
        self.pending_caller
    }

    pub fn set_pending_caller(&mut self, caller: Option<(usize, u64)>) {
        self.pending_caller = caller;
    }
}

/// A channel: two paired endpoints. A send on side `s` enqueues on the peer
/// (side `1 - s`); a receive on side `s` drains side `s`'s own queue.
///
/// Each side optionally records the `ObjectId` of the `ObjectType::Channel`
/// object minted for it, so a ring-3 handle can be resolved back to an
/// [`EndpointId`] (the handle→endpoint bridge, mirroring the handle→process
/// bridge in `process.rs`). The association is owned by the channel slot, so
/// freeing the channel frees it — no separate table to keep in sync.
pub struct Channel {
    ends: [Endpoint; 2],
    objects: [Option<ObjectId>; 2],
}

impl Channel {
    const fn new() -> Self {
        Self {
            ends: [Endpoint::new(), Endpoint::new()],
            objects: [None, None],
        }
    }

    pub fn endpoint(&self, side: usize) -> &Endpoint {
        &self.ends[side]
    }

    pub fn endpoint_mut(&mut self, side: usize) -> &mut Endpoint {
        &mut self.ends[side]
    }

    /// Binds side `side` to the object id of its `ObjectType::Channel` object.
    pub fn set_object(&mut self, side: usize, id: ObjectId) {
        self.objects[side] = Some(id);
    }

    /// The object id bound to side `side`, if any.
    pub fn object(&self, side: usize) -> Option<ObjectId> {
        self.objects[side]
    }

    /// The peer side of `side`.
    pub const fn peer(side: usize) -> usize {
        1 - side
    }

    /// Closes `side`, raising peer-closed on the other end (already-queued
    /// messages there remain drainable first).
    pub fn close_side(&mut self, side: usize) {
        self.ends[Self::peer(side)].mark_peer_closed();
    }
}

/// Identifies one endpoint: a channel index and a side (0 or 1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EndpointId {
    pub channel: usize,
    pub side: usize,
}

/// A fixed pool of channels.
pub struct ChannelTable {
    channels: [Option<Channel>; MAX_CHANNELS],
}

impl ChannelTable {
    pub const fn new() -> Self {
        Self {
            channels: [const { None }; MAX_CHANNELS],
        }
    }

    /// Creates a channel, returning the ids of its two endpoints.
    pub fn create(&mut self) -> Result<(EndpointId, EndpointId), KError> {
        let index = self
            .channels
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.channels[index] = Some(Channel::new());
        Ok((
            EndpointId {
                channel: index,
                side: 0,
            },
            EndpointId {
                channel: index,
                side: 1,
            },
        ))
    }

    pub fn channel_mut(&mut self, index: usize) -> Option<&mut Channel> {
        self.channels.get_mut(index).and_then(Option::as_mut)
    }

    pub fn channel(&self, index: usize) -> Option<&Channel> {
        self.channels.get(index).and_then(Option::as_ref)
    }

    /// Binds `endpoint` to the object id of its `ObjectType::Channel` object,
    /// so a ring-3 handle resolving to `id` can be mapped back to `endpoint`.
    pub fn set_endpoint_object(&mut self, endpoint: EndpointId, id: ObjectId) {
        if let Some(channel) = self.channel_mut(endpoint.channel) {
            channel.set_object(endpoint.side, id);
        }
    }

    /// Resolves an object id back to its bound endpoint, if any — the
    /// handle→endpoint bridge (a linear scan over channels × 2 sides, the same
    /// shape as `ProcessTable::process_of_id`). A ring-3 syscall looks the
    /// endpoint handle up in the caller's table to get the `ObjectId`, then
    /// finds the live `EndpointId` here.
    pub fn endpoint_of_object(&self, id: ObjectId) -> Option<EndpointId> {
        for (channel, slot) in self.channels.iter().enumerate() {
            let Some(chan) = slot else { continue };
            for side in 0..2 {
                if chan.object(side) == Some(id) {
                    return Some(EndpointId { channel, side });
                }
            }
        }
        None
    }
}

impl Default for ChannelTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/ipc.rs"]
mod tests;
