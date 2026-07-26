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
pub const MAX_INLINE_BYTES: usize = 256;
/// Maximum handles transferred per message (matches the B4 ≤ 4 handles case).
pub const MAX_MSG_HANDLES: usize = 4;
/// Messages a single endpoint may queue.
pub const QUEUE_CAP: usize = 8;
/// Channels the table holds.
pub const MAX_CHANNELS: usize = 64;

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
    pub fn from_wire(wire: &WireMessageHeader) -> Self {
        Self {
            interface_id: wire.interface_id,
            method_id: wire.method_id,
            flags: wire.flags as u32,
            txn_id: wire.txn_id,
            correlation: wire.correlation_lo,
        }
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
mod tests {
    use super::*;

    fn msg(method: u32, body: &[u8]) -> Message {
        let mut m = Message::new(MessageHeader::new(0xabcd, method));
        m.set_inline(body).unwrap();
        m
    }

    #[test]
    fn queue_is_fifo_and_bounded() {
        let mut ep = Endpoint::new();
        for i in 0..QUEUE_CAP {
            assert!(ep.enqueue(msg(i as u32, &[i as u8])).is_ok());
        }
        // Full.
        assert_eq!(ep.enqueue(msg(99, &[])), Err(KError::WouldBlock));
        // FIFO order out.
        for i in 0..QUEUE_CAP {
            let m = ep.dequeue().unwrap();
            assert_eq!(m.header().method_id, i as u32);
            assert_eq!(m.inline(), &[i as u8]);
        }
        assert!(ep.dequeue().is_none());
    }

    #[test]
    fn message_header_round_trips_through_the_generated_binding() {
        use tessera_isl_runtime::{decode, encode};

        // A header with non-trivial values in every semantic field.
        let header = MessageHeader {
            interface_id: 0x1122_3344_5566_7788,
            method_id: 0x9abc_def0,
            flags: 0x0000_0005,
            txn_id: 0x00fe_dcba_9876_5432,
            correlation: 0x0123_4567_89ab_cdef,
        };

        // In-kernel -> wire -> bytes -> wire -> in-kernel, through the ISL binding.
        let wire = header.to_wire();
        let mut buf = [0u8; WireMessageHeader::WIRE_SIZE];
        let n = encode(&wire, &mut buf).expect("encode");
        assert_eq!(n, WireMessageHeader::WIRE_SIZE);
        let decoded: WireMessageHeader = decode(&buf).expect("decode");
        let back = MessageHeader::from_wire(&decoded);

        // The semantic fields survive the full round trip — the in-kernel header is
        // a faithful subset of the ISL wire form (schema = source of truth). This
        // is what closes "shaped to by convention" for the message header.
        assert_eq!(back, header);
        // And the envelope carries exactly what the schema mandates.
        assert_eq!(wire.size, WireMessageHeader::WIRE_SIZE as u32);
        assert_eq!(wire.version, MESSAGE_HEADER_WIRE_VERSION);
        // The causal id crosses as 128 bits: the sequence from the header, the
        // epoch supplied by the trace facility (D60).
        assert_eq!(wire.correlation_lo, header.correlation);
        assert_eq!(wire.correlation_hi, crate::trace::epoch());
    }

    #[test]
    fn a_stamped_correlation_rides_the_header() {
        let mut m = Message::new(MessageHeader::new(0x1, 1));
        // Unstamped means "no cause recorded", never a forged one.
        assert_eq!(m.header().correlation, 0);
        m.set_correlation(0xfeed);
        assert_eq!(m.header().correlation, 0xfeed);
        // And it survives the wire, which is the point of carrying it here.
        assert_eq!(m.header().to_wire().correlation_lo, 0xfeed);
    }

    #[test]
    fn oversize_payload_and_handle_set_are_rejected() {
        let mut m = Message::new(MessageHeader::new(1, 1));
        assert_eq!(
            m.set_inline(&[0u8; MAX_INLINE_BYTES + 1]),
            Err(KError::Protocol)
        );
        assert!(m.set_inline(&[0u8; MAX_INLINE_BYTES]).is_ok());

        let h = TransferredHandle {
            object: ObjectId::from_raw(1),
            rights: Rights::READ,
        };
        for _ in 0..MAX_MSG_HANDLES {
            assert!(m.add_handle(h).is_ok());
        }
        assert_eq!(m.add_handle(h), Err(KError::Protocol));
        assert_eq!(m.handle_count(), MAX_MSG_HANDLES);
    }

    #[test]
    fn create_channel_and_peer_sides() {
        let mut table = ChannelTable::new();
        let (a, b) = table.create().unwrap();
        assert_eq!(a.channel, b.channel);
        assert_eq!(a.side, 0);
        assert_eq!(b.side, 1);
        assert_eq!(Channel::peer(a.side), b.side);
    }

    #[test]
    fn close_raises_peer_closed_on_the_other_end() {
        let mut ch = Channel::new();
        ch.close_side(0);
        assert!(ch.endpoint(1).peer_closed());
        assert!(!ch.endpoint(0).peer_closed());
    }

    #[test]
    fn endpoint_object_binds_and_resolves_both_sides() {
        let mut table = ChannelTable::new();
        let (a, b) = table.create().unwrap();
        let oa = ObjectId::from_raw(0x11);
        let ob = ObjectId::from_raw(0x22);
        table.set_endpoint_object(a, oa);
        table.set_endpoint_object(b, ob);
        assert_eq!(table.endpoint_of_object(oa), Some(a));
        assert_eq!(table.endpoint_of_object(ob), Some(b));
    }

    #[test]
    fn endpoint_of_unknown_object_is_none() {
        let mut table = ChannelTable::new();
        let (a, _b) = table.create().unwrap();
        table.set_endpoint_object(a, ObjectId::from_raw(0x11));
        assert_eq!(table.endpoint_of_object(ObjectId::from_raw(0x99)), None);
    }

    #[test]
    fn freeing_a_channel_slot_clears_the_association() {
        let mut table = ChannelTable::new();
        let (a, _b) = table.create().unwrap();
        let oa = ObjectId::from_raw(0x11);
        table.set_endpoint_object(a, oa);
        assert_eq!(table.endpoint_of_object(oa), Some(a));
        // Freeing the slot (as channel teardown would) drops the binding with it.
        table.channels[a.channel] = None;
        assert_eq!(table.endpoint_of_object(oa), None);
    }
}
