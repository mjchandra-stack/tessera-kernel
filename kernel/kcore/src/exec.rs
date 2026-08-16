// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel executive: the single owner of the run-time state a channel
//! operation touches — the `Scheduler` and the `ChannelTable`. It lives behind
//! a `static` and is re-borrowed per operation, because a context switch
//! suspends a thread mid-call and a Rust `&mut` cannot span a switch. This is
//! the same single-core-justified pattern the scheduler already uses; the
//! compiler fences in `Scheduler::switch_to` keep reads after a handoff honest.
//!
//! The load-bearing operation is `call`: it sends a request and hands off
//! *directly* to a waiting callee, then the reply hands off directly back —
//! two context switches per round trip, no run-queue traffic. That is the
//! mechanism budget B3 depends on (docs/architecture/03; the two-switch check
//! is docs/prototypes/01). Synchronous call chains are depth-limited (default
//! 8, docs/kernel/04). The caller's priority is carried to the callee for the
//! call's duration (the inheritance seam; deviation D18).
//!
//! Normative: docs/kernel/04-synchronization-and-ipc-guarantees.md
//! ("Synchronous Call Scheduling"), docs/kernel/02-scheduling-memory-ipc.md
//! Budget: B3 (round trip), B4 (per handle), B19 (scaling) — the call path;
//! unmeasured until the perf rig lands (build/README.md, D20)

use crate::devmgr::{
    DeviceTable, DmaFault, DmaFaultOutcome, InterruptRouter, IsolationPolicy, LeaseEndReason,
    RouteEndReason,
};
use crate::ipc::{Channel, ChannelTable, EndpointId, Message};
use crate::job::{
    Job, JobId, JobLimits, JobTable, MAX_JOBS, Member, SIGNAL_EMPTY, SIGNAL_MEMBER_EXIT,
};
use crate::object::ObjectId;
use crate::port::{MAX_PORTS, PortEvent, PortId, PortTable};
use crate::rights::Rights;
use crate::sched::{MAX_THREADS, Scheduler};
use crate::thread::Thread;
use crate::wait::{WaitKey, WaitSet};
use tessera_karch::{ContextOps, KError};

/// Maximum nested synchronous calls per thread (docs/kernel/04).
pub const MAX_SYNC_DEPTH: u8 = 8;

/// Wire size of `ServiceNotice` (`driver_lifecycle.isl`).
const SERVICE_NOTICE_SIZE: usize = 32;

/// The port signal a device interrupt is delivered on.
///
/// One signal, because an interrupt line has one meaning: it fired. The port
/// facility's `(source, signal)` pair carries a second dimension for sources
/// that have several — a channel's readable and writable edges — and an
/// interrupt has exactly one, so this is a constant rather than a parameter.
/// Naming it is what lets [`Executive::device_route_irq`] and the revocation
/// path agree on which binding to undo without either of them being told.
pub const IRQ_PORT_SIGNAL: u8 = 1;

/// The signal a device's removal is delivered on, to the same port and source
/// its interrupts use.
///
/// **A driver parked waiting for an interrupt has to be woken by something,
/// and it must not be woken by something that looks like an interrupt.** A
/// device that has left the machine will never raise its line again, so a
/// driver blocked on it waits forever; delivering the removal on the
/// interrupt's own signal would wake it into servicing a completion that never
/// happened. A second signal on the same binding wakes the same sleeper and
/// says something different.
///
/// **Three, because a port's signal numbers are one namespace.** One is an
/// interrupt and two is a channel message (`ipc::SIGNAL_MESSAGE`), and a
/// driver waiting on a port that carries both sees the raw number — so a
/// removal numbered two would arrive at a resident server as a client request
/// and be answered as one.
///
/// Bound by the removal itself, on the port the route was using, and only
/// then. Binding it alongside every interrupt route would spend a second
/// binding slot per device for a signal almost no device ever raises.
pub const IRQ_PORT_SIGNAL_REMOVED: u8 = 3;

/// `DEVICE_RECLAIM_LOST` cause: the reclaim message had no room for the
/// capability's handle. ABI (`kernel_event.isl`).
const RECLAIM_LOST_NO_HANDLE_ROOM: u64 = 1;
/// `DEVICE_RECLAIM_LOST` cause: the destination queue was full, so the manager
/// is not keeping up. ABI (`kernel_event.isl`).
const RECLAIM_LOST_QUEUE_FULL: u64 = 2;
/// `DEVICE_RECLAIM_LOST` cause: the object is not in the device graph, so there
/// is no recorded authority to hand it back with. Structurally impossible — the
/// reclaim list is built from the graph — and recorded rather than assumed away.
const RECLAIM_LOST_NOT_IN_GRAPH: u64 = 3;

/// Records a device capability that reclaim could not deliver. The device is
/// then as lost as it would have been without reclaim at all — which is a
/// result the system must be able to see, not a silence.
fn reclaim_lost(object: ObjectId, cause: u64) {
    crate::event::emit(
        crate::event::EventKind::DeviceReclaimLost,
        crate::event::Severity::Error,
        crate::event::Component::Driver,
        [object.raw() as u64, cause, 0, 0],
    );
}

/// Owns the scheduler and the channel table so one `&mut self` covers a call's
/// cross-subsystem work.
pub struct Executive<C: ContextOps> {
    sched: Scheduler<C>,
    channels: ChannelTable,
    next_txn: u64,
    /// Per-thread nested-synchronous-call depth, for the chain limit.
    sync_depth: [u8; MAX_THREADS],
    /// A callee's own causal id, parked while it handles a synchronous call
    /// under the caller's id and restored when the call returns. Indexed by
    /// callee, so a nested chain saves one entry per level (bounded by
    /// `MAX_SYNC_DEPTH`, and a callee cannot re-enter while its own call is
    /// outstanding — it is blocked).
    saved_correlation: [u64; MAX_THREADS],
    /// Threads blocked in `wait_on_address`, keyed by `(space, addr)`.
    waits: WaitSet,
    /// Async event-delivery ports.
    ports: PortTable,
    /// The job containment tree.
    jobs: JobTable,
    /// The device resource graph (Device object → I/O range + IRQ).
    devices: DeviceTable,
    /// Memory objects and the frames they own (`crate::memory`).
    memory: crate::memory::MemoryTable,
    /// Where each device is in its driver lifecycle. Not modelled here — the
    /// device manager owns the lifecycle — but recorded, so a declared
    /// transition can be checked against the history the kernel already has
    /// (`crate::lifecycle`).
    lifecycle: crate::lifecycle::LifecycleTable,
    /// The system wake-event counter and the wake holds that veto a suspend
    /// (`crate::power`). Here rather than in a static because the interrupt
    /// bridge that records a wake already reaches the Executive to signal a
    /// port, and two homes for one fact is one too many.
    wake: crate::power::WakeState,
    /// The thread parked inside a suspend commit, if the machine is asleep.
    ///
    /// One, not a set: the commit is the whole system stopping, and a second
    /// caller reaching it would mean user space was not frozen after all.
    sleeper: Option<usize>,
    /// What woke it, recorded at interrupt time rather than reconstructed
    /// afterwards — which is the only moment the answer is certain.
    resumed_by: Option<ObjectId>,
}

/// Why a suspend commit ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuspendOutcome {
    /// The commit was taken and a wake ended it.
    Resumed = 1,
    /// A wake arrived after the caller took its snapshot; the machine never
    /// stopped.
    WakeArrived = 2,
    /// A wake hold vetoed the commit.
    Vetoed = 3,
}

/// What a suspend commit did — see [`Executive::system_suspend`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SuspendReport {
    pub outcome: SuspendOutcome,
    /// The wake-event counter when the call returned.
    pub events: u64,
    /// The device credited with the wake for a resume, the vetoing holder for
    /// a veto, and `None` otherwise.
    pub source: Option<ObjectId>,
}

/// What a removal did — see [`Executive::remove_device`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RemovalReport {
    /// Whether the graph knew this device at all. `false` for a removal of
    /// something already removed, which is a no-op rather than an error: a bus
    /// may report the same disappearance twice.
    pub existed: bool,
    /// Processes that were holding a handle to it.
    pub holders: usize,
    /// Register windows unmapped, which is at most `holders`.
    pub windows: usize,
    /// Services depending on this device that were told it had gone.
    pub dependents_told: usize,
    /// Services that could **not** be told — their endpoint's queue was full,
    /// or the notice would not encode. Counted rather than retried, because a
    /// dependent that missed this is in a worse position than one that was
    /// never registered and should be visible as such.
    pub dependents_missed: usize,
    /// Ports told the device's line will never assert again — which is what
    /// wakes a driver parked waiting for an interrupt from it.
    pub woken: usize,
    /// How many nodes went, counting the device named and everything that sat
    /// behind it. One for a leaf.
    ///
    /// The number the caller cannot work out for itself afterwards: once the
    /// removal has run, the edges that would have answered "how big was that
    /// subtree" are the very thing that was torn down.
    pub subtree: usize,
}

impl<C: ContextOps> Executive<C> {
    pub fn new(quantum: u32, tick_limit: u64) -> Self {
        Self {
            sched: Scheduler::new(quantum, tick_limit),
            channels: ChannelTable::new(),
            next_txn: 1,
            sync_depth: [0; MAX_THREADS],
            saved_correlation: [0; MAX_THREADS],
            waits: WaitSet::new(),
            ports: PortTable::new(),
            jobs: JobTable::new(),
            devices: DeviceTable::new(),
            memory: crate::memory::MemoryTable::new(),
            lifecycle: crate::lifecycle::LifecycleTable::new(),
            wake: crate::power::WakeState::new(),
            sleeper: None,
            resumed_by: None,
        }
    }

    /// The scheduler, for spawning threads and starting/stopping the run.
    pub fn scheduler(&mut self) -> &mut Scheduler<C> {
        &mut self.sched
    }

    /// Adds a thread to the scheduler (convenience).
    pub fn add_thread(&mut self, thread: Thread<C>) -> Result<usize, KError> {
        self.sched.add_thread(thread)
    }

    /// Starts scheduling.
    pub fn run(&mut self) {
        self.sched.run();
    }

    /// Total context switches performed (for the exactly-two-switches check).
    pub fn switch_count(&self) -> u64 {
        self.sched.switch_count()
    }

    /// Creates a channel, returning its two endpoint ids.
    pub fn channel_create(&mut self) -> Result<(EndpointId, EndpointId), KError> {
        self.channels.create()
    }

    /// Binds `endpoint` to the object id of its `ObjectType::Channel` object,
    /// so a ring-3 handle resolving to that id maps back to this endpoint.
    pub fn bind_endpoint_object(&mut self, endpoint: EndpointId, id: ObjectId) {
        self.channels.set_endpoint_object(endpoint, id);
    }

    /// Resolves a channel object id back to its endpoint — the handle→endpoint
    /// bridge a ring-3 channel syscall uses after looking the handle up in the
    /// caller's table.
    pub fn endpoint_of_object(&self, id: ObjectId) -> Option<EndpointId> {
        self.channels.endpoint_of_object(id)
    }

    /// The peer of an endpoint.
    fn peer(endpoint: EndpointId) -> EndpointId {
        EndpointId {
            channel: endpoint.channel,
            side: Channel::peer(endpoint.side),
        }
    }

    /// Adopts a just-dequeued message's causal id onto the receiving thread, so
    /// the work it does handling the request is attributed to the cause that sent
    /// it rather than to the server itself (docs/observability/02: propagated "to
    /// the callee for the duration of handling").
    ///
    /// A message with no recorded cause leaves the receiver's id alone — adopting
    /// 0 would erase a good id rather than inherit a real one. There is no restore
    /// bracket on this path (unlike the synchronous `call`, which parks and
    /// restores the callee's own id): an async server carries the last request's
    /// id until its next receive adopts the next one, which is the design's
    /// "pipeline stages inherit the item's ID" (D60).
    fn adopt_message_correlation(&mut self, message: &Message) {
        let correlation = message.header().correlation;
        if correlation == 0 {
            return;
        }
        if let Some(me) = self.sched.current() {
            self.sched.set_thread_correlation(me, correlation);
        }
    }

    /// Sends a one-way message from `from` to its peer, waking a blocked
    /// receiver (asynchronously — no handoff). A full queue yields `WouldBlock`.
    pub fn send(&mut self, from: EndpointId, mut message: Message) -> Result<(), KError> {
        let peer = Self::peer(from);
        // An async send has no handoff to carry causality through, so the id
        // rides the message itself: the receiver adopts it when it dequeues
        // (docs/observability/02, "Asynchronous messages carry it explicitly in
        // the header field"; D60).
        message.set_correlation(crate::trace::current().correlation);
        let (receiver, destination) = {
            let channel = self
                .channels
                .channel_mut(from.channel)
                .ok_or(KError::BadHandle)?;
            channel.endpoint_mut(peer.side).enqueue(message)?;
            let receiver = channel.endpoint(peer.side).blocked_receiver();
            if receiver.is_some() {
                channel.endpoint_mut(peer.side).set_blocked_receiver(None);
            }
            (receiver, channel.object(peer.side))
        };
        if let Some(receiver) = receiver {
            self.sched.unblock(receiver);
        }
        // Raise the arrival on the destination endpoint's object, so a server
        // selecting across per-client endpoints learns which one has work
        // (D85). Inert unless some port bound that `(source, signal)` pair;
        // signalled outside the channel borrow, the `port_signal` discipline.
        self.signal_endpoint_arrival(destination);
        Ok(())
    }

    /// Signals a message arrival on `destination` (an endpoint's bound
    /// object) to any port watching it. A no-op for an unbound endpoint or
    /// when no port carries that binding.
    fn signal_endpoint_arrival(&mut self, destination: Option<ObjectId>) {
        if let Some(object) = destination {
            self.port_signal(u64::from(object.raw()), crate::ipc::SIGNAL_MESSAGE, 1);
        }
    }

    /// Receives a message on `on`, blocking until one arrives or the peer
    /// closes. FIFO; a closed-and-drained endpoint returns `PeerClosed`.
    pub fn receive(&mut self, on: EndpointId) -> Result<Message, KError> {
        loop {
            let channel = self
                .channels
                .channel_mut(on.channel)
                .ok_or(KError::BadHandle)?;
            if let Some(message) = channel.endpoint_mut(on.side).dequeue() {
                // Handling this request belongs to the cause that sent it. Only
                // on a successful dequeue — a parked retry must not churn the
                // receiver's id.
                self.adopt_message_correlation(&message);
                return Ok(message);
            }
            if channel.endpoint(on.side).peer_closed() {
                return Err(KError::PeerClosed);
            }
            let me = self.sched.current().ok_or(KError::BadHandle)?;
            channel.endpoint_mut(on.side).set_blocked_receiver(Some(me));
            // Park until a sender wakes us, then retry the dequeue.
            self.sched.block_current();
        }
    }

    /// Synchronous call: sends `request` from `from`, hands off directly to a
    /// waiting callee, and blocks for the reply (matched by transaction id).
    /// The caller's priority is carried to the callee; the chain depth is
    /// limited. Returns the reply, or `PeerClosed` if the callee's endpoint
    /// closes while the call is outstanding.
    pub fn call(&mut self, from: EndpointId, mut request: Message) -> Result<Message, KError> {
        let caller = self.sched.current().ok_or(KError::BadHandle)?;
        if self.sync_depth[caller] >= MAX_SYNC_DEPTH {
            return Err(KError::Protocol);
        }
        let txn = self.next_txn;
        self.next_txn += 1;
        request.set_txn(txn);
        // The request carries the caller's cause, like the txn it carries above.
        // For a parked callee this agrees with the id handed over below; for one
        // that is not yet parked it is the *only* way the cause reaches it (D60).
        let caller_correlation = self.sched.thread_correlation(caller).unwrap_or(0);
        request.set_correlation(caller_correlation);

        let peer = Self::peer(from);
        let (callee, caller_priority, destination) = {
            let channel = self
                .channels
                .channel_mut(from.channel)
                .ok_or(KError::BadHandle)?;
            // Register where the reply will arrive (this endpoint).
            channel
                .endpoint_mut(from.side)
                .set_pending_caller(Some((caller, txn)));
            // Deliver the request to the callee's queue (all-or-nothing: a full
            // queue rejects before any state is committed further).
            channel.endpoint_mut(peer.side).enqueue(request)?;
            let callee = channel.endpoint(peer.side).blocked_receiver();
            if callee.is_some() {
                channel.endpoint_mut(peer.side).set_blocked_receiver(None);
            }
            (
                callee,
                self.sched.thread_priority(caller).unwrap_or(0),
                channel.object(peer.side),
            )
        };
        // Same arrival signal as `send` (D85): a server parked on its select
        // port is woken and learns which client endpoint to serve.
        self.signal_endpoint_arrival(destination);

        self.sync_depth[caller] += 1;
        match callee {
            Some(callee) => {
                // Carry the caller's priority to the callee for the call.
                self.sched.set_thread_priority(callee, caller_priority);
                // And its causal id: "synchronous calls ... propagate it to the
                // callee for the duration of handling" (docs/observability/02),
                // so the work the callee does on this request is attributed to
                // the cause that requested it. The callee's own id is parked and
                // restored below, or a server would keep the last caller's id
                // and misattribute everything it did afterwards.
                self.saved_correlation[callee] = self.sched.thread_correlation(callee).unwrap_or(0);
                self.sched
                    .set_thread_correlation(callee, caller_correlation);
                self.sched.handoff_to(callee); // caller blocks, callee runs
            }
            None => {
                // Callee not yet waiting, so there is no callee index to stamp —
                // but the request now carries the id in its header, and whichever
                // thread later dequeues it adopts that id (D60). Block until it
                // replies.
                self.sched.block_current();
            }
        }
        // --- resumed after the reply hands back ---
        self.sync_depth[caller] -= 1;
        if let Some(callee) = callee {
            self.sched
                .set_thread_correlation(callee, self.saved_correlation[callee]);
            self.saved_correlation[callee] = 0;
        }

        let channel = self
            .channels
            .channel_mut(from.channel)
            .ok_or(KError::BadHandle)?;
        channel.endpoint_mut(from.side).set_pending_caller(None);
        match channel.endpoint_mut(from.side).dequeue() {
            Some(reply) => Ok(reply),
            None => Err(KError::PeerClosed),
        }
    }

    /// Replies to an outstanding call received on `on`, delivering `response` to
    /// the waiting caller on the peer endpoint and handing off directly back to
    /// it (two switches per round trip). If no caller waits, the response is
    /// simply queued.
    pub fn reply(&mut self, on: EndpointId, response: Message) -> Result<(), KError> {
        let peer = Self::peer(on);
        let waiting_caller = {
            let channel = self
                .channels
                .channel_mut(on.channel)
                .ok_or(KError::BadHandle)?;
            channel.endpoint_mut(peer.side).enqueue(response)?;
            channel.endpoint(peer.side).pending_caller()
        };
        if let Some((caller, _txn)) = waiting_caller {
            self.sched.handoff_to(caller); // callee blocks, caller runs with reply
        }
        Ok(())
    }

    /// Replies to the outstanding call on `on` and stays runnable: the caller
    /// is made `Ready` rather than handed off to, so this thread returns from
    /// the syscall and continues.
    ///
    /// [`reply`](Self::reply) blocks the replier as part of its handoff, which
    /// is correct only when the next `call` on the same endpoint will hand
    /// back. A server that selects across endpoints waits on a *port*, so it
    /// must not block here — nothing would ever wake it (D85).
    pub fn reply_and_continue(&mut self, on: EndpointId, response: Message) -> Result<(), KError> {
        let peer = Self::peer(on);
        let waiting_caller = {
            let channel = self
                .channels
                .channel_mut(on.channel)
                .ok_or(KError::BadHandle)?;
            channel.endpoint_mut(peer.side).enqueue(response)?;
            channel.endpoint(peer.side).pending_caller()
        };
        if let Some((caller, _txn)) = waiting_caller {
            self.sched.unblock(caller);
        }
        Ok(())
    }

    /// Replies to the outstanding call on `on` **and** waits for the next
    /// request, in one operation — the request-server primitive. The reply is
    /// delivered to the waiting caller, this thread re-parks as `on`'s receiver,
    /// and it hands off directly to the caller (which resumes with the reply).
    /// The next `call` that arrives hands off back here and its request is
    /// returned. A bare [`reply`](Self::reply) blocks the server after handing
    /// off, so a server (e.g. the pager) that must serve *many* calls uses this
    /// to stay parked between them.
    pub fn reply_receive(&mut self, on: EndpointId, response: Message) -> Result<Message, KError> {
        let me = self.sched.current().ok_or(KError::BadHandle)?;
        let peer = Self::peer(on);
        // Deliver the reply to the waiting caller and note who to hand back to.
        let caller = {
            let channel = self
                .channels
                .channel_mut(on.channel)
                .ok_or(KError::BadHandle)?;
            channel.endpoint_mut(peer.side).enqueue(response)?;
            channel.endpoint(peer.side).pending_caller().map(|(c, _)| c)
        };
        // Re-park to receive the next request; hand off to the caller on the
        // first pass (block on any later spurious wake), then return the request.
        let mut handed_off = false;
        loop {
            {
                let channel = self
                    .channels
                    .channel_mut(on.channel)
                    .ok_or(KError::BadHandle)?;
                if let Some(request) = channel.endpoint_mut(on.side).dequeue() {
                    // The next request is already queued, so the server keeps
                    // running instead of handing off — the just-replied caller
                    // must still be WOKEN, or it sleeps forever with its reply
                    // queued. Unreachable while requests only arrived through
                    // direct handoffs; first hit when interrupt-driven serving
                    // let a second client queue while the server waited on its
                    // device (D84).
                    if !handed_off && let Some(caller) = caller {
                        self.sched.unblock(caller);
                    }
                    // A server staying parked between calls adopts each new
                    // request's cause as it starts handling it (D60).
                    self.adopt_message_correlation(&request);
                    return Ok(request);
                }
                if channel.endpoint(on.side).peer_closed() {
                    return Err(KError::PeerClosed);
                }
                channel.endpoint_mut(on.side).set_blocked_receiver(Some(me));
            }
            if !handed_off {
                handed_off = true;
                match caller {
                    Some(caller) => self.sched.handoff_to(caller),
                    None => self.sched.block_current(),
                }
            } else {
                self.sched.block_current();
            }
        }
    }

    /// Closes `endpoint`, raising peer-closed on the other end and waking any
    /// caller blocked awaiting a reply there or receiver blocked on it.
    pub fn close_endpoint(&mut self, endpoint: EndpointId) -> Result<(), KError> {
        let peer = Self::peer(endpoint);
        let to_wake = {
            let channel = self
                .channels
                .channel_mut(endpoint.channel)
                .ok_or(KError::BadHandle)?;
            channel.close_side(endpoint.side);
            let ep = channel.endpoint(peer.side);
            ep.blocked_receiver()
                .or_else(|| ep.pending_caller().map(|(t, _)| t))
        };
        if let Some(thread) = to_wake {
            self.sched.unblock(thread);
        }
        Ok(())
    }

    /// Futex-style wait: block the current thread on `(space, addr)` **iff** the
    /// address still holds `expected`. `observed` is the word the arch/syscall
    /// entry already read from `addr` (kcore never dereferences a user
    /// pointer). A mismatch returns [`KError::WouldBlock`] *without* blocking —
    /// the value changed under the caller, so it should recheck and retry
    /// (the futex compare-and-block race guard). On a match the thread is
    /// enrolled and parked until [`wake`](Self::wake) targets the same key.
    ///
    /// On single-core cooperative execution the read of `observed` and this
    /// enroll-and-block are effectively atomic (nothing else runs between
    /// them); the lock/preempt-disable that makes this race-free under
    /// preemption or SMP is deferred (build/README.md, D37). There is no
    /// deadline in v0 (D37).
    pub fn wait_on_address(
        &mut self,
        space: u64,
        addr: u64,
        observed: u64,
        expected: u64,
    ) -> Result<(), KError> {
        let me = self.sched.current().ok_or(KError::BadHandle)?;
        if observed != expected {
            return Err(KError::WouldBlock);
        }
        // Enroll before parking; a full waiter pool refuses rather than
        // dropping the waiter (the caller does not then block).
        self.waits.enroll(WaitKey { space, addr }, me)?;
        self.sched.block_current();
        Ok(())
    }

    /// Wakes up to `count` threads blocked on `(space, addr)`, returning how
    /// many were woken. Each is made `Ready` (no handoff); the caller decides
    /// when to yield so a woken waiter can run. `count == 0` wakes none;
    /// `u32::MAX` wakes all. No bitset or requeue variant in v0 (D37).
    pub fn wake(&mut self, space: u64, addr: u64, count: u32) -> usize {
        let key = WaitKey { space, addr };
        let mut woken = 0;
        while (woken as u32) < count {
            match self.waits.pop_matching(key) {
                Some(thread) => {
                    self.sched.unblock(thread);
                    woken += 1;
                }
                None => break,
            }
        }
        woken
    }

    /// Creates an async event-delivery port.
    pub fn port_create(&mut self) -> Result<PortId, KError> {
        self.ports.create()
    }

    /// Binds `port` to the object id of its `ObjectType::Port` object, so a
    /// ring-3 handle resolving to that id maps back to this port.
    pub fn bind_port_object(&mut self, port: PortId, id: ObjectId) {
        self.ports.set_port_object(port, id);
    }

    /// Resolves a port object id back to its port — the handle→port bridge a
    /// ring-3 port syscall uses after looking the handle up in the caller's table.
    pub fn port_of_object(&self, id: ObjectId) -> Option<PortId> {
        self.ports.port_of_object(id)
    }

    /// Registers a device node in the resource graph: the `ObjectType::Device`
    /// object `id` is backed by the I/O range `[base, base+len)` on interrupt
    /// line `irq`. The device manager/boot populates the graph before granting.
    pub fn device_register(
        &mut self,
        id: ObjectId,
        base: u16,
        len: u16,
        irq: u8,
        rights: Rights,
    ) -> Result<(), KError> {
        self.devices.register(id, base, len, irq, rights)
    }

    /// Resolves a Device object id to its I/O range — the handle→range bridge a
    /// `DeviceIo` syscall uses to read and enforce the granted device's extent.
    pub fn device_of_object(&self, id: ObjectId) -> Option<(u16, u16)> {
        self.devices.device_of_object(id)
    }

    /// Registers a Device object `id` backed by the MMIO register window `[base,
    /// base+len)` (physical). The MMIO counterpart of [`Self::device_register`],
    /// for a memory-mapped device granted to a ring-3 driver (D77).
    pub fn device_register_mmio(
        &mut self,
        id: ObjectId,
        base: u64,
        len: u64,
        rights: Rights,
    ) -> Result<(), KError> {
        self.devices.register_mmio(id, base, len, rights)
    }

    /// Resolves a Device object id to its MMIO register window `(phys_base, len)` —
    /// the handle→window bridge a `MapDevice` syscall uses to map the granted
    /// window into a ring-3 driver's address space.
    /// Records the interrupt INTID of a registered MMIO device (D84).
    pub fn device_set_mmio_irq(&mut self, id: ObjectId, intid: u32) -> Result<(), KError> {
        self.devices.set_mmio_irq(id, intid)
    }

    /// Records that `child` sits behind `parent` in the bus topology.
    pub fn device_set_parent(&mut self, child: ObjectId, parent: ObjectId) -> Result<(), KError> {
        self.devices.set_parent(child, parent)
    }

    /// The device `id` sits behind, if any.
    pub fn device_parent_of(&self, id: ObjectId) -> Option<ObjectId> {
        self.devices.parent_of(id)
    }

    /// The devices directly behind `id`; returns how many were written.
    pub fn device_children_of(&self, id: ObjectId, out: &mut [ObjectId]) -> usize {
        self.devices.children_of(id, out)
    }

    /// Whether `id` is `root` or sits below it — the subtree test a capability
    /// scoped to a bus controller is checked against.
    pub fn device_is_descendant_of(&self, id: ObjectId, root: ObjectId) -> bool {
        self.devices.is_descendant_of(id, root)
    }

    /// The authority the graph holds over `id` — what a kernel-originated
    /// hand-out of this device carries.
    pub fn device_rights_of_object(&self, id: ObjectId) -> Option<Rights> {
        self.devices.rights_of_object(id)
    }

    /// Resolves a Device object to its interrupt INTID, if wired (D84).
    pub fn intid_of_object(&self, id: ObjectId) -> Option<u32> {
        self.devices.intid_of_object(id)
    }

    /// Arms or disarms `device`'s interrupt as a system wakeup source.
    pub fn set_wake_source(&mut self, device: ObjectId, armed: bool) -> Result<(), KError> {
        self.devices.set_wake_source(device, armed)?;
        crate::event::emit(
            crate::event::EventKind::PowerWakeSourceArmed,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [device.raw() as u64, u64::from(armed), 0, 0],
        );
        Ok(())
    }

    /// Whether `device`'s interrupt may wake this machine.
    pub fn is_wake_source(&self, device: ObjectId) -> bool {
        self.devices.is_wake_source(device)
    }

    /// Records a wake if `intid` belongs to an armed wakeup source, and
    /// answers the source that was credited.
    ///
    /// **Called from the interrupt bridge, before the port signal.** The order
    /// is the point: a wake that is delivered but not counted is exactly the
    /// lost wakeup the counter exists to close, and delivery can wake a
    /// process that then races the suspend entry. Counting first means the
    /// number has already moved by the time anything else can observe the
    /// event at all.
    ///
    /// A line nobody armed answers `None` and touches nothing — most
    /// interrupts on a running machine are not wake sources, and treating them
    /// as such would make the counter meaningless.
    pub fn record_wake(&mut self, intid: u32) -> Option<ObjectId> {
        let source = self.devices.armed_wake_source(intid)?;
        let now = self.sched.ticks();
        let grace = self.wake.record_wake(source, now);
        // **Ending the sleep is part of counting it**, not a separate step a
        // later pass could forget: the thread parked in the commit is the
        // machine being asleep, and a wake that moved the counter without
        // unblocking it would leave a system that is awake by the numbers and
        // stopped in fact.
        if let Some(thread) = self.sleeper.take() {
            self.resumed_by = Some(source);
            self.sched.unblock(thread);
        }
        crate::event::emit_with_flags(
            crate::event::EventKind::PowerWakeEvent,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            u64::from(!grace),
            [
                source.raw() as u64,
                u64::from(intid),
                self.wake.events(),
                now,
            ],
        );
        Some(source)
    }

    /// The system wake-event counter — the number a suspend commit compares
    /// its snapshot against.
    pub fn wake_events(&self) -> u64 {
        self.wake.events()
    }

    /// Takes a wake hold for `holder`, lasting `ticks` scheduler ticks or
    /// until released when `ticks` is zero.
    pub fn acquire_wake_hold(
        &mut self,
        holder: ObjectId,
        ticks: u64,
    ) -> Result<(), crate::power::WakeError> {
        let now = self.sched.ticks();
        // Sweep first: a table full of holds nobody is still asking for would
        // refuse a live one, and expiry is the only thing that ever clears
        // them for a holder that stopped renewing.
        self.wake.expire(now);
        let expires_at = (ticks != 0).then(|| now + ticks);
        self.wake.acquire(holder, expires_at)?;
        crate::event::emit(
            crate::event::EventKind::PowerWakeHoldTaken,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [holder.raw() as u64, ticks, now, self.wake.held(now) as u64],
        );
        Ok(())
    }

    /// Releases one of `holder`'s wake holds. Answers whether there was one.
    pub fn release_wake_hold(&mut self, holder: ObjectId) -> bool {
        let released = self.wake.release(holder);
        if released {
            let now = self.sched.ticks();
            crate::event::emit(
                crate::event::EventKind::PowerWakeHoldReleased,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [holder.raw() as u64, now, self.wake.held(now) as u64, 0],
            );
        }
        released
    }

    /// Releases every hold `holder` has — for a process that has gone.
    pub fn release_wake_holds_of(&mut self, holder: ObjectId) -> usize {
        self.wake.release_all(holder)
    }

    /// Wake holds still counting, and whether a suspend commit is vetoed.
    pub fn wake_holds_held(&mut self) -> usize {
        let now = self.sched.ticks();
        self.wake.expire(now);
        self.wake.held(now)
    }

    /// Who is vetoing a suspend commit, if anybody — so a refusal can name
    /// them rather than say only that one exists.
    pub fn wake_hold_holder(&self) -> Option<ObjectId> {
        self.wake.holder_at(self.sched.ticks(), 0)
    }

    /// Commits the system to sleep, and does not return until it resumes.
    ///
    /// **The final step whose correctness cannot survive a service round
    /// trip** (`docs/power/01`, "Suspend Entry And Resume", step 6). By the
    /// time this is called the power manager has frozen what it freezes and
    /// suspended the driver hosts leaves-first; what is left is the one thing
    /// that has to be right *while nothing is running*.
    ///
    /// Two refusals, in the order they matter:
    ///
    /// 1. **The counter moved.** `snapshot` is what the caller read before it
    ///    began entry. Whether the wake arrived before, during or after that
    ///    read does not matter — it either changed the number or it did not,
    ///    and if it did the entry aborts and the machine never stops. This is
    ///    the lost-wakeup race closed by counting rather than by ordering.
    /// 2. **A wake hold vetoes.** Checked second because a machine somebody is
    ///    holding awake and a machine that has just been woken are different
    ///    situations, and the more urgent one is the wake.
    ///
    /// Otherwise the caller blocks. Nothing else is runnable by construction —
    /// user space is frozen — so the CPU reaches its idle loop, which *is*
    /// suspend-to-idle (`docs/power/01`: the baseline on every profile,
    /// requiring no firmware support). [`Self::record_wake`] unblocks it.
    pub fn system_suspend(&mut self, snapshot: u64) -> SuspendReport {
        let now = self.sched.ticks();
        let events = self.wake.events();
        if events != snapshot {
            crate::event::emit(
                crate::event::EventKind::PowerSuspendAborted,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [1, events, snapshot, 0],
            );
            return SuspendReport {
                outcome: SuspendOutcome::WakeArrived,
                events,
                source: None,
            };
        }
        self.wake.expire(now);
        if let Some(holder) = self.wake.holder_at(now, 0) {
            crate::event::emit(
                crate::event::EventKind::PowerSuspendAborted,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [2, events, snapshot, holder.raw() as u64],
            );
            return SuspendReport {
                outcome: SuspendOutcome::Vetoed,
                events,
                source: Some(holder),
            };
        }

        // Recorded **before** the CPU stops. A record written afterwards would
        // describe a suspend that had already ended, and the per-stage
        // attribution `docs/power/01` asks for needs each stage visible while
        // it is happening.
        crate::event::emit(
            crate::event::EventKind::PowerSuspendCommitted,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [snapshot, now, 0, 0],
        );
        self.sleeper = self.sched.current();
        self.resumed_by = None;
        self.sched.block_current();

        // Resumed.
        let source = self.resumed_by.take();
        let events = self.wake.events();
        crate::event::emit(
            crate::event::EventKind::PowerResumed,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [
                source.map_or(0, |id| id.raw() as u64),
                events,
                self.sched.ticks(),
                0,
            ],
        );
        SuspendReport {
            outcome: SuspendOutcome::Resumed,
            events,
            source,
        }
    }

    /// Hands every device capability `process` still holds to the endpoint
    /// `to`, and returns how many were sent.
    ///
    /// This is what makes a device outlive its driver **without anyone having
    /// to remember**. Before it, a supervisor tearing down a dead driver had
    /// to know which devices it had been given and return each one by hand;
    /// a supervisor that forgot cost the machine a device permanently, because
    /// the only handle to it died with the process. Now forgetting is not
    /// possible, because the supervisor is not the one doing it.
    ///
    /// Each capability travels as its own message carrying **no payload**. The
    /// kernel does not know — and must not know — what protocol the receiver
    /// speaks; a capability arriving from the kernel *is* the whole message,
    /// and a manager that receives one has been handed a device back. That is
    /// a stronger signal than a flag in a body would be: a body can be forged
    /// by any sender, a transferred capability cannot.
    ///
    /// Called by a supervisor as part of teardown, before the process is
    /// removed. Rights travel with each capability unchanged.
    pub fn reclaim_devices<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        process: &mut crate::process::Process<A>,
        to: EndpointId,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> usize {
        // Leases and interrupt routes first, before a single handle moves.
        //
        // Per-process rather than per-reclaimed-object, deliberately: this must
        // not depend on the handle sweep below finding anything. A device whose
        // capability cannot be *delivered* — the message had no room, the
        // manager's queue was full — must still stop translating for a corpse,
        // and those are exactly the paths that skip the loop.
        self.end_leases_of(process.id(), LeaseEndReason::HolderGone, iommu);
        // And it must stop *interrupting* for one. A corpse's route would keep
        // a level-triggered line asserting into a port that will never be
        // drained again — and the manager is about to hand the device to a
        // replacement, which would then find its own route refused because the
        // graph still says the dead driver holds it.
        self.end_irq_routes_of(process.id(), RouteEndReason::HolderGone, irqs);
        // A causal origin, in the D59 sense: work that begins because something
        // outside the running trace happened — here, a process died. The
        // thread whose cause this work would otherwise inherit no longer
        // exists, and its kernel stack is gone with it, so there is nothing to
        // continue from; without minting here the reclaim records carry no
        // cause at all and cannot be joined to anything. One id per sweep, so
        // every capability recovered from one corpse shares a cause.
        crate::trace::set_current_correlation(crate::trace::mint());
        // The graph's objects first, so the handle-table scan below can ask
        // "is this a device?" without borrowing the executive inside it.
        let mut devices = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let found = self.devices.objects(&mut devices);

        let mut taken =
            [(ObjectId::from_raw(0), Rights::from_bits(0)); crate::ipc::MAX_MSG_HANDLES];
        let count = process.handles_mut().reclaim(&devices[..found], &mut taken);

        for (object, held) in taken.iter().take(count) {
            // The capability goes back with the **graph's** authority over the
            // device, not with what the dying process happened to hold. A
            // driver may have been granted a device it could not pass on (a
            // narrowed grant, D113); returning only those rights would hand
            // the manager something it could never grant again, and the device
            // would be stranded after exactly one driver. The node outlives
            // every grant, which is what makes it the right source.
            //
            // A device in `taken` came from the graph's own object list, so
            // this lookup cannot miss; a miss is recorded rather than assumed
            // away. `held` is what the corpse had — unused, and named to say
            // that ignoring it is the decision rather than an oversight.
            let _ = held;
            // **A quarantined device is not handed back.** This is where
            // `docs/drivers/01`'s device quarantine is *enforced* rather than
            // merely recorded: the manager never receives the capability, so
            // nothing can bind the device again — not because a manager
            // chooses not to, but because it has nothing to bind. The decision
            // and its reasons were recorded by `quarantine_device`; withholding
            // here needs no second record, and adding one would report a loss
            // for a device that was deliberately kept.
            if self.devices.is_quarantined(*object) {
                continue;
            }
            let Some(rights) = self.devices.rights_of_object(*object) else {
                reclaim_lost(*object, RECLAIM_LOST_NOT_IN_GRAPH);
                continue;
            };
            let mut message = Message::new(crate::ipc::MessageHeader::new(0, 0));
            // Both failures are structural, not conditional: a fresh message
            // has room for a handle, and a full destination queue means the
            // receiver is not keeping up — the capability is dropped and the
            // device is as lost as it would have been without this, which is
            // the honest bound on what reclaim can promise. Each drop emits
            // the record that says so, because degrading in silence is what
            // docs/lifecycle/04 forbids: the bound is honest only if it is
            // visible when it bites.
            if message
                .add_handle(crate::ipc::TransferredHandle {
                    object: *object,
                    rights,
                })
                .is_err()
            {
                reclaim_lost(*object, RECLAIM_LOST_NO_HANDLE_ROOM);
                continue;
            }
            if self.send(to, message).is_err() {
                reclaim_lost(*object, RECLAIM_LOST_QUEUE_FULL);
                continue;
            }
            crate::event::emit(
                crate::event::EventKind::DeviceReclaimed,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [
                    object.raw() as u64,
                    rights.bits(),
                    to.channel as u64,
                    to.side as u64,
                ],
            );
        }
        count
    }

    /// Registers a device the kernel enumerated and can describe (D114).
    pub fn device_register_identified(
        &mut self,
        id: ObjectId,
        base: u64,
        len: u64,
        rights: Rights,
        identity: crate::devmgr::DeviceIdentity,
    ) -> Result<(), KError> {
        self.devices
            .register_identified(id, base, len, rights, identity)
    }

    /// Records the lease a device translates through, and who holds it.
    pub fn device_set_aperture(
        &mut self,
        id: ObjectId,
        holder: ObjectId,
        aperture: crate::devmgr::DeviceAperture,
        expires_at: Option<u64>,
    ) -> Result<(), KError> {
        self.devices.set_aperture(id, holder, aperture, expires_at)
    }

    /// Where `device` is in its driver lifecycle, as last declared.
    pub fn lifecycle_state_of(&self, device: ObjectId) -> Option<crate::lifecycle::DriverState> {
        self.lifecycle.state_of(device)
    }

    /// Pushes `id`'s lease deadline out. See
    /// [`crate::devmgr::DeviceTable::renew_lease`].
    pub fn renew_device_lease(
        &mut self,
        id: ObjectId,
        holder: ObjectId,
        expires_at: Option<u64>,
    ) -> bool {
        self.devices.renew_lease(id, holder, expires_at)
    }

    /// Ends every lease whose deadline has passed, **through the path a
    /// departure uses**.
    ///
    /// Not a second teardown but a third caller of the one that exists: a lease
    /// that expires must leave the machine in exactly the state a lease that
    /// was given up leaves it in, and the only way to be sure of that is for it
    /// to be the same code. Returns how many ended.
    pub fn expire_leases(
        &mut self,
        now: u64,
        mut iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        let mut expired =
            [(ObjectId::from_raw(0), ObjectId::from_raw(0)); crate::devmgr::MAX_DEVICES];
        let found = self.devices.leases_expired_by(now, &mut expired);
        if found == 0 {
            return 0;
        }
        // One cause for the sweep: expiry begins because time passed, not
        // because any thread did anything, so there is nothing to inherit.
        crate::trace::set_current_correlation(crate::trace::mint());
        for (device, holder) in expired.iter().take(found) {
            self.end_one_lease(
                *holder,
                *device,
                LeaseEndReason::Expired,
                iommu.as_deref_mut(),
            );
        }
        found
    }

    /// The DMA aperture a device translates through, if it has a live lease.
    pub fn aperture_of_object(&self, id: ObjectId) -> Option<crate::devmgr::DeviceAperture> {
        self.devices.aperture_of_object(id)
    }

    /// Who holds `id`'s DMA lease, if anyone does.
    pub fn lease_holder_of_object(&self, id: ObjectId) -> Option<ObjectId> {
        self.devices.lease_holder_of_object(id)
    }

    /// Takes `len` bytes from a device's lease, returning the device-visible
    /// address. `None` when the device has no live lease or it is spent —
    /// [`Self::aperture_of_object`] tells those apart.
    pub fn device_allocate_in_aperture(&mut self, id: ObjectId, len: u64) -> Option<u64> {
        self.devices.allocate_in_aperture(id, len)
    }

    /// Ends every DMA lease `holder` holds: the devices' translations are torn
    /// down through `iommu` and their address ranges become reusable.
    ///
    /// **This is the route a register window does not have.** D93 gave process
    /// teardown no revocation code because a device window lives in the dying
    /// address space and dies with it. An IOMMU translation does not — it lives
    /// in the IOMMU, and it outlives the process completely. So a lease must be
    /// ended explicitly, and *before* the process's frames go back to the
    /// allocator: in the window between, a device that still holds an address
    /// would write into memory the kernel has already handed to someone else.
    ///
    /// Returns how many leases ended.
    pub fn end_device_leases<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        process: &crate::process::Process<A>,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        self.end_leases_of(process.id(), LeaseEndReason::HolderGone, iommu)
    }

    /// Ends `device`'s lease if `holder` is the one holding it. Returns whether
    /// a lease ended — `false` when there was none, or when it belongs to
    /// someone else, which is the case when a process gives up one of two
    /// handles it holds to the same device.
    pub fn end_device_lease(
        &mut self,
        holder: ObjectId,
        device: ObjectId,
        reason: LeaseEndReason,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> bool {
        if self.devices.lease_holder_of_object(device) != Some(holder) {
            return false;
        }
        self.end_one_lease(holder, device, reason, iommu)
    }

    /// Ends every lease `holder` holds. The graph is scanned **by device**
    /// rather than by process, which is the only direction available: nothing
    /// can enumerate the holders of an object, and there are at most
    /// [`crate::devmgr::MAX_DEVICES`] nodes to look at.
    fn end_leases_of(
        &mut self,
        holder: ObjectId,
        reason: LeaseEndReason,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        // A causal origin, for the same reason `reclaim_devices` mints one: a
        // lease ends because something outside the running trace happened —
        // a process died, or gave its device up — and the thread whose cause
        // this work would otherwise inherit may be gone with its stack. Without
        // minting, the records carry no cause and cannot be joined to anything.
        // One id per sweep, so every lease ended for one holder shares a cause.
        crate::trace::set_current_correlation(crate::trace::mint());
        let mut held = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let found = self.devices.leases_held_by(holder, &mut held);
        let mut mapper = iommu;
        for object in held.iter().take(found) {
            let reborrowed = mapper.as_deref_mut();
            self.end_one_lease(holder, *object, reason, reborrowed);
        }
        found
    }

    /// The teardown itself: hardware first, then the record.
    ///
    /// That order matters. The reverse would leave an interval in which the
    /// graph says a device reaches nothing while the IOMMU still says it
    /// reaches its buffers — and the graph is what the next lease consults
    /// before reissuing those addresses.
    fn end_one_lease(
        &mut self,
        holder: ObjectId,
        device: ObjectId,
        reason: LeaseEndReason,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> bool {
        if let Some(mapper) = iommu {
            mapper.end_lease(device);
        }
        if self.devices.end_lease(device).is_none() {
            return false;
        }
        // **Every attachment to this device is gone with the lease, and the
        // records must go too — without unmapping.** `end_lease` already
        // dropped every translation, and the address range is reusable now, so
        // a later detach calling `unmap` on one of these ranges would be
        // reaching into whatever lease holds it next. A record that outlived
        // its translation is also a lie in the other direction: it would make
        // an object look reachable by a device that can no longer reach
        // anything.
        self.forget_attachments_to(device);
        crate::event::emit(
            crate::event::EventKind::DeviceDmaLeaseEnded,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [device.raw() as u64, holder.raw() as u64, reason as u64, 0],
        );
        true
    }

    /// Applies `policy` to one refused DMA transaction.
    ///
    /// **The counterpart of [`crate::devmgr::record_dma_fault`], and the split
    /// between them is the one `docs/drivers/01` draws**: faults "are logged
    /// *and can* trigger driver isolation". Logging is unconditional, which is
    /// why it is a free function that needs nothing; isolation needs the
    /// resource graph, so it lives here and a port with no executive in scope
    /// still records the fault. A caller that has both calls both, in that
    /// order — the record describes what happened, this describes what was
    /// done about it.
    ///
    /// Isolation ends the device's **lease**, which is a strictly larger
    /// action than the hardware already took: the unit refused one address,
    /// this makes the device reach nothing at all. It is the whole of what a
    /// kernel can do to a misbehaving device without knowing what it is for.
    ///
    /// Called from the port's fault-harvest path, which may be interrupt
    /// context — so it takes no locks beyond the event ring's and never
    /// schedules. Stopping the holder is deferred to the caller through
    /// [`DmaFaultOutcome::stop`] for that reason as much as for the lack of a
    /// frame allocator here.
    pub fn isolate_dma_fault(
        &mut self,
        fault: DmaFault,
        policy: IsolationPolicy,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> DmaFaultOutcome {
        let (IsolationPolicy::EndLease | IsolationPolicy::EndLeaseAndStop) = policy else {
            return DmaFaultOutcome::default();
        };
        // A fault the port could not attribute to a device has nothing to
        // isolate: there is no lease to end and no holder to stop, and
        // pretending otherwise would be a policy that reports acting without
        // having acted.
        let Some(device) = fault.device else {
            return DmaFaultOutcome::default();
        };
        let Some(holder) = self.devices.lease_holder_of_object(device) else {
            return DmaFaultOutcome::default();
        };
        if !self.end_one_lease(holder, device, LeaseEndReason::FaultIsolated, iommu) {
            return DmaFaultOutcome::default();
        }
        crate::event::emit(
            crate::event::EventKind::DeviceDmaIsolated,
            crate::event::Severity::Critical,
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                holder.raw() as u64,
                policy as u64,
                fault.kind as u64,
            ],
        );
        DmaFaultOutcome {
            isolated: true,
            stop: matches!(policy, IsolationPolicy::EndLeaseAndStop).then_some(holder),
        }
    }

    /// Routes `device`'s interrupts to `port`, held by `holder` — the third
    /// thing a binding grants, alongside the register window and the DMA
    /// lease.
    ///
    /// The line comes from the resource graph, never from the caller
    /// ([`crate::devmgr::DeviceTable::route_irq`]).
    pub fn device_route_irq(
        &mut self,
        device: ObjectId,
        port: PortId,
        holder: ObjectId,
    ) -> Result<(), KError> {
        self.devices.route_irq(device, port, holder)?;
        let intid = self
            .devices
            .irq_route_of_object(device)
            .map_or(0, |route| route.intid);
        // Binding the port to the line is what makes the route deliver. Doing
        // it here rather than leaving it to boot glue is what lets revocation
        // be complete: the same code owns both halves, so neither can be
        // undone without the other.
        match self.ports.port_mut(port) {
            Some(p) => p.bind(u64::from(intid), IRQ_PORT_SIGNAL),
            None => Err(KError::BadHandle),
        }
    }

    /// Where `device`'s interrupts are going, if anywhere.
    pub fn irq_route_of_object(&self, device: ObjectId) -> Option<crate::devmgr::IrqRoute> {
        self.devices.irq_route_of_object(device)
    }

    /// Ends `device`'s interrupt route if `holder` is the one receiving it.
    /// Returns whether a route ended — `false` when there was none, or when it
    /// belongs to someone else, which is the case when a process gives up one
    /// of two handles it holds to the same device.
    pub fn end_device_irq_route(
        &mut self,
        holder: ObjectId,
        device: ObjectId,
        reason: RouteEndReason,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> bool {
        if self.devices.irq_route_of_object(device).map(|r| r.holder) != Some(holder) {
            return false;
        }
        self.end_one_irq_route(device, reason, irqs)
    }

    /// Ends every interrupt route `process` is receiving — the death sweep, and
    /// the interrupt half of what [`Self::end_device_leases`] does for DMA.
    ///
    /// **This is the route a register window does not have**, for exactly the
    /// reason D93 gave for leases: a window lives in the dying address space
    /// and dies with it, while an interrupt route lives in the interrupt
    /// controller and in the port table, both of which outlive the process. A
    /// route left standing keeps a level-triggered line asserting into a port
    /// nobody drains.
    ///
    /// Returns how many routes ended.
    pub fn end_device_irq_routes<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        process: &crate::process::Process<A>,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> usize {
        self.end_irq_routes_of(process.id(), RouteEndReason::HolderGone, irqs)
    }

    /// Ends every route `holder` receives. Scanned **by device** for the same
    /// reason [`Self::end_leases_of`] is: nothing can enumerate the holders of
    /// an object, and there are at most [`crate::devmgr::MAX_DEVICES`] nodes.
    fn end_irq_routes_of(
        &mut self,
        holder: ObjectId,
        reason: RouteEndReason,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> usize {
        let mut held = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let found = self.devices.irq_routes_held_by(holder, &mut held);
        if found == 0 {
            return 0;
        }
        // A causal origin, for the same reason the lease sweep mints one: a
        // route ends because something outside the running trace happened, and
        // the thread whose cause it would otherwise inherit may be gone with
        // its stack. Minted only when there is work, so a sweep that finds
        // nothing does not reroot the caller's trace.
        crate::trace::set_current_correlation(crate::trace::mint());
        let mut router = irqs;
        for object in held.iter().take(found) {
            let reborrowed = router.as_deref_mut();
            self.end_one_irq_route(*object, reason, reborrowed);
        }
        found
    }

    /// The teardown itself: hardware first, then the port binding, then the
    /// record.
    ///
    /// The order is the one [`Self::end_one_lease`] uses and for the same
    /// reason. Masking last would leave an interval in which the graph says
    /// nobody is listening while the controller still delivers — and delivery
    /// into an unbound port is a signal the port facility discards without
    /// counting, so the edges would be lost silently rather than visibly.
    fn end_one_irq_route(
        &mut self,
        device: ObjectId,
        reason: RouteEndReason,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> bool {
        let Some(route) = self.devices.end_irq_route(device) else {
            return false;
        };
        if let Some(router) = irqs {
            router.mask(route.intid);
        }
        if let Some(port) = self.ports.port_mut(route.port) {
            port.unbind(u64::from(route.intid), IRQ_PORT_SIGNAL);
        }
        crate::event::emit(
            crate::event::EventKind::DeviceIrqRevoked,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                u64::from(route.intid),
                reason as u64,
                route.holder.raw() as u64,
            ],
        );
        true
    }

    /// Records a driver-lifecycle transition for `device` and emits it.
    ///
    /// **The manager declares; the kernel checks and stamps.** What is checked
    /// is only consistency — that `from` is the state this kernel last
    /// recorded, and that the edge exists in the table — never policy. Whether
    /// a degraded device deserves a reset is the manager's question; whether
    /// the record stream describes a history that could have happened is not,
    /// because nothing downstream could tell.
    ///
    /// The record carries the device the *capability* named, so a process
    /// cannot narrate a lifecycle for a device it does not hold; the caller's
    /// identity and causal id come from the ambient trace context, as every
    /// other emission does. `detail` rides in the record's `flags` — the four
    /// payload slots are spent on the transition itself, and the detail is the
    /// one field the kernel does not interpret.
    /// Removes a device from the machine: every capability naming it is taken
    /// from every holder, everything that lived on it ends, and the graph
    /// forgets it.
    ///
    /// **The first departure nobody chose.** Every other route a capability
    /// leaves by is something its holder did — handed it on, closed it, died.
    /// This one runs while the holders are alive and using the device, which is
    /// what makes it a different mechanism rather than another caller of an
    /// existing one: `reclaim_devices` takes every device from *one* process,
    /// and this takes *one* device from every process.
    ///
    /// The order is `reclaim_devices`' order, for the same reasons.
    ///
    /// 1. **The lease and the route first**, before a single handle moves. A
    ///    device that has been pulled must stop translating and stop
    ///    interrupting whatever else succeeds — and those are exactly the paths
    ///    that a failure in the handle sweep would skip.
    /// 2. **Then every holder's handles and windows.** Taken with `reclaim`,
    ///    which requires no `TRANSFER`: that right governs a process handing a
    ///    capability on, and this is the kernel taking one back from a process
    ///    that has no say in it.
    /// 3. **Then the node.** Last, because dropping it is what makes every
    ///    device syscall refuse, and doing it first would leave the teardown
    ///    above unable to find what it was tearing down.
    ///
    /// Returns what it did, because "the device went away" is not the
    /// interesting part — "and it was taken from three processes" is.
    /// Removes `device` **and everything behind it**, deepest first.
    ///
    /// A bus controller does not leave alone. Pulling a switch out of a machine
    /// takes the ports and the endpoints below it in one physical event, and a
    /// graph that removed only the node named would leave the children behind
    /// as capabilities that still resolve, still map, and still authorize DMA
    /// for hardware that is not there — the exact condition removal exists to
    /// prevent, reintroduced one level down.
    ///
    /// **Leaves first, and that order is load-bearing rather than tidy.** Each
    /// step removes a node with no children, so no removal ever runs against a
    /// parent whose descendants are still live and no child is ever left
    /// pointing at a slot that has been emptied. Removing the root first would
    /// invert both.
    ///
    /// Iterative rather than recursive: the depth is a property of the machine,
    /// and this runs on a departure path where a kernel stack is the last thing
    /// worth spending on hardware that has already gone. The walk is bounded by
    /// the pool — a subtree cannot hold more nodes than the graph has.
    pub fn remove_device<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        device: ObjectId,
        reason: crate::lifecycle::TransitionReason,
        processes: &mut crate::process::ProcessTable<A>,
        mut iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
        mut irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> RemovalReport {
        let mut total = RemovalReport {
            existed: false,
            holders: 0,
            windows: 0,
            dependents_told: 0,
            dependents_missed: 0,
            woken: 0,
            subtree: 0,
        };
        for _ in 0..crate::devmgr::MAX_DEVICES {
            let Some(target) = self.deepest_below(device) else {
                break;
            };
            let one = self.remove_one_device(
                target,
                reason,
                processes,
                iommu.as_deref_mut(),
                irqs.as_deref_mut(),
            );
            if !one.existed {
                break;
            }
            total.existed = true;
            total.holders += one.holders;
            total.windows += one.windows;
            total.dependents_told += one.dependents_told;
            total.dependents_missed += one.dependents_missed;
            total.woken += one.woken;
            total.subtree += 1;
            if target == device {
                break;
            }
        }
        total
    }

    /// A node below `root` with no children of its own, or `root` itself when
    /// it is childless. `None` when the graph does not hold `root` at all.
    ///
    /// Descends by taking the first child at each step. Which child does not
    /// matter — every one of them is going — and the bound makes a malformed
    /// graph stop rather than spin, though [`crate::devmgr::DeviceTable::set_parent`]
    /// refuses the cycles that could produce one.
    fn deepest_below(&self, root: ObjectId) -> Option<ObjectId> {
        if !self.devices.contains(root) {
            return None;
        }
        let mut current = root;
        for _ in 0..crate::devmgr::MAX_DEVICES {
            let mut children = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
            if self.devices.children_of(current, &mut children) == 0 {
                return Some(current);
            }
            current = children[0];
        }
        Some(current)
    }

    /// Removes exactly one node — the whole of the original removal, now the
    /// step [`Self::remove_device`] repeats over a subtree.
    fn remove_one_device<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        device: ObjectId,
        reason: crate::lifecycle::TransitionReason,
        processes: &mut crate::process::ProcessTable<A>,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> RemovalReport {
        // A causal origin, in the D59 sense: this begins because something
        // outside the running trace happened — a device left the machine — so
        // there is no thread whose cause to inherit. One id for the whole
        // removal, so every record it produces joins up.
        crate::trace::set_current_correlation(crate::trace::mint());

        let mut woken = 0usize;
        let holder = self.devices.lease_holder_of_object(device);
        if let Some(holder) = holder {
            self.end_one_lease(holder, device, LeaseEndReason::Removed, iommu);
        }
        if let Some(route) = self.devices.irq_route_of_object(device) {
            self.end_device_irq_route(
                route.holder,
                device,
                crate::devmgr::RouteEndReason::Removed,
                irqs,
            );
            // **Then wake whoever is parked on the line that has just stopped
            // existing.** A driver blocked waiting for an interrupt from a
            // device that has left waits for something that can no longer
            // happen — the one failure a removal creates that correct
            // bookkeeping does not fix, because the driver is not running to
            // observe any of it.
            //
            // After the teardown, not before: ending the route unbinds the
            // port, and an unbound binding takes any event pending on it, so a
            // wake delivered first would be thrown away by the cleanup that
            // followed it. The binding is re-made here for the one delivery it
            // is needed for.
            //
            // On the removal signal rather than the interrupt's, so the driver
            // wakes knowing which of the two happened: a completion to service,
            // or a device to stop trying to.
            if let Some(port) = self.ports.port_mut(route.port)
                && port
                    .bind(u64::from(route.intid), IRQ_PORT_SIGNAL_REMOVED)
                    .is_ok()
            {
                woken = self.port_signal(u64::from(route.intid), IRQ_PORT_SIGNAL_REMOVED, 1);
            }
        }

        // An attached memory object must stop being reachable too. The device
        // is gone, so its translations cannot be reached through it any more —
        // but the *records* would outlive it, and a later detach would unmap
        // into a lease that no longer exists.
        self.forget_attachments_to(device);

        let mut holders = 0usize;
        let mut windows = 0usize;
        let wanted = [device];
        for index in 0..crate::process::MAX_PROCESSES {
            let Some(process) = processes.get_mut(index) else {
                continue;
            };
            let mut taken = [(ObjectId::from_raw(0), Rights::from_bits(0)); 1];
            if process.handles_mut().reclaim(&wanted, &mut taken) == 0 {
                continue;
            }
            holders += 1;
            // The window goes with the handle. `unless_held` is still the right
            // test even here: a process may have held two handles to the device
            // and `reclaim` takes them all, so this asks the question after the
            // fact rather than assuming it.
            if process.revoke_device_windows_unless_held(
                device,
                crate::process::WindowRevokeReason::Removed,
            ) {
                windows += 1;
            }
        }

        // **Tell the dependents before the node goes**, because the graph is
        // where the dependency edges live and removing the node takes them
        // with it. A service depending on this device learns from the same
        // `ServiceNotice` the crash ladder uses — the event is different, the
        // delivery is not, and a dependent that had to distinguish "the driver
        // failed" from "the device left" by which mechanism told it would be
        // learning the kernel's internals rather than its own situation.
        let (dependents_told, dependents_missed) =
            self.notify_dependents(device, crate::lifecycle::DriverState::Removed, reason);

        // **`Removed` becomes reachable.** It has been a terminal state with a
        // full table of transitions into it since the driver framework landed,
        // and nothing could ever put a device there, because nothing performed
        // a removal. The `from` is whatever was last recorded — a device may
        // be pulled while active, suspended, or degraded, and every one of
        // those is a legal edge — and `Discovered` when nothing was, which is
        // the only state a lifecycle may open at.
        let from = self
            .lifecycle
            .state_of(device)
            .unwrap_or(crate::lifecycle::DriverState::Discovered);
        let _ = self.declare_lifecycle(
            device,
            from,
            crate::lifecycle::DriverState::Removed,
            reason,
            0,
        );

        let dependents = self.devices.remove(device);
        let known_dependents = dependents
            .map(|list| list.iter().flatten().count())
            .unwrap_or(0);

        crate::event::emit(
            crate::event::EventKind::DeviceRemoved,
            crate::event::Severity::Warning,
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                holders as u64,
                windows as u64,
                known_dependents as u64,
            ],
        );

        RemovalReport {
            existed: dependents.is_some(),
            holders,
            windows,
            dependents_told,
            dependents_missed,
            woken,
            // One node. The subtree total is the caller's to accumulate.
            subtree: usize::from(dependents.is_some()),
        }
    }

    pub fn declare_lifecycle(
        &mut self,
        device: ObjectId,
        from: crate::lifecycle::DriverState,
        to: crate::lifecycle::DriverState,
        reason: crate::lifecycle::TransitionReason,
        detail: u64,
    ) -> Result<(), crate::lifecycle::TransitionError> {
        // **The device tree's half of the rule, checked before the edge
        // table's.** This is the only place that holds both the lifecycle
        // record and the parent edges, which is why it lives here rather than
        // in `crate::lifecycle` — and why the rule itself is a free function
        // there, testable against a list of states with no graph at all.
        //
        // Before the edge check rather than after, so a manager suspending a
        // bus under a live device is told about the device rather than about
        // an edge that was legal all along.
        let mut children = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let count = self.devices.children_of(device, &mut children);
        let mut states = [None; crate::devmgr::MAX_DEVICES];
        for (slot, child) in states.iter_mut().zip(children.iter()).take(count) {
            *slot = self.lifecycle.state_of(*child);
        }
        let parent = self.devices.parent_of(device);
        let parent_state = parent.and_then(|id| self.lifecycle.state_of(id));
        if let Err(block) = crate::lifecycle::neighbours_permit(to, &states[..count], parent_state)
        {
            let (neighbour, state) = match block {
                crate::lifecycle::NeighbourBlock::Child { index, state } => {
                    (children[index], state)
                }
                crate::lifecycle::NeighbourBlock::Parent { state } => {
                    (parent.unwrap_or(device), state)
                }
            };
            return Err(crate::lifecycle::TransitionError::OutOfOrder { neighbour, state });
        }
        self.lifecycle.declare(device, from, to)?;
        let severity = match to {
            crate::lifecycle::DriverState::Failed => crate::event::Severity::Critical,
            crate::lifecycle::DriverState::Degraded => crate::event::Severity::Error,
            crate::lifecycle::DriverState::Removed | crate::lifecycle::DriverState::Resetting => {
                crate::event::Severity::Warning
            }
            _ => crate::event::Severity::Notice,
        };
        crate::event::emit_with_flags(
            crate::event::EventKind::DriverLifecycleTransition,
            severity,
            crate::event::Component::Driver,
            detail,
            [device.raw() as u64, from as u64, to as u64, reason as u64],
        );
        Ok(())
    }

    /// Registers `endpoint` as depending on `device`.
    pub fn device_add_dependent(
        &mut self,
        device: ObjectId,
        endpoint: EndpointId,
    ) -> Result<(), KError> {
        self.devices.add_dependent(device, endpoint)
    }

    /// Tells every service depending on `device` that it is in `state`, for
    /// `reason` — ladder step 4.
    ///
    /// **The notice carries a body, unlike a reclaimed capability.** A
    /// capability arriving from the kernel *is* its own message: only
    /// something that held the device could send it, and the receiver knows
    /// what it means. A notice has no such key — a dependent may depend on
    /// several devices, and "one of yours is in trouble" is not actionable
    /// without saying which — so the kernel fills in a `ServiceNotice` and
    /// sends it. Every field of it is a fact the kernel established, not a
    /// claim forwarded from a process that might be wrong about it.
    ///
    /// Returns `(notified, unreachable)`. Both, because the second is the
    /// interesting one: a dependent that never learns its device is gone waits
    /// on it for ever, and a drop here would be exactly the silence
    /// `docs/lifecycle/04` forbids. The counts go into the record whether or
    /// not anything failed.
    pub fn notify_dependents(
        &mut self,
        device: ObjectId,
        state: crate::lifecycle::DriverState,
        reason: crate::lifecycle::TransitionReason,
    ) -> (usize, usize) {
        let mut endpoints = [EndpointId {
            channel: 0,
            side: 0,
        }; crate::devmgr::MAX_DEPENDENTS];
        let found = self.devices.dependents_of(device, &mut endpoints);
        if found == 0 {
            return (0, 0);
        }
        // A causal origin, for the same reason the lease and route sweeps mint
        // one: this work begins because something outside the running trace
        // happened, and the thread whose cause it would inherit may be gone.
        crate::trace::set_current_correlation(crate::trace::mint());
        let notice = crate::isl_binding::lifecycle::ServiceNotice {
            size: SERVICE_NOTICE_SIZE as u32,
            version: 1,
            flags: 0,
            device: device.raw(),
            state,
            reason,
            reserved: 0,
        };
        let mut body = [0u8; SERVICE_NOTICE_SIZE];
        if tessera_isl_runtime::encode(&notice, &mut body).is_err() {
            // Structurally impossible — the buffer is the wire size — and
            // reported rather than assumed away: an unencodable notice means
            // nobody is told, which must not look like nobody depending.
            return (0, found);
        }
        let (mut sent, mut lost) = (0usize, 0usize);
        for endpoint in endpoints.iter().take(found) {
            let mut message = Message::new(crate::ipc::MessageHeader::new(0, 0));
            if message.set_inline(&body).is_err() || self.send(*endpoint, message).is_err() {
                lost += 1;
                continue;
            }
            sent += 1;
        }
        crate::event::emit(
            crate::event::EventKind::DeviceDependentsNotified,
            if lost > 0 {
                crate::event::Severity::Error
            } else {
                crate::event::Severity::Notice
            },
            crate::event::Component::Driver,
            [device.raw() as u64, sent as u64, lost as u64, state as u64],
        );
        (sent, lost)
    }

    /// Attempts a reset of `device` if `policy` allows — ladder step 5.
    ///
    /// Returns `Ok(false)` when policy declined: not an error, and not a
    /// success either. A declined reset is a rung the ladder deliberately
    /// skipped, and it emits no `DEVICE_RESET` record because none was
    /// attempted — a record there would have a log service reading a reset
    /// that never touched the hardware.
    ///
    /// `Ok(true)` is a device that was reset and came back. `Err` is one the
    /// hardware refused, recorded either way so a reset that does not work is
    /// visible rather than inferred from what happens next.
    pub fn reset_device(
        &mut self,
        device: ObjectId,
        policy: crate::devmgr::ResetPolicy,
        resetter: Option<&mut (dyn crate::devmgr::DeviceResetter + '_)>,
    ) -> Result<bool, KError> {
        if matches!(policy, crate::devmgr::ResetPolicy::Never) {
            return Ok(false);
        }
        // No resetter is a fact about this port, not a reason to pretend the
        // device was reset. The ladder's next rung must know it was not.
        let Some(resetter) = resetter else {
            return Err(KError::NotSupported);
        };
        let identity = self.devices.identity_of_object(device);
        let window = self.devices.mmio_of_object(device);
        let outcome = resetter.reset(device, identity, window);
        crate::event::emit(
            crate::event::EventKind::DeviceReset,
            if outcome.is_ok() {
                crate::event::Severity::Warning
            } else {
                crate::event::Severity::Error
            },
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                outcome.err().map_or(0, |e| e as u64),
                identity.map_or(0, |id| u64::from(id.class_code)),
                policy as u64,
            ],
        );
        outcome.map(|()| true)
    }

    /// Stops offering `device`: policy has decided it is not to be bound
    /// again. Returns whether this changed anything.
    ///
    /// Quarantine is enforced by [`Self::reclaim_devices`] declining to hand
    /// the capability back, which is what makes it a property of the system
    /// rather than a flag a manager is trusted to honour.
    pub fn quarantine_device(&mut self, device: ObjectId, faults: u64, policy: u64) -> bool {
        if !self.devices.quarantine(device) {
            return false;
        }
        crate::event::emit(
            crate::event::EventKind::DeviceQuarantined,
            crate::event::Severity::Critical,
            crate::event::Component::Driver,
            [device.raw() as u64, faults, policy, 0],
        );
        true
    }

    /// Whether policy has stopped offering `device`.
    pub fn is_quarantined(&self, device: ObjectId) -> bool {
        self.devices.is_quarantined(device)
    }

    /// Offers a quarantined device again — the administrative undo.
    pub fn release_from_quarantine(&mut self, device: ObjectId) -> bool {
        self.devices.release_from_quarantine(device)
    }

    /// The lifecycle state recorded for `device`, if any.
    pub fn lifecycle_of_object(&self, device: ObjectId) -> Option<crate::lifecycle::DriverState> {
        self.lifecycle.state_of(device)
    }

    /// Backs `object` with `pages` zeroed frames — the memory object a
    /// caller then maps and hands on.
    pub fn memory_create<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        owner: ObjectId,
        pages: usize,
        space: &crate::vm::AddressSpace<A>,
        alloc: &mut dyn tessera_karch::FrameSource,
    ) -> Result<ObjectId, KError> {
        self.memory.create(owner, pages, space, alloc)
    }

    /// Moves ownership of `object` to `owner` — what a transfer does.
    pub fn memory_set_owner(&mut self, object: ObjectId, owner: ObjectId) -> bool {
        self.memory.set_owner(object, owner)
    }

    /// Who owns `object`, if it is a memory object.
    pub fn memory_owner_of(&self, object: ObjectId) -> Option<ObjectId> {
        self.memory.owner_of(object)
    }

    /// Every memory object `owner` owns, in `out`; returns how many — the
    /// sweep a departing process's teardown walks.
    pub fn memory_objects_owned_by(&self, owner: ObjectId, out: &mut [ObjectId]) -> usize {
        self.memory.objects_owned_by(owner, out)
    }

    /// The frames `object` owns, in `out`; returns how many. Zero means the
    /// capability names something that is not a memory object.
    pub fn memory_frames_of(
        &self,
        object: ObjectId,
        out: &mut [tessera_karch::PhysFrame],
    ) -> usize {
        self.memory.frames_of(object, out)
    }

    /// How many bytes `object` covers, if it is a memory object.
    pub fn memory_len_of(&self, object: ObjectId) -> Option<u64> {
        self.memory.len_of(object)
    }

    /// Drops the object's own reference to its frames — what the last handle
    /// closing must do. Returns how many were released.
    pub fn memory_destroy(
        &mut self,
        object: ObjectId,
        alloc: &mut dyn tessera_karch::FrameSource,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        // **Detach before a single frame moves.** `exec.rs`'s lease rule says
        // it for a whole lease and it is the same window here: between the
        // frames going back to the allocator and the device forgetting the
        // address, a device still holding a translation writes into memory the
        // kernel has already handed to somebody else.
        self.detach_memory(object, iommu);
        self.memory.destroy(object, alloc)
    }

    /// Records that a device can reach `object`. See
    /// [`crate::memory::MemoryTable::attach`].
    pub fn memory_attach(
        &mut self,
        object: ObjectId,
        attachment: crate::memory::Attachment,
    ) -> Result<(), tessera_karch::KError> {
        self.memory.attach(object, attachment)
    }

    /// Where `object` is reachable from, if anywhere.
    pub fn memory_attachment_of(&self, object: ObjectId) -> Option<crate::memory::Attachment> {
        self.memory.attachment_of(object)
    }

    /// The address `object` was last attached at on `device`, for a re-attach
    /// that should land where it landed before.
    pub fn memory_remembered_address(&self, object: ObjectId, device: ObjectId) -> Option<u64> {
        self.memory.remembered_address(object, device)
    }

    /// Ends `object`'s attachment: the device's translation goes away and the
    /// record with it. Returns what the attachment was.
    ///
    /// A scoped attachment with no mapper to hand is the one case that cannot
    /// be honoured, and it **keeps the record** rather than clearing it: a
    /// record that outlives its translation is a leak, and a translation that
    /// outlives its record is a device reaching memory nothing believes it can
    /// reach.
    pub fn detach_memory(
        &mut self,
        object: ObjectId,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> Option<crate::memory::Attachment> {
        let attachment = self.memory.attachment_of(object)?;
        if attachment.scoped {
            let mapper = iommu?;
            if mapper
                .unmap(attachment.device, attachment.address, attachment.len)
                .is_err()
            {
                crate::event::emit(
                    crate::event::EventKind::DeviceDmaUnscoped,
                    crate::event::Severity::Error,
                    crate::event::Component::Driver,
                    [
                        attachment.device.raw() as u64,
                        object.raw() as u64,
                        attachment.address,
                        attachment.len,
                    ],
                );
                return None;
            }
        }
        self.memory.detach(object)
    }

    /// Forgets every attachment to `device` **without unmapping**, for the one
    /// caller where the translations are already gone: the lease has ended, so
    /// there is nothing left to unmap and an `unmap` into a range that may
    /// belong to the next lease is the opposite of safe.
    fn forget_attachments_to(&mut self, device: ObjectId) {
        let mut attached = [ObjectId::from_raw(0); crate::memory::MAX_MEMORY_OBJECTS];
        let found = self.memory.objects_attached_to(device, &mut attached);
        for object in attached.iter().take(found) {
            self.memory.detach(*object);
            // And forget the address, which is the part that outlives a
            // detach. The lease is over, so the whole range belongs to
            // whoever takes the next one — an address remembered across that
            // boundary would be reissued into somebody else's aperture.
            self.memory.forget_last_attachment(*object);
        }
    }

    /// Destroys every memory object `owner` owns, dropping each object's own
    /// reference to its frames. Returns how many objects went.
    ///
    /// **The exit sweep, and it is only half of the reclamation.** The other
    /// half is `AddressSpace::teardown`, which drops the reference each
    /// *mapping* holds. The two are independent and the accounting is
    /// absolute, so they may run in either order — what must not happen is
    /// only one of them running, which is why a process teardown path that
    /// frees an address space without calling this leaks every page of every
    /// buffer that process owned.
    ///
    /// `Process` deliberately forgets its handles on drop (see the invariant
    /// on [`crate::process::Process`], which driver-restart conservation
    /// depends on), so there is no destructor that could do this and there
    /// must not be one.
    pub fn release_memory_of(
        &mut self,
        owner: ObjectId,
        alloc: &mut dyn tessera_karch::FrameSource,
        mut iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        let mut owned = [ObjectId::from_raw(0); crate::memory::MAX_MEMORY_OBJECTS];
        let found = self.memory.objects_owned_by(owner, &mut owned);
        for object in owned.iter().take(found) {
            // Reborrowed per object rather than moved: a dying process may own
            // several attached buffers, and stopping at the first would leave
            // the rest reachable by a device after their frames were freed.
            self.detach_memory(*object, iommu.as_deref_mut());
            self.memory.destroy(*object, alloc);
        }
        found
    }

    /// What a device is, if the kernel learned it during enumeration.
    pub fn identity_of_object(&self, id: ObjectId) -> Option<crate::devmgr::DeviceIdentity> {
        self.devices.identity_of_object(id)
    }

    /// Records where `device`'s configuration structures sit inside its
    /// granted window — what a driver holding only a window cannot discover.
    pub fn device_set_layout(
        &mut self,
        device: ObjectId,
        layout: crate::devmgr::DeviceLayout,
    ) -> Result<(), KError> {
        self.devices.set_layout(device, layout)
    }

    /// Where `device`'s structures are, if the kernel resolved them.
    pub fn layout_of_object(&self, device: ObjectId) -> Option<crate::devmgr::DeviceLayout> {
        self.devices.layout_of_object(device)
    }

    pub fn mmio_of_object(&self, id: ObjectId) -> Option<(u64, u64)> {
        self.devices.mmio_of_object(id)
    }

    /// Preallocates a `(source, signal)` binding slot on `port` (one per pair).
    pub fn port_bind(&mut self, port: PortId, source: u64, signal: u8) -> Result<(), KError> {
        self.ports
            .port_mut(port)
            .ok_or(KError::BadHandle)?
            .bind(source, signal)
    }

    /// Signals `edges` edges on `(source, signal)`, fanning out to every port
    /// bound to it: edges coalesce onto the slot, and a drainer blocked on a
    /// newly-asserted port is woken (asynchronously — no handoff). Returns the
    /// number of ports the signal was delivered to.
    pub fn port_signal(&mut self, source: u64, signal: u8, edges: u32) -> usize {
        let mut delivered = 0;
        for i in 0..MAX_PORTS {
            // Take the drainer to wake out of the port borrow before touching
            // the scheduler (one `&mut self` field at a time).
            let wake = match self.ports.port_mut_at(i) {
                Some(port) => {
                    if port.deliver(source, signal, edges) {
                        delivered += 1;
                        port.take_blocked_drainer()
                    } else {
                        None
                    }
                }
                None => None,
            };
            if let Some(thread) = wake {
                self.sched.unblock(thread);
            }
        }
        delivered
    }

    /// Drains one coalesced event from `port`, blocking until one is available.
    /// A drain reads current state (the coalesced pending count), mirroring
    /// `receive`'s park-and-retry.
    pub fn port_wait(&mut self, port: PortId) -> Result<PortEvent, KError> {
        loop {
            if let Some(event) = self.ports.port_mut(port).ok_or(KError::BadHandle)?.drain() {
                return Ok(event);
            }
            let me = self.sched.current().ok_or(KError::BadHandle)?;
            if let Some(p) = self.ports.port_mut(port) {
                p.set_blocked_drainer(Some(me));
            }
            self.sched.block_current();
        }
    }

    /// The coalescing count observed on `port` (observability).
    pub fn port_coalesced(&self, port: PortId) -> u64 {
        self.ports.port(port).map(|p| p.coalesced()).unwrap_or(0)
    }

    /// Creates a root job (boot authority; no right required).
    pub fn job_create_root(
        &mut self,
        object: ObjectId,
        limits: JobLimits,
    ) -> Result<JobId, KError> {
        self.jobs.create_root(object, limits)
    }

    /// Creates a child job under `parent` (needs `CREATE_JOB`; tighten-only).
    pub fn job_create_child(
        &mut self,
        parent: JobId,
        object: ObjectId,
        limits: JobLimits,
        rights: Rights,
    ) -> Result<JobId, KError> {
        self.jobs.create_child(parent, object, limits, rights)
    }

    /// Reads a job (for its state source, member count, killed flag).
    pub fn job(&self, id: JobId) -> Option<&Job> {
        self.jobs.job(id)
    }

    /// Adds a member process (needs `CREATE_PROCESS`; enforces the count cap).
    pub fn job_add_process(
        &mut self,
        job: JobId,
        member: Member,
        rights: Rights,
    ) -> Result<(), KError> {
        self.jobs.add_process(job, member, rights)
    }

    /// Kills the `root` subtree (needs `KILL`): terminates every member thread
    /// and signals each job's state port with `member-exit` per member and
    /// `emptiness` once its members are gone, **innermost-first**. The killed
    /// member process ids are written to `killed_out` (up to its length) and the
    /// count returned, so the caller can mark those processes exited and release
    /// their object references (the object/process lifecycle it owns).
    pub fn job_kill(
        &mut self,
        root: JobId,
        rights: Rights,
        killed_out: &mut [Option<ObjectId>],
    ) -> Result<usize, KError> {
        let mut order: [Option<JobId>; MAX_JOBS] = [None; MAX_JOBS];
        let count = self.jobs.kill_order(root, rights, &mut order)?;
        let mut killed = 0;
        for slot in order.iter().take(count) {
            let Some(job_id) = slot else { continue };
            // Copy what the kill needs out of the table borrow before touching
            // the scheduler and ports.
            let (state_source, members) = match self.jobs.job(*job_id) {
                Some(job) => (job.state_source(), job.members()),
                None => continue,
            };
            for member in members.iter().flatten() {
                self.sched.terminate(member.thread);
                if killed < killed_out.len() {
                    killed_out[killed] = Some(member.process);
                }
                killed += 1;
                self.port_signal(state_source, SIGNAL_MEMBER_EXIT, 1);
            }
            // The job is now empty — signal it for a supervisor to reclaim.
            self.port_signal(state_source, SIGNAL_EMPTY, 1);
        }
        Ok(killed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{Message, MessageHeader};
    use crate::thread::{Thread, ThreadId, ThreadState};
    use crate::vm::{AddressSpace, Asid};
    use tessera_karch::VirtAddr;
    use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

    extern "C" fn never(_: usize) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    fn vm() -> AddressSpace<MockAddressSpace> {
        let mut frames = MockFrameSource::new(0x1000_0000, 64);
        AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0))
            .expect("vm")
    }

    fn spawn(
        exec: &mut Executive<MockContextOps>,
        space: &mut AddressSpace<MockAddressSpace>,
        id: u64,
    ) -> usize {
        let mut frames = MockFrameSource::new(0x10_0000 + id * 0x10_0000, 64);
        let base = 0xffff_e000_0000_0000 + id * 0x10_0000;
        let t = Thread::<MockContextOps>::spawn(
            ThreadId(id),
            never,
            id as usize,
            VirtAddr::new(base),
            2,
            space,
            &mut frames,
        )
        .expect("spawn");
        exec.add_thread(t).expect("add")
    }

    fn msg(body: &[u8]) -> Message {
        let mut m = Message::new(MessageHeader::new(0x1, 1));
        m.set_inline(body).unwrap();
        m
    }

    // --- DMA faults, isolation, and interrupt routes -----------------------

    /// A device that translates and records every lease it was told to end,
    /// so a test can tell a lease the graph merely forgot from one whose
    /// translations actually came down.
    #[derive(Default)]
    struct FaultMapper {
        ended: std::vec::Vec<ObjectId>,
    }

    impl crate::devmgr::DmaMapper for FaultMapper {
        fn translates(&self, _device: ObjectId) -> bool {
            true
        }

        fn begin_lease(&mut self, _device: ObjectId) -> Result<(u64, u64), KError> {
            Ok((0x1_0000, 0x2000))
        }

        fn map(&mut self, _: ObjectId, _: u64, _: u64, _: u64) -> Result<(), KError> {
            Ok(())
        }

        fn unmap(&mut self, _: ObjectId, _: u64, _: u64) -> Result<(), KError> {
            Ok(())
        }

        fn end_lease(&mut self, device: ObjectId) {
            self.ended.push(device);
        }
    }

    /// An interrupt controller recording every line it was told to stop
    /// delivering — the only way to tell revocation from bookkeeping.
    #[derive(Default)]
    struct CountingRouter {
        masked: std::vec::Vec<u32>,
    }

    impl InterruptRouter for CountingRouter {
        fn mask(&mut self, intid: u32) {
            self.masked.push(intid);
        }
    }

    const FAULTING_DEVICE: ObjectId = ObjectId::from_raw(0x31);
    const DRIVER: ObjectId = ObjectId::from_raw(0x32);

    /// An executive holding one MMIO device with an INTID and a live lease.
    fn leased() -> Executive<MockContextOps> {
        let mut exec = Executive::<MockContextOps>::new(1, 0);
        exec.device_register_mmio(FAULTING_DEVICE, 0x0a00_0000, 0x1000, Rights::READ)
            .expect("register");
        exec.device_set_mmio_irq(FAULTING_DEVICE, 79).expect("irq");
        exec.device_set_aperture(
            FAULTING_DEVICE,
            DRIVER,
            crate::devmgr::DeviceAperture::new(0x1_0000, 0x2000),
            None,
        )
        .expect("aperture");
        exec
    }

    fn fault(device: Option<ObjectId>) -> DmaFault {
        DmaFault {
            device,
            stream: 0x10,
            address: 0x20_0000,
            kind: crate::devmgr::DmaFaultKind::Unmapped,
        }
    }

    /// A device that resets, and a resetter that refuses.
    #[derive(Default)]
    struct MockResetter {
        reset: std::vec::Vec<ObjectId>,
        refuses: bool,
    }

    impl crate::devmgr::DeviceResetter for MockResetter {
        fn reset(
            &mut self,
            device: ObjectId,
            _identity: Option<crate::devmgr::DeviceIdentity>,
            _window: Option<(u64, u64)>,
        ) -> Result<(), KError> {
            if self.refuses {
                return Err(KError::NotSupported);
            }
            self.reset.push(device);
            Ok(())
        }
    }

    /// Ladder step 4: the services depending on a device are told when its
    /// driver fails, and the notice says *which* device — a dependent may
    /// depend on several, and "one of yours is in trouble" is not actionable.
    #[test]
    fn dependents_are_notified_with_a_body_that_names_the_device() {
        let mut exec = leased();
        let (a_server, a_client) = exec.channel_create().expect("a");
        let (b_server, b_client) = exec.channel_create().expect("b");
        exec.device_add_dependent(FAULTING_DEVICE, a_server)
            .expect("a depends");
        exec.device_add_dependent(FAULTING_DEVICE, b_server)
            .expect("b depends");

        let (sent, lost) = exec.notify_dependents(
            FAULTING_DEVICE,
            crate::lifecycle::DriverState::Degraded,
            crate::lifecycle::TransitionReason::DriverCrashed,
        );
        assert_eq!((sent, lost), (2, 0));

        // Each dependent has a message waiting, and it decodes to a notice
        // naming this device and the state it is in.
        for client in [a_client, b_client] {
            let message = exec.receive(client).expect("a notice arrived");
            let notice: crate::isl_binding::lifecycle::ServiceNotice =
                tessera_isl_runtime::decode(message.inline()).expect("decodes");
            assert_eq!(notice.device, FAULTING_DEVICE.raw());
            assert_eq!(notice.state, crate::lifecycle::DriverState::Degraded);
            assert_eq!(
                notice.reason,
                crate::lifecycle::TransitionReason::DriverCrashed
            );
        }
    }

    /// A device nobody depends on notifies nobody, and says so as zero rather
    /// than as an error — having no dependents is an ordinary state.
    #[test]
    fn a_device_with_no_dependents_notifies_nobody() {
        let mut exec = leased();
        assert_eq!(
            exec.notify_dependents(
                FAULTING_DEVICE,
                crate::lifecycle::DriverState::Degraded,
                crate::lifecycle::TransitionReason::DriverCrashed,
            ),
            (0, 0),
        );
    }

    /// Registering twice is idempotent: a service that reconnects should not
    /// have to remember whether it already registered, and a second entry
    /// would have it notified twice for one failure.
    #[test]
    fn a_duplicate_dependency_does_not_double_the_notifications() {
        let mut exec = leased();
        let (server, _client) = exec.channel_create().expect("channel");
        exec.device_add_dependent(FAULTING_DEVICE, server)
            .expect("once");
        exec.device_add_dependent(FAULTING_DEVICE, server)
            .expect("twice");
        assert_eq!(
            exec.notify_dependents(
                FAULTING_DEVICE,
                crate::lifecycle::DriverState::Degraded,
                crate::lifecycle::TransitionReason::DriverCrashed,
            ),
            (1, 0),
        );
    }

    /// Ladder step 5. A declined reset is not a failed one: it emits no record
    /// because nothing was attempted, and a record there would have a log
    /// service reading a reset that never touched the hardware.
    #[test]
    fn a_reset_happens_only_when_policy_allows_it() {
        let mut exec = leased();
        let mut resetter = MockResetter::default();
        assert_eq!(
            exec.reset_device(
                FAULTING_DEVICE,
                crate::devmgr::ResetPolicy::Never,
                Some(&mut resetter),
            ),
            Ok(false),
        );
        assert!(resetter.reset.is_empty(), "nothing was touched");

        assert_eq!(
            exec.reset_device(
                FAULTING_DEVICE,
                crate::devmgr::ResetPolicy::OnDegraded,
                Some(&mut resetter),
            ),
            Ok(true),
        );
        assert_eq!(resetter.reset, std::vec![FAULTING_DEVICE]);
    }

    /// A port with no resetter cannot reset, and says so. Returning success
    /// would have the ladder's next rung taken on the premise that a device
    /// nothing touched had been reset.
    #[test]
    fn a_port_with_no_resetter_refuses_rather_than_pretending() {
        let mut exec = leased();
        assert_eq!(
            exec.reset_device(
                FAULTING_DEVICE,
                crate::devmgr::ResetPolicy::OnDegraded,
                None
            ),
            Err(KError::NotSupported),
        );
        // And hardware that refuses is reported as refusing.
        let mut resetter = MockResetter {
            refuses: true,
            ..MockResetter::default()
        };
        assert_eq!(
            exec.reset_device(
                FAULTING_DEVICE,
                crate::devmgr::ResetPolicy::OnDegraded,
                Some(&mut resetter),
            ),
            Err(KError::NotSupported),
        );
    }

    /// Quarantine is **enforced**, not advertised: the manager never receives
    /// the capability, so nothing can bind the device again — not because a
    /// manager chooses not to, but because it has nothing to bind.
    #[test]
    fn a_quarantined_device_is_not_handed_back_to_its_manager() {
        let mut exec = leased();
        let (manager, _peer) = exec.channel_create().expect("channel");
        let mut frames = MockFrameSource::new(0x2000_0000, 32);
        let space =
            AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(3))
                .expect("space");
        let mut driver = crate::process::Process::new(ObjectId::from_raw(0x88), space);
        driver
            .handles_mut()
            .install(FAULTING_DEVICE, Rights::READ | Rights::MAP)
            .expect("install");

        assert!(exec.quarantine_device(FAULTING_DEVICE, 4, 4));
        assert!(exec.is_quarantined(FAULTING_DEVICE));
        // A second quarantine changes nothing and records nothing.
        assert!(!exec.quarantine_device(FAULTING_DEVICE, 4, 4));

        assert_eq!(
            exec.reclaim_devices(&mut driver, manager, None, None),
            1,
            "the capability still leaves the corpse",
        );
        assert!(
            exec.receive(manager).is_err(),
            "but it is not offered to the manager",
        );
    }

    /// Quarantine is reversible only by an administrator. A device that could
    /// take itself out of quarantine is not quarantined.
    #[test]
    fn quarantine_is_undone_only_deliberately() {
        let mut exec = leased();
        assert!(exec.quarantine_device(FAULTING_DEVICE, 4, 4));
        assert!(exec.release_from_quarantine(FAULTING_DEVICE));
        assert!(!exec.is_quarantined(FAULTING_DEVICE));
        // Releasing one that is not quarantined changes nothing.
        assert!(!exec.release_from_quarantine(FAULTING_DEVICE));
    }

    /// The default policy changes nothing. That is the point of it being a
    /// policy: a machine still being brought up wants every fault recorded and
    /// nothing torn down, and isolating on the first one would hide the rest.
    #[test]
    fn the_report_policy_isolates_nothing() {
        let mut exec = leased();
        let mut mapper = FaultMapper::default();
        let outcome = exec.isolate_dma_fault(
            fault(Some(FAULTING_DEVICE)),
            IsolationPolicy::Report,
            Some(&mut mapper),
        );
        assert!(!outcome.isolated);
        assert_eq!(outcome.stop, None);
        assert_eq!(
            exec.lease_holder_of_object(FAULTING_DEVICE),
            Some(DRIVER),
            "the lease is untouched",
        );
        assert!(mapper.ended.is_empty(), "and so is the hardware");
    }

    /// Isolation is a strictly larger action than the hardware already took:
    /// the unit refused one address, this makes the device reach nothing.
    #[test]
    fn isolating_a_fault_ends_the_lease_in_the_graph_and_the_hardware() {
        let mut exec = leased();
        let mut mapper = FaultMapper::default();
        let outcome = exec.isolate_dma_fault(
            fault(Some(FAULTING_DEVICE)),
            IsolationPolicy::EndLease,
            Some(&mut mapper),
        );
        assert!(outcome.isolated);
        assert_eq!(exec.lease_holder_of_object(FAULTING_DEVICE), None);
        assert_eq!(exec.aperture_of_object(FAULTING_DEVICE), None);
        assert_eq!(
            mapper.ended,
            std::vec![FAULTING_DEVICE],
            "the translations came down, not just the record",
        );
        // Ending the lease is not the same as stopping the driver, and this
        // policy asks only for the first.
        assert_eq!(outcome.stop, None);
    }

    /// The stronger policy names the holder for a supervisor to stop. It names
    /// it rather than doing it because this type has no scheduler and no frame
    /// allocator — and a caller that ignores the answer has not applied the
    /// policy, which is why the outcome is `#[must_use]`.
    #[test]
    fn the_stopping_policy_names_the_holder_it_wants_stopped() {
        let mut exec = leased();
        let mut mapper = FaultMapper::default();
        let outcome = exec.isolate_dma_fault(
            fault(Some(FAULTING_DEVICE)),
            IsolationPolicy::EndLeaseAndStop,
            Some(&mut mapper),
        );
        assert!(outcome.isolated);
        assert_eq!(outcome.stop, Some(DRIVER));
    }

    /// A fault the port could not attribute to a device has nothing to
    /// isolate. Acting on it would mean picking a victim, and reporting that
    /// something was isolated when nothing was is the silent-degradation
    /// failure the outcome exists to prevent.
    #[test]
    fn an_unattributed_fault_isolates_nobody() {
        let mut exec = leased();
        let mut mapper = FaultMapper::default();
        let outcome =
            exec.isolate_dma_fault(fault(None), IsolationPolicy::EndLease, Some(&mut mapper));
        assert!(!outcome.isolated);
        assert_eq!(outcome.stop, None);
        assert_eq!(exec.lease_holder_of_object(FAULTING_DEVICE), Some(DRIVER));
        assert!(mapper.ended.is_empty());
    }

    /// A device that faults while nobody holds a lease on it: the wiring is
    /// wrong, and there is no driver to isolate. Reporting isolation here
    /// would be reporting an action that did not happen.
    #[test]
    fn a_fault_from_an_unleased_device_isolates_nothing() {
        let mut exec = Executive::<MockContextOps>::new(1, 0);
        exec.device_register_mmio(FAULTING_DEVICE, 0x0a00_0000, 0x1000, Rights::READ)
            .expect("register");
        let mut mapper = FaultMapper::default();
        let outcome = exec.isolate_dma_fault(
            fault(Some(FAULTING_DEVICE)),
            IsolationPolicy::EndLeaseAndStop,
            Some(&mut mapper),
        );
        assert!(!outcome.isolated);
        assert_eq!(outcome.stop, None);
        assert!(mapper.ended.is_empty());
    }

    /// A route is only a route once both halves exist: the graph knows who
    /// receives it, and the port is bound to the line so a signal lands.
    #[test]
    fn routing_an_interrupt_binds_the_port_to_the_devices_own_line() {
        let mut exec = leased();
        let port = exec.port_create().expect("port");
        exec.device_route_irq(FAULTING_DEVICE, port, DRIVER)
            .expect("route");
        let route = exec.irq_route_of_object(FAULTING_DEVICE).expect("routed");
        assert_eq!(route.intid, 79, "the line comes from the graph");
        assert_eq!(route.holder, DRIVER);

        // And the binding delivers: a signal on that line wakes exactly this
        // port. Without the bind the route would be a record of nothing.
        assert_eq!(exec.port_signal(79, IRQ_PORT_SIGNAL, 1), 1);
        assert_eq!(
            exec.port_wait(port).expect("event").pending,
            1,
            "the edge arrived",
        );
    }

    /// A device with no line wired is refused rather than recorded. Routing
    /// interrupts that cannot arrive would make the graph describe a delivery
    /// path nothing can use.
    #[test]
    fn a_device_with_no_interrupt_cannot_be_routed() {
        let mut exec = Executive::<MockContextOps>::new(1, 0);
        exec.device_register_mmio(FAULTING_DEVICE, 0x0a00_0000, 0x1000, Rights::READ)
            .expect("register");
        let port = exec.port_create().expect("port");
        assert_eq!(
            exec.device_route_irq(FAULTING_DEVICE, port, DRIVER),
            Err(KError::InvalidMapping),
        );
        assert_eq!(exec.irq_route_of_object(FAULTING_DEVICE), None);
    }

    /// Revocation is all three halves or none: the graph forgets, the
    /// controller stops delivering, and the port binding goes.
    ///
    /// The port binding matters as much as the mask. A route left bound would
    /// have the *next* holder of that port receive edges attributed to a
    /// device it was never given.
    #[test]
    fn revoking_a_route_masks_the_line_and_unbinds_the_port() {
        let mut exec = leased();
        let port = exec.port_create().expect("port");
        exec.device_route_irq(FAULTING_DEVICE, port, DRIVER)
            .expect("route");
        let mut router = CountingRouter::default();

        assert!(exec.end_device_irq_route(
            DRIVER,
            FAULTING_DEVICE,
            RouteEndReason::Transferred,
            Some(&mut router),
        ));
        assert_eq!(exec.irq_route_of_object(FAULTING_DEVICE), None);
        assert_eq!(router.masked, std::vec![79], "the controller was told");
        // Nothing is delivered any more, so nothing arrives at the port.
        assert_eq!(exec.port_signal(79, IRQ_PORT_SIGNAL, 1), 0);
        // And the slot was released rather than merely left unasserted: the
        // same pair binds again, which a still-occupied slot would refuse.
        // That is the difference between the route being gone and the route
        // being quiet.
        assert!(exec.port_bind(port, 79, IRQ_PORT_SIGNAL).is_ok());
    }

    /// A process that duplicated its capability and gave one copy away keeps
    /// the authority — and must keep its interrupts. Revoking on the *other*
    /// holder's departure would take away a route from a driver that did
    /// nothing wrong, which is the exact case
    /// `revoke_device_windows_unless_held` guards for register windows.
    #[test]
    fn a_route_is_not_revoked_by_someone_who_does_not_hold_it() {
        let mut exec = leased();
        let port = exec.port_create().expect("port");
        exec.device_route_irq(FAULTING_DEVICE, port, DRIVER)
            .expect("route");
        let mut router = CountingRouter::default();

        assert!(!exec.end_device_irq_route(
            ObjectId::from_raw(0xdead),
            FAULTING_DEVICE,
            RouteEndReason::Transferred,
            Some(&mut router),
        ));
        assert!(exec.irq_route_of_object(FAULTING_DEVICE).is_some());
        assert!(router.masked.is_empty());
    }

    /// Ending a route that was never taken is a no-op, so the departure paths
    /// need not first ask whether there was one.
    #[test]
    fn ending_a_route_that_was_never_taken_is_harmless() {
        let mut exec = leased();
        let mut router = CountingRouter::default();
        assert!(!exec.end_device_irq_route(
            DRIVER,
            FAULTING_DEVICE,
            RouteEndReason::HandleClosed,
            Some(&mut router),
        ));
        assert!(!exec.end_device_irq_route(
            DRIVER,
            ObjectId::from_raw(0x99),
            RouteEndReason::HandleClosed,
            Some(&mut router),
        ));
        assert!(router.masked.is_empty());
    }

    #[test]
    fn channel_create_and_async_send_delivers_to_peer() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let (a, b) = exec.channel_create().unwrap();
        // Async send from a is queued on b's endpoint and can be received.
        exec.send(a, msg(b"hi")).unwrap();
        // Receiving on b (no current thread needed since a message is queued).
        let mut space = vm();
        let _ = spawn(&mut exec, &mut space, 0);
        exec.run(); // current = thread 0
        let got = exec.receive(b).unwrap();
        assert_eq!(got.inline(), b"hi");
    }

    #[test]
    fn endpoint_objects_bridge_back_to_their_endpoints() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let (a, b) = exec.channel_create().unwrap();
        let oa = ObjectId::from_raw(0x0a);
        let ob = ObjectId::from_raw(0x0b);
        exec.bind_endpoint_object(a, oa);
        exec.bind_endpoint_object(b, ob);
        assert_eq!(exec.endpoint_of_object(oa), Some(a));
        assert_eq!(exec.endpoint_of_object(ob), Some(b));
        assert_eq!(exec.endpoint_of_object(ObjectId::from_raw(0xff)), None);
    }

    #[test]
    fn reply_and_continue_leaves_the_server_runnable() {
        // The D85 regression: `reply` blocks the replier as part of its
        // handoff, which strands a server whose next wake comes from a port
        // rather than from the next call on this endpoint. The select loop's
        // reply must ready the caller and leave the server Ready.
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let server = spawn(&mut exec, &mut space, 0);
        let client = spawn(&mut exec, &mut space, 1);
        exec.run(); // current = server

        let (server_end, client_end) = exec.channel_create().unwrap();

        // The client parked mid-`call` awaiting its reply; the server is
        // current, exactly as it is when the select loop finishes a read.
        exec.send(client_end, msg(b"req")).unwrap();
        exec.channels
            .channel_mut(client_end.channel)
            .unwrap()
            .endpoint_mut(client_end.side)
            .set_pending_caller(Some((client, 7)));
        exec.scheduler().handoff_to(client); // client current…
        exec.scheduler().handoff_to(server); // …then Blocked; server current

        exec.reply_and_continue(server_end, msg(b"rep"))
            .expect("reply");

        assert_eq!(
            exec.scheduler().thread_state(server),
            Some(ThreadState::Running),
            "the server keeps running — a blocked one would never re-select"
        );
        assert_eq!(
            exec.scheduler().thread_state(client),
            Some(ThreadState::Ready),
            "the caller is readied, not handed off to"
        );
    }

    #[test]
    fn a_message_arrival_signals_the_destination_endpoints_port() {
        // The select plumbing (D85): a port bound to (endpoint object,
        // SIGNAL_MESSAGE) is asserted when a message lands on that endpoint,
        // and the drained event names WHICH endpoint — so a server with
        // per-client channels learns where the work is.
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let server = spawn(&mut exec, &mut space, 0);
        let _client = spawn(&mut exec, &mut space, 1);
        exec.run(); // current = server

        let (client_a, server_a) = exec.channel_create().unwrap();
        let (client_b, server_b) = exec.channel_create().unwrap();
        let a_obj = ObjectId::from_raw(50);
        let b_obj = ObjectId::from_raw(52);
        exec.bind_endpoint_object(server_a, a_obj);
        exec.bind_endpoint_object(server_b, b_obj);

        let port = exec.port_create().unwrap();
        exec.port_bind(port, u64::from(a_obj.raw()), crate::ipc::SIGNAL_MESSAGE)
            .unwrap();
        exec.port_bind(port, u64::from(b_obj.raw()), crate::ipc::SIGNAL_MESSAGE)
            .unwrap();

        // An arrival on B's endpoint asserts B's binding only.
        exec.send(client_b, msg(b"to-b")).unwrap();
        let event = exec.port_wait(port).expect("event");
        assert_eq!(event.source, u64::from(b_obj.raw()));
        assert_eq!(event.signal, crate::ipc::SIGNAL_MESSAGE);
        assert_eq!(event.pending, 1);
        let _ = (client_a, server);
    }

    #[test]
    fn an_unbound_endpoint_arrival_signals_nothing() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let _t = spawn(&mut exec, &mut space, 0);
        exec.run();
        let (client, server_end) = exec.channel_create().unwrap();
        // No object bound to the server end, and a port watching some other
        // source: the send must not assert it.
        let port = exec.port_create().unwrap();
        exec.port_bind(port, 0x9999, crate::ipc::SIGNAL_MESSAGE)
            .unwrap();
        exec.send(client, msg(b"x")).unwrap();
        assert_eq!(exec.port_coalesced(port), 0);
        // Draining yields nothing (no binding asserted).
        let _ = server_end;
    }

    #[test]
    fn reply_receive_with_a_queued_request_wakes_the_replied_caller() {
        // The immediate-dequeue path: the next request is already queued when
        // the server replies, so the server keeps running — the just-replied
        // caller must be WOKEN, not left Blocked with its reply queued (found
        // by D84's interrupt-driven serving, where a second client's request
        // queues while the server waits on its device).
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let server = spawn(&mut exec, &mut space, 0);
        let caller = spawn(&mut exec, &mut space, 1);
        let (server_end, caller_end) = exec.channel_create().unwrap();
        exec.run(); // current = server

        // Simulate the caller parked mid-`call` awaiting its reply, with the
        // NEXT request already queued on the server end.
        exec.send(caller_end, msg(b"req1")).unwrap();
        exec.channels
            .channel_mut(caller_end.channel)
            .unwrap()
            .endpoint_mut(caller_end.side)
            .set_pending_caller(Some((caller, 7)));
        exec.scheduler().handoff_to(caller); // caller current…
        exec.scheduler().handoff_to(server); // …then Blocked; server current

        let next = exec
            .reply_receive(server_end, msg(b"reply"))
            .expect("immediate dequeue");
        assert_eq!(next.inline(), b"req1");
        // The replied caller is runnable again, its reply queued for pickup.
        assert_eq!(
            exec.scheduler().thread_state(caller),
            Some(ThreadState::Ready)
        );
        let _ = server;
    }

    #[test]
    fn send_wakes_a_blocked_receiver() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let receiver = spawn(&mut exec, &mut space, 0);
        let _sender = spawn(&mut exec, &mut space, 1);
        let (a, b) = exec.channel_create().unwrap();
        exec.run(); // current = receiver

        // Simulate the receiver having parked on b: mark it blocked_receiver and
        // Blocked (as `receive` would).
        exec.channels
            .channel_mut(b.channel)
            .unwrap()
            .endpoint_mut(b.side)
            .set_blocked_receiver(Some(receiver));
        exec.scheduler().unblock(receiver); // put back to a known Ready baseline
        // A send on a must wake the parked receiver on b.
        exec.send(a, msg(b"x")).unwrap();
        assert_eq!(
            exec.scheduler().thread_state(receiver),
            Some(ThreadState::Ready)
        );
        assert!(
            exec.channels
                .channel(b.channel)
                .unwrap()
                .endpoint(b.side)
                .blocked_receiver()
                .is_none()
        );
    }

    #[test]
    fn a_synchronous_call_restores_the_callees_own_correlation_id() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let caller = spawn(&mut exec, &mut space, 0);
        let callee = spawn(&mut exec, &mut space, 1);
        let (a, b) = exec.channel_create().unwrap();
        exec.run(); // current = caller

        // Distinct ids so an adopted one is distinguishable from the restored one.
        exec.scheduler().set_thread_correlation(caller, 0xca11e7);
        exec.scheduler().set_thread_correlation(callee, 0x5efbe7);

        // Park the callee as b's receiver so `call` takes the handoff path.
        exec.channels
            .channel_mut(b.channel)
            .unwrap()
            .endpoint_mut(b.side)
            .set_blocked_receiver(Some(callee));

        // The mock's `switch` is a no-op, so the callee never actually runs and
        // the call unwinds to `PeerClosed` — which is exactly the path that must
        // still restore. (That the callee *observes* the caller's id while it
        // runs is proven on target by the `correlation` boot demo, where a real
        // switch happens.)
        let _ = exec.call(a, msg(b"q"));

        assert_eq!(
            exec.scheduler().thread_correlation(callee),
            Some(0x5efbe7),
            "a server must not keep the last caller's id, or every event it \
             emits afterwards is misattributed"
        );
        assert_eq!(exec.scheduler().thread_correlation(caller), Some(0xca11e7));
        assert_eq!(
            exec.saved_correlation[callee], 0,
            "the save slot is released"
        );
    }

    #[test]
    fn an_async_send_carries_the_senders_cause_to_the_receiver() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let sender = spawn(&mut exec, &mut space, 0);
        let receiver = spawn(&mut exec, &mut space, 1);
        let (a, b) = exec.channel_create().unwrap();
        exec.run(); // current = sender

        // The sender is the origin of this work; the receiver has its own id.
        exec.scheduler().set_thread_correlation(sender, 0xd00d);
        exec.scheduler().set_thread_correlation(receiver, 0xbeef);

        // Async send: no handoff, so the id can only travel in the message.
        exec.send(a, msg(b"x")).unwrap();

        // Make the receiver current, then take delivery. (`handoff_to` moves
        // `current` even under the mock, whose register switch is a no-op.)
        exec.scheduler().handoff_to(receiver);
        let got = exec.receive(b).expect("receive");

        // The id rode the header across the boundary...
        assert_eq!(got.header().correlation, 0xd00d);
        // ...and was adopted as the receiver started handling it.
        assert_eq!(
            exec.scheduler().thread_correlation(receiver),
            Some(0xd00d),
            "handling an async request belongs to the cause that sent it"
        );
    }

    #[test]
    fn an_uncorrelated_message_does_not_erase_the_receivers_cause() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let receiver = spawn(&mut exec, &mut space, 0);
        let (a, b) = exec.channel_create().unwrap();
        exec.run(); // current = receiver

        // A message from a sender with no cause recorded (id 0).
        exec.scheduler().set_thread_correlation(receiver, 0);
        exec.send(a, msg(b"x")).unwrap();
        exec.scheduler().set_thread_correlation(receiver, 0xabc);

        exec.receive(b).expect("receive");
        assert_eq!(
            exec.scheduler().thread_correlation(receiver),
            Some(0xabc),
            "adopting 0 would erase a good id rather than inherit a real one"
        );
    }

    #[test]
    fn a_spawned_thread_gets_a_fresh_id_rather_than_its_parents() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let parent = spawn(&mut exec, &mut space, 0);
        let child = spawn(&mut exec, &mut space, 1);

        let (parent_id, child_id) = (
            exec.scheduler().thread_correlation(parent).expect("parent"),
            exec.scheduler().thread_correlation(child).expect("child"),
        );
        // Fan-out links, not shared ids: each branch is separately identifiable.
        assert_ne!(parent_id, 0);
        assert_ne!(child_id, 0);
        assert_ne!(parent_id, child_id);
    }

    #[test]
    fn oversize_and_full_queue_are_rejected_by_send() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let (a, _b) = exec.channel_create().unwrap();
        // Fill the peer queue.
        for _ in 0..crate::ipc::QUEUE_CAP {
            exec.send(a, msg(b"m")).unwrap();
        }
        assert_eq!(exec.send(a, msg(b"m")), Err(KError::WouldBlock));
    }

    #[test]
    fn call_without_a_running_thread_is_rejected() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let (a, _b) = exec.channel_create().unwrap();
        // No thread is current (run not called), so `call` has no caller.
        assert_eq!(exec.call(a, msg(b"q")).map(|_| ()), Err(KError::BadHandle));
    }

    #[test]
    fn wake_wakes_a_blocked_waiter_and_consumes_it() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let waiter = spawn(&mut exec, &mut space, 0);
        let _other = spawn(&mut exec, &mut space, 1);
        exec.run(); // current = waiter

        // Enroll the waiter as `wait_on_address(space=0, addr=0x1000)` would,
        // then set a known Ready baseline (mirrors `send_wakes_a_blocked_receiver`,
        // avoiding the mock's no-op context switch).
        exec.waits
            .enroll(
                WaitKey {
                    space: 0,
                    addr: 0x1000,
                },
                waiter,
            )
            .expect("enroll");
        exec.scheduler().unblock(waiter);

        // A wake on the same key wakes exactly the one waiter.
        assert_eq!(exec.wake(0, 0x1000, 1), 1);
        assert_eq!(
            exec.scheduler().thread_state(waiter),
            Some(ThreadState::Ready)
        );
        // The enrollment is consumed: a second wake finds nothing.
        assert_eq!(exec.wake(0, 0x1000, 1), 0);
        assert!(exec.waits.is_empty());
    }

    #[test]
    fn wake_on_a_different_key_does_not_wake() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let waiter = spawn(&mut exec, &mut space, 0);
        exec.run();
        exec.waits
            .enroll(
                WaitKey {
                    space: 0,
                    addr: 0x1000,
                },
                waiter,
            )
            .expect("enroll");
        // Wrong address and wrong space each miss.
        assert_eq!(exec.wake(0, 0x2000, u32::MAX), 0);
        assert_eq!(exec.wake(0xbeef, 0x1000, u32::MAX), 0);
        assert_eq!(exec.waits.len(), 1);
    }

    #[test]
    fn port_signal_wakes_a_blocked_drainer() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let drainer = spawn(&mut exec, &mut space, 0);
        let _other = spawn(&mut exec, &mut space, 1);
        exec.run(); // current = drainer

        let port = exec.port_create().expect("create");
        exec.port_bind(port, 0x5011, 1).expect("bind");
        // Enroll the drainer as a blocked drainer (as `port_wait` on an empty
        // port would), then a known Ready baseline (avoids the mock's no-op
        // switch inside block_current).
        exec.ports
            .port_mut(port)
            .expect("port")
            .set_blocked_drainer(Some(drainer));
        exec.scheduler().unblock(drainer);

        // A signal on the bound source delivers and wakes the drainer.
        assert_eq!(exec.port_signal(0x5011, 1, 2), 1);
        assert_eq!(
            exec.scheduler().thread_state(drainer),
            Some(ThreadState::Ready)
        );
        // The event is queued with its coalesced count; draining reads it.
        assert_eq!(exec.port_wait(port).map(|e| e.pending), Ok(2));
    }

    /// **A driver parked on a device's interrupt is woken when the device
    /// leaves**, and can tell that is what happened.
    ///
    /// Without this it waits for a line that will never assert again — the one
    /// failure mode a removal creates that no amount of correct bookkeeping
    /// fixes, because the driver is not running to observe any of it.
    #[test]
    fn removing_a_device_wakes_a_driver_parked_on_its_interrupt() {
        const DEVICE: ObjectId = ObjectId::from_raw(0x51);
        const HOLDER: ObjectId = ObjectId::from_raw(0x52);
        const INTID: u32 = 79;

        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let driver = spawn(&mut exec, &mut space, 0);
        let _other = spawn(&mut exec, &mut space, 1);
        exec.run();

        exec.device_register_mmio(DEVICE, 0x0a00_0000, 0x1000, Rights::READ | Rights::MAP)
            .expect("register");
        exec.device_set_mmio_irq(DEVICE, INTID).expect("intid");
        let port = exec.port_create().expect("create");
        exec.device_route_irq(DEVICE, port, HOLDER).expect("route");

        // Parked, exactly as `port_wait` on an empty port leaves a thread.
        exec.ports
            .port_mut(port)
            .expect("port")
            .set_blocked_drainer(Some(driver));
        exec.scheduler().unblock(driver);

        let mut processes = crate::process::ProcessTable::<MockAddressSpace>::new();
        let report = exec.remove_device(
            DEVICE,
            crate::lifecycle::TransitionReason::Removed,
            &mut processes,
            None,
            None,
        );
        assert_eq!(report.woken, 1, "the parked driver was told");
        assert_eq!(
            exec.scheduler().thread_state(driver),
            Some(ThreadState::Ready),
        );

        // **And it can tell what woke it.** An interrupt and a removal reach
        // the same sleeper on the same port, so the signal is the only thing
        // that distinguishes servicing a completion from stopping altogether.
        let event = exec.port_wait(port).expect("event");
        assert_eq!(event.signal, IRQ_PORT_SIGNAL_REMOVED);
        assert_ne!(IRQ_PORT_SIGNAL_REMOVED, IRQ_PORT_SIGNAL);
    }

    #[test]
    fn job_add_process_enforces_the_member_cap() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let root = exec
            .job_create_root(ObjectId::from_raw(0x5a_0001), JobLimits::new(1))
            .expect("root");
        let cp = Rights::CREATE_PROCESS;
        exec.job_add_process(
            root,
            Member {
                process: ObjectId::from_raw(1),
                thread: 0,
            },
            cp,
        )
        .expect("p1");
        // The second exceeds the cap of 1 — a resource error.
        assert_eq!(
            exec.job_add_process(
                root,
                Member {
                    process: ObjectId::from_raw(2),
                    thread: 1,
                },
                cp,
            ),
            Err(KError::LimitExceeded)
        );
    }

    #[test]
    fn job_kill_terminates_members_and_signals_the_state_port() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let member_thread = spawn(&mut exec, &mut space, 0);
        exec.run(); // a running context exists

        let root = exec
            .job_create_root(ObjectId::from_raw(0x5a_0002), JobLimits::new(2))
            .expect("root");
        let source = exec.job(root).expect("job").state_source();
        // A supervisor port bound to the root job's state source.
        let port = exec.port_create().expect("port");
        exec.port_bind(port, source, SIGNAL_MEMBER_EXIT)
            .expect("bind exit");
        exec.port_bind(port, source, SIGNAL_EMPTY)
            .expect("bind empty");

        let full = Rights::from_bits(Rights::CREATE_PROCESS.bits() | Rights::KILL.bits());
        exec.job_add_process(
            root,
            Member {
                process: ObjectId::from_raw(0x9e_0001),
                thread: member_thread,
            },
            full,
        )
        .expect("add");

        let mut killed = [None; 4];
        let n = exec.job_kill(root, full, &mut killed).expect("kill");
        assert_eq!(n, 1);
        assert_eq!(killed[0], Some(ObjectId::from_raw(0x9e_0001)));
        // The member thread was terminated.
        assert_eq!(
            exec.scheduler().thread_state(member_thread),
            Some(ThreadState::Exited)
        );
        // The state port drained the member-exit then the emptiness signal.
        assert_eq!(
            exec.port_wait(port).map(|e| e.signal),
            Ok(SIGNAL_MEMBER_EXIT)
        );
        assert_eq!(exec.port_wait(port).map(|e| e.signal), Ok(SIGNAL_EMPTY));
        // A killed job refuses further members.
        assert!(exec.job(root).expect("job").is_killed());
    }

    #[test]
    fn wait_on_value_mismatch_returns_wouldblock_without_blocking() {
        let mut exec = Executive::<MockContextOps>::new(4, 0);
        let mut space = vm();
        let t = spawn(&mut exec, &mut space, 0);
        exec.run(); // current = t, Running

        // observed (5) != expected (9): the address changed, so do not block.
        assert_eq!(
            exec.wait_on_address(0, 0x3000, 5, 9),
            Err(KError::WouldBlock)
        );
        assert!(exec.waits.is_empty());
        assert_eq!(exec.scheduler().thread_state(t), Some(ThreadState::Running));
    }
}
