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

use crate::devmgr::DeviceTable;
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
    ) -> Result<(), KError> {
        self.devices.register(id, base, len, irq)
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
    ) -> Result<(), KError> {
        self.devices.register_mmio(id, base, len)
    }

    /// Resolves a Device object id to its MMIO register window `(phys_base, len)` —
    /// the handle→window bridge a `MapDevice` syscall uses to map the granted
    /// window into a ring-3 driver's address space.
    /// Records the interrupt INTID of a registered MMIO device (D84).
    pub fn device_set_mmio_irq(&mut self, id: ObjectId, intid: u32) -> Result<(), KError> {
        self.devices.set_mmio_irq(id, intid)
    }

    /// Resolves a Device object to its interrupt INTID, if wired (D84).
    pub fn intid_of_object(&self, id: ObjectId) -> Option<u32> {
        self.devices.intid_of_object(id)
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
