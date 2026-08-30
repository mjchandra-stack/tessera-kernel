// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The driver SDK**: what a driver needs so that writing one does not require
//! reading a kernel.
//!
//! `docs/drivers/01` ("Developer Experience") lists nine pieces. The interface
//! schema compiler existed; this is the host template and the simulator hooks,
//! which are the two that everything else in that list is written against.
//!
//! # What the boilerplate actually was
//!
//! Measured rather than guessed. Across the ring-3 programs in this tree,
//! `channel_args` is written out **nineteen** times, `exit_reporting`
//! twenty-one, `map_device` eleven, and the bind handshake twelve — each a
//! near-copy, each with its own failure codes, and each an opportunity to get
//! the argument struct's `version` field wrong in a way that fails at run time
//! on a machine. None of that is driver logic. All of it is here now.
//!
//! # The seam is the operation, not the syscall
//!
//! [`Platform`] is what a driver talks to, and its methods are *call*, *serve*,
//! *map* and *allocate* — not `svc`. That choice is the difference between an
//! SDK and a wrapper: a trait of syscalls would leave a simulator obliged to
//! speak `ChannelMsgArgs` and a driver author still obliged to know what one
//! is. With the seam here, a driver is generic over where it runs, the same
//! source drives a real device and a modelled one, and **the thing that runs on
//! a developer's machine is the driver itself rather than something like it**.
//!
//! # What this does not do
//!
//! It is not a safety boundary. A driver still holds capabilities, still faults
//! if it dereferences a bad address, and is still confined by the kernel rather
//! than by this crate. What it removes is the need to *know* the syscall ABI in
//! order to write one, which is a documentation problem rather than a security
//! one.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Developer Experience")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// The syscall implementation, on the targets that have syscalls to make.
///
/// Absent on the host, where there is no kernel to call — which is also what
/// lets the simulator and its tests build there.
#[cfg(target_os = "none")]
pub mod machine;

pub mod dma;

/// A capability this program holds, by the handle number boot installed it at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Handle(pub u64);

/// One end of a channel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Endpoint(pub Handle);

/// What went wrong, in terms a driver author can act on.
///
/// Deliberately not the kernel's error numbering: a driver that had to know
/// `KError` would be a driver that had to read the kernel, which is the thing
/// this crate exists to make unnecessary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The other end of a channel is gone. A driver's client died, or its
    /// manager did.
    PeerGone,
    /// The request or reply did not fit the buffer offered for it.
    TooLarge,
    /// The device manager refused to bind this class to this program.
    NotBound,
    /// The device refused a mapping or an allocation — usually a capability
    /// that does not carry the right, which is a policy answer and not a bug.
    Refused,
    /// A wait reached its deadline (D282).
    ///
    /// **Named rather than left as a number**, unlike everything past
    /// `TooLarge`: a caller acts on this one differently by construction — it
    /// is the answer that says the request is still worth making, which is the
    /// opposite of every other error here.
    TimedOut,
    /// The kernel said something this crate does not have a name for. The raw
    /// value is carried so a report can still be specific.
    Kernel(i64),
}

/// A request a driver received and has not yet answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Request {
    /// The class-contract ordinal the client invoked.
    pub method: u32,
    /// How many bytes of the buffer the request filled.
    pub len: usize,
    /// How many capabilities arrived with it, installed in this program's
    /// table and reported through the `handles` buffer the receiver supplied.
    ///
    /// Zero for every message that carries none, which is most of them. The
    /// field exists so a receiver that expected one can tell it did not come,
    /// rather than reading a handle number left over from the last request.
    pub handles: usize,
}

/// A page a driver may reach and a device may reach, by its two addresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dma {
    /// Where this program can read and write it.
    pub va: u64,
    /// The address the *device* uses, which is not the same number and must
    /// never be assumed to be.
    pub device_address: u64,
}

/// A capability moving with a message.
///
/// **Two modes now, and the default is still a move** (D286). Sending with
/// `shared` false is a *transfer*: the sender's handle is taken and its
/// mappings of the object go away, which is why a driver can map every
/// request's buffer at one fixed address, and why a receiver validating a
/// buffer knows the sender cannot rewrite it underneath. `shared` true leaves
/// the sender holding and mapping it, and the frames go when the last holder
/// lets go.
///
/// **A share is the weaker guarantee**, and choosing it means giving up the
/// one that makes a transferred payload checkable. It is right for a buffer
/// two components use *together* — a ring one fills and the other drains —
/// and wrong for a request payload, where the receiver would be parsing bytes
/// the sender can still change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Transfer {
    /// The capability to hand over.
    pub handle: Handle,
    /// The rights it carries on arrival, which may narrow what the sender
    /// held and may never widen it.
    pub rights: u64,
    /// Whether the sender keeps its own copy.
    pub shared: bool,
}

impl Transfer {
    /// A capability handed over outright: the sender stops holding it.
    pub const fn moved(handle: Handle, rights: u64) -> Self {
        Transfer {
            handle,
            rights,
            shared: false,
        }
    }

    /// A capability both sides hold. See the note above on what it gives up.
    pub const fn shared(handle: Handle, rights: u64) -> Self {
        Transfer {
            handle,
            rights,
            shared: true,
        }
    }
}

/// How many capabilities one message can carry.
///
/// The kernel's `MAX_MSG_HANDLES`. Stated here so a contract that outgrows it
/// is a build failure in one place rather than a truncation in several — the
/// argument [`MAX_REPLY`] makes for inline bytes.
pub const MAX_TRANSFER: usize = 4;

/// Everything a driver asks of the world it runs in.
///
/// One trait, so a driver names its dependency once. A machine implements it
/// with syscalls; `//userspace/sdk-sim` implements it with a model.
pub trait Platform {
    /// Sends `request` and waits for the reply, which lands in `reply`.
    ///
    /// Waits as long as it takes. A client that cannot afford to — one whose
    /// service may stop rather than answer — uses
    /// [`call_until`](Platform::call_until).
    fn call(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, Error> {
        self.call_until(endpoint, method, request, reply, None)
    }

    /// As [`call`](Platform::call), giving up at `deadline`.
    ///
    /// **What a client needs to survive a service that stops** (D283). A
    /// service that is wedged, looping, or never scheduled again is
    /// indistinguishable from one that is merely slow, and a plain `call`
    /// waits for either of them until the machine is switched off — so a
    /// client with anything else to do, or anything else to try, cannot be
    /// written without this.
    ///
    /// `deadline` is monotonic nanoseconds on the clock
    /// [`now_nanos`](Platform::now_nanos) reads; `None` is exactly
    /// [`call`](Platform::call). [`Error::TimedOut`] means the request was
    /// **delivered and abandoned**, not that it was never sent: the service
    /// may still act on it, and its reply — if one comes — is discarded rather
    /// than handed to the next caller. A client that retries must be willing
    /// to have been served twice.
    fn call_until(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
        deadline: Option<u64>,
    ) -> Result<usize, Error>;

    /// Waits for a request from a client.
    fn receive(&mut self, endpoint: Endpoint, into: &mut [u8]) -> Result<Request, Error>;

    /// Answers the request most recently received, and keeps serving.
    fn respond(&mut self, endpoint: Endpoint, reply: &[u8]) -> Result<(), Error>;

    /// Maps a device's registers at `va`.
    fn map_device(&mut self, device: Handle, va: u64) -> Result<u64, Error>;

    /// Allocates one page reachable by both this program and the device.
    fn dma_alloc(&mut self, device: Handle, va: u64) -> Result<Dma, Error>;

    /// Lends the driver the bytes of a page it was granted, for the duration
    /// of `f`.
    ///
    /// **A driver does not form a pointer.** Every driver in this tree used to
    /// build one from the address `dma_alloc` returned, which is correct on a
    /// machine and meaningless anywhere else — so a driver that used DMA could
    /// not run against a model at all, and the DMA half of this SDK was
    /// untestable by construction. Going through the platform costs a driver
    /// nothing it was not already doing and is what [`dma::Pages`] can watch.
    ///
    /// Scoped rather than returning a slice, because two live references to
    /// one page is the mistake this shape makes impossible and a lifetime tied
    /// to `&mut self` would stop a driver calling anything else while it held
    /// one.
    fn with_dma<R>(&mut self, dma: &Dma, f: impl FnOnce(&mut [u8]) -> R) -> R;

    /// Fills `record` with what the kernel knows about where this device's
    /// structures are.
    ///
    /// A separate question from binding, and the second conversion is what
    /// established that: a driver holding a register window still cannot find
    /// anything in it, because configuration space is not per-device and no
    /// capability to it can be handed out. The bytes are the caller's schema to
    /// decode, for the reason `bind` returns a length — a template that decoded
    /// them would be a template with an opinion about a contract it does not
    /// own.
    fn device_info(&mut self, device: Handle, record: &mut [u8]) -> Result<(), Error>;

    /// Sends `request` with capabilities attached and waits for the reply.
    ///
    /// `give` are handed over — the sender stops holding them. `take` is
    /// filled with the handle numbers whatever came back landed at, and the
    /// count is returned: a capability arrives at a number the *receiver's*
    /// table chose, never the one the sender used, so a caller that assumed
    /// the number it sent would be the number it got back would be reading
    /// somebody else's handle.
    fn call_with(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
        give: &[Transfer],
        take: &mut [Handle],
    ) -> Result<(usize, usize), Error>;

    /// Waits for a request, and takes any capabilities that come with it.
    ///
    /// The installed handles land in `handles`; [`Request::handles`] says how
    /// many. A message carrying more than `handles` can hold is refused rather
    /// than truncated — a dropped capability is one nobody can give back.
    /// Waits for a request on **any** of `endpoints`, and says which one
    /// answered.
    ///
    /// A blocking receive on one endpoint commits a server to that caller until
    /// it speaks. A service that also answers to the kernel — a pager is one —
    /// holds two endpoints and must hear whichever talks first, so the index
    /// comes back with the request and the reply goes to the endpoint that
    /// asked rather than to a remembered one.
    ///
    /// `Ok((index, request))` indexes into `endpoints`.
    fn receive_any(
        &mut self,
        endpoints: &[Endpoint],
        into: &mut [u8],
        handles: &mut [Handle],
    ) -> Result<(usize, Request), Error>;

    /// As [`receive_any`](Platform::receive_any), giving up at `deadline`.
    ///
    /// **The first blocking call here that can be woken by time** (D282).
    /// Every other one waits until somebody speaks, which is right for a
    /// server whose clients always do and wrong for one waiting on a network
    /// that may not — the difference between a service that reports a timeout
    /// and one that stops.
    ///
    /// `deadline` is monotonic nanoseconds, on the clock
    /// [`Platform::now_nanos`] reads. Passing `None` is exactly
    /// [`receive_any`](Platform::receive_any).
    fn receive_any_until(
        &mut self,
        endpoints: &[Endpoint],
        into: &mut [u8],
        handles: &mut [Handle],
        deadline: Option<u64>,
    ) -> Result<(usize, Request), Error>;

    /// Monotonic nanoseconds, or `None` where the machine could not say.
    ///
    /// **`None` is not zero.** A deadline computed from a clock that always
    /// reads zero expires immediately, so a caller that treated the two alike
    /// would turn a machine with no usable counter into one where every wait
    /// fails at once (D281).
    fn now_nanos(&mut self) -> Option<u64>;

    fn receive_with(
        &mut self,
        endpoint: Endpoint,
        into: &mut [u8],
        handles: &mut [Handle],
    ) -> Result<Request, Error>;

    /// Answers the current request, handing `give` back with the reply.
    ///
    /// Giving a received buffer back is not a courtesy: it is how the sender
    /// gets its memory again, and how the object stops being reachable by this
    /// driver's device.
    fn respond_with(
        &mut self,
        endpoint: Endpoint,
        reply: &[u8],
        give: &[Transfer],
    ) -> Result<(), Error>;

    /// Creates a memory object of `bytes`, zero-filled, owned by this program.
    ///
    /// The buffer a program hands to somebody else. No placement constraints
    /// are offered: asking for contiguity nothing needs is how carveout
    /// pressure grows, and every caller so far wants pages the CPU writes and
    /// a device reaches through an attachment, which cares where nothing sits.
    /// A second handle to the same object, carrying `rights` — which must be a
    /// subset of what the first carries.
    ///
    /// A service that must both hand out a capability and keep one needs this,
    /// because transfer *moves*: a pager that sent its client the file's object
    /// would have sent away the authority it answers page requests with.
    fn handle_duplicate(&mut self, handle: Handle, rights: u64) -> Result<Handle, Error>;

    /// Creates a **service-backed** object of `bytes`, whose pages this program
    /// supplies on demand through `pager`.
    ///
    /// It draws no memory: the pages arrive as they are read, which is what
    /// lets a file's object be larger than what any reader has resident.
    fn memory_create_paged(&mut self, bytes: u64, pager: Handle) -> Result<Handle, Error>;

    /// Puts the contents of the page at `source` into `memory` at `offset`.
    ///
    /// Requires `SUPPLY` on the handle. The page is copied, so `source` stays
    /// this program's and stays mapped.
    fn page_supply(&mut self, memory: Handle, offset: u64, source: u64) -> Result<(), Error>;

    /// Maps a service-backed object at `va`, so its absent pages are page-in
    /// requests rather than faults.
    fn map_object(&mut self, memory: Handle, va: u64, rights: u32) -> Result<(), Error>;

    /// Which of `memory`'s pages have been written since they were supplied or
    /// last written back, ascending. Returns how many were written into
    /// `offsets` — as many as fit, never a count the caller did not receive.
    ///
    /// Requires `SUPPLY`: which pages of a file have changed is a fact about
    /// its contents.
    fn memory_dirty_pages(&mut self, memory: Handle, offsets: &mut [u64]) -> Result<usize, Error>;

    /// Tells the kernel this program has persisted `memory`'s page at `offset`,
    /// so it may stop holding it dirty.
    ///
    /// The kernel does not decide this: it marks a page clean when the thing
    /// that owns the backing store says the bytes are there. Reporting a page
    /// that was not written tells the kernel it may drop the only copy.
    fn page_written_back(&mut self, memory: Handle, offset: u64) -> Result<(), Error>;

    /// Gives a mapping back. `base`/`len` must name it exactly.
    ///
    /// A program that never unmaps holds every address it has ever used, which
    /// a service mapping a different file per flush runs out of at once.
    fn unmap(&mut self, base: u64, len: u64) -> Result<(), Error>;

    fn memory_create(&mut self, bytes: u64) -> Result<Handle, Error>;

    /// Creates a channel and returns **both** of its endpoints.
    ///
    /// Both land in this program's own table, because that is the only table
    /// the kernel can name at the moment of creation; handing one to somebody
    /// else is a separate, separately-authorized act. The first carries
    /// `READ`, the second `WRITE`, and both carry `TRANSFER` so either may be
    /// given away.
    fn channel_create(&mut self) -> Result<(Endpoint, Endpoint), Error>;

    /// Maps `memory` read-write at `va`, returning nothing — the caller knows
    /// the address it asked for.
    ///
    /// **Mapping is not idempotent, and that is load-bearing.** Handing an
    /// object away revokes this program's mapping of it, so a second map at
    /// the same address succeeds only because the first one went. A caller
    /// that maps, transfers, and maps again at one fixed address is observing
    /// the revocation rather than assuming it.
    fn memory_map(&mut self, memory: Handle, va: u64) -> Result<(), Error>;

    /// Maps `memory` **read-only** at `va`.
    ///
    /// **The map a grant needs, and [`Platform::memory_map`] is not it.** That
    /// one asks for `READ | WRITE`, which is right for an object this program
    /// made and refused for one it was handed: a buffer transferred with
    /// `{READ, MAP}` — every payload on `flow_service` and every frame on
    /// `network_driver` — cannot be mapped writable, so a receiver that used
    /// the read-write map got `AccessDenied` and no hint that the rights were
    /// the reason. Asking for exactly what the contract granted is also the
    /// honest thing: a service that mapped a caller's datagram writable could
    /// alter it, and the narrow rights exist to make that impossible.
    fn memory_map_readable(&mut self, memory: Handle, va: u64) -> Result<(), Error>;

    /// Makes a memory object this program holds reachable by `device`,
    /// returning the address the *device* uses.
    ///
    /// The counterpart of [`Platform::dma_alloc`] for memory somebody else
    /// allocated: a client's buffer arrives as a capability, and this is what
    /// turns it into something a queue descriptor can name. The driver never
    /// maps it — a driver with no mapping of a buffer did not copy it.
    fn dma_attach(&mut self, device: Handle, memory: Handle) -> Result<u64, Error>;

    /// Ends that reachability.
    ///
    /// Before the object goes back to its owner, always: an object the device
    /// can still reach is one it may write into after somebody else owns it.
    ///
    /// No device argument, because the contract has none — a memory object has
    /// at most one attachment, so naming it names the attachment.
    fn dma_detach(&mut self, memory: Handle) -> Result<(), Error>;

    /// Sleeps until this driver's device interrupts, and reports which source
    /// woke it.
    ///
    /// **Added by converting a real driver, which is what the conversion was
    /// for.** The template was built around a driver that serves a channel; the
    /// first one converted waits on an interrupt instead and never serves
    /// anything, so a `Platform` without this could not express it at all. A
    /// driver never names an interrupt line — it waits on a port it was given
    /// and the kernel decides what wakes it — which is why this takes a handle
    /// and returns a source rather than a number anybody chose.
    fn wait_for_interrupt(&mut self, port: Handle) -> Result<u64, Error>;

    /// Tells the kernel this driver has finished with the interrupt, so the
    /// line can be unmasked.
    ///
    /// Separate from the wait because the order matters and only a driver knows
    /// it: the device must be acknowledged in its *own* protocol first, and a
    /// line re-armed while the device still asserts it would interrupt again
    /// immediately and forever.
    fn interrupt_complete(&mut self, device: Handle) -> Result<(), Error>;

    /// Reports a value and stops.
    /// Gives up a capability this program holds.
    ///
    /// **The counterpart of receiving a transfer, and it is not optional.**
    /// A handle that arrived by transfer belongs to this program: closing the
    /// last one revokes its mappings and frees the pages behind it. A service
    /// that forgot would leak the caller's memory *and* keep the address it
    /// mapped it at occupied, so its next call fails somewhere unrelated —
    /// which is exactly how it presented the first time (build/README.md,
    /// D272, where a client's leak surfaced as the driver's next allocation
    /// failing).
    fn close(&mut self, handle: Handle) -> Result<(), Error>;

    fn finish(&mut self, report: u64) -> !;
}

/// Asks the device manager to bind this program, and hands back what it said.
///
/// **The whole handshake, once.** Twelve programs in this tree write this out,
/// and what differs between them is the class they ask for and the failure
/// codes they invent — neither a decision worth making twelve times.
///
/// It returns the reply's length and decodes nothing. The first version parsed
/// a device handle and a register layout out of the reply, and **no such fields
/// exist**: a driver's device capability arrives at a handle number its
/// bootstrap contract fixes, and where the device's structures are is a
/// separate question with [`Platform::device_info`] to ask it. That mistake
/// survived a full test suite because the simulator had been written to match
/// it — which is the thing to remember about simulators, and why converting a
/// real driver is the only test of a template that means anything.
pub fn bind<P: Platform>(
    platform: &mut P,
    manager: Endpoint,
    request: &[u8],
    reply: &mut [u8],
) -> Result<usize, Error> {
    platform.call(manager, BIND_METHOD, request, reply)
}

/// Serves a class contract until the client goes away.
///
/// `handler` is given the method ordinal and the request bytes, and writes its
/// reply into the same buffer, returning how many bytes it wrote. That is the
/// entire shape of a driver: **everything else in this function is the loop
/// every driver in this tree writes for itself**, including the one mistake
/// that has been made twice — replying in a way that blocks the server on its
/// own client (build/README.md, D85 and D91).
pub fn serve<P: Platform>(
    platform: &mut P,
    service: Endpoint,
    buffer: &mut [u8],
    mut handler: impl FnMut(u32, &[u8], &mut [u8]) -> Result<usize, Error>,
) -> Result<(), Error> {
    loop {
        let request = match platform.receive(service, buffer) {
            Ok(request) => request,
            // The client is gone. That is an ordinary way for a driver to be
            // finished rather than a failure, and it is the answer a driver
            // that looped on the error instead would never reach.
            Err(Error::PeerGone) => return Ok(()),
            Err(other) => return Err(other),
        };
        let (head, rest) = buffer.split_at_mut(request.len.min(buffer.len()));
        let _ = rest;
        let mut scratch = [0u8; MAX_REPLY];
        let written = handler(request.method, head, &mut scratch)?;
        if written > scratch.len() {
            return Err(Error::TooLarge);
        }
        platform.respond(service, &scratch[..written])?;
    }
}

/// Serves a class contract whose requests carry capabilities.
///
/// The transfer-aware [`serve`]. Separate rather than a parameter because the
/// two loops answer different questions: this one has to give back what it was
/// handed, on **every** path including the failing ones, and a driver that
/// forgot on one of them would strand a client's memory with no way to ask for
/// it again. A loop that sometimes carries handles would make that a runtime
/// property; two loops make it a choice at the call site.
///
/// `handler` receives the method, the request bytes, the handles that arrived,
/// and a reply buffer; it returns how many bytes it wrote and how many of
/// `give_back` it filled.
/// Serves requests arriving on **any** of `endpoints` until a peer goes away.
///
/// The handler is told which endpoint asked, because a service holding more
/// than one is answering more than one protocol: the index is what tells a
/// filesystem service a request came from the kernel asking for a page rather
/// than from a client asking to open a file.
///
/// Everything else matches [`serve_transfers`], including the rule that a
/// handler which fails still owes back whatever it was handed.
pub fn serve_many<P: Platform>(
    platform: &mut P,
    endpoints: &[Endpoint],
    buffer: &mut [u8],
    mut handler: impl FnMut(
        usize,
        u32,
        &[u8],
        &[Handle],
        &mut [u8],
        &mut [Transfer],
    ) -> Result<(usize, usize), Error>,
) -> Result<(), Error> {
    loop {
        let mut arrived = [Handle(0); MAX_TRANSFER];
        let (index, request) = match platform.receive_any(endpoints, buffer, &mut arrived) {
            Ok(pair) => pair,
            // A peer is gone, which is an ordinary way to be finished.
            Err(Error::PeerGone) => return Ok(()),
            Err(other) => return Err(other),
        };
        let Some(from) = endpoints.get(index).copied() else {
            return Err(Error::Kernel(-1));
        };
        let (head, rest) = buffer.split_at_mut(request.len.min(buffer.len()));
        let _ = rest;
        let mut scratch = [0u8; MAX_REPLY];
        let mut give_back = [Transfer {
            handle: Handle(0),
            rights: 0,
            shared: false,
        }; MAX_TRANSFER];
        let outcome = handler(
            index,
            request.method,
            head,
            &arrived[..request.handles],
            &mut scratch,
            &mut give_back,
        );
        let (written, returned) = match outcome {
            Ok(pair) => pair,
            Err(error) => {
                if request.handles > 0 {
                    let owed: [Transfer; MAX_TRANSFER] = core::array::from_fn(|slot| Transfer {
                        handle: arrived[slot],
                        rights: 0,
                        shared: false,
                    });
                    let _ = platform.respond_with(from, &[], &owed[..request.handles]);
                }
                return Err(error);
            }
        };
        if written > scratch.len() || returned > give_back.len() {
            return Err(Error::TooLarge);
        }
        // Back to the endpoint that asked, never to a remembered one: two
        // protocols share this loop and a reply on the wrong channel is a
        // page-in answered to a client that asked to open a file.
        platform.respond_with(from, &scratch[..written], &give_back[..returned])?;
    }
}

pub fn serve_transfers<P: Platform>(
    platform: &mut P,
    service: Endpoint,
    buffer: &mut [u8],
    mut handler: impl FnMut(
        u32,
        &[u8],
        &[Handle],
        &mut [u8],
        &mut [Transfer],
    ) -> Result<(usize, usize), Error>,
) -> Result<(), Error> {
    loop {
        let mut arrived = [Handle(0); MAX_TRANSFER];
        let request = match platform.receive_with(service, buffer, &mut arrived) {
            Ok(request) => request,
            // The client is gone, which is an ordinary way to be finished.
            Err(Error::PeerGone) => return Ok(()),
            Err(other) => return Err(other),
        };
        let (head, rest) = buffer.split_at_mut(request.len.min(buffer.len()));
        let _ = rest;
        let mut scratch = [0u8; MAX_REPLY];
        let mut give_back = [Transfer {
            handle: Handle(0),
            rights: 0,
            shared: false,
        }; MAX_TRANSFER];
        let outcome = handler(
            request.method,
            head,
            &arrived[..request.handles],
            &mut scratch,
            &mut give_back,
        );
        // A handler that failed still owes back whatever it was handed. Doing
        // it here rather than trusting each arm of each driver is the whole
        // reason this loop exists.
        let (written, returned) = match outcome {
            Ok(pair) => pair,
            Err(error) => {
                if request.handles > 0 {
                    let owed: [Transfer; MAX_TRANSFER] = core::array::from_fn(|index| Transfer {
                        handle: arrived[index],
                        rights: 0,
                        shared: false,
                    });
                    let _ = platform.respond_with(service, &[], &owed[..request.handles]);
                }
                return Err(error);
            }
        };
        if written > scratch.len() || returned > give_back.len() {
            return Err(Error::TooLarge);
        }
        platform.respond_with(service, &scratch[..written], &give_back[..returned])?;
    }
}

/// The largest reply this template will carry.
///
/// Bounded because a driver runs where allocation is fallible, and stated here
/// rather than per-driver so that a class contract outgrowing it is a build
/// failure in one place instead of a truncation in several.
pub const MAX_REPLY: usize = 256;

/// The bind protocol's method ordinal.
const BIND_METHOD: u32 = 1;
