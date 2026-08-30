// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The simulator**: a [`Platform`](tessera_sdk::Platform) that answers from a model
//! instead of from a machine.
//!
//! `docs/drivers/01` asks for "hardware simulator hooks" and
//! `docs/lifecycle/02` says class conformance should run "against the simulated
//! devices from the driver SDK, so a class contract is testable before any
//! hardware exists". This is what makes that sentence true: a driver written
//! against the SDK runs here unchanged, on a developer's machine, with no
//! emulator and no boot.
//!
//! # Why a script rather than a device model
//!
//! Because the interesting cases are not what a working device does. A driver
//! that only ever meets a device behaving correctly is a driver whose error
//! paths have never run — and those are most of a driver. So a [`Script`] says
//! what the world *does*, including the parts a real device will not do on
//! request: refuse a binding, refuse a mapping, hand back a client that leaves
//! mid-conversation. That is the fault injection `docs/drivers/01` lists,
//! arriving as the same mechanism rather than as a separate one.
//!
//! **The addresses it hands back differ from the ones asked for**, deliberately.
//! A simulator that returned the requested VA as the device address would let a
//! driver conflate the two and pass here, then fail on a machine with an IOMMU
//! — which is exactly the class of bug a simulator is supposed to catch rather
//! than to hide.

#![no_std]
#![deny(unsafe_code)]

use tessera_sdk::dma::Pages;
use tessera_sdk::{Dma, Endpoint, Error, Handle, Platform, Request, Transfer};

/// What the modelled world does when a driver asks it something.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Script {
    /// Whether the manager binds the class at all.
    pub binds: bool,
    /// The first byte of the record `device_info` reports, so a test can tell
    /// one modelled device from another.
    pub info: u8,
    /// Whether the device permits its registers to be mapped.
    pub maps: bool,
    /// How many DMA pages the device's capability permits before it refuses.
    ///
    /// A count rather than a flag, because the interesting case is neither
    /// "always" nor "never": a driver that handles the first refusal it meets
    /// and not the third has an error path that has never run.
    pub dma_grants: u32,
    /// How many memory objects this model will create before refusing.
    pub memory_objects: u32,
    /// Whether each request carries a memory object for the driver to fill.
    ///
    /// The out-of-line path: a client that hands its buffer over expects it
    /// back, and a driver that keeps it strands memory in a process nobody can
    /// reach. Modelled so a test can count what came back against what arrived.
    pub requests_carry_a_buffer: bool,
    /// How many requests a client makes before going away.
    pub requests: u32,
    /// How many times the device interrupts before it stops.
    pub interrupts: u32,
}

impl Script {
    /// A world where everything works: a bind, a mapping, DMA, and two requests
    /// before the client is done.
    pub const fn binds_and_answers() -> Script {
        Script {
            binds: true,
            info: 4,
            maps: true,
            dma_grants: 4,
            memory_objects: 2,
            requests_carry_a_buffer: false,
            requests: 2,
            interrupts: 1,
        }
    }

    /// A manager that will not bind this class — a policy answer, and the first
    /// thing a new driver meets when its manifest entry is wrong.
    pub const fn refuses_bind() -> Script {
        Script {
            binds: false,
            ..Script::binds_and_answers()
        }
    }

    /// A device capability that carries no right to allocate DMA at all.
    pub const fn refuses_dma() -> Script {
        Script {
            dma_grants: 0,
            ..Script::binds_and_answers()
        }
    }

    /// A device that grants `n` pages and refuses the next — the fault
    /// injection `docs/drivers/01` asks for, arriving as the same mechanism
    /// rather than a second one.
    pub const fn dma_runs_out_after(n: u32) -> Script {
        Script {
            dma_grants: n,
            ..Script::binds_and_answers()
        }
    }

    /// A device capability that does not carry the right to map.
    pub const fn refuses_mapping() -> Script {
        Script {
            maps: false,
            ..Script::binds_and_answers()
        }
    }

    /// A client that binds and then goes away without asking for anything.
    pub const fn client_leaves_immediately() -> Script {
        Script {
            memory_objects: 2,
            requests_carry_a_buffer: false,
            requests: 0,
            ..Script::binds_and_answers()
        }
    }
}

/// The modelled world.
pub struct Simulator {
    script: Script,
    served: u32,
    replies: u32,
    bound: bool,
    interrupts: u32,
    completions: u32,
    /// The pages this model owns, which is what makes a driver that uses DMA
    /// runnable here at all.
    pages: Pages,
    /// Capabilities handed away, kept because a transfer is a move: a driver
    /// that used a handle after giving it up is the mistake a model that
    /// ignored transfers would hide.
    transferred_away: u32,
    last_given: Handle,
    /// Capabilities given back with a reply, against which the count that
    /// arrived can be checked.
    returned: u32,
    attached: u32,
    detached: u32,
    created: u32,
    mapped: Option<Handle>,
    /// Capabilities given up. A transfer that arrives and is never closed is a
    /// leak, and D272 is the reason the model counts them: that defect showed
    /// up as an unrelated allocation failing several calls later, which is the
    /// hardest possible place to find it.
    closed: u32,
    last_closed: Handle,
}

impl Simulator {
    pub fn new(script: Script) -> Simulator {
        Simulator {
            script,
            served: 0,
            replies: 0,
            bound: false,
            transferred_away: 0,
            last_given: Handle(0),
            returned: 0,
            attached: 0,
            detached: 0,
            created: 0,
            mapped: None,
            closed: 0,
            last_closed: Handle(0),
            interrupts: 0,
            completions: 0,
            pages: Pages::new(),
        }
    }

    /// The DMA test harness for this run.
    ///
    /// Handed out rather than wrapped, because what a test wants to ask about
    /// DMA is not a fixed list: what the device would have read, whether a
    /// secret survived, how many grants were made. See [`Pages`].
    pub fn pages(&self) -> &Pages {
        &self.pages
    }

    /// How many requests the driver answered. A driver that served nothing and
    /// one that served everything both finish; only this tells them apart.
    pub fn replies(&self) -> u32 {
        self.replies
    }

    /// How many interrupts the driver acknowledged. A driver that waited and
    /// never completed would leave the line masked forever on a machine, and
    /// only counting both halves shows it.
    pub fn completions(&self) -> u32 {
        self.completions
    }

    /// How many capabilities this driver handed away.
    pub fn transferred_away(&self) -> u32 {
        self.transferred_away
    }

    /// The last one it handed away, so a test can tell *which*.
    pub fn last_given(&self) -> Handle {
        self.last_given
    }

    /// How many it gave back with a reply. A driver that answered every
    /// request but returned fewer buffers than arrived has kept one.
    pub fn returned(&self) -> u32 {
        self.returned
    }

    /// How many capabilities this program gave up, and the last one.
    ///
    /// **What a test asks to catch a leak.** A driver handed a buffer owns it;
    /// one that never closes it holds the caller's memory for the rest of the
    /// run and keeps whatever address it mapped it at occupied.
    pub fn closed(&self) -> u32 {
        self.closed
    }

    pub fn last_closed(&self) -> Handle {
        self.last_closed
    }

    /// Attach/detach counts. Unequal at the end of a run is a device left able
    /// to reach memory its owner has taken back.
    pub fn attached(&self) -> u32 {
        self.attached
    }

    pub fn detached(&self) -> u32 {
        self.detached
    }
}

impl Platform for Simulator {
    fn call(
        &mut self,
        _endpoint: Endpoint,
        _method: u32,
        _request: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.script.binds {
            // Short, so the template's own length check is what refuses it —
            // which is the path a real manager's refusal takes too.
            return Ok(0);
        }
        self.bound = true;
        if reply.len() < 40 {
            return Err(Error::TooLarge);
        }
        // What a bind reply carries is the manager's answer about *policy*.
        // It carries no device handle and no layout, which the simulator once
        // pretended it did — matching a template that had invented both.
        reply[..40].fill(0);
        Ok(40)
    }

    fn receive(&mut self, _endpoint: Endpoint, into: &mut [u8]) -> Result<Request, Error> {
        if self.served >= self.script.requests {
            return Err(Error::PeerGone);
        }
        self.served += 1;
        let payload = [0xa5u8, 0x5a];
        if into.len() < payload.len() {
            return Err(Error::TooLarge);
        }
        into[..payload.len()].copy_from_slice(&payload);
        Ok(Request {
            method: self.served,
            len: payload.len(),
            handles: 0,
        })
    }

    fn call_with(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
        give: &[Transfer],
        take: &mut [Handle],
    ) -> Result<(usize, usize), Error> {
        // Every capability sent is a capability the sender stops holding, so
        // the model records the move rather than ignoring it: a driver that
        // used a handle after transferring it is the mistake worth catching,
        // and a simulator that let it work would hide exactly that.
        for transfer in give {
            self.transferred_away = self.transferred_away.saturating_add(1);
            self.last_given = transfer.handle;
        }
        let len = self.call(endpoint, method, request, reply)?;
        // A model of a peer that gives what it was given back, at a handle
        // number of its own choosing — because a real one never returns the
        // number it was sent.
        let returned = take.len().min(give.len());
        for (index, slot) in take.iter_mut().enumerate().take(returned) {
            *slot = Handle(0x5100 + index as u64);
        }
        Ok((len, returned))
    }

    /// Always the first endpoint. The simulator drives one scripted client, so
    /// there is never a second endpoint with something to say — and answering
    /// "the one that spoke" honestly means answering with the only one there
    /// is, rather than inventing an order no script describes.
    fn receive_any(
        &mut self,
        endpoints: &[Endpoint],
        into: &mut [u8],
        handles: &mut [Handle],
    ) -> Result<(usize, Request), Error> {
        let Some(endpoint) = endpoints.first() else {
            return Err(Error::TooLarge);
        };
        let request = self.receive_with(*endpoint, into, handles)?;
        Ok((0, request))
    }

    fn receive_with(
        &mut self,
        endpoint: Endpoint,
        into: &mut [u8],
        handles: &mut [Handle],
    ) -> Result<Request, Error> {
        let mut request = self.receive(endpoint, into)?;
        // One buffer per request, when the script says the client sends one.
        if self.script.requests_carry_a_buffer && !handles.is_empty() {
            handles[0] = Handle(0x6100 + u64::from(self.served));
            request.handles = 1;
        }
        Ok(request)
    }

    fn respond_with(
        &mut self,
        endpoint: Endpoint,
        reply: &[u8],
        give: &[Transfer],
    ) -> Result<(), Error> {
        self.returned = self.returned.saturating_add(give.len() as u32);
        self.respond(endpoint, reply)
    }

    /// The simulator has no kernel handle table, so a duplicate is a distinct
    /// number naming the same thing — enough for a script that only checks a
    /// service kept one and gave one away.
    fn handle_duplicate(&mut self, handle: Handle, _rights: u64) -> Result<Handle, Error> {
        Ok(Handle(handle.0 | 0x8000_0000))
    }

    fn memory_create_paged(&mut self, _bytes: u64, _pager: Handle) -> Result<Handle, Error> {
        Err(Error::Refused)
    }

    fn page_supply(&mut self, _memory: Handle, _offset: u64, _source: u64) -> Result<(), Error> {
        Err(Error::Refused)
    }

    fn map_object(&mut self, _memory: Handle, _va: u64, _rights: u32) -> Result<(), Error> {
        Err(Error::Refused)
    }

    /// The simulator has no cache, so nothing is ever dirty.
    fn memory_dirty_pages(
        &mut self,
        _memory: Handle,
        _offsets: &mut [u64],
    ) -> Result<usize, Error> {
        Ok(0)
    }

    fn page_written_back(&mut self, _memory: Handle, _offset: u64) -> Result<(), Error> {
        Err(Error::Refused)
    }

    /// The model records the close rather than performing one: there is no
    /// kernel here to revoke a mapping, and what a test wants to assert is
    /// that a driver gave a capability up at all.
    /// The model maps as the machine does; what differs is only the rights,
    /// which nothing here enforces.
    /// The model has no clock and says so, which is the state a machine whose
    /// counter frequency is unknown is also in.
    fn now_nanos(&mut self) -> Option<u64> {
        None
    }

    /// The model never blocks, so a deadline changes nothing about what it
    /// returns — recorded rather than honoured.
    fn receive_any_until(
        &mut self,
        endpoints: &[Endpoint],
        into: &mut [u8],
        handles: &mut [Handle],
        _deadline: Option<u64>,
    ) -> Result<(usize, Request), Error> {
        self.receive_any(endpoints, into, handles)
    }

    fn memory_map_readable(&mut self, memory: Handle, va: u64) -> Result<(), Error> {
        self.memory_map(memory, va)
    }

    fn close(&mut self, handle: Handle) -> Result<(), Error> {
        self.closed += 1;
        self.last_closed = handle;
        Ok(())
    }

    fn unmap(&mut self, _base: u64, _len: u64) -> Result<(), Error> {
        Ok(())
    }

    fn memory_create(&mut self, bytes: u64) -> Result<Handle, Error> {
        // Bounded like the machine's: a model that granted without limit would
        // let a driver pass here and fail on a real one.
        if self.created >= self.script.memory_objects {
            return Err(Error::Refused);
        }
        self.created += 1;
        let _ = bytes;
        Ok(Handle(0x7100 + u64::from(self.created)))
    }

    fn memory_map(&mut self, memory: Handle, _va: u64) -> Result<(), Error> {
        // A second mapping of an object still mapped is refused, which is what
        // makes a driver that maps at one fixed address across a transfer a
        // driver whose revocation actually happened.
        if self.mapped == Some(memory) {
            return Err(Error::Refused);
        }
        self.mapped = Some(memory);
        Ok(())
    }

    fn dma_attach(&mut self, _device: Handle, memory: Handle) -> Result<u64, Error> {
        if !self.bound {
            return Err(Error::NotBound);
        }
        self.attached = self.attached.saturating_add(1);
        // A device address that is not the handle and not a virtual address,
        // for the reason `Dma::device_address` exists at all.
        Ok(0x4000_0000 | (memory.0 << 12))
    }

    fn dma_detach(&mut self, _memory: Handle) -> Result<(), Error> {
        self.detached = self.detached.saturating_add(1);
        Ok(())
    }

    fn respond(&mut self, _endpoint: Endpoint, _reply: &[u8]) -> Result<(), Error> {
        self.replies += 1;
        Ok(())
    }

    fn device_info(&mut self, _device: Handle, record: &mut [u8]) -> Result<(), Error> {
        if !self.bound {
            // A driver that never bound holds no device to ask about.
            return Err(Error::NotBound);
        }
        if record.is_empty() {
            return Err(Error::TooLarge);
        }
        record.fill(0);
        record[0] = self.script.info;
        Ok(())
    }

    fn map_device(&mut self, _device: Handle, va: u64) -> Result<u64, Error> {
        if !self.script.maps {
            return Err(Error::Refused);
        }
        Ok(va)
    }

    fn dma_alloc(&mut self, _device: Handle, va: u64) -> Result<Dma, Error> {
        if self.pages.granted() as u32 >= self.script.dma_grants {
            return Err(Error::Refused);
        }
        // `None` here would mean the model is out of pages, which is the same
        // answer a capability that ran out of budget gives.
        self.pages.grant(va).ok_or(Error::Refused)
    }

    fn with_dma<R>(&mut self, dma: &Dma, f: impl FnOnce(&mut [u8]) -> R) -> R {
        self.pages.with(dma, f)
    }

    fn wait_for_interrupt(&mut self, _port: Handle) -> Result<u64, Error> {
        if self.interrupts >= self.script.interrupts {
            // A device that has stopped interrupting is not an error and not a
            // hang: it is a driver with nothing left to wait for, and a
            // simulator that blocked here would model a bug rather than a
            // device.
            return Err(Error::PeerGone);
        }
        self.interrupts += 1;
        Ok(u64::from(self.interrupts))
    }

    fn interrupt_complete(&mut self, _device: Handle) -> Result<(), Error> {
        self.completions += 1;
        Ok(())
    }

    fn finish(&mut self, _report: u64) -> ! {
        // A simulated driver returns rather than exiting; a test that wanted a
        // report reads it from the driver's own return value. Reaching here
        // means a driver called `finish` mid-run, which on a machine would end
        // it — so it ends the test the same way rather than pretending.
        panic!("the driver finished; on a machine this would not return")
    }
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
