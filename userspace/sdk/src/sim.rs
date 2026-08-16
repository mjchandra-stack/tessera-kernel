// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The simulator**: a [`Platform`](super::Platform) that answers from a model
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

use super::dma::Pages;
use super::{Dma, Endpoint, Error, Handle, Platform, Request};

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
}

impl Simulator {
    pub fn new(script: Script) -> Simulator {
        Simulator {
            script,
            served: 0,
            replies: 0,
            bound: false,
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
        })
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
mod tests {
    use super::*;

    /// **The two addresses of a page are different numbers.** A simulator that
    /// blurred them would pass a driver that a machine with an IOMMU refuses.
    #[test]
    fn dma_hands_back_two_different_addresses() {
        let mut sim = Simulator::new(Script::binds_and_answers());
        let dma = sim.dma_alloc(Handle(7), 0x2000).expect("allowed");
        assert_eq!(dma.va, 0x2000);
        assert_ne!(dma.device_address, dma.va);
    }

    /// **A driver can now write to the page it was given.** Before the model
    /// owned its pages this was not a test that could exist: the address was a
    /// number nobody had mapped, and a driver that used it would have died.
    #[test]
    fn a_driver_writes_through_the_page_it_was_granted() {
        let mut sim = Simulator::new(Script::binds_and_answers());
        let dma = sim.dma_alloc(Handle(7), 0x2000).expect("allowed");
        sim.with_dma(&dma, |page| page[..3].copy_from_slice(b"abc"));
        let seen = sim
            .pages()
            .seen_by_device(dma.device_address)
            .expect("the device can reach it");
        assert_eq!(&seen[..3], b"abc");
    }

    /// A device that grants two pages refuses the third, and a driver that
    /// never met a refusal has an error path that never ran.
    #[test]
    fn dma_runs_out() {
        let mut sim = Simulator::new(Script::dma_runs_out_after(2));
        assert!(sim.dma_alloc(Handle(7), 0x1000).is_ok());
        assert!(sim.dma_alloc(Handle(7), 0x2000).is_ok());
        assert_eq!(sim.dma_alloc(Handle(7), 0x3000), Err(Error::Refused));
    }

    /// A capability with no DMA right at all.
    #[test]
    fn dma_can_be_refused_outright() {
        let mut sim = Simulator::new(Script::refuses_dma());
        assert_eq!(sim.dma_alloc(Handle(7), 0x1000), Err(Error::Refused));
    }

    /// A client that has said everything it is going to say reports the peer as
    /// gone, which is what ends a serve loop rather than an error would.
    #[test]
    fn a_finished_client_reports_the_peer_gone() {
        let mut sim = Simulator::new(Script::client_leaves_immediately());
        let mut buffer = [0u8; 16];
        assert_eq!(
            sim.receive(Endpoint(Handle(1)), &mut buffer),
            Err(Error::PeerGone),
        );
    }

    /// The refusals are refusals, not silence.
    #[test]
    fn a_capability_without_the_right_refuses() {
        let mut sim = Simulator::new(Script::refuses_mapping());
        assert_eq!(sim.map_device(Handle(7), 0x1000), Err(Error::Refused));
    }
}
