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
pub mod sim;

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

/// Everything a driver asks of the world it runs in.
///
/// One trait, so a driver names its dependency once. A machine implements it
/// with syscalls; [`sim::Simulator`] implements it with a model.
pub trait Platform {
    /// Sends `request` and waits for the reply, which lands in `reply`.
    fn call(
        &mut self,
        endpoint: Endpoint,
        method: u32,
        request: &[u8],
        reply: &mut [u8],
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

/// The largest reply this template will carry.
///
/// Bounded because a driver runs where allocation is fallible, and stated here
/// rather than per-driver so that a class contract outgrowing it is a build
/// failure in one place instead of a truncation in several.
pub const MAX_REPLY: usize = 256;

/// The bind protocol's method ordinal.
const BIND_METHOD: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use sim::{Script, Simulator};

    /// A driver written **only against this crate**: it names no syscall, no
    /// handle number it was not given, and no kernel type. That is the claim
    /// the SDK makes, and this is the smallest thing that can test it.
    /// What the example driver reports when a step refuses it. Named rather
    /// than numbered at the call site, because a driver author reading a
    /// failure should not have to count.
    const BIND_REFUSED: u64 = 0xb1;
    const MAP_REFUSED: u64 = 0xb2;
    const INFO_REFUSED: u64 = 0xb6;
    const DMA_REFUSED: u64 = 0xb3;
    const ADDRESSES_WERE_THE_SAME: u64 = 0xb4;
    const SERVE_FAILED: u64 = 0xb5;

    fn echo_driver<P: Platform>(platform: &mut P, manager: Endpoint, service: Endpoint) -> u64 {
        // The device arrives at the handle this program's bootstrap contract
        // fixes; the bind reply says whether it may use it, not where it is.
        let device = Handle(0);
        let request = [0u8; 16];
        let mut reply = [0u8; 64];
        let Ok(len) = bind(platform, manager, &request, &mut reply) else {
            return BIND_REFUSED;
        };
        if len == 0 {
            return BIND_REFUSED;
        }
        let mut record = [0u8; 32];
        if platform.device_info(device, &mut record).is_err() {
            return INFO_REFUSED;
        }
        if platform.map_device(device, 0x1000).is_err() {
            return MAP_REFUSED;
        }
        let Ok(dma) = platform.dma_alloc(device, 0x2000) else {
            return DMA_REFUSED;
        };
        // The two addresses of one page are different numbers, and a driver
        // that assumed otherwise would work on a machine with no IOMMU and
        // fail on one with.
        if dma.va == dma.device_address {
            return ADDRESSES_WERE_THE_SAME;
        }

        let mut buffer = [0u8; 128];
        let served = serve(platform, service, &mut buffer, |method, request, reply| {
            reply[0] = method as u8;
            reply[1..1 + request.len()].copy_from_slice(request);
            Ok(1 + request.len())
        });
        match served {
            Ok(()) => u64::from(record[0]),
            Err(_) => SERVE_FAILED,
        }
    }

    #[test]
    fn a_driver_written_only_against_the_sdk_runs_on_the_simulator() {
        let mut sim = Simulator::new(Script::binds_and_answers());
        let report = echo_driver(&mut sim, Endpoint(Handle(0)), Endpoint(Handle(1)));
        assert_eq!(
            report, 4,
            "the first byte of the record the kernel reported"
        );
        assert_eq!(sim.replies(), 2, "both requests were answered");
    }

    /// **A driver whose manager refuses it.** The template turns that into one
    /// named error rather than a raw syscall result nobody can read.
    #[test]
    fn a_refused_bind_is_reported_as_one() {
        let mut sim = Simulator::new(Script::refuses_bind());
        assert_eq!(
            echo_driver(&mut sim, Endpoint(Handle(0)), Endpoint(Handle(1))),
            BIND_REFUSED,
        );
    }

    /// A client that goes away mid-conversation ends the loop rather than
    /// failing it. This is the case D170 made reachable, and a driver that
    /// treated it as an error would report a failure every time it was simply
    /// finished.
    #[test]
    fn a_client_going_away_finishes_the_driver_rather_than_failing_it() {
        let mut sim = Simulator::new(Script::client_leaves_immediately());
        let report = echo_driver(&mut sim, Endpoint(Handle(0)), Endpoint(Handle(1)));
        assert_eq!(report, 4, "bound, mapped, served nothing, and finished");
        assert_eq!(sim.replies(), 0);
    }

    /// The device refusing a mapping is a policy answer, and the driver hears
    /// which one it was.
    #[test]
    fn a_refused_mapping_is_not_a_kernel_number() {
        let mut sim = Simulator::new(Script::refuses_mapping());
        assert_eq!(
            echo_driver(&mut sim, Endpoint(Handle(0)), Endpoint(Handle(1))),
            MAP_REFUSED,
        );
    }
}
