// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the simulator.

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
