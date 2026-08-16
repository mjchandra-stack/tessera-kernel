// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-1: a driver written **only against the SDK** — naming no syscall, no
//! kernel type and no handle it was not given — run against a modelled world.
//!
//! An integration test rather than a unit test, because the model lives in
//! `//userspace/sdk-sim` and a crate cannot depend on something that depends
//! on it.

use tessera_sdk::*;
use tessera_sdk_sim::{Script, Simulator};

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
