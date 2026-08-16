// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **What a driver does with a DMA page, watched.**
//!
//! The functions here are driver-shaped on purpose: each takes a
//! [`Platform`](tessera_sdk::Platform) and nothing else, so the same body would
//! compile into a ring-3 program. What the tests then assert is not that they
//! returned the right value — a driver returning `Ok` while leaving a key in a
//! page returns exactly the same value as one that cleared it — but what the
//! *memory* looks like afterwards, which is a question no driver's return type
//! can answer and which nothing in this tree could ask before the model owned
//! its pages.
//!
//! Two claims get run here that were previously only written down:
//!
//! - A driver hands a device the *device's* address. `userspace/crypto-driver`
//!   says so in a comment; on a machine with no IOMMU the two numbers are close
//!   enough that publishing the wrong one works anyway, so the machine cannot
//!   tell. The model can, and does, because it deliberately makes them differ.
//! - A driver handed a key does not leave it lying in a page. That sentence is
//!   in the crypto driver's module header and in `docs/security/02`, and until
//!   now the only thing standing behind it was that somebody had read the code.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Developer Experience"),
//! docs/security/02-cryptography-and-key-management.md

use tessera_sdk::{Error, Handle, Platform};
use tessera_sdk_sim::{Script, Simulator};

/// Where this driver-shaped code asks for its page. Any address; the point of
/// the exercise is that the driver does not get to assume anything about it.
const PAGE_VA: u64 = 0x7000;

/// A driver that is handed a key, gives a device access to it, and cleans up.
///
/// `clear` is what an inversion turns off. It is not a feature — no driver
/// would ship with it false — it is how a test proves the check it is making
/// can fail.
fn hand_a_key_to_a_device<P: Platform>(
    platform: &mut P,
    key: &[u8],
    clear: bool,
) -> Result<u64, Error> {
    let dma = platform.dma_alloc(Handle(2), PAGE_VA)?;
    platform.with_dma(&dma, |page| page[..key.len()].copy_from_slice(key));
    // The device is told where to read, in the only address it has.
    let published = dma.device_address;
    if clear {
        // The device has taken it; the page has no reason to keep it.
        platform.with_dma(&dma, |page| page[..key.len()].fill(0));
    }
    Ok(published)
}

/// The same driver with the bug this model exists to catch: it publishes the
/// address *it* writes through instead of the one the device reads.
fn publishes_its_own_address<P: Platform>(platform: &mut P) -> Result<u64, Error> {
    let dma = platform.dma_alloc(Handle(2), PAGE_VA)?;
    platform.with_dma(&dma, |page| page[0] = 0x42);
    Ok(dma.va)
}

/// The positive path: the device can reach what the driver wrote.
#[test]
fn the_device_is_given_an_address_it_can_reach() {
    let mut sim = Simulator::new(Script::binds_and_answers());
    let published = hand_a_key_to_a_device(&mut sim, &[0x11; 16], true).expect("dma allowed");
    assert!(
        sim.pages().seen_by_device(published).is_some(),
        "a device told this address would find nothing"
    );
    assert_eq!(sim.pages().granted(), 1);
    assert_eq!(sim.pages().strays(), 0);
}

/// **The bug an IOMMU turns into a fault.** Both numbers are addresses of the
/// same page and only one of them is the device's; a model that returned one
/// number for both would pass this driver.
#[test]
fn publishing_the_drivers_own_address_reaches_no_device() {
    let mut sim = Simulator::new(Script::binds_and_answers());
    let published = publishes_its_own_address(&mut sim).expect("dma allowed");
    assert!(
        sim.pages().seen_by_device(published).is_none(),
        "the driver's own address must not be reachable as a device address"
    );
}

/// **The claim the crypto driver's header makes**, run rather than read.
#[test]
fn a_key_does_not_survive_in_the_page_the_device_read_it_from() {
    let key = [0xa5u8; 16];
    let mut sim = Simulator::new(Script::binds_and_answers());
    hand_a_key_to_a_device(&mut sim, &key, true).expect("dma allowed");
    assert!(
        !sim.pages().holds(&key),
        "the key is still in a page this driver was finished with"
    );
}

/// And the inversion, so the check above is known to be capable of failing.
/// A driver that skips the clearing returns the identical value.
#[test]
fn a_driver_that_does_not_clear_leaves_the_key_behind() {
    let key = [0xa5u8; 16];
    let mut sim = Simulator::new(Script::binds_and_answers());
    let mut careless = Simulator::new(Script::binds_and_answers());
    let clean = hand_a_key_to_a_device(&mut sim, &key, true).expect("dma allowed");
    let dirty = hand_a_key_to_a_device(&mut careless, &key, false).expect("dma allowed");
    assert_eq!(
        clean, dirty,
        "the two drivers are indistinguishable from what they return"
    );
    assert!(!sim.pages().holds(&key));
    assert!(
        careless.pages().holds(&key),
        "the harness cannot tell a careless driver from a careful one"
    );
}

/// A capability that carries no DMA right at all, which a driver must handle
/// rather than assume away.
#[test]
fn a_driver_meets_a_refusal() {
    let mut sim = Simulator::new(Script::refuses_dma());
    assert_eq!(
        hand_a_key_to_a_device(&mut sim, &[0; 4], true),
        Err(Error::Refused)
    );
    assert!(
        !sim.pages().holds(&[0xa5; 4]),
        "a refused allocation must leave no page behind"
    );
}

/// Fault injection: the grant that succeeds and the next one that does not.
/// A driver whose error path only runs on the first allocation has an error
/// path that has not run.
#[test]
fn dma_runs_out_partway_through() {
    let mut sim = Simulator::new(Script::dma_runs_out_after(1));
    assert!(sim.dma_alloc(Handle(2), PAGE_VA).is_ok());
    assert_eq!(
        sim.dma_alloc(Handle(2), PAGE_VA + 0x1000),
        Err(Error::Refused)
    );
    assert_eq!(sim.pages().granted(), 1);
}

/// A driver reaching a page nobody gave it is recorded, not accommodated.
#[test]
fn a_page_nobody_granted_is_a_stray() {
    let mut sim = Simulator::new(Script::binds_and_answers());
    let invented = tessera_sdk::Dma {
        va: 0xdead_0000,
        device_address: 0xbeef_0000,
    };
    sim.with_dma(&invented, |page| page[0] = 1);
    assert_eq!(sim.pages().strays(), 1);
    assert_eq!(sim.pages().granted(), 0);
}
