// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `sdk::dma`.

use super::*;

/// **The two addresses of one page are different numbers**, and asking for
/// one by the other finds nothing.
#[test]
fn a_device_cannot_be_reached_at_the_drivers_own_address() {
    let mut pages = Pages::new();
    let dma = pages.grant(0x1000).expect("a page");
    assert_ne!(dma.device_address, dma.va);
    assert!(pages.seen_by_device(dma.device_address).is_some());
    assert!(
        pages.seen_by_device(dma.va).is_none(),
        "publishing a driver's own address to a device must find nothing"
    );
}

/// What the driver wrote is what the device would read.
#[test]
fn the_device_reads_what_the_driver_wrote() {
    let mut pages = Pages::new();
    let dma = pages.grant(0x2000).expect("a page");
    pages.with(&dma, |memory| {
        memory[..4].copy_from_slice(b"\xde\xad\xbe\xef")
    });
    let seen = pages.seen_by_device(dma.device_address).expect("granted");
    assert_eq!(&seen[..4], b"\xde\xad\xbe\xef");
}

/// A secret written and then cleared is gone; one merely written is not.
#[test]
fn a_page_can_be_asked_whether_it_still_holds_a_secret() {
    let key = [0x5au8; 16];
    let mut pages = Pages::new();
    let dma = pages.grant(0x3000).expect("a page");
    pages.with(&dma, |memory| memory[8..24].copy_from_slice(&key));
    assert!(pages.holds(&key), "the key is where the driver put it");
    pages.with(&dma, |memory| memory[8..24].fill(0));
    assert!(!pages.holds(&key), "and gone once the driver cleared it");
}

/// A page nobody granted is recorded rather than conjured.
#[test]
fn reaching_an_ungranted_page_is_recorded() {
    let mut pages = Pages::new();
    let stray = Dma {
        va: 0x9000,
        device_address: device_address_for(0x9000),
    };
    pages.with(&stray, |memory| memory[0] = 1);
    assert_eq!(pages.strays(), 1);
    assert!(pages.seen_by_device(stray.device_address).is_none());
}

/// The model runs out, and a refusal is an answer a driver must handle.
#[test]
fn the_model_runs_out_of_pages() {
    let mut pages = Pages::new();
    for index in 0..MAX_PAGES {
        assert!(pages.grant(0x1000 + index as u64 * PAGE as u64).is_some());
    }
    assert!(pages.grant(0xf000).is_none());
    assert_eq!(pages.granted(), MAX_PAGES);
}

/// Asking whether a page holds nothing must not answer yes.
#[test]
fn the_empty_secret_is_not_held() {
    let mut pages = Pages::new();
    let _ = pages.grant(0x1000);
    assert!(!pages.holds(&[]));
}

/// A secret that cannot fit in a page is not in one, and asking is not a
/// crash. The loop that searches a page has to be told where to stop, and
/// the answer for an oversize needle is "nowhere" rather than "at offset
/// zero, off the end".
#[test]
fn a_secret_larger_than_a_page_is_not_held() {
    let mut pages = Pages::new();
    let _ = pages.grant(0x1000);
    let oversize = [0u8; PAGE + 1];
    assert!(!pages.holds(&oversize));
}

/// **Two pages are two device addresses.** These two `va`s are the shape
/// every real one has — `tessera_uabi::layout` places the MMIO window, the
/// DMA page and the queue rings a megabyte apart — so a transform that
/// looked only at the low bits gave them one address between them, and the
/// device could be told about a page it would not have been reading.
#[test]
fn pages_a_megabyte_apart_are_told_apart() {
    let mut pages = Pages::new();
    let first = pages.grant(0x1000_00a0_0000).expect("a page");
    let second = pages.grant(0x1000_00b0_0000).expect("a page");
    assert_ne!(
        first.device_address, second.device_address,
        "two pages must not share one device address"
    );
    pages.with(&first, |memory| memory[0] = 1);
    pages.with(&second, |memory| memory[0] = 2);
    let seen = pages
        .seen_by_device(second.device_address)
        .expect("granted");
    assert_eq!(
        seen[0], 2,
        "a device reading the second page must not be shown the first"
    );
}

/// The same address is not handed out twice, because a machine would not.
#[test]
fn one_address_is_granted_once() {
    let mut pages = Pages::new();
    assert!(pages.grant(0x4000).is_some());
    assert!(
        pages.grant(0x4000).is_none(),
        "a second page at an address already mapped is a refusal"
    );
    assert_eq!(pages.granted(), 1);
}
