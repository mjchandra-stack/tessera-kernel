// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The driver's side of a card that has gone.
//!
//! The transport core's own tests establish that an empty slot answers
//! [`SdError::NoCard`] rather than spending a timeout. These start where those
//! stop: what the *driver* does with that answer, which is the part a client
//! sees and the part no machine in this tree can exercise, because QEMU's
//! `sdhci-pci` reports a card present in an empty slot.
//!
//! The mock is the transport's own, deliberately: a second one written here
//! could disagree with it about when a card is gone, and both suites would pass
//! while describing different hardware.

use super::*;
use tessera_sdhci_mock::MockSdhci;

/// The rate a bring-up asks for. Identification speed, as the driver uses.
const IDENTIFY_HZ: u64 = 400_000;

/// A driver that has identified a card and is serving it.
fn ready_driver() -> Driver {
    Driver {
        clocks: ClockTable::new(),
        rca: 0xaaaa,
        block_addressed: true,
        ready: true,
        power: BlockPowerState::Active,
    }
}

/// **The case the boot check cannot reach.** A card is taken out between two
/// requests, the driver notices it before the next one, and the answer becomes
/// `NO_MEDIUM` — the value the block contract has carried since it was written
/// and which nothing on this machine could previously return.
#[test]
fn a_card_taken_out_between_requests_answers_no_medium() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, IDENTIFY_HZ).expect("bring up");
    let mut driver = ready_driver();

    // The same request, twice, across the removal — because a driver that
    // always answered NO_MEDIUM would pass the second half alone.
    let mut block = [0u8; BLOCK_LEN];
    assert_eq!(
        read_block(&mut driver, &host, 0, &mut block),
        BlockError::Ok,
        "with a card in the slot the read is served"
    );

    device.remove_card();
    check_presence(&mut driver, &host);
    // **Asserted here, before the read.** A driver that noticed nothing between
    // requests would still answer `NO_MEDIUM` below, because the command it
    // then issued would come back `NoCard` on its own — so a test that only
    // looked at the answer would pass with card detection removed entirely,
    // and this is the line that makes it about the poll.
    assert!(
        !driver.ready,
        "the poll between requests is what noticed, not the request itself"
    );
    assert_eq!(
        read_block(&mut driver, &host, 0, &mut block),
        BlockError::NoMedium,
    );
}

/// A card that goes while a request is already in flight is `NO_MEDIUM` too.
///
/// This is the translation proper: nothing polled presence, so the refusal
/// arrives from the controller as [`SdError::NoCard`] out of the command
/// itself, and the driver has to recognise it there.
#[test]
fn a_card_that_goes_mid_request_is_no_medium_and_not_an_io_error() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, IDENTIFY_HZ).expect("bring up");
    let mut driver = ready_driver();

    device.remove_card();
    let mut block = [0u8; BLOCK_LEN];
    assert_eq!(
        read_block(&mut driver, &host, 0, &mut block),
        BlockError::NoMedium,
        "the command's own NoCard is the medium going, not a bus fault"
    );
    assert!(
        !driver.ready,
        "and the driver stops believing it has a card"
    );
}

/// **And nothing else becomes `NO_MEDIUM`.** A controller that refuses a
/// command is a fault the client may retry; telling it the medium is gone would
/// have it give up on a card that is still in the slot. This is the assertion
/// that gives the one above its meaning.
#[test]
fn a_controller_error_is_an_io_error_and_the_card_is_still_there() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, IDENTIFY_HZ).expect("bring up");
    let mut driver = ready_driver();

    device.fail_next_command(0x0001);
    let mut block = [0u8; BLOCK_LEN];
    assert_eq!(
        read_block(&mut driver, &host, 0, &mut block),
        BlockError::IoError,
    );
    assert!(
        driver.ready,
        "a bus error does not mean the card left, and the next request is served"
    );
    assert_eq!(
        read_block(&mut driver, &host, 0, &mut block),
        BlockError::Ok,
    );
}

/// Writes translate the same way reads do. Asserted rather than assumed,
/// because the two paths are written out separately and a driver that got reads
/// right and writes wrong would lose a client's data to a retry loop against a
/// slot with nothing in it.
#[test]
fn a_write_to_a_card_that_left_is_no_medium() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, IDENTIFY_HZ).expect("bring up");
    let mut driver = ready_driver();

    let block = [0x5au8; BLOCK_LEN];
    assert_eq!(write_block(&mut driver, &host, 0, &block), BlockError::Ok);
    assert_eq!(device.written(), block, "the write reached the card");

    device.remove_card();
    assert_eq!(
        write_block(&mut driver, &host, 0, &block),
        BlockError::NoMedium,
    );

    // And a controller fault on the write path is still an I/O error.
    device.insert_card();
    let mut fresh = ready_driver();
    device.fail_next_command(0x0002);
    assert_eq!(
        write_block(&mut fresh, &host, 0, &block),
        BlockError::IoError,
    );
}

/// **A card pushed back in is a different card.** The driver's own comment says
/// present and identified are not the same thing; this is what holds it to that.
/// Presence returning is not identification, and serving the new card as though
/// it were the old one would read a sector belonging to somebody else.
#[test]
fn a_card_put_back_is_not_served_until_it_is_identified_again() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, IDENTIFY_HZ).expect("bring up");
    let mut driver = ready_driver();

    device.remove_card();
    device.insert_card();
    // Both events are latched, and the removal is what a driver must act on
    // even though the slot is occupied again by the time it looks.
    check_presence(&mut driver, &host);
    assert!(!driver.ready);
    assert!(host.card_present(), "the slot is occupied");

    // And a later poll does not quietly restore it: only identification does,
    // and that is the serve loop's job rather than this function's.
    check_presence(&mut driver, &host);
    assert!(!driver.ready);
    let mut block = [0u8; BLOCK_LEN];
    assert_eq!(
        read_block(&mut driver, &host, 0, &mut block),
        BlockError::NoMedium,
    );
}

/// A request to a driver with no card never reaches the bus. A command issued
/// into an empty slot would be answered by the controller anyway, but the
/// driver is not entitled to ask: the sector number came from a client, and a
/// card put back in between the two would be handed a stale request.
#[test]
fn a_request_with_no_card_issues_no_command() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, IDENTIFY_HZ).expect("bring up");
    let mut driver = ready_driver();
    driver.ready = false;

    let (_, before) = device.commands();
    let mut block = [0u8; BLOCK_LEN];
    assert_eq!(
        read_block(&mut driver, &host, 0, &mut block),
        BlockError::NoMedium,
    );
    assert_eq!(
        write_block(&mut driver, &host, 0, &block),
        BlockError::NoMedium,
    );
    let (_, after) = device.commands();
    assert_eq!(before, after, "no command was issued");
}

/// A byte-addressed card takes a byte offset and a block-addressed one takes a
/// block number. They agree at sector zero and nowhere else, which is why every
/// test above reads sector zero and this one does not.
#[test]
fn a_sector_becomes_the_address_the_card_understands() {
    let block_addressed = ready_driver();
    assert_eq!(block_addressed.address_of(9), 9);

    let mut byte_addressed = ready_driver();
    byte_addressed.block_addressed = false;
    assert_eq!(byte_addressed.address_of(9), 9 * SECTOR as u32);
}
