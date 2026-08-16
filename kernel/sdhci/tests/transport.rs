// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The SD host controller transport core, against a mock controller.
//!
//! An integration test rather than a unit one, because the mock lives in its
//! own crate now — shared with the ring-3 driver, so that the tier turning an
//! empty slot into `NoCard` and the tier turning `NoCard` into `NO_MEDIUM` are
//! held to the same model of the hardware. Linking the library rather than
//! recompiling it is what keeps one `Registers` trait in the build.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage")

use tessera_sdhci::*;
use tessera_sdhci_mock::{BASE_HZ, CARD_MAGIC, MockSdhci, card_byte};

/// **The divider rounds down, never up.** A divider chosen to land closest to
/// the target can overshoot, and overshooting a card's identification rate is
/// how a driver works on the card it was written against and not on the next
/// one.
#[test]
fn the_divider_never_overshoots_its_target() {
    // 400 kHz from 50 MHz: 50/128 = 390 kHz, and 50/64 = 781 kHz would be over.
    let (field, actual) = divider_for(BASE_HZ, 400_000).expect("divider");
    assert_eq!(field, 64);
    assert_eq!(actual, 390_625);
    assert!(actual <= 400_000, "under the target, never over");

    // An exact power-of-two division is taken exactly.
    assert_eq!(divider_for(BASE_HZ, 25_000_000), Ok((1, 25_000_000)));
    // A target at or above the base takes the base undivided.
    assert_eq!(divider_for(BASE_HZ, 50_000_000), Ok((0, BASE_HZ)));
    assert_eq!(divider_for(BASE_HZ, 100_000_000), Ok((0, BASE_HZ)));
}

/// A target below what the field can express gets the slowest the controller
/// can go, reported as what it is — not a wrapped divider, which would run the
/// card fast at exactly the moment the driver was trying to slow it down.
#[test]
fn a_target_below_the_dividers_reach_is_reported_not_wrapped() {
    let (field, actual) = divider_for(BASE_HZ, 1).expect("divider");
    assert_eq!(field, 0x80);
    assert_eq!(actual, BASE_HZ / 0x100);
    assert!(
        actual > 1,
        "and the caller can see it did not get what it asked"
    );
}

/// A controller reporting no base clock is refused rather than divided by zero.
#[test]
fn a_controller_with_no_base_clock_is_refused() {
    assert_eq!(divider_for(0, 400_000), Err(Error::NoBaseClock));
}

#[test]
fn bring_up_resets_powers_and_clocks_in_that_order() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");
    assert_eq!(host.base_hz(), BASE_HZ);
    let host_control = device.host_control();
    let clock_control = device.clock_control();
    // Bus power on at 3.3 V.
    assert_eq!(host_control & (1 << 8), 1 << 8, "powered");
    assert_eq!((host_control >> 9) & 0b111, 0b111, "at 3.3 V");
    // The clock is running and divided.
    assert_eq!(clock_control & 0b111, 0b111, "internal, stable, and out");
    assert_eq!((clock_control >> 8) & 0xff, 64, "the 400 kHz divider");
}

/// A card identification sequence, in the order the specification defines and
/// with each command's response read as its own kind.
#[test]
fn a_card_identifies_through_the_defined_sequence() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");

    host.command(CMD_GO_IDLE, 0, ResponseKind::None, None)
        .expect("idle");
    let check = host
        .command(CMD_SEND_IF_COND, IF_COND_ARG, ResponseKind::Short, None)
        .expect("if cond");
    // The card echoes the pattern, which is how it says it understood the
    // question at all rather than answering a different one.
    assert_eq!(check.0[0], IF_COND_ARG);

    host.command(CMD_APP, 0, ResponseKind::Short, None)
        .expect("app");
    let ready = host
        .command(
            ACMD_SEND_OP_COND,
            OP_COND_ARG,
            ResponseKind::ShortNoCrc,
            None,
        )
        .expect("op cond");
    assert_ne!(
        ready.0[0] & OP_COND_READY,
        0,
        "the card finished powering up"
    );

    let cid = host
        .command(CMD_ALL_SEND_CID, 0, ResponseKind::Long, None)
        .expect("cid");
    assert_eq!(cid.0, [1, 2, 3, 4], "a long response fills all four words");

    let rca = host
        .command(CMD_SEND_RELATIVE_ADDR, 0, ResponseKind::Short, None)
        .expect("rca");
    assert_eq!(rca.0[0] >> 16, 0xaaaa);

    let (seen, count) = device.commands();
    assert_eq!(
        &seen[..count],
        &[
            CMD_GO_IDLE,
            CMD_SEND_IF_COND,
            CMD_APP,
            ACMD_SEND_OP_COND,
            CMD_ALL_SEND_CID,
            CMD_SEND_RELATIVE_ADDR,
        ],
    );
}

/// A block comes back in the order the card sent it. Checked against a
/// recognisable ramp rather than a magic at the front, because a driver that
/// assembled the words in the wrong byte order would pass a magic check on a
/// value that happens to be symmetric and fail on real data.
#[test]
fn a_block_arrives_in_order() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");
    host.command(
        CMD_READ_SINGLE_BLOCK,
        0,
        ResponseKind::Short,
        Some(Transfer::Read),
    )
    .expect("read");
    let mut block = [0u8; BLOCK_LEN];
    host.read_block(&mut block).expect("block");
    assert_eq!(&block[..8], &CARD_MAGIC);
    for (index, byte) in block.iter().enumerate().skip(CARD_MAGIC.len()) {
        assert_eq!(*byte, card_byte(index), "byte {index}");
    }
}

/// A written block reaches the card in the order it was handed over, and the
/// direction is the card's business: a write with the read direction set would
/// deadlock the bus, with the card waiting for bytes the controller is trying
/// to read.
#[test]
fn a_written_block_reaches_the_card_in_order() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");
    let mut block = [0u8; BLOCK_LEN];
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = (index % 241) as u8;
    }
    host.command(
        CMD_WRITE_BLOCK,
        0,
        ResponseKind::Short,
        Some(Transfer::Write),
    )
    .expect("write command");
    host.write_block(&block).expect("block");
    assert_eq!(device.written(), block);
}

/// A buffer that is not one block is refused rather than partially filled: a
/// short one would leave the controller holding bytes nobody read, and the next
/// command would find them.
#[test]
fn a_buffer_that_is_not_a_block_is_refused() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");
    let mut short = [0u8; 64];
    assert_eq!(host.read_block(&mut short), Err(Error::BadLength));
    assert_eq!(host.write_block(&short), Err(Error::BadLength));
}

/// **An error is reported as an error, not as a timeout.** A failed command
/// sets its error bit and never sets completion, so a wait that looked only for
/// completion would spend its whole budget and report a timeout for something
/// the controller had already explained.
#[test]
fn a_command_the_controller_refuses_says_so() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");
    device.fail_next_command(0x0001);
    assert_eq!(
        host.command(CMD_SEND_IF_COND, IF_COND_ARG, ResponseKind::Short, None),
        Err(Error::CommandError(0x0001)),
    );
    // And the failure does not stick: the next command is judged on its own.
    assert!(
        host.command(CMD_SEND_IF_COND, IF_COND_ARG, ResponseKind::Short, None)
            .is_ok(),
    );
}

/// **No card is its own outcome.** One means the medium is gone and the other
/// means the controller is wedged, and a driver's response to them differs —
/// so a command issued to an empty slot says which immediately rather than
/// spending a timeout to say the wrong one.
#[test]
fn a_command_to_an_empty_slot_is_no_card_and_not_a_timeout() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");
    assert!(host.card_present());
    device.remove_card();
    assert!(!host.card_present());
    assert_eq!(
        host.command(
            CMD_READ_SINGLE_BLOCK,
            0,
            ResponseKind::Short,
            Some(Transfer::Read)
        ),
        Err(Error::NoCard),
    );
}

/// Insertion and removal are taken as a pair and cleared. Both can have
/// happened between two polls — a card pulled and pushed back is a *different*
/// card — and a driver told only the current state would see nothing changed.
#[test]
fn card_events_are_latched_and_taken_once() {
    let device = MockSdhci::new();
    let host = Host::reset_and_enable(&device, 400_000).expect("bring up");
    assert_eq!(host.take_card_events(), (false, false));
    device.remove_card();
    assert_eq!(host.take_card_events(), (false, true));
    // Taken once: a second poll does not see the same removal again, which is
    // what stops a driver tearing down twice.
    assert_eq!(host.take_card_events(), (false, false));
}
