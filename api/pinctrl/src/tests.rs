// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The refusals, which are the whole of what this crate is for. Everything
//! below is a board a table could describe and a request a driver could make.

use super::*;

/// Two drivers, named the way a manager would name them.
const UART: u32 = 1;
const SPI: u32 = 2;

/// An ordinary pin: it can drive, it has both pulls, and it has four functions.
const ORDINARY: PinCapabilities = PinCapabilities {
    max_drive_ma: 8,
    has_pull_up: true,
    has_pull_down: true,
    mux_settings: 4,
};

/// An input-only pin, which is a real thing on real parts and not a pin whose
/// drive strength nobody filled in.
const INPUT_ONLY: PinCapabilities = PinCapabilities {
    max_drive_ma: 0,
    has_pull_up: true,
    has_pull_down: false,
    mux_settings: 2,
};

const UART_PINS: Function = Function {
    id: 0x10,
    pins: &[(0, 1), (1, 1)],
    revisions: Revisions::ANY,
};

/// The same peripheral, moved to different pins on a later board — which is
/// the case pin tables exist for.
const UART_PINS_REV_A: Function = Function {
    id: 0x10,
    pins: &[(0, 1), (1, 1)],
    revisions: Revisions { first: 0, last: 1 },
};
const UART_PINS_REV_B: Function = Function {
    id: 0x10,
    pins: &[(4, 2), (5, 2)],
    revisions: Revisions { first: 2, last: 3 },
};

fn board(revision: u8) -> PinTable {
    let mut table = PinTable::new(revision);
    for pin in 0..8 {
        let capabilities = if pin == 7 { INPUT_ONLY } else { ORDINARY };
        table.declare(pin, capabilities).expect("declare");
    }
    table
}

/// **One pin, one owner, and the second claim is refused rather than granted.**
/// Two drivers each believing they own a pin is two drivers each believing the
/// other's configuration is theirs — and the symptom is a peripheral that works
/// until the other one is loaded.
#[test]
fn a_pin_already_held_is_refused_and_not_reassigned() {
    let mut table = board(0);
    table.claim(3, UART).expect("claim");
    assert_eq!(table.claim(3, SPI), Err(Error::PinBusy));
    assert_eq!(
        table.owner_of(3).expect("owner"),
        Some(UART),
        "still UART's"
    );

    // Claiming a pin you already hold changes nothing and is not an error: a
    // driver reclaiming its pins on a restart must not fail because it is the
    // one holding them.
    table.claim(3, UART).expect("reclaim");
    assert_eq!(table.owner_of(3).expect("owner"), Some(UART));

    // And released, it is available to the other one.
    assert_eq!(table.release(3, SPI), Err(Error::NotOwner));
    table.release(3, UART).expect("release");
    table.claim(3, SPI).expect("claim");
    assert_eq!(table.owner_of(3).expect("owner"), Some(SPI));
}

/// A pin released gives up its mux with its claim. A pin released while still
/// muxed is one the next owner finds already driving something, with the table
/// saying it is free.
#[test]
fn releasing_a_pin_gives_up_what_it_was_muxed_to() {
    let mut table = board(0);
    table.apply(&UART_PINS, UART).expect("apply");
    assert_eq!(table.mux_of(0).expect("mux"), Some((0x10, 1)));
    table.release(0, UART).expect("release");
    assert_eq!(table.mux_of(0).expect("mux"), None);
    assert_eq!(table.owner_of(0).expect("owner"), None);
}

/// **A mux is applied whole or not at all.** A bus is not a bus with three of
/// its four lines muxed, and the pins that did move would be driving something
/// while the caller is told the function is unavailable.
#[test]
fn a_function_whose_second_pin_is_taken_moves_neither() {
    let mut table = board(0);
    // Somebody else holds the second pin of the pair.
    table.claim(1, SPI).expect("claim");

    assert_eq!(table.apply(&UART_PINS, UART), Err(Error::PinBusy));
    // **Nothing moved**, including the pin that was available.
    assert_eq!(table.owner_of(0).expect("owner"), None);
    assert_eq!(table.mux_of(0).expect("mux"), None);
    assert_eq!(table.owner_of(1).expect("owner"), Some(SPI));

    // With it free, the whole function applies.
    table.release(1, SPI).expect("release");
    table.apply(&UART_PINS, UART).expect("apply");
    assert_eq!(table.mux_of(0).expect("mux"), Some((0x10, 1)));
    assert_eq!(table.mux_of(1).expect("mux"), Some((0x10, 1)));
}

/// One pin cannot be two things, even for one owner. A table that said it was
/// would be the table lying.
#[test]
fn a_pin_muxed_to_another_function_is_a_conflict_for_its_own_owner() {
    const OTHER: Function = Function {
        id: 0x20,
        pins: &[(1, 2), (2, 2)],
        revisions: Revisions::ANY,
    };
    let mut table = board(0);
    table.apply(&UART_PINS, UART).expect("apply");
    assert_eq!(table.apply(&OTHER, UART), Err(Error::PinBusy));
    assert_eq!(table.mux_of(1).expect("mux"), Some((0x10, 1)), "unmoved");
    assert_eq!(table.mux_of(2).expect("mux"), None, "and untouched");

    // Applying the *same* function again is idempotent, which is what a driver
    // re-applying its own table after a reset does.
    table.apply(&UART_PINS, UART).expect("re-apply");
}

/// **A declaration is scoped to a revision**, and applying one out of range is
/// refused rather than done anyway. The same peripheral moves pins between
/// board revisions, and a configuration applied to the wrong one drives the
/// wrong pins with complete confidence.
#[test]
fn a_declaration_for_another_revision_does_not_apply_here() {
    let mut table = board(2);
    assert_eq!(table.revision(), 2);
    assert_eq!(
        table.apply(&UART_PINS_REV_A, UART),
        Err(Error::OutOfRevision)
    );
    assert_eq!(table.owner_of(0).expect("owner"), None, "nothing moved");

    table.apply(&UART_PINS_REV_B, UART).expect("apply");
    assert_eq!(table.mux_of(4).expect("mux"), Some((0x10, 2)));

    // The ends are inclusive, because "from revision 2" and "to revision 2"
    // both have to be expressible without an off-by-one.
    assert!(Revisions { first: 2, last: 3 }.covers(2));
    assert!(Revisions { first: 2, last: 3 }.covers(3));
    assert!(!Revisions { first: 2, last: 3 }.covers(1));
    assert!(Revisions::ANY.covers(0));
    assert!(Revisions::ANY.covers(u8::MAX));
}

/// **A table walk says what it passed over.** A walk that silently skipped the
/// declarations for other revisions would be indistinguishable from a table
/// with nothing in it for this board — and "no quirk applies here" and "the
/// quirks are all for another revision" are the difference between a working
/// board and a puzzle.
#[test]
fn a_table_walk_reports_what_it_skipped() {
    const TABLE: [Function; 2] = [UART_PINS_REV_A, UART_PINS_REV_B];

    let mut early = board(0);
    let applied = early.apply_all(&TABLE, UART).expect("walk");
    assert_eq!(applied.applied, 1);
    assert_eq!(applied.skipped, 1, "and it says so");
    assert_eq!(early.mux_of(0).expect("mux"), Some((0x10, 1)));
    assert_eq!(early.mux_of(4).expect("mux"), None);

    let mut late = board(2);
    let applied = late.apply_all(&TABLE, UART).expect("walk");
    assert_eq!(applied.applied, 1);
    assert_eq!(applied.skipped, 1);
    assert_eq!(late.mux_of(0).expect("mux"), None);
    assert_eq!(late.mux_of(4).expect("mux"), Some((0x10, 2)));

    // A board no declaration covers applies nothing and skips everything,
    // which is a report rather than a silence.
    let mut unknown = board(9);
    let applied = unknown.apply_all(&TABLE, UART).expect("walk");
    assert_eq!(applied.applied, 0);
    assert_eq!(applied.skipped, 2);
}

/// **Refused and never clamped**, for the reason a clock rate outside its range
/// is: a driver handed the nearest thing the hardware could manage cannot tell
/// it from what it asked for, and a pin driving at half the current somebody
/// sized a bus for fails at the far end rather than here.
#[test]
fn a_configuration_the_pin_cannot_honour_is_refused_not_clamped() {
    let mut table = board(0);
    table.claim(0, UART).expect("claim");
    assert_eq!(
        table.configure(
            0,
            UART,
            PinConfig {
                bias: Bias::Float,
                drive_ma: 12,
            },
        ),
        Err(Error::BadConfig),
    );
    assert_eq!(
        table.config_of(0).expect("config").drive_ma,
        0,
        "and nothing was applied at the nearest value it could manage",
    );
    table
        .configure(
            0,
            UART,
            PinConfig {
                bias: Bias::PullUp,
                drive_ma: 8,
            },
        )
        .expect("configure");
    assert_eq!(table.config_of(0).expect("config").drive_ma, 8);

    // A pull the pin does not have is the same refusal. Pin 7 has a pull-up
    // and no pull-down, which is an ordinary asymmetry on a real part.
    table.claim(7, UART).expect("claim");
    assert_eq!(
        table.configure(
            7,
            UART,
            PinConfig {
                bias: Bias::PullDown,
                drive_ma: 0,
            },
        ),
        Err(Error::BadConfig),
    );
    table
        .configure(
            7,
            UART,
            PinConfig {
                bias: Bias::PullUp,
                drive_ma: 0,
            },
        )
        .expect("configure");
    // And an input-only pin cannot be asked to drive at all.
    assert_eq!(
        table.configure(
            7,
            UART,
            PinConfig {
                bias: Bias::PullUp,
                drive_ma: 1,
            },
        ),
        Err(Error::BadConfig),
    );
}

/// Configuring a pin you have not claimed is the same mistake as claiming one
/// twice, seen from the other side.
#[test]
fn configuring_a_pin_you_do_not_hold_is_refused() {
    let mut table = board(0);
    table.claim(0, UART).expect("claim");
    assert_eq!(
        table.configure(0, SPI, PinConfig::default()),
        Err(Error::NotOwner),
    );
    assert_eq!(
        table.configure(1, SPI, PinConfig::default()),
        Err(Error::NotOwner),
        "an unclaimed pin is nobody's either",
    );
}

/// A pin no table describes is an answer, not a slot that happens to be there.
#[test]
fn a_pin_this_board_does_not_have_is_refused() {
    const OFF_BOARD: Function = Function {
        id: 0x30,
        pins: &[(0, 1), (30, 1)],
        revisions: Revisions::ANY,
    };
    let mut table = board(0);
    assert_eq!(table.claim(30, UART), Err(Error::NoSuchPin));
    assert_eq!(table.owner_of(30), Err(Error::NoSuchPin));
    assert_eq!(
        table.claim(MAX_PINS as u8, UART),
        Err(Error::NoSuchPin),
        "and past the table entirely",
    );
    // A function naming one applies none of itself, which is the all-or-nothing
    // rule reaching the case where the pin is not merely busy but absent.
    assert_eq!(table.apply(&OFF_BOARD, UART), Err(Error::NoSuchPin));
    assert_eq!(table.owner_of(0).expect("owner"), None);
}

/// A mux setting past what the pin has is not a function this pin can perform,
/// and saying so beats writing a number into a field that has no meaning.
#[test]
fn a_mux_setting_the_pin_does_not_have_is_refused() {
    const TOO_FAR: Function = Function {
        id: 0x40,
        pins: &[(0, 9)],
        revisions: Revisions::ANY,
    };
    let mut table = board(0);
    assert_eq!(table.apply(&TOO_FAR, UART), Err(Error::BadConfig));
    assert_eq!(table.owner_of(0).expect("owner"), None);
}
