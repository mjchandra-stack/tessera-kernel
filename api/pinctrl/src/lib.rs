// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Pin control: the part of it that is **data and refusals** rather than
//! registers.
//!
//! `docs/drivers/04` asks for "pin muxing and electrical configuration,
//! declared in data and scoped to hardware revisions per the quirk-management
//! rules". Every word of that is policy. Which pins a function needs, what a
//! pin may be muxed to, what electrical settings it supports and which board
//! revisions a declaration applies to are facts about a design, not about a
//! controller — and a driver that decided them for itself would be a driver
//! whose board support lives in code nobody can read as a table.
//!
//! So it lives here, host-tested, for the reason `api/clock`'s arbitration
//! does: it is where the mistakes are, and none of them need hardware to make.
//!
//! # One pin has one owner
//!
//! Not a convention — a refusal. Two drivers each believing they own a pin is
//! two drivers each believing the other's configuration is theirs, and the
//! symptom is a peripheral that works until the other one is loaded. A second
//! claim is refused rather than granted, and rather than silently overwriting
//! the first.
//!
//! # A mux is applied whole or not at all
//!
//! A function needs several pins together — a bus is not a bus with three of
//! its four lines muxed. So applying one is a transaction: if any pin in it is
//! unavailable, **nothing** is applied. A partly applied mux leaves the board
//! in a state no table describes, which is worse than the function not working,
//! because the pins that did move are now driving something.
//!
//! # A declaration is scoped to a revision
//!
//! `docs/lifecycle`'s quirk-management rules say a workaround is scoped to the
//! hardware it is for. A pin table is where that bites hardest: the same
//! peripheral moves pins between board revisions, and a configuration applied
//! to the wrong revision drives the wrong pins with complete confidence. A
//! function out of range is refused, and a table walk **reports what it
//! skipped** rather than quietly applying a subset.
//!
//! Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
//! ("GPIO And Pin Control")
//! Budget: none (a configuration path, not a data path)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
mod tests;

/// Pins one table describes. Bounded like every pool in this tree.
pub const MAX_PINS: usize = 32;

/// Pins one function may need at once.
pub const MAX_FUNCTION_PINS: usize = 8;

/// What can go wrong. Every variant is a fact about the request or about the
/// board, never a programming error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// A pin this table does not describe.
    NoSuchPin,
    /// The pin is claimed by somebody else.
    ///
    /// **Not "reassigned to you".** A pin quietly taken from its owner is a
    /// driver still configuring something it no longer has.
    PinBusy,
    /// The caller does not hold this pin. Configuring a pin you have not
    /// claimed is the same mistake as claiming one twice, seen from the other
    /// side.
    NotOwner,
    /// The pin cannot do what the configuration asks — a drive strength above
    /// what it supports, or a bias it does not have.
    ///
    /// **Refused and never clamped**, for the reason `api/clock` refuses a rate
    /// outside a declared range: a consumer handed the nearest thing the
    /// hardware could manage cannot tell it from what it asked for, and a pin
    /// driving at half the current somebody sized a bus for fails at the far
    /// end rather than here.
    BadConfig,
    /// The function's declaration does not cover this board revision.
    OutOfRevision,
    /// More pins or functions than this table holds.
    TooMany,
}

/// How a pin is held when nothing is driving it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Bias {
    /// Nothing holds it, which is what an output wants and what an unconnected
    /// input must not have.
    #[default]
    Float,
    PullUp,
    PullDown,
}

/// What a pin is physically able to do, as the design says.
///
/// Declared per pin rather than assumed per controller: on a real part the pins
/// are not alike, and a table that described the best of them would let a
/// configuration through that the worst cannot honour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PinCapabilities {
    /// The strongest drive this pin supports, milliamps. Zero for a pin that
    /// cannot drive at all — an input-only pin, which is a real thing and not
    /// a missing number.
    pub max_drive_ma: u8,
    /// Whether it has a pull-up and a pull-down. A pin with neither can only
    /// be [`Bias::Float`].
    pub has_pull_up: bool,
    pub has_pull_down: bool,
    /// The mux settings this pin has. A setting past this is not a function
    /// this pin can perform.
    pub mux_settings: u8,
}

/// A pin's electrical configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PinConfig {
    pub bias: Bias,
    /// Zero means "leave the drive strength alone", which is what a pin used as
    /// an input wants and is distinguishable from asking for zero milliamps —
    /// a request no pin can honour and which is refused.
    pub drive_ma: u8,
}

/// Board revisions a declaration applies to, inclusive at both ends.
///
/// Inclusive because a quirk that applies "from revision 2" and one that
/// applies "to revision 2" both have to be expressible, and a half-open range
/// makes one of them read as an off-by-one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Revisions {
    pub first: u8,
    pub last: u8,
}

impl Revisions {
    /// Every revision — a declaration that is not a quirk.
    pub const ANY: Revisions = Revisions {
        first: 0,
        last: u8::MAX,
    };

    pub fn covers(&self, revision: u8) -> bool {
        revision >= self.first && revision <= self.last
    }
}

/// One function, and the pins it needs together.
///
/// `&'static` because this is the table `docs/drivers/04` asks for: data,
/// declared once, readable as a description of the board. Compiled in for now
/// for the reason the device manager's manifest is — where it should come from
/// is a configuration service reading a signed package, and that is one
/// substitution away.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Function {
    pub id: u32,
    /// The pins, and the mux setting each takes. Per pin rather than one
    /// setting for the group: on a real part the same function is a different
    /// alternate number on different pins, and a table that assumed otherwise
    /// would be describing a part nobody makes.
    pub pins: &'static [(u8, u8)],
    /// Which board revisions this declaration is for.
    pub revisions: Revisions,
}

/// What one pin is doing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Pin {
    capabilities: PinCapabilities,
    /// Who holds it, and `None` for a pin nobody has claimed.
    owner: Option<u32>,
    /// The function it is muxed to and the setting that took, if any.
    mux: Option<(u32, u8)>,
    config: PinConfig,
}

/// The pins of one board, and who has what.
pub struct PinTable {
    pins: [Option<Pin>; MAX_PINS],
    revision: u8,
}

impl PinTable {
    /// A table for a board of this revision.
    ///
    /// The revision is the table's, not each request's: it is a fact about the
    /// machine this is running on, and a caller that could supply its own would
    /// be able to apply another board's quirks to this one.
    pub fn new(revision: u8) -> PinTable {
        PinTable {
            pins: [None; MAX_PINS],
            revision,
        }
    }

    pub fn revision(&self) -> u8 {
        self.revision
    }

    /// Says a pin exists and what it can do.
    pub fn declare(&mut self, pin: u8, capabilities: PinCapabilities) -> Result<(), Error> {
        let slot = self
            .pins
            .get_mut(usize::from(pin))
            .ok_or(Error::NoSuchPin)?;
        *slot = Some(Pin {
            capabilities,
            owner: None,
            mux: None,
            config: PinConfig::default(),
        });
        Ok(())
    }

    fn pin(&self, pin: u8) -> Result<&Pin, Error> {
        self.pins
            .get(usize::from(pin))
            .and_then(Option::as_ref)
            .ok_or(Error::NoSuchPin)
    }

    fn pin_mut(&mut self, pin: u8) -> Result<&mut Pin, Error> {
        self.pins
            .get_mut(usize::from(pin))
            .and_then(Option::as_mut)
            .ok_or(Error::NoSuchPin)
    }

    /// Takes a pin for `owner`.
    ///
    /// Claiming a pin you already hold succeeds and changes nothing — a driver
    /// that claims its pins during a restart must not fail because it is the
    /// one holding them.
    pub fn claim(&mut self, pin: u8, owner: u32) -> Result<(), Error> {
        let pin = self.pin_mut(pin)?;
        match pin.owner {
            None => {
                pin.owner = Some(owner);
                Ok(())
            }
            Some(held) if held == owner => Ok(()),
            Some(_) => Err(Error::PinBusy),
        }
    }

    /// Gives a pin back, and with it whatever it was muxed to.
    ///
    /// The mux goes with the claim rather than outliving it: a pin released
    /// while still muxed is a pin the next owner would find already driving
    /// something, and the table would say it was free.
    pub fn release(&mut self, pin: u8, owner: u32) -> Result<(), Error> {
        let pin = self.pin_mut(pin)?;
        match pin.owner {
            Some(held) if held == owner => {
                pin.owner = None;
                pin.mux = None;
                pin.config = PinConfig::default();
                Ok(())
            }
            _ => Err(Error::NotOwner),
        }
    }

    pub fn owner_of(&self, pin: u8) -> Result<Option<u32>, Error> {
        Ok(self.pin(pin)?.owner)
    }

    pub fn mux_of(&self, pin: u8) -> Result<Option<(u32, u8)>, Error> {
        Ok(self.pin(pin)?.mux)
    }

    pub fn config_of(&self, pin: u8) -> Result<PinConfig, Error> {
        Ok(self.pin(pin)?.config)
    }

    /// Sets a pin's electrical configuration, within what the pin can do.
    pub fn configure(&mut self, pin: u8, owner: u32, config: PinConfig) -> Result<(), Error> {
        let held = self.pin(pin)?;
        if held.owner != Some(owner) {
            return Err(Error::NotOwner);
        }
        let capabilities = held.capabilities;
        if config.drive_ma > capabilities.max_drive_ma {
            return Err(Error::BadConfig);
        }
        match config.bias {
            Bias::PullUp if !capabilities.has_pull_up => return Err(Error::BadConfig),
            Bias::PullDown if !capabilities.has_pull_down => return Err(Error::BadConfig),
            _ => {}
        }
        self.pin_mut(pin)?.config = config;
        Ok(())
    }

    /// Applies a function's mux: **all of its pins, or none of them.**
    ///
    /// The check runs over every pin before anything changes, because a partly
    /// applied mux leaves the board in a state no table describes — and the
    /// pins that did move are driving something while the caller is being told
    /// the function is not available.
    pub fn apply(&mut self, function: &Function, owner: u32) -> Result<(), Error> {
        if !function.revisions.covers(self.revision) {
            return Err(Error::OutOfRevision);
        }
        if function.pins.len() > MAX_FUNCTION_PINS {
            return Err(Error::TooMany);
        }
        // Every refusal, found before a single pin moves.
        for (pin, setting) in function.pins {
            let held = self.pin(*pin)?;
            match held.owner {
                Some(other) if other != owner => return Err(Error::PinBusy),
                _ => {}
            }
            // A pin already muxed to a *different* function is a conflict even
            // when this caller owns it: one pin cannot be two things, and the
            // table saying it is would be the table lying.
            if let Some((existing, _)) = held.mux
                && existing != function.id
            {
                return Err(Error::PinBusy);
            }
            if *setting >= held.capabilities.mux_settings {
                return Err(Error::BadConfig);
            }
        }
        for (pin, setting) in function.pins {
            let held = self.pin_mut(*pin)?;
            held.owner = Some(owner);
            held.mux = Some((function.id, *setting));
        }
        Ok(())
    }

    /// Applies every function in a table that this board's revision admits,
    /// and says how many it passed over.
    ///
    /// **The count is the point.** A walk that quietly skipped the declarations
    /// for other revisions would be indistinguishable from a table with nothing
    /// in it for this board — and the difference between "no quirk applies
    /// here" and "the quirks are all for another revision" is the difference
    /// between a working board and a puzzle.
    pub fn apply_all(&mut self, functions: &[Function], owner: u32) -> Result<Applied, Error> {
        let mut applied = Applied {
            applied: 0,
            skipped: 0,
        };
        for function in functions {
            if !function.revisions.covers(self.revision) {
                applied.skipped += 1;
                continue;
            }
            self.apply(function, owner)?;
            applied.applied += 1;
        }
        Ok(applied)
    }
}

/// What a table walk did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Applied {
    pub applied: u32,
    /// Declarations passed over because they are for another revision.
    pub skipped: u32,
}
