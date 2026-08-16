// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What the SD driver carries between requests, and how a card that has gone
//! becomes an answer a client can act on.
//!
//! **Why this is a library and not part of the binary.** The driver itself is a
//! `no_main` AArch64 program: nothing on a host can call into it, so until this
//! crate existed the translation below was reachable only from a machine with a
//! card in it. There is no such machine here — QEMU's `sdhci-pci` reports a card
//! present in an empty slot, so the boot check cannot make a card leave and the
//! `NO_MEDIUM` path it produces was never executed by anything. Split out, it
//! runs against a mock controller whose card can be taken out.
//!
//! Everything here is generic over [`Registers`] for the same reason: the driver
//! supplies a window of real MMIO and a test supplies a model, and the code
//! between them must not know which it has.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("Storage"),
//! docs/drivers/01-driver-framework.md ("Class Contracts")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use block_driver_abi::{BlockError, BlockPowerState};
use tessera_clock::ClockTable;
use tessera_sdhci::{
    BLOCK_LEN, CMD_READ_SINGLE_BLOCK, CMD_WRITE_BLOCK, Error as SdError, Host, Registers,
    ResponseKind, Transfer,
};

/// The sector size this driver reports and works in.
pub const SECTOR: u64 = BLOCK_LEN as u64;

/// Everything the serve loop carries between requests.
///
/// The register window is not here: it belongs to the `Host` the transport core
/// borrows for its whole life, and a second copy would be a second name for the
/// same mapping.
pub struct Driver {
    pub clocks: ClockTable,
    /// The card's relative address, and whether one is present as far as this
    /// driver last saw.
    pub rca: u16,
    /// Whether the card takes a block number or a byte offset. Read from the
    /// card rather than assumed, because the two agree at sector zero and
    /// nowhere else.
    pub block_addressed: bool,
    /// Whether a card has been identified and is usable. Distinct from the
    /// controller's presence bit: a card that was pulled and pushed back is
    /// present and *not* identified, and reading from it would be reading from
    /// a card that never answered `CMD7`.
    pub ready: bool,
    pub power: BlockPowerState,
}

impl Driver {
    /// The argument a data command takes for `sector` on this card.
    pub fn address_of(&self, sector: u64) -> u32 {
        let address = if self.block_addressed {
            sector
        } else {
            sector * SECTOR
        };
        address as u32
    }
}

/// Reads one block into `out`, or says why not.
///
/// **`NoCard` becomes `NO_MEDIUM` and nothing else does.** That distinction is
/// the whole of card detection from a client's side: a request that failed
/// because the card left is one the client can respond to by giving up on the
/// medium, and a request that failed for any other reason is one it may retry.
pub fn read_block<R: Registers>(
    driver: &mut Driver,
    host: &Host<'_, R>,
    sector: u64,
    out: &mut [u8],
) -> BlockError {
    if !driver.ready {
        return BlockError::NoMedium;
    }
    match host.command(
        CMD_READ_SINGLE_BLOCK,
        driver.address_of(sector),
        ResponseKind::Short,
        Some(Transfer::Read),
    ) {
        Ok(_) => {}
        Err(SdError::NoCard) => {
            driver.ready = false;
            return BlockError::NoMedium;
        }
        Err(_) => return BlockError::IoError,
    }
    match host.read_block(out) {
        Ok(()) => BlockError::Ok,
        Err(SdError::NoCard) => {
            driver.ready = false;
            BlockError::NoMedium
        }
        Err(_) => BlockError::IoError,
    }
}

/// Writes one block out of `data`.
pub fn write_block<R: Registers>(
    driver: &mut Driver,
    host: &Host<'_, R>,
    sector: u64,
    data: &[u8],
) -> BlockError {
    if !driver.ready {
        return BlockError::NoMedium;
    }
    match host.command(
        CMD_WRITE_BLOCK,
        driver.address_of(sector),
        ResponseKind::Short,
        Some(Transfer::Write),
    ) {
        Ok(_) => {}
        Err(SdError::NoCard) => {
            driver.ready = false;
            return BlockError::NoMedium;
        }
        Err(_) => return BlockError::IoError,
    }
    match host.write_block(data) {
        Ok(()) => BlockError::Ok,
        Err(SdError::NoCard) => {
            driver.ready = false;
            BlockError::NoMedium
        }
        Err(_) => BlockError::IoError,
    }
}

/// Notices a card that has gone. Called before every request, because the only
/// thing that makes card detection real is acting on it between one request and
/// the next.
pub fn check_presence<R: Registers>(driver: &mut Driver, host: &Host<'_, R>) {
    let (_, removed) = host.take_card_events();
    if removed || !host.card_present() {
        driver.ready = false;
    }
}

#[cfg(test)]
mod tests;
