// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The DMA test harness**: pages the model owns, and the questions a test can
//! ask about what a driver did with them.
//!
//! `docs/drivers/01` ("Developer Experience") lists this beside the simulator,
//! and until now the simulator could not have one. Its `dma_alloc` handed back
//! the address the driver asked for, and a driver that then wrote through that
//! address on a host would write through a number nobody mapped. **So a driver
//! that actually used DMA could not run in the simulator at all** — only one
//! that allocated pages and left them alone, which is no driver.
//!
//! The fix is a change to what a driver is allowed to do, not to the model: a
//! driver borrows its page through the [`Platform`](super::Platform) rather
//! than forming a pointer from an integer. On a machine that is the same
//! `from_raw_parts_mut` every driver was writing for itself; here it is a
//! slice into memory this harness owns, and that difference is the whole
//! reason a host test can watch.
//!
//! # What it can then ask
//!
//! Three questions, and the second is why this exists:
//!
//! - **What would the device have read?** Addressed the way a device addresses
//!   it, which is deliberately not the address the driver writes through. A
//!   driver that published its own VA to a device gets [`None`] here, and that
//!   is the bug an IOMMU turns into a fault on real hardware and a simulator
//!   sharing one number would hide.
//! - **Does any page still hold these bytes?** A driver handed a key writes it
//!   somewhere a device can read, and what happens to that page afterwards is
//!   a claim every crypto driver's comments make and nothing has ever checked.
//! - **How many grants were made, and how many strays?** A page the driver
//!   reached that the model never handed out is not something to answer
//!   quietly; a harness that invented one would model a bug as working.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Developer Experience"),
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Test Tiers")

use super::Dma;

/// One DMA page, which is what every port here maps.
pub const PAGE: usize = 4096;

/// How many pages the model owns.
///
/// Bounded because this compiles for `no_std` and lives on a stack: the store
/// is the pages themselves, so an unbounded harness would be an unbounded
/// stack frame. Four is what the largest driver converted so far asks for, and
/// a driver wanting more gets a refusal it can see rather than a page it did
/// not get.
pub const MAX_PAGES: usize = 4;

/// The pages a model hands out, and their contents.
pub struct Pages {
    store: [[u8; PAGE]; MAX_PAGES],
    /// The device address of each granted page, in grant order.
    device_addresses: [u64; MAX_PAGES],
    /// The address the driver asked for, so a stray reach can be told apart
    /// from a page that was simply never granted.
    virtual_addresses: [u64; MAX_PAGES],
    granted: usize,
    strays: usize,
    /// A page for a reach the model cannot place, so a stray is recorded
    /// rather than faulting the test that found it.
    scratch: [u8; PAGE],
}

impl Default for Pages {
    fn default() -> Pages {
        Pages::new()
    }
}

/// The device address the model hands back for a page at `va`.
///
/// **Deliberately not `va`.** A model that returned the same number would let a
/// driver conflate the two addresses of one page, pass here, and fault on the
/// first machine whose IOMMU disagreed — which is the class of bug a simulator
/// exists to catch rather than to launder.
///
/// **And deliberately injective**, which is the harder half and was got wrong
/// first: this folded `va` to its low 16 bits, and every address in
/// `tessera_uabi::layout` — the MMIO window, the DMA page, the queue rings —
/// is megabyte-aligned, so all three came back as one device address. Two
/// pages sharing one would make [`seen_by_device`](Pages::seen_by_device)
/// answer about whichever was granted first, so a driver that published the
/// wrong page's address would be told the device could read it. A model that
/// aliases is worse than no model, because it says the right thing about the
/// wrong page.
///
/// Bit 62 is what keeps the two apart, and no port here has a user half that
/// reaches it: AArch64's is 2^48, x86-64's 2^47, Sv39's 2^38, and the 32-bit
/// ports' 2^32. So the mask below is the identity on every address a driver
/// can hold, and the base is a bit none of them can set.
pub const fn device_address_for(va: u64) -> u64 {
    0x4000_0000_0000_0000 | (va & 0x0000_ffff_ffff_ffff)
}

impl Pages {
    pub const fn new() -> Pages {
        Pages {
            store: [[0; PAGE]; MAX_PAGES],
            device_addresses: [0; MAX_PAGES],
            virtual_addresses: [0; MAX_PAGES],
            granted: 0,
            strays: 0,
            scratch: [0; PAGE],
        }
    }

    /// Hands out the next page, under both its addresses.
    ///
    /// [`None`] when the model has none left, which a driver must treat as the
    /// refusal it is: allocation is fallible where a driver runs, and a test
    /// that never saw a refusal has never run the path that handles one.
    ///
    /// **Also [`None`] for an address already granted**, because a machine's
    /// `DmaAlloc` cannot map two pages at one virtual address either. A model
    /// that allowed it would hold two pages under one `va`, reach the first
    /// forever, and leave the second addressable by a device and unreachable
    /// by the driver — a state no machine can be in.
    pub fn grant(&mut self, va: u64) -> Option<Dma> {
        if self.granted >= MAX_PAGES || self.index_of(va).is_some() {
            return None;
        }
        let index = self.granted;
        let dma = Dma {
            va,
            device_address: device_address_for(va),
        };
        self.device_addresses[index] = dma.device_address;
        self.virtual_addresses[index] = va;
        self.granted += 1;
        Some(dma)
    }

    /// Lends the driver its page, scoped so no two references exist at once.
    pub fn with<R>(&mut self, dma: &Dma, f: impl FnOnce(&mut [u8]) -> R) -> R {
        match self.index_of(dma.va) {
            Some(index) => f(&mut self.store[index]),
            None => {
                // **Recorded, not invented.** Handing back a fresh page would
                // let a driver reach a page nobody gave it and see it work.
                self.strays += 1;
                f(&mut self.scratch)
            }
        }
    }

    /// What a device reading at this address would find.
    ///
    /// [`None`] for an address the model never handed to a device — which is
    /// what a driver that published its own VA produces, and is the answer that
    /// makes the two addresses of a page worth keeping apart.
    pub fn seen_by_device(&self, device_address: u64) -> Option<&[u8]> {
        (0..self.granted)
            .find(|&index| self.device_addresses[index] == device_address)
            .map(|index| &self.store[index][..])
    }

    /// Whether any granted page still holds these bytes.
    ///
    /// The question a driver that was handed a secret has to be able to fail.
    /// Searches every granted page rather than a named one, because a driver
    /// that copied a key to a second page and cleared only the first has done
    /// exactly what this is meant to catch.
    pub fn holds(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            // Every page holds the empty string; answering `true` would make
            // the question useless and answering it quietly would be worse.
            return false;
        }
        if needle.len() > PAGE {
            // Arithmetic, not a fallback: a page is [`PAGE`] bytes and cannot
            // contain more than that, so `false` is the answer rather than a
            // degraded one. Written out because the loop below cannot say it —
            // `saturating_sub` would clamp the range to a single start offset
            // and then index past the page, turning a question a harness is
            // entitled to be asked into a panic in the test asking it.
            return false;
        }
        for index in 0..self.granted {
            let page = &self.store[index];
            for start in 0..=PAGE.saturating_sub(needle.len()) {
                if &page[start..start + needle.len()] == needle {
                    return true;
                }
            }
        }
        false
    }

    /// How many pages were handed out.
    pub fn granted(&self) -> usize {
        self.granted
    }

    /// How many times a driver reached a page the model never granted.
    pub fn strays(&self) -> usize {
        self.strays
    }

    fn index_of(&self, va: u64) -> Option<usize> {
        (0..self.granted).find(|&index| self.virtual_addresses[index] == va)
    }
}

#[cfg(test)]
mod tests {
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
}
