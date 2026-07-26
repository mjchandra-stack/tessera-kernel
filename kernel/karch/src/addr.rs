// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Physical and virtual address types and the physical frame unit. Plain
//! data, checked arithmetic — address math that can overflow returns
//! `Option`, never panics (panics are bugs; docs/lifecycle/04, "Failure
//! Discipline").

/// Base page/frame size shared by every supported architecture's smallest
/// mapping granule.
pub const FRAME_SIZE: u64 = 4096;

/// A physical memory address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PhysAddr(u64);

/// A virtual memory address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VirtAddr(u64);

macro_rules! addr_common {
    ($t:ident) => {
        impl $t {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// Largest `align`-aligned address not above `self`.
            /// `align` must be a power of two.
            pub const fn align_down(self, align: u64) -> Self {
                debug_assert!(align.is_power_of_two());
                Self(self.0 & !(align - 1))
            }

            /// Smallest `align`-aligned address not below `self`, or `None`
            /// on overflow. `align` must be a power of two.
            pub const fn align_up(self, align: u64) -> Option<Self> {
                debug_assert!(align.is_power_of_two());
                match self.0.checked_add(align - 1) {
                    Some(sum) => Some(Self(sum & !(align - 1))),
                    None => None,
                }
            }

            pub const fn is_aligned(self, align: u64) -> bool {
                debug_assert!(align.is_power_of_two());
                self.0 & (align - 1) == 0
            }

            pub const fn checked_add(self, offset: u64) -> Option<Self> {
                match self.0.checked_add(offset) {
                    Some(sum) => Some(Self(sum)),
                    None => None,
                }
            }
        }
    };
}

addr_common!(PhysAddr);
addr_common!(VirtAddr);

/// A physical frame: a `FRAME_SIZE`-aligned physical address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PhysFrame(PhysAddr);

impl PhysFrame {
    /// The frame starting exactly at `base`; `None` if unaligned.
    pub const fn from_base(base: PhysAddr) -> Option<Self> {
        if base.is_aligned(FRAME_SIZE) {
            Some(Self(base))
        } else {
            None
        }
    }

    /// The frame containing `addr`.
    pub const fn containing(addr: PhysAddr) -> Self {
        Self(addr.align_down(FRAME_SIZE))
    }

    /// The frame with 0-based index `number`, or `None` past the address
    /// space.
    pub const fn from_number(number: u64) -> Option<Self> {
        match number.checked_mul(FRAME_SIZE) {
            Some(base) => Some(Self(PhysAddr::new(base))),
            None => None,
        }
    }

    pub const fn base(self) -> PhysAddr {
        self.0
    }

    pub const fn number(self) -> u64 {
        self.0.as_u64() / FRAME_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_math() {
        let a = PhysAddr::new(0x1234);
        assert_eq!(a.align_down(0x1000).as_u64(), 0x1000);
        assert_eq!(a.align_up(0x1000).map(PhysAddr::as_u64), Some(0x2000));
        assert!(PhysAddr::new(0x2000).is_aligned(0x1000));
        assert!(!a.is_aligned(0x1000));
        // Already-aligned addresses stay put on align_up.
        assert_eq!(
            PhysAddr::new(0x2000).align_up(0x1000).map(PhysAddr::as_u64),
            Some(0x2000)
        );
    }

    #[test]
    fn align_up_overflow_is_none() {
        assert_eq!(PhysAddr::new(u64::MAX).align_up(0x1000), None);
        assert_eq!(VirtAddr::new(u64::MAX).checked_add(1), None);
    }

    #[test]
    fn frames() {
        assert_eq!(PhysFrame::from_base(PhysAddr::new(0x1234)), None);
        let f = PhysFrame::containing(PhysAddr::new(0x1234));
        assert_eq!(f.base().as_u64(), 0x1000);
        assert_eq!(f.number(), 1);
        assert_eq!(
            PhysFrame::from_number(2).map(|f| f.base().as_u64()),
            Some(0x2000)
        );
        assert_eq!(PhysFrame::from_number(u64::MAX), None);
    }
}
