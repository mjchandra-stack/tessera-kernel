// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The high-precision event timer, used for one thing: telling the local
//! APIC's timer how fast it is running.
//!
//! # Why a second timer exists at all
//!
//! The local timer counts at a rate nobody states. It is derived from the bus
//! or core crystal clock, the divider is the kernel's, and there is no register
//! that says how many of its ticks make a second — so `start_periodic_this_cpu(100)`
//! cannot be honoured without measuring it against something whose rate *is*
//! stated. The TSC's deadline mode would avoid this, but its own frequency is
//! equally undiscoverable here (`CpuOps::counter_hz` answers `None` and says
//! why), and the emulator this tree is checked on does not implement it.
//!
//! The HPET states its rate. Its capability register carries the period of one
//! tick in femtoseconds, so a count of its ticks is a duration without any
//! calibration of its own. That is the whole reason it is here, and it is the
//! reason build/README.md's D87 names it: *"TSC-deadline (or the HPET where
//! TSC-deadline is absent)"*.
//!
//! It is not the tick. Nothing reads it after boot.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md, docs/kernel/01
//! ("Time")
//! Budget: none (boot calibration only)

use core::sync::atomic::{AtomicU64, Ordering};

/// Capability and identification; the counter's period sits in the high half.
const GENERAL_CAPABILITIES: usize = 0x000;
/// General configuration; bit 0 runs the counter.
const GENERAL_CONFIGURATION: usize = 0x010;
const CONFIGURATION_ENABLE: u64 = 1 << 0;
/// The main counter.
const MAIN_COUNTER: usize = 0x0f0;

/// Femtoseconds in a second.
const FEMTOSECONDS_PER_SECOND: u64 = 1_000_000_000_000_000;

/// A period this large or larger is not a working timer. The specification
/// caps it at 100 nanoseconds, and a register reading all-ones is what an
/// absent device looks like.
const MAX_PERIOD_FS: u64 = 100_000_000;

/// Where the counter is mapped, or zero before the boot glue says.
static BASE: AtomicU64 = AtomicU64::new(0);

/// One tick of the counter, in femtoseconds, as the device reported it.
///
/// Kept because a count of ticks is only a duration next to the period that
/// produced it, and reading the capability register on every clock read would
/// make a device access out of arithmetic.
static PERIOD_FS: AtomicU64 = AtomicU64::new(0);

/// Records where the boot glue mapped the device, and starts its counter.
///
/// Returns the counter's frequency in hertz, or `None` when the device does
/// not describe a usable one — which is a machine this port cannot calibrate a
/// tick on, and is reported rather than guessed at.
///
/// # Safety
///
/// `base` must be this device's register block, mapped as uncached device
/// memory, for the life of the kernel.
pub unsafe fn init(base: u64) -> Option<u64> {
    BASE.store(base, Ordering::Release);
    // SAFETY: the caller's contract — `base` is the mapped register block.
    let period_fs = unsafe { read64(GENERAL_CAPABILITIES) } >> 32;
    if period_fs == 0 || period_fs >= MAX_PERIOD_FS {
        BASE.store(0, Ordering::Release);
        return None;
    }
    PERIOD_FS.store(period_fs, Ordering::Release);
    // SAFETY: as above; enabling only starts the counter.
    unsafe {
        let config = read64(GENERAL_CONFIGURATION);
        write64(GENERAL_CONFIGURATION, config | CONFIGURATION_ENABLE);
    }
    Some(FEMTOSECONDS_PER_SECOND / period_fs)
}

/// The main counter's current value, or `None` before [`init`] succeeded.
pub fn now() -> Option<u64> {
    if BASE.load(Ordering::Acquire) == 0 {
        return None;
    }
    // SAFETY: a non-zero base is `init` having stored a mapped block.
    Some(unsafe { read64(MAIN_COUNTER) })
}

/// How long this machine has been counting, in nanoseconds, or `None` before
/// [`init`] succeeded.
///
/// **The one monotonic clock this port has that states its own rate.** A
/// thousand femtoseconds is a picosecond and a million is a nanosecond, so the
/// count multiplied by the period and divided by a million is nanoseconds —
/// done in 128 bits because the counter is 64 and the period is up to 100
/// million, which overflows the moment the machine has been up for a while.
pub fn nanos() -> Option<u64> {
    let period_fs = PERIOD_FS.load(Ordering::Acquire);
    let ticks = now()?;
    if period_fs == 0 {
        return None;
    }
    Some((u128::from(ticks) * u128::from(period_fs) / 1_000_000u128) as u64)
}

/// # Safety
///
/// [`BASE`] must hold a mapped register block and `offset` be within it.
unsafe fn read64(offset: usize) -> u64 {
    let base = BASE.load(Ordering::Acquire) as *const u64;
    // SAFETY: the caller's contract; the registers are 64-bit and naturally
    // aligned, and a read has no side effect on the two used here.
    unsafe { base.byte_add(offset).read_volatile() }
}

/// # Safety
///
/// As [`read64`], and the write must be one this device accepts.
unsafe fn write64(offset: usize, value: u64) {
    let base = BASE.load(Ordering::Acquire) as *mut u64;
    // SAFETY: the caller's contract.
    unsafe { base.byte_add(offset).write_volatile(value) }
}
