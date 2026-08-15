// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Early kernel logging over the architecture's `EarlyConsole`: the
//! `kprint!`/`kprintln!` macros and the global sink they write to. Boot
//! glue registers the real console once; before that, output is dropped —
//! and because dropping output is a degradation, `init_global` reports
//! whether anything was dropped so the boot path can say so
//! (docs/lifecycle/04, "No Silent Fallback").
//!
//! Structured, ISL-defined records are now the primary artifact: the mechanisms
//! emit observability events into a bounded ring ([`crate::event`], D57), and the
//! boot harness renders every demo verdict *from* a [`crate::verdict`] record
//! (D58) — "plain text rendering is generated from structured records"
//! (docs/observability/01). kprint is what those renderings are written through,
//! plus the bring-up and panic channel; it is no longer where the facts live.
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md
//! Budget: none (init and panic paths only)

use crate::atomic::AtomicU64;
use crate::sync::SpinLock;
use core::fmt::{self, Write};
use core::sync::atomic::Ordering;
use tessera_karch::EarlyConsole;

type GlobalSink = &'static mut (dyn EarlyConsole + Send);

static CONSOLE: SpinLock<Option<GlobalSink>> = SpinLock::new(None);
static DROPPED_WRITES: AtomicU64 = AtomicU64::new(0);

/// Registers the global console. Returns the number of writes dropped
/// before registration so the caller can report the gap.
pub fn init_global(sink: GlobalSink) -> u64 {
    *CONSOLE.lock() = Some(sink);
    DROPPED_WRITES.swap(0, Ordering::Relaxed)
}

/// Formats into any `EarlyConsole` — also the unit-testable path.
pub fn write_to(sink: &mut dyn EarlyConsole, args: fmt::Arguments<'_>) {
    struct Adapter<'a>(&'a mut dyn EarlyConsole);
    impl Write for Adapter<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.0.write_bytes(s.as_bytes());
            Ok(())
        }
    }
    // The adapter never errors; the console byte sink is infallible.
    let _ = Adapter(sink).write_fmt(args);
}

/// Backend of `kprint!`. Drops (and counts) output until `init_global`.
pub fn global_write(args: fmt::Arguments<'_>) {
    let mut guard = CONSOLE.lock();
    match guard.as_mut() {
        Some(sink) => write_to(&mut **sink, args),
        None => {
            DROPPED_WRITES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The global console viewed as an `EarlyConsole`, so code written against
/// the trait (e.g. the panic report) can target it.
pub struct GlobalConsole;

impl EarlyConsole for GlobalConsole {
    fn write_bytes(&mut self, bytes: &[u8]) {
        let mut guard = CONSOLE.lock();
        match guard.as_mut() {
            Some(sink) => sink.write_bytes(bytes),
            None => {
                DROPPED_WRITES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Busts a held console lock so panic output cannot deadlock.
///
/// # Safety
///
/// Only sound when no other CPU or interrupt handler can still hold the
/// console lock — the panic path with interrupts disabled, single CPU.
pub unsafe fn unlock_for_panic() {
    if CONSOLE.try_lock().is_none() {
        // SAFETY: forwarded from the caller's contract — the holder can no
        // longer be running.
        unsafe { CONSOLE.force_unlock() };
    }
}

/// Prints to the global kernel console (no newline).
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::console::global_write(core::format_args!($($arg)*))
    };
}

/// Prints to the global kernel console with a trailing newline.
#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {
        $crate::console::global_write(core::format_args!(
            "{}\n",
            core::format_args!($($arg)*)
        ))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_karch_mock::MockConsole;

    #[test]
    fn write_to_formats_into_the_sink() {
        let mut console = MockConsole::new();
        let value = 42;
        write_to(&mut console, format_args!("boot: value={value:#x}\n"));
        assert_eq!(console.text(), "boot: value=0x2a\n");
    }
}
