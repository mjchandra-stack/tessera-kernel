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
use core::sync::atomic::{AtomicBool, Ordering};
use tessera_karch::EarlyConsole;

type GlobalSink = &'static mut (dyn EarlyConsole + Send);

static CONSOLE: SpinLock<Option<GlobalSink>> = SpinLock::new(None);
static DROPPED_WRITES: AtomicU64 = AtomicU64::new(0);

/// The tick the first rendered line carried. Later lines report their distance
/// from it: a raw counter is eight to eleven digits of which only the last few
/// move within one boot, and the point of the field is ordering.
static BASE_TICKS: AtomicU64 = AtomicU64::new(0);
static BASE_TAKEN: AtomicBool = AtomicBool::new(false);

/// What the tick field reads when no clock is installed yet. Visible rather
/// than absent, because a line with no time is a degraded line
/// (docs/lifecycle/04, "No Silent Fallback").
pub const NO_CLOCK: &str = "-";

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

/// Ticks since the first rendered line, or `None` when no clock is installed.
///
/// Reads the clock **without blocking**: this runs on the panic path, where a
/// lock held by the code that panicked would never be released, and a console
/// that deadlocks instead of reporting is worse than one with no timestamps.
fn ticks() -> Option<u64> {
    let now = crate::event::timestamp_now()?;
    if BASE_TAKEN.swap(true, Ordering::Relaxed) {
        Some(now.saturating_sub(BASE_TICKS.load(Ordering::Relaxed)))
    } else {
        BASE_TICKS.store(now, Ordering::Relaxed);
        Some(0)
    }
}

/// The envelope every line carries: when, and from where.
///
/// `docs/observability/01` mandates a timestamp and a component on every
/// record; these are those two on the text channel. The module comes from
/// `module_path!()` at the call site, so it cannot drift from the code that
/// emitted the line the way a hand-typed subsystem tag does.
struct Envelope<'a> {
    module: &'a str,
    ticks: Option<u64>,
}

impl fmt::Display for Envelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ticks {
            Some(t) => write!(f, "{t} ")?,
            None => write!(f, "{NO_CLOCK} ")?,
        }
        match self.module.split_once("::") {
            Some((krate, rest)) => write!(f, "{}::{rest}", short_crate(krate)),
            None => write!(f, "{}", short_crate(self.module)),
        }
    }
}

/// A crate name as a reader wants it: `tessera_kcore` is `kcore`, and the
/// `_bin`/`_image_bin` a build rule appends to a kernel binary's target name is
/// not part of what emitted the line — and differs between a kernel's ELF and
/// its flat image, which are the same code.
pub fn short_crate(krate: &str) -> &str {
    let krate = krate.strip_prefix("tessera_").unwrap_or(krate);
    match krate.strip_suffix("_image_bin") {
        Some(short) => short,
        None => krate.strip_suffix("_bin").unwrap_or(krate),
    }
}

/// Renders one enveloped line into any console — the unit-testable path.
pub fn write_line(
    sink: &mut dyn EarlyConsole,
    module: &str,
    ticks: Option<u64>,
    args: fmt::Arguments<'_>,
) {
    write_to(
        sink,
        format_args!("[{}] {args}", Envelope { module, ticks }),
    );
}

/// Backend of `kprint!`. Drops (and counts) output until `init_global`.
///
/// The clock is read before the console lock is taken, never under it, so the
/// two can never nest.
pub fn global_write(module: &str, args: fmt::Arguments<'_>) {
    let ticks = ticks();
    let mut guard = CONSOLE.lock();
    match guard.as_mut() {
        Some(sink) => write_line(&mut **sink, module, ticks, args),
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

/// Prints one line to the global kernel console (no trailing newline added).
///
/// `module_path!()` is captured here rather than passed in, so every line
/// names the module it came from without a call site having to remember.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::console::global_write(core::module_path!(), core::format_args!($($arg)*))
    };
}

/// Prints to the global kernel console with a trailing newline.
#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {
        $crate::console::global_write(
            core::module_path!(),
            core::format_args!("{}\n", core::format_args!($($arg)*)),
        )
    };
}

#[cfg(test)]
#[path = "tests/console.rs"]
mod tests;
