// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Panic policy: panics are bugs. The kernel's `#[panic_handler]` (in the
//! boot glue, which owns the platform exit) delegates here for state
//! tracking and report formatting so both are host-testable. A first panic
//! reports and exits with failure; a nested panic must skip straight to
//! the exit — the poison flag makes that decision.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Failure
//! Discipline"), docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (panic path)

use core::fmt;
use core::panic::Location;
use core::sync::atomic::{AtomicBool, Ordering};
use tessera_karch::EarlyConsole;

static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PanicDisposition {
    /// First panic: report, then exit with failure.
    Report,
    /// Panic during panic handling: exit immediately, no formatting — the
    /// reporting machinery itself is suspect.
    ExitImmediately,
}

/// Marks the kernel as panicking. Idempotent state, one-way.
pub fn enter() -> PanicDisposition {
    if PANIC_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        PanicDisposition::ExitImmediately
    } else {
        PanicDisposition::Report
    }
}

pub fn is_panicking() -> bool {
    PANIC_IN_PROGRESS.load(Ordering::SeqCst)
}

/// Formats the panic report onto a console. Kept free of global state so
/// the exact wire format is unit-tested.
pub fn write_report(
    out: &mut dyn EarlyConsole,
    message: fmt::Arguments<'_>,
    location: Option<&Location<'_>>,
    ticks: Option<u64>,
) {
    // A leading newline: the panic may have interrupted a partial line, and the
    // report must start at a column a reader and a grep both expect.
    crate::console::write_to(out, format_args!("\n"));
    match location {
        Some(loc) => crate::console::write_line(
            out,
            module_path!(),
            ticks,
            format_args!(
                "KERNEL PANIC at {}:{}:{} — {message}\n",
                loc.file(),
                loc.line(),
                loc.column()
            ),
        ),
        None => crate::console::write_line(
            out,
            module_path!(),
            ticks,
            format_args!("KERNEL PANIC at unknown location — {message}\n"),
        ),
    }
}

/// Emits the panic report on the global console, busting a held console
/// lock first. This is what the kernel's `#[panic_handler]` calls.
///
/// # Safety
///
/// Panic path only: single CPU with interrupts disabled, so no lock holder
/// can still be running.
pub unsafe fn report_global(message: fmt::Arguments<'_>, location: Option<&Location<'_>>) {
    // The clock first, and without blocking: reading it after the console lock
    // is busted would be the one place a held lock could still stop the report.
    let ticks = crate::event::timestamp_now();
    // SAFETY: forwarded from the caller's panic-path contract.
    unsafe { crate::console::unlock_for_panic() };
    write_report(&mut crate::console::GlobalConsole, message, location, ticks);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_karch_mock::MockConsole;

    #[test]
    fn report_format_is_stable() {
        let mut console = MockConsole::new();
        let location = Location::caller();
        write_report(
            &mut console,
            format_args!("frame allocator exhausted"),
            Some(location),
            Some(9),
        );
        let text = console.text();
        assert!(
            text.starts_with("\n[9 kcore::panic] KERNEL PANIC at "),
            "{text}"
        );
        assert!(text.contains("panic.rs"));
        assert!(text.ends_with(" — frame allocator exhausted\n"), "{text}");
        // One message, one line: the report body is 2 lines only because of the
        // leading break that gets it off a partial one.
        assert_eq!(text.trim_start_matches('\n').lines().count(), 1, "{text}");
    }

    #[test]
    fn missing_location_is_explicit() {
        let mut console = MockConsole::new();
        write_report(&mut console, format_args!("x"), None, None);
        assert!(console.text().contains("at unknown location"));
        assert!(console.text().contains("[- kcore::panic]"));
    }
}
