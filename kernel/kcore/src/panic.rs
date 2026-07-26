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
) {
    crate::console::write_to(out, format_args!("\n!!! KERNEL PANIC"));
    match location {
        Some(loc) => crate::console::write_to(
            out,
            format_args!(" at {}:{}:{}\n", loc.file(), loc.line(), loc.column()),
        ),
        None => crate::console::write_to(out, format_args!(" at unknown location\n")),
    }
    crate::console::write_to(out, format_args!("    {message}\n"));
}

/// Emits the panic report on the global console, busting a held console
/// lock first. This is what the kernel's `#[panic_handler]` calls.
///
/// # Safety
///
/// Panic path only: single CPU with interrupts disabled, so no lock holder
/// can still be running.
pub unsafe fn report_global(message: fmt::Arguments<'_>, location: Option<&Location<'_>>) {
    // SAFETY: forwarded from the caller's panic-path contract.
    unsafe { crate::console::unlock_for_panic() };
    write_report(&mut crate::console::GlobalConsole, message, location);
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
        );
        let text = console.text();
        assert!(text.starts_with("\n!!! KERNEL PANIC at "));
        assert!(text.contains("panic.rs"));
        assert!(text.ends_with("    frame allocator exhausted\n"));
    }

    #[test]
    fn missing_location_is_explicit() {
        let mut console = MockConsole::new();
        write_report(&mut console, format_args!("x"), None);
        assert!(console.text().contains("at unknown location"));
    }
}
