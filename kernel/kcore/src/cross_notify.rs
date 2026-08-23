// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Waking a thread on another CPU through a port — budget B5.
//!
//! # What is measured, and from which end
//!
//! `docs/prototypes/01`'s BM-5: "a waiter blocked on a port on core B; a sender
//! on core A signals a bound event. Measures signal-call entry on A to waiter
//! running on B, using the shared invariant counter." So the two timestamps are
//! taken on *different CPUs* — the sender stamps before its `port_signal`, the
//! waiter stamps the instant `port_wait` hands it an event — and subtracting
//! them is only meaningful because the counter is one source for the whole
//! machine. That is the property the port supplies and the reason the clock is
//! passed in rather than read here.
//!
//! It is the same wake path [`crate::cross_call`] measures the far side of, and
//! deliberately a different shape: a call is a round trip and its number is
//! dominated by the return leg, while this is **one direction only**, which is
//! what B5 is a budget for.
//!
//! # Two Stage-0 gaps, stated rather than papered over
//!
//! BM-5 wants the waiter running *in user space*; this one is a kernel thread,
//! because a secondary has no address space of its own to run a process in yet.
//! And the "event" is a bare signal on a bound source rather than a device
//! interrupt, since no device is routed to a secondary. Both make this an
//! underestimate of the real path, and both are the same missing piece: a
//! secondary that can host ring 3.
//!
//! Normative: docs/prototypes/01-ipc-benchmark-harness.md ("BM-5"),
//! docs/architecture/03-performance-budgets.md (B5)
//! Budget: B5 (cross-core notify) — this is its measurement

use crate::atomic::AtomicU64;
use crate::exec::Executive;
use crate::port::PortId;
use core::sync::atomic::Ordering;
use tessera_karch::ContextOps;

/// Notifications the benchmark sends.
///
/// Matching `cross_call`'s round count, so the two cross-core numbers are
/// taken over comparable sample sets.
pub const ROUNDS: usize = 200;

/// The source this benchmark's events are bound to. Its own number, so an
/// event that reached the wrong port is visible as one.
const SOURCE: u64 = 0x0000_0000_0042_0035;
/// The signal within that source. One, because a source has one meaning here.
const SIGNAL: u8 = 1;

/// No port published. Not zero, which is a valid port index.
const NO_PORT: u64 = u64::MAX;

/// The port the waiter drains and the sender signals.
static PORT: AtomicU64 = AtomicU64::new(NO_PORT);
/// The counter reading the waiter took the instant it was handed an event.
static WOKE_AT: AtomicU64 = AtomicU64::new(0);
/// How many events the waiter has taken. Bumped **after** [`WOKE_AT`], so a
/// sender that sees the count sees the stamp that goes with it.
static WOKEN: AtomicU64 = AtomicU64::new(0);
/// Notifications the sender managed to time.
static SENT: AtomicU64 = AtomicU64::new(0);
/// Wakeups that crossed a CPU while the benchmark ran.
static CROSSINGS: AtomicU64 = AtomicU64::new(0);

/// Creates the port and binds the source, on the boot CPU before any CPU is
/// given work.
///
/// Bound here and not by the waiter: a port that is not bound when the first
/// signal arrives silently carries nothing, and the waiter parks for ever on
/// an event that was delivered to no port at all.
pub fn open<C: ContextOps>(exec: &mut Executive<C>) -> bool {
    let Ok(port) = exec.port_create() else {
        return false;
    };
    if exec.port_bind(port, SOURCE, SIGNAL).is_err() {
        return false;
    }
    PORT.store(port.0 as u64, Ordering::Release);
    true
}

/// Whether [`open`] published a port for this boot.
pub fn opened() -> bool {
    PORT.load(Ordering::Acquire) != NO_PORT
}

fn port() -> Option<PortId> {
    match PORT.load(Ordering::Acquire) {
        NO_PORT => None,
        raw => Some(PortId(raw as usize)),
    }
}

/// The waiting half: park on the port [`ROUNDS`] times, stamping each wake.
///
/// Runs as a kernel thread on a CPU that is not the boot CPU. The stamp is
/// taken *before* anything else the loop does, because everything else is this
/// benchmark's own bookkeeping and not the path under measurement.
pub fn wait_loop<C: ContextOps>(exec: &mut Executive<C>, now: fn() -> u64) {
    let Some(port) = port() else {
        return;
    };
    for _ in 0..ROUNDS {
        if exec.port_wait(port).is_err() {
            return;
        }
        WOKE_AT.store(now(), Ordering::Release);
        // The count last: a sender that sees it has the stamp that belongs to
        // it, which is the whole of the handshake between the two CPUs.
        WOKEN.store(WOKEN.load(Ordering::Acquire) + 1, Ordering::Release);
    }
}

/// The sending half: signal the port [`ROUNDS`] times, timing each wake.
///
/// Runs on the boot CPU's own context — no thread needed, because this side
/// never blocks. `spins` bounds each wait so a notification that never lands
/// fails the benchmark rather than hanging the boot.
///
/// **Each round waits for the waiter to be parked before signalling.** A port
/// coalesces: a signal arriving while nobody is waiting is remembered, and the
/// next `port_wait` returns from it immediately. That is correct behaviour and
/// it would measure nothing — the sample would be the cost of a queue read.
/// The wait is on the port's own registration, which is machine state, because
/// the sender cannot read the other CPU's scheduler.
pub fn send<C: ContextOps>(
    exec: &mut Executive<C>,
    now: fn() -> u64,
    samples: &mut [u64],
    spins: u64,
) -> usize {
    let Some(port) = port() else {
        return 0;
    };
    let before = crate::wakeup::crossings();
    let mut sent = 0usize;
    for slot in samples.iter_mut().take(ROUNDS) {
        let taken = WOKEN.load(Ordering::Acquire);
        if !wait_until(spins, || exec.port_has_drainer(port)) {
            break;
        }
        let start = now();
        if exec.port_signal(SOURCE, SIGNAL, 1) == 0 {
            break;
        }
        if !wait_until(spins, || WOKEN.load(Ordering::Acquire) > taken) {
            break;
        }
        *slot = WOKE_AT.load(Ordering::Acquire).wrapping_sub(start);
        sent += 1;
    }
    CROSSINGS.store(
        crate::wakeup::crossings().saturating_sub(before),
        Ordering::Release,
    );
    SENT.store(sent as u64, Ordering::Release);
    sent
}

fn wait_until(spins: u64, mut ready: impl FnMut() -> bool) -> bool {
    let mut left = spins;
    while left > 0 {
        if ready() {
            return true;
        }
        core::hint::spin_loop();
        left -= 1;
    }
    ready()
}

/// Prints what crossed and returns the claim keys.
///
/// **One crossing per notification, exactly**, and unlike the call benchmark
/// that really is invariant: the sender waits for the waiter to be registered
/// before it signals, so `port_signal` always finds a drainer to wake and that
/// drainer is always somewhere else. A benchmark whose waiter had ended up on
/// the sending CPU crosses nothing and is caught here; the microseconds alone
/// would not show it.
///
/// The timing is printed and never claimed: under QEMU/TCG it is the
/// emulator's scheduling (build/README.md, D34/D56).
pub fn report_crossings() -> &'static [&'static str] {
    let sent = SENT.load(Ordering::Acquire);
    let crossed = CROSSINGS.load(Ordering::Acquire);
    if sent == 0 {
        return &[];
    }
    crate::kprintln!(
        "perf: cross-notify crossed {} times in {} notifications (1 each)",
        crossed,
        sent
    );
    if sent == ROUNDS as u64 && crossed == sent {
        &["perf.cross-notify-crossed"]
    } else {
        &[]
    }
}

/// Whether every notification the benchmark asked for was timed.
pub fn complete() -> bool {
    SENT.load(Ordering::Acquire) == ROUNDS as u64
}
