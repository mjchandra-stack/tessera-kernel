// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A synchronous channel call whose two ends are on different CPUs.
//!
//! # What it is checking, and what it is not
//!
//! The mechanism is [`crate::exec`]'s: a `call` that finds its callee parked
//! somewhere else posts a wakeup instead of handing off, and the `reply` comes
//! back the same way. What that mechanism cannot check for itself is that the
//! two ends really were apart — a round trip completes identically when both
//! happen to be on one CPU, which is exactly the arrangement every other IPC
//! check in this tree uses. So the verdict reads
//! [`crate::wakeup::crossings`] as well as the reply: **the answer arriving is
//! not the finding, the answer arriving from another CPU is.**
//!
//! # Why both halves live here
//!
//! The server runs on a secondary, out of a thread the boot CPU built and
//! handed over ([`crate::secondary`]); the caller runs on the boot CPU. Both
//! are a dozen lines of executive calls with no architecture in them, so they
//! are here rather than duplicated in two ports, and each port supplies only
//! the `extern "C"` shim and the stack.
//!
//! # The ordering this took a deadlock to get right
//!
//! A thread's identity reaches a machine-wide table — as a blocked receiver, as
//! a pending caller — before it parks, and another CPU can read that identity
//! the instant it is written. So the record of *where* that thread is has to be
//! published no later than the identity, or the reader resolves it to "exited"
//! and never wakes it, and the thread parks for ever on a request already
//! sitting in its queue. `Executive::enter_blocking` is where that ordering
//! lives.
//!
//! Normative: docs/roadmap/02-smp-bring-up-plan.md ("Phase 3"),
//! docs/kernel/04-synchronization-and-ipc-guarantees.md
//! Budget: none (a boot check; B3 measures the one-CPU round trip)

use crate::atomic::AtomicU64;
use crate::exec::Executive;
use crate::ipc::{EndpointId, Message, MessageHeader};
use core::sync::atomic::Ordering;
use tessera_karch::ContextOps;

/// The interface the check's two messages carry. Its own number, so a message
/// that reached the wrong endpoint is visible as one.
const IFACE: u64 = 0x0000_0000_0053_4d50;
const METHOD_PING: u32 = 1;
const METHOD_PONG: u32 = 2;

const REQUEST: &[u8] = b"ping";
const REPLY: &[u8] = b"pong";

/// No endpoint published yet. Not zero, which is a valid endpoint.
const NO_ENDPOINT: u64 = u64::MAX;

/// The caller's end and the server's end, published by the boot CPU before any
/// CPU is given work to do.
static CALLER_END: AtomicU64 = AtomicU64::new(NO_ENDPOINT);
static SERVER_END: AtomicU64 = AtomicU64::new(NO_ENDPOINT);

/// A second channel whose two ends are both on the boot CPU.
///
/// **A cross-core number alone says nothing.** `docs/prototypes/01` asks for
/// B24 "reported alongside BM-3 so the same-core/cross-core ratio is tracked
/// explicitly — growth in that ratio is the signal that services need sharding
/// before the budget fails". Under QEMU/TCG the absolute microseconds are the
/// emulator's (build/README.md, D34/D56); the ratio between two paths measured
/// the same way on the same boot is the part that survives.
///
/// The same code drives both, so the difference between them is the thing
/// under test and not two harnesses.
static LOCAL_CALLER_END: AtomicU64 = AtomicU64::new(NO_ENDPOINT);
static LOCAL_SERVER_END: AtomicU64 = AtomicU64::new(NO_ENDPOINT);

/// Which CPU served, recorded by the server itself — the boot CPU cannot know
/// it any other way, and a check that assumed CPU 1 would keep passing on a
/// machine where CPU 1 never arrived.
static SERVER_CPU: AtomicU64 = AtomicU64::new(u64::MAX);

/// What the server saw: 0 nothing yet, 1 the expected request, 2 something
/// else. Three values and not a flag, because "the wrong message arrived" and
/// "no message arrived" are different failures with different causes.
static REQUEST_SEEN: AtomicU64 = AtomicU64::new(0);
/// The same three-way answer for what the caller got back.
static REPLY_SEEN: AtomicU64 = AtomicU64::new(0);
/// Crossings recorded before the call, so the verdict counts this call's own.
static CROSSINGS_BEFORE: AtomicU64 = AtomicU64::new(0);
/// Crossings recorded after it.
static CROSSINGS_AFTER: AtomicU64 = AtomicU64::new(0);

fn encode(endpoint: EndpointId) -> u64 {
    ((endpoint.channel as u64) << 8) | (endpoint.side as u64)
}

fn decode(raw: u64) -> Option<EndpointId> {
    if raw == NO_ENDPOINT {
        return None;
    }
    Some(EndpointId {
        channel: (raw >> 8) as usize,
        side: (raw & 0xff) as usize,
    })
}

/// Creates the channel and publishes both ends.
///
/// Called on the boot CPU **before** any CPU is handed work, because the
/// server reads these the moment it starts running and a server that found
/// nothing would simply exit — a passing boot with the check silently skipped.
pub fn open<C: ContextOps>(exec: &mut Executive<C>) -> bool {
    let Ok((caller, server)) = exec.channel_create() else {
        return false;
    };
    SERVER_END.store(encode(server), Ordering::Release);
    CALLER_END.store(encode(caller), Ordering::Release);
    let Ok((local_caller, local_server)) = exec.channel_create() else {
        return false;
    };
    LOCAL_SERVER_END.store(encode(local_server), Ordering::Release);
    LOCAL_CALLER_END.store(encode(local_caller), Ordering::Release);
    true
}

/// Whether [`open`] published a channel for this boot.
pub fn opened() -> bool {
    CALLER_END.load(Ordering::Acquire) != NO_ENDPOINT
}

/// Round trips the benchmark makes after the check has passed.
///
/// Two hundred, matching the context-switch benchmark's sample count: enough
/// for a percentile to mean something, few enough that a boot does not grow
/// noticeably. Each one is two wakeups, two interrupts and four scheduling
/// decisions, so this is the most expensive sample this tree takes.
pub const BENCH_ROUNDS: usize = 200;

/// The server half: answer the check's request, then serve [`BENCH_ROUNDS`]
/// more and end.
///
/// Runs as a kernel thread on a CPU that is not the boot CPU. It parks in
/// `receive`, which is what puts its identity in the endpoint and its
/// whereabouts in the executive's table — the two things the caller needs to
/// find it from another CPU.
///
/// **Resident for the benchmark, and it has to be.** A bare `reply` blocks the
/// replier when the caller is local, so a server that looped back to its own
/// `receive` would hang after exactly one exchange — a shape this tree has got
/// wrong twice (build/README.md D85, D91). `reply_receive` is the primitive
/// that replies and re-parks in one operation, and it is what makes a
/// measurable number of round trips possible at all.
pub fn serve<C: ContextOps>(exec: &mut Executive<C>) {
    let Some(server_end) = decode(SERVER_END.load(Ordering::Acquire)) else {
        return;
    };
    SERVER_CPU.store(u64::from(crate::percpu::current_index()), Ordering::Release);

    let Ok(request) = exec.receive(server_end) else {
        REQUEST_SEEN.store(2, Ordering::Release);
        return;
    };
    let expected =
        request.header().interface_id == IFACE && request.header().method_id == METHOD_PING;
    REQUEST_SEEN.store(
        if expected && request.inline() == REQUEST {
            1
        } else {
            2
        },
        Ordering::Release,
    );

    // The check's own reply, and then the benchmark's: `reply_receive` answers
    // the outstanding call and waits for the next in one operation, so each
    // pass here is exactly one round trip's worth of server work.
    let mut served = 0usize;
    while served < BENCH_ROUNDS {
        let Ok(response) = pong() else { return };
        match exec.reply_receive(server_end, response) {
            Ok(_request) => served += 1,
            Err(_) => return,
        }
    }
    // **Counted before the last reply is sent, and answered with the
    // continuing form.** `reply` hands the CPU to a caller on this CPU and
    // blocks the replier — correct for a server whose next act is to receive
    // again, and a trap for one that is finishing: the store after it would
    // never run, and the boot would wait for a count from a thread that is
    // never scheduled again. That is this tree's third encounter with the
    // shape (build/README.md D85, D91), and the first where the thread was
    // done rather than looping.
    SERVED.store(served as u64, Ordering::Release);
    if let Ok(response) = pong() {
        let _ = exec.reply_and_continue(server_end, response);
    }
}

fn pong() -> Result<Message, ()> {
    let mut response = Message::new(MessageHeader::new(IFACE, METHOD_PONG));
    response.set_inline(REPLY).map_err(|_| ())?;
    Ok(response)
}

/// Round trips the server actually answered for the benchmark.
static SERVED: AtomicU64 = AtomicU64::new(0);
/// The same, for the same-core server.
static SERVED_LOCAL: AtomicU64 = AtomicU64::new(0);

/// The same-core server: the identical loop, on the CPU that calls it.
///
/// Runs as a kernel thread on the boot CPU, added before the caller so it runs
/// first and parks — which is what lets `call` hand off to it directly, the
/// two-switch path B3 is about. It answers one request to get parked in the
/// right place and then [`BENCH_ROUNDS`] more.
pub fn serve_local<C: ContextOps>(exec: &mut Executive<C>) {
    let Some(server_end) = decode(LOCAL_SERVER_END.load(Ordering::Acquire)) else {
        return;
    };
    if exec.receive(server_end).is_err() {
        return;
    }
    let mut served = 0usize;
    while served < BENCH_ROUNDS {
        let Ok(response) = pong() else { return };
        match exec.reply_receive(server_end, response) {
            Ok(_request) => served += 1,
            Err(_) => break,
        }
    }
    // Counted before the last reply, and answered with the continuing form —
    // see [`serve`] for why.
    SERVED_LOCAL.store(served as u64, Ordering::Release);
    if let Ok(response) = pong() {
        let _ = exec.reply_and_continue(server_end, response);
    }
}

/// Times [`BENCH_ROUNDS`] cross-CPU synchronous calls against the same number
/// of same-core ones — budget B24, read against its B3 baseline.
///
/// Runs in the boot CPU's caller thread, after [`call`] has shown the
/// mechanism works. `now` is the port's serialized counter read; the samples
/// come back in its ticks and the port converts, because what a tick is worth
/// is the one thing this layer cannot know.
///
/// # Interleaved, and it had to be
///
/// The two were measured one after the other to begin with, and the ratio
/// between them swung from 1.5x to 3.1x across runs of the same image — an
/// emulated machine's host does not hold still for the length of a boot, so
/// two benchmarks taken minutes apart are not comparable however carefully
/// each is taken. Alternating them puts every cross-core sample next to a
/// same-core sample under the same conditions, which is the only way a ratio
/// measured here means anything (`docs/prototypes/01`: "reported alongside
/// BM-3 so the same-core/cross-core ratio is tracked explicitly").
///
/// # What a cross-core sample contains
///
/// The call posts a wakeup and blocks; the other CPU takes an interrupt,
/// drains its bitmap, dispatches the server, and the server replies with
/// another wakeup; this CPU drains and dispatches the caller. Two interrupts,
/// two wakeups, four scheduling decisions — and, on this side, however long it
/// takes the boot CPU to *look*, since a CPU with nothing runnable returns
/// from [`Executive::run`] to its caller rather than idling. That pump was
/// measured at under six passes per round trip and is not what dominates; the
/// far CPU waking out of `wfi` is.
pub fn bench<C: ContextOps>(
    exec: &mut Executive<C>,
    now: fn() -> u64,
    cross: &mut [u64],
    local: &mut [u64],
) -> usize {
    let (Some(cross_end), Some(local_end)) = (
        decode(CALLER_END.load(Ordering::Acquire)),
        decode(LOCAL_CALLER_END.load(Ordering::Acquire)),
    ) else {
        return 0;
    };
    // One call to the same-core server before the timed ones, unmeasured: it
    // is what gets that server parked as its endpoint's blocked receiver, and
    // until it is, `call` has nobody to hand off to and takes the slower path.
    // Measuring that pass would report the setup rather than the mechanism.
    // The cross-core server was parked the same way by the check.
    let Ok(first) = ping() else { return 0 };
    if exec.call(local_end, first).is_err() {
        return 0;
    }

    let before = crate::wakeup::crossings();
    let mut local_crossings = 0u64;
    let mut taken = 0usize;
    for round in 0..BENCH_ROUNDS.min(cross.len()).min(local.len()) {
        let Some(sample) = timed(exec, cross_end, now) else {
            break;
        };
        cross[round] = sample;
        // Read between the two halves rather than only at the end: what has to
        // be zero is the *same-core* half, and one total cannot say which half
        // it came from.
        let after_cross = crate::wakeup::crossings();
        let Some(sample) = timed(exec, local_end, now) else {
            break;
        };
        local[round] = sample;
        local_crossings += crate::wakeup::crossings().saturating_sub(after_cross);
        taken += 1;
    }
    CROSSINGS_TOTAL.store(
        crate::wakeup::crossings().saturating_sub(before),
        Ordering::Release,
    );
    LOCAL_CROSSINGS.store(local_crossings, Ordering::Release);
    BENCHED.store(taken as u64, Ordering::Release);
    taken
}

/// One timed round trip, or `None` if the call failed.
fn timed<C: ContextOps>(
    exec: &mut Executive<C>,
    endpoint: EndpointId,
    now: fn() -> u64,
) -> Option<u64> {
    let request = ping().ok()?;
    let start = now();
    let outcome = exec.call(endpoint, request);
    let end = now();
    outcome.ok()?;
    Some(end.wrapping_sub(start))
}

fn ping() -> Result<Message, ()> {
    let mut request = Message::new(MessageHeader::new(IFACE, METHOD_PING));
    request.set_inline(REQUEST).map_err(|_| ())?;
    Ok(request)
}

/// Round trips the caller completed, of each kind.
static BENCHED: AtomicU64 = AtomicU64::new(0);
/// Wakeups that crossed a CPU during the whole benchmark.
static CROSSINGS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Of those, how many the same-core half was responsible for — which must be
/// none.
static LOCAL_CROSSINGS: AtomicU64 = AtomicU64::new(0);

/// Whether every round trip the benchmark asked for completed on both sides.
///
/// The counts are checked and not assumed: a call that failed halfway leaves a
/// percentile computed over a prefix, which looks like a fast result rather
/// than a broken one.
pub fn bench_complete() -> bool {
    BENCHED.load(Ordering::Acquire) == BENCH_ROUNDS as u64
        && SERVED.load(Ordering::Acquire) == BENCH_ROUNDS as u64
        && SERVED_LOCAL.load(Ordering::Acquire) == BENCH_ROUNDS as u64
}

/// What the two benchmarks did across CPUs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BenchCrossings {
    /// Wakeups the cross-core round trips posted to another CPU.
    pub cross: u64,
    /// The same for the same-core round trips, which must be none.
    pub local: u64,
}

/// Prints what the two benchmarks did across CPUs and returns the claim keys.
///
/// **A latency number cannot say what it measured.** Both benchmarks run the
/// same code over the same message on the same boot; the only difference is
/// where the server is, and nothing in a percentile shows that. So the
/// crossings are counted — and none at all is what the same-core pair must
/// have, because it hands off directly. A "cross-core" benchmark that had
/// quietly run both ends on one CPU reports plausible microseconds and zero
/// here.
///
/// # Between once and twice per round trip, and the range is the finding
///
/// The obvious assertion is two crossings each: the request finding its callee
/// parked elsewhere, and the reply going back. It held for 400 out of 400 on a
/// quiet machine and read **399** under load, which is not a defect — it is the
/// mechanism. A `call` posts a wakeup only if the callee is *already* parked;
/// if the server has replied but not yet re-registered as its endpoint's
/// blocked receiver, the request is simply queued and the server finds it on
/// its own next pass. Nothing crosses, and nothing is lost.
///
/// The reply is the direction that cannot be raced away: the caller's
/// whereabouts are recorded on the way *into* `call`, before the request is
/// enqueued, so a server that can see the request can always find the caller
/// (build/README.md, D240). So every round trip crosses at least once and at
/// most twice, and that is what is asserted. The exact-two form would have
/// been a check that passes on an idle machine and fails on a busy one, which
/// is the worst kind.
pub fn report_crossings() -> &'static [&'static str] {
    let local = LOCAL_CROSSINGS.load(Ordering::Acquire);
    let seen = BenchCrossings {
        cross: CROSSINGS_TOTAL
            .load(Ordering::Acquire)
            .saturating_sub(local),
        local,
    };
    let rounds = BENCHED.load(Ordering::Acquire);
    crate::kprintln!(
        "perf: cross-call crossed {} times in {} round trips (1-2 each); the same-core pair {}",
        seen.cross,
        rounds,
        seen.local
    );
    if rounds > 0 && seen.cross >= rounds && seen.cross <= 2 * rounds && seen.local == 0 {
        &["perf.cross-call-crossed"]
    } else {
        &[]
    }
}

/// Whether the server has parked in its `receive`, from the boot CPU.
///
/// **Waited for, and not assumed.** If the caller runs first the request is
/// simply queued, the server picks it up without ever being woken, and only
/// the reply crosses — a round trip that completes and proves half of what is
/// claimed. Waiting for the receiver to register itself makes the request
/// direction cross too, which is what makes "two crossings" a checkable number
/// rather than a hopeful one.
///
/// The window between registering and actually parking is harmless: the
/// server's whereabouts were recorded on the way *into* `receive`, before it
/// registered, so a wakeup posted in that window is found and left on the
/// bitmap for the server's own CPU to take after it parks.
pub fn server_parked<C: ContextOps>(exec: &Executive<C>) -> bool {
    decode(SERVER_END.load(Ordering::Acquire))
        .and_then(|end| exec.endpoint_receiver(end))
        .is_some()
}

/// The caller half: one synchronous call, on the boot CPU.
///
/// The crossing count is sampled either side of the call rather than read once
/// at the end, so what the verdict reports is what *this* call did and not
/// whatever else the boot has posted.
pub fn call<C: ContextOps>(exec: &mut Executive<C>) {
    let Some(caller_end) = decode(CALLER_END.load(Ordering::Acquire)) else {
        return;
    };
    let mut request = Message::new(MessageHeader::new(IFACE, METHOD_PING));
    if request.set_inline(REQUEST).is_err() {
        return;
    }
    CROSSINGS_BEFORE.store(crate::wakeup::crossings(), Ordering::Release);
    match exec.call(caller_end, request) {
        Ok(reply) => {
            let expected =
                reply.header().interface_id == IFACE && reply.header().method_id == METHOD_PONG;
            REPLY_SEEN.store(
                if expected && reply.inline() == REPLY {
                    1
                } else {
                    2
                },
                Ordering::Release,
            );
        }
        Err(_) => REPLY_SEEN.store(2, Ordering::Release),
    }
    CROSSINGS_AFTER.store(crate::wakeup::crossings(), Ordering::Release);
}

/// Whether the caller has finished, either way — what a boot pump waits on.
pub fn finished() -> bool {
    REPLY_SEEN.load(Ordering::Acquire) != 0
}

/// What the round trip did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrossCall {
    /// The CPU that served, or `None` if nothing did.
    pub server_cpu: Option<u32>,
    /// The server got the request this check sent.
    pub request_arrived: bool,
    /// The caller got the reply this check expected.
    pub reply_arrived: bool,
    /// Wakeups posted to another CPU during the call.
    pub crossings: u64,
}

/// What the round trip did, read on the boot CPU after it has finished.
pub fn outcome() -> CrossCall {
    let cpu = SERVER_CPU.load(Ordering::Acquire);
    CrossCall {
        server_cpu: (cpu != u64::MAX).then_some(cpu as u32),
        request_arrived: REQUEST_SEEN.load(Ordering::Acquire) == 1,
        reply_arrived: REPLY_SEEN.load(Ordering::Acquire) == 1,
        crossings: CROSSINGS_AFTER
            .load(Ordering::Acquire)
            .saturating_sub(CROSSINGS_BEFORE.load(Ordering::Acquire)),
    }
}

/// Prints the boot line and returns the claim keys.
///
/// **Two crossings, not one, and the number is checked.** A request that found
/// its callee parked elsewhere is one, and the reply going back the other way
/// is the other; a boot that reported one had a call where one direction was
/// local — which is a different arrangement from the one being claimed, and
/// would pass a check that only asked whether the reply came back.
pub fn report(outcome: CrossCall) -> &'static [&'static str] {
    let Some(server_cpu) = outcome.server_cpu else {
        return &[];
    };
    crate::kprintln!(
        "exec: cross-CPU call to a server on CPU {}: request {}, reply {}, {} wakeup(s) crossed",
        server_cpu,
        if outcome.request_arrived {
            "arrived"
        } else {
            "LOST"
        },
        if outcome.reply_arrived {
            "arrived"
        } else {
            "LOST"
        },
        outcome.crossings
    );
    if outcome.request_arrived && outcome.reply_arrived && outcome.crossings >= 2 {
        &["exec.cross-cpu-call"]
    } else {
        &[]
    }
}
