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
    true
}

/// Whether [`open`] published a channel for this boot.
pub fn opened() -> bool {
    CALLER_END.load(Ordering::Acquire) != NO_ENDPOINT
}

/// The server half: receive one request, reply, and end.
///
/// Runs as a kernel thread on a CPU that is not the boot CPU. It parks in
/// `receive`, which is what puts its identity in the endpoint and its
/// whereabouts in the executive's table — the two things the caller needs to
/// find it from another CPU.
///
/// One request and not a loop: a resident server would have to use
/// `reply_receive` (a bare `reply` blocks the replier when the caller is
/// local), and what is being checked here is the crossing, not residency.
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

    let mut response = Message::new(MessageHeader::new(IFACE, METHOD_PONG));
    if response.set_inline(REPLY).is_err() {
        return;
    }
    let _ = exec.reply(server_end, response);
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
