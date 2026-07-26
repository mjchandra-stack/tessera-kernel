// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The kernel structured-observability event ABI, defined in ISL.
// `docs/observability/01-debugging-monitoring-tracing-logging.md` ("Structured
// Logging") requires records — not plain strings — carrying timestamp, component,
// thread, process, severity, event name, schema version, correlation id, and data
// classification, with "plain text rendering generated from structured records".
// `docs/lifecycle/04-coding-guidelines.md` makes it a code rule: "Events and
// tracepoints are ISL-declared; `println!`-style debugging does not land."
//
// ISL has no `event` construct, so an event is the ABI-struct shape every other
// kernel record uses: a `strict enum` discriminator plus an `@abi` struct with the
// mandatory `size`/`version`/`flags` envelope. The payload is a fixed scalar set
// (`arg0..arg3`) interpreted per `EventKind` rather than a per-kind union, because
// union wire codegen is deferred (build/README.md, D10). The kernel emits these
// into a bounded ring (`kcore::event`); the log service that harvests and merges
// them is Stage 1 (docs/observability/02, docs/roadmap/01).

library tessera.kernel.observability;

// Severity ordering. `docs/observability/01` mandates a severity field but does
// not enumerate the levels; this ladder is the project's choice, recorded in
// build/README.md (D57). Values are gapped by ten so a level can be inserted
// without renumbering — enum values are ABI and are never reused.
strict enum Severity : uint32 {
    DEBUG = 10;
    INFO = 20;
    NOTICE = 30;
    WARNING = 40;
    ERROR = 50;
    CRITICAL = 60;
};

// The emitting subsystem (the "component ID" field).
strict enum Component : uint32 {
    PAGER = 1;
    MEMORY = 2;
    DRIVER = 3;
    SCHEDULER = 4;
    IPC = 5;
    OBSERVABILITY = 6;
    EXCEPTION = 7;
};

// The data class of an event's payload, from the single normative taxonomy in
// `docs/security/01-security-model.md` ("Data Classification"). Every v0 event
// carries scalar counters and identifiers only, so all are PUBLIC; the classes
// that require redaction arrive with the payloads that need them (redaction
// codegen is deferred, D10).
strict enum Classification : uint32 {
    PUBLIC = 0;
};

// The event catalog — the "event name" field as a stable id. Values are ABI:
// append only, never renumber or reuse.
strict enum EventKind : uint32 {
    // An external-pager page-in completed: arg0 = object id, arg1 = offset,
    // arg2 = latency in the sample unit (TSC cycles).
    PAGER_PAGE_IN = 1;
    // A page-in request passed its deadline and was faulted: arg0 = miss index,
    // arg1 = the deadline, arg2 = the escalation budget.
    PAGER_DEADLINE_MISS = 2;
    // Repeated deadline misses crossed the supervision budget, escalating to a
    // supervised restart: arg0 = miss count, arg1 = escalation count.
    PAGER_SUPERVISION_ESCALATE = 3;
    // A pager-backed object entered the faulted state, losing dirty ranges
    // (the data-integrity record): arg0 = lost range count, arg1 = the lowest
    // lost offset.
    PAGER_OBJECT_FAULTED = 4;
    // A frame reclaim exceeded a bound and the frame leaked: arg0 = reason
    // (1 = free list full, 2 = shared table full), arg1 = the bound.
    MEM_RECLAIM_OVERFLOW = 5;
    // The meta-event: emission was dropped because the ring was full, so the
    // silencing is itself visible (docs/observability/02). arg0 = dropped count.
    EVENTS_DROPPED = 6;
    // A ring-3 fault was contained (the process died, the kernel did not) — the
    // exception report `docs/kernel/03` requires, carrying the faulting thread's
    // correlation id in the envelope: arg0 = trap vector, arg1 = faulting address.
    USER_FAULT_CONTAINED = 7;
    // A fan-out link: `parent` caused the fresh id in this record's envelope, so
    // traces form a tree rather than a set sharing one id (docs/observability/02,
    // "Fan-out links, not shared IDs"): arg0 = the parent correlation id,
    // arg1 = the spawned thread's scheduler index.
    CORRELATION_LINK = 8;
};

// One structured event record. The envelope is the mandated field set; the
// payload is `arg0..arg3`, interpreted per `EventKind` above. `correlation_lo`
// and `correlation_hi` are the two halves of the mandated 128-bit correlation id
// (docs/observability/02): `_hi` is the per-boot epoch and `_lo` the monotonic
// sequence minted at a causal origin (`kcore::trace`, D59). Both are zero only
// where no origin has minted yet — before boot installs the epoch.
@abi
struct KernelEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    kind: EventKind;
    severity: Severity;
    component: Component;
    classification: Classification;
    timestamp: uint64;
    thread_id: uint64;
    process_id: uint64;
    correlation_lo: uint64;
    correlation_hi: uint64;
    arg0: uint64;
    arg1: uint64;
    arg2: uint64;
    arg3: uint64;
};
