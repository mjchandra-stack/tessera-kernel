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
    // Things the system does to decide what it is allowed to trust: verifying
    // an image before reading it, and what follows from that. None of the
    // seven above names it — a store refusal is not a driver fault, a memory
    // fault or an exception — and filing it under one of them would put a
    // security decision in a stream nobody reads for security decisions.
    SECURITY = 8;
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

    // --- Driver framework (Component::DRIVER) ---
    //
    // These name what the *kernel* mediates about a device capability, and
    // deliberately nothing above it. There is no BOUND event: binding is a
    // user<->user protocol (`driver_bind.isl`) the kernel transports opaquely,
    // and a kind named for it would put protocol knowledge in the kernel that
    // the framework exists to keep out — the same reason reclaim-on-death sends
    // a capability with no payload. The lifecycle ladder `docs/drivers/01`
    // defines (Discovered, Matched, Probing, Active, ...) belongs to the ring-3
    // device manager and arrives when a ring-3 emit path does
    // (build/README.md, D112).

    // A device's register window was mapped into a driver's address space
    // through a capability carrying MAP: arg0 = device object id, arg1 = the
    // page's user VA, arg2 = the physical page base, arg3 = the resource
    // graph's window length. The authority is the capability; the physical
    // base is never the caller's to choose.
    DEVICE_WINDOW_MAPPED = 9;
    // A register window was revoked because the capability behind it left the
    // process (docs/kernel/06): arg0 = device object id, arg1 = the VA
    // unmapped, arg2 = the route it left by (1 = transferred to another
    // process, 2 = the handle was closed), arg3 = the unmap result, 0 when the
    // page came down cleanly and a KError otherwise — a non-zero value means
    // the window table and the page tables had drifted.
    DEVICE_WINDOW_REVOKED = 10;
    // A MapDevice was refused. Authority working is worth a record: arg0 =
    // the device object id, or 0 when the handle did not resolve to one;
    // arg1 = the KError; arg2 = the VA the caller asked for.
    DEVICE_MAP_REFUSED = 11;
    // A DMA buffer was granted against a device capability — the caller's VA
    // and the device-visible physical address for the same memory: arg0 =
    // device object id, arg1 = user VA, arg2 = physical base, arg3 = length.
    DEVICE_DMA_GRANTED = 12;
    // A device capability was reclaimed from a dying process and sent to the
    // manager, which the process itself never did (docs/drivers/01, crash
    // recovery): arg0 = device object id, arg1 = the rights it travelled with,
    // arg2 = the destination endpoint.
    DEVICE_RECLAIMED = 13;
    // A reclaim could not deliver, so the device is as lost as it would have
    // been without reclaim at all — the bound on what reclaim can promise,
    // recorded rather than swallowed (docs/lifecycle/04, "No Silent
    // Fallback"): arg0 = device object id, arg1 = cause (1 = no handle room in
    // the message, 2 = the destination queue was full).
    DEVICE_RECLAIM_LOST = 14;
    // A driver host faulted and was contained — step 1 of the crash-recovery
    // ladder: arg0 = the trap vector, arg1 = the faulting address, arg2 = the
    // launch index that crashed.
    DRIVER_HOST_CRASHED = 15;
    // A crashed driver host was reclaimed and relaunched against the same
    // device binding — ladder steps 6 and 7: arg0 = the new launch index,
    // arg1 = the restart budget remaining, arg2 = frames reclaimed from the
    // corpse (a leak shows up here rather than only in a final total).
    DRIVER_HOST_RESTARTED = 16;
    // A persistently crashing host exhausted its restart budget and the
    // supervisor stopped: arg0 = launches made, arg1 = the give-up code.
    DRIVER_HOST_GAVE_UP = 17;
    // A DMA buffer was granted to a device with **no aperture**, so the
    // address handed back is a physical address the device can use to reach
    // anything, not one scoped to it: arg0 = device object id, arg1 = user VA,
    // arg2 = the physical address.
    //
    // This is the honest report of a real limitation rather than an error.
    // A machine may have no IOMMU at all, and refusing would leave such a
    // machine unable to run a driver; returning the address without saying so
    // would let an unscoped grant pass for a scoped one, which is the silent
    // degradation docs/lifecycle/04 forbids. So the grant proceeds and the
    // system records that this one is not scoped.
    DEVICE_DMA_UNSCOPED = 18;
    // A DMA buffer was granted to a device that translates through an
    // aperture, so the address handed back is an **IOVA** the IOMMU resolves
    // for that device alone: arg0 = device object id, arg1 = user VA, arg2 =
    // the IOVA, arg3 = the physical page behind it.
    //
    // The counterpart to DEVICE_DMA_UNSCOPED, and the reason both exist: every
    // grant says which kind it is, so a scoped grant is a positive record
    // rather than the absence of a warning. arg2 and arg3 are the two names
    // for the same memory, and they differ here — which is the whole point,
    // and what a consumer checks to know translation is in play.
    DEVICE_DMA_SCOPED = 19;
    // A device's DMA lease began: a driver asked its device for DMA and the
    // device was given an address space it did not have a moment before.
    // arg0 = device object id, arg1 = the holding process, arg2 = the lease's
    // base address, arg3 = its length.
    //
    // Paired with DEVICE_DMA_LEASE_ENDED, and both exist because a lease is an
    // *interval* — "this device could reach memory between here and here" is
    // the question an audit asks, and one record cannot answer it.
    // DEVICE_DMA_SCOPED does not substitute: that fires per grant, this fires
    // once per lease, and the difference is exactly what tells a driver that
    // allocated ten buffers from one that was rebound ten times.
    DEVICE_DMA_LEASE_BEGAN = 20;
    // A device's DMA lease ended: its translations are gone and it can reach
    // nothing until a new lease begins. arg0 = device object id, arg1 = the
    // process that held it, arg2 = why (LeaseEndReason: 1 transferred away,
    // 2 last handle closed, 3 the holder is gone), arg3 = reserved, 0.
    //
    // This is the record with no register-window counterpart. A window dies
    // with the address space it lives in, so D93 could leave process teardown
    // uninstrumented; an IOMMU translation lives in the IOMMU and outlives the
    // process completely, so the end of a lease is a thing that has to be done
    // and therefore a thing worth recording that it was.
    DEVICE_DMA_LEASE_ENDED = 21;
    // The IOMMU refused one of a device's transactions and said why: arg0 =
    // device object id, or 0 when the fault names a stream no device
    // capability is backed by; arg1 = the address the device asked for;
    // arg2 = the normalized fault kind (`kcore::devmgr::DmaFaultKind`:
    // 1 unmapped, 2 permission, 3 unknown stream, 4 malformed configuration,
    // 0 the unit reported something this kernel does not classify); arg3 =
    // the raw stream id the unit named, so a fault on a stream the graph has
    // no device for is still traceable to the wiring that produced it.
    //
    // **The kind is normalized, not the unit's own encoding.** An SMMUv3
    // `F_TRANSLATION` and a VT-d translation fault are the same fact about
    // the system, and a consumer that had to know which IOMMU produced a
    // record could not read a fleet. The mapping lives in the port that owns
    // the unit, which is the only place that knows both vocabularies.
    //
    // Distinguishing "unmapped" from "unknown stream" is what makes this
    // evidence rather than noise: the first is an aperture doing its job, the
    // second is a device whose stream table entry was never installed — the
    // same missing DMA, opposite causes.
    DEVICE_DMA_FAULT = 22;
    // A DMA fault triggered driver isolation (docs/drivers/01, "DMA Safety":
    // *DMA faults are logged and can trigger driver isolation*): the device's
    // lease was ended, so it now reaches nothing at all rather than merely
    // being refused one address. arg0 = device object id, arg1 = the process
    // whose lease was ended, arg2 = the policy that decided
    // (`kcore::devmgr::IsolationPolicy`: 2 end the lease, 3 end it and stop
    // the holder), arg3 = the fault kind that provoked it.
    //
    // Separate from DEVICE_DMA_LEASE_ENDED, which also fires: that record
    // says a lease ended and by which route, this one says a *policy* acted.
    // A lease ending because a driver exited and one ending because its
    // device misbehaved are the same mechanism and entirely different events
    // to anything reading them.
    DEVICE_DMA_ISOLATED = 23;
    // A device's interrupt route was torn down because the capability behind
    // it left the process holding it: arg0 = device object id, arg1 = the
    // interrupt-controller INTID that stopped being delivered, arg2 = the
    // route it left by (`kcore::devmgr::RouteEndReason`: 1 transferred to
    // another process, 2 the last handle was closed, 3 the holder is gone),
    // arg3 = the process that held it.
    //
    // The interrupt counterpart of DEVICE_WINDOW_REVOKED, and it exists for
    // the same reason with one difference that decides the design: a register
    // window dies with the address space, and an interrupt route does not.
    // It lives in the interrupt controller and in the kernel's port table,
    // both of which outlive the driver completely — so a route that is not
    // ended explicitly keeps waking a port nobody is draining, on behalf of a
    // driver that no longer exists.
    DEVICE_IRQ_REVOKED = 24;
    // A memory grant's mapping was revoked because the capability behind it
    // left the process holding it: arg0 = memory object id, arg1 = the base VA
    // unmapped, arg2 = the route it left by (`kcore::process::
    // WindowRevokeReason`: 1 transferred, 2 last handle closed, 3 the holder
    // is gone), arg3 = the reclaim result — 0 when the range came down
    // cleanly and a KError otherwise.
    //
    // **A non-zero result is not cosmetic here**, unlike the device-window
    // record it is modelled on. A device window is untracked, so a failed
    // unmap leaves nothing behind that anything else will act on. A memory
    // mapping is tracked, so a failed reclaim leaves a record the address
    // space still believes in — and the kernel deliberately keeps that record
    // rather than dropping it, because dropping it is what would let teardown
    // free the same frames a second time.
    MEMORY_GRANT_REVOKED = 30;

    // A device was removed from the machine and every capability naming it was
    // invalidated: `arg0` = the device object, `arg1` = holders whose handles
    // were taken, `arg2` = register windows unmapped, `arg3` = dependents the
    // graph knew of.
    //
    // **The first departure nobody chose.** Every other record of a capability
    // leaving — transferred, closed, holder gone — describes something the
    // holder did. This one describes the thing the capability named ceasing to
    // exist while its holders were running and using it, which is why the
    // counts are in the record: "the device went away" is not the interesting
    // part, "and it was taken from three processes" is.
    DEVICE_REMOVED = 31;
    // A device moved between driver-lifecycle states (`driver_lifecycle.isl`):
    // arg0 = device object id, arg1 = the state it left, arg2 = the state it
    // entered, arg3 = the reason. The `detail` a manager supplied rides in the
    // record's `flags`, because the four payload slots are spent on the
    // transition itself and the detail is the one field the kernel does not
    // interpret.
    //
    // **This is the record `docs/drivers/01` asks for** — *"transitions are
    // observable through structured events"* — and the reason the states are
    // ABI at all. The device is resolved from a capability the caller holds,
    // never taken from the payload, so a process cannot narrate a lifecycle
    // for a device it does not have.
    DRIVER_LIFECYCLE_TRANSITION = 25;
    // A crashed driver host's dump was captured — ladder step 3: arg0 = the
    // dead process, arg1 = the faulting address, arg2 = how many trace records
    // were captured with it, arg3 = the cause the port reported.
    //
    // The dump itself is not in this record and could not be: it is a fault
    // frame and a tail of the event ring, which do not fit in four words. What
    // is here is that one was taken and how much of the trail survived —
    // because the failure mode worth recording is a dump that captured
    // *nothing*, which is indistinguishable from no crash at all if the only
    // evidence is the dump itself.
    DRIVER_CRASH_DUMP = 26;
    // Services depending on a failed device were told — ladder step 4: arg0 =
    // device object id, arg1 = how many dependents were notified, arg2 = how
    // many could not be reached, arg3 = the state they were told about.
    //
    // Both counts, because a notification that could not be delivered is the
    // interesting one: a dependent that never learns its device is gone will
    // wait on it for ever, and a silent drop here is the failure the record
    // exists to surface.
    DEVICE_DEPENDENTS_NOTIFIED = 27;
    // A device reset was attempted — ladder step 5: arg0 = device object id,
    // arg1 = the outcome (0 = the device came back, otherwise a KError),
    // arg2 = the class the reset was performed for, arg3 = reserved.
    //
    // Attempted, not performed: a reset the policy declined and a reset the
    // hardware refused are different facts, and only the second one reaches
    // this record. The first is a lifecycle transition that never happened.
    DEVICE_RESET = 28;
    // A device was quarantined: policy declined to bind it again, so the
    // kernel will not hand it back to a manager. arg0 = device object id,
    // arg1 = the failures that led here, arg2 = the policy that decided,
    // arg3 = reserved.
    //
    // The end of `docs/drivers/01`'s *"repeated crashes can trigger rollback,
    // fallback drivers, or device quarantine"*, and the loudest of the three:
    // a quarantined device is one the machine has stopped offering, and a
    // system that did that silently would look identical to one whose
    // enumeration had simply missed it.
    DEVICE_QUARANTINED = 29;
    // A device's interrupt was armed or disarmed as a system wakeup source:
    // arg0 = device object id, arg1 = 1 for armed and 0 for disarmed,
    // arg2..3 = reserved.
    //
    // `docs/power/01` requires the set of things able to wake this machine to
    // be explicit and auditable. A right gates it; this is what makes the
    // resulting set *readable* — otherwise the only way to know what may wake
    // a device is to suspend it and find out.
    POWER_WAKE_SOURCE_ARMED = 32;
    // A wakeup source fired: arg0 = the device object id credited, arg1 = the
    // controller line it arrived on, arg2 = the system wake-event counter
    // after the increment, arg3 = the scheduler tick.
    //
    // `flags` bit 0 is set when the grace hold could **not** be taken because
    // the hold table was full. The event is still counted — the counter is
    // what a suspend commit compares — but the machine has lost the short
    // veto that stops an event arriving just after a resume from being
    // swallowed by an immediate re-suspend, and that is a degradation rather
    // than a detail.
    POWER_WAKE_EVENT = 33;
    // A wake hold was taken: arg0 = the holder's object id, arg1 = the
    // requested lifetime in scheduler ticks (0 = until released), arg2 = the
    // tick it was taken at, arg3 = holds live afterwards.
    POWER_WAKE_HOLD_TAKEN = 34;
    // A wake hold was released: arg0 = the holder's object id, arg1 = the
    // tick, arg2 = holds still live, arg3 = reserved.
    //
    // Grants, durations and releases are all events because `docs/power/01`
    // asks for them by name: a suspend blocker whose lifetime nobody can see
    // is the wakelock failure this design is written against.
    POWER_WAKE_HOLD_RELEASED = 35;
    // The system was committed to sleep: arg0 = the wake-counter snapshot the
    // committer compared, arg1 = the tick, arg2..3 = reserved.
    //
    // Emitted **before** the CPU stops, because a record written afterwards
    // would be a record of a suspend that had already ended — and the whole
    // point of the timeline `docs/power/01` asks for is that each stage is
    // attributable while it is happening.
    POWER_SUSPEND_COMMITTED = 36;
    // A suspend entry aborted: arg0 = why (1 = a wake arrived after the
    // snapshot, 2 = a wake hold vetoed it), arg1 = the counter now, arg2 = the
    // snapshot compared, arg3 = the vetoing holder for a veto and zero
    // otherwise.
    //
    // The lost-wakeup race, closed by counting rather than by ordering: an
    // event that arrived between the snapshot and the commit either changed
    // the number or it did not, and if it did the entry stops here.
    POWER_SUSPEND_ABORTED = 37;
    // The system resumed: arg0 = the device object id credited with the wake,
    // arg1 = the counter, arg2 = the tick, arg3 = reserved.
    //
    // `docs/power/01` requires the first structured event of every resume to
    // name the wake source. This is that event, and the source is the one the
    // kernel credited at interrupt time rather than one reconstructed after
    // the fact.
    POWER_RESUMED = 38;

    // --- The verified image store (Component::SECURITY) ---

    // A store was mounted: its directory measured to an anchor this system
    // holds. arg0 = how many blobs it holds, arg1 = the measurement algorithm,
    // arg2 = the anchor id it named, arg3 = the leading eight bytes of the
    // measurement.
    //
    // The measurement is in the record because provenance is the point. An
    // event saying only that verification succeeded describes the verifier;
    // one carrying *what* was accepted describes the system, and is the only
    // form a fleet can be asked what it is running.
    STORE_MOUNTED = 39;
    // A store was refused: arg0 = the `StoreError`, arg1 = the size of the
    // region it was read from, arg2 = the anchor id it named where the header
    // was intact enough to say and zero otherwise, arg3 = reserved.
    //
    // Every refusal is recorded, including the ones that look like nothing is
    // installed. A system that read no store because it found none and a
    // system that read no store because the one it found had been altered are
    // different situations with the same symptom, and only this tells them
    // apart.
    STORE_REFUSED = 40;

    // --- Firmware loading (Component::SECURITY) ---

    // A firmware image was verified, admitted and handed out: arg0 = the device
    // object it was loaded for, arg1 = its security version, arg2 = its image
    // version, arg3 = the leading eight bytes of its measurement.
    //
    // **The measurement is the record.** `docs/drivers/01` requires firmware
    // provenance to be logged, and an event saying that a load succeeded
    // describes the loader; one carrying which bytes went onto which device is
    // the only form a fleet can be asked what it is running.
    //
    // The kernel emits it because a ring-3 service still cannot emit a
    // structured event (build/README.md, D140) — and because provenance
    // recorded by the component that asked for the image would be a claim
    // rather than a record.
    FIRMWARE_LOADED = 41;
    // A firmware load was refused: arg0 = the device object, or 0 where the
    // handle did not resolve to one; arg1 = the `FirmwareRefusal`, or 0 when
    // the refusal was not policy's (a missing image, a failed measurement);
    // arg2 = the KError; arg3 = the security version that was refused, where
    // the image existed to have one.
    //
    // Both halves are recorded, and the split in arg1/arg2 is the point: an
    // image the system has retired and an image nobody has are different
    // situations that a single "refused" would make identical.
    FIRMWARE_REFUSED = 42;

    // --- Memory classification (Component::SECURITY) ---

    // A memory object was put on a handling path: arg0 = the object id, arg1 =
    // the class it is now on, arg2 = the class it was on, arg3 = the process
    // that asked.
    //
    // The previous class is in the record because a *raise* is the interesting
    // event and an idempotent re-classification is not: a reader that saw only
    // the new class could not tell the moment memory became protected from the
    // hundredth time somebody said it already was.
    MEMORY_CLASSIFIED = 43;
    // A device was refused protected memory: arg0 = the device object id,
    // arg1 = the memory object id, arg2 = the class the memory is on, arg3 =
    // the rights the caller's device handle carried.
    //
    // The rights are in the record because this refusal has exactly one fix —
    // authorize the device — and a record that did not say what the caller
    // actually held would leave somebody guessing which bit was missing.
    DMA_PROTECTED_REFUSED = 44;
    // A device behind an IOMMU was refused a physically-contiguous buffer:
    // arg0 = the device object id, arg1 = the memory object id.
    //
    // Recorded because the refusal is a *policy* one and its fix is to ask for
    // device-visible contiguity instead (`docs/hardware/04`, "Contiguity
    // Contract"). A run of physical memory spent on hardware that did not need
    // one is memory nothing can defragment, and without this record the
    // over-asking would be invisible to everyone including the caller.
    DMA_CONTIGUITY_REFUSED = 45;
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
