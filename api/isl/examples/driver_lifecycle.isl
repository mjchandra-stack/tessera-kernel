// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The driver lifecycle: the thirteen states a bound device passes through, the
// reasons it moves between them, and the syscall a device manager uses to say
// that it did.
//
// `docs/drivers/01-driver-framework.md` ("Driver Lifecycle") lists the states
// and then one sentence that decides where they live: *"transitions are
// observable through structured events"*. Observable means a **record**, not a
// field a manager keeps to itself — so the states are ABI, and the transitions
// go into the same bounded ring every kernel mechanism emits into.
//
// **The manager owns the state; the kernel owns the record.** A driver
// lifecycle is a policy question — when is a device Matched, when has probing
// failed, when is it worth resetting — and answering it needs a table of
// drivers, a class map, and a binding policy, none of which belong in a kernel.
// But a manager that also owned the *recording* could describe a lifecycle that
// never happened, and a log service could not tell. So the manager declares a
// transition and the kernel stamps it: the device is resolved from a capability
// the caller holds, the emitting process and its causal id come from the kernel
// (`docs/lifecycle/04`: caller identity is never a payload field), and what the
// manager supplies is only the part it is authoritative for — which state, and
// why.
//
// This closes the D112 deferral: the ladder these states describe belonged to a
// ring-3 device manager and waited on a ring-3 emit path, which is
// `DriverLifecycle` below.

library tessera.driver.lifecycle;

// The lifecycle states, in the order `docs/drivers/01` lists them.
//
// Values are ABI: append only, never renumber or reuse. Numbered from 1 so
// that zero stays available as "no state recorded", which a decoder can tell
// apart from a real state — a lifecycle that started at 0 would make an
// uninitialised record indistinguishable from a Discovered device.
strict enum DriverState : uint32 {
    // The device exists: enumeration found it and the manager holds a
    // capability to it. Nothing has been decided about who drives it.
    DISCOVERED = 1;
    // A driver has been chosen for it. The binding inputs matched; nothing has
    // been started.
    MATCHED = 2;
    // The driver host is being brought up.
    STARTING = 3;
    // The driver is running its probe: touching the device to confirm it is
    // what the match said it was.
    PROBING = 4;
    // Probe succeeded. The device is in service.
    ACTIVE = 5;
    // A power transition is in flight, downward.
    SUSPENDING = 6;
    // The device is powered down and its driver is quiescent.
    SUSPENDED = 7;
    // A power transition is in flight, upward.
    RESUMING = 8;
    // The device is being reset — ladder step 5, or a driver's own recovery.
    RESETTING = 9;
    // The device is bound and working, but not correctly or not fully:
    // ladder step 2, where a crash has been contained and the manager has
    // marked the device before deciding what to do about it.
    //
    // Degraded is deliberately not Failed. A device whose driver crashed once
    // is still bindable, still enumerated, and still the same hardware; a
    // system that jumped straight to Failed would throw away a device that a
    // restart would have recovered.
    DEGRADED = 10;
    // The driver is being taken down, by policy or by request.
    STOPPING = 11;
    // The device is gone: unplugged, or its binding deliberately dismantled.
    REMOVED = 12;
    // The end of the ladder: the device is not driveable and the system has
    // stopped trying. Quarantine is a Failed device the manager will not offer
    // again.
    FAILED = 13;
};

// Why a transition happened.
//
// The state pair says *what* changed; this says what changed it, and the two
// are not redundant. Active -> Degraded because a driver crashed and Active ->
// Degraded because a device reported a correctable error are the same edge and
// entirely different events to anything reading them.
//
// Values are ABI: append only.
strict enum TransitionReason : uint32 {
    // No reason given. Present so an unset field is a value rather than a
    // misread of the first real reason.
    UNSPECIFIED = 0;
    // Enumeration found the device.
    ENUMERATED = 1;
    // The binding inputs selected a driver.
    BOUND = 2;
    // A driver host was launched.
    LAUNCHED = 3;
    // The driver confirmed the device is what the match said.
    PROBE_SUCCEEDED = 4;
    // The driver could not confirm it. The device is real; this driver is not
    // the right one, or the device is not answering.
    PROBE_FAILED = 5;
    // The driver host faulted and was contained.
    DRIVER_CRASHED = 6;
    // The supervisor is bringing a replacement up against the same binding.
    RESTARTED = 7;
    // A reset was attempted and the device came back.
    RESET_SUCCEEDED = 8;
    // A reset was attempted and it did not.
    RESET_FAILED = 9;
    // The restart budget is spent: no further attempt will be made.
    BUDGET_EXHAUSTED = 10;
    // Policy declined to rebind this device, and it will not be offered again.
    QUARANTINED = 11;
    // Policy restored the binding after a recovered failure.
    BINDING_RESTORED = 12;
    // A different driver configuration was chosen after the first failed.
    FALLBACK_SELECTED = 13;
    // The device was removed from the machine, or its binding dismantled.
    REMOVED = 14;
    // A power-state transition asked for it.
    POWER = 15;
};

// DriverLifecycle — declare that the device named by `device` moved from `from`
// to `to`, for `reason`.
//
// `device` must carry `Rights::MAP` — the same authority `MapDevice` and
// `IrqComplete` require, and for the same reason: it is what distinguishes the
// process responsible for a device from any process that has heard of it. A
// caller cannot narrate a lifecycle for a device it does not hold.
//
// **`from` is checked, not trusted.** The kernel does not model the lifecycle
// — the manager does — but it does remember the last state recorded for each
// device, and a transition whose `from` disagrees is refused. That is the
// difference between a record stream and a *sequence*: without it a manager
// could emit Active -> Degraded twice, or skip a state, and the records would
// still read as a plausible history. The kernel is not judging the policy, only
// that the story is consistent with the one it has already been told.
//
// `detail` is reason-specific and uninterpreted by the kernel: the exit code of
// a probe, the fault address of a crash, the launch index of a restart.
@abi
struct LifecycleTransitionArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    from: DriverState;
    to: DriverState;
    reason: TransitionReason;
    detail: uint64;
};

// What a service depending on a device is told when that device's driver
// fails — ladder step 4, *"dependent services are notified"*.
//
// This travels as an ordinary channel message to an endpoint the dependent
// registered, and it carries a body because — unlike a reclaimed capability,
// which *is* its own message — there is nothing else here to key on. A
// dependent may depend on several devices, and "one of yours is in trouble" is
// not actionable without saying which.
//
// The kernel fills every field. A notice is the kernel reporting a fact it
// established (a host faulted, a lease ended), so nothing here is a claim
// forwarded from a process that might be lying about it.
@abi
struct ServiceNotice {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The device object whose driver is in trouble.
    device: uint32;
    // The state it is in now.
    state: DriverState;
    reason: TransitionReason;
    reserved: uint32;
};
