// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **clock controller class contract** — the third class, and the first that
// moves no data at all.
//
// Written against the same ten elements as `block_driver.isl` and
// `network_driver.isl`, in the same order, because the argument for a class
// contract being a *framework* shape rather than a storage shape is only worth
// as much as the third class costs. What is worth noticing:
//
// - **Buffer ownership is stated and empty.** Nothing this class moves is a
//   buffer: every method carries a clock id and a number. The element is filled
//   in rather than dropped, because "this class transfers nothing" is an answer
//   a client can rely on, and a contract that simply omitted the question would
//   leave every reader to assume it.
// - **Reference counting is a rule of the contract, not of an implementation.**
//   A clock is on while any consumer wants it and off when the last one lets go.
//   Stated here because two consumers of one clock is the normal case — a card
//   and a controller share a bus clock — and a contract that left it to the
//   driver would have each consumer's `Disable` racing the other's `Enable`.
// - **A rate outside the declared range is refused, never clamped.** A consumer
//   handed a rate it did not ask for is one whose device runs at a speed nobody
//   chose, and it has no way to find out. `docs/drivers/04` says consumers
//   request rates through bounded APIs; this is what bounded means.
// - **Some clocks cannot be turned off, and say so.** A clock the system needs
//   for correctness answers `CRITICAL` to a disable rather than obeying — which
//   is the one refusal in this contract that protects the machine from its own
//   drivers.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it.
//
// Normative: docs/drivers/04-embedded-buses-power-and-timekeeping.md
// ("Clock Controller"), docs/drivers/01-driver-framework.md

library tessera.driver.clock;

// --- 7. Error codes ---------------------------------------------------------

// A closed set, numbered to the same discipline the other two classes use:
// `NOT_SUPPORTED` at 5, `PROTOCOL` at 6, `DEGRADED` at 7 and `REMOVED` at 8, so
// the framework rules that read those values read them the same way on every
// class. What differs is what fills 1 through 4, which is what a class is.
strict enum ClockError : uint32 {
    OK = 0;
    // The requested rate is outside the range this clock declared. Refused, not
    // clamped: a consumer running at a speed it did not choose cannot tell.
    BAD_RATE = 1;
    // No clock by that id on this controller.
    NO_SUCH_CLOCK = 2;
    // The clock is critical for correctness and will not be disabled. The one
    // refusal here that protects the machine from its own drivers.
    CRITICAL = 3;
    // The clock is in use by another consumer at a rate incompatible with this
    // request. A real outcome and not a failure: reference counting means a
    // second consumer may arrive with a requirement the first cannot meet.
    BUSY = 4;
    // The method exists in this contract and this driver does not implement it.
    NOT_SUPPORTED = 5;
    // Malformed, or not admissible in the current state.
    PROTOCOL = 6;
    // The driver has marked itself degraded and will not act.
    DEGRADED = 7;
    // The controller is no longer in the machine.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

bits ClockFeature : uint64 {
    // The driver implements `SetRate`. A fixed clock does not.
    SET_RATE = 0x1;
    // The driver implements `Disable`. A controller whose every clock is
    // critical does not, and saying so beats answering CRITICAL to each in turn.
    DISABLE = 0x2;
    // The driver implements `SetParent` — the clock is a mux.
    MUX = 0x4;
};

// --- 6. Power states --------------------------------------------------------

// The same four names as the other two classes, which is the point: a power
// manager arbitrates across every device on the machine and cannot do that
// against a per-class vocabulary.
strict enum ClockPowerState : uint32 {
    ACTIVE = 1;
    // The controller answers queries and changes nothing.
    IDLE = 2;
    // Gated. Every clock it owns is off, and the consumers that wanted them on
    // are still counted — so coming back restores what was asked for rather
    // than what happened to be running.
    STANDBY = 3;
    OFF = 4;
};

// --- 4. Buffer ownership ----------------------------------------------------

// **Stated, and empty.** Every method on this class carries a clock id and a
// number; nothing is a buffer and nothing changes hands. Filled in rather than
// omitted because "this class transfers nothing" is an answer a client can rely
// on, and a contract that left the question out would make every reader assume
// it.
strict enum ClockBufferOwnership : uint32 {
    NONE = 0;
};

// --- 9. Trace events --------------------------------------------------------

strict enum ClockTracePoint : uint32 {
    ENABLED = 1;
    DISABLED = 2;
    RATE_CHANGED = 3;
    RATE_REFUSED = 4;
    PARENT_CHANGED = 5;
    CONTROLLER_RESET = 6;
    POWER_CHANGED = 7;
};

// --- 15. Versioned vendor extension namespaces ------------------------------

@abi
struct ClockVendorNamespace {
    size: uint32;
    version: uint32;
    flags: uint64;
    vendor: uint32;
    namespace: uint32;
    extension_version: uint32;
    reserved: uint32;
};

// --- 1. Required methods, and what `Describe` answers ------------------------

@abi
struct ClockDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    contract_version: uint32;
    status: ClockError;
    features: uint64;
    // How many clocks this controller owns. A consumer walks 0..count asking
    // `GetRate`, which is the enumeration `docs/drivers/04` asks for — the ids
    // are dense and the count comes from here rather than from a separate call
    // that could disagree with it.
    clock_count: uint32;
    reserved: uint32;
    // 6. Supported power states as a bitmask of `1 << ClockPowerState`, and the
    // worst-case resume latency from the deepest.
    power_states: uint32;
    reserved2: uint32;
    resume_latency_us: uint64;
    // 15.
    vendor: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved3: uint32;
};

// Which clock, for the methods that name one and carry nothing else.
@abi
struct ClockRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    clock: uint32;
    // Meaningful only for `SetParent`: which of the mux's inputs to select.
    parent: uint32;
};

// What a clock is and what it may be asked for. Answered by `GetRate` and
// carried by `SetRate`'s reply, because a consumer that asked for a rate needs
// to know what it got — a controller may only be able to produce a divisor of
// its parent, and the *actual* rate is what its device will run at.
@abi
struct ClockRateReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    // Whether this clock is critical for correctness — one a disable is refused
    // on. Reported so a consumer can know before it asks rather than by being
    // told no.
    critical: uint32;
    // The rate now in effect.
    rate_hz: uint64;
    // The range this clock declares. A request outside it is `BAD_RATE`.
    min_hz: uint64;
    max_hz: uint64;
    // How many consumers currently hold this clock on. Reported because
    // reference counting is a rule of the contract: a consumer that sees two
    // knows its `Disable` will not stop the clock, which is a different fact
    // from its request having failed.
    holders: uint32;
    reserved: uint32;
};

@abi
struct ClockRateRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    clock: uint32;
    reserved: uint32;
    rate_hz: uint64;
};

@abi
struct ClockControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    state: ClockPowerState;
    reserved: uint32;
};

@abi
struct ClockReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    state: ClockPowerState;
};

// A rate this controller changed, announced to whoever asked for events. A
// consumer's clock may move because *another* consumer asked for a rate it
// could also meet, and a device that cannot be told would be running at a speed
// its driver believes it chose.
@abi
struct ClockRateEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    clock: uint32;
    reserved: uint32;
    rate_hz: uint64;
};

// --- The protocol -----------------------------------------------------------

// The clock controller class.
//
// **Reset behaviour (element 8).** `Reset` is defined to leave the controller:
// in `ACTIVE` power state; with every clock at its declared default rate; with
// every reference count **zero**, so a consumer that held a clock on before a
// reset does not still hold it after — the count describes live requests and a
// reset ends them; and with features re-reported, so `Describe` after a reset
// may report fewer.
protocol ClockController {
    // Required.
    1: Describe(ClockControlRequest) -> (ClockDescribeReply);
    // Required. Reference-counted: the clock runs while any consumer holds it.
    2: Enable(ClockRequest) -> (ClockReply);
    // Optional, gated by `ClockFeature.DISABLE`. Drops this consumer's hold;
    // the clock stops only when the last one goes. A critical clock answers
    // `CRITICAL` and keeps running.
    3: Disable(ClockRequest) -> (ClockReply);
    // Optional, gated by `ClockFeature.SET_RATE`. A rate outside the declared
    // range is `BAD_RATE`, never the nearest thing the hardware could manage.
    4: SetRate(ClockRateRequest) -> (ClockRateReply);
    // Required. See the reset behaviour above.
    5: Reset(ClockControlRequest) -> (ClockReply);
    // Required. A state the driver did not report is `NOT_SUPPORTED`.
    6: SetPower(ClockControlRequest) -> (ClockReply);
    // Optional, gated by `ClockFeature.MUX`.
    7: SetParent(ClockRequest) -> (ClockReply);
    // Required. What a clock is, what it may be asked for, and who holds it.
    8: GetRate(ClockRequest) -> (ClockRateReply);

    9: reserved;

    // 3. Events.
    20: -> OnRateChanged(ClockRateEvent);
    21: -> OnError(ClockRateEvent);
};
