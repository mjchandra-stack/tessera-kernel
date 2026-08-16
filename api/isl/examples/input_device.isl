// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **input device class contract**.
//
// The fourth class here, and the first whose data comes from a person. Block
// moves sectors, network moves frames, clock moves nothing — and all three are
// asked for what they carry. An input device is asked for what has *happened*,
// which is a different shape: most of the time nothing has, and "nothing yet"
// has to be an answer rather than an error or a wait.
//
// It is the same ten elements `docs/drivers/01` lists, judged by the same
// suite in `//api/class-conformance`, with the same error numbering from 5
// upward. Adding it is the cheapest test there is of whether the framework was
// built or merely described: nothing in the conformance rules knows what a
// keyboard is.
//
// **Deliberately small.** Report descriptors, usage pages, keycode translation
// and LED state are a driver's business, and a class contract that named them
// would be a description of HID rather than of input — the same reason the
// block contract has no queue geometry in it. What crosses here is a report:
// bytes the device produced, with a length and an identifier, and no claim
// about what they mean.
//
// This is a user<->user contract: the kernel transports it opaquely and never
// decodes it.

library tessera.driver.input;

// --- 7. Error codes ---------------------------------------------------------

// What an input driver is allowed to fail with. A closed set, numbered to the
// framework's discipline from 5 upward. Values are ABI: append only.
strict enum InputError : uint32 {
    OK = 0;
    // **Nothing has happened, and that is not a failure.** The distinguishing
    // value of this class: a keyboard nobody is typing on is a working
    // keyboard, and a client that could not tell it from a broken one would
    // report a fault every time the room went quiet.
    NO_REPORT = 1;
    // The transfer to the device did not complete.
    IO_ERROR = 2;
    // The report identifier named is not one this device produces.
    BAD_REPORT_ID = 3;
    // The device is mid-report and cannot start another.
    BUSY = 4;
    NOT_SUPPORTED = 5;
    PROTOCOL = 6;
    DEGRADED = 7;
    // The device has left. Distinct from `DEGRADED` for the reason it is
    // everywhere else: degraded invites a retry and removed forbids one.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

bits InputFeature : uint64 {
    // The driver implements `SetReport` — sending state *to* the device, which
    // is how a keyboard's lock lamps are lit.
    SET_REPORT = 0x1;
    // The driver implements `GetReport`: asking the device for the state it is
    // holding *now*, rather than waiting for it to say something has changed.
    //
    // A different question from `Poll`, and not a convenience version of it.
    // Poll asks what happened; this asks what is true. A client that has just
    // started and wants to know whether a key is already held has no event to
    // wait for, and no amount of polling will produce one.
    GET_REPORT = 0x2;
    // The device produces more than one report and identifies them. A device
    // with a single report leaves this clear and its reports carry id zero,
    // which is a real identifier and not an absent one.
    REPORT_IDS = 0x4;
    // Reports are pushed as `OnReport` events as well as being poll-able. A
    // driver whose transport cannot interrupt leaves this clear and is polled.
    PUSHED = 0x8;
};

// --- 6. Power states --------------------------------------------------------

// The same four names as the block, network and clock classes. A power manager
// arbitrates across every device on the machine and cannot do that against a
// per-class vocabulary.
strict enum InputPowerState : uint32 {
    ACTIVE = 1;
    IDLE = 2;
    STANDBY = 3;
    OFF = 4;
};

// --- 9. Trace events --------------------------------------------------------

strict enum InputTracePoint : uint32 {
    REPORT_RECEIVED = 1;
    REPORT_SENT = 2;
    DEVICE_RESET = 3;
    POWER_CHANGED = 4;
};

// --- 4. Buffer ownership ----------------------------------------------------

// A report is carried **inline**, and this class has no out-of-line form.
//
// Not an omission. A report is tens of bytes produced at human speed; a
// mechanism for granting a buffer would cost more than the data it moved, and
// a contract that offered one would be inviting an implementation nobody
// should write.

// --- 1, 2, 3. The methods and their payloads --------------------------------

@abi
struct InputControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The power state a `SetPower` is asking for; ignored by every other
    // method, as on the other classes.
    state: InputPowerState;
    reserved: uint32;
};

@abi
struct InputControlReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: InputError;
    state: InputPowerState;
};

// What this device is. A client calls it first, and everything else is
// conditional on the answer.
@abi
struct InputDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    contract_version: uint32;
    status: InputError;
    features: uint64;
    // What kind of thing this is, in the device's own vocabulary rather than a
    // translated one: the HID subclass and protocol bytes. A client that wants
    // "is this a keyboard" reads them; a client that does not, ignores them.
    // Translating here would mean inventing a taxonomy that every non-HID input
    // transport would then have to be forced into.
    subclass: uint32;
    protocol: uint32;
    // The largest report this device produces, so a client knows what it must
    // be able to hold before it asks for one.
    max_report_len: uint32;
    power_states: uint32;
    resume_latency_us: uint32;
    vendor: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved: uint32;
};

// One report, in either direction.
@abi
struct InputReportRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Zero on a device that does not identify its reports, which is a real
    // identifier rather than an absent one.
    report_id: uint32;
    length: uint32;
    report: array<uint8, 64>;
};

@abi
struct InputReportReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: InputError;
    report_id: uint32;
    // How much of `report` the device actually produced. A client that ignored
    // it would read whatever the previous report left in the tail.
    length: uint32;
    reserved: uint32;
    report: array<uint8, 64>;
};

@abi
struct InputEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    trace_point: InputTracePoint;
    status: InputError;
    report_id: uint32;
    length: uint32;
    report: array<uint8, 64>;
};

// --- 8. Reset behaviour -----------------------------------------------------

// `Reset` is defined to leave the device in `ACTIVE` with no report pending and
// every optional feature in the state `Describe` reported. It does **not**
// clear what the device itself holds — a key that is physically down is still
// down afterwards, and a contract that claimed otherwise would be claiming
// authority over the world.

protocol InputDevice {
    // Required.
    1: Describe(InputControlRequest) -> (InputDescribeReply);
    // Required. The next report, or `NO_REPORT` if none is waiting.
    //
    // **Non-blocking by definition.** A blocking poll would be a method whose
    // latency is a person's typing speed, holding a channel's single
    // outstanding call for as long as nobody touches the device — and every
    // other client of that driver would wait behind it.
    2: Poll(InputControlRequest) -> (InputReportReply);
    // Optional, gated by `InputFeature.SET_REPORT`.
    3: SetReport(InputReportRequest) -> (InputControlReply);
    // Optional, gated by `InputFeature.GET_REPORT`. The state the device holds
    // now, which is not the same question as `Poll`.
    4: GetReport(InputReportRequest) -> (InputReportReply);
    // Required. See the reset behaviour above.
    5: Reset(InputControlRequest) -> (InputControlReply);
    // Required. Move to a power state `Describe` reported; one it did not
    // report is `NOT_SUPPORTED`, not a best effort.
    6: SetPower(InputControlRequest) -> (InputControlReply);

    // 7..=19 are reserved, so the event range stays at a fixed boundary.

    // 3. Events, gated by `InputFeature.PUSHED`.
    20: -> OnReport(InputEvent);
    21: -> OnError(InputEvent);
    // The device is gone. Addressed to everyone holding the contract rather
    // than to whoever happened to have a call outstanding.
    22: -> OnDeviceGone(InputEvent);
};
