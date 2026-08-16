// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **GPIO controller class contract**.
//
// The fifth class here, and the first whose interrupts are not the hardware's.
// A GPIO controller multiplexes its lines onto one interrupt output — a PL061
// has eight lines and one — so a *line's* interrupt does not exist as far as
// the interrupt controller is concerned. It is something the driver works out
// by reading a status register and deciding which of its clients this edge
// belonged to.
//
// `docs/drivers/04` says those lines are "delivered as interrupt objects", and
// that is what `WatchLine` does: its reply carries **a capability**, not a
// promise to call back. This is the first class contract here whose reply hands
// one over, and it is why there is no polling method and no line-changed event.
// A client that holds line 3's interrupt object can wait on it and on nothing
// else, and a client that does not hold it cannot be woken by line 3 at all.
//
// **What is deliberately not here.** No register offsets, no interrupt number,
// no pin-mux table. The mux belongs to `api/pinctrl`, which is data about a
// board rather than a conversation with a controller, and a class contract that
// carried it would be describing one design rather than a class.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it.

library tessera.driver.gpio;

// --- 7. Error codes ---------------------------------------------------------

// What a GPIO driver is allowed to fail with. A closed set, numbered to the
// framework's discipline from 5 upward, so the values the framework reads mean
// the same thing wherever they appear. Values are ABI: append only.
strict enum GpioError : uint32 {
    OK = 0;
    // The line number is not one this controller has.
    NO_SUCH_LINE = 1;
    // The configuration asks for something this line cannot do — a trigger on
    // a controller with no interrupt, a drive strength past what the pin
    // supports. **Refused rather than clamped**, for the reason a clock rate
    // outside its range is: a caller handed the nearest thing the hardware
    // could manage cannot tell it from what it asked for.
    BAD_CONFIG = 2;
    // The line is held by another client.
    //
    // A line is not shareable the way a clock is. Two holders of a clock both
    // want it running and the counting works out; two holders of a line want it
    // at different levels, and there is no arithmetic that resolves that — so
    // the second one is refused rather than counted.
    LINE_BUSY = 3;
    // The line is pointed the other way: a write to an input, a watch on an
    // output. Its own value because it is the one failure a caller can fix
    // without knowing anything else about the board.
    WRONG_DIRECTION = 4;
    NOT_SUPPORTED = 5;
    PROTOCOL = 6;
    DEGRADED = 7;
    // The controller is gone. A watch outstanding when it left is completed
    // with this rather than left waiting for an edge that will never come.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

bits GpioFeature : uint64 {
    // Lines can be driven, so `Write` works. A controller with input-only
    // lines is a real part and leaves this clear.
    OUTPUT = 0x1;
    // Lines can interrupt, so `WatchLine` works and hands back an interrupt
    // object. A controller whose lines are read-only-by-polling leaves this
    // clear, and a client then knows there is nothing to wait on rather than
    // discovering it by waiting.
    INTERRUPTS = 0x2;
    // Bias and drive strength are configurable, so `SetElectrical` works.
    //
    // Clear on a PL061, which has neither — and that is the contract working
    // rather than a gap. A class contract shaped around the one controller in
    // front of it would have no way to say "this part cannot".
    ELECTRICAL = 0x4;
};

// --- 6. Power states --------------------------------------------------------

// The same four names as the block, network, clock and input classes. A power
// manager arbitrates across every device on the machine and cannot do that
// against a per-class vocabulary.
strict enum GpioPowerState : uint32 {
    ACTIVE = 1;
    IDLE = 2;
    STANDBY = 3;
    OFF = 4;
};

// --- 9. Trace events --------------------------------------------------------

strict enum GpioTracePoint : uint32 {
    LINE_CONFIGURED = 1;
    LINE_READ = 2;
    LINE_WRITTEN = 3;
    // The driver demultiplexed an edge and signalled a line's interrupt
    // object. Worth a trace point of its own: it is the moment one hardware
    // interrupt becomes one client's, and it is the only place that mapping
    // is visible.
    INTERRUPT_DELIVERED = 4;
    POWER_CHANGED = 5;
};

// --- Line configuration -----------------------------------------------------

strict enum GpioDirection : uint32 {
    INPUT = 0;
    OUTPUT = 1;
};

// How a line interrupts.
//
// **One value across what is three registers on the hardware.** On a PL061 the
// sense, both-edges and event bits are not independent — both-edges means
// nothing on a level-sensed line — so a contract that let a client set them
// separately would let it ask for a combination that has no meaning and get one
// that does.
strict enum GpioTrigger : uint32 {
    // Not an interrupt source. The value a line configured for reading takes,
    // and a real answer rather than an absent field.
    NONE = 0;
    RISING_EDGE = 1;
    FALLING_EDGE = 2;
    BOTH_EDGES = 3;
    HIGH_LEVEL = 4;
    LOW_LEVEL = 5;
};

strict enum GpioBias : uint32 {
    FLOAT = 0;
    PULL_UP = 1;
    PULL_DOWN = 2;
};

// --- 4. Buffer ownership ----------------------------------------------------

// Every method here carries its payload **inline**, and there is no
// out-of-line form. A line's state is a bit; a mechanism for granting a buffer
// would cost more than everything it could ever move.
//
// One thing does cross by reference, and it is not a buffer: `WatchLine`'s
// reply carries the line's interrupt object in the message's **handle vector**
// (`docs/api/03`, "Wire Format"). Capabilities never travel in the payload
// bytes — a body can be forged by any sender and a transferred capability
// cannot.

// --- 1, 2, 3. The methods and their payloads --------------------------------

@abi
struct GpioControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The power state a `SetPower` is asking for; ignored by every other
    // method, as on the other classes.
    state: GpioPowerState;
    reserved: uint32;
};

@abi
struct GpioControlReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: GpioError;
    state: GpioPowerState;
};

// What this controller is. A client calls it first, and everything else is
// conditional on the answer.
@abi
struct GpioDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    contract_version: uint32;
    status: GpioError;
    features: uint64;
    // How many lines it has. The bound on every line number below, reported
    // rather than assumed, because a client that guessed would be a client
    // that works on one part.
    line_count: uint32;
    // What the controller said it is, out of whatever identification its bus
    // offers — a PrimeCell part number, a PCI device id. Reported rather than
    // interpreted: a client that recognises the number can act on it, and one
    // that does not is not obliged to.
    vendor: uint32;
    part: uint32;
    power_states: uint32;
    resume_latency_us: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved: uint32;
};

// Names one line and nothing else.
@abi
struct GpioLineRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    line: uint32;
    reserved: uint32;
};

// Claims a line and says which way it faces and how it interrupts.
//
// Claiming and configuring are one method rather than two, because a line
// configured before it is claimed is a line whose direction changed under its
// owner — and the window between the two calls is exactly where two clients
// racing for a line would both succeed.
@abi
struct GpioConfigRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    line: uint32;
    direction: GpioDirection;
    trigger: GpioTrigger;
    reserved: uint32;
};

@abi
struct GpioLevelRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    line: uint32;
    // Non-zero drives the line high. A `uint32` rather than a bool because the
    // wire has no bool and a byte with 254 other values would need a rule
    // about them.
    level: uint32;
};

@abi
struct GpioLevelReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: GpioError;
    line: uint32;
    level: uint32;
    reserved: uint32;
};

// Bias and drive strength, for a controller that has them.
@abi
struct GpioElectricalRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    line: uint32;
    bias: GpioBias;
    // Milliamps. Zero means "leave it alone", which is what a line used as an
    // input wants and is distinguishable from asking for zero — a request no
    // pin can honour and which is `BAD_CONFIG`.
    drive_ma: uint32;
    reserved: uint32;
};

@abi
struct GpioEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    trace_point: GpioTracePoint;
    status: GpioError;
    line: uint32;
    reserved: uint32;
};

// --- 8. Reset behaviour -----------------------------------------------------

// `Reset` is defined to leave the controller in `ACTIVE`, every line released,
// every interrupt masked and acknowledged, and every line's direction back to
// input. Input is the safe end: a line left as an output after a reset is a
// line still driving something, and the whole point of resetting a controller
// nobody trusts is to stop it driving.
//
// It does **not** revoke interrupt objects already handed out. A capability is
// conserved, so a client that holds one still holds it — what changes is that
// its line is no longer watched, and the object will not be signalled until
// somebody watches it again. Claiming otherwise would be claiming the contract
// can reach into a table it does not own.

protocol GpioController {
    // Required.
    1: Describe(GpioControlRequest) -> (GpioDescribeReply);
    // Required. Claim a line and configure it.
    2: ConfigureLine(GpioConfigRequest) -> (GpioControlReply);
    // Required. Read a line's level.
    3: Read(GpioLineRequest) -> (GpioLevelReply);
    // Optional, gated by `GpioFeature.OUTPUT`. Drive a line.
    4: Write(GpioLevelRequest) -> (GpioControlReply);
    // Required. See the reset behaviour above.
    5: Reset(GpioControlRequest) -> (GpioControlReply);
    // Required.
    6: SetPower(GpioControlRequest) -> (GpioControlReply);
    // Optional, gated by `GpioFeature.INTERRUPTS`.
    //
    // **The reply carries the line's interrupt object**, in the message's
    // handle vector. A client that holds it waits on that line and on nothing
    // else; a client that does not hold it cannot be woken by that line at all,
    // which is what makes the demultiplexing a grant rather than a routing
    // decision the driver could get wrong in a client's favour.
    7: WatchLine(GpioLineRequest) -> (GpioControlReply);
    // Required. Give a line back: it stops being watched, its interrupt is
    // masked, and it goes back to being an input.
    8: ReleaseLine(GpioLineRequest) -> (GpioControlReply);
    // Optional, gated by `GpioFeature.ELECTRICAL`.
    9: SetElectrical(GpioElectricalRequest) -> (GpioControlReply);

    // 10..=19 are reserved, so the event range stays at a fixed boundary.

    // 3. Events. There is deliberately **no line-changed event**: a line's
    // edge is delivered as the interrupt object `WatchLine` handed over, and
    // an event beside it would be a second, weaker path to the same news —
    // one every holder of this contract would receive rather than only the
    // client that was granted the line.
    20: -> OnError(GpioEvent);
    21: -> OnDeviceGone(GpioEvent);
};
