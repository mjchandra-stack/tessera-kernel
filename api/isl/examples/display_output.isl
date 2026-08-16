// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **display output class contract**.
//
// The seventh class here, and the first whose result is visible from outside
// the machine. Every other device is believed: a driver reports it read a
// sector and nothing else could have produced that value, so the report stands
// in for the device. A display's output is on the glass, and somebody outside
// can go and look — which is why a driver that set everything up correctly and
// drew nothing reports exactly what a working one does.
//
// That shapes the contract in one specific way. **Nothing is visible until a
// flush**, and the contract says so rather than leaving it as a property of the
// hardware underneath. `Blit` puts pixels in a framebuffer and changes nothing
// anybody can see; `Flush` is what makes them a picture. A contract that folded
// the two together would be describing a device that has no separation between
// writing and showing, and would leave a client unable to build a frame before
// showing any of it.
//
// **What is deliberately not here.** No windows, no compositing, no layers, no
// mode setting beyond reporting the mode there is. Those belong to a service
// above this contract that can hold policy about who is allowed to be on
// screen; a class contract that carried them would be describing a window
// system rather than a device.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it.

library tessera.driver.display;

// --- 7. Error codes ---------------------------------------------------------

// What a display driver is allowed to fail with. A closed set, numbered to the
// framework's discipline from 5 upward. Values are ABI: append only.
strict enum DisplayError : uint32 {
    OK = 0;
    // **Nothing is attached, and that is a state rather than a fault.** A
    // machine with no monitor is an ordinary machine; a client told a hard
    // error would report broken hardware for something nobody plugged in, and
    // one told `OK` would draw into nothing and never find out.
    NO_SCANOUT = 1;
    // The rectangle or the pixel run lies outside the framebuffer. **Refused
    // rather than clipped**: a client that asked to draw somewhere and had the
    // request quietly trimmed would see a picture it did not compose and have
    // nothing to check.
    OUT_OF_BOUNDS = 2;
    // The pixel format asked for is not the one this display uses.
    BAD_FORMAT = 3;
    // A flush is already in flight. The device working, and how a client
    // learns to wait rather than queue frames without bound.
    BUSY = 4;
    NOT_SUPPORTED = 5;
    PROTOCOL = 6;
    DEGRADED = 7;
    // The device is gone. A flush outstanding when it left completes with this
    // rather than waiting for a screen that is not there.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

bits DisplayFeature : uint64 {
    // The driver implements `Fill`: a solid rectangle without the client
    // sending its pixels.
    FILL = 0x1;
    // The driver implements `SetCursor` — a plane above the framebuffer that
    // moves without redrawing it. Clear here, and recorded rather than written
    // (build/README.md, D159).
    CURSOR = 0x2;
    // The device can report when the mode changed under it. Clear where
    // nothing can change the mode.
    HOTPLUG = 0x4;
};

// --- 6. Power states --------------------------------------------------------

// The same four names as the six classes before it. A power manager arbitrates
// across every device on the machine and cannot do that against a per-class
// vocabulary.
strict enum DisplayPowerState : uint32 {
    ACTIVE = 1;
    IDLE = 2;
    STANDBY = 3;
    OFF = 4;
};

// --- 9. Trace events --------------------------------------------------------

strict enum DisplayTracePoint : uint32 {
    BLIT_WRITTEN = 1;
    // The moment pixels became a picture. Its own trace point because it is the
    // only event here with an effect outside the machine.
    FLUSHED = 2;
    MODE_CHANGED = 3;
    POWER_CHANGED = 4;
};

// The pixel formats a client may name. One, because this is what the device in
// front of it uses and a contract listing every format a framebuffer ever had
// would be a table nobody reads.
strict enum DisplayFormat : uint32 {
    // Eight bits each of blue, green, red and alpha in memory order — what a
    // little-endian host writes as 0xAARRGGBB.
    B8G8R8A8 = 0;
};

// --- 4. Buffer ownership ----------------------------------------------------

// **The framebuffer belongs to the driver.** A client does not hold it and
// cannot write into it directly; it sends pixels with `Blit` and the driver
// places them. That is what makes the bounds check meaningful — a client
// writing into memory it held could put pixels anywhere and the contract would
// have nothing to say about it.
//
// Pixels cross **inline**, sixty-four bytes at a time, which is sixteen of
// them. A frame is therefore many calls, and `written` says how many pixels
// each one placed. Granting the client's own memory instead is the out-of-line
// mechanism the block class has; it would suit this better and it is the same
// change D158 already records.

// --- 1, 2, 3. The methods and their payloads --------------------------------

@abi
struct DisplayControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    state: DisplayPowerState;
    reserved: uint32;
};

@abi
struct DisplayControlReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: DisplayError;
    state: DisplayPowerState;
};

// What this display is. A client calls it first, and everything else is
// conditional on the answer.
@abi
struct DisplayDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    contract_version: uint32;
    status: DisplayError;
    features: uint64;
    // **The mode there is**, rather than one a client may ask for. A client
    // that guessed would draw off the edge of a display it never asked about
    // and see nothing — the same reason the block class reports a sector size
    // and the audio class a period.
    width: uint32;
    height: uint32;
    format: DisplayFormat;
    // Bytes one pixel occupies, so a client can work out where it is writing
    // without knowing what the format enum means.
    bytes_per_pixel: uint32;
    power_states: uint32;
    resume_latency_us: uint32;
    vendor: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved: uint32;
};

// Pixels, and where they go.
@abi
struct DisplayBlitRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    x: uint32;
    y: uint32;
    // How many pixels of `pixels` are real. A client sending fewer than the
    // array holds is ordinary — the end of a row is not a whole payload.
    count: uint32;
    reserved: uint32;
    pixels: array<uint8, 64>;
};

@abi
struct DisplayBlitReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: DisplayError;
    // Pixels actually placed. Authoritative: a client that assumed the whole
    // run landed would draw the rest of its row one place to the left and see
    // a picture that is almost right, which is worse to debug than one that is
    // obviously wrong.
    written: uint32;
};

// A rectangle: what to show, or what to fill.
@abi
struct DisplayRectRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    x: uint32;
    y: uint32;
    width: uint32;
    height: uint32;
};

@abi
struct DisplayFillRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    x: uint32;
    y: uint32;
    width: uint32;
    height: uint32;
    // The colour, in the format `Describe` reported.
    colour: uint32;
    reserved: uint32;
};

@abi
struct DisplayEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    trace_point: DisplayTracePoint;
    status: DisplayError;
    reserved: uint32;
};

// --- 8. Reset behaviour -----------------------------------------------------

// `Reset` is defined to leave the driver in `ACTIVE` with the framebuffer
// cleared and the cleared framebuffer **shown** — not merely written. A reset
// that left the last picture on the glass would be a reset the only observer
// who matters cannot see.

protocol DisplayOutput {
    // Required.
    1: Describe(DisplayControlRequest) -> (DisplayDescribeReply);
    // Required. Put pixels in the framebuffer. Nothing is visible yet.
    2: Blit(DisplayBlitRequest) -> (DisplayBlitReply);
    // Required. Put a rectangle of the framebuffer on the glass.
    3: Flush(DisplayRectRequest) -> (DisplayControlReply);
    // Optional, gated by `DisplayFeature.FILL`.
    4: Fill(DisplayFillRequest) -> (DisplayControlReply);
    // Required. See the reset behaviour above.
    5: Reset(DisplayControlRequest) -> (DisplayControlReply);
    // Required.
    6: SetPower(DisplayControlRequest) -> (DisplayControlReply);
    // Optional, gated by `DisplayFeature.CURSOR`.
    7: SetCursor(DisplayRectRequest) -> (DisplayControlReply);

    // 8..=19 are reserved, so the event range stays at a fixed boundary.

    // 3. Events.
    20: -> OnModeChanged(DisplayEvent);
    21: -> OnError(DisplayEvent);
    22: -> OnDeviceGone(DisplayEvent);
};
