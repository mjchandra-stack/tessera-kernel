// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **audio output class contract**.
//
// The sixth class here, and the first whose device is not finished when it
// answers. Block moves a sector and is done; network sends a frame and is done;
// input is asked and answers. A playback stream is a standing obligation with a
// deadline: samples must keep arriving or the device plays silence, and nothing
// anywhere fails while that happens.
//
// That is why `UNDERRUN` is a value in the error set rather than a fault. A
// stream that ran dry is still running — the device did not fail, the driver
// did not fail, and a client told `OK` would have no way to know a gap was
// heard. It is the same shape as the block class's `NO_MEDIUM` and the input
// class's `NO_REPORT`: the answer a class contract exists to be able to give.
// It is the only one of the three that the **driver** observes rather than the
// device, because no register anywhere records it.
//
// **What is deliberately not here.** No mixing, no rate conversion, no routing
// between endpoints. Those belong to a service above this contract, which can
// hold policy about who is allowed to be loud; a class contract that carried
// them would be describing an audio system rather than a device.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it.

library tessera.driver.audio;

// --- 7. Error codes ---------------------------------------------------------

// What an audio driver is allowed to fail with. A closed set, numbered to the
// framework's discipline from 5 upward. Values are ABI: append only.
strict enum AudioError : uint32 {
    OK = 0;
    // **The stream ran dry, and it is still running.** Not a failure: the
    // device asked for the next period and there was none, so a gap was heard.
    // A client that was told `OK` would have no way to know — and one told a
    // hard error would tear down a stream that is playing perfectly well now.
    UNDERRUN = 1;
    // The format, rate or channel count is not one this device does. Refused
    // rather than converted: a client that asked for 48 kHz and silently got
    // 44.1 would hear its audio at the wrong speed and have nothing to check.
    BAD_FORMAT = 2;
    // No stream with that number, or one that has not been configured.
    NO_STREAM = 3;
    // The device is already holding every period it can. **Not an error to
    // recover from** — it is the stream working, and it is how a client learns
    // to wait rather than to buffer without bound.
    BUSY = 4;
    NOT_SUPPORTED = 5;
    PROTOCOL = 6;
    DEGRADED = 7;
    // The device is gone. A stream in flight when it left is completed with
    // this rather than left waiting for periods nothing will consume.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

bits AudioFeature : uint64 {
    // The driver implements `Stop`: a stream can be paused and resumed without
    // being torn down and reconfigured.
    PAUSE = 0x1;
    // The driver implements `SetVolume`.
    VOLUME = 0x2;
    // The device captures as well as plays. Clear here, and recorded rather
    // than written: against a null backend a capture stream returns silence
    // whether or not the driver is correct, which is a test that cannot fail
    // (build/README.md, D158).
    CAPTURE = 0x4;
};

// --- 6. Power states --------------------------------------------------------

// The same four names as the block, network, clock, input and GPIO classes. A
// power manager arbitrates across every device on the machine and cannot do
// that against a per-class vocabulary.
strict enum AudioPowerState : uint32 {
    ACTIVE = 1;
    IDLE = 2;
    STANDBY = 3;
    OFF = 4;
};

// --- 9. Trace events --------------------------------------------------------

strict enum AudioTracePoint : uint32 {
    STREAM_CONFIGURED = 1;
    STREAM_STARTED = 2;
    PERIOD_SUBMITTED = 3;
    // The moment the device asked for a period and there was none. Its own
    // trace point because it is the only event here that is invisible to
    // everything except the driver that saw it.
    UNDERRUN_OBSERVED = 4;
    POWER_CHANGED = 5;
};

// Sample formats, as a client names them. Small on purpose: a class contract
// listing every format a codec ever had would be a table nobody reads, and the
// device says which ones it does.
strict enum AudioFormat : uint32 {
    // Signed 16-bit, little-endian — what every backend accepts.
    S16 = 0;
};

// --- 4. Buffer ownership ----------------------------------------------------

// A period handed over **belongs to the driver until it comes back**, and that
// is the rule that makes a ring of them safe: a client that wrote into a period
// it had already submitted would be changing audio the device was reading, and
// the result is a sound nobody can reproduce from a log.
//
// Periods cross **inline**, which bounds one at sixty-four bytes. A real period
// is larger, so a driver assembles several writes into one — and `accepted`
// says how much it took, because a client that assumed the whole write landed
// would drift a little further ahead of the device on every call. Granting the
// client's own memory instead is the out-of-line mechanism the block class has;
// it would suit this better and it is its own change (build/README.md, D158).

// --- 1, 2, 3. The methods and their payloads --------------------------------

@abi
struct AudioControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The stream this is about; ignored by `Describe` and `SetPower`.
    stream: uint32;
    state: AudioPowerState;
};

@abi
struct AudioControlReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: AudioError;
    state: AudioPowerState;
};

// What this device is. A client calls it first, and everything else is
// conditional on the answer.
@abi
struct AudioDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    contract_version: uint32;
    status: AudioError;
    features: uint64;
    // How many playback streams it has.
    streams: uint32;
    // **What a client must know before it can keep up.** The period is the unit
    // the device consumes, and `periods` is how many it will hold at once — so
    // a client knows both how much to prepare and how far ahead to stay. A
    // client that guessed would either starve the device or sit further ahead
    // of it than anybody asked for, and latency nobody chose is the failure
    // mode this field exists to prevent.
    period_bytes: uint32;
    periods: uint32;
    channels_max: uint32;
    power_states: uint32;
    resume_latency_us: uint32;
    vendor: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved: uint32;
};

// Claims a stream and says what it will carry.
//
// Claiming and configuring are one method for the reason the GPIO class makes
// them one: a stream configured before it is claimed is a stream whose format
// changed under its owner, and the window between two calls is where two
// clients racing for it would both succeed.
@abi
struct AudioConfigRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    stream: uint32;
    channels: uint32;
    format: AudioFormat;
    // Frames per second. A number rather than an enum because a device's list
    // is its own, and `Describe` is not the place to enumerate every rate a
    // codec might have.
    rate: uint32;
};

// One period of samples, or as much of one as fits.
@abi
struct AudioWriteRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    stream: uint32;
    // How much of `samples` is real. A client sending less than the array holds
    // is ordinary — the tail of a sound is not a whole period.
    length: uint32;
    samples: array<uint8, 64>;
};

@abi
struct AudioWriteReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: AudioError;
    // How much the driver took. **Authoritative**: a client that assumed the
    // whole write landed would drift a little further ahead of the device every
    // call, and would discover it as audio that arrives late and never as an
    // error.
    accepted: uint32;
    // Periods the device is holding now, so a client can tell "keep going" from
    // "wait" without asking a second time.
    outstanding: uint32;
    reserved: uint32;
};

// What a stream has done. The only place an underrun is reported, because it is
// the only thing that counted them.
@abi
struct AudioStatusReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: AudioError;
    stream: uint32;
    // Periods the device has consumed and given back.
    played: uint32;
    // **Times it asked for one and there was none.** Zero is a claim rather
    // than an absence: a client is told the count either way, so "it played
    // cleanly" and "nobody was counting" are different answers.
    underruns: uint32;
    outstanding: uint32;
    reserved: uint32;
};

@abi
struct AudioVolumeRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    stream: uint32;
    // Hundredths of a decibel below full scale, so zero is full and the field
    // has no sign to get wrong.
    attenuation_centibels: uint32;
};

@abi
struct AudioEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    trace_point: AudioTracePoint;
    status: AudioError;
    stream: uint32;
    reserved: uint32;
};

// --- 8. Reset behaviour -----------------------------------------------------

// `Reset` is defined to leave the driver in `ACTIVE` with every stream stopped,
// released and unconfigured, and every period the device was holding returned.
// It does **not** preserve the underrun counts: they belong to the streams that
// were reset, and carrying them forward would report a gap in one sound as
// having happened during another.

protocol AudioOutput {
    // Required.
    1: Describe(AudioControlRequest) -> (AudioDescribeReply);
    // Required. Claim a stream and say what it will carry.
    2: Configure(AudioConfigRequest) -> (AudioControlReply);
    // Required. Begin consuming what has been written.
    3: Start(AudioControlRequest) -> (AudioControlReply);
    // Required. Hand over samples.
    4: Write(AudioWriteRequest) -> (AudioWriteReply);
    // Required. See the reset behaviour above.
    5: Reset(AudioControlRequest) -> (AudioControlReply);
    // Required.
    6: SetPower(AudioControlRequest) -> (AudioControlReply);
    // Optional, gated by `AudioFeature.PAUSE`.
    7: Stop(AudioControlRequest) -> (AudioControlReply);
    // Required. What the stream has played, and what it missed.
    8: Status(AudioControlRequest) -> (AudioStatusReply);
    // Optional, gated by `AudioFeature.VOLUME`.
    9: SetVolume(AudioVolumeRequest) -> (AudioControlReply);

    // 10..=19 are reserved, so the event range stays at a fixed boundary.

    // 3. Events.
    20: -> OnUnderrun(AudioEvent);
    21: -> OnError(AudioEvent);
    22: -> OnDeviceGone(AudioEvent);
};
