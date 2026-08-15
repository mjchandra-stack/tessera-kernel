// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The driver-binding protocol: how a driver acquires the device it drives.
//
// This is the first contract of the driver framework, and the smallest one
// that changes the shape of the system. Before it, a driver knew its device
// by a compiled-in handle number that boot happened to install — "handle 0 is
// the block device" — which is not binding, it is a shared constant. After
// it, a driver names a *class* and is granted a capability to some device of
// that class, chosen by a manager that enumerated the machine.
//
// What crosses the wire is deliberately almost nothing. The reply's real
// payload is the **transferred device capability**, which travels in the
// message's handle vector and never in these bytes (docs/api/03, "Wire
// Format"); the struct carries only what the driver needs to know *about*
// what it was given. There is no MMIO base or length here for the same
// reason: those live inside the capability, and the kernel reads them from it
// when the driver calls MapDevice. A driver that could name its own window
// would not need a capability.
//
// Exclusivity needs no field either. A handle transfer is a `take` from the
// sender's table, so the manager cannot hand the same device to two drivers —
// the reference is conserved, not copied. The framework's "one driver per
// device" rule is therefore a property of the transfer, not a flag anyone has
// to check.
//
// This is a user<->user contract: the kernel transports it opaquely and never
// decodes it.

library tessera.driver.bind;

// The device classes a driver can ask for. `Unknown` is the value a manager
// records for a device it enumerated but could not classify; a driver never
// asks for it, and a bind request carrying it is refused rather than matched
// against the machine's unclassifiable devices.
strict enum DeviceClass : uint32 {
    Unknown = 0;
    Block = 1;
    Network = 2;
};

// "Give me a device of this class." Sent with ChannelCall.
@abi
struct BindRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    class: DeviceClass;
    reserved: uint32;
};

// The outcome. `status` is 0 when a device was bound — in which case the
// message also carries exactly one transferred handle, the device capability
// — and non-zero when the manager has no unbound device of that class, in
// which case it carries none.
//
// `class` echoes what was actually bound. It is not redundant with the
// request: a driver that asked for one class and is handed another has been
// mis-bound, and checking beats trusting.
@abi
struct BindReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    class: DeviceClass;
};
