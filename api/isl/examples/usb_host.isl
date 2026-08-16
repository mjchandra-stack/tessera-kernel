// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **USB host protocol**: how a class driver reaches a device it cannot
// touch.
//
// Every driver in this tree so far has had registers. A block driver maps its
// controller's window and writes to it; an SD card's driver maps the host
// controller and issues commands through it. A USB device has no registers at
// all. There is nothing to map, no window a capability could name, and no way
// for a class driver to reach its device except by asking the process that owns
// the controller to move bytes on its behalf.
//
// That is what `docs/drivers/01` ("Bus Topology And Data Paths") calls a
// **relaying** bus host, and this file is the first one in this tree. It is why
// `Hop::Relay` has existed in the binding rules since D124 with nothing real to
// count: PCIe gives each function its own queues, so every device here has been
// `Separated` and the relay arithmetic has been describing a machine nobody
// built. A transfer to a USB device crosses this protocol, and a transfer to a
// device behind a hub crosses it and then crosses the hub — which is what makes
// the accumulated cost in `BindReply` a measurement rather than a placeholder.
//
// **What is deliberately not here.** No slot number, no endpoint context index,
// no ring. A class driver names a device by the address the host assigned it
// and an endpoint by its number, which is what the *device's* own descriptors
// say; everything about how the controller reaches it is the host's, and a
// protocol that leaked it would tie every class driver to xHCI.
//
// **Authorization is not negotiated in this protocol**, and that is the design.
// A class driver never asks whether it may drive a device. The host applies the
// policy once, at enumeration, and a device the policy refused is left
// unconfigured — it is declared into the resource graph so an operator can see
// what was turned away, given a class code no manifest entry claims so nothing
// binds to it, and answered with `UNAUTHORIZED` on every transfer naming it.
//
// Declared rather than hidden, because a refusal nobody can see is not a
// control: an operator investigating a device that does not work should find
// the reason rather than find nothing.
//
// This is a user<->user contract: the kernel transports it opaquely and never
// decodes it.

library tessera.driver.usb;

// --- Errors -----------------------------------------------------------------

// What a transfer through a USB host can fail with.
//
// A closed set, numbered to the framework's discipline: `NOT_SUPPORTED` at 5,
// `PROTOCOL` at 6, `DEGRADED` at 7 and `REMOVED` at 8, as on every class
// contract here, so the values the framework reads mean the same thing wherever
// they appear. What differs is 1 through 4, and that difference is what USB is.
//
// Values are ABI: append only, never renumbered or reused.
strict enum UsbError : uint32 {
    OK = 0;
    // The endpoint halted. **Its own value and not an I/O error**, because it
    // is a state and not an event: a halted endpoint stays halted until it is
    // cleared, so a client that retried without clearing it would retry
    // forever, and one that gave up would abandon a device that is fine.
    STALL = 1;
    // No device is at that address on this host. Distinct from `REMOVED`: this
    // is an address that never named a device, which is a bug in the caller
    // rather than news about the machine.
    NO_DEVICE = 2;
    // The transfer did not complete: a timeout, a babble, a controller error.
    TRANSFER_ERROR = 3;
    // The device is on this bus and this system will not drive it: its class is
    // not on the host's allowlist.
    //
    // **A value of its own rather than `NO_DEVICE`.** A refused device is in the
    // resource graph and can be seen there — hiding it would make the policy
    // unauditable, and an operator investigating a device that does not work
    // would find nothing rather than find the reason. `NO_DEVICE` says the
    // address names nothing, which is a bug in the caller; this says the address
    // names something the caller may not have.
    UNAUTHORIZED = 4;
    NOT_SUPPORTED = 5;
    PROTOCOL = 6;
    DEGRADED = 7;
    // The device has left the bus. A transfer in flight when it was unplugged
    // completes with this rather than being left to time out — and a client
    // that sees it must not retry, because there is nothing to retry against.
    REMOVED = 8;
};

// What an endpoint carries, as the device's own descriptor said.
//
// The host does not translate these into something of its own. A class driver
// reads its device's descriptors and asks for the endpoint it found there, so
// the vocabulary on the wire is the device's rather than the controller's.
strict enum UsbTransferKind : uint32 {
    CONTROL = 0;
    // Declared and refused. Isochronous transfers need a periodic schedule with
    // bandwidth reserved at configuration time, which this host does not have
    // (build/README.md, D155) — and a value that was simply absent would leave
    // a class driver unable to tell "this host will not" from "this host has
    // not heard of it".
    ISOCHRONOUS = 1;
    BULK = 2;
    INTERRUPT = 3;
};

// --- Requests and replies ---------------------------------------------------

// The payload arrays below hold 64 bytes, the same as the block and network
// contracts and for the same reason: an inline payload is bounded by what a
// channel message holds, and a transfer larger than this is several of these
// rather than one big one. A request asking for more is `BAD_REQUEST` and not a
// silently short read — a client that received fewer bytes than it asked for
// with no error would be a client that had been lied to about the size of its
// own disk.

// "What is at this address?"
@abi
struct UsbDeviceRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The address the host assigned this device during enumeration. Not the
    // port it is plugged into: a device that is re-plugged into a different
    // port keeps neither, and a client that named a port would be naming a
    // hole rather than a device.
    address: uint32;
    reserved: uint32;
};

// What the host knows about a device, from the descriptors it read.
//
// The **interface's** class, subclass and protocol rather than the device's:
// most devices declare nothing at the device level and let each interface speak
// for itself, so a reply carrying the device-level bytes would carry zeros for
// exactly the devices a class driver most wants to find.
@abi
struct UsbDeviceReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: UsbError;
    address: uint32;
    vendor: uint32;
    product: uint32;
    class: uint32;
    subclass: uint32;
    protocol: uint32;
    // Which interface of the device the fields above describe.
    interface: uint32;
    // How many hubs this device is behind. Zero is a root port.
    //
    // Reported because it is the one thing about the topology a class driver
    // legitimately needs: it is the difference between a device whose latency
    // budget it can meet and one it cannot, and it is a number the host already
    // knows and nothing downstream could work out.
    depth: uint32;
    reserved: uint32;
};

// One control transfer: a setup packet, and up to sixty-four bytes of data in
// whichever direction the setup packet's own first byte declares.
//
// The direction is **not** a field here, deliberately. It is bit 7 of the setup
// packet's request type, and a second copy of it in this struct would be a
// second place for it to be wrong — with the failure being a stalled endpoint
// rather than a rejected message.
@abi
struct UsbControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    address: uint32;
    length: uint32;
    setup: array<uint8, 8>;
    data: array<uint8, 64>;
};

// One bulk or interrupt transfer on an endpoint the device described.
//
// **`flags` bit 0 asks for a brief wait.** An interrupt endpoint on an idle
// device never completes: a keyboard nobody is typing on has nothing to send,
// and a transfer issued to it stays outstanding for as long as the room is
// quiet. A class driver that wants to ask "has anything happened" rather than
// "wait until something does" sets this bit, and the host answers `OK` with
// `transferred` zero when nothing had.
//
// Zero bytes moved and no error is the honest answer, and it is the same answer
// a short transfer gets — the field that says how much arrived is the one that
// carries the information, which is why it is authoritative rather than
// advisory.
@abi
struct UsbTransferRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    address: uint32;
    // The endpoint address as the device's descriptor gives it: number in bits
    // 3:0, direction in bit 7. Passed through rather than split, because it is
    // one value in the device's own words and splitting it here would invite a
    // class driver to send a number without a direction.
    endpoint: uint32;
    kind: UsbTransferKind;
    length: uint32;
    data: array<uint8, 64>;
};

// What came back.
//
// `transferred` is what the device actually moved, which for a read is the
// authoritative length: a device is allowed to send less than was asked for and
// that is not an error, it is how a bulk endpoint says "that is all there was".
// A reply with `status = OK` and `transferred` below `length` is a short
// transfer, and a client that ignored the field would read stale bytes out of
// the tail of its own buffer.
@abi
struct UsbTransferReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: UsbError;
    transferred: uint32;
    data: array<uint8, 64>;
};

// --- The protocol -----------------------------------------------------------

protocol UsbHost {
    // What is at this address, and how deep. A class driver calls this first.
    1: Describe(UsbDeviceRequest) -> (UsbDeviceReply);
    // A control transfer on endpoint zero.
    2: Control(UsbControlRequest) -> (UsbTransferReply);
    // A bulk or interrupt transfer. One method rather than two: the ring is the
    // same, the TRB is the same, and the only difference is what the endpoint
    // descriptor said — which the request already carries. Two methods would be
    // two names for the same thing, and a class driver could pick the wrong one
    // without being told.
    3: Transfer(UsbTransferRequest) -> (UsbTransferReply);

    // Ordinals 4..=19 are reserved for what this protocol has not needed yet,
    // so the event range below stays at a fixed boundary.

    // A device arrived and was admitted. The host raises this; nobody asked.
    20: -> OnDeviceArrived(UsbDeviceReply);
    // A device left. A client with a transfer outstanding gets `REMOVED` on
    // that transfer; this is for the ones that did not.
    21: -> OnDeviceGone(UsbDeviceReply);
};
