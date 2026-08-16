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
//
// `Bus` is a controller — a driver whose children are drivers
// (`docs/drivers/01`, "Bus Topology And Data Paths"). It is a class in its own
// right because the manifest has to be able to say something *about* a hub even
// where nothing binds one: what transfers passing through it cost. Until it
// existed a PCI bridge classified as `Unknown`, which is refused by design, and
// so the one question worth asking about a bus could not be asked.
strict enum DeviceClass : uint32 {
    Unknown = 0;
    Block = 1;
    Network = 2;
    Bus = 3;
    // An SD/MMC host controller. **A class of its own rather than `Bus`**, even
    // though its children are devices: what a driver binds to it must speak
    // SD's command set, and a manifest that could not tell it from a PCIe
    // bridge would offer a bridge driver a card slot. Appended, never
    // renumbered.
    Sd = 4;
    // A USB host controller. **Its own class rather than `Bus`**, for the
    // reason `Sd` is: what binds to it must speak USB, and a manifest that
    // could not tell an xHCI controller from a PCIe bridge would offer a bridge
    // driver a root hub.
    //
    // The distinction from `Sd` matters as much. Both are controllers whose
    // children are devices, but an SD controller has one slot and a fixed
    // command set, and a USB host has a tree of devices that describe
    // themselves — which is why one of them needs an authorization policy and
    // the other does not. Appended, never renumbered.
    Usb = 5;
    // A human interface device. **Not a subdivision of `Usb`**: what binds here
    // is a driver for the input *class*, and the transport it arrives over is
    // the binding's business rather than the class's — a keyboard on a serial
    // port and one on a hub are the same contract to the thing that reads them.
    // Appended, never renumbered.
    Input = 6;
    // A GPIO controller. Its own class for the reason `Sd` and `Usb` are: what
    // binds here must speak this controller's registers, and a manifest that
    // could not tell a GPIO block from a timer would offer a GPIO driver a
    // watchdog — both are platform devices on the same bus with no
    // configuration space to tell them apart. Appended, never renumbered.
    Gpio = 7;
    // An audio output device. Its own class rather than a kind of `Block`,
    // although both move bytes to hardware: what binds here must keep a stream
    // fed against a deadline, and a manifest that could not tell the two apart
    // would offer a disk driver a sound card. Appended, never renumbered.
    Audio = 8;
    // A display. Its own class rather than a kind of `Audio`, although both
    // are streams to hardware with a deadline: what binds here must compose a
    // picture, and the two share no vocabulary at all. Appended, never
    // renumbered.
    Display = 9;
    // A cryptographic accelerator. Its own class although it moves no data of
    // its own: what binds here holds keys, and a manifest that could not tell
    // it from a block device would offer a disk driver somebody's key material.
    // Appended, never renumbered.
    Crypto = 10;
};

// Returning a device needs no message of its own, and deliberately so.
//
// A message that carries a **capability** to the manager *is* a return: a bind
// request never carries one, and nothing else in this protocol hands the
// manager a device. The receiver learns it happened from the kernel's
// installed-handle report (`ChannelMsgArgs.installed_ptr`, D94), not from any
// field below.
//
// Keying on the capability rather than on a flag is the stronger choice twice
// over. A body can be forged by any sender; a transferred capability cannot —
// only something that held the device can hand it on. And it means the
// **kernel** can return a dead driver's devices without knowing this protocol
// at all, which is what makes reclaim-on-death possible: the kernel sends the
// capability with no payload, and the manager understands it.

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
//
// **Version 2 carries the binding's outputs** (build/README.md, D130).
// `docs/drivers/01` lists six; three of them — the host identity, the granted
// capabilities and the resource leases — are produced by the *transfer* and
// need no field. The other three are decisions a manifest made, and a driver
// that was not told them would have to assume: which services it may ask for,
// which channel it is updated through, and which security and power domains
// the binding placed it in.
//
// `status` is a `binding::Refusal` value when non-zero, and the reason matters
// as much as the refusal. A device unbound because nothing matched, one
// unbound because its driver is unsigned, and one unbound because an operator
// disabled it are three administrative situations with three different fixes —
// and a reply that reported them identically would leave all three looking
// like missing hardware.
//
// **Version 3 carries what the data path costs.** `docs/drivers/01` ("Bus
// Topology And Data Paths") says a relaying class contract declares its added
// latency and throughput cost so that "a deep tree of relaying hubs is a
// declared cost, not a surprise". These three fields are that cost, accumulated
// over the ancestors the manager walked — and telling the driver is the point:
// two identical devices differing only in where they are attached are no longer
// indistinguishable to the thing that has to meet a budget on one of them.
//
// A driver whose entry declared no budget still gets the numbers. Being told
// what a path costs is useful to something that never refuses on it, and a
// field filled in only when it fails is one nobody can trust when it succeeds.
//
// **`flags` bit 0 means the path figures are a lower bound**, not a total: some
// hop on the path has a cost nothing declared, or the declared costs sum past
// what a `uint64` holds. A flag rather than a sentinel in the numbers, because
// every hop count and every latency is a legitimate value — there is nothing to
// reserve — and a consumer that ignores the bit still sees plausible figures,
// which is exactly why the distinction has to travel separately from them.
@abi
struct BindReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    class: DeviceClass;
    // Services this driver requires (`binding::required_service`), so it knows
    // what it may ask for and the system knows what to start first.
    required_services: uint32;
    // The channel this driver is updated through; zero for one that does not
    // update independently of the system image.
    update_channel: uint32;
    security_domain: uint32;
    power_domain: uint32;
    // The class contract version the manifest says this driver implements. A
    // client that sees one it does not know must not proceed — the ordinals
    // may mean different things.
    contract_version: uint32;
    reserved: uint32;
    // What the relaying ancestors on this device's path declared they add, in
    // total. Zero is an answer — the path relays through nothing — and not an
    // absent field.
    accumulated_latency_us: uint64;
    // How many processes a transfer to this device relays through. An ancestor
    // providing per-child queue separation is not one of them: the transfer
    // crosses no extra process, so a well-attached device is zero rather than a
    // small number.
    relay_hops: uint32;
    // The narrowest hop on the path, Mbit/s.
    //
    // Zero is "no hop declared a ceiling", which is safe as a sentinel here for
    // the reason a zero vendor id was not: zero Mbit/s is not a throughput any
    // real path has, so nothing legitimate is being swallowed.
    path_throughput_mbps: uint32;
    // **Version 4 says which firmware image came with the device.**
    //
    // `docs/drivers/01` ("Firmware Loading") puts firmware loading in the
    // framework rather than in the driver, so a driver does not fetch its own
    // image — it is handed one, as a second transferred handle. These two
    // fields are what it was handed: the security version and the image
    // version of the bytes in that object.
    //
    // Both zero means no firmware came with this binding, which is the normal
    // case and not a failure: most devices have none. A driver whose contract
    // needs firmware and sees zeros has been bound by an entry that declared
    // none, and can say so — which it could not if the fields were absent.
    //
    // The **digest** is deliberately not here. A driver that wants to know
    // which bytes it received measures them, and one that trusted a digest in
    // the same message as the object would be checking the sender against
    // itself.
    firmware_svn: uint32;
    firmware_image_version: uint32;
};
