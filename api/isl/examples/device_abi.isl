// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The ring-3 driver-host device syscall ABI, defined in ISL: the structured
// arguments for MapDevice and DmaAlloc, retiring those syscalls' register-passed
// v0 ABI (build/README.md, D77/D78 -> D79). The device capability names the
// physical MMIO window; the caller supplies only the desired page-aligned user
// virtual address, so nothing wire-visible carries a physical address inward.

library tessera.kernel.device;

// MapDevice — map the MMIO register window named by `device` (which must carry
// Rights::MAP) into the caller's own address space at page-aligned `vaddr`.
// Returns the register base VA: the page VA plus the window's intra-page
// offset (virtio-mmio windows are 0x200-byte slots, not page-aligned).
@abi
struct MapDeviceArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    reserved: uint32;
    vaddr: uint64;
};

// DmaAlloc — allocate one zero-filled page in the caller's address space at
// page-aligned `vaddr`, authorized by `device` (which must carry Rights::MAP
// and resolve to a real MMIO-backed device capability). Returns the page's
// physical address — the device-visible name of the same memory.
@abi
struct DmaAllocArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    reserved: uint32;
    vaddr: uint64;
};

// IrqComplete — re-enable the interrupt line of the device named by `device`
// (which must carry Rights::MAP and have an INTID wired in the resource
// graph), after the driver has acknowledged the device itself. The second
// half of the mask-on-deliver interrupt protocol (D84): the kernel disables
// the line when it signals the driver's port; the driver acks the device
// through its mapped window, then calls this to re-arm.
@abi
struct IrqCompleteArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    reserved: uint32;
};

// DeviceInfo — ask what a device *is*, for a device the caller already holds a
// capability to.
//
// This exists because PCI moved a fact out of reach. A virtio-mmio transport
// says what it is in its own registers, so a device manager maps it and reads
// two words — enumeration by access, which is why the manager is a program
// rather than a table. A PCI function says what it is in **config space**,
// which is not per-device: a capability to it would be authority over every
// function behind the bridge at once. So the kernel reads config space during
// enumeration (build/README.md, D114) and normalizes what it found into the
// resource graph, and this is how a holder asks for it.
//
// It grants nothing. The answer is about a device the caller can already name,
// and possessing the capability is the whole check — the kind of query that
// makes a capability *useful* rather than one that makes it stronger.
//
// A device the graph has no identity for answers `kind = UNKNOWN`, which is an
// answer and not a failure: a manager's documented response is to fall back to
// probing the device's registers, exactly as it does for virtio-mmio.
@abi
struct DeviceInfoArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    reserved: uint32;
    record_ptr: uint64;
};

// How a device's identity was learned. Append only; values are ABI.
strict enum DeviceInfoKind : uint32 {
    // The graph holds no normalized identity — ask the device itself.
    UNKNOWN = 0;
    // Read from PCI config space during enumeration.
    PCI = 1;
};

// Which bus a device was found on — a **binding input**
// (`docs/drivers/01`, "Driver Binding"), because the same vendor and product
// id can mean different things behind different buses and a driver written
// for one transport cannot drive the other.
strict enum DeviceBusKind : uint32 {
    // The graph does not say. Matched by nothing: a binding rule that
    // accepted an unknown bus would bind a driver to a transport nobody
    // established it can speak.
    UNKNOWN = 0;
    PCI = 1;
    VIRTIO_MMIO = 2;
    PLATFORM = 3;
};

// What the kernel knows about a device, written back to `record_ptr`.
//
// `class_code` is the PCI class register's upper three bytes: class in bits
// 23:16, subclass in 15:8, prog-if in 7:0. A manager matches on the class
// byte — that is the whole point of a class code, and it is the same question
// `driver_bind.isl`'s DeviceClass asks.
//
// **Version 2 carries where the device's structures are** (build/README.md,
// D130), which is what stood between a granted register window and a ring-3
// driver able to use it. A virtio-pci function does not say where its
// controls are in any register it exposes: it says so in config space, one
// vendor capability per structure, each naming a BAR and an offset. A driver
// holding only a window has no way to find them — D126 closed with exactly
// that gap, and the check that proved the window worked read at an offset the
// *check* knew and the driver did not.
//
// The offsets are **relative to the granted window**, not absolute addresses.
// That is the difference between telling a driver where its structures are and
// telling it where they are in physical memory: the first is usable by a
// process that mapped a capability, and the second is a fact about the machine
// that no driver should be given.
@abi
struct DeviceInfoRecord {
    size: uint32;
    version: uint32;
    flags: uint64;
    kind: DeviceInfoKind;
    class_code: uint32;
    vendor: uint32;
    device: uint32;
    bdf: uint32;
    // The hardware revision, a binding input in its own right: a driver may
    // support a device from revision 3 onward and not before.
    revision: uint32;
    bus: DeviceBusKind;
    // Whether the offsets below mean anything. Zero for a device whose
    // structures the kernel did not resolve — a virtio-mmio transport, whose
    // register layout is fixed and needs no discovery, or a function whose
    // capabilities did not describe all three. Reported rather than inferred
    // from zero offsets, because offset zero is a legitimate place for a
    // structure to be.
    layout_valid: uint32;
    // Offsets within the granted window of the virtio-pci configuration
    // structures. `notify_multiplier` is the notify capability's queue
    // multiplier, which is not an offset and is carried here because it is
    // discovered in the same walk and is useless without them.
    common_offset: uint32;
    notify_offset: uint32;
    notify_multiplier: uint32;
    isr_offset: uint32;
    device_config_offset: uint32;
    reserved: uint32;
};

// DeviceChild — ask a bus controller's capability for one of the devices behind
// it, and be given a capability to that device.
//
// **The first grant that comes from neither the kernel's own tables nor the
// device manager.** Until now a driver received its device from a manager that
// had enumerated the machine, and the manager received it from boot. A bus
// controller is a driver whose children are drivers (`docs/drivers/01`, "Bus
// Topology And Data Paths"), and it cannot ask the manager for them: the
// manager does not know what is behind a bus that only the controller's own
// capability names.
//
// **What makes it safe is the edge, not a list.** The kernel answers from the
// resource graph's parent/child edges, so a controller can name exactly the
// devices below it and nothing else. There is no set of permitted ids anybody
// maintains, and therefore none to get wrong.
//
// `index` selects among the children, and the count comes back in the record —
// so a controller walks 0..count without a separate "how many" call, and a
// count that shrinks between calls answers with a smaller count rather than a
// capability to something that has left.
@abi
struct DeviceChildArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The parent. Must carry Rights::DERIVE: holding a bus is not by itself
    // authority to hand out what is on it.
    device: handle<Object, {DERIVE}>;
    index: uint32;
    record_ptr: uint64;
};

// What came back, written to `record_ptr`.
//
// `count` is filled in whether or not a capability was installed, because "how
// many children are there" is the question a controller asks first and an
// `index` past the end is an ordinary answer rather than an error — a bus with
// nothing on it is a normal bus.
//
// `child` is the installed handle, or `NOT_INSTALLED` when no capability was
// granted. Reported rather than inferred from zero: zero is a legitimate handle
// number, and a controller that treated it as failure would drop its first
// child on every machine where the table happened to be empty.
@abi
struct DeviceChildRecord {
    size: uint32;
    version: uint32;
    flags: uint64;
    // How many devices sit directly behind the parent.
    count: uint32;
    // The handle installed for child `index`, or NOT_INSTALLED.
    child: uint32;
    // The rights the child handle carries: the resource graph's own record for
    // that device, plus DERIVE so a controller can keep walking down a subtree
    // that has a switch in it. Not a narrowing of the parent's — a bus and the
    // devices on it are different objects wanting different authority, and
    // deriving one from the other would force a root port to be granted MAP
    // purely so the endpoints below it could be mapped.
    //
    // Echoed rather than assumed, so a controller can check what it was given.
    rights: uint64;
};

// WakeSource — arm or disarm a device's interrupt as a system wakeup source.
//
// **The right is the whole design.** Every driver holds a device and most of
// them have an interrupt, so if arming one came with the device, the set of
// things able to wake this machine would be the driver table — which nobody
// chose and nobody can audit. `docs/power/01-power-management.md` asks for that
// set to be explicit, auditable and profile-policed, and `Rights::WAKE` is what
// makes it a decision somebody took rather than a consequence.
//
// Brokering therefore happens where the right is granted rather than in a call
// anybody makes: a device manager whose manifest says an entry is wake-capable
// hands out a capability carrying WAKE, and one whose manifest does not, does
// not. There is no separate broker object to hold, and no third party in the
// path of an arming.
//
// A device with **no interrupt wired** is refused rather than recorded. A
// wakeup source that cannot fire is indistinguishable from one that has not
// fired yet at every later point, and a machine that suspended trusting it
// would never come back — so the one moment it can be caught is here.
@abi
struct WakeSourceArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The device whose interrupt this is about. Must carry Rights::WAKE.
    device: handle<Object, {WAKE}>;
    // Non-zero to arm, zero to disarm.
    arm: uint32;
    reserved: uint32;
};

// WakeHold — take or release a suspend blocker, or read the system wake-event
// counter.
//
// Three operations on one call because they are one mechanism seen from three
// sides, and because the counter is what a caller reads *in order to* decide
// whether to hold: a query that had to be a separate syscall would be a second
// round trip in the middle of the race this facility exists to close.
//
// **A hold is a record, not an object.** `docs/power/01` calls wake holds
// capability-gated, time-limited and attributed; the gate is Rights::WAKE, the
// limit is `ticks`, and the attribution is the calling process. Making each
// hold its own kernel object would buy transferability, which is exactly the
// property a suspend blocker must not have — a hold that can be handed on is a
// hold whose holder cannot be held responsible for it, which is the wakelock
// lesson this is written against.
strict enum WakeHoldOp : uint32 {
    // Take a hold. Vetoes the final suspend commit until released or expired.
    ACQUIRE = 1;
    // Release one of this caller's holds. One rather than all: two holds are
    // two reasons, and finishing one is not finishing the other.
    RELEASE = 2;
    // Read the counter and the live hold count, changing nothing.
    QUERY = 3;
};

@abi
struct WakeHoldArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // A capability carrying Rights::WAKE — the same right that arms a wakeup
    // source, because they are the two halves of one authority: to say what
    // may wake this machine, and to say it must not sleep.
    //
    // **What the kernel checks is the right and not the object.** The hold is
    // attributed to the calling *process*, which is what makes an abusive
    // holder nameable and what lets a departing process's holds go with it;
    // this handle is the gate, not the subject. A Power object class would
    // give the gate a thing to be about, and until something needs one — the
    // suspend commit will — inventing it would be an object nobody reads.
    power: handle<Object, {WAKE}>;
    op: WakeHoldOp;
    // How long the hold lasts, in scheduler ticks. Zero means until released.
    //
    // **Ticks, and honest about it**: they are the only monotonic source the
    // kernel has, so this is a liveness bound rather than a wall clock — it
    // answers "is the holder still asking for this", exactly as a DMA lease's
    // deadline does.
    ticks: uint64;
    record_ptr: uint64;
};

// What came back, written to `record_ptr`.
@abi
struct WakeHoldRecord {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The system wake-event counter. Monotonic and never reset: a counter that
    // could be zeroed would let a snapshot taken before the reset compare
    // equal to a count taken after it, which is the race counting exists to
    // close.
    events: uint64;
    // Wake holds still counting, across every holder.
    held: uint32;
    // The kernel's current scheduler tick — the only monotonic source there
    // is, and what a caller needs to tell "quiet for a while" from "quiet
    // since the last time I looked".
    reserved: uint32;
    ticks: uint64;
};

// SystemSuspend — the final commit: stop the machine, and say what ended it.
//
// **The commit is the kernel's and the decision is the service's**
// (`docs/power/01-power-management.md`, "The Power And Thermal Manager"). By
// the time this is called the manager has already frozen what it freezes and
// suspended the driver hosts leaves-first; what is left is the one step whose
// correctness cannot survive a service round trip, because it has to be right
// *while nothing is running*.
//
// **The snapshot is the whole mechanism.** The caller reads the wake-event
// counter before it begins entry and passes it here; the kernel refuses if the
// number has moved. Whether a wake arrived before, during or after the
// snapshot does not matter — it either changed the number or it did not. That
// is `docs/power/01`'s *"the lost-wakeup race is closed by counting, not by
// hoping"*, and it is why this argument exists rather than a flag the entry
// path could clear.
//
// The call **does not return until the machine resumes**. What comes back
// names the wake source, which is the first thing anybody debugging a resume
// wants and the last thing that can be reconstructed afterwards.
strict enum SuspendOutcome : uint32 {
    // The commit was taken and a wake ended it. `source` names the device.
    RESUMED = 1;
    // A wake arrived after the snapshot was taken. The entry aborted and the
    // machine never stopped.
    WAKE_ARRIVED = 2;
    // A wake hold vetoed the commit. `source` names the holder.
    VETOED = 3;
};

@abi
struct SystemSuspendArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // A capability carrying Rights::SLEEP. Separate from WAKE because they are
    // opposite authorities over the same machine: one says what may interrupt
    // a sleeping system, the other stops it running at all.
    power: handle<Object, {SLEEP}>;
    reserved: uint32;
    // The wake-event counter as the caller last read it.
    snapshot: uint64;
    record_ptr: uint64;
};

@abi
struct SystemSuspendRecord {
    size: uint32;
    version: uint32;
    flags: uint64;
    // A SuspendOutcome value. Typed uint32 rather than the enum so a value
    // outside the contract can be observed rather than fail to decode.
    status: uint32;
    reserved: uint32;
    // The wake-event counter when the call returned.
    events: uint64;
    // The device credited with the wake for RESUMED, the vetoing holder for
    // VETOED, and zero otherwise.
    source: uint64;
};
