// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// **The system-call surface**: every call the kernel answers, its number, the
// register frame it reads, the rights it demands, and whether it exists.
//
// This file used to declare six calls of the fifty that had arrived, and said
// so in a header claiming the bindings were "ready to wire when user-mode ABI
// stabilizes" — true when six was the whole set. The layouts moved into ISL in
// D54; the call surface did not, and the real reference became 209 lines of
// doc comment on `kcore::syscall::SyscallNumber`: good documentation, readable
// only from inside the kernel by somebody who already had the source. This is
// the rest of D24 (build/README.md, D248).
//
// **How to read a call.** Registers are written out in order. `argN: T` means
// register *N* carries a value of type `T`; `argN: SomeArgs` — a struct this
// file names with `extern` — means the register carries a **user pointer** to
// one, which the kernel validates and decodes before interpreting any field
// (docs/api/01, "Structured Arguments"). The rights a call demands ride on the
// handle types: `handle<Object, {MAP}>` in a register says this call needs MAP
// on the capability there, and a handle arriving inside an argument struct
// states its requirement in that struct's own schema.
//
// Failure is one negative word for every call — `-((domain << 16) | code)`
// over six stable domains — so only the success value is written down
// (docs/api/01, "The Result Word").
//
// **Two calls have two argument forms in this tree, and this file states one
// of them.** `HandleDuplicate` and `PageSupply` are read as registers by the
// shared dispatcher (`kcore::dispatch`, D79) and as argument structs by the
// x86-64 single-process demo handler, which predates that substrate. What is
// written here is the shared dispatcher's, because that is the path a ring-3
// program takes on four of the five ports. The divergence is D248's first
// finding and its exit criterion; it is recorded rather than resolved, because
// resolving it is a change to a boot check rather than to a schema.
//
// **What is not here.** Whether a call is a good idea, and why a deferred one
// was deferred. Those are arguments, and arguments live in the deviation
// ledger; a schema is a poor place for one. The generated reference links to
// the ledger rather than copying it.

library tessera.kernel.syscall;

// --- The argument structs, and where they are declared ---
//
// Each belongs beside the subsystem it describes rather than beside the trap
// numbers, so this file names them and the owning schema defines them. See
// `ExternDecl` in the compiler for why the dependency is declared here and
// resolved by `//tools/checks:surface_test` rather than by an import.

// Duplicate a handle with a reduced rights mask.
extern struct DuplicateArgs from tessera.kernel.handle;

// Create an empty, not-yet-started process.
extern struct ProcessCreateArgs from tessera.kernel.process;
// Map memory into a created process's address space.
extern struct AddressSpaceMapArgs from tessera.kernel.process;
// Start a created and populated process at an entry point.
extern struct ProcessStartArgs from tessera.kernel.process;
// Hand a created, not-yet-started process a capability the caller holds.
extern struct ProcessGrantArgs from tessera.kernel.process;
// Wait for a process to terminate.
extern struct ProcessWaitArgs from tessera.kernel.process;

// Create a channel and its two endpoints.
extern struct ChannelCreateArgs from tessera.kernel.channel;
// Describe a message: where its bytes are, and where a reply goes.
extern struct ChannelMsgArgs from tessera.kernel.channel;

// Map a device's MMIO register window into the caller's own space.
extern struct MapDeviceArgs from tessera.kernel.device;
// Allocate a DMA buffer for a ring-3 driver.
extern struct DmaAllocArgs from tessera.kernel.device;
// Re-arm a device's interrupt line after the driver acknowledged the device.
extern struct IrqCompleteArgs from tessera.kernel.device;
// Route a device's interrupts to a port the caller holds.
extern struct DeviceIrqBindArgs from tessera.kernel.device;
// Ask what a device is.
extern struct DeviceInfoArgs from tessera.kernel.device;
// Ask a bus controller for one of the devices behind it.
extern struct DeviceChildArgs from tessera.kernel.device;
// A bus controller says a device exists.
extern struct DeviceDeclareArgs from tessera.kernel.device;
// Map this function's own configuration space.
extern struct MapConfigArgs from tessera.kernel.device;
// Arm or disarm a device's interrupt as a system wakeup source.
extern struct WakeSourceArgs from tessera.kernel.device;
// Take or release a wake hold, or read the system wake-event counter.
extern struct WakeHoldArgs from tessera.kernel.device;
// Commit the system to sleep.
extern struct SystemSuspendArgs from tessera.kernel.device;

// Allocate a range of zeroed anonymous pages as an object.
extern struct MemoryCreateArgs from tessera.kernel.memory;
// Create an object whose pages a service supplies.
extern struct MemoryCreatePagedArgs from tessera.kernel.memory;
// Map an object the caller holds into its own space.
extern struct MemoryMapArgs from tessera.kernel.memory;
// Put an object on a handling path.
extern struct MemoryClassifyArgs from tessera.kernel.memory;
// Which of an object's pages are dirty.
extern struct MemoryDirtyPagesArgs from tessera.kernel.memory;
// Fill in one page of a service-backed object.
extern struct PageSupplyArgs from tessera.kernel.memory;
// The caller has persisted an object's page.
extern struct PageWrittenBackArgs from tessera.kernel.memory;
// Make an object reachable by a device.
extern struct DmaAttachArgs from tessera.kernel.memory;
// Stop a device reaching an object.
extern struct DmaDetachArgs from tessera.kernel.memory;
// Say a DMA lease is still wanted, and until when.
extern struct DmaRenewArgs from tessera.kernel.memory;

// Record a driver-lifecycle transition for a device the caller holds.
extern struct LifecycleTransitionArgs from tessera.driver.lifecycle;

// Verify a named firmware image and admit it against policy.
extern struct FirmwareLoadArgs from tessera.firmware;

// --- Types the register frame carries directly ---

// The rights catalog, as a value a register can hold. The same bits
// `handle_abi.isl` declares and `kernel/kcore/src/rights.rs` declares (D16);
// named here because `HandleDuplicate` and `HandleQueryRights` pass a mask in
// a register rather than inside a struct.
bits Rights : uint64 {
    READ = 0x1;
    WRITE = 0x2;
    MAP = 0x4;
    EXECUTE = 0x8;
    SIGNAL = 0x10;
    WAIT = 0x20;
    DUPLICATE = 0x40;
    TRANSFER = 0x80;
    CONFIGURE = 0x100;
    BIND = 0x200;
    ADMIN = 0x400;
    SUPPLY = 0x1000000;
    DERIVE = 0x100000000;
    WAKE = 0x1000000000;
    SLEEP = 0x2000000000;
    FIRMWARE = 0x4000000000;
    PROTECTED_DMA = 0x8000000000;
};

// --- Argument structs this library owns ---
//
// Two structs, and neither is decoded by anything. `DebugWrite` and
// `ProcessExit` read their arguments straight out of registers, which is what
// the calls below declare; these are the structured forms they would take if
// either ever needed more than two words. They stay because they are
// conformance-gated wire layouts and a fuzz target's subject — deleting a
// declared layout is an ABI removal, and there is nothing to gain from one —
// and they are marked so the reference does not present them as something a
// caller can use.

// The structured form of `DebugWrite`'s arguments: a buffer to copy to the
// debug console. The kernel would validate `[buffer, buffer + length)` against
// the caller's mappings before the copy, exactly as the register form does
// (docs/security/01, "Strict user-kernel copy validation").
@abi
@status(designed)
struct DebugWriteArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The buffer's address in the caller's space.
    buffer: uint64;
    // Its length in bytes.
    length: uint64;
};

// The structured form of `ProcessExit`'s argument: the calling process's exit
// code.
@abi
@status(designed)
struct ProcessExitArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The exit code.
    code: int32;
    reserved: array<uint8, 4>;
};

// The call numbers as an enumeration, so a decoder that only needs to name a
// number does not have to carry the whole surface. Every member here is a
// `syscall` below at the same number, which `//tools/checks:surface_test` enforces
// in both directions.
strict enum Syscall : uint64 {
    NULL = 0;
    DEBUG_WRITE = 1;
    HANDLE_DUPLICATE = 2;
    HANDLE_QUERY_RIGHTS = 3;
    HANDLE_CLOSE = 4;
    PROCESS_EXIT = 5;
    WAIT_ON_ADDRESS = 6;
    WAKE_ADDRESS = 7;
    PROCESS_CREATE = 8;
    ADDRESS_SPACE_MAP = 9;
    PROCESS_START = 10;
    CHANNEL_CREATE = 11;
    CHANNEL_SEND = 12;
    CHANNEL_RECV = 13;
    CHANNEL_CALL = 14;
    CHANNEL_REPLY = 15;
    PORT_CREATE = 16;
    PORT_BIND = 17;
    PORT_WAIT = 18;
    DEVICE_IO_READ = 19;
    DEVICE_IO_WRITE = 20;
    PAGE_SERVE = 21;
    PAGE_SUPPLY = 22;
    MAP_DEVICE = 23;
    DMA_ALLOC = 24;
    CHANNEL_REPLY_RECV = 25;
    IRQ_COMPLETE = 26;
    CHANNEL_REPLY_CONTINUE = 27;
    DEVICE_INFO = 28;
    DRIVER_LIFECYCLE = 29;
    MEMORY_CREATE = 30;
    MEMORY_MAP = 31;
    DMA_ATTACH = 32;
    DMA_DETACH = 33;
    DMA_RENEW = 34;
    DEVICE_CHILD = 35;
    WAKE_SOURCE = 36;
    WAKE_HOLD = 37;
    SYSTEM_SUSPEND = 38;
    FIRMWARE_LOAD = 39;
    MEMORY_CLASSIFY = 40;
    DEVICE_DECLARE = 41;
    MAP_CONFIG = 42;
    CHANNEL_RECV_ANY = 43;
    PORT_SIGNAL = 44;
    MEMORY_CREATE_PAGED = 45;
    MAP_OBJECT = 46;
    MEMORY_DIRTY_PAGES = 47;
    PAGE_WRITTEN_BACK = 48;
    MEMORY_UNMAP = 49;
    PROCESS_GRANT = 50;
    PROCESS_WAIT = 51;
    DEVICE_IRQ_BIND = 52;
    CLOCK_READ = 53;
};

// --- The calls ---

// Validated no-op: the kernel decodes the number, finds this, and returns.
//
// It exists to be measured. B1 is the cost of entering and leaving the kernel
// with nothing in between, which is the floor every other call is read
// against.
@status(implemented)
@available(added = 1)
syscall Null = 0 {
    // Always zero.
    returns: uint64;
};

// Write a validated user buffer to the debug console.
//
// The kernel checks `[buffer, buffer + length)` lies wholly inside the
// caller's own readable mappings before it copies a byte (docs/security/01,
// "Strict user-kernel copy validation").
@status(implemented)
@available(added = 1)
syscall DebugWrite = 1 {
    // The buffer's address in the caller's space.
    arg0: uint64;
    // Its length in bytes.
    arg1: uint64;
    // Bytes written.
    returns: uint64;
};

// Duplicate a handle, carrying no more authority than the original.
//
// **The kernel narrows, never expands.** A request for a right the source does
// not hold is refused rather than trimmed to what it could give: a caller
// handed a weaker capability than it asked for finds out by being refused
// something later, somewhere else.
//
// The B2 handle-op path. Note the two argument forms recorded in this file's
// header: the shared dispatcher reads these two registers, and the x86-64
// single-process demo handler reads a `DuplicateArgs` struct through `arg0`.
@status(implemented)
@available(added = 1)
syscall HandleDuplicate = 2 {
    // The handle to copy.
    arg0: handle<Object, {DUPLICATE}>;
    // The rights the copy is to carry, which must be a subset of the source's.
    arg1: Rights;
    // The new handle.
    returns: uint64;
};

// Ask what rights a handle carries.
//
// Grants nothing: the answer is about a capability the caller already holds.
@status(implemented)
@available(added = 1)
syscall HandleQueryRights = 3 {
    // The handle to ask about.
    arg0: handle<Object, {}>;
    // The rights mask it carries.
    returns: Rights;
};

// Drop a handle.
//
// **A capability leaves a process by being closed exactly as by being
// transferred**, and the same consequences follow the object out: a memory
// object the caller owned goes back to the allocator, a device's DMA lease
// ends, and its interrupt route is torn down. Without this a program freed a
// memory object only by dying.
@status(implemented)
@available(added = 1)
syscall HandleClose = 4 {
    // The handle to drop.
    arg0: handle<Object, {}>;
    // 1 if this was the last handle and the object was destroyed, else 0.
    returns: uint64;
};

// End the calling process.
@status(implemented)
@available(added = 1)
syscall ProcessExit = 5 {
    // The exit code.
    arg0: int32;
};

// Block if, and only if, the word at an address still holds an expected value.
//
// **The compare happens inside the lock that enrolls the waiter** (D240). Read
// the word first and enrol afterwards and another CPU can write it and wake
// the key in between, parking this thread on a condition that has already been
// signalled, for ever.
//
// The key is the *memory*, not the address: two processes mapping one page
// name that word differently and must still be able to wake each other.
@status(implemented)
@available(added = 1)
syscall WaitOnAddress = 6 {
    // A 4-byte-aligned address of a `uint32` in the caller's space.
    arg0: uint64;
    // The value the word must still hold for this call to block.
    arg1: uint32;
    // Zero once woken. `WouldBlock` if the word already differed.
    returns: uint64;
};

// Wake threads waiting on an address.
@status(implemented)
@available(added = 1)
syscall WakeAddress = 7 {
    // The address whose waiters to wake.
    arg0: uint64;
    // At most this many.
    arg1: uint64;
    // How many were woken.
    returns: uint64;
};

// Create an empty, not-yet-started process under a parent job's
// create-process authority.
//
// The first of the three-phase model (docs/api/01): create, populate, start. A
// process exists before it runs so that whoever created it can decide what it
// will be able to reach. What D42 still records is the initial handle set and
// the startup message — the capabilities a child receives from its parent
// arrive by a bootstrap channel the component-manager context installs before
// start, rather than as arguments here.
@status(implemented)
@available(added = 1)
syscall ProcessCreate = 8 {
    arg0: ProcessCreateArgs;
    // A handle to the new process.
    returns: uint64;
};

// Map memory into a created, not-yet-started process's address space.
//
// The loader operation: this is how a user-space loader populates a child
// before starting it, and it is refused once the child is running.
@status(implemented)
@available(added = 1)
syscall AddressSpaceMap = 9 {
    arg0: AddressSpaceMapArgs;
};

// Start a created and populated process at an entry point, and return as soon
// as it is runnable.
//
// **It used to hand the CPU to the child and come back with the child's exit
// code**, which is a spawn-and-wait: a parent could hold only one running child
// and a root task could not start a server and then start something to talk to
// it. docs/api/01 has always listed starting and waiting as two operations, and
// this is the first of them (build/README.md, D250). A parent that wants the
// exit code asks `ProcessWait` for it.
@status(implemented)
@available(added = 1)
syscall ProcessStart = 10 {
    arg0: ProcessStartArgs;
};

// Create a channel: two connected endpoints, both handles installed in the
// caller's own table.
//
// **The result word carries one value and a channel has two ends**, which is
// why this sat deferred while every other channel operation worked
// (build/README.md, D45). Version 2 of the argument struct answers it the way
// every other two-answer call in this ABI does: the caller says where to write
// a `ChannelCreateRecord`, and the result word stays a status.
//
// Both ends land in the creator's table, because that is the only table the
// kernel can name at that moment. Handing one to somebody else is a separate,
// separately-authorized act — `ProcessGrant` into a child that has not started,
// or a transfer over a channel that already exists.
@status(implemented)
@available(added = 1)
syscall ChannelCreate = 11 {
    arg0: ChannelCreateArgs;
};

// Send a message on an endpoint and keep running.
//
// One-way: there is no reply and no transaction to pair. A sender that needs
// an answer uses `ChannelCall`.
@status(implemented)
@available(added = 1)
syscall ChannelSend = 12 {
    arg0: ChannelMsgArgs;
    // The endpoint to send on.
    arg1: handle<Object, {WRITE}>;
    // Bytes sent.
    returns: uint64;
};

// Receive the next message on an endpoint, blocking until one arrives.
@status(implemented)
@available(added = 1)
syscall ChannelRecv = 13 {
    arg0: ChannelMsgArgs;
    // The endpoint to receive on.
    arg1: handle<Object, {READ}>;
    // The message's length in bytes.
    returns: uint64;
};

// Send a request and block for the reply, handing the CPU straight to the
// server.
//
// The B3 round-trip path, and the reason a synchronous service call is not two
// asynchronous ones: the handoff is what lets a request and its answer cost
// one scheduling decision instead of four.
@status(implemented)
@available(added = 1)
syscall ChannelCall = 14 {
    arg0: ChannelMsgArgs;
    // The endpoint to call on.
    arg1: handle<Object, {WRITE}>;
    // The reply's length in bytes.
    returns: uint64;
};

// Reply to the outstanding call on an endpoint, handing the CPU back to the
// waiting caller and **blocking this thread**.
//
// Right for a server whose next wake is the next call on that same endpoint —
// the handoff itself resumes it. Wrong for a server that loops back to its own
// receive, or that selects across several endpoints and is woken by a port:
// nothing ever hands back, and it hangs after exactly one exchange. Those use
// `ChannelReplyContinue` or `ChannelReplyRecv`.
@status(implemented)
@available(added = 1)
syscall ChannelReply = 15 {
    arg0: ChannelMsgArgs;
    // The endpoint whose outstanding call is being answered.
    arg1: handle<Object, {READ}>;
};

// Create a port: an object that collects events and can be waited on.
//
// The driver-host substrate. A port is what turns a device interrupt into
// something a ring-3 thread can block on (build/README.md, D46).
@status(implemented)
@available(added = 1)
syscall PortCreate = 16 {
    // A handle to the new port.
    returns: uint64;
};

// Bind a port to an event source and signal.
//
// What a holder of a port may later be woken by is decided here, once, rather
// than by an argument passed at signal time.
@status(implemented)
@available(added = 1)
syscall PortBind = 17 {
    // The port to bind.
    arg0: handle<Object, {BIND}>;
    // The event source, as the resource graph names it.
    arg1: uint64;
    // The signal within that source.
    arg2: uint8;
};

// Wait for the next event on a port, blocking until one arrives.
//
// A port **coalesces**: a signal raised while nobody waits is remembered, and
// the next wait returns it from the queue. That is what makes a driver that
// was busy when its device fired not lose the interrupt.
@status(implemented)
@available(added = 1)
syscall PortWait = 18 {
    // The port to wait on.
    arg0: handle<Object, {READ}>;
    // Where to write a `PortEventRecord`, or 0 to want only the count.
    arg1: uint64;
    // How many events were pending, this one included.
    returns: uint64;
};

// Read one byte of a device register through a device-I/O capability.
//
// The physical window comes solely from the capability, never from the caller:
// a driver can reach its own device's registers and no others.
@status(implemented)
@available(added = 1)
syscall DeviceIoRead = 19 {
    // The device to read.
    arg0: handle<Object, {READ}>;
    // The byte offset within that device's window.
    arg1: uint64;
    // The byte read.
    returns: uint64;
};

// Write one byte of a device register through a device-I/O capability.
@status(implemented)
@available(added = 1)
syscall DeviceIoWrite = 20 {
    // The device to write.
    arg0: handle<Object, {WRITE}>;
    // The byte offset within that device's window.
    arg1: uint64;
    // The byte to write.
    arg2: uint8;
};

// A ring-3 pager waits for the next page-in request on its endpoint.
//
// The kernel is holding a thread that faulted on a page nobody has supplied,
// and this is the service that owns that object's contents being asked to put
// it there (build/README.md, D48).
@status(implemented)
@available(added = 1)
syscall PageServe = 21 {
    // The endpoint the object was bound to at creation.
    arg0: handle<Object, {READ}>;
    // The faulting byte offset within the object, so the service can find the
    // page in its own backing store.
    returns: uint64;
};

// Fill in one page of a service-backed object from a page of the pager's own
// memory.
//
// **The kernel copies rather than taking the page.** An ownership transfer is
// what `docs/kernel/03` describes and what this becomes; a copy is what can be
// checked today, because the source stays mapped and readable so there is no
// instant at which the page belongs to neither side.
//
// Both offsets are refused rather than rounded when unaligned: a caller that
// meant one page and named an address inside another would otherwise have a
// page it never chose copied into an object somebody else reads, and would
// have no way to find out.
//
// The second of the two calls with two argument forms — see this file's
// header.
@status(implemented)
@available(added = 1)
syscall PageSupply = 22 {
    arg0: PageSupplyArgs;
};

// Map a device's MMIO register window into the caller's own address space.
//
// The window is mapped as Device memory and user-readable, and its physical
// base comes solely from the capability — never from the caller. The first
// step of the ring-3 driver host (build/README.md, D77).
@status(implemented)
@available(added = 1)
syscall MapDevice = 23 {
    arg0: MapDeviceArgs;
    // The mapped virtual address.
    returns: uint64;
};

// Allocate a DMA buffer for a ring-3 driver.
//
// Returns the buffer's **device-visible address** while mapping it at a
// virtual address the driver named, because a driver needs both: it fills the
// buffer through the mapping and hands the device the address the device DMAs
// against. The second step of the ring-3 driver host (build/README.md, D78).
@status(implemented)
@available(added = 1)
syscall DmaAlloc = 24 {
    arg0: DmaAllocArgs;
    // The address the device uses.
    returns: uint64;
};

// Reply to the current caller and receive the next request in one operation.
//
// The primitive a resident server parks in. The buffer is symmetric: the reply
// is read out of it, then the next request is copied back into it, clamped to
// its length. The third step of the ring-3 driver host (build/README.md, D82).
@status(implemented)
@available(added = 1)
syscall ChannelReplyRecv = 25 {
    arg0: ChannelMsgArgs;
    // The endpoint being served.
    arg1: handle<Object, {READ}>;
    // The next request's length in bytes.
    returns: uint64;
};

// Re-enable the interrupt line of a device the caller drives.
//
// The re-arm half of the mask-on-deliver protocol (build/README.md, D84): the
// kernel masks a line when it delivers the event, and the driver unmasks it
// after acknowledging the device through its own mapped window. Arch-coupled,
// because the enable is an interrupt-controller register write.
@status(implemented)
@available(added = 1)
syscall IrqComplete = 26 {
    arg0: IrqCompleteArgs;
};

// Reply to the outstanding call on an endpoint and **keep running**.
//
// The reply a server woken by its *port* rather than by its endpoint must use.
// `ChannelReply` blocks the replier, which strands such a server for ever
// because nothing ever hands back (build/README.md, D85).
@status(implemented)
@available(added = 1)
syscall ChannelReplyContinue = 27 {
    arg0: ChannelMsgArgs;
    // The endpoint whose outstanding call is being answered.
    arg1: handle<Object, {WRITE}>;
};

// Ask what a device is, for a device the caller holds a capability to.
//
// Grants nothing: the answer is about a capability the caller can already name
// (build/README.md, D114).
@status(implemented)
@available(added = 1)
syscall DeviceInfo = 28 {
    arg0: DeviceInfoArgs;
};

// Record a driver-lifecycle transition for a device the caller drives.
//
// The kernel does not model the lifecycle — that is the device manager's job —
// but it will not record a history that contradicts itself: the transition is
// validated against the table of legal edges and against the state already
// recorded (build/README.md, D128).
@status(implemented)
@available(added = 1)
syscall DriverLifecycle = 29 {
    arg0: LifecycleTransitionArgs;
};

// Create a memory object: a range of zeroed anonymous pages, as a capability.
//
// The pages are **zeroed**, and that is a security property rather than
// hygiene: an object exists to be handed to somebody else, and a page arriving
// with whatever its last owner left would make every grant a disclosure. The
// out-of-line buffer primitive (build/README.md, D131).
@status(implemented)
@available(added = 1)
syscall MemoryCreate = 30 {
    arg0: MemoryCreateArgs;
    // A handle to the new object.
    returns: uint64;
};

// Map a memory object the caller holds into its own address space.
//
// **Mapping rights are separate from object rights.** A holder may map
// read-only something it holds writable, which is how a driver hands a client
// a buffer it must not scribble on. A request for more than the capability
// carries is refused rather than quietly reduced.
@status(implemented)
@available(added = 1)
syscall MemoryMap = 31 {
    arg0: MemoryMapArgs;
    // The base address the object was mapped at.
    returns: uint64;
};

// Make a memory object the caller holds reachable by a device it holds.
//
// Two capabilities, because it is an authority over both: the memory's owner
// says this may be exposed, and the device's driver says this device may reach
// it.
@status(implemented)
@available(added = 1)
syscall DmaAttach = 32 {
    arg0: DmaAttachArgs;
    // The address the device uses.
    returns: uint64;
};

// Stop a device reaching a memory object.
@status(implemented)
@available(added = 1)
syscall DmaDetach = 33 {
    arg0: DmaDetachArgs;
};

// Say a DMA lease is still wanted, and until when.
//
// A lease that is never renewed expires, which is what stops a departed
// driver's device from writing memory that has been handed to somebody else.
@status(implemented)
@available(added = 1)
syscall DmaRenew = 34 {
    arg0: DmaRenewArgs;
};

// Ask a bus controller's capability for one of the devices behind it.
//
// `Rights::DERIVE` is the authority to produce a capability *from* this one,
// held by a bus controller over the devices it enumerates. Deliberately not
// implied by holding the bus.
@status(implemented)
@available(added = 1)
syscall DeviceChild = 35 {
    arg0: DeviceChildArgs;
};

// Arm or disarm a device's interrupt as a system wakeup source.
//
// `Rights::WAKE` is separate from holding the device on purpose: otherwise the
// set of things able to wake this machine would be the driver table, which
// nobody chose and nobody can audit.
@status(implemented)
@available(added = 1)
syscall WakeSource = 36 {
    arg0: WakeSourceArgs;
};

// Take or release a wake hold, or read the system wake-event counter.
//
// A wake hold vetoes a suspend. The counter is what a suspend commits against,
// so that an event arriving during the sequence cannot be lost.
@status(implemented)
@available(added = 1)
syscall WakeHold = 37 {
    arg0: WakeHoldArgs;
};

// Commit the system to sleep, and return when it resumes.
//
// `Rights::SLEEP` is separate from `WAKE` because they are opposite
// authorities over the same machine: one says what may interrupt a sleeping
// system, the other stops it running at all.
@status(implemented)
@available(added = 1)
syscall SystemSuspend = 38 {
    arg0: SystemSuspendArgs;
};

// Verify a named firmware image from the system store, admit it against
// policy, and return it as a memory object.
//
// `Rights::FIRMWARE` is not implied by holding the device: firmware is code
// that runs on hardware outside the CPU's protection, so the set of components
// able to put it there is an explicit set rather than the driver table. It is
// narrowed away when the device is handed to a driver, which is what makes
// "the framework chooses the image" a rule the kernel enforces rather than a
// convention drivers observe.
@status(implemented)
@available(added = 1)
syscall FirmwareLoad = 39 {
    arg0: FirmwareLoadArgs;
    // A handle to the admitted image.
    returns: uint64;
};

// Put a memory object on a handling path.
//
// The class may rise and never fall; a request that would lower it is refused.
// A one-way ratchet, because content that has been handled as protected cannot
// be un-handled by whoever holds it next.
@status(implemented)
@available(added = 1)
syscall MemoryClassify = 40 {
    arg0: MemoryClassifyArgs;
};

// A bus controller says a device exists.
//
// The declared config slot and register window must lie inside what the bus
// covers and forwards, so a controller cannot conjure a device outside its own
// reach.
@status(implemented)
@available(added = 1)
syscall DeviceDeclare = 41 {
    arg0: DeviceDeclareArgs;
};

// Map this function's own configuration space.
//
// Exactly the slot recorded when the device was declared, so a driver holding
// one function of a multi-function device cannot reach the next one.
@status(implemented)
@available(added = 1)
syscall MapConfig = 42 {
    arg0: MapConfigArgs;
};

// Receive on **any** of several endpoints.
//
// What a server with more than one client needs. A blocking receive on one
// endpoint commits a server to that client until it speaks, so a server
// holding two would serve whichever spoke first and never hear the other.
// Polling is not an answer under a cooperative scheduler: a server that never
// blocks is a server no other thread runs behind.
//
// The index of the endpoint that answered is written back into the args, so
// the server knows where to reply.
@status(implemented)
@available(added = 1)
syscall ChannelRecvAny = 43 {
    arg0: ChannelMsgArgs;
    // When to give up, in monotonic nanoseconds on the `MONOTONIC` clock
    // (`ClockRead`, 53). **Zero is no deadline**, which is what every caller
    // written before this existed passes without knowing it — a register that
    // defaulted to "expire immediately" would have broken all of them.
    //
    // The bound is honoured at the next scheduling point rather than by an
    // alarm, so it is a deadline with tick-granularity slack: the kernel
    // notices it when the run loop next comes round, which the timer
    // guarantees happens (build/README.md, D282).
    arg1: uint64;
    // The message's length in bytes.
    returns: uint64;
};

// Raise a software edge on a port.
//
// **The first use of `Rights::SIGNAL`.** Every other signal a port carries
// comes from the machine, and the kernel raises it because it saw it happen.
// This one is raised by a driver that saw something the machine cannot report:
// a controller multiplexing eight lines onto one interrupt output knows which
// line fired, and nothing else does. Waking somebody is authority, so it is a
// right on a capability rather than a number anyone may pass — and the edge
// goes to the port named, on a source that port is already bound to.
@status(implemented)
@available(added = 1)
syscall PortSignal = 44 {
    // The port to signal.
    arg0: handle<Object, {SIGNAL}>;
    // The source to raise, which the port must already be bound to.
    arg1: uint64;
};

// Create a **service-backed** memory object.
//
// Its pages do not exist yet and are supplied by the named pager, which is why
// it is its own number rather than a flag on `MemoryCreate`: that one's
// contract is that it returns fully-backed memory or fails, and this one draws
// no frames.
@status(implemented)
@available(added = 1)
syscall MemoryCreatePaged = 45 {
    arg0: MemoryCreatePagedArgs;
    // A handle to the new object.
    returns: uint64;
};

// Map a service-backed object into the caller's space.
//
// The same arguments `MemoryMap` takes, and that is the whole distinction:
// `MemoryMap` produces an eagerly resident mapping whose faults are bugs, this
// produces one whose absent pages are page-in requests. A caller has to say
// which it wants because the two fail in opposite directions.
@status(implemented)
@available(added = 1)
syscall MapObject = 46 {
    arg0: MemoryMapArgs;
};

// Ask which of an object's pages are dirty.
//
// The dirty-range query `docs/kernel/03` promises pagers for coordinated
// flushing. A service asked to make a file durable has to know what changed,
// and after a write through a mapping the kernel is the only thing that does —
// no message reached the service at all.
@status(implemented)
@available(added = 1)
syscall MemoryDirtyPages = 47 {
    arg0: MemoryDirtyPagesArgs;
    // How many offsets were written back to the caller's vector.
    returns: uint64;
};

// The caller has persisted an object's page.
//
// The acknowledgment half of the ordering: the kernel never marks a page clean
// on its own, only when the thing that owns the backing store says the bytes
// are there.
@status(implemented)
@available(added = 1)
syscall PageWrittenBack = 48 {
    arg0: PageWrittenBackArgs;
};

// Hand a created, not-yet-started process a capability the caller holds.
//
// **What a child starts with becomes its parent's decision.** Every service in
// this tree got its handles from kernel boot glue reaching into its table,
// which is the kernel deciding what user space may reach; docs/api/01 has
// listed this operation since it was written and nothing implemented it
// (build/README.md, D42). It is what makes the capability model load-bearing
// rather than demonstrated: a program holds what its parent chose to give it,
// and the kernel seeds the root task and nothing else.
//
// One capability per call. A vector would install a set atomically and this
// ABI has been bitten by hand-decoded vectors before (D101) — the count is the
// only guard against a misparse, and the cost of one here is a child holding
// authority nobody named. A loop costs a syscall per handle at startup and
// makes each grant separately refusable and separately auditable.
//
// The kernel narrows and never expands, exactly as HandleDuplicate does, and
// only a process still in the created state may be granted to: once it is
// running, what it holds is its own business.
@status(implemented)
@available(added = 1)
syscall ProcessGrant = 50 {
    arg0: ProcessGrantArgs;
    // The handle the capability was installed at, in the child's table.
    returns: uint64;
};

// Wait for a process to terminate, and learn how.
//
// The other half of a start that does not block: a supervisor is a loop over
// launch, wait, decide, and until `ProcessStart` stopped waiting there was no
// wait to write because the start was one.
//
// A process that has already exited returns immediately — a wait that missed
// the exit and parked for ever would make every supervisor a race against its
// own child.
@status(implemented)
@available(added = 1)
syscall ProcessWait = 51 {
    arg0: ProcessWaitArgs;
    // The child's exit code, as a uint32 bit pattern zero-extended into the
    // result word: a code is an int32 and this ABI spells failure with the
    // sign, so a negative one returned directly would read as a kernel error.
    returns: uint64;
};

// Route a device's interrupts to a port the caller holds.
//
// **The last thing a driver host needed from the kernel that was not a
// capability.** A ring-3 driver could map its device (23), allocate its DMA
// (24) and re-arm its line (26), and still could not say where the interrupts
// were to go: every route in this tree was installed by boot glue on the
// driver's behalf. docs/api/01 has listed this operation as "bind interrupt
// object" since it was written and nothing implemented it (build/README.md,
// D255).
//
// `bind` on **both** capabilities. On the device it is the authority to direct
// its line, which a bus controller withholds from a function whose registers it
// is otherwise happy to hand over; on the port it is the same right PortBind
// checks, because this is a port bind and a device route that skipped it would
// be a way around it.
//
// The route belongs to the calling process and ends when it does, alongside its
// register windows and DMA leases.
@status(implemented)
@available(added = 1)
syscall DeviceIrqBind = 52 {
    arg0: DeviceIrqBindArgs;
    // The interrupt number the route was made for — the source a PortWait on
    // that port will report. A driver learns its own line here rather than
    // being told out of band.
    returns: uint64;
};

// Which clock `ClockRead` is asked for.
//
// **Two are named and one is answered.** They differ only across a suspend —
// monotonic stops, boot keeps counting — and nothing in this tree accounts for
// suspended time, so answering `BOOT` with the monotonic value would be right
// until the first machine that sleeps and silently wrong after. It is refused,
// and the value is reserved so the call does not change when the accounting
// exists (build/README.md, D281).
strict enum ClockId : uint64 {
    MONOTONIC = 1;
    BOOT = 2;
};

// Release a mapping.
//
// **Nothing could give a mapping back before this.** A program that mapped an
// object held it until the process died, so an address used once was used for
// ever — which a service that maps a different file per flush runs out of
// immediately. The mapping's own references to the frames are released; frames
// another mapping or the object still holds stay alive.
@status(implemented)
@available(added = 1)
syscall MemoryUnmap = 49 {
    // The mapping's base address.
    arg0: uint64;
    // Its length in bytes.
    arg1: uint64;
};

// Read a clock, in nanoseconds.
//
// **The slow path, and the only one there is yet.** `docs/api/01` describes a
// time *page* as the fast path — a read-only page mapped into every process
// behind a sequence counter, so reading time is loads rather than a trap. That
// is a separate mechanism with its own ABI struct and its own mapping story;
// this is the syscall beside it, and it is what a program with no time at all
// needs first.
//
// **No right.** Time is not a capability here: a process can already observe
// duration by doing work, and refusing to tell it the time only makes it worse
// at knowing how much passed. What a capability would gate is a *precise*
// clock, which matters for side-channel reasons this kernel has no story for —
// named so the absence is on the record rather than assumed away.
@status(implemented)
@available(added = 1)
syscall ClockRead = 53 {
    // Which clock. `BOOT` is defined and refused.
    arg0: ClockId;
    // Nanoseconds. Monotonic, and zero on a machine whose counter frequency
    // this kernel could not learn — a clock that is confidently wrong is worse
    // than one that says it does not know.
    returns: uint64;
};
