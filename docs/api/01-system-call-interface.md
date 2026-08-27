<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# System Call Interface

## Goals

The system call interface is the narrowest stable contract between user space
and the kernel. It must be:

- Stable for decades.
- Small enough to understand.
- Extensible without ABI traps.
- Efficient for common operations.
- Safe to validate.
- Easy to trace.
- Suitable for multiple language runtimes.
- Compatible with sandboxing and virtualization.

## Design Shape

The ABI is object-oriented around handles. System calls perform operations on
handles, create new handles, wait for events, map memory, and exchange messages.

The ABI avoids embedding high-level subsystem policy in the kernel. Filesystems,
networking policy, graphics policy, AI policy, and package management are
service protocols above the kernel ABI.

## System Call Families

**This section is design, and it describes calls that do not exist.** That is
its job: the shape of the surface has to be decided before it is built, and a
document that could only name what had been written would be a changelog. What
it lacked was any way to tell the two apart — about twenty families, none of
them marked, so a reader could not learn from it which calls they could make.

Each family therefore opens with a status, from a fixed vocabulary, and
`//tools/checks:surface_test` fails if one does not:

- **implemented** — every operation listed exists and a check exercises it.
- **partial** — some do. The bullets that do are named, by call number.
- **designed** — the shape is decided and nothing implements it.
- **deferred** — decided, and explicitly not being built; the deviation ledger
  says why.

**Where to look instead for what exists.** The generated reference —
`islc emit-docs api/isl/examples/syscall_abi.isl`, produced by
`tools/ci/docs.sh` — describes only the calls the kernel answers, with their
numbers, register frames, and required rights, and it is generated from the
schema rather than written, so it cannot fall behind. This document stays
normative and stays free to describe what does not exist yet; that one is the
reference. Reasoning about a gap lives in the deviation ledger, which both
link to rather than copy.

### Process And Thread

**Status: partial.** Create (8), map into a created process (9), grant a
capability into it (50), start (10), wait for it (51) and exit (5) exist, and a
compiled root task drives all six — it composes several children at once and
supervises one across restarts. Threads as objects, debugger authority, and
additional address spaces do not.

- Create process.
- Map memory objects into a created, not-yet-started process under
  `create-process` authority — the loader operation; user-space loaders
  populate a new process's address space before start.
- Install the initial handle set and startup message into a created process
  before start. This is the mechanism behind "capabilities received from
  parents" and the bootstrap channel installation in
  `kernel/04-synchronization-and-ipc-guarantees.md`. The handle half exists as
  `ProcessGrant` (50), one capability per call, narrowed by the same rule
  `HandleDuplicate` applies; the startup *message* does not, and a child is
  told where its capabilities landed through `ProcessStart`'s argument word.
- Start process. Returns as soon as the child is runnable; a parent that wants
  the exit code asks for it (`build/README.md`, D250).
- Exit process.
- Wait for process termination, and read the exit code.
- Create and destroy additional address spaces within a process (JIT and
  plugin compartments per `kernel/02-scheduling-memory-ipc.md`).
- Create thread.
- Start thread.
- Exit thread.
- Set thread state under `write-state` authority.
- Read thread state for debugging under `read-state` authority.
- Suspend and resume under debugger authority.
- Wait for **thread** termination. The process half exists as `ProcessWait`
  (51); a thread is not an object here yet, so there is nothing to name.

### Jobs And Resource Control

**Status: designed.** Nothing here is implemented; the kernel has no job
object. `create-process` authority is named by the process calls above without
a job to hold it.

- Create job.
- Set job policy.
- Suspend and resume job.
- Kill job.
- Create resource domain.
- Set resource limits and reservations.
- Bind resource domain to a job.
- Query job policy.
- Query accounting and enforcement state.

See `kernel/05-jobs-containment-and-resource-control.md`.

### Security Contexts

**Status: designed.** Rights narrowing exists on handles (2); security contexts
as their own derivable object do not.

- Derive a narrowed security context from a held one.
- Assign a security context at process creation.
- Query the effective security context.

Contexts narrow and never widen, per
`kernel/05-jobs-containment-and-resource-control.md`; the derive operation is
the narrowing mechanism that document names.

### Memory

**Status: partial.** Objects and mappings exist — create (30), map (31), unmap
(49), classify (40) — as does the whole external-pager path: create paged (45),
map object (46), serve (21), supply (22), dirty ranges (47), write-back
acknowledgment (48). DMA registration exists as attach (32), detach (33), and
renew (34). Protect, commit/decommit, resize, tiers and topology, placement
hints, migration, cache synchronization, coherency ownership, and PASID binding
do not.

- Create memory object.
- Map memory into a named address space (the primary by default).
- Unmap memory.
- Protect memory.
- Commit and decommit.
- Create shared memory.
- Create guarded region.
- Query memory state.
- Resize or truncate memory object.
- Query memory tiers and topology.
- Set placement hint or binding on an object or mapped range.
- Request migration of a range to a memory tier.
- Register DMA-capable memory with the correct authority.
- Synchronize instruction caches for a modified code range.
- Execute a core-synchronizing barrier across an address space's running
  threads.
- Create memory object from a named heap with placement constraints.
- Begin and end coherency ownership on a non-coherent attachment.
- Bind and unbind an address space to a device PASID under broker authority.
- Create pager and bind memory objects to it.
- Supply, write-back, and evict pages under pager authority.
- Query dirty ranges for coordinated flush.

Demand paging, write-back, and the external pager contract are defined in
`kernel/03-paging-faults-and-exceptions.md`. Mappings may not be simultaneously
writable and executable; the write-to-execute transition is a distinct audited
operation. Heaps, contiguity, coherency ownership, and PASID binding are
defined in `hardware/04-device-memory-and-unified-memory.md`.

### Handles And Capabilities

**Status: partial.** Duplicate (2), close (4), and query rights (3) exist, and
handles travel over channels inside a message's transfer vector. Replacing
rights in place, waiting on handle signals, and revocation scopes do not —
`ReplaceRightsArgs` is declared in `handle_abi.isl` with no call behind it.

- Duplicate handle with reduced rights.
- Transfer handle over channel.
- Close handle.
- Query handle rights.
- Replace handle rights with reduced set.
- Wait on handle signals.
- Create revocation scope or child scope.
- Duplicate or transfer handle into a revocation scope.
- Revoke a scope.

Revocation scopes and their guarantees are defined in
`kernel/06-capability-revocation.md`.

### IPC

**Status: partial.** Create channel (11) exists, and with it the message
operations — send (12), receive (13), call (14), and three replies for three
server shapes: reply (15), reply and continue (27), reply and receive (25) —
along with receive-on-any (43) and the port operations: create (16), bind (17),
wait (18), signal (44). Handles transfer with a message. A create hands back
two handles through a record the caller points at, because the result word
carries one value; that is what it was deferred on (`build/README.md`, D45,
D249). Reply-obligation forwarding, peer credentials, cancellation
subscription, and the byte-stream primitive do not exist.

- Create channel.
- Send message.
- Receive message.
- Call with request and response.
- Transfer reply obligation with a forwarded request.
- Query peer credentials on a channel endpoint.
- Query and subscribe to cancellation state of a received call.
- Transfer handles.
- Create event port.
- Bind handle signals to port.
- Cancel pending operation.
- Create byte stream endpoint.
- Read and write byte stream with backpressure.

Channel bounds, flow control, peer-death signaling, ordering guarantees, the
byte-stream primitive, and the namespace bootstrap are defined in
`kernel/04-synchronization-and-ipc-guarantees.md`.

### Scheduling And Admission

**Status: designed.** No reservation or admission call exists; the scheduler is
priority-driven with no admission test.

- Declare, modify, or release a reservation on a thread or job.
- Submit or update a pipeline descriptor.
- Query admission state and remaining domain bandwidth.
- Bind admission-revocation events to a port.

Reservations, admission tests, and deadline composition are defined in
`kernel/07-scheduler-admission-control.md`.

### Synchronization

**Status: partial.** Wait on address (6) and wake address (7) exist, keyed on
the physical memory so that processes sharing a page can wake each other
(`build/README.md`, D240). Owner-aware locks with priority inheritance,
semaphores, reader-writer locks, barriers, timeline objects, events, and timers
do not.

- Wait on address.
- Wake address.
- Acquire and release owner-aware lock with priority inheritance.
- Wait and signal on semaphore.
- Acquire and release reader-writer lock.
- Wait on barrier.
- Create timeline sync object.
- Signal a timeline point.
- Wait on a timeline point with deadline.
- Bind a timeline point to a port.
- Signal event.
- Reset event.
- Wait on multiple handles.
- Create timer.
- Arm timer.
- Cancel timer.

Owner-aware locks and the priority-inheritance mechanism are defined in
`kernel/04-synchronization-and-ipc-guarantees.md`.

### Time

**Status: designed.** Neither the clock calls nor the time page exists as a
syscall surface; the kernel's own clock is reached through `karch`.

- Read monotonic and boot clocks (slow path).
- Map the time page.

The time page is the fast path: a kernel-maintained, read-only page mapped
into every process at an ASLR-randomized address, carrying monotonic and
boot time behind a sequence-counter protocol, so reading time is loads, not
a syscall. The time page is ABI: its layout is a versioned ISL struct under
the monotonic extension rules. Wall-clock time, time zones, and secure time
remain service-owned per `kernel/01-kernel-model.md`.

### I/O Queues

**Status: designed.** Nothing implements a queue; the driver framework's
requests travel over channels.

- Create I/O queue.
- Submit operations.
- Read completions.
- Cancel operations.
- Share queue with authorized component.

### Device And Interrupt

**Status: partial.** A ring-3 driver can reach its hardware: map MMIO (23), map
its own configuration space (42), read and write registers through the
capability (19, 20), allocate DMA (24), ask what a device is (28), acknowledge
an interrupt (26), record a lifecycle transition (29), and — as a bus
controller — declare a device (41) and hand out a child capability (35).
Registering an interrupt as a wakeup source (36) exists. Interrupt affinity and
explicit DMA-mapping release under a broker do not.

- Open device object through device manager capability.
- Map and unmap MMIO under driver authority.
- Bind interrupt object.
- Acknowledge interrupt.
- Set interrupt affinity under controller capability
  (`kernel/08-multicore-scalability.md`).
- Register an interrupt object as a wakeup source under power-manager
  brokering (`power/01-power-management.md`).
- Request DMA mapping.
- Release DMA mapping.

Device-specific commands are not raw syscalls. They are typed driver protocols
over channels and I/O queues.

### Power

**Status: implemented.** All three exist: suspend commits with the wake-event
counter comparison (38), and wake holds and the counter are read and taken
through one call (37).

- Enter system sleep: the final suspend commit, under power-manager
  authority, performing the wake-event counter comparison.
- Query the system wake-event counter.
- Acquire and release a wake hold, under a power-manager-granted capability.

Sleep sequencing, wake holds, and the lost-wakeup contract are defined in
`power/01-power-management.md`.

### Verified Programs

**Status: designed.** No verifier, no attach points, no program objects.

- Load and verify a program for an attach-point class, under the class
  capability.
- Create program map objects.
- Attach and detach a program at an attach point.
- Query program run statistics.

The program model, verifier guarantees, and attach points are defined in
`kernel/09-verified-programs.md`.

### Virtualization

**Status: designed.** Nothing in the tree implements virtualization.

- Create VM.
- Create vCPU.
- Map guest memory.
- Run vCPU.
- Inject interrupt.
- Read or write virtual CPU state.
- Bind virtual device queue.
- Manage confidential memory where supported.
- Request VM attestation quote.
- Checkpoint or snapshot VM state.
- Migrate VM with dirty-tracking iteration.

VM attestation, checkpoint, and live migration are defined in
`virtualization/01-virtualization-and-isolation.md`.

### Faults And Exceptions

**Status: designed.** A ring-3 fault is contained by terminating the faulting
process (`build/README.md`, D23); exception channels and handler outcomes do
not exist.

- Register exception channel on thread, process, or job.
- Receive exception report.
- Resume (optionally with modified thread state), advance, terminate, or
  forward on exception.

Exception delivery and handler outcomes are defined in
`kernel/03-paging-faults-and-exceptions.md`.

### Randomness

**Status: designed.** The kernel CSPRNG has no syscall.

- Fill buffer with cryptographically secure random bytes.

Always available after early boot, requires no capability. Kernel randomness and
seeding are defined in `kernel/03-paging-faults-and-exceptions.md`.

### Compatibility Assists

**Status: designed.** None of these exist; the POSIX tier they serve is Stage 1
(`docs/roadmap/03`, Phase 4).

Gated to the compatibility profile and declared in component manifests:

- Clone address space as a copy-on-write snapshot.
- Set foreign syscall dispatch redirection for a thread.
- Direct interruption of a thread with masking semantics.
- Owner-death signaling for wait-on-address (robust futexes).

Rationale, scope, and non-goals are defined in
`api/04-linux-and-posix-compatibility.md`.

### Firmware

**Status: implemented.** Loading firmware into a device is one call (39): the
image is verified against the system store, admitted against policy, and
returned as a memory object.

- Load a named firmware image for a device, under `firmware` authority.

The store, its measurement, and the anti-rollback rule are defined in
`../security/02-cryptography-and-key-management.md`; the authority is a right
held by whatever mediates loading and narrowed away when the device is handed
to a driver, so a driver receives an image rather than requesting one.

### Debugging And Observability

**Status: partial.** Writing a validated buffer to the debug console (1)
exists. Nothing else here does — no debugger attach, no crash dump handles, no
trace sessions, no performance-counter handles.

- Write a validated buffer to the debug console.
- Attach debugger with authority.
- Read process metadata.
- Access crash dump handles.
- Register trace provider.
- Enable trace session under policy.
- Read performance counters through policy-controlled handles.

## ABI Rules

### Structured Arguments

All non-trivial arguments use structures with:

- `size`.
- `version`.
- `flags`.
- Reserved fields initialized to zero.
- Explicit pointer lengths.
- Explicit handle counts.

The kernel validates all sizes, flags, alignment, and reserved fields.

### Monotonic Extension

Extensions may:

- Add flags.
- Add optional trailing fields.
- Add new object methods.
- Add new object types.
- Add new rights bits.

Extensions may not:

- Change existing field meaning.
- Reuse removed flags.
- Change error semantics silently.
- Require old binaries to pass new fields.

### Error Model

Errors use stable numeric domains:

- Kernel errors.
- Security policy errors.
- Resource errors.
- Protocol errors.
- Device errors.
- Virtualization errors.

Errors are machine-readable and trace-decodable.

#### The Result Word

A syscall returns one signed 64-bit word, and its sign is what distinguishes
the two outcomes:

- **Success** is the word itself, read as a non-negative value: a new handle, a
  rights mask, a byte count, a user address, or zero.
- **Failure** is `-((domain << 16) | code)`, over the six domains above.

Two rules follow from spending the sign bit, and both bind every syscall rather
than any one of them:

- **A success value is at most 2^63 - 1.** A value with bit 63 set arrives in
  the caller intact and is read as a failure — in a domain and with a code
  taken from the value's own high bits — so it is not a lost result but a wrong
  one that looks well formed. The kernel refuses such a value instead of
  returning it, reporting the kernel-domain error `ResultTooLarge` and emitting
  `SYSCALL_RESULT_UNREPRESENTABLE`.

  This is a real constraint on extension, not a formality. "Monotonic
  Extension" above permits adding new rights bits, and a rights mask is
  returned as a success value; a rights catalog that grows to bit 63 collides
  with this rule.

- **Every negative word decodes to a defined domain and code.** A negative
  value that names no domain is not an error in this ABI, and a caller is
  entitled to treat one as a kernel defect rather than as a failure to report.

### Cancellation And Timeouts

Blocking calls support cancellation through:

- Deadline arguments.
- Cancellation tokens.
- Thread interruption under debugger authority.
- Object closure.

Long-running service operations should prefer asynchronous I/O queues.

## Compatibility Layers

Compatibility layers may emulate POSIX, Linux, Android, or other APIs above the
native ABI. They should not force the native ABI to inherit every legacy
semantic.

Compatibility layers run as ordinary components with the necessary authority and
policy constraints.

## Tracing

Every syscall emits traceable metadata when tracing is enabled:

- Syscall ID.
- Object type.
- Rights requested.
- Duration.
- Result code.
- Correlation ID.
- Security context.

Sensitive arguments are redacted by default.

