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

### Process And Thread

- Create process.
- Map memory objects into a created, not-yet-started process under
  `create-process` authority — the loader operation; user-space loaders
  populate a new process's address space before start.
- Install the initial handle set and startup message into a created process
  before start. This is the mechanism behind "capabilities received from
  parents" and the bootstrap channel installation in
  `kernel/04-synchronization-and-ipc-guarantees.md`.
- Start process.
- Exit process.
- Create and destroy additional address spaces within a process (JIT and
  plugin compartments per `kernel/02-scheduling-memory-ipc.md`).
- Create thread.
- Start thread.
- Exit thread.
- Set thread state under `write-state` authority.
- Read thread state for debugging under `read-state` authority.
- Suspend and resume under debugger authority.
- Wait for process or thread termination.

### Jobs And Resource Control

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

- Derive a narrowed security context from a held one.
- Assign a security context at process creation.
- Query the effective security context.

Contexts narrow and never widen, per
`kernel/05-jobs-containment-and-resource-control.md`; the derive operation is
the narrowing mechanism that document names.

### Memory

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

- Declare, modify, or release a reservation on a thread or job.
- Submit or update a pipeline descriptor.
- Query admission state and remaining domain bandwidth.
- Bind admission-revocation events to a port.

Reservations, admission tests, and deadline composition are defined in
`kernel/07-scheduler-admission-control.md`.

### Synchronization

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

- Read monotonic and boot clocks (slow path).
- Map the time page.

The time page is the fast path: a kernel-maintained, read-only page mapped
into every process at an ASLR-randomized address, carrying monotonic and
boot time behind a sequence-counter protocol, so reading time is loads, not
a syscall. The time page is ABI: its layout is a versioned ISL struct under
the monotonic extension rules. Wall-clock time, time zones, and secure time
remain service-owned per `kernel/01-kernel-model.md`.

### I/O Queues

- Create I/O queue.
- Submit operations.
- Read completions.
- Cancel operations.
- Share queue with authorized component.

### Device And Interrupt

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

- Enter system sleep: the final suspend commit, under power-manager
  authority, performing the wake-event counter comparison.
- Query the system wake-event counter.
- Acquire and release a wake hold, under a power-manager-granted capability.

Sleep sequencing, wake holds, and the lost-wakeup contract are defined in
`power/01-power-management.md`.

### Verified Programs

- Load and verify a program for an attach-point class, under the class
  capability.
- Create program map objects.
- Attach and detach a program at an attach point.
- Query program run statistics.

The program model, verifier guarantees, and attach points are defined in
`kernel/09-verified-programs.md`.

### Virtualization

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

- Register exception channel on thread, process, or job.
- Receive exception report.
- Resume (optionally with modified thread state), advance, terminate, or
  forward on exception.

Exception delivery and handler outcomes are defined in
`kernel/03-paging-faults-and-exceptions.md`.

### Randomness

- Fill buffer with cryptographically secure random bytes.

Always available after early boot, requires no capability. Kernel randomness and
seeding are defined in `kernel/03-paging-faults-and-exceptions.md`.

### Compatibility Assists

Gated to the compatibility profile and declared in component manifests:

- Clone address space as a copy-on-write snapshot.
- Set foreign syscall dispatch redirection for a thread.
- Direct interruption of a thread with masking semantics.
- Owner-death signaling for wait-on-address (robust futexes).

Rationale, scope, and non-goals are defined in
`api/04-linux-and-posix-compatibility.md`.

### Debugging And Observability

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

