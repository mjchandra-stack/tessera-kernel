<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Synchronization And IPC Guarantees

## Purpose

`kernel/02-scheduling-memory-ipc.md` introduces the synchronization and IPC
primitives at a high level and promises priority inheritance, bounded call
chains, and structured messaging. This document defines the object-level
contracts that make those promises implementable, and closes the gaps around
lock ownership, byte streams, flow control, naming, and peer death.

## Synchronization Primitives

### Wait-On-Address

The lowest-level primitive is futex-style wait and wake on a user-space address,
as listed in the syscall families. It carries no kernel-visible owner and is the
building block for uncontended user-space locks. It does not, by itself, support
priority inheritance.

### Owner-Aware Lock

Priority inheritance requires the kernel to know which thread holds a contended
lock. The kernel therefore provides an owner-aware lock convention:

- A lock word encodes the owning thread's identity.
- On contention, the waiter enters the kernel and names the owner.
- The kernel applies priority and deadline inheritance from the highest-priority
  waiter to the owner for the duration of the hold, then restores the owner's
  base parameters on release.
- Inheritance is transitive along the wait-for chain, bounded by the maximum
  chain depth enforced for service calls.

This convention is the mechanism behind the priority-inheritance guarantee in
`kernel/02`. Uncontended lock and unlock stay in user space; the kernel is
entered only on contention or wakeup.

### Higher-Level Primitives

The following are provided as thin, kernel-assisted objects so that ownership,
inheritance, and cross-process use are correct:

- Counting semaphore: signal and wait with a bounded count.
- Reader-writer lock: shared and exclusive modes with writer-preference policy
  and inheritance applied to the blocking writer or readers as configured.
- Barrier: N-party rendezvous with generation counting.
- Event and multi-wait: signalable and resettable events and wait-on-multiple as
  already defined in the syscall families.

User-space runtimes may implement additional constructs over wait-on-address,
but any construct that needs priority inheritance or cross-process semantics must
use the owner-aware lock rather than a bare address wait.

### Timeline Sync Objects

Device completion ordering — GPU work, codec output, camera frames — needs a
synchronization primitive that crosses processes and devices. The `sync`
object is a 64-bit monotonic timeline:

- Signal advances the timeline to a value, under the `signal` right. Devices
  signal through their driver host or through the fence-signaling kernel
  fast path in `../drivers/03-graphics-display-media-sensors-ai.md`; points
  never unsignal.
- Wait blocks until the timeline reaches a target value, with a deadline
  like every blocking call; point-reached can be bound to a port for
  reactor-style completion handling.
- Sync handles transfer over channels like any handle, which is the
  buffer-plus-acquire-point handoff the surface protocol
  (`../graphics/01-surface-and-presentation.md`) is built on, and the fence
  that coherency ownership transitions compose with in
  `../hardware/04-device-memory-and-unified-memory.md`.
- Forward progress is guaranteed by poisoning, not hope: on device reset or
  removal, every pending point in the affected range signals with a
  poisoned status carrying the error, so waiters wake with a diagnosis and
  never hang on a dead GPU. This is the mechanism behind the fence
  cancellation step in `../hardware/03-component-interaction-model.md` and
  the robustness contract in `../drivers/03`.
- There is no owner, so no priority inheritance; waiters use deadlines, and
  reserved pipelines account device latency through their pipeline
  descriptors (`07-scheduler-admission-control.md`).

### Priority Inversion Diagnostics

The scheduler tracks the wait-for graph across owner-aware locks and blocking
IPC calls. It emits a diagnostic event when a high-priority thread is blocked
beyond a policy threshold, naming the blocking owner and the chain. This backs
the "scheduler-visible dependency tracking" claim in `kernel/02`.

## IPC Guarantees

Channels, ports, shared-memory rings, and I/O queues are defined in `kernel/02`.
This section specifies the behavioral guarantees that were left open.

### Message Bounds

Every channel has explicit limits established at creation and queryable by both
ends:

- Maximum message size for inline data.
- Maximum out-of-line references per message.
- Maximum transferable handles per message.
- Maximum queued messages or queued bytes.

Messages exceeding a limit are rejected at send with a protocol error rather
than truncated. Kernel memory used by queued messages is attributed to the
sender until received, so a slow reader cannot cause unbounded charge against
the kernel or the receiver.

### Flow Control And Backpressure

- A send to a full channel either blocks until space is available, subject to
  the call's deadline, or returns a would-block result when the non-blocking
  flag is set.
- Ports report readiness edges so a reactor can drain without spinning.
- Shared-memory rings use their sequence numbers for producer/consumer flow
  control; the kernel mediates ownership transitions but does not copy payload.

Backpressure is always expressible. No primitive silently drops control-plane
messages. Data-plane paths may declare explicit drop policy where a real-time
contract prefers loss to latency, and such drops are counted.

### Peer Death And Disconnect

- Closing either endpoint of a channel raises a `peer-closed` signal on the
  other endpoint after all already-queued messages are drained.
- A waiter blocked in a call whose peer dies is woken with a peer-closed error.
- Ports deliver a peer-closed event for each bound source that goes away, so
  supervisors can reclaim state deterministically.

These signals are the basis for the failure-model cleanup described in
`architecture/01-system-architecture.md`.

### Ordering And Delivery

- Messages on a single channel are delivered in send order.
- Handle transfers are atomic with the message that carries them: either the
  receiver gets the message and all its handles, or neither.
- Call-with-response pairs a request and reply through a transaction ID so
  replies cannot be confused across concurrent calls on a shared channel.

### Synchronous Call Scheduling

Call-with-response is not merely send-then-wait; it has handoff semantics,
because the IPC budgets in `../architecture/03-performance-budgets.md` are
unreachable through the run queue:

- When a caller blocks in a call and the callee is ready to receive, the
  kernel switches directly to the callee on the same core without a run-queue
  round trip, and symmetrically on reply.
- The callee runs the request under the caller's effective priority or
  deadline for its duration — the IPC form of the inheritance rules above —
  so a service thread cannot stall a real-time caller behind background work.
- Synchronous call chains are depth-limited; the kernel counts nested
  synchronous calls per thread and fails a call exceeding the limit with a
  protocol error. The default limit is 8, settable per job downward by
  policy. This makes "bounded service call chains" in `kernel/02` concrete
  and keeps inheritance chains and deadlock analysis bounded.
- Asynchronous messaging is unaffected; handoff applies only to the blocking
  call form.

### Cross-Core Calls

Handoff is a same-core mechanism, and same-core is engineered to be the
common case: sharded services (`08-multicore-scalability.md`) bind a worker
per core and clients route to their local shard. When the callee nonetheless
runs on another core, the call takes the remote path: the request posts to
the target core's lock-free wakeup mailbox with the caller's priority or
deadline carried, and the caller blocks. There is no thread migration in
this design; the remote path is budgeted separately (B24 in
`../architecture/03-performance-budgets.md`), and callee migration will be
considered only if that budget proves unreachable. Services on budgeted
paths are expected to shard rather than lean on the remote path.

### Reply Delegation

A callee holding a pending transaction may transfer the reply obligation —
together with the request — to another component, which then replies
directly to the original caller. This removes the two extra hops a proxy
would otherwise add on exactly the multi-service paths this architecture
creates (VFS to filesystem service, compositor to GPU host).

- The reply obligation is kernel-tracked transaction state; transferring it
  is atomic with the forwarded message, and each transfer counts against the
  caller's synchronous chain depth.
- Priority and deadline inheritance follow the current holder of the
  obligation, so the thread actually doing the work is always the boosted
  one.
- Peer-death and cancellation semantics follow the obligation: if its
  holder dies, the caller is woken with a peer-closed error regardless of
  how many hops the request took.

### Cancellation Of Calls

Cancellation (explicit, deadline expiry, or cancellation token) has defined
semantics at every stage:

- Not yet received: the request is removed from the queue; the caller
  unblocks with a cancelled or deadline result; the callee never sees it.
- In progress: the caller unblocks immediately with the same result, and
  the transaction is marked cancelled. The server is not interrupted —
  cancellation is cooperative — but it can observe the mark via a per-call
  query and may subscribe a port to cancellation events for long-running
  requests. Servers holding reservations must check, since orphaned work
  consumes their admitted budget (`07-scheduler-admission-control.md`).
- A reply to a cancelled transaction is discarded, counted, and traced; it
  is not an error to the replying server.

### Out-Of-Line Memory Semantics

Out-of-line references are memory-object handles with an ownership mode
declared per field in the interface schema
(`../api/03-interface-schema-language.md`):

- Transfer: ownership moves; the sender's handle and mappings are gone on
  send, so post-send mutation is impossible by construction.
- Share: both sides hold the object; sender mutation is visible to the
  receiver; rights follow the transferred handle and the schema's declared
  minimum.
- Snapshot: the receiver gets a copy-on-write snapshot taken at send;
  sender mutation after send is never visible. This is the default for
  request payloads that must be validated exactly once.

Receivers that validate then use payload data must use transfer or snapshot
modes; validating shared memory is a time-of-check race by definition, and
the schema compiler warns on it.

### Data Classification Carriage

Classification is static where possible and labeled where not:

- The default carrier is the schema: fields carry data-class annotations
  (`../api/03-interface-schema-language.md`), and a channel provisioned by
  the namespace broker has a maximum class it may carry, checked at grant
  time per `../security/01-security-model.md`.
- For dynamically classified payloads (a generic media channel carrying a
  health-classified buffer), the message header and shared-ring descriptors
  carry an optional classification label. A label may only be stronger than
  the interface's static class, never weaker, and the strongest applicable
  class governs handling — the same rule as everywhere.
- Brokers and egress-relevant services read the label; a component that
  strips or downgrades a label is a policy violation with an audit event.

### Port Delivery Semantics

Ports cannot lose events and cannot overflow, by construction:

- Port storage is preallocated per binding: one slot per bound
  (source, signal) pair, allocated at bind time. There is no overflow case.
- Events coalesce per slot: multiple edges on the same source and signal
  before a drain collapse into one event carrying a pending count.
- A drain reads current state, so coalescing never hides state — an edge
  plus a level read is the contract that keeps reactors from hanging on a
  lost edge.

### Shared Endpoints And Concurrent Receivers

Multiple threads may receive on one channel endpoint. Each message is
delivered to exactly one receiver, in queue order at dequeue time; ordering
guarantees apply to the dequeue sequence, not to the completion order of
concurrent handlers, and fairness among receivers is unspecified. This is
supported but not the scaling pattern: per-core sharded channels remain the
recommendation of `08-multicore-scalability.md`, and shared endpoints on
budgeted paths must still meet their scaling budgets.

### Peer Credentials And Acting On Behalf

Every per-caller policy check in the system assumes a service can learn who
is calling; this is the mechanism, and it is kernel-attested, never claimed
in payload:

- A channel endpoint holder may query its peer's credentials: the security
  context identity (`05-jobs-containment-and-resource-control.md`) recorded
  by the kernel when the endpoint was created or transferred — component
  identity, user, security domain. Payload-carried identity claims are
  never authoritative.
- Call-with-response stamps the caller's security context identity on the
  request as kernel-provided metadata, so per-call checks on shared
  channels do not race endpoint transfers.
- Acting on behalf: a broker forwarding work attaches the originator's
  context as a transferred read-only `security_context` handle — an
  unforgeable reference, obtainable only from the originator or the kernel,
  revocable through scopes like any handle. A service evaluates policy
  against the on-behalf-of context when present and the direct peer
  otherwise; brokers performing authority checks with their own ambient
  context instead of the originator's is the confused-deputy bug, and the
  audit record of every policy decision names which context was evaluated
  so it is detectable.
- Reply delegation (`above`) composes: the obligation carries the original
  caller's stamped identity, so the final replier can check policy against
  the real requester.

### Asynchronous Deadline Metadata

The optional deadline in an async message header has defined meaning:

- On queues that declared a drop policy (data-plane, per the flow-control
  rules above), an expired undelivered message is dropped and counted.
- Elsewhere the message is delivered with an expired flag — control-plane
  messages are never silently discarded.
- Receivers in the deadline classes may use it as a scheduling input for
  pipeline stages (`07-scheduler-admission-control.md`); it is always
  visible to tracing.

## Byte-Stream Primitive

Channels are message-oriented. Some workloads and compatibility layers need an
ordered byte stream with no message framing. The kernel provides a stream object:

- Bidirectional or unidirectional ordered byte transport with bounded buffering.
- Backpressure and peer-closed semantics identical to channels.
- No handle transfer; streams carry bytes only.

Streams back POSIX pipes and stream sockets in the compatibility layers and give
native services a simple flow-controlled transport without hand-rolling framing
over rings.

## Naming And Rendezvous

A capability system needs a defined way for two components that do not share a
parent to obtain a first channel. The kernel provides the transport; naming is a
brokered service, but the bootstrap contract is fixed here.

### Bootstrap Channel

- Every component starts with a bootstrap channel to its namespace broker,
  installed by the component manager at start according to the manifest.
- The manifest declares which capabilities the component may request by name and
  which it offers. The broker resolves a requested name to a channel to the
  providing component, subject to policy, and returns it as a transferred handle.

### Resolution Rules

- Resolution is capability-mediated: a name resolves only if the requesting
  component's manifest and current policy permit it.
- Resolution is observable: each grant emits an audit event naming requester,
  provider, capability, and decision.
- There is no global ambient namespace. A name is meaningful only relative to a
  broker view assembled by policy, consistent with design principle two.

This makes the "components receive capabilities from parents or policy services"
statement in `architecture/01` concrete for the unrelated-peer case.

## Observability

Synchronization and IPC emit structured events:

- Lock contention, hold time, and inheritance activations.
- Priority-inversion warnings with the blocking chain.
- Channel queue depth, backpressure stalls, rejected oversize messages, and
  peer-closed transitions.
- Reply-obligation transfers, cancelled transactions, and discarded replies.
- Port coalescing counts, expired-message drops and expired deliveries.
- Classification labels observed and any label-downgrade violations.
- Namespace resolution grants and denials.

Payload contents are redacted by default; only metadata and sizes are traced
unless an authorized session opts in.
