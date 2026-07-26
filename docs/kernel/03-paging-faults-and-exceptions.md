<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Paging, Faults, And Exceptions

## Purpose

The kernel owns virtual memory mechanism, but filesystems, model stores, and
many memory objects are backed by user-space services. This document defines the
contracts that make demand paging, fault handling, and exception delivery work
across that boundary without pulling policy into the kernel.

These contracts are load-bearing: file-backed mapping, copy-on-write, reclaim,
guard pages, JIT compartments, and language-runtime isolation described in
`kernel/02-scheduling-memory-ipc.md` all depend on them.

## Fault Taxonomy

The kernel distinguishes several fault and exception sources and routes each to
a defined destination:

- Resolvable page fault: page is not present but the backing object can supply
  it. Routed to the object's pager.
- Protection fault: access violates the mapping's rights. Routed to the faulting
  thread's exception path.
- Guard-page fault: access hits a reserved guard region. Routed to the exception
  path with a distinct code.
- Synchronous CPU exception: illegal instruction, alignment, divide, floating
  point, or architecture trap. Routed to the exception path.
- Synchronous memory-error consumption: an uncorrectable memory error consumed
  by a load or instruction fetch. Routed to the consuming thread's exception
  path with a distinct code, after the memory-failure handling below.
- Asynchronous machine check or hardware error: routed to the platform error
  service and health service, not to the faulting thread.

## Memory Failure Handling

An uncorrectable memory error is a page event, not just a thread event:

- The affected physical frame is poisoned: removed from the allocator and
  never reallocated; every mapping of it is invalidated so subsequent access
  faults rather than consuming the error again.
- Only threads that synchronously consumed the error receive the exception.
  Processes that merely map the page receive an object-state signal, and
  access after invalidation faults as a memory-error code.
- For pager-backed pages, a clean copy is simply refetched through the normal
  page-in path on next access; a dirty page lost to poisoning is reported
  through the same data-integrity event as write-back loss on pager death.
- Every poisoning is recorded by the platform error service with the frame
  identity, and repeated failures feed the health service for predictive
  replacement.

## External Pager Protocol

A memory object may be kernel-backed or service-backed. A service-backed object
names a pager: a user-space component holding the object's backing store.

### Pager Object

A `pager` is a kernel object with rights `supply`, `writeback`, `evict`, and
`admin`. A service creates a pager, then creates one or more memory objects
bound to it. Mappings of those objects behave like any other mapping to their
users; the pager relationship is invisible to consumers.

### Page-In Flow

1. A thread faults on a resolvable, non-present page.
2. The kernel blocks the faulting thread and enqueues a page request on the
   pager's request port. The request carries object ID, page range, fault
   access type, and a correlation ID.
3. The pager supplies the page contents into the object through a `supply`
   operation referencing a memory object it already owns, transferring
   ownership of the physical pages to the target object.
4. The kernel installs the mapping and resumes the faulting thread.
5. If the pager returns an error or a deadline expires, the kernel delivers a
   fault error to the faulting thread's exception path and marks the object
   range faulted.

Page requests are bounded per object and per pager. A pager that does not
respond within policy deadlines is subject to supervision and restart; its
consumers observe faulted ranges rather than indefinite hangs.

### Write-Back And Eviction Flow

1. Under memory pressure, or on explicit flush, the kernel selects dirty pages
   from a pager-backed object.
2. The kernel issues a `writeback` request describing the dirty range and a
   snapshot of the page contents.
3. The pager persists the data and acknowledges. Only then may the kernel drop
   the clean copy.
4. For eviction of clean pages, the kernel may reclaim without consulting the
   pager and re-fault later.

Dirty tracking is maintained by the kernel using page-table dirty bits or
software emulation where hardware lacks them. The kernel exposes dirty-range
queries to pagers for coordinated flushing (for example, filesystem `fsync`).

### Ownership, Resize, And Revocation

- A memory object has an owner rights set separate from mapping rights.
- Objects support explicit resize and truncate. Truncation past a mapped range
  causes subsequent access to that range to fault as out-of-bounds.
- On pager death, bound objects transition to a faulted state. Existing clean
  mappings may continue to read cached pages until reclaimed; dirty data whose
  write-back had not completed is reported as lost through a data-integrity
  event. Consumers holding the object receive an object-state signal.

### Anti-Deadlock Rules

- A pager must not fault, in its own page-in handler, on an object it itself
  pages. The kernel detects self-paging cycles across pagers and breaks them by
  faulting the request rather than blocking.
- Pager request handling runs on memory that is resident and non-pageable
  (pinned working set declared at pager creation), so the paging path cannot
  recurse into paging.

### Write-Back Under Memory Pressure

Pinning the pager's working set is not enough: servicing a write-back itself
consumes memory (I/O descriptors, bounce buffers, network memory for a remote
filesystem), and pressure is precisely when that memory is scarce. Three rules
close the classic reclaim deadlock and unbounded-dirty problems:

- Write-back reservation: at pager creation, a pager declares a write-back
  reservation — memory guaranteed available to its write-back path, accounted
  against its resource domain and protected from reclaim like a
  `resource_domain` reservation in
  `05-jobs-containment-and-resource-control.md`. Allocations on the write-back
  path draw from the reservation when ordinary allocation would block on
  reclaim, so reclaim can always make forward progress.
- Dirty throttling: dirty pages against a pager-backed object are bounded per
  object and per resource domain. A producer that dirties faster than its
  pager writes back is throttled at the write fault, not at reclaim time, so
  one component cannot fill physical memory with unwritable dirty pages. The
  thresholds are policy; throttling events are emitted and attributed.
- Durability ordering: a `writeback` acknowledgment is a durability statement
  under the pager's declared contract (persisted, or journaled such that it
  survives crash). The kernel never marks a page clean before acknowledgment,
  and the page snapshot taken at write-back issue is stable — the snapshot,
  not a concurrently mutating page, is what the pager persists. `fsync`-style
  coordinated flush composes from dirty-range query, write-back issue, and
  acknowledgment await; ordering between a filesystem's journal commit and its
  data pages is the filesystem service's responsibility, and the kernel
  guarantees only that it never silently declares durability the pager has not
  acknowledged.

## Exception Delivery

Threads and processes can handle their own synchronous exceptions through
exception channels. This replaces ad hoc signal handlers with a typed,
capability-mediated mechanism.

### Exception Channels

- A thread, a process, or a job may register an exception channel. Registration
  requires the `exception` right over the target.
- On a synchronous exception, the kernel suspends the faulting thread and
  delivers an exception report to the most specific registered channel: thread,
  then process, then each enclosing job innermost first, then the debugger
  authority, then default policy.
- The report contains fault type, faulting address where applicable, a snapshot
  of relevant register state accessible under `read-state` rights, and a
  correlation ID.
- Exceptions taken by a vCPU are not delivered here: guest faults are VM exits
  delivered through the VM object's event model in
  `virtualization/01-virtualization-and-isolation.md`, and the handler for a
  VM is its virtual machine monitor.

### Handler Outcomes

The handler responds on the exception channel with one of:

- Resume: the fault was repaired (for example, a JIT compartment committed code
  or grew a stack guard region). The thread retries the faulting instruction.
- Resume with modified state: before retry, the handler rewrites the thread's
  general-purpose registers, program counter, and stack pointer under
  `write-state` rights (`../security/01-security-model.md` "Rights Catalog").
  Privileged and security-relevant state (privilege level, security domain,
  pointer-authentication and shadow-stack state) is never modifiable. This is
  the mechanism behind POSIX signal delivery in
  `../api/04-linux-and-posix-compatibility.md` and behind debugger
  continue-with-modified-state.
- Advance: skip the faulting instruction where the architecture reports the
  instruction length; where it does not, the outcome is rejected and the
  handler must use resume-with-modified-state instead.
- Terminate thread.
- Terminate process.
- Forward: pass the exception to the next handler in the chain.

If no handler resolves the exception, default policy captures a crash dump per
`observability/01-debugging-monitoring-tracing-logging.md` and terminates the
faulting component according to its restart policy.

### Handler Liveness And Delivery Guarantees

Exception handlers sit on a blocking path, so they carry the same kind of
liveness contract as pagers:

- A handler has a policy-set response deadline. On expiry the kernel emits a
  diagnostic event and forwards the report to the next handler in the chain,
  exactly as if the handler had responded Forward.
- Closing or death of a registered exception channel deregisters it; pending
  and future reports fall through to the next handler, using the peer-closed
  semantics of `04-synchronization-and-ipc-guarantees.md`.
- The delivery chain is bounded by the registration points (thread, process,
  enclosing jobs, debugger), capped by policy at a maximum chain length;
  default policy is always reachable and always resolves, so a faulting thread
  is never suspended indefinitely.
- Delivery cannot fail for resources: exception report storage is preallocated
  per thread, and outstanding reports are bounded by suspended faulting
  threads — exception channels are exempt from send-rejection, which is safe
  precisely because of that bound.

## Kernel-Internal Exceptions

Everything above concerns user-mode faults. The kernel's own exceptions have a
deliberately simpler policy: the kernel does not try to heal itself.

- User-copy helpers in the architecture port are the only kernel code
  permitted to fault on user memory; they return an error to the caller and
  never propagate the fault.
- Any other kernel-mode page fault, and any Rust panic in kernel code, is a
  kernel bug. Panic semantics are abort: no unwinding across the kernel, no
  recovery attempt.
- Kernel stacks carry guard pages; overflow traps to a dedicated per-CPU
  exception stack and panics with an identifiable cause rather than
  corrupting adjacent memory.
- A machine check in kernel context that cannot be attributed to a poisonable
  user frame is unrecoverable and panics with the hardware error record
  attached.
- The panic path runs on preallocated resources only: it captures the kernel
  panic dump defined in
  `../observability/01-debugging-monitoring-tracing-logging.md`, then hands
  control to the watchdog and recovery environment. Panics count toward the
  boot-failure and crash-loop rollback triggers in
  `../lifecycle/01-development-maintenance-update-model.md`.

### Relationship To Debugging

Debugger attach in `api/01-system-call-interface.md` is a privileged consumer of
the same exception mechanism. A debugger registers at the process or job level
with elevated rights. Production policy can forbid non-debugger exception
handlers for selected components while still allowing self-repair handlers such
as JIT and stack growth for others.

## Randomness And Memory Hardening

Security-first memory management requires primitives that were previously
implicit. The kernel provides them directly because their integrity cannot
depend on user-space policy.

### Kernel Randomness

- The kernel maintains a cryptographically secure random generator seeded from
  hardware RNG, boot-time entropy, and interrupt timing, reseeded continuously.
- A `random` syscall fills a buffer with CSPRNG output. It is always available,
  never blocks after early boot, and requires no capability.
- A seed handoff is provided to the entropy service, which owns higher-level
  policy such as pool health reporting and virtualized-guest reseeding. The
  virtual entropy device in `virtualization/01-virtualization-and-isolation.md`
  feeds guests through this path.

### Address Space Layout Randomization

- The kernel randomizes the base of executable images, shared libraries, stacks,
  the initial heap region, and default mapping placement.
- Randomization entropy is a per-architecture property exposed through the CPU
  feature model. Product profiles set minimum entropy requirements.
- Explicit fixed-address mappings require a distinct right and are logged, so
  compatibility layers can request them without weakening defaults.
- The kernel randomizes its own layout at boot (text, per-CPU regions, and
  major allocations) with the same per-architecture entropy discipline, and
  kernel text is immutable after boot: write-protected, with no runtime
  patching interface outside the measured verified-program translator in
  `09-verified-programs.md`.

### Write-XOR-Execute

- A mapping may not be simultaneously writable and executable. The kernel
  rejects such requests and rejects protection changes that would create the
  condition.
- Transitioning a region from writable to executable is an explicit,
  audited operation gated by a right, intended for JIT runtimes. The runtime
  writes into a writable alias, then flips a separate executable mapping.
- The transition performs the required instruction-cache coherence as part of
  the operation: data-cache clean and instruction-cache invalidation for the
  range, effective on every core, so freshly flipped code is executable
  everywhere without architecture-specific code in the runtime.
- Where hardware supports it, the kernel pairs W^X with shadow stacks,
  control-flow integrity, and memory tagging as declared in the security model.

### Live Code Modification

Runtimes that patch code already mapped executable (inline caches, tiered
compilation replacement) need coherence without a protection flip, and x86's
coherent instruction cache must not be baked into the ABI:

- An instruction-cache synchronization operation on a range of an executable
  mapping performs the architecture's data-cache clean and instruction-cache
  invalidation, including cross-core work where invalidation is per-core
  (per-hart `fence.i` on RISC-V). It requires the same right as the
  write-to-execute transition and is traced.
- A core-synchronizing barrier forces every core currently running the
  address space's threads through a context-serializing event before
  returning, so a patch-then-activate protocol (write alias, synchronize
  caches, barrier, publish the entry point) is sound on weakly ordered
  architectures with concurrent executors.

Both operations are memory-family syscalls in
`../api/01-system-call-interface.md`; runtimes built on them are portable
across coherent and non-coherent instruction-cache architectures by
construction.

## Observability

Paging and exception activity emits structured events:

- Page-in latency, write-back latency, and eviction counts per object and pager.
- Pager deadline misses and faulted ranges.
- Exception delivery, handler outcome, and forwarding chain depth.
- Handler deadline expiries and exception-channel deregistrations.
- Memory-error poisonings with frame identity and affected objects.
- State modifications through `write-state`, attributed to the modifying
  authority.
- W^X violations, fixed-mapping requests, and ASLR entropy at load.
- Write-to-execute transitions, instruction-cache synchronizations, and
  core-synchronizing barriers, attributed per component.

Sensitive page contents are never included in trace payloads. Secure and
protected memory pools additionally suppress address and content fields per
their classification.
