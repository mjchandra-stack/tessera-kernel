<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# File I/O, Caching, And Swap

## Purpose

The storage stack is deeply designed at the bottom — the pager contract in
`../kernel/03-paging-faults-and-exceptions.md`, the native filesystem in
`01-native-cow-filesystem.md`, the driver contract in
`../drivers/02-storage-networking-usb-pcie.md` — but the path applications
actually take to their data was a five-word layer description. This document
defines the post-open data path, the caching model, direct I/O, the swap and
compression design, per-layer restart semantics, and the end-to-end
durability chain.

## Open And The Post-Open Data Path

Path resolution is the VFS service's job; the data path is not.

- `open` resolves through the VFS service (B14 budgets its two round trips)
  against the caller's filesystem view
  (`../kernel/05-jobs-containment-and-resource-control.md`). Permission and
  classification checks happen here, once.
- What `open` returns is direct authority: a handle to the file's
  pager-backed memory object and a channel (or shared I/O rings for
  high-rate use) to the owning filesystem service, scoped to that file.
  After open, the VFS service is out of the loop entirely — no per-read
  policy hop, which is what makes the budgets honest.
- Metadata operations that change the namespace (rename, unlink, mount
  changes) go back through VFS; operations on the open file (read, write,
  resize, sync) go directly to the filesystem service or through the
  mapped object.

## Caching Model

There is one cache: the kernel-held pages of pager-backed memory objects.

- Buffered reads are copies (or zero-copy maps, per sandbox policy) from
  the file's memory object; a miss is an ordinary resolvable fault served
  through the pager. Buffered writes dirty the same pages, subject to the
  dirty-throttling rules of `../kernel/03`.
- `mmap` and read/write are coherent by construction because they are the
  same pages — restating `01-native-cow-filesystem.md` as a stack-wide
  guarantee that applies to every filesystem service, not just the native
  one.
- Cached-hit reads are therefore memory-bound by design; no separate budget
  is needed because B14 (open) plus B8-class fault costs bound the miss
  path, and hits never leave user-visible memory.
- Readahead policy belongs to the filesystem service (it sees access
  patterns through page requests); the kernel supplies fault-pattern hints
  in the pager protocol rather than guessing on its own.

## Direct I/O

Databases and log-structured stores need to bypass the page cache and own
their queues:

- A filesystem service may grant an extent lease: a mapping from a file
  range to device extents, with an I/O queue bound directly to the block
  service (or, for exclusive volumes, the storage driver) scoped to those
  extents. The application submits reads and writes on its own queue —
  the io_uring-passthrough analog, but capability-scoped to leased extents
  rather than trusting offsets.
- Leases are revocable (`../kernel/06-capability-revocation.md`): truncate,
  CoW relocation, or snapshot of the range revokes or renegotiates the
  lease; a revoked lease fails fast, it never silently redirects writes.
- Coherency at the boundary is explicit: taking an extent lease flushes and
  invalidates the range's cached pages; page-cache access to a leased range
  faults until the lease drops. Mixed-mode access is a declared error, not
  an undefined behavior.

## Swap And Memory Compression

`../kernel/02-scheduling-memory-ipc.md` names compression and pageout;
this defines them.

- Compression is a kernel-internal memory tier — the first line of reclaim,
  no service dependency, exposed through the placement API as a tier so
  policy can size it per profile. Wearable and embedded profiles typically
  run compression-only with no disk swap at all.
- Disk swap, where a profile enables it, reuses the machinery that already
  exists instead of inventing a parallel path: anonymous pages selected for
  pageout are backed by the system swap pager, a storage-stack component
  bound to a volume-manager-provided swap extent, operating under the full
  pager contract — declared write-back reservation, dirty throttling,
  deadline supervision — so the reclaim path's deadlock analysis is the one
  already proven by `../prototypes/02-pager-pressure-harness.md`.
- Swap is always encrypted with a per-boot ephemeral key from the kernel
  CSPRNG, never persisted or wrapped — swapped pages are unreadable after
  reboot by construction, preserving the physical-access guarantees of
  `../security/01-security-model.md` that unencrypted swap would void.
- Class rules compose: secure memory pools are non-swappable (already
  normative); data classes may forbid disk swap while permitting
  compression; credentials and key material never reach either tier because
  they never leave secure pools.

## Failure And Restart Semantics Per Layer

- VFS service: open files hold direct handles, so a VFS crash affects only
  new opens — existing I/O, mapped pages, and dirty write-back continue
  untouched. Restart re-resolves namespaces; the strong guarantee is cheap
  and now stated.
- Filesystem service: pager death, fully specified in `../kernel/03` —
  faulted ranges, exact data-integrity events, supervised restart.
- Block service: in-flight operations complete with errors through their
  I/O queues' completion path; filesystem pagers observe failed write-backs
  through the existing pager error contract; devices rebind through the
  driver framework. The block service holds no dirty state of its own that
  can be lost silently (see durability chain below), which is what makes
  its restart survivable.
- Volume manager: crash affects volume configuration operations only;
  assembled volumes keep serving through the block service. On restart it
  re-reads volume metadata and verifies assembly before permitting
  configuration changes.

## The Durability Chain

Each layer's flush is only as good as the layer below it, so the chain is
stated end to end: a filesystem durability acknowledgment (intent-log write,
transaction commit) may propagate up only after the block service has
issued, and the device has acknowledged, the corresponding cache flush or
FUA write per the driver contract's declared semantics. The block service
may cache and reorder freely *between* barriers, but it never acknowledges a
flush it has not pushed to stable media. This composes the pager's
"acknowledged means durable" rule (`../kernel/03`), the intent log in
`01-native-cow-filesystem.md`, and the driver contract into one testable
property — and the crash-cut harness in `01-native-cow-filesystem.md`
"Testing" exercises the whole chain, not just the filesystem's slice of it.

## Network And Removable Filesystems

- Network filesystem services declare their consistency model in their
  manifest — close-to-open is the platform default assumption; anything
  weaker must be declared and is surfaced to policy (some data classes may
  refuse residence on weaker-consistency mounts). Pager deadlines for
  high-latency backends are per-pager policy, already supported by
  `../kernel/03`; a network filesystem sets deadlines matching its
  transport rather than inheriting local-disk expectations.
- Removable media: parsing is already treated as hostile input
  (`01-native-cow-filesystem.md`); policy is now stated too — automount is
  a per-profile consent decision through the permission broker, foreign
  volumes default to the User Private data class and are non-executable
  until policy says otherwise, and their filesystem services run in the
  tightest sandbox tier.

## Observability

Per-file and per-component cache hit ratios, fault and readahead
effectiveness, dirty and write-back rates, extent-lease grants and
revocations, swap and compression tier occupancy and throughput, durability
acknowledgment latency through the full chain, and per-layer restart events
are structured, consistent with
`../observability/01-debugging-monitoring-tracing-logging.md`.
