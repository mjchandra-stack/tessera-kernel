<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Native Copy-On-Write Filesystem

## Purpose

`../drivers/02-storage-networking-usb-pcie.md` requires "a native
copy-on-write filesystem for system and user data" in one line, yet snapshots,
A/B updates, verified images, container layering, per-class encryption, and
protected deletion all lean on its specific semantics. This document is its
design. The filesystem is referred to here as the native filesystem; it runs
as a filesystem service in user space, above the block service, and reaches
the kernel only through the external pager contract in
`../kernel/03-paging-faults-and-exceptions.md` and standard I/O queues.

Per `../roadmap/01-sequencing-and-mvp.md`, it is developed in parallel with a
ported v0 filesystem and becomes the default when it wins in test, not by a
date.

## Design Position

- Copy-on-write everything: no metadata or data is overwritten in place;
  the only overwritten structure is the superblock ring.
- Always-consistent on disk: a crash at any point leaves the previous
  committed state; there is no journal replay for metadata.
- Everything checksummed: every metadata node and, by default, every data
  extent carries a checksum with an algorithm identifier, following the
  crypto-agility rule in `../security/02-cryptography-and-key-management.md`
  that no algorithm is implied by position.
- Data classification is a first-class attribute, not a bolt-on, because
  `../security/01-security-model.md` makes classification a property carried
  with data through storage.

## On-Disk Structures

- Superblock ring: N fixed slots written round-robin; each carries a
  monotonic generation number, the security version for anti-rollback
  binding (`../security/02-cryptography-and-key-management.md`
  "Anti-Rollback"), and root pointers. Mount selects the highest-generation
  slot that passes checksum.
- CoW B-trees, all node-checksummed, keyed by object ID:
  - Object tree: inodes, directory entries, extended attributes.
  - Extent tree: allocated extents with back-references for refcounting.
  - Free-space tree.
  - Subvolume and snapshot tree: roots, parentage, and per-subvolume flags.
- Extent-based data with optional transparent compression per file or class.
- All sizes and counts are 64-bit; limits are format constants recorded in
  the superblock, versioned under the monotonic extension rules.

## Transactions And Durability

- All mutations join a transaction group. Commit writes new tree nodes
  bottom-up, flushes, then advances the superblock ring. Default commit
  interval is periodic (order of a second) and adaptive under pressure.
- Synchronous durability (`fsync`, rename barriers, O_SYNC-equivalents) does
  not force a full transaction commit. A compact intent log records the
  operations and their data synchronously; on mount after crash, the intent
  log is replayed on top of the last committed tree. This is the mechanism
  behind the pager durability contract: a `writeback` acknowledgment per
  `../kernel/03-paging-faults-and-exceptions.md` means intent-logged or
  committed, exactly matching "persisted, or journaled such that it survives
  crash".
- The intent log is size-capped so that crash-recovery replay is bounded:
  replay completes within one second on R2-class hardware, keeping unclean
  mounts inside the boot budget rather than adding an unbounded tax.
- Ordering: the filesystem owns journal-versus-data ordering as
  `../kernel/03` assigns it; the intent log never acknowledges data whose
  extents are not themselves durable.

## Snapshots, Clones, And Layers

- Snapshot creation clones a subvolume root and bumps refcounts: O(1) in
  data, budgeted in `../architecture/03-performance-budgets.md` (B17).
- Snapshots are read-only; clones are writable subvolumes sharing extents
  via refcounts until diverged.
- A/B system updates (`../lifecycle/01-development-maintenance-update-model.md`)
  map to subvolumes: the update writes a new system subvolume; commit flips
  the boot selection; rollback flips back. Nothing is copied.
- Filesystem feature-set advancement is gated on update commit
  (`../lifecycle/03-boot-sequence-and-update-mechanics.md`): between first
  boot on a new slot and commit, the filesystem enables no feature the
  previous system cannot read, backing the
  backward-compatible-until-commit rule for shared user data.
- Container image layers (`../kernel/05-jobs-containment-and-resource-control.md`
  "Storage Composition For Images") are subvolumes: verified read-only base
  layers plus writable overlay subvolumes, with per-layer identity recorded
  for attestation.

## Verified Subvolumes

A subvolume may be sealed: its data extents are covered by a Merkle tree
whose root is signed and whose algorithm is identified per
`../security/02-cryptography-and-key-management.md`.

- Reads of a sealed subvolume verify hashes on the paging path before pages
  are supplied to consumers; verification failure is an integrity event and
  the read faults, never returning unverified data.
- Sealed subvolumes back the verified system images in
  `../drivers/02-storage-networking-usb-pcie.md` and the measured container
  layers; the signed root participates in attestation and boot measurement.

## Encryption And Key Domains

Encryption is structured as key domains aligned with data classes:

- A volume has a default key domain; directories and files may belong to
  stricter domains selected by their data classification (health, biometric,
  credentials get their own domains with the strongest binding).
- File names and extended attributes are encrypted within a domain, not just
  file contents.
- Keys are wrapped by the hardware-rooted hierarchy in
  `../security/02-cryptography-and-key-management.md`; domain keys for
  lock-evicted classes are dropped on lock and suspend, after which their
  extents are unreadable until unlock — implementing "Physical Access
  Protection" at the filesystem layer.
- The filesystem never sees raw wrapping keys; it holds capability handles to
  the key service and per-domain working keys in secure memory pools.

## Data Classification And Protected Deletion

- Every inode carries a data-class label; directories carry a default that
  new children inherit. The strongest applicable class governs, matching
  `../security/01-security-model.md`.
- The label selects the key domain, drives quota and audit attribution, and
  is surfaced to the VFS so IPC-level classification propagation starts at
  rest.
- Protected deletion is class-aware: classes with per-file or per-domain
  keys delete by key destruction (crypto-erase), followed by discard of the
  extents. Deletion behavior per class is a stated guarantee, not
  best-effort.

## Integrity, Scrub, And Repair

- Checksums detect corruption on every read; a background scrub walks trees
  and data on a schedule and after unclean shutdown.
- Single-device profiles duplicate metadata so tree corruption is repairable
  from the duplicate; data redundancy (mirroring, parity, multi-device) is a
  later profile, out of scope for v1 per the roadmap.
- Detected corruption emits structured integrity events with extent and file
  attribution, feeding the health service and the storage troubleshooting
  workflow in `../observability/01-debugging-monitoring-tracing-logging.md`.

## Pager Integration

- Every file is a memory object bound to the filesystem's pager; mapped and
  read/write paths share one page cache by construction.
- Dirty page write-back allocates new extents (CoW) at write-back time; the
  kernel's stable-page snapshot rule means the filesystem persists the
  snapshot without racing the mutator.
- The filesystem declares its write-back reservation and honors the dirty
  throttling contract in `../kernel/03-paging-faults-and-exceptions.md`
  "Write-Back Under Memory Pressure".

## Explicitly Deferred

Multi-device redundancy and RAID profiles, deduplication, and send/receive
replication are designed-for (the extent back-reference and subvolume
structures accommodate them) but deferred past v1. Compression ships when its
budget impact is measured, defaulting off on R3-class hardware. Host-managed
zoned storage is likewise designed-for — a CoW allocator that never
overwrites in place is naturally zone-append-friendly — but zone support is
deferred until a target profile demands it, stated here so it is a decision,
not an omission.

## Performance

The filesystem joins the normative budget suite
(`../architecture/03-performance-budgets.md`): B14 governs warm path
resolution through the VFS and filesystem services, B16 governs small-file
`fsync` through the intent log, and B17 governs snapshot creation. Regressions
gate releases like any other budget.

## Testing

Per `../lifecycle/02-build-and-test-infrastructure.md`:

- Crash consistency: a block-layer power-cut harness replays truncated write
  sequences and asserts the committed-state invariant at every cut point.
- On-disk parsers are fuzzed with corrupted and adversarial images; mounting
  untrusted removable media is exactly the threat model in
  `../security/01-security-model.md`, so the mount path is treated as a
  parser of malicious input.
- Pager-contract conformance runs against the same harness as the RAM-backed
  Stage 0 filesystem, so the contract, not the implementation, is what
  consumers depend on.
