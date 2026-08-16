// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel error domain seed. Errors are stable numeric values, never
//! strings parsed by callers (docs/lifecycle/04-coding-guidelines.md,
//! "Errors As Values"). This small set grows into the full domains of
//! docs/api/01 as the syscall surface lands; the discriminants are stable
//! and must never be renumbered.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Failure Discipline")
//! Budget: none (type definitions only)

/// A kernel-internal error. Discriminants are the stable wire values for
/// this domain; append new variants, never renumber existing ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum KError {
    /// A required allocation (frame, page table, or object) failed.
    OutOfMemory = 1,
    /// An address or length was not correctly aligned for the operation.
    Unaligned = 2,
    /// The mapping would be simultaneously writable and executable, which
    /// the write-XOR-execute invariant forbids
    /// (docs/kernel/03-paging-faults-and-exceptions.md).
    WXViolation = 3,
    /// A mapping already exists at the target address.
    AlreadyMapped = 4,
    /// No mapping exists at the target address.
    NotMapped = 5,
    /// The requested mapping is otherwise invalid (e.g. non-canonical
    /// address, or an empty flag set).
    InvalidMapping = 6,
    /// A handle value is invalid, stale, or not present in the table (kernel
    /// domain).
    BadHandle = 7,
    /// A rights check failed — the operation requires rights the handle does
    /// not carry, or would expand rights (security-policy domain)
    /// (docs/security/01-security-model.md, "Rights Catalog").
    AccessDenied = 8,
    /// The object is not of the type the operation requires.
    WrongType = 9,
    /// A message-protocol rule was violated — an oversize message, or a
    /// synchronous call chain past the depth limit (protocol domain)
    /// (docs/kernel/04-synchronization-and-ipc-guarantees.md).
    Protocol = 10,
    /// The operation could not complete without blocking and the caller asked
    /// not to block — a normal *result*, not a fault (a full send queue or an
    /// empty receive queue under the non-blocking flag).
    WouldBlock = 11,
    /// The channel peer endpoint has closed; a blocked caller is woken with
    /// this once all already-queued messages are drained.
    PeerClosed = 12,
    /// A policy limit was exceeded — a resource ceiling (e.g. a job's member
    /// count) rejects the offending create rather than degrading the system
    /// (docs/kernel/05-jobs-containment-and-resource-control.md). A resource
    /// domain error, distinct from `OutOfMemory` (a physically full pool).
    LimitExceeded = 13,
    /// The operation is meaningful but this system cannot perform it: a device
    /// reset on a port with no resetter, a DMA scoping request on a machine
    /// with no IOMMU that had one recorded.
    ///
    /// Distinct from `AccessDenied` (you may not) and from `Protocol` (you
    /// asked wrongly): the caller was entitled to ask and asked correctly, and
    /// the answer is that the mechanism is absent here. Collapsing it into
    /// either would tell a caller to change something that is not the problem
    /// — and, worse, would let a missing mechanism read as a working one that
    /// declined, which is the silent degradation `docs/lifecycle/04` forbids.
    NotSupported = 14,
    /// The arguments describe something that cannot exist: a device made its
    /// own parent, a topology edge that closes a cycle.
    ///
    /// **Appended, rather than folded into `Protocol`.** That one is documented
    /// as a *message*-protocol violation — an oversize payload, a call chain
    /// past its depth — and a caller told "protocol" about a resource-graph
    /// edge would go looking at its message encoding. Distinct from `BadHandle`
    /// (the object named is not there) too, and the difference matters: an
    /// absent parent is a race with a removal and worth retrying, while a cycle
    /// is a caller that will produce the same request forever.
    InvalidArgument = 15,
}

impl KError {
    /// The stable numeric code for this error.
    pub const fn code(self) -> u16 {
        self as u16
    }
}
