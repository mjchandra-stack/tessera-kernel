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
    /// Policy declined this specific artifact. The caller was entitled to ask,
    /// asked correctly, and named something that exists — and a rule about
    /// *what it named* said no: a firmware image below the system's rollback
    /// floor, or one older than the driver asking for it requires.
    ///
    /// **Appended rather than folded into `AccessDenied`**, which is about the
    /// caller. Somebody told "access denied" for a rollback-blocked image would
    /// go looking at their rights, where nothing is wrong; the fix is a
    /// different image, and no rights change will ever produce one. Distinct
    /// from `InvalidArgument` for the same reason in the other direction: the
    /// request was well formed and describes something that exists.
    ///
    /// *Which* policy declined does not get its own code. Every one of them
    /// recovers the same way — obtain a different artifact — and the reason
    /// travels in the operation's own report, where a caller that wants to
    /// explain the refusal can read it (the D128 argument for one lifecycle
    /// refusal rather than three).
    PolicyRefused = 16,
    /// An operation the kernel was holding a thread for did not complete
    /// within its deadline, and the kernel gave up on the caller's behalf.
    ///
    /// **Distinct from [`PeerClosed`](Self::PeerClosed), which it would
    /// otherwise be reported as.** A peer that closed is gone and retrying is
    /// pointless; a peer that missed a deadline is alive and may simply be
    /// slow, so a caller that could retry is told something it can act on. The
    /// one producer today is a page-in the object's pager never answered.
    TimedOut = 17,
    /// The kernel's answer does not fit the ABI result word: a success value
    /// with bit 63 set, which reaches user space as a negative number and is
    /// therefore this ABI's spelling of failure (see [`ENOSYS`] and
    /// `kcore::syscall::encode_result`).
    ///
    /// **Appended rather than reported as one of the codes above**, none of
    /// which is true: the caller was entitled to ask, asked correctly, named
    /// something that exists, and got a right answer the boundary could not
    /// carry. It is the one code here that describes the *kernel* rather than
    /// the request, and a caller told anything else would go looking at its
    /// own arguments, where nothing is wrong.
    ///
    /// It should be unreachable — every value a syscall returns today is a
    /// handle, a user VA, a count, or a rights mask, and all of them are far
    /// below the bound. This is what says so if that stops being true, and
    /// docs/api/01's "Monotonic Extension" permits exactly the change that
    /// would do it: a rights catalog that keeps adding bits reaches bit 63.
    ResultTooLarge = 18,
}

impl KError {
    /// The stable numeric code for this error.
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Which domain this error belongs to when it crosses the syscall
    /// boundary.
    pub const fn domain(self) -> ErrorDomain {
        match self {
            KError::AccessDenied => ErrorDomain::SecurityPolicy,
            KError::OutOfMemory | KError::LimitExceeded => ErrorDomain::Resource,
            KError::Protocol => ErrorDomain::Protocol,
            _ => ErrorDomain::Kernel,
        }
    }
}

/// The six stable, machine-readable error domains (docs/api/01 "Error Model").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum ErrorDomain {
    Kernel = 1,
    SecurityPolicy = 2,
    Resource = 3,
    Protocol = 4,
    Device = 5,
    Virtualization = 6,
}

/// The ABI result word for a failure: `-((domain << 16) | code)`.
///
/// Here rather than in `kcore::syscall` — which owns the *outcome* encoding
/// and can consult the event facility about a bad one — because a port sits
/// below `kcore` and cannot name anything in it, and a port that spells this
/// word for itself spells it differently. One did: the x86-64 trampoline's
/// pre-dispatch result was `-1`, which negates to domain 0 — not one of the
/// six, so not a decodable error at all.
pub const fn encode_error(error: KError) -> i64 {
    -(((error.domain() as i64) << 16) | error.code() as i64)
}

/// Result for a syscall number the kernel does not implement.
pub const ENOSYS: i64 = -((ErrorDomain::Kernel as i64) << 16);
