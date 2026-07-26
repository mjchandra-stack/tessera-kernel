// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The virtual-memory porting surface: architecture-neutral page
//! permissions, a physical-frame source the kernel core supplies to the
//! mapper, and the address-space operations each architecture implements.
//! The kernel core is generic over `AddressSpaceOps`, so page-table
//! mechanics never leak out of the architecture port.
//!
//! `PageFlags` is the neutral *request*; each port translates it to real
//! hardware PTE bits and is the single place that enforces write-XOR-execute
//! (docs/kernel/03-paging-faults-and-exceptions.md, "Write-XOR-Execute").
//!
//! Normative: docs/kernel/02-scheduling-memory-ipc.md ("Memory Model"),
//! docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (mapping paths are budgeted per-arch; see the port)

use crate::addr::{PhysAddr, PhysFrame, VirtAddr};
use crate::error::KError;

/// Architecture-neutral page permissions and caching intent. Compose with
/// the `read`/`write`/`execute`/`user`/`global`/`device` builders (each sets
/// one bit) or the `ro`/`rw`/`rx` shorthands; the port maps the result onto
/// its PTE bits. The type can express a writable+executable set on purpose,
/// so the write-XOR-execute rule is a checked runtime invariant (needed for
/// the eventual audited JIT W→X transition) rather than merely unconstructible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageFlags(u16);

impl PageFlags {
    const READ: u16 = 1 << 0;
    const WRITE: u16 = 1 << 1;
    const EXECUTE: u16 = 1 << 2;
    const USER: u16 = 1 << 3;
    const GLOBAL: u16 = 1 << 4;
    const DEVICE: u16 = 1 << 5;

    /// No permissions.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Adds read permission.
    pub const fn read(self) -> Self {
        Self(self.0 | Self::READ)
    }

    /// Adds write permission.
    pub const fn write(self) -> Self {
        Self(self.0 | Self::WRITE)
    }

    /// Adds execute permission.
    pub const fn execute(self) -> Self {
        Self(self.0 | Self::EXECUTE)
    }

    /// Read-only data.
    pub const fn ro() -> Self {
        Self::none().read()
    }

    /// Readable, writable data (never executable).
    pub const fn rw() -> Self {
        Self::none().read().write()
    }

    /// Readable, executable code (never writable).
    pub const fn rx() -> Self {
        Self::none().read().execute()
    }

    /// Marks the mapping accessible from user mode (CPL 3).
    pub const fn user(self) -> Self {
        Self(self.0 | Self::USER)
    }

    /// Marks the mapping global (not flushed on address-space switch);
    /// appropriate only for shared kernel mappings.
    pub const fn global(self) -> Self {
        Self(self.0 | Self::GLOBAL)
    }

    /// Marks the mapping as uncacheable device memory.
    pub const fn device(self) -> Self {
        Self(self.0 | Self::DEVICE)
    }

    pub const fn readable(self) -> bool {
        self.0 & Self::READ != 0
    }

    pub const fn writable(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    pub const fn executable(self) -> bool {
        self.0 & Self::EXECUTE != 0
    }

    pub const fn is_user(self) -> bool {
        self.0 & Self::USER != 0
    }

    pub const fn is_global(self) -> bool {
        self.0 & Self::GLOBAL != 0
    }

    pub const fn is_device(self) -> bool {
        self.0 & Self::DEVICE != 0
    }

    /// True iff the flags request a writable *and* executable page — the
    /// combination the write-XOR-execute invariant forbids. Every port
    /// checks this before installing a mapping.
    pub const fn is_wx(self) -> bool {
        self.writable() && self.executable()
    }
}

/// A source of physical frames for the page-table walker. The kernel core
/// supplies one (its frame allocator) so the architecture port never has to
/// know how physical memory is tracked. Allocation is fallible — exhaustion
/// returns `None`, never panics.
pub trait FrameSource {
    /// Hands out a fresh, exclusively-owned physical frame, or `None` when
    /// physical memory is exhausted.
    fn alloc_frame(&mut self) -> Option<PhysFrame>;

    /// Records one additional reference to `frame` — copy-on-write sharing. A
    /// frame handed out by [`alloc_frame`](Self::alloc_frame) starts with a
    /// single implicit reference; each `retain_frame` adds one. The frame is
    /// not reclaimed until every reference is released with
    /// [`free_frame`](Self::free_frame).
    ///
    /// Default: no-op, for init-only sources with no reclaim (the page-table
    /// walker's frames are never shared or freed).
    fn retain_frame(&mut self, _frame: PhysFrame) {}

    /// Releases one reference to `frame`. When the last reference drops, the
    /// frame returns to the source's free pool for reuse by a later
    /// [`alloc_frame`](Self::alloc_frame). Default: no-op — the frame leaks,
    /// acceptable only for init-only sources (deviation D15/D29).
    fn free_frame(&mut self, _frame: PhysFrame) {}
}

/// The per-architecture address space: a top-level page table plus the
/// operations to map, unmap, reprotect, and activate it. The kernel core's
/// `AddressSpace` object wraps a value of this type and layers the neutral
/// bookkeeping (mapping rights, ASID, active-core mask) on top.
///
/// Mapping operations mutate *this* address space's tables. Mutating the
/// table that is currently active on this CPU is the caller's
/// responsibility to sequence safely; a wrong mapping surfaces as a fault
/// when the space is active, not as Rust unsoundness — which is why only
/// [`activate`](AddressSpaceOps::activate) is `unsafe`. That operation
/// lives in the ports.
pub trait AddressSpaceOps: Sized {
    /// Exclusive upper bound of the user-accessible virtual range: every
    /// address at or above this belongs to the kernel and can never be a
    /// valid pointer in a syscall argument.
    ///
    /// This is a per-architecture property that only looks universal. On
    /// x86-64 it is where the canonical hole starts, and it moves with the
    /// paging depth — four levels put it at 2^47, five (LA57) at 2^56. On
    /// AArch64 it is `TTBR0`'s span, set by `TCR_EL1.T0SZ`, which a port
    /// chooses rather than inherits. RISC-V's Sv39 and Sv48 differ again.
    ///
    /// It lives here because `kcore` must reject a user pointer *before*
    /// dereferencing it and cannot know where the boundary is; a constant in
    /// the core would be one architecture's number silently applied to all of
    /// them.
    const USER_ADDRESS_MAX: u64;

    /// Builds a fresh, empty address space (a zeroed top-level table),
    /// drawing table frames from `alloc`. `direct_map_base` is the virtual
    /// base at which the port may reach physical frames to edit tables.
    fn new(alloc: &mut dyn FrameSource, direct_map_base: u64) -> Result<Self, KError>;

    /// Maps `virt` (page-aligned) to `frame` with `flags`, allocating any
    /// missing intermediate tables from `alloc`. Rejects writable+executable
    /// requests with [`KError::WXViolation`] and an already-mapped target
    /// with [`KError::AlreadyMapped`].
    fn map(
        &mut self,
        virt: VirtAddr,
        frame: PhysFrame,
        flags: PageFlags,
        alloc: &mut dyn FrameSource,
    ) -> Result<(), KError>;

    /// Removes the mapping at `virt`, returning the frame it referenced, or
    /// [`KError::NotMapped`] if none exists.
    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, KError>;

    /// Zeroes the contents of `frame` through the port's direct physical
    /// map, so anonymous memory is handed out zero-filled rather than
    /// leaking a previous owner's bytes. The caller must own `frame`
    /// exclusively.
    fn zero_frame(&self, frame: PhysFrame);

    /// Fills every byte of `frame` with `byte` through the port's direct
    /// physical map — how an (in-kernel) pager produces a supplied page's
    /// contents before it is installed. The caller must own `frame`
    /// exclusively.
    fn fill_frame(&self, frame: PhysFrame, byte: u8);

    /// Changes the permissions of an existing mapping. Rejects a
    /// writable+executable result with [`KError::WXViolation`] and a missing
    /// mapping with [`KError::NotMapped`].
    fn protect(&mut self, virt: VirtAddr, flags: PageFlags) -> Result<(), KError>;

    /// Returns the frame `virt` maps to and its permissions, or `None` if the
    /// page is not present. The fault path uses this to classify a fault
    /// (present read-only page + write access → copy-on-write) and to find the
    /// source frame to copy. Reads hardware page-table state, so it reflects
    /// exactly what the CPU sees.
    fn translate(&self, virt: VirtAddr) -> Option<(PhysFrame, PageFlags)>;

    /// Copies the full contents of `src` into `dst` through the port's direct
    /// physical map — the copy-on-write step. Both frames must be owned by the
    /// caller (`dst` freshly allocated, `src` the shared page being forked).
    fn copy_frame(&self, dst: PhysFrame, src: PhysFrame);

    /// Writes `src` into `frame` at `offset` through the port's direct physical
    /// map — how a user-space loader populates a *not-yet-active* child address
    /// space's freshly-allocated frame without switching CR3
    /// (docs/api/01-system-call-interface.md, "the loader operation"). The
    /// caller must own `frame` exclusively and guarantee `offset + src.len() <=`
    /// the frame size; a shorter `src` leaves the tail (already zeroed by
    /// [`zero_frame`](Self::zero_frame)) untouched.
    fn write_bytes_to_frame(&self, frame: PhysFrame, offset: usize, src: &[u8]);

    /// Publishes bytes just written through a data mapping to the instruction
    /// stream, for `[virt, virt + len)` of *this* address space.
    ///
    /// Every path that produces executable memory writes it as data first:
    /// the ELF loader populating a text segment, copy-on-write duplicating a
    /// shared code page, an external pager supplying one. On x86-64 the
    /// instruction cache is coherent with those writes and this is nothing.
    /// On weakly ordered architectures it is not, and the bytes must be
    /// cleaned to the point of unification and the instruction cache
    /// invalidated before a fetch will see them — otherwise stale
    /// instructions execute, which surfaces as a crash nowhere near the
    /// write.
    ///
    /// `docs/kernel/03-paging-faults-and-exceptions.md` requires exactly this
    /// operation and states why it must exist at the interface: *"x86-64's
    /// coherent instruction cache must not be baked into the ABI"*.
    ///
    /// Deliberately **not** defaulted. A default no-op would be correct on
    /// x86-64 and silently wrong on every other architecture, which is the
    /// shape of bug this whole layer exists to make impossible — so each port
    /// states its answer, including the ports whose answer is "nothing".
    fn sync_instruction_cache(&self, virt: VirtAddr, len: u64);

    /// Installs this address space as the active one on the current CPU.
    ///
    /// # Safety
    ///
    /// The space must map the currently executing code, the active stack,
    /// and any data touched before the next switch, all at their current
    /// virtual addresses; otherwise the CPU faults immediately after the
    /// switch.
    unsafe fn activate(&self);

    /// Physical address of the top-level page table (the value loaded into
    /// the architecture's page-table base register).
    fn root_phys(&self) -> PhysAddr;

    /// Frees every page-table frame this space *uniquely owns* — the top-level
    /// table and all lower-half (user) intermediate tables — back to `alloc`,
    /// leaving the shared higher-half kernel tables (copied in at creation)
    /// untouched. This is the page-table half of process teardown
    /// (docs/kernel/05, deterministic reclaim); the caller must first unmap
    /// every leaf mapping (freeing the leaf frames), and the space must never
    /// be used again after this returns. Like `map`/`unmap` it is safe: a wrong
    /// free surfaces as a fault when a *reused* frame is later mis-mapped, not
    /// as Rust unsoundness.
    fn free_tables(&mut self, alloc: &mut dyn FrameSource);
}
