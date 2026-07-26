// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Mock implementation of the architecture porting layer for tier-1 host
//! tests: in-memory console, synthetic memory maps, an in-memory address
//! space, and a recording context switch. Architecture-independent kernel
//! code builds for the host against this crate instead of real hardware.
//!
//! As a porting-layer implementation it must satisfy the layer's
//! `unsafe fn` capability signatures (`AddressSpaceOps::activate`,
//! `ContextOps::init`/`switch`); on the host these perform no unsafe
//! operations, so the crate is `deny(unsafe_op_in_unsafe_fn)` (not
//! `deny(unsafe_code)`) and carries an unsafe-inventory entry recording
//! that its unsafe surface is inert.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 1")
//! Budget: none (test-only)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use tessera_karch::{
    AddressSpaceOps, ContextOps, CpuOps, EarlyConsole, FRAME_SIZE, FrameSource, KError, MemoryKind,
    MemoryRegion, PageFlags, PhysAddr, PhysFrame, UserContextOps, VirtAddr,
};

/// An `EarlyConsole` capturing everything written to it.
#[derive(Default)]
pub struct MockConsole {
    buf: Vec<u8>,
}

impl MockConsole {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Captured output as text (lossy — the console is a byte sink).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.buf).into_owned()
    }
}

impl EarlyConsole for MockConsole {
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
}

/// Builds a synthetic memory map from `(base, len, kind)` triples, sorted
/// by base as the boot contract requires.
pub fn synthetic_map(regions: &[(u64, u64, MemoryKind)]) -> Vec<MemoryRegion> {
    let mut map: Vec<MemoryRegion> = regions
        .iter()
        .map(|&(base, len, kind)| MemoryRegion {
            base: PhysAddr::new(base),
            len,
            kind,
        })
        .collect();
    map.sort_by_key(|r| r.base);
    map
}

/// A frame source over a synthetic contiguous physical range, for testing
/// the page-table walker and the kernel core's mapper against known frames.
/// Mirrors the boot allocator's bounded reclaim model (a free-list plus a
/// shared-reference table; an untracked frame has an implicit single
/// reference), so demand-paging / copy-on-write logic behaves the same on the
/// host as on target.
pub struct MockFrameSource {
    next: u64,
    end: u64,
    handed_out: usize,
    free_list: Vec<u64>,
    /// Reference counts for shared frames (>= 2); an absent frame is 1.
    refcounts: BTreeMap<u64, u32>,
}

impl MockFrameSource {
    /// A source of `count` frames starting at frame-aligned `base`.
    pub fn new(base: u64, count: u64) -> Self {
        Self {
            next: base,
            end: base + count * FRAME_SIZE,
            handed_out: 0,
            free_list: Vec::new(),
            refcounts: BTreeMap::new(),
        }
    }

    /// Frames handed out so far (new frames drawn from the range; reuse does
    /// not count).
    pub fn handed_out(&self) -> usize {
        self.handed_out
    }

    /// Frames currently available for reuse on the free-list.
    pub fn free_list_depth(&self) -> usize {
        self.free_list.len()
    }
}

impl FrameSource for MockFrameSource {
    fn alloc_frame(&mut self) -> Option<PhysFrame> {
        if let Some(base) = self.free_list.pop() {
            return PhysFrame::from_base(PhysAddr::new(base));
        }
        if self.next >= self.end {
            return None;
        }
        let frame = PhysFrame::from_base(PhysAddr::new(self.next))?;
        self.next += FRAME_SIZE;
        self.handed_out += 1;
        Some(frame)
    }

    fn retain_frame(&mut self, frame: PhysFrame) {
        let base = frame.base().as_u64();
        *self.refcounts.entry(base).or_insert(1) += 1;
    }

    fn free_frame(&mut self, frame: PhysFrame) {
        let base = frame.base().as_u64();
        match self.refcounts.get_mut(&base) {
            Some(count) => {
                *count -= 1;
                if *count <= 1 {
                    // Back to a single implicit reference: not reclaimed.
                    self.refcounts.remove(&base);
                }
            }
            // Last (implicit) reference: reclaim for reuse.
            None => self.free_list.push(base),
        }
    }
}

/// An in-memory address space recording `virt -> (phys, flags)` mappings.
/// It enforces the same alignment and write-XOR-execute rules and returns
/// the same [`KError`]s as a real port, so the kernel core's mapping logic
/// and every rejection path are exercised on the host.
pub struct MockAddressSpace {
    mappings: BTreeMap<u64, (u64, PageFlags)>,
    root: u64,
    active: bool,
}

impl MockAddressSpace {
    /// Number of live mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Whether the space holds no mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// The flags recorded for `virt`, if mapped.
    pub fn flags_at(&self, virt: VirtAddr) -> Option<PageFlags> {
        self.mappings.get(&virt.as_u64()).map(|&(_, flags)| flags)
    }

    /// Whether this space is currently the active one (last `activate`d).
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl AddressSpaceOps for MockAddressSpace {
    // The mock models no hardware split; this matches the x86-64 host the
    // tests were written against so their address choices stay meaningful.
    const USER_ADDRESS_MAX: u64 = 0x0000_8000_0000_0000;

    fn new(_alloc: &mut dyn FrameSource, _direct_map_base: u64) -> Result<Self, KError> {
        Ok(Self {
            mappings: BTreeMap::new(),
            root: FRAME_SIZE, // a nonzero stand-in root frame
            active: false,
        })
    }

    fn map(
        &mut self,
        virt: VirtAddr,
        frame: PhysFrame,
        flags: PageFlags,
        _alloc: &mut dyn FrameSource,
    ) -> Result<(), KError> {
        if !virt.is_aligned(FRAME_SIZE) {
            return Err(KError::Unaligned);
        }
        if flags.is_wx() {
            return Err(KError::WXViolation);
        }
        if self.mappings.contains_key(&virt.as_u64()) {
            return Err(KError::AlreadyMapped);
        }
        self.mappings
            .insert(virt.as_u64(), (frame.base().as_u64(), flags));
        Ok(())
    }

    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, KError> {
        let (phys, _) = self
            .mappings
            .remove(&virt.as_u64())
            .ok_or(KError::NotMapped)?;
        PhysFrame::from_base(PhysAddr::new(phys)).ok_or(KError::InvalidMapping)
    }

    fn zero_frame(&self, _frame: PhysFrame) {
        // Host mock: physical frames are not real memory here, nothing to do.
    }

    fn fill_frame(&self, _frame: PhysFrame, _byte: u8) {
        // Host mock: physical frames are not real memory here; a pager's page
        // content is boot-proven, not host-tested.
    }

    fn protect(&mut self, virt: VirtAddr, flags: PageFlags) -> Result<(), KError> {
        if flags.is_wx() {
            return Err(KError::WXViolation);
        }
        let entry = self
            .mappings
            .get_mut(&virt.as_u64())
            .ok_or(KError::NotMapped)?;
        entry.1 = flags;
        Ok(())
    }

    fn translate(&self, virt: VirtAddr) -> Option<(PhysFrame, PageFlags)> {
        let &(phys, flags) = self.mappings.get(&virt.as_u64())?;
        PhysFrame::from_base(PhysAddr::new(phys)).map(|frame| (frame, flags))
    }

    fn copy_frame(&self, _dst: PhysFrame, _src: PhysFrame) {
        // Host mock: physical frames are not real memory here, nothing to copy.
        // Copy-on-write logic (allocate, remap, drop the shared ref) is verified
        // structurally in host tests; the actual byte copy is boot-proven.
    }

    fn write_bytes_to_frame(&self, _frame: PhysFrame, _offset: usize, _src: &[u8]) {
        // Host mock: physical frames are not real memory here; the loader's byte
        // movement is boot-proven. The copy_in page-walk / offset logic that
        // calls this is verified structurally in host tests.
    }

    fn sync_instruction_cache(&self, _virt: VirtAddr, _len: u64) {
        // Host mock: these mappings are a `BTreeMap`, and nothing is ever
        // executed out of them.
    }

    // SAFETY: host mock — activation has no hardware effect and performs no
    // unsafe operation; the `unsafe fn` signature is required by the trait.
    unsafe fn activate(&self) {}

    fn root_phys(&self) -> PhysAddr {
        PhysAddr::new(self.root)
    }

    fn free_tables(&mut self, _alloc: &mut dyn FrameSource) {
        // Host mock: page tables are not modeled (mappings live in a flat
        // BTreeMap and `new` draws no table frames from the allocator), so
        // there are no table frames to reclaim. Leaf-frame reclaim is exercised
        // through the `teardown` unmap path; this is inert like `zero_frame`.
    }
}

/// Count of context switches performed through [`MockContextOps`], so
/// scheduler tests can assert a switch happened without a real stack swap.
static MOCK_SWITCHES: AtomicUsize = AtomicUsize::new(0);

/// A no-op context implementation for host scheduler tests. `switch` records
/// that it was called and returns immediately (a real switch would not
/// return until resumed), so tests drive the scheduler's *decision* logic
/// rather than an actual stack swap.
pub struct MockContextOps;

/// Opaque saved context for the mock: carries the thread's spawn argument so
/// tests can identify which thread a context belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MockContext {
    pub arg: usize,
}

/// Count of `prepare_resume` calls, so scheduler tests can assert the
/// address-space/kernel-stack resume hook fires on a switch.
static MOCK_PREPARE_RESUMES: AtomicUsize = AtomicUsize::new(0);

impl MockContextOps {
    /// Total switches performed so far this process.
    pub fn switch_count() -> usize {
        MOCK_SWITCHES.load(Ordering::Relaxed)
    }

    /// Resets the switch counter (call at the start of a test).
    pub fn reset_switch_count() {
        MOCK_SWITCHES.store(0, Ordering::Relaxed);
    }

    /// Total `prepare_resume` calls so far this process.
    pub fn prepare_resume_count() -> usize {
        MOCK_PREPARE_RESUMES.load(Ordering::Relaxed)
    }

    /// Resets the `prepare_resume` counter (call at the start of a test).
    pub fn reset_prepare_resume_count() {
        MOCK_PREPARE_RESUMES.store(0, Ordering::Relaxed);
    }
}

/// Host stand-in for per-CPU operations. The counter is a plain increment:
/// tests that time anything are measuring the host, not the target, so a
/// monotonic sequence is more useful than a real clock and cannot make a
/// test flaky.
pub struct MockCpu;

static MOCK_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl CpuOps for MockCpu {
    fn cpu_id() -> u32 {
        0
    }

    fn halt_until_interrupt() {}

    fn hw_random() -> Option<u64> {
        // No entropy source on the mock, and none invented: callers must
        // exercise their absent-entropy path.
        None
    }

    fn counter_serialized() -> u64 {
        MOCK_COUNTER.fetch_add(1, Ordering::Relaxed) as u64
    }

    fn counter_hz() -> Option<u64> {
        None
    }
}

impl ContextOps for MockContextOps {
    type Context = MockContext;

    fn empty() -> MockContext {
        MockContext { arg: 0 }
    }

    // SAFETY: host mock — records only the spawn argument; performs no
    // unsafe operation. The `unsafe fn` signature is required by the trait.
    unsafe fn init(
        _stack_top: VirtAddr,
        _entry: extern "C" fn(usize) -> !,
        arg: usize,
    ) -> MockContext {
        MockContext { arg }
    }

    // SAFETY: host mock — increments a counter and returns; performs no
    // stack swap and no unsafe operation. Signature required by the trait.
    unsafe fn switch(_prev: *mut MockContext, _next: *const MockContext) {
        MOCK_SWITCHES.fetch_add(1, Ordering::Relaxed);
    }

    // SAFETY: host mock — records the call; there is no per-CPU stack or CR3 to
    // program on the host. Signature and default overridden for test visibility.
    unsafe fn prepare_resume(_kernel_stack_top: VirtAddr, _space_root: Option<PhysAddr>) {
        MOCK_PREPARE_RESUMES.fetch_add(1, Ordering::Relaxed);
    }
}

impl UserContextOps for MockContextOps {
    // SAFETY: host mock — records only the spawn argument; there is no ring 3
    // on the host, so the user entry/stack are inert. Signature required by the
    // trait.
    unsafe fn init_user(
        _kstack_top: VirtAddr,
        _user_entry: VirtAddr,
        _user_stack_top: VirtAddr,
        arg: usize,
    ) -> MockContext {
        MockContext { arg }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_captures_writes() {
        let mut console = MockConsole::new();
        console.write_bytes(b"hello ");
        console.write_bytes(b"kernel");
        assert_eq!(console.text(), "hello kernel");
    }

    #[test]
    fn synthetic_map_is_sorted() {
        let map = synthetic_map(&[
            (0x100000, 0x1000, MemoryKind::Usable),
            (0x1000, 0x2000, MemoryKind::Reserved),
        ]);
        assert_eq!(map[0].base.as_u64(), 0x1000);
        assert_eq!(map[1].kind, MemoryKind::Usable);
    }
}
