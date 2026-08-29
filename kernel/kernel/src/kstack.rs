// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Kernel-stack windows and ASIDs for the checks that run ring 3.
//!
//! Every ring-3 or kernel demo thread maps its kernel stack into the shared boot
//! `kernel_vm` and tags its space with an `Asid`; these hand both out (D53) so no
//! check picks its own window and collides with another's. The `LoaderSupport`
//! impl is here because it is the seam that consumes them.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// --- Demo kernel-stack-window + ASID allocators --------------------------------
//
// Every ring-3/kernel demo thread maps its kernel stack into the shared boot
// `kernel_vm`, and tags its address space with an `Asid`. Rather than hand-pick a
// unique `0xffff_c000_XXXX_0000` window and a unique `Asid(n)` per demo (which
// collided as `AlreadyMapped` when two overlapped — see the module notes), threads
// draw both from these monotonic allocators, so windows and tags are unique by
// construction. This is demo-harness scaffolding: a real kernel allocates thread
// stacks per-process via the VMA/frame machinery, not from one shared window pool.

/// Base of the kstack-window region, chosen well ABOVE every historical
/// hand-picked window (which topped out near `…f800_0000`) so nothing collides.
/// Same higher-half PML4 slot as `KERNEL_VMAP_BASE`, with vast room; `map_anonymous`
/// imposes no upper bound and the arch mapper creates intermediate tables lazily.
pub(crate) const KSTACK_ALLOC_BASE: u64 = 0xffff_c008_0000_0000;
/// Per-window stride. The stack maps at the slot base; the slack above it is an
/// unmapped guard gap. 2 MiB is ≥15× the largest (32-page = 128 KiB) demo stack.
pub(crate) const KSTACK_WINDOW_SLOT: u64 = 0x0020_0000;
pub(crate) static KSTACK_NEXT: AtomicU64 = AtomicU64::new(KSTACK_ALLOC_BASE);
/// Next opaque address-space tag. `Asid(0)` is the boot `kernel_vm`.
pub(crate) static ASID_NEXT: AtomicU16 = AtomicU16::new(1);

/// Reserves the next unique kernel-stack window in the shared `kernel_vm` and
/// returns its base VA (the caller's `spawn_user`/`map_anonymous` maps `pages`
/// there). Provably infallible for a boot — at most a few dozen windows are drawn
/// from a 64-TiB region — so it returns a bare `VirtAddr`; the `assert!` catches a
/// stack that would overrun its slot (a build-time invariant, like the mapper
/// self-check), not a fallible allocation.
pub(crate) fn alloc_kstack(pages: u64) -> VirtAddr {
    assert!(
        pages * FRAME_SIZE <= KSTACK_WINDOW_SLOT,
        "kstack of {pages} pages exceeds the {KSTACK_WINDOW_SLOT:#x}-byte window slot"
    );
    VirtAddr::new(KSTACK_NEXT.fetch_add(KSTACK_WINDOW_SLOT, Ordering::Relaxed))
}

/// Reserves a contiguous block of `slots` kstack windows and returns its base VA
/// as a `u64`. The strided demos (perf, jobs) index `base + i * KSTACK_WINDOW_SLOT`
/// into the block, so slot `i` maps to one stable window regardless of how often
/// it is recomputed — the same deterministic per-slot mapping the old hand-picked
/// `BASE + i*STRIDE` gave, just drawn from the allocator.
pub(crate) fn reserve_kstack_block(slots: u64) -> u64 {
    KSTACK_NEXT.fetch_add(slots * KSTACK_WINDOW_SLOT, Ordering::Relaxed)
}

/// Allocates the next monotonic address-space tag. The value is opaque — it is
/// never programmed as a hardware PCID (CR3 carries only the page-table root), so
/// a never-reused counter is sufficient; uniqueness-among-live-spaces is all that
/// would matter if PCID tagging is introduced later.
pub(crate) fn alloc_asid() -> Asid {
    Asid(ASID_NEXT.fetch_add(1, Ordering::Relaxed))
}

// Kernel-stack windows for the children a root task starts.
//
// **A pool, because there is more than one child now.** This used to be ONE
// memoized window: a relaunched child re-mapped the same VA, which kept a
// restart loop from leaking a window per launch and was safe because
// "supervision is synchronous — one child alive at a time". A `ProcessStart`
// that no longer waits ends that (build/README.md, D250): two children exist at
// once, and the second `spawn_user` mapped a window the first was standing on.
//
// A window is taken at start and given back when the child is reclaimed, so a
// supervisor restarting a service a hundred times still uses one — the property
// the memoization was there for — while concurrent children get distinct ones.
// Exhaustion is refused rather than shared: two threads on one kernel stack is
// not a resource shortage, it is corruption.
pub(crate) const MAX_LIVE_CHILDREN: usize = 4;
pub(crate) static CHILD_KSTACKS: [AtomicU64; MAX_LIVE_CHILDREN] =
    [const { AtomicU64::new(0) }; MAX_LIVE_CHILDREN];
pub(crate) static CHILD_KSTACK_BUSY: [AtomicBool; MAX_LIVE_CHILDREN] =
    [const { AtomicBool::new(false) }; MAX_LIVE_CHILDREN];

/// Takes a kernel-stack window for a child about to start, or `None` when every
/// one is in use.
pub(crate) fn take_child_kstack() -> Option<u64> {
    for (slot, busy) in CHILD_KSTACK_BUSY.iter().enumerate() {
        if busy.swap(true, Ordering::Relaxed) {
            continue;
        }
        // Allocated on first use, so a boot that starts no child spends no
        // address space on windows it will never map.
        let window = match CHILD_KSTACKS[slot].load(Ordering::Relaxed) {
            0 => {
                let w = alloc_kstack(USER_KSTACK_PAGES).as_u64();
                CHILD_KSTACKS[slot].store(w, Ordering::Relaxed);
                w
            }
            w => w,
        };
        return Some(window);
    }
    None
}

/// What this port lends `kcore::loader`.
///
/// **Everything on it is genuinely this port's.** A fresh user address space is
/// built by `new_user`, an inherent method on this port's page tables whose
/// signature differs from every other port's — which is why it is a trait and
/// not a call. The kernel half, the kstack windows and the stack sizes are this
/// port's address-space layout. The lifecycle itself — the authority checks,
/// W^X, the copy validation, the reclaim — is in `kcore` and not here
/// (build/README.md, D251).
pub(crate) struct X86Loader;

impl kcore::loader::LoaderSupport<KernelAddressSpace> for X86Loader {
    fn new_user_space(
        &mut self,
        alloc: &mut dyn FrameSource,
    ) -> Result<AddressSpace<KernelAddressSpace>, KError> {
        let kernel_vm = self.kernel_space();
        let arch = kernel_vm.arch().new_user(alloc)?;
        Ok(AddressSpace::from_arch(
            arch,
            // A fresh tag per child: two live children cannot share one, even
            // though this port never programs a tag as a hardware PCID.
            alloc_asid(),
            1u64 << kcore::percpu::current_index(),
        ))
    }

    fn kernel_space(&mut self) -> &mut AddressSpace<KernelAddressSpace> {
        // SAFETY: the boot CPU alone; `LOADER_KERNEL_VM` names the boot kernel
        // space, published before any ring-3 thread runs and live for the
        // kernel's lifetime. A loader call that reaches here without it set is
        // a boot-order defect, so it panics rather than inventing a space.
        unsafe {
            LOADER_KERNEL_VM
                .as_mut()
                .expect("the loader's kernel space is published before ring 3 runs")
        }
    }

    fn take_kernel_stack(&mut self) -> Option<VirtAddr> {
        take_child_kstack().map(VirtAddr::new)
    }

    fn release_kernel_stack(&mut self, window: VirtAddr) {
        release_child_kstack(window.as_u64());
    }

    fn user_stack_pages(&self) -> u64 {
        CHILD_STACK_PAGES
    }

    fn kernel_stack_pages(&self) -> u64 {
        USER_KSTACK_PAGES
    }
}

/// Gives a reclaimed child's window back to the pool.
pub(crate) fn release_child_kstack(window: u64) {
    for (slot, va) in CHILD_KSTACKS.iter().enumerate() {
        if va.load(Ordering::Relaxed) == window {
            CHILD_KSTACK_BUSY[slot].store(false, Ordering::Relaxed);
            return;
        }
    }
}

pub(crate) static DRIVER_HOST_KSTACK_WINDOW: AtomicU64 = AtomicU64::new(0);
pub(crate) static DRIVER_HOST_ASID_TAG: AtomicU16 = AtomicU16::new(0);
/// The restartable driver host's reused kstack window.
pub(crate) fn driver_host_kstack_window() -> u64 {
    match DRIVER_HOST_KSTACK_WINDOW.load(Ordering::Relaxed) {
        0 => {
            let w = alloc_kstack(USER_KSTACK_PAGES).as_u64();
            DRIVER_HOST_KSTACK_WINDOW.store(w, Ordering::Relaxed);
            w
        }
        w => w,
    }
}
/// The restartable driver host's reused ASID.
pub(crate) fn driver_host_asid() -> Asid {
    match DRIVER_HOST_ASID_TAG.load(Ordering::Relaxed) {
        0 => {
            let a = alloc_asid();
            DRIVER_HOST_ASID_TAG.store(a.0, Ordering::Relaxed);
            a
        }
        a => Asid(a),
    }
}
