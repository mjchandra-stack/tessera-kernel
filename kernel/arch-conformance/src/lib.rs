// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The architecture-conformance battery: one set of checks that every port
//! runs, so "this architecture implements the porting layer" is a result
//! rather than a claim.
//!
//! `docs/hardware/01-platform-and-cpu-support.md` "Porting Rules" requires a
//! new architecture to *"pass kernel architecture tests"*. Until now there
//! were none — build/README.md D5 recorded exactly that gap — and each port's
//! evidence was whatever its own boot glue happened to check. That is the
//! failure mode this crate exists to prevent: two ports drifting into two
//! different kernels, each passing its own private bar.
//!
//! Everything here is written against the `tessera-karch` traits and nothing
//! else, so it cannot accidentally test one port's internals. A case that
//! passes on one architecture and fails on another has found either a bug in
//! the port or a hole in the abstraction, and both are worth knowing.
//!
//! Verdicts are [`kcore::verdict`] records and the rendered lines are
//! generated from them, so the battery reports the same way every other demo
//! does (docs/observability/01, "plain text rendering is generated from
//! structured records"; build/README.md, D58).
//!
//! **Scope.** These are the checks that need only the porting layer. Cases
//! that need the kernel's object graph standing — scheduler preemption under
//! a live tick, an IPC round trip through the executive — are deliberately
//! not here yet: they are worth having, but on a port that has not wired up
//! `kcore`'s address-space and executive types they would test the boot glue
//! rather than the architecture. They arrive with EL0, when both ports have
//! the same footing.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Porting Rules"),
//! docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (boot verification)

#![no_std]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use tessera_karch::{
    AddressSpaceOps, ContextOps, FRAME_SIZE, FrameSource, KError, PageFlags, PhysFrame, VirtAddr,
};
use tessera_kcore as kcore;
use tessera_kcore::kprintln;
use tessera_kcore::verdict::{DemoId, DemoVerdict, Outcome};

/// Value the port-supplied code blob must return, so a stale or partially
/// visible instruction stream cannot masquerade as a correct call.
pub const SENTINEL: u64 = 0x5e17_c0de;

/// What a port hands the battery. Everything is borrowed: the battery
/// allocates no memory of its own beyond the frames it takes from `frames`
/// and returns.
pub struct Platform<'a, A: AddressSpaceOps> {
    /// The live kernel address space — the tables currently translating.
    pub space: &'a mut A,
    /// Frame source, which must support `free_frame` for the battery to
    /// leave no permanent footprint.
    pub frames: &'a mut dyn FrameSource,
    /// Virtual base of the direct physical map, so the battery can observe a
    /// frame's contents independently of the mapping under test.
    pub direct_map_base: u64,
    /// A page-aligned, currently unmapped virtual address the battery may map
    /// and unmap freely. Two consecutive pages are used.
    pub scratch: VirtAddr,
    /// Machine code for an `extern "C" fn() -> u64` that returns
    /// [`SENTINEL`]. Necessarily per-architecture — it is instructions — but
    /// the *case* built around it is not.
    pub sentinel_code: &'a [u8],
}

/// Outcome of a battery run.
pub struct Summary {
    pub passed: u32,
    pub failed: u32,
}

/// Emits one verdict and renders its line from the record.
fn report(demo: DemoId, pass: bool, detail: &str, args: [u64; 8]) -> bool {
    let record: DemoVerdict = kcore::verdict::record(demo, pass, args);
    kprintln!(
        "arch: {} — {} ({detail})",
        case_name(record.demo),
        if record.outcome == Outcome::Pass {
            "OK"
        } else {
            "FAIL"
        }
    );
    pass
}

/// Stable short name for each case, so a failure names itself in the log.
const fn case_name(demo: DemoId) -> &'static str {
    match demo {
        DemoId::ArchMapTranslate => "map/translate",
        DemoId::ArchWxRefused => "W^X refused",
        DemoId::ArchRemapRejected => "remap rejected",
        DemoId::ArchProtect => "protect",
        DemoId::ArchUnmap => "unmap",
        DemoId::ArchFrameOps => "frame ops",
        DemoId::ArchDirectMap => "direct map",
        DemoId::ArchIcacheCoherence => "icache coherence",
        DemoId::ArchContextSwitch => "context switch",
        _ => "unknown",
    }
}

/// Runs every case. Each is independent: a failure is reported and the run
/// continues, so one broken primitive does not hide the state of the rest.
pub fn run<C: ContextOps, A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> Summary {
    let mut summary = Summary {
        passed: 0,
        failed: 0,
    };
    let mut tally = |pass: bool| {
        if pass {
            summary.passed += 1;
        } else {
            summary.failed += 1;
        }
    };

    tally(map_translate(platform));
    tally(wx_refused(platform));
    tally(remap_rejected(platform));
    tally(protect(platform));
    tally(unmap(platform));
    tally(frame_ops(platform));
    tally(direct_map(platform));
    tally(icache_coherence(platform));
    tally(context_switch::<C, A>(platform));

    summary
}

/// Takes a frame, or reports the case failed for want of memory.
fn frame<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> Option<PhysFrame> {
    platform.frames.alloc_frame()
}

fn map_translate<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let Some(f) = frame(platform) else {
        return report(DemoId::ArchMapTranslate, false, "no frame", [0; 8]);
    };
    let at = platform.scratch;

    let before_unmapped = platform.space.translate(at).is_none();
    let mapped = platform
        .space
        .map(at, f, PageFlags::rw(), platform.frames)
        .is_ok();
    let round_trip = matches!(
        platform.space.translate(at),
        Some((got, flags)) if got.base() == f.base() && flags.writable() && flags.readable()
    );
    let _ = platform.space.unmap(at);
    platform.frames.free_frame(f);

    let pass = before_unmapped && mapped && round_trip;
    report(
        DemoId::ArchMapTranslate,
        pass,
        "a mapped page translates back to its own frame and flags",
        [
            f.base().as_u64(),
            at.as_u64(),
            u64::from(before_unmapped),
            u64::from(mapped),
            u64::from(round_trip),
            0,
            0,
            0,
        ],
    )
}

fn wx_refused<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let Some(f) = frame(platform) else {
        return report(DemoId::ArchWxRefused, false, "no frame", [0; 8]);
    };
    let at = platform.scratch;

    // Writable+executable must be refused with the specific error, not merely
    // fail: a port that returned InvalidMapping here would be hiding a
    // different bug behind the right-looking outcome.
    let mapping = platform
        .space
        .map(at, f, PageFlags::rw().execute(), platform.frames);
    // And a refused mapping must leave nothing behind.
    let nothing_installed = platform.space.translate(at).is_none();
    platform.frames.free_frame(f);

    let pass = mapping == Err(KError::WXViolation) && nothing_installed;
    report(
        DemoId::ArchWxRefused,
        pass,
        "writable+executable is refused as WXViolation and installs nothing",
        [
            u64::from(mapping == Err(KError::WXViolation)),
            u64::from(nothing_installed),
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    )
}

fn remap_rejected<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let (Some(first), Some(second)) = (frame(platform), frame(platform)) else {
        return report(DemoId::ArchRemapRejected, false, "no frames", [0; 8]);
    };
    let at = platform.scratch;

    let _ = platform
        .space
        .map(at, first, PageFlags::rw(), platform.frames);
    let rejected = platform
        .space
        .map(at, second, PageFlags::rw(), platform.frames)
        == Err(KError::AlreadyMapped);
    // The original mapping must survive the rejected attempt.
    let unchanged = matches!(
        platform.space.translate(at),
        Some((got, _)) if got.base() == first.base()
    );
    let _ = platform.space.unmap(at);
    platform.frames.free_frame(first);
    platform.frames.free_frame(second);

    let pass = rejected && unchanged;
    report(
        DemoId::ArchRemapRejected,
        pass,
        "mapping an occupied address is rejected and leaves the original",
        [u64::from(rejected), u64::from(unchanged), 0, 0, 0, 0, 0, 0],
    )
}

fn protect<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let Some(f) = frame(platform) else {
        return report(DemoId::ArchProtect, false, "no frame", [0; 8]);
    };
    let at = platform.scratch;

    let _ = platform.space.map(at, f, PageFlags::rw(), platform.frames);
    let to_readonly = platform.space.protect(at, PageFlags::ro()).is_ok();
    let now_readonly = matches!(
        platform.space.translate(at),
        Some((_, flags)) if flags.readable() && !flags.writable()
    );
    // Reprotecting to writable+executable must be refused just as mapping is.
    let wx_refused =
        platform.space.protect(at, PageFlags::rw().execute()) == Err(KError::WXViolation);
    let _ = platform.space.unmap(at);
    // Protecting an absent mapping reports rather than succeeding vacuously.
    let absent = platform.space.protect(at, PageFlags::ro()) == Err(KError::NotMapped);
    platform.frames.free_frame(f);

    let pass = to_readonly && now_readonly && wx_refused && absent;
    report(
        DemoId::ArchProtect,
        pass,
        "permissions change in place, still refuse W^X, and report when absent",
        [
            u64::from(to_readonly),
            u64::from(now_readonly),
            u64::from(wx_refused),
            u64::from(absent),
            0,
            0,
            0,
            0,
        ],
    )
}

fn unmap<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let Some(f) = frame(platform) else {
        return report(DemoId::ArchUnmap, false, "no frame", [0; 8]);
    };
    let at = platform.scratch;

    let _ = platform.space.map(at, f, PageFlags::rw(), platform.frames);
    // Unmap must hand back the frame it removed — that return value is how
    // the caller knows what to reclaim, so a port that returned some other
    // frame would leak one and free another's.
    let returned = matches!(platform.space.unmap(at), Ok(got) if got.base() == f.base());
    let gone = platform.space.translate(at).is_none();
    let again = platform.space.unmap(at) == Err(KError::NotMapped);
    platform.frames.free_frame(f);

    let pass = returned && gone && again;
    report(
        DemoId::ArchUnmap,
        pass,
        "unmap returns the frame it removed and then reports absence",
        [
            u64::from(returned),
            u64::from(gone),
            u64::from(again),
            0,
            0,
            0,
            0,
            0,
        ],
    )
}

fn frame_ops<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let (Some(source), Some(destination)) = (frame(platform), frame(platform)) else {
        return report(DemoId::ArchFrameOps, false, "no frames", [0; 8]);
    };

    let read_byte = |platform: &Platform<'_, A>, f: PhysFrame, offset: u64| -> u8 {
        // SAFETY: `f` is a frame this function owns, and the direct map makes
        // every physical frame readable at `direct_map_base + phys`.
        unsafe {
            ((platform.direct_map_base + f.base().as_u64() + offset) as *const u8).read_volatile()
        }
    };

    platform.space.fill_frame(source, 0xa5);
    let filled = read_byte(platform, source, 0) == 0xa5
        && read_byte(platform, source, FRAME_SIZE - 1) == 0xa5;

    platform.space.zero_frame(destination);
    let zeroed = read_byte(platform, destination, 0) == 0
        && read_byte(platform, destination, FRAME_SIZE - 1) == 0;

    platform.space.copy_frame(destination, source);
    let copied = read_byte(platform, destination, 0) == 0xa5
        && read_byte(platform, destination, FRAME_SIZE - 1) == 0xa5;

    // A short write must leave the tail untouched, which is what lets a
    // loader populate a zeroed frame with a partial segment.
    platform.space.zero_frame(destination);
    platform
        .space
        .write_bytes_to_frame(destination, 8, &[0x11, 0x22, 0x33, 0x44]);
    let written = read_byte(platform, destination, 7) == 0
        && read_byte(platform, destination, 8) == 0x11
        && read_byte(platform, destination, 11) == 0x44
        && read_byte(platform, destination, 12) == 0;

    platform.frames.free_frame(source);
    platform.frames.free_frame(destination);

    let pass = filled && zeroed && copied && written;
    report(
        DemoId::ArchFrameOps,
        pass,
        "fill, zero, copy and partial write are observable and bounded",
        [
            u64::from(filled),
            u64::from(zeroed),
            u64::from(copied),
            u64::from(written),
            0,
            0,
            0,
            0,
        ],
    )
}

fn direct_map<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let Some(f) = frame(platform) else {
        return report(DemoId::ArchDirectMap, false, "no frame", [0; 8]);
    };
    let at = platform.scratch;
    const PATTERN: u64 = 0x0123_4567_89ab_cdef;

    let _ = platform.space.map(at, f, PageFlags::rw(), platform.frames);
    // SAFETY: `at` was just mapped read-write to a frame this function owns.
    unsafe { (at.as_u64() as *mut u64).write_volatile(PATTERN) };
    // SAFETY: the same frame, reached through the direct map.
    let through_direct_map =
        unsafe { ((platform.direct_map_base + f.base().as_u64()) as *const u64).read_volatile() };
    let _ = platform.space.unmap(at);
    platform.frames.free_frame(f);

    let pass = through_direct_map == PATTERN;
    report(
        DemoId::ArchDirectMap,
        pass,
        "a store through a mapping is visible in its frame through the direct map",
        [PATTERN, through_direct_map, 0, 0, 0, 0, 0, 0],
    )
}

/// The case this battery exists for.
///
/// `docs/kernel/03-paging-faults-and-exceptions.md` forbids baking x86's
/// coherent instruction cache into the design: *"Runtimes that patch code
/// already mapped executable ... need coherence without a protection flip,
/// and x86's coherent instruction cache must not be baked into the ABI"*. But
/// nothing checked it, and on x86-64 nothing would — the hardware makes the
/// assumption true.
///
/// This writes instructions into a frame through the direct map, maps that
/// frame executable, and calls it. That is exactly the shape of the copy-on-
/// write path, the external pager supplying an executable page, and the ELF
/// loader populating a text segment: `write_bytes_to_frame` and `copy_frame`
/// write bytes that are later executed. If a port needs cache maintenance to
/// make those bytes fetchable and does not do it, this is where it shows,
/// and the failure is a stale-instruction crash rather than anything the
/// tables would reveal.
///
/// **What a pass here does and does not prove.** Measured: with AArch64's
/// `sync_instruction_cache` stubbed to do nothing, this case still passes
/// under QEMU/TCG, because TCG invalidates its translation blocks on any
/// guest write and so models a coherent instruction cache whatever the
/// target architecture. So a pass under emulation says the *plumbing* is
/// right — the frame is written, mapped executable, published and called —
/// and says nothing about whether the maintenance is correct or even
/// present. Only real hardware can fail this case, which puts it in the same
/// QEMU-certified-only tier as the performance budgets (build/README.md,
/// D34/D56). It is still worth running everywhere: it is the case that keeps
/// the operation in the interface, and on hardware it is the one that bites.
fn icache_coherence<A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    let Some(f) = frame(platform) else {
        return report(DemoId::ArchIcacheCoherence, false, "no frame", [0; 8]);
    };
    let at = platform.scratch;

    if platform.sentinel_code.is_empty() || platform.sentinel_code.len() as u64 > FRAME_SIZE {
        platform.frames.free_frame(f);
        return report(
            DemoId::ArchIcacheCoherence,
            false,
            "no sentinel code",
            [0; 8],
        );
    }

    platform.space.zero_frame(f);
    platform
        .space
        .write_bytes_to_frame(f, 0, platform.sentinel_code);

    let mapped = platform
        .space
        .map(at, f, PageFlags::rx(), platform.frames)
        .is_ok();

    let observed = if mapped {
        // Publish the newly written instructions to the instruction stream.
        // On an architecture with a coherent instruction cache this is
        // nothing; where it is not, this is the whole case.
        platform.space.sync_instruction_cache(at, FRAME_SIZE);
        // SAFETY: `at` maps a frame holding the port's sentinel routine,
        // mapped read-execute, and the port has just published those writes
        // to the instruction stream. The routine is `extern "C" fn() -> u64`
        // by the `Platform::sentinel_code` contract.
        let entry: extern "C" fn() -> u64 = unsafe { core::mem::transmute(at.as_u64() as usize) };
        entry()
    } else {
        0
    };

    let _ = platform.space.unmap(at);
    platform.frames.free_frame(f);

    let pass = mapped && observed == SENTINEL;
    report(
        DemoId::ArchIcacheCoherence,
        pass,
        "freshly written instructions execute correctly once published",
        [
            SENTINEL,
            observed,
            u64::from(mapped),
            platform.sentinel_code.len() as u64,
            0,
            0,
            0,
            0,
        ],
    )
}

/// Storage for the context-switch case. Two contexts: the running code parks
/// itself in one and resumes the other, which switches straight back.
static mut RESUMER: Option<*const ()> = None;
static SWITCH_WITNESS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn context_switch<C: ContextOps, A: AddressSpaceOps>(platform: &mut Platform<'_, A>) -> bool {
    // A guarded two-page stack for the thread, at the second scratch page so
    // it cannot collide with the mapping cases above.
    let base = VirtAddr::new(platform.scratch.as_u64() + FRAME_SIZE);
    const PAGES: u64 = 2;

    let mut mapped = 0u64;
    for page in 0..PAGES {
        let Some(f) = platform.frames.alloc_frame() else {
            break;
        };
        let at = VirtAddr::new(base.as_u64() + page * FRAME_SIZE);
        if platform
            .space
            .map(at, f, PageFlags::rw(), platform.frames)
            .is_err()
        {
            break;
        }
        mapped += 1;
    }
    if mapped != PAGES {
        return report(
            DemoId::ArchContextSwitch,
            false,
            "stack not mapped",
            [mapped, 0, 0, 0, 0, 0, 0, 0],
        );
    }
    let top = VirtAddr::new(base.as_u64() + PAGES * FRAME_SIZE);

    SWITCH_WITNESS.store(0, core::sync::atomic::Ordering::SeqCst);

    // SAFETY: `top` tops the two exclusively-owned pages just mapped, and
    // `switch_back` never returns.
    let mut prepared = unsafe { C::init(top, switch_back::<C>, SENTINEL as usize) };
    let mut here = C::empty();

    // SAFETY: single-threaded boot; `RESUMER` is written before the switch
    // that reads it and nothing else touches it.
    unsafe { (&raw mut RESUMER).write(Some(core::ptr::from_mut(&mut here).cast())) };

    // SAFETY: `here` is valid storage to save into, and `prepared` came from
    // `C::init` above, so its stack holds the frame `switch` expects to pop.
    unsafe { C::switch(&raw mut here, &raw const prepared) };

    // Reaching here at all means both directions worked.
    let witness = SWITCH_WITNESS.load(core::sync::atomic::Ordering::SeqCst);
    let _ = &mut prepared;

    for page in 0..PAGES {
        let at = VirtAddr::new(base.as_u64() + page * FRAME_SIZE);
        if let Ok(f) = platform.space.unmap(at) {
            platform.frames.free_frame(f);
        }
    }

    let pass = witness == SENTINEL;
    report(
        DemoId::ArchContextSwitch,
        pass,
        "a fresh context runs its entry point and switches back",
        [SENTINEL, witness, 0, 0, 0, 0, 0, 0],
    )
}

/// Entry point of the switch case's thread: records that it ran on its own
/// stack, then returns to whoever switched into it.
extern "C" fn switch_back<C: ContextOps>(arg: usize) -> ! {
    SWITCH_WITNESS.store(arg as u64, core::sync::atomic::Ordering::SeqCst);
    let mut mine = C::empty();
    // SAFETY: single-threaded boot; `RESUMER` was written before this thread
    // was switched into, and points at the caller's live `Context` storage.
    unsafe {
        let resumer = (&raw const RESUMER).read();
        match resumer {
            Some(back) => C::switch(&raw mut mine, back.cast()),
            None => loop {
                core::hint::spin_loop()
            },
        }
    }
    // Nothing ever switches back into this finished thread.
    loop {
        core::hint::spin_loop()
    }
}
