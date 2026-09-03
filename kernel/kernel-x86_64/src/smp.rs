// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Checks that need more than one CPU.
//!
//! A TLB shootdown observed from the CPU that did not perform it, and a pair of
//! threads handed to a secondary that only interleave if something took the first
//! off a CPU it never yielded. Both are withheld rather than passed on a machine
//! that brought up no secondary.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

/// Kernel virtual page the shootdown check maps, remaps, and asks another CPU
/// to read, and the two values it holds either side of the remap.
pub(crate) const SHOOTDOWN_PROBE_VA: u64 = KERNEL_VMAP_BASE + 0x5000_0000;
pub(crate) const SHOOTDOWN_BEFORE: u64 = 0x1111_1111_1111_1111;
pub(crate) const SHOOTDOWN_AFTER: u64 = 0x2222_2222_2222_2222;

/// Does an unmap on this CPU reach the others?
///
/// **The property this port cannot get for free.** AArch64's invalidate is
/// inner-shareable and completes everywhere, so its shootdown targets nobody
/// (D221). Here `invlpg` affects the CPU that runs it and no other, so every
/// other CPU with the space active keeps a translation to a frame this one is
/// about to reuse — and the only thing that ends that is a message.
///
/// The sequence: map the page to one frame and have another CPU read it, which
/// is what puts the translation in *that* CPU's TLB; remap to a second frame,
/// invalidating here and shooting down there; ask the same CPU again. Seeing
/// the second frame means the shootdown reached it.
///
/// One CPU is asked, not all of them, for the reason the AArch64 check records:
/// a broadcast has no completion, so the boot CPU would learn only that *a* CPU
/// answered and could unmap the probe page while a slower one was still reading
/// it.
///
/// # Safety
///
/// The boot CPU, after bring-up, with `space` the kernel space every CPU is
/// running on.
pub(crate) unsafe fn shootdown_reaches_other_cpus(
    space: &mut AddressSpace<tessera_karch_x86_64::KernelAddressSpace>,
    frames: &mut dyn tessera_karch::FrameSource,
) -> Option<bool> {
    use tessera_karch::AddressSpaceOps;

    let target = (1..kcore::percpu::PerCpu::<u8>::capacity())
        .find(|&index| kcore::smp::cpu(index).is_some_and(|state| state.arrived))?;
    let page = VirtAddr::new(SHOOTDOWN_PROBE_VA);
    let first = frames.alloc_frame()?;
    let second = frames.alloc_frame()?;
    space.arch().fill_frame(first, 0);
    space.arch().fill_frame(second, 0);
    space
        .arch()
        .write_bytes_to_frame(first, 0, &SHOOTDOWN_BEFORE.to_le_bytes());
    space
        .arch()
        .write_bytes_to_frame(second, 0, &SHOOTDOWN_AFTER.to_le_bytes());

    let mut verdict = None;
    // SAFETY: a high-half address nothing else is mapped at, mapped read-only
    // into the space every CPU is on and unmapped again below.
    unsafe {
        if space
            .arch_mut()
            .map(page, first, PageFlags::ro().global(), frames)
            .is_ok()
        {
            let generation = kcore::smp::probe_at(SHOOTDOWN_PROBE_VA);
            <tessera_karch_x86_64::InterCpu as tessera_karch::Ipi>::send(
                target,
                tessera_karch::IpiReason::Reschedule,
            );
            if kcore::smp::probe_answer(generation, secondaries::ARRIVAL_SPINS)
                == Some(SHOOTDOWN_BEFORE)
                && space.arch_mut().unmap(page).is_ok()
                && space
                    .arch_mut()
                    .map(page, second, PageFlags::ro().global(), frames)
                    .is_ok()
            {
                // The invalidate here, and the message to everyone it did not
                // reach. `invalidate` is what says who that is.
                let remote = space.invalidate(page);
                let told = kcore::shootdown::request::<tessera_karch_x86_64::InterCpu>(
                    remote,
                    secondaries::ARRIVAL_SPINS,
                );
                let generation = kcore::smp::probe_at(SHOOTDOWN_PROBE_VA);
                <tessera_karch_x86_64::InterCpu as tessera_karch::Ipi>::send(
                    target,
                    tessera_karch::IpiReason::Reschedule,
                );
                verdict = Some(
                    told && kcore::smp::probe_answer(generation, secondaries::ARRIVAL_SPINS)
                        == Some(SHOOTDOWN_AFTER),
                );
            }
            kcore::smp::probe_off();
            let _ = space.arch_mut().unmap(page);
        }
    }
    frames.free_frame(first);
    frames.free_frame(second);
    verdict
}

/// Hands two CPU-bound threads to one secondary and waits for them to interleave.
///
/// **The only check in this tree that a thread can be taken off a CPU it did
/// not yield.** Every other secondary thread blocks — a server parks in
/// `receive`, a client in `call` — so a kernel that had stopped preempting
/// entirely would pass every one of them. These two never yield: worker 0 spins
/// waiting to see worker 1, which cannot start until worker 0 is preempted.
///
/// Returns whether the pair was handed over at all; a machine with no secondary
/// hands over nothing and the claim is withheld rather than earned vacuously.
pub(crate) fn check_secondary_preemption(
    space: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator,
) -> bool {
    let Some(target) = (1..kcore::percpu::PerCpu::<u8>::capacity())
        .find(|&index| kcore::smp::cpu(index).is_some_and(|state| state.arrived))
    else {
        return false;
    };
    // Past every slot a per-CPU worker can take, derived rather than chosen —
    // the AArch64 port picked a number here and landed inside another check's
    // stacks.
    let first = u64::from(kcore::percpu::PerCpu::<u8>::capacity()) * 2 + 2;
    for worker in 0..kcore::preempt::WORKERS {
        let base = VirtAddr::new(
            SECONDARY_THREAD_STACKS + (first + worker as u64) * SECONDARY_THREAD_STACK_BYTES,
        );
        let Ok(thread) = kcore::thread::Thread::spawn(
            kcore::preempt::spin_worker::<tessera_karch_x86_64::ContextSwitch>,
            worker,
            base,
            SECONDARY_THREAD_STACK_BYTES / FRAME_SIZE,
            space,
            frames,
        ) else {
            return false;
        };
        // SAFETY: the boot core, and that core is in its run loop, which takes
        // whatever is waiting on every pass.
        if !unsafe { secondaries::SECONDARY_HANDOFF.give(target, thread) } {
            return false;
        }
    }
    // **Bounded here rather than in the workers**, so a kernel that never
    // preempts reports promptly instead of spending a worker's whole spin
    // budget discovering it. Once the bound expires the workers are told to
    // stop, and this waits for them to leave the run queue — a pair still
    // spinning on a secondary would perturb whatever check runs next.
    let mut spins = kcore::preempt::WAIT_SPINS;
    while !kcore::preempt::interleaved() && spins > 0 {
        core::hint::spin_loop();
        spins -= 1;
    }
    kcore::preempt::give_up();
    let mut spins = kcore::preempt::WAIT_SPINS;
    while kcore::preempt::finished() < kcore::preempt::WORKERS as u64 && spins > 0 {
        core::hint::spin_loop();
        spins -= 1;
    }
    true
}
