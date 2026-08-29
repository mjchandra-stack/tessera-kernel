// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Jobs: the containment tree.
//!
//! Killing a job kills its subtree innermost-first and returns what its members
//! held.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---- Jobs (containment tree) kernel demo ------------------------------------

/// Kernel stacks for the demo's member threads: one reserved block of four
/// windows, cut from the shared allocator rather than from a slot picked by
/// hand (D53), and memoized so every member of a run shares the reservation.
pub(crate) fn job_kstack(i: u64) -> u64 {
    static BASE: AtomicU64 = AtomicU64::new(0);
    let mut base = BASE.load(Ordering::Relaxed);
    if base == 0 {
        base = reserve_kstack_block(4);
        BASE.store(base, Ordering::Relaxed);
    }
    base + i * KSTACK_WINDOW_SLOT
}

/// A member process's thread: it never runs in this demo (the scheduler is never
/// started); it exists so a kill has a real thread to terminate.
pub(crate) extern "C" fn job_member_entry(_arg: usize) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Creates a member process object + a parked thread and places it in `job`.
/// On any failure (including the member-count cap) the thread is terminated and
/// the object released, so a rejected create leaks nothing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn job_spawn_member(
    exec: &mut Executive<ContextSwitch>,
    objects: &mut ObjectTable,
    job: tessera_kcore::job::JobId,
    kstack: u64,
    rights: Rights,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) -> Result<(ObjectId, usize), KError> {
    let proc = objects.create(ObjectType::Process)?;
    let thread = match Thread::<ContextSwitch>::spawn(
        job_member_entry,
        0,
        VirtAddr::new(kstack),
        USER_KSTACK_PAGES,
        kernel_vm,
        frames,
    ) {
        Ok(thread) => thread,
        Err(e) => {
            let _ = objects.release(proc);
            return Err(e);
        }
    };
    let idx = match exec.add_thread(thread) {
        Ok(idx) => idx,
        Err(e) => {
            let _ = objects.release(proc);
            return Err(e);
        }
    };
    // The job records the thread's identity, not this CPU's slot for it: a job
    // outlives its members, and a reaped slot is reused.
    let thread_id = match exec.scheduler().thread_id(idx) {
        Some(id) => id,
        None => {
            exec.scheduler().terminate(idx);
            let _ = objects.release(proc);
            return Err(KError::BadHandle);
        }
    };
    match exec.job_add_process(
        job,
        Member {
            process: proc,
            thread: thread_id,
        },
        rights,
    ) {
        Ok(()) => Ok((proc, idx)),
        Err(e) => {
            exec.scheduler().terminate(idx);
            let _ = objects.release(proc);
            Err(e)
        }
    }
}

/// Jobs: the containment tree. Builds root + a tighter child job, enforces the
/// tighten-only limit rule and the member-count ceiling and the `KILL` right,
/// then kills the whole subtree innermost-first — terminating every member
/// thread, reclaiming each member object, and signalling the root job's state
/// port (member-exit + emptiness) for a supervisor to drain
/// (docs/kernel/05). All operations run in boot context on data structures;
/// the member threads are spawned parked and never scheduled.
pub(crate) fn jobs_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();
    // SAFETY: the boot CPU alone; the only live reference to OBJECTS.
    let objects = unsafe { &mut *&raw mut OBJECTS };

    let full = Rights::from_bits(
        Rights::CREATE_JOB.bits() | Rights::CREATE_PROCESS.bits() | Rights::KILL.bits(),
    );

    // Root job with a member-process cap of 2.
    let root_obj = match objects.create(ObjectType::Job) {
        Ok(obj) => obj,
        Err(_) => return kprintln!("jobs-demo: setup failed (root object)"),
    };
    let root = match exec.job_create_root(root_obj, JobLimits::new(2)) {
        Ok(job) => job,
        Err(_) => return kprintln!("jobs-demo: setup failed (root)"),
    };

    // Tighten-only: a child looser than its parent's ceiling is rejected.
    let loose_obj = match objects.create(ObjectType::Job) {
        Ok(obj) => obj,
        Err(_) => return kprintln!("jobs-demo: setup failed (object)"),
    };
    let tighten_rejected = matches!(
        exec.job_create_child(root, loose_obj, JobLimits::new(3), full),
        Err(KError::LimitExceeded)
    );
    let _ = objects.release(loose_obj); // reclaim the unused object

    // A child job with a tighter cap of 1.
    let child_obj = match objects.create(ObjectType::Job) {
        Ok(obj) => obj,
        Err(_) => return kprintln!("jobs-demo: setup failed (child object)"),
    };
    let child = match exec.job_create_child(root, child_obj, JobLimits::new(1), full) {
        Ok(job) => job,
        Err(_) => return kprintln!("jobs-demo: setup failed (child)"),
    };

    // Members: P1, P2 fill root's cap of 2; P3 is rejected; P4 goes in the child.
    let p1 = job_spawn_member(exec, objects, root, job_kstack(0), full, kernel_vm, frames);
    let p2 = job_spawn_member(exec, objects, root, job_kstack(1), full, kernel_vm, frames);
    let p3 = job_spawn_member(exec, objects, root, job_kstack(2), full, kernel_vm, frames);
    let p4 = job_spawn_member(exec, objects, child, job_kstack(3), full, kernel_vm, frames);

    let limit_rejected = matches!(p3, Err(KError::LimitExceeded));
    let (p1, p2, p4) = match (p1, p2, p4) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return kprintln!("jobs-demo: setup failed (members)"),
    };
    let member_threads = [p1.1, p2.1, p4.1];

    // The capability gate: a kill without the `KILL` right is denied.
    let mut sink = [None; 8];
    let rights_rejected = matches!(
        exec.job_kill(root, Rights::none(), &mut sink),
        Err(KError::AccessDenied)
    );

    // A supervisor port bound to the root job's state source.
    let source = match exec.job(root) {
        Some(job) => job.state_source(),
        None => return kprintln!("jobs-demo: setup failed (source)"),
    };
    let port = match exec.port_create() {
        Ok(port) => port,
        Err(_) => return kprintln!("jobs-demo: setup failed (port)"),
    };
    if exec.port_bind(port, source, SIGNAL_MEMBER_EXIT).is_err()
        || exec.port_bind(port, source, SIGNAL_EMPTY).is_err()
    {
        return kprintln!("jobs-demo: setup failed (bind)");
    }

    // Kill the whole subtree, innermost-first (child's member before root's).
    let mut killed = [None; 8];
    let n = match exec.job_kill(root, full, &mut killed) {
        Ok(n) => n,
        Err(_) => return kprintln!("jobs-demo: kill failed"),
    };

    // Supervisor reclaim: release each killed member's object.
    let mut released = 0;
    for slot in killed.iter().take(n) {
        if let Some(proc) = slot
            && objects.release(*proc).is_ok()
        {
            released += 1;
        }
    }

    // Every member thread must be terminated.
    let all_exited = member_threads
        .iter()
        .all(|&idx| exec.scheduler().thread_state(idx) == Some(ThreadState::Exited));

    // Drain the state port: root's two member-exits coalesce, then emptiness.
    let member_exit = exec.port_wait(port).ok().map(|e| (e.signal, e.pending));
    let empty = exec.port_wait(port).ok().map(|e| e.signal);

    let ok = tighten_rejected
        && limit_rejected
        && rights_rejected
        && n == 3
        && released == 3
        && all_exited
        && member_exit == Some((SIGNAL_MEMBER_EXIT, 2))
        && empty == Some(SIGNAL_EMPTY);
    report(&verdict(
        DemoId::Jobs,
        ok,
        [n as u64, released as u64, 0, 0, 0, 0, 0, 0],
    ));
    if !ok {
        kprintln!(
            "jobs: FAIL rejects tighten={tighten_rejected} limit={limit_rejected} rights={rights_rejected}"
        );
        kprintln!(
            "jobs: FAIL killed={n} freed={released} exited={all_exited} ex={member_exit:?} empty={empty:?}"
        );
    }
}
