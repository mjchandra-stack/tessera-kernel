// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **root task on the first 32-bit machine**: what this port lends
//! `kcore::loader`, and the check that a root task composes a system here.
//!
//! **The fourth caller of the seam, and the first that is not 64-bit.** D251
//! moved the process lifecycle into `kcore`; D252 and D257 showed it survived a
//! second and third machine. Every one of those was 64 bits wide, which is the
//! one thing they could all have been wrong about together. This machine's
//! pointers are half as wide, its ELFs are a different class, its page-table
//! root entries span 4 MiB rather than a gibibyte, and its kernel half *is* the
//! identity map. None of that reached `kcore` — the seam is the same six
//! methods, and what this port writes is one impl and a check
//! (build/README.md, D262).
//!
//! Normative: docs/api/01-system-call-interface.md ("Process And Thread"),
//! docs/roadmap/03-composition-and-self-hosting.md (Phase 1)

use crate::substrate::{
    DISPATCH_FRAMES, REPORT_COUNT, REPORTS, SUBSTRATE_FAULT, kcore_exec, kcore_exec_restart,
    kcore_processes, user_dispatch_hook,
};
use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tessera_karch::{AddressSpaceOps, KError};
use tessera_karch_riscv32::KernelAddressSpace;

/// The one 4 MiB region every kernel stack in this check lives in, and it has
/// to be one.
///
/// **Sv32 root entries span 4 MiB, and a process root copies the kernel half by
/// value** — so a process sees a kernel mapping made after its root was taken
/// only if that mapping lands under a root entry which already existed (D260).
/// The root task's own stack is mapped before it is created; a child's is
/// mapped when the child starts, which is *after* that child's root was copied.
/// Putting every window in one region, and creating that region's entry before
/// anything, is what makes each of them visible to the process running on it.
///
/// A gibibyte-grained port never had to think about this. Four mebibytes is
/// plenty — the root task takes 32 pages and four children take eight each —
/// and the guard page at the region's base is what creates the entry.
const KSTACK_REGION: u64 = 0x9840_0000;
const ROOT_TASK_KSTACK_VA: u64 = KSTACK_REGION + FRAME_SIZE;
/// Thirty-two pages, because a `ProcessCreate` builds a `Process` far larger
/// than a channel operation's frame inside a syscall; every other port here
/// sized it the same way after meeting the overflow.
const ROOT_TASK_KSTACK_PAGES: u64 = 32;

const CHILD_KSTACK_BASE: u64 = KSTACK_REGION + 0x0004_0000;
const CHILD_KSTACK_STRIDE: u64 = 0x0002_0000;
const MAX_CHILDREN: usize = 4;
static KSTACK_BUSY: [AtomicBool; MAX_CHILDREN] = [const { AtomicBool::new(false) }; MAX_CHILDREN];

/// Where the root task's own user stack goes, and how big it is.
const ROOT_TASK_USER_STACK_VA: u64 = 0x2800_0000;
const ROOT_TASK_USER_STACK_PAGES: u64 = 12;
const CHILD_USER_STACK_PAGES: u64 = 4;
const CHILD_KSTACK_PAGES: u64 = 8;

/// Address-space identifiers. Sv32's ASID field is 9 bits — a smaller pool for
/// the same job as Sv39's sixteen — so these stay well inside it.
const ROOT_TASK_ASID: u16 = 20;
const CHILD_ASID_BASE: u32 = 21;
static NEXT_CHILD_ASID: AtomicU32 = AtomicU32::new(CHILD_ASID_BASE);

/// Launches this check counted, so the boot can assert the supervisor ran its
/// policy exactly rather than approximately.
static LAUNCHES: AtomicU32 = AtomicU32::new(0);

/// Launches the root task's run must produce: one for the grant probe, three
/// for the argument probe, forty-one to bring the recovering service up, and
/// three for the one it gives up on. No driver framework here — this image
/// carries no manager and no driver, and the root task says so rather than
/// pretending.
///
/// The argument probe's three are one program run three ways (D302): a path it
/// accepts, no arguments at all, and a path it refuses. **They run here too,
/// which is the point of counting them on a 32-bit machine**: the startup
/// message exists because the startup *word* is 32 bits wide here (D259, D261),
/// so this is the port that would notice an argument shape that only worked at
/// 64 bits.
pub(crate) const EXPECTED_LAUNCHES: u32 = 1 + 3 + 41 + 3;

/// Records a launch. Called from the loader arm on a successful `ProcessStart`.
pub(crate) fn note_launch() {
    LAUNCHES.fetch_add(1, Ordering::Relaxed);
}

/// This port's answers to the six questions `kcore::loader` cannot answer for
/// itself.
pub(crate) struct RiscV32Loader {
    /// The kernel-space alias a child's kernel stack is mapped into, and whose
    /// windows the reclaim unmaps.
    pub(crate) kernel_space: kcore::vm::AddressSpace<KernelAddressSpace>,
}

impl kcore::loader::LoaderSupport<KernelAddressSpace> for RiscV32Loader {
    fn new_user_space(
        &mut self,
        alloc: &mut dyn tessera_karch::FrameSource,
    ) -> Result<kcore::vm::AddressSpace<KernelAddressSpace>, KError> {
        use kcore::vm::{AddressSpace, Asid};
        let asid = NEXT_CHILD_ASID.fetch_add(1, Ordering::Relaxed) as u16;
        let arch = self.kernel_space.arch_mut().new_user(alloc, asid)?;
        Ok(AddressSpace::from_arch(arch, Asid(asid), 0))
    }

    fn kernel_space(&mut self) -> &mut kcore::vm::AddressSpace<KernelAddressSpace> {
        &mut self.kernel_space
    }

    fn take_kernel_stack(&mut self) -> Option<VirtAddr> {
        for (slot, busy) in KSTACK_BUSY.iter().enumerate() {
            if !busy.swap(true, Ordering::Relaxed) {
                return Some(VirtAddr::new(
                    CHILD_KSTACK_BASE + slot as u64 * CHILD_KSTACK_STRIDE,
                ));
            }
        }
        None
    }

    fn release_kernel_stack(&mut self, window: VirtAddr) {
        let offset = window.as_u64().wrapping_sub(CHILD_KSTACK_BASE);
        let slot = (offset / CHILD_KSTACK_STRIDE) as usize;
        if slot < MAX_CHILDREN && offset.is_multiple_of(CHILD_KSTACK_STRIDE) {
            KSTACK_BUSY[slot].store(false, Ordering::Relaxed);
        }
    }

    fn user_stack_pages(&self) -> u64 {
        CHILD_USER_STACK_PAGES
    }

    fn kernel_stack_pages(&self) -> u64 {
        CHILD_KSTACK_PAGES
    }
}

/// The loader seam, published for the duration of the root-task run.
pub(crate) static mut ROOT_LOADER: Option<RiscV32Loader> = None;

/// The loader seam, through one place — for the reason
/// `tools/ci/arch-lint-baseline.txt` gives.
///
/// # Safety
///
/// The caller must be the boot hart with no other borrow of `ROOT_LOADER` live.
pub(crate) unsafe fn root_loader() -> Option<&'static mut RiscV32Loader> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { (*(&raw mut ROOT_LOADER)).as_mut() }
}

/// The object table `kcore::loader` mints child process ids from.
pub(crate) static mut KCORE_OBJECTS: kcore::object::ObjectTable = kcore::object::ObjectTable::new();

/// The object table, through one place — as [`root_loader`].
///
/// # Safety
///
/// The caller must be the boot hart with no other borrow live.
pub(crate) unsafe fn kcore_objects() -> &'static mut kcore::object::ObjectTable {
    // SAFETY: the caller's obligation, stated above.
    unsafe { &mut *(&raw mut KCORE_OBJECTS) }
}

/// What the run produced.
pub(crate) struct RootTaskReport {
    /// The root task's own exit code. Zero only if every step it checked held.
    pub(crate) exit: i32,
    /// Launches the supervisor made.
    pub(crate) launches: u32,
}

/// Runs the root task: the kernel starts one process and nothing else.
///
/// **One seed, and there are no others.** A job carrying `create-process`.
/// This image carries no bus and no driver framework, so the root task composes
/// what it can and says nothing about what it cannot — which is what lets one
/// program serve four machines.
pub(crate) fn root_task_check(
    kernel_space: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    image: &[u8],
) -> Result<RootTaskReport, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};

    // SAFETY: the boot hart alone; no thread runs.
    unsafe {
        kcore_exec_restart(5);
    }
    LAUNCHES.store(0, Ordering::Relaxed);
    NEXT_CHILD_ASID.store(CHILD_ASID_BASE, Ordering::Relaxed);
    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    for busy in KSTACK_BUSY.iter() {
        busy.store(false, Ordering::Relaxed);
    }
    SUBSTRATE_FAULT.store(0, Ordering::SeqCst);

    // **The guard page first**, before any process root exists — see
    // `KSTACK_REGION`. Every kernel stack in this run lives in the 4 MiB it
    // opens, so this one mapping is what makes all of them reachable from the
    // roots that copy the kernel half afterwards.
    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // into the kernel half and is never torn down.
    let mut kernel_alias = {
        let arch =
            unsafe { KernelAddressSpace::from_root(kernel_space.root_phys(), DIRECT_MAP_BASE) };
        AddressSpace::from_arch(arch, Asid(0), 0)
    };
    kernel_alias
        .map_anonymous(
            VirtAddr::new(KSTACK_REGION),
            FRAME_SIZE,
            PageFlags::rw(),
            frames,
        )
        .map_err(|_| 900u32)?;

    let root_obj = kcore::object::ObjectId::from_raw(95);
    let user_arch = kernel_space
        .new_user(frames, ROOT_TASK_ASID)
        .map_err(|_| 901u32)?;
    let user_root = user_arch.root_phys();
    let mut user_space = AddressSpace::from_arch(user_arch, Asid(ROOT_TASK_ASID), 0);
    // `Machine::RiscV32`: the same `e_machine` a 64-bit RISC-V image carries,
    // so what makes this the right target is the ELF **class** (D258).
    let entry = kcore::elf::load_into(
        image,
        &mut user_space,
        frames,
        kcore::elf::Machine::RiscV32,
        910,
    )?;
    let thread = kcore::thread::Thread::<ContextSwitch>::spawn_user(
        VirtAddr::new(entry),
        // No startup word: this image carries no driver framework, so there is
        // no report mode to forward (D256).
        0,
        VirtAddr::new(ROOT_TASK_USER_STACK_VA),
        ROOT_TASK_USER_STACK_PAGES,
        VirtAddr::new(ROOT_TASK_KSTACK_VA),
        ROOT_TASK_KSTACK_PAGES,
        root_obj,
        user_root,
        &mut user_space,
        &mut kernel_alias,
        frames,
    )
    .map_err(|_| 920u32)?;

    // SAFETY: transient raw access; no thread runs yet.
    let (root_thread, root_proc) = unsafe {
        let exec = kcore_exec().ok_or(921u32)?;
        let thread_idx = exec.add_thread(thread).map_err(|_| 922u32)?;
        let id = exec.scheduler().thread_id(thread_idx).ok_or(923u32)?;
        let mut process = kcore::process::Process::new(root_obj, user_space);
        process.add_thread(id).map_err(|_| 924u32)?;
        // The one seed: `create-process`, and the root task derives everything
        // else from it or makes it.
        process
            .handles_mut()
            .install(
                kcore::object::ObjectId::from_raw(96),
                Rights::CREATE_PROCESS,
            )
            .map_err(|_| 925u32)?;
        let proc_idx = kcore_processes().insert(process).map_err(|_| 926u32)?;
        (thread_idx, proc_idx)
    };

    // Publish the seam and the allocator, then run.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    // SAFETY: the boot hart alone; both are cleared after the run, and read
    // only from the hook while this run is on the CPU. The transmute erases
    // the borrow's lifetime; the pointer is used strictly inside that borrow.
    unsafe {
        let arch = KernelAddressSpace::from_root(kernel_space.root_phys(), DIRECT_MAP_BASE);
        ROOT_LOADER = Some(RiscV32Loader {
            kernel_space: AddressSpace::from_arch(arch, Asid(0), 0),
        });
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_riscv32::set_user_trap_hook(user_dispatch_hook);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        kcore_exec().ok_or(927u32)?.run();
    }
    // SAFETY: the run is over; the hook can no longer fire on these.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the run is over; no syscall can reach the seam again.
    let loader = unsafe { (&raw mut ROOT_LOADER).as_mut().and_then(Option::take) };
    let mut kernel_alias = loader.ok_or(928u32)?.kernel_space;

    // SAFETY: transient raw access; the run ended.
    let exit = unsafe {
        match kcore_processes()
            .get(root_proc)
            .map(kcore::process::Process::state)
        {
            Some(kcore::process::ProcessState::Exited(code)) => code,
            other => {
                kprintln!(
                    "roottask: state {other:?} fault {:#x} reports={}",
                    SUBSTRATE_FAULT.load(Ordering::SeqCst),
                    REPORT_COUNT.load(Ordering::SeqCst),
                );
                return Err(930);
            }
        }
    };

    // **Teardown, and it has to be complete.** A reaped thread still claimed by
    // a `Process` is the shape that shows up later as `AccessDenied` on a valid
    // pointer.
    // SAFETY: transient raw access; the run has ended and the thread is
    // off-CPU.
    unsafe {
        let processes = kcore_processes();
        if let Some(exec) = kcore_exec()
            && let Some(thread) = exec.scheduler().reap(root_thread)
        {
            let _ = kernel_alias.reclaim_range(
                thread.kernel_stack_base(),
                thread.stack_bytes(),
                frames,
            );
            if let Some(process) = processes.get_mut(root_proc) {
                process.forget_thread(thread.id());
            }
        }
        if let Some(mut process) = processes.remove(root_proc) {
            process.space_mut().teardown(frames);
        }
    }

    Ok(RootTaskReport {
        exit,
        launches: LAUNCHES.load(Ordering::Relaxed),
    })
}
