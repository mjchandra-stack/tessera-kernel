// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **root task on the last port**: what this port lends
//! `kcore::loader`, and the check that a root task composes a system here.
//!
//! **The fifth caller, and the one that completes the matrix.** Every port in
//! this tree runs the same root task now, from the same source. What this one
//! contributes is a machine that agrees with none of the others about how a
//! kernel is addressed: the `TTBCR` split walks the kernel out of `TTBR1` and a
//! process out of `TTBR0`, so a process's tables carry **no copy of the
//! kernel's** at all — where the RISC-V ports copy root entries by value and
//! must be careful about when (D99, D108, D260). None of that reached `kcore`
//! (build/README.md, D263).
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
use tessera_karch_arm32::KernelAddressSpace;

/// The region a kernel-half alias answers for.
///
/// **A root here has to be told which half it is**, because the level-1 index
/// is one bit: `0x0900_0000` and `0x8900_0000` reach the same entry, so a space
/// that answered for both would map a low address into the high half (D110). It
/// is the kernel's own boundary, which is also this machine's
/// `USER_ADDRESS_MAX`.
const KERNEL_REGION_BASE: u64 = 0x8000_0000;

/// Where the kernel stacks in this check live.
///
/// **No region to reserve and no guard page to open it with**, which is this
/// port's one genuine simplification over the other 32-bit machine. The
/// `TTBCR` split gives the kernel its own translation-base register, so a
/// process's tables carry no copy of the kernel's and a kernel mapping made at
/// any time is reachable from every process (D110). RISC-V 32 has one root
/// register, copies the kernel's entries into each space by value, and must
/// therefore create every kernel-stack window's 4 MiB entry before any process
/// root is taken (D260, D262). Here there is nothing to copy and nothing to be
/// careful about.
///
/// High in the kernel half, and clear of the direct map's own range — which is
/// wider than this machine's RAM, so `DIRECT_MAP_BASE + 0x4000_0000` is
/// already taken and answers `AlreadyMapped` rather than being free.
const KSTACK_REGION: u64 = 0xE000_0000;
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

/// Address-space identifiers. This port's descriptors carry `nG`, which is what
/// makes an ASID mean anything here at all.
const ROOT_TASK_ASID: u16 = 20;
const CHILD_ASID_BASE: u32 = 21;
static NEXT_CHILD_ASID: AtomicU32 = AtomicU32::new(CHILD_ASID_BASE);

/// Launches this check counted, so the boot can assert the supervisor ran its
/// policy exactly rather than approximately.
static LAUNCHES: AtomicU32 = AtomicU32::new(0);

/// Launches the root task's run must produce: one for the grant probe, one for the log service that collects
/// what the others report, three
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
pub(crate) const EXPECTED_LAUNCHES: u32 = 1 + 1 + 3 + 41 + 3;

/// Records a launch. Called from the loader arm on a successful `ProcessStart`.
pub(crate) fn note_launch() {
    LAUNCHES.fetch_add(1, Ordering::Relaxed);
}

/// This port's answers to the six questions `kcore::loader` cannot answer for
/// itself.
pub(crate) struct Arm32Loader {
    /// The kernel-space alias a child's kernel stack is mapped into, and whose
    /// windows the reclaim unmaps.
    pub(crate) kernel_space: kcore::vm::AddressSpace<KernelAddressSpace>,
}

impl kcore::loader::LoaderSupport<KernelAddressSpace> for Arm32Loader {
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
pub(crate) static mut ROOT_LOADER: Option<Arm32Loader> = None;

/// The loader seam, through one place — for the reason
/// `tools/ci/arch-lint-baseline.txt` gives.
///
/// # Safety
///
/// The caller must be the boot hart with no other borrow of `ROOT_LOADER` live.
pub(crate) unsafe fn root_loader() -> Option<&'static mut Arm32Loader> {
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

    // No guard page and no region to open — see `KSTACK_REGION`. The alias is
    // what a child's kernel stack is mapped through.
    // SAFETY: `kernel_space` is the active kernel space; the alias maps only
    // into the kernel half and is never torn down.
    let mut kernel_alias = {
        let arch = unsafe {
            KernelAddressSpace::from_root(
                kernel_space.root_phys(),
                DIRECT_MAP_BASE,
                KERNEL_REGION_BASE,
            )
        };
        AddressSpace::from_arch(arch, Asid(0), 0)
    };

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
        kcore::elf::Machine::Arm32,
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
        let arch = KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
            KERNEL_REGION_BASE,
        );
        ROOT_LOADER = Some(Arm32Loader {
            kernel_space: AddressSpace::from_arch(arch, Asid(0), 0),
        });
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_arm32::set_user_syscall_hook(user_dispatch_hook);
    tessera_karch_arm32::set_user_abort_hook(crate::substrate::user_abort_hook);
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
                    "roottask: state {other:?} fault {:#x} at {:#x} reports={} entry {:#x}",
                    SUBSTRATE_FAULT.load(Ordering::SeqCst),
                    crate::substrate::SUBSTRATE_FAULT_ADDR.load(Ordering::SeqCst),
                    REPORT_COUNT.load(Ordering::SeqCst),
                    entry,
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
