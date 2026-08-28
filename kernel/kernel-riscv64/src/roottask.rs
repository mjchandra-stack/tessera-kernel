// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **root task on the third port**: what this machine lends
//! `kcore::loader`, and the check that a root task composes a system here.
//!
//! **The third caller is what makes `kcore::loader` a facility rather than a
//! shape.** D251 moved the process lifecycle out of x86-64's `main.rs`; D252
//! showed it survived a second machine. A seam with two callers has been
//! generalized once, which is the number of times a wrong abstraction also
//! survives. This port differs from both in ways that would have shown up in
//! the seam if the seam were wrong: it builds a user space with `new_user` like
//! x86-64 and unlike AArch64, it takes traps through `scause`/`sepc` rather
//! than an exception vector, and its interrupt controller is a PLIC. None of
//! that reached `kcore` — the seam is the same six methods (build/README.md,
//! D257).
//!
//! The check is the same composition the other two run, from the same root-task
//! source: create a channel, load a real ELF, grant one endpoint into the
//! child, start it, supervise a service across restarts, and compose the driver
//! framework over a bus this port hands on.
//!
//! Normative: docs/api/01-system-call-interface.md ("Process And Thread"),
//! docs/roadmap/03-composition-and-self-hosting.md (Phase 1)

use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tessera_karch::{AddressSpaceOps, KError};
use tessera_karch_riscv64::KernelAddressSpace;

/// Kernel-stack windows the root task's children run on.
///
/// A pool rather than the named constants the rest of this port uses, for the
/// reason AArch64's is one: a root task starts as many children as its policy
/// asks for, and the supervision check starts forty-five. Taken at start, given
/// back at reclaim.
///
/// **In the same gibibyte as every other kernel stack on this port, and that is
/// forced.**
///
/// A process root here copies the kernel half **by value** at creation (D99),
/// which copies *root entries*. A kernel mapping made afterwards is visible to
/// an already-created process only if it lands under a root entry that existed
/// when the copy was taken — a new one is created in the kernel root and never
/// reaches the copies (D100). Sv39 root entries span 1 GiB, so a window at
/// `DIRECT_MAP_BASE + 0xc000_0000` is in a different entry from the
/// `0xb?00_0000` family every other check uses, and a thread running on its own
/// root faults on its own kernel stack.
///
/// It faults on the **first store in `trap_vector`**, before any handler runs,
/// so there is no syscall trace and no dying print — just a store fault at an
/// address that is neither the stack nor anything the check names.
const ROOT_CHILD_KSTACK_BASE: u64 = DIRECT_MAP_BASE + 0xbb00_0000;
const ROOT_CHILD_KSTACK_STRIDE: u64 = 0x0000_0000_0040_0000;
const MAX_ROOT_CHILDREN: usize = 4;
static ROOT_KSTACK_BUSY: [AtomicBool; MAX_ROOT_CHILDREN] =
    [const { AtomicBool::new(false) }; MAX_ROOT_CHILDREN];

/// The root task's own kernel stack, distinct from its children's pool and from
/// every window the other checks on this port hand-pick.
const ROOT_TASK_KSTACK_VA: u64 = DIRECT_MAP_BASE + 0xb900_0000;

/// Thirty-two pages, because a `ProcessCreate` builds a 30 KB `Process` inside
/// a syscall and the eight a channel operation needs are not enough.
///
/// **The overflow does not announce itself.** It lands in the callee's prologue
/// and this port takes the resulting store fault as a supervisor exception on a
/// stack that is already gone; AArch64 met the same wall and its symptom was a
/// silent hang. Sized here rather than discovered there.
const ROOT_TASK_KSTACK_PAGES: u64 = 32;

/// Where the root task's own user stack goes, and how big it is.
const ROOT_TASK_USER_STACK_VA: u64 = 0x2800_0000;
const ROOT_TASK_USER_STACK_PAGES: u64 = 12;

/// The address-space identifier the root task runs under, and the base its
/// children draw from. Distinct from every other check's on this port.
const ROOT_TASK_ASID: u16 = 40;
const ROOT_CHILD_ASID_BASE: u16 = 41;

/// Launches this check counted, so the boot can assert the supervisor ran its
/// policy exactly rather than approximately.
static ROOT_LAUNCHES: AtomicU64 = AtomicU64::new(0);

/// Launches the root task's run must produce: one for the grant probe,
/// forty-one to bring the recovering service up, three for the one it gives up
/// on, and two for the driver framework.
pub(crate) const EXPECTED_ROOT_LAUNCHES: u64 = 1 + 41 + 3 + 2;

/// Records a launch. Called from the loader arm on a successful `ProcessStart`.
pub(crate) fn note_launch() {
    ROOT_LAUNCHES.fetch_add(1, Ordering::Relaxed);
}

/// The next child address space's identifier.
static NEXT_CHILD_ASID: AtomicU64 = AtomicU64::new(ROOT_CHILD_ASID_BASE as u64);

/// This port's answers to the six questions `kcore::loader` cannot answer for
/// itself.
///
/// Each is here because it is a fact about this machine: how a user address
/// space is built, which alias of the kernel half a child's stack lands in,
/// where the kstack windows are, and how big the two stacks are. The lifecycle
/// itself is not here and must not be.
pub(crate) struct RiscV64Loader {
    /// The kernel-high alias a child's kernel stack is mapped into, and whose
    /// windows the reclaim unmaps.
    pub(crate) kernel_space: kcore::vm::AddressSpace<KernelAddressSpace>,
}

impl kcore::loader::LoaderSupport<KernelAddressSpace> for RiscV64Loader {
    fn new_user_space(
        &mut self,
        alloc: &mut dyn tessera_karch::FrameSource,
    ) -> Result<kcore::vm::AddressSpace<KernelAddressSpace>, KError> {
        use kcore::vm::{AddressSpace, Asid};
        // `new_user` off the kernel space, as x86-64 does and unlike AArch64's
        // `build_low_space`: this port's user half is empty at the root — the
        // kernel half is copied by value into every process root (D99) and
        // nothing else is shared — so there is no device range to carry in.
        let asid = NEXT_CHILD_ASID.fetch_add(1, Ordering::Relaxed) as u16;
        let arch = self
            .kernel_space
            .arch_mut()
            .new_user(alloc, asid)
            .map_err(|_| KError::OutOfMemory)?;
        Ok(AddressSpace::from_arch(arch, Asid(asid), 0))
    }

    fn kernel_space(&mut self) -> &mut kcore::vm::AddressSpace<KernelAddressSpace> {
        &mut self.kernel_space
    }

    fn take_kernel_stack(&mut self) -> Option<VirtAddr> {
        for (slot, busy) in ROOT_KSTACK_BUSY.iter().enumerate() {
            if !busy.swap(true, Ordering::Relaxed) {
                return Some(VirtAddr::new(
                    ROOT_CHILD_KSTACK_BASE + slot as u64 * ROOT_CHILD_KSTACK_STRIDE,
                ));
            }
        }
        None
    }

    fn release_kernel_stack(&mut self, window: VirtAddr) {
        let offset = window.as_u64().wrapping_sub(ROOT_CHILD_KSTACK_BASE);
        let slot = (offset / ROOT_CHILD_KSTACK_STRIDE) as usize;
        if slot < MAX_ROOT_CHILDREN && offset.is_multiple_of(ROOT_CHILD_KSTACK_STRIDE) {
            ROOT_KSTACK_BUSY[slot].store(false, Ordering::Relaxed);
        }
    }

    fn user_stack_pages(&self) -> u64 {
        // The same four every compiled program on this port gets
        // (`BLK_DRIVER_USER_STACK_PAGES`).
        crate::BLK_DRIVER_USER_STACK_PAGES
    }

    fn kernel_stack_pages(&self) -> u64 {
        // Eight, like every other U-mode program here: a channel operation
        // parks its whole dispatch frame on the kernel stack across a handoff.
        //
        // The root task's own is far larger (`ROOT_TASK_KSTACK_PAGES`) because
        // it is the one that calls `ProcessCreate`.
        crate::BLK_DRIVER_KSTACK_PAGES
    }
}

/// The loader seam, published for the duration of the root-task run.
///
/// A static because the trap hook has no argument to carry it in: a syscall
/// arrives as a trap frame and nothing else, so anything the arm needs has to
/// be reachable from a fixed place. Set before the root task's thread runs and
/// taken when the run ends.
pub(crate) static mut ROOT_LOADER: Option<RiscV64Loader> = None;

/// The loader seam, through one place — for the reason
/// `tools/ci/arch-lint-baseline.txt` gives: every reach for a `static mut` is a
/// `deref_addrof` finding, and one accessor is one finding rather than as many
/// as there are callers.
///
/// # Safety
///
/// The caller must be the boot CPU with no other borrow of `ROOT_LOADER` live.
pub(crate) unsafe fn root_loader() -> Option<&'static mut RiscV64Loader> {
    // SAFETY: the caller's obligation, stated above.
    unsafe { (*(&raw mut ROOT_LOADER)).as_mut() }
}

/// The object table `kcore::loader` mints child process ids from.
pub(crate) static mut KCORE_OBJECTS: kcore::object::ObjectTable = kcore::object::ObjectTable::new();

/// The object table, through one place — as `root_loader`.
///
/// # Safety
///
/// The caller must be the boot CPU with no other borrow live.
pub(crate) unsafe fn kcore_objects() -> &'static mut kcore::object::ObjectTable {
    // SAFETY: the caller's obligation, stated above.
    unsafe { &mut *(&raw mut KCORE_OBJECTS) }
}

/// What the run produced.
pub(crate) struct RootTaskReport {
    /// The root task's own exit code. Zero only if every step it checked held.
    pub(crate) exit: i32,
    /// Launches the supervisor made.
    pub(crate) launches: u64,
    /// What the driver the root task composed reported.
    pub(crate) driver_report: u64,
}

/// Runs the root task: the kernel starts one process and nothing else.
///
/// **The whole of what boot does here is seed two capabilities.** A job
/// carrying `create-process`, and a bus carrying the authority to enumerate
/// what is behind it. The root task creates the channels, loads the programs,
/// decides what each child holds, starts them and supervises them. A check that
/// still passed with the root task removed would be measuring boot glue, which
/// is why the assertions are about what the *root task* produced.
pub(crate) fn root_task_check(
    kernel_space: &tessera_karch_riscv64::KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
) -> Result<Option<RootTaskReport>, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};

    if components::root_task().is_empty() {
        return Ok(None);
    }
    // A fresh executive: this check's threads are its own.
    // SAFETY: the boot CPU alone; initialized before any thread runs.
    unsafe {
        kcore_exec_restart(7);
    }
    ROOT_LAUNCHES.store(0, Ordering::Relaxed);
    NEXT_CHILD_ASID.store(ROOT_CHILD_ASID_BASE as u64, Ordering::Relaxed);
    REPORT_COUNT.store(0, Ordering::SeqCst);
    for slot in &REPORTS {
        slot.store(0, Ordering::SeqCst);
    }
    for busy in ROOT_KSTACK_BUSY.iter() {
        busy.store(false, Ordering::Relaxed);
    }
    // Reports arrive from the root task, its probes and its driver — none of
    // which is the IPC check's server or client, whose thread ids this sink
    // otherwise insists on.
    REPORTS_FROM_ANY_THREAD.store(true, Ordering::SeqCst);

    let root_obj = kcore::object::ObjectId::from_raw(80);
    let (root_thread, root_proc) = spawn_elf_process_with_stack(
        kernel_space,
        frames,
        components::root_task(),
        ROOT_TASK_KSTACK_VA,
        ROOT_TASK_KSTACK_PAGES,
        ROOT_TASK_USER_STACK_VA,
        ROOT_TASK_USER_STACK_PAGES,
        ROOT_TASK_ASID,
        // The startup word the root task forwards to the driver it composes:
        // this port's device is synthetic, so the relay report is what such a
        // device can honestly answer (build/README.md, D256).
        ROOT_DRIVER_RELAY_REPORT,
        root_obj,
        800,
    )?;

    // **The two seeds, and there are no others.** A small graph stands behind
    // the bus, and its shape is the *driver's* rather than this check's
    // invention: `blk-probe` asks its manager for a block device, then for
    // another, then for a network device. Synthetic rather than this machine's
    // real virtio disk, because what this check is about is who composed the
    // framework — one that needed a disk attached would answer a different
    // question on a machine without one.
    let job_obj = kcore::object::ObjectId::from_raw(81);
    let bus_obj = kcore::object::ObjectId::from_raw(82);
    let device_obj = kcore::object::ObjectId::from_raw(83);
    let far_hub_obj = kcore::object::ObjectId::from_raw(84);
    let far_device_obj = kcore::object::ObjectId::from_raw(85);
    let far_net_obj = kcore::object::ObjectId::from_raw(86);
    let bus_rights = Rights::READ | Rights::DERIVE;
    {
        let exec = substrate_exec();
        // The vendor is not decoration: a manager charges a device's data path
        // by what the hubs above it are, and a hub whose identity the manifest
        // does not know is refused `PathUndeclared` rather than treated as
        // free.
        let identity = |class_code, vendor, device| kcore::devmgr::DeviceIdentity {
            class_code,
            vendor,
            device,
            bdf: 0,
            revision: 0,
            bus: kcore::devmgr::DeviceBus::Pci,
        };
        let bridge = |device| identity(RELAY_CLASS_BRIDGE, RELAY_REDHAT_VENDOR, device);
        let function = |class_code, device| identity(class_code, RELAY_VIRTIO_VENDOR, device);
        exec.device_register_identified(bus_obj, 0, 0, bus_rights, bridge(0x0001))
            .map_err(|_| 816u32)?;
        // The near device before the hub that leads away from it: the manager
        // walks the graph in slot order and binds the first *held* device of a
        // class, so registering the hub first would send the walk down the far
        // branch and swap which device each answer is about.
        exec.device_register_identified(
            device_obj,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            function(RELAY_CLASS_STORAGE, 0x1042),
        )
        .map_err(|_| 817u32)?;
        exec.device_set_parent(device_obj, bus_obj)
            .map_err(|_| 818u32)?;
        exec.device_register_identified(far_hub_obj, 0, 0, bus_rights, bridge(0x0002))
            .map_err(|_| 816u32)?;
        exec.device_set_parent(far_hub_obj, bus_obj)
            .map_err(|_| 818u32)?;
        exec.device_register_identified(
            far_device_obj,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            function(RELAY_CLASS_STORAGE, 0x1042),
        )
        .map_err(|_| 817u32)?;
        exec.device_set_parent(far_device_obj, far_hub_obj)
            .map_err(|_| 818u32)?;
        exec.device_register_identified(
            far_net_obj,
            0,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            function(RELAY_CLASS_NETWORK, 0x1041),
        )
        .map_err(|_| 817u32)?;
        exec.device_set_parent(far_net_obj, far_hub_obj)
            .map_err(|_| 818u32)?;
    }
    // SAFETY: transient raw access to the static process table; no thread runs.
    unsafe {
        let processes = kcore_processes();
        let root = processes.get_mut(root_proc).ok_or(810u32)?;
        root.handles_mut()
            .install(job_obj, Rights::CREATE_PROCESS)
            .map_err(|_| 811u32)?;
        // `TRANSFER` on top of what the manager will hold: handing a capability
        // on is itself an authority, and this is the process that hands it on.
        root.handles_mut()
            .install(bus_obj, bus_rights | Rights::TRANSFER)
            .map_err(|_| 819u32)?;
    }

    // Publish the loader seam and the boot allocator for the trap hook, then
    // run. A check that forgets either gets a program that dies at its first
    // syscall with nothing to say.
    // SAFETY: the boot CPU alone; both are cleared after the run.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        let alias = tessera_karch_riscv64::KernelAddressSpace::from_root(
            kernel_space.root_phys(),
            DIRECT_MAP_BASE,
        );
        ROOT_LOADER = Some(RiscV64Loader {
            kernel_space: AddressSpace::from_arch(alias, Asid(0), 0),
        });
        // The transmute only erases the borrow's lifetime; the pointer is used
        // strictly inside that borrow.
        DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_riscv64::set_user_trap_hook(user_dispatch_hook);
    // SAFETY: transient raw access to the static executive.
    unsafe {
        kcore_exec().ok_or(812u32)?.run();
    }
    // SAFETY: the run is over; the hook can no longer fire on these.
    unsafe { DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: the run is over; no syscall can reach the seam again.
    let loader = unsafe { (&raw mut ROOT_LOADER).as_mut().and_then(Option::take) };
    let mut kernel_alias = loader.ok_or(813u32)?.kernel_space;
    REPORTS_FROM_ANY_THREAD.store(false, Ordering::SeqCst);

    // SAFETY: transient raw access to the static process table; the run ended.
    let exit = unsafe {
        let processes = kcore_processes();
        match processes.get(root_proc).map(kcore::process::Process::state) {
            Some(kcore::process::ProcessState::Exited(code)) => code,
            // Not exited means the root task never got to. `0xbad2` is a check
            // that forgot to publish the boot allocator, `0xbad1` a syscall
            // this port answers for nothing.
            other => {
                kprintln!(
                    "roottask: state {other:?} fault {:#x} reports={}",
                    USER_FAULT.load(Ordering::SeqCst),
                    REPORT_COUNT.load(Ordering::SeqCst),
                );
                return Err(814);
            }
        }
    };
    // The driver reports first and the root task last, so slot 0 is the
    // driver's. By position rather than by a tag, because the value it packs
    // has no spare bit to tag with.
    let driver_report = REPORTS[0].load(Ordering::SeqCst);

    // **Teardown, and it has to be complete.** `ProcessWait` reclaims every
    // child; the root task itself is boot's to clean up, and a check that left
    // it behind would hand the next one a process table with a corpse in it —
    // a reaped thread still claimed by a `Process` is the shape that shows up
    // later as `AccessDenied` on a valid pointer.
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
    Ok(Some(RootTaskReport {
        exit,
        launches: ROOT_LAUNCHES.load(Ordering::Relaxed),
        driver_report,
    }))
}

/// The startup word this port gives its root task: `blk-probe`'s relay-report
/// mode (its own `RELAY_REPORT`, bit 61), which is what a synthetic device can
/// answer.
const ROOT_DRIVER_RELAY_REPORT: usize = 1 << 61;
