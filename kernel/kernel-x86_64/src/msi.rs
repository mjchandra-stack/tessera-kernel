// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Message-signalled interrupts, and what a driver woken by one needs.
//!
//! **A PCI function has no wire.** It signals by writing a message to an
//! address naming a local controller and a vector naming an entry in this
//! kernel's own table — neither of which a ring-3 program may choose, which is
//! why programming the entry is boot's and the driver is told only that a port
//! exists (build/README.md, D326).
//!
//! What is here is the whole of that on this port: arming a function's first
//! MSI-X entry, the bridge from the vector to the port the resource graph
//! routed, the arm that answers a driver saying it is done, and the idle loop
//! that keeps the machine alive while a completion is still on its way. It
//! lives in a module of its own because the second class needed it (D327) and a
//! block check is not where a network driver should reach for its interrupts.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Interrupt Delivery"),
//! docs/kernel/03-paging-faults-and-exceptions.md

use crate::*;

/// Where the chosen function's MSI-X table is mapped while boot programs it.
///
/// A page of its own beside the interrupt controller's, and for the same
/// reason: the direct map reaches it as cacheable 2 MiB pages, and a device
/// structure written through a cacheable mapping works under an emulator and
/// is a fault on hardware.
pub(crate) const MSIX_TABLE_VA: u64 = crate::INTERRUPT_MMIO_BASE + 2 * FRAME_SIZE;

/// A device structure the kernel writes, addressed from a mapping of its page.
///
/// `ConfigSpace` is the accessor `tessera_pci` takes for anything it writes by
/// offset; this is the memory-mapped one. Configuration space itself is
/// reached through I/O ports on this machine — [`PortConfigSpace`] — and an
/// MSI-X table is not configuration space at all but a structure in a BAR,
/// which is why the two are different types rather than one with a mode.
pub(crate) struct MsixWindow {
    base: u64,
}

impl tessera_pci::ConfigSpace for MsixWindow {
    fn read32(&self, offset: u64) -> u32 {
        // SAFETY: `base` is a mapping of the function's MSI-X table page, made
        // by `arm_msix` below and live for the duration of its call.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: as `read32`.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// How many message-signalled interrupts this check's device raised.
pub(crate) static MSI_DELIVERIES: AtomicU64 = AtomicU64::new(0);

/// The same, split by vector, so a check can say *which* queue answered.
pub(crate) static MSI_BY_VECTOR: [AtomicU64; tessera_karch_x86_64::MSI_VECTOR_COUNT as usize] =
    [const { AtomicU64::new(0) }; tessera_karch_x86_64::MSI_VECTOR_COUNT as usize];

/// Forgets what has been delivered, at the start of a check that counts.
pub(crate) fn forget_deliveries() {
    MSI_DELIVERIES.store(0, Ordering::SeqCst);
    for slot in &MSI_BY_VECTOR {
        slot.store(0, Ordering::SeqCst);
    }
}

/// The bridge from a message the device wrote to the port a ring-3 driver is
/// parked on.
///
/// **The vector is the source.** `device_route_irq` bound the driver's port to
/// the line the graph records for this device, and that line is the vector the
/// MSI-X entry raises — so signalling the vector is signalling exactly the
/// driver that was routed it, with no table here to get wrong.
///
/// Nothing is masked and nothing is acknowledged at the device. A message is
/// edge-triggered by construction: there is no line to hold high, so there is
/// no storm to prevent and no re-arming for the driver to do. The
/// acknowledgement the CPU needs is the local controller's, and the trap path
/// has already done it.
pub(crate) fn msi_bridge_hook(vector: u64) {
    let base = u64::from(tessera_karch_x86_64::MSI_VECTOR_BASE);
    let count = u64::from(tessera_karch_x86_64::MSI_VECTOR_COUNT);
    if vector < base || vector >= base + count {
        return;
    }
    MSI_DELIVERIES.fetch_add(1, Ordering::SeqCst);
    // **And which one**, because a device with a vector per queue is telling
    // the kernel which queue completed. A check that only counted the total
    // could not tell one queue answering twice from two answering once.
    MSI_BY_VECTOR[(vector - base) as usize].fetch_add(1, Ordering::SeqCst);
    // A device interrupt is where the outside world becomes work, so the port
    // event and everything the woken driver does on its behalf are attributed
    // to a fresh cause rather than to whichever thread it landed on.
    kcore::trace::set_current_correlation(kcore::trace::mint());
    exec_ref().port_signal(vector, 1, 1);
}

/// `IrqComplete`: the caller says it has handled its device's interrupt.
///
/// **On this port that is usually nothing to do, and saying so is the point.**
/// The authority check and the lines themselves are
/// [`kcore::dispatch::resolve_irq_lines`], because which lines a device has is
/// the resource graph's answer; what is port-local is what re-arming means. A
/// wired line delivered through the I/O APIC is masked while its driver works
/// and unmasked here. A **message** is edge-triggered by construction — there
/// is no line held asserted, nothing was masked to deliver it, and the local
/// controller was acknowledged by the trap path before the driver ever ran. So
/// a device whose line is this kernel's message vector completes having done
/// nothing, and answers `Ok` rather than `ENOSYS`: a driver saying "I am done"
/// is protocol, and a port that refused it would make every driver ask which
/// machine it is on.
pub(crate) fn irq_complete(caller: kcore::thread::ThreadId, args_ptr: u64) -> i64 {
    use kcore::syscall::encode_result;

    let mut lines = [0u32; kcore::devmgr::MAX_IRQ_LINES];
    // SAFETY: transient raw access to the static process table.
    let processes = unsafe { &mut *(&raw mut PROCESSES) };
    let count = match kcore::dispatch::resolve_irq_lines(
        exec_ref(),
        processes,
        caller,
        args_ptr,
        &mut lines,
    ) {
        Ok(count) => count,
        Err(e) => return encode_result(Err(e)),
    };
    for intid in &lines[..count] {
        let base = u32::from(tessera_karch_x86_64::MSI_VECTOR_BASE);
        if *intid >= base && *intid < base + u32::from(tessera_karch_x86_64::MSI_VECTOR_COUNT) {
            continue;
        }
        if let Ok(line) = u8::try_from(*intid) {
            tessera_karch_x86_64::unmask_irq(line);
        }
    }
    encode_result(Ok(0))
}

/// Passes of the executive a completion may take to arrive, for a check whose
/// device answers as soon as it is asked.
///
/// **Three times the largest ever observed, rounded up to the next hundred,
/// with a hundred as the floor** — the rule the other port's pumps are sized
/// by. Measured at 6 for the block class and 0 for the network one, which is
/// the floor doing the work rather than a derivation.
pub(crate) const PUMP_BUDGET: u32 = 100;

/// The wall clock a check that waits on a peer's silence is given.
///
/// **Time, not passes.** A flow client's last leg gives up on a peer that says
/// nothing, and that costs eight seconds of real time however many times this
/// loop goes round — while a network that is answering ends a pass every time a
/// frame lands, so a pass budget large enough for the silence is spent in a
/// second of chatter. The eight seconds the transport spends giving up, and
/// room; a run that reaches its claims leaves the moment it does, so this is
/// only ever the cost of a run that fails.
pub(crate) const PUMP_BUDGET_WAITING_MS: u64 = 20_000;

/// How often the pump's halt is ended by something other than the device.
const PUMP_TICK_HZ: u32 = 100;

/// Runs the executive, and keeps running it for as long as a message may still
/// arrive.
///
/// **A completion is asynchronous, so it can land after every thread has
/// parked** — the driver on its interrupt port, the service and its client
/// inside their calls. `run` then returns with nothing runnable, and a wake
/// that arrives a moment later has nobody to deliver it to. The boot context is
/// the idle loop: halt with interrupts unmasked, and re-enter the executive
/// when one lands.
///
/// **Unmasked here and nowhere else, every iteration.** Boot masks interrupts
/// at reset and the executive's own scheduling runs masked; a halt with them
/// still masked returns without ever taking the interrupt, and the pump then
/// spins its whole budget while the completion sits waiting. Between runs this
/// holds no borrow of the executive at all, which is what makes the hook's
/// `port_signal` safe to take from interrupt context.
///
/// Returns whether the loop stopped on its budget rather than its condition — a
/// truncated run has not earned a verdict either way (D311), so the caller says
/// so rather than judging what a half-finished composition happened to leave.
pub(crate) fn pump_for(what: &str, budget_ms: u64, mut done: impl FnMut() -> bool) -> bool {
    use tessera_karch::{CpuOps as _, InterruptControl as _, TimerControl};
    tessera_karch_x86_64::ApicTimer::start_periodic_this_cpu(PUMP_TICK_HZ);
    // **The tick, not the cycle counter.** `monotonic_nanos` divides the
    // counter by a frequency the machine reports, and under an emulator there
    // is no invariant one to report — so it answers zero, for ever, and a
    // deadline built on it never arrives. The timer this loop started is a
    // clock this machine actually has: each tick is a known fraction of a
    // second because the pump is what set the rate.
    let started = <tessera_karch_x86_64::ApicTimer as TimerControl>::ticks();
    let budget_ticks = budget_ms * u64::from(PUMP_TICK_HZ) / 1_000;
    let mut spent = false;
    loop {
        exec_ref().run();
        if done() {
            break;
        }
        let elapsed = <tessera_karch_x86_64::ApicTimer as TimerControl>::ticks() - started;
        if elapsed >= budget_ticks {
            spent = true;
            break;
        }
        Cpu::enable();
        Cpu::halt_until_interrupt();
        Cpu::disable();
    }
    let elapsed = <tessera_karch_x86_64::ApicTimer as TimerControl>::ticks() - started;
    let elapsed_ms = elapsed * 1_000 / u64::from(PUMP_TICK_HZ);
    if spent {
        kprintln!(
            "{what}: pump used all {budget_ms} ms — the loop stopped on its budget, not its condition"
        );
        return true;
    }
    kprintln!("{what}: pump used {elapsed_ms} ms of {budget_ms}");
    false
}

/// The same loop, bounded by **passes** instead of by time.
///
/// **A pass count is a proxy for time that stops being one the moment anything
/// waits for time to pass**, which is why the two exist: a check whose device
/// answers the moment it is asked is bounded by how many times it is worth
/// asking, and one that waits on a peer's silence is bounded by how long that
/// silence lasts. Same loop, same masking window, different bound.
pub(crate) fn pump_the_run(what: &str, budget: u32, mut done: impl FnMut() -> bool) -> bool {
    use tessera_karch::{CpuOps as _, InterruptControl as _, TimerControl as _};
    // **A tick, so the halt below is bounded.** Nothing else interrupts this
    // CPU during this check — the local timer is started by the scheduler
    // check, which runs later — so a halt waiting only for the device's
    // message waits for ever when the message does not come, and a check that
    // hangs says less than one that fails. No tick hook is installed here, so
    // the tick does nothing but end the halt.
    tessera_karch_x86_64::ApicTimer::start_periodic_this_cpu(PUMP_TICK_HZ);
    let mut left = budget;
    loop {
        exec_ref().run();
        // Asked with no thread on the CPU: the caller's own condition, which
        // is what "this composition is complete" means for its programs.
        if done() || left == 0 {
            break;
        }
        left -= 1;
        Cpu::enable();
        Cpu::halt_until_interrupt();
        Cpu::disable();
    }
    if left == 0 {
        kprintln!(
            "{what}: pump used all {budget} — the loop stopped on its budget, not its condition"
        );
        return true;
    }
    kprintln!("{what}: pump used {} of {budget}", budget - left);
    false
}

/// Programs the function's first MSI-X entry to raise this kernel's vector,
/// and enables MSI-X.
///
/// **Boot's job, not a driver's.** Where an interrupt goes is a platform fact:
/// the address names a local controller and the data names a vector in an
/// interrupt descriptor table, neither of which a ring-3 program can know and
/// neither of which it may choose. A driver is told only that a port exists,
/// exactly as it is told offsets into a window rather than physical addresses.
///
/// Returns the vector, which is what the resource graph records as the
/// device's line.
pub(crate) fn arm_msix(
    host: &tessera_pci::Host,
    config: &mut PortConfigSpace,
    function: &tessera_pci::Function,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    unit: Option<&mut crate::vtd::Vtd>,
) -> Result<u32, u32> {
    let mut vectors = [0u32; 1];
    arm_msix_entries(
        host,
        config,
        function,
        kernel_vm,
        frames,
        unit,
        MsixArming {
            entries: &[0],
            vectors: &mut vectors,
        },
    )?;
    Ok(vectors[0])
}

/// Programs one MSI-X entry per id in `entries`, each raising a vector of its
/// own, and enables MSI-X.
///
/// **A vector per queue, which is what the block exists for.** A controller
/// with more than one I/O queue raises a different message for each so its
/// driver never has to ask which one completed — it waits where that queue's
/// completions arrive. The entry ids are the device's (an NVMe driver creates
/// queue *n* with vector *n*); the vectors are this kernel's, handed out in
/// order from its own block, and `vectors[i]` is what the resource graph
/// records as the line for `entries[i]`.
/// Which of a device's table entries to program, and where this kernel's
/// answers go.
///
/// **One parameter because they are one correspondence**: `vectors[i]` is the
/// line `entries[i]` raises, and two slices that have to be the same length and
/// in the same order are a pair rather than two arguments.
pub(crate) struct MsixArming<'a> {
    pub(crate) entries: &'a [u16],
    pub(crate) vectors: &'a mut [u32],
}

pub(crate) fn arm_msix_entries(
    host: &tessera_pci::Host,
    config: &mut PortConfigSpace,
    function: &tessera_pci::Function,
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
    mut unit: Option<&mut crate::vtd::Vtd>,
    arming: MsixArming<'_>,
) -> Result<(), u32> {
    let capability =
        tessera_pci::find_capability(host, config, function.bdf, tessera_pci::CAP_MSIX)
            .map_err(|_| 70u32)?
            .ok_or(71u32)?;
    let table = tessera_pci::msix_table(host, config, function.bdf, capability, function)
        .map_err(|_| 72u32)?;
    if table.entries == 0 {
        return Err(73);
    }
    let Some((bar_base, bar_len)) = function.bars[table.bar] else {
        return Err(74);
    };
    let at = bar_base + u64::from(table.offset);
    // The entry this check programs must lie inside the BAR the table says it
    // is in. The device's own numbers, checked before they are trusted — the
    // same rule the virtio capability walk above obeys.
    if u64::from(table.offset) + u64::from(table.entries) * tessera_pci::MSIX_ENTRY_SIZE > bar_len {
        return Err(75);
    }
    let Some(page) = PhysFrame::from_base(PhysAddr::new(at & !(FRAME_SIZE - 1))) else {
        return Err(76);
    };
    // **Taken down first, because the window is one page and the boot has more
    // than one function to arm.** Leaving a previous device's mapping in place
    // and treating `AlreadyMapped` as success is what the block check could get
    // away with while it was the only caller: the second one then programmed
    // the *first* device's table, enabled MSI-X on its own, and waited for a
    // message that had been aimed at somebody else. Nothing is mapped here on
    // the first pass and the unmap says so by failing, which is not an error.
    let _ = kernel_vm.unmap_device_page(VirtAddr::new(MSIX_TABLE_VA));
    if kernel_vm
        .map_device_page(
            VirtAddr::new(MSIX_TABLE_VA),
            page,
            kcore::vm::DeviceReach::Kernel,
            frames,
        )
        .is_err()
    {
        return Err(76);
    }
    let mut window = MsixWindow {
        base: MSIX_TABLE_VA + (at & (FRAME_SIZE - 1)),
    };
    let MsixArming { entries, vectors } = arming;
    if entries.len() > vectors.len()
        || entries.len() > usize::from(tessera_karch_x86_64::MSI_VECTOR_COUNT)
    {
        return Err(79);
    }
    for (slot, entry) in entries.iter().enumerate() {
        // The device's own numbers, checked before they are trusted: an entry
        // past the table is one this function does not have.
        if *entry >= table.entries {
            return Err(80);
        }
        let vector = tessera_karch_x86_64::MSI_VECTOR_BASE + slot as u8;
        // **What the device is told to write, and who decides what it means.**
        // Without a remapping unit the message *is* the interrupt: the address
        // names a local controller and the data names a vector, both of them
        // fields the device supplies, so a device that can write into the
        // interrupt window can raise any vector on any CPU. With one, the
        // message carries a handle this kernel issued to this function for this
        // vector, and the vector and destination live in a table the device
        // cannot write — so the same forged write names an entry that either
        // does not exist or belongs to somebody else, and is blocked.
        //
        // **The handle is load-bearing and measured**: arming a function with a
        // handle it was not issued stops every interrupt it raises, and the
        // block check fails. What is *not* measured here is the format itself —
        // leaving these messages in the old one leaves the boot passing, because
        // this device model delivers a compatibility-format request rather than
        // blocking it. Real hardware blocks it, because `GCMD.CFI` is never
        // set; on this machine that is a fact about the emulator and not
        // something a claim can rest on.
        let (address, data) = match unit.as_deref_mut() {
            Some(unit) if unit.remaps_interrupts() => {
                let source = tessera_vtd::SourceId::new(
                    function.bdf.bus,
                    function.bdf.device,
                    function.bdf.function,
                );
                let handle = unit
                    .issue_handle(source, vector)
                    .map_err(|which| 90 + which)?;
                tessera_vtd::remappable_message(handle)
            }
            _ => tessera_karch_x86_64::msi_message(vector),
        };
        tessera_pci::program_msix_entry(&mut window, usize::from(*entry), address, data)
            .map_err(|_| 77u32)?;
        vectors[slot] = u32::from(vector);
    }
    tessera_pci::msix_enable(host, config, function.bdf, capability).map_err(|_| 78u32)?;
    Ok(())
}
