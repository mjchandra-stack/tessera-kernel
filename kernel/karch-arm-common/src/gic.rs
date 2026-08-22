// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! GICv2 interrupt controller: distributor plus per-CPU interface.
//!
//! The x86-64 port's counterpart is the 8259 PIC (`karch-x86_64/src/timer.rs`),
//! and the shapes are not comparable the way paging and context switching
//! were. A PIC has a mask register and an end-of-interrupt command. A GIC
//! splits into a *distributor* that decides which CPU an interrupt goes to
//! and a *CPU interface* that the local core acknowledges through, and the
//! acknowledge itself returns the interrupt number rather than the core
//! having to ask. That is why this is its own module here and a few functions
//! there.
//!
//! Priority is not a decoration on this controller: an interrupt whose
//! priority is not strictly below the CPU interface's mask is never
//! delivered, so `PRIORITY_MASK` and the per-interrupt priority set here have
//! to agree or the timer simply never fires — silently, with everything else
//! working.
//!
//! GICv2 is pinned rather than probed. Version 3 replaces the CPU interface
//! with system registers (`ICC_*`) and is a different driver, so the smoke
//! test names `gic-version=2` explicitly instead of taking QEMU's default,
//! which would otherwise change under us between releases.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Interrupt
//! controller interface"), docs/kernel/03-paging-faults-and-exceptions.md
//! Budget: none (interrupt entry is budgeted with the tick path)

use crate::mmio::{device_addr, read32, write32};
use core::sync::atomic::{AtomicU32, Ordering};

/// Distributor and CPU-interface bases on the QEMU `virt` machine.
/// The distributor's **physical** base. Every derived address below is
/// physical too, and each access site converts through [`device_addr`],
/// because the two ARM ports reach the GIC through different windows: AArch64
/// keeps the device identity map in `TTBR0`, ARM 32-bit empties it.
const GICD: usize = 0x0800_0000;
const GICC: usize = 0x0801_0000;

// Distributor registers.
const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_ICFGR: usize = 0xc00;
const GICD_SGIR: usize = 0xf00;

// CPU-interface registers.
const GICC_CTLR: usize = 0x00;
const GICC_PMR: usize = 0x04;
const GICC_IAR: usize = 0x0c;
const GICC_EOIR: usize = 0x10;

/// Priority mask: the CPU interface delivers only interrupts whose priority
/// value is numerically *lower* than this. Interrupts are configured at
/// [`INTERRUPT_PRIORITY`], which is below it.
const PRIORITY_MASK: u32 = 0xf0;
const INTERRUPT_PRIORITY: u8 = 0xa0;

/// The first shared peripheral interrupt. Below this are the software-generated
/// (0-15) and private peripheral (16-31) interrupts, which are banked per CPU:
/// each core has its own copy of those registers, so they need no routing and
/// [`GICD_ITARGETSR`] is read-only for them.
const FIRST_SPI: u32 = 32;

/// Interrupt IDs at or above this are the architecture's "no interrupt
/// pending" replies (1020-1023, chiefly the spurious 1023). They are the one
/// acknowledge that must *not* be followed by an end-of-interrupt.
const SPURIOUS_FLOOR: u32 = 1020;

/// The interrupt ID field of an acknowledgement.
const INTID_MASK: u32 = 0x3ff;

/// Interrupt IDs below this are software-generated — the ones a CPU sends to
/// another CPU. They are banked per CPU and their configuration is fixed by the
/// architecture.
pub const FIRST_PPI: u32 = 16;

/// The most CPU interfaces this controller can have.
///
/// **An architectural limit, not a configuration choice.** A target list in
/// [`GICD_SGIR`] and in [`GICD_ITARGETSR`] is eight bits wide, one per CPU
/// interface, so a GICv2 cannot address a ninth CPU however many the machine
/// has. A kernel built for more than this must either target a different
/// controller or accept that it cannot interrupt the rest.
pub const MAX_CPU_INTERFACES: usize = 8;

/// Each CPU's own bit in a target list, recorded by that CPU, indexed by the
/// kernel's dense index. Zero means no CPU has claimed the slot.
///
/// The indirection is the point. Three numbers name a CPU here and none of them
/// is the others: the affinity register the hardware reports, the dense index
/// the kernel assigns, and this — a bit position in the interrupt controller's
/// own numbering, which a CPU can only learn by reading a register that answers
/// differently depending on who is asking. A CPU records its own on the way up,
/// and this is where the kernel's number is turned into the controller's.
static CPU_INTERFACES: [AtomicU32; MAX_CPU_INTERFACES] =
    [const { AtomicU32::new(0) }; MAX_CPU_INTERFACES];

/// Brings up the distributor and this CPU's interface — the boot CPU's pair.
///
/// # Safety
///
/// The GIC's registers must be mapped as device memory at the addresses
/// above, and this must run once on the boot CPU before interrupts are
/// unmasked.
pub unsafe fn init() {
    // SAFETY: forwarded to the two halves, whose contracts this one's implies.
    unsafe {
        init_distributor();
        init_cpu_interface();
    }
}

/// Brings up the distributor: the half that is the machine's, not a CPU's.
///
/// # Safety
///
/// The distributor must be mapped as device memory, and this must run once on
/// the boot CPU before any interrupt is unmasked anywhere.
pub unsafe fn init_distributor() {
    // SAFETY: mapped device memory per the caller's contract; these writes
    // touch only the distributor's own control register.
    unsafe {
        // Off while it is reconfigured, then on.
        write32(device_addr(GICD + GICD_CTLR), 0);
        write32(device_addr(GICD + GICD_CTLR), 1);
    }
}

/// Brings up **this** CPU's interface.
///
/// Separate from the distributor because these registers are banked: the
/// address is the same on every CPU and the register behind it is not, so the
/// boot CPU cannot do this for anyone else. A CPU whose interface was never
/// enabled takes no interrupt at all and reports nothing about it — the
/// symptom is a CPU that simply never responds.
///
/// # Safety
///
/// The CPU interface must be mapped as device memory, and this must run once
/// per CPU, on the CPU it configures, before interrupts are unmasked there.
pub unsafe fn init_cpu_interface() {
    // SAFETY: mapped device memory per the caller's contract; both registers
    // are banked, so these writes reach this CPU's copies and no other's.
    unsafe {
        // Accept any priority at this core, then enable the interface.
        write32(device_addr(GICC + GICC_PMR), PRIORITY_MASK);
        write32(device_addr(GICC + GICC_CTLR), 1);
    }
}

/// Records this CPU's interface bit against the kernel's dense `index`, so
/// another CPU can address it.
///
/// Returns the bit, or `None` when `index` is beyond what this controller can
/// address or the CPU reports no bit of its own — neither of which is
/// corrected to a guess, because a wrong target list delivers an interrupt to
/// the wrong CPU and nothing reports that.
///
/// # Safety
///
/// The distributor must be mapped, [`init_cpu_interface`] must have run on this
/// CPU, and `index` must be this CPU's and held by no other.
pub unsafe fn record_cpu_interface(index: u32) -> Option<u32> {
    let slot = index as usize;
    if slot >= MAX_CPU_INTERFACES {
        return None;
    }
    // SAFETY: mapped device memory per the caller's contract.
    let mask = unsafe { cpu_target_mask() };
    if mask == 0 {
        return None;
    }
    CPU_INTERFACES[slot].store(mask, Ordering::Release);
    Some(mask)
}

/// Sends software-generated interrupt `sgi` to the CPU at dense `index`.
///
/// Returns `false` when that CPU never recorded an interface bit, which is the
/// honest answer to "interrupt a CPU this controller cannot name" — the
/// alternative is a target list of zero, which the distributor accepts and
/// delivers to nobody.
///
/// # Safety
///
/// `sgi` must be below [`FIRST_PPI`], and the target CPU's interface must be
/// initialized — an interrupt delivered to a CPU that cannot acknowledge it
/// stays active at that CPU's interface for ever.
pub unsafe fn send_sgi(index: u32, sgi: u32) -> bool {
    let slot = index as usize;
    if slot >= MAX_CPU_INTERFACES {
        return false;
    }
    let target = CPU_INTERFACES[slot].load(Ordering::Acquire);
    if target == 0 {
        return false;
    }
    // SAFETY: mapped device memory. Target-list filter 0 means "use the list
    // below", which is this one CPU and no other.
    unsafe {
        write32(
            device_addr(GICD + GICD_SGIR),
            ((target & 0xff) << 16) | (sgi & 0xf),
        );
    }
    true
}

/// Sends software-generated interrupt `sgi` to every CPU interface except this
/// one.
///
/// The controller's own "all but me" filter, rather than a loop over recorded
/// bits: it needs no table, and it reaches CPUs the kernel has no index for —
/// which is the right behaviour for a broadcast and the wrong one for a
/// targeted send, hence two functions.
///
/// # Safety
///
/// As [`send_sgi`], for every CPU on the machine.
pub unsafe fn broadcast_sgi(sgi: u32) {
    const TO_ALL_BUT_SELF: u32 = 1 << 24;
    // SAFETY: mapped device memory; the filter makes the target list unused.
    unsafe { write32(device_addr(GICD + GICD_SGIR), TO_ALL_BUT_SELF | (sgi & 0xf)) }
}

/// Whether an interrupt ID is software-generated — sent by a CPU rather than
/// by a device.
pub const fn is_sgi(id: u32) -> bool {
    id < FIRST_PPI
}

/// Configures `intid` as **edge**-triggered.
///
/// Wired device lines are level-triggered and stay asserted until the driver
/// services the device — the reset default, and right for them. A
/// message-signalled interrupt is not a line: the sender raises and drops it
/// in one action (a GICv2m doorbell write is a pulse), so a pending state that
/// only exists while the input is high never latches, and the interrupt is
/// simply lost. Two bits per interrupt; the upper one selects edge.
///
/// # Safety
///
/// [`init`] must have run, and `intid` must be an SPI (32 and above) — the
/// configuration of SGIs and PPIs is fixed by the architecture.
pub unsafe fn set_edge_triggered(intid: u32) {
    // SAFETY: mapped device memory, per `init`'s contract. Read-modify-write
    // because the register packs sixteen interrupts, and the fifteen this call
    // does not own must keep their configuration.
    unsafe {
        let register = GICD + GICD_ICFGR + (intid as usize / 16) * 4;
        let shift = (intid % 16) * 2;
        let current = read32(device_addr(register));
        write32(
            device_addr(register),
            (current & !(0b11 << shift)) | (0b10 << shift),
        );
    }
}

/// The reading CPU's own bit in a [`GICD_ITARGETSR`] target list.
///
/// The architecture provides no register that simply states "which CPU
/// interface am I". What it provides instead is this: the target fields for
/// interrupts 0-31 are read-only, and each returns *the value that corresponds
/// to the PE reading it*. So a core learns its own bit by reading the target
/// field of any banked interrupt, and byte 0 is as good as any.
///
/// Zero is not a legal answer for a PE that can perform the read, and it is
/// returned rather than corrected: a zero mask means [`enable`] would route
/// every shared interrupt to no CPU at all, which is a fact about the machine
/// the boot path must be able to report (`docs/lifecycle/04`, "No Silent
/// Fallback") — not one to paper over with a guess at CPU 0.
///
/// # Safety
///
/// The distributor must be mapped as device memory at [`GICD`].
pub unsafe fn cpu_target_mask() -> u32 {
    // SAFETY: mapped device memory, per the caller's contract. The first
    // ITARGETSR word covers interrupts 0-3 and is read-only, so this read has
    // no side effects.
    let targets = unsafe { read32(device_addr(GICD + GICD_ITARGETSR)) };
    targets & 0xff
}

/// Routes `intid` to this CPU and enables it.
///
/// **The routing write is what makes the first sentence true.** A GIC with one
/// CPU interface makes [`GICD_ITARGETSR`] read-as-zero/write-ignored and sends
/// every interrupt to the only core there is, so a driver that never wrote it
/// looked correct for as long as the machine had one core. On a distributor
/// with more than one interface the register becomes real, and its reset value
/// is zero — a target list naming no CPU. The interrupt then stays pending at
/// the distributor for ever, and the only symptom is a device whose completion
/// never arrives.
///
/// # Safety
///
/// [`init`] must have run, and the caller must be entitled to take this
/// interrupt.
pub unsafe fn enable(intid: u32) {
    // SAFETY: mapped device memory, per `init`'s contract. The priority and
    // target writes are byte-wide because both registers are byte-per-interrupt
    // arrays; the enable is a write-1-to-set bit, so it disturbs no other
    // interrupt. The target write is skipped below the first SPI, where the
    // field is read-only and the interrupt is already this core's own.
    unsafe {
        let priority = device_addr(GICD + GICD_IPRIORITYR + intid as usize) as *mut u8;
        priority.write_volatile(INTERRUPT_PRIORITY);
        if intid >= FIRST_SPI {
            let target = device_addr(GICD + GICD_ITARGETSR + intid as usize) as *mut u8;
            target.write_volatile(cpu_target_mask() as u8);
        }
        let bank = (intid / 32) as usize * 4;
        write32(device_addr(GICD + GICD_ISENABLER + bank), 1 << (intid % 32));
    }
}

/// Disables `intid` at the distributor.
///
/// # Safety
///
/// [`init`] must have run.
pub unsafe fn disable(intid: u32) {
    // SAFETY: mapped device memory; ICENABLER is write-1-to-clear, so this
    // disturbs no other interrupt.
    unsafe {
        let bank = (intid / 32) as usize * 4;
        write32(device_addr(GICD + GICD_ICENABLER + bank), 1 << (intid % 32));
    }
}

/// Acknowledges the highest-priority pending interrupt, returning the raw
/// acknowledgement. Pass it back to [`end_of_interrupt`] unchanged — it
/// carries the source CPU alongside the ID, and the controller wants both.
///
/// # Safety
///
/// Call only from interrupt context on a core whose interface is initialized.
pub unsafe fn acknowledge() -> u32 {
    // SAFETY: mapped device memory. Reading IAR has the side effect of
    // acknowledging, which is exactly the intent here.
    unsafe { read32(device_addr(GICC + GICC_IAR)) }
}

/// Signals completion of the interrupt `acknowledgement` identified.
///
/// # Safety
///
/// `acknowledgement` must be a value [`acknowledge`] returned on this core,
/// and must not be a spurious reply (see [`intid`]).
pub unsafe fn end_of_interrupt(acknowledgement: u32) {
    // SAFETY: mapped device memory; writing EOIR completes the interrupt the
    // caller acknowledged.
    unsafe { write32(device_addr(GICC + GICC_EOIR), acknowledgement) }
}

/// The interrupt ID an acknowledgement names.
pub const fn intid(acknowledgement: u32) -> u32 {
    acknowledgement & INTID_MASK
}

/// True when an acknowledgement means "nothing to handle" — the case where
/// no end-of-interrupt may be issued.
pub const fn is_spurious(acknowledgement: u32) -> bool {
    intid(acknowledgement) >= SPURIOUS_FLOOR
}
