// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The tick, the device lines, and the vector map — all of it on the local and
//! I/O APICs.
//!
//! # What this file used to be
//!
//! The 8259 PIC and the 8253 PIT, described in its own header as "the minimal
//! honest timer tick". It was honest, and it was also a deviation with a due
//! date: `docs/hardware/01-platform-and-cpu-support.md` ("Modern Hardware
//! Only") names both parts as permanently out of scope, and build/README.md's
//! D87 recorded that the oldest port was quietly contradicting the policy.
//!
//! Two things forced the swap rather than merely justifying it. A PIT tick is
//! one timer for the whole machine, and preemption needs one per CPU. And the
//! 8259 has no way to say which CPU an interrupt is for — the question it
//! cannot express is the question SMP is made of.
//!
//! # The vector map
//!
//! Vectors 0-31 are the architecture's exceptions. This kernel's own block is
//! 32-47, and every vector in it is assigned here:
//!
//! * **32** — the tick, from this CPU's local timer.
//! * **32 + line** — a device line the I/O APIC was told to route. Only line 3
//!   (the second serial port) is ever routed today.
//! * **46** — one CPU interrupting another.
//! * **47** — the local controller's spurious vector, which is never
//!   acknowledged.
//!
//! The two at the top sit inside the block rather than above it because the
//! trampoline table covers exactly these forty-eight vectors, and because the
//! lines they would otherwise be — the legacy disk interrupts — are ones this
//! kernel does not route and will not. That is a statement about this kernel's
//! own vector space, which it now assigns itself: the I/O APIC's redirection
//! table is programmed here, so "line 3 means vector 35" is a choice rather
//! than a fact about the chipset.
//!
//! Normative: docs/kernel/01-kernel-model.md ("Time"),
//! docs/hardware/01-platform-and-cpu-support.md ("Modern Hardware Only")
//! Budget: none (init path; the tick handler counts and acknowledges)

use crate::io::outb;
use core::sync::atomic::{AtomicU64, Ordering};
use tessera_karch::TimerControl;

/// Exception vectors end at 31; this kernel's own block starts here.
pub(crate) const IRQ_BASE: u64 = 32;
pub(crate) const IRQ_COUNT: u64 = 16;

/// The tick.
const TIMER_VECTOR: u64 = IRQ_BASE;
/// One CPU interrupting another.
pub const IPI_VECTOR: u8 = (IRQ_BASE + 14) as u8;
/// The local controller's "nothing in service after all" vector.
pub const SPURIOUS_VECTOR: u8 = (IRQ_BASE + 15) as u8;

const _: () = assert!((IPI_VECTOR as u64) < IRQ_BASE + IRQ_COUNT);
const _: () = assert!((SPURIOUS_VECTOR as u64) < IRQ_BASE + IRQ_COUNT);
const _: () = assert!(IPI_VECTOR != SPURIOUS_VECTOR);

/// The 8259 pair's command and data ports. Written once, to mask both
/// controllers, and never again — see [`silence_legacy_pic`].
const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xa0;
const PIC2_DATA: u16 = 0xa1;

/// Ticks each CPU has taken on its own timer.
///
/// One counter per CPU because there is one timer per CPU: a single counter
/// would answer "did the machine tick" where the question is "did *this* CPU
/// tick", and the two differ exactly when a CPU's own timer never started.
static TICKS: [AtomicU64; crate::CPU_TABLE_SLOTS] =
    [const { AtomicU64::new(0) }; crate::CPU_TABLE_SLOTS];

/// The slot of the CPU running this code, bounded so an index past the tables
/// counts nowhere rather than into another CPU's.
fn this_cpu() -> usize {
    let index = crate::percpu::current_cpu_index() as usize;
    if index >= crate::CPU_TABLE_SLOTS {
        0
    } else {
        index
    }
}
static UNEXPECTED_IRQS: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// Local-timer ticks per second, measured once at boot. Zero until then.
static TIMER_HZ: AtomicU64 = AtomicU64::new(0);

/// Puts the legacy pair beyond use.
///
/// **Masking, not initializing.** Firmware left these controllers configured
/// and possibly delivering, and a machine that came up with the legacy timer
/// live would take two unrelated ticks. Every line is masked, and nothing in
/// this kernel writes them again — the vectors they were remapped to are the
/// same ones the I/O APIC now delivers, so a stray legacy interrupt would
/// arrive indistinguishable from a real one.
fn silence_legacy_pic() {
    // SAFETY: the canonical 8259 initialization sequence, ending with every
    // line masked. This kernel owns both controllers and is switching them off;
    // the sequence is needed because a mask write alone is not defined against
    // whatever state firmware left.
    unsafe {
        outb(PIC1_CMD, 0x11); // ICW1: init, expect ICW4
        outb(PIC2_CMD, 0x11);
        outb(PIC1_DATA, 0xf8); // ICW2: vector offsets, clear of this kernel's
        outb(PIC2_DATA, 0xf8);
        outb(PIC1_DATA, 1 << 2); // ICW3: slave on line 2
        outb(PIC2_DATA, 2);
        outb(PIC1_DATA, 0x01); // ICW4: 8086 mode
        outb(PIC2_DATA, 0x01);
        outb(PIC1_DATA, 0xff); // and now every line, masked
        outb(PIC2_DATA, 0xff);
    }
}

/// Why the interrupt path could not be brought up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterruptInitError {
    /// The CPU has no x2APIC. `docs/hardware/01` says this kernel targets
    /// modern hardware; this is where that stops being a preference.
    NoX2Apic,
    /// The I/O controller did not describe a usable redirection table.
    NoIoApic,
    /// The reference timer did not describe a usable rate, so a tick at a
    /// stated frequency cannot be produced.
    NoReferenceClock,
}

/// Brings up the interrupt path on the boot CPU: the legacy pair off, this
/// CPU's local controller on, the I/O controller's table cleared, and the local
/// timer's rate measured.
///
/// `ioapic` and `hpet` are the virtual addresses the boot glue mapped those two
/// register blocks at, as uncached device memory.
///
/// # Safety
///
/// The boot CPU, once, with interrupts masked, the interrupt descriptor table
/// loaded, and both addresses mapped for the life of the kernel.
pub unsafe fn init_interrupts(ioapic: u64, hpet: u64) -> Result<u64, InterruptInitError> {
    if !crate::apic::supported() {
        return Err(InterruptInitError::NoX2Apic);
    }
    silence_legacy_pic();
    // SAFETY: the caller's contract, forwarded to each of the three.
    unsafe {
        crate::apic::init_cpu(SPURIOUS_VECTOR);
        crate::apic::record_cpu(0);
        crate::ioapic::init(ioapic).ok_or(InterruptInitError::NoIoApic)?;
        let reference_hz = crate::hpet::init(hpet).ok_or(InterruptInitError::NoReferenceClock)?;
        let hz = measure_timer_hz(reference_hz);
        TIMER_HZ.store(hz, Ordering::Release);
        Ok(hz)
    }
}

/// Brings up a secondary CPU's share: its own local controller.
///
/// The I/O controller and the reference clock are the machine's and were done
/// once; this is the half that is per CPU, exactly as the GIC's split is on the
/// other port.
///
/// # Safety
///
/// Once per CPU, on the CPU itself, with interrupts masked and the interrupt
/// descriptor table loaded.
pub unsafe fn init_cpu_interrupts(index: u32) {
    // SAFETY: the caller's contract. Recording the identifier is what makes
    // this CPU addressable; until then nothing can interrupt it.
    unsafe {
        crate::apic::init_cpu(SPURIOUS_VECTOR);
        crate::apic::record_cpu(index);
    }
}

/// Measures the local timer's rate against the reference clock.
///
/// The window is a hundredth of a second: long enough that the emulator's
/// counter granularity is noise against it, short enough not to be felt in a
/// boot. Both counters are read across the same interval, so what comes back is
/// a ratio and the reference's own accuracy is the only accuracy that matters.
///
/// # Safety
///
/// The local controller and the reference clock must both be initialized.
unsafe fn measure_timer_hz(reference_hz: u64) -> u64 {
    const WINDOW_DIVISOR: u64 = 100;
    let window = reference_hz / WINDOW_DIVISOR;
    // SAFETY: the caller's contract. The timer is masked throughout, so the
    // count-down delivers nothing.
    let elapsed = unsafe {
        crate::apic::count_down_during(u32::MAX, || {
            let Some(start) = crate::hpet::now() else {
                return;
            };
            while crate::hpet::now().unwrap_or(start).wrapping_sub(start) < window {
                core::hint::spin_loop();
            }
        })
    };
    u64::from(elapsed) * WINDOW_DIVISOR
}

/// The local APIC timer as this CPU's periodic tick source.
pub struct ApicTimer;

impl TimerControl for ApicTimer {
    fn start_periodic_this_cpu(hz: u32) {
        let timer_hz = TIMER_HZ.load(Ordering::Acquire);
        if timer_hz == 0 {
            // `init_interrupts` has not run or did not succeed, so the rate is
            // not known. Starting a timer at a rate this cannot honour would
            // produce a tick that looks right and is not.
            return;
        }
        let count = (timer_hz / u64::from(hz.max(1))).clamp(1, u64::from(u32::MAX)) as u32;
        // SAFETY: the controller is enabled (the rate is non-zero only after
        // `init_interrupts` enabled it) and the vector is in the table.
        unsafe { crate::apic::start_timer(TIMER_VECTOR as u8, count) }
    }

    fn ticks() -> u64 {
        TICKS[this_cpu()].load(Ordering::Relaxed)
    }

    fn ticks_on(index: u32) -> u64 {
        TICKS
            .get(index as usize)
            .map_or(0, |slot| slot.load(Ordering::Relaxed))
    }
}

/// Measured local-timer ticks per second, or zero before the boot measured it.
pub fn timer_hz() -> u64 {
    TIMER_HZ.load(Ordering::Acquire)
}

/// Interrupts delivered that nothing claimed.
pub fn unexpected_irqs() -> u64 {
    UNEXPECTED_IRQS.load(Ordering::Relaxed)
}

/// Interrupts the local controller withdrew between raising and delivery.
///
/// Counted separately from the unclaimed ones because they are not a fault:
/// they mean a source stopped asserting in the window where that is allowed.
/// A count that climbs steadily is a different problem from one that is zero,
/// and folding them together would hide both.
pub fn spurious_irqs() -> u64 {
    SPURIOUS.load(Ordering::Relaxed)
}

/// Routes device line `line` to this CPU and enables delivery.
///
/// The vector is `IRQ_BASE + line`, which is this kernel's own convention and
/// is now enforced here rather than inherited from a controller's remapping.
pub fn unmask_irq(line: u8) {
    // SAFETY: the vector is in this kernel's block and present in the table,
    // and the destination is this CPU, whose controller is enabled.
    unsafe {
        crate::ioapic::route(line, IRQ_BASE as u8 + line, crate::apic::id());
        crate::ioapic::unmask(line);
    }
}

/// Stops delivery of device line `line`.
pub fn mask_irq(line: u8) {
    // SAFETY: masking one redirection entry disturbs nothing else.
    unsafe { crate::ioapic::mask(line) }
}

/// Called from the trap dispatcher for vectors in this kernel's block.
pub(crate) fn handle_irq(vector: u64) {
    if vector == u64::from(SPURIOUS_VECTOR) {
        // The one interrupt that must not be acknowledged: the controller is
        // saying nothing is in service, and an acknowledgement would end
        // whatever genuinely is.
        SPURIOUS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if vector == TIMER_VECTOR {
        TICKS[this_cpu()].fetch_add(1, Ordering::Relaxed);
    } else if vector != u64::from(IPI_VECTOR) && !claimed_by_hook(vector) {
        UNEXPECTED_IRQS.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: acknowledging the interrupt this handler is inside of, exactly
    // once, on the CPU that took it.
    unsafe { crate::apic::eoi() }
}

/// Whether a device line has a hook registered to take it. The dispatcher calls
/// the hook itself after the acknowledgement; this only decides whether an
/// unclaimed count is warranted.
fn claimed_by_hook(vector: u64) -> bool {
    let _ = vector;
    crate::trap::has_device_irq_hook()
}
