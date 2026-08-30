// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel executive: the single owner of the run-time state a channel
//! operation touches — the `Scheduler` and the `ChannelTable`. It lives behind
//! a `static` and is re-borrowed per operation. This is the same
//! boot-CPU-justified pattern the scheduler already uses; the compiler fences
//! in `Scheduler::switch_to` keep reads after a handoff honest.
//!
//! **Re-borrowing per operation does not mean one borrow at a time.** The
//! blocking methods suspend the calling thread *inside* their own `&mut self`,
//! so a thread parked in `receive` holds a borrow until it resumes — which for
//! a server is the rest of the boot. Thirteen are live at the end of one, and
//! [`occupancy`] is what counts them. That is the fact the machine-half lock
//! had to be designed around, and it is why [`crate::machine_lock`] puts its
//! hold *down* at a park rather than trying to hold one for a method that may
//! never return.
//!
//! The load-bearing operation is `call`: it sends a request and hands off
//! *directly* to a waiting callee, then the reply hands off directly back —
//! two context switches per round trip, no run-queue traffic. That is the
//! mechanism budget B3 depends on (docs/architecture/03; the two-switch check
//! is docs/prototypes/01). Synchronous call chains are depth-limited (default
//! 8, docs/kernel/04). The caller's priority is carried to the callee for the
//! call's duration (the inheritance seam; deviation D18).
//!
//! Normative: docs/kernel/04-synchronization-and-ipc-guarantees.md
//! ("Synchronous Call Scheduling"), docs/kernel/02-scheduling-memory-ipc.md
//! Budget: B3 (round trip), B4 (per handle), B19 (scaling) — the call path;
//! unmeasured until the perf rig lands (build/README.md, D20)

use crate::devmgr::{
    DeviceTable, DmaFault, DmaFaultOutcome, InterruptRouter, IsolationPolicy, LeaseEndReason,
    RouteEndReason,
};
use crate::ipc::{Channel, ChannelTable, EndpointId, Message};
use crate::job::{
    Job, JobId, JobLimits, JobTable, MAX_JOBS, Member, SIGNAL_EMPTY, SIGNAL_MEMBER_EXIT,
};
use crate::object::ObjectId;
use crate::port::{MAX_PORTS, PortEvent, PortId, PortTable};
use crate::rights::Rights;
use crate::sched::{MAX_THREADS, Scheduler};
use crate::thread::Thread;
use crate::thread::ThreadId;
use crate::wait::{WaitKey, WaitSet};
use tessera_karch::{ContextOps, KError};

/// Maximum nested synchronous calls per thread (docs/kernel/04).
pub const MAX_SYNC_DEPTH: u8 = 8;

/// Who is inside the executive, and how deep — the observable the machine-half
/// lock will be judged by, built before the lock so the "before" is measured
/// rather than assumed.
///
/// # Two different questions
///
/// **How many threads are inside on one CPU** turned out to be the finding.
/// The executive is re-entrant by construction: [`Executive::call`] holds
/// `&mut self` across a handoff, the callee runs and takes its own, and the
/// caller's frame is suspended in the middle of the first. That predicts a
/// transient nesting of two during a round trip. What a boot actually shows is
/// **fourteen at the deepest and thirteen still inside when the boot ends** —
/// because the blocking methods are where servers *live*: a thread parked in
/// `receive` or `reply_receive` is suspended inside a `&mut Executive` and
/// holds that borrow for as long as it is parked, which is for ever. The
/// thirteen are not a leak; they are the steady state.
///
/// Two consequences, and the second is why this exists:
///
/// * Aliasing `&mut` is UB by the language's rules. It is sound in practice
///   here only because a suspended frame reads nothing until it resumes and
///   one CPU runs one thread at a time — a fact about the code, not a property
///   the type carries.
/// * **A hold on the machine tables cannot survive a park.** One taken on
///   entry to `receive` and left there would be held by every parked server,
///   so the first one to park would stop the machine. What
///   [`crate::machine_lock`] does instead is take the hold at the method
///   boundary — where it is cheap, and where the method's update is one
///   section rather than as many as it has accesses — and *put it down* at the
///   park, picking it back up when the thread runs again. Knowing that before
///   writing it is the whole point of measuring first.
///
/// **How many CPUs are inside** was one, for a reason that was not the lock:
/// no CPU but the boot CPU reached the executive at all (D8's remainder). It
/// is more than one now — a secondary dispatches out of its own half
/// (build/README.md D236) — so the claim reporting it inverted, from
/// `exec.one-cpu` to `exec.multi-cpu`. The facility is unchanged and that is
/// the point of having built it before the lock: the same counter that
/// recorded the restriction is what records its removal.
pub mod occupancy {
    use crate::atomic::{AtomicU64, CpuCounter};
    use crate::percpu::{MAX_CPUS, PerCpu, current_index};
    use core::sync::atomic::Ordering;

    /// Threads currently inside a blocking executive method, per CPU.
    ///
    /// A count and not a bit, because one CPU legitimately has several: the
    /// suspended caller and the callee running under it are both inside.
    ///
    /// Relaxed load/store rather than a read-modify-write, following
    /// [`crate::epoch`]'s per-CPU depth: a slot is written only by the CPU it
    /// belongs to, so there is nothing for an atomic read-modify-write to
    /// defend against, and `kcore::atomic::AtomicU64` has neither a `fetch_sub`
    /// nor a compare-and-swap to offer — on a 32-bit target it is a word pair.
    static DEPTH: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

    /// The deepest each CPU has been, kept per CPU for the same reason: a
    /// single high-water mark would need a compare-and-swap to be exact, and
    /// taking the maximum of an array at reporting time needs nothing.
    static DEEPEST: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

    /// Every CPU that has ever called into the executive, as a bitmap.
    ///
    /// Ever, rather than currently: a second CPU that entered and left would
    /// have raced whatever the first was doing, and a sample taken afterwards
    /// would find nothing. The question is whether it happened at all, so the
    /// record has to be one that cannot be un-set.
    static VISITORS: AtomicU64 = AtomicU64::new(0);

    /// Records that this CPU reached the executive.
    ///
    /// Called from the port's accessor rather than from the methods, because
    /// the accessor is the one place every path goes through — instrumenting a
    /// hundred methods would measure whichever ones were remembered.
    pub fn note_visit() {
        note_visit_from(current_index());
    }

    /// Records that `index` reached the executive.
    ///
    /// Split from [`note_visit`] the way `Executive::cpu_at` is split from
    /// `Executive::cpu`, and for the same reason: a host test cannot make a
    /// second CPU visit by installing a per-CPU index source, because that
    /// source is one process-wide store and pointing it at CPU 1 would move
    /// every other parallel test's per-CPU state with it.
    pub fn note_visit_from(index: u32) {
        if index >= PerCpu::<u8>::capacity() {
            return;
        }
        VISITORS.fetch_or(1 << index, Ordering::Release);
    }

    /// CPUs that have reached the executive.
    pub fn visitors() -> u64 {
        VISITORS.load(Ordering::Acquire)
    }

    /// How many distinct CPUs have reached the executive.
    pub fn visitor_count() -> u32 {
        visitors().count_ones()
    }

    /// How many threads are inside a blocking method right now, across every
    /// CPU.
    ///
    /// Read at the end of a boot this should be zero: the CPU asking is not
    /// itself inside one, and any other thread still inside is one that
    /// entered and never came out. That is a different finding from nesting —
    /// a borrow that was never released rather than one legitimately spanning
    /// a handoff — and the two are told apart by this number, not by the
    /// high-water mark.
    pub fn current() -> u64 {
        let mut live = 0;
        for slot in &DEPTH {
            live += slot.load(Ordering::Acquire);
        }
        live
    }

    /// The deepest any one CPU has nested inside a blocking method.
    pub fn deepest() -> u64 {
        let mut deepest = 0;
        for slot in &DEEPEST {
            deepest = deepest.max(slot.load(Ordering::Acquire));
        }
        deepest
    }

    /// Marks a thread as being inside a blocking executive method for as long
    /// as it is alive.
    ///
    /// A guard rather than a pair of calls: these methods return from several
    /// places, and a decrement that has to be remembered at each of them is one
    /// that will be forgotten at one of them.
    /// The suspending methods, so a thread still inside one at the end of a
    /// boot can be attributed to the call it is parked in rather than merely
    /// counted.
    #[derive(Clone, Copy)]
    pub enum Site {
        Receive = 0,
        ReceiveAny = 1,
        Call = 2,
        Reply = 3,
        ReplyReceive = 4,
        WaitOnAddress = 5,
        SystemSuspend = 6,
        PortWait = 7,
    }

    /// How many threads have entered and left each method, per CPU.
    ///
    /// **Two monotonic counters and a subtraction, not one number that goes up
    /// and down.** It used to be one `AtomicU64` per site, incremented with a
    /// load and a store — a read-modify-write that is not atomic, and which
    /// was correct only while one CPU ever entered these methods. Two CPUs
    /// entering `receive` at the same moment both read *n* and both store
    /// *n+1*, and one of them is lost. That became reachable the moment a
    /// secondary started doing IPC (build/README.md, D237), and it is the
    /// class of defect this whole phase is about: an operation that was never
    /// atomic, in code whose justification was that nothing else ran.
    ///
    /// Per CPU because a `CpuCounter` has one writer by contract, and the
    /// writer here is fixed: [`Inside`] records the CPU it entered on and uses
    /// that same index when it drops.
    static ENTERED: [[CpuCounter; 8]; MAX_CPUS] =
        [const { [const { CpuCounter::new(0) }; 8] }; MAX_CPUS];
    static LEFT: [[CpuCounter; 8]; MAX_CPUS] =
        [const { [const { CpuCounter::new(0) }; 8] }; MAX_CPUS];

    /// How many threads are inside `site` right now, across every CPU.
    pub fn at_site(site: Site) -> u64 {
        live_at(site as usize)
    }

    /// How many threads are inside `site` right now, across every CPU.
    fn live_at(site: usize) -> u64 {
        let mut live = 0u64;
        for cpu in 0..MAX_CPUS {
            live = live.saturating_add(
                ENTERED[cpu][site]
                    .get(Ordering::Acquire)
                    .saturating_sub(LEFT[cpu][site].get(Ordering::Acquire)),
            );
        }
        live
    }

    /// The names, in `Site` order, for the boot line.
    const SITE_NAMES: [&str; 8] = [
        "receive",
        "receive_any",
        "call",
        "reply",
        "reply_receive",
        "wait_on_address",
        "system_suspend",
        "port_wait",
    ];

    pub struct Inside(u32, usize);

    impl Inside {
        pub fn enter(site: Site) -> Self {
            let slot = site as usize;
            let index = current_index();
            if index < PerCpu::<u8>::capacity() {
                ENTERED[index as usize][slot].add(1, Ordering::Release);
            }
            if index < PerCpu::<u8>::capacity() {
                let depth = &DEPTH[index as usize];
                let now = depth.load(Ordering::Relaxed) + 1;
                depth.store(now, Ordering::Relaxed);
                let deepest = &DEEPEST[index as usize];
                if now > deepest.load(Ordering::Relaxed) {
                    deepest.store(now, Ordering::Release);
                }
            }
            Self(index, slot)
        }
    }

    impl Drop for Inside {
        fn drop(&mut self) {
            if self.0 < PerCpu::<u8>::capacity() {
                LEFT[self.0 as usize][self.1].add(1, Ordering::Release);
            }
            if self.0 < PerCpu::<u8>::capacity() {
                let depth = &DEPTH[self.0 as usize];
                let now = depth.load(Ordering::Relaxed);
                depth.store(now.saturating_sub(1), Ordering::Relaxed);
            }
        }
    }

    /// Prints one line per method that still has a thread inside it.
    pub fn report_sites() {
        for (slot, name) in SITE_NAMES.iter().enumerate() {
            let live = live_at(slot);
            if live > 0 {
                crate::kprintln!("exec:   {} thread(s) parked in {}", live, name);
            }
        }
    }

    /// Emits the event and prints the boot line, returning the claim keys a
    /// boot check should assert.
    ///
    /// **`exec.one-cpu` is retired, and `exec.multi-cpu` is its negation.**
    /// The old claim said no CPU but the boot CPU reaches the executive, which
    /// is what kept the unlocked tables consistent before there was a lock;
    /// build/README.md D236 made it false on purpose, by giving a secondary
    /// its half of the executive to dispatch out of. A claim that says "one"
    /// cannot be quietly re-read as saying "more than one" — the sentence is
    /// different — so this is a new key rather than the old one with a new
    /// meaning, and a reader of an old log is not misled about which kernel
    /// produced it.
    ///
    /// Withheld rather than inverted on a machine with one CPU: `visitors` is
    /// one there because there is nothing else to be, and asserting a
    /// multi-CPU property on a uniprocessor would make the claim a statement
    /// about QEMU's command line.
    ///
    /// The nesting is printed and not claimed, because it is a measurement of
    /// something that is true and unwanted — a claim asserting it would have to
    /// be retired the moment it was fixed.
    pub fn report() -> &'static [&'static str] {
        let visitors = visitor_count();
        let deepest = deepest();
        crate::event::emit(
            crate::event::EventKind::ExecOccupancy,
            // Error for *none*, not for many. More than one CPU inside the
            // executive is what this kernel now does; zero means the demos
            // never reached it at all, which is the degenerate boot no other
            // line reports.
            if visitors == 0 {
                crate::event::Severity::Error
            } else {
                crate::event::Severity::Info
            },
            crate::event::Component::Scheduler,
            [u64::from(visitors), visitors_mask(), deepest, 0],
        );
        crate::kprintln!(
            "exec: reached by {} CPU(s); {} inside at the deepest, {} still inside",
            visitors,
            deepest,
            current()
        );
        report_sites();
        if visitors > 1 {
            &["exec.multi-cpu"]
        } else {
            &[]
        }
    }

    fn visitors_mask() -> u64 {
        visitors()
    }

    /// Records an entry on `cpu`, for a test that needs a thread inside a
    /// method on a CPU it cannot be. Split out the way `Executive::cpu_at` is,
    /// and for the same reason: the per-CPU index source is one process-wide
    /// store, and a test pointing it at another CPU would move every parallel
    /// test's state with it.
    #[cfg(test)]
    pub fn note_entry(cpu: usize, site: Site) {
        ENTERED[cpu][site as usize].add(1, Ordering::Release);
    }

    /// The matching exit — see [`note_entry`].
    #[cfg(test)]
    pub fn note_exit(cpu: usize, site: Site) {
        LEFT[cpu][site as usize].add(1, Ordering::Release);
    }

    /// Forgets everything recorded. Tests only — the counters are process-wide
    /// and a host test that did not reset would read whatever ran before it.
    #[cfg(test)]
    pub fn forget() {
        for slot in DEPTH.iter().chain(DEEPEST.iter()) {
            slot.store(0, Ordering::Release);
        }
        for cpu in 0..MAX_CPUS {
            for site in 0..8 {
                ENTERED[cpu][site].set(0, Ordering::Release);
                LEFT[cpu][site].set(0, Ordering::Release);
            }
        }
        VISITORS.store(0, Ordering::Release);
    }
}

/// Wire size of `ServiceNotice` (`driver_lifecycle.isl`).
const SERVICE_NOTICE_SIZE: usize = 32;

/// The port signal a device interrupt is delivered on.
///
/// One signal, because an interrupt line has one meaning: it fired. The port
/// facility's `(source, signal)` pair carries a second dimension for sources
/// that have several — a channel's readable and writable edges — and an
/// interrupt has exactly one, so this is a constant rather than a parameter.
/// Naming it is what lets [`Executive::device_route_irq`] and the revocation
/// path agree on which binding to undo without either of them being told.
pub const IRQ_PORT_SIGNAL: u8 = 1;

/// The signal a device's removal is delivered on, to the same port and source
/// its interrupts use.
///
/// **A driver parked waiting for an interrupt has to be woken by something,
/// and it must not be woken by something that looks like an interrupt.** A
/// device that has left the machine will never raise its line again, so a
/// driver blocked on it waits forever; delivering the removal on the
/// interrupt's own signal would wake it into servicing a completion that never
/// happened. A second signal on the same binding wakes the same sleeper and
/// says something different.
///
/// **Three, because a port's signal numbers are one namespace.** One is an
/// interrupt and two is a channel message (`ipc::SIGNAL_MESSAGE`), and a
/// driver waiting on a port that carries both sees the raw number — so a
/// removal numbered two would arrive at a resident server as a client request
/// and be answered as one.
///
/// Bound by the removal itself, on the port the route was using, and only
/// then. Binding it alongside every interrupt route would spend a second
/// binding slot per device for a signal almost no device ever raises.
pub const IRQ_PORT_SIGNAL_REMOVED: u8 = 3;

/// The signal a **holder** raises on a port it was granted, rather than one the
/// kernel raises on its behalf.
///
/// Every other signal in this namespace comes from the machine: an interrupt
/// line, a channel edge, a device leaving. This one comes from a driver that
/// demultiplexed something the interrupt controller cannot see — a GPIO
/// controller has eight lines and one interrupt output, so which line fired is
/// a fact only the driver that read the status register knows.
///
/// **Four, because a port's signal numbers are one namespace.** One is an
/// interrupt, two is a channel message (`ipc::SIGNAL_MESSAGE`) and three is a
/// device removal, and a waiter sees the raw number — so reusing one would
/// have a client read a software edge as hardware news.
pub const SOFTWARE_PORT_SIGNAL: u8 = 4;

/// `DEVICE_RECLAIM_LOST` cause: the reclaim message had no room for the
/// capability's handle. ABI (`kernel_event.isl`).
const RECLAIM_LOST_NO_HANDLE_ROOM: u64 = 1;
/// `DEVICE_RECLAIM_LOST` cause: the destination queue was full, so the manager
/// is not keeping up. ABI (`kernel_event.isl`).
const RECLAIM_LOST_QUEUE_FULL: u64 = 2;
/// `DEVICE_RECLAIM_LOST` cause: the object is not in the device graph, so there
/// is no recorded authority to hand it back with. Structurally impossible — the
/// reclaim list is built from the graph — and recorded rather than assumed away.
const RECLAIM_LOST_NOT_IN_GRAPH: u64 = 3;

/// Records a device capability that reclaim could not deliver. The device is
/// then as lost as it would have been without reclaim at all — which is a
/// result the system must be able to see, not a silence.
fn reclaim_lost(object: ObjectId, cause: u64) {
    crate::event::emit(
        crate::event::EventKind::DeviceReclaimLost,
        crate::event::Severity::Error,
        crate::event::Component::Driver,
        [object.raw() as u64, cause, 0, 0],
    );
}

/// Owns the scheduler and the channel table so one `&mut self` covers a call's
/// Frames the page cache may hold across every object.
///
/// Small on purpose. This is not a tuning number so much as the thing that
/// makes eviction reachable: a ceiling nothing meets is a ceiling nothing
/// tests, and the machines here have far more memory than any check could
/// exhaust. It is `pub` so a check can size an object against it rather than
/// guess.
pub const CACHE_FRAME_BUDGET: u32 = 8;
/// Of those, how many stay available to the write-back path.
///
/// **The reclaim deadlock in one number.** When every cached page is dirty, the
/// only way to free one is to write it back, and a write-back that needed a
/// frame from the same exhausted budget could never start. These are the frames
/// it can always have.
pub const CACHE_WRITE_BACK_RESERVE: u32 = 2;

/// One page-in the kernel is holding a thread for.
///
/// Enough to undo it: who to wake, where the call was registered so its late
/// reply can be discarded, and which object to mark faulted.
#[derive(Clone, Copy)]
struct PageInFlight {
    faulter: ThreadId,
    from: EndpointId,
    object: ObjectId,
    offset: u64,
}

/// cross-subsystem work.
/// State that belongs to the CPU running, not to the machine.
///
/// Everything here is touched by one CPU and no other: a run queue is per core
/// by `docs/kernel/08-multicore-scalability.md` ("Scheduler Structure"), and
/// the two arrays beside it are indexed by *that scheduler's* thread slot, so
/// they are meaningless to any other CPU by construction.
///
/// So there is **one of these per CPU**, and no lock around any of them —
/// which is the sentence `docs/kernel/08` asks for and the one
/// [`crate::machine_lock`] exists to make possible for everything else.
/// [`Executive::cpu`] is how a method reaches the calling CPU's, and nothing
/// reaches another CPU's: waking a thread somewhere else goes through
/// [`crate::wakeup`], which posts a bit for the owning CPU to act on itself.
/// One end of a freshly created channel: the endpoint and the object id a
/// ring-3 handle resolves through to reach it.
///
/// A named pair rather than a tuple because a create returns two of them, and
/// `((a, b), (c, d))` is a shape a reader has to decode before they can read
/// the call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BoundEndpoint {
    pub endpoint: EndpointId,
    pub object: ObjectId,
}

pub struct CpuLocal<C: ContextOps> {
    sched: Scheduler<C>,
    next_txn: u64,
    /// Per-thread nested-synchronous-call depth, for the chain limit.
    sync_depth: [u8; MAX_THREADS],
    /// A callee's own causal id, parked while it handles a synchronous call
    /// under the caller's id and restored when the call returns. Indexed by
    /// callee, so a nested chain saves one entry per level (bounded by
    /// `MAX_SYNC_DEPTH`, and a callee cannot re-enter while its own call is
    /// outstanding — it is blocked).
    saved_correlation: [u64; MAX_THREADS],
}

/// The executive: one CPU's scheduling state, and the machine-wide tables it
/// operates on.
///
/// **Only the per-CPU half is a type.** The split this milestone needs is the
/// one that says which state belongs to a CPU, because that is the half Phase 3
/// of `docs/roadmap/02-smp-bring-up-plan.md` replicates — a second CPU adds a
/// [`CpuLocal`], and what is left of this struct is the machine. Naming the
/// machine half as its own struct as well was tried and reverted: it is over
/// 400 KiB, an unoptimized build materializes a nested aggregate initializer in
/// a temporary before copying it into place, and two of those do not fit on a
/// stack. It overflowed the host tests' stack and then hung the AArch64 kernel
/// at 28 lines of boot. Making the constructor `const` avoids the temporary and
/// puts the structure in the image instead, measured at +428 KiB. So the
/// machine half stays flat, where each table's constructor writes straight into
/// its own field, and it becomes a type when it is small enough to be one.
///
/// **The two halves name threads differently, and must.** Everything in
/// [`CpuLocal`] is indexed by *this CPU's scheduler slot*, because that is what
/// a slot is for. Everything machine-wide holds a [`ThreadId`] instead: a slot
/// belongs to one CPU and is reused the moment its thread is reaped, so shared
/// state that remembered one would go on naming whichever thread landed in it
/// next. Every crossing between the two is an explicit `thread_id` or
/// `index_of`, and `index_of` returning `None` is how a thread that has since
/// exited is noticed rather than aliased
/// (`docs/roadmap/02-smp-bring-up-plan.md`, Phase 1d).
/// The machine-wide half of the executive: the tables every CPU shares.
///
/// A type at last. Phase 1 of the SMP plan left this flat inside
/// [`Executive`] and wrote down when to revisit it — "the machine half becomes
/// a type when it is small enough to be one" — because naming it created a
/// nested initializer whose temporary is over 400 KiB, which overflowed a host
/// test's stack and hung a kernel at 28 lines of boot, and because avoiding
/// that temporary with a `const` constructor cost a measured +428 KiB of
/// image.
///
/// It never had to shrink. Both halves of that were about **where the constant
/// lives**:
///
/// * A `const fn` called from a runtime context is an ordinary call — it
///   builds its value and returns it, and that value is the temporary. Forcing
///   the evaluation with `const { .. }` makes it a constant instead, and the
///   overflow goes away.
/// * The +428 KiB was [`Executive::new`] copying that constant into a field.
///   Put the machine half in a `static` and the constant *is* the storage:
///   nothing is copied, the field-by-field construction the flat version
///   emitted disappears with it, and the image comes out **12 KiB smaller**
///   than before this type existed.
///
/// The `static` is also the truth. There is one machine, and a second
/// `Executive` never brought a second set of channels with it in any sense
/// that mattered — see [`Machine::reset`] for the one place it looked as
/// though it did.
///
/// The point of naming it is that a lock needs something to own. Everything
/// here is reached by every CPU that does IPC; everything in [`CpuLocal`] is
/// reached only by the CPU it belongs to. That line is the whole of the SMP
/// design, and until now it existed only as a table in a plan document.
pub(crate) struct Machine {
    channels: ChannelTable,
    /// Threads blocked in `wait_on_address`, keyed by `(space, addr)`.
    waits: WaitSet,
    /// Async event-delivery ports.
    ports: PortTable,
    /// The job containment tree.
    jobs: JobTable,
    /// The device resource graph (Device object → I/O range + IRQ).
    devices: DeviceTable,
    /// Memory objects and the frames they own (`crate::memory`).
    memory: crate::memory::MemoryTable,
    /// Page-ins the kernel is holding a thread for, and the supervisor that
    /// decides what a missed one means.
    page_ins: [Option<PageInFlight>; crate::pager::MAX_PAGERS],
    /// Threads whose page-in was given up on, waiting to be told so.
    ///
    /// A thread cannot be handed an error while it is parked — it learns when
    /// it runs again, inside the `call` frame it is parked in — so the verdict
    /// is left here for that frame to pick up.
    expired_callers: [Option<ThreadId>; crate::pager::MAX_PAGERS],
    /// Deadline policy: how many misses before a pager is escalated.
    page_in_supervisor: crate::pager::PageInSupervisor,
    /// How many frames the page cache may hold, and how many of those are kept
    /// back for write-back.
    ///
    /// **A cache is a budget, not "whatever memory is left".** Without a
    /// ceiling nothing is ever reclaimed until the machine is out of memory,
    /// which is the point at which reclaiming is hardest — a dirty page needs
    /// its write-back to make progress, and a write-back needs memory. The
    /// reservation is the frames that stay available for exactly that
    /// (docs/kernel/03, "Write-Back Under Memory Pressure").
    cache_budget: crate::pager::WriteBackReservation,
    /// Which pager serves which object, and which page-ins are in flight.
    ///
    /// Here rather than beside the objects because the question it answers is
    /// about the *graph* — whether satisfying this request would wait on a
    /// pager already waiting on the requester — and that cannot be answered
    /// from one object's entry (`crate::pager::SelfPagingGraph`; docs/kernel/03,
    /// "Anti-Deadlock Rules").
    paging: crate::pager::SelfPagingGraph,
    /// Where each device is in its driver lifecycle. Not modelled here — the
    /// device manager owns the lifecycle — but recorded, so a declared
    /// transition can be checked against the history the kernel already has
    /// (`crate::lifecycle`).
    lifecycle: crate::lifecycle::LifecycleTable,
    /// The system wake-event counter and the wake holds that veto a suspend
    /// (`crate::power`). Here rather than in a static because the interrupt
    /// bridge that records a wake already reaches the Executive to signal a
    /// port, and two homes for one fact is one too many.
    wake: crate::power::WakeState,
    /// The thread parked inside a suspend commit, if the machine is asleep.
    ///
    /// One, not a set: the commit is the whole system stopping, and a second
    /// caller reaching it would mean user space was not frozen after all.
    sleeper: Option<ThreadId>,
    /// What woke it, recorded at interrupt time rather than reconstructed
    /// afterwards — which is the only moment the answer is certain.
    resumed_by: Option<ObjectId>,
    /// Where every thread that has entered a blocking executive method was
    /// when it entered — see [`Residents`].
    residents: Residents,
}

/// Which thread is in which slot of which CPU's scheduler, for the threads
/// that can be woken by identity.
///
/// # The question it answers
///
/// `Scheduler::index_of` turns an identity into a slot, and it can only do
/// that for the CPU asking, because a scheduler is per-CPU state and reading
/// another's is a data race. So a CPU holding the identity of a thread that
/// lives elsewhere gets `None` — indistinguishable from a thread that exited,
/// which is what every wake site in this file treated it as.
///
/// This is the missing half: the machine-wide map from identity to *(CPU,
/// slot)*, so `None` from the local lookup can be told apart into "on another
/// CPU" and "gone".
///
/// # Why it is machine state and not a `static`
///
/// It is written by whichever CPU parks a thread and read by whichever CPU
/// wants to wake one, so it is shared by definition — and everything shared
/// here is already reached under [`crate::machine_lock`], which makes plain
/// fields correct and atomics unnecessary. A `static` would need atomics *and*
/// would be one table across a host test suite that runs tests in parallel
/// threads, all of which answer `current_index()` with the boot CPU; each test
/// would be writing over the others' rows. Machine state gets a test its own.
///
/// # Why a slot may be recorded and stale
///
/// A row entry says "the last thread this CPU had in this slot when it entered
/// a blocking method". A thread that resumed and exited leaves its identity
/// behind until something else enters one from that slot. That is harmless in the direction it is used: the lookup is by
/// identity, identities are never reused, so a stale entry is either found for
/// the thread it names — which is then genuinely in that slot — or not found
/// at all. What it must not do is make a *slot* authoritative, and it does not:
/// the wakeup carries the identity too, and `Scheduler::unblock_thread` checks
/// it at the far end.
#[derive(Clone, Copy)]
pub(crate) struct Residents {
    /// `[cpu][slot]`, holding [`ThreadId::UNASSIGNED`] for never-used.
    rows: [[ThreadId; MAX_THREADS]; crate::percpu::MAX_CPUS],
}

impl Residents {
    const fn new() -> Self {
        Self {
            rows: [[ThreadId::UNASSIGNED; MAX_THREADS]; crate::percpu::MAX_CPUS],
        }
    }

    /// Records that `id` is in `slot` of `cpu`'s scheduler.
    fn record(&mut self, cpu: u32, slot: usize, id: ThreadId) {
        if let Some(row) = self.rows.get_mut(cpu as usize)
            && let Some(entry) = row.get_mut(slot)
        {
            *entry = id;
        }
    }

    /// The CPU and slot `id` was last recorded at, or `None`.
    ///
    /// **One row, not the whole table.** A `ThreadId` carries the CPU that
    /// minted it in its high bits (`crate::thread`), and a thread is minted by
    /// the CPU that admits it, so the identity says which row to look in. A
    /// full scan would work and would also quietly keep working if threads
    /// started migrating, which is the wrong kind of robustness: migration has
    /// to move the record, and a lookup that never noticed would hide that it
    /// had not.
    fn locate(&self, id: ThreadId) -> Option<(u32, usize)> {
        if id == ThreadId::UNASSIGNED {
            return None;
        }
        let cpu = id.cpu();
        let row = self.rows.get(cpu as usize)?;
        row.iter()
            .position(|&entry| entry == id)
            .map(|slot| (cpu, slot))
    }
}

/// Where a thread named by identity is, from the point of view of the CPU
/// asking.
///
/// The three-way answer the executive needs and `Scheduler::index_of` cannot
/// give: it returns `Option<usize>`, and the `None` covers both "somewhere
/// else" and "nowhere", which are opposite instructions — wake it, or do
/// nothing at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Residence {
    /// In this CPU's own scheduler, at this slot — the only case a handoff or
    /// a priority change can act on.
    Here(usize),
    /// In another CPU's scheduler. Reachable only by posting a wakeup.
    Elsewhere { cpu: u32, slot: usize },
    /// Nowhere: it exited.
    Gone,
}

impl Machine {
    /// Written as a `const fn` deliberately — see the type's own header. Each
    /// field's constructor is itself `const`, so this whole structure is a
    /// constant the linker places rather than a value some stack has to carry.
    const fn new() -> Self {
        Self {
            channels: ChannelTable::new(),
            waits: WaitSet::new(),
            ports: PortTable::new(),
            jobs: JobTable::new(),
            devices: DeviceTable::new(),
            memory: crate::memory::MemoryTable::new(),
            paging: crate::pager::SelfPagingGraph::new(),
            page_ins: [const { None }; crate::pager::MAX_PAGERS],
            expired_callers: [None; crate::pager::MAX_PAGERS],
            // One miss is one abandoned reader; escalating on the third makes a
            // pager that fails repeatedly a supervision matter rather than a
            // series of unrelated faults (docs/kernel/03, "Page-In Flow").
            page_in_supervisor: crate::pager::PageInSupervisor::new(1, 3),
            cache_budget: crate::pager::WriteBackReservation::new(
                CACHE_FRAME_BUDGET,
                CACHE_WRITE_BACK_RESERVE,
            ),
            lifecycle: crate::lifecycle::LifecycleTable::new(),
            wake: crate::power::WakeState::new(),
            sleeper: None,
            resumed_by: None,
            residents: Residents::new(),
        }
    }

    /// Returns every table to empty, in place.
    ///
    /// **Field by field, and not `*self = Machine::new()`.** The whole-value
    /// form needs the constant to exist somewhere to be copied from, and a
    /// 400 KiB constant in the image is the +424 KiB Phase 1 measured and
    /// rejected. Written this way each field's constructor writes straight
    /// into its own field, which is what the flat `Executive` did before this
    /// type existed and is why naming the type ends up costing nothing.
    ///
    /// It exists because the boot restarts the executive between demos and
    /// has always relied on that to clear these tables — with the machine half
    /// in a `static`, a fresh `Executive` no longer brings fresh tables with
    /// it, so the clearing has to be asked for. Anything added to the struct
    /// and forgotten here leaks state from one demo into the next, which is
    /// why the two lists are next to each other.
    fn reset(&mut self) {
        self.channels = ChannelTable::new();
        self.waits = WaitSet::new();
        self.ports = PortTable::new();
        self.jobs = JobTable::new();
        self.devices = DeviceTable::new();
        self.memory = crate::memory::MemoryTable::new();
        self.paging = crate::pager::SelfPagingGraph::new();
        self.page_ins = [const { None }; crate::pager::MAX_PAGERS];
        self.expired_callers = [None; crate::pager::MAX_PAGERS];
        self.page_in_supervisor = crate::pager::PageInSupervisor::new(1, 3);
        self.cache_budget =
            crate::pager::WriteBackReservation::new(CACHE_FRAME_BUDGET, CACHE_WRITE_BACK_RESERVE);
        self.lifecycle = crate::lifecycle::LifecycleTable::new();
        self.wake = crate::power::WakeState::new();
        self.sleeper = None;
        self.resumed_by = None;
        self.residents = Residents::new();
    }
}

/// The one machine half, for a kernel.
///
/// A `static` and not a field, and that is what makes naming the type free.
/// Built in a `const` context, so the constant *is* the storage rather than
/// something [`Executive::new`] copies into a field — which is where Phase 1's
/// measured +424 KiB came from, and it is zero here because nothing is copied.
/// It is also the truth: there is one machine, and a second `Executive` would
/// not bring a second set of channels with it.
#[cfg(not(test))]
static MACHINE: MachineCell = MachineCell(core::cell::UnsafeCell::new(Machine::new()));

/// The `static`'s cell, following [`crate::percpu::PerCpu`] rather than
/// `static mut`: the same interior mutability, without the raw-address dance
/// edition 2024 forces on a mutable static and without the lint that dance
/// trips.
#[cfg(not(test))]
struct MachineCell(core::cell::UnsafeCell<Machine>);

// SAFETY: what makes sharing this sound is not the type — it is that every
// access to a table inside it is taken under `crate::machine_lock`, which is
// what `Executive::machine`'s callers do and what `claim
// exec.lock-released-at-park` says nobody escapes by parking. More than one
// CPU reaches the executive now (`claim exec.multi-cpu`), so the older
// argument — that only the boot CPU does — no longer carries this. The `Sync`
// is what lets it be a `static` at all; build/README.md D230, D232, D236.
#[cfg(not(test))]
unsafe impl Sync for MachineCell {}

pub struct Executive<C: ContextOps> {
    /// Monotonic nanoseconds, for deadlines. Supplied by the port, because
    /// `karch`'s counter is unit-less and only the port knows its rate (D281).
    clock: fn() -> u64,
    /// One CPU's own state, per CPU, reached by the index of whoever is
    /// asking. Sixteen kilobytes at eight CPUs, against the machine half's
    /// four hundred and forty-six — the split is lopsided because almost
    /// everything in an executive is shared, which is why the shared part is
    /// the one that needed a lock.
    cpus: [CpuLocal<C>; crate::percpu::MAX_CPUS],
    /// The tables every CPU shares — **a host test's own**, so that tests
    /// running in parallel threads do not share one set of channels. A kernel
    /// has one machine and reaches it through the `static` above; a test
    /// harness has as many as it has tests, and each has to be able to assume
    /// its tables start empty.
    #[cfg(test)]
    pub(crate) machine_storage: Machine,
}

impl<C: ContextOps> Executive<C> {
    /// The calling CPU's own half.
    ///
    /// By index and not by a field, for the same reason [`machine`](Self::machine)
    /// is by `static`: there is one `Executive` and every CPU that does IPC
    /// reaches it, so "this CPU's scheduler" cannot be a fixed one. Out of
    /// range folds to the boot CPU rather than panicking — an index past the
    /// ceiling is a configuration the boot reports (see [`crate::percpu`]), not
    /// a reason to stop.
    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    fn cpu(&self) -> &mut CpuLocal<C> {
        self.cpu_at(crate::percpu::current_index())
    }

    /// The half belonging to `index`.
    ///
    /// Split from [`cpu`](Self::cpu) so the indexing can be tested without
    /// installing a per-CPU index source — that source is one process-wide
    /// store, and a host test that pointed it at CPU 1 would move every other
    /// test's per-CPU state with it for as long as it ran.
    ///
    /// Out of range folds to the boot CPU rather than panicking: an index past
    /// the ceiling is a configuration the boot reports (see
    /// [`crate::percpu`]), not a reason to stop.
    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    fn cpu_at(&self, index: u32) -> &mut CpuLocal<C> {
        let index = index as usize;
        let index = if index < crate::percpu::MAX_CPUS {
            index
        } else {
            crate::percpu::BOOT_CPU as usize
        };
        // SAFETY: a slot is written only by the CPU it belongs to, which is
        // what selects it — the same disjointness `crate::percpu::PerCpu`
        // rests on, and which the borrow checker cannot see. The shared-to-
        // exclusive step is the one the enclosing `&self` cannot express;
        // build/README.md D230 records why these methods take `&self` at all.
        unsafe { &mut *(&raw const self.cpus[index]).cast_mut() }
    }

    /// The machine half.
    ///
    /// Every access to a shared table goes through here, which is what will
    /// make it possible to put a lock in one place rather than in a hundred.
    #[cfg(not(test))]
    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    fn machine(&self) -> &mut Machine {
        Self::machine_static()
    }

    /// The machine half without an `Executive` to ask through — for
    /// [`Executive::new`], which has to clear the tables before it hands out
    /// something that reaches them.
    #[cfg(not(test))]
    #[inline(always)]
    fn machine_static() -> &'static mut Machine {
        // SAFETY: the boot CPU, and one access *in use* rather than one live —
        // the same argument the port accessors carry, for the same reason and
        // measured by the same counters (`occupancy`, build/README.md D230).
        // This is the one place that argument has to be made, which is the
        // point of routing every table through it.
        unsafe { &mut *MACHINE.0.get() }
    }

    /// The machine half — this `Executive`'s own, under test.
    #[cfg(test)]
    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    fn machine(&self) -> &mut Machine {
        // SAFETY: a host test owns its `Executive` outright and the harness
        // gives each test its own thread; the shared-mutable form exists only
        // so the two builds present the same signature.
        unsafe { &mut *(&raw const self.machine_storage).cast_mut() }
    }
}

/// Why a suspend commit ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuspendOutcome {
    /// The commit was taken and a wake ended it.
    Resumed = 1,
    /// A wake arrived after the caller took its snapshot; the machine never
    /// stopped.
    WakeArrived = 2,
    /// A wake hold vetoed the commit.
    Vetoed = 3,
}

/// What a suspend commit did — see [`Executive::system_suspend`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SuspendReport {
    pub outcome: SuspendOutcome,
    /// The wake-event counter when the call returned.
    pub events: u64,
    /// The device credited with the wake for a resume, the vetoing holder for
    /// a veto, and `None` otherwise.
    pub source: Option<ObjectId>,
}

/// What a removal did — see [`Executive::remove_device`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RemovalReport {
    /// Whether the graph knew this device at all. `false` for a removal of
    /// something already removed, which is a no-op rather than an error: a bus
    /// may report the same disappearance twice.
    pub existed: bool,
    /// Processes that were holding a handle to it.
    pub holders: usize,
    /// Register windows unmapped, which is at most `holders`.
    pub windows: usize,
    /// Services depending on this device that were told it had gone.
    pub dependents_told: usize,
    /// Services that could **not** be told — their endpoint's queue was full,
    /// or the notice would not encode. Counted rather than retried, because a
    /// dependent that missed this is in a worse position than one that was
    /// never registered and should be visible as such.
    pub dependents_missed: usize,
    /// Ports told the device's line will never assert again — which is what
    /// wakes a driver parked waiting for an interrupt from it.
    pub woken: usize,
    /// How many nodes went, counting the device named and everything that sat
    /// behind it. One for a leaf.
    ///
    /// The number the caller cannot work out for itself afterwards: once the
    /// removal has run, the edges that would have answered "how big was that
    /// subtree" are the very thing that was torn down.
    pub subtree: usize,
}

impl<C: ContextOps> CpuLocal<C> {
    #[inline(always)]
    fn new(quantum: u32, tick_limit: u64) -> Self {
        Self {
            sched: Scheduler::new(quantum, tick_limit),
            next_txn: 1,
            sync_depth: [0; MAX_THREADS],
            saved_correlation: [0; MAX_THREADS],
        }
    }
}

impl<C: ContextOps> Executive<C> {
    pub fn new(quantum: u32, tick_limit: u64, clock: fn() -> u64) -> Self {
        // **A fresh `Executive` no longer brings fresh tables with it.** The
        // machine half is one `static`, which is the truth about a machine and
        // is what makes naming the type free — but the boot re-creates the
        // executive between demos and has always relied on that to clear them,
        // so the clearing is asked for rather than implied. Before the struct
        // is built and not after: under test the struct *is* the tables, and
        // naming it as a local long enough to reset it puts 400 KiB on the
        // stack twice, which is the overflow this whole arrangement avoids.
        #[cfg(not(test))]
        Self::machine_static().reset();
        Self {
            clock,
            cpus: core::array::from_fn(|_| CpuLocal::new(quantum, tick_limit)),
            // `const { .. }` and not `Machine::new()`. A `const fn` called
            // from a runtime context is an ordinary call: it builds its value
            // and returns it, and in an unoptimized build that value is a real
            // 400 KiB temporary on this stack — which is the overflow Phase 1
            // hit and recorded. The inline-const block forces the evaluation to
            // compile time. Only the test build has a field to fill at all.
            #[cfg(test)]
            machine_storage: const { Machine::new() },
        }
    }

    /// Returns the executive to its starting state **for this CPU**, without
    /// replacing it.
    ///
    /// The boot runs its demos one after another out of one executive and has
    /// always wanted each to start clean, which it got by building a new one
    /// and dropping the old — 67 sites across three ports. That stopped being
    /// harmless when each CPU got its own half (build/README.md D233): a fresh
    /// `Executive` brings fresh halves for *every* CPU, so a secondary running
    /// out of its own would have had its run queue rebuilt underneath it,
    /// dozens of times a boot.
    ///
    /// So the machine tables are cleared, and the **calling** CPU's half is
    /// returned to its starting state; every other CPU's is left alone. That is
    /// also the more honest reading of what a demo wants — it is restarting its
    /// own scheduling, not the machine's other processors.
    pub fn restart(&self, quantum: u32, tick_limit: u64) {
        self.machine().reset();
        self.adopt_cpu(quantum, tick_limit);
    }

    /// Returns **only the calling CPU's half** to its starting state, leaving
    /// the machine tables alone.
    ///
    /// Split out of [`restart`](Self::restart) for the CPU that must not clear
    /// the machine tables: a secondary reaching the executive for the first
    /// time takes the half its index names and gives it the quantum it means to
    /// run at, and the channels, ports and jobs it finds there belong to the
    /// machine and are in use by the boot CPU. Clearing them is what a demo
    /// wants and what an arriving CPU must never do.
    pub fn adopt_cpu(&self, quantum: u32, tick_limit: u64) {
        *self.cpu() = CpuLocal::new(quantum, tick_limit);
    }

    /// The scheduler, for spawning threads and starting/stopping the run.
    ///
    /// **`&self` and not `&mut self`**, matching [`machine`](Self::machine) and
    /// [`cpu`](Self::cpu): which scheduler this is depends on who is asking, so
    /// two CPUs holding a shared reference to one executive each get their own
    /// and neither excludes the other. An exclusive receiver would have said
    /// the opposite — that there is one scheduler and one borrower of it — and
    /// that stopped being true when a secondary started dispatching out of its
    /// own half (build/README.md D236).
    #[allow(clippy::mut_from_ref)]
    pub fn scheduler(&self) -> &mut Scheduler<C> {
        &mut self.cpu().sched
    }

    /// The scheduler belonging to `index`, for a CPU asking about another's.
    ///
    /// The boot CPU's way of naming a secondary's half — which is what
    /// `crate::secondary` compares a secondary's published scheduler against.
    /// No CPU can reach another's by calling [`scheduler`](Self::scheduler),
    /// which is the point of that method and why this one is separate.
    #[allow(clippy::mut_from_ref)]
    pub fn scheduler_at(&self, index: u32) -> &mut Scheduler<C> {
        &mut self.cpu_at(index).sched
    }

    /// Where the thread `id` is: this CPU's own scheduler, another CPU's, or
    /// nowhere at all.
    ///
    /// **The local lookup first, and the machine-wide one only if it fails.**
    /// `Scheduler::index_of` is the answer for the overwhelmingly common case
    /// — a thread woken by the CPU it lives on — and it needs no lock. The
    /// table is consulted only to tell the two meanings of its `None` apart.
    ///
    /// A record naming *this* CPU when the local lookup already failed is a
    /// thread that exited here, so it reads as [`Residence::Gone`]: the record
    /// outlives the thread on purpose (see [`Residents`]) and this is where
    /// that is resolved.
    pub fn locate_thread(&self, id: ThreadId) -> Residence {
        if let Some(idx) = self.cpu().sched.index_of(id) {
            return Residence::Here(idx);
        }
        let _machine = crate::machine_lock::hold();
        match self.machine().residents.locate(id) {
            Some((cpu, slot)) if cpu != crate::percpu::current_index() => {
                Residence::Elsewhere { cpu, slot }
            }
            _ => Residence::Gone,
        }
    }

    /// Makes `id` runnable wherever it is, and says where that was.
    ///
    /// The one shape almost every wake site in this file wants: something
    /// machine-wide handed back an identity, and the thread it names should
    /// stop being blocked. Before this, all of them resolved the identity to a
    /// local slot and read `None` as "it exited" — true when one CPU ran
    /// everything, and silently wrong the moment a thread could be somewhere
    /// else, because the wake would simply not happen and the thread would
    /// wait for an event that had already come.
    fn wake_thread(&mut self, id: ThreadId) -> Residence {
        let at = self.locate_thread(id);
        match at {
            Residence::Here(idx) => self.cpu().sched.unblock(idx),
            Residence::Elsewhere { cpu, slot } => {
                crate::wakeup::wake(cpu, slot, id);
            }
            Residence::Gone => {}
        }
        at
    }

    /// Enters a blocking executive method: marks this thread as inside it, and
    /// records where this thread is so another CPU can wake it.
    ///
    /// **The two go together and that is the point.** The set of methods that
    /// can suspend the calling thread is exactly the set that can leave its
    /// identity in a machine-wide table for another CPU to find — a blocked
    /// receiver, a pending caller, a sleeper, a waiter. [`occupancy`] already
    /// marks that set; pairing the record with the mark is what stops the two
    /// drifting apart.
    ///
    /// **At the method's entry, not at its park**, which is the part that took
    /// a deadlock to see. A method publishes the identity under one hold of
    /// the machine lock and parks under a later one; a record written at the
    /// park is therefore *behind* the identity, and another CPU that reads the
    /// identity in between finds no record, reads it as "the thread exited",
    /// and does not wake it — while the thread goes on to park for ever with
    /// its request already in its queue. The record must be no later than the
    /// identity, and the method's first line is the only place that is
    /// guaranteed.
    fn enter_blocking(&self, site: occupancy::Site) -> occupancy::Inside {
        self.note_residence();
        occupancy::Inside::enter(site)
    }

    /// Records where the running thread is, so a CPU that holds only its
    /// identity can find it.
    fn note_residence(&self) {
        let cpu = crate::percpu::current_index();
        let Some(slot) = self.cpu().sched.current() else {
            return;
        };
        let Some(id) = self.cpu().sched.thread_id(slot) else {
            return;
        };
        let _machine = crate::machine_lock::hold();
        self.machine().residents.record(cpu, slot, id);
    }

    /// Parks the running thread: puts the machine lock down, and blocks.
    ///
    /// Where the thread is was recorded by [`enter_blocking`](Self::enter_blocking)
    /// on the way into whichever method this is — every park in this file is
    /// inside one — and deliberately not here, for the reason that method
    /// gives.
    fn park_current(&mut self) {
        crate::machine_lock::park(|| self.cpu().sched.block_current());
    }

    /// Hands the CPU to `slot`, putting the machine lock down across the
    /// switch.
    fn park_handoff_to(&mut self, slot: usize) {
        crate::machine_lock::park(|| self.cpu().sched.handoff_to(slot));
    }

    /// Adds a thread to the scheduler (convenience).
    pub fn add_thread(&mut self, thread: Thread<C>) -> Result<usize, KError> {
        self.cpu().sched.add_thread(thread)
    }

    /// Total context switches performed (for the exactly-two-switches check).
    pub fn switch_count(&self) -> u64 {
        self.cpu().sched.switch_count()
    }

    /// Creates a channel, returning its two endpoint ids.
    pub fn channel_create(&mut self) -> Result<(EndpointId, EndpointId), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().channels.create()
    }

    /// Creates a channel and gives each end a freshly minted object id — the
    /// ring-3 `ChannelCreate`, where nobody outside the kernel may choose an
    /// id. Boot glue keeps [`channel_create`](Self::channel_create) and binds
    /// the ids it wired the rest of the machine with.
    pub fn channel_create_with_objects(
        &mut self,
    ) -> Result<(BoundEndpoint, BoundEndpoint), KError> {
        // The machine tables, for this method — one section, as above.
        let _machine = crate::machine_lock::hold();
        let machine = self.machine();
        let (end0, end1) = machine.channels.create_with_objects()?;
        // Read back rather than returned by the minting call: the object of an
        // endpoint is what `endpoint_of_object` resolves against, so taking it
        // from the table is what makes the two answers the same one.
        let (Some(id0), Some(id1)) = (
            machine.channels.endpoint_object(end0),
            machine.channels.endpoint_object(end1),
        ) else {
            return Err(KError::Protocol);
        };
        Ok((
            BoundEndpoint {
                endpoint: end0,
                object: id0,
            },
            BoundEndpoint {
                endpoint: end1,
                object: id1,
            },
        ))
    }

    /// Binds `endpoint` to the object id of its `ObjectType::Channel` object,
    /// so a ring-3 handle resolving to that id maps back to this endpoint.
    pub fn bind_endpoint_object(&mut self, endpoint: EndpointId, id: ObjectId) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().channels.set_endpoint_object(endpoint, id);
    }

    /// Resolves a channel object id back to its endpoint — the handle→endpoint
    /// bridge a ring-3 channel syscall uses after looking the handle up in the
    /// caller's table.
    pub fn endpoint_of_object(&self, id: ObjectId) -> Option<EndpointId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().channels.endpoint_of_object(id)
    }

    /// The thread parked in a `receive` on `endpoint`, if one is.
    ///
    /// **The one thing another CPU can observe about a server without touching
    /// that CPU's scheduler.** A boot check that has to know a server is
    /// waiting before it calls cannot ask the server's run queue — reading
    /// another CPU's scheduler is the data race this whole arrangement exists
    /// to avoid — but the endpoint is machine state, taken under the lock, and
    /// a receiver registers itself there as the last thing it does before it
    /// parks.
    pub fn endpoint_receiver(&self, endpoint: EndpointId) -> Option<ThreadId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .channels
            .channel(endpoint.channel)?
            .endpoint(endpoint.side)
            .blocked_receiver()
    }

    /// Calls the service listening on `endpoint` **from the kernel's own side
    /// of that channel**, blocking the current thread until it replies.
    ///
    /// The one caller is the page-in path: a thread has faulted on a page its
    /// object's pager has not supplied, and the kernel asks for it as an
    /// ordinary message so the pager can be an ordinary server. `endpoint` is
    /// the side the service holds — the kernel calls from the other, which no
    /// process owns.
    pub fn call_service(
        &mut self,
        endpoint: EndpointId,
        request: Message,
        object: ObjectId,
        offset: u64,
    ) -> Result<Message, KError> {
        let from = Self::peer(endpoint);
        let faulter = self
            .cpu()
            .sched
            .current()
            .and_then(|idx| self.cpu().sched.thread_id(idx))
            .ok_or(KError::BadHandle)?;
        // Registered **before** the call, because the call does not return
        // until it is answered or given up on — and giving up is done by
        // somebody else, reading this.
        self.page_in_started(faulter, from, object, offset)?;
        let outcome = self.call(from, request);
        self.page_in_finished(faulter);
        outcome
    }

    /// Starts scheduling, and runs until nothing is runnable — giving up on
    /// any page-in that can no longer be answered.
    ///
    /// **This is what makes a silent pager a fault rather than a stuck thread.**
    /// The scheduler returns to boot only when no thread can run; a page-in
    /// still in flight at that moment is one whose answer would have to come
    /// from a thread that is not going to run again, so it can never arrive.
    /// That is a stronger statement than a timeout — it is not that the pager
    /// is late, it is that it cannot answer — and on a cooperative scheduler it
    /// is decidable rather than guessed. Each such request is failed, its
    /// faulter woken to be told, and the loop runs again so the woken threads
    /// take their faults.
    ///
    /// Every check runs through here rather than reaching for the scheduler, so
    /// no check can forget to do it.
    pub fn run(&mut self) {
        // **No hold for this method**, unlike the others, and the exception is
        // the rule restated: `run` is the dispatcher and does not return until
        // the machine has nothing left to do. A hold taken here would be held
        // across every thread this loop dispatches — which is the failure
        // build/README.md D230 measured, in its purest form. The one machine
        // access below takes its own.
        loop {
            // What other CPUs asked to be made runnable here, before asking
            // the run queue what is runnable — the same order, and for the
            // same reason, as a secondary's run loop (`crate::secondary`): a
            // wakeup posted while this CPU was busy is taken before it decides
            // it has nothing to do. Without this the boot CPU is the one CPU
            // on the machine that never collects its own wakeups.
            // A receive whose deadline has passed is made runnable before the
            // queue is asked what is runnable, so an expiry is never one full
            // pass late.
            self.expire_timed_out_receivers();
            let here = crate::percpu::current_index();
            crate::wakeup::drain(here, |slot, id| {
                self.cpu().sched.unblock_thread(slot, id);
            });
            self.cpu().sched.run();
            // **Unless somebody is waiting for hardware.** "Nothing is
            // runnable" means an answer cannot come *from another thread*; it
            // says nothing about one coming from a device. A filesystem pager
            // reading the page off a disk parks the whole stack on the driver's
            // interrupt port, and every thread is off-CPU until the disk
            // answers — which looks exactly like a pager that never will.
            //
            // Told apart by asking whether anything is parked on a port. A
            // thread there is waiting for an interrupt, and the boot loop that
            // pumps interrupts will run it; nothing parked on a port means no
            // external event is expected and the request is genuinely
            // unanswerable. Learned by breaking the filesystem check, which is
            // the only one where a page-in waits on real hardware.
            if crate::machine_lock::hold_for(|| self.machine().ports.any_blocked_drainer()) {
                return;
            }
            if self.expire_stalled_page_ins() == 0 {
                return;
            }
        }
    }

    /// Wakes every blocked receiver whose deadline has passed.
    ///
    /// **Called at the head of [`run`](Self::run)'s loop, not on the timer.**
    /// The scheduler here is cooperative and `run` is re-entered every time
    /// anything becomes runnable — including on the timer tick that wakes the
    /// boot pump — so this is the earliest moment a deadline can be noticed
    /// without wiring a clock into the interrupt path. It is therefore a bound
    /// with tick-granularity slack, not a precise alarm, and a caller that
    /// needed one would need the timer (D282).
    ///
    /// The thread is woken; the receive it was parked in re-checks its own
    /// deadline and returns [`KError::TimedOut`]. Waking rather than
    /// completing here keeps the decision in the call that made it, which is
    /// the same division `expire_stalled_page_ins` uses.
    fn expire_timed_out_receivers(&mut self) -> usize {
        let now = (self.clock)();
        let mut woken = 0;
        let mut expired = [ThreadId(0); 8];
        let mut count = 0;
        {
            let _machine = crate::machine_lock::hold();
            let sched = &mut self.cpu().sched;
            for slot in 0..sched.capacity() {
                let Some(thread) = sched.thread_at(slot) else {
                    continue;
                };
                if thread.state() != crate::thread::ThreadState::Blocked {
                    continue;
                }
                let Some(deadline) = thread.recv_deadline() else {
                    continue;
                };
                if now < deadline {
                    continue;
                }
                if count < expired.len() {
                    expired[count] = thread.id();
                    count += 1;
                }
            }
        }
        for id in expired.iter().take(count) {
            self.wake_thread(*id);
            woken += 1;
        }
        woken
    }

    /// Fails every page-in that is still in flight, and returns how many.
    ///
    /// Called when nothing is runnable — see [`run`](Self::run) for why that is
    /// the moment a page-in becomes unanswerable rather than merely slow.
    fn expire_stalled_page_ins(&mut self) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut expired = 0;
        for index in 0..self.machine().page_ins.len() {
            let Some(flight) = self.machine().page_ins[index].take() else {
                continue;
            };
            // The call is given up on at the endpoint too, so the reply it is
            // still owed is discarded instead of being handed to whoever calls
            // next.
            if let Some(channel) = self.machine().channels.channel_mut(flight.from.channel) {
                channel.endpoint_mut(flight.from.side).abort_call();
            }
            // The object enters the faulted state `docs/kernel/03` describes,
            // so the *next* access fails immediately rather than asking a pager
            // that has already failed to answer once.
            self.machine().memory.set_faulted(flight.object);
            // Left for the parked `call` frame to pick up when it runs: a
            // blocked thread cannot be handed an error, only told when it next
            // runs.
            if let Some(slot) = self
                .machine()
                .expired_callers
                .iter_mut()
                .find(|s| s.is_none())
            {
                *slot = Some(flight.faulter);
            }
            let escalated = matches!(
                self.machine().page_in_supervisor.record_miss(),
                crate::pager::MissOutcome::Escalate
            );
            crate::event::emit(
                crate::event::EventKind::PagerDeadlineMiss,
                crate::event::Severity::Error,
                crate::event::Component::Pager,
                [
                    u64::from(flight.object.raw()),
                    flight.offset,
                    flight.faulter.0,
                    u64::from(escalated),
                ],
            );
            if escalated {
                crate::event::emit(
                    crate::event::EventKind::PagerSupervisionEscalate,
                    crate::event::Severity::Error,
                    crate::event::Component::Pager,
                    [
                        u64::from(flight.object.raw()),
                        u64::from(self.machine().page_in_supervisor.misses()),
                        u64::from(self.machine().page_in_supervisor.escalations()),
                        0,
                    ],
                );
            }
            // A faulter that no longer resolves exited while its page-in was
            // outstanding; there is nothing to wake, and the flight is cleared
            // either way. One that is on another CPU is woken there.
            self.wake_thread(flight.faulter);
            expired += 1;
        }
        expired
    }

    /// One endpoint of a live channel, for a test that needs to put an
    /// endpoint into a state only a partly-completed call produces.
    #[cfg(test)]
    pub fn channel_endpoint_mut(
        &mut self,
        endpoint: EndpointId,
    ) -> Option<&mut crate::ipc::Endpoint> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .channels
            .channel_mut(endpoint.channel)
            .map(|channel| channel.endpoint_mut(endpoint.side))
    }

    /// Records a page-in about to be sent, so it can be failed if the answer
    /// never comes. `Err` when too many are already outstanding.
    pub fn page_in_started(
        &mut self,
        faulter: ThreadId,
        from: EndpointId,
        object: ObjectId,
        offset: u64,
    ) -> Result<(), KError> {
        let slot = self
            .machine()
            .page_ins
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(KError::LimitExceeded)?;
        *slot = Some(PageInFlight {
            faulter,
            from,
            object,
            offset,
        });
        Ok(())
    }

    /// Clears the record of a page-in that finished, however it finished.
    pub fn page_in_finished(&mut self, faulter: ThreadId) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        for slot in self.machine().page_ins.iter_mut() {
            if matches!(slot, Some(flight) if flight.faulter == faulter) {
                *slot = None;
            }
        }
    }

    /// Deadline misses and escalations so far — what a check reads to prove the
    /// policy ran rather than that a thread merely stopped waiting.
    pub fn page_in_misses(&self) -> u32 {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().page_in_supervisor.misses()
    }

    /// Supervised-restart escalations so far.
    pub fn page_in_escalations(&self) -> u32 {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().page_in_supervisor.escalations()
    }

    /// Whether `thread` was the faulter of a page-in that was given up on,
    /// consuming the record.
    fn take_expired(&mut self, thread: ThreadId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        for slot in self.machine().expired_callers.iter_mut() {
            if *slot == Some(thread) {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Records that `object`'s pages come from `pager`, for the cycle guard.
    pub fn paging_bind(&mut self, object: ObjectId, pager: ObjectId) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .paging
            .bind(u64::from(object.raw()), pager.raw())
    }

    /// Routes a page-in of `object` requested by `requester`, refusing the ones
    /// that would deadlock (docs/kernel/03, "Anti-Deadlock Rules").
    pub fn paging_request(
        &mut self,
        requester: ObjectId,
        object: ObjectId,
    ) -> crate::pager::PageInResult {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .paging
            .request_page_in(requester.raw(), u64::from(object.raw()))
    }

    /// Clears `requester`'s in-flight page-in edge, however it ended.
    pub fn paging_complete(&mut self, requester: ObjectId) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().paging.complete(requester.raw());
    }

    /// How many page-ins are in flight.
    pub fn paging_in_flight(&self) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().paging.in_flight()
    }

    /// The peer of an endpoint.
    fn peer(endpoint: EndpointId) -> EndpointId {
        EndpointId {
            channel: endpoint.channel,
            side: Channel::peer(endpoint.side),
        }
    }

    /// Adopts a just-dequeued message's causal id onto the receiving thread, so
    /// the work it does handling the request is attributed to the cause that sent
    /// it rather than to the server itself (docs/observability/02: propagated "to
    /// the callee for the duration of handling").
    ///
    /// A message with no recorded cause leaves the receiver's id alone — adopting
    /// 0 would erase a good id rather than inherit a real one. There is no restore
    /// bracket on this path (unlike the synchronous `call`, which parks and
    /// restores the callee's own id): an async server carries the last request's
    /// id until its next receive adopts the next one, which is the design's
    /// "pipeline stages inherit the item's ID" (D60).
    fn adopt_message_correlation(&mut self, message: &Message) {
        let correlation = message.header().correlation;
        if correlation == 0 {
            return;
        }
        if let Some(me) = self.cpu().sched.current() {
            self.cpu().sched.set_thread_correlation(me, correlation);
        }
    }

    /// Sends a one-way message from `from` to its peer, waking a blocked
    /// receiver (asynchronously — no handoff). A full queue yields `WouldBlock`.
    pub fn send(&mut self, from: EndpointId, mut message: Message) -> Result<(), KError> {
        let peer = Self::peer(from);
        // An async send has no handoff to carry causality through, so the id
        // rides the message itself: the receiver adopts it when it dequeues
        // (docs/observability/02, "Asynchronous messages carry it explicitly in
        // the header field"; D60).
        message.set_correlation(crate::trace::current().correlation);
        let (receiver, destination) = {
            let channel = self
                .machine()
                .channels
                .channel_mut(from.channel)
                .ok_or(KError::BadHandle)?;
            channel.endpoint_mut(peer.side).enqueue(message)?;
            let receiver = channel.endpoint(peer.side).blocked_receiver();
            if receiver.is_some() {
                channel.endpoint_mut(peer.side).set_blocked_receiver(None);
            }
            (receiver, channel.object(peer.side))
        };
        // A receiver that no longer resolves exited while parked. The message
        // stays queued on the endpoint, so the next receiver still gets it —
        // and one parked on another CPU is woken there rather than mistaken
        // for one that exited.
        if let Some(receiver) = receiver {
            self.wake_thread(receiver);
        }
        // Raise the arrival on the destination endpoint's object, so a server
        // selecting across per-client endpoints learns which one has work
        // (D85). Inert unless some port bound that `(source, signal)` pair;
        // signalled outside the channel borrow, the `port_signal` discipline.
        self.signal_endpoint_arrival(destination);
        Ok(())
    }

    /// Signals a message arrival on `destination` (an endpoint's bound
    /// object) to any port watching it. A no-op for an unbound endpoint or
    /// when no port carries that binding.
    fn signal_endpoint_arrival(&mut self, destination: Option<ObjectId>) {
        if let Some(object) = destination {
            self.port_signal(u64::from(object.raw()), crate::ipc::SIGNAL_MESSAGE, 1);
        }
    }

    /// Receives a message on `on`, blocking until one arrives or the peer
    /// closes. FIFO; a closed-and-drained endpoint returns `PeerClosed`.
    pub fn receive(&mut self, on: EndpointId) -> Result<Message, KError> {
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::Receive);
        loop {
            let channel = self
                .machine()
                .channels
                .channel_mut(on.channel)
                .ok_or(KError::BadHandle)?;
            if let Some(message) = channel.endpoint_mut(on.side).dequeue() {
                // Handling this request belongs to the cause that sent it. Only
                // on a successful dequeue — a parked retry must not churn the
                // receiver's id.
                self.adopt_message_correlation(&message);
                return Ok(message);
            }
            if channel.endpoint(on.side).peer_closed() {
                return Err(KError::PeerClosed);
            }
            let me = self
                .cpu()
                .sched
                .current()
                .and_then(|idx| self.cpu().sched.thread_id(idx))
                .ok_or(KError::BadHandle)?;
            channel.endpoint_mut(on.side).set_blocked_receiver(Some(me));
            // Park until a sender wakes us, then retry the dequeue.
            self.park_current();
        }
    }

    /// Receive without parking: takes a message if one is queued, and says
    /// `WouldBlock` when none is.
    ///
    /// **The primitive a server with more than one endpoint needs.** A blocking
    /// receive commits a server to one client's channel until that client
    /// speaks; a server holding two of them would serve whichever spoke first
    /// and never hear the other. That is not a shortcoming of the server — it
    /// is what a blocking receive means — and until a server here had two
    /// endpoints there was nothing to say about it.
    ///
    /// A closed peer is still `PeerClosed` rather than `WouldBlock`: a channel
    /// that will never speak again is a different fact from one that has not
    /// spoken yet, and a caller polling a set of endpoints needs to be able to
    /// stop polling a dead one.
    pub fn try_receive(&mut self, on: EndpointId) -> Result<Message, KError> {
        let channel = self
            .machine()
            .channels
            .channel_mut(on.channel)
            .ok_or(KError::BadHandle)?;
        if let Some(message) = channel.endpoint_mut(on.side).dequeue() {
            self.adopt_message_correlation(&message);
            return Ok(message);
        }
        if channel.endpoint(on.side).peer_closed() {
            return Err(KError::PeerClosed);
        }
        Err(KError::WouldBlock)
    }

    /// Receive on the first of `endpoints` that has a message, parking on all
    /// of them if none does. Returns which one answered, and what it said.
    ///
    /// **Registering on every endpoint is the whole of it.** A server that
    /// parked on one and polled the others would sleep through a message on any
    /// endpoint but the one it chose; a server that polled all of them and
    /// never parked would be a server no other thread runs behind, because the
    /// scheduler here is cooperative. So the thread is recorded as the blocked
    /// receiver of each, and whichever sender arrives first wakes it.
    ///
    /// The registration is cleared on **every** endpoint after waking, not only
    /// on the one that fired: a stale receiver left on the others would have
    /// the next sender there wake a thread that is already running.
    ///
    /// An endpoint whose peer has closed is skipped rather than fatal. A set
    /// with one dead member and one live one is an ordinary state — one client
    /// left and another did not — and refusing the whole call would take the
    /// server down with the first client to exit.
    pub fn receive_any(
        &mut self,
        endpoints: &[EndpointId],
        deadline: Option<u64>,
    ) -> Result<(usize, Message), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::ReceiveAny);
        if endpoints.is_empty() {
            return Err(KError::InvalidArgument);
        }
        loop {
            let mut live = 0usize;
            for (index, ep) in endpoints.iter().enumerate() {
                let channel = self
                    .machine()
                    .channels
                    .channel_mut(ep.channel)
                    .ok_or(KError::BadHandle)?;
                if let Some(message) = channel.endpoint_mut(ep.side).dequeue() {
                    self.adopt_message_correlation(&message);
                    return Ok((index, message));
                }
                if !channel.endpoint(ep.side).peer_closed() {
                    live += 1;
                }
            }
            // Every peer has gone and nothing is queued: there is no message
            // coming, and saying so beats parking forever.
            if live == 0 {
                return Err(KError::PeerClosed);
            }
            // **The deadline expires the wait, not the call.** It is checked
            // before parking as well as after, so a caller whose deadline has
            // already passed is answered rather than parked once and woken
            // immediately (D282).
            if let Some(at) = deadline
                && (self.clock)() >= at
            {
                return Err(KError::TimedOut);
            }
            let me = self
                .cpu()
                .sched
                .current()
                .and_then(|idx| self.cpu().sched.thread_id(idx))
                .ok_or(KError::BadHandle)?;
            if let Some(slot) = self.cpu().sched.current()
                && let Some(thread) = self.cpu().sched.thread_at_mut(slot)
            {
                thread.set_recv_deadline(deadline);
            }
            for ep in endpoints {
                if let Some(channel) = self.machine().channels.channel_mut(ep.channel) {
                    channel.endpoint_mut(ep.side).set_blocked_receiver(Some(me));
                }
            }
            self.park_current();
            for ep in endpoints {
                if let Some(channel) = self.machine().channels.channel_mut(ep.channel) {
                    channel.endpoint_mut(ep.side).set_blocked_receiver(None);
                }
            }
            // Cleared on every path out, so a deadline never outlives the wait
            // that set it.
            if let Some(slot) = self.cpu().sched.current()
                && let Some(thread) = self.cpu().sched.thread_at_mut(slot)
            {
                thread.set_recv_deadline(None);
            }
            if let Some(at) = deadline
                && (self.clock)() >= at
            {
                return Err(KError::TimedOut);
            }
        }
    }

    /// Synchronous call: sends `request` from `from`, hands off directly to a
    /// waiting callee, and blocks for the reply (matched by transaction id).
    /// The caller's priority is carried to the callee; the chain depth is
    /// limited. Returns the reply, or `PeerClosed` if the callee's endpoint
    /// closes while the call is outstanding.
    pub fn call(&mut self, from: EndpointId, mut request: Message) -> Result<Message, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::Call);
        let caller = self.cpu().sched.current().ok_or(KError::BadHandle)?;
        // Both, and they are not interchangeable: the slot indexes this CPU's
        // own per-thread arrays, the identity is what machine-wide state holds.
        let caller_id = self
            .cpu()
            .sched
            .thread_id(caller)
            .ok_or(KError::BadHandle)?;
        if self.cpu().sync_depth[caller] >= MAX_SYNC_DEPTH {
            return Err(KError::Protocol);
        }
        let txn = self.cpu().next_txn;
        self.cpu().next_txn += 1;
        request.set_txn(txn);
        // The request carries the caller's cause, like the txn it carries above.
        // For a parked callee this agrees with the id handed over below; for one
        // that is not yet parked it is the *only* way the cause reaches it (D60).
        let caller_correlation = self.cpu().sched.thread_correlation(caller).unwrap_or(0);
        request.set_correlation(caller_correlation);

        let peer = Self::peer(from);
        let (callee, caller_priority, destination) = {
            let channel = self
                .machine()
                .channels
                .channel_mut(from.channel)
                .ok_or(KError::BadHandle)?;
            // **One *unanswered* call per endpoint, and a second is refused.**
            // The reply slot below holds one caller, so a second call here used
            // to overwrite the first: its reply went to whoever registered last
            // and the earlier caller waited for an answer that had already been
            // handed to somebody else. That is the failure build/README.md
            // records as "two drivers blocked on one service channel got each
            // other's replies", and the architectural answer to it — a channel
            // per client, selected across with `ChannelRecvAny` — is a rule
            // nothing enforced. Enforcing it is this line. `Protocol`, which is
            // what a call chain past its depth limit already returns, because
            // this is the same kind of thing: a caller that broke a rule about
            // how the mechanism may be used.
            //
            // Unanswered, not outstanding, and the difference is the whole
            // usefulness of the rule. Two clients sharing one service endpoint
            // is a topology this tree ships — the USB host serves its block and
            // input drivers over one — and they are fine, because each waits
            // for its answer before the next asks. `deliver_reply` clears the
            // slot when it queues the answer, so what this refuses is a call
            // made while another is genuinely still in flight.
            if channel.endpoint(from.side).pending_caller().is_some() {
                return Err(KError::Protocol);
            }
            // Deliver the request to the callee's queue **first**: this is the
            // step that can fail, and until it succeeds there is no call for a
            // reply to answer. Registering the caller before it left a full
            // queue's `WouldBlock` behind a reply slot naming a thread that is
            // not waiting — and the next reply on this endpoint would be
            // delivered to it.
            channel.endpoint_mut(peer.side).enqueue(request)?;
            // Now register where the reply will arrive (this endpoint).
            channel
                .endpoint_mut(from.side)
                .set_pending_caller(Some((caller_id, txn)));
            let callee = channel.endpoint(peer.side).blocked_receiver();
            if callee.is_some() {
                channel.endpoint_mut(peer.side).set_blocked_receiver(None);
            }
            (
                callee,
                self.cpu().sched.thread_priority(caller).unwrap_or(0),
                channel.object(peer.side),
            )
        };
        // Same arrival signal as `send` (D85): a server parked on its select
        // port is woken and learns which client endpoint to serve.
        self.signal_endpoint_arrival(destination);

        self.cpu().sync_depth[caller] += 1;
        let callee_id = callee;
        // Resolved once: a callee handed back by the endpoint is an identity,
        // and everything below it — priority, correlation, the handoff — is
        // this CPU's own bookkeeping, which is indexed by slot.
        //
        // **Three answers, not two.** A callee that is not in this CPU's run
        // queue used to mean "not parked here yet, block and wait"; it can now
        // also mean "parked on another CPU", and the two need opposite things
        // — the second has to be woken or it waits for a request that is
        // already in its queue.
        let callee_at = match callee {
            Some(id) => self.locate_thread(id),
            None => Residence::Gone,
        };
        // Only a local callee has a slot to stamp. Priority inheritance and
        // the correlation stamp are per-CPU scheduler operations, so **neither
        // crosses a CPU yet** — the request carries the cause in its header
        // either way (D60), which is what a remote callee adopts when it
        // dequeues, but the caller's priority does not follow it. That is D18's
        // seam widening rather than a new one.
        let callee = match callee_at {
            Residence::Here(idx) => Some(idx),
            _ => None,
        };
        match callee_at {
            Residence::Here(callee) => {
                // Carry the caller's priority to the callee for the call.
                self.cpu()
                    .sched
                    .set_thread_priority(callee, caller_priority);
                // And its causal id: "synchronous calls ... propagate it to the
                // callee for the duration of handling" (docs/observability/02),
                // so the work the callee does on this request is attributed to
                // the cause that requested it. The callee's own id is parked and
                // restored below, or a server would keep the last caller's id
                // and misattribute everything it did afterwards.
                self.cpu().saved_correlation[callee] =
                    self.cpu().sched.thread_correlation(callee).unwrap_or(0);
                self.cpu()
                    .sched
                    .set_thread_correlation(callee, caller_correlation);
                self.park_handoff_to(callee); // caller blocks, callee runs
            }
            Residence::Elsewhere { cpu, slot } => {
                // The callee is parked on another CPU, so there is no handoff
                // to make — this CPU cannot switch to a thread that is not on
                // it. Post the wakeup, then block here; the round trip costs a
                // wakeup and two scheduling decisions instead of two switches,
                // which is the price of the call not being local and is what
                // B3 will have to be measured against separately.
                crate::wakeup::wake(cpu, slot, callee_id.unwrap_or(ThreadId::UNASSIGNED));
                self.park_current();
            }
            Residence::Gone => {
                // Callee not yet waiting, so there is no callee index to stamp —
                // but the request now carries the id in its header, and whichever
                // thread later dequeues it adopts that id (D60). Block until it
                // replies.
                self.park_current();
            }
        }
        // --- resumed after the reply hands back ---
        self.cpu().sync_depth[caller] -= 1;
        // Or resumed because the kernel gave up waiting on this caller's
        // behalf. Told here rather than at the moment of expiry, because a
        // parked thread has no frame in which to receive an answer — this is
        // that frame, running again.
        //
        // **`TimedOut`, not the `PeerClosed` that falls out of finding no
        // reply below.** The peer is alive and merely did not answer, and a
        // caller told its peer had closed would stop retrying something that
        // may well work next time.
        if self
            .cpu()
            .sched
            .thread_id(caller)
            .is_some_and(|id| self.take_expired(id))
        {
            if let Some(channel) = self.machine().channels.channel_mut(from.channel) {
                channel.endpoint_mut(from.side).set_pending_caller(None);
            }
            return Err(KError::TimedOut);
        }
        if let Some(callee) = callee {
            self.cpu()
                .sched
                .set_thread_correlation(callee, self.cpu().saved_correlation[callee]);
            self.cpu().saved_correlation[callee] = 0;
        }

        let channel = self
            .machine()
            .channels
            .channel_mut(from.channel)
            .ok_or(KError::BadHandle)?;
        let endpoint = channel.endpoint_mut(from.side);
        // Cleared here for the paths that reach this point with the call still
        // registered — a timeout, a peer that closed, a reply that never came.
        // An *answered* call was already cleared by `deliver_reply`, which is
        // what lets the next caller in.
        endpoint.set_pending_caller(None);
        // **The reply is matched by transaction id**, which this method's own
        // contract has claimed since it was written and nothing checked. The
        // queue this drains holds whatever was sent to this endpoint, and a
        // reply is not the only thing that can be: a one-way `send` from the
        // peer lands here too, and so can the answer to somebody else's call.
        // A bare `dequeue` returned whichever was in front as the answer to a
        // question it had nothing to do with.
        match endpoint.take_reply(txn) {
            Some(reply) => Ok(reply),
            // Nothing queued at all: no answer is coming, which is what a
            // closed peer looks like from here and what this returned before.
            None if endpoint.is_empty() => Err(KError::PeerClosed),
            // Something is queued and none of it answers this call. Left where
            // it is — it is somebody's — and reported rather than taken.
            None => Err(KError::Protocol),
        }
    }

    /// Replies to an outstanding call received on `on`, delivering `response` to
    /// the waiting caller on the peer endpoint and handing off directly back to
    /// it (two switches per round trip). If no caller waits, the response is
    /// simply queued.
    pub fn reply(&mut self, on: EndpointId, response: Message) -> Result<(), KError> {
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::Reply);
        // A caller that no longer resolves exited while awaiting its reply.
        // The reply is delivered either way — it is queued on the endpoint —
        // and with nobody to hand off to, this thread simply keeps running.
        let Some(caller) = self.deliver_reply(on, response)? else {
            return Ok(());
        };
        match self.locate_thread(caller) {
            Residence::Here(idx) => self.park_handoff_to(idx), // callee blocks, caller runs with reply
            // A caller on another CPU is woken, not handed off to, and this
            // thread keeps running — the same thing it does for a caller that
            // has gone, and for the same reason: there is nobody here to give
            // the CPU to. The reply is already on the endpoint, so the caller
            // finds it when its own CPU schedules it.
            Residence::Elsewhere { cpu, slot } => {
                crate::wakeup::wake(cpu, slot, caller);
            }
            Residence::Gone => {}
        }
        Ok(())
    }

    /// Queues `response` where the next `call` on this channel will look for its
    /// reply, stamped with the transaction that call will mint — the state a
    /// server would have left behind.
    ///
    /// **A host test cannot drive a real round trip.** The mock context switch
    /// returns immediately, so a `call` never actually parks and there is no
    /// moment at which a server could run and answer it; a test that wants
    /// `call` to return a message has to stage one. Staging it with a plain
    /// `send` is what the dispatch tests used to do, and that stopped working
    /// the moment a reply had to be distinguishable from any other message on
    /// the queue — which is the whole of what [`deliver_reply`] now stamps and
    /// [`call`] now checks. A fixture that fakes the mechanism under test is a
    /// fixture that passes when the mechanism is gone, so this stages the
    /// stamp too.
    ///
    /// Test-only, and named for what it is rather than folded into `send`.
    /// `sender` is the endpoint the reply travels *from*, so this is a drop-in
    /// for the `send` these fixtures used before the stamp existed.
    #[cfg(test)]
    pub(crate) fn stage_reply_from(
        &mut self,
        sender: EndpointId,
        mut response: Message,
    ) -> Result<(), KError> {
        response.set_txn(self.cpu().next_txn);
        self.send(sender, response)
    }

    /// Puts `response` on the endpoint the caller is waiting at, **stamped with
    /// the transaction it answers**, or discards it if the call it answers was
    /// given up on. `Some(caller)` is the thread now holding a reply.
    ///
    /// The discard is one point. A reply to an abandoned call would otherwise
    /// queue, and the *next* call on that endpoint would dequeue it and take
    /// it for its own answer — a page-in served with the contents of a page
    /// somebody asked for a minute ago.
    ///
    /// # The stamp is the other, and it is what makes the match possible
    ///
    /// `call` mints a transaction id, puts it on the request, and its contract
    /// says the reply is "matched by transaction id". Only the first half of
    /// that existed: `set_txn` had exactly one caller, on the request leg, so
    /// every reply carried whatever id its *sender* happened to put in the
    /// header — zero, for every server in this tree — and the caller had
    /// nothing to match against. Checking without this would refuse every real
    /// reply; stamping without the check would leave the id decorative.
    ///
    /// **The kernel stamps it rather than the server**, for the reason
    /// [`MessageHeader::correlation`](crate::ipc::MessageHeader::correlation)
    /// gives about causes: an id a sender supplies is an id a sender can
    /// choose, and the whole value of matching on it is that a reply cannot
    /// claim to answer a call it was not asked. The endpoint already holds the
    /// only correct value, put there by the `call` this answers.
    fn deliver_reply(
        &mut self,
        on: EndpointId,
        mut response: Message,
    ) -> Result<Option<ThreadId>, KError> {
        let peer = Self::peer(on);
        let channel = self
            .machine()
            .channels
            .channel_mut(on.channel)
            .ok_or(KError::BadHandle)?;
        let endpoint = channel.endpoint_mut(peer.side);
        let Some((caller, txn)) = endpoint.pending_caller() else {
            // Nobody is waiting here. Either the call was given up on — in
            // which case the answer is for nobody and is dropped — or a server
            // is answering something that was never asked, which is queued as
            // it always was. Neither can be mistaken for an answer now: it
            // carries no transaction any caller will match.
            if endpoint.take_abandoned() {
                return Ok(None);
            }
            endpoint.enqueue(response)?;
            return Ok(None);
        };
        response.set_txn(txn);
        endpoint.enqueue(response)?;
        // **The call stops being outstanding here, not when its caller wakes
        // up.** The slot means "a call on this endpoint is unanswered", and
        // this is the moment that stops being true. Holding it until the caller
        // ran would refuse the next call for as long as a woken thread had not
        // been scheduled — which is most of the time on a cooperative
        // scheduler, and is what a shared service endpoint does between two
        // clients all day.
        endpoint.set_pending_caller(None);
        Ok(Some(caller))
    }

    /// Replies to the outstanding call on `on` and stays runnable: the caller
    /// is made `Ready` rather than handed off to, so this thread returns from
    /// the syscall and continues.
    ///
    /// [`reply`](Self::reply) blocks the replier as part of its handoff, which
    /// is correct only when the next `call` on the same endpoint will hand
    /// back. A server that selects across endpoints waits on a *port*, so it
    /// must not block here — nothing would ever wake it (D85).
    pub fn reply_and_continue(&mut self, on: EndpointId, response: Message) -> Result<(), KError> {
        if let Some(caller) = self.deliver_reply(on, response)? {
            self.wake_thread(caller);
        }
        Ok(())
    }

    /// Replies to the outstanding call on `on` **and** waits for the next
    /// request, in one operation — the request-server primitive. The reply is
    /// delivered to the waiting caller, this thread re-parks as `on`'s receiver,
    /// and it hands off directly to the caller (which resumes with the reply).
    /// The next `call` that arrives hands off back here and its request is
    /// returned. A bare [`reply`](Self::reply) blocks the server after handing
    /// off, so a server (e.g. the pager) that must serve *many* calls uses this
    /// to stay parked between them.
    pub fn reply_receive(&mut self, on: EndpointId, response: Message) -> Result<Message, KError> {
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::ReplyReceive);
        let me_id = self
            .cpu()
            .sched
            .current()
            .and_then(|idx| self.cpu().sched.thread_id(idx))
            .ok_or(KError::BadHandle)?;
        // Deliver the reply to the waiting caller and note who to hand back to.
        // Resolved here: the endpoint holds an identity, the handoff below is a
        // scheduler operation on this CPU and takes a slot. A caller that no
        // longer resolves exited while awaiting its reply — the reply is still
        // queued, and this server simply parks instead of handing off.
        let replied_to = self.deliver_reply(on, response)?;
        let caller_at = match replied_to {
            Some(id) => self.locate_thread(id),
            None => Residence::Gone,
        };
        // A caller on another CPU is woken **now**, before this server parks:
        // it cannot be handed off to, and everything below this point either
        // hands off or blocks, so there is no later moment that would still
        // reach it.
        if let (Residence::Elsewhere { cpu, slot }, Some(id)) = (caller_at, replied_to) {
            crate::wakeup::wake(cpu, slot, id);
        }
        let caller = match caller_at {
            Residence::Here(idx) => Some(idx),
            _ => None,
        };
        // Re-park to receive the next request; hand off to the caller on the
        // first pass (block on any later spurious wake), then return the request.
        let mut handed_off = false;
        loop {
            {
                let channel = self
                    .machine()
                    .channels
                    .channel_mut(on.channel)
                    .ok_or(KError::BadHandle)?;
                if let Some(request) = channel.endpoint_mut(on.side).dequeue() {
                    // The next request is already queued, so the server keeps
                    // running instead of handing off — the just-replied caller
                    // must still be WOKEN, or it sleeps forever with its reply
                    // queued. Unreachable while requests only arrived through
                    // direct handoffs; first hit when interrupt-driven serving
                    // let a second client queue while the server waited on its
                    // device (D84).
                    if !handed_off && let Some(caller) = caller {
                        self.cpu().sched.unblock(caller);
                    }
                    // A server staying parked between calls adopts each new
                    // request's cause as it starts handling it (D60).
                    self.adopt_message_correlation(&request);
                    return Ok(request);
                }
                if channel.endpoint(on.side).peer_closed() {
                    return Err(KError::PeerClosed);
                }
                channel
                    .endpoint_mut(on.side)
                    .set_blocked_receiver(Some(me_id));
            }
            if !handed_off {
                handed_off = true;
                match caller {
                    Some(caller) => self.park_handoff_to(caller),
                    None => self.park_current(),
                }
            } else {
                self.park_current();
            }
        }
    }

    /// Closes `endpoint`, raising peer-closed on the other end and waking any
    /// caller blocked awaiting a reply there or receiver blocked on it.
    pub fn close_endpoint(&mut self, endpoint: EndpointId) -> Result<(), KError> {
        let peer = Self::peer(endpoint);
        let to_wake = {
            let channel = self
                .machine()
                .channels
                .channel_mut(endpoint.channel)
                .ok_or(KError::BadHandle)?;
            channel.close_side(endpoint.side);
            let ep = channel.endpoint(peer.side);
            ep.blocked_receiver()
                .or_else(|| ep.pending_caller().map(|(t, _)| t))
        };
        // A peer that no longer resolves already exited; peer-closed is still
        // raised on the endpoint, so nothing is lost by having nobody to wake.
        if let Some(to_wake) = to_wake {
            self.wake_thread(to_wake);
        }
        Ok(())
    }

    /// Closes every endpoint whose object one of `held` names, waking whoever
    /// was waiting on the other side of each. Returns how many were closed.
    ///
    /// **This is what a process dying has to do to its channels.** A caller
    /// blocked in a synchronous call is parked until its server replies, and a
    /// server that died will not — so without this the caller waits for an
    /// event that can no longer happen, and no amount of restarting the driver
    /// reaches it. Restart is not recovery while somebody is still waiting.
    ///
    /// The asymmetry this fixes was visible in the tree: [`Self::remove_device`]
    /// already wakes a driver parked on the interrupt of a device that left,
    /// *"knowing which of the two happened"*, and nothing did the equivalent for
    /// a channel. [`Self::close_endpoint`] — the piece that wakes the waiter —
    /// existed and correct, and its only caller was a unit test.
    ///
    /// `held` is what the dying process actually held, from
    /// `HandleTable::audit`, rather than a list somebody kept alongside: a
    /// channel it was given late, or one handed to it by transfer, is exactly
    /// the one a separate list forgets.
    ///
    /// **Only where somebody is awaiting a reply.** A channel whose peer is
    /// merely parked in a receive is left open, and that distinction is the
    /// whole design rather than a refinement. Closing every endpoint a dying
    /// process held was tried: it timed out every check built on driver
    /// restart, because a device manager sits in a receive on the channel the
    /// *replacement* driver will be bound over, and telling it the peer is
    /// gone ends the conversation that recovery depends on. A caller mid-call
    /// is the opposite case — it is waiting for a reply from this process
    /// specifically, and nothing will ever send one.
    pub fn close_endpoints_of(&mut self, held: &[ObjectId]) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut closed = 0;
        for channel in 0..crate::ipc::MAX_CHANNELS {
            for side in 0..2 {
                let Some(chan) = self.machine().channels.channel(channel) else {
                    continue;
                };
                let Some(object) = chan.object(side) else {
                    continue;
                };
                if !held.contains(&object) {
                    continue;
                }
                // Somebody on the other end waiting for this process to reply.
                if chan
                    .endpoint(crate::ipc::Channel::peer(side))
                    .pending_caller()
                    .is_none()
                {
                    continue;
                }
                if self.close_endpoint(EndpointId { channel, side }).is_ok() {
                    closed += 1;
                }
            }
        }
        closed
    }

    /// Futex-style wait: block the current thread on `key` **iff** the word it
    /// names still holds `expected`. A mismatch returns [`KError::WouldBlock`]
    /// *without* blocking — the value changed under the caller, so it should
    /// recheck and retry (the futex compare-and-block race guard). On a match
    /// the thread is enrolled and parked until [`wake`](Self::wake) targets the
    /// same key.
    ///
    /// # Why the word arrives as a function and not a value
    ///
    /// It used to arrive as one: the syscall entry read the word and passed it
    /// in. **That is the futex race, not a guard against it.** Between the
    /// entry's read and this enrollment another CPU can write the word and
    /// wake the key — finding nobody enrolled — and this call then parks a
    /// thread on a condition that has already been signalled, for ever. The
    /// old note said the two were "effectively atomic on the boot CPU's
    /// cooperative execution", which was true and stopped being true when a
    /// second CPU started doing IPC (build/README.md, D237).
    ///
    /// So the entry supplies a *way to read* instead, and this calls it inside
    /// the same hold of [`crate::machine_lock`] that enrolls. kcore still never
    /// dereferences a user pointer — the closure is the entry's own validated
    /// read, invoked at the moment that makes it meaningful. That is what the
    /// plan called "the per-bucket lock or preempt-disable", and the lock turns
    /// out to be the one already there; what was missing was doing the compare
    /// under it.
    ///
    /// There is still no deadline (D37).
    pub fn wait_on_address(
        &mut self,
        key: WaitKey,
        expected: u64,
        read: impl FnOnce() -> Result<u64, KError>,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::WaitOnAddress);
        let me = self
            .cpu()
            .sched
            .current()
            .and_then(|idx| self.cpu().sched.thread_id(idx))
            .ok_or(KError::BadHandle)?;
        // Read *here*, under the hold that the enrollment below takes, so no
        // wake can land between the two.
        if read()? != expected {
            return Err(KError::WouldBlock);
        }
        // Enroll before parking; a full waiter pool refuses rather than
        // dropping the waiter (the caller does not then block).
        self.machine().waits.enroll(key, me)?;
        self.park_current();
        Ok(())
    }

    /// Wakes up to `count` threads blocked on `key`, returning how many were
    /// woken. Each is made `Ready` (no handoff); the caller decides when to
    /// yield so a woken waiter can run. `count == 0` wakes none; `u32::MAX`
    /// wakes all. No bitset or requeue variant in v0 (D37).
    pub fn wake(&mut self, key: WaitKey, count: u32) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut woken = 0;
        while (woken as u32) < count {
            match self.machine().waits.pop_matching(key) {
                // A waiter that no longer resolves exited while parked. Its
                // enrollment is consumed either way — leaving it would keep a
                // dead thread matching this key for ever — but it does not
                // count as woken, because nothing was.
                Some(thread) => {
                    if self.wake_thread(thread) != Residence::Gone {
                        woken += 1;
                    }
                }
                None => break,
            }
        }
        woken
    }

    /// Creates an async event-delivery port.
    pub fn port_create(&mut self) -> Result<PortId, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().ports.create()
    }

    /// Binds `port` to the object id of its `ObjectType::Port` object, so a
    /// ring-3 handle resolving to that id maps back to this port.
    /// Creates a port and gives it a freshly minted object id — the ring-3
    /// `PortCreate`, where nobody outside the kernel may choose an id. Boot
    /// glue keeps [`port_create`](Self::port_create) and binds the ids it
    /// wired the rest of the machine with.
    pub fn port_create_with_object(&mut self) -> Result<(PortId, ObjectId), KError> {
        // The machine tables, for this method — one section, as above.
        let _machine = crate::machine_lock::hold();
        self.machine().ports.create_with_object()
    }

    pub fn bind_port_object(&mut self, port: PortId, id: ObjectId) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().ports.set_port_object(port, id);
    }

    /// Resolves a port object id back to its port — the handle→port bridge a
    /// ring-3 port syscall uses after looking the handle up in the caller's table.
    pub fn port_of_object(&self, id: ObjectId) -> Option<PortId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().ports.port_of_object(id)
    }

    /// Registers a device node in the resource graph: the `ObjectType::Device`
    /// object `id` is backed by the I/O range `[base, base+len)` on interrupt
    /// line `irq`. The device manager/boot populates the graph before granting.
    pub fn device_register(
        &mut self,
        id: ObjectId,
        base: u16,
        len: u16,
        irq: u8,
        rights: Rights,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.register(id, base, len, irq, rights)
    }

    /// Resolves a Device object id to its I/O range — the handle→range bridge a
    /// `DeviceIo` syscall uses to read and enforce the granted device's extent.
    pub fn device_of_object(&self, id: ObjectId) -> Option<(u16, u16)> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.device_of_object(id)
    }

    /// Registers a Device object `id` backed by the MMIO register window `[base,
    /// base+len)` (physical). The MMIO counterpart of [`Self::device_register`],
    /// for a memory-mapped device granted to a ring-3 driver (D77).
    pub fn device_register_mmio(
        &mut self,
        id: ObjectId,
        base: u64,
        len: u64,
        rights: Rights,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.register_mmio(id, base, len, rights)
    }

    /// Records the interrupt INTID of a registered MMIO device (D84).
    pub fn device_set_mmio_irq(&mut self, id: ObjectId, intid: u32) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.set_mmio_irq(id, intid)
    }

    /// Records another interrupt line for `id` — what a multi-queue
    /// controller has, one per queue.
    pub fn device_add_mmio_irq(&mut self, id: ObjectId, intid: u32) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.add_mmio_irq(id, intid)
    }

    /// Every interrupt line `id` has; returns how many were written.
    pub fn intids_of_object(&self, id: ObjectId, out: &mut [u32]) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.intids_of_object(id, out)
    }

    /// Records that `child` sits behind `parent` in the bus topology.
    pub fn device_set_parent(&mut self, child: ObjectId, parent: ObjectId) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.set_parent(child, parent)
    }

    /// The device `id` sits behind, if any.
    pub fn device_parent_of(&self, id: ObjectId) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.parent_of(id)
    }

    /// Whether `id` genuinely requires physically contiguous memory.
    pub fn device_requires_contiguity(&self, id: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.requires_contiguity(id)
    }

    /// Records that `id` cannot follow a scattered buffer.
    pub fn device_set_requires_contiguity(
        &mut self,
        id: ObjectId,
        required: bool,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.set_requires_contiguity(id, required)
    }

    /// What `id` forwards, if it is a bus — what a controller needs to place
    /// the devices behind it.
    pub fn bus_window_of_object(&self, id: ObjectId) -> Option<crate::devmgr::BusWindow> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.bus_window_of_object(id)
    }

    /// Records what a bus forwards.
    pub fn device_set_bus_window(
        &mut self,
        id: ObjectId,
        window: crate::devmgr::BusWindow,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.set_bus_window(id, window)
    }

    /// This device's own configuration window `(phys_base, len)`, if a bus
    /// controller declared it with one.
    pub fn config_of_object(&self, id: ObjectId) -> Option<(u64, u64)> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.config_of_object(id)
    }

    /// Mints the object id the next declaration will use.
    pub fn mint_declared_device_id(&mut self) -> Result<ObjectId, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.mint_declared_id()
    }

    /// Registers a device a bus controller declared.
    /// Whether the graph knows `id` as a device at all — asked where a caller
    /// needs "is this a device" rather than "where are its registers", since a
    /// declared child may legitimately have none.
    pub fn device_known(&self, id: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.contains(id)
    }

    pub fn device_register_declared(
        &mut self,
        id: ObjectId,
        register: Option<(u64, u64)>,
        config: Option<(u64, u64)>,
        rights: Rights,
        identity: crate::devmgr::DeviceIdentity,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .devices
            .register_declared(id, register, config, rights, identity)
    }

    /// The devices directly behind `id`; returns how many were written.
    pub fn device_children_of(&self, id: ObjectId, out: &mut [ObjectId]) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.children_of(id, out)
    }

    /// Whether `id` is `root` or sits below it — the subtree test a capability
    /// scoped to a bus controller is checked against.
    pub fn device_is_descendant_of(&self, id: ObjectId, root: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.is_descendant_of(id, root)
    }

    /// The authority the graph holds over `id` — what a kernel-originated
    /// hand-out of this device carries.
    pub fn device_rights_of_object(&self, id: ObjectId) -> Option<Rights> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.rights_of_object(id)
    }

    /// Resolves a Device object to its interrupt INTID, if wired (D84).
    pub fn intid_of_object(&self, id: ObjectId) -> Option<u32> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.intid_of_object(id)
    }

    /// Arms or disarms `device`'s interrupt as a system wakeup source.
    pub fn set_wake_source(&mut self, device: ObjectId, armed: bool) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.set_wake_source(device, armed)?;
        crate::event::emit(
            crate::event::EventKind::PowerWakeSourceArmed,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [device.raw() as u64, u64::from(armed), 0, 0],
        );
        Ok(())
    }

    /// Whether `device`'s interrupt may wake this machine.
    pub fn is_wake_source(&self, device: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.is_wake_source(device)
    }

    /// Records a wake if `intid` belongs to an armed wakeup source, and
    /// answers the source that was credited.
    ///
    /// **Called from the interrupt bridge, before the port signal.** The order
    /// is the point: a wake that is delivered but not counted is exactly the
    /// lost wakeup the counter exists to close, and delivery can wake a
    /// process that then races the suspend entry. Counting first means the
    /// number has already moved by the time anything else can observe the
    /// event at all.
    ///
    /// A line nobody armed answers `None` and touches nothing — most
    /// interrupts on a running machine are not wake sources, and treating them
    /// as such would make the counter meaningless.
    pub fn record_wake(&mut self, intid: u32) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let source = self.machine().devices.armed_wake_source(intid)?;
        let now = self.cpu().sched.ticks();
        let grace = self.machine().wake.record_wake(source, now);
        // **Ending the sleep is part of counting it**, not a separate step a
        // later pass could forget: the thread parked in the commit is the
        // machine being asleep, and a wake that moved the counter without
        // unblocking it would leave a system that is awake by the numbers and
        // stopped in fact.
        if let Some(sleeper) = self.machine().sleeper.take() {
            self.machine().resumed_by = Some(source);
            // A sleeper that no longer resolves is a thread that died inside
            // the suspend commit. Nothing to unblock, and the wake is still
            // counted — the machine is awake either way, and the alternative is
            // unblocking whatever thread inherited the slot.
            self.wake_thread(sleeper);
        }
        crate::event::emit_with_flags(
            crate::event::EventKind::PowerWakeEvent,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            u64::from(!grace),
            [
                source.raw() as u64,
                u64::from(intid),
                self.machine().wake.events(),
                now,
            ],
        );
        Some(source)
    }

    /// The system wake-event counter — the number a suspend commit compares
    /// its snapshot against.
    pub fn wake_events(&self) -> u64 {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().wake.events()
    }

    /// Takes a wake hold for `holder`, lasting `ticks` scheduler ticks or
    /// until released when `ticks` is zero.
    pub fn acquire_wake_hold(
        &mut self,
        holder: ObjectId,
        ticks: u64,
    ) -> Result<(), crate::power::WakeError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let now = self.cpu().sched.ticks();
        // Sweep first: a table full of holds nobody is still asking for would
        // refuse a live one, and expiry is the only thing that ever clears
        // them for a holder that stopped renewing.
        self.machine().wake.expire(now);
        let expires_at = (ticks != 0).then(|| now + ticks);
        self.machine().wake.acquire(holder, expires_at)?;
        crate::event::emit(
            crate::event::EventKind::PowerWakeHoldTaken,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [
                holder.raw() as u64,
                ticks,
                now,
                self.machine().wake.held(now) as u64,
            ],
        );
        Ok(())
    }

    /// Releases one of `holder`'s wake holds. Answers whether there was one.
    pub fn release_wake_hold(&mut self, holder: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let released = self.machine().wake.release(holder);
        if released {
            let now = self.cpu().sched.ticks();
            crate::event::emit(
                crate::event::EventKind::PowerWakeHoldReleased,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [
                    holder.raw() as u64,
                    now,
                    self.machine().wake.held(now) as u64,
                    0,
                ],
            );
        }
        released
    }

    /// Releases every hold `holder` has — for a process that has gone.
    pub fn release_wake_holds_of(&mut self, holder: ObjectId) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().wake.release_all(holder)
    }

    /// Wake holds still counting, and whether a suspend commit is vetoed.
    pub fn wake_holds_held(&mut self) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let now = self.cpu().sched.ticks();
        self.machine().wake.expire(now);
        self.machine().wake.held(now)
    }

    /// Who is vetoing a suspend commit, if anybody — so a refusal can name
    /// them rather than say only that one exists.
    pub fn wake_hold_holder(&self) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().wake.holder_at(self.cpu().sched.ticks(), 0)
    }

    /// Commits the system to sleep, and does not return until it resumes.
    ///
    /// **The final step whose correctness cannot survive a service round
    /// trip** (`docs/power/01`, "Suspend Entry And Resume", step 6). By the
    /// time this is called the power manager has frozen what it freezes and
    /// suspended the driver hosts leaves-first; what is left is the one thing
    /// that has to be right *while nothing is running*.
    ///
    /// Two refusals, in the order they matter:
    ///
    /// 1. **The counter moved.** `snapshot` is what the caller read before it
    ///    began entry. Whether the wake arrived before, during or after that
    ///    read does not matter — it either changed the number or it did not,
    ///    and if it did the entry aborts and the machine never stops. This is
    ///    the lost-wakeup race closed by counting rather than by ordering.
    /// 2. **A wake hold vetoes.** Checked second because a machine somebody is
    ///    holding awake and a machine that has just been woken are different
    ///    situations, and the more urgent one is the wake.
    ///
    /// Otherwise the caller blocks. Nothing else is runnable by construction —
    /// user space is frozen — so the CPU reaches its idle loop, which *is*
    /// suspend-to-idle (`docs/power/01`: the baseline on every profile,
    /// requiring no firmware support). [`Self::record_wake`] unblocks it.
    pub fn system_suspend(&mut self, snapshot: u64) -> SuspendReport {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::SystemSuspend);
        let now = self.cpu().sched.ticks();
        let events = self.machine().wake.events();
        if events != snapshot {
            crate::event::emit(
                crate::event::EventKind::PowerSuspendAborted,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [1, events, snapshot, 0],
            );
            return SuspendReport {
                outcome: SuspendOutcome::WakeArrived,
                events,
                source: None,
            };
        }
        self.machine().wake.expire(now);
        if let Some(holder) = self.machine().wake.holder_at(now, 0) {
            crate::event::emit(
                crate::event::EventKind::PowerSuspendAborted,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [2, events, snapshot, holder.raw() as u64],
            );
            return SuspendReport {
                outcome: SuspendOutcome::Vetoed,
                events,
                source: Some(holder),
            };
        }

        // Recorded **before** the CPU stops. A record written afterwards would
        // describe a suspend that had already ended, and the per-stage
        // attribution `docs/power/01` asks for needs each stage visible while
        // it is happening.
        crate::event::emit(
            crate::event::EventKind::PowerSuspendCommitted,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [snapshot, now, 0, 0],
        );
        self.machine().sleeper = self
            .cpu()
            .sched
            .current()
            .and_then(|idx| self.cpu().sched.thread_id(idx));
        self.machine().resumed_by = None;
        self.park_current();

        // Resumed.
        let source = self.machine().resumed_by.take();
        let events = self.machine().wake.events();
        crate::event::emit(
            crate::event::EventKind::PowerResumed,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [
                source.map_or(0, |id| id.raw() as u64),
                events,
                self.cpu().sched.ticks(),
                0,
            ],
        );
        SuspendReport {
            outcome: SuspendOutcome::Resumed,
            events,
            source,
        }
    }

    /// Hands every device capability `process` still holds to the endpoint
    /// `to`, and returns how many were sent.
    ///
    /// This is what makes a device outlive its driver **without anyone having
    /// to remember**. Before it, a supervisor tearing down a dead driver had
    /// to know which devices it had been given and return each one by hand;
    /// a supervisor that forgot cost the machine a device permanently, because
    /// the only handle to it died with the process. Now forgetting is not
    /// possible, because the supervisor is not the one doing it.
    ///
    /// Each capability travels as its own message carrying **no payload**. The
    /// kernel does not know — and must not know — what protocol the receiver
    /// speaks; a capability arriving from the kernel *is* the whole message,
    /// and a manager that receives one has been handed a device back. That is
    /// a stronger signal than a flag in a body would be: a body can be forged
    /// by any sender, a transferred capability cannot.
    ///
    /// Called by a supervisor as part of teardown, before the process is
    /// removed. Rights travel with each capability unchanged.
    pub fn reclaim_devices<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        process: &mut crate::process::Process<A>,
        to: EndpointId,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // Leases and interrupt routes first, before a single handle moves.
        //
        // Per-process rather than per-reclaimed-object, deliberately: this must
        // not depend on the handle sweep below finding anything. A device whose
        // capability cannot be *delivered* — the message had no room, the
        // manager's queue was full — must still stop translating for a corpse,
        // and those are exactly the paths that skip the loop.
        self.end_leases_of(process.id(), LeaseEndReason::HolderGone, iommu);
        // And it must stop *interrupting* for one. A corpse's route would keep
        // a level-triggered line asserting into a port that will never be
        // drained again — and the manager is about to hand the device to a
        // replacement, which would then find its own route refused because the
        // graph still says the dead driver holds it.
        self.end_irq_routes_of(process.id(), RouteEndReason::HolderGone, irqs);
        // A causal origin, in the D59 sense: work that begins because something
        // outside the running trace happened — here, a process died. The
        // thread whose cause this work would otherwise inherit no longer
        // exists, and its kernel stack is gone with it, so there is nothing to
        // continue from; without minting here the reclaim records carry no
        // cause at all and cannot be joined to anything. One id per sweep, so
        // every capability recovered from one corpse shares a cause.
        crate::trace::set_current_correlation(crate::trace::mint());
        // The graph's objects first, so the handle-table scan below can ask
        // "is this a device?" without borrowing the executive inside it.
        let mut devices = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let found = self.machine().devices.objects(&mut devices);

        let mut taken =
            [(ObjectId::from_raw(0), Rights::from_bits(0)); crate::ipc::MAX_MSG_HANDLES];
        let count = process.handles_mut().reclaim(&devices[..found], &mut taken);

        for (object, held) in taken.iter().take(count) {
            // The capability goes back with the **graph's** authority over the
            // device, not with what the dying process happened to hold. A
            // driver may have been granted a device it could not pass on (a
            // narrowed grant, D113); returning only those rights would hand
            // the manager something it could never grant again, and the device
            // would be stranded after exactly one driver. The node outlives
            // every grant, which is what makes it the right source.
            //
            // A device in `taken` came from the graph's own object list, so
            // this lookup cannot miss; a miss is recorded rather than assumed
            // away. `held` is what the corpse had — unused, and named to say
            // that ignoring it is the decision rather than an oversight.
            let _ = held;
            // **A quarantined device is not handed back.** This is where
            // `docs/drivers/01`'s device quarantine is *enforced* rather than
            // merely recorded: the manager never receives the capability, so
            // nothing can bind the device again — not because a manager
            // chooses not to, but because it has nothing to bind. The decision
            // and its reasons were recorded by `quarantine_device`; withholding
            // here needs no second record, and adding one would report a loss
            // for a device that was deliberately kept.
            if self.machine().devices.is_quarantined(*object) {
                continue;
            }
            let Some(rights) = self.machine().devices.rights_of_object(*object) else {
                reclaim_lost(*object, RECLAIM_LOST_NOT_IN_GRAPH);
                continue;
            };
            let mut message = Message::new(crate::ipc::MessageHeader::new(0, 0));
            // Both failures are structural, not conditional: a fresh message
            // has room for a handle, and a full destination queue means the
            // receiver is not keeping up — the capability is dropped and the
            // device is as lost as it would have been without this, which is
            // the honest bound on what reclaim can promise. Each drop emits
            // the record that says so, because degrading in silence is what
            // docs/lifecycle/04 forbids: the bound is honest only if it is
            // visible when it bites.
            if message
                .add_handle(crate::ipc::TransferredHandle {
                    object: *object,
                    rights,
                })
                .is_err()
            {
                reclaim_lost(*object, RECLAIM_LOST_NO_HANDLE_ROOM);
                continue;
            }
            if self.send(to, message).is_err() {
                reclaim_lost(*object, RECLAIM_LOST_QUEUE_FULL);
                continue;
            }
            crate::event::emit(
                crate::event::EventKind::DeviceReclaimed,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [
                    object.raw() as u64,
                    rights.bits(),
                    to.channel as u64,
                    to.side as u64,
                ],
            );
        }
        count
    }

    /// Registers a device the kernel enumerated and can describe (D114).
    pub fn device_register_identified(
        &mut self,
        id: ObjectId,
        base: u64,
        len: u64,
        rights: Rights,
        identity: crate::devmgr::DeviceIdentity,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .devices
            .register_identified(id, base, len, rights, identity)
    }

    /// Records the lease a device translates through, and who holds it.
    pub fn device_set_aperture(
        &mut self,
        id: ObjectId,
        holder: ObjectId,
        aperture: crate::devmgr::DeviceAperture,
        expires_at: Option<u64>,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .devices
            .set_aperture(id, holder, aperture, expires_at)
    }

    /// Where `device` is in its driver lifecycle, as last declared.
    pub fn lifecycle_state_of(&self, device: ObjectId) -> Option<crate::lifecycle::DriverState> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().lifecycle.state_of(device)
    }

    /// Pushes `id`'s lease deadline out. See
    /// [`crate::devmgr::DeviceTable::renew_lease`].
    pub fn renew_device_lease(
        &mut self,
        id: ObjectId,
        holder: ObjectId,
        expires_at: Option<u64>,
    ) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.renew_lease(id, holder, expires_at)
    }

    /// Ends every lease whose deadline has passed, **through the path a
    /// departure uses**.
    ///
    /// Not a second teardown but a third caller of the one that exists: a lease
    /// that expires must leave the machine in exactly the state a lease that
    /// was given up leaves it in, and the only way to be sure of that is for it
    /// to be the same code. Returns how many ended.
    pub fn expire_leases(
        &mut self,
        now: u64,
        mut iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut expired =
            [(ObjectId::from_raw(0), ObjectId::from_raw(0)); crate::devmgr::MAX_DEVICES];
        let found = self.machine().devices.leases_expired_by(now, &mut expired);
        if found == 0 {
            return 0;
        }
        // One cause for the sweep: expiry begins because time passed, not
        // because any thread did anything, so there is nothing to inherit.
        crate::trace::set_current_correlation(crate::trace::mint());
        for (device, holder) in expired.iter().take(found) {
            self.end_one_lease(
                *holder,
                *device,
                LeaseEndReason::Expired,
                iommu.as_deref_mut(),
            );
        }
        found
    }

    /// The DMA aperture a device translates through, if it has a live lease.
    pub fn aperture_of_object(&self, id: ObjectId) -> Option<crate::devmgr::DeviceAperture> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.aperture_of_object(id)
    }

    /// Who holds `id`'s DMA lease, if anyone does.
    pub fn lease_holder_of_object(&self, id: ObjectId) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.lease_holder_of_object(id)
    }

    /// Takes `len` bytes from a device's lease, returning the device-visible
    /// address. `None` when the device has no live lease or it is spent —
    /// [`Self::aperture_of_object`] tells those apart.
    pub fn device_allocate_in_aperture(&mut self, id: ObjectId, len: u64) -> Option<u64> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.allocate_in_aperture(id, len)
    }

    /// Ends every DMA lease `holder` holds: the devices' translations are torn
    /// down through `iommu` and their address ranges become reusable.
    ///
    /// **This is the route a register window does not have.** D93 gave process
    /// teardown no revocation code because a device window lives in the dying
    /// address space and dies with it. An IOMMU translation does not — it lives
    /// in the IOMMU, and it outlives the process completely. So a lease must be
    /// ended explicitly, and *before* the process's frames go back to the
    /// allocator: in the window between, a device that still holds an address
    /// would write into memory the kernel has already handed to someone else.
    ///
    /// Returns how many leases ended.
    pub fn end_device_leases<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        process: &crate::process::Process<A>,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        self.end_leases_of(process.id(), LeaseEndReason::HolderGone, iommu)
    }

    /// Ends `device`'s lease if `holder` is the one holding it. Returns whether
    /// a lease ended — `false` when there was none, or when it belongs to
    /// someone else, which is the case when a process gives up one of two
    /// handles it holds to the same device.
    pub fn end_device_lease(
        &mut self,
        holder: ObjectId,
        device: ObjectId,
        reason: LeaseEndReason,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        if self.machine().devices.lease_holder_of_object(device) != Some(holder) {
            return false;
        }
        self.end_one_lease(holder, device, reason, iommu)
    }

    /// Ends every lease `holder` holds. The graph is scanned **by device**
    /// rather than by process, which is the only direction available: nothing
    /// can enumerate the holders of an object, and there are at most
    /// [`crate::devmgr::MAX_DEVICES`] nodes to look at.
    fn end_leases_of(
        &mut self,
        holder: ObjectId,
        reason: LeaseEndReason,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // A causal origin, for the same reason `reclaim_devices` mints one: a
        // lease ends because something outside the running trace happened —
        // a process died, or gave its device up — and the thread whose cause
        // this work would otherwise inherit may be gone with its stack. Without
        // minting, the records carry no cause and cannot be joined to anything.
        // One id per sweep, so every lease ended for one holder shares a cause.
        crate::trace::set_current_correlation(crate::trace::mint());
        let mut held = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let found = self.machine().devices.leases_held_by(holder, &mut held);
        let mut mapper = iommu;
        for object in held.iter().take(found) {
            let reborrowed = mapper.as_deref_mut();
            self.end_one_lease(holder, *object, reason, reborrowed);
        }
        found
    }

    /// The teardown itself: hardware first, then the record.
    ///
    /// That order matters. The reverse would leave an interval in which the
    /// graph says a device reaches nothing while the IOMMU still says it
    /// reaches its buffers — and the graph is what the next lease consults
    /// before reissuing those addresses.
    fn end_one_lease(
        &mut self,
        holder: ObjectId,
        device: ObjectId,
        reason: LeaseEndReason,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        if let Some(mapper) = iommu {
            mapper.end_lease(device);
        }
        if self.machine().devices.end_lease(device).is_none() {
            return false;
        }
        // **Every attachment to this device is gone with the lease, and the
        // records must go too — without unmapping.** `end_lease` already
        // dropped every translation, and the address range is reusable now, so
        // a later detach calling `unmap` on one of these ranges would be
        // reaching into whatever lease holds it next. A record that outlived
        // its translation is also a lie in the other direction: it would make
        // an object look reachable by a device that can no longer reach
        // anything.
        self.forget_attachments_to(device);
        crate::event::emit(
            crate::event::EventKind::DeviceDmaLeaseEnded,
            crate::event::Severity::Notice,
            crate::event::Component::Driver,
            [device.raw() as u64, holder.raw() as u64, reason as u64, 0],
        );
        true
    }

    /// Applies `policy` to one refused DMA transaction.
    ///
    /// **The counterpart of [`crate::devmgr::record_dma_fault`], and the split
    /// between them is the one `docs/drivers/01` draws**: faults "are logged
    /// *and can* trigger driver isolation". Logging is unconditional, which is
    /// why it is a free function that needs nothing; isolation needs the
    /// resource graph, so it lives here and a port with no executive in scope
    /// still records the fault. A caller that has both calls both, in that
    /// order — the record describes what happened, this describes what was
    /// done about it.
    ///
    /// Isolation ends the device's **lease**, which is a strictly larger
    /// action than the hardware already took: the unit refused one address,
    /// this makes the device reach nothing at all. It is the whole of what a
    /// kernel can do to a misbehaving device without knowing what it is for.
    ///
    /// Called from the port's fault-harvest path, which may be interrupt
    /// context — so it takes no locks beyond the event ring's and never
    /// schedules. Stopping the holder is deferred to the caller through
    /// [`DmaFaultOutcome::stop`] for that reason as much as for the lack of a
    /// frame allocator here.
    pub fn isolate_dma_fault(
        &mut self,
        fault: DmaFault,
        policy: IsolationPolicy,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> DmaFaultOutcome {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let (IsolationPolicy::EndLease | IsolationPolicy::EndLeaseAndStop) = policy else {
            return DmaFaultOutcome::default();
        };
        // A fault the port could not attribute to a device has nothing to
        // isolate: there is no lease to end and no holder to stop, and
        // pretending otherwise would be a policy that reports acting without
        // having acted.
        let Some(device) = fault.device else {
            return DmaFaultOutcome::default();
        };
        let Some(holder) = self.machine().devices.lease_holder_of_object(device) else {
            return DmaFaultOutcome::default();
        };
        if !self.end_one_lease(holder, device, LeaseEndReason::FaultIsolated, iommu) {
            return DmaFaultOutcome::default();
        }
        crate::event::emit(
            crate::event::EventKind::DeviceDmaIsolated,
            crate::event::Severity::Critical,
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                holder.raw() as u64,
                policy as u64,
                fault.kind as u64,
            ],
        );
        DmaFaultOutcome {
            isolated: true,
            stop: matches!(policy, IsolationPolicy::EndLeaseAndStop).then_some(holder),
        }
    }

    /// Routes `device`'s interrupts to `port`, held by `holder` — the third
    /// thing a binding grants, alongside the register window and the DMA
    /// lease.
    ///
    /// The line comes from the resource graph, never from the caller
    /// ([`crate::devmgr::DeviceTable::route_irq`]).
    pub fn device_route_irq(
        &mut self,
        device: ObjectId,
        port: PortId,
        holder: ObjectId,
    ) -> Result<(), KError> {
        let intid = self
            .machine()
            .devices
            .intid_of_object(device)
            .ok_or(KError::InvalidMapping)?;
        self.device_route_irq_line(device, intid, port, holder)
    }

    /// Routes one **named** line of `device` to `port` — what a controller with
    /// a vector per queue needs, since each queue's completions must reach a
    /// different port for the port to identify the queue.
    ///
    /// **Both halves, here and nowhere else.** Recording the route and binding
    /// the port to the line are one operation: the record is what revocation
    /// walks, and the binding is what makes an interrupt arrive. A second entry
    /// point that did only the first would record a route that delivers nothing
    /// — which is exactly what happened when this was added as a passthrough to
    /// the graph, and the driver parked forever on a completion the port never
    /// heard about. [`Self::device_route_irq`] is written in terms of this so
    /// there is one path and not two.
    pub fn device_route_irq_line(
        &mut self,
        device: ObjectId,
        intid: u32,
        port: PortId,
        holder: ObjectId,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .devices
            .route_irq_line(device, intid, port, holder)?;
        match self.machine().ports.port_mut(port) {
            Some(p) => p.bind(u64::from(intid), IRQ_PORT_SIGNAL),
            None => Err(KError::BadHandle),
        }
    }

    /// The interrupt line the resource graph records for `device`, if it has
    /// one.
    ///
    /// The graph's answer to "which line is this device's", which
    /// [`Self::device_route_irq`] asks internally and a caller that must
    /// *report* the line — a syscall answering a ring-3 driver with the source
    /// its port will see — asks before routing.
    pub fn device_intid(&self, device: ObjectId) -> Option<u32> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's read is one section
        // rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.intid_of_object(device)
    }

    /// Where `device`'s interrupts are going, if anywhere.
    pub fn irq_route_of_object(&self, device: ObjectId) -> Option<crate::devmgr::IrqRoute> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.irq_route_of_object(device)
    }

    /// Ends `device`'s interrupt route if `holder` is the one receiving it.
    /// Returns whether a route ended — `false` when there was none, or when it
    /// belongs to someone else, which is the case when a process gives up one
    /// of two handles it holds to the same device.
    pub fn end_device_irq_route(
        &mut self,
        holder: ObjectId,
        device: ObjectId,
        reason: RouteEndReason,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> bool {
        if self
            .machine()
            .devices
            .irq_route_of_object(device)
            .map(|r| r.holder)
            != Some(holder)
        {
            return false;
        }
        self.end_one_irq_route(device, reason, irqs)
    }

    /// Ends every interrupt route `process` is receiving — the death sweep, and
    /// the interrupt half of what [`Self::end_device_leases`] does for DMA.
    ///
    /// **This is the route a register window does not have**, for exactly the
    /// reason D93 gave for leases: a window lives in the dying address space
    /// and dies with it, while an interrupt route lives in the interrupt
    /// controller and in the port table, both of which outlive the process. A
    /// route left standing keeps a level-triggered line asserting into a port
    /// nobody drains.
    ///
    /// Returns how many routes ended.
    pub fn end_device_irq_routes<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        process: &crate::process::Process<A>,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> usize {
        self.end_irq_routes_of(process.id(), RouteEndReason::HolderGone, irqs)
    }

    /// Ends every route `holder` receives. Scanned **by device** for the same
    /// reason [`Self::end_leases_of`] is: nothing can enumerate the holders of
    /// an object, and there are at most [`crate::devmgr::MAX_DEVICES`] nodes.
    fn end_irq_routes_of(
        &mut self,
        holder: ObjectId,
        reason: RouteEndReason,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut held = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let found = self.machine().devices.irq_routes_held_by(holder, &mut held);
        if found == 0 {
            return 0;
        }
        // A causal origin, for the same reason the lease sweep mints one: a
        // route ends because something outside the running trace happened, and
        // the thread whose cause it would otherwise inherit may be gone with
        // its stack. Minted only when there is work, so a sweep that finds
        // nothing does not reroot the caller's trace.
        crate::trace::set_current_correlation(crate::trace::mint());
        let mut router = irqs;
        for object in held.iter().take(found) {
            let reborrowed = router.as_deref_mut();
            self.end_one_irq_route(*object, reason, reborrowed);
        }
        found
    }

    /// The teardown itself: hardware first, then the port binding, then the
    /// record.
    ///
    /// The order is the one [`Self::end_one_lease`] uses and for the same
    /// reason. Masking last would leave an interval in which the graph says
    /// nobody is listening while the controller still delivers — and delivery
    /// into an unbound port is a signal the port facility discards without
    /// counting, so the edges would be lost silently rather than visibly.
    fn end_one_irq_route(
        &mut self,
        device: ObjectId,
        reason: RouteEndReason,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // **Every route this device has, not just its first.** A multi-queue
        // controller is routed once per queue, and a sweep that ended one would
        // leave the rest delivering into ports whose holder is gone — the exact
        // hole routing exists to close, reopened by a device having more than
        // one line.
        let mut router = irqs;
        let mut ended = false;
        while let Some(route) = self.machine().devices.end_irq_route(device) {
            if let Some(router) = router.as_deref_mut() {
                router.mask(route.intid);
            }
            if let Some(port) = self.machine().ports.port_mut(route.port) {
                port.unbind(u64::from(route.intid), IRQ_PORT_SIGNAL);
            }
            crate::event::emit(
                crate::event::EventKind::DeviceIrqRevoked,
                crate::event::Severity::Notice,
                crate::event::Component::Driver,
                [
                    device.raw() as u64,
                    u64::from(route.intid),
                    reason as u64,
                    route.holder.raw() as u64,
                ],
            );
            ended = true;
        }
        ended
    }

    /// Removes `device` **and everything behind it**, deepest first.
    ///
    /// A bus controller does not leave alone. Pulling a switch out of a machine
    /// takes the ports and the endpoints below it in one physical event, and a
    /// graph that removed only the node named would leave the children behind
    /// as capabilities that still resolve, still map, and still authorize DMA
    /// for hardware that is not there — the exact condition removal exists to
    /// prevent, reintroduced one level down.
    ///
    /// **Leaves first, and that order is load-bearing rather than tidy.** Each
    /// step removes a node with no children, so no removal ever runs against a
    /// parent whose descendants are still live and no child is ever left
    /// pointing at a slot that has been emptied. Removing the root first would
    /// invert both.
    ///
    /// Iterative rather than recursive: the depth is a property of the machine,
    /// and this runs on a departure path where a kernel stack is the last thing
    /// worth spending on hardware that has already gone. The walk is bounded by
    /// the pool — a subtree cannot hold more nodes than the graph has.
    pub fn remove_device<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        device: ObjectId,
        reason: crate::lifecycle::TransitionReason,
        processes: &mut crate::process::ProcessTable<A>,
        mut iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
        mut irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> RemovalReport {
        let mut total = RemovalReport {
            existed: false,
            holders: 0,
            windows: 0,
            dependents_told: 0,
            dependents_missed: 0,
            woken: 0,
            subtree: 0,
        };
        for _ in 0..crate::devmgr::MAX_DEVICES {
            let Some(target) = self.deepest_below(device) else {
                break;
            };
            let one = self.remove_one_device(
                target,
                reason,
                processes,
                iommu.as_deref_mut(),
                irqs.as_deref_mut(),
            );
            if !one.existed {
                break;
            }
            total.existed = true;
            total.holders += one.holders;
            total.windows += one.windows;
            total.dependents_told += one.dependents_told;
            total.dependents_missed += one.dependents_missed;
            total.woken += one.woken;
            total.subtree += 1;
            if target == device {
                break;
            }
        }
        total
    }

    /// A node below `root` with no children of its own, or `root` itself when
    /// it is childless. `None` when the graph does not hold `root` at all.
    ///
    /// Descends by taking the first child at each step. Which child does not
    /// matter — every one of them is going — and the bound makes a malformed
    /// graph stop rather than spin, though [`crate::devmgr::DeviceTable::set_parent`]
    /// refuses the cycles that could produce one.
    fn deepest_below(&self, root: ObjectId) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        if !self.machine().devices.contains(root) {
            return None;
        }
        let mut current = root;
        for _ in 0..crate::devmgr::MAX_DEVICES {
            let mut children = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
            if self.machine().devices.children_of(current, &mut children) == 0 {
                return Some(current);
            }
            current = children[0];
        }
        Some(current)
    }

    /// Removes one device from the machine: every capability naming it is taken
    /// from every holder, everything that lived on it ends, and the graph
    /// forgets it.
    ///
    /// The whole of the original removal, now the step
    /// [`Self::remove_device`] repeats over a subtree.
    ///
    /// **The first departure nobody chose.** Every other route a capability
    /// leaves by is something its holder did — handed it on, closed it, died.
    /// This one runs while the holders are alive and using the device, which is
    /// what makes it a different mechanism rather than another caller of an
    /// existing one: `reclaim_devices` takes every device from *one* process,
    /// and this takes *one* device from every process.
    ///
    /// The order is `reclaim_devices`' order, for the same reasons.
    ///
    /// 1. **The lease and the route first**, before a single handle moves. A
    ///    device that has been pulled must stop translating and stop
    ///    interrupting whatever else succeeds — and those are exactly the paths
    ///    that a failure in the handle sweep would skip.
    /// 2. **Then every holder's handles and windows.** Taken with `reclaim`,
    ///    which requires no `TRANSFER`: that right governs a process handing a
    ///    capability on, and this is the kernel taking one back from a process
    ///    that has no say in it.
    /// 3. **Then the node.** Last, because dropping it is what makes every
    ///    device syscall refuse, and doing it first would leave the teardown
    ///    above unable to find what it was tearing down.
    ///
    /// Returns what it did, because "the device went away" is not the
    /// interesting part — "and it was taken from three processes" is.
    fn remove_one_device<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        device: ObjectId,
        reason: crate::lifecycle::TransitionReason,
        processes: &mut crate::process::ProcessTable<A>,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
        irqs: Option<&mut (dyn InterruptRouter + '_)>,
    ) -> RemovalReport {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // A causal origin, in the D59 sense: this begins because something
        // outside the running trace happened — a device left the machine — so
        // there is no thread whose cause to inherit. One id for the whole
        // removal, so every record it produces joins up.
        crate::trace::set_current_correlation(crate::trace::mint());

        let mut woken = 0usize;
        let holder = self.machine().devices.lease_holder_of_object(device);
        if let Some(holder) = holder {
            self.end_one_lease(holder, device, LeaseEndReason::Removed, iommu);
        }
        if let Some(route) = self.machine().devices.irq_route_of_object(device) {
            self.end_device_irq_route(
                route.holder,
                device,
                crate::devmgr::RouteEndReason::Removed,
                irqs,
            );
            // **Then wake whoever is parked on the line that has just stopped
            // existing.** A driver blocked waiting for an interrupt from a
            // device that has left waits for something that can no longer
            // happen — the one failure a removal creates that correct
            // bookkeeping does not fix, because the driver is not running to
            // observe any of it.
            //
            // After the teardown, not before: ending the route unbinds the
            // port, and an unbound binding takes any event pending on it, so a
            // wake delivered first would be thrown away by the cleanup that
            // followed it. The binding is re-made here for the one delivery it
            // is needed for.
            //
            // On the removal signal rather than the interrupt's, so the driver
            // wakes knowing which of the two happened: a completion to service,
            // or a device to stop trying to.
            if let Some(port) = self.machine().ports.port_mut(route.port)
                && port
                    .bind(u64::from(route.intid), IRQ_PORT_SIGNAL_REMOVED)
                    .is_ok()
            {
                woken = self.port_signal(u64::from(route.intid), IRQ_PORT_SIGNAL_REMOVED, 1);
            }
        }

        // An attached memory object must stop being reachable too. The device
        // is gone, so its translations cannot be reached through it any more —
        // but the *records* would outlive it, and a later detach would unmap
        // into a lease that no longer exists.
        self.forget_attachments_to(device);

        let mut holders = 0usize;
        let mut windows = 0usize;
        let wanted = [device];
        for index in 0..crate::process::MAX_PROCESSES {
            let Some(process) = processes.get_mut(index) else {
                continue;
            };
            let mut taken = [(ObjectId::from_raw(0), Rights::from_bits(0)); 1];
            if process.handles_mut().reclaim(&wanted, &mut taken) == 0 {
                continue;
            }
            holders += 1;
            // The window goes with the handle. `unless_held` is still the right
            // test even here: a process may have held two handles to the device
            // and `reclaim` takes them all, so this asks the question after the
            // fact rather than assuming it.
            if process.revoke_device_windows_unless_held(
                device,
                crate::process::WindowRevokeReason::Removed,
            ) {
                windows += 1;
            }
        }

        // **Tell the dependents before the node goes**, because the graph is
        // where the dependency edges live and removing the node takes them
        // with it. A service depending on this device learns from the same
        // `ServiceNotice` the crash ladder uses — the event is different, the
        // delivery is not, and a dependent that had to distinguish "the driver
        // failed" from "the device left" by which mechanism told it would be
        // learning the kernel's internals rather than its own situation.
        let (dependents_told, dependents_missed) =
            self.notify_dependents(device, crate::lifecycle::DriverState::Removed, reason);

        // **`Removed` becomes reachable.** It has been a terminal state with a
        // full table of transitions into it since the driver framework landed,
        // and nothing could ever put a device there, because nothing performed
        // a removal. The `from` is whatever was last recorded — a device may
        // be pulled while active, suspended, or degraded, and every one of
        // those is a legal edge — and `Discovered` when nothing was, which is
        // the only state a lifecycle may open at.
        let from = self
            .machine()
            .lifecycle
            .state_of(device)
            .unwrap_or(crate::lifecycle::DriverState::Discovered);
        let _ = self.declare_lifecycle(
            device,
            from,
            crate::lifecycle::DriverState::Removed,
            reason,
            0,
        );

        let dependents = self.machine().devices.remove(device);
        let known_dependents = dependents
            .map(|list| list.iter().flatten().count())
            .unwrap_or(0);

        crate::event::emit(
            crate::event::EventKind::DeviceRemoved,
            crate::event::Severity::Warning,
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                holders as u64,
                windows as u64,
                known_dependents as u64,
            ],
        );

        RemovalReport {
            existed: dependents.is_some(),
            holders,
            windows,
            dependents_told,
            dependents_missed,
            woken,
            // One node. The subtree total is the caller's to accumulate.
            subtree: usize::from(dependents.is_some()),
        }
    }

    /// Records a driver-lifecycle transition for `device` and emits it.
    ///
    /// **The manager declares; the kernel checks and stamps.** What is checked
    /// is only consistency — that `from` is the state this kernel last
    /// recorded, and that the edge exists in the table — never policy. Whether
    /// a degraded device deserves a reset is the manager's question; whether
    /// the record stream describes a history that could have happened is not,
    /// because nothing downstream could tell.
    ///
    /// The record carries the device the *capability* named, so a process
    /// cannot narrate a lifecycle for a device it does not hold; the caller's
    /// identity and causal id come from the ambient trace context, as every
    /// other emission does. `detail` rides in the record's `flags` — the four
    /// payload slots are spent on the transition itself, and the detail is the
    /// one field the kernel does not interpret.
    pub fn declare_lifecycle(
        &mut self,
        device: ObjectId,
        from: crate::lifecycle::DriverState,
        to: crate::lifecycle::DriverState,
        reason: crate::lifecycle::TransitionReason,
        detail: u64,
    ) -> Result<(), crate::lifecycle::TransitionError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // **The device tree's half of the rule, checked before the edge
        // table's.** This is the only place that holds both the lifecycle
        // record and the parent edges, which is why it lives here rather than
        // in `crate::lifecycle` — and why the rule itself is a free function
        // there, testable against a list of states with no graph at all.
        //
        // Before the edge check rather than after, so a manager suspending a
        // bus under a live device is told about the device rather than about
        // an edge that was legal all along.
        let mut children = [ObjectId::from_raw(0); crate::devmgr::MAX_DEVICES];
        let count = self.machine().devices.children_of(device, &mut children);
        let mut states = [None; crate::devmgr::MAX_DEVICES];
        for (slot, child) in states.iter_mut().zip(children.iter()).take(count) {
            *slot = self.machine().lifecycle.state_of(*child);
        }
        let parent = self.machine().devices.parent_of(device);
        let parent_state = parent.and_then(|id| self.machine().lifecycle.state_of(id));
        if let Err(block) = crate::lifecycle::neighbours_permit(to, &states[..count], parent_state)
        {
            let (neighbour, state) = match block {
                crate::lifecycle::NeighbourBlock::Child { index, state } => {
                    (children[index], state)
                }
                crate::lifecycle::NeighbourBlock::Parent { state } => {
                    (parent.unwrap_or(device), state)
                }
            };
            return Err(crate::lifecycle::TransitionError::OutOfOrder { neighbour, state });
        }
        self.machine().lifecycle.declare(device, from, to)?;
        let severity = match to {
            crate::lifecycle::DriverState::Failed => crate::event::Severity::Critical,
            crate::lifecycle::DriverState::Degraded => crate::event::Severity::Error,
            crate::lifecycle::DriverState::Removed | crate::lifecycle::DriverState::Resetting => {
                crate::event::Severity::Warning
            }
            _ => crate::event::Severity::Notice,
        };
        crate::event::emit_with_flags(
            crate::event::EventKind::DriverLifecycleTransition,
            severity,
            crate::event::Component::Driver,
            detail,
            [device.raw() as u64, from as u64, to as u64, reason as u64],
        );
        Ok(())
    }

    /// Registers `endpoint` as depending on `device`.
    pub fn device_add_dependent(
        &mut self,
        device: ObjectId,
        endpoint: EndpointId,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.add_dependent(device, endpoint)
    }

    /// Tells every service depending on `device` that it is in `state`, for
    /// `reason` — ladder step 4.
    ///
    /// **The notice carries a body, unlike a reclaimed capability.** A
    /// capability arriving from the kernel *is* its own message: only
    /// something that held the device could send it, and the receiver knows
    /// what it means. A notice has no such key — a dependent may depend on
    /// several devices, and "one of yours is in trouble" is not actionable
    /// without saying which — so the kernel fills in a `ServiceNotice` and
    /// sends it. Every field of it is a fact the kernel established, not a
    /// claim forwarded from a process that might be wrong about it.
    ///
    /// Returns `(notified, unreachable)`. Both, because the second is the
    /// interesting one: a dependent that never learns its device is gone waits
    /// on it for ever, and a drop here would be exactly the silence
    /// `docs/lifecycle/04` forbids. The counts go into the record whether or
    /// not anything failed.
    pub fn notify_dependents(
        &mut self,
        device: ObjectId,
        state: crate::lifecycle::DriverState,
        reason: crate::lifecycle::TransitionReason,
    ) -> (usize, usize) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut endpoints = [EndpointId {
            channel: 0,
            side: 0,
        }; crate::devmgr::MAX_DEPENDENTS];
        let found = self.machine().devices.dependents_of(device, &mut endpoints);
        if found == 0 {
            return (0, 0);
        }
        // A causal origin, for the same reason the lease and route sweeps mint
        // one: this work begins because something outside the running trace
        // happened, and the thread whose cause it would inherit may be gone.
        crate::trace::set_current_correlation(crate::trace::mint());
        let notice = crate::isl_binding::lifecycle::ServiceNotice {
            size: SERVICE_NOTICE_SIZE as u32,
            version: 1,
            flags: 0,
            device: device.raw(),
            state,
            reason,
            reserved: 0,
        };
        let mut body = [0u8; SERVICE_NOTICE_SIZE];
        if tessera_isl_runtime::encode(&notice, &mut body).is_err() {
            // Structurally impossible — the buffer is the wire size — and
            // reported rather than assumed away: an unencodable notice means
            // nobody is told, which must not look like nobody depending.
            return (0, found);
        }
        let (mut sent, mut lost) = (0usize, 0usize);
        for endpoint in endpoints.iter().take(found) {
            let mut message = Message::new(crate::ipc::MessageHeader::new(0, 0));
            if message.set_inline(&body).is_err() || self.send(*endpoint, message).is_err() {
                lost += 1;
                continue;
            }
            sent += 1;
        }
        crate::event::emit(
            crate::event::EventKind::DeviceDependentsNotified,
            if lost > 0 {
                crate::event::Severity::Error
            } else {
                crate::event::Severity::Notice
            },
            crate::event::Component::Driver,
            [device.raw() as u64, sent as u64, lost as u64, state as u64],
        );
        (sent, lost)
    }

    /// Attempts a reset of `device` if `policy` allows — ladder step 5.
    ///
    /// Returns `Ok(false)` when policy declined: not an error, and not a
    /// success either. A declined reset is a rung the ladder deliberately
    /// skipped, and it emits no `DEVICE_RESET` record because none was
    /// attempted — a record there would have a log service reading a reset
    /// that never touched the hardware.
    ///
    /// `Ok(true)` is a device that was reset and came back. `Err` is one the
    /// hardware refused, recorded either way so a reset that does not work is
    /// visible rather than inferred from what happens next.
    pub fn reset_device(
        &mut self,
        device: ObjectId,
        policy: crate::devmgr::ResetPolicy,
        resetter: Option<&mut (dyn crate::devmgr::DeviceResetter + '_)>,
    ) -> Result<bool, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        if matches!(policy, crate::devmgr::ResetPolicy::Never) {
            return Ok(false);
        }
        // No resetter is a fact about this port, not a reason to pretend the
        // device was reset. The ladder's next rung must know it was not.
        let Some(resetter) = resetter else {
            return Err(KError::NotSupported);
        };
        let identity = self.machine().devices.identity_of_object(device);
        let window = self.machine().devices.mmio_of_object(device);
        let outcome = resetter.reset(device, identity, window);
        crate::event::emit(
            crate::event::EventKind::DeviceReset,
            if outcome.is_ok() {
                crate::event::Severity::Warning
            } else {
                crate::event::Severity::Error
            },
            crate::event::Component::Driver,
            [
                device.raw() as u64,
                outcome.err().map_or(0, |e| e as u64),
                identity.map_or(0, |id| u64::from(id.class_code)),
                policy as u64,
            ],
        );
        outcome.map(|()| true)
    }

    /// Stops offering `device`: policy has decided it is not to be bound
    /// again. Returns whether this changed anything.
    ///
    /// Quarantine is enforced by [`Self::reclaim_devices`] declining to hand
    /// the capability back, which is what makes it a property of the system
    /// rather than a flag a manager is trusted to honour.
    pub fn quarantine_device(&mut self, device: ObjectId, faults: u64, policy: u64) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        if !self.machine().devices.quarantine(device) {
            return false;
        }
        crate::event::emit(
            crate::event::EventKind::DeviceQuarantined,
            crate::event::Severity::Critical,
            crate::event::Component::Driver,
            [device.raw() as u64, faults, policy, 0],
        );
        true
    }

    /// Whether policy has stopped offering `device`.
    pub fn is_quarantined(&self, device: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.is_quarantined(device)
    }

    /// Offers a quarantined device again — the administrative undo.
    pub fn release_from_quarantine(&mut self, device: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.release_from_quarantine(device)
    }

    /// The lifecycle state recorded for `device`, if any.
    pub fn lifecycle_of_object(&self, device: ObjectId) -> Option<crate::lifecycle::DriverState> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().lifecycle.state_of(device)
    }

    /// Backs `object` with `pages` zeroed frames — the memory object a
    /// caller then maps and hands on.
    pub fn memory_create<A: tessera_karch::AddressSpaceOps>(
        &mut self,
        owner: ObjectId,
        pages: usize,
        placement: crate::memory::Placement,
        space: &crate::vm::AddressSpace<A>,
        alloc: &mut dyn tessera_karch::FrameSource,
    ) -> Result<ObjectId, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .memory
            .create(owner, pages, placement, space, alloc)
    }

    /// Creates a **service-backed** object: `pages` pages that do not exist
    /// yet, supplied on demand by `pager`.
    pub fn memory_create_paged(
        &mut self,
        owner: ObjectId,
        pages: usize,
        pager: ObjectId,
    ) -> Result<ObjectId, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.create_paged(owner, pages, pager)
    }

    /// The endpoint that supplies `object`'s pages, or `None` if it is
    /// kernel-backed.
    pub fn memory_pager_of(&self, object: ObjectId) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.pager_of(object)
    }

    /// The process that answers for `object`'s contents.
    pub fn memory_served_by(&self, object: ObjectId) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.served_by(object)
    }

    /// Whether `object`'s pager has failed it.
    pub fn memory_is_faulted(&self, object: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.is_faulted(object)
    }

    /// Takes a cache frame from the budget, or reports pressure.
    ///
    /// `None` does not mean the machine is out of memory — it means the *cache*
    /// is at its ceiling and something must be reclaimed before it grows again.
    pub fn cache_take(&mut self) -> Option<()> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().cache_budget.alloc_ordinary()
    }

    /// Gives a cache frame back to the budget, after a page was evicted.
    pub fn cache_give_back(&mut self) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().cache_budget.free_ordinary();
    }

    /// Whether the cache is at its ceiling.
    pub fn cache_at_pressure(&self) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().cache_budget.at_pressure()
    }

    /// A clean page somewhere that could be dropped.
    pub fn cache_evictable(&self) -> Option<(ObjectId, u64)> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.any_evictable()
    }

    /// A dirty page somewhere — what reclaim writes back when nothing clean is
    /// left to take.
    pub fn cache_dirty_anywhere(&self) -> Option<(ObjectId, u64)> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.any_dirty()
    }

    /// Drops `object`'s page at `offset` from the cache, handing back the frame
    /// the object held it in. `None` for a dirty page.
    pub fn memory_evict(
        &mut self,
        object: ObjectId,
        offset: u64,
    ) -> Option<tessera_karch::PhysFrame> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.evict(object, offset)
    }

    /// Records that `object`'s page at `offset` has been written, or asks for
    /// the writer to be throttled.
    pub fn memory_mark_dirty(
        &mut self,
        object: ObjectId,
        offset: u64,
    ) -> crate::pager::DirtyOutcome {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.mark_dirty(object, offset)
    }

    /// Marks `object`'s page at `offset` clean, after its write-back was
    /// acknowledged.
    pub fn memory_mark_clean(&mut self, object: ObjectId, offset: u64) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.mark_clean(object, offset);
    }

    /// Opens a write-back window over `object`'s page at `offset`.
    ///
    /// Paired with [`memory_write_back_finished`](Self::memory_write_back_finished)
    /// around the blocking request, so a store that lands while the asking
    /// thread is parked is seen rather than lost.
    pub fn memory_write_back_started(&mut self, object: ObjectId, offset: u64) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.begin_write_back(object, offset);
    }

    /// Closes the window, reporting whether a store landed inside it. `true`
    /// means the page must stay dirty whatever the service answered.
    pub fn memory_write_back_finished(&mut self, object: ObjectId, offset: u64) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.end_write_back(object, offset)
    }

    /// Whether `object`'s page at `offset` is dirty.
    pub fn memory_is_dirty(&self, object: ObjectId, offset: u64) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.is_dirty(object, offset)
    }

    /// How many of `object`'s pages are dirty.
    pub fn memory_dirty_count(&self, object: ObjectId) -> u32 {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.dirty_count(object)
    }

    /// The offsets of `object`'s dirty pages, ascending.
    pub fn memory_dirty_offsets(&self, object: ObjectId, out: &mut [u64]) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.dirty_offsets(object, out)
    }

    /// Records `frame` as `object`'s page `page`.
    pub fn memory_supply(
        &mut self,
        object: ObjectId,
        page: usize,
        frame: tessera_karch::PhysFrame,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.supply(object, page, frame)
    }

    /// The frame holding `object`'s page `page`, if it is resident.
    pub fn memory_frame_at(
        &self,
        object: ObjectId,
        page: usize,
    ) -> Option<tessera_karch::PhysFrame> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.frame_at(object, page)
    }

    /// How many pages `object` has, resident or not.
    pub fn memory_pages_of(&self, object: ObjectId) -> Option<usize> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.pages_of(object)
    }

    /// How many of `object`'s pages are resident right now.
    pub fn memory_resident_pages(&self, object: ObjectId) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.resident_pages(object)
    }

    /// Where `object`'s creator said it had to be.
    pub fn memory_placement_of(&self, object: ObjectId) -> Option<crate::memory::Placement> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.placement_of(object)
    }

    /// Moves ownership of `object` to `owner` — what a transfer does.
    pub fn memory_set_owner(&mut self, object: ObjectId, owner: ObjectId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.set_owner(object, owner)
    }

    /// Who owns `object`, if it is a memory object.
    /// Puts a memory object on a handling path. See
    /// [`crate::memory::MemoryTable::classify`] — the class may rise and never
    /// fall.
    pub fn memory_classify(
        &mut self,
        object: ObjectId,
        class: crate::memory::MemoryClass,
    ) -> Result<(), tessera_karch::KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.classify(object, class)
    }

    /// The handling path `object` is on, if it is a memory object.
    pub fn memory_class_of(&self, object: ObjectId) -> Option<crate::memory::MemoryClass> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.class_of(object)
    }

    pub fn memory_owner_of(&self, object: ObjectId) -> Option<ObjectId> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.owner_of(object)
    }

    /// Every memory object `owner` owns, in `out`; returns how many — the
    /// sweep a departing process's teardown walks.
    pub fn memory_objects_owned_by(&self, owner: ObjectId, out: &mut [ObjectId]) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.objects_owned_by(owner, out)
    }

    /// The frames `object` owns, in `out`; returns how many. Zero means the
    /// capability names something that is not a memory object.
    pub fn memory_frames_of(
        &self,
        object: ObjectId,
        out: &mut [tessera_karch::PhysFrame],
    ) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.frames_of(object, out)
    }

    /// How many bytes `object` covers, if it is a memory object.
    pub fn memory_len_of(&self, object: ObjectId) -> Option<u64> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.len_of(object)
    }

    /// Drops the object's own reference to its frames — what the last handle
    /// closing must do. Returns how many were released.
    pub fn memory_destroy(
        &mut self,
        object: ObjectId,
        alloc: &mut dyn tessera_karch::FrameSource,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // **Detach before a single frame moves.** `exec.rs`'s lease rule says
        // it for a whole lease and it is the same window here: between the
        // frames going back to the allocator and the device forgetting the
        // address, a device still holding a translation writes into memory the
        // kernel has already handed to somebody else.
        self.detach_memory(object, iommu);
        self.machine().memory.destroy(object, alloc)
    }

    /// Records that a device can reach `object`. See
    /// [`crate::memory::MemoryTable::attach`].
    pub fn memory_attach(
        &mut self,
        object: ObjectId,
        attachment: crate::memory::Attachment,
    ) -> Result<(), tessera_karch::KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.attach(object, attachment)
    }

    /// Where `object` is reachable from, if anywhere.
    pub fn memory_attachment_of(&self, object: ObjectId) -> Option<crate::memory::Attachment> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.attachment_of(object)
    }

    /// The address `object` was last attached at on `device`, for a re-attach
    /// that should land where it landed before.
    pub fn memory_remembered_address(&self, object: ObjectId, device: ObjectId) -> Option<u64> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().memory.remembered_address(object, device)
    }

    /// Ends `object`'s attachment: the device's translation goes away and the
    /// record with it. Returns what the attachment was.
    ///
    /// A scoped attachment with no mapper to hand is the one case that cannot
    /// be honoured, and it **keeps the record** rather than clearing it: a
    /// record that outlives its translation is a leak, and a translation that
    /// outlives its record is a device reaching memory nothing believes it can
    /// reach.
    pub fn detach_memory(
        &mut self,
        object: ObjectId,
        iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> Option<crate::memory::Attachment> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let attachment = self.machine().memory.attachment_of(object)?;
        if attachment.scoped {
            let mapper = iommu?;
            if mapper
                .unmap(attachment.device, attachment.address, attachment.len)
                .is_err()
            {
                crate::event::emit(
                    crate::event::EventKind::DeviceDmaUnscoped,
                    crate::event::Severity::Error,
                    crate::event::Component::Driver,
                    [
                        attachment.device.raw() as u64,
                        object.raw() as u64,
                        attachment.address,
                        attachment.len,
                    ],
                );
                return None;
            }
        }
        self.machine().memory.detach(object)
    }

    /// Forgets every attachment to `device` **without unmapping**, for the one
    /// caller where the translations are already gone: the lease has ended, so
    /// there is nothing left to unmap and an `unmap` into a range that may
    /// belong to the next lease is the opposite of safe.
    fn forget_attachments_to(&mut self, device: ObjectId) {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut attached = [ObjectId::from_raw(0); crate::memory::MAX_MEMORY_OBJECTS];
        let found = self
            .machine()
            .memory
            .objects_attached_to(device, &mut attached);
        for object in attached.iter().take(found) {
            self.machine().memory.detach(*object);
            // And forget the address, which is the part that outlives a
            // detach. The lease is over, so the whole range belongs to
            // whoever takes the next one — an address remembered across that
            // boundary would be reissued into somebody else's aperture.
            self.machine().memory.forget_last_attachment(*object);
        }
    }

    /// Destroys every memory object `owner` owns, dropping each object's own
    /// reference to its frames. Returns how many objects went.
    ///
    /// **The exit sweep, and it is only half of the reclamation.** The other
    /// half is `AddressSpace::teardown`, which drops the reference each
    /// *mapping* holds. The two are independent and the accounting is
    /// absolute, so they may run in either order — what must not happen is
    /// only one of them running, which is why a process teardown path that
    /// frees an address space without calling this leaks every page of every
    /// buffer that process owned.
    ///
    /// `Process` deliberately forgets its handles on drop (see the invariant
    /// on [`crate::process::Process`], which driver-restart conservation
    /// depends on), so there is no destructor that could do this and there
    /// must not be one.
    pub fn release_memory_of(
        &mut self,
        owner: ObjectId,
        alloc: &mut dyn tessera_karch::FrameSource,
        mut iommu: Option<&mut (dyn crate::devmgr::DmaMapper + '_)>,
    ) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut owned = [ObjectId::from_raw(0); crate::memory::MAX_MEMORY_OBJECTS];
        let found = self.machine().memory.objects_owned_by(owner, &mut owned);
        for object in owned.iter().take(found) {
            // Reborrowed per object rather than moved: a dying process may own
            // several attached buffers, and stopping at the first would leave
            // the rest reachable by a device after their frames were freed.
            self.detach_memory(*object, iommu.as_deref_mut());
            self.machine().memory.destroy(*object, alloc);
        }
        found
    }

    /// What a device is, if the kernel learned it during enumeration.
    pub fn identity_of_object(&self, id: ObjectId) -> Option<crate::devmgr::DeviceIdentity> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.identity_of_object(id)
    }

    /// Records where `device`'s configuration structures sit inside its
    /// granted window — what a driver holding only a window cannot discover.
    pub fn device_set_layout(
        &mut self,
        device: ObjectId,
        layout: crate::devmgr::DeviceLayout,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.set_layout(device, layout)
    }

    /// Where `device`'s structures are, if the kernel resolved them.
    pub fn layout_of_object(&self, device: ObjectId) -> Option<crate::devmgr::DeviceLayout> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.layout_of_object(device)
    }

    /// Resolves a Device object id to its MMIO register window
    /// `(phys_base, len)` — the handle→window bridge a `MapDevice` syscall
    /// uses to map the granted window into a ring-3 driver's address space.
    pub fn mmio_of_object(&self, id: ObjectId) -> Option<(u64, u64)> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().devices.mmio_of_object(id)
    }

    /// Preallocates a `(source, signal)` binding slot on `port` (one per pair).
    pub fn port_bind(&mut self, port: PortId, source: u64, signal: u8) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .ports
            .port_mut(port)
            .ok_or(KError::BadHandle)?
            .bind(source, signal)
    }

    /// Signals `edges` edges on `(source, signal)`, fanning out to every port
    /// bound to it: edges coalesce onto the slot, and a drainer blocked on a
    /// newly-asserted port is woken (asynchronously — no handoff). Returns the
    /// number of ports the signal was delivered to.
    pub fn port_signal(&mut self, source: u64, signal: u8, edges: u32) -> usize {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut delivered = 0;
        for i in 0..MAX_PORTS {
            // Take the drainer to wake out of the port borrow before touching
            // the scheduler (one `&mut self` field at a time).
            let wake = match self.machine().ports.port_mut_at(i) {
                Some(port) => {
                    if port.deliver(source, signal, edges) {
                        delivered += 1;
                        port.take_blocked_drainer()
                    } else {
                        None
                    }
                }
                None => None,
            };
            // A drainer that no longer resolves exited while parked on the
            // port. The event stays delivered — it is queued on the port, not
            // handed to the thread — so the next drainer still sees it.
            if let Some(wake) = wake {
                self.wake_thread(wake);
            }
        }
        delivered
    }

    /// Signals **one** port, on a source that port is already bound to.
    ///
    /// The narrow form of [`Self::port_signal`], and the difference is the
    /// whole reason a holder may call it. The broadcast form delivers to every
    /// port bound to a source, which is right for an interrupt line — the line
    /// is the machine's and whoever bound it asked for its news. A holder
    /// raising a *software* edge must reach the port it was granted and no
    /// other, or a driver that demultiplexed line 3 could wake everybody
    /// waiting on line 5 by naming their source.
    ///
    /// The binding is the authority: a port can only be signalled on something
    /// it is bound to, so what a holder may raise was decided when the port was
    /// made and not by the number it passes.
    pub fn port_signal_one(
        &mut self,
        port: PortId,
        source: u64,
        signal: u8,
        edges: u32,
    ) -> Result<(), KError> {
        let wake = {
            let held = self
                .machine()
                .ports
                .port_mut(port)
                .ok_or(KError::BadHandle)?;
            if !held.deliver(source, signal, edges) {
                // Not a source this port carries. Refused rather than
                // delivered to nothing: a signal that silently reached nobody
                // is a driver believing it woke a client it did not.
                return Err(KError::Protocol);
            }
            held.take_blocked_drainer()
        };
        if let Some(wake) = wake {
            self.wake_thread(wake);
        }
        Ok(())
    }

    /// Whether a wait on this port would return without parking.
    pub fn port_asserted(&self, port: PortId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .ports
            .port(port)
            .is_some_and(|held| held.is_asserted())
    }

    /// Whether a thread is parked in a `port_wait` on `port`.
    ///
    /// The port's counterpart to [`endpoint_receiver`](Self::endpoint_receiver),
    /// and it exists for the same reason: a CPU that wants to know whether a
    /// thread on *another* CPU is waiting cannot read that CPU's scheduler, but
    /// the port is machine state and a drainer registers itself there as the
    /// last thing it does before parking.
    pub fn port_has_drainer(&self, port: PortId) -> bool {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .ports
            .port(port)
            .is_some_and(crate::port::Port::has_blocked_drainer)
    }

    /// Drains one coalesced event from `port`, blocking until one is available.
    /// A drain reads current state (the coalesced pending count), mirroring
    /// `receive`'s park-and-retry.
    pub fn port_wait(&mut self, port: PortId) -> Result<PortEvent, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        // Inside a method that can suspend this thread mid-borrow — see
        // [`occupancy`].
        let _inside = self.enter_blocking(occupancy::Site::PortWait);
        loop {
            if let Some(event) = self
                .machine()
                .ports
                .port_mut(port)
                .ok_or(KError::BadHandle)?
                .drain()
            {
                return Ok(event);
            }
            let me = self
                .cpu()
                .sched
                .current()
                .and_then(|idx| self.cpu().sched.thread_id(idx))
                .ok_or(KError::BadHandle)?;
            if let Some(p) = self.machine().ports.port_mut(port) {
                p.set_blocked_drainer(Some(me));
            }
            self.park_current();
        }
    }

    /// The coalescing count observed on `port` (observability).
    pub fn port_coalesced(&self, port: PortId) -> u64 {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .ports
            .port(port)
            .map(|p| p.coalesced())
            .unwrap_or(0)
    }

    /// Creates a root job (boot authority; no right required).
    pub fn job_create_root(
        &mut self,
        object: ObjectId,
        limits: JobLimits,
    ) -> Result<JobId, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().jobs.create_root(object, limits)
    }

    /// Creates a child job under `parent` (needs `CREATE_JOB`; tighten-only).
    pub fn job_create_child(
        &mut self,
        parent: JobId,
        object: ObjectId,
        limits: JobLimits,
        rights: Rights,
    ) -> Result<JobId, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine()
            .jobs
            .create_child(parent, object, limits, rights)
    }

    /// Reads a job (for its state source, member count, killed flag).
    pub fn job(&self, id: JobId) -> Option<&Job> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().jobs.job(id)
    }

    /// Adds a member process (needs `CREATE_PROCESS`; enforces the count cap).
    pub fn job_add_process(
        &mut self,
        job: JobId,
        member: Member,
        rights: Rights,
    ) -> Result<(), KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        self.machine().jobs.add_process(job, member, rights)
    }

    /// Kills the `root` subtree (needs `KILL`): terminates every member thread
    /// and signals each job's state port with `member-exit` per member and
    /// `emptiness` once its members are gone, **innermost-first**. The killed
    /// member process ids are written to `killed_out` (up to its length) and the
    /// count returned, so the caller can mark those processes exited and release
    /// their object references (the object/process lifecycle it owns).
    pub fn job_kill(
        &mut self,
        root: JobId,
        rights: Rights,
        killed_out: &mut [Option<ObjectId>],
    ) -> Result<usize, KError> {
        // The machine tables, for this method. Nested holds inside it are
        // free; what this one buys is that the method's update is one
        // section rather than as many as it has accesses.
        let _machine = crate::machine_lock::hold();
        let mut order: [Option<JobId>; MAX_JOBS] = [None; MAX_JOBS];
        let count = self.machine().jobs.kill_order(root, rights, &mut order)?;
        let mut killed = 0;
        for slot in order.iter().take(count) {
            let Some(job_id) = slot else { continue };
            // Copy what the kill needs out of the table borrow before touching
            // the scheduler and ports.
            let (state_source, members) = match self.machine().jobs.job(*job_id) {
                Some(job) => (job.state_source(), job.members()),
                None => continue,
            };
            for member in members.iter().flatten() {
                // A member whose thread no longer resolves has already exited.
                // It still counts as killed and still signals member-exit: the
                // job's membership is what the kill is about, and a process
                // that died first is one this call does not have to stop.
                if let Some(idx) = self.cpu().sched.index_of(member.thread) {
                    self.cpu().sched.terminate(idx);
                }
                if killed < killed_out.len() {
                    killed_out[killed] = Some(member.process);
                }
                killed += 1;
                self.port_signal(state_source, SIGNAL_MEMBER_EXIT, 1);
            }
            // The job is now empty — signal it for a supervisor to reclaim.
            self.port_signal(state_source, SIGNAL_EMPTY, 1);
        }
        Ok(killed)
    }
}

#[cfg(test)]
#[path = "tests/exec.rs"]
mod tests;
