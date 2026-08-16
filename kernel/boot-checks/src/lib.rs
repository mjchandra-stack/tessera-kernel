// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Boot checks that are not about any architecture.
//!
//! A port's `main.rs` is its composition root: it knows a boot protocol, a
//! trap frame and an exit mechanism, and nothing else should. What has been
//! accumulating there instead is the *checks* — and a check written against
//! `kcore` alone is the same check on every port, so two ports carrying one
//! each is two things that can drift into disagreeing about what passed.
//!
//! This is the counterpart of `kernel/arch-conformance`, which holds the
//! checks that need only the porting layer. These need only the kernel core.
//!
//! **A check here reports and returns; it never exits.** Ending the run is the
//! harness's business and the mechanism is the port's — Arm semihosting, a
//! RISC-V test finisher, an x86 debug-exit device — so a check that called one
//! would be a check that could only live on one port.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md,
//! docs/observability/01-debugging-monitoring-tracing-logging.md
//! Budget: none (boot verification)

#![no_std]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use tessera_kcore as kcore;
use tessera_kcore::kprintln;
use tessera_kcore::object::ObjectId;

/// How many restarts the driver-restart self-test gives a host before the
/// supervisor gives up on it.
///
/// Here rather than in each port's harness because this check reads the
/// records that self-test produced and has to know what it asked for: the two
/// numbers agreeing by coincidence is the failure this removes.
pub const DRIVER_RESTART_SELFTEST_BUDGET: u32 = 3;

/// Maps one user-readable page at `virt` holding `bytes`, for a check that
/// needs a user program to have something to read.
///
/// **Bytes rather than a word.** Three ports had a copy of this taking a
/// value, and two of them took a `u32` where the third took a `u64` — so the
/// three wrote a different number of bytes into the page and only looked like
/// one function. The width belongs to the caller, which knows its register
/// size; what is shared is the page.
pub fn map_user_bytes(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
    virt: u64,
    bytes: &[u8],
    fail: u32,
) -> Result<(), u32> {
    use tessera_karch::{PageFlags, VirtAddr};
    let frame = frames.alloc_frame().ok_or(fail)?;
    space.zero_frame(frame);
    space.write_bytes_to_frame(frame, 0, bytes);
    space
        .map(VirtAddr::new(virt), frame, PageFlags::rw().user(), frames)
        .map_err(|_| fail)
}

/// Reads the driver framework's own event records and checks they tell the
/// story the framework's counters told (docs/drivers/01: "Transitions are
/// observable through structured events"; build/README.md, D112).
///
/// Everything a port's rebind check proves, it proves from values the boot
/// glue itself collected. This proves the same story from the **kernel's
/// records** — which is what a log service will have to work from, and what
/// nothing was checking. The two are independent: a rebind check can pass
/// while the framework emits nothing at all, which is the state both ports
/// were in before.
///
/// Written against `kcore::event` alone, so no port decides separately what
/// the records have to say.
pub fn device_events(device_obj: ObjectId) -> bool {
    use kcore::event::{self, Component, EventKind, KernelEvent, Severity};
    const CAP: usize = event::EVENT_RING_CAPACITY;

    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );

    // Drops that happened *while the framework ran* — nothing on this port has
    // ever drained the ring, so this is the first time its occupancy has been
    // looked at. A non-zero count means records were lost before anything
    // could read them, and the check must say so rather than assert past it.
    let dropped_during_boot = event::dropped();
    let mut drained = [blank; CAP];
    let n = event::drain(&mut drained);
    let summary = event::summarize_device_events(&drained[..n], kcore::trace::epoch());
    // The same records, read as the crash-recovery ladder. Read from *this*
    // drain rather than its own, because the ring is drained once per boot and
    // a second reader would find it empty — and because the two readings
    // describing the same run is the point: the rebind and the recovery that
    // made it necessary are one story.
    let ladder = event::summarize_driver_ladder(&drained[..n], kcore::trace::epoch());

    // The envelope every record must carry. The wire round-trip is not
    // repeated here: it is the same generated binding the x86-64 harness
    // encodes and decodes every boot, and adding an ISL-runtime dependency to
    // two more kernels would buy a second run of the same proof.
    let envelope_ok = drained[..n].iter().all(|e| {
        e.size == KernelEvent::WIRE_SIZE as u32 && e.version == event::EVENT_SCHEMA_VERSION
    });

    // The bound holds on this port too: overflow the ring, confirm the drops
    // are counted at the source, and that the next emission with room reports
    // them once (docs/observability/02, "Flood control").
    for _ in 0..(CAP as u32 + 8) {
        event::emit(
            EventKind::DeviceMapRefused,
            Severity::Debug,
            Component::Driver,
            [0; 4],
        );
    }
    let flood_dropped = event::dropped();
    let mut flood = [blank; CAP];
    let flooded = event::drain(&mut flood);
    event::emit(
        EventKind::DeviceMapRefused,
        Severity::Debug,
        Component::Driver,
        [0; 4],
    );
    let mut tail = [blank; CAP];
    let tail_n = event::drain(&mut tail);
    let bound_ok = flood_dropped == 8
        && flooded == CAP
        && tail[..tail_n]
            .iter()
            .any(|e| e.kind == EventKind::EventsDropped && e.arg0 == 8)
        && event::dropped() == 0;

    // One crash in the rebind check, plus one per launch of the give-up
    // self-test. Derived from the budget rather than written as a number, so
    // changing the budget cannot silently change what this asserts.
    let expected_crashes = 1 + DRIVER_RESTART_SELFTEST_BUDGET;
    let pass = dropped_during_boot == 0
        && envelope_ok
        && summary.describes_a_rebind(device_obj.raw())
        && ladder.describes_a_contained_ladder(expected_crashes)
        // The other four rungs — the ones a supervisor cannot climb alone: a
        // manager marking the device, a dump taken, dependents told, a reset
        // attempted. A system recording only the supervisor's three would be
        // running half a ladder and describing a whole one.
        && ladder.describes_the_full_ladder()
        // One supervisor gave up — the self-test's. The rebind check's did
        // not, and a run where both did would mean recovery never succeeded.
        && ladder.gave_up == 1
        // And the policy that answered the give-up stopped offering the
        // device, which is the enforcement behind quarantine rather than the
        // decision to quarantine.
        && ladder.quarantined == 1
        && bound_ok;

    if pass {
        // device-events: OK — the framework's own records tell the same story
        // the check above told from its own counters ({} driver records: {}
        // window-grant, {} window-revoke-on-transfer, {} dma-grant, {} device-
        // reclaim): device {} was granted a register window {} times, which is
        // the rebind — one driver held it, died, and the manager gave the same
        // transport to another. The whole seven-step crash-recovery ladder is
        // in the same records: {} contained crashes, each contained and dumped
        // ({} trace records captured with them), {} device marked degraded by
        // its manager, {} dependent service told, {} reset attempted, {}
        // reclaim-and-rebind that recovered {} frames, and {} supervisor that
        // spent its budget, gave up, and quarantined the device rather than
        // respawning for ever. {} lifecycle transitions were recorded and
        // every one of them followed the last, so the states join up end to
        // end rather than merely each being plausible. Every record carries a
        // live 128-bit cause from this boot's epoch; ring bounded at {} (8
        // dropped at the source, reported by one meta-event)
        kprintln!(
            "device-events: OK — {} rec ({} grant/{} revoke/{} dma/{} reclaim); dev {} x{}; ladder {}/{}/{}/{}/{}/{}/{}/{}/{} cap {}",
            summary.records,
            summary.mapped,
            summary.revoked_on_transfer,
            summary.dma_granted,
            summary.reclaimed,
            device_obj.raw(),
            summary.grants_of(device_obj.raw()),
            ladder.crashed,
            ladder.crash_dump_records,
            ladder.degraded_marks,
            ladder.dependents_notified,
            ladder.resets,
            ladder.restarted,
            ladder.reclaimed_frames,
            ladder.gave_up,
            ladder.transitions,
            CAP
        );
    } else {
        kprintln!(
            "device-events: FAIL env n={n} dropped={dropped_during_boot} rec={} ok={} ts={} corr={} epoch={} thread={} kind={} wire={envelope_ok}",
            summary.records,
            summary.envelope_ok,
            summary.no_timestamp,
            summary.no_correlation,
            summary.wrong_epoch,
            summary.no_thread,
            summary.envelope_offender,
        );
        kprintln!(
            "device-events: FAIL grants mapped={} revoked={} dma={} reclaimed={} of_dev={} unmap_err={} unmatched={} overflow={} lost={} irq={} bound={bound_ok}",
            summary.mapped,
            summary.revoked_on_transfer,
            summary.dma_granted,
            summary.reclaimed,
            summary.grants_of(device_obj.raw()),
            summary.unmap_errors,
            summary.unmatched_revokes,
            summary.grant_overflow,
            summary.reclaim_lost,
            summary.irq_revoked,
        );
        kprintln!(
            "device-events: FAIL ladder crashed={} want={expected_crashes} restarted={} gave_up={} frames={} comp={} sev={} stamped={}",
            ladder.crashed,
            ladder.restarted,
            ladder.gave_up,
            ladder.reclaimed_frames,
            ladder.component_ok,
            ladder.severities_ok,
            ladder.stamped_ok,
        );
        kprintln!(
            "device-events: FAIL ladder degraded={} dumps={}/{} told={}/{} resets={}/{} quarantined={} trans={}/{}",
            ladder.degraded_marks,
            ladder.crash_dumps,
            ladder.crash_dump_records,
            ladder.dependents_notified,
            ladder.dependents_unreachable,
            ladder.resets,
            ladder.resets_failed,
            ladder.quarantined,
            ladder.transitions,
            ladder.transition_gaps,
        );
        return false;
    }
    true
}

/// **Step 7 of the restart ladder: the binding is restored or disabled based
/// on failure policy** — applied, and then checked to have been applied.
///
/// Everything before this is the supervisor deciding it has tried enough; this
/// is the system deciding what that means for the device. The four outcomes
/// are `docs/drivers/01`'s closing sentence — *"repeated crashes can trigger
/// rollback, fallback drivers, or device quarantine"* — and which one applies
/// is read from a policy rather than being whatever the give-up path happens
/// to do.
///
/// The policy quarantines at the self-test's own budget rather than at the
/// shared default's threshold, because "the budget is spent" is exactly when
/// this supervisor has decided — and a threshold above the budget could never
/// reach the rung the check exists to demonstrate. The other rungs are
/// host-tested in `kcore::supervise`, including the fallback this tree cannot
/// exercise on hardware while there is one driver image per class.
///
/// Here rather than in a port because none of it is architectural: it is the
/// shared supervisor's policy, the shared graph's quarantine, and the shared
/// lifecycle's closing record. Two ports deciding it separately is two ports
/// that can end the same ladder differently.
///
/// Returns whether the device was quarantined, which the port needs to hand
/// back to [`driver_giveup_verdict`] after its own teardown.
pub fn apply_giveup_policy<C: tessera_karch::ContextOps>(
    exec: &mut kcore::exec::Executive<C>,
    device_obj: ObjectId,
    outcome: &kcore::supervise::RestartOutcome,
) -> bool {
    let policy = kcore::supervise::FailurePolicy {
        quarantine_after: Some(u64::from(DRIVER_RESTART_SELFTEST_BUDGET)),
        ..kcore::supervise::FailurePolicy::DEFAULT
    };
    let action = policy.after(outcome.faults);
    let quarantined = matches!(action, kcore::supervise::FailureAction::Quarantine);
    if quarantined {
        exec.quarantine_device(device_obj, outcome.faults, action as u64);
    }
    // The device's lifecycle ends where the policy put it. The manager is not
    // the one declaring this: it never held the device again — that is what
    // quarantine means — so the kernel closes the record for it. A lifecycle
    // that simply stopped mid-ladder would leave the last thing anyone knows
    // about this device being that its driver crashed.
    let _ = exec.declare_lifecycle(
        device_obj,
        kcore::lifecycle::DriverState::Degraded,
        kcore::lifecycle::DriverState::Failed,
        kcore::lifecycle::TransitionReason::BudgetExhausted,
        outcome.faults,
    );
    quarantined
}

/// The give-up rung's verdict: the ladder stopped where the budget said, and
/// the policy it ended on was carried out.
///
/// Exactly the budget, no more — the loop was stopped by the policy and not by
/// its own runaway guard, and every launch died. And the quarantine is read
/// back from the graph rather than assumed, because a quarantine that was
/// decided and not applied looks exactly like one that was never decided: the
/// device is simply never offered again either way, and only the graph can
/// tell them apart.
pub fn driver_giveup_verdict<C: tessera_karch::ContextOps>(
    exec: Option<&kcore::exec::Executive<C>>,
    device_obj: ObjectId,
    outcome: &kcore::supervise::RestartOutcome,
    quarantined: bool,
    fail_counts: u32,
    fail_quarantine: u32,
) -> Result<(), u32> {
    if outcome.launches != u64::from(DRIVER_RESTART_SELFTEST_BUDGET)
        || outcome.faults != outcome.launches
        || !outcome.gave_up
    {
        return Err(fail_counts);
    }
    if quarantined != exec.is_some_and(|exec| exec.is_quarantined(device_obj)) {
        return Err(fail_quarantine);
    }
    Ok(())
}
