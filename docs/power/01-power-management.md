<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Power Management And System Sleep

## Purpose

The device-side power design is thorough — the voting model and dependency
graph in `../hardware/03-component-interaction-model.md`, the battery,
charger, thermal, and regulator classes in
`../drivers/04-embedded-buses-power-and-timekeeping.md`, wakeup rate ceilings
in `../kernel/05-jobs-containment-and-resource-control.md`, and thermally
derated admission in `../kernel/07-scheduler-admission-control.md`. What was
missing is the top: the power manager itself was referenced in four documents
but defined in none, there was no system sleep design, no wakeup-source
contract, and no CPU power governing. This document defines them.

## The Power And Thermal Manager

The power and thermal manager is a system service, listed in the service
roster of `../architecture/01-system-architecture.md`. The boundary follows
design principle one:

- The service owns policy: suspend and idle decisions, vote arbitration
  across the power dependency graph, governor parameters, thermal mapping of
  zone readings and trip points to cooling levels, wake-hold grants, and
  charging policy.
- The kernel owns mechanisms whose decision rate is coupled to the scheduler
  and cannot tolerate a service round trip: CPU idle-state entry and
  frequency selection (below), low-level power state transitions needed for
  correctness (`../architecture/02-separation-of-concerns.md`), and the
  final suspend commit.
- Platform sleep is entered through the firmware interfaces declared in the
  platform support package (PSCI, ACPI sleep states;
  `../hardware/01-platform-and-cpu-support.md`); the kernel invokes them,
  the service decides when.

## CPU Power Governing

Frequency and idle selection are kernel-resident mechanisms with
service-set policy parameters.

### Frequency Scaling

- A per-cluster performance controller selects frequency from runqueue
  utilization, updated at scheduler tick and wakeup granularity.
- Admitted reservations set a frequency floor: the sustainable-capacity
  analysis in `../kernel/07-scheduler-admission-control.md` assumes a
  frequency, and the controller may not undershoot it while the reservation
  is active — reserved deadlines never depend on ramp-up latency.
- Thermal capacity ceilings from the thermal manager bound the controller
  from above; interactive wakeups may boost within policy; task energy
  preference hints (`../kernel/02-scheduling-memory-ipc.md`) bias the curve.
- The power manager sets the parameters — boost aggressiveness, energy bias,
  floors and ceilings per profile. The shipped default parameter set is the
  "production governor" that budget compliance is judged under
  (`../prototypes/01-ipc-benchmark-harness.md`).

### Idle Selection

- The idle governor selects a state per core from predicted idle duration
  (next timer including slack batching, recent wakeup history) bounded by
  latency constraints: a core in a domain with admitted reservations may not
  enter a state whose exit latency exceeds the tightest admitted slack.
- Wake-capable interrupt affinity (`../kernel/08-multicore-scalability.md`)
  keeps wake sources on cores whose idle states can honor them.

## System Sleep States

- Suspend-to-idle is the baseline on every profile: user space frozen,
  devices at their lowest vote, cores in deepest permissible idle. It
  requires no firmware support and is the wearable fast-path.
- Platform sleep (firmware-entered suspend) is used where the platform
  support package declares it, entered through PSCI or ACPI after the same
  sequencing.
- Hibernate is not supported in v1 (`../roadmap/01-sequencing-and-mvp.md`
  posture: designed-for, deferred). When a profile enables it, the image
  must be encrypted with hardware-bound keys, measured at resume, and
  respect key-eviction classes — a hibernation image must never contain
  plaintext lock-evicted key material
  (`../security/01-security-model.md` "Physical Access Protection").

## Suspend Entry And Resume

Entry is sequenced, abortable, and race-free:

1. The power manager decides to suspend (policy: user intent, idle timeout,
   lid, profile) and snapshots the system wake-event counter.
2. Active wake holds veto entry; the veto is attributed and logged.
3. Applications and background work are frozen by job suspension, innermost
   jobs first; services flush state per their manifests.
4. Lock-evicted data-class keys are dropped per
   `../security/01-security-model.md` — key eviction strictly precedes any
   state where memory could be extracted.
5. Driver hosts suspend in reverse dependency-graph order (leaves before
   parents), each through its lifecycle states, arming registered wakeup
   sources as they go.
6. Final commit: the kernel compares the wake-event counter against the
   snapshot. If any wake event arrived during entry, the entry aborts and
   resumes cleanly — the lost-wakeup race is closed by counting, not by
   hoping.
7. Cores enter platform sleep or deepest idle.

Resume runs in reverse dependency order. The first structured event of every
resume names the wake source. Suspend entry and resume-to-first-frame are
budgeted (B22, B23 in `../architecture/03-performance-budgets.md`) and each
stage's latency is attributed, so a slow-resuming driver is named, not
guessed.

## Wakeup Sources And Wake Holds

- A wake-capable interrupt object may be registered as a wakeup source by a
  driver host holding the appropriate right; registration is brokered by the
  power manager, so the set of things that can wake the device is explicit,
  auditable, and profile-policed.
- Every wake event increments the system wake-event counter and takes a
  short grace-period wake hold, so an event arriving during suspend entry
  aborts it and an event arriving just after resume is not lost to an
  immediate re-suspend.
- Wake holds are the suspend-blocker equivalent, designed against the
  wakelock lessons: capability-gated objects granted by the power manager,
  time-limited by policy, attributed to a component, and charged against the
  holder's resource-domain wakeup and background ceilings — an abusive
  holder throttles itself, and every grant, hold, and release is an event.
- Kernel-side, a held wake hold simply vetoes final commit; there is no
  polling.
- The kernel operations — the suspend commit, wake-event counter query, wake
  holds, and wakeup-source registration — are listed in
  `../api/01-system-call-interface.md` "Power" and "Device And Interrupt".

## Energy Attribution

The "power estimates" accounting dimension in `../kernel/02` gets its
mechanism:

- Measurement sources in preference order: per-rail telemetry from PMIC and
  fuel-gauge classes, hardware energy counters where the architecture
  provides them, and otherwise model-based estimation — per-state residency
  multiplied by calibrated costs shipped in the platform support package's
  calibration data.
- Attribution rules: CPU energy by weighted runnable time at the frequency
  in effect; device energy to the lease holder; DMA and I/O energy to the
  requesting component through the same attribution as I/O accounting;
  accelerator energy to the submitting security domain per
  `../future/01-ai-and-wearable-era.md`; shared surfaces (display,
  backlight) to the foreground owner per profile policy.
- Attributed energy feeds the accounting dimensions, the battery-drain
  troubleshooting workflow in
  `../observability/01-debugging-monitoring-tracing-logging.md`, and the
  idle-floor regression gate in `../architecture/03-performance-budgets.md`.

## Thermal Emergency Path

Throttling and reservation revocation are policy; the emergency path is not:

- Hard trip points declared by thermal sensor drivers are latched in the
  kernel at binding time. Crossing one triggers kernel-enforced action
  without any service round trip: clamp frequency ceilings, force deep idle,
  and at the final trip, an orderly emergency shutdown.
- Emergency actions emit hardware error records through the platform error
  service and are visible to attestation-relevant posture like any other
  hardware event; the health service uses recurrence for predictive
  mitigation.
- The escalation ladder — throttle (policy) → revoke reservations
  (`../kernel/07`) → clamp (kernel) → shutdown (kernel) — is ordered so that
  the safety floor never depends on a service being alive.

## Observability

Suspend and resume timelines with per-stage attribution, wake-source
registrations and every wake attribution, wake-hold grants, durations, and
vetoes, governor decisions at policy-change granularity, frequency and idle
residency histograms per cluster, energy attribution per component, and
every thermal trip and emergency action are structured events, consistent
with `../observability/01-debugging-monitoring-tracing-logging.md`.
