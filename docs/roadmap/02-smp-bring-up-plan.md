<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# SMP Bring-Up Plan

## Purpose

`../kernel/08-multicore-scalability.md` states what a multicore kernel must
be. This document states how this tree gets there, for x86-64 and AArch64,
and — the part that decides whether the work is reusable — where the line
between architecture-dependent and architecture-independent code falls.

It exists because SMP is the one remaining prerequisite of a gate that has
already been declared. `01-sequencing-and-mvp.md` records that Stage 0's exit
depends on budgets B5 and B24, both of them cross-core, and that the kernel is
single-core by D8 — so R1 compliance is gated on multicore support rather than
on procurement. SMP is therefore a Stage-0 debt being paid in Stage 1, and it
appears in no stage's scope list. This document is that scope list.

## The Boundary Rule

Two sentences decide every split below. Everything else follows from them.

1. **A porting-layer trait expresses a mechanism the hardware provides; the
   kernel core owns the policy about when to use it.** "Send an interrupt to
   CPU 3" is architecture. "Which CPUs need one, and when the operation is
   complete" is not.
2. **The kernel core never sees a hardware CPU identifier.** It sees a dense
   index in `0..cpu_count` that the bring-up layer assigns. Affinity fields and
   local-interrupt-controller ids are sparse and architecture-shaped;
   `1u64 << Cpu::cpu_id()` in `kernel/kernel/src/main.rs` is that confusion
   already written into the tree.

A third rule earns its keep on AArch64 specifically: **where the hardware
already does the neutral layer's job, the neutral layer must be able to
compile to nothing.** AArch64 broadcasts TLB invalidation to the whole
inner-shareable domain; x86-64 has no broadcast invalidate and needs an
inter-processor interrupt. That difference belongs in an associated constant
the optimizer can fold, not a runtime branch on every unmap.

## Where The Tree Stands

Nothing multicore is built. What exists is a set of seams — structures shaped
so that cores can be added without redesign — and they are in mixed repair:

- **Sound.** `Scheduler` and `RunQueue` take no lock and are `&mut self`-shaped,
  so adding cores adds instances. `HandleTable` is per-process with a genuinely
  shared-write-free lookup. AArch64's page tables are already inner-shareable
  and its invalidate is already the broadcast form with the full barrier
  bracket.
- **Decayed.** `AddressSpace::active_core_mask` has no reader, is never
  cleared, and is populated by one port of five — the other four bypass
  `AddressSpace::activate` and call the architecture's own `activate` directly.
  An unverified seam decays; this is what that looks like.
- **Absent.** Secondary-CPU startup, inter-processor interrupts, CPU topology
  discovery, epoch reclamation, per-CPU storage on any port but x86-64, and a
  local interrupt controller on x86-64 at all.

No boot script passes `-smp`. Every gate in the tree runs one virtual CPU, so
none of the above is a regression anything could have caught.

## Phase 0 — Enforce Single-Core, And Acquire A Harness

No SMP code. The goal is to turn "single-core by assumption" into "single-core
by enforcement", and to acquire the test surface every later phase needs.

- Pass `-smp 2` on one x86-64 and one AArch64 boot script. Both firmwares park
  secondaries until asked (a bootloader until its per-CPU entry is written,
  `virt` until PSCI `CPU_ON`), so nothing starts — but the machine changes
  shape, and that is the point.
- **This exposes a live defect on AArch64 immediately.** `GICD_ITARGETSR` is
  RAZ/WI in a uniprocessor GIC and becomes a real, zero-reset register the
  moment the distributor has more than one CPU interface. The GIC driver never
  programs it, so under `-smp 2` every shared peripheral interrupt targets no
  CPU and delivery stops. The fix is small; finding it before bring-up is worth
  the phase on its own.
- Carry `cpu_count` in `BootInfo`, normalized by boot glue from the boot
  protocol on x86-64 and from the device tree's `/cpus` on AArch64. The
  device-tree crate parses nothing about CPUs today.
- Emit the structured event naming how many CPUs are present and how many are
  online. A kernel that declines to start three of four says so, per
  `../lifecycle/04-coding-guidelines.md` ("No Silent Fallback").
- Add a ledger row recording "N present, one online, secondaries parked", with
  Phase 3 as its exit criterion.

**Done when** both ports boot green under `-smp 2`, every verdict unchanged,
and the kernel reports what it declined to start.

**Done** (D217). Both defects the phase predicted were real and are fixed. The
GIC target register was one of them; the other was not predicted and is the
more interesting: on x86-64, *asking* the boot protocol how many CPUs there are
starts them, into a wait loop that lives in memory the same protocol reports as
usable. The kernel then built its page tables over an instruction stream another
core was executing. Reading a count turned out to be a write, and the price of
the count is `kernel/kernel/src/secondaries.rs` — every application processor
moved into kernel text before the first frame is allocated, then onto the
kernel's own page-table root once one exists. That is the first half of Phase
2's bring-up stub, arriving early because the count could not be had honestly
without it.

## Phase 1 — The Neutral Substrate

Architecture-independent, host-testable against `karch-mock`, and landing
entirely before any second CPU runs. This is the long pole, and almost none of
it can be wasted: every item is correct and useful on one core.

**Sizing.** `MAX_CPUS` joins `config/kernel.config` as a `size` (default 8,
range 1..=64). The upper bound is a claim about the code, which is what that
file wants: it is where `active_core_mask` stops fitting a `u64`.

**Per-CPU storage.** `kcore::percpu` holds a `MAX_CPUS`-wide array and an
accessor keyed by the architecture's dense index. The payoff is that the
"one accessor, not one per use site" pattern the ports already use is the seam:
rewriting those three accessors to resolve per-CPU leaves several hundred call
sites untouched.

**Splitting the Executive.** `kcore::exec::Executive` holds the per-CPU
scheduler and the machine-global tables in one structure. Replicating it per
CPU forks the global tables; sharing one serializes the scheduler. Neither is
acceptable, so it splits in two:

| Per-CPU (`exec::Cpu`) | Machine-global (`exec::Machine`) |
|---|---|
| `sched` | `channels`, `ports`, `jobs` |
| `sync_depth` | `devices`, `memory` |
| `saved_correlation` | `waits` |
| `next_txn`, tagged with the CPU index | `page_ins`, `expired_callers`, `page_in_supervisor` |
| | `cache_budget`, pager bindings |

Methods take the machine half as a parameter. Behaviour is identical, but the
crate graph changes — so this is proved by diffing the serial log rather than
by byte-identity, and by inverting each split.

**Naming a thread.** The global tables name threads by a *per-CPU scheduler
slot*. `ThreadId` exists on `Thread` and is not what they key by. Re-key them to
`ThreadId` and add the neutral resolution back to a `(cpu, slot)` pair. Doing
this here, as a refactor with existing tests, is the difference between an
afternoon and a silent wrong-thread bug under load.

**Interrupt-safe locking.** `kcore::sync::SpinLock` does not mask interrupts;
its own header promised that upgrade "with the interrupt milestone", which
shipped in D84 without it. Acquisition masks local interrupts and the guard
restores them. This also repairs the two `try_lock` callers whose reasoning —
a failed acquire means this call interrupted the holder — silently becomes
"another core holds it", costing a dropped timestamp in one case and a busted
live lock in the other.

## Phase 2 — Architecture-Dependent Work

New porting-layer traits, each of them mechanism only. The two ports are
independent workstreams and can run concurrently.

| Trait | x86-64 | AArch64 |
|---|---|---|
| `CpuLocal::{install, get, index}` | `GS` base — extend the existing per-CPU block | `TPIDR_EL1` |
| `CpuIdentity::hw_id` | Local-controller id | `MPIDR_EL1` affinity, all fields |
| `CpuBringUp::start(hw_id, index)` | Boot-protocol per-CPU entry, release-stored | PSCI `CPU_ON`, method read from the device tree |
| `Ipi::{send, send_all_but_self}` | Interrupt command register, one vector per reason | Software-generated interrupt, one id per reason |
| `TimerControl::start_periodic_this_cpu` | Local timer or deadline mode | Generic timer's per-CPU private interrupt |
| `AddressSpaceOps::invalidate_local` and `const INVALIDATE_IS_BROADCAST` | `invlpg`, **false** | `tlbi ...is` with barriers, **true** |

**Secondary entry stays inside the port, and the trait carries no entry
address.** This is deliberate. One bootloader hands a secondary a virtual,
already-paged entry under the loader's own tables; PSCI hands a physical
address with the MMU off. Forcing one signature on both would leak one port's
boot protocol into the other. The neutral layer says "start hardware id X as
index I"; the port does whatever that takes and eventually calls the neutral
`secondary_main(index)`.

- On x86-64 the stub loads this kernel's page-table root, its own descriptor
  tables, the shared interrupt descriptor table, and its per-CPU base.
- On AArch64 the stub repeats the boot path's exception-level normalization,
  enables the MMU on the **existing** boot tables — it does not rebuild them
  and does not clear `.bss` — branches to the high half, then takes its
  per-CPU stack and identity register before calling in.

**Per-CPU hardware state.** On x86-64 the descriptor table and task-state
segment must become per-CPU: each CPU needs its own privileged stack pointer
and its own interrupt-stack-table entries, and therefore its own descriptor
table to hold the segment. The **interrupt descriptor table stays shared** — it
is read-only after init, and replicating it out of symmetry is a cost with no
purchase. On AArch64 the vector base is likewise shared; per-CPU are the
privileged stack, the identity register, and the stacks themselves. The
per-thread half of this is already known (D81) and does not change here.

**Interrupt controllers.** On x86-64 the local controller lands here, which
places **D87 on the SMP critical path**: inter-processor interrupts need its
command register and a per-CPU tick needs its timer, and neither exists — the
current timer is the legacy pair, whose own header names SMP as what replaces
it. On AArch64 the existing single `init` splits into a distributor half (once,
on the boot CPU) and a CPU-interface half (on every CPU, because those
registers are banked), the target register is programmed, software-generated
interrupts are added for the IPI, and each CPU enables its own timer interrupt
— the boot CPU cannot do that for anyone else, because that register is banked
below the shared-peripheral range.

## Phase 3 — Running More Than One CPU

Architecture-independent again, consuming Phase 2's mechanisms.

- **`kcore::smp`** enumerates, assigns dense indices, starts CPUs **one at a
  time** with a rendezvous, barriers, and reports. One at a time is the right
  default: it is simpler, and a CPU that never arrives is attributable to
  itself rather than to the batch.
- **`secondary_main`** installs the per-CPU block, starts this CPU's tick, and
  enters its scheduler's idle loop — unmasking interrupts on every iteration,
  because `wfi` returns without taking a masked one.
- **Per-CPU schedulers** fall out of Phase 1 at no additional cost.
- **Cross-core wakeup** is a lock-free per-CPU mailbox plus a reschedule IPI,
  sent only when the target may be idle or running lower-priority work. This is
  D17's exit, and D17 already records that the remote path is additive.
- **TLB shootdown** is the clearest instance of the boundary rule. On AArch64
  it compiles to the existing local sequence and **no IPI at all**: the
  broadcast invalidate followed by its barrier completes on every processing
  element, which covers both translation correctness and safe frame reuse. On
  x86-64 it walks the active-core mask and sends IPIs, batched one per range
  and pending-unmap set rather than one per page. Making the mask real — set on
  activate, **cleared on switch-away**, read by the shootdown, and reached
  through `AddressSpace::activate` on both ports rather than bypassed — is
  D8's exit.
- **Epoch reclamation** is the single mandated facility, and the handle table
  and every read-mostly snapshot ride it. This is D14's exit. It is also the
  piece to defer if the schedule bites: holding the machine-half lock in the
  interim is correct, merely unscalable, and that is a trade worth recording
  rather than rushing.

## Phase 4 — The Debt SMP Invalidates

Routinely underbudgeted, and none of it optional.

- **Thirty-three of the 127 unsafe-inventory justifications cite
  single-threadedness** — "single-threaded boot state", "every thread is
  off-CPU", "one core". Those sentences become false the instant a second CPU
  runs. A quarter of the recorded memory-safety argument must be rewritten or
  the code changed. This is the largest line item in the plan and belongs
  early, not at the end.
- **`karch::atomic::AtomicU64::fetch_add` is not linearizable** where the
  target lacks a 64-bit atomic, and says so, naming D8 as why that is
  tolerable. Neither port here is affected, but the type is neutral and shared.
  The honest fix is to split it by intent: a per-CPU counter that is
  split-safe by construction, and a shared counter that simply does not exist
  on a target that cannot implement it.
- **Wait-on-address** is atomic "only by single-core cooperative execution"
  (D37). It needs a per-bucket lock and physical-frame keying.
- **The event ring is one global lock**, against kernel/08's per-CPU rings.
  That is D57's own stated exit criterion.
- **Counters shard per CPU** with lazy aggregation (D15).

## Phase 5 — Verification

- **Architecture conformance** gains porting-layer cases: per-CPU storage round
  trips, hardware ids are distinct, an IPI reaches its target *and only* its
  target, and the broadcast-invalidate claim actually holds.
- **Boot checks** gain neutral cases: every CPU reaches the barrier; a thread
  woken on one CPU runs on another; an unmap on one is observed on another; a
  channel call crossing cores completes.
- **Each ships with its inversion.** A shootdown check that still passes with
  the shootdown removed is measuring nothing, and this tree has already learned
  that an inversion must discriminate.
- **B5, B24, and B19–B21 become measurable**, closing D36 and removing the last
  blocker on the R1 exit criterion in `01-sequencing-and-mvp.md`.
- **CI** moves both ports to `-smp 4` once green, keeping one single-CPU run so
  that path stays exercised rather than merely still compiling.

## Dependency Order

```text
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 5
              │           │            ▲
              │           └─ D87 (local + I/O interrupt
              │              controllers) is a hard
              │              prerequisite, x86-64 only
              │
              └─ Phase 4 may run in parallel from here;
                 the unsafe re-audit gates Phase 3 landing
```

AArch64 will reach a running secondary before x86-64 does, because PSCI is a
firmware call while x86-64 must first grow an interrupt controller it does not
have.

## Deviations This Closes

D8 (single-core, no shootdown), D14 (single-core handle table, no epoch
facility), D15 (unsharded counts), D17 (no cross-core IPC path), D21 (no
per-CPU syscall stack), D36 (no cross-core or scaling benchmarks), D37 (futex
atomicity by cooperation), D57 (no per-CPU event rings), and D87 (legacy
x86-64 interrupt and timer path). D50 and D61 are narrowed rather than closed —
each names SMP among several remaining items.

`01-sequencing-and-mvp.md` should gain SMP explicitly in Stage 1's scope.
Without it, that stage's "the OS builds itself on itself" exit gate is a
single-core self-host.

## Risks

1. **The Executive split touches every syscall path.** Mitigated by landing it
   pre-SMP, where the serial log is a complete oracle and every path already
   has a test.
2. **The unsafe re-audit is discovered late.** Schedule it as work with an
   owner, not as a review step.
3. **x86-64's missing interrupt controller turns "add SMP" into "add SMP and
   rewrite interrupt delivery".** Budget D87 as its own milestone.
4. **Thread-index-as-name escaping Phase 1.** It becomes a silent wrong-thread
   bug under load, which is a class this tree has already been bitten by more
   than once.
