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
   `1u64 << Cpu::cpu_id()` in `kernel/kernel/src/main.rs` was that confusion
   already written into the tree, and Phase 2 removed it.

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

**Revised by what happened.** Only the per-CPU half became a type. The machine
half is over 400 KiB, and an unoptimized build — which is what this tree builds,
kernel included — materializes a nested aggregate initializer in a temporary
before copying it into place. Two of those do not fit: it overflowed the host
tests and then hung the AArch64 kernel at 28 lines of boot. A `const`
constructor avoids the temporary by putting the whole structure in the image,
measured at +428 KiB, which is a worse trade. So `Executive` holds a `CpuLocal`
and keeps the machine-wide tables flat, where each table's constructor writes
straight into its own field. That is the half Phase 3 needs anyway: a second CPU
adds a `CpuLocal`, and what remains of `Executive` *is* the machine. The machine
half becomes a type when it is small enough to be one.

**Naming a thread.** The global tables name threads by a *per-CPU scheduler
slot*. `ThreadId` exists on `Thread` and is not what they key by. Re-key them to
`ThreadId` and add the neutral resolution back to a `(cpu, slot)` pair. Doing
this here, as a refactor with existing tests, is the difference between an
afternoon and a silent wrong-thread bug under load.

**Revised: `ThreadId` was not a key.** The plan assumed the identity existed and
only the tables needed pointing at it. It did not. Every caller passed a
hand-picked constant — `ThreadId(1)` named four different threads across the
tree, `ThreadId(0x_d217_e021)` two, and one port's threads were named after
their kernel-stack addresses. That is a debugging label, and a label with
duplicates cannot key anything. So 1d splits in two: the scheduler that admits a
thread now mints its identity, as a CPU index above a per-CPU sequence, so two
CPUs cannot collide and neither has to ask the other. Re-keying follows,
against an identity that is now worth keying on.

**And the surface was wider than three fields.** Seven pieces of machine-wide
state named a thread by a scheduler slot, not three: `sleeper`,
`expired_callers`, the faulter of a page-in, the waiters inside `waits`, a
port's blocked drainer, an endpoint's blocked receiver and pending caller, and a
job's members. All seven now hold a `ThreadId`, and every crossing back to a
slot is an explicit `index_of`. That call returning `None` is the point rather
than an inconvenience: a thread that has exited is noticed, where a remembered
slot would have named whichever thread was admitted into it next. The job case
is the one that mattered most — acting on the wrong thread there means killing
it.

**Interrupt-safe locking.** `kcore::sync::SpinLock` masks this CPU's
interrupts for the critical section, and restores exactly the state it found.
Its header used to promise this "with the interrupt milestone"; interrupts
arrived in D84 and it did not, leaving every caller relying on hand-audited
reasoning about which locks an interrupt path could reach.

Masking is two architecture instructions and these locks live in `static`s, so
the type cannot be generic over the porting layer — a `static` names a concrete
type and the core does not know which. Boot glue installs the pair, exactly as
it installs the event clock, and the mask/restore is written once in the core
rather than five times in the ports. Acquisitions before installation are
**counted**, and the installation sits ahead of the first lock of any kind — the
console's own — so the count is zero and a non-zero one is a real finding rather
than a known-benign boot window.

That leaves one of the two `try_lock` miscalibrations from the survey. The
other, the event clock, is not fixed but **deleted**: a read-mostly function
pointer written once at boot does not need a lock, and the lock was worse than
redundant, because the panic path renders a timestamp from it and a fault taken
inside the critical section would have deadlocked the report explaining the
fault. `try_lock` avoided that by dropping the timestamp silently, and would
have dropped it for ordinary contention under SMP as well. An atomic load has
neither failure mode.

## Phase 1 outcome

Phase 1 is complete, and three of its five items came out differently from the
plan. The machine half of the executive stayed flat, because naming it as a type
overflowed a stack (1c). `ThreadId` had to be *made* an identity before anything
could be keyed by it, and the surface needing re-keying was seven pieces of
state rather than three (1d). And interrupt-safe locking turned out to be half a
deletion. The neutral substrate is in place: per-CPU storage, a CPU-tagged
identity, machine-wide state that names threads by it, and locks that are safe
against the interrupt path they share a CPU with.

## Phase 2 — Architecture-Dependent Work

New porting-layer traits, each of them mechanism only. The two ports are
independent workstreams and can run concurrently.

| Trait | x86-64 | AArch64 |
|---|---|---|
| `CpuLocal::{install, index}` — **done** | `GS` base — extend the existing per-CPU block | `TPIDR_EL1` |
| `CpuOps::hw_id` — **done** | Local-controller id, from CPUID | `MPIDR_EL1` affinity, all fields |
| `CpuBringUp::start(hw_id, index)` — **done** | Boot-protocol per-CPU entry, release-stored | PSCI `CPU_ON`, method read from the device tree |
| `Ipi::{send, send_all_but_self}` — **done** | Interrupt command register, one vector per reason | Software-generated interrupt, one id per reason |
| `TimerControl::start_periodic_this_cpu` — **done** | Local timer or deadline mode | Generic timer's per-CPU private interrupt |
| `AddressSpaceOps::invalidate_local` and `const INVALIDATE_IS_BROADCAST` — **done** | `invlpg`, **false** | `tlbi ...is` with barriers, **true** |

**Revised by what happened: `CpuIdentity` is not a trait.** It was going to be
one, alongside `CpuLocal`, on the reasoning that a port unable to answer should
not be made to fake an answer — the same reasoning that keeps `UserContextOps`
separate from `ContextOps`. That reasoning does not apply here. Every one of the
five ports already had this method, under the name `CpuOps::cpu_id`, so a
separate trait would have been a bound no port could fail to satisfy. What the
five implementations did *not* have was one meaning: it returned the assigned
dense index on x86-64, `MPIDR` Aff0 on AArch64 and ARM 32, and the firmware's
hart id on both RISC-V ports. Three different questions behind one name, and the
name is what made `1u64 << Cpu::cpu_id()` look correct.

So the method was replaced rather than joined: `CpuOps::hw_id() -> u64`, the
hardware's own number and nothing else. The width is not future-proofing —
AArch64 fills 40 bits of it, and the old `u32` fit only because every port had
truncated to whatever field happened to be dense on the machines it had been run
on. The dense index is now reached exactly one way, through
`kcore::percpu::current_index`, and the 49 sites in `kernel/kernel/src/main.rs`
that shifted or activated by `cpu_id` call that instead.

x86-64 changed behaviour, not just names: it reads its local-controller id from
CPUID (the topology leaf where present, the initial 8-bit id otherwise) rather
than returning the index out of its own `GS` block. On a machine with one CPU
both are zero, so the read is unverifiable by itself — which is why
`smp::survey` now takes the platform's id for the boot CPU *as well as* the
CPU's own and reports whether they agree, as the claim `smp.boot_id`. AArch64
passes `None` there for now: the device tree carries each CPU's affinity in its
`cpu` node's `reg`, but reading it is only worth doing where the id names a CPU
other than the one asking, which is `CPU_ON`'s problem and arrives with it.

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

**What bring-up landed, and where it stopped.** AArch64 starts every CPU the
device tree lists: the conduit and the `CPU_ON` identifier are read from
`/psci`, each CPU's identifier from its `cpu` node's `reg`, and the entry stub
is the boot stub with the three things a second CPU must not do removed — it
does not normalize its exception level (firmware started it where the caller
already was), does not build page tables, and does not clear `.bss`. It comes up
on the coarse boot tables because those are the only ones reachable with
translation off, adopts the kernel's real roots once it is in the high half
where a `static` is legible, takes its vector base and its index, and halts.

**They arrive and stop there, and that is the increment.** Nothing dispatches to
them. What it establishes is the sentence Phase 3 needs to be able to assume:
every CPU on the machine is executing this kernel's code, on this kernel's page
tables, with an index of its own. `kcore::smp::start_secondaries` is the neutral
driver — it assigns the dense indices, skips the boot CPU by identifier, starts
one CPU at a time and waits for each, and reports; Phase 3 said that driver was
its own, and it arrived here because a mechanism nothing calls is a mechanism
nothing checks.

**An arriving CPU touches one atomic and nothing else.** The registry is a
`PerCpu` array behind one `UnsafeCell` whose mutable path requires that no other
reference into the array is live — an obligation two CPUs cannot keep by
convention. So a secondary sets one bit in an arrival bitmap, and the boot CPU,
which remains the registry's only writer, records the arrival once it sees the
bit. This is the first place in the tree where Phase 4's problem is real rather
than pending, and it is answered by keeping the second CPU out of the data
structure rather than by arguing that the race is unlikely.

**Two things the work turned up.**

- **A stack is not a byte array.** The per-CPU stacks were `[[u8; N]; MAX_CPUS]`,
  which is byte-aligned, and the entry stub loaded a stack pointer four bytes
  off. It cost nothing visible: `SCTLR_EL1.SA` is clear in this port's boot
  value, so the misaligned pointer was permitted, and the CPU simply never
  arrived. The fix is a `repr(align(16))` wrapper; the lesson is that the type
  that makes a stack a stack is its alignment, and nothing else in the
  declaration says so.
- **`-smp 16` does not boot, and did not before this.** Above eight CPUs QEMU's
  `virt` machine supplies a GICv3, whose CPU interface is system registers
  rather than the MMIO block this port's GICv2 driver writes; the boot CPU takes
  a data abort in GIC init. Identical at the commit before this one. The gate
  pins `gic-version=2`, so the ceiling this port really has is eight, which is
  also `MAX_CPUS` — a coincidence worth not relying on.

**x86-64's half, and why its mechanism is not a firmware call.** The
bootloader's per-CPU entry pointer is a one-shot — writing it is what took the
core out of the wait loop, and by the time the kernel wants to *start* a CPU
that core left long ago. So the release is the kernel's own: a store to a cell
the core is already spinning on, in memory the kernel owns, needing no firmware
at all. That is the whole of the difference from AArch64, where an unstarted CPU
may be powered down and only firmware can wake it, and it is why the trait says
"start hardware id X as index I" and nothing about how.

The parking stub grew a third stage. A core claims a slot with one atomic
increment on arrival — arrival order, because sparse identifiers cannot index an
array, which is the same reason the kernel's index is assigned — takes a stack
at that slot once it is on the kernel's tables, and calls into Rust. There it
publishes the local-controller id it reads for itself, waits on a cell of its
own, and on release takes its descriptor tables and per-CPU block, reports what
it loaded, announces itself, and halts. The bootloader's list of identifiers is
kept separately, captured before its memory is reclaimed: two statements of the
same set, and a start request that matches nothing says so rather than starting
whichever core was first.

**Per-CPU GDT/TSS landed with it, because nothing else needed it.** A task-state
segment holds a CPU's privileged stack pointer and its interrupt-stack-table
entries, so two CPUs sharing one take faults onto the same stack and the report
that comes out describes neither. The GDT follows because the TSS descriptor
lives in it. The IDT stays shared: written once, read-only after, identical on
every CPU, and the IST *slot numbers* its gates carry resolve through whichever
task-state segment the reading CPU loaded — which is already the per-CPU part.

**Arrival does not prove the tables are distinct, so that is checked
separately.** A CPU that loaded a bad descriptor triple-faults before it can
report anything, so arriving proves each CPU has *a* table; it says nothing
about whether two loaded the same one, which is exactly the state this port was
in beforehand. Each arriving CPU reads its descriptor-table base back out of the
hardware and the boot CPU compares them, including its own — `claim
smp.own-tables`. Inverted by pinning every CPU to slot zero, which is the
pre-change behaviour and which the check names in as many words.

**One number is duplicated on purpose.** `CPU_TABLE_SLOTS` in the port and
`MAX_CPUS` in `config/kernel.config` are declared separately because the porting
layer reading kernel configuration would invert the dependency the crate exists
to keep pointing one way. The boot glue is the one crate that sees both and
asserts the relationship at compile time, so a configuration that outgrew the
port fails to build rather than producing a CPU with no task-state segment.

**Per-CPU hardware state** (done on x86-64, see above). On x86-64 the descriptor
table and task-state segment must become per-CPU: each CPU needs its own privileged stack pointer
and its own interrupt-stack-table entries, and therefore its own descriptor
table to hold the segment. The **interrupt descriptor table stays shared** — it
is read-only after init, and replicating it out of symmetry is a cost with no
purchase. On AArch64 the vector base is likewise shared; per-CPU are the
privileged stack, the identity register, and the stacks themselves. The
per-thread half of this is already known (D81) and does not change here.

**The IPI, and the third name of a CPU.** A CPU is named three ways on one
machine and no two agree: the identifier the hardware reports for itself, the
dense index the kernel assigns, and a bit position in the interrupt
controller's own numbering. The third is the one a targeted send needs, and a
CPU can only learn its own by reading a register that answers differently
depending on who reads it. So each CPU records its bit on the way up, and the
GIC module turns the kernel's index into the controller's when something is
sent. `IpiReason` maps to an interrupt id rather than to a payload, because the
controller has ids to spare and making every recipient read shared state to
find out what it was woken for — with interrupts masked — re-asks a question
the controller already answered.

The distributor/CPU-interface split fell out of it. Those registers are banked:
the address is the same on every CPU and the register behind it is not, so the
boot CPU cannot enable anyone else's interface, and a CPU whose interface was
never enabled takes no interrupt and reports nothing about it. Each arriving CPU
now enables its own, records its bit, enables the one id this kernel sends, and
only then unmasks — which is the difference between a CPU that is parked and one
that is merely idle.

**Two claims, and the reason they are named the way they are.** A targeted send
and a broadcast are different register writes with different addressing, so
`smp.ipi-targeted` and `smp.ipi-broadcast` are asserted separately; inverting the
index-to-bit translation fails the first and leaves the second passing, which is
what proves they are separable. The names are also deliberately not prefixes of
each other: a boot check matches a claim as a *substring*, and the first version
of this used `smp.ipi`, which the line announcing `smp.ipi-broadcast` satisfied.
The check passed with the targeted send aimed at the wrong CPU — the exact defect
it exists to catch — and only stopped passing once the names could be told apart.

**The invalidate, and the constant that deletes a shootdown.** Every port
already invalidated inside its own `map`/`unmap`/`protect`; what it lacked was a
name the neutral layer could call and a statement of how far the call reaches.
Both now exist, and each port's three call sites go through the trait method —
otherwise the constant would describe a function nothing runs. `kcore::vm`'s
`invalidate` returns the CPUs still holding a stale entry, which is the whole of
what a shootdown has left to do; on AArch64 it is always empty and the caller's
cross-CPU half is a branch on a `const`, which the optimizer removes.

**AArch64 is the only `true` in the tree, and ARM 32 is not.** `TLBIALL` is the
local form and the inner-shareable one is a different coprocessor operation;
this port issues the local one. The two Arm ports share a device tree, a generic
timer and an interrupt controller, and they do not share this — which is why the
answer is a per-port constant rather than a family-wide assumption.

**A constant asserted against itself proves nothing**, so the boot asks another
CPU. The probe maps a page to one frame and has a secondary read it, which is
what puts the translation in *that* CPU's TLB; remaps to a second frame,
invalidating only on the boot CPU; and asks the same CPU again. Seeing the
second frame means the invalidate reached it. Dropping the `is` from the
instruction fails this and nothing else, and QEMU models the shareability domain
faithfully enough for that to be a real result rather than an emulator artefact.

**The first version of the probe was broken, and four CPUs found it.** It woke
every other CPU with a broadcast, and the boot CPU learns only that *a* CPU
answered — it then unmapped the probe page while a slower CPU was still inside
the handler, which faulted at the probe address on a CPU nobody was waiting for.
A targeted send has exactly one reader, and waiting for its answer is waiting
for all of them. The general lesson is worth more than the fix: a broadcast IPI
has no completion, so anything the sender tears down afterwards needs a
different mechanism to know when the receivers are done.

**The tick was already per-CPU on four ports; the fifth is what hid it.** Every
port's tick source is part of the core — a generic timer, a supervisor timer, a
local APIC timer — and only x86-64's was a device for the whole machine. That
one exception was enough to make `start_periodic` read as a sentence about the
machine, and the counter behind it a single number. Both are per-CPU now, in
name and in storage, and the check is the discriminating one: a machine-wide
count advances on the boot CPU's tick alone, so a secondary whose timer never
started would look exactly like one whose did. `claim smp.tick-per-cpu` fails
when a secondary's timer interrupt is left disabled, and nothing else does.

**Only the boot CPU runs the tick hook, for now.** Every CPU ticks and counts
its own, but the hook drives the one scheduler this kernel has, and a CPU with
no run queue has nothing to preempt. The guard sits in each port's dispatcher
with that sentence on it, and Phase 3 removes it by giving every CPU something
to preempt.

**Interrupt controllers — x86-64 done, and it was D87.** The local controller
landed here, which is what put **D87 on the SMP critical path**: inter-processor
interrupts need its command register and a per-CPU tick needs its timer, and the
legacy pair could supply neither. That is worth stating precisely: the 8259 has
no register naming a destination CPU, so the question SMP is made of is one it
cannot express — the swap was the precondition for the kernel above it, not an
improvement to the path below.

The port now runs the local APIC in **x2APIC mode** (registers as MSRs), device
lines through the **I/O APIC**, and the tick on the **local APIC timer**,
calibrated against the **HPET** — which is the reference D87's own text names
for the case where TSC-deadline is absent, and it is absent under the emulator
this tree checks on. The 8259 pair is masked once at boot and never written
again. x2APIC is *required*, not preferred: a CPU without it fails the boot with
a named reason rather than falling back, and the smoke invocation names
`+x2apic` the way the AArch64 one names `gic-version=2`, so the requirement is
visible in the command line instead of hidden in a default.

The vector block did not move: 32 is still the tick and 32 + line is still a
device line, so the dispatcher and every caller are unchanged. What changed is
that the mapping is now this kernel's own choice, programmed into a redirection
table, rather than a controller's remapping it inherited. Two vectors at the top
of the block became the IPI and the spurious vector — inside the block because
the trampoline table covers exactly those forty-eight, and because the legacy
lines they would otherwise be are ones this port does not route.

**The unclaimed-interrupt count went from seven to zero.** The legacy path was
delivering interrupts nothing owned on every boot, counted and reported and
never chased. Nothing in this change was aimed at that; it is what the count was
for.

**What D87 still holds:** the BIOS half. `kernel/image` still builds a
BIOS-bootable ISO and the UEFI path is still the untested one. That is
independent of SMP and of everything above, and it is what remains of the
deviation. On AArch64 the existing single `init` splits into a distributor half (once,
on the boot CPU) and a CPU-interface half (on every CPU, because those
registers are banked), the target register is programmed, software-generated
interrupts are added for the IPI, and each CPU enables its own timer interrupt
— the boot CPU cannot do that for anyone else, because that register is banked
below the shared-peripheral range.

## Phase 2 outcome

Every row of the table above is done on both ports. What the kernel can now do
that it could not: name a CPU three ways and convert between them, start every
CPU the machine has and know when each arrived, give each its own privileged
tables and its own tick, interrupt one or all of them, and say how far an
invalidate reaches. What it still does not do is *use* any of it — the started
CPUs halt, nothing dispatches to them, and `smp.single` still holds. That
sentence is Phase 3's whole subject.

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

  **Done — and the scheduler lives on the CPU's own stack.** Not in a static
  array indexed by CPU, which is what every other per-CPU structure here does,
  because this one does not have to be: the runner never returns, so the
  scheduler's lifetime is the CPU's, and a local on a stack no other CPU can
  name is unreachable by construction rather than by convention. `PerCpu`'s
  borrowing obligation — the one the arrival bitmap exists to avoid needing —
  does not arise at all.

  One word per CPU is published: a pointer to that scheduler, written by that
  CPU and dereferenced only by it, because a kernel thread that wants to exit
  holds no reference to whatever dispatched it. That is the entire shared
  surface.

  **The boot CPU builds the thread and hands it over.** It owns the address
  space and the frame allocator, so it is the only CPU that can build one at
  all; a secondary's first thread therefore arrives rather than being created
  where it runs. The handoff is checked on every pass of the run loop and not
  once, because a secondary reaches its loop as soon as it has a tick — which
  is before the boot CPU has a mapper to build a thread with. A one-shot read
  finds nothing and idles for ever with work waiting; the CPU's own tick is
  what brings it back to look.

  **What a secondary does not do:** channels, ports, page faults, syscalls.
  Those live in machine-wide tables two CPUs would have to take turns over, and
  the turn-taking is the next step. Keeping the first CPU to run scheduled work
  away from all of it is what makes this increment one thing instead of two.

  **`smp.single` is gone.** It said this kernel dispatches to one CPU, which is
  what D8 declared, and it stopped being true here. What replaces it is
  `smp.all-online`, asserted after bring-up rather than at the survey, because
  how many CPUs a kernel runs work on is not something the survey can know — it
  runs before any of them are started. `smp.second-cpu-runs` and
  `smp.all-online` are separate claims: a machine where one of four CPUs failed
  to start earns the first and not the second, and that difference is the whole
  of what D8 was about.
- **Cross-core wakeup** is a lock-free per-CPU mailbox plus a reschedule IPI,
  sent only when the target may be idle or running lower-priority work. This is
  D17's exit, and D17 already records that the remote path is additive.

  **Done — `kcore::wakeup`.** The mailbox is a **bitmap**, not a queue, and the
  reasoning is worth keeping: a wakeup carries no information beyond which
  thread, it is idempotent, and it has no useful order, because the CPU
  receiving it is about to consult its own run queue anyway. Those three facts
  make the right structure a set, and a set of small integers is a bitmap.
  A queue would need a compare-and-swap to reserve a slot, a published-marker
  per slot so the consumer cannot read a reserved-but-unwritten one, and a
  policy for full — three problems a bitmap does not have. Setting a bit is one
  `fetch_or`, taking every bit is one `swap`; neither can fail, and duplicates
  collapse on their own. It is also what makes the module the same code on all
  five ports: `kcore::atomic::AtomicU64` offers no compare-and-swap, because on
  a 32-bit target it is a pair of words and cannot.

  **The bit is the message; the interrupt is only a prompt to look.** They are
  posted in that order, so a target that misses the interrupt still finds the
  bit, and a target already about to look needs no interrupt at all. The
  inversion is what shows the two are separable: stopping the target from
  draining leaves every IPI claim passing and fails `smp.wakeup-crosses` alone.
  A check that had asserted only "the interrupt arrived" would have passed on a
  kernel that delivered no wakeups.
- **TLB shootdown** is the clearest instance of the boundary rule. On AArch64
  it compiles to the existing local sequence and **no IPI at all**: the
  broadcast invalidate followed by its barrier completes on every processing
  element, which covers both translation correctness and safe frame reuse. On
  x86-64 it walks the active-core mask and sends IPIs.

  **Done, and the mask was worse than the plan assumed.** The plan expected to
  make it real by setting it on activate and clearing it on switch-away. For the
  *kernel* space that is unachievable by construction: a CPU joins the mask by
  calling `AddressSpace::activate`, and a secondary adopts the kernel tables in
  its entry stub, before any such object exists. So the mask named the boot CPU
  and no other — it **under**-reported, which loses a shootdown rather than
  wasting one. A space every CPU runs on is now marked as such and its target
  set is the online CPUs, which is exact and needs no bookkeeping that can fall
  behind. Other spaces still use the mask, which over-reports.

  **A generation, not a queue of addresses.** A requester takes the next number
  and interrupts its targets; each target drops every translation it has and
  publishes the number it reached; the requester waits until every target's is
  at least its own. A per-address queue would need a bound, an overflow policy,
  and a decision about what a target does on overflow — whose only correct
  answer is to drop everything anyway. Starting from the answer the overflow
  path needs gives the mechanism one behaviour instead of two. It also makes a
  late target harmless: a CPU that services two requests as one satisfies both,
  correctly, because the flush it performed covers both.

  **`TlbShootdown` is its own interrupt id**, not a flag inside the reschedule.
  A reschedule is advisory — a target that coalesces or notices late loses
  nothing — while this one has a sender blocked on its completion and a
  correctness argument resting on the answer. Two obligations that different do
  not belong behind one interrupt.

  On x86-64 the flush is a `CR3` reload with `CR4.PGE` cleared across it, and
  the `PGE` part is not decoration: the kernel's own pages are mapped global so
  they survive an address-space switch, and a plain reload would leave exactly
  the kernel mapping a kernel-range shootdown is about. Asserted by `claim
  smp.shootdown`; telling nobody leaves the other CPU reading the old frame,
  which is what shows the emulator models per-CPU translation caching here too.
  AArch64 has no counterpart claim because its set is empty by construction —
  `smp.invalidate-reaches` already shows the invalidate arriving without one.
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
