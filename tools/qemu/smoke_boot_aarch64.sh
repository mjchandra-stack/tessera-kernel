#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 smoke boot, AArch64: boot the Stage 0 kernel under QEMU and require
# both the clean success exit (status 33) AND the alive marker on the serial
# console — the same contract `smoke_boot.sh` enforces for x86-64, reached by
# a different mechanism.
#
# Differences from the x86-64 script, all forced by the machine:
#   * `-kernel` loads the ELF directly; there is no bootloader and no ISO.
#   * The `virt` machine has no port I/O and so no `isa-debug-exit` device.
#     The exit status comes from Arm semihosting instead, which is why
#     `-semihosting-config` is not optional: without it the kernel's exit
#     call traps as an undefined instruction and the boot hangs after
#     succeeding.
#   * `gic-version` is pinned rather than left to QEMU's default, so the
#     interrupt controller the port programs does not change under us
#     between QEMU releases.
#
# `-smp 4` is not incidental. A GICv2 with one CPU interface makes its target
# register read-as-zero/write-ignored and delivers every interrupt to the only
# core there is, so a distributor driver that never wrote that register looked
# correct for as long as the machine had one core — and stopped delivering the
# moment it had two. Booting with more than one is what holds that fixed.
#
# Four rather than two, because two cores make "the other CPU" and "every CPU"
# the same set: a target register written with the wrong bit, or not written at
# all, delivers to the same place either way. Only a third core makes a wrong
# address show up as an interrupt somebody else took, which is what
# `smp.ipi-only-target` below asserts. Every other boot check in this tree
# still runs a single CPU, so nothing here gives up the single-CPU path.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3",
# "CI Topology")

set -u

MARKER='claim boot.alive'
# The data path's declared cost, checked at binding time (D143). Two block
# devices of one class, matched by one manifest entry with one budget, and the
# only difference between the bind and the refusal is how deep each sits — which
# is `docs/drivers/01`'s claim that a class cannot silently miss its budget
# behind a hub. Its own markers, because a manager that stopped accumulating
# would bind everything and report nothing.
RELAY_MARKER='claim relay.ok'
RELAY_BUDGET_MARKER='claim relay.budget-exceeded'
RELAY_THROUGHPUT_MARKER='claim relay.throughput-too-low'
# A hub the kernel cannot identify is not free. The failure this guards against
# is silent by construction: assuming zero would bind the device and look
# entirely healthy.
RELAY_UNDECLARED_MARKER='claim relay.path-undeclared'
# The verified image store (D146). Two markers, because the interesting half of
# a verifier is the half that says no: the first asserts a container mounted
# against the anchor this kernel is compiled to trust, the second that the same
# code refused an altered one — a check with only the first would pass against
# a `mount` that returned success unconditionally.
#
# Matched as claim keys rather than as a phrase out of the verdict's prose:
# the prose is what the kernel says, not what this asserts, and a reworded
# sentence used to break the check silently.
STORE_MARKER='claim store.ok'
STORE_REFUSAL_MARKER='claim store.refused'
# Firmware loading (D148). Four markers, because four of the five claims are
# refusals and a check that only asserted the successful load would pass against
# a policy that had stopped applying: the image measured by the driver itself
# matching the kernel's, an image below the rollback floor refused *while
# measuring perfectly*, one below the manifest entry's requirement refused
# differently, and the driver's own load refused because the right stayed with
# the framework.
FIRMWARE_MARKER='claim firmware.ok'
FIRMWARE_MEASURED_MARKER='claim firmware.measured'
FIRMWARE_ROLLBACK_MARKER='claim firmware.rollback-refused'
FIRMWARE_RIGHT_MARKER='claim firmware.right-required'
# What the machine has against what this kernel starts on it. Three markers,
# because they are separable claims: `smp.single` is D8 — one CPU dispatched to
# — `smp.counted` is that the kernel knows how many CPUs there are, and
# `smp.started` is that every one of the others is running this kernel's code on
# this kernel's page tables. A run asserting only the first would pass on a
# kernel that had stopped counting, which is the state every port was in before
# `-smp 2`; one asserting only the first two would pass on a kernel whose
# firmware call was accepted and whose CPU never arrived, which is what a wrong
# entry address looks like.
SMP_MARKER='claim smp.all-online'
SMP_COUNTED_MARKER='claim smp.counted'
SMP_STARTED_MARKER='claim smp.started'
SMP_RUNS_MARKER='claim smp.second-cpu-runs'
# ...and the last two are that this kernel can interrupt a CPU it started. Two
# markers because a targeted send and a broadcast are different register writes
# with different addressing: the first turns the kernel's dense index into the
# controller's own numbering and the second skips that translation, so a run
# asserting one would pass with the other broken.
#
# Neither name is a prefix of the other on purpose: a marker is matched as a
# substring, so a `claim smp.ipi` would have been satisfied by the line
# announcing the broadcast — which is how this check first passed with the
# targeted send aimed at the wrong CPU.
SMP_IPI_MARKER='claim smp.ipi-targeted'
SMP_IPI_BROADCAST_MARKER='claim smp.ipi-broadcast'
# ...and that it reached only that CPU. The two above are earned by every named
# CPU taking one, which a send whose target list names everybody also earns —
# on this port that is one bit misplaced in `GICD_SGIR`. This one is earned by
# no CPU taking an interrupt it was not sent, and the kernel withholds it below
# three CPUs rather than making it vacuously.
SMP_IPI_ONLY_MARKER='claim smp.ipi-only-target'
# ...and that no CPU but the boot CPU has reached the kernel executive. Its
# machine-wide tables were unlocked, so the whole of what kept them consistent
# was that one CPU touched them (build/README.md, D230). Both halves of that
# have moved: the tables have a lock (D232), and a secondary now reaches the
# executive on purpose (D236) — so the old `exec.one-cpu` is retired and this
# is its inversion. A new key rather than the old one re-read, because "one
# CPU" and "more than one" are different sentences and an old log must not be
# mistaken for a new kernel's.
EXEC_MULTI_CPU_MARKER='claim exec.multi-cpu'
# ...and that each of those CPUs dispatched out of **the executive's** half for
# its own index, rather than out of a scheduler of its own that the executive
# has never heard of. `smp.second-cpu-runs` above cannot tell the two apart —
# a thread that ran advances the same counter either way — so each CPU
# publishes the scheduler it dispatched from and the boot CPU compares it
# against the half that index owns. A secondary keeping its run queue on its
# own stack fails this and nothing else; so does an `Executive::cpu` that
# ignored its index and handed every CPU the boot CPU's half.
EXEC_SECOND_CPU_MARKER='claim exec.second-cpu-scheduled'
# ...and that a synchronous channel call reached a server on one of them and
# got its answer back. This is the executive's remote-wake path end to end: a
# `call` whose callee is parked on another CPU cannot hand off to it — a
# handoff is a context switch, and a CPU cannot switch to a thread that is not
# on it — so it posts a wakeup and blocks, and the `reply` comes back the same
# way. Before this, both directions read "not in my run queue" as "the thread
# exited" and simply did not wake it (build/README.md, D237).
#
# **The reply arriving is not the finding; it arriving from another CPU is.**
# A round trip completes identically with both ends on one CPU, which is what
# every other IPC check in this tree does, so the check counts the wakeups that
# actually crossed and requires both directions. A kernel that resolved the
# callee locally still passes the round trip and fails this.
EXEC_CROSS_CALL_MARKER='claim exec.cross-cpu-call'
# ...and that the benchmark reported beside it measured the path it names.
# Both halves of B24/B3 run the same code over the same message on the same
# boot; the only difference is where the server is, and nothing in a percentile
# shows that — a "cross-core" benchmark that had quietly run both ends on one
# CPU reports plausible microseconds. So the wakeups that actually crossed are
# counted: two per cross-core round trip, none at all for the same-core pair.
# The timings are printed and never claimed; under QEMU/TCG they are the
# emulator's scheduling (build/README.md, D34/D56), and what is claimed here is
# the shape of the work, which the emulator does not change.
PERF_CROSS_CALL_MARKER='claim perf.cross-call-crossed'
# ...and the one-way half, budget B5: a thread parked on a port on one CPU,
# signalled from another. Exactly one crossing per notification, and here that
# really is invariant — the sender waits for the waiter to be registered before
# it signals, so `port_signal` always finds a drainer and that drainer is
# always somewhere else. Without the wait a port simply coalesces: the signal
# is remembered, the next wait returns from the queue, and the benchmark
# measures a queue read while crossing nothing.
PERF_CROSS_NOTIFY_MARKER='claim perf.cross-notify-crossed'
# ...and that the scaling condition replicated what it says. Every worker must
# have completed every round trip and every fault it was asked for, and not one
# wakeup may have crossed a CPU — an "independent same-core pair" whose server
# had ended up elsewhere would cross on every call and still report a plausible
# efficiency. The efficiency itself is printed and never claimed: under
# QEMU/TCG a wall-clock ratio across vCPU threads is the host's scheduler as
# much as the kernel's (build/README.md, D34/D56). What survives that is the
# machine-lock wait count beside it, which separates the two benchmarks by
# three orders of magnitude on every run.
PERF_SCALING_MARKER='claim perf.scaling-replicated'
# ...and that no thread ever went off-CPU still holding the executive's
# machine-wide tables. Nine of its methods suspend the calling thread inside
# their own borrow, and a hold that survived one of those is a hold nobody
# releases — the deadlock D230 measured, waiting for a second CPU to exist.
# Checked where the scheduler actually parks a thread rather than where the
# release was meant to happen, so a park that was never converted is counted
# instead of assumed away: before the eleven were converted this said 119, and
# un-converting the one in `call` says 47.
EXEC_PARK_MARKER='claim exec.lock-released-at-park'
# ...and that an invalidate performed on one CPU reached another. This is the
# only property in the SMP work a single CPU cannot demonstrate, and the one
# `AddressSpaceOps::INVALIDATE_IS_BROADCAST` asserts — a constant checked
# against itself would prove nothing, so the boot asks another CPU what it can
# still translate. Dropping the `is` from the invalidate fails this and nothing
# else.
SMP_INVALIDATE_MARKER='claim smp.invalidate-reaches'
# ...and that a writer here can know when no other CPU can still be looking at
# something. That is the epoch facility docs/kernel/08 mandates; the grace
# period completes only because each other CPU reaches a point in its own loop
# where it holds nothing and says so.
SMP_GRACE_MARKER='claim smp.grace-period'
# ...and that every unmap and rights narrowing that had another CPU to tell was
# answered by it. Distinct from `smp.shootdown` above, which proves the
# *mechanism* on a page the check maps for itself: this one is about the
# ordinary paths — `kcore::vm`'s unmap, reclaim, teardown and device-window
# revocation — which for most of this tree's life computed a target set nobody
# ever asked them for. **Claimed on both ports**, and it is the failures it
# names rather than the successes: a port whose invalidate broadcasts completes
# none of these and is entirely correct, so "some happened" is not a property
# every port has, while "none went unanswered" is.
VM_SHOOTDOWN_MARKER='claim vm.shootdowns-answered'
# ...and that a thread can be taken off a CPU it never asked to leave. Every
# other secondary check above runs threads that block — a server parks in
# `receive`, a client in `call` — so all of them pass on a kernel that preempts
# nothing at all. Two CPU-bound threads on one secondary do not: the first spins
# waiting to see the second, and the second cannot start until a tick takes the
# first off the CPU. A cooperative kernel leaves the first spinning out its
# whole bound, so it reports 1/2 rather than 2/2 and this marker is absent.
PREEMPT_MARKER='claim smp.secondary-preempted'
# ...and that each started CPU is ticking on a timer of its own. The counter is
# per CPU because the timer is: a machine-wide count advances on the boot CPU's
# tick alone, so a secondary whose timer never started would be indistinguishable
# from one whose did.
SMP_TICK_MARKER='claim smp.tick-per-cpu'
# ...and that a wakeup posted by one CPU reaches another. This is the mechanism a
# scheduler on one CPU will use to make a thread runnable on another: a bit set
# here, an interrupt to prompt the target, and the target taking it off its own
# bitmap. Delivering the prompt is not delivering the wakeup — the IPI claims
# above pass on a kernel whose target never drains — so this is its own marker.
SMP_WAKEUP_MARKER='claim smp.wakeup-crosses'

KERNEL="${1:?usage: smoke_boot_aarch64.sh <kernel-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial-aarch64.log"

# `cortex-a76` rather than the `cortex-a72` this used to run: the kernel turns
# on privileged-access-never (D247), which arrived in ARMv8.1 and which a v8.0
# part like the a72 reports as absent. A check that never exercises the feature
# cannot defend it — the same reason the x86-64 boot asks for `+smep,+smap`.
timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a76 -m 512M -accel "$ACCEL" \
    -smp 4 \
    -kernel "$KERNEL" \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native
status=$?

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# Semihosting SYS_EXIT propagates the kernel's status directly, so the port
# reports 33 on success and 65 on failure to match the x86-64 convention.
# 124 is the timeout.
case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
# Privileged-access-never is on and the kernel says which CPUs took it. The
# claim is what makes the CPU-model choice above load-bearing rather than
# incidental: on a part without the feature this line is absent and the check
# fails, which is the reverse of a feature quietly not being exercised.
PAN_MARKER='claim pan.installed'
# The root task, on the second port and from the same source x86-64 runs
# (D252). Six markers, and the point of asserting them *here* is that they are
# the same six: the process lifecycle is a kernel facility rather than one
# port's, so a second machine composing a system unchanged is what makes that a
# claim rather than a refactor.
ROOTTASK_CHANNEL_MARKER='claim roottask.channel-created'
ROOTTASK_GRANT_MARKER='claim roottask.granted'
ROOTTASK_SPOKE_MARKER='claim roottask.child-spoke'
ROOTTASK_CONCURRENT_MARKER='claim roottask.concurrent'
ROOTTASK_SUPERVISED_MARKER='claim roottask.supervised'
ROOTTASK_RECLAIMED_MARKER='claim roottask.reclaimed'
# A port the root task made itself, bound to one source, and handed to a child
# carrying SIGNAL and nothing else. Waking somebody is a different authority
# from talking to them, and this is a child holding one of each -- neither put
# there by the kernel (D254).
ROOTTASK_PORT_MARKER='claim roottask.port'
# And the roadmap's second Phase-1 bullet: the root task starts the device
# manager, which binds a driver, which serves its class. The sequence exists in
# kernel code three times over — bring_up_device_host, relay_pair,
# driver_bind_check — each of them boot glue creating a channel, spawning two
# programs and reaching into their handle tables. This is the same thing in
# user code, over a bus the kernel seeded and the root task handed on.
ROOTTASK_FRAMEWORK_MARKER='claim roottask.framework'
# And the last thing between a root task and a real driver host: a **real
# device's interrupt**, routed by the root task to a port it made for itself
# (D255). Every route in this tree before this one was installed by kernel boot
# glue on a driver's behalf, which made a driver host something only the kernel
# could assemble -- a program could map its device, allocate its DMA and re-arm
# its line, and still could not say where the interrupts should go.
#
# Distinct from ROOTTASK_PORT_MARKER, which is a software edge a child raised.
# This one is the machine's own PL031 alarm firing on its own line, and the
# kernel's bridge counts the delivery independently of what the program says
# about itself -- a check that trusted only the program would pass on one that
# skipped the step, which is exactly what its inversion produces.
ROOTTASK_INTERRUPT_MARKER='claim roottask.interrupt'

for marker in "$PAN_MARKER" "$ROOTTASK_CHANNEL_MARKER" "$ROOTTASK_GRANT_MARKER" \
              "$ROOTTASK_SPOKE_MARKER" "$ROOTTASK_CONCURRENT_MARKER" \
              "$ROOTTASK_SUPERVISED_MARKER" "$ROOTTASK_RECLAIMED_MARKER" \
              "$ROOTTASK_PORT_MARKER" \
              "$ROOTTASK_FRAMEWORK_MARKER" "$ROOTTASK_INTERRUPT_MARKER" \
              "$RELAY_MARKER" "$RELAY_BUDGET_MARKER" "$RELAY_THROUGHPUT_MARKER" \
              "$RELAY_UNDECLARED_MARKER" "$STORE_MARKER" "$STORE_REFUSAL_MARKER" \
              "$FIRMWARE_MARKER" "$FIRMWARE_MEASURED_MARKER" \
              "$FIRMWARE_ROLLBACK_MARKER" "$FIRMWARE_RIGHT_MARKER" \
              "$SMP_MARKER" "$SMP_COUNTED_MARKER" "$SMP_STARTED_MARKER" "$SMP_RUNS_MARKER" \
              "$SMP_IPI_MARKER" "$SMP_IPI_BROADCAST_MARKER" "$SMP_IPI_ONLY_MARKER" \
              "$EXEC_MULTI_CPU_MARKER" "$EXEC_SECOND_CPU_MARKER" "$EXEC_CROSS_CALL_MARKER" "$PERF_CROSS_CALL_MARKER" "$PERF_CROSS_NOTIFY_MARKER" "$PERF_SCALING_MARKER" "$EXEC_PARK_MARKER" \
              "$SMP_INVALIDATE_MARKER" \
              "$SMP_TICK_MARKER" "$SMP_WAKEUP_MARKER" "$SMP_GRACE_MARKER" \
              "$VM_SHOOTDOWN_MARKER" "$PREEMPT_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "marker '$marker' not found in serial output"
done

# **No line longer than 150 characters.** Checked against what the machine
# actually printed rather than against the format strings, because the length
# that matters is the one after the envelope and the interpolated values.
# The certificate is exempt: it is a fixed-size wire record rendered as hex
# for //tools/certify to read back, not a message a person reads.
long_line=$(awk 'length > 150 && $0 !~ /\] certificate: /' "$SERIAL_LOG" | head -1)
[ -z "$long_line" ] ||
    fail "a log line exceeds 150 characters (${#long_line}): $long_line"

echo "PASS: clean exit 33, alive marker present, a device's data path is a declared cost, the image store is verified, and firmware loads only when policy allows it"
