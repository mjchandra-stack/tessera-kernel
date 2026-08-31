#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 smoke boot: boot the Stage 0 image under QEMU and require both the
# clean success exit (isa-debug-exit status 33) AND the alive marker on the
# serial console. TCG by default for determinism; set
# TESSERA_QEMU_ACCEL=kvm (bazel test --config=kvm) for local speed.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3",
# "CI Topology")

set -u

MARKER='claim boot.alive'
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
# PCI as a bus driver (D151). Three markers, because the claims are separable:
# that a ring-3 program walked the bus at all, that the functions in the
# resource graph were put there by it rather than by the kernel, and that a
# driver reached its own configuration space and nothing adjacent.
PCI_BUS_MARKER='claim pci-bus.ok'
PCI_BUS_DECLARED_MARKER='claim pci-bus.declared'
PCI_BUS_CONFIG_MARKER='claim pci-bus.own-config'
# The root task composing a child (D249). Three markers, because the claims are
# separable and each is a thing that could not be done before:
#
#   * `channel-created` — a ring-3 program made a channel. `ChannelCreate` was
#     deferred until now, so every channel in this system's history was wired by
#     kernel boot glue (D45).
#   * `granted` — a capability reached a process because its *parent* put it
#     there, with rights the parent chose. Every service in this tree got its
#     handles from the kernel reaching into its table.
#   * `child-spoke` — and the child used it. Without this the first two are a
#     kernel bookkeeping exercise: a handle installed in a table nobody reads
#     proves nothing about whether it carries authority.
#
# The third is what makes the set hard to fake. A message arriving on the
# parent's end of a channel the parent created means the child held a writable
# capability to the far end, and the grant is the only way it could have.
ROOTTASK_CHANNEL_MARKER='claim roottask.channel-created'
# A child told what to work on, and refusing in a vocabulary its parent reads
# (D302). Both fail apart: `arguments` is the path echoed back intact on a
# channel the parent created, `exit-status` is the same program refusing two
# other legs with two different statuses.
ROOTTASK_ARGUMENTS_MARKER='claim roottask.arguments'
ROOTTASK_EXIT_STATUS_MARKER='claim roottask.exit-status'
ROOTTASK_GRANT_MARKER='claim roottask.granted'
ROOTTASK_SPOKE_MARKER='claim roottask.child-spoke'
# And what a start that no longer waits for its child buys (D250). Three more,
# and they are what the three retired component-manager demos used to claim
# from kernel-side assembly:
#
#   * `concurrent` — two children were runnable at once. A start that handed
#     the CPU to its child and came back with an exit code could not produce
#     that, so a root task could hold one program at a time.
#   * `supervised` — a service was restarted until it came up, and a service
#     that never would was given up on at its budget. The second half is the
#     one that decides whether a restart policy is real.
#   * `reclaimed` — across 45 launches, with 16 process slots and 16 thread
#     slots. A seventeenth launch fails unless every exited instance gave back
#     its slots, its kernel stack and its frames, so the count is the proof.
ROOTTASK_CONCURRENT_MARKER='claim roottask.concurrent'
ROOTTASK_SUPERVISED_MARKER='claim roottask.supervised'
ROOTTASK_RECLAIMED_MARKER='claim roottask.reclaimed'
# A port the root task made itself, bound to one source, and handed to a child
# carrying SIGNAL and nothing else. Waking somebody is a different authority
# from talking to them, and this is a child holding one of each -- neither put
# there by the kernel (D254).
ROOTTASK_PORT_MARKER='claim roottask.port'
# The driver framework on this port, and it is the **root task** that composes
# it now: a ring-3 manager holding a bus the root task handed on binds a real
# PCI function by class to a ring-3 driver, which reads past the first page of
# the window it was granted and agrees with what the kernel reads at that
# physical address. This was `driver_bind_check` -- 234 lines of boot glue
# creating the channel, spawning both programs and reaching into their handle
# tables -- and it is gone (D256).
#
# Its own marker for the reason the retired one had its own: an exit status
# cannot distinguish a check that stopped running from one that never existed.
ROOTTASK_FRAMEWORK_MARKER='claim roottask.framework'
# What the machine has against what this kernel starts on it. Three markers,
# because they are separable claims: `smp.single` is D8 — one CPU online —
# `smp.counted` is that the kernel knows how many it declined to start, and
# `smp.boot_id` is that the CPU's own id (CPUID) is the one the bootloader lists
# for it. A run asserting only the first would pass on a kernel that had stopped
# counting, which is the state every port was in before this; one asserting only
# the first two would pass on a kernel that read its APIC id wrong, which is
# invisible until something is addressed by it.
SMP_MARKER='claim smp.all-online'
SMP_COUNTED_MARKER='claim smp.counted'
SMP_BOOT_ID_MARKER='claim smp.boot_id'
# ...and `smp.started` is that every other CPU is running this kernel's code,
# on its tables, with its own descriptor tables and index. A run asserting only
# the three above would pass on a kernel whose application processors were still
# parked in the stub with the bootloader's GDT.
SMP_STARTED_MARKER='claim smp.started'
SMP_RUNS_MARKER='claim smp.second-cpu-runs'
# Supervisor-mode execution prevention, on every CPU rather than on the one
# that happened to program it: `CR4` is per CPU, so a kernel that set the bit
# in its boot path alone would leave every other CPU able to execute a user
# page, and no CPU can read another's `CR4` to notice.
SMEP_MARKER='claim smep.all-cpus'
# ...and access prevention, which is the half that needs the kernel to say when
# it means to reach a user page rather than merely never doing so by accident.
# ...and access prevention, which is the half that needs the kernel to say when
# it means to reach a user page rather than merely never doing so by accident.
# Every site that does is declared; an undeclared one faults the boot, which is
# how the remaining ones were found.
SMAP_MARKER='claim smap.installed'
# ...and `smp.own-tables` is that no two of them loaded the same descriptor
# table. Arrival proves a CPU loaded *a* table; only this proves the task-state
# segment, and so the fault stacks, are not shared.
SMP_OWN_TABLES_MARKER='claim smp.own-tables'
# ...and that this kernel can interrupt a CPU it started. Two markers because a
# targeted send and a broadcast are different fields of the same register: the
# first turns the kernel's dense index into the controller's own identifier and
# the second uses a shorthand that skips that. Neither name is a prefix of the
# other, because a marker is matched as a substring.
SMP_IPI_MARKER='claim smp.ipi-targeted'
SMP_IPI_BROADCAST_MARKER='claim smp.ipi-broadcast'
# ...and that it interrupted only that CPU. `smp.ipi-targeted` is earned by
# every CPU that was named taking one, which a send that names nobody and wakes
# the machine also earns. This one is earned by no CPU taking an interrupt it
# was not sent, and the kernel withholds it below three CPUs because with one
# other core there is no address left to get wrong. That is what `-smp 4` is
# for: at `-smp 2` this marker is absent and the run fails here.
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
# ...and that no thread ever went off-CPU still holding the executive's
# machine-wide tables. Nine of its methods suspend the calling thread inside
# their own borrow, and a hold that survived one of those is a hold nobody
# releases — the deadlock D230 measured waiting for a second CPU to exist.
# Checked where the scheduler actually parks a thread rather than where the
# release was meant to happen, so a park that was never converted is counted
# instead of assumed away: before the eleven were converted this said 119.
EXEC_PARK_MARKER='claim exec.lock-released-at-park'
# The interrupt path itself: the local APIC in its MSR form and the I/O APIC,
# with the 8259/8253 pair masked and never written again (build/README.md D87).
# A kernel that fell back to the legacy pair would still tick and still take
# IRQ3, and would fail this and nothing else.
IRQ_APIC_MARKER='claim irq.apic'
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
# ...and that an unmap on the boot CPU reaches the others. This port's
# invalidate is local, so `kcore::vm::invalidate` hands back the CPUs still
# holding the translation and a shootdown is what empties that set. The AArch64
# script has no counterpart: its invalidate is inner-shareable and the set is
# empty by construction, which `claim smp.invalidate-reaches` already shows.
SMP_SHOOTDOWN_MARKER='claim smp.shootdown'
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
ISO="${1:?usage: smoke_boot.sh <iso> <disk-image>}"
DISK="${2:?usage: smoke_boot.sh <iso> <disk-image>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
SERIAL_LOG="${TEST_TMPDIR:-/tmp}/serial.log"

# The disk arrives as a read-only build artifact and QEMU opens it read-write.
WRITABLE_DISK="${TEST_TMPDIR:-/tmp}/smoke-disk-x86_64.img"
cp "$DISK" "$WRITABLE_DISK"
chmod u+w "$WRITABLE_DISK"

# `+x2apic` is named rather than taken from the default, exactly as the AArch64
# script names `gic-version=2`. The kernel requires the local APIC's
# register-set-in-MSRs form and refuses to boot without it
# (docs/hardware/01, "Modern Hardware Only"); QEMU's `qemu64` model does not
# advertise it unless asked, so a run that did not ask would be testing a
# machine this kernel does not target. Asking here keeps the requirement
# visible in the invocation instead of hidden in a default.
#
# `+smep` is asked for on the same grounds and for one more: the kernel turns
# execution prevention on per CPU and reports the count, and on a model that
# does not advertise it that report is "absent" — honest, and indistinguishable
# from a kernel that had stopped enabling it. A feature CI never exercises is a
# feature CI cannot defend.
timeout 120s qemu-system-x86_64 \
    -M q35 -m 512M -accel "$ACCEL" \
    -cpu qemu64,+x2apic,+smep,+smap \
    -smp 4 \
    -cdrom "$ISO" \
    -drive "file=$WRITABLE_DISK,if=none,format=raw,id=bootdisk" \
    -device virtio-blk-pci,drive=bootdisk \
    -serial "file:$SERIAL_LOG" \
    -serial null \
    -display none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
status=$?

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# isa-debug-exit: QEMU exits (value << 1) | 1; the kernel writes 0x10 on
# success (=> 33) and 0x20 on failure (=> 65). 124 is the timeout.
case "$status" in
    33) ;;
    124) fail "boot timed out after 120s" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"

for marker in "$STORE_MARKER" "$STORE_REFUSAL_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "marker '$marker' not found in serial output"
done


for marker in "$ROOTTASK_CHANNEL_MARKER" "$ROOTTASK_ARGUMENTS_MARKER" \
              "$ROOTTASK_EXIT_STATUS_MARKER" "$ROOTTASK_GRANT_MARKER" "$ROOTTASK_SPOKE_MARKER" \
              "$ROOTTASK_CONCURRENT_MARKER" "$ROOTTASK_SUPERVISED_MARKER" \
              "$ROOTTASK_RECLAIMED_MARKER" "$ROOTTASK_PORT_MARKER" \
              "$ROOTTASK_FRAMEWORK_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" ||
        fail "marker '$marker' not found in serial output"
done

for marker in "$PCI_BUS_MARKER" "$PCI_BUS_DECLARED_MARKER" "$PCI_BUS_CONFIG_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "PCI was not enumerated from ring 3: '$marker'"
done

# `-smp 4` above is what makes these load-bearing. Asking the bootloader for
# its CPU list starts the other cores into a wait loop in usable memory, so the
# kernel must take them before it allocates; a boot that reported the count and
# did not would triple-fault a core long after appearing to succeed.
#
# Four rather than two, and not for margin. Two cores make "the other CPU" and
# "every CPU" the same set, so a targeted send that ignores its argument is
# indistinguishable from one that honours it and `smp.ipi-only-target` cannot
# be earned at all. Every other boot check in this tree still runs a single
# CPU, so the single-CPU path is not what this gives up.
for marker in "$SMP_MARKER" "$SMP_COUNTED_MARKER" "$SMP_BOOT_ID_MARKER" \
              "$SMP_STARTED_MARKER" "$SMP_RUNS_MARKER" "$SMP_OWN_TABLES_MARKER" "$SMP_IPI_MARKER" \
              "$SMP_IPI_BROADCAST_MARKER" "$SMP_IPI_ONLY_MARKER" "$EXEC_MULTI_CPU_MARKER" "$EXEC_SECOND_CPU_MARKER" "$EXEC_CROSS_CALL_MARKER" "$EXEC_PARK_MARKER" \
              "$IRQ_APIC_MARKER" "$SMP_TICK_MARKER" \
              "$SMP_WAKEUP_MARKER" "$SMP_SHOOTDOWN_MARKER" \
              "$SMP_GRACE_MARKER" "$VM_SHOOTDOWN_MARKER" "$PREEMPT_MARKER" \
              "$SMEP_MARKER" "$SMAP_MARKER"; do
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

echo "PASS: clean exit 33, alive marker present, the image store is verified, and PCI was enumerated by a ring-3 bus driver"
