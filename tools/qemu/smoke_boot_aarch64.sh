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

timeout 120s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
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
for marker in "$RELAY_MARKER" "$RELAY_BUDGET_MARKER" "$RELAY_THROUGHPUT_MARKER" \
              "$RELAY_UNDECLARED_MARKER" "$STORE_MARKER" "$STORE_REFUSAL_MARKER" \
              "$FIRMWARE_MARKER" "$FIRMWARE_MEASURED_MARKER" \
              "$FIRMWARE_ROLLBACK_MARKER" "$FIRMWARE_RIGHT_MARKER" \
              "$SMP_MARKER" "$SMP_COUNTED_MARKER" "$SMP_STARTED_MARKER" "$SMP_RUNS_MARKER" \
              "$SMP_IPI_MARKER" "$SMP_IPI_BROADCAST_MARKER" "$SMP_IPI_ONLY_MARKER" \
              "$SMP_INVALIDATE_MARKER" \
              "$SMP_TICK_MARKER" "$SMP_WAKEUP_MARKER" "$SMP_GRACE_MARKER"; do
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
