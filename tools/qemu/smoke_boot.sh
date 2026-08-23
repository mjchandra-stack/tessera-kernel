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
# The driver framework on this port: a ring-3 manager binds a real PCI function
# by class to a ring-3 driver that is a compiled program rather than a blob. Its
# own marker, because a check that stopped running is not something an exit
# status can distinguish from one that never existed.
BIND_MARKER='claim driver-bind.ok'
# The half a manager handing over the wrong thing cannot fake: the driver read
# past the first page of its window and agreed with what the kernel reads at
# that physical address.
BIND_WINDOW_MARKER='claim driver-bind.window'
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
timeout 120s qemu-system-x86_64 \
    -M q35 -m 512M -accel "$ACCEL" \
    -cpu qemu64,+x2apic \
    -smp 2 \
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
grep -qF "$BIND_MARKER" "$SERIAL_LOG" ||
    fail "the ring-3 device manager did not bind a PCI device to a ring-3 driver"
grep -qF "$BIND_WINDOW_MARKER" "$SERIAL_LOG" ||
    fail "the driver did not read past the first page of its own window"

for marker in "$STORE_MARKER" "$STORE_REFUSAL_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "marker '$marker' not found in serial output"
done


for marker in "$PCI_BUS_MARKER" "$PCI_BUS_DECLARED_MARKER" "$PCI_BUS_CONFIG_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "PCI was not enumerated from ring 3: '$marker'"
done

# `-smp 2` above is what makes these two load-bearing. Asking the bootloader for
# its CPU list starts the other cores into a wait loop in usable memory, so the
# kernel must take them before it allocates; a boot that reported the count and
# did not would triple-fault a core long after appearing to succeed.
for marker in "$SMP_MARKER" "$SMP_COUNTED_MARKER" "$SMP_BOOT_ID_MARKER" \
              "$SMP_STARTED_MARKER" "$SMP_RUNS_MARKER" "$SMP_OWN_TABLES_MARKER" "$SMP_IPI_MARKER" \
              "$SMP_IPI_BROADCAST_MARKER" "$IRQ_APIC_MARKER" "$SMP_TICK_MARKER" \
              "$SMP_WAKEUP_MARKER" "$SMP_SHOOTDOWN_MARKER" \
              "$SMP_GRACE_MARKER"; do
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
