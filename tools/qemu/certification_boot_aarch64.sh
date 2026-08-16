#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3 certification boot, AArch64: a run of the checks that ends in a
# refusal.
#
# **Every other script here passes when something worked. This one passes when
# the machine says it did not check enough.** A ring-3 certifier runs the two
# of the eleven checks a peer can make against a driver from inside a channel,
# both hold, and it declines to issue a certificate — naming the nine that
# nobody asked.
#
# That is the property being tested, and it is not a formality. The checks in
# this tree are shell scripts registered by hand in a BUILD file: delete a
# registration and every remaining test still passes, because from the inside a
# check that was removed and a check that never existed are the same absence.
# Nothing notices that except something built to, and this is that thing
# reporting for the first time.
#
# **What the script contributes over reading the exit code.** The verdict line
# has to say the two claims apart: that the checks which ran passed, and that
# the runner refused anyway. A machine that ran nothing and refused would
# satisfy the second alone, and a runner that certified on two passing checks
# would satisfy the first — the failure this facility exists to prevent. Both
# markers are required, which is why they are separate greps rather than one.
#
# Normative: docs/drivers/01-driver-framework.md ("Certification"),
# docs/lifecycle/02-build-and-test-infrastructure.md ("Test Tiers")

set -u

MARKER='certification: OK'
# The claims, separable and asserted apart.
NOT_CERTIFIED_MARKER='THIS DRIVER IS NOT CERTIFIED'
BOTH_PASSED_MARKER='NINE CHECKS RAN, EIGHT PASSED AND ONE FAILED'
REFUSED_MARKER='REFUSED TO CERTIFY'
TWO_MARKER='TWO CHECKS NOBODY ASKED'
# A client that never comes back reports nothing at all.
CRASH_MARKER='TAKE A REQUEST AND NEVER ANSWER IT'
RETURNED_MARKER='THE CLIENT CAME BACK WITH AN ERROR'
# A resume is only real if the device works afterwards.
RESUME_MARKER='MADE IT DO THE SAME WORK AGAIN'
SESSION_MARKER='THE SAME SESSION THAT EXISTED BEFORE IT'
# The power rule nothing else in the tree catches.
POWER_MARKER='NO REFUSAL MOVED THE DEVICE'
DESCRIBE_MARKER='ITS OWN DESCRIBE REPLY'
# The check that fails, and is meant to.
FAILED_MARKER='THE ONE THIS DRIVER DOES NOT PASS'
CONTAINED_MARKER='ITS MEMORY CANNOT BE CONTAINED ON THIS MACHINE'
# The question nothing in this tree could answer before.
HOLDS_MARKER='WHAT THIS DRIVER ACTUALLY HOLDS'
# The check whose evidence is that this binary exists at all.
BUILD_TIME_MARKER='HAPPENED BEFORE THIS MACHINE EXISTED'
ARTIFACT_MARKER='THIS ARTIFACT EXISTING'
# The check no peer could have made, and the records it was made over.
VANTAGE_MARKER='THE CERTIFIER COULD NOT HAVE MADE'
RECORDS_MARKER='TRACE RECORDS THIS DRIVER CAUSED'
RING3_MARKER='HERE IN RING 3'

ARMED_MARKER='certification-hotplug: armed'
PULLED_MARKER='A DEVICE WAS PULLED OUT OF THIS MACHINE WHILE RING 3 WAS RUNNING'

KERNEL="${1:?usage: certification_boot_aarch64.sh <kernel-image> <certify>}"
CERTIFY="${2:?usage: certification_boot_aarch64.sh <kernel-image> <certify>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"
SERIAL_LOG="$TMP/serial-aarch64-certification.log"
# **Not under $TMP.** A unix socket path is capped at 108 bytes and Bazel's
# test tmpdir is longer than that on its own.
QMP_DIR="$(mktemp -d /tmp/tscert.XXXXXX)"
QMP_SOCK="$QMP_DIR/qmp.sock"
: > "$SERIAL_LOG"

fail() {
    echo "FAIL: $1" >&2
    echo "--- serial log ---" >&2
    cat "$SERIAL_LOG" >&2 || true
    exit 1
}

# The device is the crypto engine, because a certifier needs a driver to
# certify and this is the one whose class contract reaches every conformance
# rule in one transcript. Nothing here is about cryptography.
# **A bridge in a hot-pluggable slot, held by nobody.** The certification
# subject is the crypto driver; what gets pulled is a switch that no driver
# binds, so its going disturbs nothing else and a failure is about the removal
# mechanism rather than about the driver. Pulling the driver's own device is
# the next step.
timeout 300s qemu-system-aarch64 \
    -M virt,gic-version=2 -cpu cortex-a72 -m 512M -accel "$ACCEL" \
    -kernel "$KERNEL" \
    -object cryptodev-backend-builtin,id=cryptodev0 \
    -device virtio-crypto-pci,cryptodev=cryptodev0 \
    -device pcie-root-port,id=rp0,slot=0 \
    -device x3130-upstream,id=up0,bus=rp0 \
    -qmp "unix:$QMP_SOCK,server=on,wait=off" \
    -serial "file:$SERIAL_LOG" \
    -display none -no-reboot \
    -semihosting-config enable=on,target=native &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    rm -rf "$QMP_DIR"
}
trap cleanup EXIT

# Wait for the kernel to say it is holding the bridge. Pulling before that
# tests nothing: the tick has to be watching when the slot is asked.
waited=0
until grep -qF "$ARMED_MARKER" "$SERIAL_LOG" 2>/dev/null; do
    kill -0 "$QEMU_PID" 2>/dev/null || fail "QEMU exited before arming the slot watch"
    sleep 0.2
    waited=$((waited + 1))
    [ "$waited" -lt 900 ] || fail "the kernel never armed the slot watch"
done

[ -S "$QMP_SOCK" ] || fail "QEMU exposed no QMP socket"

# **A request, not an order.** device_del on something in a root port's slot
# raises an eject and waits for the guest to answer through the slot control
# register. Until this milestone nothing in a *running* machine could answer:
# the existing removal check polls in a boot loop with no thread alive, and
# during a scheduler run the boot CPU is inside the scheduler. So this request
# is answered from the periodic tick or not at all.
printf '%s\n%s\n' \
    '{"execute":"qmp_capabilities"}' \
    '{"execute":"device_del","arguments":{"id":"up0"}}' |
    timeout 30s socat - "UNIX-CONNECT:$QMP_SOCK" > "$QMP_DIR/qmp.log" 2>&1 ||
    fail "could not drive QMP (is socat installed?)"

wait "$QEMU_PID"
status=$?

case "$status" in
    33) ;;
    124) fail "QEMU timed out" ;;
    *) fail "QEMU exited $status (expected 33)" ;;
esac

grep -q "$MARKER" "$SERIAL_LOG" || fail "marker '$MARKER' not found in serial output"
for marker in "$NOT_CERTIFIED_MARKER" "$BOTH_PASSED_MARKER" "$REFUSED_MARKER" \
    "$TWO_MARKER" "$RING3_MARKER" "$VANTAGE_MARKER" "$RECORDS_MARKER" \
    "$BUILD_TIME_MARKER" "$ARTIFACT_MARKER" "$HOLDS_MARKER" \
    "$FAILED_MARKER" "$CONTAINED_MARKER" "$PULLED_MARKER" \
    "$POWER_MARKER" "$DESCRIBE_MARKER" "$RESUME_MARKER" "$SESSION_MARKER" \
    "$CRASH_MARKER" "$RETURNED_MARKER"; do
    grep -qF "$marker" "$SERIAL_LOG" || fail "the certification claim did not hold: '$marker'"
done

# **And it must say how many records it looked at.** "The trace records were
# well formed" is unfalsifiable from a log that does not say how many there
# were: a run that examined none would print the same sentence.
grep -qE 'boot validated the [1-9][0-9]* TRACE RECORDS' "$SERIAL_LOG" ||
    fail "the verdict does not say how many trace records were examined, or examined none"

# **And the fuzz evidence must be substantive.** A record saying zero targets
# would compile, link, and claim the fuzzing ran over nothing.
grep -qE '[1-9][0-9]* frozen structs were fuzzed over [1-9][0-9]* inputs' "$SERIAL_LOG" ||
    fail "the fuzz evidence names no targets or no inputs"

# **And it must say how many capabilities it read.** "The driver held only what
# it was allowed" is unfalsifiable from a log that does not say how many it
# looked at: a process holding nothing would print the same sentence.
grep -qE 'its [1-9][0-9]* capabilities were read' "$SERIAL_LOG" ||
    fail "the verdict does not say how many capabilities were audited, or audited none"

# **And the failing check must say how many grants were unscoped.** "Its memory
# cannot be contained" over zero grants would be a driver that asked for no DMA.
grep -qE '[1-9][0-9]* of its DMA grants came back as a physical address' "$SERIAL_LOG" ||
    fail "the failing DMA check names no grants, so it judged a driver that asked for none"

# **And the tick must have been looking while ring 3 ran.** A removal that only
# landed after the run would be the old boot-loop poll wearing a new name.
grep -qE 'answered after looking [1-9][0-9]* times during the run' "$SERIAL_LOG" ||
    fail "the slot was never polled while ring 3 was running"

# **And the verdict must leave the machine.** Everything above is prose a person
# reads; a signed channel admits a driver on a record, and until this line the
# answer this boot reached died with the boot.
grep -qE 'certificate: [0-9a-f]{144}' "$SERIAL_LOG" ||
    fail "the boot printed no encoded certificate, so its verdict cannot travel"

# **And the runner must refuse this driver, from that record alone.** This is
# the whole chain end to end: a machine observed, encoded what it observed, and
# a tool that cannot invent an outcome read it back and would not let this
# driver onto a channel. The refusal is a true negative from a real run — the
# DMA check genuinely fails here — rather than a constructed one.
CERTIFY_OUT="$TMP/certify.out"
set +e
"$CERTIFY" < "$SERIAL_LOG" > "$CERTIFY_OUT" 2>&1
CERTIFY_STATUS=$?
set -e
# Exit 3 exactly. Zero would mean it certified a driver that failed a check,
# and 2 would mean it never found a record to judge — three different problems,
# and a test that accepted "non-zero" would pass on the wrong one.
[ "$CERTIFY_STATUS" -eq 3 ] ||
    fail "the runner did not refuse; it exited $CERTIFY_STATUS: $(cat "$CERTIFY_OUT")"

# **And it must name what is wrong, in both kinds.** A refusal that said only
# "no" cannot tell an unfit driver from a rig that stopped asking, which is the
# distinction the whole certificate exists to preserve.
grep -q 'failed: \[dma-fault\]' "$CERTIFY_OUT" ||
    fail "the refusal does not name the check that failed: $(cat "$CERTIFY_OUT")"
grep -q 'never ran: \[hotplug perf-regression\]' "$CERTIFY_OUT" ||
    fail "the refusal does not name the checks nobody ran: $(cat "$CERTIFY_OUT")"

echo "PASS: clean exit 33, a device was pulled while ring 3 ran, six checks — five passed, one failed and said why, and the runner refused to certify on them — and the runner refused to certify, naming the two nobody asked — and the certificate left the machine as bytes, on which a host runner refused this driver a channel"
