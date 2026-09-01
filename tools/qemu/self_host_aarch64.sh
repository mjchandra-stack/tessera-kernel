#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-3: a program one boot of this machine compiled is run by the next one.
#
# **Two boots, one volume, and nothing of the host's in between.** Every other
# check here is a single machine that builds something and then uses it, which
# proves a code generator works and does not prove the output is a *program* —
# an artifact whose existence no longer depends on the process that wrote it.
# The distance between those two is a power cycle, and it is the only part of
# `docs/roadmap/04` Phase 6 that this tree can reach: the literal gate is a
# kernel image, and a kernel image needs a target triple (D1) and a toolchain
# port that are neither of them this row.
#
# The first boot finds no `/gate.elf`, compiles `/gate.tsm` into one with the
# compiler *as a program* — `tsmc`, told what to build in its arguments — syncs
# it, and stops **without running it**. The second boot of that same volume
# finds it and runs it. Which half a boot performs is decided by the volume
# alone: same kernel image, same client, no flag and no argument. A boot cannot
# be told which half to be, which is what stops the second one from faking the
# first one's work.
#
# What the host does between them is the other half of the claim, and it is
# nothing: the image is checksummed after the first boot and again before the
# second, and the two must match. `debugfs` reads it and never `-w`. If this
# script ever grows a step that touches the volume between boots, that
# comparison fails and says so.
# Normative: docs/roadmap/04-self-hosting.md ("Phase 6")

set -u

# **What the pump loops had left, on the way past** (D311). These checks bound
# their wait for an asynchronous completion with an iteration budget, and
# running out does not fail — it truncates, ending the boot wherever it
# happened to reach. Printing the headroom on a *passing* run is the point: the
# next person to add work to this composition sees how much room there is
# instead of finding out by exhausting it, which is how D310 found out.
pump_report() {
    grep -oE '[a-z0-9/-]+: pump used ([0-9]+ of [0-9]+|all [0-9]+)' "$1" | sed 's/^/  /'
}

KERNEL="${1:?usage: self_host_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
SCRATCH="${2:?usage: self_host_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
EXT2="${3:?usage: self_host_aarch64.sh <kernel-image> <scratch-disk> <ext2-disk>}"
ACCEL="${TESSERA_QEMU_ACCEL:-tcg}"
TMP="${TEST_TMPDIR:-/tmp}"

STAGED='claim selfhost.staged'
BOOTED='claim selfhost.booted'

W_SCRATCH="$TMP/self-host-scratch.img"
W_EXT2="$TMP/self-host-ext2.img"
cp "$SCRATCH" "$W_SCRATCH" && chmod u+w "$W_SCRATCH"
cp "$EXT2" "$W_EXT2" && chmod u+w "$W_EXT2"

SERIAL_LOG=""
fail() {
    echo "FAIL: $1" >&2
    [ -n "$SERIAL_LOG" ] && [ -f "$SERIAL_LOG" ] && sed -n '1,200p' "$SERIAL_LOG" >&2
    exit 1
}

dbg() { PATH="/usr/sbin:/sbin:$PATH" debugfs -R "$1" "$2" 2>/dev/null; }
sum() { sha256sum "$1" | cut -d' ' -f1; }

# See `fs_boot_aarch64.sh` for why this machine is a cortex-a76 with all three
# network options: the kernel needs ARMv8.1 for privileged-access-never (D247),
# and the flow service needs IPv4, IPv6 and a TCP peer named explicitly
# (D279, D280).
NETDEV='user,id=n0,ipv4=on,ipv6=on,guestfwd=tcp:10.0.2.100:9-cmd:/bin/cat'

boot() {
    SERIAL_LOG="$TMP/serial-self-host-$1-aarch64.log"
    # 300s rather than the 120s the single-boot checks use: this machine runs
    # the whole filesystem composition *and* a compiler, and the boot that runs
    # the staged program does the most work of any check here. Under a parallel
    # `bazel test //...` the second boot exceeded 120s and was killed, which
    # reads as a failed check rather than as load (D311).
    timeout 300s qemu-system-aarch64 \
        -M virt,gic-version=2 -cpu cortex-a76 -m 512M -accel "$ACCEL" \
        -global virtio-mmio.force-legacy=false \
        -kernel "$KERNEL" \
        -drive "file=$W_EXT2,if=none,format=raw,id=hd1" \
        -device virtio-blk-device,drive=hd1 \
        -drive "file=$W_SCRATCH,if=none,format=raw,id=hd0" \
        -device virtio-blk-device,drive=hd0 \
        -netdev "$NETDEV" \
        -device virtio-net-device,netdev=n0 \
        -serial "file:$SERIAL_LOG" \
        -display none -no-reboot \
        -semihosting-config enable=on,target=native
}

# **The program must not already exist**, or the first boot takes the second
# boot's branch and the whole check passes on the image builder's work. The
# source must, because the division of labour is the point: the builder ships
# the text and the machine ships the program.
dbg "ls -l /" "$EXT2" | grep -q 'gate\.tsm' ||
    fail "the pristine volume is missing /gate.tsm — there is nothing to compile"
if dbg "ls -l /" "$EXT2" | grep -q 'gate\.elf'; then
    fail "the pristine volume already carries gate.elf — the build made it, not the machine"
fi

# --- the first boot: compile it, and stop ---
boot one
status=$?
[ "$status" -eq 33 ] || fail "first boot: expected clean exit 33, got $status"
grep -qF "$STAGED" "$SERIAL_LOG" ||
    fail "first boot did not compile the gate program — the staged claim is absent"
# **And it did not run what it built.** Without this the two boots are one
# story told twice, and `selfhost.booted` below would be the loop this tree
# already had before Phase 6 (D304).
grep -qF "$BOOTED" "$SERIAL_LOG" &&
    fail "first boot ran the program it had just built — the two halves are not separated"

dbg "ls -l /" "$W_EXT2" | grep -q 'gate\.elf' ||
    fail "first boot claims it staged a program, and the volume does not have one"
dbg "dump /gate.elf $TMP/gate-after-one.elf" "$W_EXT2"
[ -s "$TMP/gate-after-one.elf" ] ||
    fail "the staged program is empty or could not be read off the volume"

# What the host must not do to the image, made checkable rather than promised:
# checksummed the moment the first machine stops and again the moment before the
# second one starts, with every step between them a read.
BEFORE="$(sum "$W_EXT2")"

# --- the second boot: find it, and run it ---
[ "$(sum "$W_EXT2")" = "$BEFORE" ] ||
    fail "the host changed the volume between the two boots"
boot two
status=$?
[ "$status" -eq 33 ] || fail "second boot: expected clean exit 33, got $status"
grep -qF "$BOOTED" "$SERIAL_LOG" ||
    fail "second boot did not run the program the first one left — the booted claim is absent"
# And it did not rebuild it. A boot that could not find the program and
# compiled a fresh one would run something indistinguishable and prove nothing
# about the volume having carried it.
grep -qF "$STAGED" "$SERIAL_LOG" &&
    fail "second boot compiled the gate program again — it did not find the first one's"

# **The bytes it ran are the bytes the first boot wrote**, compared outside the
# machine. The claim above is the guest's word for having run a program; this
# is the volume's word for it being the same one.
dbg "dump /gate.elf $TMP/gate-after-two.elf" "$W_EXT2"
cmp -s "$TMP/gate-after-one.elf" "$TMP/gate-after-two.elf" ||
    fail "the program on the volume changed across the second boot"

# The program is on the volume and nowhere else: absent from the kernel image
# that ran it, which is the artifact a boot could have been carrying it in.
cmp -s "$TMP/gate-after-one.elf" "$KERNEL" && fail "internal: the kernel image is the program"
if command -v e2fsck >/dev/null 2>&1 || [ -x /usr/sbin/e2fsck ]; then
    PATH="/usr/sbin:/sbin:$PATH" e2fsck -fn "$W_EXT2" >/dev/null 2>&1 ||
        fail "e2fsck rejects the volume after two boots wrote to it"
else
    fail "e2fsck is required: it is what judges the volume these boots wrote"
fi

for phase in one two; do
    echo "  boot $phase:"
    pump_report "$TMP/serial-self-host-$phase-aarch64.log"
done
echo "PASS: one boot compiled /gate.tsm into /gate.elf and stopped; the next boot of the same volume, with nothing done to it in between, found that program and ran it"
