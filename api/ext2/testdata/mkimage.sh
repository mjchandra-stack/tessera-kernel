#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Builds the ext2 image the tests read, with `mke2fs` — the point of choosing a
# real format is that an outside tool lays out the bytes, so a test can be
# wrong about this crate and cannot be wrong about ext2.
#
# One script rather than two invocations: the Bazel genrule and the cargo
# build script both run this, so the image a host unit test reads and the image
# a boot check mounts cannot differ (the same argument //tools/kconfig makes
# for the configuration surface).
#
# Deterministic on purpose. `mke2fs` writes a random UUID, a random directory
# hash seed and three timestamps unless it is told otherwise; a build artifact
# that differs run to run cannot be compared, and this tree compares artifacts.
# **One optional extra file, and the invariant that survives it.** The boot
# check's volume carries a program the build compiled — the one Phase 2's third
# bullet runs from the filesystem — and the host tests' volume cannot, because
# that ELF is a Bazel artifact and the cargo inner loop has no way to produce
# one. So the two images differ by exactly one file, added by the same script
# with the same tool: the layout rules, the block size, the pinned UUID and the
# normalisation below are identical, and every path the host tests look up is
# in both. What the comment above forbids is two *different* builders, which is
# still what this refuses to be.
# Usage: mkimage.sh <output.img> [program.elf]
set -euo pipefail

OUT="${1:?usage: mkimage.sh <output.img> [program.elf]}"
PROGRAM="${2:-}"
SEED="$(mktemp -d)"
trap 'rm -rf "$SEED"' EXIT

printf 'hello from ext2\n' > "$SEED/hello.txt"
mkdir -p "$SEED/dir"
printf 'nested\n' > "$SEED/dir/nested.txt"
# Larger than 12 blocks at 1 KiB, so reading it walks the single-indirect
# block rather than the direct list alone. The pattern varies per byte, so a
# reader that returns the right length full of zeroes fails.
# LC_ALL=C is load-bearing: in a UTF-8 locale awk's %c emits multibyte for
# every value above 127, and this file came out 105000 bytes rather than 70000.
LC_ALL=C awk 'BEGIN{for(i=0;i<70000;i++)printf "%c",(i*7+3)%256}' > "$SEED/big.bin"

# A file with more pages than the kernel's page cache holds frames, and fewer
# than one memory object may carry: twelve pages against a ceiling of eight and
# a cap of sixteen. That gap is the whole reason it exists — a reader walking it
# through one mapping cannot have it all resident, so pages it has already read
# are dropped behind it and fetched again, and the same per-byte pattern says
# whether what came back the second time was the right page.
LC_ALL=C awk 'BEGIN{for(i=0;i<49152;i++)printf "%c",(i*7+3)%256}' > "$SEED/cache.bin"

if [ -n "$PROGRAM" ]; then
    cp "$PROGRAM" "$SEED/program.elf"
fi


# A source with a mistake in it, for the leg that checks the compiler can say
# *why* rather than only that it failed (D307). Line 3 names an operation that
# does not exist, and the diagnostic must carry that number.
cat > "$SEED/bad.tsm" <<'TSM'
; this one does not compile
load 0x1
frobnicate 7
emit
TSM

# The source a program on the machine compiles (docs/roadmap/04 Phase 2, D304).
# It is here rather than generated, because what the check is about is that the
# machine turned *this text* into a program: the value below is arithmetic no
# byte of the build performs, and a generator that emitted a constant would have
# to have that constant in it.
#
#   0xc0de << 12 = 0xc0de000; + 0xbee = 0xc0debee; << 4 = 0xc0debee0; + 0xf.
cat > "$SEED/source.tsm" <<'TSM'
; compiled on the machine, by a program that read this file
load 0xc0de
shl 12
add 0xbee
shl 4
add 0xf
emit
TSM

# **The source the gate compiles, and the one file this image deliberately
# leaves incomplete** (docs/roadmap/04 Phase 6). Every other artifact a check
# needs is here; the program this one describes is not, and must not be. A boot
# that finds no `/gate.elf` compiles this into one and stops; the *next* boot of
# the same volume finds it and runs it. So the image builder ships the source
# and the machine ships the program, which is the only division of labour that
# makes "an image built by the system" mean anything.
#
#   0x5e1f << 12 = 0x5e1f000; + 0xb00 = 0x5e1fb00; << 4 = 0x5e1fb000; + 7.
cat > "$SEED/gate.tsm" <<'TSM'
; compiled by one boot of this machine, run by the next
load 0x5e1f
shl 12
add 0xb00
shl 4
add 0x7
emit
TSM

# `-d` takes each file's mtime from the source, which is the clock, not the
# faked one. Pinned so the inode table is a function of the content alone.
find "$SEED" -exec touch -h -d @1700000000 {} +

rm -f "$OUT"
truncate -s 4M "$OUT"
E2FSPROGS_FAKE_TIME=1700000000 mke2fs -q -t ext2 -b 1024 \
    -U 11111111-2222-3333-4444-555555555555 \
    -E hash_seed=66666666-7777-8888-9999-aaaaaaaaaaaa \
    -d "$SEED" -F "$OUT"

# `mke2fs -d` stamps each copied inode's ctime from the real clock, and ctime
# is the one timestamp `touch` cannot set. Normalised through debugfs rather
# than by patching bytes, so every byte of this image is still e2fsprogs'
# idea of ext2 and not ours.
# The boot block: ext2 reserves the first 1024 bytes for boot code and puts its
# superblock at 1024, so these two sectors belong to nobody. The markers every
# block-layer check looks for go here, which is what lets one volume be both a
# filesystem and a disk a driver will self-test against — without them
# `device-host` refuses to serve it.
printf 'TESSERAV' | dd of="$OUT" bs=1 seek=0 conv=notrunc status=none
printf 'TESSERA2' | dd of="$OUT" bs=1 seek=512 conv=notrunc status=none

for path in /hello.txt /big.bin /cache.bin /dir /dir/nested.txt; do
    debugfs -w -R "sif $path ctime 20231114182640" "$OUT" >/dev/null 2>&1
done
if [ -n "$PROGRAM" ]; then
    debugfs -w -R "sif /program.elf ctime 20231114182640" "$OUT" >/dev/null 2>&1
fi
