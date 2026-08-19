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
# Usage: mkimage.sh <output.img>
set -euo pipefail

OUT="${1:?usage: mkimage.sh <output.img>}"
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
for path in /hello.txt /big.bin /dir /dir/nested.txt; do
    debugfs -w -R "sif $path ctime 20231114182640" "$OUT" >/dev/null 2>&1
done
