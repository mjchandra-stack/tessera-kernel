#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Lints the architecture ports and kernel binaries, and holds the finding count
# to `arch-lint-baseline.txt`.
#
# These targets sit behind the kernel platform transition, which the aspects in
# `--config=lint` do not cross from a host build — so `bazel build //...
# --config=lint` reports nothing for them and reported nothing for years
# (deviation D183). Each architecture therefore gets its own invocation, naming
# its crates rather than globbing the package: a host `rust_test` carries no
# `target_compatible_with`, so a wildcard would try to build the test harness
# for bare metal and bury the lint output in `cannot find macro assert_eq`.
#
# **Two checks, counted two ways, because they fail differently.** Clippy's
# findings are held to a baseline that may only fall (see the file). Rustfmt is
# not a count: a file either matches the formatter or it does not, so it is a
# hard failure with the diff printed.
#
# Both come out of the *same* build — `--config=lint` runs both aspects — and
# for its first two years this script read only clippy's half of the output. It
# grepped `^error: `, which is the shape of a clippy finding; rustfmt says
# `ERROR: ... Rustfmt ... failed` and `Diff in <file>`, neither of which
# matches, and the pipe threw the exit status away. So the formatter ran on
# every port, failed, and said so into a pipe nobody read (D268).
#
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")
set -uo pipefail

cd "$(dirname "$0")/../.."
BASELINE="tools/ci/arch-lint-baseline.txt"

targets_for() {
    case "$1" in
        x86_64)  echo "//kernel/karch-x86_64 //kernel/kernel:kernel_bin" ;;
        aarch64) echo "//kernel/karch-aarch64 //kernel/karch-arm-common //kernel/kernel-aarch64:kernel-aarch64_bin" ;;
        riscv64) echo "//kernel/karch-riscv64 //kernel/karch-riscv-common //kernel/kernel-riscv64:kernel-riscv64_bin" ;;
        riscv32) echo "//kernel/karch-riscv32 //kernel/karch-riscv-common //kernel/kernel-riscv32:kernel-riscv32_bin //kernel/width-conformance:width-conformance_lib" ;;
        arm32)   echo "//kernel/karch-arm32 //kernel/karch-arm-common //kernel/kernel-arm32:kernel-arm32_bin" ;;
        *)       echo "" ;;
    esac
}

status=0

# --- Is every bare-metal crate named above? ---------------------------------
#
# `targets_for` is a hand-written list and the loop below walks the baseline
# file, so a package neither of them names is not *failed* by this gate — it is
# never linted at all. That silence is what D183 and D268 were both about, and
# a sixth port would land in it. Bazel knows the real answer: a target
# constrained to `os:none` is one a host `//... --config=lint` build skips, and
# that set is exactly what this script exists to cover.
#
# Compared per package rather than per target, because a package can hold two
# binaries over one `srcs` — `kernel-aarch64_bin` and `kernel-aarch64_image_bin`
# are the ELF and the flat image of the same sources, and linting either lints
# the files.
#
# A query that cannot run is reported rather than skipped: a check that goes
# quiet when its input is missing reads exactly like a check that passed.
arches=$(grep -vE '^\s*(#|$)' "$BASELINE" | awk '{print $1}')
if bare=$(bazel query 'attr(target_compatible_with, "os:none", //kernel/...)' 2>/dev/null |
    grep -v ':srcs$' | sed 's|^//||; s|:.*||' | LC_ALL=C sort -u) && [ -n "$bare" ]; then
    named=$(for a in $arches; do targets_for "$a"; done |
        tr ' ' '\n' | grep -E '^//' | sed 's|^//||; s|:.*||' | LC_ALL=C sort -u)
    missing=$(LC_ALL=C comm -23 <(echo "$bare") <(echo "$named"))
    if [ -n "$missing" ]; then
        echo "FAIL: bare-metal package(s) no architecture lints:" >&2
        echo "$missing" | sed 's/^/  /' >&2
        echo "  add them to targets_for in $0" >&2
        status=1
    else
        echo "coverage: $(echo "$bare" | wc -l) bare-metal package(s), all linted"
    fi
else
    echo "FAIL: could not ask Bazel which packages are bare-metal — coverage unchecked" >&2
    status=1
fi

while read -r arch want; do
    case "$arch" in ''|\#*) continue ;; esac
    targets="$(targets_for "$arch")"
    if [ -z "$targets" ]; then
        echo "FAIL: $BASELINE names $arch, which arch-lint.sh has no targets for" >&2
        status=1
        continue
    fi
    # `-k` so every crate is linted rather than stopping at the first refusal;
    # the "aborting due to N previous errors" line is a summary, not a finding.
    #
    # Captured to a file rather than piped, so both readings come from one
    # build and neither can silently discard the other's result.
    log="$(mktemp)"
    bazel build $targets --config="lint-$arch" -k > "$log" 2>&1

    # Rustfmt first: it is the check that used to be invisible here, and a
    # formatting diff makes the clippy line numbers below misleading anyway.
    # Two signals, because they are not the same failure: `Diff in` is a file
    # the formatter would rewrite, and a failed Rustfmt action with no diff is
    # something worse — a file it could not parse. Matching only the first
    # would pass the second silently, which is the mistake this check exists
    # to stop repeating.
    if grep -qE '^Diff in |Rustfmt .* failed' "$log"; then
        if grep -q '^Diff in ' "$log"; then
            echo "FAIL: $arch is not formatted — run rustfmt on:" >&2
            grep -oE '^Diff in [^:]+' "$log" | sed "s|^Diff in $PWD/||" | sort -u |
                sed 's/^/  /' >&2
            grep -A 12 '^Diff in ' "$log" | sed "s|$PWD/||" | head -40 >&2
        else
            echo "FAIL: $arch: the formatter could not read a file — no diff, an error:" >&2
            grep -E 'Rustfmt .* failed' "$log" | sed "s|$PWD/||" | cut -c1-160 |
                sed 's/^/  /' >&2
        fi
        status=1
    fi

    found=$(grep -E '^error: ' "$log" | grep -vc 'aborting due to')
    rm -f "$log"
    if [ "$found" -gt "$want" ]; then
        echo "FAIL: $arch has $found lint findings, up from $want (see $BASELINE)" >&2
        status=1
    elif [ "$found" -lt "$want" ]; then
        echo "$arch: $found findings, down from $want — lower the baseline" >&2
        status=1
    else
        echo "$arch: $found findings, unchanged"
    fi
done < "$BASELINE"

exit "$status"
