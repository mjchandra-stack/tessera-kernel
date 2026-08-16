#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Lints the architecture ports and kernel binaries, and holds the finding count
# to `arch-lint-baseline.txt`.
#
# These targets sit behind the kernel platform transition, which the clippy and
# rustfmt aspects do not cross — so `bazel build //... --config=lint` reports
# nothing for them and reported nothing for years (deviation D183). Each
# architecture therefore gets its own invocation, naming its crates rather than
# globbing the package: a host `rust_test` carries no `target_compatible_with`,
# so a wildcard would try to build the test harness for bare metal and bury the
# lint output in `cannot find macro assert_eq`.
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
        riscv32) echo "//kernel/karch-riscv32 //kernel/karch-riscv-common //kernel/kernel-riscv32:kernel-riscv32_bin" ;;
        arm32)   echo "//kernel/karch-arm32 //kernel/karch-arm-common //kernel/kernel-arm32:kernel-arm32_bin" ;;
        *)       echo "" ;;
    esac
}

status=0
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
    found=$(bazel build $targets --config="lint-$arch" -k 2>&1 \
        | grep -E '^error: ' | grep -vc 'aborting due to')
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
