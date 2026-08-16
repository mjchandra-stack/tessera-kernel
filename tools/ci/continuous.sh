#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Post-merge gate: everything the pre-merge budget could not afford — the full
# tier-3 matrix, which is every boot check on every architecture.
#
# Tier 4 (the perf rig on real hardware, R1) and the fuzzing fleet belong here
# too and are not wired up: there is no hardware worker and no fuzzing
# infrastructure yet (deviations D34, D12). This runs what exists rather than
# implying what does not.
#
# Requires: bazelisk, and qemu-system-{aarch64,arm,x86_64,riscv64,riscv32},
# xorriso for the x86-64 ISO, socat for the GPIO check's button press.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("CI Topology")
set -euo pipefail

cd "$(dirname "$0")/../.."
started=$SECONDS

printf '\n=== every tier, every architecture\n'
bazel test //... --config=ci

printf '\n=== rustfmt + clippy (host-configurable targets)\n'
bazel build //... --config=ci --config=lint

printf '\n=== rustfmt + clippy (ports and kernel binaries)\n'
tools/ci/arch-lint.sh

printf '\ncontinuous passed in %dm%02ds\n' $(( (SECONDS-started)/60 )) $(( (SECONDS-started)%60 ))
