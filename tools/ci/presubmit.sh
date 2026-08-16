#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Pre-merge gate: tiers 0–2 and a one-architecture tier-3 boot, inside the
# thirty-minute budget `docs/lifecycle/02` sets. Anything slower belongs in
# `continuous.sh` rather than being skipped.
#
# **This is the local presubmit as well as the CI one, and deliberately the
# same file.** `docs/lifecycle/02` ("Developer Experience") asks that the local
# presubmit be the same execution as CI pre-merge; a script both run is the
# only arrangement where that stays true without anybody checking.
#
# Requires: bazelisk on PATH as `bazel`, and qemu-system-aarch64.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("CI Topology")
set -euo pipefail

cd "$(dirname "$0")/../.."
started=$SECONDS
step() { printf '\n=== %s\n' "$1"; }

# Tiers 0–2: the static gates, the host unit tests, and the generated
# conformance and fuzz targets. Everything that needs no machine.
step "tiers 0-2"
bazel test //... --config=ci --test_tag_filters=-requires-qemu

# Tier 0, the half that is a build rather than a test: rustfmt and clippy over
# everything the host platform can configure.
step "rustfmt + clippy (host-configurable targets)"
bazel build //... --config=ci --config=lint

# The ports and kernel binaries, which the aspects above cannot reach (D183).
step "rustfmt + clippy (ports and kernel binaries)"
tools/ci/arch-lint.sh

# One architecture boots. The full matrix is post-merge: AArch64 is the port
# that runs the most checks, so it is the one worth spending pre-merge time on.
step "tier 3, one architecture"
bazel test //tools/qemu:smoke_boot_aarch64_test --config=ci

printf '\npresubmit passed in %dm%02ds (budget 30m)\n' $(( (SECONDS-started)/60 )) $(( (SECONDS-started)%60 ))
