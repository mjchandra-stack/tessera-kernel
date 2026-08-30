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
# Requires: bazelisk, cargo, and qemu-system-{aarch64,arm,x86_64,riscv64,riscv32},
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

printf '\n=== documentation (generated interface reference + rustdoc)\n'
tools/ci/docs.sh --check

# The artifact somebody without this tree targets the system with. It is built
# by `//...` above like anything else; what this does is put it where a release
# step can pick it up, and print what went into it, so "published nowhere"
# stops being true of the one thing Phase 0 existed to hand over.
printf '\n=== the published ABI\n'
mkdir -p build-out
cp "$(bazel cquery //api/abi:abi_bundle --config=ci --output=files 2>/dev/null | tail -1)" \
    build-out/
tar -tf build-out/tessera-abi.tar | sed -n '1,3p'
printf 'abi: build-out/tessera-abi.tar\n'

printf '\ncontinuous passed in %dm%02ds\n' $(( (SECONDS-started)/60 )) $(( (SECONDS-started)%60 ))
