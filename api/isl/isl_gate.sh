#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Tier-0 ISL gate: every valid example schema must `check` clean and emit a
# byte-identical IR twice (determinism); every schema under an `invalid/` path
# must be rejected. This is the "no interface stabilizes without conformance
# tests" gate applied to the schemas themselves.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

set -uo pipefail

islc="$1"
shift
status=0

for schema in "$@"; do
    "$islc" check "$schema"
    rc=$?
    case "$schema" in
        *invalid/*)
            if [ "$rc" -eq 0 ]; then
                echo "FAIL: $schema must be rejected but passed"
                status=1
            else
                echo "ok (rejected): $schema"
            fi
            ;;
        *)
            if [ "$rc" -ne 0 ]; then
                echo "FAIL: $schema must pass but was rejected"
                status=1
                continue
            fi
            a=$("$islc" emit-ir "$schema" 2>/dev/null)
            b=$("$islc" emit-ir "$schema" 2>/dev/null)
            if [ "$a" != "$b" ]; then
                echo "FAIL: $schema emit-ir is not deterministic"
                status=1
            else
                echo "ok: $schema"
            fi
            ;;
    esac
done

if [ "$status" -eq 0 ]; then
    echo "isl gate: all schemas ok"
fi
exit "$status"
