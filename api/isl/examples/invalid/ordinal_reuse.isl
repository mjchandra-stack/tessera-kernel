// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Negative fixture: reuses table ordinal 1. `islc check` must reject this
// (ISL0007 ordinal-reused), proving the schema-lint gate is live.

library tessera.example.bad;

table T {
    1: a: uint32;
    1: b: uint32;
};
