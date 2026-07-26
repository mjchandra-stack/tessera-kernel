// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Example unions: the tagged-choice construct, strict and flexible, over
// inline variants (a bool, a scalar, a nested frozen struct). Exercises union
// wire codegen — the ordinal + size envelope, canonical per-variant decoding,
// strict unknown-tag rejection, and flexible unknown-tag preservation into a
// bounded buffer (deviation D66). Out-of-line variants (string/vector/table)
// remain deferred (D10).

library tessera.example.unions;

// A nested frozen struct, used as a union variant to prove non-scalar payloads
// ride the envelope correctly.
struct Point {
    x: int32;
    y: int32;
};

// Strict: every tag is known; an unknown ordinal is a decode error.
strict union Scalar {
    1: flag: bool;
    2: count: uint64;
    3: point: Point;
};

// Flexible: an unknown ordinal is preserved rather than rejected, so the
// choice can gain variants without breaking an older decoder. Ordinal 2 is a
// permanently-reserved removed slot.
flexible union Signal {
    1: tick: uint64;
    2: reserved;
    3: at: Point;
};
