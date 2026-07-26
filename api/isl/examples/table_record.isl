// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Example table: the extensible-record construct over inline fields. Each
// field is optional — absent fields cost nothing on the wire — and present
// fields are envelopes (ordinal + size + value) in ascending-ordinal order.
// Exercises table wire codegen (deviation D67): optional fields, an ordinal
// gap, a reserved slot, and canonical decode. Out-of-line fields (string,
// vector) remain deferred (D10).

library tessera.example.record;

strict enum Color : uint8 {
    RED = 1;
    GREEN = 2;
    BLUE = 3;
};

// A nested frozen struct, used as a table field to prove non-scalar values
// ride the envelope.
struct Point {
    x: int32;
    y: int32;
};

table Sample {
    1: id: uint64;
    2: enabled: bool;
    3: hue: Color;
    // ordinal 4 deliberately unused — a gap the encoding must tolerate.
    5: origin: Point;
    // a removed field's ordinal, permanently reserved.
    6: reserved;
};
