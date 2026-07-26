// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Example bounded collections: `string:N` and `vector<T>:N`, the out-of-line
// field types (deviation D68). Exercises them in a table (alongside an inline
// field, so the fixed- vs runtime-size envelope split is covered) and in a
// union variant. Vector elements are the inline subset (a scalar and a nested
// struct); vector-of-string / vector-of-vector stay deferred.

library tessera.example.collections;

struct Coord {
    lat: int32;
    lon: int32;
};

table Record {
    1: id: uint64;                 // inline field: fixed-size envelope
    2: label: string:32;           // bounded string: runtime-size envelope
    3: samples: vector<uint32>:8;  // bounded vector of a scalar
    4: path: vector<Coord>:4;      // bounded vector of a nested struct
};

flexible union Payload {
    1: note: string:64;
    2: counts: vector<uint16>:6;
};
