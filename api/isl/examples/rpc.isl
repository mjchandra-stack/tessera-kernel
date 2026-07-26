// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Example protocol exercising the dispatch codegen (deviation D69): a call with
// a named request and response, a one-way with an EMPTY request (the unit
// dispatch variant that frames zero bytes), and a server-initiated event.

library tessera.example.rpc;

struct GetArgs {
    key: uint64;
};

struct GetReply {
    value: uint64;
    found: bool;
};

struct TickEvent {
    seq: uint64;
};

protocol Store {
    // Named request and response.
    1: Get(GetArgs) -> (GetReply);
    // One-way with no arguments: the empty-payload unit variant.
    2: Flush();
    // Server-initiated event.
    3: -> Tick(TickEvent);
};
