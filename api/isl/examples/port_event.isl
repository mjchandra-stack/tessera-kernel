// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The port event record, defined in ISL: what a `PortWait` hands back to a
// ring-3 driver or service when it drains an event (build/README.md, D85).
// A port carries several bindings, so the drained event must name WHICH one
// fired — that is what makes a port a **select** across event sources: a
// device interrupt (source = its INTID) or a message arriving on one of a
// server's per-client endpoints (source = that endpoint's object id).

library tessera.kernel.port;

// One drained port event. `source`/`signal` identify the binding that fired
// (the pair the port was bound with); `pending` is the coalesced edge count
// since the binding was last drained, so a waiter that missed wakeups still
// learns how many arrived.
@abi
struct PortEventRecord {
    size: uint32;
    version: uint32;
    flags: uint64;
    source: uint64;
    signal: uint32;
    pending: uint32;
};
