// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// Example service protocol: a channel interface using tables (the default for
// evolvable service protocols), a bounded string, and the three method kinds.
// Parsed and type-checked with an interface ID derived; wire codegen for the
// out-of-line types (tables, strings) is deferred (deviation D10).

library tessera.example.echo;

@available(added = 1)
table EchoRequest {
    1: message: string:256;
    2: @data_class(UserPrivate) tag: uint64;
};

table EchoReply {
    1: reply: string:256;
};

protocol Echo {
    // Round-trip call: request and paired response.
    1: Echo(EchoRequest) -> (EchoReply);
    // Fire-and-forget one-way request.
    2: Log(struct { size: uint32; version: uint32; flags: uint64; level: uint8; });
    // Server-initiated event.
    3: -> OnHeartbeat(struct { seq: uint64; });
    // A removed method's ordinal, permanently reserved.
    4: reserved;
};
