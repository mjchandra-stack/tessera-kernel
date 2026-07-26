// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The ring-3 block service protocol (build/README.md, D81): the request and
// reply a client exchanges with the ring-3 blk driver over a channel. This is
// a user<->user contract — the kernel transports the payload opaquely and
// never decodes it; only the two EL0 programs hold these bindings.

library tessera.driver.block;

// A read of one sector, sent by the client with ChannelCall. The reply
// arrives in the same call buffer (the symmetric call-buffer convention:
// ChannelMsgArgs' inline descriptor is the request source and the reply
// destination, so the buffer must hold the larger of the two structs).
@abi
struct BlockReadRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    sector: uint64;
};

// The driver's reply: the outcome and the sector's first 64 bytes — enough
// for the proof (the test disk's magic lives at byte 0) while fitting the
// channel's inline payload. Full-sector transfer needs a shared-memory grant,
// deferred with the rest of the service surface.
@abi
struct BlockReadReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    reserved: uint32;
    data: array<uint8, 64>;
};
