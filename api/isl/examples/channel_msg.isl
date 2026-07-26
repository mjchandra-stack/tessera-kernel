// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The channel message ABI, defined in ISL. `MessageHeader` is the header every
// channel message carries (kernel/kcore/src/ipc.rs shapes the in-kernel struct
// to this subset); `ChannelCreateArgs` is the structured argument for creating
// a channel. Their wire bindings are generated and conformance-checked,
// demonstrating the IPC message boundary is ISL-expressible and ready to wire
// when user-mode entry lands. Handles travel in a message's separate transfer
// vector, never in the header bytes (docs/api/03, "Wire Format"), so the header
// itself carries no handle fields.
//
// `bits Rights` mirrors the kernel Rights Catalog (kernel/kcore/src/rights.rs)
// by convention until the ABI-diff path enforces it (deviation D16).

library tessera.kernel.channel;

// Core rights bits, matching the kernel Rights Catalog bit positions.
bits Rights : uint64 {
    READ = 0x1;
    WRITE = 0x2;
    MAP = 0x4;
    EXECUTE = 0x8;
    SIGNAL = 0x10;
    WAIT = 0x20;
    DUPLICATE = 0x40;
    TRANSFER = 0x80;
    CONFIGURE = 0x100;
    BIND = 0x200;
    ADMIN = 0x400;
};

// The channel message header: the fields every message carries. `size` and
// `version` front the struct per the @abi convention; `interface_id`,
// `method_id`, `flags`, and `txn_id` mirror the in-kernel `MessageHeader`.
//
// `correlation_lo`/`correlation_hi` are the two halves of the mandated 128-bit
// correlation id (`docs/observability/02`), matching `kernel_event.isl`: `_hi` is
// the per-boot epoch and `_lo` the origin-minted sequence. This is the header
// field the design calls the one "that already exists" for carrying causality
// across an asynchronous message — it did not, until D60. The **kernel** stamps
// it from the sending thread's ambient context; a sender never supplies it, so a
// ring-3 process cannot forge a cause (`docs/lifecycle/04`: identity comes from
// kernel-attested credentials, never payload fields). That is also why
// `ChannelMsgArgs` below, which is how ring 3 *describes* a message, carries no
// correlation field.
@abi
struct MessageHeader {
    size: uint32;
    version: uint32;
    flags: uint64;
    interface_id: uint64;
    txn_id: uint64;
    method_id: uint32;
    correlation_lo: uint64;
    correlation_hi: uint64;
};

// Arguments for creating a channel: the initial rights each of the two returned
// endpoint handles carries. The endpoints themselves are returned as handles in
// the reply's transfer vector, so they are not header fields here.
@abi
struct ChannelCreateArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    end0_rights: Rights;
    end1_rights: Rights;
};

// Arguments for the message-carrying channel operations (send / call / recv /
// reply). The target endpoint travels in a register (never the struct), so this
// describes only the message: its header fields, the inline payload, and the
// transfer-handle vector. `inline_ptr`/`handles_ptr` are caller-address-space
// pointers the kernel validates and copies; `txn_id` is stamped by the kernel on
// a call, so callers pass 0. Handle *values* live in the `handles_ptr` vector,
// never in the payload bytes (docs/api/03, "Wire Format").
@abi
struct ChannelMsgArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    interface_id: uint64;
    txn_id: uint64;
    method_id: uint32;
    msg_flags: uint32;
    inline_ptr: uint64;
    inline_len: uint64;
    handles_ptr: uint64;
    handle_count: uint64;
};
