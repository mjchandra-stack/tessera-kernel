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

// What happens to the sender's copy of a transferred capability
// (`docs/kernel/04`, "Out-Of-Line Memory Semantics"). The mode is declared per
// handle rather than per message because one message may hand over a buffer
// and lend a control endpoint.
//
// Strict, so a mode this kernel has never heard of fails to decode instead of
// being read as `TRANSFER` — the safe-looking default is the dangerous one,
// since a sender that asked to keep its copy and lost it corrupts nothing it
// can observe, while a sender that asked to give its copy away and kept it
// leaves the receiver validating a buffer that can still change underneath it.
strict enum TransferMode : uint32 {
    // Ownership moves. The sender's handle is taken from its table and its
    // mappings of the object are revoked before the message is delivered, so
    // post-send mutation is impossible by construction rather than by
    // convention.
    TRANSFER = 0;
    // Both sides hold the object and both may map it. Declared here so the
    // wire format does not have to change again, and refused with
    // `NotSupported` until every port carries an object table to refcount
    // against (`build/README.md`, D131).
    SHARE = 1;
};

// One entry in the outgoing transfer vector: a handle to move, and the rights
// it is to arrive with.
//
// The rights field is what makes a grant narrowable. Without it a transferred
// capability keeps exactly the rights it had, and because moving a handle
// *requires* `TRANSFER`, every capability that could be handed over
// necessarily arrived able to be handed on again — there was no way to grant a
// device a driver could not pass to a third party. Rights are reduced when a
// handle is duplicated or transferred (docs/kernel/01, "Handle And Rights
// System"); this is the transferred half.
//
// The kernel refuses a set that is not a subset of what the sender holds
// (`AccessDenied`) — the same rule, and the same error, as duplication, so
// "narrowing" means one thing everywhere. Zero is a legal request: a
// capability with no rights is useless but not dangerous, and refusing it
// would be a special case with nothing behind it.
//
// `rights` is 64 bits because the rights catalog is: the object-lifecycle
// rights sit at bits 32 and 33, and a 32-bit field would silently drop them.
//
// **`mode` says what happens to the sender's copy**, and it occupies what was
// version 3's `reserved` padding — which had to be zero, so a v3 descriptor is
// byte-identical to a v4 one asking for `TRANSFER`. That is the whole reason
// the field was kept reserved rather than left as anonymous padding.
//
// Deliberately **not** `@abi`: that convention's `size`/`version`/`flags`
// envelope belongs to a message, and this is an *element* of a vector the
// containing `ChannelMsgArgs` already versions. Repeating the envelope per
// element would double the descriptor's size to carry a version that cannot
// disagree with the one the kernel already read.
struct HandleTransfer {
    handle: uint32;
    mode: TransferMode;
    rights: uint64;
};

// Arguments for the message-carrying channel operations (send / call / recv /
// reply). The target endpoint travels in a register (never the struct), so this
// describes only the message: its header fields, the inline payload, and the
// transfer-handle vector. `inline_ptr`/`handles_ptr` are caller-address-space
// pointers the kernel validates and copies; `txn_id` is stamped by the kernel on
// a call, so callers pass 0. Handle *values* live in the `handles_ptr` vector,
// never in the payload bytes (docs/api/03, "Wire Format").
//
// **`handles_ptr` addresses a `HandleTransfer` vector, and `version` is the
// only thing that says so.** The struct's own size is unchanged across this
// change, so a producer left at version 2 would hand the kernel a vector of
// bare `uint32` handle values to be read as 16-byte descriptors — a handle
// number would land where a rights mask is expected. The version gate is
// therefore load-bearing rather than ceremonial, and a stale producer is
// refused rather than reinterpreted.
//
// `installed_ptr`/`installed_cap` are the **receive** direction's answer to a
// question the rest of the descriptor cannot express: which handles did the
// capabilities in this message land on?
//
// A handle is an index *and* a generation, and taking a handle bumps the
// generation of the slot it vacates. So a capability returning to a table it
// once lived in comes back at the same index with a different value, and any
// number the receiver remembered is stale by construction — that is the
// generation counter working, not failing. Without somewhere to report the
// answer, a receiver can only guess, and guessing right once is worse than
// failing.
//
// They are separate fields rather than a reuse of `handles_ptr`/`handle_count`
// because a **call is a send and a receive at once**: that vector is already
// the request's input transfer list, so a caller that transfers nothing but
// expects a capability back has no way to say so with one pair. Version 2 of
// this struct is exactly that pair; `installed_ptr = 0` opts out and is what
// every send-only caller passes.
//
// The report stays a plain `uint32` vector even though the outgoing side is
// now a descriptor. It answers "which handle numbers did the kernel install",
// and rights are not part of that answer — the receiver was granted what the
// sender chose and can ask with `HandleQueryRights`. Giving the two directions
// the same element type would imply a symmetry that is not there.
@abi
struct ChannelMsgArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    interface_id: uint64;
    txn_id: uint64;
    // Which method this message names.
    //
    // **Symmetric, like `inline_ptr`.** On a send it is what the caller is
    // invoking; on a **receive** the kernel writes back the method the arrived
    // message named, because a receiver that could not learn it could not
    // serve a protocol with more than one method — which is what a driver
    // class contract is. A receiver whose args buffer is not writable loses the
    // report and keeps the message, the same graceful degradation
    // `installed_ptr` has.
    method_id: uint32;
    msg_flags: uint32;
    inline_ptr: uint64;
    inline_len: uint64;
    handles_ptr: uint64;
    handle_count: uint64;
    installed_ptr: uint64;
    installed_cap: uint64;
};
