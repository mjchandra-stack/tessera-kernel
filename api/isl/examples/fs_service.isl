// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// What a program asks a filesystem service for, once it has a path.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it. Only the two EL0 programs hold these bindings.
//
// **Not the whole of `docs/storage/02`, and the shape says which part.** That
// document splits the work: the VFS service resolves a path once and is then
// out of the loop, and what it hands back is "a handle to the file's
// pager-backed memory object and a channel ... scoped to that file". There is
// no VFS service yet and no way for a ring-3 program to be handed a
// pager-backed object at all — `map_object` has no syscall — so v0 does the
// resolution and the reading over one channel, and reads copy through a
// transferred buffer instead of faulting on a mapping.
//
// Both deviations are recorded (build/README.md) rather than designed in: the
// method set below is deliberately the one that survives the change, because
// `Open` returning a file id and `Read` taking one is what a pager-backed
// version would still offer to a caller that did not want to map.

library tessera.fs.service;

// What went wrong, as a closed set. A service answers one of these and never
// an errno the caller has to parse.
strict enum FsError : uint32 {
    OK = 0;
    // The path names nothing.
    NOT_FOUND = 1;
    // A component of the path is not a directory, or the target is one and the
    // caller asked to read it as a file.
    NOT_A_FILE = 2;
    // The volume is not one this service can read: a format it does not
    // implement, or a structure that does not make sense.
    BAD_VOLUME = 3;
    // The medium refused, or answered wrongly.
    IO_ERROR = 4;
    // The request itself is malformed — a bad envelope, a path longer than the
    // format allows, a file id nobody opened.
    PROTOCOL = 5;
    // A read was asked for through a buffer that did not arrive, or arrived
    // without the rights it needs.
    NO_BUFFER = 6;
    // More files are open than this service can track.
    TOO_MANY_OPEN = 7;
};

// The longest path this contract carries.
//
// Inline, because a path is small and a service that had to be handed a buffer
// to learn what to open would need a buffer before it could refuse a name.
// 128 keeps the request under the kernel's 256-byte inline limit with room for
// the envelope.
@abi
struct FsOpenRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Bytes, not a string: a filesystem's names are not required to be UTF-8,
    // and deciding they are is how a reader loses a file.
    path: array<uint8, 128>;
    path_len: uint32;
    reserved: uint32;
};

@abi
struct FsOpenReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    // What the caller names this file in every later request. Not an inode
    // number: a service that handed out its own on-disk identifiers would let
    // a caller name a file it never opened.
    file: uint32;
    // The file's length, so a caller can size its reads without a second call.
    length: uint64;
};

@abi
struct FsReadRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    file: uint32;
    reserved: uint32;
    offset: uint64;
    // How many bytes to read into the buffer. Short at end of file, which is
    // not an error — the reply says how many arrived.
    length: uint64;
    // Where they go. Transferred, because the kernel's inline limit is 256
    // bytes and a file read that had to fit in one would be a contract built
    // around a message size.
    buffer: transfer handle<Object, {READ, WRITE, MAP, TRANSFER}>;
};

@abi
struct FsReadReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    reserved: uint32;
    // How many bytes were actually read.
    read: uint64;
};

@abi
struct FsCloseRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    file: uint32;
    reserved: uint32;
};

@abi
struct FsCloseReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: uint32;
    reserved: uint32;
};

protocol FileSystem {
    // Resolves a path and returns something to read it with.
    1: Open(FsOpenRequest) -> (FsOpenReply);
    // Reads into the transferred buffer, which comes back with the reply.
    2: Read(FsReadRequest) -> (FsReadReply);
    // Gives up a file id. A service that leaked them would refuse the caller
    // that opened the most files rather than the one that leaked.
    3: Close(FsCloseRequest) -> (FsCloseReply);
    // 4..=9 reserved for the write path (M5/M6): Write, Sync, Create, Unlink.
    4: reserved;
    5: reserved;
    6: reserved;
    7: reserved;
};
