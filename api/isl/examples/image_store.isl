// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The verified image store: how the system delivers data it has to *trust*.
//
// Everything the kernel has read until now was compiled into it — the binding
// manifest is a Rust `static`, the ring-3 programs are byte arrays a genrule
// embedded — and the kernel trusts each of them because it cannot tell them
// from its own `.rodata`. That works exactly as long as nothing arrives from
// anywhere else. `docs/security/01` ("Boot Security") requires a *verified
// initial system image*, and `docs/security/02` ("Anti-Rollback") requires
// firmware to carry a monotonically increasing security version number. This
// container is what those two sentences are about.
//
// This is not a protocol. Nothing sends these bytes to anybody: a host tool
// writes the container and the kernel reads it, which is a cross-component
// interface with a long life and two independent implementations — the case
// `docs/lifecycle/04` forbids hand-rolled serialization for. Declaring it here
// means the builder and the reader decode the *same generated struct* and
// cannot drift apart in a way a test would have to think to look for.
//
// # The trust structure, which is the only interesting part
//
// A hash tree two deep.
//
//   - Each entry carries the digest of its own blob.
//   - The **anchor** is the digest of the header and the directory together —
//     that is, of every entry's digest.
//   - The verifier holds the anchor and nothing else.
//
// So one 32-byte constant in the verifier authenticates a container of any
// size, and the reader can measure a blob when it is *read* rather than when
// the container is mounted. That ordering is deliberate: a store proved intact
// at boot and then read from for the rest of the boot is a store trusted for
// what it was, and nothing here is willing to say when "was" ended.
//
// # Why there is an algorithm identifier in a format with one algorithm
//
// `docs/security/02` ("Crypto Agility") is categorical: no algorithm is
// hard-coded into an on-disk format, and every signed or encrypted object
// carries its algorithm identifier, key identifier and format version in its
// own header. A verifier accepts a *set* of currently valid algorithms and
// rejects the rest by policy rather than by code change. A format that meant
// SHA-256 by position would have to be re-versioned to say anything else, and
// every reader in the fleet would have to be taught the new position.
//
// `anchor_id` is the key identifier of that sentence. Trust anchors are
// versioned and replaceable (`docs/security/02`, "Trust Anchors And Signing
// Infrastructure"), so a container names *which* anchor is supposed to
// authenticate it and a verifier holding several does not have to try them all
// and accept whichever matched — which would make revoking one of them
// meaningless.
//
// Normative: docs/security/01-security-model.md ("Boot Security"),
// docs/security/02-cryptography-and-key-management.md ("Crypto Agility",
// "Anti-Rollback")

library tessera.image.store;

// How a measurement in this container was computed.
//
// `Unspecified` is not a default anybody may fall back to — it is the value a
// container that never said has, and a reader that met one would be choosing an
// algorithm on the writer's behalf. It is refused.
strict enum DigestAlgorithm : uint32 {
    Unspecified = 0;
    Sha256 = 1;
};

// The container header, at offset zero.
//
// It leads with `size`/`version`/`flags` because every `@abi` struct in this
// tree does, and the magic follows. Field order is not read order: this is the
// first thing read from a region that may hold anything at all, so the reader
// takes the magic from its fixed offset and refuses before it has believed a
// length — a reader that parsed one out of arbitrary bytes first would be
// trusting the very thing it is trying to check.
//
// `total_length` bounds the container within whatever region it was handed.
// A store embedded in an image sits next to other bytes, and a reader that
// treated everything to the end of the region as store contents would be
// letting whatever follows it decide what is inside it.
@abi
struct StoreHeader {
    // The wire size of this header.
    size: uint32;
    // Container format version, governing the directory's layout as well as
    // this header's. A reader that does not know a version refuses; it never
    // reads the fields it recognizes and ignores the rest, because the fields
    // it recognizes may be what changed.
    version: uint32;
    flags: uint64;
    // "TESSTORE", little-endian.
    magic: uint64;
    algorithm: DigestAlgorithm;
    // Which trust anchor is expected to authenticate this container.
    anchor_id: uint32;
    entry_count: uint32;
    reserved: uint32;
    // Where the directory starts. The anchor is the digest over everything from
    // offset zero to the end of the directory.
    directory_offset: uint64;
    // The whole container, header included.
    total_length: uint64;
};

// One blob's directory entry.
//
// Its `version` must equal the header's, and the reader enforces that rather
// than reading each entry on its own terms: a directory whose entries could
// disagree with their header about their own shape is one that cannot be walked
// to find out what shape it is.
@abi
struct StoreEntry {
    size: uint32;
    version: uint32;
    flags: uint64;
    // From the start of the container, never from the end of the directory.
    offset: uint64;
    length: uint64;
    // NUL-padded ASCII. Fixed width so the directory can be indexed rather than
    // walked: a reader looking for one blob does not touch any other entry's
    // bytes, and a corrupt length cannot make the *next* entry unfindable.
    name: array<uint8, 24>;
    // The security version number `docs/security/02` ("Anti-Rollback") requires:
    // monotonically increasing, and compared against a stored minimum so that a
    // correctly measured but downgraded image is still refused. Nothing in this
    // container enforces that — it is data for whoever holds the floor, and the
    // rollback rule is not a property of a file format.
    svn: uint32;
    // What the artifact *is*, as whoever produced it numbers it — and
    // deliberately not the same number as `svn`.
    //
    // `docs/security/02` ("Anti-Rollback") makes the security version a
    // monotonic counter compared against a floor, so that a correctly measured
    // but downgraded image is refused **even though nothing is wrong with it**.
    // That is not what a driver means when it says which firmware it
    // understands: a driver's constraint is about capability and is satisfied
    // or not by a given release, while the floor is about vulnerability and
    // outranks every driver. One field would make those two questions the same
    // comparison under two names — and the case worth catching, an image a
    // driver is happy with that the system refuses anyway, could not be
    // expressed at all.
    image_version: uint32;
    reserved: uint32;
    // The blob's own measurement, checked when the blob is read.
    digest: array<uint8, 32>;
};
