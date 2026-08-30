<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# The Tessera ABI

Everything needed to target this system without holding its source tree.

## What is here

| Path | What it is |
| --- | --- |
| `VERSION` | the published ABI version, one integer |
| `surface.lock` | one digest per schema over its compiled IR, and one over the set |
| `schemas/*.isl` | the interface definitions — the ABI itself |
| `ir/*.ir` | each schema compiled: resolved names, ordinals, syscall numbers, interface IDs, and every field's offset and size |
| `reference/*.md` | the readable form of the same thing, one page per schema |
| `api/isl/` | the generated Rust bindings and a `BUILD.bazel` declaring them |
| `api/isl-runtime/` | the wire codec those bindings call |
| `userspace/uabi/` | the syscall stub and address-space layout a program traps through |
| `MANIFEST` | SHA-256 of every file above |

## Verifying it

Two independent checks, and they answer different questions.

**Did the files arrive intact?** `sha256sum -c MANIFEST`.

**Is this the interface the version claims?** Each line of `surface.lock` is
the digest of one schema's compiled IR, so
`sha256sum ir/process_abi.ir` reproduces the `process_abi` line with no tooling
from the tree that built this. The digest is over the IR and not the source
because that is what `docs/api/03` requires: rewrapping a doc comment must not
look like an ABI change, and reordering two struct fields must.

## Building against it

The bindings arrive as libraries, not as instructions. Place `api/isl/`,
`api/isl-runtime/` and `userspace/uabi/` at those paths in a Bazel workspace
and the labels a program already uses — `//api/isl:process_abi_bindings`,
`//api/isl-runtime:isl_runtime`, `//userspace/uabi:uabi` — resolve against this
artifact instead of against a schema compiler. Nothing in a program changes,
which is the point: if a program had to be edited to build against the
published ABI, the published ABI would not be the thing the program was written
against.

There is no `islc` here and no need for one. The compiler's output is what is
published; the compiler is a detail of how it was made.

## What a version means

The version changes when the surface does, and a person decides whether a
change was breaking — `docs/api/02-abi-versioning-and-compatibility.md` is the
rule and `docs/api/03` ("Evolution Rules") is how it applies to a schema.
`//tools/checks:abi_test` holds the mechanical half: the lock matches the
schemas, every schema is accounted for in both directions, and the version a
program here was compiled against is the version this artifact publishes.
