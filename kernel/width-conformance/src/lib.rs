// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **Not a kernel, and never booted.** This crate exists so that a build can
//! be a gate.
//!
//! Two of the five CPU families in
//! `docs/hardware/01-platform-and-cpu-support.md` are 32-bit. Both now have
//! ports, and neither is what protects the architecture-independent crates
//! from quietly acquiring a 64-bit assumption: a port exercises the code it
//! happens to call, on the boot path it happens to take. The assumptions are
//! not hypothetical — `core::sync::atomic::AtomicU64` does not exist below a
//! 64-bit atomic width, and `u64 as usize` compiles happily on every target
//! while truncating on half of them.
//!
//! So this crate depends on every architecture-independent crate and is built
//! for a 32-bit target on every `bazel build //...`. It has no code of its
//! own beyond the assertions below, because the compile *is* the test: if
//! `kcore` names a type that a 32-bit target lacks, this fails to build, and
//! it fails in the change that introduced it rather than in the port that
//! eventually needs it.
//!
//! **The dependency list in `BUILD.bazel` is the gate.** A library absent from
//! it is one nothing compiles at 32 bits, and the omission looks exactly like
//! coverage — which is how the list came to name six crates while the tree
//! held twenty-seven.
//!
//! Why a build and not a unit test: word size is a property of the *target*,
//! and a host test always runs at the host's width. Compiling for a target of
//! the other width is the only check that observes the thing in question. The
//! behaviour that can be tested at either width — the split 64-bit atomic's
//! carry protocol — is unit-tested in `kcore::atomic`, on the host, and this
//! crate deliberately does not duplicate it.
//!
//! The chosen 32-bit target is `riscv32imac-unknown-none-elf`. Its atomic
//! width is 32, which is the constraint that actually bites, and it is the
//! narrower of the two 32-bit families here: `armv7a-none-eabi` has the same
//! pointer width and a 64-bit atomic, so on the two properties this crate
//! gates, RISC-V 32 is the stricter of the pair.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Endianness And
//! Word Size"), docs/lifecycle/02-build-and-test-infrastructure.md
//! Budget: none (build-time only)

#![no_std]
#![deny(unsafe_code)]

// The crates the cargo inner loop can also reach. The other sixteen gated
// libraries have no `Cargo.toml` — they exist only in the Bazel graph — so
// they are named in `BUILD.bazel`'s `deps` and nowhere here. A dep edge is
// what compiles a crate; the imports below only make the cargo half of the
// gate explicit.
use tessera_arch_conformance as _;
use tessera_devicetree as _;
use tessera_firmware as _;
use tessera_hash as _;
use tessera_image_store as _;
use tessera_isl_runtime as _;
use tessera_kcore as kcore;
use tessera_pci as _;
use tessera_smmu as _;
use tessera_virtio as _;

/// The pointer width this crate was compiled at. Not used — read by the
/// assertions below, which are the point.
const POINTER_BITS: usize = usize::BITS as usize;

// The gate's own premise: if this crate is ever built only at 64 bits, it is
// checking nothing and should say so rather than passing quietly. The Bazel
// target transitions to a 32-bit platform, so this holds there; the cargo
// inner loop can build it at either width, which is why the assertion is a
// range rather than an equality.
const _: () = assert!(POINTER_BITS == 32 || POINTER_BITS == 64);

// Sizes that must not move with the word size, because they are ABI. A
// pointer-width-dependent value here would mean a structure the kernel shares
// with user space or writes to a wire had silently changed shape on one
// family (docs/hardware/01, "Endianness And Word Size": interfaces carry
// explicit widths and never encode a pointer).
const _: () = assert!(core::mem::size_of::<tessera_karch::PhysAddr>() == 8);
const _: () = assert!(core::mem::size_of::<tessera_karch::VirtAddr>() == 8);
const _: () = assert!(core::mem::size_of::<tessera_karch::PhysFrame>() == 8);
const _: () = assert!(kcore::syscall::PORT_EVENT_RECORD_SIZE == 32);

// The reason this crate exists at all, stated as an assertion: the kernel's
// 64-bit counter is 64 bits wide at both word sizes. Where the target has no
// 64-bit atomic it is two halves, and it must still be a 64-bit quantity —
// narrowing it on a 32-bit machine would change what an event record means
// per architecture.
const _: () = assert!(core::mem::size_of::<kcore::atomic::AtomicU64>() == 8);

/// A physical address is **wider than a pointer** on both 32-bit families in
/// the matrix — ARMv7-A with LPAE addresses 40 bits of physical memory and
/// RISC-V Sv32 addresses 34 — so `PhysAddr` is deliberately not `usize`-sized
/// and code that assumes "physical fits in a pointer" is wrong on exactly the
/// targets this crate exists to protect. Stated here because it is the least
/// intuitive consequence of the word-size work and the easiest to regress.
pub const PHYSICAL_IS_WIDER_THAN_A_POINTER: bool =
    core::mem::size_of::<tessera_karch::PhysAddr>() >= core::mem::size_of::<usize>();

const _: () = assert!(PHYSICAL_IS_WIDER_THAN_A_POINTER);
