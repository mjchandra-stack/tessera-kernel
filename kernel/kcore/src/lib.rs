// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Kernel core: architecture-independent mechanism — early logging,
//! physical frame allocation, the fallible kernel heap, and panic policy.
//! Generic over the `tessera-karch` traits; contains no
//! architecture-specific code and never depends on a concrete architecture
//! crate, so it builds for the host (tier-1 tests against
//! `tessera-karch-mock`) and for the kernel platform unchanged.
//!
//! Normative: docs/kernel/01-kernel-model.md
//! Budget: none (init paths only, this milestone)

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
extern crate std;

/// ISL-generated wire bindings for the kernel ABI (the schema is the source of
/// truth; the code is never hand-written or checked in). The cargo inner loop
/// generates them via `build.rs` into `OUT_DIR`; Bazel links the equivalent
/// genrule crates (`//api/isl:*_bindings`) and sets `--cfg=isl_bazel`. Both expose
/// the same items (e.g. `isl_binding::process::ProcessCreateArgs`). One submodule
/// per schema — each schema has its own `Rights` bits type, so they cannot be
/// flattened. The allow set mirrors the generated files' own (their inner
/// attributes are stripped so the `include!`s are valid inside a `mod` — see
/// `build.rs`); submodule names differ from the crate names so `pub use
/// <crate>::*` resolves unambiguously to the Bazel bindings crate.
#[allow(dead_code, unused_imports, non_upper_case_globals, clippy::all)]
mod isl_binding {
    pub mod process {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/process_abi.rs"));
        #[cfg(isl_bazel)]
        pub use process_abi::*;
    }
    pub mod handle {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/handle_abi.rs"));
        #[cfg(isl_bazel)]
        pub use handle_abi::*;
    }
    pub mod channel {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/channel_msg.rs"));
        #[cfg(isl_bazel)]
        pub use channel_msg::*;
    }
    pub mod device {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/device_abi.rs"));
        #[cfg(isl_bazel)]
        pub use device_abi::*;
    }
    pub mod memory {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/memory_abi.rs"));
        #[cfg(isl_bazel)]
        pub use memory_abi::*;
    }
    pub mod port {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/port_event.rs"));
        #[cfg(isl_bazel)]
        pub use port_event::*;
    }
    pub mod event {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/kernel_event.rs"));
        #[cfg(isl_bazel)]
        pub use kernel_event::*;
    }
    pub mod lifecycle {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/driver_lifecycle.rs"));
        #[cfg(isl_bazel)]
        pub use driver_lifecycle::*;
    }
    pub mod firmware {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/firmware.rs"));
        #[cfg(isl_bazel)]
        pub use firmware_abi::*;
    }
    pub mod verdict {
        #[cfg(not(isl_bazel))]
        include!(concat!(env!("OUT_DIR"), "/demo_verdict.rs"));
        #[cfg(isl_bazel)]
        pub use demo_verdict::*;
    }
}

// The width-portable 64-bit counter lives in the porting layer, because
// the ports need it too (a 32-bit port's own timer keeps a 64-bit tick
// count). Re-exported here so `kcore::atomic` stays the name the kernel
// core uses.
pub use tessera_karch::atomic;

pub mod bench;
pub mod console;
pub mod devmgr;
pub mod dispatch;
pub mod elf;
pub mod event;
pub mod exec;
pub mod firmware;
pub mod handle;
pub mod heap;
pub mod ipc;
pub mod job;
pub mod lifecycle;
pub mod memory;
pub mod object;
pub mod pager;
pub mod panic;
pub mod pmem;
pub mod port;
pub mod power;
pub mod process;
pub mod rights;
pub mod sched;
pub mod store;
pub mod supervise;
pub mod sync;
pub mod syscall;
pub mod thread;
pub mod trace;
pub mod verdict;
pub mod vm;
pub mod wait;
