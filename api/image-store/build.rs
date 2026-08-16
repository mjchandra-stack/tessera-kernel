// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Cargo build script (host-only): generates the image-store format bindings,
//! so the cargo inner loop needs no Bazel-produced artifact (D24). Bazel
//! produces the same bindings via its `//api/isl:image_store_bindings` genrule
//! and does NOT run this script; the two paths are bridged by the `isl_bazel`
//! cfg, which Bazel sets and cargo does not.
//!
//! The same shape as `kernel/kcore/build.rs`, for one schema.
//!
//! Normative: docs/api/03-interface-schema-language.md,
//! docs/lifecycle/02-build-and-test-infrastructure.md

use std::path::Path;

const SCHEMA: &str = "../../api/isl/examples/image_store.isl";
const GENERATED: &str = "image_store.rs";

fn main() {
    println!("cargo::rustc-check-cfg=cfg(isl_bazel)");

    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let schema_path = Path::new(&manifest).join(SCHEMA);
    println!("cargo::rerun-if-changed={}", schema_path.display());

    let src = std::fs::read_to_string(&schema_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", schema_path.display()));
    let (ir, diags) = tessera_isl::compile(&src);
    for diag in diags.iter() {
        println!("cargo::warning={}: {diag}", schema_path.display());
    }
    let ir = ir.unwrap_or_else(|| panic!("{}: schema failed to compile", schema_path.display()));
    let bindings = tessera_isl::codegen_rust::emit(&ir);
    // The emitted file leads with crate-level inner attributes — valid when
    // Bazel compiles it as a crate root, rejected by `include!` into a `mod`.
    // The equivalent allow is an outer attribute on `mod abi` in lib.rs.
    let bindings: String = bindings
        .lines()
        .filter(|line| !line.trim_start().starts_with("#!["))
        .collect::<Vec<_>>()
        .join("\n");

    let out_path = Path::new(&out_dir).join(GENERATED);
    std::fs::write(&out_path, bindings)
        .unwrap_or_else(|e| panic!("write {}: {e}", out_path.display()));
}
