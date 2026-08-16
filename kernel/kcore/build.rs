// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Cargo build script (host-only): generates the ISL bindings the kernel ABI
//! consumes, so the cargo inner loop needs no Bazel-produced artifact (D24).
//! Bazel produces the same bindings via its `//api/isl:process_abi_bindings`
//! genrule and does NOT run this script; the two paths are bridged by the
//! `isl_bazel` cfg (declared below), which Bazel sets and cargo does not.
//!
//! Normative: docs/api/03-interface-schema-language.md,
//! docs/lifecycle/02-build-and-test-infrastructure.md

use std::path::Path;

/// Schemas generated into `OUT_DIR`. Each entry is (schema path relative to this
/// crate, generated file name `mod isl_binding` includes).
const SCHEMAS: &[(&str, &str)] = &[
    ("../../api/isl/examples/process_abi.isl", "process_abi.rs"),
    ("../../api/isl/examples/handle_abi.isl", "handle_abi.rs"),
    ("../../api/isl/examples/channel_msg.isl", "channel_msg.rs"),
    ("../../api/isl/examples/device_abi.isl", "device_abi.rs"),
    ("../../api/isl/examples/memory_abi.isl", "memory_abi.rs"),
    ("../../api/isl/examples/port_event.isl", "port_event.rs"),
    ("../../api/isl/examples/kernel_event.isl", "kernel_event.rs"),
    (
        "../../api/isl/examples/driver_lifecycle.isl",
        "driver_lifecycle.rs",
    ),
    ("../../api/isl/examples/demo_verdict.isl", "demo_verdict.rs"),
    ("../../api/isl/examples/firmware.isl", "firmware.rs"),
];

fn main() {
    // The `isl_bazel` cfg is set only by the Bazel build (which links the
    // genrule bindings crate instead of including this script's output); declare
    // it so cargo's `unexpected_cfgs` lint stays quiet.
    println!("cargo::rustc-check-cfg=cfg(isl_bazel)");
    // Likewise `kconfig_bazel`: Bazel links `//config:values` rather than
    // including what this script writes.
    println!("cargo::rustc-check-cfg=cfg(kconfig_bazel)");

    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");

    // The kernel's sizing constants, from the same declaration and the same
    // code Bazel's `//config:values` runs — the point of routing both paths
    // through one library rather than two emitters.
    let config_path = Path::new(&manifest).join("../../config/kernel.config");
    let profile_path = Path::new(&manifest).join("../../config/profiles/default.profile");
    println!("cargo::rerun-if-changed={}", config_path.display());
    println!("cargo::rerun-if-changed={}", profile_path.display());
    let decl_text = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", config_path.display()));
    let profile_text = std::fs::read_to_string(&profile_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", profile_path.display()));
    let decl = tessera_kconfig::parse_declaration(&decl_text)
        .unwrap_or_else(|e| panic!("{}: {e:?}", config_path.display()));
    let overrides = tessera_kconfig::parse_profile(&profile_text)
        .unwrap_or_else(|e| panic!("{}: {e:?}", profile_path.display()));
    let values = tessera_kconfig::resolve(&decl, &overrides)
        .unwrap_or_else(|e| panic!("{}: {e:?}", profile_path.display()));
    std::fs::write(
        Path::new(&out_dir).join("kconfig.rs"),
        tessera_kconfig::emit(&decl, &values, "default", tessera_kconfig::Form::Included),
    )
    .expect("write kconfig.rs");

    for (schema_rel, out_name) in SCHEMAS {
        let schema_path = Path::new(&manifest).join(schema_rel);
        println!("cargo::rerun-if-changed={}", schema_path.display());

        let src = std::fs::read_to_string(&schema_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", schema_path.display()));
        let (ir, diags) = tessera_isl::compile(&src);
        for diag in diags.iter() {
            println!("cargo::warning={}: {diag}", schema_path.display());
        }
        let ir =
            ir.unwrap_or_else(|| panic!("{}: schema failed to compile", schema_path.display()));
        let bindings = tessera_isl::codegen_rust::emit(&ir);
        // The emitted file leads with a crate-level `#![allow(...)]` inner
        // attribute — valid when Bazel compiles it as a crate root, but rejected
        // by `include!` into a `mod`. Strip inner attributes; the equivalent
        // allow is an outer attribute on `mod isl_binding` (kcore/src/lib.rs).
        let bindings: String = bindings
            .lines()
            .filter(|line| !line.trim_start().starts_with("#!["))
            .collect::<Vec<_>>()
            .join("\n");

        let out_path = Path::new(&out_dir).join(out_name);
        std::fs::write(&out_path, bindings)
            .unwrap_or_else(|e| panic!("write {}: {e}", out_path.display()));
    }
}
