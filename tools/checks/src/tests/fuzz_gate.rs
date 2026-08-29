// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::fuzz_gate`.

use super::*;

/// Every listed parser's crate name, spelled the way a complete harness would
/// name it.
///
/// **Derived rather than written out.** These tests build a tree where the
/// harness is complete and assert the gate finds nothing else wrong; a
/// hardcoded list would make them fail the next time `HAND_WRITTEN_PARSERS`
/// grew, which is a test failing for the one reason it must not — the gate
/// doing its job. That is what happened when `api/net` was added.
fn every_harness_name() -> String {
    HAND_WRITTEN_PARSERS
        .iter()
        .map(|(path, _)| {
            let leaf = path.rsplit('/').next().unwrap_or(path);
            format!("tessera_{}", leaf.replace('-', "_"))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The gate must notice a schema whose target is gone. Checked against a
/// temporary tree rather than the real one, because the real one is
/// (correctly) complete and would prove nothing.
#[test]
fn a_schema_with_no_fuzz_target_is_a_violation() {
    let dir = std::env::temp_dir().join("tessera-fuzz-gate-missing");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("api/isl/examples")).expect("temp tree");
    std::fs::create_dir_all(dir.join("api/isl-fuzz/tests")).expect("temp tree");
    std::fs::write(
        dir.join("api/isl/examples/thing.isl"),
        "library t;\n@abi\nstruct Thing { size: uint32; };\n",
    )
    .expect("schema");
    std::fs::write(dir.join("api/isl/BUILD.bazel"), "# nothing here\n").expect("build");
    std::fs::write(dir.join("api/isl-fuzz/tests/blob.rs"), every_harness_name()).expect("harness");

    let violations = check(&dir);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].reason.contains("`fuzz = True`"));
}

/// And a hand-written parser nobody fuzzes.
#[test]
fn a_listed_parser_with_no_harness_is_a_violation() {
    let dir = std::env::temp_dir().join("tessera-fuzz-gate-unfuzzed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("api/isl/examples")).expect("temp tree");
    std::fs::create_dir_all(dir.join("api/isl-fuzz/tests")).expect("temp tree");
    std::fs::write(
        dir.join("api/isl/examples/thing.isl"),
        "library t;\n@abi\nstruct Thing { size: uint32; };\n",
    )
    .expect("schema");
    std::fs::write(
        dir.join("api/isl/BUILD.bazel"),
        "isl_bindings(\n    name = \"thing\",\n    fuzz = True,\n)\n",
    )
    .expect("build");
    std::fs::write(dir.join("api/isl-fuzz/tests/blob.rs"), "nothing at all").expect("harness");

    let violations = check(&dir);
    assert_eq!(
        violations.len(),
        HAND_WRITTEN_PARSERS.len(),
        "{violations:?}"
    );
}

/// A schema that declares no `@abi` struct declares no decoder, so it is
/// not owed a target — the five feature-demo schemas in this tree are that
/// case, and treating them as violations would make the gate noise.
#[test]
fn a_schema_with_no_abi_struct_is_owed_nothing() {
    let dir = std::env::temp_dir().join("tessera-fuzz-gate-noabi");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("api/isl/examples")).expect("temp tree");
    std::fs::create_dir_all(dir.join("api/isl-fuzz/tests")).expect("temp tree");
    std::fs::write(
        dir.join("api/isl/examples/demo.isl"),
        "library t;\ntable Thing { 1: a uint32; };\n",
    )
    .expect("schema");
    std::fs::write(
        dir.join("api/isl/examples/real.isl"),
        "library t;\n@abi\nstruct Real { size: uint32; };\n",
    )
    .expect("schema");
    std::fs::write(
        dir.join("api/isl/BUILD.bazel"),
        "isl_bindings(\n    name = \"real\",\n    fuzz = True,\n)\n",
    )
    .expect("build");
    std::fs::write(dir.join("api/isl-fuzz/tests/blob.rs"), every_harness_name()).expect("harness");

    assert_eq!(check(&dir), Vec::new());
}
