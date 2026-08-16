// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::fuzz_gate`.

use super::*;

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
    std::fs::write(
        dir.join("api/isl-fuzz/tests/blob.rs"),
        "tessera_devicetree tessera_image_store tessera_update_channel",
    )
    .expect("harness");

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
    std::fs::write(
        dir.join("api/isl-fuzz/tests/blob.rs"),
        "tessera_devicetree tessera_image_store tessera_update_channel",
    )
    .expect("harness");

    assert_eq!(check(&dir), Vec::new());
}
