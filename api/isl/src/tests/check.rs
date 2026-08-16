// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl::check`.

use super::rights_mask;
use crate::compile;
use crate::diag::Code;

/// Compiles and requires success (no error diagnostics), returning the IR
/// text.
fn ir_text(src: &str) -> String {
    let (ir, diags) = compile(src);
    assert!(!diags.has_errors(), "unexpected errors: {diags:?}");
    ir.expect("ir").emit_text()
}

/// Compiles and requires an error carrying `code`.
fn expect_error(src: &str, code: Code) {
    let (ir, diags) = compile(src);
    assert!(diags.has(code), "expected {}, got: {diags:?}", code.label());
    assert!(ir.is_none(), "IR should be withheld on error");
}

const ABI: &str = "library t.abi;\n\
    bits Rights : uint64 { READ = 0x1; DUPLICATE = 0x4; };\n\
    @abi\n\
    struct DupArgs {\n\
      size: uint32;\n\
      version: uint32;\n\
      flags: uint64;\n\
      handle: handle<Object, {DUPLICATE}>;\n\
      new_rights: Rights;\n\
      reserved: array<uint8, 4>;\n\
    };\n";

#[test]
fn frozen_abi_struct_layout_is_canonical() {
    let expected = "library t.abi\n\
        bits Rights : uint64\n\
        \x20\x20READ = 0x1\n\
        \x20\x20DUPLICATE = 0x4\n\
        struct DupArgs abi size=40 align=8\n\
        \x20\x20size: uint32 @0 size=4\n\
        \x20\x20version: uint32 @4 size=4\n\
        \x20\x20flags: uint64 @8 size=8\n\
        \x20\x20handle: handle<Object, {DUPLICATE}> @16 size=4\n\
        \x20\x20new_rights: bits Rights @24 size=8\n\
        \x20\x20reserved: array<uint8, 4> @32 size=4\n";
    assert_eq!(ir_text(ABI), expected);
}

#[test]
fn emit_text_is_deterministic() {
    assert_eq!(ir_text(ABI), ir_text(ABI));
}

#[test]
fn ordinal_reuse_is_rejected() {
    expect_error(
        "library t.o;\n\
         table T { 1: a: uint32; 1: b: uint32; };\n",
        Code::OrdinalReused,
    );
}

#[test]
fn unbounded_vector_and_string_are_rejected() {
    expect_error(
        "library t.v;\n\
         table T { 1: items: vector<uint32>; };\n",
        Code::UnboundedVector,
    );
    expect_error(
        "library t.s;\n\
         table T { 1: name: string; };\n",
        Code::UnboundedVector,
    );
}

#[test]
fn abi_subset_violation_is_rejected() {
    // A struct may not hold an out-of-line vector.
    expect_error(
        "library t.a;\n\
         struct S { data: vector<uint8>:16; };\n",
        Code::AbiSubsetViolation,
    );
}

#[test]
fn missing_abi_header_is_rejected() {
    expect_error(
        "library t.h;\n\
         @abi struct S { x: uint32; };\n",
        Code::MissingAbiHeader,
    );
}

#[test]
fn unknown_type_rights_and_data_class_are_rejected() {
    expect_error(
        "library t.t;\n\
         struct S { f: Nope; };\n",
        Code::UnknownType,
    );
    expect_error(
        "library t.r;\n\
         struct S { h: handle<Object, {BOGUS}>; };\n",
        Code::UnknownRights,
    );
    expect_error(
        "library t.d;\n\
         table T { 1: @data_class(Nonexistent) x: uint32; };\n",
        Code::UnknownDataClass,
    );
}

#[test]
fn duplicate_names_and_bad_base_are_rejected() {
    expect_error(
        "library t.dup;\n\
         struct A { x: uint32; };\n\
         struct A { y: uint32; };\n",
        Code::DuplicateName,
    );
    expect_error(
        "library t.b;\n\
         bits B : int32 { X = 1; };\n",
        Code::InvalidBaseType,
    );
}

/// **The compiler's rights catalog and the schema's `bits Rights` are two
/// copies of one fact** (`kernel/kcore/src/rights.rs` is a third — D16).
/// This is the first thing that can notice them disagreeing: before, the
/// compiler knew only the names, so a value drifting in either copy was
/// invisible until something built on one met something built on the other.
#[test]
fn the_rights_catalog_agrees_with_the_schema_that_declares_it() {
    let (ir, diags) = compile(include_str!("../../examples/handle_abi.isl"));
    assert!(!diags.has_errors());
    let ir = ir.expect("ir");
    let declared = ir
        .decls
        .iter()
        .find_map(|d| match d {
            crate::ir::IrDecl::Bits(b) if b.name == "Rights" => Some(b),
            _ => None,
        })
        .expect("handle_abi.isl declares `bits Rights`");
    for (name, value) in super::RIGHTS {
        let member = declared
            .members
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("`bits Rights` is missing `{name}`"));
        assert_eq!(
            member.1, *value,
            "`{name}` is {:#x} in the schema and {value:#x} in the catalog",
            member.1
        );
    }
    // And nothing in the schema that the catalog has never heard of: a
    // right a schema can name but the compiler cannot resolve would emit a
    // mask silently missing a bit.
    for member in &declared.members {
        assert!(
            super::RIGHTS.iter().any(|(name, _)| *name == member.0),
            "`bits Rights` declares `{}`, which is not in the catalog",
            member.0
        );
    }
}

/// A handle field's declaration — object type, rights, and ownership mode —
/// reaches the IR. Until it did, `docs/api/03`'s *"part of the type"* was
/// true of the schema and of nothing built from it.
#[test]
fn a_handle_fields_declaration_survives_lowering() {
    let text = ir_text(
        "library t.h;\n\
         @abi\n\
         struct S {\n\
           size: uint32;\n\
           version: uint32;\n\
           flags: uint64;\n\
           buffer: transfer handle<Object, {READ, WRITE}>;\n\
         };\n",
    );
    assert!(
        text.contains("buffer: transfer handle<Object, {READ, WRITE}> @16 size=4"),
        "got: {text}"
    );
}

/// The mask comes from the compiler's catalog, so a consumer never has to
/// compute one. `READ | WRITE | MAP | TRANSFER` is the set a transferable
/// buffer travels with.
#[test]
fn rights_names_resolve_to_the_catalogs_mask() {
    let names: Vec<String> = ["READ", "WRITE", "MAP", "TRANSFER"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(rights_mask(&names), 0x87);
    // A name outside the catalog contributes nothing — `check_rights` has
    // already reported it, and inventing a bit for it would put a right in
    // the mask that no kernel implements.
    assert_eq!(rights_mask(&["NOSUCH".to_owned()]), 0);
}

/// An ownership mode says what happens to a second copy of something. An
/// inline field has no second copy.
#[test]
fn an_ownership_mode_on_an_inline_field_is_an_error() {
    expect_error(
        "library t.own;\n\
         table T { 1: n: transfer uint64; };\n",
        Code::OwnershipOnNonHandle,
    );
    // And it stays legal on the out-of-line kinds the spec names.
    let (ir, diags) = compile(
        "library t.own2;\n\
         table T { 1: buf: transfer vector<uint8>:64; };\n",
    );
    assert!(!diags.has_errors());
    assert!(ir.is_some());
}

#[test]
fn share_mode_is_a_warning_not_an_error() {
    let src = "library t.sh;\n\
               table T { 1: buf: share vector<uint8>:64; };\n";
    let (ir, diags) = compile(src);
    assert!(diags.has(Code::ShareInValidateThenUse));
    assert!(!diags.has_errors(), "share-mode is only a warning");
    assert!(ir.is_some(), "a warning still yields IR");
}

#[test]
fn protocol_interface_ids_and_methods_compile() {
    let text = ir_text(
        "library t.svc;\n\
         protocol Echo {\n\
           1: Echo(struct { x: uint32; }) -> (struct { y: uint32; });\n\
           2: -> OnPing(struct { seq: uint64; });\n\
           3: reserved;\n\
         };\n",
    );
    assert!(text.contains("protocol Echo"));
    assert!(text.contains("1: call Echo"));
    assert!(text.contains("2: event OnPing"));
    assert!(text.contains("3: reserved"));
}
