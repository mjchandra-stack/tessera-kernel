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
            .find(|m| m.name == *name)
            .unwrap_or_else(|| panic!("`bits Rights` is missing `{name}`"));
        assert_eq!(
            member.value, *value,
            "`{name}` is {:#x} in the schema and {value:#x} in the catalog",
            member.value
        );
    }
    // And nothing in the schema that the catalog has never heard of: a
    // right a schema can name but the compiler cannot resolve would emit a
    // mask silently missing a bit.
    for member in &declared.members {
        assert!(
            super::RIGHTS.iter().any(|(name, _)| *name == member.name),
            "`bits Rights` declares `{}`, which is not in the catalog",
            member.name
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

// --- the call surface ---

/// A syscall is a trap number and a register frame, and both of those have to
/// reach the IR intact: the number is the ABI, and a slot pointing at an
/// argument struct is a different instruction sequence from one holding a
/// value.
#[test]
fn a_syscall_lowers_to_its_number_and_its_frame() {
    let (ir, diags) = compile(
        "library t.sys;\n\
         extern struct MapDeviceArgs from t.dev;\n\
         @status(implemented)\n\
         @available(added = 2)\n\
         syscall MapDevice = 23 {\n\
           arg0: MapDeviceArgs;\n\
           returns: uint64;\n\
         };\n",
    );
    assert!(!diags.has_errors(), "{diags:?}");
    let ir = ir.expect("ir");
    let call = ir
        .decls
        .iter()
        .find_map(|d| match d {
            crate::ir::IrDecl::Syscall(s) => Some(s),
            _ => None,
        })
        .expect("the syscall");
    assert_eq!(call.number, 23);
    assert_eq!(call.added, Some(2));
    assert_eq!(call.status, crate::ast::Status::Implemented);
    assert_eq!(call.args.len(), 1);
    assert!(
        call.args[0].slot.by_pointer,
        "a register naming an argument struct carries a pointer to it"
    );
    assert!(!call.returns.as_ref().expect("a return").by_pointer);
}

/// The status vocabulary exists so a generated page can be filtered. Every
/// other declaration may leave it unstated; a syscall may not, because "which
/// of these exist" is the question the reference is for.
#[test]
fn a_syscall_without_a_status_is_rejected() {
    let (_, diags) = compile("library t.sys;\nsyscall Null = 0 {};\n");
    assert!(diags.has(Code::MissingStatus), "{diags:?}");
}

#[test]
fn an_invented_status_is_rejected() {
    let (_, diags) = compile("library t.sys;\n@status(mostly)\nsyscall Null = 0 {};\n");
    assert!(diags.has(Code::UnknownStatus), "{diags:?}");
}

/// A gap in the register slots would leave the frame ambiguous about which
/// register holds what, which is the one thing the declaration is for.
#[test]
fn a_gap_in_the_register_frame_is_rejected() {
    let (_, diags) = compile(
        "library t.sys;\n@status(implemented)\nsyscall X = 1 { arg0: uint64; arg2: uint64; };\n",
    );
    assert!(diags.has(Code::SyscallArgOrder), "{diags:?}");
}

/// Two calls behind one number is not a versioning slip: the number is the
/// trap's own argument, so the dispatch has no way to choose.
#[test]
fn two_calls_at_one_number_are_rejected() {
    let (_, diags) = compile(
        "library t.sys;\n\
         @status(implemented)\n\
         syscall A = 7 {};\n\
         @status(implemented)\n\
         syscall B = 7 {};\n",
    );
    assert!(diags.has(Code::SyscallNumberReused), "{diags:?}");
}

/// A register carries a scalar, a handle, or a pointer. A bounded collection
/// is neither, and accepting one would put a length prefix in a register.
#[test]
fn an_out_of_line_type_in_a_register_is_rejected() {
    let (_, diags) = compile(
        "library t.sys;\n@status(implemented)\nsyscall X = 1 { arg0: vector<uint8>:16; };\n",
    );
    assert!(diags.has(Code::SyscallArgType), "{diags:?}");
}

/// A syscall returns one word. An argument struct is passed in, never handed
/// back — the kernel has nowhere to write one the caller did not name.
#[test]
fn returning_an_argument_struct_is_rejected() {
    let (_, diags) = compile(
        "library t.sys;\n\
         extern struct SomeArgs from t.other;\n\
         @status(implemented)\n\
         syscall X = 1 { returns: SomeArgs; };\n",
    );
    assert!(diags.has(Code::SyscallArgType), "{diags:?}");
}

/// An external name has no layout here, so laying one out inside a struct
/// would size it at zero — a wire format that decodes and means something
/// else. Refused instead.
#[test]
fn an_external_struct_cannot_be_a_field() {
    let (_, diags) = compile(
        "library t.sys;\n\
         extern struct Other from t.other;\n\
         struct S { size: uint32; version: uint32; flags: uint64; inner: Other; };\n",
    );
    assert!(diags.has(Code::AbiSubsetViolation), "{diags:?}");
}

/// The prose written above a declaration is what the reference page is made
/// of, so it has to survive lexing, parsing and lowering. A blank line breaks
/// the run: a remark floating between declarations documents neither.
#[test]
fn documentation_reaches_the_ir_and_a_blank_line_ends_it() {
    let (ir, diags) = compile(
        "// The library's own header.\n\
         \n\
         library t.doc;\n\
         \n\
         // Not attached to anything.\n\
         \n\
         // The flag set.\n\
         bits F : uint32 {\n\
           // The first bit.\n\
           A = 0x1;\n\
         };\n",
    );
    assert!(!diags.has_errors(), "{diags:?}");
    let ir = ir.expect("ir");
    assert_eq!(ir.doc, "The library's own header.");
    let bits = ir
        .decls
        .iter()
        .find_map(|d| match d {
            crate::ir::IrDecl::Bits(b) => Some(b),
            _ => None,
        })
        .expect("the bits");
    assert_eq!(bits.doc, "The flag set.");
    assert_eq!(bits.members[0].doc, "The first bit.");
}
