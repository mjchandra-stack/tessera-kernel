// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl::codegen_rust`.

use super::*;
use crate::compile;

#[test]
fn generated_source_is_deterministic() {
    let (ir, diags) = compile(include_str!("../../examples/syscall_handle_ops.isl"));
    assert!(!diags.has_errors(), "{diags:?}");
    let ir = ir.expect("ir");
    assert_eq!(emit(&ir), emit(&ir));
}

#[test]
fn emits_expected_shapes() {
    let (ir, _) = compile(include_str!("../../examples/syscall_handle_ops.isl"));
    let src = emit(&ir.expect("ir"));
    assert!(src.contains("pub struct Rights(pub u64);"));
    assert!(src.contains("pub enum ObjectType"));
    assert!(src.contains("pub struct DuplicateArgs"));
    assert!(src.contains("pub source: HandleRef,"));
    assert!(src.contains("pub reserved: [u8; 4],"));
    assert!(src.contains("const WIRE_SIZE: usize = 40;"));
}

/// **What a program should never have to compute.** Both ring-3 programs
/// hard-coded `0x1 | 0x2 | 0x4 | 0x80` and the literal transfer mode, so
/// the contract's answer and the program's answer were two facts that
/// happened to agree. Now the contract emits its own.
#[test]
fn a_handle_field_emits_the_rights_and_mode_it_declared() {
    let (ir, _) = compile(
        "library t.h;\n\
         @abi\n\
         struct S {\n\
           size: uint32;\n\
           version: uint32;\n\
           flags: uint64;\n\
           buffer: transfer handle<Object, {READ, WRITE, MAP, TRANSFER}>;\n\
         };\n",
    );
    let src = emit(&ir.expect("ir"));
    assert!(
        src.contains("pub const BUFFER_RIGHTS: u64 = 0x87;"),
        "{src}"
    );
    assert!(
        src.contains("pub const BUFFER_OWNERSHIP: Ownership = Ownership::Transfer;"),
        "{src}"
    );
    // The doc comment says it the way the schema did, because `0x87` is
    // not what anybody wrote.
    assert!(
        src.contains("handle<Object, {READ, WRITE, MAP, TRANSFER}>"),
        "{src}"
    );
}

/// A field that declared no mode emits no mode. Defaulting to `Snapshot`
/// would put a claim in the generated output that the schema never made —
/// and every handle field in a syscall-argument struct is exactly that
/// case, because a mode is a statement about a message.
#[test]
fn a_handle_field_without_a_mode_emits_only_its_rights() {
    let (ir, _) = compile(include_str!("../../examples/syscall_handle_ops.isl"));
    let src = emit(&ir.expect("ir"));
    assert!(
        src.contains("pub const SOURCE_RIGHTS: u64 = 0x40;"),
        "{src}"
    );
    assert!(!src.contains("SOURCE_OWNERSHIP"), "{src}");
}

#[test]
fn to_camel_converts_names() {
    assert_eq!(to_camel("NONE"), "None");
    assert_eq!(to_camel("PROTECTED_MEDIA"), "ProtectedMedia");
}
