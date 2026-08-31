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

/// An `array<Struct, N>` decodes without requiring `Default` of its element.
///
/// **This arm had never been compiled.** Every array in the tree was
/// `array<uint8, N>` until `StartupArgs` (D302), and the struct arm emitted
/// `[Default::default(); N]` against generated structs that derive `Copy` and
/// not `Default` — so the first schema to use one failed in rustc rather than
/// in `islc`, which is the wrong place for a language to say no.
#[test]
fn an_array_of_structs_decodes_without_a_default_bound() {
    let (ir, _) = compile(
        "library t.a;\
         struct Elem { a: uint32; };\
         @abi struct Holder { size: uint32; version: uint32; flags: uint64; \
         items: array<Elem, 3>; };",
    );
    let src = emit(&ir.expect("ir"));
    assert!(!src.contains("Default::default()"), "{src}");
    // Seeded from the first element, then the remaining two are read: three
    // elements on the wire, one decode expression plus a loop that skips the
    // slot already filled.
    assert!(src.contains("let items_first = Elem::decode(r)?;"), "{src}");
    assert!(
        src.contains("let mut items_vec: [Elem; 3] = [items_first; 3];"),
        "{src}"
    );
    assert!(
        src.contains("for slot in items_vec.iter_mut().skip(1)"),
        "{src}"
    );
}

/// And a zero-length one decodes nothing at all.
///
/// The seeding above is wrong for `N = 0`: it would read an element that is
/// not on the wire, taking the *next* field's bytes as this one's. `array<T,
/// 0>` is legal — `islc` accepts it — so the case is reachable rather than
/// hypothetical.
#[test]
fn a_zero_length_array_of_structs_reads_no_bytes() {
    let (ir, _) = compile(
        "library t.z;\
         struct Elem { a: uint32; };\
         @abi struct Holder { size: uint32; version: uint32; flags: uint64; \
         items: array<Elem, 0>; };",
    );
    let src = emit(&ir.expect("ir"));
    assert!(src.contains("let items: [Elem; 0] = [];"), "{src}");
    assert!(!src.contains("Elem::decode(r)"), "{src}");
}
