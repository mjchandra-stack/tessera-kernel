// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The C backend, checked for the things a C compiler cannot check for us.
//!
//! **The layout is not tested here, deliberately.** Every emitted struct
//! carries `_Static_assert`s for its size and each field's offset, and those
//! are checked by a C compiler on the target it compiles for
//! (`//api/abi:c_headers_conformance`). A Rust test asserting the same numbers
//! would be asserting that this file printed what it was given — which is true
//! and worth nothing. What is tested here is what the header *says*: that the
//! asserts are present, that the types are the ones the wire is defined in, and
//! that nothing out-of-line is quietly dropped.

use super::*;
use crate::compile;

fn header(src: &str) -> String {
    let (ir, diags) = compile(src);
    assert!(diags.is_empty(), "{diags:?}");
    emit(&ir.expect("ir"))
}

#[test]
fn a_frozen_struct_carries_a_size_and_an_offset_assert_per_field() {
    let out = header(
        "library tessera.t;\
         @abi struct Rec { size: uint32; version: uint32; flags: uint64; \
         n: uint32; pad: uint32; };",
    );
    assert!(out.contains("typedef struct tessera_t_rec_s {"), "{out}");
    assert!(
        out.contains("_Static_assert(sizeof(tessera_t_rec_t) == 24, \"Rec: wire size\");"),
        "{out}"
    );
    for (field, offset) in [
        ("size", 0),
        ("version", 4),
        ("flags", 8),
        ("n", 16),
        ("pad", 20),
    ] {
        let want = format!(
            "_Static_assert(offsetof(tessera_t_rec_t, {field}) == {offset}, \"Rec.{field}: wire offset\");"
        );
        assert!(out.contains(&want), "missing {want}\n{out}");
    }
}

/// The header is `#include`-safe: a guard, and only the two headers the wire
/// types need.
#[test]
fn the_header_is_self_contained_and_guarded() {
    let out = header(
        "library tessera.t;\n@abi struct R { size: uint32; version: uint32; flags: uint64; };",
    );
    assert!(out.contains("#ifndef TESSERA_T_H"), "{out}");
    assert!(out.contains("#define TESSERA_T_H"), "{out}");
    assert!(out.contains("#endif /* TESSERA_T_H */"), "{out}");
    assert!(out.contains("#include <stdint.h>"), "{out}");
    assert!(out.contains("#include <stddef.h>"), "{out}");
    // Nothing else. A header that pulled in more would make the ABI depend on
    // whatever that brought with it.
    assert_eq!(out.matches("#include").count(), 2, "{out}");
}

/// An enum is a typedef of its declared base plus constants, never a C `enum`:
/// an enum's underlying type is the implementation's choice and the wire's is
/// the schema's.
#[test]
fn an_enum_is_a_typedef_of_its_base_not_a_c_enum() {
    let out = header(
        "library tessera.t;\
         strict enum Colour : uint32 { RED = 1; BLUE = 7; };",
    );
    assert!(
        out.contains("typedef uint32_t tessera_t_colour_t;"),
        "{out}"
    );
    assert!(
        out.contains("#define TESSERA_T_COLOUR_RED ((tessera_t_colour_t)(1))"),
        "{out}"
    );
    assert!(
        out.contains("#define TESSERA_T_COLOUR_BLUE ((tessera_t_colour_t)(7))"),
        "{out}"
    );
    assert!(!out.contains("enum tessera_t_colour"), "{out}");
}

#[test]
fn a_handle_is_four_bytes_and_says_nothing_about_rights() {
    let out = header(
        "library tessera.t;\
         @abi struct H { size: uint32; version: uint32; flags: uint64; \
         who: handle<Object, {READ}>; pad: uint32; };",
    );
    assert!(out.contains("uint32_t who;"), "{out}");
    // The rights are a fact about who may hold it, not about its width.
    assert!(!out.contains("READ"), "{out}");
}

#[test]
fn an_array_puts_its_bound_after_the_name() {
    let out = header(
        "library tessera.t;\
         @abi struct A { size: uint32; version: uint32; flags: uint64; \
         bytes: array<uint8, 16>; };",
    );
    assert!(out.contains("uint8_t bytes[16];"), "{out}");
}

#[test]
fn a_nested_struct_is_the_nested_typedef() {
    let out = header(
        "library tessera.t;\
         @abi struct Inner { size: uint32; version: uint32; flags: uint64; };\
         @abi struct Outer { size: uint32; version: uint32; flags: uint64; \
         inner: Inner; };",
    );
    assert!(out.contains("tessera_t_inner_t inner;"), "{out}");
    // And the inner one is defined first, or the outer would not compile.
    let inner_at = out.find("typedef struct tessera_t_inner_s").expect("inner");
    let outer_at = out.find("typedef struct tessera_t_outer_s").expect("outer");
    assert!(inner_at < outer_at, "{out}");
}

/// What is out-of-line is named rather than silently dropped, so a reader of
/// the header knows the schema had more in it than this.
#[test]
fn out_of_line_declarations_are_named_rather_than_omitted_in_silence() {
    let out = header(
        "library tessera.t;\
         @abi struct R { size: uint32; version: uint32; flags: uint64; };\
         table T { 1: label: string:8; };",
    );
    assert!(out.contains("Not in the C ABI surface"), "{out}");
    assert!(out.contains("table T"), "{out}");
    // And no struct was emitted for it.
    assert!(!out.contains("tessera_t_t_t"), "{out}");
}

#[test]
fn a_syscall_becomes_one_number() {
    let out = header(
        "library tessera.t;\
         @status(implemented) syscall DebugWrite = 1 { arg0: uint64; returns: uint64; };",
    );
    assert!(
        out.contains("#define TESSERA_T_SYS_DEBUG_WRITE ((uint64_t)1)"),
        "{out}"
    );
}

#[test]
fn a_protocol_becomes_an_interface_id_and_its_ordinals() {
    let out = header(
        "library tessera.t;\
         @abi struct Req { size: uint32; version: uint32; flags: uint64; };\
         protocol P { 1: Go(Req); 2: Stop(); };",
    );
    assert!(out.contains("TESSERA_T_P_INTERFACE_ID"), "{out}");
    assert!(
        out.contains("#define TESSERA_T_P_GO ((uint32_t)1)"),
        "{out}"
    );
    assert!(
        out.contains("#define TESSERA_T_P_STOP ((uint32_t)2)"),
        "{out}"
    );
}

/// The name mangling, which is where the first version of this was wrong: an
/// already-shouting member came out as `_r_e_d`.
#[test]
fn a_name_splits_on_word_boundaries_not_on_every_capital() {
    assert_eq!(snake("RED"), "red");
    assert_eq!(snake("DiagnosticRecord"), "diagnostic_record");
    assert_eq!(snake("SYS_DebugWrite"), "sys_debug_write");
    assert_eq!(snake("P_INTERFACE_ID"), "p_interface_id");
    assert_eq!(snake("HTTPServer"), "http_server");
}

#[test]
fn the_output_is_byte_stable_across_runs() {
    let src =
        "library tessera.t;\n@abi struct R { size: uint32; version: uint32; flags: uint64; };";
    assert_eq!(header(src), header(src));
}

/// **Nothing is packed.** A packed struct would force the layout to agree and
/// prove nothing about whether the natural one already did — which is the whole
/// question the static asserts exist to answer.
#[test]
fn no_struct_is_packed() {
    let out = header(
        "library tessera.t;\
         @abi struct R { size: uint32; version: uint32; flags: uint64; };",
    );
    assert!(!out.contains("packed"), "{out}");
    assert!(!out.contains("#pragma pack"), "{out}");
}
