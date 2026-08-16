// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `isl::parser`.

use super::*;

fn parse_ok(src: &str) -> Schema {
    let (schema, diags) = parse(src);
    assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");
    schema.expect("schema")
}

#[test]
fn parses_a_frozen_abi_struct() {
    let schema = parse_ok(
        "library t.abi;\n\
         bits Rights : uint64 { READ = 0x1; DUPLICATE = 0x4; };\n\
         struct DupArgs {\n\
           size: uint32;\n\
           version: uint32;\n\
           flags: uint64;\n\
           handle: handle<Object, {DUPLICATE}>;\n\
           new_rights: Rights;\n\
           reserved: array<uint8, 4>;\n\
         };\n",
    );
    assert_eq!(schema.library, "t.abi");
    assert_eq!(schema.decls.len(), 2);
    assert_eq!(schema.decls[1].name(), "DupArgs");
}

#[test]
fn parses_a_service_protocol() {
    let schema = parse_ok(
        "library t.svc;\n\
         protocol Echo {\n\
           1: Echo(struct { message: string:256; }) -> (struct { reply: string:256; });\n\
           2: Notify(struct { note: string:64; });\n\
           3: -> OnPing(struct { seq: uint64; });\n\
           4: reserved;\n\
         };\n",
    );
    let Decl::Protocol(p) = &schema.decls[0] else {
        panic!("expected protocol");
    };
    assert_eq!(p.methods.len(), 4);
    assert!(matches!(p.methods[0].kind, MethodKind::Call { .. }));
    assert!(matches!(p.methods[1].kind, MethodKind::OneWay { .. }));
    assert!(matches!(p.methods[2].kind, MethodKind::Event { .. }));
    assert!(matches!(p.methods[3].kind, MethodKind::Reserved));
}

#[test]
fn parses_annotations_and_tables() {
    let schema = parse_ok(
        "library t.tab;\n\
         @available(added=1)\n\
         table Profile {\n\
           1: @data_class(Health) heart_rate: uint32;\n\
           2: reserved;\n\
           3: name: string:64;\n\
         };\n",
    );
    let Decl::Table(t) = &schema.decls[0] else {
        panic!("expected table");
    };
    assert_eq!(t.availability.added, Some(1));
    assert_eq!(t.members.len(), 3);
}

#[test]
fn reports_error_and_recovers_to_next_decl() {
    // First struct is malformed (missing type); the second must still parse.
    let (schema, diags) = parse(
        "library t.rec;\n\
         struct Bad { x: ; };\n\
         struct Good { y: uint32; };\n",
    );
    assert!(!diags.is_empty());
    let schema = schema.expect("schema");
    assert!(schema.decls.iter().any(|d| d.name() == "Good"));
}

#[test]
fn missing_library_is_a_diagnostic() {
    let (_, diags) = parse("struct Foo { x: uint32; };\n");
    assert!(!diags.is_empty());
}

#[test]
fn parser_never_panics_on_arbitrary_input() {
    // A tiny seeded LCG generating random ASCII soup; the parser must
    // return diagnostics, never panic (docs/lifecycle/04, fuzz target for
    // parsers of external input; a libfuzzer target is deferred, D12).
    let mut state: u64 = 0x1234_5678_9abc_def0;
    let alphabet: &[u8] =
        b"library struct enum bits table union protocol handle vector array string \
          {}()<>:;,=@?-> 0123456789 abcXYZ_ .";
    for _ in 0..2000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = (state >> 33) as usize % 120;
        let mut s = String::new();
        let mut local = state;
        for _ in 0..len {
            local = local.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = (local >> 40) as usize % alphabet.len();
            s.push(alphabet[idx] as char);
        }
        let _ = parse(&s);
    }
}
