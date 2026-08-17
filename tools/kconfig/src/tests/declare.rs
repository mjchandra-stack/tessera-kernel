// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for reading the declaration.

use super::*;
use crate::Value;

const SIZE: &str = "\
[MAX_PROCESSES]
type = size
module = process
default = 16
range = 2..=256
doc = How many processes fit.
";

#[test]
fn a_complete_size_parses() {
    let decl = parse_declaration(SIZE).expect("parses");
    let setting = &decl["MAX_PROCESSES"];
    assert_eq!(setting.default, Value::Int(16));
    assert_eq!(
        setting.kind,
        Kind::Size {
            module: "process".to_owned(),
            min: 2,
            max: 256
        }
    );
    assert_eq!(setting.doc, vec!["How many processes fit.".to_owned()]);
    // No `machines` means every machine — one `kcore` is linked into all five
    // kernels, so a size that named machines would be claiming something the
    // build cannot honour.
    assert!(setting.applies_to("aarch64"));
    assert!(setting.applies_to("riscv32"));
}

#[test]
fn a_complete_feature_parses() {
    let text = "\
[SYSTEM_STORE]
type = feature
cfg = has_system_store
default = y
doc = The verified image store.
";
    let decl = parse_declaration(text).expect("parses");
    let setting = &decl["SYSTEM_STORE"];
    assert_eq!(
        setting.kind,
        Kind::Feature {
            cfg: "has_system_store".to_owned()
        }
    );
    assert_eq!(setting.default, Value::Bool(true));
}

#[test]
fn a_complete_component_parses() {
    let text = "\
[gpu_driver]
type = component
machines = aarch64, riscv64
default = y
doc = The GPU driver.
";
    let decl = parse_declaration(text).expect("parses");
    let setting = &decl["gpu_driver"];
    assert_eq!(setting.kind, Kind::Component);
    assert!(setting.applies_to("aarch64"));
    assert!(setting.applies_to("riscv64"));
    assert!(!setting.applies_to("x86_64"));
}

/// The whole point of a declaration is that a kind is stated rather than
/// guessed at from which fields happen to have parsed.
#[test]
fn a_setting_with_no_type_is_refused() {
    let text = "[A]\nmodule = m\ndefault = 1\nrange = 0..=2\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("no type");
    assert!(errors[0].message.contains("has no type"), "{errors:?}");
}

#[test]
fn a_setting_with_an_unknown_type_is_refused() {
    let text = "[A]\ntype = tristate\ndefault = 1\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("unknown type");
    assert!(
        errors[0].message.contains("not size, feature"),
        "{errors:?}"
    );
}

/// Every field a kind is missing is reported together: a section with two
/// mistakes should take one run to fix, not two.
#[test]
fn every_missing_field_is_named_at_once() {
    let text = "[A]\ntype = size\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("missing three");
    let message = &errors[0].message;
    assert!(message.contains("module"), "{message}");
    assert!(message.contains("range"), "{message}");
    assert!(message.contains("default"), "{message}");
}

/// A number whose reasoning stayed behind in the source it moved out of is the
/// thing this migration was for; an undocumented setting is refused.
#[test]
fn a_setting_with_no_doc_is_refused() {
    let text = "[A]\ntype = size\nmodule = m\ndefault = 1\nrange = 0..=2\n";
    let errors = parse_declaration(text).expect_err("no doc");
    assert!(
        errors.iter().any(|e| e.message.contains("no doc")),
        "{errors:?}"
    );
}

#[test]
fn a_default_outside_its_own_range_is_an_error() {
    let text = "[A]\ntype = size\nmodule = m\ndefault = 9\nrange = 0..=2\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("out of range");
    assert!(errors[0].message.contains("outside 0..=2"), "{errors:?}");
}

/// A field that belongs to another kind is a mistake about what the setting
/// *is*, and gets a sentence saying so rather than "unknown key".
#[test]
fn a_field_from_another_kind_says_which_kind_this_is() {
    let text = "\
[A]
type = feature
cfg = has_a
range = 0..=2
default = y
doc = d
";
    let errors = parse_declaration(text).expect_err("range on a feature");
    assert!(
        errors[0]
            .message
            .contains("is a feature and has no `range`"),
        "{errors:?}"
    );
}

/// A component with no machines is a program no image can carry, and the
/// machine list is what says an image for it exists at all.
#[test]
fn a_component_must_name_its_machines() {
    let text = "[a]\ntype = component\ndefault = y\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("no machines");
    assert!(errors[0].message.contains("machines"), "{errors:?}");
}

#[test]
fn an_on_off_default_is_only_y_or_n() {
    let text = "[a]\ntype = component\nmachines = m\ndefault = true\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("not y/n");
    assert!(errors[0].message.contains("`y` or `n`"), "{errors:?}");
}

#[test]
fn a_setting_declared_twice_is_an_error() {
    let errors = parse_declaration(&format!("{SIZE}{SIZE}")).expect_err("twice");
    assert!(errors.iter().any(|e| e.message.contains("declared twice")));
}

#[test]
fn an_unknown_key_is_an_error_rather_than_ignored() {
    let text = "[A]\ntype = size\nmodule = m\ndefault = 1\nrange = 0..=2\ndoc = d\nsize = 4\n";
    let errors = parse_declaration(text).expect_err("unknown key");
    assert!(
        errors
            .iter()
            .any(|e| e.message.contains("unknown key `size`")),
        "{errors:?}"
    );
}

#[test]
fn a_comparison_requirement_parses() {
    let text = format!("{SIZE}requires = MAX_PROCESSES >= 2\n");
    let decl = parse_declaration(&text).expect("parses");
    assert_eq!(
        decl["MAX_PROCESSES"].requires,
        vec![Requirement::Compare {
            left: Operand::Setting("MAX_PROCESSES".to_owned()),
            op: Op::Ge,
            right: Operand::Literal(2),
        }]
    );
}

/// `<=` must not be read as `<` followed by a right-hand side that starts with
/// `=`, which is what splitting on the one-character operator first would do.
#[test]
fn a_two_character_operator_is_not_read_as_one() {
    let text = format!("{SIZE}requires = MAX_PROCESSES <= 256\n");
    let decl = parse_declaration(&text).expect("parses");
    let Requirement::Compare { op, right, .. } = &decl["MAX_PROCESSES"].requires[0] else {
        panic!("not a comparison");
    };
    assert_eq!(*op, Op::Le);
    assert_eq!(*right, Operand::Literal(256));
}

#[test]
fn an_implication_requirement_parses() {
    let text = "\
[a]
type = component
machines = m
default = y
doc = d
requires = a -> b
[b]
type = component
machines = m
default = y
doc = d
";
    let decl = parse_declaration(text).expect("parses");
    assert_eq!(
        decl["a"].requires,
        vec![Requirement::Implies {
            left: "a".to_owned(),
            right: "b".to_owned()
        }]
    );
}

/// A requirement pointing at a renamed setting is an invariant that quietly
/// stopped being checked — the same failure the profile check catches, one
/// level up.
#[test]
fn a_requirement_naming_a_setting_that_does_not_exist_is_refused() {
    let text = format!("{SIZE}requires = MAX_PROCESSES <= MAX_GONE\n");
    let errors = parse_declaration(&text).expect_err("unknown name");
    assert!(
        errors[0].message.contains("`MAX_GONE` is not declared"),
        "{errors:?}"
    );
}

#[test]
fn a_requirement_that_is_not_a_relation_is_refused() {
    let text = format!("{SIZE}requires = MAX_PROCESSES\n");
    let errors = parse_declaration(&text).expect_err("not a relation");
    assert!(
        errors[0].message.contains("is not `A <op> B`"),
        "{errors:?}"
    );
}

#[test]
fn every_error_is_reported_not_just_the_first() {
    let text = "[A]\ntype = size\nmodule = m\ndefault = x\nrange = bad\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("two bad values");
    assert!(errors.len() >= 2, "{errors:?}");
}

#[test]
fn a_field_before_any_section_is_refused() {
    let errors = parse_declaration("default = 4\n").expect_err("no section");
    assert!(errors[0].message.contains("before any"), "{errors:?}");
}
