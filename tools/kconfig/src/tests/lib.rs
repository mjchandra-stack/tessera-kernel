// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the configuration surface.

use super::*;

const ONE: &str = "\
[MAX_PROCESSES]
module = process
default = 16
range = 2..=256
doc = How many processes fit.
";

#[test]
fn a_complete_tunable_parses() {
    let decl = parse_declaration(ONE).expect("parses");
    let t = &decl["MAX_PROCESSES"];
    assert_eq!((t.default, t.min, t.max), (16, 2, 256));
    assert_eq!(t.module, "process");
    assert_eq!(t.doc, vec!["How many processes fit.".to_owned()]);
}

#[test]
fn a_missing_field_is_an_error_rather_than_a_default() {
    let text = "[A]\nmodule = m\ndefault = 1\ndoc = why\n";
    let errors = parse_declaration(text).expect_err("no range");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("missing range"), "{errors:?}");
}

/// A number whose reasoning stayed behind in the source it moved out of is the
/// thing this migration was for; an undocumented tunable is refused.
#[test]
fn a_tunable_with_no_doc_is_refused() {
    let text = "[A]\nmodule = m\ndefault = 1\nrange = 0..=2\n";
    let errors = parse_declaration(text).expect_err("no doc");
    assert!(errors[0].message.contains("no doc"), "{errors:?}");
}

#[test]
fn a_default_outside_its_own_range_is_an_error() {
    let text = "[A]\nmodule = m\ndefault = 9\nrange = 0..=2\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("out of range");
    assert!(errors[0].message.contains("outside 0..=2"), "{errors:?}");
}

#[test]
fn a_tunable_declared_twice_is_an_error() {
    let errors = parse_declaration(&format!("{ONE}{ONE}")).expect_err("twice");
    assert!(errors.iter().any(|e| e.message.contains("declared twice")));
}

#[test]
fn an_unknown_key_is_an_error_rather_than_ignored() {
    let text = "[A]\nmodule = m\ndefault = 1\nrange = 0..=2\ndoc = d\nsize = 4\n";
    let errors = parse_declaration(text).expect_err("unknown key");
    assert!(
        errors[0].message.contains("unknown key `size`"),
        "{errors:?}"
    );
}

#[test]
fn every_error_is_reported_not_just_the_first() {
    let text = "[A]\nmodule = m\ndefault = x\nrange = bad\ndoc = d\n";
    let errors = parse_declaration(text).expect_err("two bad values");
    assert_eq!(errors.len(), 2, "{errors:?}");
}

#[test]
fn a_profile_overrides_only_what_it_names() {
    let decl = parse_declaration(ONE).expect("parses");
    let profile = parse_profile("MAX_PROCESSES = 4\n").expect("parses");
    let values = resolve(&decl, &profile).expect("resolves");
    assert_eq!(values["MAX_PROCESSES"], 4);
}

/// The one that matters most: a profile is refused, never clamped. Clamping
/// would build a kernel sized differently from the one that was asked for,
/// and nothing downstream could tell.
#[test]
fn a_profile_value_outside_the_range_is_refused_not_clamped() {
    let decl = parse_declaration(ONE).expect("parses");
    let profile = parse_profile("MAX_PROCESSES = 1\n").expect("parses");
    let errors = resolve(&decl, &profile).expect_err("below minimum");
    assert!(errors[0].message.contains("outside 2..=256"), "{errors:?}");
}

/// A profile naming a tunable that no longer exists would otherwise be
/// silently ignored, and the kernel built at a size nobody asked for.
#[test]
fn a_profile_naming_an_unknown_tunable_is_refused() {
    let decl = parse_declaration(ONE).expect("parses");
    let profile = parse_profile("MAX_GONE = 4\n").expect("parses");
    let errors = resolve(&decl, &profile).expect_err("unknown");
    assert!(errors[0].message.contains("unknown tunable"), "{errors:?}");
}

#[test]
fn the_emitted_crate_carries_the_value_and_its_reasoning() {
    let decl = parse_declaration(ONE).expect("parses");
    let values = resolve(&decl, &parse_profile("MAX_PROCESSES = 4\n").expect("p")).expect("r");
    let out = emit(&decl, &values, "small", Form::Included);
    assert!(out.contains("pub const MAX_PROCESSES: usize = 4;"), "{out}");
    assert!(out.contains("/// How many processes fit."), "{out}");
    assert!(out.contains("Range 2..=256, default 16."), "{out}");
    assert!(out.contains("profile `small`"), "{out}");
    assert!(
        !out.contains("#![no_std]"),
        "an included file carries no inner attribute"
    );
}

/// The one difference between the two forms, asserted rather than assumed:
/// Bazel links a crate that needs `#![no_std]`, cargo includes text that
/// cannot carry it.
#[test]
fn only_the_crate_form_carries_the_inner_attribute() {
    let decl = parse_declaration(ONE).expect("parses");
    let values = resolve(&decl, &BTreeMap::new()).expect("r");
    assert!(emit(&decl, &values, "d", Form::Crate).contains("#![no_std]"));
    assert!(!emit(&decl, &values, "d", Form::Included).contains("#![no_std]"));
}
