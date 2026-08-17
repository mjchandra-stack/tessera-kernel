// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for reading and writing profiles.

use super::*;
use crate::declare::parse_declaration;
use crate::resolve::resolve;

const DECL: &str = "\
[MAX_PROCESSES]
type = size
module = process
default = 16
range = 2..=256
doc = d
[gpu_driver]
type = component
machines = aarch64
default = y
doc = d
";

#[test]
fn a_profile_reads_numbers_and_switches() {
    let profile = parse_profile("MAX_PROCESSES = 4\ngpu_driver = n\n").expect("parses");
    assert_eq!(profile["MAX_PROCESSES"], Value::Int(4));
    assert_eq!(profile["gpu_driver"], Value::Bool(false));
}

#[test]
fn comments_and_blank_lines_are_not_settings() {
    let profile = parse_profile("# a comment\n\nMAX_PROCESSES = 4\n").expect("parses");
    assert_eq!(profile.len(), 1);
}

/// A setting given twice is a profile whose meaning depends on which line the
/// reader stopped at.
#[test]
fn a_setting_given_twice_is_refused() {
    let errors = parse_profile("A = 1\nA = 2\n").expect_err("twice");
    assert!(errors[0].message.contains("set twice"), "{errors:?}");
}

/// One spelling for on and off, so a diff between two profiles is about what
/// they say rather than how they say it.
#[test]
fn only_y_and_n_spell_on_and_off() {
    for text in ["A = true\n", "A = yes\n", "A = 1y\n"] {
        let errors = parse_profile(text).expect_err(text);
        assert!(
            errors[0].message.contains("neither a number nor"),
            "{errors:?}"
        );
    }
}

/// `savedefconfig`: what comes back out is only what differs from the
/// declaration, so a profile written by the menu reads like one written by
/// hand.
#[test]
fn writing_a_profile_records_only_what_differs_from_the_default() {
    let decl = parse_declaration(DECL).expect("parses");
    let overrides = parse_profile("MAX_PROCESSES = 4\ngpu_driver = y\n").expect("parses");
    let config = resolve(&decl, &overrides, "small").expect("resolves");
    let text = write_profile(&config, &[]);
    assert!(text.contains("MAX_PROCESSES = 4"), "{text}");
    // Named by the profile, but identical to the declared default: writing it
    // back out would record an opinion nobody has.
    assert!(!text.contains("gpu_driver"), "{text}");
}

#[test]
fn a_written_profile_keeps_the_header_it_was_given() {
    let decl = parse_declaration(DECL).expect("parses");
    let config = resolve(&decl, &parse_profile("").expect("p"), "default").expect("resolves");
    let header = vec![
        "SPDX-License-Identifier: Apache-2.0".to_owned(),
        String::new(),
        "Why this profile exists.".to_owned(),
    ];
    let text = write_profile(&config, &header);
    assert!(
        text.starts_with("# SPDX-License-Identifier: Apache-2.0\n#\n"),
        "{text}"
    );
    assert!(text.contains("# Why this profile exists."), "{text}");
}

/// A profile that names nothing is legal, and is what `default` is.
#[test]
fn a_profile_with_no_overrides_writes_back_as_its_header_alone() {
    let decl = parse_declaration(DECL).expect("parses");
    let config = resolve(&decl, &parse_profile("").expect("p"), "default").expect("resolves");
    assert_eq!(
        write_profile(&config, &["only this".to_owned()]),
        "# only this\n"
    );
}

/// Round trip: what a profile says, resolved and written back out, says the
/// same thing. A `savedefconfig` that lost an override would silently resize a
/// machine.
#[test]
fn writing_a_profile_and_reading_it_back_gives_the_same_configuration() {
    let decl = parse_declaration(DECL).expect("parses");
    let first = parse_profile("MAX_PROCESSES = 4\ngpu_driver = n\n").expect("parses");
    let config = resolve(&decl, &first, "small").expect("resolves");
    let round_tripped = parse_profile(&write_profile(&config, &[])).expect("re-reads");
    let again = resolve(&decl, &round_tripped, "small").expect("resolves");
    assert_eq!(config.values, again.values);
}
