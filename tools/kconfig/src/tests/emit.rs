// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for what a resolved configuration turns into.

use super::*;
use crate::declare::parse_declaration;
use crate::profile::parse_profile;
use crate::resolve::resolve;

const DECL: &str = "\
[MAX_PROCESSES]
type = size
module = process
default = 16
range = 2..=256
doc = How many processes fit.
[SYSTEM_STORE]
type = feature
cfg = has_system_store
default = y
doc = d
[gpu_driver]
type = component
machines = aarch64
default = y
doc = d
[blk_driver]
type = component
machines = aarch64
default = y
doc = d
";

fn config(profile: &str, name: &str) -> (crate::Declaration, crate::profile::Overrides) {
    let decl = parse_declaration(DECL).expect("parses");
    let overrides = parse_profile(profile).expect("parses");
    // Resolving here as well proves the fixture is one the build would accept.
    resolve(&decl, &overrides, name).expect("resolves");
    (decl, overrides)
}

fn catalog() -> BTreeMap<String, String> {
    [
        ("gpu_driver".to_owned(), "gpu_driver_image".to_owned()),
        ("blk_driver".to_owned(), "blk_driver_image".to_owned()),
    ]
    .into_iter()
    .collect()
}

#[test]
fn the_emitted_constants_carry_the_value_and_its_reasoning() {
    let (decl, overrides) = config("MAX_PROCESSES = 4\n", "small");
    let resolved = resolve(&decl, &overrides, "small").expect("resolves");
    let out = emit(&resolved, Form::Included);
    assert!(out.contains("pub const MAX_PROCESSES: usize = 4;"), "{out}");
    assert!(out.contains("/// How many processes fit."), "{out}");
    assert!(out.contains("Range 2..=256, default 16."), "{out}");
    assert!(out.contains("profile `small`"), "{out}");
}

/// Only sizes become constants. A feature is a `#[cfg]` and a component is a
/// byte slice, and neither is a number the kernel reads.
#[test]
fn only_sizes_become_constants() {
    let (decl, overrides) = config("", "default");
    let out = emit(
        &resolve(&decl, &overrides, "default").expect("r"),
        Form::Included,
    );
    assert!(!out.contains("SYSTEM_STORE"), "{out}");
    assert!(!out.contains("gpu_driver"), "{out}");
}

/// The one difference between the two forms, asserted rather than assumed:
/// Bazel links a crate that needs `#![no_std]`, cargo includes text that
/// cannot carry it.
#[test]
fn only_the_crate_form_carries_the_inner_attribute() {
    let (decl, overrides) = config("", "default");
    let resolved = resolve(&decl, &overrides, "default").expect("r");
    assert!(emit(&resolved, Form::Crate).contains("#![no_std]"));
    assert!(!emit(&resolved, Form::Included).contains("#![no_std]"));
}

#[test]
fn a_component_that_is_on_reads_its_image_crate() {
    let (decl, overrides) = config("", "default");
    let resolved = resolve(&decl, &overrides, "default").expect("r");
    let out = emit_components(&resolved, "aarch64", &catalog()).expect("emits");
    assert!(
        out.contains("pub fn gpu_driver() -> &'static [u8] {"),
        "{out}"
    );
    assert!(out.contains("&gpu_driver_image::GPU_DRIVER_ELF"), "{out}");
}

/// A component that is off keeps its accessor and returns nothing — the
/// absence every check already reports. Nothing references the image crate, so
/// the linker never pulls the program's bytes into the image.
#[test]
fn a_component_that_is_off_keeps_its_accessor_and_names_no_crate() {
    let (decl, overrides) = config("gpu_driver = n\n", "small");
    let resolved = resolve(&decl, &overrides, "small").expect("r");
    let out = emit_components(&resolved, "aarch64", &catalog()).expect("emits");
    assert!(
        out.contains("pub fn gpu_driver() -> &'static [u8] {"),
        "{out}"
    );
    assert!(!out.contains("GPU_DRIVER_ELF"), "{out}");
    // The one that is still on is untouched by the other being off.
    assert!(out.contains("&blk_driver_image::BLK_DRIVER_ELF"), "{out}");
}

/// Bazel must know the image labels statically, so the catalog stays in
/// Starlark and the selection comes from the declaration — and the two are held
/// to each other in both directions.
#[test]
fn an_image_the_declaration_does_not_know_about_is_refused() {
    let (decl, overrides) = config("", "default");
    let resolved = resolve(&decl, &overrides, "default").expect("r");
    let mut catalog = catalog();
    catalog.insert("mystery".to_owned(), "mystery_image".to_owned());
    let errors = emit_components(&resolved, "aarch64", &catalog).expect_err("undeclared");
    assert!(errors[0].message.contains("does not declare"), "{errors:?}");
}

#[test]
fn a_declared_component_with_no_image_is_refused() {
    let (decl, overrides) = config("", "default");
    let resolved = resolve(&decl, &overrides, "default").expect("r");
    let mut catalog = catalog();
    catalog.remove("gpu_driver");
    let errors = emit_components(&resolved, "aarch64", &catalog).expect_err("no image");
    assert!(
        errors[0].message.contains("has no image for it"),
        "{errors:?}"
    );
}

/// A machine's crate holds that machine's programs. A port naming one its
/// machine has no image for fails to compile, which is the property the
/// generated crate has always had and must keep.
#[test]
fn a_machine_gets_only_its_own_programs() {
    let (decl, overrides) = config("", "default");
    let resolved = resolve(&decl, &overrides, "default").expect("r");
    let out = emit_components(&resolved, "riscv64", &BTreeMap::new()).expect("emits");
    assert!(!out.contains("pub fn gpu_driver"), "{out}");
}
