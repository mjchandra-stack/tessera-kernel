// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for applying a profile, and for the refusals that keeps.

use super::*;
use crate::declare::parse_declaration;
use crate::profile::parse_profile;

const DECL: &str = "\
[MAX_PROCESSES]
type = size
module = process
default = 16
range = 2..=256
doc = d
[MAX_THREADS]
type = size
module = sched
default = 16
range = 2..=256
doc = d
[MAX_WAITERS]
type = size
module = wait
default = 16
range = 1..=256
doc = d
requires = MAX_WAITERS >= MAX_THREADS
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
[gpu_client]
type = component
machines = aarch64
default = y
doc = d
requires = gpu_client -> gpu_driver
[blk_driver]
type = component
machines = aarch64, riscv64
default = y
doc = d
";

fn config_of(text: &str) -> Result<(Declaration, crate::profile::Overrides), String> {
    let decl = parse_declaration(DECL).map_err(|e| format!("{e:?}"))?;
    let overrides = parse_profile(text).map_err(|e| format!("{e:?}"))?;
    Ok((decl, overrides))
}

#[test]
fn a_profile_overrides_only_what_it_names() {
    let (decl, overrides) = config_of("MAX_PROCESSES = 4\n").expect("reads");
    let config = resolve(&decl, &overrides, "small").expect("resolves");
    assert_eq!(config.get("MAX_PROCESSES"), Some(Value::Int(4)));
    assert_eq!(config.get("MAX_THREADS"), Some(Value::Int(16)));
}

/// The one that matters most: a profile is refused, never clamped. Clamping
/// would build a kernel sized differently from the one that was asked for,
/// and nothing downstream could tell.
#[test]
fn a_size_outside_the_range_is_refused_not_clamped() {
    let (decl, overrides) = config_of("MAX_PROCESSES = 1\n").expect("reads");
    let errors = resolve(&decl, &overrides, "small").expect_err("below minimum");
    assert!(errors[0].message.contains("outside 2..=256"), "{errors:?}");
}

/// A profile naming a setting that no longer exists would otherwise be
/// silently ignored, and the kernel built as something nobody asked for.
#[test]
fn a_profile_naming_an_unknown_setting_is_refused() {
    let (decl, overrides) = config_of("MAX_GONE = 4\n").expect("reads");
    let errors = resolve(&decl, &overrides, "small").expect_err("unknown");
    assert!(errors[0].message.contains("unknown setting"), "{errors:?}");
}

#[test]
fn a_switch_where_a_size_belongs_is_refused() {
    let (decl, overrides) = config_of("MAX_PROCESSES = y\n").expect("reads");
    let errors = resolve(&decl, &overrides, "small").expect_err("wrong kind");
    assert!(errors[0].message.contains("is a size"), "{errors:?}");
}

#[test]
fn a_size_where_a_switch_belongs_is_refused() {
    let (decl, overrides) = config_of("gpu_driver = 4\n").expect("reads");
    let errors = resolve(&decl, &overrides, "small").expect_err("wrong kind");
    assert!(errors[0].message.contains("is on or off"), "{errors:?}");
}

/// The invariant `config/kernel.config` used to state in prose: the waiter set
/// is sized to the scheduler's thread table. A profile that raises one without
/// the other is refused rather than producing a machine whose threads cannot
/// all block.
#[test]
fn a_profile_that_breaks_a_numeric_invariant_is_refused() {
    let (decl, overrides) = config_of("MAX_THREADS = 32\n").expect("reads");
    let errors = resolve(&decl, &overrides, "small").expect_err("waiters too small");
    assert!(
        errors[0].message.contains("MAX_WAITERS >= MAX_THREADS"),
        "{errors:?}"
    );
}

/// Raising both together is legal, and must not be refused for the order the
/// lines happen to be in — which is why invariants are checked against the
/// whole resolved set rather than as each override lands.
#[test]
fn raising_two_settings_together_is_accepted() {
    let (decl, overrides) = config_of("MAX_THREADS = 32\nMAX_WAITERS = 32\n").expect("reads");
    resolve(&decl, &overrides, "bigger").expect("resolves");
}

/// A client with no driver is a program that will wait for a service nobody
/// offers.
#[test]
fn a_profile_that_breaks_an_implication_is_refused() {
    let (decl, overrides) = config_of("gpu_driver = n\n").expect("reads");
    let errors = resolve(&decl, &overrides, "small").expect_err("client without driver");
    assert!(
        errors[0]
            .message
            .contains("is on while `gpu_driver` is off"),
        "{errors:?}"
    );
}

#[test]
fn turning_off_both_halves_of_an_implication_is_accepted() {
    let (decl, overrides) = config_of("gpu_driver = n\ngpu_client = n\n").expect("reads");
    resolve(&decl, &overrides, "small").expect("resolves");
}

#[test]
fn a_machine_sees_only_the_components_it_has_an_image_for() {
    let (decl, overrides) = config_of("").expect("reads");
    let config = resolve(&decl, &overrides, "default").expect("resolves");
    let riscv = config.components_for("riscv64");
    assert!(riscv.contains_key("blk_driver"));
    assert!(!riscv.contains_key("gpu_driver"));
    assert_eq!(config.components_for("aarch64").len(), 3);
}

/// A feature that is off contributes nothing rather than a negated flag: the
/// ports read `#[cfg(has_x)]` / `#[cfg(not(has_x))]`, so absence is already how
/// off is spelled.
#[test]
fn a_feature_that_is_off_emits_no_flag() {
    let (decl, on) = config_of("").expect("reads");
    let config = resolve(&decl, &on, "default").expect("resolves");
    assert_eq!(config.cfg_flags("aarch64"), vec!["has_system_store"]);

    let (decl, off) = config_of("SYSTEM_STORE = n\n").expect("reads");
    let config = resolve(&decl, &off, "bare").expect("resolves");
    assert!(config.cfg_flags("aarch64").is_empty());
}

/// The `.config` this tree has never had: every value, and where it came from.
#[test]
fn the_resolved_configuration_records_where_each_value_came_from() {
    let (decl, overrides) = config_of("MAX_PROCESSES = 4\n").expect("reads");
    let config = resolve(&decl, &overrides, "small").expect("resolves");
    let text = config.show(Some("aarch64"));
    assert!(text.contains("# profile: small"), "{text}");
    assert!(text.contains("# machine: aarch64"), "{text}");
    assert!(text.contains("MAX_PROCESSES = 4    # profile"), "{text}");
    assert!(text.contains("MAX_THREADS = 16    # default"), "{text}");

    // A machine's `.config` lists what that machine has, and nothing else:
    // RISC-V 64 has an image for the block driver and none for the GPU.
    let riscv = config.show(Some("riscv64"));
    assert!(riscv.contains("blk_driver"), "{riscv}");
    assert!(!riscv.contains("gpu_driver"), "{riscv}");
}

/// Name order interleaves the modules, so anything printing a heading per group
/// needs the reading order instead — or it prints the same heading twice.
#[test]
fn each_group_heading_appears_once() {
    let (decl, overrides) = config_of("").expect("reads");
    let config = resolve(&decl, &overrides, "default").expect("resolves");
    let text = config.show(None);
    assert_eq!(text.matches("# --- components ---").count(), 1, "{text}");
    assert_eq!(
        text.matches("# --- kcore::process ---").count(),
        1,
        "{text}"
    );
}

#[test]
fn a_diff_names_only_what_two_profiles_disagree_about() {
    let (decl, left) = config_of("MAX_PROCESSES = 4\n").expect("reads");
    let (_, right) =
        config_of("MAX_PROCESSES = 8\ngpu_driver = n\ngpu_client = n\n").expect("reads");
    let a = resolve(&decl, &left, "a").expect("resolves");
    let b = resolve(&decl, &right, "b").expect("resolves");
    let differences = crate::resolve::diff(&a, &b);
    let names: Vec<&str> = differences.iter().map(|(n, _, _)| n.as_str()).collect();
    assert_eq!(names, ["MAX_PROCESSES", "gpu_client", "gpu_driver"]);
}
