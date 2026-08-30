// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the boundary gate.

use super::*;

fn graph_of(edges: &[(&str, &[&str])]) -> Graph {
    edges
        .iter()
        .map(|(package, deps)| {
            (
                (*package).to_owned(),
                deps.iter().map(|d| (*d).to_owned()).collect(),
            )
        })
        .collect()
}

#[test]
fn a_direct_dependency_on_the_kernel_is_a_violation() {
    let graph = graph_of(&[
        ("userspace/probe", &["kernel/kcore"][..]),
        ("kernel/kcore", &[]),
    ]);
    let found = check_graph(&graph);
    assert_eq!(found.len(), 1);
    assert!(
        found[0]
            .reason
            .contains("//userspace/probe -> //kernel/kcore"),
        "the violation must name the path: {}",
        found[0].reason
    );
}

/// The case the gate exists for. One hop out is how it actually happened —
/// a driver on a device core, the device core on the architecture seam — and
/// a gate reading `deps` one line at a time would have called this clean.
#[test]
fn an_indirect_dependency_on_the_kernel_is_a_violation() {
    let graph = graph_of(&[
        ("userspace/blk-driver", &["drivers/virtio"][..]),
        ("drivers/virtio", &["kernel/karch"]),
        ("kernel/karch", &[]),
    ]);
    let found = check_graph(&graph);
    assert_eq!(found.len(), 1);
    assert!(
        found[0]
            .reason
            .contains("//userspace/blk-driver -> //drivers/virtio -> //kernel/karch"),
        "the violation must name every hop: {}",
        found[0].reason
    );
}

#[test]
fn a_user_program_on_the_abi_and_a_driver_core_is_clean() {
    let graph = graph_of(&[
        (
            "userspace/blk-driver",
            &["userspace/uabi", "drivers/virtio"][..],
        ),
        ("userspace/uabi", &[]),
        ("drivers/virtio", &[]),
        ("kernel/kcore", &["kernel/karch"]),
        ("kernel/karch", &[]),
    ]);
    assert_eq!(check_graph(&graph), Vec::new());
}

/// The kernel depending on a driver core is the arrow the rule permits: shared
/// device logic is shared, and only one direction of sharing is a violation.
#[test]
fn the_kernel_may_depend_on_a_driver_core() {
    let graph = graph_of(&[
        ("kernel/kernel-aarch64", &["drivers/virtio"][..]),
        ("drivers/virtio", &[]),
        ("userspace/blk-driver", &["drivers/virtio"]),
    ]);
    assert_eq!(check_graph(&graph), Vec::new());
}

#[test]
fn a_visibility_list_is_not_a_dependency() {
    let build = "rust_library(\n    name = \"virtio\",\n    visibility = [\n        \
                 \"//kernel:__subpackages__\",\n        \"//userspace/blk-driver:__pkg__\",\n    \
                 ],\n)\n";
    assert_eq!(dependencies(build), BTreeSet::new());
}

#[test]
fn a_single_string_visibility_is_not_a_dependency() {
    let build = "rust_library(\n    name = \"x\",\n    visibility = \"//kernel:__pkg__\",\n    \
                 deps = [\"//api/hash\"],\n)\n";
    assert_eq!(
        dependencies(build),
        ["api/hash".to_owned()].into_iter().collect()
    );
}

/// A documentation tree has to be able to name what it describes.
#[test]
fn a_label_in_a_comment_is_not_a_dependency() {
    let build = "# The ring-3 driver used to depend on //kernel/virtio.\nrust_library(\n    \
                 name = \"x\",\n    deps = [\"//userspace/uabi\"],\n)\n";
    assert_eq!(
        dependencies(build),
        ["userspace/uabi".to_owned()].into_iter().collect()
    );
}

/// A `#` inside a string is a property name, not the start of a comment —
/// device-tree property names look exactly like one.
#[test]
fn a_hash_inside_a_string_does_not_start_a_comment() {
    let build = "genrule(\n    name = \"x\",\n    cmd = \"echo '#address-cells'\",\n    \
                 tools = [\"//kernel/kcore\"],\n)\n";
    assert!(dependencies(build).contains("kernel/kcore"));
}

/// Every field, not just `deps`: `data` and `srcs` put a package in the
/// closure just as surely, and reading only `deps` would let a violation move
/// one field to the left.
#[test]
fn a_data_dependency_counts() {
    let build = "rust_test(\n    name = \"t\",\n    data = [\"//kernel/kcore:srcs\"],\n)\n";
    assert!(dependencies(build).contains("kernel/kcore"));
}

/// A cycle must not hang the walk, and a tree with cycles is a tree Bazel
/// would reject — so the gate has to survive reading one before Bazel does.
#[test]
fn a_cycle_terminates() {
    let graph = graph_of(&[
        ("userspace/a", &["userspace/b"][..]),
        ("userspace/b", &["userspace/a"]),
    ]);
    assert_eq!(check_graph(&graph), Vec::new());
}
