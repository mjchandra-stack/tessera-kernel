// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **boundary gate**: a user-space program's only path to the kernel is
//! the ABI.
//!
//! `userspace/uabi` is what a user program is supposed to know about the kernel
//! — the syscall numbers, the argument encodings, the error words — and every
//! other kernel crate is supposed to be unreachable from user space. That was
//! never true and nothing said so: seven device-logic crates lived under
//! `kernel/` and nine user-space packages depended on them, which meant the
//! boundary a repository split has to be affordable across (docs/roadmap/03,
//! Phase 4) existed only as an intention.
//!
//! So the rule is stated as a graph reachability question rather than as a list
//! of forbidden edges. **No package under `userspace/` may reach a package
//! under `kernel/`, by any path.** A direct dependency is the obvious way to
//! break it; the way that actually happened is one hop further out — a driver
//! depending on a device core that depended on the architecture seam — and a
//! gate that only read `deps` lines one at a time would have called that clean.
//!
//! Two things this reads and one it does not:
//!
//! - **Every `//…` label in every `BUILD.bazel`** is an edge, whatever field it
//!   sits in. `data`, `srcs` and `deps` all put a package in a target's
//!   dependency closure, and distinguishing them would only invite a violation
//!   to move fields.
//! - **`visibility` lists are not edges.** They name who may depend on *this*
//!   package, which is the arrow pointing the other way; reading them as
//!   dependencies would make every driver core look like it depended on the
//!   kernel it is depended on by.
//! - **Comments are not edges either**, so prose may name `//kernel/kcore`
//!   without being a violation. It is a documentation tree; it has to be able
//!   to say what it is describing.
//!
//! Normative: docs/roadmap/03-composition-and-self-hosting.md ("Phase 4"),
//! docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0")

use crate::{Violation, walk};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

/// The tree a user program must not reach into.
pub const KERNEL_TREE: &str = "kernel/";

/// The tree the rule is stated about.
pub const USER_TREE: &str = "userspace/";

/// Package path → the packages its `BUILD.bazel` names.
pub type Graph = BTreeMap<String, BTreeSet<String>>;

/// Whether `package` is one of the two trees this gate separates.
fn in_tree(package: &str, tree: &str) -> bool {
    package.starts_with(tree)
}

/// Strips `#` comments, honouring quotes so a `"#address-cells"` inside a
/// string is not read as the start of one.
fn strip_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.lines() {
        let mut quoted = false;
        let mut cut = line.len();
        for (at, byte) in line.bytes().enumerate() {
            match byte {
                b'"' => quoted = !quoted,
                b'#' if !quoted => {
                    cut = at;
                    break;
                }
                _ => {}
            }
        }
        out.push_str(&line[..cut]);
        out.push('\n');
    }
    out
}

/// Removes every `visibility = …` / `default_visibility = …` value, so the
/// labels naming who may depend on this package are not read as dependencies.
fn strip_visibility(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut at = 0usize;
    while at < content.len() {
        let Some(found) = content[at..].find("visibility") else {
            out.push_str(&content[at..]);
            break;
        };
        let start = at + found;
        out.push_str(&content[at..start]);
        let mut cursor = start + "visibility".len();
        // The keyword, then `=`, then either a list or a single string.
        while bytes.get(cursor).is_some_and(|b| b.is_ascii_whitespace()) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            // Not an assignment — a word inside prose the comment strip left.
            out.push_str(&content[start..cursor]);
            at = cursor;
            continue;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(|b| b.is_ascii_whitespace()) {
            cursor += 1;
        }
        let close = match bytes.get(cursor) {
            Some(b'[') => b']',
            Some(b'"') => b'"',
            // An assignment whose value is a name (`visibility = PUBLIC`);
            // it carries no label, so there is nothing to remove.
            _ => {
                at = cursor;
                continue;
            }
        };
        if close == b'"' {
            cursor += 1;
        }
        match content[cursor..].find(close as char) {
            Some(end) => at = cursor + end + 1,
            None => break,
        }
    }
    out
}

/// The packages one `BUILD.bazel` body names as dependencies.
pub fn dependencies(content: &str) -> BTreeSet<String> {
    let body = strip_visibility(&strip_comments(content));
    body.split('"')
        .skip(1)
        .step_by(2)
        .filter_map(|label| label.strip_prefix("//"))
        .map(|label| label.split(':').next().unwrap_or(label).to_owned())
        .filter(|package| !package.is_empty())
        .collect()
}

/// Builds the package dependency graph of the tree under `root`.
pub fn graph(root: &Path) -> Graph {
    let mut out = Graph::new();
    for (abs, rel) in walk::walk_files(root) {
        let Some(dir) = rel.strip_suffix("BUILD.bazel") else {
            continue;
        };
        let package = dir.trim_end_matches('/').to_owned();
        let Ok(content) = std::fs::read_to_string(&abs) else {
            continue;
        };
        out.insert(package, dependencies(&content));
    }
    out
}

/// The shortest path from `from` to a package in `tree`, or `None` if the tree
/// is unreachable. Breadth-first, so what a violation reports is the shortest
/// explanation rather than whichever one the walk found first.
pub fn path_into(graph: &Graph, from: &str, tree: &str) -> Option<Vec<String>> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut came_from: BTreeMap<&str, &str> = BTreeMap::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    seen.insert(from);
    queue.push_back(from);

    while let Some(package) = queue.pop_front() {
        if package != from && in_tree(package, tree) {
            let mut chain = vec![package.to_owned()];
            let mut step = package;
            while let Some(previous) = came_from.get(step) {
                chain.push((*previous).to_owned());
                step = previous;
            }
            chain.reverse();
            return Some(chain);
        }
        for next in graph.get(package).into_iter().flatten() {
            if seen.insert(next) {
                came_from.insert(next, package);
                queue.push_back(next);
            }
        }
    }
    None
}

/// Every user-space package that can reach the kernel tree, with the path.
pub fn check_graph(graph: &Graph) -> Vec<Violation> {
    let mut out = Vec::new();
    for package in graph.keys().filter(|p| in_tree(p, USER_TREE)) {
        let Some(chain) = path_into(graph, package, KERNEL_TREE) else {
            continue;
        };
        let route = chain
            .iter()
            .map(|step| format!("//{step}"))
            .collect::<Vec<_>>()
            .join(" -> ");
        out.push(Violation {
            path: format!("{package}/BUILD.bazel"),
            reason: format!(
                "reaches the kernel tree: {route}. A user program's only path to the kernel is \
                 //userspace/uabi and the generated bindings; device logic a driver shares with \
                 a port belongs under //drivers"
            ),
        });
    }
    out
}

/// Checks the tree under `root`.
pub fn check(root: &Path) -> Vec<Violation> {
    check_graph(&graph(root))
}

#[cfg(test)]
#[path = "tests/boundary.rs"]
mod tests;
