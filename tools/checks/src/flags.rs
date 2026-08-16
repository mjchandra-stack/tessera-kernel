// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **codegen-flag agreement gate**: a kernel binary is built with the same
//! flags whether the Bazel graph or the cargo inner loop built it.
//!
//! The flags exist in three places — `build/rules/kernel.bzl`, each kernel's own
//! `BUILD.bazel`, and `.cargo/config.toml` — and `.cargo/config.toml` says so
//! itself: *"Mirrors of the kernel codegen flags in build/rules/kernel.bzl."* A
//! mirror nothing checks is a mirror that drifts, and the drift is quiet in the
//! worst way: a missing `-Ccode-model` produces an image that links and does not
//! boot, on the inner loop only, long after the change that caused it.
//!
//! **Nothing here is a fourth list.** The architectures come from
//! `kernel.bzl`'s own table, the kernel packages from whichever `BUILD.bazel`
//! calls `tessera_kernel_binary`, and each cargo block is matched to its kernel
//! by the linker script it names — so an architecture added to the tree is an
//! architecture this gate already expects.
//!
//! Two flag classes are deliberately outside the comparison:
//!
//! - `--cfg=` / `--check-cfg=`. Feature selection is Bazel-only by construction
//!   (the cargo loop builds without the embedded ring-3 images and reports them
//!   absent), so these differing is the design rather than a drift.
//! - `-Clink-arg=-T…`. Both sides pass a linker script and spell the path
//!   differently — `$(location)` against a repo-relative path — so the gate
//!   matches on *which* script rather than on the text.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0"),
//! docs/hardware/01-platform-and-cpu-support.md ("Porting Rules")

use crate::{Violation, walk};
use std::collections::BTreeMap;
use std::path::Path;

/// Where the one per-architecture table lives.
pub const ARCH_TABLE: &str = "build/rules/arch.bzl";

/// The kernel rule, which reads that table and adds the linker script.
pub const KERNEL_RULES: &str = "build/rules/kernel.bzl";

/// The ring-3 rule, which reads the same table.
pub const USERSPACE_RULES: &str = "build/rules/userspace.bzl";

/// The cargo inner loop's mirror.
pub const CARGO_CONFIG: &str = ".cargo/config.toml";

/// One architecture as `ARCHITECTURES` describes it. `flags` is the kernel
/// side; the ring-3 flags are not compared against cargo, which builds no
/// ring-3 programs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArchEntry {
    pub cpu: String,
    pub platform: String,
    pub flags: Vec<String>,
}

/// One kernel binary as its `BUILD.bazel` declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBinary {
    pub package: String,
    pub arch: String,
    pub linker_script: String,
    pub rustc_flags: Vec<String>,
}

/// Whether a flag takes part in the comparison. See the module doc for the two
/// classes that do not.
pub fn is_compared(flag: &str) -> bool {
    !flag.starts_with("--cfg=")
        && !flag.starts_with("--check-cfg=")
        && !flag.starts_with("-Clink-arg=-T")
}

/// The flags of a build, reduced to the ones both sides must agree on.
fn compared(flags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = flags.iter().filter(|f| is_compared(f)).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// Every entry of an `ARCHITECTURES = { "name": struct(...) }` table.
pub fn architectures(bzl: &str) -> BTreeMap<String, ArchEntry> {
    let mut out = BTreeMap::new();
    let Some(table) = block_after(bzl, "ARCHITECTURES = {", "\n}") else {
        return out;
    };
    let mut key: Option<String> = None;
    let mut entry = ArchEntry::default();
    for line in table.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(": struct(") {
            key = quoted(trimmed).first().cloned();
            entry = ArchEntry::default();
        } else if trimmed == ")," {
            if let Some(name) = key.take() {
                out.insert(name, std::mem::take(&mut entry));
            }
        } else if let Some(value) = field(trimmed, "cpu") {
            entry.cpu = value;
        } else if let Some(value) = field(trimmed, "platform") {
            entry.platform = value;
        } else if trimmed.starts_with("kernel_flags = [") {
            entry.flags = quoted(trimmed);
        }
    }
    out
}

/// The flags every bare-metal binary gets, whatever its architecture.
pub fn common_flags(bzl: &str) -> Vec<String> {
    block_after(bzl, "COMMON_FLAGS = [", "\n]").map_or_else(Vec::new, quoted)
}

/// The `arch` a `tessera_kernel_binary` gets when its target does not say.
pub fn default_arch(bzl: &str) -> Option<String> {
    let signature = block_after(bzl, "def tessera_kernel_binary(", "):")?;
    signature
        .lines()
        .find_map(|line| field(line.trim(), "arch"))
}

/// Every kernel binary in the tree, found by the rule it calls rather than by a
/// list of packages.
pub fn kernel_binaries(root: &Path, default_arch: &str) -> Vec<KernelBinary> {
    let mut out = Vec::new();
    for (abs, rel) in walk::walk_files(root) {
        let Some(package) = rel.strip_suffix("/BUILD.bazel") else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&abs) else {
            continue;
        };
        let Some(call) = block_after(&text, "tessera_kernel_binary(", "\n)") else {
            continue;
        };
        let arch = call
            .lines()
            .find_map(|line| field(line.trim(), "arch"))
            .unwrap_or_else(|| default_arch.to_owned());
        let linker_script = call
            .lines()
            .find_map(|line| field(line.trim(), "linker_script"))
            .unwrap_or_default();
        out.push(KernelBinary {
            package: package.to_owned(),
            arch,
            linker_script,
            rustc_flags: block_after(call, "rustc_flags = [", "\n    ]")
                .map_or_else(Vec::new, quoted),
        });
    }
    out.sort_by(|a, b| a.package.cmp(&b.package));
    out
}

/// Each `[target.<triple>]` block's `rustflags`.
pub fn cargo_targets(toml: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for section in toml.split("\n[target.").skip(1) {
        let Some((triple, rest)) = section.split_once(']') else {
            continue;
        };
        let flags = block_after(rest, "rustflags = [", "\n]").map_or_else(Vec::new, quoted);
        out.insert(triple.trim().to_owned(), flags);
    }
    out
}

/// Checks the three tables against each other.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut violations = Vec::new();

    let Some(arch_bzl) = read(root, ARCH_TABLE, &mut violations) else {
        return violations;
    };
    let Some(kernel_bzl) = read(root, KERNEL_RULES, &mut violations) else {
        return violations;
    };
    let Some(cargo_toml) = read(root, CARGO_CONFIG, &mut violations) else {
        return violations;
    };

    let table = architectures(&arch_bzl);
    if table.is_empty() {
        violations.push(Violation {
            path: ARCH_TABLE.into(),
            reason: "no `ARCHITECTURES` table — gate misconfigured".into(),
        });
        return violations;
    }
    let common = common_flags(&arch_bzl);
    let default = default_arch(&kernel_bzl).unwrap_or_default();
    let binaries = kernel_binaries(root, &default);
    if binaries.is_empty() {
        violations.push(Violation {
            path: KERNEL_RULES.into(),
            reason: "no package calls `tessera_kernel_binary` — gate misconfigured".into(),
        });
        return violations;
    }
    let cargo = cargo_targets(&cargo_toml);

    for binary in &binaries {
        let Some(arch) = table.get(&binary.arch) else {
            violations.push(Violation {
                path: format!("{}/BUILD.bazel", binary.package),
                reason: format!(
                    "builds for arch `{}`, which {ARCH_TABLE} does not describe",
                    binary.arch
                ),
            });
            continue;
        };

        let mut bazel_flags = common.clone();
        bazel_flags.extend(arch.flags.iter().cloned());
        bazel_flags.extend(binary.rustc_flags.iter().cloned());
        let bazel_flags = compared(&bazel_flags);

        let script = format!("-Clink-arg=-T{}/{}", binary.package, binary.linker_script);
        let Some((triple, cargo_flags)) = cargo.iter().find(|(_, flags)| flags.contains(&script))
        else {
            violations.push(Violation {
                path: CARGO_CONFIG.into(),
                reason: format!(
                    "no [target.*] block links `{}/{}`, so the inner loop cannot build \
                     //{}",
                    binary.package, binary.linker_script, binary.package
                ),
            });
            continue;
        };
        let cargo_flags = compared(cargo_flags);

        for flag in bazel_flags.iter().filter(|f| !cargo_flags.contains(f)) {
            violations.push(Violation {
                path: CARGO_CONFIG.into(),
                reason: format!(
                    "[target.{triple}] is missing `{flag}`, which the Bazel graph gives \
                     //{}",
                    binary.package
                ),
            });
        }
        for flag in cargo_flags.iter().filter(|f| !bazel_flags.contains(f)) {
            violations.push(Violation {
                path: CARGO_CONFIG.into(),
                reason: format!(
                    "[target.{triple}] adds `{flag}`, which the Bazel graph does not give \
                     //{}",
                    binary.package
                ),
            });
        }
    }

    violations.extend(check_one_table(root));
    violations
}

/// There must be exactly one architecture table.
///
/// The kernel rule and the ring-3 rule each carried their own, and the two
/// agreed about the platform an architecture builds for only because nobody had
/// edited one of them. A rule that grows a table back is the drift this stops.
fn check_one_table(root: &Path) -> Vec<Violation> {
    let mut violations = Vec::new();
    for rel in [KERNEL_RULES, USERSPACE_RULES] {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            violations.push(Violation {
                path: rel.into(),
                reason: "unreadable — the flag gate cannot tell which table it reads".into(),
            });
            continue;
        };
        if text.contains("ARCHITECTURES = {") {
            violations.push(Violation {
                path: rel.into(),
                reason: format!(
                    "declares its own architecture table; there is one, in {ARCH_TABLE}"
                ),
            });
        }
    }
    violations
}

fn read(root: &Path, rel: &str, violations: &mut Vec<Violation>) -> Option<String> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(text) => Some(text),
        Err(_) => {
            violations.push(Violation {
                path: rel.into(),
                reason: "unreadable — the flag gate cannot compare the tables".into(),
            });
            None
        }
    }
}

/// The text between `open` and the next `close`, exclusive of both.
fn block_after<'a>(text: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = text.find(open)? + open.len();
    let rest = &text[start..];
    let end = rest.find(close)?;
    Some(&rest[..end])
}

/// The contents of every double-quoted run in `text`.
fn quoted(text: &str) -> Vec<String> {
    text.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The quoted value of `name = "…"` on a single line.
fn field(line: &str, name: &str) -> Option<String> {
    let rest = line.strip_prefix(name)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_owned())
}

#[cfg(test)]
#[path = "tests/flags.rs"]
mod tests;
