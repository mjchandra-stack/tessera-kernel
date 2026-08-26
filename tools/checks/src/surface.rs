// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **interface-surface gate**: the three places the system call surface is
//! written down are held against each other, so that none of them can quietly
//! stop being true.
//!
//! **Why a gate rather than a document.** The surface has drifted once
//! already, measurably. `syscall_abi.isl` declared six calls of the fifty that
//! had arrived and carried a header saying the bindings were "ready to wire
//! when user-mode ABI stabilizes" — true when six was the whole set, and false
//! for the forty-four that came after. `docs/api/01` described about twenty
//! call families and marked none of them, so a reader could not tell which
//! existed. The one accurate reference was 209 lines of doc comment on
//! `SyscallNumber`, readable only from inside the kernel by somebody who
//! already had the source. Each of those is a document that was true when it
//! was written; what none of them had was anything that fails when they stop
//! agreeing. Ungated, the surface drifts back within three milestones, which
//! is exactly what it did between D54 and D248.
//!
//! **The four agreements.**
//!
//! - **Every `SyscallNumber` variant is a `syscall` in the schema**, at the
//!   same number, under the same name, with a non-empty description — and the
//!   reverse, so the schema cannot describe a call the kernel does not answer.
//!   This is the one that matters: it makes adding a syscall without
//!   documenting it impossible rather than discouraged.
//! - **The schema's `enum Syscall` matches its own `syscall` declarations.**
//!   The enum exists for a decoder that only needs to name a number; two
//!   spellings of the surface in one file is exactly the shape that rots.
//! - **Every `extern struct N from L` resolves** to an `@abi struct N` in the
//!   library `L`. ISL has no imports and deliberately grew none for this
//!   (`ExternDecl` says why); this gate is what a module system would have
//!   done at compile time, done once across the schema set instead.
//! - **Every family in `docs/api/01` states a status.** That document is a
//!   design document and stays free to describe what does not exist — its job
//!   — but it has to say which is which, or it can be trusted as neither
//!   design nor reference.
//!
//! The gate reads the schema through the ISL compiler rather than by matching
//! text, so it cannot disagree with the compiler about what a schema says.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0"),
//! docs/api/01-system-call-interface.md,
//! docs/api/03-interface-schema-language.md ("Generated Artifacts")
//! Budget: none (build-time tooling)

use crate::Violation;
use std::collections::BTreeMap;
use std::path::Path;
use tessera_isl::ast::Status;
use tessera_isl::ir::{Ir, IrDecl};

/// The kernel's call-number enumeration: the surface as the kernel implements
/// it.
pub const SYSCALL_SOURCE: &str = "kernel/kcore/src/syscall.rs";

/// The call surface as ISL declares it.
pub const SYSCALL_SCHEMA: &str = "api/isl/examples/syscall_abi.isl";

/// Where every schema lives, for resolving `extern` references.
pub const SCHEMA_DIR: &str = "api/isl/examples";

/// The design document whose families must each state a status.
pub const FAMILIES_DOC: &str = "docs/api/01-system-call-interface.md";

/// The heading the checked region of [`FAMILIES_DOC`] starts at.
const FAMILIES_HEADING: &str = "## System Call Families";

/// The statuses a family may claim. `partial` is the one the schema has no use
/// for and the document cannot do without: a family is a group of operations,
/// and "Memory" lists twenty operations of which thirteen exist. A family forced to choose
/// between implemented and designed would have to lie either way.
const FAMILY_STATUSES: &[&str] = &["implemented", "partial", "designed", "deferred"];

/// How a family declares its status: the first non-blank line under the
/// heading. A fixed prefix rather than a free sentence, because a reader
/// filtering for what exists needs to match on something.
const STATUS_PREFIX: &str = "**Status: ";

/// One variant of the kernel's `SyscallNumber`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustCall {
    pub name: String,
    pub number: u64,
    /// Non-empty doc-comment lines above the variant.
    pub doc_lines: usize,
    /// 1-based line of the variant, for error reporting.
    pub line: usize,
}

/// One family heading in [`FAMILIES_DOC`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
    pub title: String,
    /// The status word it claims, or `None` when it claims none.
    pub status: Option<String>,
    pub line: usize,
}

/// Runs every agreement, returning what disagrees.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut violations = Vec::new();

    let rust_src = match read(root, SYSCALL_SOURCE, &mut violations) {
        Some(src) => src,
        None => return violations,
    };
    let (rust_calls, mut v) = parse_rust_calls(&rust_src);
    violations.append(&mut v);

    let schema_src = match read(root, SYSCALL_SCHEMA, &mut violations) {
        Some(src) => src,
        None => return violations,
    };
    let (ir, diags) = tessera_isl::compile(&schema_src);
    let Some(ir) = ir else {
        for diag in diags.iter() {
            violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!("schema does not compile: {diag}"),
            });
        }
        return violations;
    };

    violations.append(&mut check_calls(&rust_calls, &ir));
    violations.append(&mut check_enum_agrees(&ir));
    violations.append(&mut check_externs(root, &ir));

    if let Some(doc) = read(root, FAMILIES_DOC, &mut violations) {
        let (_, mut v) = check_families(FAMILIES_DOC, &doc);
        violations.append(&mut v);
    }
    violations
}

fn read(root: &Path, rel: &str, violations: &mut Vec<Violation>) -> Option<String> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(src) => Some(src),
        Err(err) => {
            violations.push(Violation {
                path: rel.to_owned(),
                reason: format!("cannot read: {err}"),
            });
            None
        }
    }
}

/// The `syscall` declarations of a compiled schema, by name.
fn schema_calls(ir: &Ir) -> BTreeMap<&str, &tessera_isl::ir::IrSyscall> {
    ir.decls
        .iter()
        .filter_map(|d| match d {
            IrDecl::Syscall(s) => Some((s.name.as_str(), s)),
            _ => None,
        })
        .collect()
}

/// Parses `pub enum SyscallNumber { ... }` out of the kernel source: each
/// variant's name, explicit discriminant, and how many doc lines describe it.
///
/// Text rather than a Rust parser, for the reason every gate here is text: a
/// tier-0 gate with a syntax-tree dependency is a gate that stops running when
/// the dependency does. The shape it reads is narrow and enforced — a variant
/// without an explicit discriminant is reported rather than counted, because
/// this enum's numbers are ABI and an implicit one is a number nobody wrote.
pub fn parse_rust_calls(src: &str) -> (Vec<RustCall>, Vec<Violation>) {
    let mut calls = Vec::new();
    let mut violations = Vec::new();
    let mut inside = false;
    let mut doc_lines = 0usize;

    for (index, raw) in src.lines().enumerate() {
        let line = raw.trim();
        if !inside {
            if line.starts_with("pub enum SyscallNumber") {
                inside = true;
            }
            continue;
        }
        if line == "}" {
            break;
        }
        if let Some(text) = line.strip_prefix("///") {
            if !text.trim().is_empty() {
                doc_lines += 1;
            }
            continue;
        }
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        let entry = line.trim_end_matches(',');
        let Some((name, value)) = entry.split_once('=') else {
            violations.push(Violation {
                path: SYSCALL_SOURCE.to_owned(),
                reason: format!(
                    "line {}: `{entry}` has no explicit discriminant; a call number is ABI and \
                     cannot be left to the compiler",
                    index + 1
                ),
            });
            doc_lines = 0;
            continue;
        };
        let name = name.trim().to_owned();
        match value.trim().parse::<u64>() {
            Ok(number) => calls.push(RustCall {
                name,
                number,
                doc_lines,
                line: index + 1,
            }),
            Err(_) => violations.push(Violation {
                path: SYSCALL_SOURCE.to_owned(),
                reason: format!(
                    "line {}: `{entry}` has a discriminant that is not a number",
                    index + 1
                ),
            }),
        }
        doc_lines = 0;
    }

    if calls.is_empty() {
        violations.push(Violation {
            path: SYSCALL_SOURCE.to_owned(),
            reason: "no `pub enum SyscallNumber` variants found — the gate is reading the wrong \
                     shape and would report clean on anything"
                .to_owned(),
        });
    }
    (calls, violations)
}

/// The kernel's variants and the schema's calls describe the same set, at the
/// same numbers, and every one of them is described.
fn check_calls(rust: &[RustCall], ir: &Ir) -> Vec<Violation> {
    let mut violations = Vec::new();
    let schema = schema_calls(ir);

    for call in rust {
        let Some(declared) = schema.get(call.name.as_str()) else {
            violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!(
                    "`SyscallNumber::{}` ({}, {}:{}) has no `syscall` declaration; a call the \
                     schema does not carry is a call the reference cannot describe",
                    call.name, call.number, SYSCALL_SOURCE, call.line
                ),
            });
            continue;
        };
        if declared.number != call.number {
            violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!(
                    "`{}` is call {} in the schema and {} in the kernel",
                    call.name, declared.number, call.number
                ),
            });
        }
        if declared.doc.trim().is_empty() {
            violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!("`syscall {}` has no description", call.name),
            });
        }
        if declared.status == Status::Unstated {
            violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!("`syscall {}` states no @status", call.name),
            });
        }
        if call.doc_lines == 0 {
            violations.push(Violation {
                path: SYSCALL_SOURCE.to_owned(),
                reason: format!(
                    "line {}: `SyscallNumber::{}` has no doc comment",
                    call.line, call.name
                ),
            });
        }
    }

    let known: BTreeMap<&str, u64> = rust.iter().map(|c| (c.name.as_str(), c.number)).collect();
    for name in schema.keys() {
        if !known.contains_key(name) {
            violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!(
                    "`syscall {name}` has no `SyscallNumber` variant; the schema describes a call \
                     the kernel does not answer"
                ),
            });
        }
    }
    violations
}

/// The schema's `enum Syscall` and its `syscall` declarations are the same
/// surface. The enum is `SCREAMING_SNAKE`, the declarations are `CamelCase`,
/// and the conversion is the only thing that relates them.
fn check_enum_agrees(ir: &Ir) -> Vec<Violation> {
    let mut violations = Vec::new();
    let calls = schema_calls(ir);
    let Some(numbers) = ir.decls.iter().find_map(|d| match d {
        IrDecl::Enum(e) if e.name == "Syscall" => Some(e),
        _ => None,
    }) else {
        violations.push(Violation {
            path: SYSCALL_SCHEMA.to_owned(),
            reason: "no `enum Syscall`; the call numbers have no form a decoder can name"
                .to_owned(),
        });
        return violations;
    };

    let by_screaming: BTreeMap<String, u64> = calls
        .values()
        .map(|c| (screaming_snake(&c.name), c.number))
        .collect();
    for member in &numbers.members {
        match by_screaming.get(&member.name) {
            Some(&number) if number == member.value => {}
            Some(&number) => violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!(
                    "`Syscall::{}` is {} but its `syscall` declaration is {number}",
                    member.name, member.value
                ),
            }),
            None => violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!("`Syscall::{}` has no `syscall` declaration", member.name),
            }),
        }
    }
    let declared: BTreeMap<&str, u64> = numbers
        .members
        .iter()
        .map(|m| (m.name.as_str(), m.value))
        .collect();
    for name in by_screaming.keys() {
        if !declared.contains_key(name.as_str()) {
            violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!("`enum Syscall` is missing `{name}`"),
            });
        }
    }
    violations
}

/// Every `extern struct N from L` names an `@abi struct N` in a schema whose
/// library is `L`.
fn check_externs(root: &Path, ir: &Ir) -> Vec<Violation> {
    let mut violations = Vec::new();
    let externs: Vec<_> = ir
        .decls
        .iter()
        .filter_map(|d| match d {
            IrDecl::Extern(e) => Some(e),
            _ => None,
        })
        .collect();
    if externs.is_empty() {
        return violations;
    }

    // Library name -> the `@abi` struct names it declares.
    let mut libraries: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let dir = root.join(SCHEMA_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) => {
            violations.push(Violation {
                path: SCHEMA_DIR.to_owned(),
                reason: format!("cannot read the schema directory: {err}"),
            });
            return violations;
        }
    };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "isl"))
        .collect();
    paths.sort();
    for path in paths {
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let (Some(other), _) = tessera_isl::compile(&src) else {
            continue;
        };
        let abi = other
            .decls
            .iter()
            .filter_map(|d| match d {
                IrDecl::Struct(s) if s.abi => Some(s.name.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        libraries.entry(other.library).or_default().extend(abi);
    }

    for e in externs {
        match libraries.get(&e.library) {
            Some(names) if names.contains(&e.name) => {}
            Some(_) => violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!(
                    "`extern struct {} from {}`: that library declares no `@abi struct` by that \
                     name",
                    e.name, e.library
                ),
            }),
            None => violations.push(Violation {
                path: SYSCALL_SCHEMA.to_owned(),
                reason: format!(
                    "`extern struct {} from {}`: no schema declares that library",
                    e.name, e.library
                ),
            }),
        }
    }
    violations
}

/// Every `###` family under "System Call Families" states a status from the
/// fixed vocabulary, on the first non-blank line below its heading.
pub fn check_families(rel: &str, content: &str) -> (Vec<Family>, Vec<Violation>) {
    let mut families = Vec::new();
    let mut violations = Vec::new();
    let mut inside = false;
    let mut pending: Option<Family> = None;

    for (index, raw) in content.lines().enumerate() {
        let line = raw.trim_end();
        if line == FAMILIES_HEADING {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        // Any other `##` heading ends the section.
        if line.starts_with("## ") {
            break;
        }
        if let Some(title) = line.strip_prefix("### ") {
            if let Some(previous) = pending.take() {
                violations.push(missing_status(rel, &previous));
                families.push(previous);
            }
            pending = Some(Family {
                title: title.trim().to_owned(),
                status: None,
                line: index + 1,
            });
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some(mut family) = pending.take() {
            match parse_status(line) {
                Some(status) => family.status = Some(status),
                None => violations.push(missing_status(rel, &family)),
            }
            families.push(family);
        }
    }
    if let Some(previous) = pending.take() {
        violations.push(missing_status(rel, &previous));
        families.push(previous);
    }

    if families.is_empty() {
        violations.push(Violation {
            path: rel.to_owned(),
            reason: format!(
                "no `###` families under \"{FAMILIES_HEADING}\" — the gate is reading the wrong \
                 shape and would report clean on anything"
            ),
        });
    }
    (families, violations)
}

/// The status word a family's lead line claims, if it claims one from the
/// vocabulary.
fn parse_status(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(STATUS_PREFIX)?;
    let word = rest.split(['.', '*']).next()?.trim();
    FAMILY_STATUSES.contains(&word).then(|| word.to_owned())
}

fn missing_status(rel: &str, family: &Family) -> Violation {
    Violation {
        path: rel.to_owned(),
        reason: format!(
            "line {}: family \"{}\" does not open with `{STATUS_PREFIX}<{}>.**` — a family that \
             does not say whether it exists makes this document readable as neither design nor \
             reference",
            family.line,
            family.title,
            FAMILY_STATUSES.join("|")
        ),
    }
}

/// `HandleDuplicate` -> `HANDLE_DUPLICATE`.
fn screaming_snake(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, c) in name.char_indices() {
        if c.is_ascii_uppercase() && index != 0 {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

#[cfg(test)]
#[path = "tests/surface.rs"]
mod tests;
