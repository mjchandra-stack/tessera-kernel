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
//! **The six agreements**, in the order [`check`] runs them. Named rather
//! than numbered: this list said "five" while `check` ran six for as long as
//! it took somebody to count, because D300 appended an agreement and the
//! heading above it was a number nothing recomputed.
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
//! - **Every handler reads the frame the schema declares** (D298). A call's
//!   name and number agreeing is not the call agreeing: `HandleDuplicate` and
//!   `PageSupply` had two argument shapes apiece in one tree, and this is what
//!   reduced them to one. See "the frame agreement" below.
//! - **One implementation of the shared surface per port.** A port registers
//!   ring-3 traps at one seam and may keep arms only that machine can serve;
//!   what it may not do is answer a call `kcore::dispatch` already answers.
//!   That is where a number comes to mean two things — this tree had eight
//!   registered handlers on one port, four of them answering `Null`,
//!   `HandleDuplicate` or `PageSupply` in their own way, which is the
//!   divergence D298 found by reading (D300).
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
use std::collections::{BTreeMap, BTreeSet};
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
    let handlers = all_registered_handlers(root);
    violations.append(&mut check_frames(root, &ir, &handlers));
    violations.append(&mut check_handlers(root));

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

// --- The frame agreement: every handler reads the frame the schema declares ---

/// Where a handler may live. Every one is walked, because the defect this
/// catches is one handler disagreeing with the others.
const HANDLER_ROOT: &str = "kernel";

/// A syscall arm found in kernel source: which call, and which argument
/// registers its body names.
#[derive(Debug, PartialEq, Eq)]
pub struct Arm {
    /// The function the arm is in — how an agreement tells a handler from an
    /// observer that happens to match on the same name.
    pub function: String,
    pub call: String,
    pub reads: BTreeSet<u64>,
    /// Whether the arm refuses rather than implements — `ENOSYS`, and nothing
    /// else. A port that does not answer a call is not a port that disagrees
    /// about its shape.
    pub refuses: bool,
    /// Whether the enclosing function names an argument register this scanner
    /// understands (`frame.argN`, `req.args[N]`). False for a port whose frame
    /// spells its registers some other way, and for an arm in a helper that
    /// takes the value as a parameter.
    pub sees_frame: bool,
}

/// Every `SyscallNumber::Name =>` arm in one file, with the registers it reads.
///
/// Text, like every gate here, and the shape it reads is narrow: an arm's body
/// runs from `=>` to the comma or brace that closes it at depth zero, and the
/// registers are whatever `frame.argN`, `req.args[N]` or `args[N]` it names.
/// That works because this tree passes registers **at the arm** — a handler
/// that delegates writes `fs_page_supply(caller, frame.arg0)`, so the frame it
/// reads is visible without following the call.
pub fn arms_in(content: &str) -> Vec<Arm> {
    const PATTERN: &str = "SyscallNumber::";
    let bindings = register_bindings(content);
    let mut out = Vec::new();
    let mut at = 0usize;

    while let Some(found) = content[at..].find(PATTERN) {
        let start = at + found;
        at = start + PATTERN.len();
        let rest = &content[at..];
        let name_len = rest
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        if name_len == 0 {
            continue;
        }
        let call = rest[..name_len].to_owned();
        // Only a match arm counts: `SyscallNumber::X =>`, or `X | Y => ...`
        // where the last alternative carries the body. A mention inside an
        // expression (`SyscallNumber::from_u64`) is not an arm.
        let Some(cursor) = arrow_after(content, at + name_len) else {
            continue;
        };
        let enclosing = enclosing_fn(content, start);
        // An arm that cannot see the frame is not the arm that reads it. The
        // four ports route the loader trio through a helper taking the pointer
        // as a parameter and matching on the number again; the register was
        // read by that helper's caller, which is an arm this walk also sees.
        // Judging the inner one would be reporting a handler twice and failing
        // it once. Recorded rather than skipped, because the handler agreement
        // asks a different question of the same arms.
        let sees_frame = !registers_in(enclosing).is_empty();
        let function = fn_name(enclosing);
        let body = arm_body(content, cursor);
        let mut reads = registers_in(body);
        // A register the arm reaches through a name bound earlier in the same
        // file — `let args_ptr = frame.arg0;` and then `create(.., args_ptr)`,
        // which is how the four ports route the loader trio. Without this the
        // gate reports the arm as reading nothing, which is a gate failing on
        // correct code.
        for (name, index) in &bindings {
            if names_ident(body, name) {
                reads.insert(*index);
            }
        }
        let refuses = body.contains("ENOSYS") && reads.is_empty();
        out.push(Arm {
            function,
            call,
            reads,
            refuses,
            sees_frame,
        });
    }
    out
}

/// The `=>` that follows a `SyscallNumber::Name` mention, if the mention is a
/// match arm — skipping the closing parentheses of any pattern wrapped around
/// it.
///
/// **`Some(SyscallNumber::Null) =>` is an arm.** Both gates below read arms by
/// text, and both looked only for a name followed directly by `=>` until D300
/// — so every handler written as `match SyscallNumber::from_u64(n) { Some(..)
/// => }` was invisible to them, which on this port was three of the eight. The
/// inversion that found it was a second handler answering `Null`: it passed.
fn arrow_after(content: &str, from: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut cursor = from;
    loop {
        while bytes.get(cursor).is_some_and(|b| b.is_ascii_whitespace()) {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b')') {
            cursor += 1;
            continue;
        }
        break;
    }
    content[cursor..].starts_with("=>").then_some(cursor + 2)
}

/// The text of one arm: the balanced block when the arm opens one, and
/// otherwise the expression up to the comma or brace that ends it.
///
/// The two cases have to be told apart. A braced arm carries no trailing comma,
/// so a scanner that only looked for one would run into the arm below it and
/// report that arm's registers as this one's — which is a gate that fails on
/// correct code and says nothing about the wrong kind.
fn arm_body(content: &str, from: usize) -> &str {
    let bytes = content.as_bytes();
    let mut cursor = from;
    while bytes.get(cursor).is_some_and(|b| b.is_ascii_whitespace()) {
        cursor += 1;
    }
    let start = cursor;
    let mut depth = 0i32;
    let braced = bytes.get(cursor) == Some(&b'{');
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
                if braced && depth == 0 {
                    cursor += 1;
                    break;
                }
            }
            b',' if depth == 0 => break,
            _ => {}
        }
        cursor += 1;
    }
    &content[start..cursor]
}

/// The source of the function containing the byte at `at`, bounded by the
/// nearest `fn` declarations either side of it.
///
/// Approximate on purpose: what it is asked is only whether the enclosing
/// function names a register anywhere, and a slice that runs to the next `fn`
/// answers that without a parser.
fn enclosing_fn(content: &str, at: usize) -> &str {
    const STARTS: [&str; 3] = ["\nfn ", "\npub fn ", "\npub(crate) fn "];
    let start = STARTS
        .iter()
        .filter_map(|s| content[..at].rfind(s))
        .max()
        .unwrap_or(0);
    let end = STARTS
        .iter()
        .filter_map(|s| content[at..].find(s).map(|e| at + e))
        .min()
        .unwrap_or(content.len());
    &content[start..end]
}

/// Names bound directly to an argument register: `let args_ptr = frame.arg0;`.
///
/// One map per file rather than per function, because a name bound to a
/// register in one handler and used in another's arm would be a defect of a
/// different kind — and this gate is not the one that would catch it.
fn register_bindings(content: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("let ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_start_matches("mut ").trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let registers = registers_in(value);
        // Exactly one register, or the name does not stand for one.
        if let (1, Some(index)) = (registers.len(), registers.iter().next()) {
            out.insert(name.to_owned(), *index);
        }
    }
    out
}

/// Whether `body` names `ident` as a whole word rather than as part of one.
fn names_ident(body: &str, ident: &str) -> bool {
    let mut at = 0usize;
    while let Some(found) = body[at..].find(ident) {
        let start = at + found;
        at = start + ident.len();
        let before = body[..start].chars().next_back();
        let after = body[at..].chars().next();
        let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        if boundary(before) && boundary(after) {
            return true;
        }
    }
    false
}

/// The argument-register indices a body names.
fn registers_in(body: &str) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for (marker, closing) in [(".arg", None), (".args[", Some(']')), ("args[", Some(']'))] {
        let mut at = 0usize;
        while let Some(found) = body[at..].find(marker) {
            let start = at + found + marker.len();
            at = start;
            let rest = &body[start..];
            let digits = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            if digits == 0 {
                continue;
            }
            if let Some(close) = closing
                && !rest[digits..].starts_with(close)
            {
                continue;
            }
            if let Ok(index) = rest[..digits].parse::<u64>() {
                out.insert(index);
            }
        }
    }
    out
}

/// Every handler reads exactly the registers `syscall_abi.isl` declares.
///
/// **The agreement D248 recorded as missing.** Its own finding was that the
/// gate checked a call's name and number and not its argument shapes, and that
/// `HandleDuplicate` and `PageSupply` therefore had two argument forms in one
/// tree — one syscall number meaning two things, which is the one defect a
/// published ABI cannot carry. A handler reading a register the schema does not
/// declare, or ignoring one it does, fails here (D298).
fn check_frames(root: &Path, ir: &Ir, handlers: &BTreeSet<String>) -> Vec<Violation> {
    let calls = schema_calls(ir);
    let mut out = Vec::new();
    let mut seen = 0usize;

    for (abs, rel) in crate::walk::walk_files(&root.join(HANDLER_ROOT)) {
        if !rel.ends_with(".rs") || rel.contains("/tests/") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&abs) else {
            continue;
        };
        for arm in arms_in(&content) {
            // Only what **answers** the call. A check's observer matches on a
            // call name to record what it returned and reads no register at
            // all, which is right for an observer and would be a finding here
            // — the reason it is not one is that it is not a handler.
            if !arm.sees_frame || !handlers.contains(&arm.function) {
                continue;
            }
            let Some(call) = calls.get(arm.call.as_str()) else {
                continue;
            };
            seen += 1;
            if arm.refuses {
                continue;
            }
            let declared: BTreeSet<u64> = call.args.iter().map(|a| a.index).collect();
            if arm.reads.is_empty() && !declared.is_empty() {
                // A handler that names no register at all is delegating in a
                // shape this gate cannot read. Reported, not ignored: silence
                // about a call is what let two shapes coexist.
                out.push(Violation {
                    path: format!("{HANDLER_ROOT}/{rel}"),
                    reason: format!(
                        "`{}` reads no argument register, and the schema declares {}",
                        arm.call,
                        declared.len()
                    ),
                });
                continue;
            }
            if arm.reads != declared {
                out.push(Violation {
                    path: format!("{HANDLER_ROOT}/{rel}"),
                    reason: format!(
                        "`{}` reads registers {:?} and `{SYSCALL_SCHEMA}` declares {:?}: one \
                         syscall number with two argument shapes",
                        arm.call,
                        arm.reads.iter().collect::<Vec<_>>(),
                        declared.iter().collect::<Vec<_>>()
                    ),
                });
            }
        }
    }

    // A walk that found no arms agrees with every schema there could be.
    if seen == 0 {
        out.push(Violation {
            path: HANDLER_ROOT.to_owned(),
            reason: "no syscall handler arms found — the frame agreement checked nothing".into(),
        });
    }
    out
}

/// Where the ports live: one directory each under this root.
const PORT_ROOT: &str = "kernel";

/// The crate holding the shared dispatcher, which is not a port.
const SHARED_CRATE: &str = "kcore";

/// The shared dispatcher itself: the authority on which numbers are common.
const SHARED_DISPATCHER: &str = "kernel/kcore/src/dispatch.rs";

/// How a port registers the function its ring-3 traps arrive at. One entry per
/// port's seam, because the seam is the port's own and has no shared name.
///
/// A port whose seam is not listed here registers nothing this can see, which
/// is why [`check_handlers`] fails when a port directory yields no registered
/// handler at all rather than passing it as agreeing.
const HOOK_SEAMS: &[&str] = &[
    "set_syscall_handler",   // x86-64
    "set_el0_sync_hook",     // AArch64
    "set_user_trap_hook",    // RISC-V 64 and 32
    "set_user_syscall_hook", // ARM 32
];

/// The name in `fn NAME`, or `?` when the slice holds no declaration.
fn fn_name(source: &str) -> String {
    let Some(at) = source.find("fn ") else {
        return "?".to_owned();
    };
    let rest = &source[at + 3..];
    let len = rest
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    rest[..len].to_owned()
}

/// The handler names a file registers at a port's trap seam.
pub fn registered_handlers(content: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for seam in HOOK_SEAMS {
        let marker = format!("{seam}(");
        let mut at = 0usize;
        while let Some(found) = content[at..].find(&marker) {
            let start = at + found + marker.len();
            at = start;
            let rest = &content[start..];
            let len = rest
                .find(|c: char| !c.is_alphanumeric() && c != '_' && c != ':')
                .unwrap_or(rest.len());
            // The last path segment: `crate::loader::syscall_handler` and
            // `syscall_handler` are the same function, and a gate that counted
            // them as two would fail on a spelling.
            let named = rest[..len].rsplit("::").next().unwrap_or_default();
            if !named.is_empty() {
                out.insert(named.to_owned());
            }
        }
    }
    out
}

/// Every function this tree registers at any port's trap seam, plus the shared
/// dispatcher — the set of functions that *answer* a syscall.
///
/// One set across the tree rather than one per port: a name that means a
/// handler on one port and something else on another would be an ambiguity
/// worth its own finding, and this gate is not the one that would catch it.
pub fn all_registered_handlers(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    out.insert("dispatch".to_owned());
    for (abs, rel) in crate::walk::walk_files(&root.join(PORT_ROOT)) {
        if !rel.ends_with(".rs") || rel.contains("/tests/") {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&abs) {
            out.append(&mut registered_handlers(&content));
        }
    }
    out
}

/// **One implementation of the shared call surface per port.**
///
/// The agreement D299 left open and D300 closed. A port answers ring-3 traps at
/// one seam, and what it registers there is free to keep arms only that machine
/// can serve — a console write, an exit, an `in`/`out` instruction, a
/// three-phase loader reaching this port's page tables. What it must not do is
/// *re-implement a call `kcore::dispatch` already answers*, because the second
/// implementation is where a syscall number comes to mean two things: this port
/// had eight registered handlers, four of them answering `Null`,
/// `HandleDuplicate` or `PageSupply` in their own way, and D298 found exactly
/// that divergence by hand.
///
/// The shared surface is read from the dispatcher rather than listed here, so
/// a call that moves into `kcore::dispatch` becomes a call the ports may no
/// longer implement, with nothing to update.
///
/// A port that registers nothing this can see **fails**: a walk that finds no
/// handler agrees with every dispatcher there could be.
fn check_handlers(root: &Path) -> Vec<Violation> {
    let mut out = Vec::new();

    // What the shared dispatcher answers.
    let shared: BTreeSet<String> = match std::fs::read_to_string(root.join(SHARED_DISPATCHER)) {
        Ok(content) => arms_in(&content)
            .into_iter()
            .filter(|arm| !arm.refuses && arm.function == "dispatch")
            .map(|arm| arm.call)
            .collect(),
        Err(e) => {
            out.push(Violation {
                path: SHARED_DISPATCHER.to_owned(),
                reason: format!("cannot read the shared dispatcher: {e}"),
            });
            return out;
        }
    };
    if shared.is_empty() {
        out.push(Violation {
            path: SHARED_DISPATCHER.to_owned(),
            reason: "the shared dispatcher answers no calls — the handler agreement checked \
                     nothing"
                .into(),
        });
        return out;
    }

    let ports = root.join(PORT_ROOT);
    let Ok(entries) = std::fs::read_dir(&ports) else {
        out.push(Violation {
            path: PORT_ROOT.to_owned(),
            reason: "no port tree to walk".into(),
        });
        return out;
    };
    let mut dirs: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != SHARED_CRATE)
        .collect();
    dirs.sort();

    let mut ports_seen = 0usize;
    for port in dirs {
        let mut sources = Vec::new();
        for (abs, rel) in crate::walk::walk_files(&ports.join(&port)) {
            if !rel.ends_with(".rs") || rel.contains("/tests/") {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&abs) {
                sources.push((rel, content));
            }
        }
        let registered: BTreeSet<String> = sources
            .iter()
            .flat_map(|(_, content)| registered_handlers(content))
            .collect();
        if registered.is_empty() {
            continue; // not a port: a support crate with no trap seam
        }
        ports_seen += 1;

        // Which registered handlers implement a shared call, and which calls.
        let mut implementers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (rel, content) in &sources {
            for arm in arms_in(content) {
                if arm.refuses || !shared.contains(&arm.call) {
                    continue;
                }
                if !registered.contains(&arm.function) {
                    continue;
                }
                implementers
                    .entry(arm.function)
                    .or_default()
                    .insert(format!("{} ({rel})", arm.call));
            }
        }
        if implementers.len() > 1 {
            let named: Vec<String> = implementers
                .iter()
                .map(|(function, calls)| {
                    format!("{function} answers {:?}", calls.iter().collect::<Vec<_>>())
                })
                .collect();
            out.push(Violation {
                path: format!("{PORT_ROOT}/{port}"),
                reason: format!(
                    "{} registered handlers implement calls `kcore::dispatch` also answers: {}: \
                     one syscall number with two implementations in one port",
                    implementers.len(),
                    named.join("; ")
                ),
            });
        }
    }

    if ports_seen == 0 {
        out.push(Violation {
            path: PORT_ROOT.to_owned(),
            reason: format!(
                "no port registers a handler at any of {HOOK_SEAMS:?} — the handler agreement \
                 checked nothing"
            ),
        });
    }
    out
}

#[cfg(test)]
#[path = "tests/surface.rs"]
mod tests;
