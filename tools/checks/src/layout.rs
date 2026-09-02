// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **address-layout gate**: the two languages a ring-3 program may be
//! written in agree about where that program may put things.
//!
//! **Why this exists at all.** `userspace/uabi`'s module note names the only
//! two facts a user program needs that are genuinely per-architecture: the
//! syscall instruction and its register convention, and *the addresses a
//! program is entitled to assume*. Both had one home while every program here
//! was Rust. `userspace/libc` is the second home for both — `tessera/syscall.h`
//! for the first, `tessera/layout.h` for this one — and a second home for a
//! constant with nothing holding the two together is the drift
//! [`crate::surface`] exists because this tree already paid for once.
//!
//! **What drift would look like.** Nothing fails to compile. A C program links,
//! loads, and maps its heap somewhere a Rust program on the same machine
//! believes is free — or somewhere the port's user half does not reach, which
//! on the narrower paging formats is only a few bits away. The symptom is a
//! fault in whichever program mapped second, and it names neither file.
//!
//! **The comparison is textual and deliberately narrow.** It reads the `pub
//! const` lines out of `uabi`'s `layout` module with their `cfg(target_arch)`
//! attributes, reads the `#define`s out of the header with their `#if
//! defined(__arch__)` guards, and requires that every constant the header
//! declares for an architecture equals `uabi`'s for that same architecture.
//! **Only that direction**: `uabi` has constants the C tier has no caller for
//! yet — the probe windows a device manager places — and requiring the header
//! to carry them would be requiring the C tier to grow ahead of its callers,
//! which is the opposite of the rule Phase 4 works to (D306).
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 0"),
//! docs/roadmap/04-self-hosting.md ("Phase 4")
//! Budget: none (build-time tooling)

use crate::Violation;
use std::collections::BTreeMap;
use std::path::Path;

/// The Rust side: where a ring-3 program's address layout is declared.
pub const UABI_SOURCE: &str = "userspace/uabi/src/lib.rs";

/// The C side.
pub const LIBC_HEADER: &str = "userspace/libc/include/tessera/layout.h";

/// The prefix every constant in the header carries. Stripped before comparing,
/// because C has no modules and the Rust name is the same word without it.
const C_PREFIX: &str = "TESSERA_";

/// A constant, keyed by the architecture it was declared for.
///
/// `None` is "declared outside any `cfg`/`#if`", which is how both files spell
/// a value that is the same everywhere.
type Constants = BTreeMap<(Option<String>, String), u128>;

/// Evaluates the small arithmetic both files write their sizes in: a product of
/// integer literals, each decimal or `0x`-hex, with `_` separators and a C
/// integer suffix allowed.
///
/// **A product and nothing more.** `64 * 1024 * 1024` is the shape that
/// actually appears; anything richer would be a reason to declare the value
/// once and derive it, not a reason for this to grow an expression parser that
/// could disagree with a compiler.
fn value(text: &str) -> Option<u128> {
    let mut total: u128 = 1;
    for term in text.split('*') {
        let term = term.trim().trim_matches(|c| c == '(' || c == ')').trim();
        let term = term
            .trim_end_matches(['u', 'U', 'l', 'L'])
            .trim_end_matches("ULL");
        let term = term.replace('_', "");
        let parsed = match term.strip_prefix("0x").or_else(|| term.strip_prefix("0X")) {
            Some(hex) => u128::from_str_radix(hex, 16).ok()?,
            None => term.parse::<u128>().ok()?,
        };
        total = total.checked_mul(parsed)?;
    }
    Some(total)
}

/// Reads `pub const NAME: T = EXPR;` out of `uabi`, keyed by the
/// `#[cfg(target_arch = "…")]` immediately above it when there is one.
///
/// Attribute-directed rather than positional: a `cfg` binds to the item that
/// follows it, and reading them in order is how the file itself is read.
pub fn rust_constants(text: &str) -> Constants {
    let mut found = Constants::new();
    let mut arch: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("#[cfg(target_arch = \"") {
            arch = rest.split('"').next().map(str::to_string);
            continue;
        }
        let Some(rest) = line.strip_prefix("pub const ") else {
            // Anything that is not an item leaves a pending `cfg` alone;
            // anything that *is* consumes it.
            if !line.is_empty() && !line.starts_with("//") && !line.starts_with("#[") {
                arch = None;
            }
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            arch = None;
            continue;
        };
        if let Some((_, expr)) = tail.split_once('=')
            && let Some(v) = value(expr.trim_end_matches(';'))
        {
            found.insert((arch.take(), name.trim().to_string()), v);
        }
        arch = None;
    }
    found
}

/// Reads `#define TESSERA_NAME (…)` out of the C header, keyed by the
/// architecture of the `#if defined(__…__)` arm it sits in.
///
/// The prefix is stripped, so the keys are directly comparable with
/// [`rust_constants`]'s.
pub fn c_constants(text: &str) -> Constants {
    let mut found = Constants::new();
    let mut arch: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("#if defined(__")
            .or_else(|| line.strip_prefix("#elif defined(__"))
        {
            arch = rest.split("__").next().map(str::to_string);
            continue;
        }
        if line.starts_with("#else") || line.starts_with("#endif") {
            arch = None;
            continue;
        }
        let Some(rest) = line.strip_prefix("#define ") else {
            continue;
        };
        let Some((name, expr)) = rest.split_once(char::is_whitespace) else {
            continue;
        };
        let Some(name) = name.strip_prefix(C_PREFIX) else {
            continue;
        };
        // The cast a C constant carries to give itself a width — `((uint64_t)…)`
        // — is not part of the value.
        let expr = expr.trim().trim_start_matches('(');
        let expr = match expr.split_once(')') {
            Some((cast, rest)) if cast.starts_with("uint") || cast.starts_with("int") => rest,
            _ => expr,
        };
        if let Some(v) = value(expr.trim_end_matches(')')) {
            found.insert((arch.clone(), name.to_string()), v);
        }
    }
    found
}

/// Every constant the C header declares must equal `uabi`'s for the same
/// architecture.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut violations = Vec::new();
    let Ok(rust) = std::fs::read_to_string(root.join(UABI_SOURCE)) else {
        return vec![Violation {
            path: UABI_SOURCE.to_string(),
            reason: "cannot be read".to_string(),
        }];
    };
    let Ok(c) = std::fs::read_to_string(root.join(LIBC_HEADER)) else {
        return vec![Violation {
            path: LIBC_HEADER.to_string(),
            reason: "cannot be read".to_string(),
        }];
    };
    let rust = rust_constants(&rust);
    let c = c_constants(&c);

    for ((arch, name), want) in &c {
        // A value the header declares unconditionally is compared against
        // `uabi`'s unconditional one; one declared under an architecture is
        // compared against that architecture's, falling back to an
        // unconditional Rust declaration, since "the same everywhere" and
        // "this value on this machine" agree when they agree.
        let found = rust
            .get(&(arch.clone(), name.clone()))
            .or_else(|| rust.get(&(None, name.clone())));
        let where_ = match arch {
            Some(a) => format!("{name} (for {a})"),
            None => name.clone(),
        };
        match found {
            None => violations.push(Violation {
                path: LIBC_HEADER.to_string(),
                reason: format!("{where_} is declared here and nowhere in {UABI_SOURCE}"),
            }),
            Some(have) if have != want => violations.push(Violation {
                path: LIBC_HEADER.to_string(),
                reason: format!("{where_} is {want:#x} here and {have:#x} in {UABI_SOURCE}"),
            }),
            Some(_) => {}
        }
    }
    violations
}
