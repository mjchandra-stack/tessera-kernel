// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The Interface Schema Language (ISL) compiler: it lexes and parses `.isl`
//! schemas, resolves and type-checks them under the ABI rules, lowers them to
//! a stable compiled IR, and generates Rust bindings with a canonical wire
//! codec. Host-only, zero-dependency std Rust; the one definition of validity
//! shared by the syscall boundary and every service boundary.
//!
//! The pipeline lands across this milestone's steps; this is the crate
//! skeleton.
//!
//! Normative: docs/api/03-interface-schema-language.md,
//! docs/api/01-system-call-interface.md ("Structured Arguments"),
//! docs/api/02-abi-versioning-and-compatibility.md

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod ast;
pub mod check;
pub mod codegen_rust;
pub mod diag;
pub mod ifaceid;
pub mod ir;
pub mod lexer;
pub mod parser;
pub mod sha256;
pub mod token;

use diag::Diagnostics;
use ir::Ir;

/// Compiler version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Compiles ISL source end to end: parse, then resolve and check, producing the
/// compiled IR when there are no errors (warnings do not block) plus every
/// diagnostic. A schema that fails to parse (no library header) yields no IR.
pub fn compile(src: &str) -> (Option<Ir>, Diagnostics) {
    let (schema, mut diags) = parser::parse(src);
    let Some(schema) = schema else {
        return (None, diags);
    };
    let (ir, check_diags) = check::check(&schema);
    for diag in check_diags.into_vec() {
        diags.push(diag);
    }
    let ir = if diags.has_errors() { None } else { ir };
    (ir, diags)
}
