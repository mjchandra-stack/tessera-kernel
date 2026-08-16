// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! `islc` — the ISL compiler CLI, used both interactively and by the codegen
//! build rules. Subcommands: `check` a schema, `emit-ir` its compiled IR text,
//! `emit-rust` its Rust bindings, and `version`. Diagnostics go to stderr;
//! generated artifacts go to stdout. Exit codes: 0 success, 1 schema error,
//! 2 usage error.
//!
//! Normative: docs/api/03-interface-schema-language.md,
//! docs/lifecycle/02-build-and-test-infrastructure.md

use std::process::ExitCode;
use tessera_isl::diag::{Diagnostics, Severity};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("version") => {
            println!("islc {}", tessera_isl::VERSION);
            ExitCode::SUCCESS
        }
        Some("check") => run(args.get(2), |src| {
            let (_, diags) = tessera_isl::compile(src);
            (String::new(), diags)
        }),
        Some("emit-ir") => run(args.get(2), |src| {
            let (ir, diags) = tessera_isl::compile(src);
            let text = ir.map(|ir| ir.emit_text()).unwrap_or_default();
            (text, diags)
        }),
        // `emit-fuzz <bindings-crate> <schema>`: the structure-aware fuzz
        // targets, which need the name of the crate holding the bindings they
        // exercise — the schema does not know what its generated crate is
        // called, and guessing from the library name would be a convention
        // nothing enforces.
        Some("emit-fuzz") => {
            let Some(bindings) = args.get(2).cloned() else {
                eprintln!("islc: emit-fuzz expects a bindings crate name");
                return ExitCode::from(2);
            };
            run(args.get(3), move |src| {
                let (ir, diags) = tessera_isl::compile(src);
                let text = ir
                    .map(|ir| tessera_isl::codegen_fuzz::emit(&ir, &bindings))
                    .unwrap_or_default();
                (text, diags)
            })
        }
        Some("emit-rust") => run(args.get(2), |src| {
            let (ir, diags) = tessera_isl::compile(src);
            let text = ir
                .map(|ir| tessera_isl::codegen_rust::emit(&ir))
                .unwrap_or_default();
            (text, diags)
        }),
        _ => {
            eprintln!(
                "usage: islc <check|emit-ir|emit-rust|version> [schema.isl]\n\
                 \x20      islc emit-fuzz <bindings-crate> <schema.isl>"
            );
            ExitCode::from(2)
        }
    }
}

/// Reads the schema at `path`, runs `compile`, prints diagnostics to stderr and
/// the produced text to stdout. Exits 1 on any error diagnostic.
fn run(path: Option<&String>, compile: impl Fn(&str) -> (String, Diagnostics)) -> ExitCode {
    let Some(path) = path else {
        eprintln!("islc: expected a schema path");
        return ExitCode::from(2);
    };
    let src = match std::fs::read_to_string(path) {
        Ok(src) => src,
        Err(err) => {
            eprintln!("islc: cannot read {path}: {err}");
            return ExitCode::from(2);
        }
    };

    let (text, diags) = compile(&src);
    for diag in diags.iter() {
        eprintln!("{path}: {diag}");
    }
    if diags.iter().any(|d| d.severity == Severity::Error) {
        ExitCode::from(1)
    } else {
        if !text.is_empty() {
            print!("{text}");
        }
        ExitCode::SUCCESS
    }
}
