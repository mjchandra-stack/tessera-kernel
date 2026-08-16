// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Emits the kernel's sizing constants for one profile.
//!
//! Usage: `kconfig <kernel.config> <profile> <out.rs>`. Both build paths call
//! it — the Bazel genrule and the cargo build script — so the constants the
//! inner loop compiles against and the ones a release image is built from come
//! from one program reading one declaration.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    // `--crate` emits `#![no_std]`: Bazel links the output as a crate, and the
    // cargo path includes the same text inside a module where an inner
    // attribute is not valid.
    let (form, args) = match args.last().map(String::as_str) {
        Some("--crate") => (
            tessera_kconfig::Form::Crate,
            &args[..args.len().saturating_sub(1)],
        ),
        _ => (tessera_kconfig::Form::Included, args.as_slice()),
    };
    let [_, config, profile, out] = args else {
        eprintln!("usage: kconfig <kernel.config> <profile> <out.rs> [--crate]");
        return ExitCode::FAILURE;
    };

    let decl_text = match std::fs::read_to_string(config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{config}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let profile_text = match std::fs::read_to_string(profile) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{profile}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let decl = match tessera_kconfig::parse_declaration(&decl_text) {
        Ok(d) => d,
        Err(errors) => return report(config, &errors),
    };
    let overrides = match tessera_kconfig::parse_profile(&profile_text) {
        Ok(p) => p,
        Err(errors) => return report(profile, &errors),
    };
    let values = match tessera_kconfig::resolve(&decl, &overrides) {
        Ok(v) => v,
        Err(errors) => return report(profile, &errors),
    };

    let name = std::path::Path::new(profile)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(profile);
    match std::fs::write(out, tessera_kconfig::emit(&decl, &values, name, form)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{out}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Reports every error rather than the first: a profile with three bad values
/// should take one run to fix, not three.
fn report(path: &str, errors: &[tessera_kconfig::Error]) -> ExitCode {
    for e in errors {
        eprintln!("{path}:{e}");
    }
    ExitCode::FAILURE
}
