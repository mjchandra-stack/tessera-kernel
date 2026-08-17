// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The configuration tool: what a build of Tessera can be told to be, and the
//! one program that answers.
//!
//! Two of these subcommands are the build (`emit`, `components`); the rest are
//! for the person deciding what to build. They are one program because they
//! must agree: a menu that accepted a value the build refuses, or a `show` that
//! reported a configuration the compiler was not given, would be worse than no
//! tool at all. Every one of them goes through the same declaration parser and
//! the same resolver.
//!
//! ```text
//! kconfig emit       <decl> <profile> <out.rs> [--crate]   the sizing constants
//! kconfig components <decl> <profile> <machine> <out.rs> <name=crate>…
//! kconfig flags      <decl> <profile> <machine>            the --cfg flags
//! kconfig show       <decl> <profile> [machine]            the resolved .config
//! kconfig menu       <decl> <profile> [out.profile]        browse and edit
//! kconfig diff       <decl> <a.profile> <b.profile>        what two differ in
//! kconfig migrate    <decl> <profile>                      drop what is gone
//! kconfig check      <decl> <profile>…                     resolve every one
//! ```
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use tessera_kconfig::menu::{Menu, Outcome};
use tessera_kconfig::resolve::{Config, diff, resolve};
use tessera_kconfig::term::Terminal;
use tessera_kconfig::{Declaration, Error, Form, emit, emit_components, parse_declaration};

const USAGE: &str = "\
usage:
  kconfig emit       <decl> <profile> <out.rs> [--crate]
  kconfig components <decl> <profile> <machine> <out.rs> <name=crate>...
  kconfig flags      <decl> <profile> <machine>
  kconfig show       <decl> <profile> [machine]
  kconfig menu       <decl> <profile> [out.profile]
  kconfig diff       <decl> <a.profile> <b.profile>
  kconfig migrate    <decl> <profile>
  kconfig check      <decl> <profile>...";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    match args.first().map(String::as_str) {
        Some("emit") => run(cmd_emit(&rest)),
        Some("components") => run(cmd_components(&rest)),
        Some("flags") => run(cmd_flags(&rest)),
        Some("show") => run(cmd_show(&rest)),
        Some("menu") => run(cmd_menu(&rest)),
        Some("diff") => run(cmd_diff(&rest)),
        Some("migrate") => run(cmd_migrate(&rest)),
        Some("check") => run(cmd_check(&rest)),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Every subcommand fails the same way: a message on stderr, a failing status,
/// and nothing half-written.
fn run(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Reads the declaration and one profile, resolving them.
///
/// The profile's file stem is its name, which is what every generated file
/// records as its provenance.
fn load(decl_path: &str, profile_path: &str) -> Result<(Declaration, Overrides, String), String> {
    let decl_text = read(decl_path)?;
    let decl = parse_declaration(&decl_text).map_err(|e| report(decl_path, &e))?;
    let profile_text = read(profile_path)?;
    let overrides =
        tessera_kconfig::parse_profile(&profile_text).map_err(|e| report(profile_path, &e))?;
    Ok((decl, overrides, name_of(profile_path)))
}

type Overrides = BTreeMap<String, tessera_kconfig::Value>;

fn name_of(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_owned()
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn write(path: &str, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("{path}: {e}"))
}

/// Reports every error rather than the first: a profile with three bad values
/// should take one run to fix, not three.
fn report(path: &str, errors: &[Error]) -> String {
    errors
        .iter()
        .map(|e| format!("{path}:{e}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn resolved<'a>(
    decl: &'a Declaration,
    overrides: &Overrides,
    name: &str,
    path: &str,
) -> Result<Config<'a>, String> {
    resolve(decl, overrides, name).map_err(|e| report(path, &e))
}

fn cmd_emit(args: &[&str]) -> Result<(), String> {
    let (form, args) = match args.last() {
        Some(&"--crate") => (Form::Crate, &args[..args.len() - 1]),
        _ => (Form::Included, args),
    };
    let [decl_path, profile_path, out] = args else {
        return Err(USAGE.to_owned());
    };
    let (decl, overrides, name) = load(decl_path, profile_path)?;
    let config = resolved(&decl, &overrides, &name, profile_path)?;
    write(out, &emit(&config, form))
}

fn cmd_components(args: &[&str]) -> Result<(), String> {
    let [decl_path, profile_path, machine, out, catalog @ ..] = args else {
        return Err(USAGE.to_owned());
    };
    let mut images = BTreeMap::new();
    for entry in catalog {
        let Some((program, krate)) = entry.split_once('=') else {
            return Err(format!("`{entry}` is not `name=crate`"));
        };
        images.insert(program.to_owned(), krate.to_owned());
    }
    let (decl, overrides, name) = load(decl_path, profile_path)?;
    let config = resolved(&decl, &overrides, &name, profile_path)?;
    let text = emit_components(&config, machine, &images).map_err(|e| report(decl_path, &e))?;
    write(out, &text)
}

fn cmd_flags(args: &[&str]) -> Result<(), String> {
    let [decl_path, profile_path, machine] = args else {
        return Err(USAGE.to_owned());
    };
    let (decl, overrides, name) = load(decl_path, profile_path)?;
    let config = resolved(&decl, &overrides, &name, profile_path)?;
    for cfg in config.cfg_flags(machine) {
        println!("--cfg={cfg}");
    }
    Ok(())
}

fn cmd_show(args: &[&str]) -> Result<(), String> {
    let (decl_path, profile_path, machine) = match args {
        [d, p] => (*d, *p, None),
        [d, p, m] => (*d, *p, Some(*m)),
        _ => return Err(USAGE.to_owned()),
    };
    let (decl, overrides, name) = load(decl_path, profile_path)?;
    let config = resolved(&decl, &overrides, &name, profile_path)?;
    print!("{}", config.show(machine));
    Ok(())
}

fn cmd_diff(args: &[&str]) -> Result<(), String> {
    let [decl_path, left_path, right_path] = args else {
        return Err(USAGE.to_owned());
    };
    let (decl, left_overrides, left_name) = load(decl_path, left_path)?;
    let right_text = read(right_path)?;
    let right_overrides =
        tessera_kconfig::parse_profile(&right_text).map_err(|e| report(right_path, &e))?;
    let left = resolved(&decl, &left_overrides, &left_name, left_path)?;
    let right = resolved(&decl, &right_overrides, &name_of(right_path), right_path)?;

    let differences = diff(&left, &right);
    if differences.is_empty() {
        println!("{} and {} resolve alike", left.profile, right.profile);
        return Ok(());
    }
    for (name, l, r) in differences {
        let text =
            |v: Option<tessera_kconfig::Value>| v.map_or_else(|| "—".to_owned(), |v| v.to_string());
        println!("{name}: {} → {}", text(l), text(r));
    }
    Ok(())
}

/// Brings a profile forward across a declaration that has changed.
///
/// This is `olddefconfig`, and it is the one subcommand that edits a file
/// somebody wrote. It only ever *removes* — a setting the declaration no longer
/// has — and it says what it removed. A value that is now out of range is
/// reported and left alone: only a person knows what it should become, and a
/// tool that picked for them would produce a machine nobody chose.
fn cmd_migrate(args: &[&str]) -> Result<(), String> {
    let [decl_path, profile_path] = args else {
        return Err(USAGE.to_owned());
    };
    let decl_text = read(decl_path)?;
    let decl = parse_declaration(&decl_text).map_err(|e| report(decl_path, &e))?;
    let profile_text = read(profile_path)?;
    let overrides =
        tessera_kconfig::parse_profile(&profile_text).map_err(|e| report(profile_path, &e))?;

    let (kept, gone): (Overrides, Overrides) = overrides
        .into_iter()
        .partition(|(name, _)| decl.contains_key(name));
    if gone.is_empty() {
        println!("{profile_path}: nothing to drop");
    }
    for name in gone.keys() {
        println!("{profile_path}: dropped `{name}`, which is no longer declared");
    }

    let config = resolved(&decl, &kept, &name_of(profile_path), profile_path)?;
    let header = leading_comment(&profile_text);
    write(
        profile_path,
        &tessera_kconfig::profile::write_profile(&config, &header),
    )
}

fn cmd_check(args: &[&str]) -> Result<(), String> {
    let [decl_path, profiles @ ..] = args else {
        return Err(USAGE.to_owned());
    };
    if profiles.is_empty() {
        return Err("check needs at least one profile".to_owned());
    }
    let decl_text = read(decl_path)?;
    let decl = parse_declaration(&decl_text).map_err(|e| report(decl_path, &e))?;
    let mut failures = Vec::new();
    for path in profiles {
        let Ok(text) = std::fs::read_to_string(path) else {
            failures.push(format!("{path}: unreadable"));
            continue;
        };
        match tessera_kconfig::parse_profile(&text) {
            Err(errors) => failures.push(report(path, &errors)),
            Ok(overrides) => {
                if let Err(errors) = resolve(&decl, &overrides, &name_of(path)) {
                    failures.push(report(path, &errors));
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn cmd_menu(args: &[&str]) -> Result<(), String> {
    let (decl_path, profile_path, out) = match args {
        [d, p] => (*d, *p, *p),
        [d, p, o] => (*d, *p, *o),
        _ => return Err(USAGE.to_owned()),
    };
    let (decl, overrides, name) = load(decl_path, profile_path)?;
    // A profile that does not resolve cannot be browsed, and saying so here is
    // better than opening on a screen that has to invent a state for it.
    resolved(&decl, &overrides, &name, profile_path)?;
    let profile_text = read(profile_path)?;
    let header = leading_comment(&profile_text);

    let Some(mut menu) = Menu::new(&decl, overrides, &name) else {
        return Err(format!("{profile_path}: cannot be browsed"));
    };
    let mut terminal = Terminal::open().map_err(|e| e.to_string())?;
    loop {
        let (rows, cols) = terminal.size();
        terminal.draw(&menu.render(rows, cols));
        let Some(key) = terminal.key() else {
            break;
        };
        match menu.press(key) {
            Outcome::Continue => {}
            Outcome::Save => {
                write(out, &menu.profile_text(&header))?;
            }
            Outcome::Quit => break,
        }
    }
    drop(terminal);
    if menu.dirty() {
        // Not a prompt. A browser that asks "save?" on the way out is one that
        // can lose the answer to a stray keypress; saying what was not written
        // leaves the file exactly as it was and the person in charge of it.
        println!("{out}: not written — changes were not saved (press `s` to save)");
    }
    Ok(())
}

/// The comment block a profile opens with — its SPDX header and the prose
/// saying what the profile is for.
///
/// Rewriting a profile must not throw that away: the reason a machine is sized
/// the way it is belongs to the file, and a tool that dropped it would leave a
/// list of numbers behind.
fn leading_comment(text: &str) -> Vec<String> {
    text.lines()
        .take_while(|line| line.trim_start().starts_with('#'))
        .map(|line| line.trim_start().trim_start_matches('#').trim().to_owned())
        .collect()
}
