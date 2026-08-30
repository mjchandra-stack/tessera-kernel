// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **`mkstore`** — writes a verified image store, and prints the anchor that
//! authenticates one.
//!
//! Deliberately thin. Every rule about the container lives in
//! `//api/image-store`, which is `no_std` and host-tested and is also what the
//! kernel reads with; this is argument parsing and file I/O around it. A tool
//! that knew the format would be a second implementation, and the two would
//! agree until the day they did not.
//!
//! Three subcommands:
//!
//! - `build --anchor-id N [--sign-key HEX64] -o OUT NAME=PATH[,svn=N][,ver=M]...` — assemble a
//!   container. Entries are sorted here, because a build file listing its
//!   inputs in a readable order should not have to know that the format wants
//!   them sorted. **The versions come from the caller and default to 1**: a
//!   tool that invented a security version number would be signing off on an
//!   anti-rollback decision it knows nothing about.
//! - `synth --seed N --len N -o OUT` — a deterministic pattern blob. The
//!   synthetic firmware image is *generated* rather than checked in: every file
//!   in this tree carries an SPDX header and a binary cannot, and a blob
//!   produced from a seed is reproducible in a way a committed one only looks.
//! - `anchor PATH` — print the anchor of an existing container, which is the
//!   value a verifier has to hold.
//!
//! Normative: docs/security/01-security-model.md ("Boot Security"),
//! docs/lifecycle/02-build-and-test-infrastructure.md

use std::process::ExitCode;

use tessera_image_store::{BuildEntry, build_into, built_size, measure};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") => build(&args[1..]),
        Some("synth") => synth(&args[1..]),
        Some("anchor") => anchor(&args[1..]),
        _ => Err(usage()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("mkstore: {message}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    concat!(
        "usage:\n",
        "  mkstore build --anchor-id N [--sign-key HEX64] -o OUT ",
        "NAME=PATH[,svn=N][,ver=M]...\n",
        "  mkstore synth --seed N --len N -o OUT\n",
        "  mkstore anchor PATH"
    )
    .to_owned()
}

/// Assembles a container from named files.
fn build(args: &[String]) -> Result<(), String> {
    let mut anchor_id: u32 = 0;
    let mut out: Option<String> = None;
    let mut inputs: Vec<Input> = Vec::new();
    let mut secret: Option<[u8; 32]> = None;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--anchor-id" => {
                let value = rest.next().ok_or("--anchor-id needs a value")?;
                anchor_id = value
                    .parse()
                    .map_err(|_| format!("--anchor-id: not a number: {value}"))?;
            }
            "-o" => out = Some(rest.next().ok_or("-o needs a path")?.clone()),
            "--sign-key" => {
                let value = rest.next().ok_or("--sign-key needs a value")?;
                secret = Some(parse_secret(value)?);
            }
            other => inputs.push(parse_input(other)?),
        }
    }
    let out = out.ok_or("build needs -o OUT")?;

    // Sorted here so a BUILD file can list its inputs however it reads best.
    // The format requires ascending order and the library refuses anything
    // else; that refusal is for a *reader* meeting a malformed container, not
    // a spelling rule for whoever writes one.
    inputs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut contents = Vec::new();
    for input in &inputs {
        let bytes = std::fs::read(&input.path).map_err(|e| format!("read {}: {e}", input.path))?;
        contents.push((input.clone(), bytes));
    }

    let entries: Vec<BuildEntry<'_>> = contents
        .iter()
        .map(|(input, bytes)| BuildEntry {
            name: &input.name,
            svn: input.svn,
            image_version: input.image_version,
            flags: 0,
            bytes,
        })
        .collect();

    let signed = secret.is_some();
    let size = built_size(&entries, signed).ok_or("container would be too large")?;
    let mut buffer = vec![0u8; size];
    let built =
        build_into(&mut buffer, anchor_id, &entries, signed).map_err(|e| format!("build: {e:?}"))?;
    // **Signed over the anchor the builder returned**, never over one this tool
    // measured for itself. A signer that re-read the container would be signing
    // its own reading of it, and the gap between what was measured and what was
    // signed is where every interesting attack on a signed artifact lives.
    if let (Some(secret), Some(at)) = (secret, built.signature_at) {
        let signature = tessera_ed25519_signer::sign(&secret, &built.anchor);
        buffer[at..at + signature.len()].copy_from_slice(&signature);
    }
    std::fs::write(&out, &buffer[..built.len]).map_err(|e| format!("write {out}: {e}"))
}

/// Parses a 32-byte Ed25519 secret seed given as 64 hex characters.
///
/// **A seed on the command line, and that is stated rather than hidden.** This
/// is a build tool on a build machine; `docs/security/02`'s signing
/// infrastructure — custody, rotation, revocation, an HSM — is untouched by
/// anything here, exactly as `tools/ed25519-signer`'s own note says (D173).
/// What this buys is that a container's positive path can be tested at all.
fn parse_secret(text: &str) -> Result<[u8; 32], String> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err("--sign-key takes 64 hex characters".into());
    }
    let mut secret = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let text = core::str::from_utf8(pair).map_err(|_| "--sign-key is not hex".to_string())?;
        secret[index] =
            u8::from_str_radix(text, 16).map_err(|_| "--sign-key is not hex".to_string())?;
    }
    Ok(secret)
}

/// One `NAME=PATH[,svn=N][,ver=M]` argument, parsed.
#[derive(Clone)]
struct Input {
    name: String,
    path: String,
    svn: u32,
    image_version: u32,
}

/// Parses `NAME=PATH[,svn=N][,ver=M]`.
///
/// Both versions default to 1 and neither is inferred from the other. They are
/// different questions — `svn` is the monotonic anti-rollback counter, `ver` is
/// what the artifact's producer calls the release — and a tool that derived one
/// from the other would be deciding an anti-rollback policy from a release
/// number that has nothing to do with it.
fn parse_input(spec: &str) -> Result<Input, String> {
    let mut parts = spec.split(',');
    let head = parts.next().unwrap_or_default();
    let (name, path) = head
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=PATH, got {head}"))?;
    let mut input = Input {
        name: name.to_owned(),
        path: path.to_owned(),
        svn: 1,
        image_version: 1,
    };
    for part in parts {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("expected key=value, got {part}"))?;
        let number = u32::try_from(parse_u64(value)?)
            .map_err(|_| format!("{key}: does not fit in 32 bits: {value}"))?;
        match key {
            "svn" => input.svn = number,
            "ver" => input.image_version = number,
            other => return Err(format!("unknown entry key {other}")),
        }
    }
    Ok(input)
}

/// Writes a deterministic pattern blob.
fn synth(args: &[String]) -> Result<(), String> {
    let mut seed: u64 = 0;
    let mut len: usize = 0;
    let mut out: Option<String> = None;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let value = || rest_value(arg);
        match arg.as_str() {
            "--seed" => {
                let raw = rest.next().ok_or_else(value)?;
                seed = parse_u64(raw)?;
            }
            "--len" => {
                let raw = rest.next().ok_or_else(value)?;
                len = parse_u64(raw)? as usize;
            }
            "-o" => out = Some(rest.next().ok_or_else(value)?.clone()),
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    let out = out.ok_or("synth needs -o OUT")?;

    // SplitMix64: a seed in, a stream of bytes out, the same every time on
    // every host. Nothing here is random — a blob whose contents varied between
    // builds would change the container's anchor on every build.
    let mut state = seed;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let take = (len - bytes.len()).min(8);
        bytes.extend_from_slice(&z.to_le_bytes()[..take]);
    }
    std::fs::write(&out, &bytes).map_err(|e| format!("write {out}: {e}"))
}

/// Prints the anchor of an existing container.
fn anchor(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("anchor needs a path")?;
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let digest = measure(&bytes).map_err(|e| format!("{path}: {e:?}"))?;
    let hex = tessera_hash::hex(&digest);
    match std::str::from_utf8(&hex) {
        Ok(text) => {
            println!("{text}");
            Ok(())
        }
        Err(_) => Err("digest hex was not ASCII".to_owned()),
    }
}

fn rest_value(arg: &str) -> String {
    format!("{arg} needs a value")
}

fn parse_u64(raw: &str) -> Result<u64, String> {
    let parsed = match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse(),
    };
    parsed.map_err(|_| format!("not a number: {raw}"))
}
