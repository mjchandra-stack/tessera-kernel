// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Vendored-dependency license gate: every `third_party/<pkg>/` carries a
//! `LICENSE`, a `METADATA` record naming an allowlisted license, and a
//! content hash for every vendored file. Nothing enters the tree unpinned.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Dependencies")
//!
//! METADATA format (line-oriented, `#` comments):
//! ```text
//! name: limine
//! version: 10.5.0
//! upstream: https://github.com/limine-bootloader/limine
//! license: BSD-2-Clause
//! sha256: <hex> <path-relative-to-package>
//! ```

use crate::Violation;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const LICENSE_ALLOWLIST: &[&str] = &["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause"];

const REQUIRED_KEYS: &[&str] = &["name", "version", "upstream", "license"];

/// Checks every `third_party/` package among `files` (absolute path,
/// repo-relative path). An empty `third_party/` passes trivially.
pub fn check_third_party(files: &[(PathBuf, String)]) -> Vec<Violation> {
    let mut violations = Vec::new();
    // package name -> (rel-within-package -> absolute path)
    let mut packages: BTreeMap<String, BTreeMap<String, PathBuf>> = BTreeMap::new();
    for (abs, rel) in files {
        if let Some(rest) = rel.strip_prefix("third_party/")
            && let Some((pkg, inner)) = rest.split_once('/')
        {
            packages
                .entry(pkg.to_owned())
                .or_default()
                .insert(inner.to_owned(), abs.clone());
        }
    }

    for (pkg, contents) in &packages {
        let pkg_path = format!("third_party/{pkg}");
        if !contents.contains_key("LICENSE") {
            violations.push(Violation {
                path: pkg_path.clone(),
                reason: "missing LICENSE file".to_owned(),
            });
        }
        let Some(metadata_path) = contents.get("METADATA") else {
            violations.push(Violation {
                path: pkg_path.clone(),
                reason: "missing METADATA file".to_owned(),
            });
            continue;
        };
        let metadata = match std::fs::read_to_string(metadata_path) {
            Ok(text) => text,
            Err(err) => {
                violations.push(Violation {
                    path: format!("{pkg_path}/METADATA"),
                    reason: format!("unreadable: {err}"),
                });
                continue;
            }
        };
        violations.extend(check_package(&pkg_path, contents, &metadata));
    }
    violations
}

fn check_package(
    pkg_path: &str,
    contents: &BTreeMap<String, PathBuf>,
    metadata: &str,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut keys: BTreeMap<String, String> = BTreeMap::new();
    let mut pins: BTreeMap<String, String> = BTreeMap::new();

    for (lineno, line) in metadata.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            violations.push(Violation {
                path: format!("{pkg_path}/METADATA"),
                reason: format!("line {}: not a `key: value` line", lineno + 1),
            });
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key == "sha256" {
            match value.split_once(char::is_whitespace) {
                Some((hex, path)) => {
                    pins.insert(path.trim().to_owned(), hex.trim().to_lowercase());
                }
                None => violations.push(Violation {
                    path: format!("{pkg_path}/METADATA"),
                    reason: format!("line {}: sha256 needs `<hex> <path>`", lineno + 1),
                }),
            }
        } else {
            keys.insert(key.to_owned(), value.to_owned());
        }
    }

    for required in REQUIRED_KEYS {
        if !keys.contains_key(*required) {
            violations.push(Violation {
                path: format!("{pkg_path}/METADATA"),
                reason: format!("missing required key `{required}`"),
            });
        }
    }
    if let Some(license) = keys.get("license")
        && !LICENSE_ALLOWLIST.contains(&license.as_str())
    {
        violations.push(Violation {
            path: format!("{pkg_path}/METADATA"),
            reason: format!("license `{license}` is not on the allowlist {LICENSE_ALLOWLIST:?}"),
        });
    }

    // Every vendored file must be pinned, and every pin must match the
    // vendored bytes. METADATA itself and first-party Bazel build glue are
    // the only exceptions.
    for (inner, abs) in contents {
        if inner == "METADATA" || inner == "BUILD.bazel" {
            continue;
        }
        match pins.remove(inner) {
            None => violations.push(Violation {
                path: format!("{pkg_path}/{inner}"),
                reason: "vendored file has no sha256 pin in METADATA".to_owned(),
            }),
            Some(expected) => match std::fs::read(abs) {
                Ok(bytes) => {
                    let digest = tessera_hash::hex(&tessera_hash::sha256(&bytes));
                    // Infallible: `hex` emits only ASCII hex digits.
                    let actual = String::from_utf8_lossy(&digest);
                    if actual != expected {
                        violations.push(Violation {
                            path: format!("{pkg_path}/{inner}"),
                            reason: format!("sha256 mismatch: pinned {expected}, actual {actual}"),
                        });
                    }
                }
                Err(err) => violations.push(Violation {
                    path: format!("{pkg_path}/{inner}"),
                    reason: format!("unreadable: {err}"),
                }),
            },
        }
    }
    for (stale, _) in pins {
        violations.push(Violation {
            path: format!("{pkg_path}/{stale}"),
            reason: "sha256 pin for a file that does not exist".to_owned(),
        });
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_third_party_passes() {
        assert!(check_third_party(&[]).is_empty());
    }

    #[test]
    fn rejects_disallowed_license_and_missing_keys() {
        let violations = check_package("third_party/x", &BTreeMap::new(), "license: GPL-3.0\n");
        assert!(violations.iter().any(|v| v.reason.contains("allowlist")));
        assert!(violations.iter().any(|v| v.reason.contains("`name`")));
    }
}
