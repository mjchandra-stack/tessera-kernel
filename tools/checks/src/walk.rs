// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Source-tree discovery for the tier-0 gates. Under Bazel the checked
//! sources arrive as runfiles beneath `$TEST_SRCDIR/_main`; under cargo the
//! gates walk the repository from the crate's manifest directory.

use std::path::{Path, PathBuf};

/// Directories never walked: VCS state, build outputs, editor/session state.
const SKIPPED_DIRS: &[&str] = &[".git", "target", ".cache", ".claude"];

/// Root of the checked source tree.
pub fn source_root() -> PathBuf {
    if let Ok(dir) = std::env::var("TEST_SRCDIR") {
        return PathBuf::from(dir).join("_main");
    }
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let repo = Path::new(&dir).join("..").join("..");
        if let Ok(canonical) = repo.canonicalize() {
            return canonical;
        }
    }
    PathBuf::from(".")
}

/// All regular files under `root` as (absolute path, repo-relative path with
/// forward slashes), sorted by relative path.
pub fn walk_files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            // Follows symlinks: Bazel runfiles are symlink forests.
            let meta = match std::fs::metadata(&path) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if meta.is_dir() {
                if SKIPPED_DIRS.contains(&name.as_str()) || name.starts_with("bazel-") {
                    continue;
                }
                stack.push(path);
            } else if meta.is_file()
                && let Ok(rel) = path.strip_prefix(root)
            {
                out.push((path.clone(), rel.to_string_lossy().replace('\\', "/")));
            }
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// True if the head of a file looks like binary content (NUL byte present).
pub fn is_binary(head: &[u8]) -> bool {
    head.contains(&0)
}
