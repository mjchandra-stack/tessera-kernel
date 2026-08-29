// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `checks::walk`.
//!
//! **The walker had no tests, which is how `build-out` came to be missing from
//! the skip list.** Every gate in this directory is a walk plus a predicate, so
//! a directory the walk should not enter is a defect in all of them at once —
//! and it surfaced as four thousand licence violations rather than as anything
//! naming the walk (build/README.md, D274).

use super::*;

/// A tree with one real source file and one file under each skipped directory.
fn tree_with_generated_output(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("temp tree");
    std::fs::write(dir.join("src/real.rs"), "// a source file\n").expect("source");
    for skipped in SKIPPED_DIRS {
        let nested = dir.join(skipped).join("deep");
        std::fs::create_dir_all(&nested).expect("skipped dir");
        std::fs::write(nested.join("generated.html"), "<html>no header</html>")
            .expect("generated file");
    }
    dir
}

/// Nothing under a skipped directory is walked, at any depth.
#[test]
fn generated_output_is_never_walked() {
    let dir = tree_with_generated_output("tessera-walk-skips");
    let found = walk_files(&dir);
    assert_eq!(
        found.len(),
        1,
        "only the real source file should be walked: {found:?}"
    );
    assert_eq!(found[0].1, "src/real.rs");
}

/// `build-out` specifically, because that is the one that was missing and the
/// one the tree's own `tools/ci/docs.sh` creates.
#[test]
fn the_documentation_scripts_output_is_skipped() {
    assert!(
        SKIPPED_DIRS.contains(&"build-out"),
        "tools/ci/docs.sh writes generated HTML here, and generated HTML \
         carries no SPDX header",
    );
}
