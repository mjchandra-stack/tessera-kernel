// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tier-0 gate: no log format string longer than 150 characters.
//!
//! The rendered line is what the rule is about, and only a boot can measure
//! that — every check under //tools/qemu asserts it against the serial log.
//! This runs one build earlier, on the half that can be read from source.
//!
//! Normative: docs/observability/01-debugging-monitoring-tracing-logging.md

use tessera_checks::{assert_no_violations, logging, walk};

#[test]
fn no_log_line_is_longer_than_the_limit() {
    let root = walk::source_root();
    assert!(
        root.join("kernel/kcore/src/console.rs").is_file(),
        "no kernel sources under {} — gate misconfigured",
        root.display()
    );
    assert_no_violations("logging", &logging::check(&root));
}
