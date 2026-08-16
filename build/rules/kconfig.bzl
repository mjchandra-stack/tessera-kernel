# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# tessera_kconfig: the kernel's sizing constants, for one profile.
#
# The same program the cargo inner loop runs from `kernel/kcore/build.rs`
# (`//tools/kconfig`) reads the same declaration (`config/kernel.config`), so
# the constants a host unit test compiles against and the ones a release image
# is built from cannot differ. The two paths are bridged by the
# `kconfig_bazel` cfg, exactly as the ISL bindings are bridged by `isl_bazel`
# (D24/D54).
#
# The output is a build artifact and is never committed
# (docs/lifecycle/04-coding-guidelines.md, "Never edit or check in generated
# code").
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md

load("@rules_rust//rust:defs.bzl", "rust_library")

def tessera_kconfig(name, profile, visibility = None):
    """The sizing constants a kernel built with `profile` compiles against.

    Args:
      name: the target; the crate is always `tessera_kconfig_values`, so the
        kernel's `use` reads the same whichever profile it was built with.
      profile: the profile file under `profiles/`.
      visibility: which packages may link it.
    """
    native.genrule(
        name = name + "_src",
        srcs = ["kernel.config", profile],
        outs = [name + "_kconfig.rs"],
        cmd = "$(location //tools/kconfig:kconfig) $(location kernel.config) $(location %s) $@ --crate" % profile,
        tools = ["//tools/kconfig:kconfig"],
    )

    rust_library(
        name = name,
        srcs = [":" + name + "_src"],
        crate_name = "tessera_kconfig_values",
        edition = "2024",
        visibility = visibility,
    )
