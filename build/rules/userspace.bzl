# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# tessera_user_binary: a rust_binary for a ring-3 user program — a real ELF the
# kernel's loader parses and maps (docs/api/01: user programs are loaded, not
# built into the kernel). Unlike the kernel binary it uses the default (small)
# code model and links low-half at a user address via its own linker script.
# Re-exported through the kernel platform transition so it builds for bare
# x86-64 from a plain host `bazel build //...`.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md, D42

load("@rules_rust//rust:defs.bzl", "rust_binary")
load(":arch.bzl", "COMMON_FLAGS", "architecture")
load(":platform_transition.bzl", "platform_binary")


def tessera_user_binary(
        name,
        srcs,
        linker_script,
        arch = "x86_64",
        deps = [],
        rustc_flags = [],
        visibility = None,
        **kwargs):
    target = architecture("tessera_user_binary", arch)
    if target.user_flags == None:
        fail("tessera_user_binary: {} has no ring-3 support yet (//userspace/uabi has no syscall sequence for it)".format(arch))
    flags = COMMON_FLAGS + [
        "-Clink-arg=-T$(location {})".format(linker_script),
    ] + target.user_flags + rustc_flags
    rust_binary(
        name = name + "_bin",
        srcs = srcs,
        compile_data = [linker_script],
        deps = deps,
        edition = "2024",
        rustc_flags = flags,
        target_compatible_with = [
            "@platforms//os:none",
            target.cpu,
        ],
        **kwargs
    )

    platform_binary(
        name = name,
        binary = ":" + name + "_bin",
        platform = target.platform,
        visibility = visibility,
    )
