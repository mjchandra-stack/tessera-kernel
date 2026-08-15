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
load(":platform_transition.bzl", "platform_binary")

# Per-architecture build parameters, mirroring kernel.bzl's table. AArch64
# needs 4 KiB max-page-size (lld's AArch64 default is 64 KiB) so the loader
# can enforce per-page W^X on the program's PT_LOAD segments.
_ARCHITECTURES = {
    "x86_64": struct(
        cpu = "@platforms//cpu:x86_64",
        platform = "//build/platforms:x86_64-kernel",
        flags = [],
    ),
    "aarch64": struct(
        cpu = "@platforms//cpu:aarch64",
        platform = "//build/platforms:aarch64-kernel",
        flags = [
            "-Clink-arg=-z",
            "-Clink-arg=max-page-size=4096",
        ],
    ),
    # `medlow` assumes the low 2 GiB; a user program is linked below that, but
    # the kernel table uses `medium` for the same toolchain reason and matching
    # it keeps one answer per architecture rather than two.
    "riscv64": struct(
        cpu = "@platforms//cpu:riscv64",
        platform = "//build/platforms:riscv64-kernel",
        flags = ["-Ccode-model=medium"],
    ),
}

def tessera_user_binary(
        name,
        srcs,
        linker_script,
        arch = "x86_64",
        deps = [],
        rustc_flags = [],
        visibility = None,
        **kwargs):
    target = _ARCHITECTURES[arch]
    flags = [
        "-Crelocation-model=static",
        "-Clink-arg=--gc-sections",
        "-Clink-arg=-T$(location {})".format(linker_script),
    ] + target.flags + rustc_flags
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
