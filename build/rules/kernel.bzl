# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# tessera_kernel_binary: a rust_binary configured for the kernel environment,
# re-exported through the kernel platform transition so it always builds for
# bare metal regardless of the invocation platform.
#
# Both bare-metal triples carry most of the mandated codegen flags (no red
# zone / no FP, panic=abort) but default to a position-independent
# executable, so static relocation is forced here — a kernel links at a
# fixed address (deviation D1, build/README.md).
#
# Architecture-specific codegen lives in `_ARCHITECTURES` below, keyed by the
# `arch` attribute, rather than in a `select()`: a kernel binary is built for
# exactly one architecture (its boot glue names a concrete port), so the
# choice belongs to the target, not to the configuration.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md,
# docs/hardware/01-platform-and-cpu-support.md ("Porting Rules")

load("@rules_rust//rust:defs.bzl", "rust_binary")
load(":arch.bzl", "COMMON_FLAGS", "architecture")
load(":platform_transition.bzl", "platform_binary")


def tessera_kernel_binary(
        name,
        srcs,
        arch = "x86_64",
        deps = [],
        linker_script = None,
        rustc_flags = [],
        compile_data = [],
        flat_image = False,
        **kwargs):
    """A bare-metal kernel binary for one CPU architecture.

    Args:
      name: target name; the transitioned ELF is `<name>.elf`.
      srcs: Rust sources.
      arch: key into `//build/rules:arch.bzl` — the CPU family this kernel boots on.
      deps: Rust dependencies (must include exactly one architecture port).
      linker_script: linker script controlling the image layout.
      rustc_flags: extra flags appended after the architecture's own.
      compile_data: non-source inputs.
      flat_image: also emit `<name>_image.elf`, the same objects linked to a
        headerless flat binary. Needed where the boot protocol is selected by
        a header at offset 0 of a raw image rather than by an ELF (AArch64's
        Linux `Image` protocol, which is what makes the firmware supply a
        device tree). Produced by a second link rather than by objcopy so the
        graph stays hermetic — no host binutils, which in any case are built
        for a single architecture and cannot read a foreign ELF.
      **kwargs: forwarded to `rust_binary`.
    """
    target = architecture("tessera_kernel_binary", arch)

    flags = COMMON_FLAGS + target.kernel_flags + rustc_flags
    data = list(compile_data)
    if linker_script:
        flags.append("-Clink-arg=-T$(location {})".format(linker_script))
        data.append(linker_script)

    variants = [("", flags)]
    if flat_image:
        variants.append(("_image", flags + ["-Clink-arg=--oformat=binary"]))

    for suffix, variant_flags in variants:
        rust_binary(
            name = name + suffix + "_bin",
            srcs = srcs,
            compile_data = data,
            deps = deps,
            edition = "2024",
            rustc_flags = variant_flags,
            target_compatible_with = [
                "@platforms//os:none",
                target.cpu,
            ],
            **kwargs
        )

        platform_binary(
            name = name + suffix,
            binary = ":" + name + suffix + "_bin",
            platform = target.platform,
            visibility = kwargs.get("visibility"),
        )
