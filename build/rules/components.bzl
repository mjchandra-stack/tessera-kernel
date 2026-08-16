# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# tessera_image_components: what ring-3 programs a machine's image carries.
#
# The kernel has no filesystem to load a ring-3 program from, so every program
# it starts is compiled into it (see embed.bzl). What followed from that is
# that each port's BUILD file listed the userspace packages it embedded — 36
# labels across five kernels — and each port's `main.rs` carried a
# `#[cfg(has_x)] fn y_elf()` / `#[cfg(not(has_x))] fn y_elf()` pair per
# program, 31 pairs in all, differing only in a symbol.
#
# The list is composition, not kernel: which programs a machine boots with is a
# property of the image being built, and a kernel package naming
# `//userspace/gpu-driver` is a layering the dependency direction otherwise
# forbids. So the list lives in //components, the kernel names one label, and
# these accessors are generated from the same list rather than written twice.
#
# **This is not `docs/architecture/01`'s component manifest**, which is a
# runtime object declaring required and offered capabilities, restart policy
# and budgets. This is the build-time composition — the binary-identity half of
# what that manifest will eventually carry, and nothing else. Naming it
# "manifest" would put two different things under one word.
#
# The output is a build artifact and is never committed
# (docs/lifecycle/04-coding-guidelines.md, "Never edit or check in generated
# code").
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md, D42

load("@rules_rust//rust:defs.bzl", "rust_library")

def tessera_image_components(name, components, visibility = None):
    """The ring-3 programs one machine image carries, as a crate of accessors.

    Args:
      name: the target, e.g. `aarch64`. The crate is always `tessera_components`
        so a port's code reads the same on every architecture; only one is ever
        linked into a given kernel.
      components: `{program: image_label}`. The program name is the accessor —
        `device_manager` generates `pub fn device_manager()` — and the symbol it
        reads is that name upper-cased with `_ELF` appended, which is what
        `tessera_embedded_elf` exports for both the plain and the
        per-architecture image crates.
      visibility: which kernel packages may link it.
    """
    lines = [
        "// SPDX-License-Identifier: Apache-2.0",
        "// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>",
        "// Generated from //components:{} — do not edit.".format(name),
        "//! The ring-3 programs this image carries.",
        "//!",
        "//! A program absent from a build is absent from this crate, so a port",
        "//! naming one it does not embed fails to compile rather than reading",
        "//! an empty slice at boot.",
        "#![no_std]",
    ]
    for program in sorted(components):
        crate = components[program].split(":")[-1]
        lines.append("")
        lines.append("/// The `{}` program, embedded by `{}`.".format(program, components[program]))
        lines.append("pub fn {}() -> &'static [u8] {{".format(program))
        lines.append("    &{}::{}_ELF".format(crate, program.upper()))
        lines.append("}")

    native.genrule(
        name = name + "_src",
        outs = [name + "_components.rs"],
        cmd = "cat > $@ <<'TESSERA_EOF'\n{}\nTESSERA_EOF\n".format("\n".join(lines)),
    )

    rust_library(
        name = name,
        srcs = [":" + name + "_src"],
        crate_name = "tessera_components",
        edition = "2024",
        visibility = visibility,
        deps = [components[program] for program in sorted(components)],
    )
