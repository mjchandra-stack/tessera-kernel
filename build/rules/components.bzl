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
# **What is here and what is in `config/kernel.config`.** The labels are here,
# because Bazel must know them statically to form the dependency edges. Which
# of them a build actually carries is the profile's business, so the accessors
# are emitted by `//tools/kconfig` rather than by this file, and it holds the
# two lists to each other: a label here that the declaration does not know, or
# a component declared for this machine with no label, fails the build.
#
# A program the profile turned off keeps its accessor and returns an empty
# slice — the absence every check already reports, and what the cargo inner
# loop has always seen. Nothing references its image crate, so the linker never
# pulls the bytes in and the image really does lose the program.
#
# The output is a build artifact and is never committed
# (docs/lifecycle/04-coding-guidelines.md, "Never edit or check in generated
# code").
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md, D42

load("//build/rules:embed.bzl", "tessera_embedded_elf")
load("@rules_rust//rust:defs.bzl", "rust_library")

# **The key this tree's program stores are signed with, and it is a development
# key.** It is here, in plain sight, because that is what it is: a seed in a
# build file that anyone reading the repository can sign with. What it buys is
# that the *mechanism* runs — a container is signed, the kernel verifies it, and
# a tampered one is refused — not that the signature means anything against an
# adversary. `docs/security/02`'s custody, rotation and revocation are untouched
# (D173, D289), and the day this tree has a real key the only thing that changes
# is where this string comes from.
PROGRAM_STORE_KEY = "5445535345524150524f4752414d53544f52454445564b45593031323334353637"[:64]

# The anchor id the program store carries, distinct from the system store's 1.
# A verifier holding both must not accept one where the other was meant.
PROGRAM_STORE_ANCHOR_ID = 2

def tessera_image_components(name, components, visibility = None):
    """The ring-3 programs one machine image carries, as a signed store.

    Args:
      name: the target, e.g. `aarch64`. It is also the machine name the
        declaration is read for, so a component's `machines` and the target it
        is listed in cannot disagree. The crate is always `tessera_components`
        so a port's code reads the same on every architecture; only one is ever
        linked into a given kernel.
      components: `{program: binary_label}`. The program name is the accessor —
        `device_manager` generates `pub fn device_manager()` — and it is also
        the name the program is filed under in the store, which is what the
        accessor looks up.
      visibility: which kernel packages may link it.
    """
    catalog = " ".join([
        "{}={}".format(program, components[program].split(":")[-1])
        for program in sorted(components)
    ])

    # **One container per machine, holding every program that machine boots.**
    # It replaces thirty linked symbols with one, and — the reason for the
    # change rather than a side effect — puts the programs under the same
    # measurement the firmware blobs have had since D146: each entry carries its
    # blob's digest, and the whole directory is signed (D290).
    #
    # Every program is at svn 1 and version 1. The anti-rollback machinery reads
    # those for firmware, where a downgrade is the attack; a program store is
    # replaced wholesale with the image it came in, so there is no older one to
    # roll back *to* and a number that pretended otherwise would be decoration.
    native.genrule(
        name = name + "_programs_bin",
        srcs = [components[program] for program in sorted(components)],
        outs = [name + "_programs.bin"],
        cmd = " ".join(
            [
                "$(location //tools/mkstore) build",
                "--anchor-id {}".format(PROGRAM_STORE_ANCHOR_ID),
                "--sign-key {}".format(PROGRAM_STORE_KEY),
                "-o $@",
            ] + [
                "{}=$(location {})".format(program, components[program])
                for program in sorted(components)
            ],
        ),
        tools = ["//tools/mkstore"],
    )

    # **One crate name across every machine**, for the same reason
    # `tessera_components` has one: the generated source below is identical on
    # all five ports, and a per-machine crate name would put the machine into
    # the code rather than into which target gets linked.
    tessera_embedded_elf(
        name = name + "_programs_image",
        binary = ":" + name + "_programs.bin",
        symbol = "PROGRAM_STORE",
        crate = "tessera_program_store",
    )

    native.genrule(
        name = name + "_src",
        srcs = [
            "//config:kernel.config",
            "//config:selected_profile",
        ],
        outs = [name + "_components.rs"],
        cmd = "$(location //tools/kconfig:kconfig) components " +
              "$(location //config:kernel.config) $(location //config:selected_profile) " +
              "{} $@ {}".format(name, catalog),
        tools = ["//tools/kconfig:kconfig"],
    )

    rust_library(
        name = name,
        srcs = [":" + name + "_src"],
        crate_name = "tessera_components",
        edition = "2024",
        visibility = visibility,
        deps = [
            ":" + name + "_programs_image",
            "//kernel/kcore",
        ],
    )
