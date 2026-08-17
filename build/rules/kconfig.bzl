# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# The kernel's configuration surface, in the build graph.
#
# `--//config:profile=<name>` selects which profile every target in the
# invocation is built from — the sizing constants `kcore` compiles against and
# the ring-3 programs each image carries, together, because they are one
# statement about one machine. It is a build setting rather than a second set
# of targets: a kernel built two ways should be one graph configured two ways,
# not two graphs to keep in step.
#
# **Why the profile list is globbed rather than written here.** A profile the
# build cannot select is a profile nobody can use, and a list of them in
# Starlark is a list somebody has to remember to extend. Dropping a file into
# `config/profiles/` is the whole of adding a profile.
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

# The profile this invocation builds. Its own rule rather than skylib's
# `string_flag`: this tree declares two Bazel modules and adding a third for
# eight lines of Starlark would be a supply-chain entry for a convenience.
def _profile_flag_impl(_ctx):
    return []

profile_flag = rule(
    implementation = _profile_flag_impl,
    build_setting = config.string(flag = True),
    doc = "Which profile under config/profiles/ this build uses.",
)

def _profile_transition_impl(_settings, attr):
    return {"//config:profile": attr.profile}

_profile_transition = transition(
    implementation = _profile_transition_impl,
    inputs = [],
    outputs = ["//config:profile"],
)

def _profile_binary_impl(ctx):
    files = ctx.attr.binary[0][DefaultInfo].files.to_list()
    if len(files) != 1:
        fail("profile_binary expects one file from %s, got %d" % (ctx.attr.binary[0].label, len(files)))

    # Renamed, not re-exported. A transitioned target keeps its original
    # filename, and two configurations of one kernel therefore have the same
    # runfiles path — so a test given both would silently receive one of them
    # twice. (Found exactly that way: the boot check compared the two images'
    # sizes and got the same number.)
    out = ctx.actions.declare_file(ctx.label.name + ".elf")
    ctx.actions.symlink(output = out, target_file = files[0])
    return [DefaultInfo(files = depset([out]))]

profile_binary = rule(
    implementation = _profile_binary_impl,
    doc = """Re-exports `binary`, built from a named profile.

    What makes a second configuration a thing that has been built rather than a
    thing the tool allows. Both images come from one graph, which is the point:
    a target per profile would be two graphs to keep in step, and the second one
    would rot.

    **A profile name with no file is not an error here**, because a `select`
    that matches nothing takes its default arm — so this would quietly produce
    the default kernel under another name. The check that closes that is in the
    boot test, which requires the two images to actually differ.""",
    attrs = {
        "binary": attr.label(cfg = _profile_transition, mandatory = True),
        "profile": attr.string(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

def tessera_kconfig(name, visibility = None):
    """The configuration surface: the profile flag, and the constants it picks.

    Declares `--//config:profile`, one `config_setting` per profile on disk,
    `:selected_profile` (the file that flag resolves to), and `name` — the
    crate of sizing constants the kernel core compiles against.

    Args:
      name: the constants target; the crate is always
        `tessera_kconfig_values`, so the kernel's `use` reads the same
        whichever profile it was built with.
      visibility: which packages may link the constants.
    """
    profiles = [
        path[len("profiles/"):-len(".profile")]
        for path in native.glob(["profiles/*.profile"])
    ]
    if not profiles:
        fail("config/profiles/ is empty: every build needs a profile to select")
    if "default" not in profiles:
        fail("config/profiles/default.profile is missing: it is what --//config:profile falls back to")

    profile_flag(
        name = "profile",
        build_setting_default = "default",
        visibility = ["//visibility:public"],
    )
    for profile in profiles:
        native.config_setting(
            name = "profile_" + profile,
            flag_values = {":profile": profile},
            visibility = ["//visibility:public"],
        )

    # The default arm is the fallback rather than an entry of its own, so an
    # invocation that names no profile still resolves — and the file it
    # resolves to is one somebody chose, not the absence of a choice.
    selected = {"//conditions:default": ["profiles/default.profile"]}
    for profile in profiles:
        if profile != "default":
            selected[":profile_" + profile] = ["profiles/" + profile + ".profile"]

    native.filegroup(
        name = "selected_profile",
        srcs = select(selected),
        visibility = ["//visibility:public"],
    )

    native.genrule(
        name = name + "_src",
        srcs = ["kernel.config", ":selected_profile"],
        outs = [name + "_kconfig.rs"],
        cmd = "$(location //tools/kconfig:kconfig) emit $(location kernel.config) " +
              "$(location :selected_profile) $@ --crate",
        tools = ["//tools/kconfig:kconfig"],
    )

    rust_library(
        name = name,
        srcs = [":" + name + "_src"],
        crate_name = "tessera_kconfig_values",
        edition = "2024",
        visibility = visibility,
    )
