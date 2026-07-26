# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# Outgoing platform transition so kernel binaries build for their bare-metal
# platform from a plain host-platform `bazel build //...` — one graph for
# everything, no separate invocation per platform.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md

def _kernel_platform_transition_impl(settings, attr):
    return {"//command_line_option:platforms": str(attr.platform)}

_kernel_platform_transition = transition(
    implementation = _kernel_platform_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _platform_binary_impl(ctx):
    binary = ctx.attr.binary[0]
    src = binary[DefaultInfo].files_to_run.executable
    out = ctx.actions.declare_file(ctx.label.name + ".elf")
    ctx.actions.symlink(output = out, target_file = src)
    return [DefaultInfo(files = depset([out]))]

platform_binary = rule(
    implementation = _platform_binary_impl,
    doc = "Re-exports `binary` built for the given target platform.",
    attrs = {
        "binary": attr.label(
            cfg = _kernel_platform_transition,
            executable = True,
            mandatory = True,
        ),
        # Mandatory, deliberately: with more than one bare-metal platform in
        # the graph, a defaulted target platform would let a mis-wired binary
        # build silently for the wrong architecture.
        "platform": attr.label(
            mandatory = True,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
