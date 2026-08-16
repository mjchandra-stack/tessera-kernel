# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# isl_bindings: one schema's build graph — the codegen, the crate it produces,
# the conformance test that round-trips its golden vectors, and (where the
# schema declares an `@abi` struct) the structure-aware fuzz target and the
# library `//api/isl-fuzz` links to count what was fuzzed.
#
# Written out by hand, that is five or six targets per schema and thirty-one
# schemas. The shape never varied; only the names did, and a name is not a
# reason to repeat a rule. What survives as an argument here is what genuinely
# differs between schemas: which crate the bindings are called, who may depend
# on them, and the handful of test targets whose names predate the convention.
#
# Generated code is a build output and is never committed
# (docs/lifecycle/04-coding-guidelines.md, "Never edit or check in generated
# code").
# Normative: docs/api/03-interface-schema-language.md,
# docs/lifecycle/02-build-and-test-infrastructure.md

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

_RUNTIME = "//api/isl-runtime:isl_runtime"
_FUZZ_ENGINE = "//api/isl-fuzz:isl_fuzz"

def isl_bindings(
        name,
        crate = None,
        schema = None,
        visibility = None,
        generated = None,
        bindings = None,
        test = None,
        test_srcs = None,
        test_deps = [],
        fuzz = False,
        fuzz_test = None):
    """The build graph for one ISL schema.

    Args:
      name: the schema's stem, e.g. `audio_output` for `examples/audio_output.isl`.
      crate: the generated crate's name. Defaults to `name`; a few schemas emit
        a crate whose name says `_abi` where the file does not.
      schema: the schema file. Defaults to `examples/<name>.isl`.
      visibility: who may depend on the bindings crate.
      generated: the codegen target's name. Defaults to `<crate>_generated`.
      bindings: the bindings target's name. Defaults to `<crate>_bindings`.
      test: the conformance test's name. Defaults to `<name>_conformance_test`.
      test_srcs: its sources. Default `["tests/<name>_conformance.rs"]`.
      test_deps: dependencies beyond the bindings and the wire runtime.
      fuzz: whether the schema declares an `@abi` struct, and so owes a fuzz
        target. `//tools/checks:fuzz_gate_test` is what decides that it does —
        this flag only records the answer.
      fuzz_test: the fuzz test's name. Defaults to `<name>_fuzz_test`.
    """
    crate = crate or name
    schema = schema or "examples/{}.isl".format(name)
    generated = generated or "{}_generated".format(crate)
    bindings = bindings or "{}_bindings".format(crate)

    native.genrule(
        name = generated,
        srcs = [schema],
        outs = ["{}.rs".format(generated)],
        cmd = "$(location :islc) emit-rust $(location {}) > $@".format(schema),
        tools = [":islc"],
    )

    rust_library(
        name = bindings,
        srcs = [":" + generated],
        crate_name = crate,
        edition = "2024",
        visibility = visibility,
        deps = [_RUNTIME],
    )

    rust_test(
        name = test or "{}_conformance_test".format(name),
        srcs = test_srcs or ["tests/{}_conformance.rs".format(name)],
        edition = "2024",
        deps = [":" + bindings] + test_deps + [_RUNTIME],
    )

    if not fuzz:
        return

    fuzz_src = "{}_fuzz_src".format(name)
    fuzz_deps = [":" + bindings, _FUZZ_ENGINE]

    native.genrule(
        name = fuzz_src,
        srcs = [schema],
        outs = ["{}_fuzz.rs".format(name)],
        cmd = "$(location :islc) emit-fuzz {} $(location {}) > $@".format(crate, schema),
        tools = [":islc"],
    )

    rust_test(
        name = fuzz_test or "{}_fuzz_test".format(name),
        srcs = [":" + fuzz_src],
        edition = "2024",
        deps = fuzz_deps,
    )

    # The same generated targets as a library, so `//api/isl-fuzz:fuzz_all` can
    # run every schema's targets in one program and count what it ran.
    rust_library(
        name = "{}_fuzz".format(name),
        srcs = [":" + fuzz_src],
        crate_name = "{}_fuzz".format(name),
        edition = "2024",
        visibility = ["//api/isl-fuzz:__pkg__"],
        deps = fuzz_deps,
    )
