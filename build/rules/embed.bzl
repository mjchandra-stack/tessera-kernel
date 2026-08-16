# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# tessera_embedded_elf: a built artifact as a Rust byte array the kernel can
# link.
#
# The kernel has no filesystem to load a ring-3 program from, so every program
# it starts is compiled into it. The pipeline that does it — measure the file,
# emit a `pub static` of that length, spell the bytes — was written out
# thirty-two times, identically apart from a symbol name.
#
# The output is a build artifact and is never committed
# (docs/lifecycle/04-coding-guidelines.md, "Never edit or check in generated
# code").
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md, D42

load("@rules_rust//rust:defs.bzl", "rust_library")

def tessera_embedded_elf(name, binary, symbol = None, visibility = None):
    """A built binary, as a `no_std` crate holding its bytes.

    Args:
      name: the generated crate, e.g. `net_driver_image`.
      binary: the artifact to embed.
      symbol: the `pub static` the crate exports. Defaults to the name with any
        `_image` suffix dropped, upper-cased, and `_ELF` appended — which is
        what a program's own image crate wants; the per-architecture variants
        and the image store pass their own, because several crates export the
        same symbol for different architectures and the kernel picks one by
        `cfg`.
      visibility: which kernel packages may link it.
    """
    symbol = symbol or (name[:-len("_image")] if name.endswith("_image") else name).upper() + "_ELF"

    # The generated file records where it came from, and a reader of it is not
    # in this package: the comment spells the label in full even when the rule
    # names it relatively.
    origin = binary if binary.startswith("//") else "//{}{}".format(native.package_name(), binary)

    native.genrule(
        name = name + "_src",
        srcs = [binary],
        outs = [name + ".rs"],
        cmd = """
{{
  echo '// SPDX-License-Identifier: Apache-2.0'
  echo '// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>'
  echo '// Generated from {origin} — do not edit.'
  echo '#![no_std]'
  printf 'pub static {symbol}: [u8; %s] = [' "$$(wc -c < $(location {binary}))"
  od -An -v -tu1 $(location {binary}) | tr ' ' '\\n' | grep . | paste -sd, -
  echo '];'
}} > $@
""".format(binary = binary, origin = origin, symbol = symbol),
    )

    rust_library(
        name = name,
        srcs = [":" + name + "_src"],
        crate_name = name,
        edition = "2024",
        visibility = visibility,
    )
