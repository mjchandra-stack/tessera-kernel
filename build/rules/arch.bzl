# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# One table per architecture, for every rule that builds for one.
#
# The kernel rule and the ring-3 rule each used to carry their own copy, and
# the two agreed about the platform an architecture builds for only because
# nobody had edited one of them. They must agree: a user program and the kernel
# that loads it are the same machine, and a program built for a different
# platform than its kernel is a defect no test would name.
#
# `.cargo/config.toml` is a third copy, and the one that cannot be merged —
# cargo will not read Starlark. `//tools/checks:flags_test` holds it to this
# table instead.
# Normative: docs/hardware/01-platform-and-cpu-support.md ("Porting Rules"),
# docs/lifecycle/02-build-and-test-infrastructure.md

# Flags every bare-metal binary gets, kernel or ring 3. Both triples default to
# a position-independent executable and neither may be one: a kernel links at a
# fixed address and a user program is ET_EXEC (deviation D1, D42).
COMMON_FLAGS = [
    "-Crelocation-model=static",
    "-Clink-arg=--gc-sections",
]

# `user_flags = None` means the architecture has no ring-3 support yet: the
# porting layer and the kernel are there, `//userspace/uabi` has no syscall
# sequence for it. Asking for a user binary on one fails rather than silently
# building for another machine.
ARCHITECTURES = {
    # -Ccode-model=kernel places the image in the topmost 2 GiB, which the
    # higher-half link address and Limine both require. It is an x86-64-only
    # code model.
    "x86_64": struct(
        cpu = "@platforms//cpu:x86_64",
        platform = "//build/platforms:x86_64-kernel",
        kernel_flags = ["-Ccode-model=kernel"],
        user_flags = [],
    ),
    # AArch64 uses the default code model and reaches its high half through
    # TTBR1. A ring-3 program needs 4 KiB max-page-size — lld's AArch64 default
    # is 64 KiB — so the loader can enforce per-page W^X on its PT_LOADs.
    "aarch64": struct(
        cpu = "@platforms//cpu:aarch64",
        platform = "//build/platforms:aarch64-kernel",
        kernel_flags = [],
        user_flags = [
            "-Clink-arg=-z",
            "-Clink-arg=max-page-size=4096",
        ],
    ),
    # As AArch64: the default code model, and the image links at its physical
    # load address.
    "arm32": struct(
        cpu = "@platforms//cpu:armv7",
        platform = "//build/platforms:arm32-kernel",
        kernel_flags = [],
        user_flags = None,
    ),
    # -Ccode-model=medium keeps the image reachable by auipc-relative
    # addressing within a 2 GiB window, which the `virt` load address at
    # 0x8020_0000 sits inside. The `medlow` default assumes the low 2 GiB and
    # would relocate out of range. A user program links below that, but the
    # kernel needs `medium` for the toolchain reason above and matching it
    # keeps one answer per architecture rather than two.
    "riscv64": struct(
        cpu = "@platforms//cpu:riscv64",
        platform = "//build/platforms:riscv64-kernel",
        kernel_flags = ["-Ccode-model=medium"],
        user_flags = ["-Ccode-model=medium"],
    ),
    # Same reasoning as riscv64: the image sits at 0x8040_0000.
    "riscv32": struct(
        cpu = "@platforms//cpu:riscv32",
        platform = "//build/platforms:riscv32-kernel",
        kernel_flags = ["-Ccode-model=medium"],
        user_flags = None,
    ),
}

def architecture(rule, arch):
    """The table entry for `arch`, or a build error naming what is known."""
    if arch not in ARCHITECTURES:
        fail("{}: unknown arch {}; known: {}".format(rule, arch, sorted(ARCHITECTURES)))
    return ARCHITECTURES[arch]
