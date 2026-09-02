# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# tessera_c_binary: a ring-3 program written in C.
#
# The counterpart of `tessera_user_binary` for the other language this system
# admits. `docs/api/03` has always said C is the ABI/FFI boundary, D305 made the
# ABI speak it, and this is what turns a header a C compiler can read into a
# program this kernel can run (docs/roadmap/04, Phase 4).
#
# **Why a genrule and not `cc_binary`.** Bazel's C++ toolchain here targets the
# host: it links against the host's libc and start files, which is precisely
# what a program for this machine must not do. Getting `cc_binary` to emit a
# freestanding ET_EXEC at a fixed load address means a custom `cc_toolchain`,
# which is a build-system project rather than a milestone — and the tree already
# drives host tools directly for exactly this kind of thing (`mkimage.sh`,
# `mkstore`). What is lost is Bazel's header dependency tracking, and what
# replaces it is that both header roots are declared as `srcs` below, so a
# changed header rebuilds the program.
#
# **x86-64 only, and the reason is the environment rather than the design.**
# The host toolchain compiles for the machine it runs on; there is no C
# cross-compiler here, so the one port whose programs the host `gcc` can build
# is the one whose CPU it shares. `tessera/syscall.h` already carries the
# AArch64 sequence, so a machine with a cross-compiler needs no change here
# beyond the triple.
# Normative: docs/roadmap/04-self-hosting.md ("Phase 4"),
# docs/lifecycle/02-build-and-test-infrastructure.md

# Freestanding, no host runtime, and no position independence: this kernel's
# loader maps ET_EXEC at the address the linker script names (D42).
_CFLAGS = [
    "-std=c11",
    "-ffreestanding",
    "-fno-pie",
    "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    # A ring-3 program that trapped on an unaligned or vector access the kernel
    # does not save state for would fault for a reason nothing here explains.
    #
    # **`-mno-red-zone` alone did not do this, and the comment above said it
    # did.** No port here enables SSE for ring 3 or saves its state across a
    # context switch, so an `xmm` register in a user program is an invalid
    # opcode — and `-O2` reaches for one as soon as there is anything worth
    # vectorising. `c-probe` was 84 bytes of text and never gave it the chance;
    # the first C program with a real loop in it faulted `#UD` on a `movq
    # %xmm3` gcc emitted to load two constants at once (`build/README.md`,
    # D316). `-mgeneral-regs-only` is the flag that means what the sentence
    # above claimed, on both machines `tessera/syscall.h` has a sequence for.
    # **A guard against `memcpy` calling itself**, which `-O2` is entitled to
    # produce: it recognises a byte-copy loop and rewrites it as a call to
    # `memcpy`, and inside `memcpy`'s own body that is unbounded recursion.
    # **It changes nothing on this target and is kept anyway.** gcc emits
    # `rep movsb` here rather than a call, so `string.c`'s object file is
    # byte-identical with the flag and without it; AArch64, whose syscall
    # sequence `tessera/syscall.h` already carries, has no such instruction and
    # is where this would bite — unverified, because there is no C
    # cross-compiler in this environment (D318). A precaution that costs a
    # measured zero against a failure that appears as a stack overflow in
    # whichever program first copies anything.
    "-fno-tree-loop-distribute-patterns",
    "-mgeneral-regs-only",
    "-mno-red-zone",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
]

def tessera_c_binary(
        name,
        srcs,
        linker_script = "//build/rules:user-x86_64.ld",
        visibility = None):
    """A ring-3 ELF built from C by the host toolchain.

    Args:
      name: the program, and the ELF it produces.
      srcs: its `.c` files. `crt0.c`, `malloc.c` and `string.c` are added, so a
        program writes `main`, may allocate, and has the `<string.h>` subset.
      linker_script: the port's ring-3 layout.
      visibility: who may depend on the ELF.
    """
    native.genrule(
        name = name,
        srcs = srcs + [
            linker_script,
            "//userspace/libc:crt0",
            "//userspace/libc:malloc",
            "//userspace/libc:string",
            "//userspace/libc:headers",
            "//api/isl:syscall_abi_header",
            "//api/isl:memory_abi_header",
            "//api/isl:process_abi_header",
        ],
        outs = [name + ".elf"],
        # `$(GENDIR)` for the generated ABI headers and the source tree for the
        # hand-written ones: two include roots, because one is a build output
        # and the other is not, and collapsing them would mean copying
        # generated headers into the tree.
        # One object per source, because `gcc -c -o` takes a single input.
        # `basename` is not enough for a name — two directories may hold a
        # `main.c` — so the object is named from the path with the separators
        # flattened, which cannot collide for inputs Bazel already made unique.
        cmd = " && ".join([
            "OUT=$$(mktemp -d)",
            " ".join([
                "for SRC in",
            ] + ["$(locations %s)" % s for s in srcs] + [
                "$(location //userspace/libc:crt0)",
                "$(location //userspace/libc:malloc)",
                "$(location //userspace/libc:string)",
                "; do",
                "gcc",
            ] + _CFLAGS + [
                "-I$(GENDIR)/api/isl/include",
                "-Iuserspace/libc/include",
                "-c $$SRC -o $$OUT/$$(echo $$SRC | tr / _).o || exit 1",
                "; done",
            ]),
            # `--gc-sections` for the same reason every other binary here gets
            # it: the linker script's two segments are what W^X is enforced on,
            # and a section nothing reaches should not be in either.
            "ld -T $(location %s) --gc-sections -o $@ $$OUT/*.o" % linker_script,
            "rm -rf $$OUT",
        ]),
        visibility = visibility,
    )
