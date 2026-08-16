# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# tessera_boot_check: a tier-3 check that boots a kernel image under QEMU and
# reads the verdict off its serial console.
#
# Twenty-four of these were written out in full, and the twenty-four differed in
# a name, a list of inputs and a timeout. The tags never differed and could not:
# QEMU comes from the host for this milestone (deviation D4), so every one of
# them is local-only.
#
# The script itself is where a check's substance lives — which machine, which
# devices, which claims. That stays a file per check; only the wiring collapses.
# Normative: docs/lifecycle/02-build-and-test-infrastructure.md ("Tier 3")

def tessera_boot_check(name, inputs, timeout = "moderate", script = None):
    """Boots a kernel under QEMU and asserts what it printed.

    Args:
      name: the check, e.g. `smoke_boot_aarch64`. The target is `<name>_test`
        and the script defaults to `<name>.sh`.
      inputs: the labels the script takes, in the order it takes them. Each is
        both a data dependency and a positional argument.
      timeout: Bazel's timeout bucket. `long` for the checks that drive a device
        through a whole conversation rather than a single read.
      script: the shell script, when it is not `<name>.sh`.
    """
    native.sh_test(
        name = name + "_test",
        srcs = [script or name + ".sh"],
        args = ["$(location {})".format(i) for i in inputs],
        data = inputs,
        tags = [
            # QEMU is a host package (deviation D4), so these cannot run on a
            # remote executor and must not be cached as though they could.
            "no-remote",
            "requires-qemu",
        ],
        timeout = timeout,
    )
