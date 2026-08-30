<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Device Logic

Eight crates that know a device and nothing else: the virtio transport, NVMe,
xHCI, SDHCI, PL061, PCIe enumeration, and the Device Tree reader — plus one
test double. Each puts register access behind a trait, forbids `unsafe`
outright, and is host-tested against a mock, so the fragile part of a driver is
the part that never touches a machine.

**They are here because they are not the kernel.** They lived under `kernel/`
until D295, for no better reason than that the kernel was the first thing to
need them, and `docs/roadmap/03` Phase 4 is where that stopped being free: a
repository boundary is affordable exactly when the interface across it is
frozen, and nine user-space packages reaching into `kernel/` for a device
protocol meant the boundary did not exist. Moving them did not change a line of
what they do. It changed what the tree is able to say about them, and
`//tools/checks:boundary_test` now says it — no package under `userspace/`
reaches a package under `kernel/`, by any path.

The layering is `docs/architecture/01`'s own: driver hosts sit above the
kernel, and a class driver's protocol logic belongs with the driver rather than
with the kernel that happens to also run it.

**Which arrow is a violation.** A kernel port may depend on these crates, and
four of them do — the same virtio core drives a disk from inside the kernel on
one port and from ring 3 on another, which is the point. The reverse is what
the gate refuses. Nothing here may depend on `kernel/`: D295's last coupling
was the Device Tree reader normalizing into the kernel's boot vocabulary, and
it now reports [`Region`](devicetree/src/lib.rs) — a base, a length, and the
one distinction firmware draws — leaving the port to widen that into its own
kinds, exactly as the x86-64 glue does for Limine's map.

A user-space program's only path to the kernel is `//userspace/uabi` and the
ISL-generated bindings.
