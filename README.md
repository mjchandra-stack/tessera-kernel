<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Tessera

A capability-based operating system built from scratch in Rust: a small
enforcing kernel, isolated restartable services, and interfaces that are typed,
versioned, and budgeted from day one.

A *tessera* is a single tile in a mosaic — small, sharply bounded, and
meaningful only in composition. That is the architecture. Every driver,
service, and application is an isolated component holding exactly the
capabilities it was granted, composing into a whole that no single tile can
compromise.

## Status

Early but real. The kernel boots on **five architectures**, runs user programs
in ring 3, and drives actual emulated hardware from there.

| | |
| --- | --- |
| **Architectures** | x86-64, AArch64, RISC-V 64, RISC-V 32, ARM 32 |
| **Kernel** | Paging, threads, preemptive scheduler, capabilities, synchronous IPC, demand paging and copy-on-write, external pager, jobs, ELF loading |
| **User space** | 28 ring-3 programs — device manager, driver hosts, drivers, clients, supervisors |
| **Drivers** | 8 device class contracts served from ring 3: block, network, display, audio, input, GPIO, clock, crypto |
| **Tests** | 131 Bazel targets, 24 of which boot a kernel image under QEMU |

Everything runs on emulated hardware. No board support or product work has
started.

### What works today

- **Capabilities, not ambient authority.** A process touches only what it holds
  a handle to. Rights only ever narrow, and a driver handed a device cannot
  pass it on.
- **Drivers in user space.** A ring-3 device manager owns the resource graph
  and grants each driver the device it binds to by class. Drivers map registers
  and DMA buffers through capability-gated syscalls and take their device's
  interrupt in ring 3.
- **Crashes are contained.** A driver that dies by a real CPU fault is
  reclaimed, its device revoked and rebound, and the driver restarted — with
  the client's outstanding request returning an error rather than hanging.
- **One schema language at every boundary.** Syscalls, driver contracts, and
  service protocols are defined in a typed interface schema language that
  generates bindings, wire codecs, and structure-aware fuzz targets.
- **Certification instead of a green checkmark.** A boot runs checks against a
  driver and records which ones *ran*, so a check nobody ran can never look
  like a check that passed.

## Building And Running

**Prerequisites:** [Bazelisk](https://github.com/bazelbuild/bazelisk) on `PATH`
as `bazel`, rustup (the pinned toolchain installs itself on first use), and the
QEMU system packages for the architectures you want to boot
(`qemu-system-x86`, `qemu-system-arm`, `qemu-system-misc`), plus `xorriso` for
the x86-64 ISO.

```bash
# The pre-merge gate, which is the script CI runs: tiers 0-2, rustfmt and
# clippy, and a boot on one architecture.
tools/ci/presubmit.sh

# The post-merge gate: every boot check on every architecture.
tools/ci/continuous.sh

# Or the pieces directly.
bazel test //...                  # every tier
bazel build //... --config=lint   # rustfmt + clippy
bazel test //tools/qemu/...       # just the boot checks
```

Booting the x86-64 image by hand:

```bash
bazel build //kernel/image:tessera_iso

qemu-system-x86_64 -M q35 -m 512M \
  -cdrom bazel-bin/kernel/image/tessera.iso \
  -serial stdio -display none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

Cargo (`cargo test`, `cargo kbuild`) is the inner development loop. Release
artifacts come only from the Bazel graph — see [build/README.md](build/README.md).

## How It Is Tested

Two things are unusual here and worth knowing before reading the tree.

**Boot checks, not just unit tests.** Twenty-four of the test targets build a
kernel image, boot it under QEMU with real emulated devices attached, and grep
the serial output for a verdict the kernel prints about itself. A driver is
proven by driving hardware, not by a mock agreeing with it.

**Claims are inverted, not asserted.** Every property the tree claims has had
its implementation deliberately broken to confirm the test that names it
actually fails. A test nobody has watched fail is a test nobody has checked.

## Repository Layout

```text
api/                 Shared, no_std, host-tested libraries
  isl/               Interface schema language: parser, type checker, IR, codegen
  isl-runtime/       Canonical wire codec for generated bindings
  isl-fuzz/          Structure-aware fuzz targets generated from the schemas
  certification/     The certificate: which checks ran, and which passed
  class-conformance/ One rule battery every device class is held to
  ed25519/           Verify-only signatures for signed update channels
  clock/ power/ usb/ pinctrl/ firmware/ image-store/ hash/ ...

kernel/
  karch/             Architecture porting layer: traits and plain types
  karch-x86_64/      x86-64 port
  karch-aarch64/     AArch64 port
  karch-riscv64/     RISC-V 64 port
  karch-riscv32/     RISC-V 32 port
  karch-arm32/       ARM 32-bit port
  karch-*-common/    Devices a family shares (GICv2 and PL011; PLIC and NS16550A)
  karch-mock/        Mock architecture layer for host unit tests
  arch-conformance/  One battery every port runs, so "implements the porting
                     layer" is a result rather than a claim
  kcore/             Architecture-independent core: memory, threads, scheduler,
                     objects and handles, IPC, jobs, ELF loading, syscall
                     dispatch, structured events
  kernel/            x86-64 boot glue and composition root
  kernel-aarch64/    Per-architecture boot glue, linker scripts, and the boot
  kernel-riscv64/    checks each one runs
  kernel-riscv32/
  kernel-arm32/
  pci/ devicetree/   Discovery: PCIe over ECAM, Flattened Device Tree
  virtio/ nvme/      Device transports, architecture-neutral and unsafe-free
  sdhci/ xhci/
  pl061/ smmu/
  sdhci-mock/        A mock SD controller whose card can be taken out
  width-conformance/ Build gate: the core compiled at a 32-bit word size
  image/             Bootable ISO assembly

userspace/           28 ring-3 programs
  uabi/              What every ring-3 program shares: syscall instruction,
                     failure encoding, per-port address layout
  sdk/               The driver SDK: platform seam, simulator, fault injection,
                     DMA test harness
  device-manager/    Owns the resource graph and grants devices by class
  device-host/       A resident driver host serving clients over channel IPC
  *-driver/          Ring-3 class drivers
  *-client/          Ring-3 clients that exercise a class contract

build/               Bazel platforms, rules, and the deviation ledger
tools/
  ci/                The pre-merge and post-merge gates, as scripts a
                     developer runs unchanged
  checks/            Gates: SPDX headers, license pins, unsafe inventory
  lint/              rustfmt and clippy targets
  qemu/              Boot checks
  certify/           Reads a boot's certificate and admits or refuses a driver
  mkstore/           Builds and signs image stores
third_party/         Vendored dependencies (hash-pinned, permissive licenses)
docs/                Architecture and design specifications
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) —
Apache-2.0 inbound = outbound, with a DCO sign-off (`git commit -s`) on every
commit.

The project's one standing rule: no component stays named but undesigned, no
hot path ships unbudgeted, and no degradation is silent.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright 2026 Jagadeesh Chandra Muddana.
