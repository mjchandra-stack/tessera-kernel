<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Platform And CPU Support

## Goals

The OS supports multiple CPU families and platform types without letting
hardware-specific code leak throughout the system.

Supported platform categories:

- Phones and tablets.
- Laptops and desktops.
- Workstations.
- Wearables.
- Embedded systems.
- Edge servers.
- Virtual machines.
- Development boards.

Supported CPU architecture families:

- x86-64.
- AArch64.
- RISC-V 64, targeting the RVA23 profile.
- ARM 32-bit (ARMv7-A class application profiles and later).
- RISC-V 32-bit.
- Future capability or memory-safe architectures.

The three 64-bit families are the primary ABI targets. The two 32-bit
families are first-class ports for the embedded and appliance profiles, not
compatibility modes of their 64-bit siblings and not legacy accommodations:
32-bit application cores are current products in that market. Every family
enters through the same porting layer and must pass the same architecture
conformance battery; a port that cannot is absent, not partial.

## Modern Hardware Only

The supported set is bounded at the front as well as the back. The following
are out of scope permanently, by policy rather than by sequencing:

- CPU architectures no longer in production, and superseded modes of
  supported ones: 32-bit x86 and x86 real/protected-mode legacy, ARMv5 and
  earlier, MIPS, PowerPC, SPARC, Itanium, and big-endian variants of any
  supported family.
- Legacy firmware and boot paths where a modern one exists: PC BIOS in favour
  of UEFI, and hardware discovery that is neither device tree nor ACPI.
- Platform devices retained only for backward compatibility: the 8259 PIC,
  the 8253/8254 PIT, the CMOS RTC, PS/2 controllers, ISA and ISA DMA,
  parallel, serial-over-ISA beyond the boot console, floppy, and IDE/PATA.

The modern equivalents are the baseline rather than an optimisation: APIC,
GIC, or PLIC for interrupt routing; the per-CPU architectural timer for time;
NVMe for storage; xHCI for USB; PCIe with ECAM for enumeration; and
firmware-supplied device tree or ACPI for discovery.

This is a constraint on the OS, not a claim about what the emulator offers. A
port that reaches for a legacy device to get its first boot green incurs a
tracked deviation with a closure plan, exactly as a memory-safety exception
does — it is a debt with a due date, never a supported configuration.

## Emulation-First Development

Every subsystem is developed and validated on the emulated platform before it
is validated on physical hardware, at every stage of the roadmap rather than
only during core-bet validation. Where the emulator models the device, the
driver, the class contract, the service, and the user-space path above them
are built and tested there first. Hardware bring-up then confirms a working
design against real timing, errata, and firmware, instead of being the place
where the design is discovered.

Two consequences the build honours:

- The architecture matrix above is the set of machines the emulator can run,
  so adding a port is never blocked on procurement. Each family's reference
  virtual machine is the QEMU `virt`-class platform for that family, or `q35`
  on x86-64.
- "Green under emulation" is not a weaker claim wearing the same word. The
  boot tests are the tests hardware will run, and anything that reproduces
  only under emulation is a tracked gap. What emulated execution may *not* be
  used to claim is bounded separately: timing results are governed by
  `../prototypes/01-ipc-benchmark-harness.md`, which admits emulated runs for
  harness correctness only.

## Architecture Porting Layer

Each CPU family implements an architecture porting layer. The layer exposes a
small set of primitives to the kernel core:

- CPU discovery.
- Boot CPU and secondary CPU startup.
- Trap entry and return.
- Syscall entry and return.
- Context switch.
- Page table creation and update.
- TLB shootdown.
- Atomic operations.
- Cache maintenance.
- Interrupt controller interface.
- Timer interface.
- CPU idle states.
- Memory ordering primitives.
- User-kernel copy helpers.
- Architecture security controls.

The kernel core never directly reaches into architecture-specific registers
outside this layer.

## Platform Support Package

A platform support package describes board or device-specific integration:

- Boot protocol.
- Firmware interfaces.
- Firmware power and sleep interfaces (PSCI, ACPI sleep states) consumed by
  `../power/01-power-management.md`.
- Memory map.
- Interrupt topology.
- Power domains.
- Clock and reset controllers.
- Security domains.
- Device tree or ACPI overrides.
- Firmware blobs and version constraints.
- Known hardware quirks.
- Recovery mode.
- Update constraints.

Platform support packages are signed, versioned, and tested against OS
compatibility suites.

## Heterogeneous Processors

Modern systems may contain:

- Performance CPU cores.
- Efficiency CPU cores.
- Low-power always-on cores.
- DSPs.
- NPUs.
- GPUs.
- ISPs.
- Video encode/decode engines.
- Secure enclaves.
- Sensor hubs.
- Radio processors.

The OS represents these as schedulable or service-managed compute resources.
They are not treated as invisible implementation details.

The resource graph records:

- Which memory regions each processor can access.
- Which interrupts each processor can raise.
- Which firmware owns each processor.
- Which security domain controls it.
- Which driver or runtime schedules it.
- Which power and thermal domains it belongs to.

## CPU Feature Model

CPU features are exposed through stable feature sets, not raw vendor-specific
flags. Raw details remain available for diagnostics.

Feature sets include:

- Virtualization.
- Memory tagging.
- Pointer authentication or control-flow integrity.
- Trusted execution.
- Vector extensions.
- Matrix extensions.
- Cryptographic acceleration.
- Fine-grained timers.
- Performance counters.
- Cache partitioning.
- Memory encryption.

Applications should target feature profiles. System services decide when to use
specific CPU capabilities.

## Endianness And Word Size

The primary ABI assumes 64-bit little-endian platforms, and the 32-bit ports
are little-endian too: pointer width varies across the supported set, byte
order does not. Big-endian platforms are out of scope.

Because 32-bit is a supported target rather than a possibility, the design
carries the cost rather than the assumption. Interface schemas declare
explicit field widths and never encode a pointer; the kernel core is written
against the porting layer's address types rather than an assumed 64-bit
`usize`; and any structure shared between kernel and user space has one
layout per pointer width, generated, not hand-maintained.

Two consequences are easy to get backwards. A **physical address is wider
than a pointer** on both 32-bit families — ARMv7-A with LPAE addresses 40
bits and RISC-V Sv32 addresses 34 — so physical addresses are a fixed 64-bit
type everywhere and are never narrowed to a pointer. And a **64-bit atomic is
not portable**: it does not exist below a 64-bit atomic width, so the core
uses its own 64-bit counter type rather than the standard one.

This is enforced by compiling, not by review. The architecture-independent
crates are built for a 32-bit target on every build, so a 64-bit assumption
fails in the change that introduces it rather than in the port that
eventually needs it.

Compatibility layers can support foreign binary ABIs
(`../api/04-linux-and-posix-compatibility.md`) where a product profile
requires it. That is a question about binaries, and is not a licence to
support the hardware ruled out under "Modern Hardware Only".

## Virtual Platform Support

The OS must boot well as a guest. The virtual platform profile includes:

- Paravirtual clock.
- Paravirtual interrupt controller where available.
- Virtio-style devices.
- Synthetic GPU and display.
- Balloon memory device.
- Shared clipboard and file exchange policy.
- VM attestation.
- Confidential VM support where hardware permits.

The guest profile should use the same driver framework as physical hardware.

## Porting Rules

To add a new CPU architecture or platform:

1. Implement the architecture porting layer.
2. Provide boot and firmware integration.
3. Provide a platform support package.
4. Produce a normalized hardware resource graph.
5. Pass kernel architecture tests.
6. Pass driver binding tests.
7. Pass security and boot measurement tests.
8. Pass suspend, resume, hotplug, and update tests for the target product
   profile.

No product-specific code should be accepted into core services unless it
represents a general platform capability.

