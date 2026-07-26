<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Storage, Networking, USB, And PCIe Drivers

## Storage Stack

### Layers

```text
Applications
  File APIs, database APIs, backup APIs.

Virtual filesystem service
  Namespaces, mounts, permissions, path resolution, file handles.

Filesystem services
  Filesystem implementation, snapshots, quotas, indexing hooks.

Volume manager
  Partitioning, encryption, RAID, thin provisioning, snapshots.

Block service
  Block queues, scheduling, caching, integrity, discard, flush.

Storage drivers
  NVMe, UFS, eMMC, SATA, USB mass storage, SD, virtual block.

Kernel
  I/O queues, memory mapping, DMA isolation, interrupts.
```

### Storage Driver Contract

Storage drivers expose:

- Queue count and depth.
- Block size.
- Atomic write capabilities.
- Flush and barrier semantics.
- Discard and trim support.
- Zoned storage support.
- Namespace management.
- Health and wear metrics.
- Encryption offload where supported.
- Secure erase where supported.
- Hotplug and removal semantics.

### Filesystems

Filesystems run outside the kernel by default. The VFS service owns path and
namespace policy. Filesystem services own format-specific implementation.

The OS should support:

- A native copy-on-write filesystem for system and user data, designed in
  `../storage/01-native-cow-filesystem.md`.
- Read-only verified system images.
- Removable media filesystems.
- Network filesystems.
- Virtual filesystems for compatibility.

Filesystem services use stable file object and memory object interfaces rather
than private kernel hooks.

The post-open data path, caching model, direct I/O, swap, per-layer restart
semantics, and the end-to-end durability chain are defined in
`../storage/02-file-io-and-caching.md`.

### Storage Security

Storage supports:

- Per-volume encryption.
- Per-file or per-data-class keys where profiles require them.
- Hardware-backed key wrapping.

Encryption layering is reconciled, not duplicated: volume-level encryption
(volume manager) is the whole-volume, boot-measurement-bound floor;
filesystem key domains (`../storage/01-native-cow-filesystem.md`) layer
per-data-class keys above it and take precedence for classified data.
Inline-crypto engines are an offload resource, not a third key owner: the
block service brokers keyslot allocation between both layers, keys are
programmed as hardware-wrapped keyslots via the key service so the block
service never sees raw key material where hardware permits, and software
crypto in the owning layer is the fallback when slots are exhausted or
absent.
- Secure rollback protection for system images.
- Verified boot integration.
- Data classification labels.
- Protected deletion policy.

## Networking Stack

### Layers

```text
Applications
  Sockets, HTTP, QUIC, VPN, peer-to-peer APIs.

Network policy service
  Per-app rules, firewall, DNS policy, VPN, captive portal, privacy relay.

Protocol stack
  IP, TCP, UDP, QUIC support hooks, routing, neighbor discovery.

Packet I/O service
  Packet buffers, queueing, offloads, classification.

Network drivers
  Ethernet, Wi-Fi, cellular, Bluetooth, virtual NICs.

Kernel
  I/O queues, event delivery, DMA isolation, packet fast paths.
```

The stack's instancing and restart model, data path, flow API, port
authority, firewall enforcement, VPN, migration, and DNS are defined in
`../network/01-network-stack.md`.

### Network Driver Contract

Network drivers expose:

- Link state.
- MTU.
- Queue model.
- Offload capabilities.
- Timestamping.
- Wake-on-network support.
- Power states.
- Radio coexistence metadata where relevant.
- Firmware health.
- Secure management operations.

### Packet Processing

The stack supports:

- Zero-copy receive where policy permits.
- Batched transmit and receive.
- Packet filters using verified programs.
- Per-application network accounting.
- QoS and traffic classes.
- VPN and container routing.
- VM virtual switching.
- Privacy-preserving telemetry.

### Wireless

Wi-Fi, cellular, Bluetooth, UWB, Thread, and similar radios include sensitive
location and identity implications. Radio policy is separated from radio
drivers.

The radio policy service owns:

- Network selection.
- Roaming.
- SIM/eSIM policy.
- Pairing policy.
- Device identity rotation.
- Regulatory domain policy.
- User consent for nearby device discovery.

## USB

### USB Host Stack

The USB stack includes:

- Host controller drivers.
- Hub driver.
- Descriptor parser.
- Class driver binding.
- Device authorization policy.
- Power negotiation.
- Alternate mode coordination.
- USB4 and Thunderbolt policy integration where applicable.

### USB Security

USB is treated as untrusted hotplug input.

Controls include:

- Locked-screen attach policy.
- Class allowlists and denylists.
- User consent for sensitive devices.
- DMA protection for USB4 and Thunderbolt.
- Firmware update restrictions.
- Input device spoofing detection support.
- Per-device audit logs.

### USB Classes

Class drivers include:

- HID.
- Mass storage.
- Audio.
- Video.
- Network.
- Serial.
- Smart card.
- Billboard and alternate mode.
- Vendor-specific development mode.

Vendor-specific USB drivers run in user-space driver hosts.

## PCIe

### PCIe Core

The PCIe core handles:

- Bus enumeration.
- BAR allocation.
- MSI/MSI-X.
- Power management.
- Hotplug.
- Advanced error reporting.
- IOMMU grouping.
- SR-IOV.
- PASID and PRI where available.
- Device assignment to VMs.

### PCIe Security

PCIe can be high risk because devices may DMA and expose complex firmware.

Controls include:

- IOMMU isolation by default.
- External PCIe authorization.
- Option ROM restrictions.
- DMA fault logging.
- Device reset on driver crash.
- Per-device security posture.
- Firmware provenance reporting.

### Virtualization

PCIe devices can be:

- Emulated.
- Paravirtualized.
- Assigned directly to a VM.
- Partitioned through SR-IOV.
- Mediated by a host service.

The virtualization manager coordinates with the device manager to prevent host
and guest ownership conflicts.

