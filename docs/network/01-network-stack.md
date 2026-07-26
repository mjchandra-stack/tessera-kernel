<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Network Stack

## Purpose

`../drivers/02-storage-networking-usb-pcie.md` defines the networking layers
and driver contract but leaves open what the "network stack service"
actually is, how packets move between the layers, what the native flow API
looks like, where the firewall is enforced, and how VPN and interface
migration behave. This document decides them. The policy split is unchanged:
the network manager owns policy, the radio policy service owns radios, and
nothing here moves policy into drivers or the kernel.

## Instancing, Trust, And Restart

- The protocol stack runs as one stack instance per network namespace
  (`../kernel/05-jobs-containment-and-resource-control.md`). The system
  default namespace gets the shared default instance; containers, VMs'
  host-side networking, and isolation-sensitive profiles get their own.
  Instances are ordinary sandboxed components with no reach into each
  other.
- Trust: the stack sees packet payloads, which are TLS ciphertext for
  well-behaved traffic; it is still the fattest network trust domain, which
  is why per-namespace instancing bounds its blast radius and why firewall
  enforcement does not depend on it (below).
- Restart: transport state does not survive a stack-instance crash. Flows
  are reset; applications observe a distinct connection-reset error through
  the flow API's peer-closed semantics, and the instance restarts per the
  failure model. State replication for connection survival is explicitly
  not a v1 goal — the design optimizes for fast, clean reset over
  transparent recovery.

## Data Path

The path is designed around one rule: payload lands in memory once and is
copied at most once more, at the application boundary, if policy demands it.

- Each NIC's receive and transmit buffers come from a DMA-safe pool
  allocated from a device heap
  (`../hardware/04-device-memory-and-unified-memory.md`), mapped by the
  driver host and the packet I/O service.
- Receive: the NIC DMA-writes into the pool; descriptors — never payload —
  flow through shared-memory rings from driver host to packet I/O, where
  kernel-attached verified filters have already issued verdicts (below),
  then to the owning stack instance, which parses headers in place.
- Delivery to the application is per-flow rings: zero-copy (pool pages
  mapped read-only into the app) where the sandbox profile permits sharing
  pool pages, or a single copy into app-private memory where it does not.
  Transmit is symmetric, with headers built in descriptor-referenced
  buffers.
- Budgets: the existing bulk and latency budgets, plus the small-packet
  budget B25 in `../architecture/03-performance-budgets.md`, which is the
  one that exposes descriptor-path overhead that bulk TCP hides.

## Flow API And Port Authority

- A component opens a control channel to its namespace's stack instance
  through the namespace broker. Flow lifecycle (bind, listen, connect,
  accept, options) is a typed ISL protocol on that channel; accepted and
  connected flows arrive as transferred handles carrying a data ring (or a
  stream object for low-rate flows) plus a signal set that binds to ports
  for readiness.
- Listening is not ambient authority: binding a listen port requires a
  port-range capability resolved through the namespace broker — privileged
  ranges are brokered per policy, an ephemeral range is granted to any
  component with network access, and every listen grant is audited. Legacy
  "any app may listen anywhere" behavior does not exist.
- POSIX `AF_INET`/`AF_INET6` sockets in the compatibility tiers
  (`../api/04-linux-and-posix-compatibility.md`) are implemented by libc
  and the Linux supervisor over this flow API.
- Flows are bound at creation to the requesting security context, which is
  what makes per-app rules, accounting, and classification enforceable.

## Firewall Enforcement

Policy is owned by the network manager; enforcement is layered so it does
not depend on trusting the things it polices:

- Packet-level rules (L3/L4 drops, rate limits, address scoping) compile to
  verified filter programs (`../kernel/09-verified-programs.md`) attached at
  the kernel packet path, below every service. A compromised stack or
  packet I/O service cannot bypass them.
- Flow-level per-app rules are enforced at flow creation inside the stack
  instance via a policy query keyed by the flow's security context, and
  re-checked when policy changes (existing flows are reset if newly
  forbidden, with an audit event).
- The two layers fail closed: no verified filter set loaded means no
  forwarding, and a policy-service outage denies new flows rather than
  defaulting them open.

## VPN

- A VPN provider is an ordinary component exposing a virtual NIC through
  the standard network driver contract; it holds no special kernel
  privilege.
- Per-app and per-class VPN routing is namespace routing: components (or
  data classes, per egress policy) bound to a VPN route resolve through the
  tunnel's interface.
- Fail closed is the default and is enforced below the services: VPN-bound
  routes carry no fallback, and a kernel-attached verified filter drops
  VPN-bound traffic that appears on any other interface. Tunnel loss means
  blocked traffic and an event — never silent leakage around a dead tunnel.
  Fail-open is an explicit, audited policy choice per profile.

## Interface Migration

- Flows are interface-agnostic at the API; interface identity is metadata,
  not addressing.
- QUIC connection migration is the blessed continuity path: the radio
  policy service emits pre-migration events, and the stack surfaces path
  change and validation signals to QUIC libraries so connections survive
  Wi-Fi/cellular handover.
- TCP flows on a lost interface reset with a distinct
  interface-changed error so applications can distinguish handover from
  peer failure. MPTCP is deferred, not precluded — the flow API carries no
  single-path assumption.

## DNS

- A system resolver service per namespace owns name resolution; apps
  resolve through it by capability, not by raw port 53 access.
- Encrypted transports (DoH/DoT) are policy-selected; split-DNS follows VPN
  and enterprise policy per namespace.
- Resolution is an egress surface: queries carry the requester's identity
  and are subject to data-class egress rules and auditing like any other
  egress. Per-app resolver overrides are policy-gated, not free.

## Stack Internals Kept Flexible

- Congestion control is internal to the stack instance, pluggable per
  policy, and explicitly not ABI — applications observe outcomes, not
  algorithms.
- "QUIC support hooks" concretely means: UDP batching, segmentation and
  receive coalescing offload pass-through, ECN marking access, and
  per-flow pacing from the packet scheduler. TLS remains in applications;
  the stack never terminates it.
- Driver hardware timestamping feeds the time service for PTP-class
  synchronization in the industrial and automotive profiles; the stack
  passes timestamps through, it does not own time.

## Observability

Per-flow lifecycle events with security-context attribution, per-namespace
instance health, buffer-pool occupancy, verified-filter verdict counters,
policy denials and flow resets with rule identity, VPN tunnel state
transitions and fail-closed drops, migration events, and resolver query
metadata (subject to classification redaction) are structured events,
consistent with `../observability/01-debugging-monitoring-tracing-logging.md`.
