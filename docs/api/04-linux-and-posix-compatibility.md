<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Linux And POSIX Compatibility

## Purpose

`02-abi-versioning-and-compatibility.md` names Linux userspace compatibility
as a sandboxed component, but pure user-space emulation of Linux semantics —
`fork`, signals, `/proc`, `ptrace` — above a handle-based, multi-address-space
ABI is where such efforts historically fail (WSL1's abandonment, Fuchsia's
pivot to kernel-adjacent starnix). This document decides the posture
explicitly, because the decision constrains the kernel ABI now, not later:
either the kernel commits a small set of compatibility assists, or Linux
compatibility is scoped down honestly. We do both, in tiers.

## The Three Tiers

### Tier 1 — POSIX Source Compatibility

A native libc exposes a POSIX-flavored API implemented over the native ABI.
It targets porting: toolchains, servers, interpreters, and CLI software built
from source.

- Process creation is spawn-based (`posix_spawn` is the model); `fork` is not
  provided in tier 1.
- Pipes and stream sockets map onto the stream object in
  `../kernel/04-synchronization-and-ipc-guarantees.md`.
- Unix domain sockets map onto channels, not streams, because `SCM_RIGHTS`
  file-descriptor passing requires handle transfer and streams deliberately
  carry no handles.
- Signals are emulated with documented deltas: synchronous signals
  (SIGSEGV-class) via exception channels using resume-with-modified-state to
  redirect execution to the signal handler
  (`../kernel/03-paging-faults-and-exceptions.md` "Handler Outcomes");
  asynchronous signals via the directed interruption assist below.
- Deltas from POSIX are documented per function, not discovered by users.

### Tier 2 — Linux Binary Compatibility

Unmodified Linux user binaries run inside a compatibility runtime: a
user-space Linux supervisor implementing Linux semantics over native
primitives, with narrow kernel assists for the semantics that user space
cannot express. The supervisor is an ordinary sandboxed component; a Linux
process is a native process whose authority is whatever its sandbox grants.

Target workloads: developer tools, language runtimes, servers. Non-goals are
listed below.

### Tier 3 — Linux System VM

Full-fidelity Linux, including containers and out-of-tree kernel modules,
runs in a lightweight Linux VM with virtio devices and integration services
(file sharing, networking, clipboard per policy). This is the supported path
for Docker-style container workloads and for the Linux driver containment
bridge in `../roadmap/01-sequencing-and-mvp.md`. Fidelity questions end here:
anything tier 2 does not support is a tier 3 workload, by design rather than
by apology.

## Kernel Compatibility Assists

These are the kernel commitments tier 2 needs. They are part of the ABI,
listed in `01-system-call-interface.md` "Compatibility Assists", and gated to
the compatibility profile. Each exists because the semantic is impossible or
pathologically slow in pure user space; each is small, bounded, and useful
beyond Linux emulation.

1. Address-space clone: create a copy-on-write snapshot of an address space,
   preserving mapping layout. This implements `fork`. It is also the
   substrate for process checkpointing, so it earns its place independently.
2. Syscall dispatch redirection: a thread may enter a mode where foreign
   syscall numbers vector to a registered in-process supervisor entry point
   instead of the native syscall table (the shape of Linux's own syscall user
   dispatch). The common case costs one intra-process redirect, not a channel
   round trip.
3. Directed interruption: interrupt a specific thread, forcing it out of a
   blocking call with a distinct result and transferring control to a
   registered handler, honoring a per-thread mask. This is the substrate for
   signal delivery with correct interaction between signals and blocking
   syscalls.
4. Wait-on-address extensions for robust futexes: an owner-death signal on
   the address when the owning process exits, so `pthread` robust mutexes
   work.

Native code does not use these interfaces; they are compat-profile ABI and
their use is a per-component manifest declaration, visible to policy and
audit.

## Explicit Non-Goals

Tier 2 does not provide, at any fidelity:

- Linux kernel modules, eBPF programs, or `/sys` fidelity.
- Full `ptrace` (a debugging-oriented subset only), full `/proc` (curated
  subset).
- 32-bit binaries.
- Linux namespaces/cgroups APIs (containers are tier 3; native containment is
  the job model in `../kernel/05-jobs-containment-and-resource-control.md`).
- Device nodes beyond what the sandbox's device view grants.

Each unsupported area has a named disposition: curated subset, tier 3, or
never. The list is maintained with the compatibility component so the answer
to "will my binary run" is documentation, not experiment.

## Security Posture

Compatibility layers translate authority into the native capability model,
never bypass it, per `02-abi-versioning-and-compatibility.md`:

- A Linux process's filesystem view is its sandbox's namespace; `open` is a
  brokered operation like any native file access.
- Foreign syscalls are traceable events with the same correlation IDs as
  native syscalls, and the supervisor's translation decisions are observable.
- The compatibility runtime holds no standing privilege; a sandbox running
  Linux binaries is exactly as contained as one running native binaries.

## Sequencing

Tier 1 lands in Stage 1 of `../roadmap/01-sequencing-and-mvp.md` (the
self-hosting gate depends on it). Tier 3 lands with virtualization in Stage
3. Tier 2 also lands in Stage 3, scoped to developer workloads, because its
kernel assists must be designed with the Stage 0 ABI even though the
supervisor ships later.
