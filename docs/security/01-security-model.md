<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Security Model

## Threat Model

The OS assumes:

- Applications can be malicious.
- Documents and media can be malicious.
- Drivers can contain vulnerabilities.
- Peripherals can be malicious.
- Firmware can be flawed or compromised.
- Networks are hostile.
- AI models and plugins can leak or transform sensitive data.
- Physical access may occur, including cold-boot and DMA attacks against memory.
- Supply chains can be attacked, from source code through build and signing.
- For confidential workloads, the hypervisor and host OS are themselves untrusted
  and may be curious or malicious.
- Microarchitectural side channels can leak data across isolation boundaries.

Security must therefore be layered and measurable.

Each assumed adversary has corresponding controls in this document: supply chain
in "Supply Chain Security", host and hypervisor in "Confidential Computing",
side channels in "Microarchitectural Isolation", and physical access in "Physical
Access Protection".

## Core Principles

- Least privilege by default.
- Capability-based authority.
- Mandatory sandboxing.
- Strong process and driver isolation.
- Measured and verified boot.
- Signed system components.
- Hardware-backed key storage.
- Memory safety for new privileged code.
- Auditable policy.
- Privacy-preserving diagnostics.
- Secure update and rollback.
- Crypto agility and post-quantum readiness (see
  `02-cryptography-and-key-management.md`).

## Capability Security

Authority is represented by handles with rights. Components receive only the
handles they need.

Capability sources:

- Parent component.
- User consent broker.
- System policy service.
- Device manager.
- Package manifest.
- Enterprise policy.
- Temporary delegation.

Capabilities are revocable. Revocation behavior is defined per object class
rather than left implicit:

- Objects reached through a broker or service (device, permission, namespace,
  data-class access) are revoked at the broker: the next operation fails and
  in-flight operations are cancelled with a distinct error.
- Directly held kernel objects support revocation by handle invalidation; mapped
  memory objects are unmapped on revocation, and subsequent access faults rather
  than reading stale data.
- Delegated capabilities are revoked transitively: revoking a capability revokes
  every capability derived from it.

Every revocation emits an audit event and the reason is recorded. Object classes
that cannot support immediate revocation are documented as such and are not used
for sensitive data-class access.

The kernel mechanism behind direct-object and transitive revocation — including
its cost model and its guarantees on return — is revocation scopes, defined
normatively in `../kernel/06-capability-revocation.md`. Transitive revocation
operates at the granularity of delegation across trust boundaries; duplication
within a component shares the component's fate through its job.

The complete set of rights and their meaning is defined in the "Rights Catalog"
section below.

## Sandboxing

Every app and service runs in a sandbox. Sandbox profiles define:

- Filesystem view.
- Network access.
- Device access.
- IPC targets.
- Sensor access.
- Background execution.
- Debugging permissions.
- Trace visibility.
- AI model and data access.

System services have narrow service-specific sandboxes rather than broad root
authority.

## Identity And Policy

The policy engine evaluates:

- User identity.
- Application identity.
- Component signature.
- Device posture.
- Data classification.
- Requested capability.
- Execution context.
- Network context.
- Enterprise policy.
- User consent.

Device posture is a policy-evaluated summary of device trust state, established
from measured boot records, attestation results (see "Attestation"), debug-unlock
state, security patch level, and enforcement of disk and lock-screen encryption.
Posture is re-evaluated on boot, on attestation refresh, and on relevant state
changes; policy can require a minimum posture before releasing a capability or a
data class. Posture is not assumed static — it is continuously verified rather
than granted once.

Decisions are logged in structured audit records.

How users authenticate, how unlock state releases key domains, the
multi-user and work-profile model, the trusted consent path, and backup and
recovery are defined in `03-authentication-and-user-model.md`. Services
authenticate their callers through kernel-attested peer credentials
(`../kernel/04-synchronization-and-ipc-guarantees.md` "Peer Credentials And
Acting On Behalf"), never through payload claims.

## Boot Security

Boot security includes:

- Immutable root of trust where hardware provides it.
- Verified bootloader.
- Verified kernel.
- Verified platform support package.
- Verified initial system image.
- Measured boot records.
- Rollback protection.
- Recovery environment.
- Debug unlock policy.

Development devices can permit unlock, but unlock state is visible to policy
and attestation.

The signature algorithms, trust anchors, key rotation, revocation, and
anti-rollback mechanisms behind every item above are defined in
`02-cryptography-and-key-management.md`. Rollback protection uses monotonic
security version numbers so that a correctly signed but downgraded image is
still rejected.

## Memory Safety

Memory safety is a gate for new privileged code, not an aspiration:

- New code in the kernel, drivers, and system services must be written in a
  memory-safe language (Rust or equivalent). This is a requirement, not a
  preference.
- Exceptions are permitted only for narrow, justified cases (for example a
  hardware primitive with no safe expression). Each exception names an owner, a
  bounded scope, a sandboxing plan, and a review record, and is tracked so the
  set of unsafe privileged code is known and shrinking.
- New unsafe code is not admitted to privileged paths without meeting the
  in-kernel fast-path gate in `../01-design-principles.md` section 4.

Runtime hardening applies regardless of language:

- Hardened allocators.
- Guard pages.
- Stack canaries.
- Control-flow integrity.
- Shadow stacks where hardware supports them.
- Memory tagging where hardware supports it.
- Strict user-kernel copy validation.
- Fuzzing for parsers and binary interfaces.

The concrete kernel-level mechanisms — ASLR entropy floors, enforced
write-XOR-execute, and the kernel CSPRNG — are specified in
`../kernel/03-paging-faults-and-exceptions.md` "Randomness And Memory Hardening"
and are the normative source for those controls.

Legacy C and C++ code must be sandboxed and audited according to risk, and is
prioritized for replacement based on privilege and exposure.

## Locally Generated Executable Code

Signature checks cover code as shipped; JIT compilation and on-device
ahead-of-time compilation (bitcode-delivered applications, compatibility
translators) generate executable code that no publisher signed. Both forms
have defined trust stories rather than being quiet exceptions:

- JIT: runtime code generation is gated by the write-to-execute right and the
  W^X mechanics in `../kernel/03-paging-faults-and-exceptions.md`. The right
  is granted per sandbox profile, its use is audited, and generated code
  never outlives its process — JIT output is not a persistence mechanism.
- Ahead-of-time: a local compilation service is the only principal whose
  sandbox permits producing persistent executable-classed artifacts. It
  accepts only signed, provenance-checked intermediate code from verified
  packages, runs sandboxed like any component, and records for each output a
  binding of the input's identity, the compiler's build ID, and the policy
  version.
- The loader accepts a locally compiled artifact only with a valid binding
  record; the artifact is measured like any other component, so attestation
  and device posture distinguish publisher-signed code, locally compiled
  code from signed input, and JIT — and profiles may forbid any tier.
- Revoking a compiler version (a miscompilation or security defect)
  invalidates its binding records and triggers recompilation, following the
  same revocation-and-replace pattern as keys and models
  (`02-cryptography-and-key-management.md`).
- Compilation and first-load of locally generated artifacts are audit
  events.
- Accelerator artifacts — GPU shader and pipeline caches, compiled
  accelerator graphs — are locally generated code for a different ISA and
  follow the same discipline scaled to their risk: caches are
  per-application, integrity-protected, bound to the producing compiler and
  driver versions, invalidated on driver update or revocation, and never
  shared across applications by default (a shared cache is both a poisoning
  vector and a timing side channel).

## Device And DMA Security

Controls include:

- IOMMU isolation by default.
- DMA mapping leases.
- Device authorization policy.
- Restricted external PCIe and USB4 access.
- USB class policy.
- Driver host isolation.
- Firmware signature checks.
- Device quarantine after repeated faults.

## Data Classification

This taxonomy is the single normative definition of data classes for the whole
system. Other documents that mention "data classification" — observability,
platforms, virtualization, and the AI documents — refer to these classes and
their handling rules rather than defining their own.

Data is classified into policy classes:

- Public.
- User private.
- Sensitive personal.
- Health.
- Biometric.
- Credentials.
- Enterprise confidential.
- Protected media.
- AI personal context.

Classification is a property carried with data through storage, IPC, and
inference, not a per-call decision. Every class defines handling rules along the
same axes so behavior is uniform across subsystems:

- Encryption: at rest and in transit, with key binding strength from
  `02-cryptography-and-key-management.md`.
- Logging and tracing: whether values may appear in logs or traces, or must be
  redacted (see `../observability/01-debugging-monitoring-tracing-logging.md`).
- IPC transfer: which components may receive the data and over what channels.
- Egress and telemetry: whether the data, or inferences derived from it, may
  leave the device.
- Inference eligibility: whether the class may be used for local inference, cloud
  inference, or neither (see `../future/01-ai-and-wearable-era.md`).
- Retention and deletion: lifetime limits and guaranteed deletion behavior.

Illustrative handling by class:

- Public: no encryption requirement; loggable; freely transferable.
- User private and Sensitive personal: encrypted at rest and in transit;
  redacted in logs; egress requires consent.
- Health and Biometric: strongest key binding; redacted everywhere; local-only
  inference by default; egress requires explicit per-purpose consent; short
  retention.
- Credentials: never logged, never traced, never used for inference; stored only
  in key storage; access always audited.
- Enterprise confidential: governed by enterprise policy for egress, retention,
  and inference placement.
- Protected media: protected memory path; capture and export controlled by media
  policy.
- AI personal context: mediated by the personal context store; scoped views
  only; egress and cross-app sharing require consent and are audited.

More sensitive classes never inherit weaker handling by being combined with a
less sensitive class; the strongest applicable class governs.

### Memory Classification

Memory carries a classification, and it is the **handling path** a data class
selects rather than the data class itself. Several classes above select the same
treatment of memory — protected media and credentials both require that no
device reach the bytes without explicit authority — and the memory manager needs
to know which treatment applies, not which of nine reasons produced it. This is
the concept `01-kernel-model.md` refers to as "secure and protected memory
pools" and `03-paging-faults-and-exceptions.md` refers to when it says protected
pools suppress address and content fields in traces.

Two paths are defined:

- **Unclassified**: memory with no handling requirement beyond the ordinary
  isolation every process gets.
- **Protected**: memory that may not be made reachable by a device unless the
  device is explicitly authorized for it (`protected-dma` in the Rights
  Catalog). Its contents and addresses are suppressed in traces.

Further paths are added when they have handling rules; a classification the
system declares and does not enforce is worse than one it does not offer,
because a component would plan around it.

Two rules govern the mechanism:

- **Classification only rises.** A region's class may be raised and never
  lowered, which is the rule above — that the strongest applicable class governs
  — applied to memory. Declassification is a policy act with its own authority
  and audit, not an operation available to whoever holds the memory; without
  this rule, protection is advisory.
- **Enforcement is two-layer.** A request to expose protected memory to an
  unauthorized device is refused when it is made, and the IOMMU faults the
  device if it reaches for the memory anyway. The first layer is the policy; the
  second is what makes the policy true of the hardware rather than only of the
  interface, since a device may hold an address from a descriptor no longer
  under the system's control.

## AI Security And Privacy

AI introduces new risks:

- Prompt or context leakage.
- Model inversion.
- Tool misuse.
- Sensitive sensor fusion.
- Untrusted model plugins.
- Cross-application memory through AI agents.
- Cloud fallback without consent.

Controls include:

- Model provenance and signing (`02-cryptography-and-key-management.md`).
- Runtime attestation via the unified "Attestation" flow below.
- Tool capability gating.
- Per-data-class inference policy driven by "Data Classification".
- Local-only execution option.
- Redaction before logging.
- User-visible AI memory controls.
- Audit records for sensitive tool use.

Isolation of the model runtime itself, and containment of untrusted weights and
prompt-injection, are specified in `../future/02-ai-runtime-security.md`.

## Attestation

Attestation is one unified system facility, not a per-subsystem afterthought.
Every place that mentions attestation — driver load, model and AI-runtime trust,
device identity, and confidential VMs — uses this flow. The VM-specific
application is detailed in `../virtualization/01-virtualization-and-isolation.md`
"Attestation"; this section defines the shared model.

- Evidence: a signed quote over measurements (boot chain, loaded components, and
  the subject being attested) plus a verifier-supplied nonce for freshness. Boot
  measurements originate from the boot flow in
  `../architecture/01-system-architecture.md`.
- Freshness: the nonce and a monotonic counter prevent replay of stale evidence.
- Verifier and relying party: a relying party (enterprise policy, a remote
  service, the permission broker, or the model permission broker) checks evidence
  against expected measurements before releasing secrets or data-class access.
- Result binding: a passing attestation yields capabilities — handles to sealed
  keys or data-class access — rather than ambient trust. A failing attestation
  degrades posture (see "Identity And Policy").
- Signing and key handling follow `02-cryptography-and-key-management.md`; the
  root of trust signs quotes and its keys are never software-exposed.

Attestable subjects include the boot chain, driver hosts and the in-kernel fast
paths they use, device and firmware identity where hardware supports it, the AI
model runtime and loaded models, and confidential VMs.

## Microarchitectural Isolation

Shared CPU and accelerator hardware can leak data across isolation boundaries
through timing, cache, and speculative-execution side channels. The OS treats
this as a first-class boundary, not an incidental one.

- Transient-execution mitigations (Spectre/Meltdown class) are applied at
  privilege and address-space transitions, with per-architecture defaults set by
  the architecture port.
- Security domains that must not co-tenant a physical core do not share SMT
  siblings; the scheduler enforces this using the security-domain definition
  below (see `../kernel/02-scheduling-memory-ipc.md` "Heterogeneous CPU
  Scheduling").
- Sensitive cryptographic code must be constant-time and avoid secret-dependent
  branching and memory access.
- Shared accelerator command queues isolate submissions between security domains,
  preventing cross-domain observation or priority-based leakage
  (`../kernel/02-scheduling-memory-ipc.md` "Accelerator-Aware Scheduling").
- High-resolution time is treated as a side-channel primitive: sandbox
  profiles can reduce timer resolution and restrict access to fine-grained
  cycle counters for untrusted code, per profile policy, without affecting
  components holding the performance-counter capability.
- Mitigations are policy-selectable per product profile, because their cost
  differs across wearable, mobile, and server deployments, but a documented
  minimum applies to every profile.

### Security Domains

A security domain is a normative label attached to a job
(`../kernel/05-jobs-containment-and-resource-control.md`) that groups principals
which may share microarchitectural resources. It is the meaning of the "Security
constraints" scheduling hint in `../kernel/02-scheduling-memory-ipc.md`.

- Principals in different security domains are treated as mutually distrusting.
- Policy specifies which domains may co-tenant a core, share an SMT sibling, or
  share an accelerator queue; the default for distinct domains is no core
  co-tenancy for the most sensitive classes.
- Confidential VMs, the AI runtime handling sensitive classes, and credential
  handling each run in their own security domain.

## Confidential Computing

For confidential workloads the host is untrusted. The threat model includes a
curious or malicious hypervisor and host OS.

- Guest memory is hardware-encrypted with integrity protection so the host cannot
  read or undetectably alter it (`../kernel/02-scheduling-memory-ipc.md` "Secure
  Memory", Confidential VM memory).
- The host is excluded from guest register and memory state except through
  explicit, guest-consented interfaces.
- A guest proves its launch state to a relying party through the "Attestation"
  flow before receiving secrets or sensitive data classes.
- Confidential guest I/O uses encrypted or bounce-buffered paths so the host data
  plane never sees plaintext sensitive data.
- Containment still composes on the same job and resource-domain primitives
  (`../kernel/05-jobs-containment-and-resource-control.md`), and migration
  constraints follow `../virtualization/01-virtualization-and-isolation.md`.

## Supply Chain Security

Supply-chain attack is an assumed adversary, so it has explicit controls rather
than only signature checks at the end. These controls are implemented by the
development and release model in
`../lifecycle/01-development-maintenance-update-model.md` "Supply Chain Security";
this section states the security requirement.

- Every shipped artifact (image, component, driver, firmware, model) has a
  software bill of materials and verifiable build provenance.
- Builds are reproducible and hermetic so that a rebuild from pinned sources
  reproduces the signed artifact bit-for-bit.
- Dependencies are pinned and verified; unpinned or unverified inputs do not
  enter a release build.
- Signing infrastructure holds keys in hardware, logs every signing operation
  attributably, and requires more than one operator for release signing.
- Provenance and SBOM are checked at install and update time, not only at build
  time, and feed the "Attestation" and "Device posture" evaluations.

## Physical Access Protection

Physical access is in the threat model, so data-at-rest and memory-at-rest are
protected independently of the running OS.

- Storage is encrypted with keys bound to hardware and to boot measurements.
- Sensitive data-class keys are evicted from memory on lock and suspend, so a
  seized locked device does not yield plaintext keys.
- Memory encryption, where hardware supports it, mitigates cold-boot extraction.
- External DMA-capable ports are restricted and IOMMU-mediated per "Device And
  DMA Security".
- Debug and unlock state is measured and visible to attestation and posture.

## Rights Catalog

Rights are named consistently across the system. This catalog is the single
source of truth; the object-model list in
`../architecture/01-system-architecture.md`, the kernel handle model in
`../kernel/01-kernel-model.md`, and the job and pager rights in
`../kernel/05-jobs-containment-and-resource-control.md` and
`../kernel/03-paging-faults-and-exceptions.md` refer to it.

Core rights applicable to most objects:

- `read`, `write`, `map`, `execute`.
- `signal`, `wait`. On a **port**, these are the two halves of an interrupt
  object and they are deliberately separate. `wait` is the authority to be
  woken by it; `signal` is the authority to do the waking. A client that
  watches a GPIO line holds the first, and the driver that demultiplexed the
  edge holds the second — and neither should be able to do the other's half,
  because a client that could signal its own port could report an edge that
  never happened, and a driver that could wait on one could consume an event
  its client was owed. What a `signal` holder may raise is bounded by the
  port's own bindings rather than by the argument it passes, so the set of
  things it can wake was decided when the port was made
  (`../drivers/04-embedded-buses-power-and-timekeeping.md`, "GPIO And Pin
  Control").
- `duplicate`, `transfer`.
- `configure`, `bind`, `admin`. On a device, `configure` is the authority over
  its **configuration space** — the registers that turn on bus mastering, move a
  BAR out from under whoever placed it, and arm message-signalled interrupts. It
  is deliberately not implied by `map`: those are different authorities over the
  same device, and a driver may be trusted with a device's registers and not
  with the ability to reprogram what the device can reach. A bus controller
  grants it to the functions it means to and withholds it from the rest, which
  is a distinction it can only draw because the two rights are separate. What a
  holder may reach is one function's own slice and nothing adjacent
  (`../drivers/01-driver-framework.md`, "Bus Topology And Data Paths").

Object-class-specific rights extend the core set and are defined with their
object:

- Job: `create-process`, `create-job`, `set-policy`, `set-limits`, `suspend`,
  `kill`.
- Pager and memory: `supply`, `writeback`, `evict`.
- Exceptions: `exception`, `read-state`, `write-state` (modify a suspended
  thread's unprivileged register state;
  `../kernel/03-paging-faults-and-exceptions.md` "Handler Outcomes").
- Revocation scope: `derive`, `revoke`
  (`../kernel/06-capability-revocation.md`).
- Power: `wake` — register a device's interrupt as a system wakeup source, and
  hold a wake hold against the power object (`../power/01-power-management.md`).
  It is a right of its own rather than an implication of holding a device,
  which is what makes the set of things able to wake the machine an explicit,
  auditable set rather than a consequence of the driver table. `sleep` — commit
  the system to sleep. Separate from `wake` because they are opposite
  authorities over the same machine: one says what may interrupt a sleeping
  system, the other stops it running at all, and a component that needs the
  first almost never needs the second.
- Firmware: `firmware` — load a firmware image into a device
  (`../drivers/01-driver-framework.md` "Firmware Loading"). A right of its own,
  and not implied by holding the device, for the reason `wake` is not: firmware
  is code that runs on hardware outside the CPU's protection, so the set of
  components able to put it there must be an explicit, auditable set rather than
  whatever the driver table happens to contain. It is held by the component that
  *mediates* loading — the driver framework — and is narrowed away when a device
  is handed to a driver, so a driver receives the image it was granted and
  cannot ask for another.
- Protected memory: `protected-dma` — expose memory on the protected handling
  path ("Memory Classification" above) to this device. It is a right of the
  *device* rather than of whoever holds the memory, because which hardware may
  be trusted with protected content is a property of the platform and not a
  decision each buffer's owner should be making. Narrowed away on transfer like
  any other right, so a driver handed a device is handed that answer with it.

Rights can only be reduced on duplication or transfer, never expanded except
through a broker that already holds the authority (`../kernel/01-kernel-model.md`).
New rights are added to this catalog before use so the model does not diverge.

## Audit And Forensics

Security-relevant actions produce audit events:

- Capability grants.
- Permission changes.
- Driver binding.
- Firmware loading.
- Debug attach.
- Policy override.
- Key access.
- Protected data access.
- AI sensitive inference.
- Remote management action.

Audit logs are tamper-resistant where hardware and product profile permit
(sealed to a hardware root of trust, append-only, and remotely attestable). Where
such hardware is absent, a baseline still applies: audit records are
append-only within the log service, hash-chained so that deletion or reordering
is detectable, and exported promptly to a more trusted store where one exists.
Audit integrity therefore has a defined floor rather than degrading to freely
tamperable on low-end devices.

