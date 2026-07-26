<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# AI And Wearable Era

## Context

Future personal computing will be shaped by:

- Local AI inference.
- Cloud-assisted AI.
- Wearable sensors.
- Spatial displays.
- Always-on context.
- Personal data vaults.
- Multi-device continuity.
- New accelerators.
- Stricter privacy expectations.
- More regulatory pressure around data processing.

The OS should treat these as core design inputs.

## AI As A Platform Service

AI is exposed through platform services rather than every app directly owning
models, sensors, accelerators, and context stores.

Core AI services:

- Model registry.
- Model runtime.
- Model permission broker.
- Personal context store.
- Tool execution broker.
- Accelerator scheduler.
- Prompt and context redaction service.
- Local/cloud placement policy.
- Evaluation and safety telemetry.

The prompt and context redaction service applies the data-class handling
rules to prompts, context views, and inference outputs before they cross
logging, telemetry, or lower-classification boundaries — the AI-side
enforcement point for `../security/01-security-model.md` "Data
Classification".

Isolation of the model runtime, containment of untrusted weights, context
integrity, and prompt-injection and tool-abuse defenses are specified in
`02-ai-runtime-security.md`.

## Model Registry

The model registry tracks:

- Model identity.
- Publisher.
- Signature.
- License.
- Version.
- Capabilities.
- Required runtime.
- Required accelerator features.
- Data classes allowed.
- Offline support.
- Cloud fallback behavior.
- Update policy.

Models are components with explicit permissions, not anonymous files.

Model signing, provenance, and revocation follow
`../security/02-cryptography-and-key-management.md`. Model updates and rollback
are owned by the update model in
`../lifecycle/01-development-maintenance-update-model.md` "Model Updates":
models use A/B swap, are rolled back on quality or safety regression, and are
health-checked like any other updatable component.

## Inference Sessions

The application-facing runtime contract is a typed ISL protocol like every
other service interface:

- A session is a capability: opening one binds a model identity, the
  granted data classes, and placement constraints. Everything the session
  may touch is decided at open, checked against the caller's
  kernel-attested identity.
- Tensor and token I/O uses the device memory model — buffers from
  negotiated heaps with timeline sync acquire/release points
  (`../hardware/04-device-memory-and-unified-memory.md`,
  `../kernel/04-synchronization-and-ipc-guarantees.md`) — with
  shared rings for bulk streams.
- Streaming output is first-class: token or chunk delivery over a
  flow-controlled stream with optional per-chunk deadline hints, because
  interactive generation is the dominant pattern, not an afterthought.
- Scheduling classes are mapped, not implied: interactive sessions run in
  the interactive class, batch and speculative inference in the compute and
  background classes (`../kernel/02-scheduling-memory-ipc.md`), and
  multi-model pipelines (speech to LLM to speech) declare pipeline
  descriptors so end-to-end deadlines are admitted per
  `../kernel/07-scheduler-admission-control.md` rather than hoped.
- Inference state is classified: KV caches and session state inherit the
  strongest class of the session's inputs, reside in secure memory pools
  for sensitive classes, are never persisted for local-only classes, and
  are destroyed at session end.
- Residency is policy: interactive-path models may be pinned resident;
  cold model load (paging from sealed images) and pressure eviction emit
  runtime-visible events so cold-start regressions are attributable.

## Personal Context Store

The personal context store holds user-approved context:

- Preferences.
- Memories.
- Recent activity summaries.
- Cross-device continuity state.
- App-provided facts.
- Enterprise-scoped knowledge.

Access is mediated by policy. Applications and agents request scoped context
views rather than raw global memory.

## Tool Execution Broker

AI agents use tools through the same capability model as applications.

The broker enforces:

- User consent.
- App identity.
- Tool capability.
- Data classification.
- Rate limits.
- Audit logging.
- Confirmation for destructive actions.
- Enterprise restrictions.

An AI agent cannot operate devices or private data merely because it can
generate text.

Tool manifests are ISL-declared and classify each method's action — read,
write, destructive, egress. Confirmation and rate rules key off the declared
class, and the declaration is validated at certification, so a tool cannot
describe a destructive method as read-only and route around confirmation.

## Local And Cloud Placement

The AI runtime chooses placement based on:

- User preference.
- Data classification.
- Model availability.
- Latency.
- Battery.
- Thermal state.
- Accelerator load.
- Network state.
- Enterprise policy.
- Cost policy.

Sensitive data can be restricted to local-only execution.

Local-only is a real boundary, including for telemetry. Evaluation and safety
telemetry from a local-only inference may not egress the raw data or any
inference derived from a class marked local-only; it is confined to on-device
aggregates or must stay on device entirely, governed by the class handling rules
in `../security/01-security-model.md` "Data Classification". Telemetry that would
violate the class egress rule is not sent. Users can inspect and, where policy
permits, opt out of AI safety telemetry.

When placement selects cloud, the path has a trust model, not merely
permission: transport is encrypted and mutually authenticated;
cloud-eligible-but-sensitive classes may require an attested remote runtime —
a confidential-compute endpoint verified through the
`../security/01-security-model.md` "Attestation" flow before data release —
and provider retention bounds are policy inputs recorded with the placement
decision. Under degraded posture or failed endpoint attestation, cloud
fallback fails closed to local execution or refusal; it never silently
down-tiers protection.

## Accelerator Scheduling

The accelerator scheduler arbitrates GPU, NPU, DSP, ISP, and media engines
across competing AI and non-AI workloads. It complements the kernel
accelerator-aware scheduling in `../kernel/02-scheduling-memory-ipc.md`.

- Fairness and QoS: workloads declare priority classes; foreground and
  interactive inference preempts background and speculative inference.
- Isolation: mutually distrusting workloads are separated by security domain,
  and their command queues are isolated per
  `../security/01-security-model.md` "Microarchitectural Isolation".
- Thermal-budget arbitration: sustained inference is bounded by a thermal budget
  shared with foreground UX. When headroom is scarce, background and speculative
  inference throttle first; foreground responsiveness is protected. On wearables a
  strict continuous-inference energy budget applies so always-on inference cannot
  drain the battery or overheat the device.
- Graceful degradation: when a required accelerator feature is absent, the
  runtime falls back to a compatible path (a smaller model, a different engine, or
  CPU) rather than failing, using the capability discovery in "AI Accelerator
  Evolution".

## Wearable Computing

Wearables introduce unique constraints:

- Very small batteries.
- Always-on sensors.
- Health and biometric data.
- Intermittent connectivity.
- Companion device dependence.
- Glanceable interaction.
- Haptic and audio output.
- Body-worn privacy implications.

The OS supports a wearable profile with:

- Low-power sensor hub.
- Batching and wake policies.
- Health data classification.
- Companion sync service.
- On-device inference for immediate signals.
- Strict background limits.
- Minimal UI shell.
- Reliable emergency and health workflows.

## Spatial And Ambient Computing

Future displays may be:

- AR glasses.
- Mixed reality headsets.
- Projected surfaces.
- Vehicle displays.
- Multi-screen rooms.

The display and input architecture supports:

- Multiple coordinate spaces.
- Gaze and gesture input.
- Privacy-preserving scene understanding.
- Secure screen capture policy.
- Protected surfaces.
- Remote and shared rendering.

## AI Accelerator Evolution

Accelerators will change quickly. The OS prepares by:

- Using operation capability discovery.
- Avoiding hard-coded model formats in the kernel.
- Keeping graph compilation in user-space runtimes.
- Supporting multiple accelerator queues.
- Accounting power and thermal cost.
- Treating accelerator firmware as security-sensitive.
- Supporting secure execution and attestation where available.

## Privacy And Auditability

AI and wearables increase privacy risk because they can combine many weak
signals into strong inferences. The OS therefore tracks:

- Sensor source.
- Data classification.
- Inference purpose.
- Model identity.
- Tool use.
- Output destination.
- Retention policy.

Users and administrators can inspect and revoke AI memory, sensor permissions,
and tool permissions.

## Future-Proofing Rules

To add a future device or AI capability:

1. Describe it in the hardware resource graph or component schema.
2. Define a driver class or service interface.
3. Define data classifications.
4. Define permission and policy rules.
5. Add observability events.
6. Add conformance tests.
7. Add power and thermal accounting.
8. Add update and rollback support.

No future feature should bypass capabilities, policy, or observability.

