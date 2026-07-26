<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# AI Runtime Security

## Purpose

`01-ai-and-wearable-era.md` establishes AI as a set of platform services and
constrains agent tool use through the capability model. What it does not specify
is how the model runtime itself is isolated, how untrusted model weights are
contained, and how prompt-injection and tool-abuse are prevented at the OS
boundary. This document fills that gap. It treats a model, its weights, and its
prompt inputs as untrusted data that must be contained, not as trusted code.

## Threat Model

The AI runtime faces risks beyond ordinary applications:

- Malicious or poisoned model weights.
- Prompt injection that attempts to escalate the agent's authority.
- Tool abuse: an agent invoking capabilities beyond the user's intent.
- Data exfiltration through inference outputs or telemetry.
- Cross-application leakage through shared model or context state.
- Side channels between tenants sharing an accelerator.

These extend, and are governed by, the AI risks in
`../security/01-security-model.md` "AI Security And Privacy".

## Runtime Isolation

The model runtime runs in its own sandbox and its own security domain, never in
the address space of the application that requested inference.

- Inference for sensitive data classes runs in a dedicated security domain (see
  `../security/01-security-model.md` "Security Domains"), so it does not share
  microarchitectural resources with mutually distrusting workloads.
- The highest-sensitivity inference (health, biometric, credentials) can run in a
  confidential VM or enclave where hardware supports it, using the confidential
  computing model in `../security/01-security-model.md`.
- The runtime holds only the capabilities needed for a given request. It receives
  scoped context views from the personal context store, never raw global memory.
- Runtime crashes are contained and restartable like any other service, per the
  failure model in `../architecture/01-system-architecture.md`.

## Untrusted Weights

Model weights are data, and large data from external publishers is a classic
parsing and memory-safety hazard.

- Weights are signed and provenance-checked before load, per
  `../security/02-cryptography-and-key-management.md` and the supply-chain
  controls in `../lifecycle/01-development-maintenance-update-model.md`.
- Weight loading and graph compilation run in the sandboxed runtime with
  memory-safe parsing and fuzzed loaders, consistent with the memory-safety gate
  in `../security/01-security-model.md`.
- A loaded model cannot gain capabilities merely by being loaded; authority comes
  only from the permission broker and the tool execution broker.
- Weight residency uses secure memory pools for sensitive models and is paged and
  evicted under the memory model in `../kernel/02-scheduling-memory-ipc.md`.

## Prompt Injection And Tool Abuse

The OS cannot judge whether a prompt is adversarial, so it constrains what a
compromised or manipulated agent can do rather than trying to sanitize intent.

- Every tool call passes through the tool execution broker
  (`01-ai-and-wearable-era.md` "Tool Execution Broker") and is checked against the
  capability model — a persuasive prompt cannot grant authority the agent does
  not hold.
- Destructive or sensitive actions require explicit user confirmation regardless
  of what the model requests.
- Context and tool outputs carry data classifications
  (`../security/01-security-model.md` "Data Classification"); the broker prevents
  an agent from moving data to a lower-classification egress than policy allows,
  which contains exfiltration through tool chains.
- Untrusted content ingested during inference (documents, web content, tool
  results) is treated as data, never as an instruction that can widen authority.

## Context Integrity

The tool boundary stops an agent from *doing* what it shouldn't; the context
store must stop it from *remembering* what isn't true. A malicious app or a
poisoned document writing falsehoods into personal context is prompt
injection with persistence and cross-session reach, so context writes are a
guarded boundary:

- Every context entry carries provenance: the writing principal
  (kernel-attested via `../kernel/04-synchronization-and-ipc-guarantees.md`
  "Peer Credentials"), time, the consent state under which it was written,
  and its derivation — direct user statement, app-provided fact, agent
  inference, or ingested untrusted content.
- Scoped views deliver provenance with the content; policy weights trust
  per source, and the runtime labels untrusted-derived entries in prompt
  assembly so a model consumes them as claims, not facts.
- Content derived from untrusted ingestion (web pages, documents, tool
  results) is quarantined by default: excluded from durable memory unless
  the user explicitly confirms its retention. Persistent prompt injection
  is defeated at the write path, not detected at read time.
- Memory controls surface provenance — the user sees who wrote each fact —
  and revocation is per source and transitive: revoking a source revokes
  its entries and what was derived from them.
- Context-store writes are audited like sensitive tool use.

## Agent Authorization

Agentic workflows are often multi-step and long-running, which needs more than a
single up-front grant.

- Authorization is scoped to a task and time-bounded; long-running agents
  re-authorize rather than holding open-ended authority.
- Chained agents narrow scope: a sub-agent receives a subset of the parent's
  capabilities, never a superset.
- Capabilities can be revoked mid-task using the revocation rules in
  `../security/01-security-model.md`; an in-flight agent loses authority
  immediately.
- Rate and budget limits bound tool invocation volume, and unattended
  (autonomous) runs are audited distinctly from user-attended ones.

## Runtime And Model Attestation

Model and runtime trust use the unified attestation flow in
`../security/01-security-model.md` "Attestation":

- A relying party can require attestation of the runtime and the specific model
  version before sensitive data classes are released to it.
- Attestation binds the loaded model identity and runtime measurement, so a
  swapped or tampered model fails verification.
- Accelerator firmware backing the runtime is itself security-sensitive and
  attested where hardware supports it (`01-ai-and-wearable-era.md` "AI
  Accelerator Evolution").

## Observability

The runtime emits structured events consistent with
`../observability/01-debugging-monitoring-tracing-logging.md`:

- Model load, version, and attestation result.
- Tool calls with capability, data classification, and consent state.
- Placement decisions (local versus cloud) and their inputs.
- Redaction applies before logging; prompt and inference content follow the
  data-class handling rules and never leak through traces.
