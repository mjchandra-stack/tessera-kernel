<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Debugging, Monitoring, Tracing, And Logging

## Goals

Observability must work before, during, and after failure. It must support:

- Kernel debugging.
- Driver debugging.
- Service debugging.
- Application debugging.
- VM and container debugging.
- Production fleet diagnostics.
- Local developer workflows.
- Privacy-preserving user support.

## Structured Logging

Logs are structured records, not plain strings only.

Fields include:

- Timestamp.
- Component ID.
- Thread ID.
- Process ID.
- User or tenant ID where policy permits.
- Severity.
- Event name.
- Schema version.
- Correlation ID.
- Data classification.
- Redaction policy.

Plain text rendering is generated from structured records.

Collection, persistence across crashes, flood control, the flight recorder,
correlation-ID semantics, and the telemetry egress pipeline are defined in
`02-collection-persistence-and-telemetry.md`.

## Tracing

The tracing system supports:

- Kernel tracepoints.
- User-space tracepoints.
- Driver tracepoints.
- IPC tracing.
- Syscall tracing.
- Scheduler tracing.
- Memory pressure tracing.
- I/O latency tracing.
- Power and thermal tracing.
- VM exit tracing.
- AI inference pipeline tracing.

Trace sessions are policy-controlled. Sensitive payloads are redacted unless
explicitly authorized.

## Metrics

Metrics are collected for:

- CPU time.
- Memory usage.
- I/O latency.
- Network throughput.
- Wakeups.
- Battery usage.
- Thermal contribution.
- Accelerator utilization.
- Driver faults.
- Service restart count.
- Permission denials.
- Update success and failure.

Metrics are tagged by component, application, user, device, VM, and policy
domain as allowed.

## Crash Dumps

Crash dump types:

- Kernel panic dump.
- Driver host dump.
- Service dump.
- Application dump.
- VM dump.
- Firmware crash record.
- Hardware error record.

Dump policy respects data classification. Sensitive memory is excluded or
encrypted unless the debugging authority is present.

## Live Debugging

Debug attach requires capability and policy approval.

Supported operations:

- Breakpoints.
- Watchpoints.
- Thread inspection.
- Memory inspection.
- Register inspection.
- Handle table inspection.
- IPC queue inspection.
- Symbolized stack traces.
- Time-travel or record/replay where profile permits.

Production systems can restrict or disable live debugging.

## Health Monitoring

The health service tracks:

- Service liveness.
- Driver liveness.
- Device health.
- Firmware health.
- Filesystem health.
- Update health.
- Security posture.
- Battery health.
- Thermal stability.
- VM health.

Health checks produce actionable diagnoses, not just raw counters.

## Troubleshooting Workflows

The system provides built-in workflows for:

- Boot failure.
- Update rollback.
- Driver crash loop.
- Battery drain.
- Thermal throttling.
- Network failure.
- Storage corruption.
- Display black screen.
- Audio glitch.
- Camera privacy conflict.
- AI accelerator failure.
- App permission denial.
- VM performance issue.

Each workflow collects a minimal diagnostic bundle with clear privacy policy.

## Symbol And Build Identity

Every binary has:

- Build ID.
- Source revision.
- Symbol package reference.
- Interface schema version.
- Compiler and hardening metadata.
- Signing identity.

Crash dumps and traces can be symbolized offline or through a trusted symbol
service.

## Field Diagnostics

Field diagnostics support:

- User-approved diagnostic bundle generation.
- Enterprise-managed diagnostics.
- Remote support sessions.
- Automatic crash clustering.
- Regression detection.
- Staged rollout monitoring.
- Privacy filtering.

Diagnostic tools are part of the platform compatibility profile, not optional
afterthoughts.

