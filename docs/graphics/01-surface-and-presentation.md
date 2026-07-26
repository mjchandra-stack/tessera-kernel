<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Surface And Presentation Protocol

## Purpose

`../drivers/03-graphics-display-media-sensors-ai.md` defines the compositor,
display service, and GPU stack, but not the contract applications actually
program against: how surfaces are created, buffers submitted, frames paced,
and presentation confirmed. This document defines that protocol — the layer
every UI framework builds on — plus buffer format negotiation and the
compositor restart contract. The protocol is a typed ISL interface
(`../api/03-interface-schema-language.md`) like every other service
protocol; nothing here is a special case.

## Surface Model

- A surface is a compositor object reached through the client's surface
  channel, obtained from the namespace broker per sandbox policy. Surfaces
  carry a role (toplevel, subsurface, cursor, overlay; shells may add
  roles), a transform, and an attached buffer.
- Surface state changes are transactional: a commit atomically applies the
  pending state of a surface and, for a declared surface tree, all of its
  subsurfaces — no client can be observed half-updated.
- Direct scanout paths (fullscreen exclusive, VR) bypass composition via
  display leasing (`../drivers/03` "Display Service"); the surface protocol
  targets composed presentation.

## Buffer Submission

A buffer attach carries three things, all first-class:

- The buffer: a memory-object handle from a negotiated heap
  (`../hardware/04-device-memory-and-unified-memory.md`).
- An acquire point on a timeline sync object
  (`../kernel/04-synchronization-and-ipc-guarantees.md` "Timeline Sync
  Objects"): the compositor consumes the buffer only when the point
  signals, so clients submit before rendering completes without races.
- A format descriptor (below).

The compositor signals a release point per buffer when it no longer reads
it; clients reuse buffers on release, giving swapchain semantics without a
kernel swapchain object. Damage rectangles accompany the attach so
composition and scanout can be partial-update; full-surface damage is the
degenerate case, never an assumption.

Protected buffers follow `../security/01-security-model.md`: the compositor
routes them to protected composition or hardware planes and cannot map
their contents; capture policy composes unchanged.

## Frame Scheduling And Present Feedback

- Frame callbacks pace rendering: a client requests one and the compositor
  fires it when starting the frame the client should render for — clients
  that render only on callback never produce dead frames.
- Present feedback is delivered per committed buffer: the presentation
  timestamp, the refresh interval, and mode flags (vsynced, hardware
  plane, copied). This is what makes the input-to-photon budget in
  `../architecture/03-performance-budgets.md` measurable end to end, and
  jank attributable to a stage rather than a vibe.
- A commit may carry a target presentation time for VRR displays and A/V
  sync; the compositor schedules to it within the display's declared
  timing capabilities, and the media-deadline machinery in
  `../kernel/07-scheduler-admission-control.md` applies to pipelines that
  declared one.

## Format And Modifier Negotiation

Buffer layout interop (tiling, compression) is negotiated, never assumed:

- A format descriptor is a schema-defined type: pixel format, a
  vendor-namespaced layout modifier, and constraint metadata (alignment,
  plane count). Modifiers are registered identifiers under the ABI rules —
  never opaque vendor magic.
- Producers and consumers (GPU, camera, codec, display controller) each
  publish supported descriptor sets through their driver contracts; the
  allocation path intersects the sets of every declared consumer and
  allocates from a heap satisfying the intersection.
- Cross-device sharing re-negotiates on topology change (external GPU
  attach, display hotplug); falling back to linear layouts is an explicit,
  traced outcome — silent linear fallback is a performance bug the
  observability section makes visible.

## Compositor Restart And Session Continuity

The isolated-services bet pays off only if a compositor crash is a flicker,
not a session loss:

- Client buffers, sync objects, and surface channels are kernel objects; a
  compositor crash destroys none of them. Clients observe peer-closed on
  the surface channel per `../kernel/04-synchronization-and-ipc-guarantees.md`.
- On restart, clients reattach through the namespace broker and re-register
  surfaces with their current buffers; the protocol makes surface state
  client-replayable by construction (the client always knows its own
  committed state). The shell re-establishes stacking and focus from the
  session manager.
- Applications are never terminated by compositor failure, and the session
  must be recomposed within the failure-model expectations — pending
  frame callbacks are reissued, in-flight commits are simply re-committed.
- Display leases survive compositor restart independently; a VR session
  does not collapse because a desktop compositor crashed.

## Observability

Per-frame timing (commit to present) with stage attribution, present-mode
statistics (plane versus composition versus copy), damage efficiency,
negotiation outcomes including linear fallbacks, frame-callback latency,
protocol errors per client, and restart/reattach events are structured
events, consistent with
`../observability/01-debugging-monitoring-tracing-logging.md`. The
composition budget B26 in `../architecture/03-performance-budgets.md` is
measured from these events.
