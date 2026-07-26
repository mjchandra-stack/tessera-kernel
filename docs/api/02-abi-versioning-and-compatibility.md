<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# ABI Versioning And Compatibility

## Compatibility Goal

Applications and drivers built against a stable profile should keep working
across OS updates unless they depend on explicitly experimental APIs or violate
security policy.

Compatibility is maintained through:

- Stable syscall ABI.
- Versioned service interfaces.
- Versioned driver class contracts.
- Compatibility profiles.
- Conformance tests.
- Deprecation windows.
- Automated ABI diffing.

## ABI Profiles

The OS publishes ABI profiles such as:

- Base application profile.
- Desktop application profile.
- Mobile application profile.
- Wearable application profile.
- Server application profile.
- Driver profile.
- Hypervisor host profile.
- Guest profile.
- Embedded profile.

Profiles define required object types, syscalls, service interfaces, permission
classes, and behavioral guarantees.

## Interface Schemas

Stable interfaces are defined in schemas. Schemas generate:

- Bindings.
- Validators.
- Fuzzers.
- Trace decoders.
- Mock services.
- Compatibility tests.
- Documentation.

Schema changes are reviewed as ABI changes.

## Version Negotiation

Clients and servers negotiate:

- Interface ID.
- Major version.
- Minor version.
- Feature flags.
- Required rights.
- Optional extensions.

Major versions can break compatibility but must coexist for a defined support
period. Minor versions are backward-compatible.

## Deprecation

Deprecation requires:

- Public notice.
- Replacement API.
- Static analysis support.
- Runtime diagnostics.
- Migration documentation.
- Product-profile-specific deadline.

Security-critical removals can be accelerated, but compatibility fallout must be
tracked.

## Experimental APIs

Experimental APIs are:

- Disabled by default in production profiles.
- Clearly marked in schemas.
- Excluded from stable ABI guarantees.
- Versioned aggressively.
- Logged when used.

Promotion to stable requires tests, documentation, security review, and
observability support.

## Driver Compatibility

Driver compatibility is maintained at the class contract level, not by freezing
all kernel internals.

Driver packages declare:

- Supported class contract versions.
- Required OS profile.
- Required hardware IDs.
- Required firmware versions.
- Required security features.
- Update channel.

The driver host provides compatibility shims where needed.

## Application Compatibility

Applications declare:

- Minimum OS profile.
- Required capabilities.
- Optional capabilities.
- ABI target.
- Framework target.
- Data migration rules.

The package manager can install compatibility support packages when allowed.

## Legacy Compatibility

Legacy API environments can be implemented as compatibility components:

- POSIX shell environment.
- Linux userspace compatibility.
- Android-like app runtime.
- Web runtime.
- Enterprise legacy runtime.

Legacy environments should be sandboxed and should translate authority into the
native capability model.

## ABI Testing

The release process includes:

- Syscall ABI tests.
- Service protocol tests.
- Driver class tests.
- Package compatibility tests.
- Trace schema tests.
- Crash dump compatibility tests.
- Cross-version upgrade and rollback tests.

No release is accepted without ABI diff review.

