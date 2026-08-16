// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The firmware-loading syscall ABI: how a component that mediates firmware
// asks the kernel for an image, and what it is told about the one it gets.
//
// `docs/drivers/01` ("Firmware Loading") says firmware loading is mediated by
// the driver framework, and the framework is a ring-3 device manager. But the
// store the images live in is verified against anchors compiled into the
// kernel (`api/image-store`, build/README.md D146), and handing those anchors
// to a manager would move the root of trust into ring 3. So the work is split
// exactly where the trust is: **the manager holds the authority and asks, the
// kernel measures and decides.**
//
// # What crosses, and what deliberately does not
//
// The image does not travel in these bytes. It arrives as a **memory object**
// — the syscall's result is that object's handle — which is what lets the
// manager pass it to a driver by transfer rather than by copy, and what lets
// the driver map it read-only and measure it for itself.
//
// The *device* is named because firmware is loaded into something, and because
// naming it is what makes the authority checkable: `Rights::FIRMWARE` on that
// handle is the whole access decision, and it is narrowed away when the device
// is handed to a driver, so a driver holds images it was given and can ask for
// none.
//
// Normative: docs/drivers/01-driver-framework.md ("Firmware Loading"),
// docs/security/01-security-model.md ("Rights Catalog"),
// docs/security/02-cryptography-and-key-management.md ("Anti-Rollback")

library tessera.firmware;

// Why an image was refused, mirroring `tessera_firmware::Refusal`.
//
// `None` is the value on a load that succeeded, so a report is readable without
// consulting the syscall's return value — and, more to the point, so a report
// from a *failed* load never has to leave this field at a value that means
// something else.
//
// The two refusals are different authorities and not different severities.
// `ROLLBACK_BLOCKED` is the system retiring a security version and cannot be
// fixed by changing any driver; `VERSION_TOO_OLD` is a driver and an image that
// do not match, and either of them moving fixes it. A caller told only "policy
// refused" would not know which of those two conversations to have.
strict enum FirmwareRefusal : uint32 {
    NONE = 0;
    ROLLBACK_BLOCKED = 1;
    VERSION_TOO_OLD = 2;
};

// FirmwareLoad — verify a named image from the system store, admit it against
// policy, and return it as a memory object.
//
// `min_image_version` is what the *caller* requires. It is deliberately not the
// only thing checked: the system's rollback floor is applied first and outranks
// it, so a caller cannot lower its own requirement into accepting an image the
// system has retired.
//
// `name` is a store entry name, NUL-padded — the same fixed width the store's
// directory uses, so a name that fits one fits the other and no truncation can
// happen in between.
@abi
struct FirmwareLoadArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    // The device the image is destined for. `FIRMWARE` is the authority; the
    // device also scopes the provenance record, so a fleet can be asked which
    // image is on which hardware rather than only what was loaded.
    device: handle<Object, {FIRMWARE}>;
    min_image_version: uint32;
    name: array<uint8, 24>;
    reserved: uint32;
    // Where to write the `FirmwareReport`.
    report_ptr: uint64;
};

// What the kernel says about the image — written on **both** paths.
//
// A refusal that produced no report would leave a caller knowing that policy
// said no and unable to say which policy, which is the distinction the whole
// enum above exists to preserve. On success `refusal` is `None` and the rest
// describes what was actually handed over.
//
// `digest` is the image's measurement, and it is here because provenance is
// *what* was accepted rather than that something was: a manager that logs this
// value has said which bytes are on that device, and one that logs a success
// has said nothing a fleet can be queried about.
@abi
struct FirmwareReport {
    size: uint32;
    version: uint32;
    flags: uint64;
    refusal: FirmwareRefusal;
    // The security version of the image named, as the store recorded it —
    // filled in even on a rollback refusal, because the number that was
    // refused is what somebody has to compare against the floor.
    svn: uint32;
    image_version: uint32;
    reserved: uint32;
    length: uint64;
    digest: array<uint8, 32>;
};
