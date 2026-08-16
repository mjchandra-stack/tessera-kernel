// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **driver certification record**: what a run of the checks proved about
// one driver, in bytes that outlive the run that produced them.
//
// `docs/drivers/01` ("Certification") lists the checks and then the sentence
// that decides this schema exists: *"certified drivers can be distributed
// through signed update channels"*. A distribution channel is somewhere else
// and later — a different machine, a different boot, possibly a different
// release — so the verdict has to travel. A verdict that lived only in a test
// runner's memory could never be what a channel admits a driver on.
//
// `api/certification` holds the rules that produce this record; this holds the
// record. The two are declared separately and cross-checked against each other
// (`tests/certification_conformance.rs`), the arrangement `rights.rs` and
// `handle_abi.isl` already use: one is the judgement, one is the wire, and a
// silent disagreement between them is caught by a test that walks both rather
// than by whoever notices first.
//
// # Two masks, and why a certificate is not a boolean
//
// The record carries **what ran** and **what passed**, separately. A single
// "certified" bit — or a single mask of passes — would make a driver nobody
// finished checking indistinguishable from a driver that was checked and was
// fine, which is the failure this whole facility exists to prevent. With both
// masks present, a reader can always compute the three populations that matter:
// passed, failed, and never asked.
//
// It also means the record is self-contradictory in exactly one way, and a
// decoder must refuse it: `passed` claiming a bit `ran` does not. The masks
// arrive independently, so no encoder's good intentions rule that out —
// `tessera_certification::Certificate::from_parts` is where it is refused.
//
// # Why the record names bytes and not only a driver
//
// `driver` names a driver the way a binding manifest does: an identifier
// somebody chose. That is enough for a report and **not** enough for a channel,
// because the channel ships an *artifact*, and an artifact that claims the same
// identifier is not the artifact that was certified. Any certificate keyed only
// on a name is transferable to whatever else answers to that name.
//
// So the record carries a measurement, and names the algorithm that produced
// it — `docs/security/02` ("Crypto Agility") requires every signed artifact to
// name its own algorithm rather than leaving a verifier to assume the one it
// happens to implement. `NONE` is a real and useful value: a certificate
// produced by a runner that had no artifact in front of it is honest evidence
// about the checks and no evidence about any bytes, and a channel is the thing
// that must refuse it. The rules crate does not judge this field, because
// judging it means measuring bytes and a rules crate has none.
//
// Normative: docs/drivers/01-driver-framework.md ("Certification"),
// docs/lifecycle/02-build-and-test-infrastructure.md ("Test Tiers"),
// docs/security/02-cryptography-and-key-management.md ("Crypto Agility")

library tessera.certification;

// The checks, numbered as `tessera_certification::Check` numbers them.
//
// Ten are `docs/drivers/01`'s certification list verbatim. `CLASS_CONFORMANCE`
// is the eleventh: that document names it separately, as the tenth element of a
// class contract, and it is a different question from `ABI_CONFORMANCE` — one
// asks whether the bytes are what the schema says, the other whether the driver
// behaves as the contract says. Neither implies the other, so a certificate
// resting on either alone rests on half a driver.
//
// Values are ABI: append only, never renumbered or reused. A check that stops
// being required keeps its number and stops being asked for.
strict enum CertificationCheck : uint32 {
    ABI_CONFORMANCE = 1;
    CLASS_CONFORMANCE = 2;
    FUZZ = 3;
    SUSPEND_RESUME = 4;
    HOTPLUG = 5;
    DMA_FAULT = 6;
    POWER = 7;
    CRASH_RECOVERY = 8;
    SECURITY_POLICY = 9;
    PERF_REGRESSION = 10;
    TRACE_SCHEMA = 11;
};

// What running one check produced.
//
// **Three values, and `NOT_RUN` is zero.** A record that arrived zeroed, or a
// field a producer forgot to fill, must not read as a pass — the same rule the
// crypto contract needed for its algorithm field, for the same reason: the
// default must be the value that claims nothing.
strict enum CheckOutcome : uint32 {
    NOT_RUN = 0;
    PASSED = 1;
    FAILED = 2;
};

// Where a check has to run, in `docs/lifecycle/02`'s vocabulary, numbered by
// its tier so the name and the number say the same thing.
//
// Carried so a refusal is diagnosable rather than merely negative: a reader
// told that nine checks did not run learns much more when it can also tell
// which of them nobody on that machine could have run.
strict enum CheckTier : uint32 {
    COMPONENT = 2;
    SYSTEM = 3;
    PERFORMANCE = 4;
};

// How the artifact was measured.
//
// Numbered to agree with `api/image-store`'s `DigestAlgorithm`, deliberately:
// the two describe the same measurement of the same kind of thing, and a value
// that meant `SHA256` in one record and something else in the other would be a
// trap laid for whoever eventually carries a digest between them.
strict enum CertificateDigest : uint32 {
    // Nothing was measured. Evidence about the checks, and none about any
    // bytes — which a report may print and a channel must refuse.
    NONE = 0;
    SHA256 = 1;
};

// What a run of the checks proved about one driver.
//
// `contract_version` is the field that is easy to omit and expensive to lack.
// The checks were run against one version of a class contract — its required
// ordinals, its feature bits, its error range — so what they showed is a
// statement about that contract. A driver that has moved to a later one holds a
// certificate that is still perfectly valid and no longer about it, and without
// the version in the record nothing could ever say so.
@abi
struct Certificate {
    size: uint32;
    version: uint32;
    flags: uint64;
    // --- the subject -------------------------------------------------------
    // The driver, as its binding manifest names it.
    driver: uint32;
    // The class it was certified for, as `driver_bind.isl`'s `DeviceClass`
    // numbers them.
    device_class: uint32;
    // The major version of that class contract.
    contract_version: uint32;
    // --- the outcomes ------------------------------------------------------
    // Which checks ran, as a bitmask of `1 << CertificationCheck`. Bit zero is
    // unused because the checks are numbered from one, which leaves an
    // all-zero mask meaning "nothing ran" rather than "check zero ran".
    ran: uint32;
    // Which of those passed. Always a subset of `ran`; a decoder that finds
    // otherwise has a forgery, not a certificate.
    passed: uint32;
    // --- the artifact ------------------------------------------------------
    digest_algorithm: CertificateDigest;
    // The measurement of the artifact certified, left zero when the algorithm
    // is `NONE`. Thirty-two bytes because that is what SHA-256 produces and
    // what the store's directory already carries.
    image: array<uint8, 32>;
};
