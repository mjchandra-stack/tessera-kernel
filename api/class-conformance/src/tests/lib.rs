// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

const DESCRIBED: Described = Described {
    contract_version: 1,
    // WRITE and FLUSH, not DISCARD.
    features: 0x1 | 0x2,
    vendor: 0,
};

fn ok(ordinal: u32) -> Exchange {
    Exchange {
        ordinal,
        status: 0,
        answered: true,
        detail: 0,
    }
}

/// A transcript that exercises every rule of the block class and breaks
/// none of it.
fn clean_block() -> [Exchange; 6] {
    [
        ok(1), // Describe
        ok(2), // Read
        ok(3), // Write — advertised
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1, // left ACTIVE
        },
        ok(6), // SetPower
        Exchange {
            ordinal: 7, // Discard — not advertised
            status: BLOCK.not_supported,
            answered: true,
            detail: 0,
        },
    ]
}

#[test]
fn a_conformant_driver_passes_every_rule_the_transcript_reaches() {
    let report = check(&BLOCK, &DESCRIBED, &clean_block());
    assert!(report.is_clean());
    for rule in ALL_RULES {
        if rule == Rule::VendorMethodsNeedANamespace {
            // Never exercised by this transcript, and therefore unchecked
            // rather than passing.
            assert!(!report.checked(rule));
            continue;
        }
        assert!(report.passed(rule), "{rule:?} did not pass");
    }
    assert!(!report.is_complete(), "one clause was never reached");
}

/// **The clause that keeps the suite honest.** A transcript that called
/// nothing must not produce a clean bill of health, and the difference
/// between "nothing failed" and "everything held" is the whole distinction
/// between a smoke test and a conformance suite.
#[test]
fn an_empty_transcript_proves_nothing() {
    let report = check(&BLOCK, &DESCRIBED, &[]);
    assert!(report.is_clean(), "nothing failed, because nothing ran");
    assert!(!report.is_complete(), "and nothing was shown either");
    for rule in ALL_RULES {
        if rule == Rule::ContractVersionIsUnderstood {
            // The version is checked from `Describe`'s own reply and needs
            // no exchange.
            continue;
        }
        assert!(!report.checked(rule), "{rule:?} was not exercised");
    }
}

/// A required method the client skipped is unchecked, not passed: the
/// driver has not been shown to answer it, and blaming it for the client's
/// omission would be as wrong as absolving it.
#[test]
fn a_required_method_nobody_called_is_unchecked() {
    let report = check(&BLOCK, &DESCRIBED, &[ok(1), ok(2)]);
    assert!(report.is_clean());
    assert!(
        report.unchecked & (1 << Rule::RequiredMethodsAnswered as u32) != 0,
        "Reset and SetPower were never called",
    );
}

/// A required method that was called and not answered fails, which is the
/// other half of the rule and a different fact: the driver was asked and
/// did not reply.
#[test]
fn a_required_method_that_went_unanswered_fails() {
    let mut transcript = clean_block();
    transcript[1].answered = false;
    let report = check(&BLOCK, &DESCRIBED, &transcript);
    assert!(report.failed(Rule::RequiredMethodsAnswered));
    assert_eq!(report.offending_ordinal, 2);
    assert!(!report.is_clean());
}

/// One bad exchange condemns a rule however many good ones follow it.
/// Without this a driver could fail a call and pass the suite by making
/// the same call again.
#[test]
fn a_later_success_does_not_absolve_an_earlier_failure() {
    let transcript = [
        Exchange {
            ordinal: 2,
            status: 99, // outside the closed set
            answered: true,
            detail: 0,
        },
        ok(2),
        ok(2),
    ];
    let report = check(&BLOCK, &DESCRIBED, &transcript);
    assert!(report.failed(Rule::ErrorsAreInTheClosedSet));
    assert!(!report.passed(Rule::ErrorsAreInTheClosedSet));
    assert_eq!(report.offending_status, 99);
}

/// An unimplemented optional method must say `NOT_SUPPORTED` and nothing
/// else. A generic failure leaves a client unable to tell "this driver
/// cannot" from "this attempt failed".
#[test]
fn an_unimplemented_optional_that_fails_generically_is_not_conformant() {
    let mut transcript = clean_block();
    // Discard is not advertised; answering IO_ERROR is the wrong refusal.
    transcript[5].status = 2;
    let report = check(&BLOCK, &DESCRIBED, &transcript);
    assert!(report.failed(Rule::UnsupportedOptionalsSaySo));
    assert_eq!(report.offending_ordinal, 7);
}

/// Worse than refusing wrongly: succeeding at a method that was never
/// advertised, which makes every feature check a client performs
/// meaningless.
#[test]
fn an_unadvertised_optional_that_works_is_not_conformant_either() {
    let mut transcript = clean_block();
    transcript[5].status = 0;
    let report = check(&BLOCK, &DESCRIBED, &transcript);
    assert!(report.failed(Rule::UnsupportedOptionalsSaySo));
}

/// And the converse: a driver that advertised a feature and then refused
/// it. `Describe` and the method disagree, and the client believed
/// `Describe`.
#[test]
fn an_advertised_optional_that_refuses_is_not_conformant() {
    let mut transcript = clean_block();
    transcript[2].status = BLOCK.not_supported;
    let report = check(&BLOCK, &DESCRIBED, &transcript);
    assert!(report.failed(Rule::AdvertisedOptionalsWork));
    assert_eq!(report.offending_ordinal, 3);
}

/// A reset that did not leave the state a reset is defined to leave. The
/// contract says `ACTIVE`; a driver that came back suspended has left its
/// client holding an assumption the contract made for it.
#[test]
fn a_reset_that_leaves_the_wrong_state_is_not_conformant() {
    let mut transcript = clean_block();
    transcript[3].detail = 3; // STANDBY
    let report = check(&BLOCK, &DESCRIBED, &transcript);
    assert!(report.failed(Rule::ResetLeavesTheDefinedState));
    assert_eq!(report.offending_status, 3);
}

/// A vendor-range method must be refused with `PROTOCOL` until its
/// namespace has been negotiated. This is what stops a private extension
/// from becoming reachable — and therefore public — by accident.
#[test]
fn a_vendor_method_is_unreachable_until_its_namespace_is_negotiated() {
    let refused = [Exchange {
        ordinal: VENDOR_ORDINAL_BASE,
        status: PROTOCOL_STATUS,
        answered: true,
        detail: 0,
    }];
    assert!(check(&BLOCK, &DESCRIBED, &refused).passed(Rule::VendorMethodsNeedANamespace));

    // Answered instead of refused, with nothing negotiated: the extension
    // is reachable by anyone who guesses an ordinal.
    let reachable = [ok(VENDOR_ORDINAL_BASE)];
    let report = check(&BLOCK, &DESCRIBED, &reachable);
    assert!(report.failed(Rule::VendorMethodsNeedANamespace));
    assert_eq!(report.offending_ordinal, VENDOR_ORDINAL_BASE);

    // With a namespace declared, the same call is legitimate.
    let negotiated = Described {
        vendor: 0x1af4,
        ..DESCRIBED
    };
    assert!(check(&BLOCK, &negotiated, &reachable).passed(Rule::VendorMethodsNeedANamespace));
}

/// A contract version the client does not understand fails first and
/// loudest: every other rule reads ordinals whose meaning that version
/// defines, so a mismatch makes the rest meaningless rather than merely
/// additional.
#[test]
fn an_unknown_contract_version_fails() {
    let described = Described {
        contract_version: 2,
        ..DESCRIBED
    };
    let report = check(&BLOCK, &described, &clean_block());
    assert!(report.failed(Rule::ContractVersionIsUnderstood));
    assert!(!report.is_clean());
}

/// **The generalisation claim, checked rather than asserted.** The same
/// checker, the same rules and the same report run against the network
/// class with nothing but its spec changed — different ordinals, different
/// feature bits, a different reset method. A rule that had quietly been
/// about block devices would not survive this.
#[test]
fn the_same_rules_judge_the_network_class() {
    let described = Described {
        contract_version: 1,
        // TRANSMIT, not PROMISCUOUS.
        features: 0x1,
        vendor: 0,
    };
    let transcript = [
        ok(1), // Describe
        ok(2), // Transmit — advertised
        Exchange {
            ordinal: 3, // Reset
            status: 0,
            answered: true,
            detail: 1, // ACTIVE
        },
        ok(4), // SetPower
        Exchange {
            ordinal: 5, // SetPromiscuous — not advertised
            status: NETWORK.not_supported,
            answered: true,
            detail: 0,
        },
    ];
    let report = check(&NETWORK, &described, &transcript);
    assert!(report.is_clean());
    assert!(report.passed(Rule::RequiredMethodsAnswered));
    assert!(report.passed(Rule::AdvertisedOptionalsWork));
    assert!(report.passed(Rule::UnsupportedOptionalsSaySo));
    assert!(report.passed(Rule::ResetLeavesTheDefinedState));

    // And it catches the network class's own violations: `Reset` here is
    // ordinal 3, not the block class's 5, so a checker that had hardcoded
    // one would find nothing to judge.
    let mut bad = transcript;
    bad[2].detail = 4; // OFF
    assert!(check(&NETWORK, &described, &bad).failed(Rule::ResetLeavesTheDefinedState));
}

/// A transcript that reaches every rule reports complete — the state a
/// certification run has to reach, and the one an incomplete transcript
/// must never be mistaken for.
#[test]
fn a_transcript_that_reaches_every_rule_reports_complete() {
    let mut full = [ok(0); 7];
    full[..6].copy_from_slice(&clean_block());
    full[6] = Exchange {
        ordinal: VENDOR_ORDINAL_BASE,
        status: PROTOCOL_STATUS,
        answered: true,
        detail: 0,
    };
    let report = check(&BLOCK, &DESCRIBED, &full);
    assert!(report.is_complete());
    assert_eq!(report.unchecked, 0);
}
/// **The third class needs no new rule**, and this is what says so: the
/// same seven rules, run against a spec whose class moves no data at all,
/// with a transcript that exercises every one of them.
///
/// Two classes agreeing on a shape can be a coincidence of both moving
/// bytes through queues. A clock controller carries a clock id and a
/// number, and the suite judges it unchanged.
#[test]
fn the_clock_class_is_judged_by_the_same_seven_rules() {
    let described = Described {
        contract_version: 1,
        // SET_RATE advertised, DISABLE and MUX not — so both optional rules
        // are reachable on one transcript.
        features: 0x1,
        vendor: 0,
    };
    let refused = |ordinal: u32, status: u32| Exchange {
        ordinal,
        status,
        answered: true,
        detail: 0,
    };
    let transcript = [
        ok(1),                           // Describe
        ok(2),                           // Enable
        ok(8),                           // GetRate
        ok(4),                           // SetRate — advertised, and it works
        refused(3, CLOCK.not_supported), // Disable — not advertised, says so
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1, // a reset leaves ACTIVE
        },
        ok(6),                           // SetPower
        refused(VENDOR_ORDINAL_BASE, 6), // a vendor ordinal, PROTOCOL
    ];
    let report = check(&CLOCK, &described, &transcript);
    assert!(
        report.is_complete(),
        "every rule reached and held: {report:?}"
    );
}

/// A seventh class, and the table is still the only thing that changed.
#[test]
fn the_display_class_is_judged_by_the_same_seven_rules() {
    let described = Described {
        contract_version: 1,
        // FILL advertised, CURSOR not — both optional rules reachable on
        // one transcript, and honest: this driver fills and has no cursor
        // plane.
        features: 0x1,
        vendor: 0,
    };
    let transcript = [
        ok(1), // Describe
        ok(2), // Blit
        ok(3), // Flush
        ok(4), // Fill — advertised, and it works
        // SetCursor — not advertised, and it says so.
        Exchange {
            ordinal: 7,
            status: DISPLAY.not_supported,
            answered: true,
            detail: 0,
        },
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1, // a reset leaves ACTIVE
        },
        ok(6), // SetPower
        // A vendor ordinal, answered PROTOCOL.
        Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: 6,
            answered: true,
            detail: 0,
        },
    ];
    let report = check(&DISPLAY, &described, &transcript);
    assert!(
        report.is_complete(),
        "every rule reached and held: {report:?}"
    );
}

/// **An eighth class, and the rule that judges it counts a refusal as a
/// pass.** `NOT_SUPPORTED` for an algorithm this driver does not implement
/// is not a shortfall — it is the behaviour the contract exists to
/// guarantee, and the rule that says "answered within the closed set"
/// already covers it. Which is the fifth class in a row to need no new rule.
#[test]
fn the_crypto_class_is_judged_by_the_same_seven_rules() {
    let described = Described {
        contract_version: 1,
        // It decrypts; it holds one session at a time.
        features: 0x1,
        vendor: 0,
    };
    let transcript = [
        ok(1), // Describe
        ok(2), // CreateSession
        ok(3), // Encrypt
        ok(4), // Decrypt — advertised, and it works
        // SetIv — not advertised, and it says so.
        Exchange {
            ordinal: 8,
            status: CRYPTO.not_supported,
            answered: true,
            detail: 0,
        },
        ok(7), // DestroySession
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1, // a reset leaves ACTIVE, with every session gone
        },
        ok(6), // SetPower
        // A vendor ordinal, answered PROTOCOL.
        Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: 6,
            answered: true,
            detail: 0,
        },
    ];
    let report = check(&CRYPTO, &described, &transcript);
    assert!(
        report.is_complete(),
        "every rule reached and held: {report:?}"
    );
}

/// **An algorithm refused is inside the closed set, and a substitution is
/// not detectable here at all.** Worth stating where the suite is defined:
/// this rule catches a driver that answered with a code it has no business
/// using, and it cannot catch a driver that answered `OK` after doing the
/// wrong thing. That one is caught by a known-answer test against a
/// published vector, outside this suite, and there is no rule that could
/// replace it.
#[test]
fn refusing_an_algorithm_is_an_answer_within_the_set() {
    let described = Described {
        contract_version: 1,
        features: 0x1,
        vendor: 0,
    };
    let transcript = [
        ok(1),
        ok(2),
        // Encrypt, refused because the algorithm named is not implemented.
        // A *required* method answering NOT_SUPPORTED, which is still an
        // answer inside the closed set: the method exists and the algorithm
        // does not.
        Exchange {
            ordinal: 3,
            status: CRYPTO.not_supported,
            answered: true,
            detail: 0,
        },
        ok(4),
        // SetIv is not advertised, and says so.
        Exchange {
            ordinal: 8,
            status: CRYPTO.not_supported,
            answered: true,
            detail: 0,
        },
        ok(7),
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1,
        },
        ok(6),
        Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: 6,
            answered: true,
            detail: 0,
        },
    ];
    let report = check(&CRYPTO, &described, &transcript);
    assert!(report.is_complete(), "a refusal is an answer: {report:?}");
}

/// **A sixth class, and the rule that judges it was written for disks.**
/// A stream that ran dry answers `UNDERRUN` and is still running, and
/// "answered within the closed set" counts that as a pass — the same
/// sentence that counts an idle keyboard's `NO_REPORT`.
#[test]
fn the_audio_class_is_judged_by_the_same_seven_rules() {
    let described = Described {
        contract_version: 1,
        // PAUSE advertised, VOLUME not — both optional rules reachable on
        // one transcript, and honest: this driver pauses and has no mixer.
        features: 0x1,
        vendor: 0,
    };
    let transcript = [
        ok(1), // Describe
        ok(2), // Configure
        ok(3), // Start
        // Write, answered UNDERRUN: the stream ran dry, and that is a
        // value in the set rather than a failure of the call.
        Exchange {
            ordinal: 4,
            status: 1,
            answered: true,
            detail: 0,
        },
        ok(7), // Stop — advertised, and it works
        // SetVolume — not advertised, and it says so.
        Exchange {
            ordinal: 9,
            status: AUDIO.not_supported,
            answered: true,
            detail: 0,
        },
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1, // a reset leaves ACTIVE
        },
        ok(6), // SetPower
        ok(8), // Status
        // A vendor ordinal, answered PROTOCOL.
        Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: 6,
            answered: true,
            detail: 0,
        },
    ];
    let report = check(&AUDIO, &described, &transcript);
    assert!(
        report.is_complete(),
        "every rule reached and held: {report:?}"
    );
}

/// **A fifth class, and still no new rule.** What a class contract *is*, is
/// the table: which ordinals are required, which are gated by which bit,
/// and what a reset leaves. Everything the suite does with that table was
/// written for disks.
#[test]
fn the_gpio_class_is_judged_by_the_same_seven_rules() {
    let described = Described {
        contract_version: 1,
        // A PL061: it drives and it interrupts, and it has no bias or
        // drive strength — so both optional rules are reachable on one
        // transcript without contriving anything.
        features: 0x1 | 0x2,
        vendor: 0,
    };
    let transcript = [
        ok(1), // Describe
        ok(2), // ConfigureLine
        ok(3), // Read
        ok(4), // Write — advertised, and it works
        ok(7), // WatchLine — advertised, and it hands over the line
        // SetElectrical — not advertised, and it says so rather than
        // failing generically. A PL061 has no bias control at all.
        Exchange {
            ordinal: 9,
            status: GPIO.not_supported,
            answered: true,
            detail: 0,
        },
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1, // a reset leaves ACTIVE
        },
        ok(6), // SetPower
        ok(8), // ReleaseLine
        // A vendor ordinal, answered PROTOCOL.
        Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: 6,
            answered: true,
            detail: 0,
        },
    ];
    let report = check(&GPIO, &described, &transcript);
    assert!(
        report.is_complete(),
        "every rule reached and held: {report:?}"
    );
}

/// **A fourth class, and the suite did not change.** The rules that judge a
/// keyboard are the rules that judge a disk; what differs is the table.
/// A class contract this suite could not read without being taught about it
/// would be a description of one device rather than a framework.
#[test]
fn the_input_class_is_judged_by_the_same_seven_rules() {
    let described = Described {
        contract_version: 1,
        // GET_REPORT advertised and SET_REPORT not, so both optional rules
        // are reachable on one transcript — which for a keyboard means it
        // can be asked what is held down and cannot be told to light a lamp.
        features: 0x2,
        vendor: 0,
    };
    let transcript = [
        ok(1), // Describe
        // Poll, answered with NO_REPORT: **nothing happened, and that is a
        // pass.** The rule is "answered within the closed set", and an idle
        // keyboard is the ordinary case rather than an exception to it.
        Exchange {
            ordinal: 2,
            status: 1,
            answered: true,
            detail: 0,
        },
        Exchange {
            ordinal: 3,
            status: INPUT.not_supported,
            answered: true,
            detail: 0,
        },
        ok(4), // GetReport — advertised, and it works
        Exchange {
            ordinal: 5,
            status: 0,
            answered: true,
            detail: 1, // a reset leaves ACTIVE
        },
        ok(6), // SetPower
        // A vendor ordinal, answered PROTOCOL.
        Exchange {
            ordinal: VENDOR_ORDINAL_BASE,
            status: 6,
            answered: true,
            detail: 0,
        },
    ];
    let report = check(&INPUT, &described, &transcript);
    assert!(
        report.is_complete(),
        "every rule reached and held: {report:?}"
    );
}
