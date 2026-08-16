// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

use super::*;

/// A certificate for every check, over measured bytes, earns an entry.
fn full_record() -> certification::Certificate {
    certification::Certificate {
        size: certification::Certificate::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        driver: 7,
        device_class: 10,
        contract_version: 1,
        ran: tessera_certification::ALL,
        passed: tessera_certification::ALL,
        digest_algorithm: certification::CertificateDigest::Sha256,
        image: [0xa5; 32],
    }
}

fn log_of(record: &certification::Certificate) -> String {
    let mut bytes = [0u8; certification::Certificate::WIRE_SIZE];
    tessera_isl_runtime::encode(record, &mut bytes).expect("the record encodes");
    let mut hex = String::new();
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("boot: something\n{TAG}{hex}\nboot: something else\n")
}

#[test]
fn a_complete_certificate_earns_an_entry() {
    let entry = run(&log_of(&full_record())).expect("certified");
    assert_eq!(entry.len(), tessera_update_channel::ENTRY_SIZE * 2);
}

/// **The one that matters.** One check missing is the whole difference
/// between a driver a channel may ship and one it may not.
#[test]
fn one_check_that_never_ran_refuses() {
    let mut record = full_record();
    let hotplug = tessera_certification::Check::Hotplug.bit();
    record.ran &= !hotplug;
    record.passed &= !hotplug;
    let Err(Outcome::Refused(why)) = run(&log_of(&record)) else {
        panic!("a certificate missing a check must not earn an entry");
    };
    assert!(why.contains("hotplug"), "the refusal must name it: {why}");
}

/// A record claiming a check it never ran is refused as a forgery, and by
/// the rules crate rather than by anything written here.
#[test]
fn a_pass_without_a_run_is_a_forgery() {
    let mut record = full_record();
    record.ran &= !tessera_certification::Check::Fuzz.bit();
    let Err(Outcome::Refused(why)) = run(&log_of(&record)) else {
        panic!("a forged record must not earn an entry");
    };
    assert!(why.contains("forgery"), "{why}");
}

/// A certificate about no bytes is evidence about a name.
#[test]
fn an_unmeasured_artifact_refuses() {
    let mut record = full_record();
    record.image = [0; 32];
    let Err(Outcome::Refused(why)) = run(&log_of(&record)) else {
        panic!("an unmeasured certificate must not earn an entry");
    };
    assert!(why.contains("artifact"), "{why}");
}

/// A boot that printed nothing is a broken rig, not an unfit driver, and
/// the two must not arrive as the same answer.
#[test]
fn no_record_is_not_a_refusal() {
    let Err(Outcome::NoRecord(_)) = run("boot: nothing to see\n") else {
        panic!("an absent certificate must not read as a refusal");
    };
}

/// Two runs concatenated is not one run.
#[test]
fn two_certificates_are_two_runs() {
    let one = log_of(&full_record());
    let Err(Outcome::NoRecord(why)) = run(&format!("{one}{one}")) else {
        panic!("two certificates must not silently become one");
    };
    assert!(why.contains("more than one"), "{why}");
}
