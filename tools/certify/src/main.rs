// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The certification test runner**, as a command a driver author runs.
//!
//! `docs/drivers/01` ("Developer Experience") lists nine things a driver SDK
//! provides and ends on this one. The rules have existed since the runner
//! landed and the channel has refused an uncertified entry since it landed, but
//! the two were joined only in code: nothing carried an outcome from the
//! machine that observed it to the manifest that claims it. A person typed the
//! masks in. **A certificate a person can type is not evidence about a run**,
//! and every property the channel checks rests on those two numbers.
//!
//! So this reads a boot's own log, takes the record the kernel encoded, and
//! either emits a channel entry or refuses and says what is missing. It is
//! deliberately incapable of inventing an outcome: `ran` and `passed` are
//! copied out of the record and never computed, and there is no flag that
//! overrides them. A tool that could be argued into certifying is a tool whose
//! refusals mean nothing.
//!
//! ```text
//! certify < boot.log        # exit 0 and an entry, or exit 3 and a reason
//! ```
//!
//! Normative: docs/drivers/01-driver-framework.md ("Certification",
//! "Developer Experience"), docs/lifecycle/02-build-and-test-infrastructure.md

use std::io::Read;

/// What the kernel prefixes its encoded certificate with.
const TAG: &str = "certificate: ";

/// Exit codes, distinct because they are three different problems with three
/// different owners: a tool that said only "no" would leave a driver author
/// unable to tell an unfit driver from a rig that never ran.
const EXIT_REFUSED: i32 = 3;
const EXIT_NO_RECORD: i32 = 2;

fn main() {
    let mut log = String::new();
    if std::io::stdin().read_to_string(&mut log).is_err() {
        eprintln!("certify: could not read the log on stdin");
        std::process::exit(EXIT_NO_RECORD);
    }
    match run(&log) {
        Ok(entry) => {
            println!("CERTIFIED: {entry}");
        }
        Err(Outcome::NoRecord(why)) => {
            eprintln!("certify: {why}");
            std::process::exit(EXIT_NO_RECORD);
        }
        Err(Outcome::Refused(why)) => {
            eprintln!("REFUSED: {why}");
            std::process::exit(EXIT_REFUSED);
        }
    }
}

#[derive(Debug)]
enum Outcome {
    /// There was nothing to judge. Distinct from a refusal, because a boot that
    /// printed no certificate is a broken rig and not an uncertified driver.
    NoRecord(String),
    /// There was a record, and it does not admit this driver to a channel.
    Refused(String),
}

fn run(log: &str) -> Result<String, Outcome> {
    let bytes = record_in(log)?;
    let record: certification::Certificate = tessera_isl_runtime::decode(&bytes)
        .map_err(|_| Outcome::NoRecord("the certificate line did not decode".into()))?;

    let subject = tessera_certification::Subject {
        driver: record.driver,
        class: record.device_class,
        contract_version: record.contract_version,
    };
    // **The forgery check comes first and is not this tool's judgement.** A
    // record claiming a check passed that never ran is refused by the rules
    // crate itself, so the same answer is reached in ring 3, at boot, and here.
    let Some(certificate) =
        tessera_certification::Certificate::from_parts(subject, record.ran, record.passed)
    else {
        return Err(Outcome::Refused(
            "the record claims a check that never ran, which is a forgery and not a certificate"
                .into(),
        ));
    };

    if record.digest_algorithm == certification::CertificateDigest::None
        || record.image == [0u8; 32]
    {
        // Evidence about a name is what an attacker substituting an image
        // keeps, so the channel refuses it and so does this.
        return Err(Outcome::Refused(
            "the certificate measures no artifact, so it is evidence about a name and not about \
             any bytes"
                .into(),
        ));
    }

    if !certificate.is_certified() {
        let failed = named(certificate.failures());
        let missing = named(certificate.missing());
        return Err(Outcome::Refused(format!(
            "this driver is not certified. failed: [{failed}]; never ran: [{missing}]. A check \
             nobody ran is not a check that passed — the second list is a rig that stopped \
             asking, and it is the one that would otherwise go unnoticed"
        )));
    }

    Ok(entry_hex(&record))
}

/// Strips the kernel's log envelope — `[<ticks> <module>] ` — so a line can
/// still be matched from its start.
///
/// Anchored on purpose: searching the line for [`TAG`] instead would match a
/// verdict that merely mentions a certificate, and a tool that reads the wrong
/// line reports one run's answer for another's.
fn without_envelope(line: &str) -> &str {
    line.strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .map_or(line, |(_, rest)| rest)
}

/// Finds the encoded certificate in a boot log.
fn record_in(log: &str) -> Result<Vec<u8>, Outcome> {
    let mut found = None;
    for line in log.lines() {
        let Some(hex) = without_envelope(line.trim()).strip_prefix(TAG) else {
            continue;
        };
        let hex = hex.trim();
        // **The last one, and it is an error for there to be several.** A log
        // with two certificates is two runs concatenated, and picking either
        // silently would report one machine's answer as another's.
        if found.is_some() {
            return Err(Outcome::NoRecord(
                "the log carries more than one certificate, so it is more than one run".into(),
            ));
        }
        found = Some(decode_hex(hex)?);
    }
    found.ok_or_else(|| {
        Outcome::NoRecord("the log carries no certificate; this run certified nothing".into())
    })
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, Outcome> {
    if !hex.len().is_multiple_of(2) {
        return Err(Outcome::NoRecord(
            "the certificate line is not a whole number of bytes".into(),
        ));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let digits = hex.as_bytes();
    for pair in digits.chunks(2) {
        let (Some(high), Some(low)) = (nibble(pair[0]), nibble(pair[1])) else {
            return Err(Outcome::NoRecord(
                "the certificate line is not hexadecimal".into(),
            ));
        };
        out.push(high << 4 | low);
    }
    Ok(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Names the checks in a mask, so a refusal is actionable.
fn named(mask: u32) -> String {
    let mut names = Vec::new();
    for check in tessera_certification::ALL_CHECKS {
        if mask & check.bit() != 0 {
            names.push(check.name());
        }
    }
    names.join(" ")
}

/// The channel entry this certificate earns, as hex for the signer.
///
/// The layout is `api/update-channel`'s, and the fields it carries are the
/// record's — the security version excepted, which certification says nothing
/// about and which whoever assembles a manifest supplies. Left zero here so
/// that a channel built from this alone is refused by the rollback floor rather
/// than admitted at a version this tool made up.
fn entry_hex(record: &certification::Certificate) -> String {
    let mut entry = Vec::with_capacity(tessera_update_channel::ENTRY_SIZE);
    entry.extend_from_slice(&record.driver.to_le_bytes());
    entry.extend_from_slice(&record.device_class.to_le_bytes());
    entry.extend_from_slice(&record.contract_version.to_le_bytes());
    entry.extend_from_slice(&0u32.to_le_bytes());
    entry.extend_from_slice(&record.ran.to_le_bytes());
    entry.extend_from_slice(&record.passed.to_le_bytes());
    entry.extend_from_slice(&[0u8; 8]);
    entry.extend_from_slice(&record.image);
    let mut hex = String::with_capacity(entry.len() * 2);
    for byte in &entry {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
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
}
