// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **certifier**: a `no_std` Rust program that runs the checks it
//! can run against a real driver and then **refuses to certify it**.
//!
//! Every other ring-3 client in this tree exists to show that something works.
//! This one exists to show what a run of the checks did *not* cover, which is
//! the harder half and the one nothing else here reports. Two of the eleven
//! checks can be made against a driver from inside a channel; the other nine
//! need a machine somebody is interfering with from outside, a fuzzing engine,
//! or a measurement rig. So the certificate it produces is honest and negative:
//! two checks ran, both passed, and this driver is not certified.
//!
//! **That refusal is the result.** A runner that certified on two checks would
//! be a runner whose certificate meant nothing, and the failure it would be
//! hiding is not a driver bug — it is a rig that stopped asking. The checks in
//! this tree are shell scripts registered by hand; delete a registration and
//! every remaining test still passes. Nothing notices absence except something
//! built to.
//!
//! # What it can actually check from here
//!
//! **Class conformance**: the seven rules of `api/class-conformance`, over a
//! transcript this program drives to completeness — every required method, an
//! advertised optional, an unadvertised one, a reset, and a vendor ordinal
//! nobody negotiated.
//!
//! **ABI conformance**, in the only form a peer can check it: every reply is
//! **self-describing**, and this program compares the size the driver declared
//! against the size of the type it decoded. That is not the same question the
//! host golden tests answer — they ask whether an encoder matches the schema,
//! this asks whether the peer's declaration matches what the reader assumed.
//! The two disagree in practice: `DestroySession` answers with a control reply
//! where a data reply was sent, and a client that decoded by *method* rather
//! than by declaration would read a status out of the wrong offset.
//!
//! # What it cannot check, and does not pretend to
//!
//! The subject. A client sees whoever answers its channel, and from the inside
//! that is "the driver" whatever it is — so the identity in the certificate
//! comes from boot, which spawned it, as this program's startup argument. A
//! certificate a client filled in for itself would be a certificate about
//! nothing in particular.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Certification")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use crypto_service::{
    CryptoAlgorithm, CryptoControlReply, CryptoControlRequest, CryptoDataReply, CryptoDataRequest,
    CryptoDescribeReply, CryptoError, CryptoPowerState, CryptoService, CryptoSessionReply,
    CryptoSessionRequest,
};
use tessera_certification::{ALL, Certificate, Check, Outcome, Runner, Subject};
use tessera_class_conformance::{CRYPTO, Described, Exchange, check};
use tessera_isl_runtime::{decode, encode};
use tessera_power_conformance::{Observed, PowerSpec, check as check_power};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;

/// The one capability boot installs: the driver's service endpoint.
const DRIVER_ENDPOINT_HANDLE: u64 = 0;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// Exchanges the conformance transcript holds.
const TRANSCRIPT_LEN: usize = 9;

/// The class this certifier speaks, as `driver_bind.isl` numbers them.
const DEVICE_CLASS_CRYPTO: u32 = 10;

/// The session key. Any key at all: this program is not checking a cipher, and
/// the driver refusing a bad key length would be a different check than the one
/// being made.
const SESSION_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const SESSION_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
/// Two AES blocks, which is a length CBC can work in.
const DATA_LEN: u32 = 32;

/// What this program reports.
const REPORT_TAG: u64 = 0xc1 << 56;
/// Every reply declared the size of the type it turned out to be.
const REPORT_ABI_AGREED: u64 = 1 << 32;
/// The seven class rules were all reached and all held.
const REPORT_CLASS_COMPLETE: u64 = 1 << 33;
/// **The result**: the runner would not issue a certificate.
const REPORT_REFUSED: u64 = 1 << 34;
/// And the refusal named the nine checks nobody asked.
const REPORT_NINE_MISSING: u64 = 1 << 35;
/// A record claiming a check that never ran was refused, here in ring 3.
const REPORT_FORGERY_REFUSED: u64 = 1 << 36;
/// A certificate for one contract version is not evidence about a later one.
const REPORT_VERSION_MATTERS: u64 = 1 << 37;
/// The device did the same work after a suspend and resume that it did before.
const REPORT_RESUME_WORKS: u64 = 1 << 39;
/// Every power state the driver advertised was reached, every one it did not
/// was refused, and no refusal moved it.
const REPORT_POWER_CONFORMS: u64 = 1 << 38;

/// The four states this class names, so the run below can ask for all of them
/// and not only for the ones the driver happens to have.
const POWER_STATES: [CryptoPowerState; 4] = [
    CryptoPowerState::Active,
    CryptoPowerState::Idle,
    CryptoPowerState::Standby,
    CryptoPowerState::Off,
];

/// The state a class contract defines a driver to be in before anything moves
/// it, and the one a reset returns it to.
const POWER_INITIAL: u32 = CryptoPowerState::Active as u32;

/// Writes a `ChannelMsgArgs` naming a method.
fn channel_args(buf_ptr: u64, method: u32) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xc8, 0xe)),
    }
}

/// One call to the driver. The reply lands back in the same buffer.
fn call(buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Result<(), u64> {
    let args = channel_args(buf.as_ptr() as u64, method)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        DRIVER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xc9, (-n) as u64));
    }
    Ok(())
}

/// An exchange the driver did not answer at all.
fn unanswered(ordinal: u32) -> Exchange {
    Exchange {
        ordinal,
        status: 0,
        answered: false,
        detail: 0,
    }
}

/// What the ABI check accumulates as replies arrive.
///
/// One `bool` and not a count, because the question is whether the peer's
/// declarations *ever* disagreed with what this program read. A driver that
/// declared nine replies correctly and the tenth wrongly is a driver a client
/// misreads once, which is enough.
struct AbiWitness {
    agreed: bool,
    /// How many replies were examined, so a run in which nothing was checked is
    /// distinguishable from one in which everything agreed.
    seen: u32,
}

impl AbiWitness {
    /// Compares what the driver said its reply was against what it was read as.
    fn observe(&mut self, declared: u32, expected: usize) {
        self.seen += 1;
        if declared as usize != expected {
            self.agreed = false;
        }
    }

    /// Whether the peer agreed about every reply it sent, and sent some.
    fn held(&self) -> bool {
        self.agreed && self.seen > 0
    }
}

/// Asks for one power state and reports what came back.
///
/// Every state the class names, not only the advertised ones: half the rules
/// are about what a driver does with a state it does not have, and a run that
/// only asked for the ones it advertised could never reach them.
fn set_power(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    state: CryptoPowerState,
    abi: &mut AbiWitness,
) -> Option<Observed> {
    let request = CryptoControlRequest {
        size: CryptoControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..CryptoControlRequest::WIRE_SIZE]).is_err() {
        return None;
    }
    if call(msg_buf, CryptoService::SET_POWER).is_err() {
        return None;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoControlReply>(&bytes[..CryptoControlReply::WIRE_SIZE]) {
        Ok(reply) => {
            abi.observe(reply.size, CryptoControlReply::WIRE_SIZE);
            Some(Observed {
                requested: state as u32,
                status: reply.status as u32,
                reported: reply.state as u32,
            })
        }
        Err(_) => None,
    }
}

/// One cipher operation, keeping what came back.
///
/// The plain [`cipher`] above throws the payload away because a transcript only
/// needs the status. Here the bytes *are* the check: a resume is only real if
/// the device does the same work afterwards, and the only way to know it is the
/// same work is to compare the answer.
fn cipher_bytes(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    session: u64,
    abi: &mut AbiWitness,
) -> Option<([u8; 64], u32, u32)> {
    let request = CryptoDataRequest {
        size: CryptoDataRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        session,
        algorithm: CryptoAlgorithm::Aes128Cbc,
        len: DATA_LEN,
        data: [0x6b; 64],
    };
    if encode(&request, &mut msg_buf[..CryptoDataRequest::WIRE_SIZE]).is_err() {
        return None;
    }
    if call(msg_buf, CryptoService::ENCRYPT).is_err() {
        return None;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoDataReply>(&bytes[..CryptoDataReply::WIRE_SIZE]) {
        Ok(reply) => {
            abi.observe(reply.size, CryptoDataReply::WIRE_SIZE);
            Some((reply.data, reply.len, reply.status as u32))
        }
        Err(_) => None,
    }
}

/// Whether two byte runs of `len` agree.
fn same(left: &[u8], right: &[u8], len: usize) -> bool {
    left.len() >= len && right.len() >= len && left[..len] == right[..len]
}

/// Calls a method taking a control request, and witnesses its reply's shape.
fn control(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32, abi: &mut AbiWitness) -> Exchange {
    let request = CryptoControlRequest {
        size: CryptoControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: CryptoPowerState::Active,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..CryptoControlRequest::WIRE_SIZE]).is_err() {
        return unanswered(method);
    }
    if call(msg_buf, method).is_err() {
        return unanswered(method);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoControlReply>(&bytes[..CryptoControlReply::WIRE_SIZE]) {
        Ok(reply) => {
            abi.observe(reply.size, CryptoControlReply::WIRE_SIZE);
            Exchange {
                ordinal: method,
                status: reply.status as u32,
                answered: true,
                detail: reply.state as u32,
            }
        }
        Err(_) => unanswered(method),
    }
}

/// Opens a session, and reports both the status and the session it named.
fn create_session(msg_buf: &mut [u8; MSG_BUF_LEN], abi: &mut AbiWitness) -> (Exchange, u64) {
    let mut key = [0u8; 32];
    key[..SESSION_KEY.len()].copy_from_slice(&SESSION_KEY);
    let request = CryptoSessionRequest {
        size: CryptoSessionRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        algorithm: CryptoAlgorithm::Aes128Cbc,
        encrypt: 1,
        key_len: SESSION_KEY.len() as u32,
        iv_len: SESSION_IV.len() as u32,
        key,
        iv: SESSION_IV,
    };
    let method = CryptoService::CREATE_SESSION;
    if encode(&request, &mut msg_buf[..CryptoSessionRequest::WIRE_SIZE]).is_err() {
        return (unanswered(method), 0);
    }
    if call(msg_buf, method).is_err() {
        return (unanswered(method), 0);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoSessionReply>(&bytes[..CryptoSessionReply::WIRE_SIZE]) {
        Ok(reply) => {
            abi.observe(reply.size, CryptoSessionReply::WIRE_SIZE);
            (
                Exchange {
                    ordinal: method,
                    status: reply.status as u32,
                    answered: true,
                    detail: 0,
                },
                reply.session,
            )
        }
        Err(_) => (unanswered(method), 0),
    }
}

/// One cipher operation, for the transcript rather than for its output.
fn cipher(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    method: u32,
    session: u64,
    abi: &mut AbiWitness,
) -> Exchange {
    let request = CryptoDataRequest {
        size: CryptoDataRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        session,
        algorithm: CryptoAlgorithm::Aes128Cbc,
        len: DATA_LEN,
        data: [0x6b; 64],
    };
    if encode(&request, &mut msg_buf[..CryptoDataRequest::WIRE_SIZE]).is_err() {
        return unanswered(method);
    }
    if call(msg_buf, method).is_err() {
        return unanswered(method);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoDataReply>(&bytes[..CryptoDataReply::WIRE_SIZE]) {
        Ok(reply) => {
            abi.observe(reply.size, CryptoDataReply::WIRE_SIZE);
            Exchange {
                ordinal: method,
                status: reply.status as u32,
                answered: true,
                detail: reply.len,
            }
        }
        Err(_) => unanswered(method),
    }
}

/// Destroys a session.
///
/// **The reply is a control reply, and the request was a data request.** This is
/// where decoding by declaration rather than by method earns its keep: a client
/// that assumed the reply matched the request would read a status out of the
/// wrong offset and be told something plausible. The size the driver declares is
/// what says which of the two this is.
fn destroy(msg_buf: &mut [u8; MSG_BUF_LEN], session: u64, abi: &mut AbiWitness) -> Exchange {
    let method = CryptoService::DESTROY_SESSION;
    let request = CryptoDataRequest {
        size: CryptoDataRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        session,
        algorithm: CryptoAlgorithm::None,
        len: 0,
        data: [0; 64],
    };
    if encode(&request, &mut msg_buf[..CryptoDataRequest::WIRE_SIZE]).is_err() {
        return unanswered(method);
    }
    if call(msg_buf, method).is_err() {
        return unanswered(method);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoControlReply>(&bytes[..CryptoControlReply::WIRE_SIZE]) {
        Ok(reply) => {
            abi.observe(reply.size, CryptoControlReply::WIRE_SIZE);
            Exchange {
                ordinal: method,
                status: reply.status as u32,
                answered: true,
                detail: reply.state as u32,
            }
        }
        Err(_) => unanswered(method),
    }
}

/// Runs the checks that can be run from here and reports what they proved.
///
/// `driver` is the identity boot supplied. See the module header: a client
/// cannot observe who it is talking to.
fn run(driver: u32) -> u64 {
    let mut found = REPORT_TAG;
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut transcript = [unanswered(0); TRANSCRIPT_LEN];
    let mut abi = AbiWitness {
        agreed: true,
        seen: 0,
    };

    // What this driver says it is, which every rule about optional methods is
    // relative to.
    let request = CryptoControlRequest {
        size: CryptoControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: CryptoPowerState::Active,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..CryptoControlRequest::WIRE_SIZE]).is_err() {
        return fail(0xca, 0);
    }
    if let Err(code) = call(&mut msg_buf, CryptoService::DESCRIBE) {
        return code;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
    let described: CryptoDescribeReply = match decode(&bytes[..CryptoDescribeReply::WIRE_SIZE]) {
        Ok(reply) => reply,
        Err(_) => return fail(0xca, 1),
    };
    abi.observe(described.size, CryptoDescribeReply::WIRE_SIZE);
    transcript[0] = Exchange {
        ordinal: CryptoService::DESCRIBE,
        status: described.status as u32,
        answered: true,
        detail: 0,
    };

    // A session, so the operations below have something to name.
    let (exchange, session) = create_session(&mut msg_buf, &mut abi);
    transcript[1] = exchange;
    if exchange.status != CryptoError::Ok as u32 {
        return fail(0xcb, u64::from(exchange.status));
    }

    // The required operation, and the advertised optional one — the two halves
    // of the rule that says `Describe` and the methods must agree.
    transcript[2] = cipher(&mut msg_buf, CryptoService::ENCRYPT, session, &mut abi);
    transcript[3] = cipher(&mut msg_buf, CryptoService::DECRYPT, session, &mut abi);
    // And an optional one this driver does not advertise, which must say so
    // rather than doing something.
    transcript[4] = control(&mut msg_buf, CryptoService::SET_IV, &mut abi);

    transcript[5] = destroy(&mut msg_buf, session, &mut abi);
    transcript[6] = control(&mut msg_buf, CryptoService::RESET, &mut abi);
    transcript[7] = control(&mut msg_buf, CryptoService::SET_POWER, &mut abi);
    // A vendor ordinal with nothing negotiated, which must be refused.
    transcript[8] = control(&mut msg_buf, VENDOR_ORDINAL_BASE, &mut abi);

    // **Suspend, resume, and then ask for the same work again.**
    //
    // A resume that returns success and leaves a dead device is the failure
    // this is shaped against, and nothing about the resume itself can catch it:
    // the reply says `Ok` either way. The only thing that distinguishes a
    // device that came back from one that merely said it did is *doing
    // something with it* afterwards and getting the answer it gave before.
    //
    // The same session across the round trip, deliberately. A driver that
    // rebuilt its state from nothing would answer a fresh session correctly and
    // a surviving one with `NO_SESSION`, and only the second is a resume.
    let (resume_exchange, resume_session) = create_session(&mut msg_buf, &mut abi);
    if resume_exchange.status == CryptoError::Ok as u32 {
        let before = cipher_bytes(&mut msg_buf, resume_session, &mut abi);
        let suspended = set_power(&mut msg_buf, CryptoPowerState::Idle, &mut abi);
        let resumed = set_power(&mut msg_buf, CryptoPowerState::Active, &mut abi);
        let after = cipher_bytes(&mut msg_buf, resume_session, &mut abi);
        if let (
            Some((before_data, before_len, before_status)),
            Some(suspended),
            Some(resumed),
            Some((after_data, after_len, after_status)),
        ) = (before, suspended, resumed, after)
            && before_status == CryptoError::Ok as u32
            && after_status == CryptoError::Ok as u32
            && suspended.status == CryptoError::Ok as u32
            && resumed.status == CryptoError::Ok as u32
            && resumed.reported == CryptoPowerState::Active as u32
            && before_len == DATA_LEN
            && after_len == DATA_LEN
            && same(&before_data, &after_data, DATA_LEN as usize)
        {
            found |= REPORT_RESUME_WORKS;
        }
        let _ = destroy(&mut msg_buf, resume_session, &mut abi);
    }

    // **The power run, after the transcript and before the verdict.** It ends
    // by asking for `Active` again, so the driver is left where the contract
    // says it starts rather than wherever the last refusal found it.
    let mut power_run = [Observed {
        requested: 0,
        status: 0,
        reported: 0,
    }; POWER_STATES.len() + 1];
    let mut power_len = 0;
    for state in POWER_STATES {
        if let Some(seen) = set_power(&mut msg_buf, state, &mut abi) {
            power_run[power_len] = seen;
            power_len += 1;
        }
    }
    if let Some(seen) = set_power(&mut msg_buf, CryptoPowerState::Active, &mut abi) {
        power_run[power_len] = seen;
        power_len += 1;
    }
    let power = check_power(
        &PowerSpec {
            advertised: described.power_states,
            ok: CryptoError::Ok as u32,
            not_supported: CryptoError::NotSupported as u32,
            initial: POWER_INITIAL,
        },
        &power_run[..power_len],
    );

    let report = check(
        &CRYPTO,
        &Described {
            contract_version: described.contract_version,
            features: described.features,
            vendor: described.vendor_namespace,
        },
        &transcript,
    );

    // **The two checks, recorded, and the nine deliberately not.** Nothing here
    // records `NotRun` for the rest: a check that declined to run and a check
    // nobody wrote leave the same trace, which is the point.
    let subject = Subject {
        driver,
        class: DEVICE_CLASS_CRYPTO,
        contract_version: described.contract_version,
    };
    let mut runner = Runner::new(subject);
    runner.record(Check::AbiConformance, Outcome::ran(abi.held()));
    runner.record(Check::ClassConformance, Outcome::ran(report.is_complete()));
    runner.record(Check::Power, Outcome::ran(power.is_complete()));
    runner.record(
        Check::SuspendResume,
        Outcome::ran(found & REPORT_RESUME_WORKS != 0),
    );
    let certificate = runner.certificate();

    if abi.held() {
        found |= REPORT_ABI_AGREED;
    }
    if report.is_complete() {
        found |= REPORT_CLASS_COMPLETE;
    }
    if power.is_complete() {
        found |= REPORT_POWER_CONFORMS;
    }
    // The result. Two checks passed and this driver is not certified.
    if !certificate.is_certified() {
        found |= REPORT_REFUSED;
    }
    if certificate.missing().count_ones() == 7 {
        found |= REPORT_NINE_MISSING;
    }

    // The same rules judging records no run produces, here rather than on a
    // host — which is the claim the rules crate makes about itself, checked
    // where it would fail if it were false.
    if Certificate::from_parts(subject, 0, ALL).is_none() {
        found |= REPORT_FORGERY_REFUSED;
    }
    if !certificate.covers(Subject {
        contract_version: described.contract_version + 1,
        ..subject
    }) {
        found |= REPORT_VERSION_MATTERS;
    }

    // The low half carries which checks ran, so a failure names them.
    found | u64::from(certificate.ran())
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, value, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry point; the startup argument is the driver this run is about.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    exit_reporting(run(arg as u32))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
