// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **crypto client**: a `no_std` Rust program that runs a
//! known-answer test against the display's opposite.
//!
//! **The answer came from outside this machine.** Every value below — the key,
//! the IV, the plaintext and the ciphertext — is published in NIST SP 800-38A,
//! appendix F.2.1, and nothing in this tree computed any of them. That is the
//! whole point: a cipher's output cannot be inspected for correctness the way a
//! sector or a picture can, and everything a driver *reports* about an
//! encryption — that it completed, that the device took the session — is
//! reported identically by one that returned its input unchanged, or encrypted
//! it with a different key, or with a mode nobody asked for. A vector fixed by
//! a standard is the only thing here that a wrong implementation cannot agree
//! with by accident.
//!
//! It also runs the class conformance suite over the driver, as `blk-client`,
//! `input-client`, `snd-client` and `gpu-client` do — the same seven rules, an
//! eighth contract.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Crypto Agility")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use crypto_service::{
    CryptoAlgorithm, CryptoControlReply, CryptoControlRequest, CryptoDataReply, CryptoDataRequest,
    CryptoDescribeReply, CryptoError, CryptoPowerState, CryptoService, CryptoSessionReply,
    CryptoSessionRequest,
};
use tessera_class_conformance::{CRYPTO, Described, Exchange, check};
use tessera_isl_runtime::{decode, encode};
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

/// What this program reports.
const REPORT_TAG: u64 = 0xc0 << 56;
/// The conformance suite came back complete.
const REPORT_CONFORMANT: u64 = 1 << 32;
/// The ciphertext is the one the standard publishes.
const REPORT_KNOWN_ANSWER: u64 = 1 << 33;
/// Decrypting it gave the plaintext back.
const REPORT_ROUND_TRIP: u64 = 1 << 34;
/// A different key produced a different ciphertext.
const REPORT_KEY_MATTERS: u64 = 1 << 35;
/// An algorithm this driver refuses was refused rather than substituted.
const REPORT_REFUSED_ALGORITHM: u64 = 1 << 36;
/// A length the mode cannot work in was refused.
const REPORT_REFUSED_LENGTH: u64 = 1 << 37;
/// An operation on a destroyed session said so.
const REPORT_NO_SESSION: u64 = 1 << 38;
/// An operation naming a different algorithm than its session was refused.
const REPORT_REFUSED_DISAGREEMENT: u64 = 1 << 39;
/// A reset took every session with it.
const REPORT_RESET_CLEARED: u64 = 1 << 40;

/// NIST SP 800-38A, F.2.1 — CBC-AES128.Encrypt.
///
/// Reproduced from the standard, and deliberately not computed: a vector this
/// program worked out would be agreed with by a driver that made the same
/// mistake.
const NIST_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const NIST_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
/// The first two plaintext blocks, and the two the standard says they become.
const NIST_PLAINTEXT: [u8; 32] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
];
const NIST_CIPHERTEXT: [u8; 32] = [
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
];
/// The vector's length, which is two AES blocks.
const DATA_LEN: usize = 32;

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
        Err(_) => Err(fail(0xd8, 0xe)),
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
        return Err(fail(0xd9, (-n) as u64));
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

/// Calls a method taking a control request.
fn control(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Exchange {
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
        Ok(reply) => Exchange {
            ordinal: method,
            status: reply.status as u32,
            answered: true,
            detail: reply.state as u32,
        },
        Err(_) => unanswered(method),
    }
}

/// Opens a session, and reports both the status and the session it named.
fn create_session(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    algorithm: CryptoAlgorithm,
    encrypt: bool,
    key: &[u8],
    iv: &[u8],
) -> (Exchange, u64) {
    let mut key_bytes = [0u8; 32];
    key_bytes[..key.len()].copy_from_slice(key);
    let mut iv_bytes = [0u8; 16];
    iv_bytes[..iv.len()].copy_from_slice(iv);
    let request = CryptoSessionRequest {
        size: CryptoSessionRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        algorithm,
        encrypt: u32::from(encrypt),
        key_len: key.len() as u32,
        iv_len: iv.len() as u32,
        key: key_bytes,
        iv: iv_bytes,
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
        Ok(reply) => (
            Exchange {
                ordinal: method,
                status: reply.status as u32,
                answered: true,
                detail: 0,
            },
            reply.session,
        ),
        Err(_) => (unanswered(method), 0),
    }
}

/// One cipher operation. Returns the exchange and what came back.
fn cipher(
    msg_buf: &mut [u8; MSG_BUF_LEN],
    method: u32,
    session: u64,
    algorithm: CryptoAlgorithm,
    data: &[u8],
    len: u32,
) -> (Exchange, [u8; 64], u32) {
    let mut payload = [0u8; 64];
    payload[..data.len()].copy_from_slice(data);
    let request = CryptoDataRequest {
        size: CryptoDataRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        session,
        algorithm,
        len,
        data: payload,
    };
    if encode(&request, &mut msg_buf[..CryptoDataRequest::WIRE_SIZE]).is_err() {
        return (unanswered(method), [0u8; 64], 0);
    }
    if call(msg_buf, method).is_err() {
        return (unanswered(method), [0u8; 64], 0);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoDataReply>(&bytes[..CryptoDataReply::WIRE_SIZE]) {
        Ok(reply) => (
            Exchange {
                ordinal: method,
                status: reply.status as u32,
                answered: true,
                detail: reply.len,
            },
            reply.data,
            reply.len,
        ),
        Err(_) => (unanswered(method), [0u8; 64], 0),
    }
}

/// Destroys a session. Takes a data request, because naming one is all it needs.
fn destroy(msg_buf: &mut [u8; MSG_BUF_LEN], session: u64) -> Exchange {
    let (exchange, _, _) = cipher(
        msg_buf,
        CryptoService::DESTROY_SESSION,
        session,
        CryptoAlgorithm::None,
        &[],
        0,
    );
    // The reply to this one is a control reply, not a data reply — decoded
    // again over the same bytes, because the two disagree past the status.
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<CryptoControlReply>(&bytes[..CryptoControlReply::WIRE_SIZE]) {
        Ok(reply) => Exchange {
            ordinal: CryptoService::DESTROY_SESSION,
            status: reply.status as u32,
            answered: true,
            detail: reply.state as u32,
        },
        Err(_) => exchange,
    }
}

/// Whether two byte runs of `len` agree.
fn same(left: &[u8], right: &[u8], len: usize) -> bool {
    left.len() >= len && right.len() >= len && left[..len] == right[..len]
}

/// The whole program.
fn run() -> u64 {
    let mut found = REPORT_TAG;
    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut transcript = [unanswered(0); TRANSCRIPT_LEN];

    // What this accelerator is, asked before a key is anywhere near it.
    let request = CryptoControlRequest {
        size: CryptoControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        state: CryptoPowerState::Active,
        reserved: 0,
    };
    if encode(&request, &mut msg_buf[..CryptoControlRequest::WIRE_SIZE]).is_err() {
        return fail(0xda, 0);
    }
    if let Err(code) = call(&mut msg_buf, CryptoService::DESCRIBE) {
        return code;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
    let described: CryptoDescribeReply = match decode(&bytes[..CryptoDescribeReply::WIRE_SIZE]) {
        Ok(reply) => reply,
        Err(_) => return fail(0xda, 1),
    };
    transcript[0] = Exchange {
        ordinal: CryptoService::DESCRIBE,
        status: described.status as u32,
        answered: true,
        detail: 0,
    };
    if described.max_data_bytes < DATA_LEN as u32 || described.max_key_bytes < 16 {
        return fail(0xda, 2);
    }

    // The session the standard's vector runs in.
    let (exchange, encrypting) = create_session(
        &mut msg_buf,
        CryptoAlgorithm::Aes128Cbc,
        true,
        &NIST_KEY,
        &NIST_IV,
    );
    transcript[1] = exchange;
    if exchange.status != CryptoError::Ok as u32 {
        return fail(0xdb, u64::from(exchange.status));
    }

    // **The known-answer test.** Two blocks in, and the two blocks the standard
    // says they become — or something else, which is the only way a wrong
    // cipher ever announces itself.
    let (exchange, produced, len) = cipher(
        &mut msg_buf,
        CryptoService::ENCRYPT,
        encrypting,
        CryptoAlgorithm::Aes128Cbc,
        &NIST_PLAINTEXT,
        DATA_LEN as u32,
    );
    transcript[2] = exchange;
    if exchange.status == CryptoError::Ok as u32
        && len == DATA_LEN as u32
        && same(&produced, &NIST_CIPHERTEXT, DATA_LEN)
    {
        found |= REPORT_KNOWN_ANSWER;
    }
    let ciphertext = produced;

    // **An operation whose algorithm disagrees with its session.** The client
    // says AES-256 over a session made for AES-128; both are real algorithms
    // and the driver can do either, which is what makes proceeding tempting and
    // wrong. It must refuse.
    let (exchange, _, _) = cipher(
        &mut msg_buf,
        CryptoService::ENCRYPT,
        encrypting,
        CryptoAlgorithm::Aes256Cbc,
        &NIST_PLAINTEXT,
        DATA_LEN as u32,
    );
    if exchange.status == CryptoError::Protocol as u32 {
        found |= REPORT_REFUSED_DISAGREEMENT;
    }

    // A length CBC cannot work in.
    let (exchange, _, _) = cipher(
        &mut msg_buf,
        CryptoService::ENCRYPT,
        encrypting,
        CryptoAlgorithm::Aes128Cbc,
        &NIST_PLAINTEXT,
        17,
    );
    if exchange.status == CryptoError::BadDataLength as u32 {
        found |= REPORT_REFUSED_LENGTH;
    }

    // **An algorithm the driver refuses.** The device can do AES-ECB; this
    // driver will not, and the answer is `NOT_SUPPORTED` rather than a session
    // that quietly does something else.
    let (exchange, _) = create_session(
        &mut msg_buf,
        CryptoAlgorithm::Aes128Ecb,
        true,
        &NIST_KEY,
        &[],
    );
    if exchange.status == CryptoError::NotSupported as u32 {
        found |= REPORT_REFUSED_ALGORITHM;
    }

    // The other direction, and back to where this started.
    let (exchange, decrypting) = create_session(
        &mut msg_buf,
        CryptoAlgorithm::Aes128Cbc,
        false,
        &NIST_KEY,
        &NIST_IV,
    );
    if exchange.status != CryptoError::Ok as u32 {
        return fail(0xdc, u64::from(exchange.status));
    }
    let (exchange, back, len) = cipher(
        &mut msg_buf,
        CryptoService::DECRYPT,
        decrypting,
        CryptoAlgorithm::Aes128Cbc,
        &ciphertext,
        DATA_LEN as u32,
    );
    transcript[3] = exchange;
    if exchange.status == CryptoError::Ok as u32
        && len == DATA_LEN as u32
        && same(&back, &NIST_PLAINTEXT, DATA_LEN)
    {
        found |= REPORT_ROUND_TRIP;
    }

    // **A different key, and the same everything else.** What proves the key
    // reached the device rather than being taken and dropped: one byte of it
    // differs and the ciphertext must not be the standard's.
    let mut other_key = NIST_KEY;
    other_key[0] ^= 0x01;
    let (exchange, wrong) = create_session(
        &mut msg_buf,
        CryptoAlgorithm::Aes128Cbc,
        true,
        &other_key,
        &NIST_IV,
    );
    if exchange.status != CryptoError::Ok as u32 {
        return fail(0xdd, u64::from(exchange.status));
    }
    let (exchange, produced, len) = cipher(
        &mut msg_buf,
        CryptoService::ENCRYPT,
        wrong,
        CryptoAlgorithm::Aes128Cbc,
        &NIST_PLAINTEXT,
        DATA_LEN as u32,
    );
    if exchange.status == CryptoError::Ok as u32
        && len == DATA_LEN as u32
        && !same(&produced, &NIST_CIPHERTEXT, DATA_LEN)
    {
        found |= REPORT_KEY_MATTERS;
    }

    // An optional method this driver does not have, which must say so.
    transcript[4] = control(&mut msg_buf, CryptoService::SET_IV);

    // Letting go of a session, and then asking it for something.
    transcript[5] = destroy(&mut msg_buf, encrypting);
    let (exchange, _, _) = cipher(
        &mut msg_buf,
        CryptoService::ENCRYPT,
        encrypting,
        CryptoAlgorithm::Aes128Cbc,
        &NIST_PLAINTEXT,
        DATA_LEN as u32,
    );
    if exchange.status == CryptoError::NoSession as u32 {
        found |= REPORT_NO_SESSION;
    }

    // **A reset takes every session and every key with it**, which is this
    // contract's strongest sentence and the one nothing else here would notice
    // being broken: a session that survived a reset is a key still installed in
    // a device the next client to bind can reach.
    transcript[6] = control(&mut msg_buf, CryptoService::RESET);
    let (exchange, _, _) = cipher(
        &mut msg_buf,
        CryptoService::ENCRYPT,
        wrong,
        CryptoAlgorithm::Aes128Cbc,
        &NIST_PLAINTEXT,
        DATA_LEN as u32,
    );
    if exchange.status == CryptoError::NoSession as u32 {
        found |= REPORT_RESET_CLEARED;
    }
    transcript[7] = control(&mut msg_buf, CryptoService::SET_POWER);
    transcript[8] = control(&mut msg_buf, VENDOR_ORDINAL_BASE);

    let report = check(
        &CRYPTO,
        &Described {
            contract_version: described.contract_version,
            features: described.features,
            vendor: described.vendor_namespace,
        },
        &transcript,
    );
    if report.is_complete() {
        found |= REPORT_CONFORMANT;
    }
    // The low half carries the rule bits, which the verdict does not need and a
    // failure does.
    found | u64::from(report.passed)
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, value, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    exit_reporting(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
