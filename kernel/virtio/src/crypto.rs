// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The virtio-crypto symmetric-cipher protocol: what an accelerator says it
//! can do, how a key gets into it, and what one operation looks like.
//!
//! Beside [`snd`](crate::snd) and [`gpu`](crate::gpu), on the same transport
//! and the same split virtqueue. What is different here is not the mechanism
//! but the consequence of getting it wrong.
//!
//! # A wrong answer looks exactly like a right one
//!
//! Every other device in this tree tells on itself. A block driver that reads
//! the wrong sector is caught by whatever reads it next; a display that draws
//! at the wrong stride is visibly wrong. A cipher that quietly did something
//! other than what was asked for returns bytes that are indistinguishable from
//! correct ones until somebody tries to decrypt them somewhere else, years
//! later. So the checks in this module are refusals, and they happen **before**
//! anything is sent: a request that cannot be right is not made.
//!
//! # The algorithm is never implied
//!
//! `docs/security/02-cryptography-and-key-management.md` is normative: an
//! algorithm is never implied by position or field length. This protocol names
//! it twice — once when the session is created and again in every operation —
//! and a driver that let the second one default to "whatever the session was"
//! would be performing exactly the substitution that document forbids. So a
//! [`Session`] carries its algorithm and [`cipher_request`] writes it from
//! there; the two cannot disagree because there is only one of them.
//!
//! # What a key is
//!
//! A key goes into the device once, when a session is created, and is named by
//! a session id afterwards. Nothing in this module returns key material, logs
//! it, or keeps a copy: the bytes are written into a caller's buffer and the
//! caller owns what happens to them next.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Crypto Agility")
//! Budget: none (driven from ring 3)

use crate::Error;

/// The virtio device id a crypto accelerator carries.
pub const DEVICE_ID: u32 = 20;

/// The device's own revision bit, in the low feature word.
///
/// Not `VIRTIO_F_VERSION_1`, which is in the high word and means the transport
/// is modern. This one says the *protocol* is the current revision, and a
/// device that offers it and a driver that does not accept it disagree about
/// the shape of every structure below.
pub const FEATURE_REVISION_1: u32 = 1 << 0;

/// The block a symmetric cipher works in. Every AES mode here uses it, for the
/// key length and the data length alike.
pub const BLOCK_LEN: usize = 16;

/// Bytes of the control request that precede the key.
pub const CTRL_REQ_LEN: usize = 72;
/// Bytes the device writes back when a session is created.
pub const SESSION_INPUT_LEN: usize = 16;
/// Bytes of the operation request that precede the IV and the data.
pub const DATA_REQ_LEN: usize = 72;

/// The queue operations go on. The first, and the control queue is past the
/// last of them.
pub const DATA_QUEUE: u16 = 0;

/// Which of the device's services a bit in `crypto_services` stands for.
pub mod service {
    pub const CIPHER: u32 = 1 << 0;
    pub const HASH: u32 = 1 << 1;
    pub const MAC: u32 = 1 << 2;
    pub const AEAD: u32 = 1 << 3;
    pub const AKCIPHER: u32 = 1 << 4;
}

/// What a request asks for. The service is the high byte and the operation the
/// low one, which is why these are not a dense range.
pub mod opcode {
    pub const CIPHER_ENCRYPT: u32 = 0x0000;
    pub const CIPHER_DECRYPT: u32 = 0x0001;
    pub const CIPHER_CREATE_SESSION: u32 = 0x0002;
    pub const CIPHER_DESTROY_SESSION: u32 = 0x0003;
}

/// What the device answers with. A closed set, and the last two are worth
/// keeping apart: `NOTSUPP` is "this build does not do that" and
/// `KEY_REJECTED` is "that key is not acceptable", which have different fixes.
pub mod status {
    pub const OK: u32 = 0;
    pub const ERR: u32 = 1;
    pub const BADMSG: u32 = 2;
    pub const NOTSUPP: u32 = 3;
    pub const INVSESS: u32 = 4;
    pub const NOSPC: u32 = 5;
    pub const KEY_REJECTED: u32 = 6;
}

/// Whether a status means the request was carried out.
pub fn accepted(code: u32) -> bool {
    code == status::OK
}

/// The symmetric operation a session is for. Named `op_type` on the wire.
const SYM_OP_CIPHER: u32 = 1;

/// A cipher this module can frame a request for.
///
/// Deliberately not "every algorithm the device lists". A driver that framed a
/// request for an algorithm it has no block size or IV length for would be
/// guessing at both, and the guess would be invisible: the device would encrypt
/// something.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Algorithm {
    AesEcb = 2,
    AesCbc = 3,
    AesCtr = 4,
}

impl Algorithm {
    /// The bit this algorithm occupies in the device's `cipher_algo_l` word.
    pub fn bit(self) -> u32 {
        1 << (self as u32)
    }

    /// Bytes of IV this algorithm takes. **Zero is a real answer**: ECB has no
    /// IV, and sending one would shift every byte of the data behind it.
    pub fn iv_len(self) -> usize {
        match self {
            Algorithm::AesEcb => 0,
            Algorithm::AesCbc | Algorithm::AesCtr => BLOCK_LEN,
        }
    }

    /// Whether this algorithm requires whole blocks.
    ///
    /// CTR does not: it is a stream cipher built out of a block cipher, and
    /// refusing a partial last block there would refuse something correct.
    pub fn whole_blocks(self) -> bool {
        match self {
            Algorithm::AesEcb | Algorithm::AesCbc => true,
            Algorithm::AesCtr => false,
        }
    }

    /// Whether `len` is a key length this algorithm has.
    pub fn key_len_ok(self, len: usize) -> bool {
        match self {
            Algorithm::AesEcb | Algorithm::AesCbc | Algorithm::AesCtr => {
                matches!(len, 16 | 24 | 32)
            }
        }
    }
}

/// Which way a session runs. A session is created for one direction and the
/// device keeps it that way; an operation asking for the other one is a
/// different session's work.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Direction {
    Encrypt = 1,
    Decrypt = 2,
}

impl Direction {
    fn opcode(self) -> u32 {
        match self {
            Direction::Encrypt => opcode::CIPHER_ENCRYPT,
            Direction::Decrypt => opcode::CIPHER_DECRYPT,
        }
    }
}

/// What the device says it can do, read out of its configuration space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Config {
    /// How many data queues there are. The control queue comes **after** them.
    pub data_queues: u32,
    /// Which services the device offers, as a bit set.
    pub services: u32,
    /// Which ciphers it offers, as a bit set over the low algorithm word.
    pub cipher_algorithms: u32,
    /// The longest key it will take.
    pub max_key_len: u32,
    /// The most data one request may carry.
    pub max_size: u64,
}

/// Configuration-space offsets, in the order the device publishes them.
mod config_offset {
    pub const MAX_DATAQUEUES: usize = 4;
    pub const CRYPTO_SERVICES: usize = 8;
    pub const CIPHER_ALGO_L: usize = 12;
    pub const MAX_CIPHER_KEY_LEN: usize = 36;
    pub const MAX_SIZE_LOW: usize = 48;
    pub const MAX_SIZE_HIGH: usize = 52;
}

impl Config {
    /// Reads the device's configuration space.
    pub fn read<T: crate::Transport>(transport: &T) -> Result<Config, Error> {
        let config = Config {
            data_queues: transport.config_u32(config_offset::MAX_DATAQUEUES),
            services: transport.config_u32(config_offset::CRYPTO_SERVICES),
            cipher_algorithms: transport.config_u32(config_offset::CIPHER_ALGO_L),
            max_key_len: transport.config_u32(config_offset::MAX_CIPHER_KEY_LEN),
            max_size: u64::from(transport.config_u32(config_offset::MAX_SIZE_LOW))
                | (u64::from(transport.config_u32(config_offset::MAX_SIZE_HIGH)) << 32),
        };
        // A device with no data queue, or with no cipher service, is not one
        // this driver can use — and finding that out here is the difference
        // between a refusal and a request sent to a queue that is not there.
        if config.data_queues == 0 || config.services & service::CIPHER == 0 {
            return Err(Error::NotCryptoDevice);
        }
        Ok(config)
    }

    /// The queue index sessions are made on.
    ///
    /// **After** the data queues, which is the reverse of every other device
    /// here — a driver that assumed the control queue was queue zero would
    /// create its sessions on the queue it then sent operations to, and the
    /// device would answer both from the wrong place.
    pub fn control_queue(&self) -> u16 {
        self.data_queues as u16
    }

    /// Whether the device offers this algorithm.
    ///
    /// Asked rather than assumed, and a `false` here is a refusal rather than
    /// a reason to pick something else: substituting an algorithm the caller
    /// did not name is the failure this whole module is shaped against.
    pub fn offers(&self, algorithm: Algorithm) -> bool {
        self.cipher_algorithms & algorithm.bit() != 0
    }
}

/// A session the device is holding: an algorithm, a direction and a key, under
/// one id.
///
/// The algorithm lives here rather than being passed to each operation so that
/// the operation's copy **cannot** disagree with the session's. There is no key
/// in this structure: the device has it, and this side has an id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Session {
    pub id: u64,
    pub algorithm: Algorithm,
    pub direction: Direction,
}

fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

/// Encodes a create-session request, key and all, into `out`.
///
/// Returns the number of bytes the device may read. The key is copied in
/// directly after the request, which is where the device looks for it — its
/// length is a field, not a delimiter.
pub fn create_session(
    out: &mut [u8],
    algorithm: Algorithm,
    direction: Direction,
    key: &[u8],
    config: &Config,
) -> Result<usize, Error> {
    if !config.offers(algorithm) {
        return Err(Error::AlgorithmNotOffered);
    }
    // Two separate questions, and both have to be asked. A key length the
    // algorithm does not have is a caller's mistake; one the *device* will not
    // take is a smaller device than the caller assumed, and neither is worth
    // finding out from a failed session.
    if !algorithm.key_len_ok(key.len()) || key.len() > config.max_key_len as usize {
        return Err(Error::BadKeyLength);
    }
    let total = CTRL_REQ_LEN + key.len();
    if out.len() < total {
        return Err(Error::ShortResponse);
    }
    out[..CTRL_REQ_LEN].fill(0);
    put32(out, 0, opcode::CIPHER_CREATE_SESSION);
    put32(out, 4, algorithm as u32);
    // The cipher parameters, at the head of the union the request ends with.
    put32(out, 16, algorithm as u32);
    put32(out, 20, key.len() as u32);
    put32(out, 24, direction as u32);
    put32(out, 64, SYM_OP_CIPHER);
    out[CTRL_REQ_LEN..total].copy_from_slice(key);
    Ok(total)
}

/// Encodes a destroy-session request into `out`.
pub fn destroy_session(out: &mut [u8], session_id: u64) -> Result<usize, Error> {
    if out.len() < CTRL_REQ_LEN {
        return Err(Error::ShortResponse);
    }
    out[..CTRL_REQ_LEN].fill(0);
    put32(out, 0, opcode::CIPHER_DESTROY_SESSION);
    put64(out, 16, session_id);
    Ok(CTRL_REQ_LEN)
}

/// Reads back what the device wrote when a session was created.
///
/// Returns the id and the status together, because a status that is not
/// [`accepted`] leaves the id meaningless and separating them invites using it.
pub fn session_reply(bytes: &[u8]) -> Result<(u64, u32), Error> {
    if bytes.len() < SESSION_INPUT_LEN {
        return Err(Error::ShortResponse);
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&bytes[..8]);
    Ok((u64::from_le_bytes(id), get32(bytes, 8)))
}

/// Reads back what the device wrote when a session was destroyed.
///
/// **One byte, where creating a session answered with sixteen.** A driver that
/// read a status word here would read three bytes of whatever was in its own
/// buffer along with it, and a stale non-zero byte would turn a destroyed
/// session into a reported failure.
pub fn destroy_status(bytes: &[u8]) -> Result<u32, Error> {
    match bytes.first() {
        Some(&status) => Ok(u32::from(status)),
        None => Err(Error::ShortResponse),
    }
}

/// Encodes one cipher operation into `out`.
///
/// Returns the number of bytes the device may read *before* the IV and the
/// data, which the caller places after it. `data_len` is the length of the
/// source, and the destination is the same length — for a cipher those are
/// equal by definition, and this function writes both from the one number so
/// that a caller cannot size them apart.
pub fn cipher_request(
    out: &mut [u8],
    session: &Session,
    direction: Direction,
    iv_len: usize,
    data_len: usize,
    config: &Config,
) -> Result<usize, Error> {
    // The session was created for one direction and the device kept it that
    // way. Asking the other way round would encrypt with a decrypt session and
    // return something that is not an error and is not the answer either.
    if direction != session.direction {
        return Err(Error::SessionMismatch);
    }
    if iv_len != session.algorithm.iv_len() {
        return Err(Error::BadDataLength);
    }
    if data_len == 0 || data_len as u64 > config.max_size {
        return Err(Error::BadDataLength);
    }
    if session.algorithm.whole_blocks() && !data_len.is_multiple_of(BLOCK_LEN) {
        return Err(Error::BadDataLength);
    }
    if out.len() < DATA_REQ_LEN {
        return Err(Error::ShortResponse);
    }
    out[..DATA_REQ_LEN].fill(0);
    put32(out, 0, direction.opcode());
    // Written from the session, so that the algorithm in the operation is the
    // algorithm of the session by construction rather than by agreement.
    put32(out, 4, session.algorithm as u32);
    put64(out, 8, session.id);
    // The cipher parameters. `src_data_len` counts the data **only** — the IV
    // is its own region, and folding it in here shifts every byte the device
    // reads.
    put32(out, 24, iv_len as u32);
    put32(out, 28, data_len as u32);
    put32(out, 32, data_len as u32);
    put32(out, 64, SYM_OP_CIPHER);
    Ok(DATA_REQ_LEN)
}
