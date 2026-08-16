// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **crypto service class contract**.
//
// The eighth class here, and the first that handles a secret.
//
// Every class before this one describes work whose result can be inspected: a
// sector read, a packet sent, a picture on the glass. A cipher's result cannot.
// Bytes encrypted with the wrong algorithm, the wrong key or the wrong mode are
// indistinguishable from correct ones — nothing fails, nothing looks wrong, and
// the mistake is discovered by whoever tries to decrypt them somewhere else,
// possibly years later. That single fact shapes everything below.
//
// **An algorithm is never implied.** Not by key length, not by field position,
// not by "the one the session was created with". Every request names one, and a
// driver that cannot do what was named answers `NOT_SUPPORTED` and does
// nothing. Substituting is the failure this contract exists to make impossible,
// and it is the one failure that would otherwise go unnoticed. This is
// docs/security/02-cryptography-and-key-management.md's crypto-agility rule
// written as a method signature rather than as advice.
//
// **A key is not data.** It crosses this contract exactly once, in
// `CreateSession`, and every operation afterwards names only the session it
// made. No reply carries key material, no trace event carries it, and no error
// quotes it back. The alternative — a key on every request — would put the same
// secret in every message queue it passes through, once per block encrypted.
//
// **What is deliberately not here.** No key generation, no key storage, no key
// derivation, no certificates and no random numbers. Those belong to a key
// service that owns key lifetime and policy; a device class that carried them
// would be describing a key manager with an accelerator attached. The successor
// to the inline key is a capability to a key that service minted, which is an
// appended field here and a milestone of its own elsewhere (build/README.md,
// D160).
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it.

library tessera.driver.crypto;

// --- 7. Error codes ---------------------------------------------------------

// What a crypto driver is allowed to fail with. A closed set, numbered to the
// framework's discipline from 5 upward. Values are ABI: append only.
strict enum CryptoError : uint32 {
    OK = 0;
    // **No such session, and that is a state rather than a fault.** A session
    // that was destroyed, or that a client never made, is an ordinary thing to
    // discover — a driver restarted underneath a client loses every session it
    // held, and the client's next request has to be able to say so without
    // reporting broken hardware.
    NO_SESSION = 1;
    // The key is not a length this algorithm has, or not one the device will
    // take. Its own code because the fix is a different key, not a different
    // request.
    BAD_KEY_LENGTH = 2;
    // The data is not a length this mode can work in — not whole blocks where
    // the mode needs them, or more than one request carries.
    BAD_DATA_LENGTH = 3;
    // The device itself refused the key. Distinct from `BAD_KEY_LENGTH`
    // because the judgement is the hardware's and no reshaping of the request
    // will change it: a weak key, or one policy forbids.
    KEY_REJECTED = 4;
    // **The algorithm asked for is not available here.** The most important
    // value in this contract. A driver returns it and performs no operation;
    // it never picks something else it can do. A client that receives it has
    // learned a real fact about this machine, which is the whole point of
    // algorithms being named rather than implied.
    NOT_SUPPORTED = 5;
    PROTOCOL = 6;
    DEGRADED = 7;
    // The device is gone. Every session went with it, and an operation
    // outstanding when it left completes with this.
    REMOVED = 8;
};

// --- 2. Optional methods ----------------------------------------------------

bits CryptoFeature : uint64 {
    // The driver implements `Decrypt`. Clear on an accelerator that only
    // encrypts, which is a real shape for a device that exists to protect data
    // on its way out.
    DECRYPT = 0x1;
    // More than one session may be open at a time. Clear where the device
    // holds one and a second `CreateSession` would displace it.
    MULTIPLE_SESSIONS = 0x2;
    // The driver implements `SetIv`: a new IV on an existing session.
    //
    // **A CBC IV must not repeat across messages under one key**, so a contract
    // that could only set an IV when the session was made would force a new
    // session — and a fresh installation of the key — for every message. Clear
    // on a driver that cannot, and a client that reads it clear makes a new
    // session instead. Neither is wrong; what would be wrong is a client
    // silently reusing an IV because there was no way to ask.
    PER_MESSAGE_IV = 0x4;
};

// --- 6. Power states --------------------------------------------------------

// The same four names as the seven classes before it. A power manager
// arbitrates across every device on the machine and cannot do that against a
// per-class vocabulary.
strict enum CryptoPowerState : uint32 {
    ACTIVE = 1;
    IDLE = 2;
    STANDBY = 3;
    OFF = 4;
};

// --- 9. Trace events --------------------------------------------------------

// **No trace point carries key or plaintext bytes**, and that is stated here
// rather than left to a driver's judgement. A trace is written to be read by
// somebody who is not the client, which is exactly the property a secret must
// not have. What a trace carries is the session id, the algorithm and the
// status — enough to follow what happened and nothing that was protected.
strict enum CryptoTracePoint : uint32 {
    SESSION_CREATED = 1;
    SESSION_DESTROYED = 2;
    OPERATION_COMPLETED = 3;
    // An algorithm was asked for and refused. Its own trace point because it is
    // the event an operator most needs to see: it means somebody's software
    // expects a capability this machine does not have, and the alternative to
    // seeing it is a client that silently stops working.
    ALGORITHM_REFUSED = 4;
};

// The algorithms a client may name. **Explicit values, and no default
// anywhere**: there is no "the usual one", because a request that did not have
// to name an algorithm could be served with any of them.
strict enum CryptoAlgorithm : uint32 {
    // Reserved so that a zeroed request names nothing rather than naming the
    // first algorithm in the list by accident.
    NONE = 0;
    AES_128_CBC = 1;
    AES_256_CBC = 2;
    AES_128_CTR = 3;
    AES_128_ECB = 4;
};

// --- 4. Buffer ownership ----------------------------------------------------

// **Everything crosses inline**: the key and IV in `CreateSession`, the data in
// `Encrypt` and `Decrypt`, sixty-four bytes at a time. Which makes this a
// correctness path and not a throughput one, and the contract says so rather
// than implying a rate it cannot sustain.
//
// The out-of-line grant that would change this is the same one the block class
// has and D158 and D159 already record. It matters more here than there: a key
// in an inline payload is bytes in a page the kernel transported, and a key
// behind a capability would never be in a message at all.

// --- 1, 2, 3. The methods and their payloads --------------------------------

@abi
struct CryptoControlRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    state: CryptoPowerState;
    reserved: uint32;
};

@abi
struct CryptoControlReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: CryptoError;
    state: CryptoPowerState;
};

// What this accelerator can do. A client calls it first and asks for nothing
// that is not in the answer.
@abi
struct CryptoDescribeReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    contract_version: uint32;
    status: CryptoError;
    features: uint64;
    // **The algorithms there are**, as a bit per `CryptoAlgorithm` value. A
    // client that guessed would be told `NOT_SUPPORTED` and have to guess
    // again; a client that reads this knows before it holds a key.
    algorithms: uint32;
    // The largest key and the largest single operation this driver takes, so
    // that a client learns its limits rather than discovering them as errors.
    max_key_bytes: uint32;
    max_data_bytes: uint32;
    // How many sessions may be open at once. One is a valid answer.
    max_sessions: uint32;
    power_states: uint32;
    resume_latency_us: uint32;
    vendor: uint32;
    vendor_namespace: uint32;
    vendor_extension_version: uint32;
    reserved: uint32;
};

// A key, an algorithm and a direction, going in once.
@abi
struct CryptoSessionRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    algorithm: CryptoAlgorithm;
    // Whether this session encrypts or decrypts. A session runs one way, and
    // asking it for the other is a different session's work — which is checked,
    // because a device asked the wrong way returns something that is neither an
    // error nor the answer.
    encrypt: uint32;
    // How many bytes of `key` are the key. A field rather than a delimiter: a
    // key is arbitrary bytes and may contain any value, zero included.
    key_len: uint32;
    // How many bytes of `iv` are the IV. Zero is a real answer — ECB has none,
    // and sending one would shift every byte of the data behind it.
    iv_len: uint32;
    key: array<uint8, 32>;
    iv: array<uint8, 16>;
};

@abi
struct CryptoSessionReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: CryptoError;
    reserved: uint32;
    // The name of the session, and the only thing that names its key from here
    // on. Meaningless unless `status` is `OK`.
    session: uint64;
};

// Data, and which session to put it through.
@abi
struct CryptoDataRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    session: uint64;
    // **The algorithm again, named by the client.** Redundant with the
    // session's on purpose: it is the client's statement of what it believes it
    // is doing, and a driver whose session says otherwise refuses rather than
    // proceeding on either reading. Redundancy is what makes a substitution
    // detectable instead of silent.
    algorithm: CryptoAlgorithm;
    len: uint32;
    data: array<uint8, 64>;
};

@abi
struct CryptoDataReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    status: CryptoError;
    // Bytes produced. A cipher's output is exactly as long as its input, so a
    // shorter answer than the request means something went wrong that the
    // status alone would not have distinguished.
    len: uint32;
    data: array<uint8, 64>;
};

@abi
struct CryptoEvent {
    size: uint32;
    version: uint32;
    flags: uint64;
    trace_point: CryptoTracePoint;
    status: CryptoError;
    algorithm: CryptoAlgorithm;
    session: uint64;
};

// --- 8. Reset behaviour -----------------------------------------------------

// `Reset` is defined to leave the driver in `ACTIVE` with **every session
// destroyed and every key zeroized**, in the driver and in the device both.
//
// Which is what makes reset mean something specific in this class rather than
// "put the device back". A reset that left sessions installed would leave a
// secret alive in a device that the next client to bind can reach, and that
// client would not have to do anything wrong to use it.

protocol CryptoService {
    // Required.
    1: Describe(CryptoControlRequest) -> (CryptoDescribeReply);
    // Required. A key goes in; a session id comes back.
    2: CreateSession(CryptoSessionRequest) -> (CryptoSessionReply);
    // Required.
    3: Encrypt(CryptoDataRequest) -> (CryptoDataReply);
    // Optional, gated by `CryptoFeature.DECRYPT`.
    4: Decrypt(CryptoDataRequest) -> (CryptoDataReply);
    // Required. See the reset behaviour above.
    5: Reset(CryptoControlRequest) -> (CryptoControlReply);
    // Required.
    6: SetPower(CryptoControlRequest) -> (CryptoControlReply);
    // Required, and not optional despite having an obvious default: a session
    // holds a key, and a class where letting go of one was optional would have
    // drivers that never did.
    7: DestroySession(CryptoDataRequest) -> (CryptoControlReply);
    // Optional, gated by `CryptoFeature.PER_MESSAGE_IV`. Only `iv` and `iv_len`
    // are read; a request that also carries a key is refused rather than
    // rekeying something the client asked to re-IV.
    8: SetIv(CryptoSessionRequest) -> (CryptoControlReply);

    // 9..=19 are reserved, so the event range stays at a fixed boundary.

    // 3. Events.
    20: -> OnSessionLost(CryptoEvent);
    21: -> OnError(CryptoEvent);
    22: -> OnDeviceGone(CryptoEvent);
};
