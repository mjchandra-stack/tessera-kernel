// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **crypto driver**: a `no_std` Rust program that brings a
//! virtio-crypto device up and serves `tessera.driver.crypto` over it.
//!
//! **The first driver here that holds a secret.** Every other one moves data
//! that is already the client's; this one is handed a key, puts it into a
//! device, and then has to make sure it does not keep it. So the key is written
//! into the DMA page the device reads, and the moment the device has taken it
//! that page is zeroed — not because anything in this machine would go looking,
//! but because a page that no longer holds a key cannot leak one.
//!
//! **It refuses AES-ECB although the device offers it.** ECB encrypts equal
//! blocks to equal ciphertext, which leaks the shape of whatever it protects;
//! `docs/security/02-cryptography-and-key-management.md` has policy decide which
//! algorithms are valid rather than code, and this driver is the smallest
//! honest version of that: the refusal is a compiled constant here, and where
//! that policy should live is recorded in build/README.md, D160.
//!
//! The transport is `tessera-virtio`'s PCI transport, split virtqueue and
//! symmetric-cipher encodings, unchanged; what this file adds is the volatile
//! access to a window the kernel mapped, and the pages the device reads keys
//! and data out of.
//!
//! **It names no syscall.** Binding, the register window, the DMA pages and the
//! serve loop all go through [`tessera_sdk`], which is the whole of what a
//! driver author has to know — so the argument-struct versions, the ordinals
//! and the reply-that-does-not-block-the-server live in one place instead of
//! being copied into each driver that needs them.
//!
//! Normative: docs/security/02-cryptography-and-key-management.md
//! ("Crypto Agility")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use crypto_service::{
    CryptoAlgorithm, CryptoControlReply, CryptoDataReply, CryptoDescribeReply, CryptoError,
    CryptoPowerState, CryptoServiceIncoming, CryptoSessionReply,
};
use device_abi::DeviceInfoRecord;
use driver_bind::{BindReply, BindRequest, DeviceClass};
use tessera_isl_runtime::{Reader, WireError, decode, encode};
use tessera_sdk::{
    Dma as Page, Endpoint, Error as SdkError, Handle as SdkHandle, Platform as _, machine::Machine,
};
use tessera_uabi::fail;
use tessera_virtio::pci::{PciTransport, Regs};
use tessera_virtio::{Layout, Transport, crypto};

/// The capabilities boot installs, in order.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;
const CLIENT_ENDPOINT_HANDLE: u64 = 1;
const DEVICE_HANDLE: u32 = 2;

/// Where this program asks for the device's registers and its DMA pages.
const MMIO_VA: u64 = 0x0000_1000_0060_0000;
const DMA_VA_BASE: u64 = 0x0000_1000_0070_0000;
const PAGE: u64 = 0x1000;

/// Queue entries. One operation at a time and a chain is up to five
/// descriptors, so eight is room for one in flight and slack behind it.
const QUEUE_SIZE: u16 = 8;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// How many sessions this driver holds at once.
const MAX_SESSIONS: usize = 4;

/// The longest key and the most data one request carries, which is what the
/// contract's inline payloads hold.
const MAX_KEY_BYTES: u32 = 32;
const MAX_DATA_BYTES: u32 = 64;

/// What this driver advertises: it decrypts, and it holds more than one session.
/// `PER_MESSAGE_IV` is clear — a new IV means a new session here.
const FEATURES: u64 = 0x1 | 0x2;

/// The class contract version this driver implements.
const CONTRACT_VERSION: u32 = 1;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// Where things live in the one DMA page this driver works out of.
///
/// Separated rather than packed, so that a request, its IV, its input and its
/// output never overlap — a device told to write its output over the input it
/// is still reading produces something that is neither.
const CTRL_AT: usize = 0;
const CTRL_IN_AT: usize = 256;
const DATA_REQ_AT: usize = 512;
const IV_AT: usize = 768;
const SRC_AT: usize = 1024;
const DST_AT: usize = 1280;
const STATUS_AT: usize = 1536;

/// A window the kernel mapped, at some offset into it.
struct Window {
    base: usize,
}

impl Regs for Window {
    fn read8(&self, offset: usize) -> u8 {
        // SAFETY: `base` is inside the window `MapDevice` installed in this
        // address space, and every offset is a defined field of the structure
        // the device's own capabilities placed there.
        unsafe { ((self.base + offset) as *const u8).read_volatile() }
    }
    fn read16(&self, offset: usize) -> u16 {
        // SAFETY: as `read8`.
        unsafe { ((self.base + offset) as *const u16).read_volatile() }
    }
    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: as `read8`.
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }
    fn write8(&self, offset: usize, value: u8) {
        // SAFETY: as `read8`; this driver exclusively owns the device.
        unsafe { ((self.base + offset) as *mut u8).write_volatile(value) }
    }
    fn write16(&self, offset: usize, value: u16) {
        // SAFETY: as `write8`.
        unsafe { ((self.base + offset) as *mut u16).write_volatile(value) }
    }
    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: as `write8`.
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
}

/// Hands a slice over a DMA page to a caller, scoped so no two exist at once.
///
/// **This program no longer forms the pointer.** It used to, in one line every
/// driver here had a copy of, and the address in it is only memory on the
/// machine that mapped it — which is why nothing could ever watch what a
/// driver did with a page. Going through the platform costs nothing and is
/// what `tessera_sdk::dma` can model.
fn with_page<R>(page: &Page, f: impl FnOnce(&mut [u8]) -> R) -> R {
    Machine.with_dma(page, f)
}

/// Acquires a crypto accelerator from the device manager.
fn bind() -> Result<(), u64> {
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class: DeviceClass::Crypto,
        reserved: 0,
    };
    let mut message = [0u8; BindRequest::WIRE_SIZE];
    if encode(&request, &mut message).is_err() {
        return Err(fail(0xc1, 0xe));
    }
    // The manager's answer is about policy. What it says is this driver's
    // business — the SDK carries the bytes and reads none of them.
    let mut answer = [0u8; BindReply::WIRE_SIZE];
    tessera_sdk::bind(
        &mut Machine,
        Endpoint(SdkHandle(MANAGER_ENDPOINT_HANDLE)),
        &message,
        &mut answer,
    )
    .map_err(|_| fail(0xc1, 1))?;
    let reply: BindReply = match decode(&answer) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0xc1, 0xd)),
    };
    if reply.status != 0 {
        return Err(fail(0xc1, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Crypto {
        return Err(fail(0xc1, 0x200 | (reply.class as u64)));
    }
    Ok(())
}

/// Asks the kernel where this device's virtio structures are.
fn device_layout() -> Result<DeviceInfoRecord, u64> {
    // Where this device's structures are. A driver holding a register window
    // still cannot find anything in it: configuration space is not per-device
    // and no capability to it can be handed out, so the kernel is asked.
    let mut record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    Machine
        .device_info(SdkHandle(u64::from(DEVICE_HANDLE)), &mut record)
        .map_err(|_| fail(0xc2, 1))?;
    let info: DeviceInfoRecord = match decode(&record) {
        Ok(info) => info,
        Err(_) => return Err(fail(0xc2, 0xd)),
    };
    Ok(info)
}

/// Maps the device's register window.
fn map_device(vaddr: u64) -> Result<u64, u64> {
    Machine
        .map_device(SdkHandle(u64::from(DEVICE_HANDLE)), vaddr)
        .map_err(|_| fail(0xc3, 1))
}

/// Hands out the next page the device can address.
struct Pages {
    next: usize,
}

impl Pages {
    fn take(&mut self) -> Result<Page, u64> {
        let vaddr = DMA_VA_BASE + (self.next as u64) * PAGE;
        // The two addresses of one page. This program writes through the
        // first and hands the device the second, and nothing it could
        // compute would relate them.
        let dma = Machine
            .dma_alloc(SdkHandle(u64::from(DEVICE_HANDLE)), vaddr)
            .map_err(|_| fail(0xc4, 1))?;
        self.next += 1;
        Ok(dma)
    }
}

/// One region of a chain: where it is, how long, and which way it goes.
#[derive(Clone, Copy)]
struct Region {
    phys: u64,
    len: u32,
    writable: bool,
}

/// A queue and where the driver is in it.
struct Ring {
    page: Page,
    layout: Layout,
    next_desc: u16,
    avail_index: u16,
    used_index: u16,
}

/// The longest chain here: request, IV, source, destination, status.
const MAX_CHAIN: usize = 5;

impl Ring {
    /// Puts one chain on the ring.
    ///
    /// A chain rather than a pair, because a cipher operation is four or five
    /// regions and the device reads their directions off the descriptors: the
    /// **last writable byte is the status**, and a driver that put it anywhere
    /// else would have the device write its status over the ciphertext.
    fn submit(&mut self, regions: &[Region]) -> Result<(), u64> {
        if regions.is_empty() || regions.len() > MAX_CHAIN {
            return Err(fail(0xc5, 2));
        }
        let head = self.next_desc;
        let (layout, avail) = (self.layout, self.avail_index);
        let count = regions.len() as u16;
        with_page(&self.page, |memory| {
            for (index, region) in regions.iter().enumerate() {
                let slot = (head + index as u16) % QUEUE_SIZE;
                let next = (head + index as u16 + 1) % QUEUE_SIZE;
                let last = index + 1 == regions.len();
                let mut flags = if region.writable { 0x2u16 } else { 0 };
                if !last {
                    flags |= 0x1;
                }
                let at = layout.desc_offset + usize::from(slot) * 16;
                memory[at..at + 8].copy_from_slice(&region.phys.to_le_bytes());
                memory[at + 8..at + 12].copy_from_slice(&region.len.to_le_bytes());
                memory[at + 12..at + 14].copy_from_slice(&flags.to_le_bytes());
                let next = if last { 0 } else { next };
                memory[at + 14..at + 16].copy_from_slice(&next.to_le_bytes());
            }
            let slot = layout.avail_offset + 4 + usize::from(avail % QUEUE_SIZE) * 2;
            memory[slot..slot + 2].copy_from_slice(&head.to_le_bytes());
            let at = layout.avail_offset + 2;
            memory[at..at + 2].copy_from_slice(&avail.wrapping_add(1).to_le_bytes());
        });
        self.avail_index = self.avail_index.wrapping_add(1);
        self.next_desc = (head + count) % QUEUE_SIZE;
        Ok(())
    }

    fn completed(&self) -> bool {
        let layout = self.layout;
        let published = with_page(&self.page, |memory| {
            let at = layout.used_offset + 2;
            u16::from_le_bytes([memory[at], memory[at + 1]])
        });
        published != self.used_index
    }

    fn collect(&mut self) {
        self.used_index = self.used_index.wrapping_add(1);
    }
}

/// A session this driver is holding on the client's behalf.
#[derive(Clone, Copy)]
struct SessionSlot {
    live: bool,
    /// What the class contract calls it, which is what the device calls it.
    session: crypto::Session,
    /// What the client named it as, kept so that an operation naming something
    /// else can be refused rather than reconciled.
    named: CryptoAlgorithm,
    /// The IV this session runs with. Not a secret, and needed on every
    /// operation because the device takes it per request rather than holding it.
    iv: [u8; 16],
    iv_len: usize,
}

/// Everything the driver carries.
struct Driver {
    control: Ring,
    data: Ring,
    page: Page,
    config: crypto::Config,
    sessions: [SessionSlot; MAX_SESSIONS],
    power: CryptoPowerState,
}

/// Runs one chain and waits for the device to finish with it.
fn run_chain<T: Transport>(
    ring: &mut Ring,
    transport: &T,
    queue: u16,
    regions: &[Region],
) -> Result<(), u64> {
    ring.submit(regions)?;
    transport.notify(queue);
    // Bounded: a device that never answers is a device, not a hang.
    for _ in 0..4_000_000u32 {
        if ring.completed() {
            ring.collect();
            return Ok(());
        }
    }
    Err(fail(0xc5, 1))
}

/// What the device said, as this class's vocabulary.
///
/// The mapping is deliberately narrow. A device status this driver has no name
/// for becomes `DEGRADED` rather than something more specific, because guessing
/// which of the contract's errors an unknown code meant would tell a client
/// something nobody knows.
fn device_status(code: u32) -> CryptoError {
    match code {
        crypto::status::OK => CryptoError::Ok,
        crypto::status::NOTSUPP => CryptoError::NotSupported,
        crypto::status::KEY_REJECTED => CryptoError::KeyRejected,
        crypto::status::INVSESS => CryptoError::NoSession,
        crypto::status::BADMSG => CryptoError::Protocol,
        _ => CryptoError::Degraded,
    }
}

/// What a named algorithm is, on the wire and in key bytes.
///
/// **AES-ECB is absent on purpose.** The device offers it and this driver does
/// not: equal blocks encrypt to equal ciphertext, which leaks the shape of
/// whatever is being protected. A client that names it is told `NOT_SUPPORTED`,
/// which is a true statement about this machine.
fn algorithm_of(named: CryptoAlgorithm) -> Option<(crypto::Algorithm, usize)> {
    match named {
        CryptoAlgorithm::Aes128Cbc => Some((crypto::Algorithm::AesCbc, 16)),
        CryptoAlgorithm::Aes256Cbc => Some((crypto::Algorithm::AesCbc, 32)),
        CryptoAlgorithm::Aes128Ctr => Some((crypto::Algorithm::AesCtr, 16)),
        CryptoAlgorithm::Aes128Ecb | CryptoAlgorithm::None => None,
    }
}

/// The algorithms this driver serves, as the bit set `Describe` reports.
fn offered(config: &crypto::Config) -> u32 {
    let mut bits = 0;
    for named in [
        CryptoAlgorithm::Aes128Cbc,
        CryptoAlgorithm::Aes256Cbc,
        CryptoAlgorithm::Aes128Ctr,
    ] {
        if let Some((algorithm, _)) = algorithm_of(named)
            && config.offers(algorithm)
        {
            bits |= 1 << (named as u32);
        }
    }
    bits
}

/// Creates a session in the device and remembers it.
fn create_session<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    named: CryptoAlgorithm,
    encrypt: bool,
    key: &[u8],
    iv: &[u8],
) -> Result<(CryptoError, u64), u64> {
    let Some((algorithm, key_len)) = algorithm_of(named) else {
        return Ok((CryptoError::NotSupported, 0));
    };
    if !driver.config.offers(algorithm) {
        return Ok((CryptoError::NotSupported, 0));
    }
    // The key length belongs to the *named* algorithm, not to whatever the
    // client sent: AES-128 and AES-256 are the same mode and a client that sent
    // 32 bytes for the first would otherwise get a cipher it did not name.
    if key.len() != key_len {
        return Ok((CryptoError::BadKeyLength, 0));
    }
    if iv.len() != algorithm.iv_len() {
        return Ok((CryptoError::BadDataLength, 0));
    }
    let Some(slot) = driver.sessions.iter().position(|slot| !slot.live) else {
        return Ok((CryptoError::Degraded, 0));
    };

    let direction = if encrypt {
        crypto::Direction::Encrypt
    } else {
        crypto::Direction::Decrypt
    };
    let mut request = [0u8; crypto::CTRL_REQ_LEN + 32];
    let len = match crypto::create_session(&mut request, algorithm, direction, key, &driver.config)
    {
        Ok(len) => len,
        Err(tessera_virtio::Error::AlgorithmNotOffered) => {
            return Ok((CryptoError::NotSupported, 0));
        }
        Err(tessera_virtio::Error::BadKeyLength) => return Ok((CryptoError::BadKeyLength, 0)),
        Err(_) => return Err(fail(0xc6, 0)),
    };

    let page = driver.page;
    with_page(&page, |memory| {
        memory[CTRL_AT..CTRL_AT + len].copy_from_slice(&request[..len]);
        memory[CTRL_IN_AT..CTRL_IN_AT + crypto::SESSION_INPUT_LEN].fill(0);
    });
    // The key has been copied into the page the device reads; this program's
    // own copy of it stops existing here.
    request.fill(0);

    let result = run_chain(
        &mut driver.control,
        transport,
        driver.config.control_queue(),
        &[
            Region {
                phys: page.device_address + CTRL_AT as u64,
                len: len as u32,
                writable: false,
            },
            Region {
                phys: page.device_address + CTRL_IN_AT as u64,
                len: crypto::SESSION_INPUT_LEN as u32,
                writable: true,
            },
        ],
    );
    // **The key leaves the page whether or not the session was made.** A
    // failure is the case where a driver most easily forgets, and a page still
    // holding a key it could not install is the same secret sitting in memory
    // for no reason at all.
    let reply = with_page(&page, |memory| {
        let reply = crypto::session_reply(&memory[CTRL_IN_AT..CTRL_IN_AT + 16]);
        memory[CTRL_AT..CTRL_AT + crypto::CTRL_REQ_LEN + 32].fill(0);
        reply
    });
    result?;

    let Ok((id, status)) = reply else {
        return Err(fail(0xc6, 1));
    };
    if !crypto::accepted(status) {
        return Ok((device_status(status), 0));
    }
    let mut stored = [0u8; 16];
    stored[..iv.len()].copy_from_slice(iv);
    driver.sessions[slot] = SessionSlot {
        live: true,
        session: crypto::Session {
            id,
            algorithm,
            direction,
        },
        named,
        iv: stored,
        iv_len: iv.len(),
    };
    Ok((CryptoError::Ok, id))
}

/// Destroys one session in the device and forgets it here.
fn destroy_session<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    id: u64,
) -> Result<CryptoError, u64> {
    let Some(slot) = driver
        .sessions
        .iter()
        .position(|slot| slot.live && slot.session.id == id)
    else {
        return Ok(CryptoError::NoSession);
    };
    let mut request = [0u8; crypto::CTRL_REQ_LEN];
    if crypto::destroy_session(&mut request, id).is_err() {
        return Err(fail(0xc7, 0));
    }
    let page = driver.page;
    with_page(&page, |memory| {
        memory[CTRL_AT..CTRL_AT + crypto::CTRL_REQ_LEN].copy_from_slice(&request);
        memory[STATUS_AT] = 0xff;
    });
    run_chain(
        &mut driver.control,
        transport,
        driver.config.control_queue(),
        &[
            Region {
                phys: page.device_address + CTRL_AT as u64,
                len: crypto::CTRL_REQ_LEN as u32,
                writable: false,
            },
            Region {
                phys: page.device_address + STATUS_AT as u64,
                len: 1,
                writable: true,
            },
        ],
    )?;
    let status = with_page(&page, |memory| {
        crypto::destroy_status(&memory[STATUS_AT..STATUS_AT + 1])
    });
    // Forgotten here whatever the device said. A slot pointing at a session the
    // device may or may not still hold is worse than no slot: the next
    // operation on it would be answered by something nobody can name.
    driver.sessions[slot].live = false;
    driver.sessions[slot].iv.fill(0);
    match status {
        Ok(code) if crypto::accepted(code) => Ok(CryptoError::Ok),
        Ok(code) => Ok(device_status(code)),
        Err(_) => Err(fail(0xc7, 1)),
    }
}

/// Runs one cipher operation, writing the result into `out`.
fn cipher<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    id: u64,
    named: CryptoAlgorithm,
    encrypt: bool,
    data: &[u8],
    out: &mut [u8; 64],
) -> Result<(CryptoError, u32), u64> {
    let Some(slot) = driver
        .sessions
        .iter()
        .position(|slot| slot.live && slot.session.id == id)
    else {
        return Ok((CryptoError::NoSession, 0));
    };
    let session = driver.sessions[slot];
    // **The client's algorithm and the session's must agree.** Refused rather
    // than reconciled: proceeding on either reading would be performing an
    // operation nobody asked for, which is the one mistake in this class that
    // produces no visible symptom.
    if named != session.named {
        return Ok((CryptoError::Protocol, 0));
    }
    let direction = if encrypt {
        crypto::Direction::Encrypt
    } else {
        crypto::Direction::Decrypt
    };
    if direction != session.session.direction {
        return Ok((CryptoError::Protocol, 0));
    }

    let mut request = [0u8; crypto::DATA_REQ_LEN];
    match crypto::cipher_request(
        &mut request,
        &session.session,
        direction,
        session.iv_len,
        data.len(),
        &driver.config,
    ) {
        Ok(_) => {}
        Err(tessera_virtio::Error::BadDataLength) => return Ok((CryptoError::BadDataLength, 0)),
        Err(tessera_virtio::Error::SessionMismatch) => return Ok((CryptoError::Protocol, 0)),
        Err(_) => return Err(fail(0xc8, 0)),
    }

    let page = driver.page;
    with_page(&page, |memory| {
        memory[DATA_REQ_AT..DATA_REQ_AT + crypto::DATA_REQ_LEN].copy_from_slice(&request);
        memory[IV_AT..IV_AT + session.iv_len].copy_from_slice(&session.iv[..session.iv_len]);
        memory[SRC_AT..SRC_AT + data.len()].copy_from_slice(data);
        // Zeroed, so what is read back is what the device wrote rather than
        // what the last operation left.
        memory[DST_AT..DST_AT + data.len()].fill(0);
        memory[STATUS_AT] = 0xff;
    });

    let mut regions = [Region {
        phys: 0,
        len: 0,
        writable: false,
    }; MAX_CHAIN];
    let mut count = 0;
    let mut push = |phys: u64, len: u32, writable: bool| {
        regions[count] = Region {
            phys,
            len,
            writable,
        };
        count += 1;
    };
    push(
        page.device_address + DATA_REQ_AT as u64,
        crypto::DATA_REQ_LEN as u32,
        false,
    );
    if session.iv_len > 0 {
        push(
            page.device_address + IV_AT as u64,
            session.iv_len as u32,
            false,
        );
    }
    push(
        page.device_address + SRC_AT as u64,
        data.len() as u32,
        false,
    );
    push(page.device_address + DST_AT as u64, data.len() as u32, true);
    push(page.device_address + STATUS_AT as u64, 1, true);

    run_chain(
        &mut driver.data,
        transport,
        crypto::DATA_QUEUE,
        &regions[..count],
    )?;

    let (status, produced) = with_page(&page, |memory| {
        let status = memory[STATUS_AT];
        out[..data.len()].copy_from_slice(&memory[DST_AT..DST_AT + data.len()]);
        // The plaintext this driver was handed does not outlive the operation
        // that needed it.
        memory[SRC_AT..SRC_AT + data.len()].fill(0);
        (u32::from(status), data.len() as u32)
    });
    if !crypto::accepted(status) {
        return Ok((device_status(status), 0));
    }
    Ok((CryptoError::Ok, produced))
}

/// Answers one client request. Returns the reply's encoded length.
fn serve<T: Transport>(
    driver: &mut Driver,
    transport: &T,
    method: u32,
    request: Result<CryptoServiceIncoming, WireError>,
    msg_buf: &mut [u8; MSG_BUF_LEN],
) -> Result<usize, u64> {
    let control_reply =
        |status: CryptoError, state: CryptoPowerState, buf: &mut [u8; MSG_BUF_LEN]| {
            let reply = CryptoControlReply {
                size: CryptoControlReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                state,
            };
            match encode(&reply, &mut buf[..CryptoControlReply::WIRE_SIZE]) {
                Ok(_) => Ok(CryptoControlReply::WIRE_SIZE),
                Err(_) => Err(fail(0xc9, 0xe)),
            }
        };
    let session_reply = |status: CryptoError, session: u64, buf: &mut [u8; MSG_BUF_LEN]| {
        let reply = CryptoSessionReply {
            size: CryptoSessionReply::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            status,
            reserved: 0,
            session,
        };
        match encode(&reply, &mut buf[..CryptoSessionReply::WIRE_SIZE]) {
            Ok(_) => Ok(CryptoSessionReply::WIRE_SIZE),
            Err(_) => Err(fail(0xc9, 0xe)),
        }
    };
    let data_reply =
        |status: CryptoError, len: u32, data: [u8; 64], buf: &mut [u8; MSG_BUF_LEN]| {
            let reply = CryptoDataReply {
                size: CryptoDataReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                status,
                len,
                data,
            };
            match encode(&reply, &mut buf[..CryptoDataReply::WIRE_SIZE]) {
                Ok(_) => Ok(CryptoDataReply::WIRE_SIZE),
                Err(_) => Err(fail(0xc9, 0xe)),
            }
        };

    if method >= VENDOR_ORDINAL_BASE {
        return control_reply(CryptoError::Protocol, driver.power, msg_buf);
    }
    let request = match request {
        Ok(request) => request,
        Err(WireError::UnknownMethod | WireError::HandleIndexOutOfRange) => {
            return control_reply(CryptoError::Protocol, driver.power, msg_buf);
        }
        Err(_) => return Err(fail(0xca, u64::from(method))),
    };

    match request {
        CryptoServiceIncoming::Describe(_) => {
            let reply = CryptoDescribeReply {
                size: CryptoDescribeReply::WIRE_SIZE as u32,
                version: 1,
                flags: 0,
                contract_version: CONTRACT_VERSION,
                status: CryptoError::Ok,
                features: FEATURES,
                algorithms: offered(&driver.config),
                max_key_bytes: MAX_KEY_BYTES,
                max_data_bytes: MAX_DATA_BYTES,
                max_sessions: MAX_SESSIONS as u32,
                power_states: (1 << CryptoPowerState::Active as u32)
                    | (1 << CryptoPowerState::Idle as u32),
                resume_latency_us: 100,
                vendor: 0,
                vendor_namespace: 0,
                vendor_extension_version: 0,
                reserved: 0,
            };
            match encode(&reply, &mut msg_buf[..CryptoDescribeReply::WIRE_SIZE]) {
                Ok(_) => Ok(CryptoDescribeReply::WIRE_SIZE),
                Err(_) => Err(fail(0xc9, 0xe)),
            }
        }
        CryptoServiceIncoming::CreateSession(ask) => {
            if ask.key_len as usize > ask.key.len() || ask.key_len > MAX_KEY_BYTES {
                return session_reply(CryptoError::BadKeyLength, 0, msg_buf);
            }
            if ask.iv_len as usize > ask.iv.len() {
                return session_reply(CryptoError::BadDataLength, 0, msg_buf);
            }
            let (status, session) = create_session(
                driver,
                transport,
                ask.algorithm,
                ask.encrypt != 0,
                &ask.key[..ask.key_len as usize],
                &ask.iv[..ask.iv_len as usize],
            )?;
            session_reply(status, session, msg_buf)
        }
        CryptoServiceIncoming::Encrypt(ask) | CryptoServiceIncoming::Decrypt(ask) => {
            let encrypt = method == crypto_service::CryptoService::ENCRYPT;
            let mut out = [0u8; 64];
            if ask.len as usize > ask.data.len() || ask.len == 0 {
                return data_reply(CryptoError::BadDataLength, 0, out, msg_buf);
            }
            let (status, len) = cipher(
                driver,
                transport,
                ask.session,
                ask.algorithm,
                encrypt,
                &ask.data[..ask.len as usize],
                &mut out,
            )?;
            data_reply(status, len, out, msg_buf)
        }
        CryptoServiceIncoming::DestroySession(ask) => {
            let status = destroy_session(driver, transport, ask.session)?;
            control_reply(status, driver.power, msg_buf)
        }
        CryptoServiceIncoming::Reset(_) => {
            // **Every session destroyed and every key gone with it.** A reset
            // that left one installed would leave a secret alive in a device the
            // next client to bind can reach.
            let live: [u64; MAX_SESSIONS] = core::array::from_fn(|index| {
                let slot = driver.sessions[index];
                if slot.live { slot.session.id } else { 0 }
            });
            let mut status = CryptoError::Ok;
            for id in live {
                if id != 0 {
                    let outcome = destroy_session(driver, transport, id)?;
                    if outcome != CryptoError::Ok {
                        status = outcome;
                    }
                }
            }
            for slot in driver.sessions.iter_mut() {
                slot.live = false;
                slot.iv.fill(0);
            }
            driver.power = CryptoPowerState::Active;
            control_reply(status, CryptoPowerState::Active, msg_buf)
        }
        CryptoServiceIncoming::SetPower(ask) => match ask.state {
            CryptoPowerState::Active | CryptoPowerState::Idle => {
                driver.power = ask.state;
                control_reply(CryptoError::Ok, ask.state, msg_buf)
            }
            _ => control_reply(CryptoError::NotSupported, driver.power, msg_buf),
        },
        CryptoServiceIncoming::SetIv(_) => {
            // Advertised as absent and answered as absent: a new IV means a new
            // session here, and a client that reads the feature bit knows to
            // make one.
            control_reply(CryptoError::NotSupported, driver.power, msg_buf)
        }
    }
}

/// Startup-argument bit asking this driver to die **after taking a request and
/// before answering it**.
///
/// After, deliberately, and not after binding. A driver that crashed at bind
/// would be dead before any client called it, and a call to an
/// already-dead server is refused at the door — `channel_call` checks for a
/// closed peer before it parks. What has to be exercised is the other case: a
/// caller already parked, waiting for a reply from a process that is about to
/// stop existing. That is the one nothing woke.
const CRASH_BEFORE_REPLYING: u64 = 1 << 63;

/// Dies the way a real driver does: a fault, not an exit.
///
/// A tidy exit would release the same things through a different path and
/// prove the wrong thing. This is a read of address zero, which no process this
/// kernel builds has mapped.
fn crash() -> ! {
    // SAFETY: there is no invariant to uphold — the read is meant to fault, at
    // an address chosen because it can never accidentally succeed.
    unsafe { core::ptr::read_volatile(core::ptr::null::<u64>()) };
    exit_reporting(fail(0xfe, 0))
}

/// The whole program.
fn run(arg: u64) -> u64 {
    if let Err(code) = bind() {
        return code;
    }
    let info = match device_layout() {
        Ok(info) => info,
        Err(code) => return code,
    };
    let base = match map_device(MMIO_VA) {
        Ok(base) => base,
        Err(code) => return code,
    };
    let common = Window {
        base: (base + u64::from(info.common_offset)) as usize,
    };
    let notify = Window {
        base: (base + u64::from(info.notify_offset)) as usize,
    };
    let isr = Window {
        base: (base + u64::from(info.isr_offset)) as usize,
    };
    let device_cfg = Window {
        base: (base + u64::from(info.device_config_offset)) as usize,
    };
    let transport = PciTransport::new(
        &common,
        &notify,
        info.notify_multiplier,
        Some(&isr),
        Some(&device_cfg),
        crypto::DEVICE_ID,
    );
    if transport
        .probe(crypto::DEVICE_ID, tessera_virtio::Error::NotCryptoDevice)
        .is_err()
    {
        return fail(0xcb, 0);
    }

    let mut pages = Pages { next: 0 };
    let layout = Layout::for_size(QUEUE_SIZE);
    if layout.total > PAGE as usize {
        return fail(0xcb, 1);
    }
    transport.begin();
    let low = transport.device_features_low();
    // The device's own revision bit as well as the transport's modern bit: a
    // device offering `REVISION_1` and a driver that did not take it would
    // disagree about the shape of every structure below.
    if transport
        .negotiate(low & crypto::FEATURE_REVISION_1, 1)
        .is_err()
    {
        return fail(0xcb, 2);
    }
    let state = match transport.set_features_ok() {
        Ok(state) => state,
        Err(_) => return fail(0xcb, 3),
    };
    let config = match crypto::Config::read(&transport) {
        Ok(config) => config,
        Err(_) => return fail(0xcb, 4),
    };

    // The data queue and the control queue, in that order — which is the order
    // the device numbers them, not the order a driver would guess.
    let mut rings = [const { None }; 2];
    for (slot, index) in [
        (0usize, u32::from(crypto::DATA_QUEUE)),
        (1usize, u32::from(config.control_queue())),
    ] {
        let page = match pages.take() {
            Ok(page) => page,
            Err(code) => return code,
        };
        with_page(&page, |memory| {
            for byte in memory.iter_mut() {
                *byte = 0;
            }
        });
        if transport
            .configure_queue(
                index,
                QUEUE_SIZE,
                page.device_address + layout.desc_offset as u64,
                page.device_address + layout.avail_offset as u64,
                page.device_address + layout.used_offset as u64,
            )
            .is_err()
        {
            return fail(0xcb, 5);
        }
        rings[slot] = Some(Ring {
            page,
            layout,
            next_desc: 0,
            avail_index: 0,
            used_index: 0,
        });
    }
    if transport.driver_ok(state).is_err() {
        return fail(0xcb, 6);
    }

    let page = match pages.take() {
        Ok(page) => page,
        Err(code) => return code,
    };
    let (Some(data), Some(control)) = (rings[0].take(), rings[1].take()) else {
        return fail(0xcb, 7);
    };
    let mut driver = Driver {
        control,
        data,
        page,
        config,
        sessions: [SessionSlot {
            live: false,
            session: crypto::Session {
                id: 0,
                algorithm: crypto::Algorithm::AesCbc,
                direction: crypto::Direction::Encrypt,
            },
            named: CryptoAlgorithm::None,
            iv: [0u8; 16],
            iv_len: 0,
        }; MAX_SESSIONS],
        power: CryptoPowerState::Active,
    };
    if offered(&driver.config) == 0 {
        return fail(0xcb, 8);
    }

    let mut msg_buf = [0u8; MSG_BUF_LEN];
    let mut failure = 0u64;
    // The receive, the reply-and-loop-back, and the volatile read of what the
    // kernel wrote are the SDK's; what a crypto request means is this driver's.
    let served = tessera_sdk::serve(
        &mut Machine,
        Endpoint(SdkHandle(CLIENT_ENDPOINT_HANDLE)),
        &mut msg_buf,
        |method, bytes, out| {
            // Taken the request, and now it will never answer it. The caller is
            // parked at this moment, which is the whole point of crashing here.
            if arg & CRASH_BEFORE_REPLYING != 0 {
                crash();
            }
            let request = CryptoServiceIncoming::decode(method, &mut Reader::in_message(bytes, 0));
            let mut reply = [0u8; MSG_BUF_LEN];
            match serve(&mut driver, &transport, method, request, &mut reply) {
                Ok(len) if len <= out.len() => {
                    out[..len].copy_from_slice(&reply[..len]);
                    Ok(len)
                }
                Ok(_) => Err(SdkError::TooLarge),
                Err(code) => {
                    // The SDK's errors are the platform's; a class failure is
                    // this driver's, so it is carried out rather than folded
                    // into one of them.
                    failure = code;
                    Err(SdkError::NotBound)
                }
            }
        },
    );
    if failure != 0 {
        return failure;
    }
    match served {
        // A client that has said everything it is going to say. Nothing else
        // ends this loop, so reaching here at all is worth reporting.
        Ok(()) => fail(0xcc, 11),
        Err(error) => fail(0xcc, platform_code(error)),
    }
}

/// Turns a platform error back into a number this driver's boot check reads.
fn platform_code(error: SdkError) -> u64 {
    match error {
        SdkError::PeerGone => 11,
        SdkError::Refused => 8,
        SdkError::TooLarge => 10,
        SdkError::NotBound => 1,
        SdkError::Kernel(code) => code as u64,
    }
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    Machine.finish(value)
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    exit_reporting(run(arg))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
