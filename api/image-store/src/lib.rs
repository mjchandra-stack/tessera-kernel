// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! **The verified image store**: a read-only container the system delivers data
//! it has to *trust* through, and the reader that refuses one it cannot vouch
//! for.
//!
//! Everything this tree has read so far was compiled into the kernel. The
//! binding manifest is a Rust `static` (D130, restated by D143), the ring-3
//! programs are byte arrays a genrule embedded, and the kernel trusts all of
//! them because it cannot tell them from its own `.rodata`. `docs/security/01`
//! ("Boot Security") requires a *verified initial system image* and
//! `docs/security/02` ("Anti-Rollback") requires firmware to carry a
//! monotonically increasing security version number; neither had a mechanism.
//! This is it, and its first consumer is firmware loading.
//!
//! # What "verified" means here, stated plainly
//!
//! **Measurement against a trust anchor, and no asymmetric cryptography
//! anywhere in this tree.** `docs/security/02` ("Trust Anchors And Signing
//! Infrastructure") defines trust anchors as *"the public keys **and
//! measurements** that verifiers treat as authoritative"* — so a measurement
//! anchor is one of the two kinds it names, not a placeholder for the other.
//! What it cannot do is distinguish *who* produced a container: a verifier
//! holding a digest can tell that these are the bytes it was told to expect, and
//! cannot tell that they came from anybody in particular. A public-key anchor
//! is what says that, and it arrives behind [`DigestAlgorithm`] and
//! `anchor_id` without a format change — which is the whole reason those fields
//! exist in a format with one algorithm and one anchor.
//!
//! # The structure
//!
//! A hash tree two deep: each entry carries the digest of its blob, and the
//! anchor is the digest of the header and directory together. One 32-byte
//! constant in the verifier therefore authenticates a container of any size.
//!
//! [`Store::mount`] verifies the directory once. [`Store::open`] measures the
//! blob it returns, **every time**, and that split is deliberate: a container
//! proved intact at boot and read from for the rest of the boot is a container
//! trusted for what it was, and nothing here is willing to say when "was"
//! ended. Measuring on read costs a pass over one blob and makes the guarantee
//! contemporaneous with the use.
//!
//! # Where this runs
//!
//! `no_std`, `forbid(unsafe_code)`, no allocator: the host tool that writes a
//! container and the kernel that reads one are the same code, so a container
//! that builds is a container that mounts. Every length in the format is
//! `u64` and every conversion to `usize` is checked, because this crate is
//! built for 32-bit targets too (`//kernel/width-conformance`).
//!
//! Normative: docs/security/01-security-model.md ("Boot Security"),
//! docs/security/02-cryptography-and-key-management.md ("Crypto Agility",
//! "Anti-Rollback"), docs/api/03-interface-schema-language.md ("Wire Format")

#![no_std]
#![forbid(unsafe_code)]

/// The ISL-generated format structs, from whichever build produced them.
///
/// Bazel links the `//api/isl:image_store_bindings` genrule crate; the cargo
/// inner loop generates the same source into `OUT_DIR` from `build.rs` and
/// includes it here (D24 — the cargo loop depends on no Bazel output). The
/// `isl_bazel` cfg is what Bazel sets and cargo does not.
#[allow(dead_code, unused_imports, non_upper_case_globals, clippy::all)]
mod abi {
    #[cfg(not(isl_bazel))]
    include!(concat!(env!("OUT_DIR"), "/image_store.rs"));
    #[cfg(isl_bazel)]
    pub use image_store_abi::*;
}

pub use abi::{DigestAlgorithm, StoreEntry, StoreHeader};
use tessera_hash::{Digest, Sha256};
use tessera_isl_runtime::{WireError, decode, encode};

/// "TESSTORE", little-endian: the bytes `T E S S T O R E` in order.
pub const MAGIC: u64 = 0x4552_4f54_5353_4554;
/// The container format version this crate writes and accepts.
///
/// Version 2 added `image_version` to every entry. There is no version-1 reader
/// here and deliberately so: a container this crate does not understand is
/// refused, never read for the fields whose names it recognizes, because the
/// fields it recognizes may be exactly what changed.
pub const FORMAT_VERSION: u32 = 2;
/// The fixed width of an entry's name field, in bytes.
pub const MAX_NAME: usize = 24;

const HEADER_SIZE: usize = StoreHeader::WIRE_SIZE;
const ENTRY_SIZE: usize = StoreEntry::WIRE_SIZE;

/// Why a container was refused.
///
/// A stable-domain value rather than a message: `docs/lifecycle/04` forbids
/// errors that have to be parsed, and every one of these has a different fix.
/// `UnsupportedFormat` is a system that needs updating, `UntrustedAnchor` is a
/// container that was not built for this system, and `DigestMismatch` is one
/// whose bytes changed after it was built — three situations that a single
/// "invalid store" would leave indistinguishable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum StoreError {
    /// The region does not begin with a store at all.
    BadMagic = 1,
    /// A container version or header size this reader does not implement.
    UnsupportedFormat = 2,
    /// A measurement algorithm this reader does not implement — or none named.
    UnsupportedAlgorithm = 3,
    /// The region is smaller than the container says it is.
    Truncated = 4,
    /// The container is self-inconsistent: a directory outside it, an entry
    /// reaching past its end, entries out of order, a name that is not a name.
    Malformed = 5,
    /// The directory does not measure to the anchor expected for its
    /// `anchor_id` — or this verifier holds no anchor under that id.
    UntrustedAnchor = 6,
    /// No entry has that name.
    NotFound = 7,
    /// A blob does not measure to the digest its entry carries.
    DigestMismatch = 8,
}

/// A trust anchor: an identifier and the measurement it authorizes.
///
/// Anchors are looked up **by id** rather than tried in turn. Trust anchors are
/// versioned and revocable (`docs/security/02`), and a verifier that accepted a
/// container because *some* anchor it held matched would make revoking one of
/// them mean nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub id: u32,
    pub digest: Digest,
}

/// One blob's metadata, as the directory records it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    name: [u8; MAX_NAME],
    name_len: usize,
    /// Where the blob starts, from the beginning of the container.
    pub offset: u64,
    pub length: u64,
    /// The security version number `docs/security/02` ("Anti-Rollback")
    /// requires. Carried, never enforced here: the minimum acceptable version
    /// belongs to whoever holds the rollback floor, and a file format that
    /// decided it would be deciding policy.
    pub svn: u32,
    /// What the artifact is, as its producer numbers it — the question a
    /// driver's constraint asks, and not the one the rollback floor asks.
    pub image_version: u32,
    pub flags: u64,
    /// The blob's expected measurement.
    pub digest: Digest,
}

impl Entry {
    /// The entry's name, without its padding.
    pub fn name(&self) -> &str {
        // Validated printable ASCII at mount, so this cannot fail — and the
        // empty fallback is unreachable rather than a degradation: an entry
        // with no name never leaves `read_entry`, so nothing can ask this and
        // be answered with one.
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or_default()
    }
}

/// A measured blob: bytes that matched the digest the directory recorded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blob<'a> {
    pub bytes: &'a [u8],
    pub svn: u32,
    pub image_version: u32,
    pub flags: u64,
    /// What it measured to — equal to the entry's digest by construction, and
    /// returned so a caller can record *what* it accepted rather than only
    /// that it accepted something. Firmware provenance is this value.
    pub digest: Digest,
}

/// A mounted container.
#[derive(Clone, Copy)]
pub struct Store<'a> {
    bytes: &'a [u8],
    header: StoreHeader,
    /// The measurement of header+directory that mounting computed.
    anchor: Digest,
}

impl<'a> Store<'a> {
    /// Verifies the container in `region` against `anchors` and returns a
    /// handle to it.
    ///
    /// Structure is checked before the measurement and the measurement before
    /// anything is handed out. Nothing is trusted for being listed: the
    /// directory is authentic after this, and each blob is measured when it is
    /// read.
    pub fn mount(region: &'a [u8], anchors: &[Anchor]) -> Result<Self, StoreError> {
        let (header, directory_end) = parse(region)?;
        let anchor = measure_directory(region, directory_end);
        let trusted = anchors
            .iter()
            .find(|candidate| candidate.id == header.anchor_id)
            .ok_or(StoreError::UntrustedAnchor)?;
        if trusted.digest != anchor {
            return Err(StoreError::UntrustedAnchor);
        }
        let total = as_usize(header.total_length)?;
        Ok(Store {
            bytes: &region[..total],
            header,
            anchor,
        })
    }

    /// What this container's header and directory measured to.
    pub fn anchor(&self) -> Digest {
        self.anchor
    }

    /// The anchor id the container named.
    pub fn anchor_id(&self) -> u32 {
        self.header.anchor_id
    }

    /// The measurement algorithm the container named.
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.header.algorithm
    }

    /// How many blobs the container holds.
    pub fn len(&self) -> usize {
        self.header.entry_count as usize
    }

    /// Whether the container holds no blobs. A legal container, and not an
    /// error: a system with nothing installed still has a store.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `index`th directory entry.
    pub fn entry(&self, index: usize) -> Result<Entry, StoreError> {
        if index >= self.len() {
            return Err(StoreError::NotFound);
        }
        let start = as_usize(self.header.directory_offset)? + index * ENTRY_SIZE;
        read_entry(self.bytes, start)
    }

    /// The entry named `name`.
    pub fn find(&self, name: &str) -> Result<Entry, StoreError> {
        for index in 0..self.len() {
            let entry = self.entry(index)?;
            if entry.name() == name {
                return Ok(entry);
            }
        }
        Err(StoreError::NotFound)
    }

    /// The blob named `name`, **measured**.
    ///
    /// The digest check is the whole point of the call. A caller that wanted
    /// the bytes without it would be reading a file, and this container exists
    /// because reading a file was not enough.
    pub fn open(&self, name: &str) -> Result<Blob<'a>, StoreError> {
        let entry = self.find(name)?;
        let start = as_usize(entry.offset)?;
        let len = as_usize(entry.length)?;
        let end = start.checked_add(len).ok_or(StoreError::Malformed)?;
        let bytes = self.bytes.get(start..end).ok_or(StoreError::Malformed)?;
        let digest = tessera_hash::sha256(bytes);
        if digest != entry.digest {
            return Err(StoreError::DigestMismatch);
        }
        Ok(Blob {
            bytes,
            svn: entry.svn,
            image_version: entry.image_version,
            flags: entry.flags,
            digest,
        })
    }
}

/// The anchor a container *would* need, without checking it against anything.
///
/// This is what a build tool prints and a human pastes into the verifier. It
/// validates structure exactly as [`Store::mount`] does — a measurement of a
/// container nobody could mount would be a number that means nothing.
pub fn measure(region: &[u8]) -> Result<Digest, StoreError> {
    let (_, directory_end) = parse(region)?;
    Ok(measure_directory(region, directory_end))
}

/// Validates the header and every directory entry, returning the header and the
/// offset one past the directory.
fn parse(region: &[u8]) -> Result<(StoreHeader, usize), StoreError> {
    let head = region.get(..HEADER_SIZE).ok_or(StoreError::Truncated)?;
    // The magic is read from its fixed offset *before* any length is believed:
    // a reader that parsed a length out of arbitrary bytes and then decided
    // whether it was looking at a store would have trusted the bytes first.
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&head[16..24]);
    if u64::from_le_bytes(magic) != MAGIC {
        return Err(StoreError::BadMagic);
    }
    let header = decode::<StoreHeader>(head).map_err(|err| match err {
        // The only enum in the header is the measurement algorithm, so a value
        // outside the schema is a container naming one this reader does not
        // implement — which `docs/security/02` requires be a refusal and not a
        // fall back to the algorithm that happens to exist.
        WireError::BadEnum => StoreError::UnsupportedAlgorithm,
        _ => StoreError::Malformed,
    })?;
    if header.size as usize != HEADER_SIZE || header.version != FORMAT_VERSION {
        return Err(StoreError::UnsupportedFormat);
    }
    if header.algorithm != DigestAlgorithm::Sha256 {
        return Err(StoreError::UnsupportedAlgorithm);
    }
    if header.reserved != 0 {
        return Err(StoreError::Malformed);
    }

    let total = as_usize(header.total_length)?;
    if total > region.len() || total < HEADER_SIZE {
        return Err(StoreError::Truncated);
    }
    let directory = as_usize(header.directory_offset)?;
    if directory < HEADER_SIZE {
        return Err(StoreError::Malformed);
    }
    let span = (header.entry_count as usize)
        .checked_mul(ENTRY_SIZE)
        .ok_or(StoreError::Malformed)?;
    let directory_end = directory.checked_add(span).ok_or(StoreError::Malformed)?;
    if directory_end > total {
        return Err(StoreError::Malformed);
    }

    // Every entry is checked now rather than on the way out, so that reaching
    // an entry cannot fail in a way a caller has to handle twice — and so that
    // a container built wrong is refused whole instead of one blob at a time.
    let mut previous: Option<[u8; MAX_NAME]> = None;
    for index in 0..header.entry_count as usize {
        let entry = read_entry(region, directory + index * ENTRY_SIZE)?;
        let start = as_usize(entry.offset)?;
        let len = as_usize(entry.length)?;
        let end = start.checked_add(len).ok_or(StoreError::Malformed)?;
        if start < directory_end || end > total {
            return Err(StoreError::Malformed);
        }
        // Strictly ascending, which rejects duplicates: two blobs with one
        // name would make "the blob called x" a question with two answers, and
        // whichever a reader picked would be an accident of its search order.
        if let Some(previous) = previous
            && previous >= entry.name
        {
            return Err(StoreError::Malformed);
        }
        previous = Some(entry.name);
    }

    Ok((header, directory_end))
}

/// The measurement over the header and directory — the anchor.
fn measure_directory(region: &[u8], directory_end: usize) -> Digest {
    let mut hash = Sha256::new();
    hash.update(&region[..directory_end]);
    hash.finish()
}

/// Decodes and validates one directory entry at `start`.
fn read_entry(region: &[u8], start: usize) -> Result<Entry, StoreError> {
    let end = start.checked_add(ENTRY_SIZE).ok_or(StoreError::Malformed)?;
    let bytes = region.get(start..end).ok_or(StoreError::Malformed)?;
    let raw = decode::<StoreEntry>(bytes).map_err(|_| StoreError::Malformed)?;
    if raw.size as usize != ENTRY_SIZE || raw.version != FORMAT_VERSION {
        return Err(StoreError::UnsupportedFormat);
    }
    // Reserved means reserved: a value here is either a writer this reader does
    // not understand or a field somebody is smuggling something through.
    if raw.reserved != 0 {
        return Err(StoreError::Malformed);
    }
    let name_len = name_length(&raw.name)?;
    Ok(Entry {
        name: raw.name,
        name_len,
        offset: raw.offset,
        length: raw.length,
        svn: raw.svn,
        image_version: raw.image_version,
        flags: raw.flags,
        digest: raw.digest,
    })
}

/// The length of a NUL-padded name, refusing anything that is not one.
///
/// Names are printable ASCII and the padding is all NUL. Both halves matter:
/// interior NULs would let two entries carry names that compare differently
/// here and identically to a C consumer, and non-printable bytes would let a
/// name that cannot be typed be the only way to ask for a blob.
fn name_length(name: &[u8; MAX_NAME]) -> Result<usize, StoreError> {
    let len = name.iter().position(|byte| *byte == 0).unwrap_or(MAX_NAME);
    if len == 0 {
        return Err(StoreError::Malformed);
    }
    if name[..len].iter().any(|byte| !byte.is_ascii_graphic()) {
        return Err(StoreError::Malformed);
    }
    if name[len..].iter().any(|byte| *byte != 0) {
        return Err(StoreError::Malformed);
    }
    Ok(len)
}

/// A container offset as a `usize`, refusing one this target cannot address.
///
/// On a 32-bit port an offset past 4 GiB names a place no region reaches, which
/// is the same thing as the region being too small — so it is `Truncated` and
/// not a separate error nobody could act on differently.
fn as_usize(value: u64) -> Result<usize, StoreError> {
    usize::try_from(value).map_err(|_| StoreError::Truncated)
}

/// What a builder is asked to store.
#[derive(Clone, Copy)]
pub struct BuildEntry<'a> {
    pub name: &'a str,
    pub svn: u32,
    pub image_version: u32,
    pub flags: u64,
    pub bytes: &'a [u8],
}

/// Why a container could not be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum BuildError {
    /// A name longer than [`MAX_NAME`], or not printable ASCII, or empty.
    BadName = 1,
    /// Entries were not in strictly ascending name order.
    Unsorted = 2,
    /// The output buffer is too small for the container.
    BufferTooSmall = 3,
    /// The container would be larger than this target can address.
    TooLarge = 4,
}

/// The exact size [`build_into`] needs for `entries`.
pub fn built_size(entries: &[BuildEntry<'_>]) -> Option<usize> {
    let mut total = HEADER_SIZE.checked_add(entries.len().checked_mul(ENTRY_SIZE)?)?;
    for entry in entries {
        total = total.checked_add(entry.bytes.len())?;
    }
    Some(total)
}

/// Writes a container into `out` and returns its length.
///
/// `entries` must be in strictly ascending name order. The builder refuses
/// rather than sorting, because it has no allocator to sort with and because a
/// caller that did not know its own ordering would not know what it had built.
///
/// The output is a pure function of the inputs — no timestamps, no padding
/// left uninitialized — so the same inputs produce the same container and
/// therefore the same anchor. A build tool that varied would make the anchor
/// meaningless the first time somebody rebuilt.
pub fn build_into(
    out: &mut [u8],
    anchor_id: u32,
    entries: &[BuildEntry<'_>],
) -> Result<usize, BuildError> {
    let total = built_size(entries).ok_or(BuildError::TooLarge)?;
    if out.len() < total {
        return Err(BuildError::BufferTooSmall);
    }
    let out = &mut out[..total];
    out.fill(0);

    let directory_offset = HEADER_SIZE;
    let mut contents = directory_offset + entries.len() * ENTRY_SIZE;
    let mut previous: Option<[u8; MAX_NAME]> = None;

    for (index, entry) in entries.iter().enumerate() {
        let name = fixed_name(entry.name)?;
        if let Some(previous) = previous
            && previous >= name
        {
            return Err(BuildError::Unsorted);
        }
        previous = Some(name);

        let end = contents + entry.bytes.len();
        out[contents..end].copy_from_slice(entry.bytes);
        let record = StoreEntry {
            size: ENTRY_SIZE as u32,
            version: FORMAT_VERSION,
            flags: entry.flags,
            offset: contents as u64,
            length: entry.bytes.len() as u64,
            name,
            svn: entry.svn,
            image_version: entry.image_version,
            reserved: 0,
            digest: tessera_hash::sha256(entry.bytes),
        };
        let at = directory_offset + index * ENTRY_SIZE;
        encode(&record, &mut out[at..at + ENTRY_SIZE]).map_err(|_| BuildError::BufferTooSmall)?;
        contents = end;
    }

    let header = StoreHeader {
        size: HEADER_SIZE as u32,
        version: FORMAT_VERSION,
        flags: 0,
        magic: MAGIC,
        algorithm: DigestAlgorithm::Sha256,
        anchor_id,
        entry_count: entries.len() as u32,
        reserved: 0,
        directory_offset: directory_offset as u64,
        total_length: total as u64,
    };
    encode(&header, &mut out[..HEADER_SIZE]).map_err(|_| BuildError::BufferTooSmall)?;
    Ok(total)
}

/// A name as its fixed-width, NUL-padded field.
fn fixed_name(name: &str) -> Result<[u8; MAX_NAME], BuildError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME || !bytes.iter().all(u8::is_ascii_graphic) {
        return Err(BuildError::BadName);
    }
    let mut field = [0u8; MAX_NAME];
    field[..bytes.len()].copy_from_slice(bytes);
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR_ID: u32 = 7;

    fn sample() -> [BuildEntry<'static>; 2] {
        [
            BuildEntry {
                name: "firmware.bin",
                svn: 3,
                image_version: 2,
                flags: 0,
                bytes: b"the firmware image, such as it is",
            },
            BuildEntry {
                name: "manifest.dat",
                svn: 1,
                image_version: 5,
                flags: 0x21,
                bytes: b"entries",
            },
        ]
    }

    fn built() -> ([u8; 512], usize) {
        let mut buffer = [0u8; 512];
        let len = build_into(&mut buffer, ANCHOR_ID, &sample()).expect("build");
        (buffer, len)
    }

    fn anchors(container: &[u8]) -> [Anchor; 1] {
        [Anchor {
            id: ANCHOR_ID,
            digest: measure(container).expect("measure"),
        }]
    }

    #[test]
    fn round_trip() {
        let (buffer, len) = built();
        let container = &buffer[..len];
        let store = Store::mount(container, &anchors(container)).expect("mount");

        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert_eq!(store.anchor_id(), ANCHOR_ID);
        assert_eq!(store.algorithm(), DigestAlgorithm::Sha256);

        let firmware = store.open("firmware.bin").expect("open");
        assert_eq!(firmware.bytes, b"the firmware image, such as it is");
        assert_eq!(firmware.svn, 3);
        assert_eq!(firmware.digest, tessera_hash::sha256(firmware.bytes));

        let manifest = store.open("manifest.dat").expect("open");
        assert_eq!(manifest.bytes, b"entries");
        assert_eq!(manifest.svn, 1);
        assert_eq!(manifest.flags, 0x21);

        assert_eq!(store.entry(0).expect("entry").name(), "firmware.bin");
        assert_eq!(store.entry(1).expect("entry").name(), "manifest.dat");
        assert_eq!(store.entry(2), Err(StoreError::NotFound));
        assert_eq!(store.open("absent"), Err(StoreError::NotFound));
    }

    /// A container is a pure function of its inputs, which is what makes a
    /// checked-in anchor maintainable at all.
    #[test]
    fn build_is_deterministic() {
        let (first, first_len) = built();
        let (second, second_len) = built();
        assert_eq!(first_len, second_len);
        assert_eq!(first[..first_len], second[..second_len]);
    }

    /// The empty container: legal, mountable, and holding nothing.
    #[test]
    fn empty_container_mounts() {
        let mut buffer = [0u8; 128];
        let len = build_into(&mut buffer, ANCHOR_ID, &[]).expect("build");
        let container = &buffer[..len];
        let store = Store::mount(container, &anchors(container)).expect("mount");
        assert!(store.is_empty());
        assert_eq!(store.open("anything"), Err(StoreError::NotFound));
    }

    /// **A byte flipped in a blob is caught when the blob is read, not when the
    /// container is mounted** — the anchor covers the directory, and the
    /// directory's digest of that blob is what fails.
    #[test]
    fn tampered_blob_mounts_but_will_not_open() {
        let (mut buffer, len) = built();
        let flip = len - 1;
        buffer[flip] ^= 0x01;
        let container = &buffer[..len];
        // Anchors computed over the *tampered* container, so this is not the
        // anchor check passing by accident of the tamper being outside it.
        let store = Store::mount(container, &anchors(container)).expect("mount");
        assert_eq!(store.open("manifest.dat"), Err(StoreError::DigestMismatch));
        // The blob nobody touched still opens: the failure is scoped to what
        // changed, rather than a container that fails as a whole.
        assert!(store.open("firmware.bin").is_ok());
    }

    /// A byte flipped in the directory changes the anchor, so the container
    /// does not mount at all.
    #[test]
    fn tampered_directory_will_not_mount() {
        let (buffer, len) = built();
        let trusted = anchors(&buffer[..len]);
        let mut tampered = buffer;
        // The svn field of the first entry: a change with a motive.
        tampered[HEADER_SIZE + 56] ^= 0x04;
        assert_eq!(
            Store::mount(&tampered[..len], &trusted).err(),
            Some(StoreError::UntrustedAnchor)
        );
    }

    /// The same for the header, whose fields the anchor also covers.
    #[test]
    fn tampered_header_will_not_mount() {
        let (buffer, len) = built();
        let trusted = anchors(&buffer[..len]);
        let mut tampered = buffer;
        // `flags`, which nothing reads — so the mount still finds the anchor
        // by its id and fails on the measurement, rather than failing because
        // the id no longer names an anchor this verifier holds.
        tampered[8] ^= 0x01;
        assert_eq!(
            Store::mount(&tampered[..len], &trusted).err(),
            Some(StoreError::UntrustedAnchor)
        );
    }

    /// An anchor this verifier does not hold is refused even when the container
    /// measures correctly — an anchor is selected by id, never by matching.
    #[test]
    fn unknown_anchor_id_is_refused() {
        let (buffer, len) = built();
        let container = &buffer[..len];
        let wrong = [Anchor {
            id: ANCHOR_ID + 1,
            digest: measure(container).expect("measure"),
        }];
        assert_eq!(
            Store::mount(container, &wrong).err(),
            Some(StoreError::UntrustedAnchor)
        );
        assert_eq!(
            Store::mount(container, &[]).err(),
            Some(StoreError::UntrustedAnchor)
        );
    }

    #[test]
    fn not_a_store_at_all() {
        let noise = [0xa5u8; 256];
        assert_eq!(measure(&noise), Err(StoreError::BadMagic));
        assert_eq!(measure(&[]), Err(StoreError::Truncated));
        assert_eq!(measure(&[0u8; 40]), Err(StoreError::Truncated));
    }

    /// A container cut short is refused, and refused as *truncated* rather than
    /// as anything about its contents.
    #[test]
    fn truncated_region_is_refused() {
        let (buffer, len) = built();
        for cut in [HEADER_SIZE, HEADER_SIZE + ENTRY_SIZE, len - 1] {
            assert_eq!(measure(&buffer[..cut]), Err(StoreError::Truncated), "{cut}");
        }
    }

    /// **Both directions, and the backward one is the interesting one.** A
    /// version from the future is obviously refused; version 1 — the format
    /// D146 shipped, before entries carried `image_version` — is refused too,
    /// rather than read for the fields whose names this reader still
    /// recognizes. Every one of them sits at the same offset it did, which is
    /// exactly what would make reading them look like it worked.
    #[test]
    fn unsupported_version_and_algorithm() {
        for version in [1u8, 3] {
            let (mut buffer, len) = built();
            buffer[4] = version;
            assert_eq!(
                measure(&buffer[..len]),
                Err(StoreError::UnsupportedFormat),
                "version {version}"
            );
        }

        let (mut buffer, len) = built();
        buffer[24] = 0; // algorithm = Unspecified, which decode refuses outright
        assert_eq!(
            measure(&buffer[..len]),
            Err(StoreError::UnsupportedAlgorithm)
        );
    }

    /// An entry reaching past the end of the container is malformed — the check
    /// that stops a directory from describing memory the container does not own.
    #[test]
    fn entry_out_of_range_is_malformed() {
        let (mut buffer, len) = built();
        // The first entry's length field, at directory + 24.
        buffer[HEADER_SIZE + 24] = 0xff;
        assert_eq!(measure(&buffer[..len]), Err(StoreError::Malformed));
    }

    /// A blob starting inside the directory is malformed too: it would be
    /// measured as content and as directory at once.
    #[test]
    fn entry_overlapping_directory_is_malformed() {
        let (mut buffer, len) = built();
        buffer[HEADER_SIZE + 16] = 0x00; // first entry's offset -> 0
        assert_eq!(measure(&buffer[..len]), Err(StoreError::Malformed));
    }

    #[test]
    fn builder_refuses_bad_names_and_disorder() {
        let mut buffer = [0u8; 512];
        let long = "a-name-far-too-long-for-the-field";
        assert_eq!(
            build_into(
                &mut buffer,
                ANCHOR_ID,
                &[BuildEntry {
                    name: long,
                    svn: 0,
                    image_version: 0,
                    flags: 0,
                    bytes: b"x"
                }]
            ),
            Err(BuildError::BadName)
        );
        assert_eq!(
            build_into(
                &mut buffer,
                ANCHOR_ID,
                &[BuildEntry {
                    name: "",
                    svn: 0,
                    image_version: 0,
                    flags: 0,
                    bytes: b"x"
                }]
            ),
            Err(BuildError::BadName)
        );
        assert_eq!(
            build_into(
                &mut buffer,
                ANCHOR_ID,
                &[BuildEntry {
                    name: "has space",
                    svn: 0,
                    image_version: 0,
                    flags: 0,
                    bytes: b"x"
                }]
            ),
            Err(BuildError::BadName)
        );

        let mut backwards = sample();
        backwards.swap(0, 1);
        assert_eq!(
            build_into(&mut buffer, ANCHOR_ID, &backwards),
            Err(BuildError::Unsorted)
        );

        let duplicate = [sample()[0], sample()[0]];
        assert_eq!(
            build_into(&mut buffer, ANCHOR_ID, &duplicate),
            Err(BuildError::Unsorted)
        );
    }

    #[test]
    fn builder_refuses_a_buffer_that_does_not_fit() {
        let entries = sample();
        let needed = built_size(&entries).expect("size");
        let mut exact = [0u8; 512];
        assert_eq!(
            build_into(&mut exact[..needed - 1], ANCHOR_ID, &entries),
            Err(BuildError::BufferTooSmall)
        );
        assert_eq!(
            build_into(&mut exact[..needed], ANCHOR_ID, &entries),
            Ok(needed)
        );
    }
}
