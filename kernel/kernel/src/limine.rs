// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Hand-written Limine boot protocol requests — the subset this kernel
//! uses (base revision, HHDM, memory map). Constants transcribed from the
//! Limine protocol specification, v12.4.2 era, base revision 3:
//! <https://github.com/Limine-Bootloader/limine-protocol> — the vendored
//! bootloader in `third_party/limine/` is the matching implementation.
//!
//! The bootloader writes response pointers into these statics before
//! `_start` runs, so every bootloader-written field is an atomic (which
//! also keeps the sections writable). Only this module and `main.rs` know
//! Limine exists; everything downstream sees `tessera_karch::BootInfo`.
//!
//! Normative: docs/hardware/01-platform-and-cpu-support.md ("Platform
//! Support Packages")
//! Budget: none (boot path)

use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use tessera_karch::{MemoryKind, MemoryRegion, PhysAddr};

const COMMON_MAGIC: [u64; 2] = [0xc7b1dd30df4c8b88, 0x0a82e883a194f07b];

/// The base revision of the protocol this kernel is written against.
const REQUESTED_BASE_REVISION: u64 = 3;

// Request-region delimiters: the bootloader only honors requests between
// the start and end markers.
#[used]
// SAFETY: placing this static in the Limine requests region is exactly
// the protocol contract; the section is scanned, not executed.
#[unsafe(link_section = ".limine_requests_start")]
static REQUESTS_START_MARKER: [u64; 4] = [
    0xf6b8f4b39de7d1ae,
    0xfab91a6940fcb9cf,
    0x785c6ed015d3e316,
    0x181e920a7852b9d9,
];

#[used]
// SAFETY: placing this static in the Limine requests region is exactly
// the protocol contract; the section is scanned, not executed.
#[unsafe(link_section = ".limine_requests_end")]
static REQUESTS_END_MARKER: [u64; 2] = [0xadc0e0531bb10d03, 0x9572709f31764c62];

#[repr(C)]
pub struct BaseRevisionTag {
    magic: [u64; 2],
    /// Set to 0 by the bootloader iff the requested revision is supported.
    revision: AtomicU64,
}

#[used]
// SAFETY: placing this static in the Limine requests region is exactly
// the protocol contract; the section is scanned, not executed.
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: BaseRevisionTag = BaseRevisionTag {
    magic: [0xf9562b2d5c95a6c8, 0x6a7b384944536bdc],
    revision: AtomicU64::new(REQUESTED_BASE_REVISION),
};

/// True iff the bootloader booted us at the revision we asked for.
pub fn base_revision_supported() -> bool {
    BASE_REVISION.revision.load(Ordering::Acquire) == 0
}

#[repr(C)]
pub struct HhdmRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<HhdmResponse>,
}

#[repr(C)]
pub struct HhdmResponse {
    revision: u64,
    pub offset: u64,
}

#[used]
// SAFETY: placing this static in the Limine requests region is exactly
// the protocol contract; the section is scanned, not executed.
#[unsafe(link_section = ".limine_requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest {
    id: [
        COMMON_MAGIC[0],
        COMMON_MAGIC[1],
        0x48dcf1cb8ad2b852,
        0x63984e959a98244b,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

/// The HHDM offset, if the bootloader answered.
pub fn hhdm_offset() -> Option<u64> {
    let response = NonNull::new(HHDM_REQUEST.response.load(Ordering::Acquire))?;
    // SAFETY: a non-null response pointer is the bootloader's guarantee of
    // a valid, immutable response structure in bootloader-reclaimable
    // memory (which we have not reclaimed).
    Some(unsafe { response.as_ref() }.offset)
}

#[repr(C)]
pub struct ExecutableAddressRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<ExecutableAddressResponse>,
}

#[repr(C)]
pub struct ExecutableAddressResponse {
    revision: u64,
    pub physical_base: u64,
    pub virtual_base: u64,
}

#[used]
// SAFETY: placing this static in the Limine requests region is exactly
// the protocol contract; the section is scanned, not executed.
#[unsafe(link_section = ".limine_requests")]
static EXECUTABLE_ADDRESS_REQUEST: ExecutableAddressRequest = ExecutableAddressRequest {
    id: [
        COMMON_MAGIC[0],
        COMMON_MAGIC[1],
        0x71ba76863cc55f63,
        0xb2644a48c516a487,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

/// The kernel image's `(physical_base, virtual_base)`, if the bootloader
/// answered. `virtual_base` is the higher-half link address; a byte at
/// virtual `v` in the image lives at physical `physical_base + (v -
/// virtual_base)`.
pub fn executable_address() -> Option<(u64, u64)> {
    let response = NonNull::new(EXECUTABLE_ADDRESS_REQUEST.response.load(Ordering::Acquire))?;
    // SAFETY: a non-null response pointer is the bootloader's guarantee of a
    // valid, immutable response structure in memory we have not reclaimed.
    let r = unsafe { response.as_ref() };
    Some((r.physical_base, r.virtual_base))
}

#[repr(C)]
pub struct MemmapRequest {
    id: [u64; 4],
    revision: u64,
    response: AtomicPtr<MemmapResponse>,
}

#[repr(C)]
pub struct MemmapResponse {
    revision: u64,
    entry_count: u64,
    entries: *mut *mut MemmapEntry,
}

#[repr(C)]
pub struct MemmapEntry {
    base: u64,
    length: u64,
    kind: u64,
}

// Memory map entry types from the protocol specification.
const MEMMAP_USABLE: u64 = 0;
const MEMMAP_RESERVED: u64 = 1;
const MEMMAP_ACPI_RECLAIMABLE: u64 = 2;
const MEMMAP_ACPI_NVS: u64 = 3;
const MEMMAP_BAD_MEMORY: u64 = 4;
const MEMMAP_BOOTLOADER_RECLAIMABLE: u64 = 5;
const MEMMAP_EXECUTABLE_AND_MODULES: u64 = 6;
const MEMMAP_FRAMEBUFFER: u64 = 7;

#[used]
// SAFETY: placing this static in the Limine requests region is exactly
// the protocol contract; the section is scanned, not executed.
#[unsafe(link_section = ".limine_requests")]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest {
    id: [
        COMMON_MAGIC[0],
        COMMON_MAGIC[1],
        0x67cf3d9d378a806f,
        0xe304acdfc50c3c62,
    ],
    revision: 0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

/// Normalizes the bootloader memory map into `out`, returning the filled
/// prefix. Entries beyond `out.len()` are dropped **loudly** by the caller
/// via the `(filled, total)` pair — never silently.
pub fn normalize_memory_map(out: &mut [MemoryRegion]) -> Option<(usize, usize)> {
    let response = NonNull::new(MEMMAP_REQUEST.response.load(Ordering::Acquire))?;
    // SAFETY: non-null response ⇒ valid response struct per the protocol;
    // `entries` then points at `entry_count` valid entry pointers.
    let (count, entries) = unsafe {
        let r = response.as_ref();
        (r.entry_count as usize, r.entries)
    };
    let filled = count.min(out.len());
    for (i, slot) in out.iter_mut().enumerate().take(filled) {
        // SAFETY: `i < entry_count`, so both the pointer-array element and
        // the entry it points to are valid per the protocol.
        let entry = unsafe { &**entries.add(i) };
        *slot = MemoryRegion {
            base: PhysAddr::new(entry.base),
            len: entry.length,
            kind: match entry.kind {
                MEMMAP_USABLE => MemoryKind::Usable,
                MEMMAP_BOOTLOADER_RECLAIMABLE => MemoryKind::BootloaderReclaimable,
                MEMMAP_EXECUTABLE_AND_MODULES => MemoryKind::KernelAndModules,
                MEMMAP_FRAMEBUFFER => MemoryKind::Framebuffer,
                MEMMAP_ACPI_RECLAIMABLE => MemoryKind::AcpiReclaimable,
                MEMMAP_ACPI_NVS => MemoryKind::AcpiNvs,
                MEMMAP_BAD_MEMORY => MemoryKind::Bad,
                // RESERVED, RESERVED_MAPPED, and anything newer than this
                // kernel: never touched.
                MEMMAP_RESERVED | _ => MemoryKind::Reserved,
            },
        };
    }
    Some((filled, count))
}
