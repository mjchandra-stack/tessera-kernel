// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The Tessera **root task**: the first program the kernel starts, and the
//! last one it composes.
//!
//! It used to be 167 lines of `global_asm!` that created a child, copied a
//! twenty-instruction blob into it and started it. That proved the loader
//! syscalls worked and it could not grow — which is why this is Rust now, the
//! same step `blk-driver` took in D80 and for the same reason
//! (`docs/roadmap/03`, Phase 1).
//!
//! **What it does that the blob could not: it decides what its child holds.**
//!
//! 1. `ChannelCreate` — two endpoints, both handles its own. Nothing in this
//!    system could create a channel before; a process could only ever be handed
//!    one somebody else made for it (`build/README.md`, D45).
//! 2. `ProcessCreate` — an empty child under the job the kernel seeded it with.
//! 3. `AddressSpaceMap`, once per `PT_LOAD` — a real ELF walk over a real
//!    compiled program, not a blob copied to a fixed address. The program is
//!    linked into this one's `.rodata` today; Phase 2 changes where the bytes
//!    come from and nothing else here.
//! 4. `ProcessGrant` — one endpoint into the child, narrowed to `WRITE`. This
//!    is the step that has never existed: every service in this tree got its
//!    handles from kernel boot glue reaching into its table.
//! 5. `ProcessStart` — with the granted handle number as the child's startup
//!    argument, so the child is *told* where its capability is rather than
//!    assuming a number the kernel and it agreed on out of band.
//! 6. `ChannelRecv`, non-blocking — the child ran to completion inside the
//!    synchronous start, so its message is already queued. A blocking receive
//!    would be correct too and would hang the boot if the child never sent, so
//!    the bit is set: this program cannot stall a machine.
//!
//! **What it is not yet.** It starts one child, not the device manager; the
//! child's image is linked into it rather than read from a store; and the job
//! it creates under is one the kernel seeded. Those are Phase 1's remaining
//! steps and Phase 2.
//!
//! Reporting is one `DebugWrite` and the exit code. Every failure names its
//! step, because a root task that only says "failed" costs an afternoon.
//!
//! Normative: docs/api/01-system-call-interface.md ("Process And Thread"),
//! docs/lifecycle/03-boot-sequence-and-update-mechanics.md

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

// Two schemas, two `Rights` — each declares the catalog bits it needs and the
// generated types are distinct. Aliased rather than glob-imported so a reader
// can see which boundary each value crosses; the bit values are the same
// catalog and `//api/isl`'s own test holds them to it (D16).
use channel_msg::{
    ChannelCreateArgs, ChannelCreateRecord, ChannelMsgArgs, Rights as ChannelRights,
};
use device_abi::{DeviceIrqBindArgs, MapDeviceArgs};
use port_event::PortEventRecord;
use process_abi::{
    AddressSpaceMapArgs, ProcessCreateArgs, ProcessGrantArgs, ProcessStartArgs, ProcessWaitArgs,
    Rights as ProcessRights, StartupHandles,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{read_kernel_filled, syscall2, syscall3};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_PROCESS_CREATE: u64 = 8;
const SYS_ADDRESS_SPACE_MAP: u64 = 9;
const SYS_PROCESS_START: u64 = 10;
const SYS_CHANNEL_CREATE: u64 = 11;
const SYS_CHANNEL_RECV: u64 = 13;
const SYS_PROCESS_GRANT: u64 = 50;
const SYS_PROCESS_WAIT: u64 = 51;
const SYS_PORT_CREATE: u64 = 16;
const SYS_PORT_BIND: u64 = 17;
const SYS_PORT_WAIT: u64 = 18;
const SYS_HANDLE_QUERY_RIGHTS: u64 = 3;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DEVICE_IRQ_BIND: u64 = 52;

/// The job the kernel seeded this process with: the create-process authority,
/// and the one handle here that was not earned.
///
/// **The kernel seeds the root task and nothing else.** That is the whole rule
/// (`docs/roadmap/03`), and this constant is the seam it names — everything
/// below is derived from it or created by this program.
const SEEDED_JOB_HANDLE: u32 = 0;

/// The programs this task runs, linked in at build time.
///
/// `.rodata` is where a kernel keeps a program it has nowhere else to load from,
/// and this is the same compromise moved up one level: the root task has no
/// filesystem either, yet. What changes in Phase 2 is these two lines.
const GRANT_PROBE_ELF: &[u8] = &grant_probe_image::GRANT_PROBE_ELF;
const RESTART_PROBE_ELF: &[u8] = &restart_probe_image::RESTART_PROBE_ELF;

/// The bus capability boot seeds, when it seeds one.
///
/// **Handle 1, immediately after the job.** Two seeds rather than one, and the
/// second is what makes the driver framework composable from here: a manager
/// cannot enumerate devices it was never given, and this root task cannot hand
/// on what it does not hold. Everything else in the run is still made here.
const SEEDED_BUS_HANDLE: u32 = 1;

/// The device capability boot seeds, when this machine has one to seed.
///
/// **Handle 2, and the only seed that is a piece of hardware.** A job and a bus
/// are authority over making things; a device cannot be made, and no capability
/// system can conjure one that was not on the machine. So it is given, and what
/// this program does with it is the whole of step 13: map its registers, route
/// its interrupts to a port of its own, arm it, and be woken by it.
const SEEDED_DEVICE_HANDLE: u32 = 2;

/// What the manager is told at startup: how many capabilities follow the
/// endpoint.
///
/// **A number this program does not interpret**, and that is the point. A root
/// task that decided it would be deciding what the framework is for.
const DEVICE_MANAGER_ARG: u64 = 1;

/// The driver framework this **image** carries, linked in at build time — the
/// same compromise as the probes above, and Phase 2 removes all four together.
///
/// **`has_framework`, not `target_arch`.** Whether a build carries the manager
/// and the driver is composition rather than architecture: the programs are the
/// same source on every machine, and a build that leaves them out is a smaller
/// image and not a different port. The kernels key their own program lists the
/// same way (`has_components`).
#[cfg(has_framework)]
const DEVICE_MANAGER_ELF: &[u8] = &device_manager_image::DEVICE_MANAGER_ELF;
#[cfg(has_framework)]
const BLK_PROBE_ELF: &[u8] = &blk_probe_image::BLK_PROBE_ELF;

/// How many times the restart probe fails before coming up clean. It exits with
/// the countdown it is given, so forty means it fails with 40, 39, … 1 and then
/// succeeds with 0 — forty-one launches.
///
/// **Forty rather than three, and the number is the claim.** A process slot and
/// a scheduler thread slot are both capped at sixteen, so a seventeenth launch
/// fails `OutOfMemory` unless every exited instance's slots, kernel stack and
/// frames go back to their pools. Reaching a clean exit at launch forty-one is
/// not a supervision result, it is the reclaim proof.
const RESTART_COUNTDOWN: u64 = 40;

/// The most launches the supervisor will spend on the service that recovers.
///
/// **A cap, not a target.** A supervisor with no bound restarts a service that
/// can never come up for as long as the machine runs, which is a livelock that
/// reads as uptime. Sixty-four is above the forty-one the countdown needs, so
/// the recovery path is reached on its own merits and the cap is not what ends
/// that loop.
const RESTART_BUDGET: u32 = 64;

/// A service that cannot come up inside its budget: it is asked for a countdown
/// of ten and given three launches.
///
/// **The half a supervisor is judged on.** Restarting something until it works
/// is the easy case; the one that matters is a service that never will, because
/// a supervisor without this restarts it for ever. These two numbers are what
/// make the give-up path reachable, and `GIVE_UP_BUDGET` is deliberately below
/// `GIVE_UP_COUNTDOWN` so nothing but the cap can end it.
const GIVE_UP_COUNTDOWN: u64 = 10;
const GIVE_UP_BUDGET: u32 = 3;

/// Where a child's stack is mapped. The kernel maps the pages behind it at
/// start; this is only where they land, and it is clear of the addresses the
/// child's own segments link at.
///
/// **One of the three things in this program that is per-architecture**, and it
/// is here rather than in `uabi` because it is this loader's layout decision
/// rather than a fact about the port: a program chooses where its children's
/// stacks go, and a different root task could choose otherwise.
#[cfg(target_arch = "x86_64")]
const CHILD_STACK_BASE: u64 = 0x6800_0000;
/// AArch64's user half is 2^48 and its programs link at `0x1000_0000_0000`, so
/// the stack goes well below that and well above nothing.
#[cfg(target_arch = "aarch64")]
const CHILD_STACK_BASE: u64 = 0x0000_0f00_0000_0000;
/// RISC-V 64 links its programs at `0x1000_0000` under Sv39's 2^38 user half,
/// so the stack goes well above the segments and well below the top.
#[cfg(target_arch = "riscv64")]
const CHILD_STACK_BASE: u64 = 0x6800_0000;
/// RISC-V 32 links at the same `0x1000_0000`, and its user half ends at the
/// 2 GiB boundary where RAM begins (D106) — so this sits well inside it.
#[cfg(target_arch = "riscv32")]
const CHILD_STACK_BASE: u64 = 0x6800_0000;

/// Where a child finds its startup message, when it was given one.
///
/// **This program's layout decision, and the child is told rather than
/// assuming it**: the address arrives as the child's `arg`, so nothing depends
/// on the two sides having compiled the same constant. It is here because the
/// parent has to name a page, and one clear of every child's segments, stack
/// and image is a fact about this loader's layout.
const CHILD_MESSAGE_VA: u64 = 0x6900_0000;

/// The bytes the child sends back. Kept in step with
/// `//userspace/grant-probe`'s own constant by the boot check, which asserts
/// the same eight bytes from the kernel side.
const GRANTED_MAGIC: [u8; 8] = *b"GRANTED!";

/// A failure, as a step and a cause. The step is what this program was doing;
/// the cause is the kernel's error word where there is one.
struct Failure {
    step: u32,
    cause: i64,
}

impl Failure {
    fn new(step: u32, cause: i64) -> Self {
        Self { step, cause }
    }
}

/// Steps, in the order they run. A boot that fails names one of these.
const STEP_CHANNEL_CREATE: u32 = 1;
const STEP_PROCESS_CREATE: u32 = 2;
const STEP_ELF_PARSE: u32 = 3;
const STEP_SEGMENT_MAP: u32 = 4;
const STEP_GRANT: u32 = 5;
const STEP_START: u32 = 6;
const STEP_RECEIVE: u32 = 7;
const STEP_PAYLOAD: u32 = 8;
const STEP_ENCODE: u32 = 9;
const STEP_WAIT: u32 = 10;
const STEP_SUPERVISE: u32 = 11;
const STEP_GIVE_UP: u32 = 12;
const STEP_FRAMEWORK: u32 = 13;
const STEP_GRANT_SERVER: u32 = 14;
const STEP_GRANT_BUS: u32 = 15;
const STEP_GRANT_CLIENT: u32 = 16;
const STEP_PORT: u32 = 17;
const STEP_IRQ_BIND: u32 = 18;
const STEP_IRQ_MAP: u32 = 19;
const STEP_IRQ_WAIT: u32 = 20;
const STEP_IRQ_SOURCE: u32 = 21;

/// The source the child raises on the port this task makes for it. Bound here,
/// raised there: what may wake a port is decided once, by whoever made it.
const SIGNAL_SOURCE: u64 = 0x5161;

/// The edge `PortSignal` raises (`kcore::exec::SOFTWARE_PORT_SIGNAL`), which is
/// the one a port must be bound to for a software signal to reach it. A port
/// bound to another edge is not woken, which is what makes a bind a decision
/// rather than a formality.
const SIGNAL_EDGE: u8 = 4;

/// The edge a **device interrupt** raises (`kcore::exec::IRQ_PORT_SIGNAL`).
/// Distinct from `SIGNAL_EDGE` above, which is what a program raises by hand:
/// a port that reported the two as one could not tell a driver "your device
/// fired" from "somebody asked you to look".
const IRQ_EDGE: u32 = 1;

/// Where this program maps the device it was seeded with. Its own space, its
/// own choice — well clear of where its programs link and where its children's
/// stacks go.
#[cfg(target_arch = "x86_64")]
const DEVICE_VA: u64 = 0x7000_0000;
#[cfg(target_arch = "aarch64")]
const DEVICE_VA: u64 = 0x0000_0e00_0000_0000;
#[cfg(target_arch = "riscv64")]
const DEVICE_VA: u64 = 0x0000_0020_0000_0000;
#[cfg(target_arch = "riscv32")]
const DEVICE_VA: u64 = 0x7000_0000;

/// The PL031 real-time clock's registers, as this program uses them: the
/// counter, the match register the alarm compares against, the interrupt mask,
/// and the write-one-to-clear.
///
/// **A driver, written in the root task, and deliberately the smallest one
/// possible.** What step 13 has to show is that a program can route a real
/// line to a port it made and be woken on it; arming the source is the least
/// hardware knowledge that makes such a wake happen at all. A device with more
/// to it would have made the interrupt claim depend on a driver claim.
const PL031_DR: usize = 0x00;
const PL031_MR: usize = 0x04;
const PL031_IMSC: usize = 0x10;
const PL031_ICR: usize = 0x1c;

/// Reads one of the mapped device's registers.
fn mmio_read(base: u64, offset: usize) -> u32 {
    // SAFETY: `base` is the window `MapDevice` granted for a capability this
    // program holds, and every offset used here is inside the first 0x20 bytes
    // of a PL031's page.
    unsafe { ((base as usize + offset) as *const u32).read_volatile() }
}

/// Writes one of the mapped device's registers.
fn mmio_write(base: u64, offset: usize, value: u32) {
    // SAFETY: as `mmio_read`; nothing else on this machine holds this device
    // while the root task does.
    unsafe { ((base as usize + offset) as *mut u32).write_volatile(value) }
}

/// Encodes an argument struct into `buf`, or reports the encode step.
fn encode_args<T: tessera_isl_runtime::WireEncode>(
    value: &T,
    buf: &mut [u8],
    step: u32,
) -> Result<(), Failure> {
    encode(value, buf).map(|_| ()).map_err(|_| Failure::new(STEP_ENCODE, i64::from(step)))
}

/// One syscall, turning a negative result word into a named failure.
fn call(number: u64, arg0: u64, arg1: u64, step: u32) -> Result<i64, Failure> {
    let value = syscall2(number, arg0, arg1);
    if value < 0 {
        return Err(Failure::new(step, value));
    }
    Ok(value)
}

// --- the ELF walk ---

/// The 64-bit ELF header fields this loader reads, and nothing else.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_DATA_LSB: u8 = 1;
const ET_EXEC: u16 = 2;

/// Where this machine's ELFs keep the fields this loader reads, and the class
/// byte one must declare.
///
/// **A table rather than two parsers**, for the reason `kcore::elf` gives for
/// the same split (D258): every check here — the magic, the type, the machine,
/// the segment bounds, W^X — is the same check on both classes, and two
/// parsers would mean two places for one of them to be missing from.
///
/// **The program headers are reordered, not merely narrowed.** ELF32 puts
/// `p_flags` *last*, after the sizes, where ELF64 puts it second. A loader
/// assuming narrowing alone reads a segment's flags out of its file offset and
/// maps a text segment with no permissions at all.
///
/// `cfg` rather than a runtime branch: a program loads images for the machine
/// it is running on, so the class is decided at build time and an image of the
/// other one is refused rather than reinterpreted.
#[cfg(target_pointer_width = "64")]
mod elf_layout {
    pub const CLASS: u8 = 2;
    pub const EHDR: usize = 64;
    pub const PHDR: usize = 56;
    pub const E_ENTRY: usize = 24;
    pub const E_PHOFF: usize = 32;
    pub const E_PHENTSIZE: usize = 54;
    pub const E_PHNUM: usize = 56;
    pub const P_FLAGS: usize = 4;
    pub const P_OFFSET: usize = 8;
    pub const P_VADDR: usize = 16;
    pub const P_FILESZ: usize = 32;
    pub const P_MEMSZ: usize = 40;
}

#[cfg(target_pointer_width = "32")]
mod elf_layout {
    pub const CLASS: u8 = 1;
    pub const EHDR: usize = 52;
    pub const PHDR: usize = 32;
    pub const E_ENTRY: usize = 24;
    pub const E_PHOFF: usize = 28;
    pub const E_PHENTSIZE: usize = 42;
    pub const E_PHNUM: usize = 44;
    pub const P_OFFSET: usize = 4;
    pub const P_VADDR: usize = 8;
    pub const P_FILESZ: usize = 16;
    pub const P_MEMSZ: usize = 20;
    pub const P_FLAGS: usize = 24;
}

/// An address-sized ELF field, read at whichever width this machine's class
/// uses.
#[cfg(target_pointer_width = "64")]
fn le_addr(bytes: &[u8], at: usize) -> Option<u64> {
    le_u64(bytes, at)
}

#[cfg(target_pointer_width = "32")]
fn le_addr(bytes: &[u8], at: usize) -> Option<u64> {
    le_u32(bytes, at).map(u64::from)
}
/// The machine a loaded image must name. The second per-architecture fact: an
/// ELF for the wrong machine is refused rather than mapped, because a loader
/// that mapped it would produce a process faulting on its first instruction
/// with nothing to say why.
#[cfg(target_arch = "x86_64")]
const EM_THIS: u16 = 62;
#[cfg(target_arch = "aarch64")]
const EM_THIS: u16 = 183;
#[cfg(target_arch = "riscv64")]
const EM_THIS: u16 = 243;
/// The same number as RISC-V 64: the ELF specification gives RISC-V one
/// machine value for both widths and distinguishes them by the **class** byte,
/// which `elf_layout::CLASS` is what checks (D258).
#[cfg(target_arch = "riscv32")]
const EM_THIS: u16 = 243;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// One loadable segment, as this loader needs it.
#[derive(Clone, Copy)]
struct Segment {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
    flags: u32,
}

/// Reads a little-endian `u16`/`u32`/`u64` at `at`, or `None` past the end.
///
/// **Bounds-checked at every field**, because this is a parser of bytes that
/// will one day come off a disk. It reads a program the build produced today
/// and it must not be the reason that stops being safe (`docs/security/01`).
fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// The most segments this loader will map. A program with more is refused
/// rather than truncated: a half-loaded program is one that faults somewhere
/// unrelated to what was dropped.
const MAX_SEGMENTS: usize = 8;

/// The entry point and loadable segments of a 64-bit executable for this
/// architecture.
///
/// Refuses anything that is not exactly what it expects — the class, the byte
/// order, the type, the machine — rather than proceeding on the parts it
/// recognised. A loader that maps segments out of a file it has misidentified
/// has already lost.
fn parse_elf(image: &[u8]) -> Option<(u64, [Segment; MAX_SEGMENTS], usize)> {
    if image.len() < elf_layout::EHDR
        || image.get(0..4)? != ELF_MAGIC
        || *image.get(4)? != elf_layout::CLASS
        || *image.get(5)? != EI_DATA_LSB
        || le_u16(image, 16)? != ET_EXEC
        || le_u16(image, 18)? != EM_THIS
    {
        return None;
    }
    let entry = le_addr(image, elf_layout::E_ENTRY)?;
    let phoff = le_addr(image, elf_layout::E_PHOFF)? as usize;
    let phentsize = le_u16(image, elf_layout::E_PHENTSIZE)? as usize;
    let phnum = le_u16(image, elf_layout::E_PHNUM)? as usize;
    if phentsize < elf_layout::PHDR {
        return None;
    }

    let mut segments = [Segment {
        vaddr: 0,
        offset: 0,
        filesz: 0,
        memsz: 0,
        flags: 0,
    }; MAX_SEGMENTS];
    let mut count = 0;
    for index in 0..phnum {
        let at = phoff.checked_add(index.checked_mul(phentsize)?)?;
        if le_u32(image, at)? != PT_LOAD {
            continue;
        }
        if count == MAX_SEGMENTS {
            return None;
        }
        let segment = Segment {
            flags: le_u32(image, at + elf_layout::P_FLAGS)?,
            offset: le_addr(image, at + elf_layout::P_OFFSET)?,
            vaddr: le_addr(image, at + elf_layout::P_VADDR)?,
            filesz: le_addr(image, at + elf_layout::P_FILESZ)?,
            memsz: le_addr(image, at + elf_layout::P_MEMSZ)?,
        };
        // A segment claiming more file bytes than it has, or fewer memory
        // bytes than file bytes, is malformed. Checked here so the mapping
        // loop below can be arithmetic rather than validation.
        let end = segment.offset.checked_add(segment.filesz)?;
        if end > image.len() as u64 || segment.memsz < segment.filesz {
            return None;
        }
        // W^X, refused rather than downgraded: a program the loader silently
        // made non-writable faults on its own data (`docs/kernel/03`).
        if segment.flags & PF_W != 0 && segment.flags & PF_X != 0 {
            return None;
        }
        segments[count] = segment;
        count += 1;
    }
    if count == 0 {
        return None;
    }
    Some((entry, segments, count))
}

/// The `AddressSpaceMapArgs` rights a segment's `p_flags` ask for.
fn segment_rights(flags: u32) -> ProcessRights {
    let mut rights = ProcessRights(0);
    if flags & PF_R != 0 {
        rights = ProcessRights(rights.bits() | ProcessRights::READ.bits());
    }
    if flags & PF_W != 0 {
        rights = ProcessRights(rights.bits() | ProcessRights::WRITE.bits());
    }
    if flags & PF_X != 0 {
        rights = ProcessRights(rights.bits() | ProcessRights::EXECUTE.bits());
    }
    rights
}

/// Rounds up to a whole number of 4 KiB pages — the granularity
/// `AddressSpaceMap` works in, so the zero-fill for a segment's `.bss` tail
/// starts where the copied part's last page ends.
fn page_up(value: u64) -> u64 {
    (value + 0xfff) & !0xfff
}

/// Maps one segment into `child`.
///
/// Two calls where `memsz` exceeds `filesz`: the file bytes, then the
/// zero-filled tail. The kernel maps anonymous zeroed pages and copies into
/// them, so the tail is a map with no source rather than a copy of zeros.
fn map_segment(child: u32, image: &[u8], segment: Segment) -> Result<(), Failure> {
    let mut args_buf = [0u8; AddressSpaceMapArgs::WIRE_SIZE];
    let rights = segment_rights(segment.flags);
    if segment.filesz > 0 {
        let src = image
            .get(segment.offset as usize..(segment.offset + segment.filesz) as usize)
            .ok_or_else(|| Failure::new(STEP_SEGMENT_MAP, 0))?;
        let args = AddressSpaceMapArgs {
            size: AddressSpaceMapArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            process: HandleRef::new(child),
            reserved: 0,
            vaddr: segment.vaddr,
            length: segment.filesz,
            rights,
            src: src.as_ptr() as u64,
        };
        encode_args(&args, &mut args_buf, STEP_SEGMENT_MAP)?;
        call(
            SYS_ADDRESS_SPACE_MAP,
            args_buf.as_ptr() as u64,
            0,
            STEP_SEGMENT_MAP,
        )?;
    }
    // The `.bss` tail, if the file bytes did not already fill their last page.
    let covered = page_up(segment.filesz);
    if segment.memsz > covered {
        let args = AddressSpaceMapArgs {
            size: AddressSpaceMapArgs::WIRE_SIZE as u32,
            version: 1,
            flags: 0,
            process: HandleRef::new(child),
            reserved: 0,
            vaddr: segment.vaddr + covered,
            length: segment.memsz - covered,
            rights,
            // No source: the kernel's anonymous pages are already zeroed, which
            // is what a `.bss` is.
            src: 0,
        };
        encode_args(&args, &mut args_buf, STEP_SEGMENT_MAP)?;
        call(
            SYS_ADDRESS_SPACE_MAP,
            args_buf.as_ptr() as u64,
            0,
            STEP_SEGMENT_MAP,
        )?;
    }
    Ok(())
}

/// Creates a process, loads `image` into it, and returns its handle.
///
/// Everything up to the start, so a caller can grant capabilities in between —
/// which is the whole reason create and start are separate operations.
fn load_process(image: &[u8]) -> Result<(u32, u64), Failure> {
    let create = ProcessCreateArgs {
        size: ProcessCreateArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        job: HandleRef::new(SEEDED_JOB_HANDLE),
        reserved: 0,
    };
    let mut args_buf = [0u8; ProcessCreateArgs::WIRE_SIZE];
    encode_args(&create, &mut args_buf, STEP_PROCESS_CREATE)?;
    let child = call(
        SYS_PROCESS_CREATE,
        args_buf.as_ptr() as u64,
        0,
        STEP_PROCESS_CREATE,
    )? as u32;

    let (entry, segments, count) =
        parse_elf(image).ok_or_else(|| Failure::new(STEP_ELF_PARSE, image.len() as i64))?;
    for segment in segments.iter().take(count) {
        map_segment(child, image, *segment)?;
    }
    Ok((child, entry))
}

/// Starts `child` at `entry` with `arg`, and returns as soon as it is
/// runnable — the child has not run when this returns.
fn start_process(child: u32, entry: u64, arg: u64) -> Result<(), Failure> {
    start_process_with_message(child, entry, arg, &[])
}

/// As [`start_process`], and with a **startup message** copied into the child.
///
/// The message lands at [`CHILD_MESSAGE_VA`] and the child is told where by
/// that address being its `arg` — which is why this takes the two together
/// rather than letting a caller name an address the child would have to guess.
///
/// An empty message is the plain start: nothing is copied, nothing is mapped,
/// and `arg` is whatever the caller said. That is what every program that
/// wants a scalar keeps doing.
fn start_process_with_message(
    child: u32,
    entry: u64,
    arg: u64,
    message: &[u8],
) -> Result<(), Failure> {
    let start = ProcessStartArgs {
        size: ProcessStartArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        process: HandleRef::new(child),
        reserved: 0,
        entry,
        stack: CHILD_STACK_BASE,
        arg,
        message_ptr: message.as_ptr() as u64,
        message_len: message.len() as u64,
        message_va: CHILD_MESSAGE_VA,
    };
    let mut args_buf = [0u8; ProcessStartArgs::WIRE_SIZE];
    encode_args(&start, &mut args_buf, STEP_START)?;
    call(SYS_PROCESS_START, args_buf.as_ptr() as u64, 0, STEP_START)?;
    Ok(())
}

/// Blocks until `child` has exited and returns its code.
///
/// The kernel hands the code back as a `u32` bit pattern, because the result
/// word spells failure with its sign and an exit code is signed.
fn wait_process(child: u32) -> Result<i32, Failure> {
    let wait = ProcessWaitArgs {
        size: ProcessWaitArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        process: HandleRef::new(child),
        reserved: 0,
    };
    let mut args_buf = [0u8; ProcessWaitArgs::WIRE_SIZE];
    encode_args(&wait, &mut args_buf, STEP_WAIT)?;
    let code = call(SYS_PROCESS_WAIT, args_buf.as_ptr() as u64, 0, STEP_WAIT)?;
    Ok(code as u32 as i32)
}

/// What supervising one service produced.
struct Supervision {
    /// How many times it was launched.
    launches: u32,
    /// The code it last exited with. Zero means it came up.
    last_exit: i32,
}

/// Launches a service and relaunches it while it keeps failing, up to a budget.
///
/// **This is the component manager, and it is nine lines.** It was an assembly
/// blob reading a countdown out of a hand-patched data page, because the loader
/// syscalls were all a blob could reach and a blocking `ProcessStart` was the
/// only wait there was. A supervisor is a loop over launch, wait, decide; what
/// it needed was for those to be three things rather than two.
///
/// The service is given the remaining countdown as its argument and exits with
/// it, so it fails that many times and then comes up. The budget is a cap and
/// not a target: a supervisor with no bound restarts a service that can never
/// come up for as long as the machine runs, which is a livelock that reads as
/// uptime.
fn supervise(image: &[u8], countdown: u64, budget: u32) -> Result<Supervision, Failure> {
    let mut launches = 0;
    let mut remaining = countdown;
    loop {
        if launches == budget {
            // Gave up. The caller decides what that means; this reports it.
            return Ok(Supervision {
                launches,
                last_exit: remaining as i32,
            });
        }
        let (child, entry) = load_process(image)?;
        start_process(child, entry, remaining)?;
        launches += 1;
        let code = wait_process(child)?;
        if code == 0 {
            return Ok(Supervision {
                launches,
                last_exit: 0,
            });
        }
        // A crash. The next launch gets one fewer, which is this probe's way of
        // modelling a fault that clears.
        remaining = remaining.saturating_sub(1);
    }
}

/// Composes the driver framework: a device manager holding the bus this task
/// was seeded, and a driver holding one channel and no device at all.
///
/// **This is the roadmap's second Phase-1 bullet.** The sequence exists in
/// kernel code three times over — `bring_up_device_host`, `relay_pair`,
/// `driver_bind_check` — each of them boot glue creating a channel, spawning
/// two programs and reaching into their handle tables. Here it is user code,
/// and every capability either was made here or was handed on from the one
/// the kernel seeded.
///
/// **The manager is never waited for.** It is a resident server: it parks on
/// its endpoint and does not exit, so a parent that waited on it would wait
/// for ever. What ends the run is the *driver* having reported, which is the
/// thing a start that no longer blocks made expressible (build/README.md,
/// D250).
///
/// Returns the driver's exit code.
#[cfg(has_framework)]
fn compose_driver_framework(bus: u32, driver_arg: u64) -> Result<i32, Failure> {
    // The manager's service channel: the driver's only inbound authority, and
    // the one thing it is told rather than discovers.
    let record_buf = [0u8; ChannelCreateRecord::WIRE_SIZE];
    let create = ChannelCreateArgs {
        size: ChannelCreateArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        // The server end is the manager's to read; the client end is the
        // driver's to write, and travels, so it is created with TRANSFER.
        end0_rights: ChannelRights(ChannelRights::READ.bits() | ChannelRights::TRANSFER.bits()),
        end1_rights: ChannelRights(ChannelRights::WRITE.bits() | ChannelRights::TRANSFER.bits()),
        record_ptr: record_buf.as_ptr() as u64,
    };
    let mut args_buf = [0u8; ChannelCreateArgs::WIRE_SIZE];
    encode_args(&create, &mut args_buf, STEP_FRAMEWORK)?;
    call(
        SYS_CHANNEL_CREATE,
        args_buf.as_ptr() as u64,
        0,
        STEP_FRAMEWORK,
    )?;
    let record_bytes: [u8; ChannelCreateRecord::WIRE_SIZE] = read_kernel_filled(&record_buf);
    let record: ChannelCreateRecord =
        decode(&record_bytes).map_err(|_| Failure::new(STEP_FRAMEWORK, 1))?;

    // The manager first, so it is parked on its endpoint before the driver
    // calls. A racing call would queue and park harmlessly either way; this is
    // the order that makes the run's shape obvious rather than lucky.
    let (manager, manager_entry) = load_process(DEVICE_MANAGER_ELF)?;
    // Handle 0 is the service endpoint, handle 1 the bus. That install order is
    // the bootstrap ABI the program mirrors, and grants land in call order.
    grant(
        manager,
        record.end0,
        ProcessRights(ProcessRights::READ.bits()),
        STEP_GRANT_SERVER,
    )?;
    let bus_rights = held_rights(bus)?;
    // Narrowed by dropping TRANSFER: the manager derives children from the bus
    // and hands *those* on, so it never needs to pass the bus itself.
    grant(
        manager,
        bus,
        ProcessRights(bus_rights & !ProcessRights::TRANSFER.bits()),
        STEP_GRANT_BUS,
    )?;
    start_process(manager, manager_entry, DEVICE_MANAGER_ARG)?;

    // The driver: one endpoint, and no device. What it ends up holding arrives
    // by transfer from the manager or not at all.
    let (driver, driver_entry) = load_process(BLK_PROBE_ELF)?;
    grant(
        driver,
        record.end1,
        ProcessRights(ProcessRights::WRITE.bits()),
        STEP_GRANT_CLIENT,
    )?;
    start_process(driver, driver_entry, driver_arg)?;
    wait_process(driver)
}

/// The rights a handle this task holds carries, or a failure if it holds none.
fn held_rights(handle: u32) -> Result<u64, Failure> {
    Ok(call(
        SYS_HANDLE_QUERY_RIGHTS,
        u64::from(handle),
        0,
        STEP_FRAMEWORK,
    )? as u64)
}

/// What the kernel installed in this program's handle table before it ran.
struct Seeds {
    /// The bus to enumerate behind, if this machine has one.
    bus: Option<u32>,
    /// The device whose interrupts this task routes, if it was given one.
    device: Option<u32>,
}

/// Reads the seeds, **before this program creates anything**, and that is the
/// whole point.
///
/// A handle number is an index into a table this program is about to fill, so
/// "is handle 1 a bus?" has a different answer at startup than it does forty
/// handles later — and the late answer is always yes, because by then handle 1
/// is something this task made. Asked first, a failure means boot installed
/// nothing there, which is the only moment the question is answerable at all.
///
/// **Rights, not mere existence.** A handle that answers a rights query proves
/// only that the slot is filled. What makes a capability a bus is `DERIVE` —
/// the authority to produce a capability *from* it — and what makes one a
/// device to route is `BIND`. Checking the bit is what distinguishes a seed
/// from a channel endpoint that happens to have landed on the same number.
fn seeds() -> Seeds {
    let carries = |handle: u32, right: u64| {
        held_rights(handle)
            .ok()
            .is_some_and(|rights| rights & right != 0)
            .then_some(handle)
    };
    Seeds {
        bus: carries(SEEDED_BUS_HANDLE, ProcessRights::DERIVE.bits()),
        device: carries(SEEDED_DEVICE_HANDLE, ProcessRights::BIND.bits()),
    }
}

/// Hands `source` to a created process, narrowed to `rights`.
fn grant(process: u32, source: u32, rights: ProcessRights, step: u32) -> Result<u32, Failure> {
    let args = ProcessGrantArgs {
        size: ProcessGrantArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        process: HandleRef::new(process),
        source: HandleRef::new(source),
        rights,
        reserved: 0,
    };
    let mut args_buf = [0u8; ProcessGrantArgs::WIRE_SIZE];
    encode_args(&args, &mut args_buf, step)?;
    Ok(call(SYS_PROCESS_GRANT, args_buf.as_ptr() as u64, 0, step)? as u32)
}

// --- the composition ---

/// What the run produced, for the report.
struct Outcome {
    /// The handle the child's endpoint landed at, in the child's table.
    granted_handle: u32,
    /// The child's exit code.
    child_exit: i64,
    /// Bytes the child's message carried.
    received: usize,
    /// How many times the supervised service was launched before it came up.
    launches: u32,
    /// How many launches the service that never comes up was given before the
    /// supervisor stopped.
    gave_up_after: u32,
    /// The driver's exit code, on a machine that gave this task a bus.
    framework: Option<i32>,
    /// The interrupt line this task routed to a port of its own and was woken
    /// on, or `None` on a machine that seeded it no device.
    irq: Option<u32>,
}

fn run(startup: u64) -> Result<Outcome, Failure> {
    // 0. What boot seeded, asked before anything is created — see `seeds` for
    //    why this cannot wait until the steps that use it.
    //
    //    `startup` is the word the kernel started *this* program with, and it
    //    was ignored until now. It carries what the driver this task composes
    //    is to be started with: which report a machine's check expects is a
    //    fact about that machine, not about this program, and passing it here
    //    is what let the last `cfg` come out of the composition. AArch64's
    //    device is synthetic and asks for the relay report; x86-64's is a real
    //    PCI function and asks for the full probe (build/README.md, D256).
    let seeded = seeds();

    // 1. A channel of this program's own. Both handles land here; the far end
    //    is created with TRANSFER because it is the end that will travel.
    let record_buf = [0u8; ChannelCreateRecord::WIRE_SIZE];
    let create = ChannelCreateArgs {
        size: ChannelCreateArgs::WIRE_SIZE as u32,
        version: 2,
        flags: 0,
        end0_rights: ChannelRights(ChannelRights::READ.bits() | ChannelRights::WRITE.bits()),
        end1_rights: ChannelRights(ChannelRights::WRITE.bits() | ChannelRights::TRANSFER.bits()),
        record_ptr: record_buf.as_ptr() as u64,
    };
    let mut args_buf = [0u8; ChannelCreateArgs::WIRE_SIZE];
    encode_args(&create, &mut args_buf, STEP_CHANNEL_CREATE)?;
    call(
        SYS_CHANNEL_CREATE,
        args_buf.as_ptr() as u64,
        0,
        STEP_CHANNEL_CREATE,
    )?;
    // The kernel wrote the record; the compiler did not see it happen.
    let record_bytes: [u8; ChannelCreateRecord::WIRE_SIZE] = read_kernel_filled(&record_buf);
    let record: ChannelCreateRecord =
        decode(&record_bytes).map_err(|_| Failure::new(STEP_CHANNEL_CREATE, 0))?;
    let (mine, theirs) = (record.end0, record.end1);

    // 2-3. An empty child under the job the kernel seeded, with its own
    //      segments loaded from its own ELF.
    let (child, entry) = load_process(GRANT_PROBE_ELF)?;

    // 4. The grant. This is the step nothing in this tree could do. Narrowed:
    //    the child may send on this endpoint and may not pass it on.
    let granted_handle = grant(
        child,
        theirs,
        ProcessRights(ProcessRights::WRITE.bits()),
        STEP_GRANT,
    )?;

    // 5. **A port of this task's own**, bound to one source, and handed to the
    //    child with `SIGNAL` and nothing else. A capability to *wake somebody*
    //    is a different authority from a capability to talk to them, and this
    //    is the child holding one of each — neither of which the kernel put
    //    there (build/README.md, D254).
    let port = call(SYS_PORT_CREATE, 0, 0, STEP_PORT)? as u32;
    // Three registers: the port, the source, and the signal. `PortBind` is one
    // of the two calls in this ABI that needs a third, and until `syscall3`
    // existed no ring-3 program could make either.
    let bound = syscall3(
        SYS_PORT_BIND,
        u64::from(port),
        SIGNAL_SOURCE,
        u64::from(SIGNAL_EDGE),
    );
    if bound < 0 {
        return Err(Failure::new(STEP_PORT, bound));
    }
    let granted_port = grant(
        child,
        port,
        ProcessRights(ProcessRights::SIGNAL.bits()),
        STEP_PORT,
    )?;

    // 6. Start it with a **startup message** saying where both capabilities
    //    landed. This used to be the two handle numbers packed into the halves
    //    of the startup word — which said everything it needed to on a 64-bit
    //    machine and nothing at all on a 32-bit one, where the argument
    //    register is 32 bits (build/README.md, D261). The word now carries the
    //    address of the message, and the message is a schema both sides
    //    decode rather than a layout both sides remember.
    let handles = StartupHandles {
        size: StartupHandles::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        endpoint: HandleRef::new(granted_handle),
        port: HandleRef::new(granted_port),
    };
    let mut message = [0u8; StartupHandles::WIRE_SIZE];
    encode_args(&handles, &mut message, STEP_START)?;
    start_process_with_message(child, entry, CHILD_MESSAGE_VA, &message)?;

    // 7. **A second program, running alongside the first.** This is what a
    //    start that no longer waits buys: two children exist at once, neither
    //    of which the kernel assembled, and this task supervises one while the
    //    other is still runnable.
    //
    //    Forty-one launches, which is also the reclaim proof: a process slot
    //    and a thread slot are capped at sixteen, so a seventeenth launch
    //    fails unless every exited instance gave both back.
    let supervision = supervise(RESTART_PROBE_ELF, RESTART_COUNTDOWN, RESTART_BUDGET)?;
    if supervision.last_exit != 0 {
        return Err(Failure::new(
            STEP_SUPERVISE,
            i64::from(supervision.last_exit),
        ));
    }

    // 8. And a service that never comes up. A supervisor that only knows how to
    //    retry restarts such a thing for ever; this one stops at its budget and
    //    says so, which is the half that decides whether the policy is real.
    let gave_up = supervise(RESTART_PROBE_ELF, GIVE_UP_COUNTDOWN, GIVE_UP_BUDGET)?;
    if gave_up.launches != GIVE_UP_BUDGET || gave_up.last_exit == 0 {
        return Err(Failure::new(STEP_GIVE_UP, i64::from(gave_up.launches)));
    }

    // 9. **The driver framework, when this machine gave us a bus to run it
    //    on.** Asked rather than assumed: a port that seeds no device gets a
    //    root task that composes what it can and says nothing about what it
    //    cannot, which is what lets one program serve two machines.
    let framework = framework_exit(seeded.bus, startup)?;

    // 10. Collect the grant probe. It very likely ran and exited while the
    //    supervisor was blocked, in which case this returns straight away —
    //    which is the case a wait that insisted on seeing the transition would
    //    park for ever on.
    let child_exit = i64::from(wait_process(child)?);
    // **Checked here rather than at the end, because what follows blocks.** A
    // port wait parks until an edge arrives, and a child that failed before
    // raising one never will — so a root task that read the exit code last
    // would hang the machine on exactly the failure it was meant to report.
    if child_exit != 0 {
        return Err(Failure::new(STEP_WAIT, child_exit));
    }

    // 11. What the child sent, on the end it was given. Non-blocking, because
    //    the child has already exited: a message either is queued or never
    //    will be, and a root task that parked here would hang the machine.
    let mut inbox = [0u8; 32];
    let recv = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        // Bit 0: do not block.
        msg_flags: 1,
        inline_ptr: inbox.as_mut_ptr() as u64,
        inline_len: inbox.len() as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut args_buf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    encode_args(&recv, &mut args_buf, STEP_RECEIVE)?;
    let received = call(
        SYS_CHANNEL_RECV,
        args_buf.as_ptr() as u64,
        u64::from(mine),
        STEP_RECEIVE,
    )? as usize;

    let arrived: [u8; 8] = read_kernel_filled(&inbox[..8]);
    if received != GRANTED_MAGIC.len() || arrived != GRANTED_MAGIC {
        return Err(Failure::new(STEP_PAYLOAD, received as i64));
    }

    // 12. And the edge the child raised on the port. It has already exited, so
    //     the event is queued and this returns the pending count rather than
    //     parking — a port coalesces, which is what makes a driver that was
    //     busy when its device fired not lose the interrupt.
    let pending = call(SYS_PORT_WAIT, u64::from(port), 0, STEP_PORT)?;
    if pending == 0 {
        return Err(Failure::new(STEP_PORT, 0));
    }

    // 13. **A real device's interrupt, routed by this program to a port it
    //     made.** Everything above composes processes and channels, which are
    //     things the kernel can make on request. This is the machine's own
    //     hardware: the last authority a driver host needed that no capability
    //     could hand it, because until now saying where a line goes was the
    //     kernel's alone (build/README.md, D255).
    //
    //     Last, because it blocks for a whole second and everything before it
    //     is cheap — and because a step that parks must have nothing after it
    //     that a failure would skip.
    let irq = interrupt_route(seeded.device)?;

    Ok(Outcome {
        granted_handle,
        child_exit,
        received,
        launches: supervision.launches,
        gave_up_after: gave_up.launches,
        framework,
        irq,
    })
}

/// Routes the seeded device's interrupts to a port of this task's own, arms the
/// device, and is woken by the line — answering the interrupt number, or `None`
/// on a machine that seeded no device.
///
/// **This is the last thing a root task needed that it could not do.** A
/// program could map its device (23), allocate its DMA (24) and re-arm its line
/// (26), and still could not say where the interrupts were to go: every route
/// in this tree was installed by kernel boot glue on a driver's behalf, which
/// made a driver host something only the kernel could assemble
/// (`build/README.md`, D255).
///
/// The order matters. The route is made **before** the device is armed, because
/// a line that fires with nowhere to go is delivered to no port and nothing
/// remembers it — a coalescing port remembers an edge raised while nobody
/// waits, but only if it was bound to the source when the edge arrived.
fn interrupt_route(device: Option<u32>) -> Result<Option<u32>, Failure> {
    // A machine that seeded no device gets a root task that says so and does
    // not fail. Whether it did is decided by `seeded_device` at startup and
    // passed in, **not** re-asked here: by this point the program has created a
    // dozen handles of its own, and handle 2 answers a rights query whether or
    // not boot put a device there. Asking late is how this check first came to
    // hand a channel endpoint to `DeviceIrqBind` on a port that seeds nothing.
    let Some(device) = device else {
        return Ok(None);
    };

    // A second port, and not the one the grant probe raises an edge on. Two
    // ports rather than two signals on one, so that being woken here can only
    // mean the device: a port carrying both would let a child's software edge
    // stand in for a hardware interrupt this check exists to observe.
    let port = call(SYS_PORT_CREATE, 0, 0, STEP_IRQ_BIND)? as u32;

    let bind = DeviceIrqBindArgs {
        size: DeviceIrqBindArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        port: HandleRef::new(port),
        // Zero: this device's own line, whatever the machine's description
        // says it is. A root task that named a number would be asserting a
        // fact about the hardware that the resource graph already holds.
        intid: 0,
        reserved: 0,
    };
    let mut buf = [0u8; DeviceIrqBindArgs::WIRE_SIZE];
    encode_args(&bind, &mut buf, STEP_IRQ_BIND)?;
    // The kernel answers with the line it routed, which is the source a wait
    // on this port will report — learned from the call that made the route
    // rather than agreed out of band.
    let intid = call(SYS_DEVICE_IRQ_BIND, buf.as_ptr() as u64, 0, STEP_IRQ_BIND)? as u32;

    // The registers, in this program's own space.
    let map = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        reserved: 0,
        vaddr: DEVICE_VA,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    encode_args(&map, &mut buf, STEP_IRQ_MAP)?;
    let regs = call(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0, STEP_IRQ_MAP)? as u64;

    // Arm the alarm one tick out. The PL031 counts at 1 Hz, so this is a whole
    // second — slow for a boot check and the price of the source being real.
    mmio_write(regs, PL031_ICR, 1);
    let now = mmio_read(regs, PL031_DR);
    mmio_write(regs, PL031_MR, now.wrapping_add(1));
    mmio_write(regs, PL031_IMSC, 1);

    // And park. This is a real block on a real line: nothing else on the
    // machine is runnable, and what ends it is the device.
    let mut event = [0u8; PortEventRecord::WIRE_SIZE];
    let pending = syscall2(SYS_PORT_WAIT, u64::from(port), event.as_ptr() as u64);

    // Mask and acknowledge the device before judging the result, so a failure
    // does not leave a live line behind it.
    mmio_write(regs, PL031_IMSC, 0);
    mmio_write(regs, PL031_ICR, 1);

    if pending < 0 {
        return Err(Failure::new(STEP_IRQ_WAIT, pending));
    }
    let bytes = read_kernel_filled::<{ PortEventRecord::WIRE_SIZE }>(&event);
    let Ok(record) = decode::<PortEventRecord>(&bytes) else {
        return Err(Failure::new(STEP_IRQ_WAIT, 0));
    };
    // **What makes this a hardware wake and not any other kind.** The source is
    // the line the route was made for and the signal is the interrupt edge —
    // neither of which anything in user space can raise on this port, because
    // the only binding it carries is the one `DeviceIrqBind` installed.
    if record.source != u64::from(intid) || record.signal != IRQ_EDGE {
        return Err(Failure::new(STEP_IRQ_SOURCE, record.source as i64));
    }
    Ok(Some(intid))
}

/// The driver's exit code, or `None` on a machine that seeded no bus.
///
/// **Which machines can do this is a fact about what boot hands over**, not
/// about the program: a machine that seeds no bus gets `None` here and a root
/// task that says so. x86-64 used to have a second body for that, keyed on its
/// architecture; it seeds a real PCI function today and composes the same
/// framework from the same source (`build/README.md`, D256).
///
/// The second body below is keyed on whether this *build* carries the framework
/// images at all, which is composition and not architecture.
#[cfg(has_framework)]
fn framework_exit(bus: Option<u32>, driver_arg: u64) -> Result<Option<i32>, Failure> {
    match bus {
        Some(bus) => compose_driver_framework(bus, driver_arg).map(Some),
        None => Ok(None),
    }
}

/// A build carrying no framework images has nothing to compose, and says so
/// with the same `None` a machine that seeded no bus produces.
#[cfg(not(has_framework))]
fn framework_exit(bus: Option<u32>, _driver_arg: u64) -> Result<Option<i32>, Failure> {
    let _ = bus;
    Ok(None)
}

/// Renders the report and exits.
///
/// One line, fixed width, hex — the console is a serial port and a boot check
/// greps this. The fields are what a reader needs to tell a working
/// composition from a plausible one: where the capability landed in the child,
/// what the child exited with, and how many bytes came back.
fn report_and_exit(result: Result<Outcome, Failure>) -> ! {
    let mut line =
        *b"roottask: granted=00 exit=00000000 bytes=00 runs=00 gaveup=00 fw=0000 irq=0000 step=00 cause=00000000";
    let code = match result {
        Ok(outcome) => {
            write_hex(&mut line, 18, u64::from(outcome.granted_handle), 2);
            write_hex(&mut line, 26, outcome.child_exit as u64, 8);
            write_hex(&mut line, 41, outcome.received as u64, 2);
            write_hex(&mut line, 49, u64::from(outcome.launches), 2);
            write_hex(&mut line, 59, u64::from(outcome.gave_up_after), 2);
            // `ffff` where the machine seeded no bus, which is a different
            // fact from a driver that exited zero.
            write_hex(
                &mut line,
                65,
                outcome.framework.map_or(0xffff, |code| code as u64 & 0xffff),
                4,
            );
            // `ffff` where the machine seeded no device, which is a different
            // fact from a line that was routed and never fired — the latter
            // does not reach here at all, because the wait is what fails.
            write_hex(
                &mut line,
                74,
                outcome.irq.map_or(0xffff, u64::from),
                4,
            );
            if outcome.child_exit == 0 && outcome.framework.unwrap_or(0) == 0 {
                0
            } else {
                1
            }
        }
        Err(failure) => {
            write_hex(&mut line, 84, u64::from(failure.step), 2);
            write_hex(&mut line, 93, failure.cause as u64, 8);
            // **The step, in the exit code.** The line above says everything,
            // and on a port whose `DebugWrite` records the argument register
            // rather than the buffer behind it there is nowhere for a line to
            // go. An exit code reaches every port, so it carries the one field
            // a reader needs first: which step failed.
            100 + failure.step as i32
        }
    };
    syscall2(SYS_DEBUG_WRITE, line.as_ptr() as u64, line.len() as u64);
    syscall2(SYS_PROCESS_EXIT, code as u64, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Writes `digits` hex digits of `value` at `at`, least significant last.
fn write_hex(buf: &mut [u8], at: usize, value: u64, digits: usize) {
    for index in 0..digits {
        let shift = 4 * (digits - 1 - index);
        let nibble = ((value >> shift) & 0xf) as u8;
        if let Some(slot) = buf.get_mut(at + index) {
            *slot = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
        }
    }
}

// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg: u64) -> ! {
    report_and_exit(run(arg))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    report_and_exit(Err(Failure::new(0xff, 0)))
}
