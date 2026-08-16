// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A minimal block driver, existing to be killed and replaced.
//!
//! It does the smallest thing a driver of a class does: asks the device
//! manager for a `Block` device, maps the capability it is handed, reads the
//! transport's identifying register, and reports what it found. It runs
//! twice in one boot — once as the driver that dies, and once as the driver
//! that takes over — and the point of the second run is that it acquires the
//! *same physical device* through the same protocol, with nothing carried
//! over from the first.
//!
//! Why a separate program rather than the device host: the host is a resident
//! service with two devices, an interrupt port, a select loop and clients. A
//! restart proof wants the opposite — something that starts, takes a device,
//! and stops — so the thing under test is the handover and not the driver.
//!
//! Its startup argument is the incarnation number, which it folds into its
//! report so the two runs are distinguishable in the sink rather than being
//! two identical values that could equally be one value written twice.
//!
//! Normative: docs/hardware/03-component-interaction-model.md,
//! docs/kernel/05-jobs-containment-and-resource-control.md ("failure model")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::ChannelMsgArgs;
use device_abi::{
    DeviceChildArgs, DeviceChildRecord, DeviceInfoArgs, DeviceInfoKind, DeviceInfoRecord,
    DmaAllocArgs, MapConfigArgs, MapDeviceArgs,
};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use driver_lifecycle::{DriverState, LifecycleTransitionArgs, TransitionReason};
use firmware_abi::{FirmwareLoadArgs, FirmwareReport};
use memory_abi::{MapRights, MemoryMapArgs};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{fail, layout, read_kernel_filled, syscall1, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;
const SYS_MAP_DEVICE: u64 = 23;
const SYS_DMA_ALLOC: u64 = 24;
const SYS_DEVICE_INFO: u64 = 28;
const SYS_DEVICE_CHILD: u64 = 35;
const SYS_DRIVER_LIFECYCLE: u64 = 29;
const SYS_MEMORY_MAP: u64 = 31;
const SYS_FIRMWARE_LOAD: u64 = 39;
const SYS_MAP_CONFIG: u64 = 42;

/// The bind channel boot installs first, so it is always handle 0 — this
/// program's whole bootstrap contract.
const MANAGER_ENDPOINT_HANDLE: u64 = 0;

/// The bind exchange's buffer: the larger of `BindRequest` and `BindReply`.
///
/// Taken from the type rather than written out. A reply that grew past a
/// literal would truncate a driver's outputs at run time, which is a failure
/// nobody would connect back to the schema change that caused it.
const BIND_BUF_LEN: usize = BindReply::WIRE_SIZE;

/// The block class contract version this driver implements. A binding that
/// placed it against a different one is a mis-binding, and checking beats
/// trusting — the same reason `BindReply.class` is echoed and verified.
const BLOCK_CONTRACT_VERSION: u32 = 1;
/// `tessera_binding::required_service::LOGGING`. Named rather than imported
/// because a ring-3 driver has no business linking the manager's matcher; what
/// it needs is the one bit it acts on.
const REQUIRED_SERVICE_LOGGING: u32 = 0x1;

/// The most added path latency a block driver tolerates, microseconds.
///
/// **Deliberately duplicated** from the device manager's manifest entry. This
/// is the driver's own budget — `docs/architecture/03` states the storage
/// budgets for a direct-attached device — and a driver that read the number
/// from the same place the manager did would be checking nothing. Two copies
/// that must agree is the point: if the manifest is edited to tolerate more,
/// this fails until somebody decides the driver can live with it.
const BLOCK_MAX_PATH_LATENCY_US: u64 = 30;

const REG_MAGIC: usize = 0x000;
const VIRTIO_MAGIC: u32 = 0x7472_6976;

/// Asks the manager for a block device, returning the handle the capability
/// was installed at.
///
/// The handle is **read back**, not assumed. A handle is an index and a
/// generation, and a device that has been through another process's table
/// comes back with a different value than it left with — so a driver that
/// hard-coded "my device is handle 1" would be right exactly once. The
/// transfer vector doubles as the kernel's report of what it installed.
fn bind() -> Result<u32, u64> {
    let (reply, installed) = bind_call(DeviceClass::Block)?;
    if reply.status != 0 {
        return Err(fail(0x50, 0x100 | u64::from(reply.status)));
    }
    if reply.class != DeviceClass::Block {
        return Err(fail(0x50, 0x200));
    }
    // **The binding's outputs, checked rather than ignored.** A driver told
    // which services it may require and which contract version it was bound
    // against, and then not looking, would leave those outputs decorative —
    // and a manifest that stopped filling them in would break nothing until
    // something needed them.
    if reply.contract_version != BLOCK_CONTRACT_VERSION {
        return Err(fail(0x50, 0x300 | u64::from(reply.contract_version)));
    }
    if reply.required_services & REQUIRED_SERVICE_LOGGING == 0 {
        return Err(fail(0x50, 0x400));
    }
    if reply.update_channel == 0 {
        return Err(fail(0x50, 0x500));
    }
    // **What the data path costs, checked against this driver's own budget.**
    // The manager applied it — that is why this bind succeeded — and checking
    // it here is the driver holding the manager to the arithmetic rather than
    // trusting it. A manager that stopped accumulating would hand this driver
    // a device behind any number of hubs and nothing would notice.
    if reply.accumulated_latency_us > BLOCK_MAX_PATH_LATENCY_US {
        return Err(fail(0x51, reply.accumulated_latency_us));
    }
    // A path with no hops has no cost. The pair is reported together, so they
    // must agree: a hop count of zero beside a latency is a number that came
    // from somewhere other than the path.
    if reply.relay_hops == 0
        && (reply.accumulated_latency_us != 0 || reply.path_throughput_mbps != 0)
    {
        return Err(fail(0x51, 0x600 | reply.accumulated_latency_us));
    }
    Ok(installed)
}

/// The bind exchange itself, with no policy attached: one `BindRequest` out,
/// one `BindReply` back, and the handle the kernel installed.
///
/// Split from [`bind`] because a refusal is a legitimate answer to look at.
/// Folding the checks in would make every caller that wants to *see* a status
/// go through something that turns one into an error.
fn bind_call(class: DeviceClass) -> Result<(BindReply, u32), u64> {
    bind_call_installed(class).map(|(reply, installed)| (reply, installed[0]))
}

/// [`bind_call`], reporting **every** handle the kernel installed.
///
/// A bind can now carry two: the device, and the firmware image the manifest
/// entry declared. They are read back rather than assumed, for the reason the
/// device's handle always has been — a handle is an index and a generation, and
/// a value remembered across a table is stale by construction.
fn bind_call_installed(class: DeviceClass) -> Result<(BindReply, [u32; 2]), u64> {
    // Sized for the larger of the two: a `BindRequest` going out and a
    // `BindReply` coming back, and the reply is now the bigger of them —
    // binding produces outputs, and a buffer sized for the request alone would
    // truncate them (`docs/drivers/01`, "Binding outputs").
    let mut message = [0u8; BIND_BUF_LEN];
    let mut installed = [0u32; 2];
    let request = BindRequest {
        size: BindRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        class,
        reserved: 0,
    };
    if encode(&request, &mut message).is_err() {
        return Err(fail(0x53, 0xe));
    }
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: message.as_ptr() as u64,
        inline_len: message.len() as u64,
        handles_ptr: 0,
        handle_count: 0,
        // Transfer nothing, but ask which handle the capability lands on —
        // the pair a call could not express before the descriptor grew.
        installed_ptr: installed.as_ptr() as u64,
        installed_cap: installed.len() as u64,
    };
    let mut abuf = [0u8; ChannelMsgArgs::WIRE_SIZE];
    if encode(&args, &mut abuf).is_err() {
        return Err(fail(0x53, 0xe));
    }
    let n = syscall2(
        SYS_CHANNEL_CALL,
        abuf.as_ptr() as u64,
        MANAGER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0x50, (-n) as u64));
    }
    let bytes = read_kernel_filled::<{ BindReply::WIRE_SIZE }>(&message);
    let reply: BindReply = match decode(&bytes) {
        Ok(reply) => reply,
        Err(_) => return Err(fail(0x50, 0xd)),
    };
    // SAFETY: the kernel wrote these slots while installing the transferred
    // capabilities during the call above; volatile only forbids the compiler
    // from assuming the zeros it stored are still there.
    Ok((reply, unsafe {
        [
            core::ptr::read_volatile(&installed[0]),
            core::ptr::read_volatile(&installed[1]),
        ]
    }))
}

/// Tags a report as "this is what the kernel says the device is", so the boot
/// check cannot mistake a PCI identity for a virtio magic value.
const PCI_REPORT_TAG: u64 = 0x5043 << 48;

/// Asks the kernel what the bound device is, and reports a PCI identity
/// rather than driving.
///
/// A driver checking what it was handed is not paranoia: the bind reply echoes
/// a class, but the class a manager assigned and the device the kernel
/// enumerated are two different facts, and this is the one place they can be
/// compared. It matters more here than for virtio-mmio, because a PCI
/// function's identity is not readable from its BAR — only the kernel saw it.
///
/// Returns `None` when the kernel holds no identity, which is every
/// virtio-mmio transport: those are driven, not merely identified.
fn identity(device: u32) -> Result<Option<u64>, u64> {
    identity_and_layout(device).map(|answer| answer.map(|(report, _)| report))
}

/// The same query, keeping the structure offsets the record now carries.
///
/// Split out rather than folded into [`identity`] because the two answers have
/// different lifetimes in this program: the identity is what it reports, and
/// the layout is what it *uses* — and a driver that read the record twice
/// would be asking the kernel a question it has already been answered.
#[allow(clippy::type_complexity)]
fn identity_and_layout(device: u32) -> Result<Option<(u64, Option<(u32, u32)>)>, u64> {
    let mut record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    let args = DeviceInfoArgs {
        size: DeviceInfoArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        reserved: 0,
        record_ptr: record.as_ptr() as u64,
    };
    let mut buf = [0u8; DeviceInfoArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x54, 0xe));
    }
    let result = syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0);
    if result < 0 {
        return Err(fail(0x54, (-result) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceInfoRecord::WIRE_SIZE }>(&record);
    let decoded: DeviceInfoRecord = match decode(&bytes) {
        Ok(record) => record,
        Err(_) => return Err(fail(0x54, 0xd)),
    };
    match decoded.kind {
        DeviceInfoKind::Unknown => Ok(None),
        // A virtio-pci transport is not implemented, so this driver reports
        // what it was given and stops there rather than driving a BAR whose
        // layout it does not speak. Saying so beats reading a register that
        // means something else and calling the result a magic value.
        DeviceInfoKind::Pci => Ok(Some((
            PCI_REPORT_TAG | (u64::from(decoded.vendor) << 16) | u64::from(decoded.device),
            // Where the device's structures are, when the kernel resolved
            // them. `layout_valid` is asked rather than the offsets being
            // tested for zero: offset zero is a legitimate place for a
            // structure to be, and a driver that inferred otherwise would
            // refuse to drive a device whose common configuration happens to
            // sit at the start of its BAR.
            (decoded.layout_valid != 0).then_some((decoded.common_offset, decoded.notify_offset)),
        ))),
    }
}

/// Asks the bound device for a DMA buffer.
///
/// A driver does this because it needs memory the device can reach, and it
/// cannot tell from the answer whether the address is an IOVA scoped to its
/// device or a physical address that reaches everything — that is a property of
/// the machine, and deliberately not of this call. What it *can* tell is that
/// the request was refused, which is why a failure is reported rather than
/// stepped over.
fn dma(device: u32) -> Result<u64, u64> {
    let args = DmaAllocArgs {
        size: DmaAllocArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        reserved: 0,
        vaddr: layout::DEVICE_DMA_VA,
    };
    let mut buf = [0u8; DmaAllocArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x55, 0xe));
    }
    let address = syscall1(SYS_DMA_ALLOC, buf.as_ptr() as u64);
    if address < 0 {
        return Err(fail(0x56, (-address) as u64));
    }
    Ok(address as u64)
}

/// Maps the bound device and returns its identifying register.
fn probe(device: u32) -> Result<u32, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        reserved: 0,
        vaddr: layout::DEVICE_MMIO_VA,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x53, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x51, (-base) as u64));
    }
    // SAFETY: `base` is the register base MapDevice granted from the
    // capability the manager handed over; the magic is the first word of the
    // virtio-mmio header the capability covers.
    let magic = unsafe { ((base as usize + REG_MAGIC) as *const u32).read_volatile() };
    if magic != VIRTIO_MAGIC {
        return Err(fail(0x52, u64::from(magic & 0xffff)));
    }
    Ok(magic)
}

/// How far into its own window this driver reads to prove it got all of it.
///
/// Past the first page, which is the whole point: until `MapDevice` granted a
/// device's window rather than its first page, this load faulted. The offset is
/// the check's knowledge of this machine, not the driver's — a driver is told
/// where its structures are, and nothing tells one yet.
const FAR_OFFSET: usize = 0x2000;

/// Maps the bound device's **whole** window and reads a word beyond the first
/// page, returning its low 16 bits.
///
/// The value means nothing to this program deliberately. The boot check reads
/// the same physical location through the kernel's direct map and requires the
/// two to agree, so what is proven is that the mapping reaches that far and
/// shows the same bytes — no interpretation needed, and none possible to get
/// accidentally right.
/// Reads the device's **common configuration structure** through the window
/// the capability granted, at the offset the kernel told this driver it is at.
///
/// **This is the thing that stood between a granted window and a ring-3
/// virtio-pci driver** (D126's open item). A virtio-pci function does not say
/// where its controls are in any register it exposes — it says so in config
/// space, one vendor capability per structure, and config space is not
/// per-device, so no capability to it can be handed out. Until the kernel
/// reported the offsets, a driver holding the right window still had no way to
/// find anything in it: the check that proved the window worked read at an
/// offset the *check* knew and the driver did not.
///
/// What is read back is `device_feature_select`, which the specification puts
/// at offset 0 of the common structure and which a device answers with the
/// selector it was last given. Writing a value and reading it back is the
/// smallest thing that distinguishes "this is the common configuration
/// structure" from "this is somewhere inside the right BAR": a wrong offset
/// lands on a register that does not behave this way, and the mismatch is the
/// finding.
fn common_config_probe(base: u64, offset: u32) -> u64 {
    let at = (base as usize) + offset as usize;
    // SAFETY: `base` is the window MapDevice granted from the capability the
    // manager transferred, and `offset` came from the kernel's own walk of
    // this device's capabilities — it is inside the window by construction of
    // the graph, which checked the device's numbers against the BAR length
    // before recording them.
    unsafe {
        // `device_feature_select` at +0: write a selector, read it back.
        let reg = at as *mut u32;
        reg.write_volatile(1);
        let high = reg.read_volatile();
        reg.write_volatile(0);
        let low = reg.read_volatile();
        // Both halves, so a register that answers with a constant fails as
        // loudly as one that answers with nothing.
        u64::from(high) << 8 | u64::from(low)
    }
}

fn far_word(device: u32) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        reserved: 0,
        vaddr: layout::DEVICE_MMIO_VA,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x57, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x58, (-base) as u64));
    }
    // SAFETY: `base` is the window MapDevice granted from the capability the
    // manager handed over, and `FAR_OFFSET` is inside it — which is exactly
    // what this read exists to demonstrate.
    let word = unsafe { ((base as usize + FAR_OFFSET) as *const u32).read_volatile() };
    Ok(u64::from(word & 0xffff))
}

/// Declares that this driver's device moved from `from` to `to`.
///
/// **Two of the thirteen states belong to the driver and to nothing else.**
/// The manager owns the lifecycle, but it cannot see a probe: it hands a
/// capability away and the next thing it hears is whether a bind reply was
/// consumed. Whether the device answered — whether this is the hardware the
/// match said it was — is known here and nowhere else, so `Starting ->
/// Probing -> Active` is declared here.
///
/// Failure is deliberately not fatal. A driver whose device works and whose
/// lifecycle record was refused has still driven its device; killing it would
/// turn an observability gap into an outage. The refusal is visible in the
/// records by the transition's absence, which is the right severity for it.
fn declare(handle: u32, from: DriverState, to: DriverState, reason: TransitionReason) {
    let args = LifecycleTransitionArgs {
        size: LifecycleTransitionArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        from,
        to,
        reason,
        detail: 0,
    };
    let mut buf = [0u8; LifecycleTransitionArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_ok() {
        syscall2(SYS_DRIVER_LIFECYCLE, buf.as_ptr() as u64, 0);
    }
}

/// Startup-argument bit asking this driver to crash once it holds its device.
///
/// **After binding, deliberately.** A driver that died before acquiring
/// anything would exercise nothing but process teardown; one that dies holding
/// a device capability is what the crash-recovery ladder is for — the
/// capability has to come back from the corpse, its register window has to go
/// with it, and the replacement has to acquire the same physical device
/// through the same protocol. A crash before the bind would let all three
/// stay untested while the supervisor looked busy.
///
/// The high bit, so the low bits stay the incarnation number and a supervisor
/// can ask for a crashing incarnation without a second argument register.
const CRASH_AFTER_BIND: u64 = 1 << 63;

/// Asks this program to run as a **queue child** instead of a driver: derive
/// the one queue behind the controller it holds, and submit on that queue
/// alone.
///
/// The second-highest bit, for the same reason the crash flag is the highest —
/// the low bits stay the incarnation number.
const QUEUE_CHILD: u64 = 1 << 62;

/// The handle the kernel installs the controller capability at for a queue
/// child. Handle 0, as every other startup capability in this tree.
const CONTROLLER_HANDLE: u32 = 0;

/// Asks this program to report **what the manager said its data path costs**,
/// over three binds, instead of driving anything.
const RELAY_REPORT: u64 = 1 << 61;
/// Asks this program to report **what firmware came with its device**, instead
/// of driving anything.
const FIRMWARE_REPORT: u64 = 1 << 60;
/// Asks this program to report **what its own configuration space says it is**,
/// instead of driving anything.
const CONFIG_REPORT: u64 = 1 << 59;

/// Where this program maps its function's configuration space. Its own address,
/// distinct from the device window and the DMA page, so a mapping that landed
/// in the wrong place fails rather than overwriting something.
const CONFIG_VA: u64 = layout::PROBE_WINDOW_BASE + 0x20_0000;

/// Where the firmware image is mapped to be measured. Its own address, distinct
/// from the device window and the DMA page, so a mapping that landed in the
/// wrong place would fail rather than overwrite something.
const FIRMWARE_VA: u64 = layout::PROBE_WINDOW_BASE + 0x10_0000;

/// The largest image this driver will measure. A page: the store's firmware is
/// one, and a driver that measured only part of what it was given and reported
/// a digest for it would be reporting about bytes nobody sent.
const FIRMWARE_MAX: usize = 4096;

/// What this function's **own configuration space** says it is, read by this
/// program through a capability scoped to one function.
///
/// The whole of what the milestone claims, from the one side that can check it.
/// This device was put in the resource graph by a program in ring 3 — nothing
/// privileged ever looked at it — so the graph's word for what it is came from
/// a bus driver. Reading configuration space here is asking the hardware
/// directly, and the two agreeing is what makes the ring-3 walk believable
/// rather than merely self-consistent.
///
/// The layout, low to high: the 32-bit word at configuration offset zero, which
/// is the vendor id and the device id as the function reports them; then a bit
/// for whether `DeviceInfo` agreed; then a tag.
fn config_report() -> u64 {
    const TAG: u64 = 0x43 << 56;
    const AGREED: u64 = 1 << 48;
    let device = match bind() {
        Ok(device) => device,
        Err(code) => return code,
    };
    let base = match map_config(device) {
        Ok(base) => base,
        Err(code) => return code,
    };
    // SAFETY: the kernel just mapped this function's own configuration slot at
    // `base` and the call succeeded; offset zero is the vendor/device register,
    // inside the 4 KiB the capability covers. Volatile because configuration
    // space is device memory.
    let word = unsafe { (base as *const u32).read_volatile() };

    // What the graph says, which is what the bus driver declared.
    let agreed = match identity(device) {
        Ok(Some(packed)) => {
            // `identity` packs vendor above device, under a tag.
            let vendor = (packed >> 16) & 0xffff;
            let product = packed & 0xffff;
            u64::from(vendor == u64::from(word & 0xffff) && product == u64::from(word >> 16))
        }
        // No identity at all is a different failure from a disagreement, and
        // reported as one: it means nothing declared this device.
        Ok(None) => return fail(0x5a, 0),
        Err(code) => return code,
    };
    TAG | (agreed * AGREED) | u64::from(word)
}

/// Maps this function's configuration space and returns its base.
///
/// `MapConfig` and not `MapDevice`: they name different windows and need
/// different rights. What comes back is 4 KiB — this function's slot and not the
/// one beside it — which is the property the whole capability exists for.
fn map_config(device: u32) -> Result<u64, u64> {
    let args = MapConfigArgs {
        size: MapConfigArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        reserved: 0,
        vaddr: CONFIG_VA,
    };
    let mut buf = [0u8; MapConfigArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x5b, 0xe));
    }
    let base = syscall2(SYS_MAP_CONFIG, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x5b, (-base) as u64));
    }
    Ok(base as u64)
}

/// What the driver was handed with its device, packed into one word.
///
/// **The digest is computed here, from the mapped bytes, by this program.** It
/// would have been far easier to read the one the kernel reported — and it
/// would have proved nothing: a driver that echoes the sender's digest is
/// checking the sender against itself. Measuring the object it actually mapped
/// is the only version of this claim with content, and it is why this program
/// links the same hash the kernel measures with.
///
/// The layout, low to high: the leading four bytes of the digest this program
/// computed; the image version and security version the reply reported; then
/// the outcome of this driver asking for firmware **itself**, which must fail.
fn firmware_report() -> u64 {
    let (reply, installed) = match bind_call_installed(DeviceClass::Block) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    if reply.status != 0 {
        return fail(0x60, 0x100 | u64::from(reply.status));
    }
    // Two capabilities: the device, then the image. A binding that carried no
    // firmware installs one, and this driver's whole subject is the second.
    if installed[1] == 0 {
        return fail(0x60, 0x200);
    }

    let bytes = match map_firmware(installed[1]) {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let digest = tessera_hash::sha256(bytes);
    let mut lead = [0u8; 4];
    lead.copy_from_slice(&digest[..4]);

    // **This driver asks for firmware and must be refused.** It holds the
    // device — it can map it and drive it — and the manager narrowed
    // `Rights::FIRMWARE` away on the way over, so the authority to put code on
    // that hardware stayed with the framework. Without this the right would be
    // a field nobody had watched refuse anything.
    let refused = firmware_self_load(installed[0]);

    u64::from(u32::from_le_bytes(lead))
        | (u64::from(reply.firmware_image_version) & 0xff) << 32
        | (u64::from(reply.firmware_svn) & 0xff) << 40
        | (refused & 0xff) << 48
}

/// Maps the firmware object read-only and returns its bytes.
fn map_firmware(handle: u32) -> Result<&'static [u8], u64> {
    let args = MemoryMapArgs {
        size: MemoryMapArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        memory: HandleRef::new(handle),
        // **Read only, and it could not be otherwise**: the kernel installed
        // this object without `WRITE`, so asking for it would be refused. A
        // driver that could edit its firmware would make the digest in the
        // provenance record describe bytes that no longer exist.
        rights: MapRights(MapRights::READ.bits()),
        vaddr: FIRMWARE_VA,
    };
    let mut buf = [0u8; MemoryMapArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x61, 0xe));
    }
    let mapped = syscall2(SYS_MEMORY_MAP, buf.as_ptr() as u64, 0);
    if mapped < 0 {
        return Err(fail(0x61, (-mapped) as u64));
    }
    // SAFETY: the kernel just mapped this object read-only at FIRMWARE_VA and
    // the call succeeded; the object is a whole page, nothing else in this
    // program references the range, and it stays mapped for this program's
    // life.
    Ok(unsafe { core::slice::from_raw_parts(FIRMWARE_VA as *const u8, FIRMWARE_MAX) })
}

/// Asks the kernel for firmware against this driver's own device handle, and
/// reports what happened as a small code: 0 if the refusal was
/// `AccessDenied` — the expected answer — and anything else otherwise, with a
/// load that *succeeded* reported as `0xff`.
fn firmware_self_load(device: u32) -> u64 {
    const ACCESS_DENIED: i64 = 8;
    let mut field = [0u8; 24];
    field[..12].copy_from_slice(b"firmware.bin");
    let report = [0u8; FirmwareReport::WIRE_SIZE];
    let args = FirmwareLoadArgs {
        size: FirmwareLoadArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        min_image_version: 1,
        name: field,
        reserved: 0,
        report_ptr: report.as_ptr() as u64,
    };
    let mut buf = [0u8; FirmwareLoadArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return 0xe;
    }
    let result = syscall2(SYS_FIRMWARE_LOAD, buf.as_ptr() as u64, 0);
    if result >= 0 {
        return 0xff;
    }
    // The ABI packs a KError into the low bits of the negative result.
    let code = (-result) & 0xffff;
    if code == ACCESS_DENIED {
        0
    } else {
        code as u64
    }
}

/// Three bind requests against one manager, packed into one word.
///
/// **The three answers have to come from one process against one manager**, or
/// they would not be comparable: what makes the second call's refusal mean
/// something is that it is the *same* manifest entry, with the same budget,
/// answering about a device one hop further down than the first. Two boots
/// would differ in more than the topology.
///
/// The layout, low to high: the first bind's status, its hop count, its
/// accumulated latency; then the second and third binds' statuses; then the
/// first bind's path throughput.
fn relay_report() -> u64 {
    let mut packed = 0u64;
    // The near block device: expected to bind, and its numbers are the ones
    // worth carrying.
    match bind_call(DeviceClass::Block) {
        Ok((reply, _)) => {
            packed |= u64::from(reply.status) & 0xff;
            packed |= (u64::from(reply.relay_hops) & 0xff) << 8;
            packed |= (reply.accumulated_latency_us & 0xffff) << 16;
            packed |= (u64::from(reply.path_throughput_mbps) & 0xffff) << 48;
        }
        Err(code) => return code,
    }
    // The far block device, behind one more hub than this driver's budget
    // allows.
    match bind_call(DeviceClass::Block) {
        Ok((reply, _)) => packed |= (u64::from(reply.status) & 0xff) << 32,
        Err(code) => return code,
    }
    // The network device, whose path is wide enough for neither.
    match bind_call(DeviceClass::Network) {
        Ok((reply, _)) => packed |= (u64::from(reply.status) & 0xff) << 40,
        Err(code) => return code,
    }
    packed
}

/// Runs as the child of a bus controller: take the queue behind it, publish a
/// request on that queue's ring, and ring that queue's doorbell.
///
/// **What this holds is the whole point.** It never sees the controller's
/// registers, never touches queue 0, and never asks another process to submit
/// on its behalf — it has one queue's rings, mapped for it because they are
/// memory the *device* reads and therefore not a child's to place, and one
/// doorbell page, which it derived from the controller capability rather than
/// being handed. A transfer from here crosses no other process
/// (`docs/drivers/01`, "Bus Topology And Data Paths").
///
/// It does not write the descriptors. Those name buffers by their
/// device-visible addresses, which is knowledge about the machine a child has
/// no way to have and no business holding; the controller forms the chain and
/// the child *publishes* it — the available-ring index is the point at which a
/// request becomes the device's, and the doorbell is what tells it so.
fn queue_child() -> Result<u64, u64> {
    // The queue behind the controller. Nothing here names a device: the index
    // selects among whatever the resource graph records as being behind the
    // capability this program was started with.
    let record = [0u8; DeviceChildRecord::WIRE_SIZE];
    let args = DeviceChildArgs {
        size: DeviceChildArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(CONTROLLER_HANDLE),
        index: 0,
        record_ptr: record.as_ptr() as u64,
    };
    let mut buf = [0u8; DeviceChildArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x20, 0xe));
    }
    let result = syscall2(SYS_DEVICE_CHILD, buf.as_ptr() as u64, 0);
    if result < 0 {
        return Err(fail(0x20, (-result) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceChildRecord::WIRE_SIZE }>(&record);
    let decoded: DeviceChildRecord = match decode(&bytes) {
        Ok(record) => record,
        Err(_) => return Err(fail(0x20, 0xd)),
    };
    if decoded.count == 0 || decoded.child == u32::MAX {
        return Err(fail(0x21, u64::from(decoded.count)));
    }

    // Its doorbell, and nothing else: the window this capability names is one
    // page, which is why a queue can be a thing a child holds at all.
    let map = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(decoded.child),
        reserved: 0,
        vaddr: layout::DEVICE_MMIO_VA,
    };
    let mut mbuf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&map, &mut mbuf).is_err() {
        return Err(fail(0x22, 0xe));
    }
    let doorbell = syscall2(SYS_MAP_DEVICE, mbuf.as_ptr() as u64, 0);
    if doorbell < 0 {
        return Err(fail(0x22, (-doorbell) as u64));
    }

    // Publish the chain the controller formed: name its head in the available
    // ring, then make the ring's index say so.
    //
    // **The index is cumulative and the ring is circular**, so where to publish
    // is read from the queue rather than assumed to be the start. This queue has
    // been used before — the controller read a sector on it during bring-up —
    // and a child that wrote slot 0 and set the index to 1 would be republishing
    // a request the device had already completed, and then waiting for a
    // completion that never comes.
    let avail = (layout::QUEUE_RING_VA + layout::QUEUE_AVAIL_OFFSET) as *mut u16;
    // SAFETY: the controller mapped this queue's ring page at `QUEUE_RING_VA`
    // before starting this program, and the available ring begins
    // `QUEUE_AVAIL_OFFSET` into it: `flags` at +0, `idx` at +2, the ring from
    // +4. Every access below is 2-byte aligned and inside the page, because the
    // slot is taken modulo the ring size.
    unsafe {
        let idx = core::ptr::read_volatile(avail.add(1));
        let slot = idx % layout::QUEUE_RING_SIZE;
        // ring[slot] = descriptor 0, the head of the chain.
        core::ptr::write_volatile(avail.add(2 + slot as usize), 0u16);
        // The index the device reads to find it. Written second, and after a
        // barrier, because it is what makes the entry above a request rather
        // than whatever was in the ring before.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(avail.add(1), idx.wrapping_add(1));
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    // And ring **its own** doorbell. A 16-bit write of the queue index, to a
    // page no other queue shares.
    // SAFETY: `doorbell` is the VA the kernel just mapped this queue's notify
    // page at, and a virtio-pci doorbell is a 16-bit register at its start.
    unsafe {
        core::ptr::write_volatile(doorbell as u64 as *mut u16, 1u16);
    }
    Ok(doorbell as u64)
}

/// Faults on purpose, in the way a real driver bug does: a load from an
/// address nothing has mapped.
///
/// Not a panic — the panic handler reports and exits cleanly, which is the
/// opposite of what a crash test wants. This has to reach the kernel as a
/// **contained CPU fault**, because that is the path the ladder's first step
/// is about, and a driver that exits tidily proves nothing about it.
fn crash() -> ! {
    // SAFETY: there is no safe way to state this, and no invariant to uphold —
    // the read is *meant* to fault. Address zero is never mapped into any
    // process this kernel builds, so the fault is a page fault at a known
    // address rather than something that might accidentally succeed.
    unsafe { core::ptr::read_volatile(core::ptr::null::<u64>()) };
    // Not reached. If it somehow is — a kernel that mapped page zero — say so
    // rather than continuing as though the crash had happened.
    syscall2(SYS_DEBUG_WRITE, fail(0xfe, 0), 0);
    syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry. `incarnation` distinguishes the driver that dies from the one that
/// replaces it; it is folded into the report so the two runs cannot be
/// mistaken for one. Its high bit ([`CRASH_AFTER_BIND`]) asks this driver to
/// die holding its device.
///
/// # Safety
///
/// The unmangled `_start` symbol is the ELF entry the linker script names and
/// the kernel loader jumps to, with the startup argument in `x0`.
#[unsafe(no_mangle)]
extern "C" fn _start(arg: u64) -> ! {
    let incarnation =
        arg & !(CRASH_AFTER_BIND | QUEUE_CHILD | RELAY_REPORT | FIRMWARE_REPORT | CONFIG_REPORT);
    if arg & CONFIG_REPORT != 0 {
        syscall2(SYS_DEBUG_WRITE, config_report(), 0);
        syscall2(SYS_PROCESS_EXIT, 0, 0);
        loop {
            core::hint::spin_loop();
        }
    }
    if arg & FIRMWARE_REPORT != 0 {
        syscall2(SYS_DEBUG_WRITE, firmware_report(), 0);
        syscall2(SYS_PROCESS_EXIT, 0, 0);
        loop {
            core::hint::spin_loop();
        }
    }
    if arg & RELAY_REPORT != 0 {
        syscall2(SYS_DEBUG_WRITE, relay_report(), 0);
        syscall2(SYS_PROCESS_EXIT, 0, 0);
        loop {
            core::hint::spin_loop();
        }
    }
    if arg & QUEUE_CHILD != 0 {
        let report = match queue_child() {
            Ok(doorbell) => doorbell,
            Err(code) => code,
        };
        syscall2(SYS_DEBUG_WRITE, report, 0);
        syscall2(SYS_PROCESS_EXIT, 0, 0);
        loop {
            core::hint::spin_loop();
        }
    }
    if arg & CRASH_AFTER_BIND != 0 {
        // Bind first: the point is to die *holding* something.
        match bind() {
            Ok(_) => crash(),
            // Never got the device, so crashing would test the wrong thing.
            // Report instead, and let the supervisor's own count fail.
            Err(code) => {
                syscall2(SYS_DEBUG_WRITE, code, 0);
                syscall2(SYS_PROCESS_EXIT, 1, 0);
                loop {
                    core::hint::spin_loop();
                }
            }
        }
    }
    let report = match bind().and_then(|device| {
        // The driver's own two states, declared as they are reached. Probing
        // starts the moment this program has the capability and is about to
        // touch the device.
        declare(
            device,
            DriverState::Starting,
            DriverState::Probing,
            TransitionReason::Launched,
        );
        match identity_and_layout(device)? {
            // A device the kernel enumerated: take the DMA a driver of it would
            // need, read a word from beyond its first page to show the whole
            // window arrived, **and reach its common configuration structure at
            // the offset the kernel reported** — which is the thing a driver
            // holding only a window could not do.
            Some((pci, structures)) => dma(device).and_then(|_| {
                far_word(device).and_then(|far| {
                    let report = pci | (far << 32);
                    match structures {
                        // The offsets arrived, so use them. `far_word` has already
                        // mapped the window, so this is the same mapping seen from
                        // the address the kernel named.
                        Some((common, _notify)) => {
                            let seen = common_config_probe(layout::DEVICE_MMIO_VA, common);
                            // The selector reads back what was written: 1 then 0.
                            if seen == (1u64 << 8) {
                                Ok(report)
                            } else {
                                Err(fail(0x59, seen))
                            }
                        }
                        // The kernel resolved no layout for this device, so there
                        // is nothing to reach and nothing to claim. Reported as it
                        // stands rather than treated as a failure: a transport
                        // whose register layout is fixed needs no discovery.
                        None => Ok(report),
                    }
                })
            }),
            // A device that identifies itself: drive it, as before.
            None => probe(device)
                .map(|magic| u64::from(magic).rotate_left((incarnation as u32 % 64) * 8)),
        }
        .inspect(|_| {
            // The device answered, so it is what the match said it was. That
            // is the whole content of `Probing -> Active`, and it is declared
            // only on the success path — a probe that failed leaves the device
            // in Probing for the manager to find, which is exactly the state
            // that says "a driver was given this and could not confirm it".
            declare(
                device,
                DriverState::Probing,
                DriverState::Active,
                TransitionReason::ProbeSucceeded,
            );
        })
    }) {
        Ok(report) => report,
        Err(code) => code,
    };
    syscall2(SYS_DEBUG_WRITE, report, 0);
    syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    syscall2(SYS_DEBUG_WRITE, fail(0xff, 0), 0);
    syscall2(SYS_PROCESS_EXIT, 1, 0);
    loop {
        core::hint::spin_loop();
    }
}
