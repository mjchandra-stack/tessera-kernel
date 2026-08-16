// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 device manager: the piece that decides which driver gets which
//! device.
//!
//! # What this changes
//!
//! Before this program, a driver knew its device by a compiled-in handle
//! number — `BLK_DEVICE_HANDLE = 0` — that the boot glue happened to install
//! in that slot. That is not binding; it is a constant shared between two
//! files, and it fails the moment the machine has its devices in a different
//! order, or two of a kind, or one fewer than expected. The driver was not
//! bound to a device, it was bound to a *convention*.
//!
//! Now boot grants **this** program a capability to every device it
//! discovered and nothing else grants any driver anything. A driver names a
//! class over a channel and is handed a capability to some device of that
//! class — or told there is none. It never learns a device's address, its
//! interrupt, or its position in the machine, because it does not need to:
//! all three live inside the capability, and the kernel reads them from there
//! when the driver maps it.
//!
//! # Enumeration is why this is a program and not a table
//!
//! The manager classifies devices by **probing** them: every virtio-mmio
//! transport on this machine has the same device-tree `compatible` string,
//! and what kind of device it is lives in a register (`device_id` at offset
//! 8). So the manager maps each device it was granted, reads two registers,
//! and records what it found. There is no way to learn this without touching
//! the device, on this bus or on PCIe, which is why enumeration is a job for
//! something holding capabilities rather than a constant in a header.
//!
//! To classify a device the manager must map it, which would leave this
//! program more privileged than the design wants — it has mapped every
//! device's registers — except that the kernel takes the mapping back. A
//! capability transferred out of a handle table takes its register window
//! with it, so the probe mappings made here are gone the moment each device
//! is handed on. Nothing in this program does the revoking, and nothing in it
//! could decline to.
//!
//! # Exclusivity is not a flag
//!
//! Nothing here marks a device "bound". A handle transferred in a reply is
//! removed from this program's table by the kernel, so a device can be handed
//! out exactly once; a second request for the same class finds the next
//! unbound device or fails. The framework's one-driver-per-device rule is a
//! property of capability conservation, and this program could not violate it
//! if it tried.
//!
//! Normative: docs/hardware/03-component-interaction-model.md,
//! docs/api/01-system-call-interface.md,
//! docs/kernel/02-scheduling-memory-ipc.md ("Channels")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use channel_msg::{ChannelMsgArgs, HandleTransfer, TransferMode};
use device_abi::{
    DeviceBusKind, DeviceChildArgs, DeviceChildRecord, DeviceInfoArgs, DeviceInfoKind,
    DeviceInfoRecord, MapDeviceArgs,
};
use driver_bind::{BindReply, BindRequest, DeviceClass};
use driver_lifecycle::{DriverState, LifecycleTransitionArgs, ServiceNotice, TransitionReason};
use handle_abi::Rights;
use tessera_binding::{
    BIND_FLAG_PATH_INCOMPLETE, BusKind, DeviceFacts, Hop, ManifestEntry, Refusal, RelayCost,
    SystemPolicy, hop_for, product_policy, required_service, select,
};
use tessera_isl_runtime::{HandleRef, decode, encode};
use tessera_uabi::{fail, layout, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 13;
/// **Continue**, not plain `ChannelReply`. `reply` hands off to the caller and
/// leaves the replier Blocked, which is correct only for a server whose next
/// wake is the next call on that same endpoint — because `call` wakes a peer
/// only if it registered itself with `receive`. A server that replies and then
/// loops back to `recv` is Blocked without being a registered receiver, so the
/// *second* request deadlocks: the caller finds no waiting receiver and blocks
/// too, and neither side ever runs again. `ChannelReplyContinue` enqueues the
/// reply, unblocks the caller, and leaves this program runnable to reach its
/// own `recv`.
const SYS_CHANNEL_REPLY_CONTINUE: u64 = 27;
const SYS_MAP_DEVICE: u64 = 23;
/// Ask the kernel what a held device is. Needed because a PCI function's class
/// lives in config space, which is not per-device and so cannot be delegated —
/// the kernel read it while enumerating and this is how a holder gets it
/// (build/README.md, D114).
const SYS_DEVICE_INFO: u64 = 28;
const SYS_DEVICE_CHILD: u64 = 35;
/// Record a driver-lifecycle transition for a device this program holds. The
/// syscall that makes `docs/drivers/01`'s "transitions are observable through
/// structured events" true of this system rather than of its documentation.
const SYS_DRIVER_LIFECYCLE: u64 = 29;

/// The service endpoint boot installs first, so it is always handle 0. Device
/// capabilities follow at 1..=count, and the count arrives as this program's
/// startup argument — the whole of its bootstrap contract with boot.
const SERVICE_ENDPOINT_HANDLE: u64 = 0;
const FIRST_DEVICE_HANDLE: u32 = 1;

/// Most devices this manager will enumerate. The `virt` machine lays out 32
/// virtio-mmio transports; boot grants only the ones it found populated.
const MAX_DEVICES: usize = 8;

/// PCI class codes this manager maps onto a driver-facing class. The class
/// byte is the top of a PCI class code and is exactly the question
/// `driver_bind.isl`'s `DeviceClass` asks.
const PCI_CLASS_MASS_STORAGE: u32 = 0x01;
const PCI_CLASS_NETWORK: u32 = 0x02;
/// A PCI-to-PCI bridge — a root port, a switch port. `docs/drivers/01`'s bus
/// controller, and the thing a device's path is made of.
const PCI_CLASS_BRIDGE: u32 = 0x06;

/// The deepest chain of ancestors this manager walks, and therefore the deepest
/// path it can account for.
///
/// A machine with more than this between a device and the root is one whose
/// data-path costs this program cannot add up, and it says so rather than
/// enumerating a subset — a partial inventory looks exactly like a small
/// machine.
const MAX_RELAY_DEPTH: usize = 4;

/// **The binding manifest**: the policy data this manager matches a device's
/// facts against.
///
/// What used to be here was a class map — two arms of a `match`, one per
/// class, deciding everything. That is a lookup and not a binding decision,
/// and the difference shows the moment a machine has two devices of one class
/// that must not run the same driver, a driver whose signature nobody trusts,
/// or a device whose firmware is too old for the driver that would otherwise
/// claim it. `docs/drivers/01` lists ten binding inputs; a class map can
/// express one.
///
/// Compiled in, for now. A manifest is *data* — that is the point of it — and
/// the thing that should deliver it is a configuration service reading a
/// signed package, which needs a filesystem this system does not have yet. An
/// array here is the honest interim: the manager consults a manifest rather
/// than deciding for itself, and where the manifest comes from is one
/// substitution away.
/// The power domains this manifest places devices in, and the identifier a
/// driver votes on.
///
/// **Zero used to be the answer for every entry**, which made the field
/// decorative: one domain is the same as no domains, and a driver told which
/// one it was in learned nothing. Two entries is the smallest number that
/// makes the field mean something — the block device and the network device
/// can be powered down independently, which is exactly what a domain is.
///
/// The value crosses to the power manager in `BindReply.power_domain`, and a
/// voter names it rather than naming a kernel object id it has no business
/// holding (`power_manager.isl`).
const BLOCK_POWER_DOMAIN: u32 = 1;
const NETWORK_POWER_DOMAIN: u32 = 2;

/// Red Hat, the vendor of every bus QEMU presents.
const REDHAT_VENDOR: u16 = 0x1b36;
/// The `pcie-root-port` this machine puts a device behind.
const PCIE_ROOT_PORT_PRODUCT: u16 = 0x000c;
/// The two relaying hubs whose costs the boot check accumulates.
const RELAY_HUB_NEAR_PRODUCT: u16 = 0x0001;
const RELAY_HUB_FAR_PRODUCT: u16 = 0x0002;

/// What a block driver's data path may cost it.
///
/// A number with a reason: `docs/architecture/03`'s storage budgets are stated
/// for a direct-attached device, so an entry that tolerated any depth would be
/// promising a budget it cannot keep behind a hub. The value is deliberately
/// between one hub's declared cost and two, which is what makes the same entry
/// bind the same device one hop up and refuse it two hops down.
const BLOCK_MAX_PATH_LATENCY_US: u64 = 30;

const MANIFEST: [ManifestEntry; 6] = [
    // The block driver. Specific to virtio's vendor id, so a mass-storage
    // controller from anyone else falls through to the general entry below
    // rather than being handed a driver that speaks the wrong transport.
    ManifestEntry {
        class: DeviceClass::Block as u32,
        vendor: Some(VIRTIO_VENDOR),
        product: None,
        min_revision: None,
        bus: None,
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: BLOCK_POWER_DOMAIN,
        driver_signature: BLK_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED | product_policy::EARLY_BOOT,
        relay: None,
        max_latency_us: Some(BLOCK_MAX_PATH_LATENCY_US),
        min_throughput_mbps: None,
        required_services: required_service::LOGGING | required_service::POWER,
        update_channel: UPDATE_CHANNEL_BASE,
    },
    // The network driver.
    ManifestEntry {
        class: DeviceClass::Network as u32,
        vendor: Some(VIRTIO_VENDOR),
        product: None,
        min_revision: None,
        bus: None,
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: NETWORK_POWER_DOMAIN,
        driver_signature: NET_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED,
        relay: None,
        // A network driver's budget is throughput before latency — a line-rate
        // path that adds a few microseconds is fine and a narrow one is not,
        // which is why the two dimensions are separate requirements and not one
        // score.
        max_latency_us: Some(100),
        min_throughput_mbps: Some(800),
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
    },
    // A general block entry for anything else that presents as mass storage.
    // Less specific than the first, so it is chosen only when the first does
    // not claim the device — never because the first was refused, which would
    // be a downgrade nobody asked for (`tessera_binding::select`).
    ManifestEntry {
        class: DeviceClass::Block as u32,
        vendor: None,
        product: None,
        min_revision: None,
        bus: None,
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: BLOCK_POWER_DOMAIN,
        driver_signature: BLK_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED,
        relay: None,
        max_latency_us: Some(BLOCK_MAX_PATH_LATENCY_US),
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
    },
    // --- The buses, which nothing binds and everything behind them pays for ---
    //
    // These entries exist to be read by `hop_for` rather than by `select`: they
    // say what a transfer passing through each hub costs. `docs/drivers/01`
    // makes that a property of the *class contract*, so the manifest is where
    // it belongs — and a hub nobody described is refused rather than assumed
    // free, which is why these are specific and there is no catch-all.
    //
    // **The root port relays nothing.** A `pcie-root-port` gives each function
    // behind it its own configuration and its own BARs; the endpoint's queues
    // are mapped straight to its driver and the transfer crosses no extra
    // process. That is `docs/drivers/01`'s first bullet, and declaring a cost
    // here would be asserting a price nothing pays.
    ManifestEntry {
        class: DeviceClass::Bus as u32,
        vendor: Some(REDHAT_VENDOR),
        product: Some(PCIE_ROOT_PORT_PRODUCT),
        min_revision: None,
        bus: None,
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: BLOCK_POWER_DOMAIN,
        driver_signature: BLK_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED,
        relay: None,
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
    },
    // A PCI-to-PCI bridge does relay: everything behind it is forwarded by the
    // host that drives it, and both numbers below are that host's declaration.
    ManifestEntry {
        class: DeviceClass::Bus as u32,
        vendor: Some(REDHAT_VENDOR),
        product: Some(RELAY_HUB_NEAR_PRODUCT),
        min_revision: None,
        bus: None,
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: BLOCK_POWER_DOMAIN,
        driver_signature: BLK_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED,
        relay: Some(RelayCost {
            added_latency_us: 10,
            throughput_mbps: Some(1000),
        }),
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
    },
    // A second bridge, costlier and narrower than the first — so a path through
    // both has a sum that is not a doubling and a minimum that is not the last
    // hop, and neither number could be produced by accident.
    ManifestEntry {
        class: DeviceClass::Bus as u32,
        vendor: Some(REDHAT_VENDOR),
        product: Some(RELAY_HUB_FAR_PRODUCT),
        min_revision: None,
        bus: None,
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: BLOCK_POWER_DOMAIN,
        driver_signature: BLK_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED,
        relay: Some(RelayCost {
            added_latency_us: 25,
            throughput_mbps: Some(500),
        }),
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
    },
];

/// What this installation permits, against which a manifest entry is itself
/// checked. A manifest is a claim about a driver; this is the operator's
/// answer to it, and an entry that satisfies its own claims can still be
/// refused.
const POLICY: SystemPolicy = SystemPolicy {
    trusted_signatures: &[BLK_DRIVER_SIGNATURE, NET_DRIVER_SIGNATURE],
    // Signatures are required. The drivers here are part of the system image
    // and their signatures are constants rather than verified cryptography —
    // recorded as a deviation rather than dressed up, because a signature
    // nobody checks is a field and not a control.
    allow_unsigned: false,
    permitted_domains: &[DRIVER_DOMAIN],
    min_contract_version: 1,
    // The devices this manager binds are brought up after the system is
    // running, so the early-boot gate is not the one being exercised here.
    early_boot: false,
    // **On here, and this is a deliberately narrow claim.** It is on because
    // this manager is the one demonstrating the mechanism, and the boot check
    // that proves a budget can refuse a device two hubs down needs it on.
    //
    // An installation whose buses all give per-child separation — which is
    // every machine this system boots today, PCIe giving each function its own
    // queues — should set it false. Nothing then refuses on a path, the figures
    // are still reported, and no device can be stranded by a budget against a
    // cost nothing has yet measured. Turning it on belongs with the arrival of
    // a bus where transfers really do relay through a host.
    enforce_path_budgets: true,
};

/// The virtio vendor id, which every device on these machines carries.
const VIRTIO_VENDOR: u16 = 0x1af4;
/// The security domain the framework's drivers run in.
const DRIVER_DOMAIN: u32 = 1;
/// The signatures over the two driver images in the system image.
const BLK_DRIVER_SIGNATURE: u64 = 0x7465_7373_6572_6100;
const NET_DRIVER_SIGNATURE: u64 = 0x7465_7373_6572_6101;
/// The update channel the base system's drivers are delivered through.
const UPDATE_CHANNEL_BASE: u32 = 1;

/// virtio-mmio register offsets and the values that identify a transport.
const REG_MAGIC: usize = 0x000;
const REG_DEVICE_ID: usize = 0x008;
const VIRTIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_ID_NET: u32 = 1;
const VIRTIO_ID_BLOCK: u32 = 2;

/// Reports `code` and ends this process. Never returns.
fn die(code: u64) -> ! {
    syscall2(SYS_DEBUG_WRITE, code, 0);
    syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Reads a device register the manager mapped for probing.
fn read_register(base: u64, offset: usize) -> u32 {
    // SAFETY: `base` is a register base MapDevice granted, and both offsets
    // used here are inside the virtio-mmio header the capability covers.
    unsafe { ((base as usize + offset) as *const u32).read_volatile() }
}

/// Maps the device named by `handle` so its identifying registers can be read.
fn map_device(handle: u32, vaddr: u64) -> Result<u64, u64> {
    let args = MapDeviceArgs {
        size: MapDeviceArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        reserved: 0,
        vaddr,
    };
    let mut buf = [0u8; MapDeviceArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x01, 0xe));
    }
    let base = syscall2(SYS_MAP_DEVICE, buf.as_ptr() as u64, 0);
    if base < 0 {
        return Err(fail(0x01, (-base) as u64));
    }
    Ok(base as u64)
}

/// The states a device can be in while a driver is holding it.
///
/// The manager hands a capability away and stops being able to narrate the
/// lifecycle — a transition needs `Rights::MAP` on a *held* handle — so when a
/// device comes back it does not know how far its driver got before it
/// stopped. The kernel does, and refuses any transition that disagrees, so
/// walking these in order and keeping the one that is accepted is how the
/// manager finds out.
///
/// Ordered most-likely first: a driver that ran long enough to be returned
/// almost always reached `Active`. This is deliberately a probe rather than a
/// guess — every wrong attempt is refused and records nothing, and the one
/// that lands is by construction the device's real state.
const BOUND_STATES: [DriverState; 4] = [
    DriverState::Active,
    DriverState::Probing,
    DriverState::Starting,
    DriverState::Suspended,
];

/// A device this manager holds a capability to, and what probing said it is.
#[derive(Clone, Copy)]
struct Device {
    handle: u32,
    /// Where this device's registers are mapped while it is held. The window
    /// is revoked by the kernel when the capability is handed on, so a
    /// returned device is re-probed at the same address it used before.
    probe_va: u64,
    class: DeviceClass,
    /// What enumeration observed about this device — the binding inputs a
    /// manager cannot choose and a device cannot either.
    vendor: u16,
    product: u16,
    revision: u8,
    bus: BusKind,
    /// Cleared once the capability has been transferred to a driver. Tracked
    /// only so the manager can skip it without asking the kernel; the kernel's
    /// `take` is what actually makes the transfer exclusive.
    held: bool,
    /// Whether this device has been bound before.
    ///
    /// It decides where the lifecycle resumes. A device nobody has driven
    /// opens at `Discovered`; one that came back from a driver that stopped is
    /// `Degraded`, and rebinding it is `Degraded -> Starting` rather than a
    /// second discovery of hardware that never went anywhere.
    bound_before: bool,
    /// What the ancestors between this device and the granted root declared,
    /// nearest first — the device's **path**, valid to `path_len`.
    ///
    /// Recorded at enumeration rather than computed at bind time, because it is
    /// what the walk found: the chain a request travels is a fact about where
    /// the device sits, and asking again later would be asking a graph that may
    /// have changed under a device already classified.
    path: [Hop; MAX_RELAY_DEPTH],
    path_len: usize,
}

/// A device the walk found, and the ancestors it passed through to reach it.
#[derive(Clone, Copy)]
struct Discovered {
    handle: u32,
    ancestors: [u32; MAX_RELAY_DEPTH],
    depth: usize,
}

/// Declares that `handle`'s device moved from `from` to `to`.
///
/// Returns whether the kernel accepted it. A refusal is not fatal here: the
/// kernel refuses transitions that contradict the history it holds, and the
/// manager uses exactly that to find out what it does not know
/// ([`BOUND_STATES`]). What must never happen is the manager carrying on as
/// though a refused transition had been recorded, which is why every caller
/// looks at this.
fn declare(handle: u32, from: DriverState, to: DriverState, reason: TransitionReason) -> bool {
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
    if encode(&args, &mut buf).is_err() {
        return false;
    }
    syscall2(SYS_DRIVER_LIFECYCLE, buf.as_ptr() as u64, 0) >= 0
}

/// Marks a returned device degraded — ladder step 2, *"the device manager
/// marks the device degraded"*.
///
/// **A device the manager did not ask for is a device whose driver stopped
/// without saying so.** Nothing in the bind protocol returns a capability; the
/// only thing that does is the kernel, reclaiming from a process that is gone.
/// So an arrival here is always a driver that ended without handing its device
/// back, which is a degradation whether it crashed or merely exited.
///
/// Returns the state the device turned out to be in, or `None` if the kernel
/// accepted no transition at all — which would mean the manager and the kernel
/// disagree about a device more fundamentally than this can repair, and the
/// caller must not proceed as though it had been marked.
fn mark_degraded(handle: u32) -> Option<DriverState> {
    for from in BOUND_STATES {
        if declare(
            handle,
            from,
            DriverState::Degraded,
            TransitionReason::DriverCrashed,
        ) {
            return Some(from);
        }
    }
    None
}

/// Encodes a `ChannelMsgArgs` describing the message buffer, optionally
/// carrying one handle to transfer.
fn channel_args(
    buf_ptr: u64,
    buf_len: u64,
    handle_ptr: u64,
    handle_count: u64,
    installed_ptr: u64,
    installed_cap: u64,
) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: 0,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: buf_len,
        handles_ptr: handle_ptr,
        handle_count,
        installed_ptr,
        installed_cap,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0x07, 0xe)),
    }
}

/// Asks the kernel what a device is. `Ok(None)` means the kernel holds no
/// normalized identity for it — an answer, not a failure, and the caller's
/// response is to ask the device itself.
fn device_identity(handle: u32) -> Result<Option<DeviceInfoRecord>, u64> {
    let record = [0u8; DeviceInfoRecord::WIRE_SIZE];
    let args = DeviceInfoArgs {
        size: DeviceInfoArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        reserved: 0,
        record_ptr: record.as_ptr() as u64,
    };
    let mut buf = [0u8; DeviceInfoArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x09, 0xe));
    }
    let result = syscall2(SYS_DEVICE_INFO, buf.as_ptr() as u64, 0);
    if result < 0 {
        return Err(fail(0x09, (-result) as u64));
    }
    let bytes = read_kernel_filled::<{ DeviceInfoRecord::WIRE_SIZE }>(&record);
    let decoded: DeviceInfoRecord = match decode(&bytes) {
        Ok(record) => record,
        Err(_) => return Err(fail(0x09, 0xd)),
    };
    match decoded.kind {
        DeviceInfoKind::Unknown => Ok(None),
        DeviceInfoKind::Pci => Ok(Some(decoded)),
    }
}

/// The handle the kernel reports when it installed none.
const HANDLE_NOT_INSTALLED: u32 = u32::MAX;

/// Asks `handle` for the device at `index` behind it.
///
/// Returns `(children, derived handle)`. A handle that is not a bus answers
/// zero children — an answer, not a failure, and the same answer a bus with
/// nothing plugged into it gives. A handle the manager was not given `DERIVE`
/// on is refused, which is also not a failure here: it means this is a device
/// the manager holds directly rather than a bus it is expected to walk.
fn device_child(handle: u32, index: u32) -> Result<(u32, u32), u64> {
    let record = [0u8; DeviceChildRecord::WIRE_SIZE];
    let args = DeviceChildArgs {
        size: DeviceChildArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(handle),
        index,
        record_ptr: record.as_ptr() as u64,
    };
    let mut buf = [0u8; DeviceChildArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return Err(fail(0x0a, 0xe));
    }
    let result = syscall2(SYS_DEVICE_CHILD, buf.as_ptr() as u64, 0);
    if result < 0 {
        // AccessDenied — no DERIVE on this handle, so it is not a bus this
        // manager is meant to walk. Reported as "no children" rather than as an
        // error, because that is what it means for the inventory.
        return Ok((0, HANDLE_NOT_INSTALLED));
    }
    let bytes = read_kernel_filled::<{ DeviceChildRecord::WIRE_SIZE }>(&record);
    let decoded: DeviceChildRecord = match decode(&bytes) {
        Ok(record) => record,
        Err(_) => return Err(fail(0x0a, 0xd)),
    };
    Ok((decoded.count, decoded.child))
}

/// Turns one granted handle into the devices behind it, **and the path to each**.
///
/// **This is what makes the manager a bus controller's manager.** It is granted
/// a capability and asks the graph what is behind it: a bus expands into the
/// devices on it, and a device stands for itself. Nothing tells it which kind
/// it was given — `docs/drivers/01`'s bus controllers are drivers whose
/// children are drivers, and the whole point is that the same program works
/// either way.
///
/// It used to expand exactly one level, which made a device two buses down
/// invisible and left the manager with no notion of depth at all. Now it
/// descends, carrying the ancestors it passed through — and that chain *is* the
/// data path, obtained from the graph's own parent edges rather than from a
/// topology somebody described.
///
/// Bounded by `out`, because a bus with more devices than the inventory can
/// hold is a real machine and not an error; the ones that fit are recorded and
/// the rest are simply not, which the count reports.
fn expand_bus(
    handle: u32,
    ancestors: [u32; MAX_RELAY_DEPTH],
    depth: usize,
    out: &mut [Option<Discovered>],
    found: &mut usize,
) -> Result<(), u64> {
    if *found == out.len() {
        return Ok(());
    }
    let (count, first) = device_child(handle, 0)?;
    if count == 0 || first == HANDLE_NOT_INSTALLED {
        // A leaf: it stands for itself, and the chain that reached it is its
        // path.
        out[*found] = Some(Discovered {
            handle,
            ancestors,
            depth,
        });
        *found += 1;
        return Ok(());
    }

    // A bus, so it is an ancestor of everything below it. A chain deeper than
    // this manager walks is refused outright rather than truncated: a truncated
    // walk would leave the devices past the limit out of the inventory, and a
    // machine missing half its hardware is indistinguishable from a small one.
    if depth == MAX_RELAY_DEPTH {
        return Err(fail(0x0c, depth as u64));
    }
    let mut below = ancestors;
    below[depth] = handle;

    for index in 0..count {
        if *found == out.len() {
            break;
        }
        let child = if index == 0 {
            first
        } else {
            let (_, child) = device_child(handle, index)?;
            if child == HANDLE_NOT_INSTALLED {
                continue;
            }
            child
        };
        expand_bus(child, below, depth + 1, out, found)?;
    }
    Ok(())
}

/// What the manifest says about one ancestor on a device's path.
///
/// An ancestor the **kernel** cannot identify is [`Hop::Undeclared`], not
/// `Separated`. There is no second route here of the kind a leaf device has:
/// classifying by mapping means reading the bus's own registers, and a bus is
/// granted without `Rights::MAP` precisely so that nobody does. So an
/// unidentifiable hub is one whose cost is unknown, and it says so.
fn hop_of(handle: u32) -> Result<Hop, u64> {
    let Some(record) = device_identity(handle)? else {
        return Ok(Hop::Undeclared);
    };
    let class = match record.class_code >> 16 {
        PCI_CLASS_BRIDGE => DeviceClass::Bus,
        PCI_CLASS_MASS_STORAGE => DeviceClass::Block,
        PCI_CLASS_NETWORK => DeviceClass::Network,
        _ => DeviceClass::Unknown,
    };
    Ok(hop_for(
        &MANIFEST,
        &DeviceFacts {
            class: class as u32,
            vendor: record.vendor as u16,
            product: record.device as u16,
            revision: record.revision as u8,
            bus: bus_kind(record.bus),
            firmware_version: 0,
        },
    ))
}

/// The manager's `BusKind` for what the kernel recorded.
fn bus_kind(bus: DeviceBusKind) -> BusKind {
    match bus {
        DeviceBusKind::Pci => BusKind::Pci,
        DeviceBusKind::VirtioMmio => BusKind::VirtioMmio,
        DeviceBusKind::Platform => BusKind::Platform,
        DeviceBusKind::Unknown => BusKind::Unknown,
    }
}

/// Probes every granted device and records what it is.
fn enumerate(count: usize) -> Result<[Option<Device>; MAX_DEVICES], u64> {
    let mut devices = [None; MAX_DEVICES];

    // **What was granted is not necessarily what is driven.** Each granted
    // handle is either a device or a bus; a bus expands into the devices behind
    // it, which the manager obtains from the kernel rather than from anybody's
    // list.
    let mut discovered = [None; MAX_DEVICES];
    let mut total = 0usize;
    for index in 0..count {
        if total == discovered.len() {
            break;
        }
        let granted = FIRST_DEVICE_HANDLE + index as u32;
        expand_bus(
            granted,
            [0; MAX_RELAY_DEPTH],
            0,
            &mut discovered,
            &mut total,
        )?;
    }

    for (index, slot) in devices.iter_mut().enumerate().take(total) {
        let Some(found) = discovered[index] else {
            continue;
        };
        let handle = found.handle;
        let probe_va = layout::PROBE_WINDOW_BASE + index as u64 * layout::PROBE_WINDOW_STRIDE;

        // **What the path to this device costs**, asked of the manifest once
        // per ancestor the walk actually passed through. A device on the root
        // has none, which is the honest zero rather than an unfilled field.
        let mut path = [Hop::Separated; MAX_RELAY_DEPTH];
        for (slot, ancestor) in path.iter_mut().zip(&found.ancestors[..found.depth]) {
            *slot = hop_of(*ancestor)?;
        }

        // Ask the kernel first. A device on a bus whose identity is not in the
        // device's own registers — PCI — can only be classified from what the
        // kernel read while enumerating; mapping it and reading offset 8 would
        // find whatever that BAR happens to expose, not a class.
        // The facts a manifest is matched against, filled in by whichever
        // route classified the device. A device nothing was learned about
        // keeps the defaults, which no entry naming a bus can claim.
        let (mut vendor, mut product, mut revision, mut bus) = (0u16, 0u16, 0u8, BusKind::Unknown);
        let class = match device_identity(handle)? {
            Some(record) => {
                vendor = record.vendor as u16;
                product = record.device as u16;
                revision = record.revision as u8;
                bus = bus_kind(record.bus);
                match record.class_code >> 16 {
                    PCI_CLASS_MASS_STORAGE => DeviceClass::Block,
                    PCI_CLASS_NETWORK => DeviceClass::Network,
                    // A bus with nothing behind it that the graph would name.
                    // Classified rather than left unknown, because the manifest
                    // has something to say about a hub even when nothing binds
                    // one.
                    PCI_CLASS_BRIDGE => DeviceClass::Bus,
                    _ => DeviceClass::Unknown,
                }
            }
            // The kernel has no identity for it, so the device has one: map it
            // and read the transport's own registers, as every virtio-mmio
            // device is classified.
            None => {
                let base = map_device(handle, probe_va)?;
                // A transport that does not identify itself is not something to
                // guess about: report rather than record a class nobody verified.
                let magic = read_register(base, REG_MAGIC);
                if magic != VIRTIO_MAGIC {
                    return Err(fail(0x02, u64::from(magic & 0xffff)));
                }
                // A virtio-mmio transport is on a bus the kernel did not
                // enumerate, and it carries virtio's vendor id by definition —
                // it is what the magic just confirmed.
                vendor = VIRTIO_VENDOR;
                bus = BusKind::VirtioMmio;
                match read_register(base, REG_DEVICE_ID) {
                    VIRTIO_ID_BLOCK => DeviceClass::Block,
                    VIRTIO_ID_NET => DeviceClass::Network,
                    // A device the manager cannot classify is still recorded —
                    // it is real, it is held, and it is simply never matched.
                    // Dropping it silently would make the inventory a lie.
                    _ => DeviceClass::Unknown,
                }
            }
        };
        *slot = Some(Device {
            handle,
            probe_va,
            class,
            vendor,
            product,
            revision,
            bus,
            held: true,
            bound_before: false,
            path,
            path_len: found.depth,
        });
    }
    Ok(devices)
}

/// Serves bind requests until the process is reaped. Never returns normally.
fn serve(devices: &mut [Option<Device>; MAX_DEVICES]) -> ! {
    // One buffer serves as both the request destination and the reply source
    // — the symmetric call-buffer convention the block protocol uses.
    // Serves as request destination and reply source. Sized for the largest of
    // the three things that cross it: a `BindRequest` in, a `ServiceNotice`
    // in, and a `BindReply` out — the reply is the biggest, because binding
    // produces outputs and they all travel in it.
    let mut message = [0u8; 64];
    // The capability to hand out travels in its own vector, never in the
    // payload bytes (docs/api/03, "Wire Format"). Each entry says which handle
    // to move *and* the rights it is to arrive with.
    let mut transfer = [0u8; HandleTransfer::WIRE_SIZE];
    // Where the kernel reports the handles it installed on a receive. A
    // separate buffer from the one above, because the two directions are not
    // symmetric: outbound is a request carrying rights, inbound is the kernel
    // answering "which numbers did these land on".
    let mut installed = [0u32; 1];

    loop {
        // If this request carries a capability, the kernel writes back the
        // handle it installed. Without that the number could not be known —
        // `take` bumps the generation of the slot it vacates, so a device
        // coming back to this table arrives with a different handle value than
        // it left with, and any remembered number is stale by construction.
        installed[0] = 0;
        let args = match channel_args(
            message.as_ptr() as u64,
            message.len() as u64,
            // Nothing is transferred *out* on a receive; the vector below is
            // where the kernel reports what came in.
            0,
            0,
            installed.as_ptr() as u64,
            1,
        ) {
            Ok(args) => args,
            Err(code) => die(code),
        };
        let received = syscall2(
            SYS_CHANNEL_RECV,
            args.as_ptr() as u64,
            SERVICE_ENDPOINT_HANDLE,
        );
        if received < 0 {
            die(fail(0x03, (-received) as u64));
        }

        // SAFETY: the kernel wrote this slot while installing any transferred
        // capability during the recv above; volatile only forbids the compiler
        // from assuming the zero it stored is still there.
        let returned = unsafe { core::ptr::read_volatile(&installed[0]) };

        // A return, rather than an acquisition. The capability is already in
        // this program's table — the kernel installed it out of the message's
        // handle vector before this code ran — so the work is to find *which*
        // record it belongs to and make it available again.
        //
        // Which handle it landed on is not reported anywhere, so it is
        // deduced: the kernel installs at the lowest free slot, and the slots
        // this program has freed are exactly the ones it gave away. The lowest
        // handle among the records currently not held is therefore where the
        // return arrived. That deduction is sound only because this program is
        // the sole owner of its own table, and it is the same handle-discovery
        // gap the framework already carries — a returned handle should name
        // itself rather than be inferred from an allocation policy.
        // A message that carried a capability *is* a return — the kernel
        // reports the handle it installed, and nothing else in this protocol
        // hands this program a device. That is a stronger discriminator than a
        // flag in the body: a body can be forged by any sender, an installed
        // capability cannot. It also lets the **kernel** return a dead
        // driver's devices without knowing this protocol at all, which is
        // exactly what makes reclaim-on-death possible.
        if returned != 0 {
            let reclaimed = devices.iter_mut().flatten().find(|device| !device.held);
            match reclaimed {
                Some(device) => {
                    device.handle = returned;
                    // Re-probe rather than trust the old classification: the
                    // window was revoked when the capability left, so this both
                    // re-establishes the mapping and re-verifies that what came
                    // back is the device that went out.
                    // Re-verify the same way it was classified in the first
                    // place. A device the kernel enumerated has no magic in
                    // its BAR to check, so asking the kernel again is both the
                    // available check and the right one — it confirms the
                    // capability still names a device the graph describes.
                    let known = match device_identity(device.handle) {
                        Ok(known) => known,
                        Err(code) => die(code),
                    };
                    match known {
                        Some(_) => device.held = true,
                        None => match map_device(device.handle, device.probe_va) {
                            Ok(base) if read_register(base, REG_MAGIC) == VIRTIO_MAGIC => {
                                device.held = true;
                            }
                            // Something came back that is not what left.
                            _ => die(fail(0x08, 0x1)),
                        },
                    }
                    // Ladder step 2. Done after re-verifying, not before: a
                    // device that came back as something else is not a
                    // degraded device, it is a capability the manager should
                    // not have accepted, and marking it first would put a
                    // lifecycle record on hardware nobody has identified.
                    if mark_degraded(device.handle).is_none() {
                        die(fail(0x0a, 0x1));
                    }
                    device.bound_before = true;
                }
                // Nothing is outstanding, so nothing can be returned. Accepting
                // would grow the inventory past the machine.
                None => die(fail(0x08, 0x2)),
            }
            // A return is a notification, not a request: the supervisor that
            // sends it is reclaiming on behalf of a driver that is already
            // gone, and is not waiting on an answer. Replying would queue a
            // message on the endpoint that the next caller's `call` would
            // dequeue as *its* reply — so the honest thing is to say nothing
            // and let a bad return kill this program instead.
            continue;
        }

        // A **service notice** — ladder step 4, the kernel telling a dependent
        // that one of its devices is in trouble.
        //
        // Told apart from a bind request by its `size` word, which is the
        // first field of every ABI struct and differs between the two. That is
        // a real discriminator and not a convention: a request that happened
        // to carry a notice's size would fail to decode as either, because the
        // generated decoder checks the whole shape and not just the prefix.
        let notice_bytes = read_kernel_filled::<{ ServiceNotice::WIRE_SIZE }>(&message);
        if u32::from_le_bytes([
            notice_bytes[0],
            notice_bytes[1],
            notice_bytes[2],
            notice_bytes[3],
        ]) == ServiceNotice::WIRE_SIZE as u32
        {
            let notice: ServiceNotice = match decode(&notice_bytes) {
                Ok(notice) => notice,
                Err(_) => die(fail(0x0b, 0xd)),
            };
            // Acknowledged by not offering the device again until it comes
            // back. There is nothing else to do here and deliberately so: the
            // manager does not hold this device — a driver does, or a corpse
            // did — so it has no authority to act on it yet. What the notice
            // buys is that the manager knows *before* the capability arrives,
            // which is the difference between a dependent that is told and one
            // that infers.
            for slot in devices.iter_mut().flatten() {
                if slot.class != DeviceClass::Unknown && !slot.held {
                    slot.bound_before = true;
                }
            }
            let _ = notice.device;
            // A notice is a notification, not a request: nobody is waiting on
            // an answer, and replying would queue a message the next caller's
            // `call` would dequeue as its own reply.
            continue;
        }

        let bytes = read_kernel_filled::<{ BindRequest::WIRE_SIZE }>(&message);
        let request: BindRequest = match decode(&bytes) {
            Ok(request) => request,
            Err(_) => die(fail(0x04, 0xd)),
        };

        // Match: the first held device of the requested class. `Unknown` is
        // never matched, so a driver cannot acquire a device by asking for the
        // class the manager uses to mean "I could not tell".
        let matched = if request.class == DeviceClass::Unknown {
            None
        } else {
            devices
                .iter_mut()
                .flatten()
                .find(|device| device.held && device.class == request.class)
        };

        // **The manifest decides, not the class match.** Finding a device of
        // the requested class is where binding used to end; it is where it now
        // begins. The manifest is consulted with the facts enumeration
        // observed, and it can refuse a device this program is holding, has
        // classified, and would happily have handed over — which is the whole
        // point of there being a policy.
        let outcome = matched.as_ref().map(|device| {
            select(
                &MANIFEST,
                &DeviceFacts {
                    class: device.class as u32,
                    vendor: device.vendor,
                    product: device.product,
                    revision: device.revision,
                    bus: device.bus,
                    // No device on these machines reports a firmware version,
                    // and zero is "did not say" rather than version zero — so
                    // a manifest minimum does not refuse them.
                    firmware_version: 0,
                },
                &POLICY,
                // Where the device sits, which the manifest weighs alongside
                // what it is. Two identical devices at different depths are no
                // longer the same question.
                &device.path[..device.path_len],
            )
        });

        let (status, class, count, binding) = match (matched, outcome) {
            // A device the manifest claims. Everything below is unchanged from
            // when a class match was the whole decision, because the *transfer*
            // was always right — what was missing was anything deciding whether
            // it should happen.
            (Some(device), Some(Ok(binding))) => {
                // **READ | MAP, and deliberately not TRANSFER.** A driver gets
                // the authority to map and drive its device, not the authority
                // to hand it to a third party — one-driver-per-device stops
                // depending on every driver choosing not to pass its device on.
                // Reclaim-on-death still works: the kernel taking a capability
                // back from a corpse goes through `HandleTable::reclaim`, which
                // requires no TRANSFER precisely because it is not a process
                // handing one on.
                let descriptor = HandleTransfer {
                    handle: device.handle,
                    // The grant is a move: the manager keeps no way to touch a
                    // device it has handed to a driver, which is what makes
                    // revocation-by-death a complete answer rather than a
                    // partial one.
                    mode: TransferMode::Transfer,
                    rights: Rights::READ.bits() | Rights::MAP.bits(),
                };
                if encode(&descriptor, &mut transfer).is_err() {
                    die(fail(0x05, 0xf));
                }
                // The class reported is the one *probing* found, not the one
                // the request asked for. They agree by construction of the
                // match above — which is exactly why echoing the request would
                // make the driver's cross-check vacuous, and echoing the
                // device keeps it meaning something if the match ever changes.
                let bound = device.class;
                // **The lifecycle is declared before the transfer, and it has
                // to be.** A transition needs `Rights::MAP` on a handle this
                // program holds, and the next thing that happens is the handle
                // leaving. After the reply there is no device here to speak
                // for.
                //
                // Where it resumes depends on whether anyone has driven this
                // device before: a fresh one opens at `Discovered`, and one
                // that came back from a stopped driver is `Degraded`. Rebinding
                // the second as a new discovery would erase the failure that
                // made it available.
                let handed = if device.bound_before {
                    declare(
                        device.handle,
                        DriverState::Degraded,
                        DriverState::Starting,
                        TransitionReason::Restarted,
                    )
                } else {
                    declare(
                        device.handle,
                        DriverState::Discovered,
                        DriverState::Matched,
                        TransitionReason::Bound,
                    ) && declare(
                        device.handle,
                        DriverState::Matched,
                        DriverState::Starting,
                        TransitionReason::Launched,
                    )
                };
                if !handed {
                    die(fail(0x0a, 0x2));
                }
                // Marked before the reply, because after it the handle is gone
                // from this program's table and the number would name nothing.
                device.held = false;
                (0u32, bound, 1u64, Some(binding))
            }
            // A device the manifest **refused**, and the reason travels back.
            // A driver told only "no" would report missing hardware for a
            // device that is present, classified, and deliberately not being
            // given to it.
            (Some(_), Some(Err(refusal))) => (refusal as u32, DeviceClass::Unknown, 0u64, None),
            // No device of that class is available at all.
            _ => (Refusal::NoMatch as u32, DeviceClass::Unknown, 0u64, None),
        };

        let reply = BindReply {
            size: BindReply::WIRE_SIZE as u32,
            version: 3,
            // Says when the path figures below are a lower bound rather than a
            // total. A driver that ignores the bit still sees plausible
            // numbers, which is why the fact travels beside them and not in
            // them.
            flags: match binding {
                Some(b) if !b.path_complete => BIND_FLAG_PATH_INCOMPLETE,
                _ => 0,
            },
            status,
            class,
            // The binding's outputs. Zeroes on a refusal, because a driver
            // that was not bound has no services to require and no channel to
            // be updated through — and reporting a plausible set would have it
            // proceed as though it had been bound.
            required_services: binding.map_or(0, |b| b.required_services),
            update_channel: binding.map_or(0, |b| b.update_channel),
            security_domain: binding.map_or(0, |b| b.security_domain),
            power_domain: binding.map_or(0, |b| b.power_domain),
            contract_version: binding.map_or(0, |b| b.contract_version),
            reserved: 0,
            // What the path costs, told to the driver whether or not its entry
            // declared a budget. Being told is useful to something that never
            // refuses on it, and a number filled in only on the way to a
            // refusal is one nobody can trust on the way to a bind.
            accumulated_latency_us: binding.map_or(0, |b| b.accumulated_latency_us),
            relay_hops: binding.map_or(0, |b| b.relay_hops),
            // Zero is "no hop declared a ceiling" (`driver_bind.isl`).
            path_throughput_mbps: binding.map_or(0, |b| b.path_throughput_mbps.unwrap_or(0)),
        };
        if encode(&reply, &mut message).is_err() {
            die(fail(0x05, 0xe));
        }

        let args = match channel_args(
            message.as_ptr() as u64,
            BindReply::WIRE_SIZE as u64,
            transfer.as_ptr() as u64,
            count,
            0,
            0,
        ) {
            Ok(args) => args,
            Err(code) => die(code),
        };
        let replied = syscall2(
            SYS_CHANNEL_REPLY_CONTINUE,
            args.as_ptr() as u64,
            SERVICE_ENDPOINT_HANDLE,
        );
        if replied < 0 {
            die(fail(0x06, (-replied) as u64));
        }
    }
}

/// Entry point. `count` is the number of device capabilities boot installed
/// at handles 1..=count — this program's entire bootstrap contract, and the
/// only thing it is told rather than discovers.
///
/// # Safety
///
/// The unmangled `_start` symbol is the ELF entry the linker script names and
/// the kernel loader jumps to, with the startup argument in `x0`.
#[unsafe(no_mangle)]
extern "C" fn _start(count: u64) -> ! {
    let count = (count as usize).min(MAX_DEVICES);
    match enumerate(count) {
        Ok(mut devices) => serve(&mut devices),
        Err(code) => die(code),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    die(fail(0xff, 0))
}
