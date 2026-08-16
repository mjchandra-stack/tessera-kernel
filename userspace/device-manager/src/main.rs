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
use firmware_abi::{FirmwareLoadArgs, FirmwareRefusal, FirmwareReport};
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
const SYS_CHANNEL_RECV_ANY: u64 = 43;
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
const SYS_FIRMWARE_LOAD: u64 = 39;
/// Record a driver-lifecycle transition for a device this program holds. The
/// syscall that makes `docs/drivers/01`'s "transitions are observable through
/// structured events" true of this system rather than of its documentation.
const SYS_DRIVER_LIFECYCLE: u64 = 29;

/// The service endpoint boot installs first, so it is always handle 0. Device
/// capabilities follow at 1..=count, and the count arrives as this program's
/// startup argument — the whole of its bootstrap contract with boot.
const SERVICE_ENDPOINT_HANDLE: u64 = 0;

/// Service endpoints this manager will hold.
///
/// **More than one, because more than one driver calls.** A service endpoint is
/// a channel, and a channel carries one outstanding call: two drivers blocked
/// on the same one is a reply going to whichever of them the kernel wakes
/// first, which is a driver being handed another driver's device. Until a
/// machine here had two drivers binding at once — a bus host and the class
/// drivers for what it declares — one endpoint was enough and nothing said so.
const MAX_SERVICE_ENDPOINTS: usize = 4;

/// Startup-argument bits naming how many service endpoints boot installed
/// **after** the device handles, so `FIRST_DEVICE_HANDLE` stays where it is and
/// every other check is unchanged. Zero means the one at handle 0 alone.
const EXTRA_ENDPOINTS_SHIFT: u64 = 56;
const EXTRA_ENDPOINTS_MASK: u64 = 0x7 << EXTRA_ENDPOINTS_SHIFT;
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
/// An SD host controller: system peripheral, subclass SD. Matched on both
/// bytes because the base byte alone is a category — interrupt controllers and
/// timers share it — and a manifest matching on it would offer a card driver a
/// timer.
const PCI_CLASS_SD_HOST: u32 = 0x0805;
/// A USB host controller: serial bus controller, subclass USB. Matched on both
/// bytes for the reason the SD controller is — the base byte covers FireWire,
/// SMBus and CAN as well, and an entry matching it would offer a USB host
/// driver a CAN controller.
const PCI_CLASS_XHCI: u32 = 0x0c03;
/// Input devices. One byte is enough: unlike the two above, the base class has
/// no other meaning to be confused with.
const PCI_CLASS_INPUT: u32 = 0x09;
/// A GPIO controller: base system peripheral, subclass "other". PCI names no
/// class for one, so this is where a device the taxonomy does not cover
/// honestly sits — matched on both bytes, because the base byte is a category
/// shared with timers and interrupt controllers.
const PCI_CLASS_GPIO: u32 = 0x0880;
/// An audio device: multimedia controller, subclass audio. Matched on both
/// bytes, because the base byte covers video and telephony as well and a
/// manifest matching it would offer an audio driver a camera.
const PCI_CLASS_AUDIO: u32 = 0x0401;
/// A display controller. One byte, not two: every subclass of this base class
/// is a display of some kind, which is not true of the multimedia class beside
/// it — that one carries video and telephony as well.
const PCI_CLASS_DISPLAY: u32 = 0x03;
/// A virtio crypto function, by vendor and device id.
///
/// **Not a class code**, because this transport has no useful one: it declares
/// itself "other", the same byte a dozen unrelated devices use. Matching on it
/// would offer the crypto driver whatever else said "other" that boot. So this
/// device is identified by what it is — 0x1040 plus the virtio device id, which
/// is how a modern virtio function names itself.
const VIRTIO_CRYPTO_PRODUCT: u16 = 0x1040 + 20;

/// The deepest chain of ancestors this manager walks, and therefore the deepest
/// path it can account for.
///
/// A machine with more than this between a device and the root is one whose
/// data-path costs this program cannot add up, and it says so rather than
/// enumerating a subset — a partial inventory looks exactly like a small
/// machine.
const MAX_RELAY_DEPTH: usize = 4;

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

/// What one relay through a ring-3 USB host adds.
///
/// **The first relay cost in this manifest that describes something real.** The
/// two `Bus` entries below are synthetic products attached to prove the
/// arithmetic; this one is a fact about the machine — a USB device has no
/// registers, so every transfer to it is an IPC round trip into the process
/// that owns the controller and back, and a device behind a hub pays it twice
/// because the hub is a second relaying host in the graph.
///
/// Deliberately under half of [`BLOCK_MAX_PATH_LATENCY_US`], which is what
/// makes the same block entry bind a USB disk on a root port, bind one behind a
/// hub, and refuse one two hubs down. The bound is not new: it is the storage
/// budget that has been there since D130, now being asked a question a real
/// topology can answer.
const USB_RELAY_LATENCY_US: u64 = 12;

/// What a USB 2.0 high-speed path carries. A ceiling and not a measurement:
/// what the bus is rated at is the most any hop on it can narrow to.
const USB_RELAY_THROUGHPUT_MBPS: u32 = 480;

/// What an input device's data path may cost it.
///
/// Deliberately not [`BLOCK_MAX_PATH_LATENCY_US`]. A budget is a claim about
/// what a class needs, and a keyboard needs nothing a hub can take away — the
/// data arrives at a person's speed. An entry that reused the storage number
/// would refuse a keyboard three hubs deep over a delay nobody could perceive,
/// which is a budget being applied rather than a budget being met.
const INPUT_MAX_PATH_LATENCY_US: u64 = 10_000;

/// What an audio device's data path may cost it.
///
/// **Tighter than storage, and for a reason storage does not have.** A disk
/// read that takes longer than it might is slow; a period that arrives after
/// the device wanted it is a gap somebody hears, and no amount of retrying
/// makes the sound that was already played correct. The number is the period
/// this driver uses expressed as time, which is the budget the hardware itself
/// sets.
const AUDIO_MAX_PATH_LATENCY_US: u64 = 5;

/// The virtio product id whose block driver is bound with firmware.
///
/// A device id of its own, so that exactly one manifest entry declares an
/// image: every other block device in this tree keeps binding with none, which
/// is what most hardware does and what the other checks depend on.
const FIRMWARE_BLOCK_PRODUCT: u16 = 0x1052;

/// The firmware image a block driver is bound with, by store entry name.
const BLOCK_FIRMWARE: &str = "firmware.bin";
/// The lowest image version that driver understands.
///
/// Chosen to sit **above** one of the images in the store and below the one
/// that loads, so the entry can refuse an image on its own authority — the
/// question that is not the rollback floor's. The floor lives in the kernel and
/// nothing here can lower it.
const BLOCK_FIRMWARE_MIN_VERSION: u32 = 2;

/// Images this manager asks for that it expects to be refused, and the store
/// entry names it knows them by.
///
/// **Not a test fixture bolted onto a service.** `docs/drivers/01` puts firmware
/// loading in the framework, so the framework is the only thing in this system
/// that can demonstrate a refusal at all — a driver has no authority to ask and
/// the kernel has nobody to ask it. Under [`FIRMWARE_PROBE`] the manager asks
/// for both before it serves anything, and reports what it was told.
const REFUSABLE_FIRMWARE: [&str; 2] = ["firmware-old.bin", "firmware-v1.bin"];

/// Startup-argument bit asking this manager to report the two refusals before
/// it serves. High enough that no device count can collide with it.
const FIRMWARE_PROBE: u64 = 1 << 60;

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
const MANIFEST: [ManifestEntry; 14] = [
    // **The one entry that declares firmware**, and it is product-specific
    // because firmware is: an image is built for a particular controller, and
    // an entry that demanded one of every mass-storage device would refuse
    // every device whose vendor ships none. The manager fetches it before the
    // transfer and hands it over with the device; a driver bound by this entry
    // receives an image and never asks for one.
    ManifestEntry {
        class: DeviceClass::Block as u32,
        vendor: Some(VIRTIO_VENDOR),
        product: Some(FIRMWARE_BLOCK_PRODUCT),
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
        firmware_name: Some(BLOCK_FIRMWARE),
        firmware_min_image_version: BLOCK_FIRMWARE_MIN_VERSION,
        grants_configure: true,
        grants_derive: false,
    },
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
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: true,
        grants_derive: false,
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
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
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
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
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
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
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
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
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
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
    },
    // **The SD host controller**, and the only entry that grants `DERIVE`. Its
    // devices are buses: a card is a device behind the controller, and the
    // driver is what puts it in the resource graph — which is authority no
    // other entry here has any use for.
    //
    // No firmware, no relay cost of its own: the *card's* path relays through
    // this controller, and what that costs is the card's entry to declare.
    ManifestEntry {
        class: DeviceClass::Sd as u32,
        vendor: None,
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
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: true,
    },
    // **The USB host controller, and every hub behind it.** One entry for both,
    // because they are the same thing at different depths: a bus whose children
    // have no registers and whose transfers relay through the process that
    // drives it. The class code a hub is declared with is the controller's own,
    // so this entry matches it without naming it.
    //
    // It grants `DERIVE` for the reason the SD entry does — the driver is what
    // puts its devices in the graph — and it is the first entry here to declare
    // a relay cost that is a fact about the machine rather than a fixture.
    ManifestEntry {
        class: DeviceClass::Usb as u32,
        vendor: None,
        product: None,
        min_revision: None,
        bus: None,
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: BLOCK_POWER_DOMAIN,
        driver_signature: BLK_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED | product_policy::EARLY_BOOT,
        relay: Some(RelayCost {
            added_latency_us: USB_RELAY_LATENCY_US,
            throughput_mbps: Some(USB_RELAY_THROUGHPUT_MBPS),
        }),
        // No budget of its own. A host controller is where a path *starts*
        // being relayed, and holding it to a path budget would be holding it to
        // the cost of the devices it is about to declare.
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: true,
    },
    // **The input driver**, and the entry that shows a class is not a
    // transport. Nothing here says USB: a keyboard reached through a relaying
    // host and one on a bus that has not been written yet match the same line,
    // and the path cost the binding reports is what differs between them.
    ManifestEntry {
        class: DeviceClass::Input as u32,
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
        // **A budget an input device can actually keep.** A person's typing is
        // slower than any path this machine has, so the number here is not the
        // storage budget: holding a keyboard to a disk's latency would refuse a
        // device three hubs deep for a delay nobody could perceive.
        max_latency_us: Some(INPUT_MAX_PATH_LATENCY_US),
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
    },
    // **The GPIO controller, and the first entry that names a bus.** Every
    // other entry here leaves `bus` as `None`, because until now there were two
    // transports and a vendor id told them apart. A platform device has no
    // vendor id of its own — ARM designed the cell, not the board — so what
    // distinguishes it is the bus it was found on, which is exactly the binding
    // input `docs/drivers/01` says a bus kind is for.
    ManifestEntry {
        class: DeviceClass::Gpio as u32,
        vendor: Some(ARM_DESIGNER),
        product: None,
        min_revision: None,
        bus: Some(BusKind::Platform),
        min_firmware: None,
        security_domain: DRIVER_DOMAIN,
        power_domain: BLOCK_POWER_DOMAIN,
        driver_signature: BLK_DRIVER_SIGNATURE,
        contract_version: 1,
        product_policy: product_policy::ENABLED | product_policy::EARLY_BOOT,
        relay: None,
        // A GPIO line is a level, not a transfer: there is no path budget worth
        // holding it to, and inventing one would be a number nobody could
        // justify.
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
    },
    // **The audio driver**, and the first entry whose device has a deadline.
    // Its path budget is its own: a stream that arrives late is a gap somebody
    // hears, which is a different kind of failure from a disk read that takes
    // longer than it might.
    ManifestEntry {
        class: DeviceClass::Audio as u32,
        vendor: Some(VIRTIO_VENDOR),
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
        max_latency_us: Some(AUDIO_MAX_PATH_LATENCY_US),
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: true,
        grants_derive: false,
    },
    // **The display driver.** No path budget: a frame that arrives late is a
    // frame somebody sees late, and there is no number here that says how late
    // is too late without a compositor above this contract to hold the policy.
    // Saying `None` records that, where a number would have invented it.
    ManifestEntry {
        class: DeviceClass::Display as u32,
        vendor: Some(VIRTIO_VENDOR),
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
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: true,
        grants_derive: false,
    },
    // **The crypto driver**, and the only entry whose device handles a secret.
    // No path budget, as the display has none: an operation that takes longer
    // than it might is slow, and there is no number here that makes it wrong.
    ManifestEntry {
        class: DeviceClass::Crypto as u32,
        vendor: Some(VIRTIO_VENDOR),
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
        max_latency_us: None,
        min_throughput_mbps: None,
        required_services: required_service::LOGGING,
        update_channel: UPDATE_CHANNEL_BASE,
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: true,
        grants_derive: false,
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
    /// Where the graph says this device is on its bus. **The discriminator
    /// between a device coming back and a device arriving for the first
    /// time**: a return brings back the one that went out, and an offer names
    /// hardware this manager has never seen. Zero for a device the kernel has
    /// no identity for, which is why the fallback below still exists.
    bdf: u32,
    bus: BusKind,
    /// Whether this device has a configuration window of its own — whether
    /// granting `Rights::CONFIGURE` with it would mean anything.
    ///
    /// Only a bus controller's declaration creates one, so this is also how
    /// this program tells a device somebody outside the kernel found from one
    /// the kernel registered itself.
    configurable: bool,
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

/// Where `msg_flags` sits in an encoded `ChannelMsgArgs`, which is where a
/// wait on several endpoints reports the one that answered.
const ARGS_MSG_FLAGS: usize = 36;

/// Reads back a u32 the kernel wrote into this program's args buffer.
///
/// Volatile because the compiler has no idea a syscall wrote here and would
/// otherwise hand back whatever this program last put there.
fn args_u32(bytes: &[u8], at: usize) -> u32 {
    let mut out = [0u8; 4];
    for (index, slot) in out.iter_mut().enumerate() {
        if at + index >= bytes.len() {
            return 0;
        }
        // SAFETY: a bounds-checked byte of this program's own stack buffer.
        *slot = unsafe { core::ptr::read_volatile(&bytes[at + index]) };
    }
    u32::from_le_bytes(out)
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
    // A USB host controller and a USB hub are the same class here, and both are
    // relaying ancestors: a hub declared by the host carries the controller's
    // own class code, because it is a bus of the same kind one level down.
    let class = if record.class_code >> 8 == PCI_CLASS_XHCI {
        DeviceClass::Usb
    } else {
        match record.class_code >> 16 {
            PCI_CLASS_BRIDGE => DeviceClass::Bus,
            PCI_CLASS_MASS_STORAGE => DeviceClass::Block,
            PCI_CLASS_NETWORK => DeviceClass::Network,
            PCI_CLASS_INPUT => DeviceClass::Input,
            PCI_CLASS_DISPLAY => DeviceClass::Display,
            _ if record.vendor as u16 == VIRTIO_VENDOR
                && record.device as u16 == VIRTIO_CRYPTO_PRODUCT =>
            {
                DeviceClass::Crypto
            }
            _ => DeviceClass::Unknown,
        }
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

/// What a device is, asked the only two ways there are.
///
/// **The kernel first.** A device on a bus whose identity is not in the
/// device's own registers — PCI — can only be classified from what was read
/// during enumeration; mapping it and reading offset 8 would find whatever that
/// BAR happens to expose, not a class. A device the graph has no identity for
/// has one of its own, and is asked.
///
/// Shared by the enumeration of what boot granted and the acceptance of what a
/// bus controller offers, because those differ in where the capability came
/// from and in nothing else: a device is classified the same way whoever found
/// it, and a second copy of this would be a second answer to drift from.
fn classify(handle: u32, probe_va: u64) -> Result<(DeviceClass, u16, u16, u8, BusKind, bool), u64> {
    // The facts a manifest is matched against, filled in by whichever route
    // classified the device. A device nothing was learned about keeps the
    // defaults, which no entry naming a bus can claim.
    let (mut vendor, mut product, mut revision, mut bus) = (0u16, 0u16, 0u8, BusKind::Unknown);
    // Whether this device has a configuration window of its own, which only a
    // bus controller's declaration creates. It decides whether granting
    // `Rights::CONFIGURE` would mean anything at all.
    let mut configurable = false;
    let class = match device_identity(handle)? {
        Some(record) => {
            vendor = record.vendor as u16;
            product = record.device as u16;
            revision = record.revision as u8;
            bus = bus_kind(record.bus);
            configurable = record.config_valid != 0;
            // Subclass first for the one class where the base byte is not
            // enough: `0x08` is "system peripheral", which is a category rather
            // than a driver interface, and an SD host controller shares it with
            // interrupt controllers and timers.
            if record.class_code >> 8 == PCI_CLASS_SD_HOST {
                return Ok((
                    DeviceClass::Sd,
                    vendor,
                    product,
                    revision,
                    bus,
                    configurable,
                ));
            }
            // The same two-byte question for USB, and it is asked of a declared
            // hub as well as of the controller: a hub is a bus of the same kind
            // one level down, and the host declares it with the class code that
            // says so.
            if record.class_code >> 8 == PCI_CLASS_AUDIO {
                return Ok((
                    DeviceClass::Audio,
                    vendor,
                    product,
                    revision,
                    bus,
                    configurable,
                ));
            }
            if record.class_code >> 8 == PCI_CLASS_GPIO {
                return Ok((
                    DeviceClass::Gpio,
                    vendor,
                    product,
                    revision,
                    bus,
                    configurable,
                ));
            }
            if record.class_code >> 8 == PCI_CLASS_XHCI {
                return Ok((
                    DeviceClass::Usb,
                    vendor,
                    product,
                    revision,
                    bus,
                    configurable,
                ));
            }
            match record.class_code >> 16 {
                PCI_CLASS_MASS_STORAGE => DeviceClass::Block,
                PCI_CLASS_NETWORK => DeviceClass::Network,
                PCI_CLASS_INPUT => DeviceClass::Input,
                PCI_CLASS_DISPLAY => DeviceClass::Display,
                _ if record.vendor as u16 == VIRTIO_VENDOR
                    && record.device as u16 == VIRTIO_CRYPTO_PRODUCT =>
                {
                    DeviceClass::Crypto
                }
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
                // **A third way to ask, for a bus that has no other.** A PCI
                // function says what it is in configuration space and a
                // virtio-mmio transport says so in a magic word; a platform
                // device has neither — no bus enumerated it, and there is
                // nowhere to look but the device. A PrimeCell answers in its
                // own identification registers, which is the same question
                // asked of the third kind of bus.
                //
                // Asked here rather than answered from the device tree on
                // purpose. The tree is a description somebody wrote; these
                // registers are the part itself, and a device that is not what
                // the tree said is a device this manager must not classify.
                if let Some(part) = tessera_pl061::identify(&ProbeWindow { base }) {
                    return Ok((
                        match part {
                            tessera_pl061::PL061_PART => DeviceClass::Gpio,
                            // A PrimeCell that is some other peripheral is a
                            // device this manager has met and cannot place.
                            // Recorded as unknown rather than guessed at.
                            _ => DeviceClass::Unknown,
                        },
                        ARM_DESIGNER,
                        part as u16,
                        0,
                        BusKind::Platform,
                        false,
                    ));
                }
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
    Ok((class, vendor, product, revision, bus, configurable))
}

/// ARM, as a PrimeCell's identification registers give the designer. Recorded
/// as the vendor so a manifest can match on it the way it matches virtio's.
const ARM_DESIGNER: u16 = 0x41;

/// A mapped window, so the PrimeCell reader can be handed one.
///
/// The reader lives in `tessera_pl061` and forbids `unsafe`; this is the two
/// lines that cross the boundary, and they are the same volatile access every
/// other probe here uses.
struct ProbeWindow {
    base: u64,
}

impl tessera_pl061::Registers for ProbeWindow {
    fn read32(&self, offset: usize) -> u32 {
        read_register(self.base, offset)
    }

    fn write32(&self, _offset: usize, _value: u32) {
        // **Identification reads and never writes.** A manager that wrote to a
        // device it has not classified would be writing to something it cannot
        // name, which is the one thing a probe must not do.
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

        let (class, vendor, product, revision, bus, configurable) = classify(handle, probe_va)?;
        *slot = Some(Device {
            handle,
            probe_va,
            class,
            vendor,
            product,
            revision,
            bdf: device_identity(handle)?.map_or(0, |record| record.bdf),
            bus,
            configurable,
            held: true,
            bound_before: false,
            path,
            path_len: found.depth,
        });
    }
    Ok(devices)
}

/// Asks the kernel for a verified firmware image, returning the object handle
/// and what the kernel said about it.
///
/// **This program supplies the authority and none of the judgement.** It holds
/// `Rights::FIRMWARE` on the device and knows which image its manifest asked
/// for; whether that image may be loaded is decided against a store and a
/// rollback floor it cannot see, which is the whole reason firmware loading is
/// a syscall rather than a file read.
///
/// A refusal comes back as `(Err(code), report)` — the report is written on
/// both paths, so the caller can say *which* policy refused rather than only
/// that one did.
fn load_firmware(device: u32, name: &str, min_image_version: u32) -> (i64, FirmwareReport) {
    let mut field = [0u8; 24];
    let bytes = name.as_bytes();
    let take = if bytes.len() > field.len() {
        field.len()
    } else {
        bytes.len()
    };
    field[..take].copy_from_slice(&bytes[..take]);

    let report_bytes = [0u8; FirmwareReport::WIRE_SIZE];
    let blank = FirmwareReport {
        size: FirmwareReport::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        refusal: FirmwareRefusal::None,
        svn: 0,
        image_version: 0,
        reserved: 0,
        length: 0,
        digest: [0; 32],
    };
    let args = FirmwareLoadArgs {
        size: FirmwareLoadArgs::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        device: HandleRef::new(device),
        min_image_version,
        name: field,
        reserved: 0,
        report_ptr: report_bytes.as_ptr() as u64,
    };
    let mut buf = [0u8; FirmwareLoadArgs::WIRE_SIZE];
    if encode(&args, &mut buf).is_err() {
        return (-1, blank);
    }
    let result = syscall2(SYS_FIRMWARE_LOAD, buf.as_ptr() as u64, 0);
    // Read back whatever the kernel wrote. On a refusal this is the only place
    // the reason exists; on success it is the provenance of what arrived.
    // Read back through the volatile helper: the kernel wrote these bytes and
    // this program never did, so nothing here may assume the buffer still holds
    // the zeros it was initialised with.
    let filled: [u8; FirmwareReport::WIRE_SIZE] = read_kernel_filled(&report_bytes);
    let report = decode::<FirmwareReport>(&filled).unwrap_or(blank);
    (result, report)
}

/// Asks for each image this manager expects to be refused, and packs what it
/// was told into one word: two nibbles of `FirmwareRefusal`, then the two
/// security versions the kernel reported for them.
///
/// The versions are in the report because a refusal that did not carry the
/// number it refused could not be checked against a floor by anyone reading it.
fn firmware_refusal_report(device: u32) -> u64 {
    let mut packed = 0u64;
    for (index, name) in REFUSABLE_FIRMWARE.iter().enumerate() {
        // Ask for the version the block entry asks for, so the *only* thing
        // that differs between these two requests and the real one is the
        // image named.
        let (result, report) = load_firmware(device, name, BLOCK_FIRMWARE_MIN_VERSION);
        // A load that succeeded is the failure this reports: these two images
        // exist to be refused, and one arriving means a policy stopped
        // applying.
        let outcome = if result >= 0 {
            0xf
        } else {
            report.refusal as u32 as u64 & 0xf
        };
        packed |= outcome << (index * 4);
        packed |= (u64::from(report.svn) & 0xff) << (32 + index * 8);
    }
    packed
}

/// Serves bind requests until the process is reaped. Never returns normally.
fn serve(devices: &mut [Option<Device>; MAX_DEVICES], endpoints: &[u32]) -> ! {
    // One buffer serves as both the request destination and the reply source
    // — the symmetric call-buffer convention the block protocol uses.
    // Serves as request destination and reply source. Sized from the largest of
    // the three things that cross it: a `BindRequest` in, a `ServiceNotice`
    // in, and a `BindReply` out — the reply is the biggest, because binding
    // produces outputs and they all travel in it. Taken from the type rather
    // than written out, because a reply that grew past a literal would fail at
    // run time in a `die` nobody would connect to the schema change.
    let mut message = [0u8; BindReply::WIRE_SIZE];
    // The capabilities to hand out travel in their own vector, never in the
    // payload bytes (docs/api/03, "Wire Format"). Each entry says which handle
    // to move *and* the rights it is to arrive with.
    //
    // Room for two: the device, and the firmware image where the manifest
    // entry declared one. The image is a second *capability* rather than a
    // payload because that is what lets it move without a copy — and because a
    // driver that received bytes in a message would have no object to map.
    let mut transfer = [0u8; 2 * HandleTransfer::WIRE_SIZE];
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
            // Nothing is transferred *out* on a receive, so the handle vector
            // is free to say which endpoints to wait on — and that is what a
            // wait on several uses it for. The vector below is where the kernel
            // reports what came *in*.
            endpoints.as_ptr() as u64,
            endpoints.len() as u64,
            installed.as_ptr() as u64,
            1,
        ) {
            Ok(args) => args,
            Err(code) => die(code),
        };
        // **Wait on every endpoint, and remember which answered.** A blocking
        // receive on one of several would commit this manager to whichever
        // driver spoke first and leave the others unheard for as long as it
        // stayed quiet; the reply then has to go back to the one that asked,
        // which is why the kernel reports the index rather than the caller
        // guessing.
        let received = if endpoints.len() == 1 {
            syscall2(
                SYS_CHANNEL_RECV,
                args.as_ptr() as u64,
                SERVICE_ENDPOINT_HANDLE,
            )
        } else {
            syscall2(SYS_CHANNEL_RECV_ANY, args.as_ptr() as u64, 0)
        };
        if received < 0 {
            die(fail(0x03, (-received) as u64));
        }
        let from = if endpoints.len() == 1 {
            SERVICE_ENDPOINT_HANDLE
        } else {
            let index = args_u32(&args, ARGS_MSG_FLAGS) as usize;
            match endpoints.get(index) {
                Some(handle) => u64::from(*handle),
                None => die(fail(0x03, 0x200)),
            }
        };

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
            // **A return or an offer, and the difference is what is
            // outstanding.** A slot that exists and is not held means a device
            // went out to a driver and something is bringing it back. Nothing
            // outstanding means this capability names hardware this manager has
            // never seen — which is what a bus controller does when it walks a
            // bus and hands on what it found.
            //
            // They must not take the same path. A return is re-verified and
            // marked degraded, because it came back from a driver that stopped;
            // a device nobody has ever driven is not degraded, and opening its
            // lifecycle at `Degraded` would claim a failure that never happened.
            //
            // **Matched by identity, not by "is anything outstanding".** That
            // question was enough while a bus controller offered before
            // anything had been bound. It is not enough for a controller that
            // binds its *own* device and then declares children behind it: both
            // are true at once, and a manager that could not tell them apart
            // would mark a brand-new device degraded for a failure that never
            // happened.
            let arriving = match device_identity(returned) {
                Ok(arriving) => arriving,
                Err(code) => die(code),
            };
            let outstanding = match arriving {
                Some(record) => devices
                    .iter()
                    .flatten()
                    .any(|device| !device.held && device.bdf == record.bdf),
                // Nothing to compare — a transport the kernel has no identity
                // for. The older question is the only one available, and it is
                // the one this used to ask alone.
                None => devices.iter().flatten().any(|device| !device.held),
            };
            if !outstanding {
                let free = devices.iter().position(Option::is_none);
                let Some(index) = free else {
                    // The machine has more devices than this manager can hold.
                    // Reported rather than silently dropped: an inventory
                    // missing a device is one that will never bind it, and
                    // nothing downstream could tell that from the device not
                    // being there.
                    die(fail(0x08, 0x3));
                };
                let probe_va =
                    layout::PROBE_WINDOW_BASE + index as u64 * layout::PROBE_WINDOW_STRIDE;
                let (class, vendor, product, revision, bus, configurable) =
                    match classify(returned, probe_va) {
                        Ok(classified) => classified,
                        Err(code) => die(code),
                    };
                devices[index] = Some(Device {
                    handle: returned,
                    probe_va,
                    class,
                    vendor,
                    product,
                    revision,
                    bdf: arriving.map_or(0, |record| record.bdf),
                    bus,
                    configurable,
                    held: true,
                    bound_before: false,
                    // An offered device's path is empty and that is the truth
                    // of it: this manager did not walk to it, so it knows of no
                    // ancestors between itself and the device. What the
                    // controller passed through on the way is the controller's
                    // to account for.
                    path: [Hop::Separated; MAX_RELAY_DEPTH],
                    path_len: 0,
                });
                continue;
            }
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

        // Five things now: the last is what firmware came with the binding,
        // which the reply reports and which only the success arm can know.
        let (status, class, count, binding, firmware) = 'bind: {
            match (matched, outcome) {
                // A device the manifest claims. Everything below is unchanged from
                // when a class match was the whole decision, because the *transfer*
                // was always right — what was missing was anything deciding whether
                // it should happen.
                (Some(device), Some(Ok(binding))) => {
                    // **The image is fetched before the device moves, and a bind
                    // that cannot supply the one its entry declared does not
                    // happen.** A driver told it matched, handed its device, and
                    // left to discover that the firmware never arrived would be
                    // driving hardware in a state nobody chose. So this is a
                    // refusal like any other, and it is taken before the transfer
                    // — after which there is no device here to decline with.
                    let firmware = match binding.firmware_name {
                        None => Some(None),
                        Some(name) => {
                            let (result, report) = load_firmware(
                                device.handle,
                                name,
                                binding.firmware_min_image_version,
                            );
                            if result < 0 {
                                None
                            } else {
                                Some(Some((result as u32, report)))
                            }
                        }
                    };
                    let Some(firmware) = firmware else {
                        // Which policy refused is in the kernel's report and in its
                        // event stream. The driver hears that the binding did not
                        // happen, which is the part it can act on.
                        break 'bind (
                            Refusal::FirmwareUnavailable as u32,
                            DeviceClass::Unknown,
                            0u64,
                            None,
                            None,
                        );
                    };
                    // **READ | MAP, and deliberately not TRANSFER.** A driver gets
                    // the authority to map and drive its device, not the authority
                    // to hand it to a third party — one-driver-per-device stops
                    // depending on every driver choosing not to pass its device on.
                    // Reclaim-on-death still works: the kernel taking a capability
                    // back from a corpse goes through `HandleTable::reclaim`, which
                    // requires no TRANSFER precisely because it is not a process
                    // handing one on.
                    // **`CONFIGURE` where the manifest asks for it and there is
                    // something to reach.** It is the authority over the registers
                    // that turn on bus mastering and move a BAR, so which drivers
                    // get it is a decision the manifest takes rather than a
                    // consequence of the transport. And it is only asked for on a
                    // device that has a configuration window — one a bus
                    // controller declared. Asking for it on a device that has none
                    // would fail every such bind for a right that would have gated
                    // nothing.
                    let configure = if binding.grants_configure && device.configurable {
                        Rights::CONFIGURE.bits()
                    } else {
                        0
                    };
                    // **The authority to put devices in the graph**, and only
                    // for entries whose devices are buses. A driver that cannot
                    // populate a bus is merely limited; one that can and should
                    // not is a driver inventing hardware for the rest of the
                    // system to bind against.
                    //
                    // **`TRANSFER` travels with it**, because half an authority
                    // is not one. A bus driver that can declare a device and
                    // cannot hand it on has put something in the graph that no
                    // driver will ever be given — visible, unusable, and
                    // indistinguishable from a device the manifest refused.
                    // The two rights answer the same question, so they are
                    // granted by the same decision.
                    let derive = if binding.grants_derive {
                        Rights::DERIVE.bits() | Rights::TRANSFER.bits()
                    } else {
                        0
                    };
                    let descriptor = HandleTransfer {
                        handle: device.handle,
                        // The grant is a move: the manager keeps no way to touch a
                        // device it has handed to a driver, which is what makes
                        // revocation-by-death a complete answer rather than a
                        // partial one.
                        mode: TransferMode::Transfer,
                        rights: Rights::READ.bits() | Rights::MAP.bits() | configure | derive,
                    };
                    if encode(&descriptor, &mut transfer[..HandleTransfer::WIRE_SIZE]).is_err() {
                        die(fail(0x05, 0xf));
                    }
                    // The image travels beside the device, as a second capability.
                    //
                    // **The device goes without `FIRMWARE` and the image goes
                    // without `WRITE`**, and together those two narrowings are what
                    // make the framework's authority real rather than conventional:
                    // a driver cannot ask for a different image, and cannot edit the
                    // one it was given into something the provenance record no
                    // longer describes.
                    let handles = match firmware {
                        Some((handle, _)) => {
                            let image = HandleTransfer {
                                handle,
                                mode: TransferMode::Transfer,
                                rights: Rights::READ.bits() | Rights::MAP.bits(),
                            };
                            if encode(&image, &mut transfer[HandleTransfer::WIRE_SIZE..]).is_err() {
                                die(fail(0x05, 0x10));
                            }
                            2u64
                        }
                        None => 1u64,
                    };
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
                    (0u32, bound, handles, Some(binding), firmware)
                }
                // A device the manifest **refused**, and the reason travels back.
                // A driver told only "no" would report missing hardware for a
                // device that is present, classified, and deliberately not being
                // given to it.
                (Some(_), Some(Err(refusal))) => {
                    (refusal as u32, DeviceClass::Unknown, 0u64, None, None)
                }
                // No device of that class is available at all.
                _ => (
                    Refusal::NoMatch as u32,
                    DeviceClass::Unknown,
                    0u64,
                    None,
                    None,
                ),
            }
        };

        let reply = BindReply {
            size: BindReply::WIRE_SIZE as u32,
            version: 4,
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
            // Which image came with the device. Zeroes mean none came, which
            // is the normal case — most bindings carry no firmware, and a
            // driver that needs one can tell those apart from a version.
            firmware_svn: firmware.map_or(0, |(_, report)| report.svn),
            firmware_image_version: firmware.map_or(0, |(_, report)| report.image_version),
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
        let replied = syscall2(SYS_CHANNEL_REPLY_CONTINUE, args.as_ptr() as u64, from);
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
extern "C" fn _start(arg: u64) -> ! {
    // The high bit asks this manager to demonstrate the two firmware refusals
    // before it starts serving. It reports and **keeps going**, unlike the
    // report-and-exit modes the drivers have: this is a resident service, and a
    // manager that exited after reporting would leave nothing to bind against.
    let probe = arg & FIRMWARE_PROBE != 0;
    let extra = ((arg & EXTRA_ENDPOINTS_MASK) >> EXTRA_ENDPOINTS_SHIFT) as usize;
    let count = ((arg & !(FIRMWARE_PROBE | EXTRA_ENDPOINTS_MASK)) as usize).min(MAX_DEVICES);
    // The extras sit **after** the device handles, so the device base stays
    // where every other check expects it and adding a client to one machine
    // does not renumber another's.
    let mut endpoints = [0u32; MAX_SERVICE_ENDPOINTS];
    let held = (1 + extra).min(MAX_SERVICE_ENDPOINTS);
    for (index, slot) in endpoints[..held].iter_mut().enumerate() {
        *slot = if index == 0 {
            SERVICE_ENDPOINT_HANDLE as u32
        } else {
            FIRST_DEVICE_HANDLE + count as u32 + index as u32 - 1
        };
    }
    if probe {
        syscall2(
            SYS_DEBUG_WRITE,
            firmware_refusal_report(FIRST_DEVICE_HANDLE),
            0,
        );
    }
    match enumerate(count) {
        Ok(mut devices) => serve(&mut devices, &endpoints[..held]),
        Err(code) => die(code),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    die(fail(0xff, 0))
}
