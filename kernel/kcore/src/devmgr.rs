// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The device resource graph: the kernel's normalized record of which physical
//! I/O resources back each `ObjectType::Device` capability. In v0 a node carries
//! a device's I/O port range and its interrupt line — the minimal
//! `docs/hardware/02-hardware-description-and-discovery.md` "Normalized Resource
//! Graph" (a Device node with a memory/port region and an interrupt route).
//!
//! This closes the ObjectTable-payload deferral for devices (D42/D45/D46): the
//! object table stays a pure typed-refcount registry, and a Device object's
//! authority-scoping payload — its `(base, len)` range — lives here, keyed by the
//! object id and reached by a linear-scan bridge, exactly as `PortTable` and
//! `ChannelTable` key their state to an object id. A ring-3 `DeviceIo` syscall
//! resolves the caller's handle to an `ObjectId`, then reads+enforces the range
//! from this table — no compile-time device constant on the generic path.
//!
//! The device manager (a ring-3 service) brokers *binding* — granting a Device
//! capability to a driver host — on top of these nodes; discovery sources
//! (ACPI/DT/PCI) and the fuller graph (buses, clocks, power domains, DMA
//! apertures) are deferred (build/README.md, D47).
//!
//! Normative: docs/hardware/02-hardware-description-and-discovery.md
//! ("Normalized Resource Graph"), docs/hardware/01-platform-and-cpu-support.md
//! Budget: none (capability resolution; register access is the driver's path)

use crate::object::ObjectId;
use crate::port::PortId;
use crate::rights::Rights;
use tessera_karch::KError;

/// Device nodes the resource graph holds.
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_DEVICES;

/// One resource-graph device node: the object it backs, its I/O port range
/// (`base`, `len` registers), and its interrupt line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DeviceNode {
    object: ObjectId,
    base: u16,
    len: u16,
    /// A port-I/O device's interrupt line, as its controller numbers it.
    ///
    /// The narrow legacy field, kept for the port-I/O nodes that predate MMIO
    /// devices; [`Self::intid`] is the wider one every device registered since
    /// uses, and [`Self::irq_route`] is where a *live* delivery path is
    /// recorded. The bridge stopped being a kernel constant in D127.
    irq: u8,
    /// The authority the graph holds over this device — the rights a
    /// capability to it carries when the **kernel** hands it out, which today
    /// means reclaim-on-death returning it to whoever administers it.
    ///
    /// The node is the root a grant is narrowed *from*, not a copy of what any
    /// grant carries. That distinction is what makes reclaim-and-rebind work
    /// once grants can be narrowed: a driver may hold a device it cannot pass
    /// on, and when it dies the device still returns to its manager with the
    /// authority to be granted again. Recovering that from the corpse's handle
    /// would recover only what the corpse held.
    rights: Rights,
    /// The device's memory-mapped register window `(phys_base, len)`, for devices
    /// reached by MMIO rather than I/O ports (D77). `None` for a port-only node.
    /// A `MapDevice` syscall reads this to map the window into a ring-3 driver's
    /// address space; the physical base is the capability's authority, never the
    /// caller's to choose.
    mmio: Option<(u64, u64)>,
    /// The MMIO device's interrupt-controller INTID (e.g. a GIC SPI's, parsed
    /// from the device tree), for wiring the IRQ→port bridge and gating a
    /// ring-3 `IrqComplete` (D84). `None` for port-I/O nodes (whose narrow
    /// `irq` line field predates this) and for MMIO devices with no interrupt
    /// wired.
    ///
    /// **The first of possibly several.** A single-function device raises one
    /// line and this is it. A multi-queue controller raises one per queue —
    /// that is the whole point of per-queue interrupts — and the rest live in
    /// [`Self::extra_intids`]. Kept as a distinguished first rather than as an
    /// array with a length, because every existing caller wants "the device's
    /// interrupt" and would otherwise have to decide which of several it meant.
    intid: Option<u32>,
    /// The device's other interrupt lines, if it has any.
    extra_intids: [Option<u32>; MAX_EXTRA_IRQS],
    /// The DMA aperture this device currently translates through — the body of
    /// its live **lease**. `None` means no lease is out: either the machine has
    /// no IOMMU (the honest state that must be reported rather than quietly
    /// treated as an aperture covering everything), or no driver has yet asked
    /// this device for DMA, or the last one gave the device up.
    aperture: Option<DeviceAperture>,
    /// The process holding that lease. Recorded because a lease outlives the
    /// handle table that justified it: a dead driver's capabilities are
    /// reclaimed in bulk, so by teardown there is nothing left to ask.
    lease_holder: Option<ObjectId>,
    /// The scheduler tick after which this lease is no longer held, or `None`
    /// for one that does not expire.
    ///
    /// **Ticks, and honest about it.** They are the only monotonic source the
    /// kernel has, so this is a *liveness* bound rather than a deadline in the
    /// wall-clock sense: it answers "is the holder still asking for this" and
    /// not "how long has it been". A lease that expires is one whose holder
    /// stopped renewing, which is the one case none of the other end-reasons
    /// can express — nothing happened, and that is the point.
    lease_expires_at: Option<u64>,
    /// What the device *is*, where the kernel learned it during enumeration.
    ///
    /// `None` for a device whose identity is in its own registers — a
    /// virtio-mmio transport says what it is at offset 8, and a manager
    /// holding a capability can read it. PCI is why this field exists: a
    /// function's class lives in config space, which is not per-device and
    /// therefore not delegable, so the kernel reads it once and records it
    /// here rather than handing anyone the bus (build/README.md, D114).
    identity: Option<DeviceIdentity>,
    /// This device's own slice of configuration space `(phys_base, len)`, set
    /// when a bus controller declared it.
    ///
    /// **The scoping, as a field.** Configuration space is one flat window per
    /// host bridge, so a capability to the whole of it is authority over every
    /// device behind that bridge — which is why the kernel had to read it on
    /// drivers' behalf. A declaration names a function's slot inside a window
    /// the declarer already holds, so the kernel can record 4 KiB of it here
    /// and `MapConfig` hands out that and nothing adjacent.
    config: Option<(u64, u64)>,
    /// What this device forwards, if it is a bus. `None` for everything else.
    bus_window: Option<BusWindow>,
    /// Whether this device genuinely requires **physically contiguous** memory
    /// — no scatter-gather capability and no IOMMU on its path.
    ///
    /// The graph records it because it is a fact about the machine's topology
    /// that neither the device nor its driver can establish: a driver knows
    /// whether its hardware can follow a scattered buffer, and only the graph
    /// knows whether anything translates for it. `docs/hardware/04` makes this
    /// the gate on honouring a physical-contiguity request at all, so that
    /// carveout pressure stays proportional to hardware that actually needs it.
    requires_contiguity: bool,
    /// Where this device's configuration structures sit inside its window,
    /// when the kernel resolved them. `None` for a transport whose register
    /// layout is fixed and needs no discovery — a virtio-mmio slot — and for a
    /// function whose capabilities did not describe a usable set.
    layout: Option<DeviceLayout>,
    /// Where this device's interrupts are being delivered, and to whom — the
    /// live **interrupt route**, the third thing a binding hands a driver
    /// alongside its register window and its DMA lease.
    ///
    /// `None` means nobody is receiving this device's interrupts: either none
    /// is wired, or the driver that was receiving them gave the device up.
    /// **Several, because a multi-queue controller has several.** One line per
    /// queue means one route per queue, and a graph that held a single route
    /// would leave every line but the first outliving its driver — which is
    /// exactly the hole routing was introduced to close.
    irq_routes: [Option<IrqRoute>; 1 + MAX_EXTRA_IRQS],
    /// Endpoints belonging to services that depend on this device, and must be
    /// told when its driver fails — ladder step 4.
    ///
    /// A **dependency edge in the graph**, which is the only place it can
    /// live: the dependent is a process, the device is a capability, and the
    /// relation outlives both the driver that is failing and the message that
    /// announces it. Held as endpoints rather than as process ids because what
    /// a notification needs is somewhere to be delivered, and a process is not
    /// that — a service with no endpoint registered cannot be told anything,
    /// and pretending otherwise would make the notification look sent.
    dependents: [Option<crate::ipc::EndpointId>; MAX_DEPENDENTS],
    /// Whether policy has stopped offering this device.
    ///
    /// A quarantined node stays in the graph — it is still a real device at a
    /// real address, and forgetting it would make the machine's inventory a
    /// lie — but the kernel will not hand its capability back to a manager, so
    /// nothing can bind it again. That is the enforcement behind
    /// `docs/drivers/01`'s *"device quarantine"*: not a flag a manager is
    /// trusted to respect, but a capability it never receives.
    quarantined: bool,
    /// The device this one sits behind — a PCI function's bridge, a hub's
    /// upstream port — or `None` for one attached directly.
    ///
    /// **One edge, pointing up, and no list pointing down.** Children are found
    /// by scanning the pool, which is eight slots; keeping a second copy of the
    /// relationship would mean two records that can disagree, and a
    /// `MAX_CHILDREN` constant that is wrong for some machine. Up is also the
    /// direction the questions are actually asked in: "may this capability
    /// reach that device" walks upward from the device, and "what goes when
    /// this bridge goes" is the same walk read backwards.
    ///
    /// `docs/drivers/01` ("Bus Topology And Data Paths"): bus controllers are
    /// drivers whose children are drivers. This is the edge that makes the
    /// binding tree a tree rather than a list.
    parent: Option<ObjectId>,
    /// Whether this device's interrupt is armed as a **system wakeup source**.
    ///
    /// A property of the node rather than of the route, and that is the point:
    /// a route says where interrupts go, and this says whether one of them may
    /// wake a machine that has stopped. They are different authorities — every
    /// driver with an interrupt has the first, and `docs/power/01` requires
    /// the second to be an explicit, auditable set — so arming needs
    /// `Rights::WAKE` and leaves a mark here that the interrupt bridge reads.
    wake_source: bool,
}

/// Services that may depend on one device.
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_DEPENDENTS;

/// A device's live interrupt route: the port its interrupts wake, the process
/// holding that port, and the controller line they arrive on.
///
/// The INTID is copied in rather than read back from [`DeviceNode::intid`] at
/// teardown for the same reason [`crate::process::DeviceWindow`] records its
/// extent: what has to be undone is what was actually installed, and the
/// node's INTID may have been re-registered since.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IrqRoute {
    /// The port the bridge signals when the line fires.
    pub port: PortId,
    /// The process holding that port — recorded for the same reason
    /// [`DeviceNode::lease_holder`] is: a route outlives the handle table that
    /// justified it, so by teardown there is nothing left to ask.
    pub holder: ObjectId,
    /// The interrupt-controller line, as the controller numbers it.
    pub intid: u32,
}

/// Why an interrupt route ended — the payload of `DEVICE_IRQ_REVOKED`.
///
/// The same three departures a DMA lease has ([`LeaseEndReason`]), and
/// deliberately the same values: a capability leaves a process by being handed
/// on, by being dropped, or by the process ceasing to exist, and everything
/// the capability authorized follows it out by whichever route it took.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum RouteEndReason {
    /// The capability was transferred to another process.
    Transferred = 1,
    /// The last handle naming the device was closed.
    HandleClosed = 2,
    /// The holder is gone — it died, or was torn down.
    HolderGone = 3,
    /// The device was removed from the machine — a line that can no longer
    /// assert, belonging to a driver that has not asked for anything.
    Removed = 4,
}

/// The seam between the kernel's record of which interrupts belong to which
/// driver and the controller that actually delivers them.
///
/// The counterpart of [`DmaMapper`], and it exists for the same reason: the
/// kernel core knows *that* a device interrupts and which port that wakes, and
/// must not know what a GIC or a PLIC is. So a port implements this and hands
/// it to the dispatcher alongside the frame allocator and the IOMMU.
///
/// **Masking is not optional and cannot fail.** A route ends on a departure
/// path — a capability handed on, a handle closed, a process torn down — where
/// there is no caller left to act on a refusal and nothing to unwind. A
/// controller that returns without masking leaves the line asserting into a
/// port whose holder is gone, which on a level-triggered source is an
/// interrupt storm the system has no way to stop.
pub trait InterruptRouter {
    /// Stops delivering `intid`.
    fn mask(&mut self, intid: u32);
}

/// A device's normalized identity, as the kernel learned it.
///
/// Every field here is a **binding input** (`docs/drivers/01`, "Driver
/// Binding") and every one of them is enumeration's answer rather than
/// anybody's choice. That division is what the manifest depends on: a manager
/// observes these, and the policy it matches them against comes from
/// somewhere a device cannot reach.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceIdentity {
    /// PCI class register bits 23:16 class, 15:8 subclass, 7:0 prog-if.
    pub class_code: u32,
    pub vendor: u16,
    pub device: u16,
    /// Bus/device/function packed as `bus << 8 | device << 3 | function`.
    pub bdf: u16,
    /// The hardware revision, as the bus reports it. A binding input on its
    /// own: a driver may support a device from revision 3 onward and not
    /// before, and a manifest that could not say so would have to claim every
    /// revision or none.
    pub revision: u8,
    /// Which bus this was found on.
    pub bus: DeviceBus,
}

/// Which bus a device was found on. Values are ABI (`device_abi.isl`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum DeviceBus {
    /// The graph does not say — matched by no manifest rule that names a bus.
    Unknown = 0,
    Pci = 1,
    VirtioMmio = 2,
    Platform = 3,
}

/// Where a device's configuration structures sit **inside its granted
/// window**.
///
/// The answer to D126's open item. A virtio-pci function does not say where
/// its controls are in any register it exposes — it says so in config space,
/// one vendor capability per structure, each naming a BAR and an offset. Config
/// space is not per-device, so no capability to it can be handed out; the
/// kernel reads it during enumeration and this is where it puts what it found.
///
/// **Offsets, not addresses.** Telling a driver where its structures are and
/// telling it where they are in physical memory are different things: the
/// first is usable by a process that mapped a capability, and the second is a
/// fact about the machine no driver should be given.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeviceLayout {
    pub common: u32,
    pub notify: u32,
    /// The notify capability's queue multiplier. Not an offset, and carried
    /// here because it is discovered in the same walk and the offsets are
    /// useless without it.
    pub notify_multiplier: u32,
    pub isr: u32,
    pub device_config: u32,
}

/// What a **bus controller** needs to enumerate what is behind it, and nothing
/// more.
///
/// Present only on a host bridge. A driver of an ordinary device has no use for
/// any of it, and reporting it everywhere would be handing out the machine's
/// address map to every process that holds a NIC.
///
/// **A config length and no config base.** The controller maps its window with
/// `MapDevice` and works in the address the kernel chose, so where
/// configuration space sits in physical memory stays a fact about the machine —
/// the same rule [`DeviceLayout`]'s offsets follow. The forwarded window is the
/// exception and has to be: a BAR holds a machine address, and a controller
/// that could not name one could not place a single device.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BusWindow {
    /// How far the granted configuration window reaches.
    pub config_len: u64,
    /// The memory window this bus forwards, as the CPU addresses it.
    pub forward_cpu_base: u64,
    /// The same window as a device behind the bridge addresses it.
    pub forward_bus_base: u64,
    pub forward_len: u64,
    /// The bus numbers the window covers, inclusive.
    pub first_bus: u8,
    pub last_bus: u8,
    /// **The interrupt lines this bus may declare a device on**, as a first
    /// INTID and a count.
    ///
    /// The wire-shaped half of what a bus forwards. Memory has had a
    /// containment check since declarations existed — a device's register
    /// window must lie inside what its bus forwards — and an interrupt needs
    /// the same one for the same reason: without it a bus driver could declare
    /// a device on somebody else's line and have the graph route that line to
    /// itself.
    ///
    /// **Zero lines is the default and the honest one.** A PCI bridge forwards
    /// memory and no wires; its functions interrupt by message, through a
    /// different door entirely. So a bus that has never been given a range can
    /// declare no interrupt at all, and every bus that existed before this
    /// field did keeps exactly the authority it had.
    pub first_intid: u32,
    pub intid_count: u32,
}

/// Interrupt lines a device may have beyond its first.
///
/// Declared in `config/kernel.config`: the number and the reasoning
/// above moved there together, so a machine can be sized without editing
/// this module.
pub use crate::config::MAX_EXTRA_IRQS;

/// Every interrupt line one device can have: its first, plus the extras.
///
/// Named because [`DeviceTable::intids_of_object`] fills a caller's buffer and
/// **stops when the buffer ends**, which for a short buffer is the silent
/// dropping of a line — the failure the constant above is written to prevent,
/// one layer up. A caller that takes `&mut [u32; MAX_IRQ_LINES]` cannot be
/// given one.
pub const MAX_IRQ_LINES: usize = 1 + MAX_EXTRA_IRQS;

/// Where the object ids of **declared** devices start.
///
/// Minted here for the same recorded reason memory objects are minted in
/// `crate::memory` and not by the object table: three of the five ports have no
/// `ObjectTable` at all and fabricate ids with `ObjectId::from_raw`, so a fresh
/// table would alias them. A reserved range above the fabricated ids, above
/// `ObjectTable`'s raw values, and above the memory objects' base keeps all
/// three apart until the ports gain a real table.
pub const DECLARED_DEVICE_ID_BASE: u32 = 0x2000;

/// The DMA aperture a device translates through: the address space it may
/// reach, and nothing else.
///
/// This is the graph's record of a fact enforced elsewhere — an IOMMU holds
/// the translation tables and refuses what they do not cover. What the graph
/// needs to know is which address space belongs to which device, and how much
/// of it has been handed out, because that is what a DMA allocation for that
/// device has to come from.
///
/// `next` grows and never reuses **within one lease**. A device-visible address
/// handed out once must not name different memory later: a device may hold it
/// in a descriptor ring the kernel cannot see, and reuse would turn a stale
/// descriptor into a write to whatever now occupies the address.
///
/// Across leases it may, and that is the whole point of a lease. Ending one
/// tears down the device's translations, so an address the device still
/// remembers now **faults** instead of resolving — which is the "way to know
/// the device has forgotten" that recycling was waiting for. See
/// [`DmaMapper::end_lease`] and [`Self::release`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceAperture {
    /// The lowest device-visible address in the aperture.
    pub base: u64,
    /// Its length in bytes.
    pub len: u64,
    /// The next unallocated device-visible address.
    pub next: u64,
}

impl DeviceAperture {
    /// An empty aperture over `[base, base + len)`.
    pub const fn new(base: u64, len: u64) -> Self {
        Self {
            base,
            len,
            next: base,
        }
    }

    /// Takes the next `len` bytes, returning the device-visible address, or
    /// `None` when the aperture is exhausted.
    ///
    /// Exhaustion is a refusal, not a wrap: an aperture that started reissuing
    /// its low addresses would hand a driver something a device already
    /// believes means something else.
    pub fn allocate(&mut self, len: u64) -> Option<u64> {
        let at = self.next;
        let end = at.checked_add(len)?;
        if end > self.base.checked_add(self.len)? {
            return None;
        }
        self.next = end;
        Some(at)
    }

    /// Whether `address` lies inside this aperture.
    pub const fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < self.len
    }

    /// Returns every address to the pool, for reuse by the next lease.
    ///
    /// **Only correct after the device's translations are gone.** Calling this
    /// while the IOMMU still resolves the addresses it releases would reissue
    /// an address the device can still reach — the exact failure the
    /// never-reuse rule exists to prevent. The one caller is the lease
    /// teardown, which invalidates first.
    pub const fn release(&mut self) {
        self.next = self.base;
    }

    /// How much of the aperture has been handed out.
    pub const fn used(&self) -> u64 {
        self.next - self.base
    }
}

/// Why a DMA lease ended — the payload of `DEVICE_DMA_LEASE_ENDED`.
///
/// The first two values are deliberately `WindowRevokeReason`'s, because they
/// are the same two departures: a capability leaves a process by being handed
/// on or by being dropped, and a lease and a register window both follow it
/// out. The third has no window counterpart, and that asymmetry is the reason
/// this milestone exists — a window dies with the address space, a translation
/// in an IOMMU does not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum LeaseEndReason {
    /// The capability was transferred to another process.
    Transferred = 1,
    /// The last handle naming the device was closed.
    HandleClosed = 2,
    /// The holder is gone — it died, or was torn down.
    HolderGone = 3,
    /// The device faulted and policy isolated it — the one route a lease can
    /// end by that the *device*, rather than its driver, provoked.
    FaultIsolated = 4,
    /// The device was removed from the machine.
    Removed = 5,
    /// The lease's deadline passed without a renewal.
    ///
    /// Distinct from every other reason here because nothing *happened*: no
    /// capability moved, no device misbehaved, no holder died. A lease ends
    /// this way precisely when its holder has stopped saying it still wants
    /// one, which is the case none of the others can express.
    Expired = 6,
}

/// What an IOMMU refused, normalized across units.
///
/// A port maps its unit's own encoding onto this; nothing above the port sees
/// an SMMUv3 event type or a VT-d fault reason. The mapping belongs there
/// because that is the only layer that knows both vocabularies, and the
/// normalization belongs *somewhere* because a consumer that had to know which
/// IOMMU produced a record could not read a fleet.
///
/// The values are ABI (`kernel_event.isl`, `DEVICE_DMA_FAULT`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum DmaFaultKind {
    /// The unit reported something this kernel does not classify. Kept as a
    /// value rather than dropped: a fault nobody can name is still a fault,
    /// and a record saying so is what makes the gap visible.
    Unclassified = 0,
    /// The address has no translation — an aperture's boundary doing its job.
    Unmapped = 1,
    /// The address is mapped, but not for what the device tried to do.
    Permission = 2,
    /// The unit has no configuration for the stream at all: a device whose
    /// stream table entry was never installed. The same missing DMA as
    /// [`Self::Unmapped`] and the opposite cause, which is exactly why the
    /// two are not folded together.
    UnknownStream = 3,
    /// The configuration exists and is malformed — the kernel's own bug.
    BadConfiguration = 4,
}

/// One refusal, as the kernel records it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DmaFault {
    /// The device whose transaction was refused, when the port could resolve
    /// the unit's stream to one. `None` is a real answer, not a lookup
    /// failure: a fault on a stream no capability is backed by is a fact
    /// about the machine's wiring worth recording.
    pub device: Option<ObjectId>,
    /// The raw stream (or equivalent requester) id the unit named — kept even
    /// when `device` resolves, so a record can be joined back to the hardware.
    pub stream: u32,
    /// The address the device asked for.
    pub address: u64,
    pub kind: DmaFaultKind,
}

/// What the system does about a DMA fault.
///
/// `docs/drivers/01` ("DMA Safety") says faults *"are logged and can trigger
/// driver isolation"* — two clauses, and the "can" is the policy. Logging is
/// unconditional; isolation is a decision, and a decision needs somewhere to
/// be written down rather than being implied by which code path ran.
///
/// The values are ABI (`kernel_event.isl`, `DEVICE_DMA_ISOLATED`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum IsolationPolicy {
    /// Record the fault and change nothing. The right policy for a device
    /// whose driver is *expected* to probe an aperture's edge — and for a
    /// machine still being brought up, where isolating on the first fault
    /// would hide every fault after it.
    Report = 1,
    /// End the device's lease: it stops reaching anything at all, rather than
    /// merely being refused the one address it asked for. The driver finds
    /// out on its next DMA, which is a refusal it can report.
    EndLease = 2,
    /// End the lease **and** stop the process holding it. The driver does not
    /// get to find out; the crash-recovery ladder does.
    ///
    /// Stopping is not done here — this type has no scheduler — so
    /// [`DmaFaultOutcome::stop`] names the holder and the caller performs it.
    /// A caller that ignores it has not applied this policy, which is why the
    /// outcome is `#[must_use]`.
    EndLeaseAndStop = 3,
}

/// What isolating a fault actually did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[must_use]
pub struct DmaFaultOutcome {
    /// Whether a live lease was torn down. `false` under
    /// [`IsolationPolicy::Report`], and also when the device had no lease to
    /// end — a fault from a device nobody has leased is the wiring being
    /// wrong, and there is nothing to isolate.
    pub isolated: bool,
    /// The process the caller must stop, under
    /// [`IsolationPolicy::EndLeaseAndStop`] and only when a lease was
    /// actually found to end.
    pub stop: Option<ObjectId>,
}

/// The seam between the graph's record of an aperture and the hardware that
/// enforces it: whatever installs a device-visible address in an IOMMU's
/// translation tables.
///
/// The kernel core knows that a device translates and which addresses belong to
/// it; it does not know what an SMMUv3 or a DMAR unit is, and must not — the
/// IOMMU is a port's device, of which four of the five ports have none. So a
/// port that has one implements this and hands it to the dispatcher alongside
/// the frame allocator, and a port that has none passes `None` and says so in
/// every grant it makes (`DEVICE_DMA_UNSCOPED`).
///
/// **No allocation.** Neither `begin_lease` nor `map` may ask for a frame,
/// because a mapper that allocates fails halfway through installing a
/// translation, and unwinding an IOMMU table is a harder job than sizing it up
/// front. An implementation builds its translation structures once, when it is
/// brought up, and the lease operations only write into what already exists.
/// This is why a lease has a bounded length rather than growing.
///
/// **The lifecycle is the point** (`docs/drivers/01`, "DMA Safety": *IOMMU
/// mappings are scoped to a device and lease*). A lease begins when a driver
/// first asks its device for DMA and ends when the driver stops holding the
/// device — by any route, including dying. Ending it is what makes an address
/// safe to issue again, so an implementation that returns from `end_lease`
/// without actually invalidating turns the next lease's first allocation into
/// a stale descriptor's target.
pub trait DmaMapper {
    /// Whether `device`'s DMA passes through this unit at all.
    ///
    /// This, not the resource graph, is the authority on whether a device is
    /// scoped: it is a fact about how the machine is wired, and a mapper knows
    /// it because it is the thing the device's transactions arrive at. A
    /// `false` here is what makes a grant honestly unscoped rather than
    /// refused (`DEVICE_DMA_UNSCOPED`).
    fn translates(&self, device: ObjectId) -> bool;

    /// Gives `device` an address space and returns it as `(base, len)`, with
    /// nothing mapped in it yet — the device can reach exactly nothing until
    /// [`Self::map`] says otherwise.
    ///
    /// **The mapper chooses the range, not the caller.** How wide an address
    /// space a device can be given is a property of the translation structures
    /// in front of it — an SMMUv3 stream whose table describes one 2 MiB span
    /// cannot honour a request for more, and a kernel that picked a range would
    /// be guessing at a constraint only the hardware knows. Asking removes the
    /// failure mode rather than handling it.
    ///
    /// Called only for a device this mapper [`Self::translates`], and only when
    /// it has no live lease. An implementation clears any translations left
    /// over from a previous lease here, so a new lease can never inherit one.
    fn begin_lease(&mut self, device: ObjectId) -> Result<(u64, u64), KError>;

    /// Makes `[iova, iova + len)` name the physical memory at `[phys, phys +
    /// len)` for `device`, and nothing else name it.
    ///
    /// `iova` and `len` are page-aligned and the range lies inside the lease
    /// the graph holds for `device` — the caller has already checked both. An
    /// implementation that does not recognize `device`, or cannot describe
    /// that range, **refuses**: returning `Ok` for a translation that was not
    /// installed would hand a driver an address its device cannot reach, or
    /// worse, one that resolves somewhere else.
    fn map(&mut self, device: ObjectId, iova: u64, phys: u64, len: u64) -> Result<(), KError>;

    /// Stops `[iova, iova + len)` naming anything for `device`, so a
    /// transaction to it faults instead of resolving.
    ///
    /// **Why this exists when [`Self::end_lease`] says a lease does not
    /// shrink.** That rule is about revocation *imposed on a driver*: "which of
    /// these addresses is the driver still entitled to" is not a question a
    /// dead driver can answer, so its lease goes all at once. This is the
    /// opposite situation — a live driver handing back a buffer it still knows
    /// about, naming the range itself. The lease is untouched; one attachment
    /// inside it ends.
    ///
    /// Returns a `Result` for the same reason `end_lease` does not: there is a
    /// live caller here, and it must not mistake a failure for "the device can
    /// no longer reach that memory". A refusal means the translation may still
    /// be there, and the caller keeps treating the memory as reachable.
    ///
    /// The address is **not** reusable afterwards. A device may hold it in a
    /// descriptor ring the kernel cannot see, and only ending the lease is a
    /// point at which the device is known to have forgotten
    /// ([`DeviceAperture`]).
    fn unmap(&mut self, device: ObjectId, iova: u64, len: u64) -> Result<(), KError>;

    /// Ends `device`'s lease: every translation it has goes away, and the
    /// address range becomes reusable.
    ///
    /// **All at once, and never refusing.** A lease ends, it does not shrink —
    /// the same all-or-nothing shape as register-window revocation (D93),
    /// because "which of these addresses is the driver still entitled to" is
    /// not a question a dead driver can answer. And a teardown path cannot
    /// meaningfully fail: there is nothing to unwind and no caller that could
    /// act on a refusal, so anything that goes wrong is reported as an event
    /// rather than returned.
    ///
    /// Ending a lease that does not exist is a no-op, so callers on the
    /// departure paths need not first ask whether there was one.
    fn end_lease(&mut self, device: ObjectId);
}

/// The seam between the kernel's decision to reset a device and the code that
/// knows how — ladder step 5, *"device reset is attempted if policy allows"*.
///
/// The third seam of this shape, after [`DmaMapper`] and [`InterruptRouter`],
/// and the one where the "per class" in `docs/drivers/01` actually lands. The
/// kernel core knows *that* a degraded device should be reset and *whether
/// policy permits it*; how to reset one is a fact about a transport — write
/// zero to a virtio status register, pulse a PCIe function-level reset, toggle
/// a platform line — and every one of those is register access the kernel core
/// must not contain.
///
/// The implementation is handed the graph's identity for the device so it can
/// dispatch on class — `None` for a device the kernel never enumerated, which
/// is a virtio-mmio transport saying what it is in its own registers — and the
/// device's register window, because resetting one means writing to it and the
/// window's base is the capability's authority rather than the resetter's to
/// choose.
///
/// **A reset this cannot perform is a refusal, not a no-op.** A resetter that
/// returned `Ok` for a class it does not know would have the ladder record a
/// successful reset of a device nothing touched, and the next rung would be
/// taken on a false premise.
pub trait DeviceResetter {
    fn reset(
        &mut self,
        device: ObjectId,
        identity: Option<DeviceIdentity>,
        window: Option<(u64, u64)>,
    ) -> Result<(), KError>;
}

/// When a device may be reset.
///
/// `docs/drivers/01` says a reset is attempted *"if policy allows"*, which
/// means there has to be a policy to consult rather than a call site that
/// always tries. Resetting is not free: it drops the device's state, and on a
/// shared controller it can disturb functions that were working.
///
/// The values are ABI (`kernel_event.isl`, `DEVICE_RESET`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum ResetPolicy {
    /// Never reset. The right policy for a device whose reset would disturb
    /// something else, and the conservative default for a class nobody has
    /// characterised.
    Never = 1,
    /// Reset a device that has been marked degraded — the ladder's own step,
    /// after a crash has been contained and before the host is restarted.
    OnDegraded = 2,
    /// Reset before every bind, degraded or not: a device inherited from
    /// firmware, or from a driver that died without tidying up, is in a state
    /// nobody has characterised.
    OnEveryBind = 3,
}

/// Records one refused DMA transaction.
///
/// **Unconditional, and a free function so that it can be.** `docs/drivers/01`
/// ("DMA Safety") says faults "are logged and can trigger driver isolation" —
/// two clauses with different preconditions. Isolation needs the resource
/// graph and lives on the executive
/// ([`crate::exec::Executive::isolate_dma_fault`]); logging needs nothing, and
/// making it need nothing is what lets a port harvest faults from contexts
/// where no executive exists — early boot, or an interrupt that lands between
/// two checks. A fault the system saw and did not record is worse than one it
/// did not act on.
///
/// A fault naming a stream no device is backed by is recorded too, with
/// `device: None`. That is the kernel's own stream wiring being wrong, and it
/// is precisely the case a "resolve the device or return" guard would hide.
pub fn record_dma_fault(fault: &DmaFault) {
    crate::event::emit(
        crate::event::EventKind::DeviceDmaFault,
        crate::event::Severity::Error,
        crate::event::Component::Driver,
        [
            fault.device.map_or(0, |d| d.raw() as u64),
            fault.address,
            fault.kind as u64,
            u64::from(fault.stream),
        ],
    );
}

/// A fixed pool of device nodes — the normalized resource graph.
pub struct DeviceTable {
    nodes: [Option<DeviceNode>; MAX_DEVICES],
    /// The next object id a declaration will mint.
    next_declared: u32,
}

impl DeviceTable {
    pub const fn new() -> Self {
        Self {
            nodes: [const { None }; MAX_DEVICES],
            next_declared: DECLARED_DEVICE_ID_BASE,
        }
    }

    /// Registers a device node backing `object` with the I/O range `[base,
    /// base+len)` and interrupt line `irq`, or [`KError::OutOfMemory`] if the
    /// graph is full. The manager/boot populates the graph before granting.
    pub fn register(
        &mut self,
        object: ObjectId,
        base: u16,
        len: u16,
        irq: u8,
        rights: Rights,
    ) -> Result<(), KError> {
        let slot = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.nodes[slot] = Some(DeviceNode {
            object,
            rights,
            base,
            len,
            irq,
            mmio: None,
            intid: None,
            extra_intids: [None; MAX_EXTRA_IRQS],
            identity: None,
            aperture: None,
            lease_holder: None,
            lease_expires_at: None,
            irq_routes: [None; 1 + MAX_EXTRA_IRQS],
            config: None,
            bus_window: None,
            requires_contiguity: false,
            layout: None,
            dependents: [None; MAX_DEPENDENTS],
            quarantined: false,
            parent: None,
            wake_source: false,
        });
        Ok(())
    }

    /// Registers a device node backing `object` with the MMIO register window
    /// `[base, base+len)` (physical), or [`KError::OutOfMemory`] if the graph is
    /// full. The port fields are left empty — this is an MMIO-only node, the shape
    /// a memory-mapped device (e.g. virtio-mmio) grants to a ring-3 driver (D77).
    pub fn register_mmio(
        &mut self,
        object: ObjectId,
        base: u64,
        len: u64,
        rights: Rights,
    ) -> Result<(), KError> {
        let slot = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.nodes[slot] = Some(DeviceNode {
            object,
            rights,
            base: 0,
            len: 0,
            irq: 0,
            mmio: Some((base, len)),
            intid: None,
            extra_intids: [None; MAX_EXTRA_IRQS],
            identity: None,
            aperture: None,
            lease_holder: None,
            lease_expires_at: None,
            irq_routes: [None; 1 + MAX_EXTRA_IRQS],
            config: None,
            bus_window: None,
            requires_contiguity: false,
            layout: None,
            dependents: [None; MAX_DEPENDENTS],
            quarantined: false,
            parent: None,
            wake_source: false,
        });
        Ok(())
    }

    /// Registers a device the kernel enumerated and can therefore describe:
    /// its register window, the authority the graph holds over it, and what it
    /// is. The MMIO counterpart of [`Self::register_mmio`] for a bus whose
    /// devices do not identify themselves through their own registers.
    pub fn register_identified(
        &mut self,
        object: ObjectId,
        base: u64,
        len: u64,
        rights: Rights,
        identity: DeviceIdentity,
    ) -> Result<(), KError> {
        let slot = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        self.nodes[slot] = Some(DeviceNode {
            object,
            rights,
            base: 0,
            len: 0,
            irq: 0,
            mmio: Some((base, len)),
            intid: None,
            extra_intids: [None; MAX_EXTRA_IRQS],
            identity: Some(identity),
            aperture: None,
            lease_holder: None,
            lease_expires_at: None,
            irq_routes: [None; 1 + MAX_EXTRA_IRQS],
            config: None,
            bus_window: None,
            requires_contiguity: false,
            layout: None,
            dependents: [None; MAX_DEPENDENTS],
            quarantined: false,
            parent: None,
            wake_source: false,
        });
        Ok(())
    }

    /// Records that `child` sits behind `parent` — the topology edge, applied
    /// to a node that is already registered.
    ///
    /// A separate step rather than a fourth `register_*`, following
    /// [`Self::set_mmio_irq`]: every registration path can acquire an edge, and
    /// the alternative is a fourth copy of the node literal that the next field
    /// has to be added to as well.
    ///
    /// **Three refusals, and each is a graph that would answer questions
    /// wrongly rather than a caller being clumsy.** An edge to a device that is
    /// not in the graph names nothing, so a later walk would stop early and
    /// report a subtree smaller than the machine's. A device parented to itself
    /// is a one-node cycle. And an edge that closes a longer cycle makes
    /// "everything below this" unanswerable — the walk that tears a subtree
    /// down would never finish, which on a departure path is a hang with the
    /// hardware already gone.
    pub fn set_parent(&mut self, child: ObjectId, parent: ObjectId) -> Result<(), KError> {
        if child == parent {
            return Err(KError::InvalidArgument);
        }
        if !self.nodes.iter().flatten().any(|n| n.object == parent) {
            return Err(KError::BadHandle);
        }
        // Walking up from the proposed parent must not arrive back at the
        // child. Bounded by the pool: a chain longer than every node is already
        // a cycle, whatever it looks like locally.
        let mut ancestor = Some(parent);
        for _ in 0..MAX_DEVICES {
            match ancestor {
                None => break,
                Some(id) if id == child => return Err(KError::InvalidArgument),
                Some(id) => ancestor = self.parent_of(id),
            }
        }
        for node in self.nodes.iter_mut().flatten() {
            if node.object == child {
                node.parent = Some(parent);
                return Ok(());
            }
        }
        Err(KError::BadHandle)
    }

    /// Whether the graph holds a node for `id` at all.
    pub fn contains(&self, id: ObjectId) -> bool {
        self.nodes.iter().flatten().any(|node| node.object == id)
    }

    /// The device `id` sits behind, if any.
    pub fn parent_of(&self, id: ObjectId) -> Option<ObjectId> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .and_then(|node| node.parent)
    }

    /// The devices sitting directly behind `id`, written to `out`. Returns how
    /// many; a full `out` truncates, which is why callers size it at
    /// [`MAX_DEVICES`].
    pub fn children_of(&self, id: ObjectId, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for node in self.nodes.iter().flatten() {
            if node.parent != Some(id) {
                continue;
            }
            if n == out.len() {
                break;
            }
            out[n] = node.object;
            n += 1;
        }
        n
    }

    /// Whether `id` is `root` or sits anywhere below it.
    ///
    /// **Reflexive on purpose.** The question every caller asks is "does
    /// authority over `root` extend to `id`", and it plainly does when they are
    /// the same device. A strict version would make every caller write the
    /// equality case itself, and one of them would forget.
    pub fn is_descendant_of(&self, id: ObjectId, root: ObjectId) -> bool {
        let mut at = Some(id);
        for _ in 0..=MAX_DEVICES {
            match at {
                None => return false,
                Some(current) if current == root => return true,
                Some(current) => at = self.parent_of(current),
            }
        }
        false
    }

    /// Records the interrupt-controller INTID of an already-registered MMIO
    /// device (the IRQ half of its resource-graph payload, D84).
    pub fn set_mmio_irq(&mut self, object: ObjectId, intid: u32) -> Result<(), KError> {
        for node in self.nodes.iter_mut().flatten() {
            if node.object == object {
                node.intid = Some(intid);
                return Ok(());
            }
        }
        Err(KError::BadHandle)
    }

    /// Records another interrupt line for `object` — what a multi-queue
    /// controller has, one per queue.
    ///
    /// Refused when the graph has no room rather than dropped: a queue whose
    /// completions reach nobody is a driver that waits forever, and a
    /// registration that said no is far easier to find than that.
    pub fn add_mmio_irq(&mut self, object: ObjectId, intid: u32) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == object)
            .ok_or(KError::BadHandle)?;
        if node.intid.is_none() {
            node.intid = Some(intid);
            return Ok(());
        }
        let slot = node
            .extra_intids
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(KError::LimitExceeded)?;
        *slot = Some(intid);
        Ok(())
    }

    /// Every interrupt line `object` has, written to `out`; returns how many.
    ///
    /// All of them, because re-arming after a completion is per *device* on
    /// this system — a driver that took one queue's interrupt has no way to
    /// name the line it arrived on, and re-enabling a line that is already
    /// enabled costs nothing. What would cost something is leaving one masked:
    /// that queue's next completion would never arrive.
    pub fn intids_of_object(&self, id: ObjectId, out: &mut [u32]) -> usize {
        let Some(node) = self.nodes.iter().flatten().find(|node| node.object == id) else {
            return 0;
        };
        let mut count = 0;
        for intid in core::iter::once(node.intid).chain(node.extra_intids) {
            match (intid, out.get_mut(count)) {
                (Some(intid), Some(slot)) => {
                    *slot = intid;
                    count += 1;
                }
                _ => break,
            }
        }
        count
    }

    /// Arms or disarms `object`'s interrupt as a system wakeup source.
    ///
    /// Refuses a device with **no interrupt wired**, rather than recording an
    /// arming that can never fire. A wakeup source that cannot produce a wake
    /// is indistinguishable at every later point from one that simply has not
    /// fired yet, and a machine that suspended trusting it would never come
    /// back — so the one moment it can be caught is here.
    pub fn set_wake_source(&mut self, object: ObjectId, armed: bool) -> Result<(), KError> {
        for node in self.nodes.iter_mut().flatten() {
            if node.object == object {
                if armed && node.intid.is_none() {
                    return Err(KError::InvalidArgument);
                }
                node.wake_source = armed;
                return Ok(());
            }
        }
        Err(KError::BadHandle)
    }

    /// Whether `object` is armed as a wakeup source.
    pub fn is_wake_source(&self, object: ObjectId) -> bool {
        self.nodes
            .iter()
            .flatten()
            .any(|node| node.object == object && node.wake_source)
    }

    /// The armed wakeup source whose interrupt is `intid`, if any.
    ///
    /// The lookup the interrupt bridge does, in the direction an interrupt
    /// actually arrives: a controller hands over a line number, and the
    /// question is whether *this machine* said that line may wake it. Reading
    /// it out of the graph rather than out of a list the boot glue keeps is
    /// what makes a device's departure take its wake capability with it —
    /// removing the node removes the answer.
    pub fn armed_wake_source(&self, intid: u32) -> Option<ObjectId> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.wake_source && node.intid == Some(intid))
            .map(|node| node.object)
    }

    /// Resolves a Device object id to its interrupt INTID, if one is wired —
    /// the gate a ring-3 `IrqComplete` resolves through.
    /// Every object this graph backs, so a caller can ask "is this handle a
    /// device?" without knowing how the graph is stored. Returns how many were
    /// written; `out` shorter than the graph truncates, which is why callers
    /// size it at [`MAX_DEVICES`].
    pub fn objects(&self, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for node in self.nodes.iter().flatten() {
            if n == out.len() {
                break;
            }
            out[n] = node.object;
            n += 1;
        }
        n
    }

    /// What `id` is, if the kernel learned it during enumeration. `None` means
    /// "ask the device", not "no such device".
    pub fn identity_of_object(&self, id: ObjectId) -> Option<DeviceIdentity> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .and_then(|node| node.identity)
    }

    /// Records the aperture `id` translates through, held by `holder` — the
    /// live lease.
    ///
    /// `holder` is what makes the lease end at the right time: the departure
    /// paths ask "whose lease was this?" *after* the capability has already
    /// been taken out of the process's handle table (a corpse's handles are
    /// reclaimed in bulk), so the handle table can no longer answer it.
    pub fn set_aperture(
        &mut self,
        id: ObjectId,
        holder: ObjectId,
        aperture: DeviceAperture,
        expires_at: Option<u64>,
    ) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
            .ok_or(KError::BadHandle)?;
        node.aperture = Some(aperture);
        node.lease_holder = Some(holder);
        node.lease_expires_at = expires_at;
        Ok(())
    }

    /// Pushes `id`'s lease deadline to `expires_at`. `false` when there is no
    /// live lease, or when `holder` is not the one holding it — a renewal is a
    /// statement by the holder about its own lease, and letting anyone else
    /// make it would let a second process keep a lease alive that its owner
    /// had stopped wanting.
    pub fn renew_lease(&mut self, id: ObjectId, holder: ObjectId, expires_at: Option<u64>) -> bool {
        match self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
        {
            Some(node) if node.aperture.is_some() && node.lease_holder == Some(holder) => {
                node.lease_expires_at = expires_at;
                true
            }
            _ => false,
        }
    }

    /// Every live lease whose deadline is at or before `now`, written into
    /// `out` as `(device, holder)`. Returns how many.
    pub fn leases_expired_by(&self, now: u64, out: &mut [(ObjectId, ObjectId)]) -> usize {
        let mut n = 0;
        for node in self.nodes.iter().flatten() {
            if n == out.len() {
                break;
            }
            let (Some(holder), Some(deadline)) = (node.lease_holder, node.lease_expires_at) else {
                continue;
            };
            if node.aperture.is_some() && deadline <= now {
                out[n] = (node.object, holder);
                n += 1;
            }
        }
        n
    }

    /// The aperture `id` translates through, if it has a live lease.
    pub fn aperture_of_object(&self, id: ObjectId) -> Option<DeviceAperture> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .and_then(|node| node.aperture)
    }

    /// Who holds `id`'s lease, if anyone does.
    pub fn lease_holder_of_object(&self, id: ObjectId) -> Option<ObjectId> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .and_then(|node| node.lease_holder)
    }

    /// Every device `holder` holds a lease on, in `out`; returns how many.
    /// The sweep a departing process's teardown walks.
    pub fn leases_held_by(&self, holder: ObjectId, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for node in self.nodes.iter().flatten() {
            if n == out.len() {
                break;
            }
            if node.lease_holder == Some(holder) {
                out[n] = node.object;
                n += 1;
            }
        }
        n
    }

    /// Ends `id`'s lease in the graph, returning what it covered so the caller
    /// can report it. The **hardware** teardown is the mapper's
    /// ([`DmaMapper::end_lease`]) and must happen with this, never instead of
    /// it: dropping the record alone would leave the device still reaching the
    /// memory while the kernel believed otherwise.
    pub fn end_lease(&mut self, id: ObjectId) -> Option<DeviceAperture> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)?;
        node.lease_holder = None;
        node.lease_expires_at = None;
        let mut ended = node.aperture.take()?;
        // Released as it leaves the graph: the value handed back describes what
        // the lease covered, and the pool it came from is the mapper's.
        ended.release();
        Some(ended)
    }

    /// Removes `id`'s node from the graph entirely, returning its dependents so
    /// they can be told.
    ///
    /// **This is what makes a removed device's capability invalid rather than
    /// merely unheld.** Every syscall that reaches a device resolves it through
    /// this table — `MapDevice`, `DmaAlloc`, `DmaAttach`, `DeviceInfo`,
    /// `IrqComplete`, `DriverLifecycle` — so once the node is gone they all
    /// refuse, and not one of them had to learn a new rule. A handle that
    /// somehow outlives the removal names nothing.
    ///
    /// Deliberately **not** quarantine, which is the opposite situation:
    /// a quarantined node stays in the graph because it is still a real device
    /// at a real address that policy has stopped offering. A removed one is not
    /// there any more, and a graph that kept it would be describing a machine
    /// that does not exist.
    ///
    /// The **hardware and holder teardown is the caller's**, and must already
    /// have happened: this drops the kernel's last record of the device, so a
    /// lease or route still live at this point becomes unreachable rather than
    /// ended. `Executive::remove_device` is the caller that gets that order
    /// right.
    ///
    /// The same applies **downward**: children are the caller's to remove
    /// first. Any that remain are detached here rather than left pointing at a
    /// slot that is empty or, worse, at one a later registration reuses — an
    /// orphan whose parent id has been handed to a different device would be
    /// reported as sitting behind hardware it has never been near.
    pub fn remove(
        &mut self,
        id: ObjectId,
    ) -> Option<[Option<crate::ipc::EndpointId>; MAX_DEPENDENTS]> {
        let slot = self
            .nodes
            .iter()
            .position(|node| matches!(node, Some(node) if node.object == id))?;
        let dependents = self.nodes[slot].map(|node| node.dependents);
        self.nodes[slot] = None;
        for node in self.nodes.iter_mut().flatten() {
            if node.parent == Some(id) {
                node.parent = None;
            }
        }
        dependents
    }

    /// Takes `len` bytes from `id`'s lease, returning the device-visible
    /// address. `None` when the device has no live lease or it is exhausted —
    /// two different facts a caller must not conflate, which is why the
    /// caller checks [`Self::aperture_of_object`] to tell them apart.
    pub fn allocate_in_aperture(&mut self, id: ObjectId, len: u64) -> Option<u64> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)?;
        node.aperture.as_mut()?.allocate(len)
    }

    /// Records where `id`'s configuration structures sit inside its window.
    ///
    /// Called during enumeration, by the only code that can know: the kernel
    /// reading a bus's config space. A driver cannot discover this for itself,
    /// which is the whole reason the graph holds it.
    pub fn set_layout(&mut self, id: ObjectId, layout: DeviceLayout) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
            .ok_or(KError::BadHandle)?;
        node.layout = Some(layout);
        Ok(())
    }

    /// Where `id`'s structures are, if the kernel resolved them. `None` is an
    /// answer — a transport whose layout is fixed — and not a lookup failure.
    pub fn layout_of_object(&self, id: ObjectId) -> Option<DeviceLayout> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .and_then(|node| node.layout)
    }

    /// Records what a bus forwards. Applied to a node already registered, like
    /// [`Self::set_parent`] and for the same reason.
    pub fn set_bus_window(&mut self, id: ObjectId, window: BusWindow) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|n| n.object == id)
            .ok_or(KError::BadHandle)?;
        node.bus_window = Some(window);
        Ok(())
    }

    /// Records that `id` cannot follow a scattered buffer and has nothing
    /// translating for it.
    pub fn set_requires_contiguity(&mut self, id: ObjectId, required: bool) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|n| n.object == id)
            .ok_or(KError::BadHandle)?;
        node.requires_contiguity = required;
        Ok(())
    }

    /// Whether `id` genuinely requires physically contiguous memory. `false`
    /// for a device the graph does not know, which is the safe answer: it makes
    /// a physical-contiguity request a refusal rather than a grant.
    pub fn requires_contiguity(&self, id: ObjectId) -> bool {
        self.nodes
            .iter()
            .flatten()
            .find(|n| n.object == id)
            .is_some_and(|n| n.requires_contiguity)
    }

    /// What `id` forwards, if it is a bus.
    pub fn bus_window_of_object(&self, id: ObjectId) -> Option<BusWindow> {
        self.nodes
            .iter()
            .flatten()
            .find(|n| n.object == id)
            .and_then(|n| n.bus_window)
    }

    /// This device's own configuration window `(phys_base, len)`, if it was
    /// declared with one.
    pub fn config_of_object(&self, id: ObjectId) -> Option<(u64, u64)> {
        self.nodes
            .iter()
            .flatten()
            .find(|n| n.object == id)
            .and_then(|n| n.config)
    }

    /// Registers a device a **bus controller** declared: its register window,
    /// its own slice of configuration space, and what the controller read out
    /// of that slice.
    ///
    /// A registration path of its own rather than a flag on
    /// [`Self::register_identified`], because it is the only one that records a
    /// config window — and the config window is the whole of what distinguishes
    /// a device somebody outside the kernel put in the graph from one the
    /// kernel walked to find.
    /// Mints the object id the next declaration will use.
    ///
    /// Monotonic and never reused, which is what stops a controller that
    /// declares, gives up and declares again from handing a driver a
    /// capability that names a device somebody else already holds.
    pub fn mint_declared_id(&mut self) -> Result<ObjectId, KError> {
        let raw = self.next_declared;
        self.next_declared = raw.checked_add(1).ok_or(KError::OutOfMemory)?;
        Ok(ObjectId::from_raw(raw))
    }

    pub fn register_declared(
        &mut self,
        object: ObjectId,
        register: Option<(u64, u64)>,
        config: Option<(u64, u64)>,
        rights: Rights,
        identity: DeviceIdentity,
    ) -> Result<(), KError> {
        let (base, len) = register.unwrap_or((0, 0));
        self.register_identified(object, base, len, rights, identity)?;
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|n| n.object == object)
            .ok_or(KError::BadHandle)?;
        node.config = config;
        // **A device with nothing to map holds no window at all**, rather than a
        // window of length zero. The difference matters: every path that maps
        // or allocates against a device asks for its window first, and one that
        // answered `Some((0, 0))` would send `MapDevice` off to map the page at
        // physical zero. `None` is what makes those paths refuse on their own
        // rather than each needing to remember this case.
        if register.is_none() {
            node.mmio = None;
        }
        Ok(())
    }

    /// Records that `id`'s interrupts wake `port`, held by `holder`, on the
    /// line the graph has for the device.
    ///
    /// The INTID comes from the node rather than the caller, for the same
    /// reason a `MapDevice` reads the physical base from the node: which line
    /// a device interrupts on is the capability's authority, and a caller that
    /// could name it could route another device's interrupts to itself.
    /// [`KError::InvalidMapping`] when the device has no line wired — routing
    /// interrupts that cannot arrive is a request worth refusing rather than
    /// recording.
    pub fn route_irq(
        &mut self,
        id: ObjectId,
        port: PortId,
        holder: ObjectId,
    ) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
            .ok_or(KError::BadHandle)?;
        let intid = node.intid.ok_or(KError::InvalidMapping)?;
        Self::install_route(node, intid, port, holder)
    }

    /// Routes one **named** line of `id` to `port` — what a controller with a
    /// vector per queue needs, since each queue's completions must reach a
    /// different port for the port to identify the queue.
    ///
    /// The line must be one the graph recorded for this device. A route for an
    /// interrupt nobody registered would deliver whatever else raises that
    /// number to a driver that never asked for it, and would survive that
    /// driver's death with nothing to attribute it to.
    pub fn route_irq_line(
        &mut self,
        id: ObjectId,
        intid: u32,
        port: PortId,
        holder: ObjectId,
    ) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
            .ok_or(KError::BadHandle)?;
        let known = core::iter::once(node.intid)
            .chain(node.extra_intids)
            .flatten()
            .any(|line| line == intid);
        if !known {
            return Err(KError::InvalidMapping);
        }
        Self::install_route(node, intid, port, holder)
    }

    /// Records a route, replacing the one for that line if it already had one.
    ///
    /// Replacing rather than adding a second, because a line delivers to one
    /// place: two routes for one interrupt would mean the sweep ended one and
    /// left the other, and the driver that thought it had given the device up
    /// would go on receiving.
    fn install_route(
        node: &mut DeviceNode,
        intid: u32,
        port: PortId,
        holder: ObjectId,
    ) -> Result<(), KError> {
        let route = IrqRoute {
            port,
            holder,
            intid,
        };
        if let Some(slot) = node
            .irq_routes
            .iter_mut()
            .find(|slot| slot.map(|r| r.intid) == Some(intid))
        {
            *slot = Some(route);
            return Ok(());
        }
        let slot = node
            .irq_routes
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(KError::LimitExceeded)?;
        *slot = Some(route);
        Ok(())
    }

    /// Where `id`'s interrupts are being delivered, if anywhere.
    pub fn irq_route_of_object(&self, id: ObjectId) -> Option<IrqRoute> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .and_then(|node| node.irq_routes.iter().flatten().next().copied())
    }

    /// Every device whose interrupts `holder` is receiving, in `out`; returns
    /// how many. The sweep a departing process's teardown walks, by device for
    /// the same reason [`Self::leases_held_by`] is: nothing can enumerate the
    /// holders of an object.
    pub fn irq_routes_held_by(&self, holder: ObjectId, out: &mut [ObjectId]) -> usize {
        let mut n = 0;
        for node in self.nodes.iter().flatten() {
            if n == out.len() {
                break;
            }
            // Once per device however many of its lines this holder receives:
            // the sweep ends all of a device's routes when it reaches it, and
            // listing it twice would make it try again on a device with none
            // left.
            if node
                .irq_routes
                .iter()
                .flatten()
                .any(|route| route.holder == holder)
            {
                out[n] = node.object;
                n += 1;
            }
        }
        n
    }

    /// Ends `id`'s interrupt route in the graph, returning what it covered so
    /// the caller can unbind the port and mask the line. Ending a route that
    /// does not exist is a no-op, so the departure paths need not first ask
    /// whether there was one.
    ///
    /// The **hardware** teardown is the router's ([`InterruptRouter::mask`])
    /// and must happen with this, never instead of it: dropping the record
    /// alone would leave the line still asserting into a port whose holder is
    /// gone, while the kernel believed nobody was listening.
    pub fn end_irq_route(&mut self, id: ObjectId) -> Option<IrqRoute> {
        self.nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)?
            .irq_routes
            .iter_mut()
            .find(|slot| slot.is_some())?
            .take()
    }

    /// Registers `endpoint` as depending on `id`, so it is told when this
    /// device's driver fails.
    ///
    /// Duplicate registrations are idempotent rather than an error: a service
    /// that reconnects should not have to remember whether it already
    /// registered, and a second entry would have it notified twice for one
    /// failure. [`KError::LimitExceeded`] when the device has no room left —
    /// refused, never silently dropped, because a dependent that believes it
    /// is registered and is not will wait for ever.
    pub fn add_dependent(
        &mut self,
        id: ObjectId,
        endpoint: crate::ipc::EndpointId,
    ) -> Result<(), KError> {
        let node = self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
            .ok_or(KError::BadHandle)?;
        if node.dependents.iter().flatten().any(|e| *e == endpoint) {
            return Ok(());
        }
        let slot = node
            .dependents
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(KError::LimitExceeded)?;
        *slot = Some(endpoint);
        Ok(())
    }

    /// The endpoints depending on `id`, in `out`; returns how many.
    pub fn dependents_of(&self, id: ObjectId, out: &mut [crate::ipc::EndpointId]) -> usize {
        let Some(node) = self.nodes.iter().flatten().find(|node| node.object == id) else {
            return 0;
        };
        let mut n = 0;
        for endpoint in node.dependents.iter().flatten() {
            if n == out.len() {
                break;
            }
            out[n] = *endpoint;
            n += 1;
        }
        n
    }

    /// Stops offering `id`: policy has decided it is not to be bound again.
    ///
    /// Returns whether this changed anything, so a caller does not emit a
    /// second `DEVICE_QUARANTINED` for a device that was already quarantined.
    pub fn quarantine(&mut self, id: ObjectId) -> bool {
        match self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
        {
            Some(node) if !node.quarantined => {
                node.quarantined = true;
                true
            }
            _ => false,
        }
    }

    /// Offers `id` again — the administrative undo, and the only route out of
    /// quarantine. Deliberately not reachable from any failure path: a device
    /// that could take itself out of quarantine is not quarantined.
    pub fn release_from_quarantine(&mut self, id: ObjectId) -> bool {
        match self
            .nodes
            .iter_mut()
            .flatten()
            .find(|node| node.object == id)
        {
            Some(node) if node.quarantined => {
                node.quarantined = false;
                true
            }
            _ => false,
        }
    }

    /// Whether policy has stopped offering `id`. `false` for a device the
    /// graph has never heard of — which is not the same fact, and callers that
    /// need to tell them apart ask the graph first.
    pub fn is_quarantined(&self, id: ObjectId) -> bool {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .is_some_and(|node| node.quarantined)
    }

    /// The authority the graph holds over `id` — what a kernel-originated
    /// hand-out of this device carries.
    pub fn rights_of_object(&self, id: ObjectId) -> Option<Rights> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .map(|node| node.rights)
    }

    pub fn intid_of_object(&self, id: ObjectId) -> Option<u32> {
        for node in self.nodes.iter().flatten() {
            if node.object == id {
                return node.intid;
            }
        }
        None
    }

    /// Resolves an object id to its device node's I/O range — the handle→range
    /// bridge a `DeviceIo` syscall uses after looking the handle up in the
    /// caller's table (a linear scan, the `ProcessTable::process_of_id` pattern).
    pub fn device_of_object(&self, id: ObjectId) -> Option<(u16, u16)> {
        for node in self.nodes.iter().flatten() {
            if node.object == id {
                return Some((node.base, node.len));
            }
        }
        None
    }

    /// Resolves a Device object id to its MMIO register window `(phys_base, len)` —
    /// the handle→window bridge a `MapDevice` syscall uses to map the granted
    /// window into a ring-3 driver's address space. `None` for a port-only node.
    pub fn mmio_of_object(&self, id: ObjectId) -> Option<(u64, u64)> {
        for node in self.nodes.iter().flatten() {
            if node.object == id {
                return node.mmio;
            }
        }
        None
    }

    /// The interrupt line recorded for the device backing `object`, if any.
    pub fn irq_of_object(&self, id: ObjectId) -> Option<u8> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.object == id)
            .map(|node| node.irq)
    }
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/devmgr.rs"]
mod tests;
