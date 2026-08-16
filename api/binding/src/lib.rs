// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The **binding manifest**: the policy data a device manager matches a
//! device against, and the rules for matching it.
//!
//! `docs/drivers/01-driver-framework.md` ("Driver Binding") lists ten binding
//! *inputs* and six *outputs*. The manager had one of each: it matched on
//! device class, and the answer was a capability. That is not a binding
//! decision, it is a lookup — and the difference shows the moment a machine
//! has two devices of one class that must not run the same driver, or a driver
//! whose signature the system does not trust, or a device whose firmware is
//! too old for the driver that would otherwise match it.
//!
//! # Where each input comes from, and why that matters
//!
//! The ten inputs divide into two kinds, and conflating them is how a binding
//! policy becomes unenforceable:
//!
//! - **Facts about the device** — class, vendor and product id, revision,
//!   firmware version, bus type. These come from enumeration. A manager
//!   *observes* them; it cannot choose them, and neither can a driver.
//! - **Policy about the driver** — security domain, power domain, driver
//!   signature, contract version, product policy. These come from the
//!   manifest. They are decisions somebody made, and a system that read them
//!   from the device would be letting the device decide what it is allowed to
//!   do.
//!
//! [`DeviceFacts`] is the first kind and [`ManifestEntry`] the second.
//! [`SystemPolicy`] is the third thing neither of them is: what *this*
//! installation permits, against which a manifest entry is itself checked. A
//! manifest is a vendor's claim about a driver; the system policy is the
//! operator's answer to it, and an entry that satisfies its own claims can
//! still be refused.
//!
//! # Why a refusal has a reason
//!
//! [`Refusal`] is an enum and not a `None`. A device that stays unbound
//! because nothing matched, one that stays unbound because its driver is
//! unsigned, and one that stays unbound because the operator disabled its
//! product policy are three different administrative situations with three
//! different fixes — and a manager that reported them identically would leave
//! every one of them looking like missing hardware.
//!
//! # What the path costs
//!
//! Everything above is about a device and a driver. `docs/drivers/01` ("Bus
//! Topology And Data Paths") adds a question about neither: **where the device
//! sits**. A transfer either crosses no extra process — the controller gave it
//! per-child queue separation — or it relays through the bus host, and a
//! relaying class contract "declares its added latency and throughput cost" so
//! that "a deep tree of relaying hubs is a declared cost, not a surprise".
//!
//! So a manifest entry declares two things it did not before: what passing
//! *through* it costs ([`ManifestEntry::relay`]) and what its own path may cost
//! ([`ManifestEntry::max_latency_us`], [`ManifestEntry::min_throughput_mbps`]).
//! [`select`] accumulates the first along the ancestors it is given and checks
//! the second — which is the doc's last clause, that a class "cannot meet its
//! budget on direct-attach and silently miss it behind two hubs without the
//! declaration making that arithmetic visible at binding time".
//!
//! Two identical devices differing only in where they are attached therefore
//! get different answers, and the one that is refused is told the arithmetic
//! rather than left to discover the miss at run time.
//!
//! **Reported always, enforced rarely.** Refusing a binding is a strong act,
//! and a system whose job is to bind every device it has should do it for a
//! reason somebody chose. So the figures are an output of every successful
//! binding, and a *refusal* needs two things to line up: an entry that named a
//! budget ([`ManifestEntry::max_latency_us`] or
//! [`ManifestEntry::min_throughput_mbps`] set), and an installation that
//! enforces them ([`SystemPolicy::enforce_path_budgets`]). An entry that named
//! no budget binds wherever it sits, however deep and however undescribed the
//! hubs above it — it asked no question the path could answer wrongly.
//!
//! That matters because the buses this runs on today have nothing to enforce
//! against: PCIe gives each function its own queues, so every real path costs
//! zero. The case the budgets exist for is a bus where transfers genuinely
//! relay through a host — USB hubs above all — and the declaration is here
//! first so that arriving at one is not a redesign.
//!
//! Normative: docs/drivers/01-driver-framework.md ("Driver Binding", "Bus
//! Topology And Data Paths")

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// Which bus a device was found on — a binding input, because the same
/// vendor and product id can mean different things behind different buses,
/// and because a driver written for one transport cannot drive the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum BusKind {
    /// The manager could not determine it. Matched by nothing: a rule that
    /// accepted an unknown bus would bind a driver to a transport it has not
    /// been shown to speak.
    Unknown = 0,
    Pci = 1,
    VirtioMmio = 2,
    Platform = 3,
}

/// What the manager observed about a device. Every field is enumeration's
/// answer, not anybody's choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceFacts {
    /// The driver-facing class (`driver_bind.isl`'s `DeviceClass`).
    pub class: u32,
    pub vendor: u16,
    pub product: u16,
    /// The hardware revision, as the bus reports it.
    pub revision: u8,
    pub bus: BusKind,
    /// The device's firmware version, where it reports one.
    ///
    /// **Zero means it did not say**, which is not the same as version zero
    /// and is why this is checked against a minimum only when a minimum is
    /// set: refusing a silent device for being too old would refuse every
    /// device that has no firmware to speak of.
    pub firmware_version: u32,
}

/// Product policy bits — the operator's switches, and the input that has
/// nothing to do with the hardware at all.
///
/// A bitmask rather than an enum because these compose: a device can be
/// permitted for a class of user *and* required to be in a particular
/// security domain, and a single-valued policy would force one of those to be
/// expressed somewhere else.
pub mod product_policy {
    /// The entry may be bound at all. A cleared bit is an operator having
    /// switched a driver off, which is a different situation from no driver
    /// existing and is reported as one.
    pub const ENABLED: u32 = 0x1;
    /// The device may be bound before the system reaches its normal
    /// operating state — a boot disk, a console.
    pub const EARLY_BOOT: u32 = 0x2;
    /// The device may be handed to a driver that is not part of the base
    /// system image.
    pub const THIRD_PARTY: u32 = 0x4;
}

/// Services a bound driver requires — a binding *output*, told to the driver
/// so it knows what it may ask for, and to the system so it knows what to
/// start first.
pub mod required_service {
    /// A log sink.
    pub const LOGGING: u32 = 0x1;
    /// A source of firmware images.
    pub const FIRMWARE: u32 = 0x2;
    /// The power manager, for a driver that votes on states.
    pub const POWER: u32 = 0x4;
    /// A source of persistent configuration.
    pub const CONFIG: u32 = 0x8;
}

/// What one relaying ancestor adds to every transfer passing through it.
///
/// Both numbers are **declarations**, not measurements. Nothing here weighs a
/// hub; a class contract states what relaying through it costs and the system
/// holds it to that, which is what makes the arithmetic available at binding
/// time rather than after the budget has already been missed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelayCost {
    /// Added latency, microseconds.
    pub added_latency_us: u64,
    /// The most this hub can carry, Mbit/s.
    ///
    /// `None` is a hub that declares no ceiling — it does not narrow the path.
    /// Distinguishable from `Some(0)`, which is a hub declaring it can carry
    /// nothing and which no entry needing throughput can bind behind.
    pub throughput_mbps: Option<u32>,
}

/// One ancestor on the path between a device and the root, as
/// `docs/drivers/01` divides them.
///
/// The three variants are the doc's three sentences, and keeping them one type
/// is what lets [`select`]'s rule read the way the doc reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hop {
    /// The controller provides per-child queue separation: the child's queues
    /// are mapped to it directly, the controller host stays on the control
    /// path, and **the transfer crosses no extra process**. Not a hop at all,
    /// which is why the answer for a well-attached device is zero and not a
    /// small number.
    Separated,
    /// Transfers relay through this ancestor's host, at what its contract
    /// declared.
    ///
    /// A `RelayCost` of zero latency still counts as a hop. `docs/drivers/01`
    /// counts hops against the class budget in their own right, and a relay
    /// that claims to add no latency is a claim about latency — not a claim to
    /// have stopped being a process in the path.
    Relay(RelayCost),
    /// Nothing in the manifest claims this ancestor, so what it costs is
    /// **unknown**.
    ///
    /// Deliberately not `Separated`. Treating an ancestor nobody declared as
    /// free is the silent fallback `docs/lifecycle/04` forbids: it would let a
    /// device behind an undescribed hub bind as though it were direct-attached,
    /// and the arithmetic that was supposed to be visible would be a guess.
    Undeclared,
}

/// One manifest entry: which devices it claims, and what binding one produces.
///
/// The match fields are `Option`, and that is load-bearing. `None` is "this
/// entry does not care", which is what lets one entry cover a whole class and
/// another cover exactly one revision of one product — and it is
/// distinguishable from `Some(0)`, which is a real vendor id that a
/// wildcard-as-zero encoding would have quietly swallowed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ManifestEntry {
    // --- Inputs this entry matches on ---
    pub class: u32,
    pub vendor: Option<u16>,
    pub product: Option<u16>,
    /// The lowest hardware revision this driver supports.
    pub min_revision: Option<u8>,
    pub bus: Option<BusKind>,
    /// The lowest device firmware version this driver supports. Checked only
    /// against a device that reported one.
    pub min_firmware: Option<u32>,

    // --- Policy this entry declares about itself ---
    /// The security domain the driver runs in. Checked against the system
    /// policy's permitted set: a manifest cannot grant itself a domain.
    pub security_domain: u32,
    /// The power domain the device belongs to, so the power manager can
    /// arbitrate across everything sharing it.
    pub power_domain: u32,
    /// The signature over the driver image. Checked against the system's
    /// trusted set; zero is an unsigned driver, which a policy may refuse.
    pub driver_signature: u64,
    /// The class contract version the driver implements.
    pub contract_version: u32,
    /// The operator's switches for this entry.
    pub product_policy: u32,

    // --- What this entry costs a path, and what it needs from one ---
    /// What passing **through** a driver bound by this entry costs.
    ///
    /// `None` is per-child queue separation — nothing relays, so this driver
    /// adds no hop to the devices behind it. `Some(..)` is a relaying bus host.
    /// Most entries are `None`, and an entry for a device with nothing behind
    /// it is `None` because the question does not arise.
    pub relay: Option<RelayCost>,
    /// The most added path latency a device bound by this entry tolerates.
    ///
    /// `None` is "this entry does not constrain its path", which is
    /// distinguishable from `Some(0)` — an entry that will bind only a
    /// direct-attached device. Same reason `min_firmware` is an `Option`: a
    /// zero-as-wildcard encoding would have swallowed a real requirement.
    pub max_latency_us: Option<u64>,
    /// The least path throughput a device bound by this entry needs, Mbit/s.
    /// `None` does not constrain.
    pub min_throughput_mbps: Option<u32>,

    // --- Outputs this entry produces ---
    /// Services the driver requires.
    pub required_services: u32,
    /// The channel this driver is updated through. Zero is a driver that does
    /// not update independently of the system image.
    pub update_channel: u32,
    /// The firmware image a driver bound by this entry needs, by store entry
    /// name. `None` is a driver that loads no firmware — most of them.
    ///
    /// **The manifest declares the need and judges none of it.** Whether an
    /// image may actually be loaded is `api/firmware`'s question, asked of the
    /// kernel that holds the store; an entry that decided it here would be
    /// deciding an anti-rollback policy from a device manifest.
    pub firmware_name: Option<&'static str>,
    /// The lowest image version a driver bound by this entry understands.
    /// Meaningless without `firmware_name`, and zero constrains nothing.
    pub firmware_min_image_version: u32,
    /// Whether a driver bound by this entry may reach its device's
    /// **configuration space**.
    ///
    /// A manifest decision and not a consequence of the bus, which is the whole
    /// reason `Rights::CONFIGURE` is a right of its own. Configuration space is
    /// where bus mastering is turned on, where a BAR can be moved out from
    /// under whoever placed it, and where message-signalled interrupts are
    /// armed; a driver that only reads registers needs none of it, and granting
    /// it to every driver on a bus that has config space would make the right a
    /// consequence again. `false` for a device whose bus has no such space at
    /// all, where the grant would gate nothing.
    pub grants_configure: bool,
    /// Whether a driver bound by this entry may **declare devices behind its
    /// own** — `Rights::DERIVE`.
    ///
    /// A manifest decision like the one above, and for a sharper reason: a
    /// driver holding this can put nodes in the resource graph, which is
    /// authority over what the rest of the system will bind drivers to. It
    /// belongs to entries whose devices are buses — a host controller with card
    /// children, a bridge — and to nothing else, because a driver that cannot
    /// populate a bus is merely limited while one that can and should not is a
    /// driver inventing hardware.
    pub grants_derive: bool,
}

/// What this installation permits, against which a manifest entry is checked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SystemPolicy {
    /// Signatures the system trusts. An entry whose signature is not here is
    /// refused however well it matches.
    pub trusted_signatures: &'static [u64],
    /// Whether an unsigned driver (`driver_signature == 0`) may bind. False
    /// on a production system; true is a development posture, and having it
    /// as a field rather than as an absent check is what makes that posture a
    /// decision somebody took.
    pub allow_unsigned: bool,
    /// Security domains a driver may run in here.
    pub permitted_domains: &'static [u32],
    /// The oldest class contract version this system's clients can speak.
    pub min_contract_version: u32,
    /// Whether the system has reached its normal operating state. Before it
    /// has, only entries with `EARLY_BOOT` may bind.
    pub early_boot: bool,
    /// Whether a declared data-path cost may **refuse** a binding, as opposed
    /// to merely being reported.
    ///
    /// A field rather than an absent check, for the reason [`Self::allow_unsigned`]
    /// is one: enforcing path budgets is a posture somebody takes, and the
    /// operator who takes it should be able to see that they did.
    ///
    /// **False is the reasonable default for a machine with no relaying bus.**
    /// PCIe root ports and switches give each function its own configuration
    /// and its own queues, so nothing relays and every path costs zero; the
    /// budgets have nothing to bite on and an enforcement mistake could only
    /// strand hardware. The case they exist for is a bus where transfers really
    /// do relay through a host — USB hubs above all — and turning enforcement
    /// on belongs with the arrival of one.
    ///
    /// The figures are accumulated and reported either way. Nothing about what
    /// a driver is *told* depends on this.
    pub enforce_path_budgets: bool,
}

/// Why a device was not bound.
///
/// Each variant is a different administrative situation with a different fix,
/// which is the whole reason this is not a `None`. A manager that reported
/// them identically would leave an unsigned driver, a disabled policy and
/// absent hardware all looking the same to whoever has to fix it.
///
/// The values are ABI (`driver_bind.isl`'s `BindReply.status`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Refusal {
    /// No entry claims this device. The ordinary answer for hardware nobody
    /// has written a driver for.
    NoMatch = 1,
    /// An entry claims it, and the driver's signature is not trusted here.
    UntrustedSignature = 2,
    /// The driver implements a contract version older than this system's
    /// clients speak.
    ContractTooOld = 3,
    /// The driver wants a security domain this installation does not permit.
    DomainNotPermitted = 4,
    /// The device's firmware is older than the driver supports.
    FirmwareTooOld = 5,
    /// An operator switched this entry off.
    PolicyDisabled = 6,
    /// The entry is not permitted this early in boot.
    NotAllowedYet = 7,
    /// The declared latency of the path to this device is more than the entry
    /// tolerates. The fix is to attach the device closer — it is the only
    /// refusal here whose cause is neither the driver, the installation nor
    /// the device, but where the device sits.
    BudgetExceeded = 8,
    /// The narrowest hop on the path cannot carry what the entry needs. A
    /// different situation from `BudgetExceeded` and with a different fix: a
    /// shorter path does not help if the remaining hop is the slow one.
    ThroughputTooLow = 9,
    /// Something on the path to this device is claimed by no manifest entry,
    /// so what it costs is unknown — **and this entry named a budget that the
    /// unknown makes uncheckable**.
    ///
    /// Neither of the two above, because those are costs that were declared
    /// and found wanting. This is policy data that is missing, and the fix is
    /// to declare the hub rather than to move the device.
    ///
    /// An entry that named no budget is never refused this way. It asked no
    /// question about the path, so an unknown hop answers nothing wrongly —
    /// it is simply reported, and the binding says the figures are a lower
    /// bound (`Binding::path_complete`).
    PathUndeclared = 10,
    /// The entry declares firmware this device cannot be given: the image is
    /// missing, or policy refused the one that is there.
    ///
    /// **A refusal to bind rather than a bind without firmware.** A driver that
    /// was told it matched, handed its device, and left to discover that the
    /// image it declared a need for never arrived would be a driver running
    /// against hardware in a state nobody chose. Which firmware policy spoke is
    /// in the kernel's report to the manager, not here — this reply says only
    /// that the binding did not happen, which is what the driver can act on.
    FirmwareUnavailable = 11,
}

/// The binding a successful match produces — `docs/drivers/01`'s outputs, less
/// the three the *kernel* produces rather than the manifest: the host
/// identity, the granted capabilities, and the resource leases all come from
/// the transfer itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Binding {
    /// Index of the entry that matched, so a decision can be traced back to
    /// the line of policy that made it.
    pub entry: usize,
    pub required_services: u32,
    pub update_channel: u32,
    pub security_domain: u32,
    pub power_domain: u32,
    pub contract_version: u32,
    /// How many processes a transfer to this device relays through.
    pub relay_hops: u32,
    /// What those hops declared they add, in total. Zero for a device whose
    /// path relays through nothing, which is an answer and not an absence.
    pub accumulated_latency_us: u64,
    /// The narrowest hop on the path, Mbit/s; `None` when no hop declared a
    /// ceiling.
    pub path_throughput_mbps: Option<u32>,
    /// Whether the two figures above are the whole cost of the path.
    ///
    /// False when some hop's cost is unknown, which makes them a **lower
    /// bound**. Reported rather than folded into the numbers, because a
    /// consumer that treated a lower bound as a total would be doing exactly
    /// what counting an undeclared hop as free would have done.
    pub path_complete: bool,
    /// The firmware image this entry declares its driver needs, if any — and
    /// the version it needs of it.
    ///
    /// Carried out of `select` rather than looked up again by the caller: the
    /// entry that matched is a decision this made, and a manager re-deriving it
    /// could disagree with the binding it is acting on.
    pub firmware_name: Option<&'static str>,
    pub firmware_min_image_version: u32,
    /// Whether the driver this binding hands the device to may reach its
    /// configuration space. Carried out of `select` for the same reason the
    /// firmware name is: it is a decision the matched entry made, and a manager
    /// re-deriving it could disagree with the binding it is acting on.
    pub grants_configure: bool,
    /// Whether a driver bound by this entry may **declare devices behind its
    /// own** — `Rights::DERIVE`.
    ///
    /// A manifest decision like the one above, and for a sharper reason: a
    /// driver holding this can put nodes in the resource graph, which is
    /// authority over what the rest of the system will bind drivers to. It
    /// belongs to entries whose devices are buses — a host controller with card
    /// children, a bridge — and to nothing else, because a driver that cannot
    /// populate a bus is merely limited while one that can and should not is a
    /// driver inventing hardware.
    pub grants_derive: bool,
}

/// `BindReply.flags` bit 0: the reply's path figures are a lower bound, not a
/// total — some hop on the path has a cost nothing declared.
///
/// A flag rather than a sentinel in the numbers themselves: every value a hop
/// count or a latency can take is a legitimate one, so there is nothing to
/// reserve, and a consumer that ignores the flag still sees plausible figures
/// — which is precisely why the distinction has to be carried separately.
pub const BIND_FLAG_PATH_INCOMPLETE: u64 = 1 << 0;

/// What a path costs, accumulated from its hops.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PathCost {
    hops: u32,
    latency_us: u64,
    throughput_mbps: Option<u32>,
    /// Whether these numbers are the **whole** cost of the path.
    ///
    /// False when some ancestor's cost is unknown — nothing in the manifest
    /// claims it, or the total could not be represented. The figures above are
    /// then a lower bound rather than a total, which is a different thing and
    /// has to travel as one.
    complete: bool,
}

/// Adds up a path.
///
/// Latency **sums** and throughput takes the **minimum**: a relayed transfer
/// pays every hop's added latency, and a path is only as fast as its narrowest
/// hop. Nothing here refuses anything — this is what the path costs, and
/// whether that is acceptable is a question about an entry and an installation.
///
/// **An unknown hop makes the total incomplete rather than fatal.** Counting it
/// as free would be the silent fallback `docs/lifecycle/04` forbids; refusing
/// outright would strand a device whose driver never asked about latency. What
/// is true is that the sum is a lower bound, and `complete` is how that is said.
fn accumulate(path: &[Hop]) -> PathCost {
    let mut cost = PathCost {
        hops: 0,
        latency_us: 0,
        throughput_mbps: None,
        complete: true,
    };
    for hop in path {
        let relay = match hop {
            // Not a hop: the transfer crosses no extra process.
            Hop::Separated => continue,
            Hop::Undeclared => {
                // It is still a process in the path, so it counts as a hop —
                // what is unknown is what it costs, not that it is there.
                cost.hops += 1;
                cost.complete = false;
                continue;
            }
            Hop::Relay(relay) => relay,
        };
        cost.hops += 1;
        match cost.latency_us.checked_add(relay.added_latency_us) {
            Some(total) => cost.latency_us = total,
            // Unrepresentable. Saturating silently would present a number
            // nobody computed as one somebody did, so the total saturates *and*
            // says it is not a faithful one.
            None => {
                cost.latency_us = u64::MAX;
                cost.complete = false;
            }
        }
        if let Some(declared) = relay.throughput_mbps {
            cost.throughput_mbps = Some(match cost.throughput_mbps {
                Some(narrowest) => narrowest.min(declared),
                None => declared,
            });
        }
    }
    cost
}

/// Chooses a manifest entry for a device.
///
/// **Specificity first, then order.** Entries are scored by how many of their
/// optional match fields are set, and the most specific wins; ties go to the
/// earlier entry. Without that, a catch-all class entry placed before a
/// device-specific one would shadow it, and a manifest would depend on line
/// order in a way nobody could see from reading it.
///
/// **A device that matched something and was then refused reports why.** The
/// scan finds the best-matching entry first and applies policy to it,
/// deliberately rather than skipping refused entries and falling through to a
/// weaker match: falling through would silently bind a device to a less
/// specific driver because the right one was unsigned, which is the kind of
/// downgrade `docs/lifecycle/04` forbids doing quietly.
/// **The path is checked last and refuses rather than falling through.** A
/// device that met every policy and sits too deep is refused with the
/// arithmetic, not quietly handed to a less specific entry that happens to
/// tolerate more — that would be the same silent downgrade a failed signature
/// must not cause.
pub fn select(
    manifest: &[ManifestEntry],
    facts: &DeviceFacts,
    policy: &SystemPolicy,
    path: &[Hop],
) -> Result<Binding, Refusal> {
    let index = best_match(manifest, facts).ok_or(Refusal::NoMatch)?;
    let entry = &manifest[index];

    // Policy, in the order a failure is most worth knowing about. Signature
    // first: a driver the system does not trust is a different problem from
    // one that is merely misconfigured, and reporting the misconfiguration
    // would send somebody to fix the wrong thing.
    if entry.driver_signature == 0 {
        if !policy.allow_unsigned {
            return Err(Refusal::UntrustedSignature);
        }
    } else if !policy.trusted_signatures.contains(&entry.driver_signature) {
        return Err(Refusal::UntrustedSignature);
    }
    if !policy.permitted_domains.contains(&entry.security_domain) {
        return Err(Refusal::DomainNotPermitted);
    }
    if entry.contract_version < policy.min_contract_version {
        return Err(Refusal::ContractTooOld);
    }
    if entry.product_policy & product_policy::ENABLED == 0 {
        return Err(Refusal::PolicyDisabled);
    }
    if policy.early_boot && entry.product_policy & product_policy::EARLY_BOOT == 0 {
        return Err(Refusal::NotAllowedYet);
    }
    // Firmware last, because it is the only refusal a *device* can cause: the
    // ones above are all about the driver and the installation, and knowing
    // the difference is most of what a report is for.
    if let Some(minimum) = entry.min_firmware
        && facts.firmware_version != 0
        && facts.firmware_version < minimum
    {
        return Err(Refusal::FirmwareTooOld);
    }
    // The path, last of all. Everything above is about the driver, the
    // installation or the device itself; this is the only check about where the
    // device *is*, and reporting it before the others would send somebody to
    // rewire a machine whose driver was never going to be trusted anyway.
    //
    // **Always accumulated, conditionally enforced.** The numbers are an output
    // every driver gets; refusing on them takes both an entry that asked for a
    // budget and an installation that enforces them.
    let cost = accumulate(path);
    let budgeted = entry.max_latency_us.is_some() || entry.min_throughput_mbps.is_some();
    if policy.enforce_path_budgets && budgeted {
        // **The declared part first, even when the total is a lower bound.** A
        // path whose *known* hops already exceed the budget is over it whatever
        // the unknown one costs, and saying so names the more useful reason:
        // "this is too deep" sends somebody to move the device, where "some hub
        // is undescribed" would send them to write manifest entries that could
        // not change the answer.
        if let Some(budget) = entry.max_latency_us
            && cost.latency_us > budget
        {
            return Err(Refusal::BudgetExceeded);
        }
        if let Some(needed) = entry.min_throughput_mbps
            && cost
                .throughput_mbps
                .is_some_and(|narrowest| narrowest < needed)
        {
            return Err(Refusal::ThroughputTooLow);
        }
        // The known part fits — but a lower bound fitting is not evidence that
        // the real cost does, and this entry asked a question that cannot be
        // answered without the missing hop.
        if !cost.complete {
            return Err(Refusal::PathUndeclared);
        }
    }

    Ok(Binding {
        entry: index,
        required_services: entry.required_services,
        update_channel: entry.update_channel,
        security_domain: entry.security_domain,
        power_domain: entry.power_domain,
        contract_version: entry.contract_version,
        relay_hops: cost.hops,
        accumulated_latency_us: cost.latency_us,
        path_throughput_mbps: cost.throughput_mbps,
        path_complete: cost.complete,
        firmware_name: entry.firmware_name,
        firmware_min_image_version: entry.firmware_min_image_version,
        grants_configure: entry.grants_configure,
        grants_derive: entry.grants_derive,
    })
}

/// What one ancestor on a device's path contributes, according to the manifest.
///
/// **The other half of the accumulation rule, and it lives here for the same
/// reason the first half does.** Deciding *which* ancestors are hops is as much
/// policy as adding their costs up; a manager that made that decision itself
/// would put half the arithmetic somewhere no test can reach.
///
/// An ancestor no entry claims is [`Hop::Undeclared`] — never `Separated`.
pub fn hop_for(manifest: &[ManifestEntry], facts: &DeviceFacts) -> Hop {
    match best_match(manifest, facts) {
        None => Hop::Undeclared,
        Some(index) => match manifest[index].relay {
            None => Hop::Separated,
            Some(relay) => Hop::Relay(relay),
        },
    }
}

/// The index of the entry that claims `facts` most specifically, if any.
///
/// Ties keep the earlier entry, so order is a tie-break and never the whole
/// rule.
fn best_match(manifest: &[ManifestEntry], facts: &DeviceFacts) -> Option<usize> {
    let mut best: Option<(usize, u32)> = None;
    for (index, entry) in manifest.iter().enumerate() {
        let Some(score) = matches(entry, facts) else {
            continue;
        };
        // Strictly greater: see above.
        if best.is_none_or(|(_, best_score)| score > best_score) {
            best = Some((index, score));
        }
    }
    best.map(|(index, _)| index)
}

/// Whether `entry` claims `facts`, and how specifically.
///
/// The score is the number of optional fields the entry constrained, so an
/// entry naming a vendor and a product beats one naming a class alone. Class
/// is not scored: it is required of every entry, so it cannot distinguish
/// them.
fn matches(entry: &ManifestEntry, facts: &DeviceFacts) -> Option<u32> {
    if entry.class != facts.class {
        return None;
    }
    let mut score = 0;
    // A closure would need to mutate `score` and return early; written out so
    // each field's rule is visible where the field is.
    if let Some(vendor) = entry.vendor {
        if vendor != facts.vendor {
            return None;
        }
        score += 1;
    }
    if let Some(product) = entry.product {
        if product != facts.product {
            return None;
        }
        score += 1;
    }
    if let Some(minimum) = entry.min_revision {
        if facts.revision < minimum {
            return None;
        }
        score += 1;
    }
    if let Some(bus) = entry.bus {
        // An unknown bus matches nothing, even an entry that names one:
        // accepting it would bind a driver to a transport nobody established
        // it can speak.
        if bus != facts.bus || facts.bus == BusKind::Unknown {
            return None;
        }
        score += 1;
    }
    if entry.min_firmware.is_some() {
        // Scored but not filtered here: a firmware mismatch is a *refusal with
        // a reason*, not a non-match, because the operator's fix is to update
        // the device rather than to wonder why nothing claimed it.
        score += 1;
    }
    Some(score)
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
