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
mod tests {
    use super::*;

    const SIGNED: u64 = 0x00a1_1ce5;
    const BLOCK: u32 = 1;
    const NETWORK: u32 = 2;

    const POLICY: SystemPolicy = SystemPolicy {
        trusted_signatures: &[SIGNED],
        allow_unsigned: false,
        permitted_domains: &[0, 1],
        min_contract_version: 1,
        early_boot: false,
        // On for most of these cases: what the path rules do is what is under
        // test. The cases that turn it off say so.
        enforce_path_budgets: true,
    };

    const fn entry(class: u32) -> ManifestEntry {
        ManifestEntry {
            class,
            vendor: None,
            product: None,
            min_revision: None,
            bus: None,
            min_firmware: None,
            security_domain: 1,
            power_domain: 0,
            driver_signature: SIGNED,
            contract_version: 1,
            product_policy: product_policy::ENABLED,
            relay: None,
            max_latency_us: None,
            min_throughput_mbps: None,
            required_services: required_service::LOGGING,
            update_channel: 7,
        }
    }

    /// A hub declaring what relaying through it costs.
    const fn hub(added_latency_us: u64, throughput_mbps: Option<u32>) -> Hop {
        Hop::Relay(RelayCost {
            added_latency_us,
            throughput_mbps,
        })
    }

    const fn facts(class: u32) -> DeviceFacts {
        DeviceFacts {
            class,
            vendor: 0x1af4,
            product: 0x1042,
            revision: 2,
            bus: BusKind::Pci,
            firmware_version: 0,
        }
    }

    #[test]
    fn a_class_entry_binds_a_device_of_that_class_and_produces_its_outputs() {
        let manifest = [entry(BLOCK)];
        let binding = select(&manifest, &facts(BLOCK), &POLICY, &[]).expect("bound");
        assert_eq!(binding.entry, 0);
        assert_eq!(binding.required_services, required_service::LOGGING);
        assert_eq!(binding.update_channel, 7);
        assert_eq!(binding.contract_version, 1);
    }

    /// Nothing claims it. The ordinary answer for hardware nobody has written
    /// a driver for, and distinguishable from every refusal below.
    #[test]
    fn a_device_no_entry_claims_is_a_no_match() {
        let manifest = [entry(BLOCK)];
        assert_eq!(
            select(&manifest, &facts(NETWORK), &POLICY, &[]),
            Err(Refusal::NoMatch),
        );
    }

    /// **Specificity beats order.** A catch-all class entry placed first must
    /// not shadow a device-specific one, or a manifest's meaning would depend
    /// on line order in a way nobody could see from reading it.
    #[test]
    fn the_most_specific_entry_wins_regardless_of_where_it_sits() {
        let specific = ManifestEntry {
            vendor: Some(0x1af4),
            product: Some(0x1042),
            update_channel: 9,
            ..entry(BLOCK)
        };
        // The general entry first...
        let manifest = [entry(BLOCK), specific];
        assert_eq!(
            select(&manifest, &facts(BLOCK), &POLICY, &[])
                .expect("bound")
                .update_channel,
            9,
        );
        // ...and last. Same answer.
        let manifest = [specific, entry(BLOCK)];
        assert_eq!(
            select(&manifest, &facts(BLOCK), &POLICY, &[])
                .expect("bound")
                .update_channel,
            9,
        );
    }

    /// A tie goes to the earlier entry, so order is a tie-break and never the
    /// whole rule.
    #[test]
    fn equally_specific_entries_are_resolved_by_order() {
        let first = ManifestEntry {
            update_channel: 1,
            ..entry(BLOCK)
        };
        let second = ManifestEntry {
            update_channel: 2,
            ..entry(BLOCK)
        };
        assert_eq!(
            select(&[first, second], &facts(BLOCK), &POLICY, &[])
                .expect("bound")
                .update_channel,
            1,
        );
    }

    /// `None` is "this entry does not care" and is distinguishable from
    /// `Some(0)`, which is a real vendor id a wildcard-as-zero encoding would
    /// have quietly swallowed.
    #[test]
    fn an_absent_match_field_is_not_a_match_on_zero() {
        let wildcard = entry(BLOCK);
        let zero_vendor = ManifestEntry {
            vendor: Some(0),
            ..entry(BLOCK)
        };
        let device = DeviceFacts {
            vendor: 0,
            ..facts(BLOCK)
        };
        // The wildcard claims both devices.
        assert!(select(&[wildcard], &facts(BLOCK), &POLICY, &[]).is_ok());
        assert!(select(&[wildcard], &device, &POLICY, &[]).is_ok());
        // The zero-vendor entry claims only the one whose vendor is zero.
        assert_eq!(
            select(&[zero_vendor], &facts(BLOCK), &POLICY, &[]),
            Err(Refusal::NoMatch),
        );
        assert!(select(&[zero_vendor], &device, &POLICY, &[]).is_ok());
    }

    /// Each of the device-fact inputs can refuse on its own. That is the
    /// property that makes them inputs rather than decoration.
    #[test]
    fn every_device_fact_can_exclude_an_entry() {
        let device = facts(BLOCK);
        for (name, entry) in [
            (
                "vendor",
                ManifestEntry {
                    vendor: Some(0xdead),
                    ..entry(BLOCK)
                },
            ),
            (
                "product",
                ManifestEntry {
                    product: Some(0xbeef),
                    ..entry(BLOCK)
                },
            ),
            (
                "revision",
                ManifestEntry {
                    min_revision: Some(9),
                    ..entry(BLOCK)
                },
            ),
            (
                "bus",
                ManifestEntry {
                    bus: Some(BusKind::VirtioMmio),
                    ..entry(BLOCK)
                },
            ),
        ] {
            assert_eq!(
                select(&[entry], &device, &POLICY, &[]),
                Err(Refusal::NoMatch),
                "{name} did not exclude",
            );
        }
    }

    /// A bus the manager could not determine matches nothing, even an entry
    /// that names one: accepting it would bind a driver to a transport nobody
    /// established it can speak.
    #[test]
    fn an_unknown_bus_matches_no_entry_that_names_one() {
        let device = DeviceFacts {
            bus: BusKind::Unknown,
            ..facts(BLOCK)
        };
        let named = ManifestEntry {
            bus: Some(BusKind::Pci),
            ..entry(BLOCK)
        };
        assert_eq!(
            select(&[named], &device, &POLICY, &[]),
            Err(Refusal::NoMatch)
        );
        // An entry that does not care still claims it — not caring about the
        // bus is a legitimate thing for a manifest to say.
        assert!(select(&[entry(BLOCK)], &device, &POLICY, &[]).is_ok());
    }

    /// Each policy input can refuse on its own, and each refusal names itself.
    /// Three devices that stayed unbound for three different reasons need
    /// three different fixes, and a manager reporting them identically would
    /// send somebody to fix the wrong thing.
    #[test]
    fn every_policy_input_can_refuse_with_its_own_reason() {
        let device = facts(BLOCK);
        let cases = [
            (
                Refusal::UntrustedSignature,
                ManifestEntry {
                    driver_signature: 0xbad,
                    ..entry(BLOCK)
                },
            ),
            (
                Refusal::DomainNotPermitted,
                ManifestEntry {
                    security_domain: 9,
                    ..entry(BLOCK)
                },
            ),
            (
                Refusal::ContractTooOld,
                ManifestEntry {
                    contract_version: 0,
                    ..entry(BLOCK)
                },
            ),
            (
                Refusal::PolicyDisabled,
                ManifestEntry {
                    product_policy: 0,
                    ..entry(BLOCK)
                },
            ),
        ];
        for (expected, entry) in cases {
            assert_eq!(select(&[entry], &device, &POLICY, &[]), Err(expected));
        }
    }

    /// An unsigned driver is refused on a system that requires signatures and
    /// permitted on one that does not — a posture somebody chose, which is
    /// why it is a field rather than an absent check.
    #[test]
    fn an_unsigned_driver_binds_only_where_policy_allows_it() {
        let unsigned = ManifestEntry {
            driver_signature: 0,
            ..entry(BLOCK)
        };
        assert_eq!(
            select(&[unsigned], &facts(BLOCK), &POLICY, &[]),
            Err(Refusal::UntrustedSignature),
        );
        let development = SystemPolicy {
            allow_unsigned: true,
            ..POLICY
        };
        assert!(select(&[unsigned], &facts(BLOCK), &development, &[]).is_ok());
    }

    /// Firmware is the only refusal a *device* can cause, and it fires only
    /// against a device that reported a version: refusing a silent device for
    /// being too old would refuse every device that has no firmware to speak
    /// of.
    #[test]
    fn firmware_refuses_an_old_device_and_not_a_silent_one() {
        let demanding = ManifestEntry {
            min_firmware: Some(5),
            ..entry(BLOCK)
        };
        let old = DeviceFacts {
            firmware_version: 3,
            ..facts(BLOCK)
        };
        assert_eq!(
            select(&[demanding], &old, &POLICY, &[]),
            Err(Refusal::FirmwareTooOld),
        );
        let current = DeviceFacts {
            firmware_version: 5,
            ..facts(BLOCK)
        };
        assert!(select(&[demanding], &current, &POLICY, &[]).is_ok());
        // Zero is "did not say", not "version zero".
        assert!(select(&[demanding], &facts(BLOCK), &POLICY, &[]).is_ok());
    }

    /// Before the system is up, only entries marked for it may bind.
    #[test]
    fn early_boot_admits_only_what_is_marked_for_it() {
        let early = SystemPolicy {
            early_boot: true,
            ..POLICY
        };
        assert_eq!(
            select(&[entry(BLOCK)], &facts(BLOCK), &early, &[]),
            Err(Refusal::NotAllowedYet),
        );
        let boot_disk = ManifestEntry {
            product_policy: product_policy::ENABLED | product_policy::EARLY_BOOT,
            ..entry(BLOCK)
        };
        assert!(select(&[boot_disk], &facts(BLOCK), &early, &[]).is_ok());
    }

    /// **A refused best match is not silently downgraded to a weaker one.**
    /// Falling through would bind the device to a less specific driver because
    /// the right one was unsigned — a downgrade nobody asked for and nothing
    /// would report.
    #[test]
    fn a_refused_specific_entry_does_not_fall_through_to_a_general_one() {
        let specific_unsigned = ManifestEntry {
            vendor: Some(0x1af4),
            product: Some(0x1042),
            driver_signature: 0,
            ..entry(BLOCK)
        };
        let manifest = [specific_unsigned, entry(BLOCK)];
        assert_eq!(
            select(&manifest, &facts(BLOCK), &POLICY, &[]),
            Err(Refusal::UntrustedSignature),
            "the general entry must not quietly take over",
        );
    }

    // --- The path (`docs/drivers/01`, "Bus Topology And Data Paths") ---

    /// A device whose transfers relay through nothing costs nothing, and the
    /// binding says so. Zero here is an answer — the controller gave it
    /// per-child separation — rather than a field nobody filled in, which is
    /// why `Separated` ancestors are reported the same as no ancestors at all.
    #[test]
    fn a_path_that_relays_through_nothing_costs_nothing() {
        let manifest = [entry(BLOCK)];
        for path in [&[][..], &[Hop::Separated, Hop::Separated][..]] {
            let binding = select(&manifest, &facts(BLOCK), &POLICY, path).expect("bound");
            assert_eq!(binding.relay_hops, 0);
            assert_eq!(binding.accumulated_latency_us, 0);
            assert_eq!(binding.path_throughput_mbps, None);
        }
    }

    /// Latency sums and throughput takes the minimum — a relayed transfer pays
    /// every hop, and a path is only as fast as its narrowest one.
    #[test]
    fn hops_sum_their_latency_and_keep_the_narrowest_throughput() {
        let manifest = [entry(BLOCK)];
        let path = [
            hub(10, Some(1000)),
            Hop::Separated,
            hub(25, Some(500)),
            hub(5, Some(2500)),
        ];
        let binding = select(&manifest, &facts(BLOCK), &POLICY, &path).expect("bound");
        assert_eq!(binding.relay_hops, 3, "Separated is not a hop");
        assert_eq!(binding.accumulated_latency_us, 40);
        assert_eq!(
            binding.path_throughput_mbps,
            Some(500),
            "the narrowest hop, not the last one",
        );
    }

    /// A hub that declares no ceiling does not narrow the path, and a path of
    /// only such hubs has no throughput to report.
    #[test]
    fn a_hop_declaring_no_ceiling_does_not_narrow_the_path() {
        let manifest = [entry(BLOCK)];
        let binding = select(
            &manifest,
            &facts(BLOCK),
            &POLICY,
            &[hub(1, None), hub(1, Some(800)), hub(1, None)],
        )
        .expect("bound");
        assert_eq!(binding.path_throughput_mbps, Some(800));
        let binding = select(&manifest, &facts(BLOCK), &POLICY, &[hub(1, None)]).expect("bound");
        assert_eq!(binding.path_throughput_mbps, None);
    }

    /// **A relay that claims to add no latency is still a process in the path.**
    /// `docs/drivers/01` counts hops against the class budget in their own
    /// right, so the count and the cost are separate answers.
    #[test]
    fn a_zero_cost_relay_is_still_a_hop() {
        let manifest = [entry(BLOCK)];
        let binding = select(&manifest, &facts(BLOCK), &POLICY, &[hub(0, None)]).expect("bound");
        assert_eq!(binding.relay_hops, 1);
        assert_eq!(binding.accumulated_latency_us, 0);
    }

    /// **The doc's sentence, as a test.** One entry, one budget, one device —
    /// and the only thing that differs between binding and refusal is how deep
    /// the device sits. A class that meets its budget on direct-attach must not
    /// silently miss it behind two hubs.
    #[test]
    fn the_same_entry_binds_one_hop_up_and_refuses_two_hops_down() {
        let manifest = [ManifestEntry {
            max_latency_us: Some(30),
            ..entry(BLOCK)
        }];
        let near = select(&manifest, &facts(BLOCK), &POLICY, &[hub(10, None)]).expect("bound");
        assert_eq!(near.accumulated_latency_us, 10);
        assert_eq!(
            select(
                &manifest,
                &facts(BLOCK),
                &POLICY,
                &[hub(10, None), hub(25, None)],
            ),
            Err(Refusal::BudgetExceeded),
        );
    }

    /// `Some(0)` is an entry that will bind only a direct-attached device, and
    /// is distinguishable from `None`, which does not constrain the path at
    /// all. A zero-as-wildcard encoding would have swallowed the requirement.
    #[test]
    fn a_zero_budget_admits_only_a_direct_attached_device() {
        let strict = [ManifestEntry {
            max_latency_us: Some(0),
            ..entry(BLOCK)
        }];
        assert!(select(&strict, &facts(BLOCK), &POLICY, &[Hop::Separated]).is_ok());
        assert_eq!(
            select(&strict, &facts(BLOCK), &POLICY, &[hub(1, None)]),
            Err(Refusal::BudgetExceeded),
        );
        // The same path against an entry that does not constrain one.
        assert!(select(&[entry(BLOCK)], &facts(BLOCK), &POLICY, &[hub(1, None)]).is_ok());
    }

    /// Throughput refuses on its own and names itself. A shorter path is the
    /// fix for one and no help at all for the other, which is why they are two
    /// values.
    #[test]
    fn throughput_refuses_separately_from_latency() {
        let hungry = [ManifestEntry {
            max_latency_us: Some(100),
            min_throughput_mbps: Some(800),
            ..entry(BLOCK)
        }];
        // Well inside the latency budget, and far too narrow.
        assert_eq!(
            select(&hungry, &facts(BLOCK), &POLICY, &[hub(1, Some(500))]),
            Err(Refusal::ThroughputTooLow),
        );
        // Wide enough, and now the latency is what fails.
        assert_eq!(
            select(&hungry, &facts(BLOCK), &POLICY, &[hub(200, Some(1000))]),
            Err(Refusal::BudgetExceeded),
        );
        assert!(select(&hungry, &facts(BLOCK), &POLICY, &[hub(1, Some(1000))]).is_ok());
        // A path that declares no ceiling anywhere does not fail a requirement
        // it says nothing about — the alternative would refuse every device on
        // a bus whose contract is silent, which is missing data and not a slow
        // path.
        assert!(select(&hungry, &facts(BLOCK), &POLICY, &[hub(1, None)]).is_ok());
    }

    /// **An ancestor nobody declared is not free — but it is not fatal either.**
    /// Treating it as `Separated` would let a device behind an undescribed hub
    /// bind as though it were direct-attached, and the arithmetic that was
    /// supposed to be visible would be a guess. Refusing outright would strand
    /// a device whose driver never asked about latency. So it counts as a hop,
    /// the total becomes a lower bound, and the binding says so.
    #[test]
    fn an_undeclared_ancestor_makes_the_total_a_lower_bound() {
        let path = [Hop::Separated, hub(7, None), Hop::Undeclared];
        let binding = select(&[entry(BLOCK)], &facts(BLOCK), &POLICY, &path).expect("bound");
        assert_eq!(binding.relay_hops, 2, "the unknown hop is still a hop");
        assert_eq!(binding.accumulated_latency_us, 7, "and only the known cost");
        assert!(!binding.path_complete, "which makes this a lower bound");
    }

    /// **An entry that named no budget is never refused for the path.** It
    /// asked no question an unknown hop could answer wrongly, and a device
    /// nobody set a budget for should bind wherever it is — which is most
    /// devices, on every bus that gives per-child separation.
    #[test]
    fn an_entry_with_no_budget_binds_behind_anything() {
        let deep = [Hop::Undeclared, hub(10_000, Some(1)), hub(10_000, Some(1))];
        let binding = select(&[entry(BLOCK)], &facts(BLOCK), &POLICY, &deep).expect("bound");
        assert_eq!(binding.relay_hops, 3);
        assert!(!binding.path_complete);
    }

    /// The same path against an entry that *did* name a budget: the known cost
    /// fits, and what refuses it is the hop nothing described.
    #[test]
    fn a_budgeted_entry_refuses_a_path_it_cannot_add_up() {
        let budgeted = [ManifestEntry {
            max_latency_us: Some(30),
            ..entry(BLOCK)
        }];
        assert_eq!(
            select(
                &budgeted,
                &facts(BLOCK),
                &POLICY,
                &[hub(7, None), Hop::Undeclared],
            ),
            Err(Refusal::PathUndeclared),
        );
    }

    /// **A lower bound that already busts the budget names the budget**, not
    /// the missing hub: the device is too deep whatever the unknown hop costs,
    /// and the fix is to move it rather than to write manifest entries that
    /// could not change the answer.
    #[test]
    fn a_known_cost_over_budget_wins_over_an_unknown_hop() {
        let budgeted = [ManifestEntry {
            max_latency_us: Some(30),
            ..entry(BLOCK)
        }];
        assert_eq!(
            select(
                &budgeted,
                &facts(BLOCK),
                &POLICY,
                &[hub(40, None), Hop::Undeclared],
            ),
            Err(Refusal::BudgetExceeded),
        );
    }

    /// **The installation's switch.** With enforcement off, every path refusal
    /// stops firing and the figures are still reported — which is the posture a
    /// machine with no relaying bus should be in, and the one that guarantees a
    /// device is never stranded by a budget nothing can measure yet.
    #[test]
    fn enforcement_off_reports_everything_and_refuses_nothing() {
        let permissive = SystemPolicy {
            enforce_path_budgets: false,
            ..POLICY
        };
        let strict = [ManifestEntry {
            max_latency_us: Some(1),
            min_throughput_mbps: Some(10_000),
            ..entry(BLOCK)
        }];
        for path in [
            &[hub(40, Some(100))][..],
            &[Hop::Undeclared][..],
            &[hub(40, Some(100)), Hop::Undeclared][..],
        ] {
            // Every one of these is a refusal when enforcement is on...
            assert!(select(&strict, &facts(BLOCK), &POLICY, path).is_err());
            // ...and a binding when it is off.
            let binding = select(&strict, &facts(BLOCK), &permissive, path).expect("bound");
            assert!(binding.relay_hops > 0, "and the figures still arrive");
        }
    }

    /// A path whose declared cost cannot be represented saturates **and says
    /// the total is not a faithful one**, so a budgeted entry is refused and an
    /// unbudgeted one still binds. Saturating silently would report a number
    /// nobody computed as though somebody had.
    #[test]
    fn a_path_cost_that_cannot_be_represented_saturates_and_says_so() {
        let path = [hub(u64::MAX, None), hub(1, None)];
        let binding = select(&[entry(BLOCK)], &facts(BLOCK), &POLICY, &path).expect("bound");
        assert_eq!(binding.accumulated_latency_us, u64::MAX);
        assert!(!binding.path_complete);
        let budgeted = [ManifestEntry {
            max_latency_us: Some(30),
            ..entry(BLOCK)
        }];
        assert_eq!(
            select(&budgeted, &facts(BLOCK), &POLICY, &path),
            Err(Refusal::BudgetExceeded),
        );
    }

    /// **A path failure does not fall through to a more tolerant entry.**
    /// Binding the general driver because the specific one's budget was
    /// exceeded is the same silent downgrade a failed signature must not cause.
    #[test]
    fn a_deep_path_does_not_fall_through_to_a_more_tolerant_entry() {
        let specific = ManifestEntry {
            vendor: Some(0x1af4),
            product: Some(0x1042),
            max_latency_us: Some(5),
            ..entry(BLOCK)
        };
        let manifest = [specific, entry(BLOCK)];
        assert_eq!(
            select(&manifest, &facts(BLOCK), &POLICY, &[hub(10, None)]),
            Err(Refusal::BudgetExceeded),
            "the tolerant general entry must not quietly take over",
        );
    }

    /// `hop_for` answers what the manifest declared about an ancestor, and
    /// answers `Undeclared` — never `Separated` — for one nothing claims.
    #[test]
    fn hop_for_reports_what_an_ancestor_declared() {
        const BUS: u32 = 3;
        let relaying = ManifestEntry {
            vendor: Some(0x1b36),
            relay: Some(RelayCost {
                added_latency_us: 25,
                throughput_mbps: Some(500),
            }),
            ..entry(BUS)
        };
        let separated = ManifestEntry {
            vendor: Some(0x8086),
            ..entry(BUS)
        };
        let manifest = [relaying, separated];

        let bus = |vendor| DeviceFacts {
            class: BUS,
            vendor,
            ..facts(BUS)
        };
        assert_eq!(
            hop_for(&manifest, &bus(0x1b36)),
            hub(25, Some(500)),
            "a declared relay",
        );
        assert_eq!(
            hop_for(&manifest, &bus(0x8086)),
            Hop::Separated,
            "declared, and it relays nothing",
        );
        assert_eq!(
            hop_for(&manifest, &bus(0xdead)),
            Hop::Undeclared,
            "claimed by no entry, so its cost is unknown rather than zero",
        );
    }

    /// The specificity rule applies to ancestors too: a vendor-specific hub
    /// entry beats a catch-all one wherever it sits.
    #[test]
    fn hop_for_uses_the_most_specific_entry() {
        const BUS: u32 = 3;
        let general = entry(BUS);
        let specific = ManifestEntry {
            vendor: Some(0x1b36),
            relay: Some(RelayCost {
                added_latency_us: 7,
                throughput_mbps: None,
            }),
            ..entry(BUS)
        };
        let ancestor = DeviceFacts {
            class: BUS,
            vendor: 0x1b36,
            ..facts(BUS)
        };
        assert_eq!(hop_for(&[general, specific], &ancestor), hub(7, None));
        assert_eq!(hop_for(&[specific, general], &ancestor), hub(7, None));
    }
}
