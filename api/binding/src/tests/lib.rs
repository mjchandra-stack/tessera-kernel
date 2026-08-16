// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the crate root.

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
        firmware_name: None,
        firmware_min_image_version: 0,
        grants_configure: false,
        grants_derive: false,
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
