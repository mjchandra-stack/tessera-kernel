// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::devmgr`.

use super::*;

#[test]
fn registers_and_resolves_independent_nodes() {
    let mut table = DeviceTable::new();
    let com2 = ObjectId::from_raw(0x11);
    let other = ObjectId::from_raw(0x22);
    table
        .register(
            com2,
            0x2f8,
            8,
            3,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .unwrap();
    table
        .register(
            other,
            0x3e8,
            4,
            5,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .unwrap();
    // The graph holds N nodes, each resolving independently.
    assert_eq!(table.device_of_object(com2), Some((0x2f8, 8)));
    assert_eq!(table.device_of_object(other), Some((0x3e8, 4)));
    assert_eq!(table.irq_of_object(com2), Some(3));
    assert_eq!(table.irq_of_object(other), Some(5));
}

#[test]
fn unregistered_object_resolves_to_none() {
    let mut table = DeviceTable::new();
    table
        .register(
            ObjectId::from_raw(0x11),
            0x2f8,
            8,
            3,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .unwrap();
    assert_eq!(table.device_of_object(ObjectId::from_raw(0x99)), None);
    assert_eq!(table.irq_of_object(ObjectId::from_raw(0x99)), None);
}

#[test]
fn registers_and_resolves_an_mmio_window() {
    let mut table = DeviceTable::new();
    let virtio = ObjectId::from_raw(0x33);
    table
        .register_mmio(
            virtio,
            0x0a00_0000,
            0x200,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .unwrap();
    // The MMIO window resolves; the object carries no I/O-port range.
    assert_eq!(table.mmio_of_object(virtio), Some((0x0a00_0000, 0x200)));
    assert_eq!(table.device_of_object(virtio), Some((0, 0)));
}

#[test]
fn records_and_resolves_an_mmio_intid() {
    let mut devices = DeviceTable::new();
    let id = ObjectId::from_raw(9);
    devices
        .register_mmio(
            id,
            0x0a00_3e00,
            0x200,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .expect("mmio");
    assert_eq!(devices.intid_of_object(id), None);
    devices.set_mmio_irq(id, 79).expect("set irq");
    assert_eq!(devices.intid_of_object(id), Some(79));
    // An unknown object neither sets nor resolves.
    assert!(devices.set_mmio_irq(ObjectId::from_raw(99), 50).is_err());
    assert_eq!(devices.intid_of_object(ObjectId::from_raw(99)), None);
}

#[test]
fn a_port_node_has_no_mmio_window() {
    let mut table = DeviceTable::new();
    let com2 = ObjectId::from_raw(0x11);
    table
        .register(
            com2,
            0x2f8,
            8,
            3,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
        )
        .unwrap();
    // A port-only node resolves its ports but reports no MMIO window.
    assert_eq!(table.device_of_object(com2), Some((0x2f8, 8)));
    assert_eq!(table.mmio_of_object(com2), None);
    // An unregistered object has neither.
    assert_eq!(table.mmio_of_object(ObjectId::from_raw(0x99)), None);
}

#[test]
fn a_full_graph_rejects_further_registration() {
    let mut table = DeviceTable::new();
    for i in 0..MAX_DEVICES {
        table
            .register(
                ObjectId::from_raw(i as u32 + 1),
                0x100 + i as u16,
                1,
                0,
                Rights::READ | Rights::MAP | Rights::TRANSFER,
            )
            .unwrap();
    }
    assert_eq!(
        table.register(
            ObjectId::from_raw(0xfff),
            0x200,
            1,
            0,
            Rights::READ | Rights::MAP | Rights::TRANSFER
        ),
        Err(KError::OutOfMemory)
    );
}

/// An aperture hands out addresses in order and refuses when spent — it
/// never wraps, because a device-visible address that once meant one page
/// must not later mean another. A device can hold it in a ring the kernel
/// cannot see.
#[test]
fn an_aperture_allocates_forward_and_refuses_when_spent() {
    let mut aperture = DeviceAperture::new(0x1000, 0x3000);
    assert_eq!(aperture.allocate(0x1000), Some(0x1000));
    assert_eq!(aperture.allocate(0x1000), Some(0x2000));
    assert_eq!(aperture.allocate(0x1000), Some(0x3000));
    assert_eq!(aperture.allocate(0x1000), None, "spent, not wrapped");
    // And it stays refused rather than recovering.
    assert_eq!(aperture.allocate(0x1000), None);
}

#[test]
fn an_aperture_refuses_a_request_larger_than_it_has_left() {
    let mut aperture = DeviceAperture::new(0x1000, 0x2000);
    assert_eq!(aperture.allocate(0x1800), Some(0x1000));
    assert_eq!(aperture.allocate(0x1000), None);
    // The partial request did not move the cursor past the end.
    assert!(aperture.next <= aperture.base + aperture.len);
}

#[test]
fn an_aperture_knows_what_is_inside_it() {
    let aperture = DeviceAperture::new(0x1000, 0x1000);
    assert!(aperture.contains(0x1000));
    assert!(aperture.contains(0x1fff));
    assert!(!aperture.contains(0x0fff));
    assert!(!aperture.contains(0x2000));
}

/// "No aperture" and "aperture exhausted" are different facts, and a
/// caller that cannot tell them apart would report an unscoped device as
/// an out-of-memory condition.
#[test]
fn a_device_without_an_aperture_is_distinguishable_from_a_spent_one() {
    let mut table = DeviceTable::new();
    let unscoped = ObjectId::from_raw(0x11);
    let scoped = ObjectId::from_raw(0x22);
    table
        .register_mmio(unscoped, 0x1000, 0x1000, Rights::READ)
        .unwrap();
    table
        .register_mmio(scoped, 0x2000, 0x1000, Rights::READ)
        .unwrap();
    table
        .set_aperture(
            scoped,
            HOLDER,
            DeviceAperture::new(0x8000_0000, 0x1000),
            None,
        )
        .unwrap();

    assert_eq!(table.aperture_of_object(unscoped), None);
    assert!(table.aperture_of_object(scoped).is_some());

    // Both allocate to None, for different reasons the caller can tell
    // apart by asking whether an aperture exists at all.
    assert_eq!(table.allocate_in_aperture(unscoped, 0x1000), None);
    assert_eq!(
        table.allocate_in_aperture(scoped, 0x1000),
        Some(0x8000_0000)
    );
    assert_eq!(table.allocate_in_aperture(scoped, 0x1000), None);
}

#[test]
fn setting_an_aperture_on_an_unknown_device_is_refused() {
    let mut table = DeviceTable::new();
    assert_eq!(
        table.set_aperture(
            ObjectId::from_raw(0x99),
            HOLDER,
            DeviceAperture::new(0, 0x1000),
            None
        ),
        Err(KError::BadHandle)
    );
}

/// A stand-in process object for the lease tests.
const HOLDER: ObjectId = ObjectId::from_raw(0x77);

/// Ending a lease returns the range it covered **already released**, so the
/// next lease over the same window starts from its base again. That is the
/// whole of D120's deferred recycling: within a lease an address is never
/// reissued, across leases it must be, or a rebound driver would exhaust
/// the window its predecessor spent.
#[test]
fn the_next_lease_starts_where_the_last_one_began() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x33);
    table
        .register_mmio(device, 0x2000, 0x1000, Rights::READ)
        .unwrap();

    table
        .set_aperture(
            device,
            HOLDER,
            DeviceAperture::new(0x8000_0000, 0x2000),
            None,
        )
        .unwrap();
    assert_eq!(
        table.allocate_in_aperture(device, 0x1000),
        Some(0x8000_0000)
    );
    assert_eq!(
        table.allocate_in_aperture(device, 0x1000),
        Some(0x8000_1000)
    );
    assert_eq!(table.allocate_in_aperture(device, 0x1000), None, "spent");

    let ended = table.end_lease(device).expect("a lease was live");
    assert_eq!(ended.used(), 0, "released as it leaves");
    assert_eq!(table.lease_holder_of_object(device), None);
    assert_eq!(
        table.allocate_in_aperture(device, 0x1000),
        None,
        "and no allocation survives the lease that authorized it",
    );

    let next = ObjectId::from_raw(0x78);
    table
        .set_aperture(device, next, DeviceAperture::new(0x8000_0000, 0x2000), None)
        .unwrap();
    assert_eq!(
        table.allocate_in_aperture(device, 0x1000),
        Some(0x8000_0000),
        "the second lease reissues the first's addresses",
    );
}

/// The sweep a dying process's teardown walks — by device, because nothing
/// can enumerate the holders of an object.
#[test]
fn leases_are_found_by_their_holder() {
    let mut table = DeviceTable::new();
    let mine = ObjectId::from_raw(0x33);
    let theirs = ObjectId::from_raw(0x34);
    let other_holder = ObjectId::from_raw(0x78);
    table
        .register_mmio(mine, 0x2000, 0x1000, Rights::READ)
        .unwrap();
    table
        .register_mmio(theirs, 0x3000, 0x1000, Rights::READ)
        .unwrap();
    table
        .set_aperture(mine, HOLDER, DeviceAperture::new(0x8000_0000, 0x1000), None)
        .unwrap();
    table
        .set_aperture(
            theirs,
            other_holder,
            DeviceAperture::new(0x9000_0000, 0x1000),
            None,
        )
        .unwrap();

    let mut out = [ObjectId::from_raw(0); MAX_DEVICES];
    assert_eq!(table.leases_held_by(HOLDER, &mut out), 1);
    assert_eq!(out[0], mine, "a bystander's lease is not swept up");
    assert_eq!(
        table.leases_held_by(ObjectId::from_raw(0xdead), &mut out),
        0
    );
}

/// A route records the line from the **node**, not from whoever asked.
/// A caller that could name the INTID could route another device's
/// interrupts to itself, which is the same authority argument that keeps a
/// `MapDevice` caller from naming its own physical base.
#[test]
fn a_route_takes_its_line_from_the_graph() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x33);
    table
        .register_mmio(device, 0x2000, 0x1000, Rights::READ)
        .unwrap();
    // No line wired yet: routing interrupts that cannot arrive is refused
    // rather than recorded.
    assert_eq!(
        table.route_irq(device, PortId(2), HOLDER),
        Err(KError::InvalidMapping)
    );
    assert_eq!(table.irq_route_of_object(device), None);

    table.set_mmio_irq(device, 79).unwrap();
    table.route_irq(device, PortId(2), HOLDER).unwrap();
    assert_eq!(
        table.irq_route_of_object(device),
        Some(IrqRoute {
            port: PortId(2),
            holder: HOLDER,
            intid: 79,
        })
    );
}

#[test]
fn routing_an_unknown_device_is_refused() {
    let mut table = DeviceTable::new();
    assert_eq!(
        table.route_irq(ObjectId::from_raw(0x99), PortId(0), HOLDER),
        Err(KError::BadHandle)
    );
}

/// The sweep a departing process's teardown walks — by device, because
/// nothing can enumerate the holders of an object, and a bystander's route
/// must not be swept up with it.
#[test]
fn routes_are_found_by_their_holder() {
    let mut table = DeviceTable::new();
    let mine = ObjectId::from_raw(0x33);
    let theirs = ObjectId::from_raw(0x34);
    let other = ObjectId::from_raw(0x78);
    for (device, intid) in [(mine, 79u32), (theirs, 80)] {
        table
            .register_mmio(device, 0x2000, 0x1000, Rights::READ)
            .unwrap();
        table.set_mmio_irq(device, intid).unwrap();
    }
    table.route_irq(mine, PortId(1), HOLDER).unwrap();
    table.route_irq(theirs, PortId(2), other).unwrap();

    let mut out = [ObjectId::from_raw(0); MAX_DEVICES];
    assert_eq!(table.irq_routes_held_by(HOLDER, &mut out), 1);
    assert_eq!(out[0], mine);
    assert_eq!(
        table.irq_routes_held_by(ObjectId::from_raw(0xdead), &mut out),
        0
    );
}

/// Ending a route hands back what it covered, so the caller can unbind the
/// port and mask the line it actually installed. Ending one that was never
/// taken is a no-op, so the departure paths need not first ask.
#[test]
fn ending_a_route_returns_what_it_covered() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x33);
    table
        .register_mmio(device, 0x2000, 0x1000, Rights::READ)
        .unwrap();
    table.set_mmio_irq(device, 79).unwrap();
    assert_eq!(table.end_irq_route(device), None, "none was taken");
    table.route_irq(device, PortId(3), HOLDER).unwrap();
    assert_eq!(
        table.end_irq_route(device).map(|route| route.intid),
        Some(79)
    );
    assert_eq!(table.irq_route_of_object(device), None);
    assert_eq!(table.end_irq_route(device), None, "and it is gone");
    assert_eq!(table.end_irq_route(ObjectId::from_raw(0x99)), None);
}

/// A lease and a route are independent: a device can be receiving
/// interrupts with no DMA outstanding, and ending one must not end the
/// other. They depart together only because the *capability* departs.
#[test]
fn a_lease_and_a_route_are_independent() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x33);
    table
        .register_mmio(device, 0x2000, 0x1000, Rights::READ)
        .unwrap();
    table.set_mmio_irq(device, 79).unwrap();
    table.route_irq(device, PortId(1), HOLDER).unwrap();
    table
        .set_aperture(
            device,
            HOLDER,
            DeviceAperture::new(0x8000_0000, 0x1000),
            None,
        )
        .unwrap();

    assert!(table.end_lease(device).is_some());
    assert!(
        table.irq_route_of_object(device).is_some(),
        "the route outlives the lease",
    );
    assert!(table.end_irq_route(device).is_some());
}

/// Ending a lease that does not exist is a no-op, so the departure paths
/// need not first ask whether there was one.
#[test]
fn ending_a_lease_that_was_never_taken_is_harmless() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x33);
    table
        .register_mmio(device, 0x2000, 0x1000, Rights::READ)
        .unwrap();
    assert_eq!(table.end_lease(device), None);
    assert_eq!(table.end_lease(ObjectId::from_raw(0x99)), None);
}

// -----------------------------------------------------------------------
// Bus topology (`docs/drivers/01`, "Bus Topology And Data Paths").
// -----------------------------------------------------------------------

/// A root port, a switch's two ports, and an endpoint under them — the
/// topology the hotplug machine presents.
fn switch_graph() -> (DeviceTable, [ObjectId; 4]) {
    let mut table = DeviceTable::new();
    let ids = [0x40, 0x41, 0x42, 0x43].map(ObjectId::from_raw);
    for (index, id) in ids.iter().enumerate() {
        table
            .register_mmio(*id, 0x1000 * (index as u64 + 1), 0x1000, Rights::READ)
            .unwrap();
    }
    table.set_parent(ids[1], ids[0]).unwrap();
    table.set_parent(ids[2], ids[1]).unwrap();
    table.set_parent(ids[3], ids[2]).unwrap();
    (table, ids)
}

#[test]
fn a_device_records_the_one_it_sits_behind() {
    let (table, ids) = switch_graph();
    assert_eq!(
        table.parent_of(ids[0]),
        None,
        "the root port sits behind nothing"
    );
    assert_eq!(table.parent_of(ids[3]), Some(ids[2]));

    let mut children = [ObjectId::from_raw(0); MAX_DEVICES];
    assert_eq!(table.children_of(ids[2], &mut children), 1);
    assert_eq!(children[0], ids[3]);
    assert_eq!(table.children_of(ids[3], &mut children), 0, "a leaf");
}

/// Authority over a controller reaches everything below it, and stops at
/// the edge of the subtree — which is the whole content of "capabilities
/// scoped to a subtree".
#[test]
fn descent_answers_for_the_whole_subtree_and_nothing_beside_it() {
    let (mut table, ids) = switch_graph();
    assert!(table.is_descendant_of(ids[3], ids[0]), "three levels down");
    assert!(table.is_descendant_of(ids[0], ids[0]), "reflexive");
    assert!(!table.is_descendant_of(ids[0], ids[3]), "not upward");

    // A device on another branch is outside, however deep the first goes.
    let sibling = ObjectId::from_raw(0x50);
    table
        .register_mmio(sibling, 0x9000, 0x1000, Rights::READ)
        .unwrap();
    table.set_parent(sibling, ids[0]).unwrap();
    assert!(table.is_descendant_of(sibling, ids[0]));
    assert!(
        !table.is_descendant_of(sibling, ids[1]),
        "a different branch"
    );
}

/// An edge to a device the graph does not hold names nothing, and a walk
/// that trusted it would report a subtree smaller than the machine's.
#[test]
fn an_edge_to_an_absent_parent_is_refused() {
    let mut table = DeviceTable::new();
    let child = ObjectId::from_raw(0x60);
    table
        .register_mmio(child, 0x1000, 0x1000, Rights::READ)
        .unwrap();
    assert_eq!(
        table.set_parent(child, ObjectId::from_raw(0x99)),
        Err(KError::BadHandle),
    );
    assert_eq!(table.parent_of(child), None);
}

/// A cycle makes "everything below this" unanswerable — and the walk that
/// answers it runs on a departure path, where not finishing is a hang with
/// the hardware already gone.
#[test]
fn an_edge_that_closes_a_cycle_is_refused() {
    let (mut table, ids) = switch_graph();
    assert_eq!(
        table.set_parent(ids[0], ids[3]),
        Err(KError::InvalidArgument),
        "the root cannot sit behind its own grandchild",
    );
    assert_eq!(
        table.set_parent(ids[0], ids[0]),
        Err(KError::InvalidArgument),
        "nor behind itself",
    );
    // And the graph is unchanged, so the refusal cost nothing.
    assert_eq!(table.parent_of(ids[0]), None);
    assert!(table.is_descendant_of(ids[3], ids[0]));
}

/// Removing a node without removing its children first is the caller's
/// mistake, and the orphan must not be left naming an id a later
/// registration can reuse.
#[test]
fn removing_a_parent_directly_detaches_what_was_behind_it() {
    let (mut table, ids) = switch_graph();
    assert!(table.remove(ids[1]).is_some());
    assert_eq!(table.parent_of(ids[2]), None, "detached, not dangling");
    assert!(!table.is_descendant_of(ids[3], ids[0]));
}

/// A wakeup source is a property of the node, so the interrupt bridge can
/// ask the graph which line may wake this machine rather than consulting a
/// list the boot glue keeps.
#[test]
fn an_armed_source_is_found_by_the_line_it_arrives_on() {
    let mut table = DeviceTable::new();
    let rtc = ObjectId::from_raw(0x60);
    table
        .register_mmio(rtc, 0x9010000, 0x1000, Rights::READ)
        .unwrap();
    table.set_mmio_irq(rtc, 34).unwrap();

    assert_eq!(table.armed_wake_source(34), None, "not armed yet");
    assert!(!table.is_wake_source(rtc));
    table.set_wake_source(rtc, true).unwrap();
    assert_eq!(table.armed_wake_source(34), Some(rtc));
    assert!(table.is_wake_source(rtc));
    // A different line is a different question, however armed this one is.
    assert_eq!(table.armed_wake_source(35), None);
    // And disarming is not removal: the device is still there.
    table.set_wake_source(rtc, false).unwrap();
    assert_eq!(table.armed_wake_source(34), None);
    assert!(table.contains(rtc));
}

/// Arming a device with no interrupt is refused rather than recorded. A
/// wakeup source that cannot fire looks exactly like one that has not
/// fired yet at every later point, and a machine that suspended trusting
/// it would never come back.
#[test]
fn a_device_with_no_interrupt_cannot_be_a_wakeup_source() {
    let mut table = DeviceTable::new();
    let silent = ObjectId::from_raw(0x61);
    table
        .register_mmio(silent, 0x9020000, 0x1000, Rights::READ)
        .unwrap();
    assert_eq!(
        table.set_wake_source(silent, true),
        Err(KError::InvalidArgument),
    );
    assert!(!table.is_wake_source(silent));
    // Disarming one is still fine — it is already what it claims to be.
    assert_eq!(table.set_wake_source(silent, false), Ok(()));
    // And a device the graph has never heard of is a bad handle, which is
    // a different mistake from a device that cannot do this.
    assert_eq!(
        table.set_wake_source(ObjectId::from_raw(0xfff), true),
        Err(KError::BadHandle),
    );
}

/// A device leaving takes its wake capability with it. Reading the arming
/// out of the graph rather than out of a side table is what makes that
/// true without anybody remembering to undo it.
#[test]
fn a_removed_device_stops_being_able_to_wake_the_machine() {
    let mut table = DeviceTable::new();
    let rtc = ObjectId::from_raw(0x62);
    table
        .register_mmio(rtc, 0x9010000, 0x1000, Rights::READ)
        .unwrap();
    table.set_mmio_irq(rtc, 34).unwrap();
    table.set_wake_source(rtc, true).unwrap();
    assert!(table.remove(rtc).is_some());
    assert_eq!(table.armed_wake_source(34), None);
    assert!(!table.is_wake_source(rtc));
}
/// **A device may have more than one interrupt line, because a multi-queue
/// controller does.** Every device before this one raised a single
/// interrupt, so the graph held a single INTID; a controller with a vector
/// per queue needs the rest recorded, or the queues whose lines nobody
/// knows about are queues whose completions never re-arm.
#[test]
fn a_device_can_have_a_line_per_queue() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x70);
    table
        .register_mmio(device, 0x1000, 0x1000, Rights::READ)
        .expect("register");
    table.set_mmio_irq(device, 40).expect("first");
    table.add_mmio_irq(device, 41).expect("second");
    table.add_mmio_irq(device, 42).expect("third");

    // The first is still what "the device's interrupt" means, so every
    // caller that wants one is unaffected.
    assert_eq!(table.intid_of_object(device), Some(40));
    let mut lines = [0u32; 8];
    assert_eq!(table.intids_of_object(device, &mut lines), 3);
    assert_eq!(&lines[..3], &[40, 41, 42]);
}

/// A line the graph has no room for is **refused**, not dropped. A queue
/// whose completions reach nobody is a driver that waits forever, and that
/// is far harder to find than a registration that said no.
#[test]
fn a_line_the_graph_cannot_hold_is_refused() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x71);
    table
        .register_mmio(device, 0x1000, 0x1000, Rights::READ)
        .expect("register");
    for intid in 0..=MAX_EXTRA_IRQS as u32 {
        table.add_mmio_irq(device, 40 + intid).expect("fits");
    }
    assert_eq!(
        table.add_mmio_irq(device, 99),
        Err(KError::LimitExceeded),
        "one past what the node holds",
    );
    let mut lines = [0u32; 8];
    assert_eq!(
        table.intids_of_object(device, &mut lines),
        1 + MAX_EXTRA_IRQS,
        "and the refusal changed nothing",
    );
}

/// A caller's buffer shorter than the device's line count truncates rather
/// than overruns, and says how many it wrote.
#[test]
fn asking_for_fewer_lines_than_there_are_truncates() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x72);
    table
        .register_mmio(device, 0x1000, 0x1000, Rights::READ)
        .expect("register");
    table.set_mmio_irq(device, 40).expect("first");
    table.add_mmio_irq(device, 41).expect("second");
    let mut one = [0u32; 1];
    assert_eq!(table.intids_of_object(device, &mut one), 1);
    assert_eq!(one[0], 40);
    // And a device the graph does not know has none.
    assert_eq!(
        table.intids_of_object(ObjectId::from_raw(0x99), &mut one),
        0
    );
}
/// **A route per queue, and the sweep takes all of them.** Routing exists
/// so an interrupt path dies with the driver that held it; a device with
/// one line per queue would otherwise keep delivering on every line but the
/// first, which is the hole routing was introduced to close, reopened by a
/// controller having more than one interrupt.
#[test]
fn every_route_a_device_has_ends_with_its_holder() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x74);
    let holder = ObjectId::from_raw(0x75);
    table
        .register_mmio(device, 0x1000, 0x1000, Rights::READ)
        .expect("register");
    table.set_mmio_irq(device, 50).expect("first");
    table.add_mmio_irq(device, 51).expect("second");
    table
        .route_irq_line(device, 50, PortId(0), holder)
        .expect("route one");
    table
        .route_irq_line(device, 51, PortId(1), holder)
        .expect("route two");

    // Listed once however many lines it has, so a sweep does not try twice
    // on a device with none left.
    let mut held = [ObjectId::from_raw(0); MAX_DEVICES];
    assert_eq!(table.irq_routes_held_by(holder, &mut held), 1);
    assert_eq!(held[0], device);

    // Both come off, one per call, and then there is nothing.
    let first = table.end_irq_route(device).expect("a route");
    let second = table.end_irq_route(device).expect("and the other");
    assert_ne!(first.intid, second.intid);
    assert_eq!(table.end_irq_route(device), None);
    assert_eq!(table.irq_route_of_object(device), None);
}

/// A line the graph never recorded cannot be routed. A route for an
/// interrupt nobody registered would deliver whatever else raises that
/// number to a driver that never asked, and would survive that driver with
/// nothing to attribute it to.
#[test]
fn routing_a_line_the_device_does_not_have_is_refused() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x76);
    table
        .register_mmio(device, 0x1000, 0x1000, Rights::READ)
        .expect("register");
    table.set_mmio_irq(device, 50).expect("first");
    assert_eq!(
        table.route_irq_line(device, 99, PortId(0), ObjectId::from_raw(0x77)),
        Err(KError::InvalidMapping),
    );
    assert_eq!(table.irq_route_of_object(device), None);
}

/// Routing a line twice **replaces** its route rather than adding a second.
/// A line delivers to one place, and two records for it would mean a sweep
/// ended one and left the other — leaving a driver that gave the device up
/// still receiving.
#[test]
fn routing_a_line_again_replaces_where_it_goes() {
    let mut table = DeviceTable::new();
    let device = ObjectId::from_raw(0x78);
    let holder = ObjectId::from_raw(0x79);
    table
        .register_mmio(device, 0x1000, 0x1000, Rights::READ)
        .expect("register");
    table.set_mmio_irq(device, 60).expect("line");
    table
        .route_irq_line(device, 60, PortId(0), holder)
        .expect("route");
    table
        .route_irq_line(device, 60, PortId(2), holder)
        .expect("reroute");
    let route = table.end_irq_route(device).expect("a route");
    assert_eq!(route.port, PortId(2), "the second one won");
    assert_eq!(table.end_irq_route(device), None, "and there is only one");
}
