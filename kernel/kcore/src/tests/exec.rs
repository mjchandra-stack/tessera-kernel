// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::exec`.

use super::*;
use crate::ipc::{Message, MessageHeader};
use crate::thread::{Thread, ThreadId, ThreadState};
use crate::vm::{AddressSpace, Asid};
use tessera_karch::VirtAddr;
use tessera_karch_mock::{MockAddressSpace, MockContextOps, MockFrameSource};

extern "C" fn never(_: usize) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn vm() -> AddressSpace<MockAddressSpace> {
    let mut frames = MockFrameSource::new(0x1000_0000, 64);
    AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(0)).expect("vm")
}

fn spawn(
    exec: &mut Executive<MockContextOps>,
    space: &mut AddressSpace<MockAddressSpace>,
    id: u64,
) -> usize {
    let mut frames = MockFrameSource::new(0x10_0000 + id * 0x10_0000, 64);
    let base = 0xffff_e000_0000_0000 + id * 0x10_0000;
    let t = Thread::<MockContextOps>::spawn(
        ThreadId(id),
        never,
        id as usize,
        VirtAddr::new(base),
        2,
        space,
        &mut frames,
    )
    .expect("spawn");
    exec.add_thread(t).expect("add")
}

fn msg(body: &[u8]) -> Message {
    let mut m = Message::new(MessageHeader::new(0x1, 1));
    m.set_inline(body).unwrap();
    m
}

// --- DMA faults, isolation, and interrupt routes -----------------------

/// A device that translates and records every lease it was told to end,
/// so a test can tell a lease the graph merely forgot from one whose
/// translations actually came down.
#[derive(Default)]
struct FaultMapper {
    ended: std::vec::Vec<ObjectId>,
}

impl crate::devmgr::DmaMapper for FaultMapper {
    fn translates(&self, _device: ObjectId) -> bool {
        true
    }

    fn begin_lease(&mut self, _device: ObjectId) -> Result<(u64, u64), KError> {
        Ok((0x1_0000, 0x2000))
    }

    fn map(&mut self, _: ObjectId, _: u64, _: u64, _: u64) -> Result<(), KError> {
        Ok(())
    }

    fn unmap(&mut self, _: ObjectId, _: u64, _: u64) -> Result<(), KError> {
        Ok(())
    }

    fn end_lease(&mut self, device: ObjectId) {
        self.ended.push(device);
    }
}

/// An interrupt controller recording every line it was told to stop
/// delivering — the only way to tell revocation from bookkeeping.
#[derive(Default)]
struct CountingRouter {
    masked: std::vec::Vec<u32>,
}

impl InterruptRouter for CountingRouter {
    fn mask(&mut self, intid: u32) {
        self.masked.push(intid);
    }
}

const FAULTING_DEVICE: ObjectId = ObjectId::from_raw(0x31);
const DRIVER: ObjectId = ObjectId::from_raw(0x32);

/// An executive holding one MMIO device with an INTID and a live lease.
fn leased() -> Executive<MockContextOps> {
    let mut exec = Executive::<MockContextOps>::new(1, 0);
    exec.device_register_mmio(FAULTING_DEVICE, 0x0a00_0000, 0x1000, Rights::READ)
        .expect("register");
    exec.device_set_mmio_irq(FAULTING_DEVICE, 79).expect("irq");
    exec.device_set_aperture(
        FAULTING_DEVICE,
        DRIVER,
        crate::devmgr::DeviceAperture::new(0x1_0000, 0x2000),
        None,
    )
    .expect("aperture");
    exec
}

fn fault(device: Option<ObjectId>) -> DmaFault {
    DmaFault {
        device,
        stream: 0x10,
        address: 0x20_0000,
        kind: crate::devmgr::DmaFaultKind::Unmapped,
    }
}

/// A device that resets, and a resetter that refuses.
#[derive(Default)]
struct MockResetter {
    reset: std::vec::Vec<ObjectId>,
    refuses: bool,
}

impl crate::devmgr::DeviceResetter for MockResetter {
    fn reset(
        &mut self,
        device: ObjectId,
        _identity: Option<crate::devmgr::DeviceIdentity>,
        _window: Option<(u64, u64)>,
    ) -> Result<(), KError> {
        if self.refuses {
            return Err(KError::NotSupported);
        }
        self.reset.push(device);
        Ok(())
    }
}

/// Ladder step 4: the services depending on a device are told when its
/// driver fails, and the notice says *which* device — a dependent may
/// depend on several, and "one of yours is in trouble" is not actionable.
#[test]
fn dependents_are_notified_with_a_body_that_names_the_device() {
    let mut exec = leased();
    let (a_server, a_client) = exec.channel_create().expect("a");
    let (b_server, b_client) = exec.channel_create().expect("b");
    exec.device_add_dependent(FAULTING_DEVICE, a_server)
        .expect("a depends");
    exec.device_add_dependent(FAULTING_DEVICE, b_server)
        .expect("b depends");

    let (sent, lost) = exec.notify_dependents(
        FAULTING_DEVICE,
        crate::lifecycle::DriverState::Degraded,
        crate::lifecycle::TransitionReason::DriverCrashed,
    );
    assert_eq!((sent, lost), (2, 0));

    // Each dependent has a message waiting, and it decodes to a notice
    // naming this device and the state it is in.
    for client in [a_client, b_client] {
        let message = exec.receive(client).expect("a notice arrived");
        let notice: crate::isl_binding::lifecycle::ServiceNotice =
            tessera_isl_runtime::decode(message.inline()).expect("decodes");
        assert_eq!(notice.device, FAULTING_DEVICE.raw());
        assert_eq!(notice.state, crate::lifecycle::DriverState::Degraded);
        assert_eq!(
            notice.reason,
            crate::lifecycle::TransitionReason::DriverCrashed
        );
    }
}

/// A device nobody depends on notifies nobody, and says so as zero rather
/// than as an error — having no dependents is an ordinary state.
#[test]
fn a_device_with_no_dependents_notifies_nobody() {
    let mut exec = leased();
    assert_eq!(
        exec.notify_dependents(
            FAULTING_DEVICE,
            crate::lifecycle::DriverState::Degraded,
            crate::lifecycle::TransitionReason::DriverCrashed,
        ),
        (0, 0),
    );
}

/// Registering twice is idempotent: a service that reconnects should not
/// have to remember whether it already registered, and a second entry
/// would have it notified twice for one failure.
#[test]
fn a_duplicate_dependency_does_not_double_the_notifications() {
    let mut exec = leased();
    let (server, _client) = exec.channel_create().expect("channel");
    exec.device_add_dependent(FAULTING_DEVICE, server)
        .expect("once");
    exec.device_add_dependent(FAULTING_DEVICE, server)
        .expect("twice");
    assert_eq!(
        exec.notify_dependents(
            FAULTING_DEVICE,
            crate::lifecycle::DriverState::Degraded,
            crate::lifecycle::TransitionReason::DriverCrashed,
        ),
        (1, 0),
    );
}

/// Ladder step 5. A declined reset is not a failed one: it emits no record
/// because nothing was attempted, and a record there would have a log
/// service reading a reset that never touched the hardware.
#[test]
fn a_reset_happens_only_when_policy_allows_it() {
    let mut exec = leased();
    let mut resetter = MockResetter::default();
    assert_eq!(
        exec.reset_device(
            FAULTING_DEVICE,
            crate::devmgr::ResetPolicy::Never,
            Some(&mut resetter),
        ),
        Ok(false),
    );
    assert!(resetter.reset.is_empty(), "nothing was touched");

    assert_eq!(
        exec.reset_device(
            FAULTING_DEVICE,
            crate::devmgr::ResetPolicy::OnDegraded,
            Some(&mut resetter),
        ),
        Ok(true),
    );
    assert_eq!(resetter.reset, std::vec![FAULTING_DEVICE]);
}

/// A port with no resetter cannot reset, and says so. Returning success
/// would have the ladder's next rung taken on the premise that a device
/// nothing touched had been reset.
#[test]
fn a_port_with_no_resetter_refuses_rather_than_pretending() {
    let mut exec = leased();
    assert_eq!(
        exec.reset_device(
            FAULTING_DEVICE,
            crate::devmgr::ResetPolicy::OnDegraded,
            None
        ),
        Err(KError::NotSupported),
    );
    // And hardware that refuses is reported as refusing.
    let mut resetter = MockResetter {
        refuses: true,
        ..MockResetter::default()
    };
    assert_eq!(
        exec.reset_device(
            FAULTING_DEVICE,
            crate::devmgr::ResetPolicy::OnDegraded,
            Some(&mut resetter),
        ),
        Err(KError::NotSupported),
    );
}

/// Quarantine is **enforced**, not advertised: the manager never receives
/// the capability, so nothing can bind the device again — not because a
/// manager chooses not to, but because it has nothing to bind.
#[test]
fn a_quarantined_device_is_not_handed_back_to_its_manager() {
    let mut exec = leased();
    let (manager, _peer) = exec.channel_create().expect("channel");
    let mut frames = MockFrameSource::new(0x2000_0000, 32);
    let space = AddressSpace::<MockAddressSpace>::new(&mut frames, 0xffff_8000_0000_0000, Asid(3))
        .expect("space");
    let mut driver = crate::process::Process::new(ObjectId::from_raw(0x88), space);
    driver
        .handles_mut()
        .install(FAULTING_DEVICE, Rights::READ | Rights::MAP)
        .expect("install");

    assert!(exec.quarantine_device(FAULTING_DEVICE, 4, 4));
    assert!(exec.is_quarantined(FAULTING_DEVICE));
    // A second quarantine changes nothing and records nothing.
    assert!(!exec.quarantine_device(FAULTING_DEVICE, 4, 4));

    assert_eq!(
        exec.reclaim_devices(&mut driver, manager, None, None),
        1,
        "the capability still leaves the corpse",
    );
    assert!(
        exec.receive(manager).is_err(),
        "but it is not offered to the manager",
    );
}

/// Quarantine is reversible only by an administrator. A device that could
/// take itself out of quarantine is not quarantined.
#[test]
fn quarantine_is_undone_only_deliberately() {
    let mut exec = leased();
    assert!(exec.quarantine_device(FAULTING_DEVICE, 4, 4));
    assert!(exec.release_from_quarantine(FAULTING_DEVICE));
    assert!(!exec.is_quarantined(FAULTING_DEVICE));
    // Releasing one that is not quarantined changes nothing.
    assert!(!exec.release_from_quarantine(FAULTING_DEVICE));
}

/// The default policy changes nothing. That is the point of it being a
/// policy: a machine still being brought up wants every fault recorded and
/// nothing torn down, and isolating on the first one would hide the rest.
#[test]
fn the_report_policy_isolates_nothing() {
    let mut exec = leased();
    let mut mapper = FaultMapper::default();
    let outcome = exec.isolate_dma_fault(
        fault(Some(FAULTING_DEVICE)),
        IsolationPolicy::Report,
        Some(&mut mapper),
    );
    assert!(!outcome.isolated);
    assert_eq!(outcome.stop, None);
    assert_eq!(
        exec.lease_holder_of_object(FAULTING_DEVICE),
        Some(DRIVER),
        "the lease is untouched",
    );
    assert!(mapper.ended.is_empty(), "and so is the hardware");
}

/// Isolation is a strictly larger action than the hardware already took:
/// the unit refused one address, this makes the device reach nothing.
#[test]
fn isolating_a_fault_ends_the_lease_in_the_graph_and_the_hardware() {
    let mut exec = leased();
    let mut mapper = FaultMapper::default();
    let outcome = exec.isolate_dma_fault(
        fault(Some(FAULTING_DEVICE)),
        IsolationPolicy::EndLease,
        Some(&mut mapper),
    );
    assert!(outcome.isolated);
    assert_eq!(exec.lease_holder_of_object(FAULTING_DEVICE), None);
    assert_eq!(exec.aperture_of_object(FAULTING_DEVICE), None);
    assert_eq!(
        mapper.ended,
        std::vec![FAULTING_DEVICE],
        "the translations came down, not just the record",
    );
    // Ending the lease is not the same as stopping the driver, and this
    // policy asks only for the first.
    assert_eq!(outcome.stop, None);
}

/// The stronger policy names the holder for a supervisor to stop. It names
/// it rather than doing it because this type has no scheduler and no frame
/// allocator — and a caller that ignores the answer has not applied the
/// policy, which is why the outcome is `#[must_use]`.
#[test]
fn the_stopping_policy_names_the_holder_it_wants_stopped() {
    let mut exec = leased();
    let mut mapper = FaultMapper::default();
    let outcome = exec.isolate_dma_fault(
        fault(Some(FAULTING_DEVICE)),
        IsolationPolicy::EndLeaseAndStop,
        Some(&mut mapper),
    );
    assert!(outcome.isolated);
    assert_eq!(outcome.stop, Some(DRIVER));
}

/// A fault the port could not attribute to a device has nothing to
/// isolate. Acting on it would mean picking a victim, and reporting that
/// something was isolated when nothing was is the silent-degradation
/// failure the outcome exists to prevent.
#[test]
fn an_unattributed_fault_isolates_nobody() {
    let mut exec = leased();
    let mut mapper = FaultMapper::default();
    let outcome = exec.isolate_dma_fault(fault(None), IsolationPolicy::EndLease, Some(&mut mapper));
    assert!(!outcome.isolated);
    assert_eq!(outcome.stop, None);
    assert_eq!(exec.lease_holder_of_object(FAULTING_DEVICE), Some(DRIVER));
    assert!(mapper.ended.is_empty());
}

/// A device that faults while nobody holds a lease on it: the wiring is
/// wrong, and there is no driver to isolate. Reporting isolation here
/// would be reporting an action that did not happen.
#[test]
fn a_fault_from_an_unleased_device_isolates_nothing() {
    let mut exec = Executive::<MockContextOps>::new(1, 0);
    exec.device_register_mmio(FAULTING_DEVICE, 0x0a00_0000, 0x1000, Rights::READ)
        .expect("register");
    let mut mapper = FaultMapper::default();
    let outcome = exec.isolate_dma_fault(
        fault(Some(FAULTING_DEVICE)),
        IsolationPolicy::EndLeaseAndStop,
        Some(&mut mapper),
    );
    assert!(!outcome.isolated);
    assert_eq!(outcome.stop, None);
    assert!(mapper.ended.is_empty());
}

/// A route is only a route once both halves exist: the graph knows who
/// receives it, and the port is bound to the line so a signal lands.
#[test]
fn routing_an_interrupt_binds_the_port_to_the_devices_own_line() {
    let mut exec = leased();
    let port = exec.port_create().expect("port");
    exec.device_route_irq(FAULTING_DEVICE, port, DRIVER)
        .expect("route");
    let route = exec.irq_route_of_object(FAULTING_DEVICE).expect("routed");
    assert_eq!(route.intid, 79, "the line comes from the graph");
    assert_eq!(route.holder, DRIVER);

    // And the binding delivers: a signal on that line wakes exactly this
    // port. Without the bind the route would be a record of nothing.
    assert_eq!(exec.port_signal(79, IRQ_PORT_SIGNAL, 1), 1);
    assert_eq!(
        exec.port_wait(port).expect("event").pending,
        1,
        "the edge arrived",
    );
}

/// A device with no line wired is refused rather than recorded. Routing
/// interrupts that cannot arrive would make the graph describe a delivery
/// path nothing can use.
#[test]
fn a_device_with_no_interrupt_cannot_be_routed() {
    let mut exec = Executive::<MockContextOps>::new(1, 0);
    exec.device_register_mmio(FAULTING_DEVICE, 0x0a00_0000, 0x1000, Rights::READ)
        .expect("register");
    let port = exec.port_create().expect("port");
    assert_eq!(
        exec.device_route_irq(FAULTING_DEVICE, port, DRIVER),
        Err(KError::InvalidMapping),
    );
    assert_eq!(exec.irq_route_of_object(FAULTING_DEVICE), None);
}

/// Revocation is all three halves or none: the graph forgets, the
/// controller stops delivering, and the port binding goes.
///
/// The port binding matters as much as the mask. A route left bound would
/// have the *next* holder of that port receive edges attributed to a
/// device it was never given.
#[test]
fn revoking_a_route_masks_the_line_and_unbinds_the_port() {
    let mut exec = leased();
    let port = exec.port_create().expect("port");
    exec.device_route_irq(FAULTING_DEVICE, port, DRIVER)
        .expect("route");
    let mut router = CountingRouter::default();

    assert!(exec.end_device_irq_route(
        DRIVER,
        FAULTING_DEVICE,
        RouteEndReason::Transferred,
        Some(&mut router),
    ));
    assert_eq!(exec.irq_route_of_object(FAULTING_DEVICE), None);
    assert_eq!(router.masked, std::vec![79], "the controller was told");
    // Nothing is delivered any more, so nothing arrives at the port.
    assert_eq!(exec.port_signal(79, IRQ_PORT_SIGNAL, 1), 0);
    // And the slot was released rather than merely left unasserted: the
    // same pair binds again, which a still-occupied slot would refuse.
    // That is the difference between the route being gone and the route
    // being quiet.
    assert!(exec.port_bind(port, 79, IRQ_PORT_SIGNAL).is_ok());
}

/// **A route that is recorded and not bound delivers nothing**, and the
/// only way to tell is to signal the line and see whether anything
/// arrives.
///
/// This is the bug that shipped: routing a named line was added as a
/// passthrough to the graph, which recorded the route and left the port
/// unbound, and an NVMe driver parked forever on a completion its port
/// never heard about. Recording and binding are one operation, and this is
/// what says so.
#[test]
fn routing_a_named_line_makes_it_deliver() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let device = ObjectId::from_raw(0x80);
    let holder = ObjectId::from_raw(0x81);
    exec.device_register_mmio(device, 0x1000, 0x1000, Rights::READ)
        .expect("register");
    exec.device_add_mmio_irq(device, 90).expect("first");
    exec.device_add_mmio_irq(device, 91).expect("second");
    let first = exec.port_create().expect("port");
    let second = exec.port_create().expect("port");
    exec.device_route_irq_line(device, 90, first, holder)
        .expect("route one");
    exec.device_route_irq_line(device, 91, second, holder)
        .expect("route two");

    // Each line reaches its own port, which is the whole point of a vector
    // per queue: where it arrives is what identifies the queue.
    assert_eq!(exec.port_signal(90, IRQ_PORT_SIGNAL, 1), 1);
    assert_eq!(exec.port_signal(91, IRQ_PORT_SIGNAL, 1), 1);
    // A line nobody routed still reaches nobody.
    assert_eq!(exec.port_signal(92, IRQ_PORT_SIGNAL, 1), 0);
}

/// A process that duplicated its capability and gave one copy away keeps
/// the authority — and must keep its interrupts. Revoking on the *other*
/// holder's departure would take away a route from a driver that did
/// nothing wrong, which is the exact case
/// `revoke_device_windows_unless_held` guards for register windows.
#[test]
fn a_route_is_not_revoked_by_someone_who_does_not_hold_it() {
    let mut exec = leased();
    let port = exec.port_create().expect("port");
    exec.device_route_irq(FAULTING_DEVICE, port, DRIVER)
        .expect("route");
    let mut router = CountingRouter::default();

    assert!(!exec.end_device_irq_route(
        ObjectId::from_raw(0xdead),
        FAULTING_DEVICE,
        RouteEndReason::Transferred,
        Some(&mut router),
    ));
    assert!(exec.irq_route_of_object(FAULTING_DEVICE).is_some());
    assert!(router.masked.is_empty());
}

/// Ending a route that was never taken is a no-op, so the departure paths
/// need not first ask whether there was one.
#[test]
fn ending_a_route_that_was_never_taken_is_harmless() {
    let mut exec = leased();
    let mut router = CountingRouter::default();
    assert!(!exec.end_device_irq_route(
        DRIVER,
        FAULTING_DEVICE,
        RouteEndReason::HandleClosed,
        Some(&mut router),
    ));
    assert!(!exec.end_device_irq_route(
        DRIVER,
        ObjectId::from_raw(0x99),
        RouteEndReason::HandleClosed,
        Some(&mut router),
    ));
    assert!(router.masked.is_empty());
}

#[test]
fn channel_create_and_async_send_delivers_to_peer() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let (a, b) = exec.channel_create().unwrap();
    // Async send from a is queued on b's endpoint and can be received.
    exec.send(a, msg(b"hi")).unwrap();
    // Receiving on b (no current thread needed since a message is queued).
    let mut space = vm();
    let _ = spawn(&mut exec, &mut space, 0);
    exec.run(); // current = thread 0
    let got = exec.receive(b).unwrap();
    assert_eq!(got.inline(), b"hi");
}

#[test]
fn endpoint_objects_bridge_back_to_their_endpoints() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let (a, b) = exec.channel_create().unwrap();
    let oa = ObjectId::from_raw(0x0a);
    let ob = ObjectId::from_raw(0x0b);
    exec.bind_endpoint_object(a, oa);
    exec.bind_endpoint_object(b, ob);
    assert_eq!(exec.endpoint_of_object(oa), Some(a));
    assert_eq!(exec.endpoint_of_object(ob), Some(b));
    assert_eq!(exec.endpoint_of_object(ObjectId::from_raw(0xff)), None);
}

#[test]
fn reply_and_continue_leaves_the_server_runnable() {
    // The D85 regression: `reply` blocks the replier as part of its
    // handoff, which strands a server whose next wake comes from a port
    // rather than from the next call on this endpoint. The select loop's
    // reply must ready the caller and leave the server Ready.
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let server = spawn(&mut exec, &mut space, 0);
    let client = spawn(&mut exec, &mut space, 1);
    exec.run(); // current = server

    let (server_end, client_end) = exec.channel_create().unwrap();

    // The client parked mid-`call` awaiting its reply; the server is
    // current, exactly as it is when the select loop finishes a read.
    exec.send(client_end, msg(b"req")).unwrap();
    exec.channels
        .channel_mut(client_end.channel)
        .unwrap()
        .endpoint_mut(client_end.side)
        .set_pending_caller(Some((client, 7)));
    exec.scheduler().handoff_to(client); // client current…
    exec.scheduler().handoff_to(server); // …then Blocked; server current

    exec.reply_and_continue(server_end, msg(b"rep"))
        .expect("reply");

    assert_eq!(
        exec.scheduler().thread_state(server),
        Some(ThreadState::Running),
        "the server keeps running — a blocked one would never re-select"
    );
    assert_eq!(
        exec.scheduler().thread_state(client),
        Some(ThreadState::Ready),
        "the caller is readied, not handed off to"
    );
}

#[test]
fn a_message_arrival_signals_the_destination_endpoints_port() {
    // The select plumbing (D85): a port bound to (endpoint object,
    // SIGNAL_MESSAGE) is asserted when a message lands on that endpoint,
    // and the drained event names WHICH endpoint — so a server with
    // per-client channels learns where the work is.
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let server = spawn(&mut exec, &mut space, 0);
    let _client = spawn(&mut exec, &mut space, 1);
    exec.run(); // current = server

    let (client_a, server_a) = exec.channel_create().unwrap();
    let (client_b, server_b) = exec.channel_create().unwrap();
    let a_obj = ObjectId::from_raw(50);
    let b_obj = ObjectId::from_raw(52);
    exec.bind_endpoint_object(server_a, a_obj);
    exec.bind_endpoint_object(server_b, b_obj);

    let port = exec.port_create().unwrap();
    exec.port_bind(port, u64::from(a_obj.raw()), crate::ipc::SIGNAL_MESSAGE)
        .unwrap();
    exec.port_bind(port, u64::from(b_obj.raw()), crate::ipc::SIGNAL_MESSAGE)
        .unwrap();

    // An arrival on B's endpoint asserts B's binding only.
    exec.send(client_b, msg(b"to-b")).unwrap();
    let event = exec.port_wait(port).expect("event");
    assert_eq!(event.source, u64::from(b_obj.raw()));
    assert_eq!(event.signal, crate::ipc::SIGNAL_MESSAGE);
    assert_eq!(event.pending, 1);
    let _ = (client_a, server);
}

#[test]
fn an_unbound_endpoint_arrival_signals_nothing() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let _t = spawn(&mut exec, &mut space, 0);
    exec.run();
    let (client, server_end) = exec.channel_create().unwrap();
    // No object bound to the server end, and a port watching some other
    // source: the send must not assert it.
    let port = exec.port_create().unwrap();
    exec.port_bind(port, 0x9999, crate::ipc::SIGNAL_MESSAGE)
        .unwrap();
    exec.send(client, msg(b"x")).unwrap();
    assert_eq!(exec.port_coalesced(port), 0);
    // Draining yields nothing (no binding asserted).
    let _ = server_end;
}

#[test]
fn reply_receive_with_a_queued_request_wakes_the_replied_caller() {
    // The immediate-dequeue path: the next request is already queued when
    // the server replies, so the server keeps running — the just-replied
    // caller must be WOKEN, not left Blocked with its reply queued (found
    // by D84's interrupt-driven serving, where a second client's request
    // queues while the server waits on its device).
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let server = spawn(&mut exec, &mut space, 0);
    let caller = spawn(&mut exec, &mut space, 1);
    let (server_end, caller_end) = exec.channel_create().unwrap();
    exec.run(); // current = server

    // Simulate the caller parked mid-`call` awaiting its reply, with the
    // NEXT request already queued on the server end.
    exec.send(caller_end, msg(b"req1")).unwrap();
    exec.channels
        .channel_mut(caller_end.channel)
        .unwrap()
        .endpoint_mut(caller_end.side)
        .set_pending_caller(Some((caller, 7)));
    exec.scheduler().handoff_to(caller); // caller current…
    exec.scheduler().handoff_to(server); // …then Blocked; server current

    let next = exec
        .reply_receive(server_end, msg(b"reply"))
        .expect("immediate dequeue");
    assert_eq!(next.inline(), b"req1");
    // The replied caller is runnable again, its reply queued for pickup.
    assert_eq!(
        exec.scheduler().thread_state(caller),
        Some(ThreadState::Ready)
    );
    let _ = server;
}

/// **Restart is not recovery while somebody is still waiting.** A caller
/// parked mid-call is waiting for a reply from a server that has died, and
/// nothing else in the system will ever produce one.
#[test]
fn a_dying_process_wakes_the_caller_blocked_on_its_channel() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let server = spawn(&mut exec, &mut space, 0);
    let caller = spawn(&mut exec, &mut space, 1);
    let (server_end, caller_end) = exec.channel_create().unwrap();
    let server_obj = ObjectId::from_raw(0x900);
    exec.bind_endpoint_object(server_end, server_obj);
    exec.run();

    // The caller is parked awaiting a reply, exactly as a synchronous call
    // leaves it.
    exec.send(caller_end, msg(b"req")).unwrap();
    exec.channels
        .channel_mut(caller_end.channel)
        .unwrap()
        .endpoint_mut(caller_end.side)
        .set_pending_caller(Some((caller, 1)));
    exec.scheduler().handoff_to(caller);
    exec.scheduler().handoff_to(server);
    assert_eq!(
        exec.scheduler().thread_state(caller),
        Some(ThreadState::Blocked),
        "parked awaiting a reply",
    );

    // The server dies, and what it held goes with it.
    assert_eq!(exec.close_endpoints_of(&[server_obj]), 1);
    assert_eq!(
        exec.scheduler().thread_state(caller),
        Some(ThreadState::Ready),
        "the caller must be able to run again and discover the peer is gone",
    );
}

/// And it discovers *why*: the endpoint reports peer-closed, so the woken
/// caller returns an error rather than looping back to wait again.
#[test]
fn the_woken_caller_finds_the_peer_closed() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let _server = spawn(&mut exec, &mut space, 0);
    let _caller = spawn(&mut exec, &mut space, 1);
    let (server_end, caller_end) = exec.channel_create().unwrap();
    let server_obj = ObjectId::from_raw(0x901);
    exec.bind_endpoint_object(server_end, server_obj);

    exec.channels
        .channel_mut(caller_end.channel)
        .unwrap()
        .endpoint_mut(caller_end.side)
        .set_pending_caller(Some((0, 1)));
    exec.close_endpoints_of(&[server_obj]);
    assert!(
        exec.channels
            .channel(caller_end.channel)
            .unwrap()
            .endpoint(caller_end.side)
            .peer_closed(),
        "a woken caller that could not tell why would park again",
    );
}

/// Only what the dying process held. A channel it never had is somebody
/// else's, and closing it would take down a conversation between two live
/// processes.
#[test]
fn a_channel_the_process_never_held_is_left_alone() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let (mine, _) = exec.channel_create().unwrap();
    let (theirs, theirs_peer) = exec.channel_create().unwrap();
    exec.bind_endpoint_object(mine, ObjectId::from_raw(0x902));
    exec.bind_endpoint_object(theirs, ObjectId::from_raw(0x903));
    for end in [mine, theirs] {
        exec.channels
            .channel_mut(end.channel)
            .unwrap()
            .endpoint_mut(crate::ipc::Channel::peer(end.side))
            .set_pending_caller(Some((0, 1)));
    }

    assert_eq!(exec.close_endpoints_of(&[ObjectId::from_raw(0x902)]), 1);
    assert!(
        !exec
            .channels
            .channel(theirs_peer.channel)
            .unwrap()
            .endpoint(theirs_peer.side)
            .peer_closed(),
        "somebody else's channel",
    );
}

/// A process that held no endpoints closes none, and says so rather than
/// reporting a number nobody can distinguish from success.
#[test]
fn a_process_holding_no_endpoints_closes_nothing() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let (a, _) = exec.channel_create().unwrap();
    exec.bind_endpoint_object(a, ObjectId::from_raw(0x904));
    assert_eq!(exec.close_endpoints_of(&[ObjectId::from_raw(0xdead)]), 0);
}

#[test]
fn send_wakes_a_blocked_receiver() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let receiver = spawn(&mut exec, &mut space, 0);
    let _sender = spawn(&mut exec, &mut space, 1);
    let (a, b) = exec.channel_create().unwrap();
    exec.run(); // current = receiver

    // Simulate the receiver having parked on b: mark it blocked_receiver and
    // Blocked (as `receive` would).
    exec.channels
        .channel_mut(b.channel)
        .unwrap()
        .endpoint_mut(b.side)
        .set_blocked_receiver(Some(receiver));
    exec.scheduler().unblock(receiver); // put back to a known Ready baseline
    // A send on a must wake the parked receiver on b.
    exec.send(a, msg(b"x")).unwrap();
    assert_eq!(
        exec.scheduler().thread_state(receiver),
        Some(ThreadState::Ready)
    );
    assert!(
        exec.channels
            .channel(b.channel)
            .unwrap()
            .endpoint(b.side)
            .blocked_receiver()
            .is_none()
    );
}

#[test]
fn a_synchronous_call_restores_the_callees_own_correlation_id() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let caller = spawn(&mut exec, &mut space, 0);
    let callee = spawn(&mut exec, &mut space, 1);
    let (a, b) = exec.channel_create().unwrap();
    exec.run(); // current = caller

    // Distinct ids so an adopted one is distinguishable from the restored one.
    exec.scheduler().set_thread_correlation(caller, 0xca11e7);
    exec.scheduler().set_thread_correlation(callee, 0x5efbe7);

    // Park the callee as b's receiver so `call` takes the handoff path.
    exec.channels
        .channel_mut(b.channel)
        .unwrap()
        .endpoint_mut(b.side)
        .set_blocked_receiver(Some(callee));

    // The mock's `switch` is a no-op, so the callee never actually runs and
    // the call unwinds to `PeerClosed` — which is exactly the path that must
    // still restore. (That the callee *observes* the caller's id while it
    // runs is proven on target by the `correlation` boot demo, where a real
    // switch happens.)
    let _ = exec.call(a, msg(b"q"));

    assert_eq!(
        exec.scheduler().thread_correlation(callee),
        Some(0x5efbe7),
        "a server must not keep the last caller's id, or every event it \
         emits afterwards is misattributed"
    );
    assert_eq!(exec.scheduler().thread_correlation(caller), Some(0xca11e7));
    assert_eq!(
        exec.saved_correlation[callee], 0,
        "the save slot is released"
    );
}

#[test]
fn an_async_send_carries_the_senders_cause_to_the_receiver() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let sender = spawn(&mut exec, &mut space, 0);
    let receiver = spawn(&mut exec, &mut space, 1);
    let (a, b) = exec.channel_create().unwrap();
    exec.run(); // current = sender

    // The sender is the origin of this work; the receiver has its own id.
    exec.scheduler().set_thread_correlation(sender, 0xd00d);
    exec.scheduler().set_thread_correlation(receiver, 0xbeef);

    // Async send: no handoff, so the id can only travel in the message.
    exec.send(a, msg(b"x")).unwrap();

    // Make the receiver current, then take delivery. (`handoff_to` moves
    // `current` even under the mock, whose register switch is a no-op.)
    exec.scheduler().handoff_to(receiver);
    let got = exec.receive(b).expect("receive");

    // The id rode the header across the boundary...
    assert_eq!(got.header().correlation, 0xd00d);
    // ...and was adopted as the receiver started handling it.
    assert_eq!(
        exec.scheduler().thread_correlation(receiver),
        Some(0xd00d),
        "handling an async request belongs to the cause that sent it"
    );
}

#[test]
fn an_uncorrelated_message_does_not_erase_the_receivers_cause() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let receiver = spawn(&mut exec, &mut space, 0);
    let (a, b) = exec.channel_create().unwrap();
    exec.run(); // current = receiver

    // A message from a sender with no cause recorded (id 0).
    exec.scheduler().set_thread_correlation(receiver, 0);
    exec.send(a, msg(b"x")).unwrap();
    exec.scheduler().set_thread_correlation(receiver, 0xabc);

    exec.receive(b).expect("receive");
    assert_eq!(
        exec.scheduler().thread_correlation(receiver),
        Some(0xabc),
        "adopting 0 would erase a good id rather than inherit a real one"
    );
}

#[test]
fn a_spawned_thread_gets_a_fresh_id_rather_than_its_parents() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let parent = spawn(&mut exec, &mut space, 0);
    let child = spawn(&mut exec, &mut space, 1);

    let (parent_id, child_id) = (
        exec.scheduler().thread_correlation(parent).expect("parent"),
        exec.scheduler().thread_correlation(child).expect("child"),
    );
    // Fan-out links, not shared ids: each branch is separately identifiable.
    assert_ne!(parent_id, 0);
    assert_ne!(child_id, 0);
    assert_ne!(parent_id, child_id);
}

#[test]
fn oversize_and_full_queue_are_rejected_by_send() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let (a, _b) = exec.channel_create().unwrap();
    // Fill the peer queue.
    for _ in 0..crate::ipc::QUEUE_CAP {
        exec.send(a, msg(b"m")).unwrap();
    }
    assert_eq!(exec.send(a, msg(b"m")), Err(KError::WouldBlock));
}

#[test]
fn call_without_a_running_thread_is_rejected() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let (a, _b) = exec.channel_create().unwrap();
    // No thread is current (run not called), so `call` has no caller.
    assert_eq!(exec.call(a, msg(b"q")).map(|_| ()), Err(KError::BadHandle));
}

#[test]
fn wake_wakes_a_blocked_waiter_and_consumes_it() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let waiter = spawn(&mut exec, &mut space, 0);
    let _other = spawn(&mut exec, &mut space, 1);
    exec.run(); // current = waiter

    // Enroll the waiter as `wait_on_address(space=0, addr=0x1000)` would,
    // then set a known Ready baseline (mirrors `send_wakes_a_blocked_receiver`,
    // avoiding the mock's no-op context switch).
    exec.waits
        .enroll(
            WaitKey {
                space: 0,
                addr: 0x1000,
            },
            waiter,
        )
        .expect("enroll");
    exec.scheduler().unblock(waiter);

    // A wake on the same key wakes exactly the one waiter.
    assert_eq!(exec.wake(0, 0x1000, 1), 1);
    assert_eq!(
        exec.scheduler().thread_state(waiter),
        Some(ThreadState::Ready)
    );
    // The enrollment is consumed: a second wake finds nothing.
    assert_eq!(exec.wake(0, 0x1000, 1), 0);
    assert!(exec.waits.is_empty());
}

#[test]
fn wake_on_a_different_key_does_not_wake() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let waiter = spawn(&mut exec, &mut space, 0);
    exec.run();
    exec.waits
        .enroll(
            WaitKey {
                space: 0,
                addr: 0x1000,
            },
            waiter,
        )
        .expect("enroll");
    // Wrong address and wrong space each miss.
    assert_eq!(exec.wake(0, 0x2000, u32::MAX), 0);
    assert_eq!(exec.wake(0xbeef, 0x1000, u32::MAX), 0);
    assert_eq!(exec.waits.len(), 1);
}

#[test]
fn port_signal_wakes_a_blocked_drainer() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let drainer = spawn(&mut exec, &mut space, 0);
    let _other = spawn(&mut exec, &mut space, 1);
    exec.run(); // current = drainer

    let port = exec.port_create().expect("create");
    exec.port_bind(port, 0x5011, 1).expect("bind");
    // Enroll the drainer as a blocked drainer (as `port_wait` on an empty
    // port would), then a known Ready baseline (avoids the mock's no-op
    // switch inside block_current).
    exec.ports
        .port_mut(port)
        .expect("port")
        .set_blocked_drainer(Some(drainer));
    exec.scheduler().unblock(drainer);

    // A signal on the bound source delivers and wakes the drainer.
    assert_eq!(exec.port_signal(0x5011, 1, 2), 1);
    assert_eq!(
        exec.scheduler().thread_state(drainer),
        Some(ThreadState::Ready)
    );
    // The event is queued with its coalesced count; draining reads it.
    assert_eq!(exec.port_wait(port).map(|e| e.pending), Ok(2));
}

/// **A driver parked on a device's interrupt is woken when the device
/// leaves**, and can tell that is what happened.
///
/// Without this it waits for a line that will never assert again — the one
/// failure mode a removal creates that no amount of correct bookkeeping
/// fixes, because the driver is not running to observe any of it.
#[test]
fn removing_a_device_wakes_a_driver_parked_on_its_interrupt() {
    const DEVICE: ObjectId = ObjectId::from_raw(0x51);
    const HOLDER: ObjectId = ObjectId::from_raw(0x52);
    const INTID: u32 = 79;

    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let driver = spawn(&mut exec, &mut space, 0);
    let _other = spawn(&mut exec, &mut space, 1);
    exec.run();

    exec.device_register_mmio(DEVICE, 0x0a00_0000, 0x1000, Rights::READ | Rights::MAP)
        .expect("register");
    exec.device_set_mmio_irq(DEVICE, INTID).expect("intid");
    let port = exec.port_create().expect("create");
    exec.device_route_irq(DEVICE, port, HOLDER).expect("route");

    // Parked, exactly as `port_wait` on an empty port leaves a thread.
    exec.ports
        .port_mut(port)
        .expect("port")
        .set_blocked_drainer(Some(driver));
    exec.scheduler().unblock(driver);

    let mut processes = crate::process::ProcessTable::<MockAddressSpace>::new();
    let report = exec.remove_device(
        DEVICE,
        crate::lifecycle::TransitionReason::Removed,
        &mut processes,
        None,
        None,
    );
    assert_eq!(report.woken, 1, "the parked driver was told");
    assert_eq!(
        exec.scheduler().thread_state(driver),
        Some(ThreadState::Ready),
    );

    // **And it can tell what woke it.** An interrupt and a removal reach
    // the same sleeper on the same port, so the signal is the only thing
    // that distinguishes servicing a completion from stopping altogether.
    let event = exec.port_wait(port).expect("event");
    assert_eq!(event.signal, IRQ_PORT_SIGNAL_REMOVED);
    assert_ne!(IRQ_PORT_SIGNAL_REMOVED, IRQ_PORT_SIGNAL);
}

#[test]
fn job_add_process_enforces_the_member_cap() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let root = exec
        .job_create_root(ObjectId::from_raw(0x5a_0001), JobLimits::new(1))
        .expect("root");
    let cp = Rights::CREATE_PROCESS;
    exec.job_add_process(
        root,
        Member {
            process: ObjectId::from_raw(1),
            thread: 0,
        },
        cp,
    )
    .expect("p1");
    // The second exceeds the cap of 1 — a resource error.
    assert_eq!(
        exec.job_add_process(
            root,
            Member {
                process: ObjectId::from_raw(2),
                thread: 1,
            },
            cp,
        ),
        Err(KError::LimitExceeded)
    );
}

#[test]
fn job_kill_terminates_members_and_signals_the_state_port() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let member_thread = spawn(&mut exec, &mut space, 0);
    exec.run(); // a running context exists

    let root = exec
        .job_create_root(ObjectId::from_raw(0x5a_0002), JobLimits::new(2))
        .expect("root");
    let source = exec.job(root).expect("job").state_source();
    // A supervisor port bound to the root job's state source.
    let port = exec.port_create().expect("port");
    exec.port_bind(port, source, SIGNAL_MEMBER_EXIT)
        .expect("bind exit");
    exec.port_bind(port, source, SIGNAL_EMPTY)
        .expect("bind empty");

    let full = Rights::from_bits(Rights::CREATE_PROCESS.bits() | Rights::KILL.bits());
    exec.job_add_process(
        root,
        Member {
            process: ObjectId::from_raw(0x9e_0001),
            thread: member_thread,
        },
        full,
    )
    .expect("add");

    let mut killed = [None; 4];
    let n = exec.job_kill(root, full, &mut killed).expect("kill");
    assert_eq!(n, 1);
    assert_eq!(killed[0], Some(ObjectId::from_raw(0x9e_0001)));
    // The member thread was terminated.
    assert_eq!(
        exec.scheduler().thread_state(member_thread),
        Some(ThreadState::Exited)
    );
    // The state port drained the member-exit then the emptiness signal.
    assert_eq!(
        exec.port_wait(port).map(|e| e.signal),
        Ok(SIGNAL_MEMBER_EXIT)
    );
    assert_eq!(exec.port_wait(port).map(|e| e.signal), Ok(SIGNAL_EMPTY));
    // A killed job refuses further members.
    assert!(exec.job(root).expect("job").is_killed());
}

#[test]
fn wait_on_value_mismatch_returns_wouldblock_without_blocking() {
    let mut exec = Executive::<MockContextOps>::new(4, 0);
    let mut space = vm();
    let t = spawn(&mut exec, &mut space, 0);
    exec.run(); // current = t, Running

    // observed (5) != expected (9): the address changed, so do not block.
    assert_eq!(
        exec.wait_on_address(0, 0x3000, 5, 9),
        Err(KError::WouldBlock)
    );
    assert!(exec.waits.is_empty());
    assert_eq!(exec.scheduler().thread_state(t), Some(ThreadState::Running));
}
