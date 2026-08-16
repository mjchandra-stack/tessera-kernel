// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A mock xHCI controller, so register discovery, the reset handshake, the
//! rings' wrap behaviour and the event ring's cycle bit are exercised on the
//! host without any hardware.
//!
//! The mock puts its registers at **deliberately unusual offsets**. A driver
//! with a table of constants passes against a controller that happens to match
//! it; this one does not match anything, which is the point.
//!
//! Core-only (fixed arrays and `RefCell`), matching the crate's `no_std` stance.

use super::*;
use core::cell::RefCell;

/// Where the mock puts things. None of these is a common value: the capability
/// length is not 0x20, the runtime and doorbell offsets are not the ones the
/// reference controllers use, and a driver that assumed any of them fails here.
const CAP_LENGTH: usize = 0x40;
const DBOFF: usize = 0x2000;
const RTSOFF: usize = 0x1800;
const MAX_SLOTS: u8 = 32;
const MAX_PORTS: u8 = 4;

#[derive(Default)]
struct State {
    usbcmd: u32,
    usbsts: u32,
    config: u32,
    dcbaap: u64,
    crcr: u64,
    erstsz: u32,
    erstba: u64,
    erdp: u64,
    /// Each port's status register.
    ports: [u32; MAX_PORTS as usize],
    /// The last doorbell rung, as `(slot, endpoint)`.
    doorbell: Option<(u8, u32)>,
    /// Whether the controller refuses to come out of reset.
    wedged: bool,
}

struct MockXhci {
    state: RefCell<State>,
}

impl MockXhci {
    fn new() -> Self {
        let mut state = State {
            // Halted to begin with, which is what a controller that has not
            // been started reports.
            usbsts: sts::HALTED,
            ..State::default()
        };
        // One port with something plugged into it.
        state.ports[0] = port::CONNECTED | port::CONNECT_CHANGED;
        Self {
            state: RefCell::new(state),
        }
    }

    fn port_at(&self, offset: usize) -> Option<usize> {
        let first = CAP_LENGTH + op::PORTSC;
        if offset < first {
            return None;
        }
        let index = (offset - first) / op::PORT_STRIDE;
        (index < MAX_PORTS as usize && (offset - first).is_multiple_of(op::PORT_STRIDE))
            .then_some(index)
    }
}

impl Registers for MockXhci {
    fn read32(&self, offset: usize) -> u32 {
        let st = self.state.borrow();
        if let Some(port) = self.port_at(offset) {
            return st.ports[port];
        }
        match offset {
            cap::LENGTH_VERSION => (CAP_LENGTH as u32) | (0x0110 << 16),
            cap::HCSPARAMS1 => u32::from(MAX_SLOTS) | (u32::from(MAX_PORTS) << 24),
            cap::HCSPARAMS2 => 0,
            cap::HCCPARAMS1 => 1,
            cap::DBOFF => DBOFF as u32,
            cap::RTSOFF => RTSOFF as u32,
            o if o == CAP_LENGTH + op::USBCMD => st.usbcmd,
            o if o == CAP_LENGTH + op::USBSTS => st.usbsts,
            o if o == CAP_LENGTH + op::CONFIG => st.config,
            _ => 0,
        }
    }

    fn write32(&self, offset: usize, value: u32) {
        let mut st = self.state.borrow_mut();
        if let Some(port) = self.port_at(offset) {
            // Write-one-to-clear on the change bits, and a reset that completes
            // immediately and enables the port — which is what a controller
            // with nothing to negotiate does.
            let cleared = st.ports[port] & !(value & port::CHANGE_BITS);
            let mut next = (cleared & port::CHANGE_BITS) | (value & !port::CHANGE_BITS);
            next |= st.ports[port] & port::CONNECTED;
            if value & port::RESET != 0 {
                next = (next & !port::RESET) | port::ENABLED | port::RESET_CHANGED;
            }
            st.ports[port] = next;
            return;
        }
        match offset {
            o if o == CAP_LENGTH + op::USBCMD => {
                if value & cmd::RESET != 0 {
                    if st.wedged {
                        st.usbcmd = value;
                        st.usbsts = sts::HALTED | sts::NOT_READY;
                        return;
                    }
                    // A reset clears itself and leaves the controller halted.
                    st.usbcmd = 0;
                    st.usbsts = sts::HALTED;
                    return;
                }
                st.usbcmd = value;
                st.usbsts = if value & cmd::RUN != 0 {
                    st.usbsts & !sts::HALTED
                } else {
                    st.usbsts | sts::HALTED
                };
            }
            o if o == CAP_LENGTH + op::CONFIG => st.config = value,
            o if o == CAP_LENGTH + op::DCBAAP => {
                st.dcbaap = (st.dcbaap & !0xffff_ffff) | u64::from(value)
            }
            o if o == CAP_LENGTH + op::DCBAAP + 4 => {
                st.dcbaap = (st.dcbaap & 0xffff_ffff) | (u64::from(value) << 32)
            }
            o if o == CAP_LENGTH + op::CRCR => {
                st.crcr = (st.crcr & !0xffff_ffff) | u64::from(value)
            }
            o if o == CAP_LENGTH + op::CRCR + 4 => {
                st.crcr = (st.crcr & 0xffff_ffff) | (u64::from(value) << 32)
            }
            o if o == RTSOFF + rt::ERSTSZ => st.erstsz = value,
            o if o == RTSOFF + rt::ERSTBA => {
                st.erstba = (st.erstba & !0xffff_ffff) | u64::from(value)
            }
            o if o == RTSOFF + rt::ERSTBA + 4 => {
                st.erstba = (st.erstba & 0xffff_ffff) | (u64::from(value) << 32)
            }
            o if o == RTSOFF + rt::ERDP => st.erdp = (st.erdp & !0xffff_ffff) | u64::from(value),
            o if o == RTSOFF + rt::ERDP + 4 => {
                st.erdp = (st.erdp & 0xffff_ffff) | (u64::from(value) << 32)
            }
            o if o >= DBOFF && (o - DBOFF).is_multiple_of(4) && (o - DBOFF) / 4 < 64 => {
                st.doorbell = Some((((o - DBOFF) / 4) as u8, value));
            }
            _ => {}
        }
    }
}

const RING_BASE: u64 = 0x1000;
const EVENT_BASE: u64 = 0x2000;

/// **Nothing is at a fixed offset, and this is what says so.** The mock reports
/// unusual values for every one of them; a driver with a table of constants
/// works on the controller it was written against and fails here.
#[test]
fn every_register_base_comes_from_the_controller() {
    let device = MockXhci::new();
    let controller = Controller::discover(&device).expect("discover");
    assert_eq!(controller.max_slots(), MAX_SLOTS);
    assert_eq!(controller.max_ports(), MAX_PORTS);
    // Reading a port proves the operational base was taken from the capability
    // length rather than assumed: at any other base this reads zero.
    assert_eq!(
        controller.port_status(1).expect("port") & port::CONNECTED,
        port::CONNECTED,
    );
}

/// A controller reporting a layout that cannot be right is refused rather than
/// driven at offset zero.
#[test]
fn an_impossible_layout_is_refused() {
    struct Blank;
    impl Registers for Blank {
        fn read32(&self, _: usize) -> u32 {
            0
        }
        fn write32(&self, _: usize, _: u32) {}
    }
    assert_eq!(
        Controller::discover(&Blank).map(|_| ()),
        Err(Error::BadLayout),
    );
}

#[test]
fn bring_up_halts_resets_and_starts_in_that_order() {
    let device = MockXhci::new();
    let controller = Controller::discover(&device).expect("discover");
    let mut memory = [0u8; 16 * TRB_LEN];
    let ring = Ring::new(RING_BASE, 16, &mut memory).expect("ring");
    let events = EventRing::new(EVENT_BASE, 16).expect("events");
    controller
        .reset_and_run(0x3000, &ring, 0x4000, &events)
        .expect("run");

    let st = device.state.borrow();
    assert_eq!(st.usbcmd & cmd::RUN, cmd::RUN, "running");
    assert_eq!(st.usbsts & sts::HALTED, 0, "and not halted");
    assert_eq!(st.config, u32::from(MAX_SLOTS), "every slot enabled");
    assert_eq!(st.dcbaap, 0x3000);
    // The command ring's cycle travels with its address: the controller has to
    // agree with the producer about which lap it is on.
    assert_eq!(st.crcr, RING_BASE | 1);
    assert_eq!(st.erstsz, 1);
    assert_eq!(st.erstba, 0x4000);
}

/// A controller that never comes out of reset is reported rather than waited on
/// forever.
#[test]
fn a_controller_that_never_resets_is_reported() {
    let device = MockXhci::new();
    device.state.borrow_mut().wedged = true;
    let controller = Controller::discover(&device).expect("discover");
    let mut memory = [0u8; 4 * TRB_LEN];
    let ring = Ring::new(RING_BASE, 4, &mut memory).expect("ring");
    let events = EventRing::new(EVENT_BASE, 4).expect("events");
    assert_eq!(
        controller.reset_and_run(0x3000, &ring, 0x4000, &events),
        Err(Error::NotReady),
    );
}

/// **A ring wraps through its link, and crossing it toggles the cycle.** A ring
/// that wrapped by resetting an index would hand the controller entries it has
/// already consumed, with a cycle bit claiming they are new.
#[test]
fn a_ring_wraps_through_its_link_and_toggles_the_cycle() {
    let mut memory = [0u8; 4 * TRB_LEN];
    let mut ring = Ring::new(RING_BASE, 4, &mut memory).expect("ring");
    assert!(ring.cycle());

    // Three usable slots: the fourth is the link.
    let mut addresses = [0u64; 3];
    for (slot, address) in addresses.iter_mut().enumerate() {
        *address = ring
            .push(command(trb::ENABLE_SLOT, 0), &mut memory)
            .expect("push");
        assert_eq!(*address, RING_BASE + (slot as u64) * TRB_LEN as u64);
    }
    // Having filled the last usable slot, the ring is back at the start on the
    // other cycle.
    assert!(!ring.cycle(), "the lap changed");
    let wrapped = ring
        .push(command(trb::ENABLE_SLOT, 0), &mut memory)
        .expect("push");
    assert_eq!(wrapped, RING_BASE, "and it wrote the first slot again");

    // Every entry carries the cycle of the lap it was written on, which is the
    // only thing distinguishing the two passes over the same memory.
    let first = Trb::read(&memory[..TRB_LEN]).expect("read");
    assert_eq!(first.control & 1, 0, "second lap");
    let second = Trb::read(&memory[TRB_LEN..2 * TRB_LEN]).expect("read");
    assert_eq!(second.control & 1, 1, "still the first lap's");

    // The link points home and asks the controller to toggle with it.
    let link = Trb::read(&memory[3 * TRB_LEN..4 * TRB_LEN]).expect("read");
    assert_eq!(link.kind(), trb::LINK);
    assert_eq!(link.parameter, RING_BASE);
    assert_eq!(link.control & (1 << 1), 1 << 1, "toggle cycle");
}

/// A ring too small to hold work and a link is refused rather than built.
#[test]
fn a_ring_with_no_room_is_refused() {
    let mut memory = [0u8; 4 * TRB_LEN];
    assert_eq!(
        Ring::new(RING_BASE, 1, &mut memory).map(|_| ()),
        Err(Error::RingSize),
    );
    // And a ring whose memory is shorter than it claims.
    let mut small = [0u8; TRB_LEN];
    assert_eq!(
        Ring::new(RING_BASE, 4, &mut small).map(|_| ()),
        Err(Error::ShortBuffer),
    );
}

/// **The cycle bit, which is the whole reason the event ring is a type.**
/// Nothing in an event says it is new. A reader that ignored it would process
/// the previous lap's events again on every wrap — indistinguishable from a
/// controller completing work twice.
#[test]
fn a_wrapped_event_ring_does_not_replay_the_previous_lap() {
    const ENTRIES: u16 = 4;
    let mut memory = [0u8; ENTRIES as usize * TRB_LEN];
    let mut events = EventRing::new(EVENT_BASE, ENTRIES).expect("events");

    // The controller posts a full lap, each with the cycle set.
    for slot in 0..ENTRIES {
        let event = Trb {
            parameter: 0,
            status: u32::from(COMPLETION_SUCCESS) << 24,
            control: (trb::COMMAND_COMPLETION << 10) | (u32::from(slot + 1) << 24) | 1,
        };
        let at = usize::from(slot) * TRB_LEN;
        event.write(&mut memory[at..at + TRB_LEN]).expect("write");
    }
    for slot in 0..ENTRIES {
        let event = events.poll(&memory).expect("poll").expect("an event");
        assert_eq!(event.slot(), (slot + 1) as u8);
        assert!(event.is_success());
    }
    // Back at the start on the other cycle. The entries are still there, and
    // must not be read again.
    assert_eq!(
        events.poll(&memory).expect("poll"),
        None,
        "the previous lap is not new work",
    );

    // The controller writes over slot zero with the flipped cycle, and that one
    // *is* new.
    let event = Trb {
        parameter: 0,
        status: u32::from(COMPLETION_SUCCESS) << 24,
        control: (trb::COMMAND_COMPLETION << 10) | (0x20 << 24),
    };
    event.write(&mut memory[..TRB_LEN]).expect("write");
    let taken = events.poll(&memory).expect("poll").expect("an event");
    assert_eq!(taken.slot(), 0x20);
}

/// A completion code other than success is reported as itself, so a driver can
/// say which — and a **short packet counts as success**, because on a bulk
/// endpoint it is how a device says "that is all there was". A driver treating
/// it as a failure would report an error for every read that reached the end.
#[test]
fn a_short_packet_is_a_success_and_a_stall_is_not() {
    let short = Trb {
        parameter: 0,
        status: (u32::from(COMPLETION_SHORT_PACKET) << 24) | 12,
        control: trb::TRANSFER_EVENT << 10,
    };
    assert!(short.is_success());
    assert_eq!(short.residual(), 12, "twelve bytes were not transferred");

    let stalled = Trb {
        parameter: 0,
        status: 6 << 24, // stall error
        control: trb::TRANSFER_EVENT << 10,
    };
    assert!(!stalled.is_success());
    assert_eq!(stalled.completion_code(), 6);
}

/// A control transfer is three TRBs and one transaction, and **the status stage
/// runs the other way from the data stage**. That direction cannot be derived
/// from the request alone, and getting it backwards stalls the endpoint.
#[test]
fn a_control_transfer_reverses_its_status_stage() {
    // A device-to-host request: eight bytes of setup, data in, status out.
    let setup = [0x80, 6, 0, 1, 0, 0, 18, 0];
    let [setup_trb, data, status] = control_transfer(setup, 0x5000, 18, true);
    assert_eq!(setup_trb.kind(), trb::SETUP);
    assert_eq!(setup_trb.status, 8, "a setup stage is always eight bytes");
    assert_eq!((setup_trb.control >> 16) & 0x3, 3, "an IN data stage");
    assert_eq!(data.kind(), trb::DATA);
    assert_eq!(data.parameter, 0x5000);
    assert_eq!(data.status, 18);
    assert_eq!((data.control >> 16) & 1, 1, "data comes in");
    assert_eq!(status.kind(), trb::STATUS);
    assert_eq!((status.control >> 16) & 1, 0, "and status goes out");

    // The other way round.
    let setup = [0x00, 9, 1, 0, 0, 0, 0, 0];
    let [_, _, status] = control_transfer(setup, 0, 0, false);
    assert_eq!((status.control >> 16) & 1, 1, "no data, so status comes in");
}

/// Resetting a port leaves it enabled, and **acknowledges only the change bits
/// that reset raised**. Those bits are write-one-to-clear, so a
/// read-modify-write that put them all back would clear a connection nobody had
/// acted on — and the device that arrived would never be enumerated.
#[test]
fn resetting_a_port_enables_it_without_clearing_what_it_did_not_handle() {
    let device = MockXhci::new();
    let controller = Controller::discover(&device).expect("discover");
    // Something is plugged in and the controller has said so.
    assert_ne!(
        controller.port_status(1).expect("port") & port::CONNECT_CHANGED,
        0,
    );
    controller.reset_port(1).expect("reset");
    let status = controller.port_status(1).expect("port");
    assert_ne!(status & port::ENABLED, 0, "enabled");
    assert_eq!(status & port::RESET, 0, "and the reset finished");
    assert_eq!(
        status & port::RESET_CHANGED,
        0,
        "its own change bit was acknowledged",
    );
    assert_ne!(
        status & port::CONNECT_CHANGED,
        0,
        "and the connection nobody has handled is still there",
    );
}

/// A port this controller does not have is an answer, not a read of whatever
/// follows the port array.
#[test]
fn a_port_that_does_not_exist_is_refused() {
    let device = MockXhci::new();
    let controller = Controller::discover(&device).expect("discover");
    assert_eq!(controller.port_status(0), Err(Error::NoSuchPort));
    assert_eq!(
        controller.port_status(MAX_PORTS + 1),
        Err(Error::NoSuchPort),
    );
    assert_eq!(controller.reset_port(MAX_PORTS + 1), Err(Error::NoSuchPort));
}

/// The doorbell array is indexed by slot, and slot zero is the command ring.
#[test]
fn the_doorbell_is_indexed_by_slot() {
    let device = MockXhci::new();
    let controller = Controller::discover(&device).expect("discover");
    controller.doorbell(0, 0);
    assert_eq!(device.state.borrow().doorbell, Some((0, 0)));
    // Endpoint one on slot three — the control endpoint of an addressed device.
    controller.doorbell(3, 1);
    assert_eq!(device.state.borrow().doorbell, Some((3, 1)));
}

/// A TRB round-trips through memory unchanged, which is what lets a driver read
/// back what it wrote and a test read what a driver wrote.
#[test]
fn a_trb_round_trips() {
    let value = command_with_context(trb::ADDRESS_DEVICE, 7, 0x1234_5678_9abc_0000);
    let mut bytes = [0u8; TRB_LEN];
    value.write(&mut bytes).expect("write");
    assert_eq!(Trb::read(&bytes).expect("read"), value);
    assert_eq!(value.kind(), trb::ADDRESS_DEVICE);
    assert_eq!(value.slot(), 7);
    // And a buffer too short for one is refused rather than partly read.
    assert_eq!(Trb::read(&bytes[..8]), Err(Error::ShortBuffer));
}

/// **Context size is read, not assumed.** A driver that assumed thirty-two
/// bytes on a controller using sixty-four would write every context after the
/// first into the middle of the one before it — and the device would address
/// successfully and then transfer nothing.
#[test]
fn the_context_size_comes_from_the_controller() {
    let device = MockXhci::new();
    assert_eq!(context::size_of(&device), 32, "HCCPARAMS1 bit 2 clear");
    assert_eq!(context::at(2, 32), 64);
    assert_eq!(context::at(2, 64), 128, "and the stride follows it");

    struct Wide;
    impl Registers for Wide {
        fn read32(&self, offset: usize) -> u32 {
            if offset == cap::HCCPARAMS1 { 1 << 2 } else { 0 }
        }
        fn write32(&self, _: usize, _: u32) {}
    }
    assert_eq!(context::size_of(&Wide), 64);
}

/// A device has to be addressed before it can be asked anything, and addressing
/// it names a packet size — so the first one comes from the link speed.
#[test]
fn the_first_packet_size_comes_from_the_speed() {
    assert_eq!(context::default_packet_size(context::SPEED_LOW), 8);
    assert_eq!(context::default_packet_size(context::SPEED_FULL), 8);
    assert_eq!(context::default_packet_size(context::SPEED_HIGH), 64);
    assert_eq!(context::default_packet_size(context::SPEED_SUPER), 512);
}

/// **The route string is how a controller reaches a device it has no port
/// for.** Left zero for a device behind a hub, it describes the hub's own port
/// on the root controller — and every transfer goes to the hub instead.
#[test]
fn a_slot_context_carries_the_path_through_the_hubs() {
    let mut memory = [0u8; 64];
    // A full-speed device on port 3 of a hub, itself on root port 1.
    context::write_slot(&mut memory, 0, 3, context::SPEED_FULL, 1, 1, Some((2, 3))).expect("slot");
    assert_eq!(
        word(&memory, 0) & 0xf_ffff,
        3,
        "the hub port, one tier down"
    );
    assert_eq!(
        (word(&memory, 0) >> 20) & 0xf,
        u32::from(context::SPEED_FULL)
    );
    assert_eq!(word(&memory, 0) >> 27, 1, "one endpoint context follows");
    assert_eq!(
        (word(&memory, 4) >> 16) & 0xff,
        1,
        "and the root port it hangs off"
    );
    // The transaction translator: which hub speaks to it, and on which port.
    // A full-speed device behind a high-speed hub is unreachable without it.
    assert_eq!(word(&memory, 8) & 0xff, 2);
    assert_eq!((word(&memory, 8) >> 8) & 0xff, 3);

    // A device on a root port routes through nothing.
    context::write_slot(&mut memory, 0, 0, context::SPEED_HIGH, 1, 2, None).expect("slot");
    assert_eq!(word(&memory, 0) & 0xf_ffff, 0);
    assert_eq!(word(&memory, 8), 0, "and needs no translator");
}

/// An endpoint context carries the ring's **cycle state** in its dequeue
/// pointer, for the reason the command ring's address does: a controller
/// starting on the wrong lap waits for work it can already see.
#[test]
fn an_endpoint_context_starts_the_controller_on_the_producers_lap() {
    let mut memory = [0u8; 64];
    context::write_endpoint(&mut memory, 0, context::BULK_IN, 512, 0x8000, true, 0)
        .expect("endpoint");
    assert_eq!((word(&memory, 4) >> 3) & 0x7, u32::from(context::BULK_IN));
    assert_eq!(word(&memory, 4) >> 16, 512);
    assert_eq!((word(&memory, 4) >> 1) & 0x3, 3, "three error retries");
    assert_eq!(
        word(&memory, 8),
        0x8001,
        "the ring, and the cycle it is producing at"
    );
    assert_eq!(word(&memory, 12), 0);
    assert_ne!(
        word(&memory, 16),
        0,
        "an average TRB length the controller can budget"
    );

    // The other lap.
    context::write_endpoint(&mut memory, 0, context::CONTROL, 64, 0x8000, false, 0)
        .expect("endpoint");
    assert_eq!(word(&memory, 8), 0x8000);
}

/// **A command that adds nothing changes nothing, and says it succeeded.** The
/// add mask is an argument rather than being inferred from what the caller
/// filled in, because the failure is silent: the controller reads the flags,
/// finds no context selected, and reports success.
#[test]
fn an_input_control_context_says_what_to_read() {
    let mut memory = [0u8; 32];
    // The slot context and endpoint one — what addressing a device adds.
    context::write_input_control(&mut memory, 0b11, 0, 0).expect("control");
    assert_eq!(word(&memory, 0), 0, "nothing dropped");
    assert_eq!(word(&memory, 4), 0b11);
    assert_eq!(word(&memory, 28), 0);

    // A configure-endpoint command carries the configuration value it applies.
    context::write_input_control(&mut memory, 0b1001, 0b100, 1).expect("control");
    assert_eq!(word(&memory, 0), 0b100);
    assert_eq!(word(&memory, 4), 0b1001);
    assert_eq!(word(&memory, 28) & 0xff, 1);
}

/// One little-endian word of a context under test.
fn word(memory: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([memory[at], memory[at + 1], memory[at + 2], memory[at + 3]])
}
