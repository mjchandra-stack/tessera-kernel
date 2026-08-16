// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Descriptors that are wrong on purpose.
//!
//! Every device here is one a plugged-in USB device can be. None of them needs
//! hardware to make, and none of them is unlikely — the byte strings below are
//! four lines of firmware apiece.

use super::*;

/// A descriptor chain under construction. Fixed size, like everything else in
/// this crate.
struct Bytes {
    buf: [u8; 256],
    len: usize,
}

impl Bytes {
    fn new() -> Bytes {
        Bytes {
            buf: [0; 256],
            len: 0,
        }
    }

    fn push(&mut self, part: &[u8]) {
        self.buf[self.len..self.len + part.len()].copy_from_slice(part);
        self.len += part.len();
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Writes the honest total length into the configuration descriptor, which
    /// is what a device that is not lying does.
    fn seal(&mut self) -> &[u8] {
        let total = (self.len as u16).to_le_bytes();
        self.buf[2] = total[0];
        self.buf[3] = total[1];
        self.as_slice()
    }
}

fn configuration(interfaces: u8) -> [u8; 9] {
    // Total length is patched by `seal`; 0xfa is 500 mA.
    [
        9,
        descriptor::CONFIGURATION,
        0,
        0,
        interfaces,
        1,
        0,
        0x80,
        0xfa,
    ]
}

fn interface(number: u8, alternate: u8, endpoints: u8, class: u8, sub: u8, proto: u8) -> [u8; 9] {
    [
        9,
        descriptor::INTERFACE,
        number,
        alternate,
        endpoints,
        class,
        sub,
        proto,
        0,
    ]
}

fn endpoint(address: u8, attributes: u8, max_packet: u16, interval: u8) -> [u8; 7] {
    let size = max_packet.to_le_bytes();
    [
        7,
        descriptor::ENDPOINT,
        address,
        attributes,
        size[0],
        size[1],
        interval,
    ]
}

/// A mass-storage device: one interface, bulk in and bulk out.
fn storage_device() -> Bytes {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(
        0,
        0,
        2,
        class::MASS_STORAGE,
        storage::SUBCLASS_SCSI,
        storage::PROTOCOL_BULK_ONLY,
    ));
    bytes.push(&endpoint(0x81, 2, 512, 0));
    bytes.push(&endpoint(0x02, 2, 512, 0));
    bytes
}

#[test]
fn a_storage_device_describes_two_bulk_pipes() {
    let mut bytes = storage_device();
    let config = Configuration::parse(bytes.seal()).expect("parse");
    assert_eq!(config.value, 1);
    assert_eq!(config.max_power, 0xfa);
    assert_eq!(config.interfaces().len(), 1);

    let interface = config.default_setting(0).expect("interface");
    assert_eq!(interface.class, class::MASS_STORAGE);
    assert_eq!(interface.endpoints().len(), 2);

    let input = interface
        .find_endpoint(TransferType::Bulk, true)
        .expect("bulk in");
    assert_eq!(input.number(), 1);
    assert_eq!(input.max_packet_size, 512);
    let output = interface
        .find_endpoint(TransferType::Bulk, false)
        .expect("bulk out");
    assert_eq!(output.number(), 2);
    // The two directions of endpoint one are different context indices, and a
    // driver that used the endpoint number would address one of them twice.
    assert_eq!(input.context_index(), 3);
    assert_eq!(output.context_index(), 4);
}

/// A HID device carries a HID descriptor between its interface and its
/// endpoint. **Skipping what is not understood is required, not lenient** — a
/// parser that refused an unknown descriptor type would refuse every keyboard.
#[test]
fn a_class_specific_descriptor_is_walked_past_rather_than_refused() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(
        0,
        0,
        1,
        class::HID,
        hid::SUBCLASS_BOOT,
        hid::PROTOCOL_KEYBOARD,
    ));
    // A HID descriptor: nine bytes, type 0x21, and nothing this parser knows.
    bytes.push(&[9, 0x21, 0x11, 0x01, 0, 1, 0x22, 65, 0]);
    bytes.push(&endpoint(0x81, 3, 8, 10));
    let config = Configuration::parse(bytes.seal()).expect("parse");

    let interface = config.default_setting(0).expect("interface");
    assert_eq!(interface.protocol, hid::PROTOCOL_KEYBOARD);
    let report = interface
        .find_endpoint(TransferType::Interrupt, true)
        .expect("interrupt in");
    assert_eq!(report.interval, 10);
    assert_eq!(report.max_packet_size, 8);
}

/// **The one input that is a hang rather than a wrong answer.** A length byte
/// of zero, walked by advancing the length read, never advances. It costs a
/// device one byte to send and it would hang enumeration for good.
#[test]
fn a_length_of_zero_is_refused_rather_than_walked() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(0, 0, 0, class::HID, 0, 0));
    // Where the next descriptor would be.
    bytes.push(&[0, descriptor::ENDPOINT, 0, 0, 0, 0, 0]);
    assert_eq!(Configuration::parse(bytes.seal()), Err(Error::ZeroLength));

    // And a length of one, which is the same failure wearing a different byte:
    // the header alone is two.
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&[1, descriptor::INTERFACE, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(Configuration::parse(bytes.seal()), Err(Error::ZeroLength));
}

/// A length that runs past what was read is refused, not read as given. Read as
/// given it returns whatever the host's buffer held before the transfer.
#[test]
fn a_length_past_the_buffer_is_refused() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    // An interface descriptor claiming sixty bytes, with nine present.
    bytes.push(&[60, descriptor::INTERFACE, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(Configuration::parse(bytes.seal()), Err(Error::Truncated));

    // And a trailing byte with no room for a header.
    let mut bytes = storage_device();
    bytes.push(&[9]);
    assert_eq!(Configuration::parse(bytes.seal()), Err(Error::Truncated));
}

/// A total length past what was read means the second transfer did not
/// complete. Parsing what arrived would describe a device by half its own
/// description — with the missing half being, say, the interface that was not
/// on the allowlist.
#[test]
fn a_total_length_past_what_was_read_is_refused() {
    let mut bytes = storage_device();
    let sealed_len = bytes.seal().len();
    let overstated = ((sealed_len + 1) as u16).to_le_bytes();
    bytes.buf[2] = overstated[0];
    bytes.buf[3] = overstated[1];
    assert_eq!(
        Configuration::parse(bytes.as_slice()),
        Err(Error::TotalLength)
    );

    // A total length shorter than the descriptor that declares it is refused
    // for the same reason it is impossible.
    let mut bytes = storage_device();
    bytes.seal();
    bytes.buf[2] = 4;
    bytes.buf[3] = 0;
    assert_eq!(
        Configuration::parse(bytes.as_slice()),
        Err(Error::TotalLength)
    );
}

/// Bytes after the configuration's own length belong to the host's buffer, not
/// to the device, and are not parsed. A host reads a fixed-size buffer, so this
/// is the normal case rather than an odd one.
#[test]
fn trailing_bytes_beyond_the_declared_length_are_not_the_devices_word() {
    let mut bytes = storage_device();
    let honest = bytes.seal().len();
    // A third bulk endpoint, past the length the device declared.
    bytes.push(&endpoint(0x83, 2, 512, 0));
    let total = (honest as u16).to_le_bytes();
    bytes.buf[2] = total[0];
    bytes.buf[3] = total[1];

    let config = Configuration::parse(bytes.as_slice()).expect("parse");
    let interface = config.default_setting(0).expect("interface");
    assert_eq!(
        interface.endpoints().len(),
        2,
        "the smuggled pipe is not one"
    );
}

/// A count that disagrees with what is present is a device asking a driver to
/// use something that does not exist.
#[test]
fn a_count_that_disagrees_with_what_arrived_is_refused() {
    // Two interfaces claimed, one supplied.
    let mut bytes = Bytes::new();
    bytes.push(&configuration(2));
    bytes.push(&interface(0, 0, 0, class::HID, 0, 0));
    assert_eq!(
        Configuration::parse(bytes.seal()),
        Err(Error::CountMismatch)
    );

    // Two endpoints claimed, one supplied — the one a driver would open a
    // second pipe on, having read an endpoint that was never described.
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(0, 0, 2, class::MASS_STORAGE, 6, 0x50));
    bytes.push(&endpoint(0x81, 2, 512, 0));
    assert_eq!(
        Configuration::parse(bytes.seal()),
        Err(Error::CountMismatch)
    );
}

/// Alternate settings are extra descriptors of the *same* interface, so they do
/// not count against `bNumInterfaces`. A parser that counted descriptors would
/// refuse every device with a second setting — which is most of them that carry
/// audio or video.
#[test]
fn alternate_settings_are_not_extra_interfaces() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(0, 0, 0, class::AUDIO, 2, 0));
    bytes.push(&interface(0, 1, 1, class::AUDIO, 2, 0));
    bytes.push(&endpoint(0x81, 1, 192, 1));
    let config = Configuration::parse(bytes.seal()).expect("parse");

    assert_eq!(config.interfaces().len(), 2, "both settings are kept");
    assert_eq!(
        config.default_setting(0).expect("default").alternate,
        0,
        "and the default is the one with no endpoints",
    );
    // The alternate's endpoint is isochronous, which this transport does not
    // schedule — named rather than folded into bulk, so a host declines it
    // knowingly.
    let alternate = config.interfaces()[1];
    assert_eq!(
        alternate.endpoints()[0].transfer_type(),
        TransferType::Isochronous,
    );
}

/// An endpoint before any interface belongs to nothing. Attaching it to
/// whichever interface comes next is how a driver ends up talking to the wrong
/// one.
#[test]
fn an_endpoint_owned_by_nothing_is_refused() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&endpoint(0x81, 2, 512, 0));
    bytes.push(&interface(0, 0, 0, class::MASS_STORAGE, 6, 0x50));
    assert_eq!(
        Configuration::parse(bytes.seal()),
        Err(Error::StrayEndpoint)
    );
}

/// More than this parser holds is **refused, not clipped**. A driver handed a
/// configuration with the tail quietly removed would drive a device that is not
/// the one attached — and would never be told.
#[test]
fn a_configuration_larger_than_the_bound_is_refused_not_clipped() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration((MAX_INTERFACES + 1) as u8));
    for number in 0..=MAX_INTERFACES {
        bytes.push(&interface(number as u8, 0, 0, class::VENDOR, 0, 0));
    }
    assert_eq!(Configuration::parse(bytes.seal()), Err(Error::TooMany));

    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(
        0,
        0,
        (MAX_ENDPOINTS + 1) as u8,
        class::VENDOR,
        0,
        0,
    ));
    for index in 0..=MAX_ENDPOINTS {
        bytes.push(&endpoint(0x81 + index as u8, 2, 64, 0));
    }
    assert_eq!(Configuration::parse(bytes.seal()), Err(Error::TooMany));
}

#[test]
fn a_device_descriptor_is_read_or_refused() {
    let device = [
        18,
        descriptor::DEVICE,
        0x00,
        0x02, // USB 2.00
        class::PER_INTERFACE,
        0,
        0,
        64,
        0x30,
        0x46, // vendor 0x4630
        0x01,
        0x00, // product 0x0001
        0x00,
        0x01, // device 0x0100
        1,
        2,
        3,
        1,
    ];
    let parsed = DeviceDescriptor::parse(&device).expect("parse");
    assert_eq!(parsed.usb_version, 0x0200);
    assert_eq!(parsed.class, class::PER_INTERFACE);
    assert_eq!(parsed.vendor, 0x4630);
    assert_eq!(parsed.product, 1);
    assert_eq!(parsed.max_packet_size0, 64);
    assert_eq!(parsed.configurations, 1);

    // A device descriptor that is really a configuration descriptor.
    let mut wrong = device;
    wrong[1] = descriptor::CONFIGURATION;
    assert_eq!(DeviceDescriptor::parse(&wrong), Err(Error::WrongType));

    // A device descriptor claiming to be a device descriptor and being eight
    // bytes long. Well-formed as a descriptor, short for what it is.
    let short = [8, descriptor::DEVICE, 0, 2, 0, 0, 0, 64];
    assert_eq!(DeviceDescriptor::parse(&short), Err(Error::ShortDescriptor));
}

#[test]
fn a_hub_says_how_many_ports_it_has() {
    let hub = [9, descriptor::HUB, 8, 0x09, 0x00, 50, 100, 0xff, 0x00];
    let parsed = HubDescriptor::parse(&hub).expect("parse");
    assert_eq!(parsed.ports, 8);
    assert_eq!(parsed.characteristics, 0x0009);
    assert_eq!(parsed.power_on_delay, 50);

    let short = [3, descriptor::HUB, 8];
    assert_eq!(HubDescriptor::parse(&short), Err(Error::ShortDescriptor));
}

/// **A policy admits nothing until it is told to.** A policy that started open
/// would admit whatever arrived before anyone configured it, which is the
/// window a hotplug attack wants.
#[test]
fn a_policy_admits_nothing_until_it_is_told_to() {
    let mut bytes = storage_device();
    let config = Configuration::parse(bytes.seal()).expect("parse");
    let policy = Policy::new();
    assert!(policy.is_empty());
    assert_eq!(
        policy.authorize_device(&config),
        Authorization::Refused {
            interface: 0,
            alternate: 0,
            class: class::MASS_STORAGE,
            subclass: storage::SUBCLASS_SCSI,
            protocol: storage::PROTOCOL_BULK_ONLY,
        },
    );
}

/// A device that enumerates perfectly and is still not driven — which is the
/// thing USB has that no other bus here does. The refusal names what the device
/// claimed, so it can be recorded rather than merely taken.
#[test]
fn a_class_off_the_list_is_refused_and_the_refusal_says_what_it_claimed() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(0, 0, 1, class::AUDIO, 1, 0));
    bytes.push(&endpoint(0x81, 1, 192, 1));
    let config = Configuration::parse(bytes.seal()).expect("parse");

    let mut policy = Policy::new();
    policy.allow_class(class::MASS_STORAGE).expect("allow");
    policy.allow_class(class::HID).expect("allow");
    policy.allow_class(class::HUB).expect("allow");
    assert_eq!(
        policy.authorize_device(&config),
        Authorization::Refused {
            interface: 0,
            alternate: 0,
            class: class::AUDIO,
            subclass: 1,
            protocol: 0,
        },
    );

    // And with its class on the list it is admitted — which is what shows the
    // refusal was the policy's doing and not a parser that could not cope.
    policy.allow_class(class::AUDIO).expect("allow");
    assert_eq!(policy.authorize_device(&config), Authorization::Allowed);
}

/// **Every interface, not any.** A device presenting a keyboard alongside
/// something else would otherwise be admitted on the strength of the keyboard,
/// and the something else is the entire point of the attack.
#[test]
fn a_composite_device_is_judged_by_its_worst_interface() {
    let mut bytes = Bytes::new();
    bytes.push(&configuration(2));
    bytes.push(&interface(
        0,
        0,
        1,
        class::HID,
        hid::SUBCLASS_BOOT,
        hid::PROTOCOL_KEYBOARD,
    ));
    bytes.push(&endpoint(0x81, 3, 8, 10));
    bytes.push(&interface(1, 0, 1, class::WIRELESS, 1, 1));
    bytes.push(&endpoint(0x82, 3, 16, 10));
    let config = Configuration::parse(bytes.seal()).expect("parse");

    let mut policy = Policy::new();
    policy.allow_class(class::HID).expect("allow");
    match policy.authorize_device(&config) {
        Authorization::Refused {
            interface, class, ..
        } => {
            assert_eq!(interface, 1);
            assert_eq!(class, class::WIRELESS);
        }
        Authorization::Allowed => panic!("the second interface is not on the list"),
    }
    // The keyboard on its own would have been admitted, which is what the
    // device was counting on.
    assert_eq!(
        policy.authorize(&config.interfaces()[0]),
        Authorization::Allowed,
    );
}

/// A policy may be narrower than a class: bulk-only SCSI storage, and not a
/// storage device speaking something else.
#[test]
fn a_policy_entry_may_narrow_to_a_subclass_and_protocol() {
    let mut policy = Policy::new();
    policy
        .allow(Allowed {
            class: class::MASS_STORAGE,
            subclass: Some(storage::SUBCLASS_SCSI),
            protocol: Some(storage::PROTOCOL_BULK_ONLY),
        })
        .expect("allow");

    let mut bytes = storage_device();
    let config = Configuration::parse(bytes.seal()).expect("parse");
    assert_eq!(policy.authorize_device(&config), Authorization::Allowed);

    // The same class over a different protocol is a different device.
    let mut bytes = Bytes::new();
    bytes.push(&configuration(1));
    bytes.push(&interface(0, 0, 0, class::MASS_STORAGE, 6, 0x00));
    let other = Configuration::parse(bytes.seal()).expect("parse");
    assert_ne!(policy.authorize_device(&other), Authorization::Allowed);
}

/// A full policy refuses the entry rather than dropping it. A policy silently
/// missing a line turns away a device the administrator meant to permit, and
/// nothing says so.
#[test]
fn a_full_policy_refuses_rather_than_drops() {
    let mut policy = Policy::new();
    for class in 0..MAX_POLICY {
        policy.allow_class(class as u8).expect("allow");
    }
    assert_eq!(policy.len(), MAX_POLICY);
    assert_eq!(policy.allow_class(0x40), Err(Error::TooMany));
}

/// The setup bytes, which encode direction in the request type. A request whose
/// direction disagrees with its data stage stalls the endpoint, and the mistake
/// is invisible in a constant written per driver.
#[test]
fn the_standard_requests_are_built_with_their_direction() {
    let get = request::get_descriptor(descriptor::DEVICE, 0, 18);
    assert_eq!(get[0], request::IN_STANDARD_DEVICE, "reads come in");
    assert_eq!(get[1], 6);
    assert_eq!(u16::from_le_bytes([get[2], get[3]]), 0x0100, "type, index");
    assert_eq!(u16::from_le_bytes([get[6], get[7]]), 18);

    let set = request::set_address(3);
    assert_eq!(set[0], request::OUT_STANDARD_DEVICE, "writes go out");
    assert_eq!(set[1], 5);
    assert_eq!(u16::from_le_bytes([set[2], set[3]]), 3);
    assert_eq!(u16::from_le_bytes([set[6], set[7]]), 0, "and carry no data");

    // A hub's own descriptor looks like a descriptor read and is a class
    // request; sent as a standard one it returns the wrong descriptor.
    let hub = request::get_hub_descriptor(9);
    assert_eq!(hub[0], request::IN_CLASS_DEVICE);
    assert_eq!(u16::from_le_bytes([hub[2], hub[3]]), 0x2900);

    // A hub's port requests name the port in the index, not the value.
    let status = request::get_port_status(4);
    assert_eq!(status[0], request::IN_CLASS_OTHER);
    assert_eq!(u16::from_le_bytes([status[4], status[5]]), 4);
    let reset = request::set_port_feature(4, hub_port::FEATURE_RESET);
    assert_eq!(reset[0], request::OUT_CLASS_OTHER);
    assert_eq!(u16::from_le_bytes([reset[2], reset[3]]), 4);
    assert_eq!(u16::from_le_bytes([reset[4], reset[5]]), 4);

    let configure = request::set_configuration(1);
    assert_eq!(configure[1], 9);
    let clear = request::clear_port_feature(2, hub_port::FEATURE_C_CONNECTION);
    assert_eq!(clear[1], 1);
    assert_eq!(u16::from_le_bytes([clear[2], clear[3]]), 16);
}

/// Arbitrary bytes, which is what a hostile device sends. Nothing here may
/// panic and nothing may fail to return — the second half is the one the
/// zero-length guard buys, and a test that hangs is how it would be reported.
///
/// A seeded generator rather than a libfuzzer target, for the reason the ISL
/// parser's is (D12): the fuzzing toolchain is not vendored yet.
#[test]
fn the_parsers_never_panic_on_arbitrary_input() {
    let mut state: u64 = 0x0badc0de_5eed1234;
    let mut buffer = [0u8; 96];
    for round in 0..4000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = ((state >> 33) as usize % buffer.len()) + 1;
        let mut local = state;
        for byte in buffer[..len].iter_mut() {
            local = local.wrapping_mul(6364136223846793005).wrapping_add(1);
            // Mostly small values, so lengths and types land in the range that
            // reaches the interesting paths rather than being refused at once.
            *byte = if local & 0x30 == 0 {
                (local >> 40) as u8
            } else {
                (local >> 40) as u8 % 12
            };
        }
        // Half the rounds start with a well-formed configuration header, so the
        // walk gets past the first check and into the chain.
        if round % 2 == 0 && len >= 9 {
            buffer[..9].copy_from_slice(&configuration(1));
            let total = (len as u16).to_le_bytes();
            buffer[2] = total[0];
            buffer[3] = total[1];
        }
        let _ = Configuration::parse(&buffer[..len]);
        let _ = DeviceDescriptor::parse(&buffer[..len]);
        let _ = HubDescriptor::parse(&buffer[..len]);
        let mut walk = Walk::new(&buffer[..len]);
        while let Ok(Some(_)) = walk.next_descriptor() {}
    }
}
