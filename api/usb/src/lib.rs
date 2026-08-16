// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The parts of USB that are bytes rather than registers: the standard
//! requests, the descriptors a device uses to describe itself, and the policy
//! that decides whether what it described is allowed to be driven.
//!
//! # A device's descriptors are a device's word
//!
//! Every other bus in this tree hands out devices that are *there*: firmware
//! found them, or a config space the host owns describes them. A USB device
//! describes itself, in bytes it chooses, after being plugged into a running
//! system by whoever is standing next to it. `docs/drivers/02` calls this
//! untrusted hotplug input, and it means every field below is external input in
//! the strict sense — not "probably a device" but "an attacker's byte string
//! that a driver is about to believe".
//!
//! So the parsing is separated from the driving, put here, and host-tested
//! against input that is wrong on purpose. Three failures are worth naming
//! because they are the ones that are not merely a wrong answer:
//!
//! - **A length byte of zero.** A walker that advanced by the length it read
//!   would never advance, and the enumeration would never finish. This is the
//!   only way a flat descriptor chain can contain a cycle, and it costs one
//!   byte to make.
//! - **A length that runs past the buffer.** Read as given, it reads whatever
//!   the host left after the transfer — the previous device's descriptors, or
//!   worse.
//! - **A count that disagrees with what is present.** A configuration claiming
//!   more interfaces or endpoints than it carries is a device asking a driver
//!   to use a thing that does not exist.
//!
//! Each is a typed error. Nothing here panics, nothing here truncates quietly,
//! and a bound reached is refused rather than silently clipped.
//!
//! # Describing yourself is not the same as being allowed
//!
//! [`Policy`] is the other half. A device can enumerate perfectly — correct
//! descriptors, every count honest — and still not be given a driver, because
//! its class is not one this system drives. That is where USB differs from
//! every bus so far, and the refusal carries what the device claimed so the
//! decision can be recorded rather than merely taken.
//!
//! Normative: docs/drivers/02-storage-networking-usb-pcie.md ("USB")
//! Budget: none (enumeration, not a data path)

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
mod tests;

/// Interface descriptors one configuration may present.
///
/// Alternate settings count against this: each is its own descriptor, and each
/// carries its own class — which is the point of judging them separately.
pub const MAX_INTERFACES: usize = 8;

/// Endpoints one interface may present, over and above its control endpoint.
pub const MAX_ENDPOINTS: usize = 8;

/// Entries an authorization policy may hold.
pub const MAX_POLICY: usize = 8;

/// What can go wrong reading what a device said about itself. Every variant is
/// a fact about the bytes, and every one of them is reachable from a device
/// that chooses to send it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// A descriptor claims a length that runs past what was read.
    Truncated,
    /// A descriptor claims a length of zero or one — shorter than its own
    /// header. The walk that trusted it would never advance.
    ZeroLength,
    /// A descriptor is well-formed as a descriptor but too short for what its
    /// type must contain.
    ShortDescriptor,
    /// The first descriptor is not the type asked for.
    WrongType,
    /// A configuration's total length disagrees with the bytes handed in.
    TotalLength,
    /// More interfaces or endpoints than this parser will hold. Refused rather
    /// than clipped: a driver given a configuration with the tail quietly
    /// removed would drive a device that is not the one attached.
    TooMany,
    /// A declared count disagrees with what the byte string actually carries.
    CountMismatch,
    /// An endpoint descriptor before any interface descriptor. It belongs to
    /// nothing, and guessing which interface owns it is how a driver ends up
    /// talking to the wrong one.
    StrayEndpoint,
}

/// Standard descriptor types.
pub mod descriptor {
    pub const DEVICE: u8 = 1;
    pub const CONFIGURATION: u8 = 2;
    pub const STRING: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const ENDPOINT: u8 = 5;
    /// A hub's own descriptor, which is class-specific rather than standard.
    pub const HUB: u8 = 0x29;
}

/// Standard class codes, as they appear in a device or interface descriptor.
pub mod class {
    /// The device declines to say, and each interface speaks for itself. The
    /// common case, and the reason authorization is per interface.
    pub const PER_INTERFACE: u8 = 0x00;
    pub const AUDIO: u8 = 0x01;
    pub const HID: u8 = 0x03;
    pub const MASS_STORAGE: u8 = 0x08;
    pub const HUB: u8 = 0x09;
    pub const VIDEO: u8 = 0x0e;
    pub const WIRELESS: u8 = 0xe0;
    pub const VENDOR: u8 = 0xff;
}

/// Mass-storage subclass and protocol values this tree understands.
pub mod storage {
    /// SCSI transparent command set.
    pub const SUBCLASS_SCSI: u8 = 0x06;
    /// Bulk-only transport.
    pub const PROTOCOL_BULK_ONLY: u8 = 0x50;
}

/// HID subclass and protocol values.
pub mod hid {
    /// Boot interface — the small fixed report a firmware can read.
    pub const SUBCLASS_BOOT: u8 = 0x01;
    pub const PROTOCOL_KEYBOARD: u8 = 0x01;
    pub const PROTOCOL_MOUSE: u8 = 0x02;
}

/// What an endpoint carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferType {
    Control,
    /// Parsed and named rather than folded into bulk, so a host that does not
    /// schedule periodic bandwidth declines it explicitly instead of driving it
    /// as something it is not. Isochronous transfers are a recorded deviation.
    Isochronous,
    Bulk,
    Interrupt,
}

impl TransferType {
    fn from_attributes(attributes: u8) -> TransferType {
        match attributes & 0x3 {
            0 => TransferType::Control,
            1 => TransferType::Isochronous,
            2 => TransferType::Bulk,
            _ => TransferType::Interrupt,
        }
    }
}

/// One endpoint of one interface.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Endpoint {
    /// Endpoint number in bits 3:0, direction in bit 7.
    pub address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    /// Polling interval, in the units the speed defines.
    pub interval: u8,
}

impl Endpoint {
    const EMPTY: Endpoint = Endpoint {
        address: 0,
        attributes: 0,
        max_packet_size: 0,
        interval: 0,
    };

    pub fn number(&self) -> u8 {
        self.address & 0x0f
    }

    /// Whether this endpoint carries data from the device to the host.
    pub fn device_to_host(&self) -> bool {
        self.address & 0x80 != 0
    }

    pub fn transfer_type(&self) -> TransferType {
        TransferType::from_attributes(self.attributes)
    }

    /// The endpoint's index in a device context, which is what a controller
    /// addresses it by.
    ///
    /// It is not the endpoint number: the control endpoint is index one, and
    /// every other endpoint takes two indices because the two directions are
    /// separate endpoints wearing one number.
    pub fn context_index(&self) -> u8 {
        if self.number() == 0 {
            1
        } else {
            self.number() * 2 + u8::from(self.device_to_host())
        }
    }
}

/// One interface descriptor — one alternate setting of one interface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Interface {
    pub number: u8,
    pub alternate: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// What the descriptor said it has, kept so it can be checked against what
    /// actually followed.
    declared_endpoints: u8,
    endpoint_count: usize,
    endpoints: [Endpoint; MAX_ENDPOINTS],
}

impl Interface {
    const EMPTY: Interface = Interface {
        number: 0,
        alternate: 0,
        class: 0,
        subclass: 0,
        protocol: 0,
        declared_endpoints: 0,
        endpoint_count: 0,
        endpoints: [Endpoint::EMPTY; MAX_ENDPOINTS],
    };

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints[..self.endpoint_count]
    }

    /// The first endpoint of a given type and direction, which is how a class
    /// driver finds the pipe it needs.
    pub fn find_endpoint(&self, kind: TransferType, device_to_host: bool) -> Option<Endpoint> {
        self.endpoints()
            .iter()
            .find(|e| e.transfer_type() == kind && e.device_to_host() == device_to_host)
            .copied()
    }
}

/// A device descriptor: eighteen bytes, and the first thing read off a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeviceDescriptor {
    pub usb_version: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// The control endpoint's maximum packet size, as the byte the device sent.
    pub max_packet_size0: u8,
    pub vendor: u16,
    pub product: u16,
    pub device_version: u16,
    pub configurations: u8,
}

impl DeviceDescriptor {
    /// The bytes a full device descriptor occupies.
    pub const WIRE_SIZE: usize = 18;

    pub fn parse(bytes: &[u8]) -> Result<DeviceDescriptor, Error> {
        let mut walk = Walk::new(bytes);
        let raw = walk.next_descriptor()?.ok_or(Error::Truncated)?;
        if raw.kind != descriptor::DEVICE {
            return Err(Error::WrongType);
        }
        // Sixteen bytes past the two-byte header.
        if raw.body.len() < Self::WIRE_SIZE - 2 {
            return Err(Error::ShortDescriptor);
        }
        let b = raw.body;
        Ok(DeviceDescriptor {
            usb_version: u16::from_le_bytes([b[0], b[1]]),
            class: b[2],
            subclass: b[3],
            protocol: b[4],
            max_packet_size0: b[5],
            vendor: u16::from_le_bytes([b[6], b[7]]),
            product: u16::from_le_bytes([b[8], b[9]]),
            device_version: u16::from_le_bytes([b[10], b[11]]),
            configurations: b[15],
        })
    }
}

/// A hub's own descriptor. Read for one number — how many ports there are to
/// walk — and one delay, which is how long power takes to become usable.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HubDescriptor {
    pub ports: u8,
    pub characteristics: u16,
    /// Time from powering a port to the power being good, in 2 ms units.
    pub power_on_delay: u8,
}

impl HubDescriptor {
    pub fn parse(bytes: &[u8]) -> Result<HubDescriptor, Error> {
        let mut walk = Walk::new(bytes);
        let raw = walk.next_descriptor()?.ok_or(Error::Truncated)?;
        if raw.kind != descriptor::HUB {
            return Err(Error::WrongType);
        }
        if raw.body.len() < 4 {
            return Err(Error::ShortDescriptor);
        }
        Ok(HubDescriptor {
            ports: raw.body[0],
            characteristics: u16::from_le_bytes([raw.body[1], raw.body[2]]),
            power_on_delay: raw.body[3],
        })
    }
}

/// A configuration, and everything under it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Configuration {
    pub value: u8,
    pub attributes: u8,
    /// Maximum current draw, in 2 mA units.
    pub max_power: u8,
    interface_count: usize,
    interfaces: [Interface; MAX_INTERFACES],
}

impl Configuration {
    /// Parses a configuration's byte string: the configuration descriptor, and
    /// the interface, endpoint and class-specific descriptors that follow it.
    ///
    /// A host reads this in two transfers — nine bytes to learn the total
    /// length, then the whole thing — so `bytes` may be longer than the
    /// configuration. It may not be **shorter**: a total length past what was
    /// read means the second transfer did not complete, and parsing what
    /// arrived would describe a device by half its own description.
    pub fn parse(bytes: &[u8]) -> Result<Configuration, Error> {
        let mut header = Walk::new(bytes);
        let raw = header.next_descriptor()?.ok_or(Error::Truncated)?;
        if raw.kind != descriptor::CONFIGURATION {
            return Err(Error::WrongType);
        }
        if raw.body.len() < 7 {
            return Err(Error::ShortDescriptor);
        }
        let total = usize::from(u16::from_le_bytes([raw.body[0], raw.body[1]]));
        let declared_interfaces = raw.body[2];
        let mut config = Configuration {
            value: raw.body[3],
            attributes: raw.body[5],
            max_power: raw.body[6],
            interface_count: 0,
            interfaces: [Interface::EMPTY; MAX_INTERFACES],
        };
        if total < 9 || total > bytes.len() {
            return Err(Error::TotalLength);
        }

        // Walk only what the device said the configuration is. Anything after
        // it is the host's buffer, not the device's word.
        let mut walk = Walk::new(&bytes[..total]);
        while let Some(item) = walk.next_descriptor()? {
            match item.kind {
                descriptor::CONFIGURATION => {}
                descriptor::INTERFACE => {
                    if item.body.len() < 7 {
                        return Err(Error::ShortDescriptor);
                    }
                    if config.interface_count == MAX_INTERFACES {
                        return Err(Error::TooMany);
                    }
                    config.interfaces[config.interface_count] = Interface {
                        number: item.body[0],
                        alternate: item.body[1],
                        declared_endpoints: item.body[2],
                        class: item.body[3],
                        subclass: item.body[4],
                        protocol: item.body[5],
                        endpoint_count: 0,
                        endpoints: [Endpoint::EMPTY; MAX_ENDPOINTS],
                    };
                    config.interface_count += 1;
                }
                descriptor::ENDPOINT => {
                    if item.body.len() < 5 {
                        return Err(Error::ShortDescriptor);
                    }
                    let interface = config
                        .interfaces
                        .get_mut(config.interface_count.wrapping_sub(1))
                        .ok_or(Error::StrayEndpoint)?;
                    if interface.endpoint_count == MAX_ENDPOINTS {
                        return Err(Error::TooMany);
                    }
                    interface.endpoints[interface.endpoint_count] = Endpoint {
                        address: item.body[0],
                        attributes: item.body[1],
                        max_packet_size: u16::from_le_bytes([item.body[2], item.body[3]]),
                        interval: item.body[4],
                    };
                    interface.endpoint_count += 1;
                }
                // Class-specific descriptors sit between an interface and its
                // endpoints: a HID descriptor, an audio control header, a
                // vendor's own. Skipping them is required rather than lenient —
                // refusing what is not understood would refuse every HID
                // device, and every device this system most wants to drive.
                _ => {}
            }
        }

        // What the device claimed, against what it sent. A configuration
        // claiming an interface or an endpoint it did not supply is asking a
        // driver to open a pipe that is not there.
        let settings = config.interfaces[..config.interface_count]
            .iter()
            .filter(|i| i.alternate == 0)
            .count();
        if settings != usize::from(declared_interfaces) {
            return Err(Error::CountMismatch);
        }
        for interface in &config.interfaces[..config.interface_count] {
            if usize::from(interface.declared_endpoints) != interface.endpoint_count {
                return Err(Error::CountMismatch);
            }
        }
        Ok(config)
    }

    /// Every interface descriptor, alternate settings included.
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces[..self.interface_count]
    }

    /// The default setting of interface `number` — alternate zero, which is
    /// what a device presents until told otherwise.
    pub fn default_setting(&self, number: u8) -> Option<&Interface> {
        self.interfaces()
            .iter()
            .find(|i| i.number == number && i.alternate == 0)
    }
}

/// One entry of an authorization policy: a class, and optionally a narrower
/// subclass and protocol within it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Allowed {
    pub class: u8,
    /// `None` admits every subclass of the class.
    pub subclass: Option<u8>,
    /// `None` admits every protocol.
    pub protocol: Option<u8>,
}

impl Allowed {
    fn admits(&self, interface: &Interface) -> bool {
        self.class == interface.class
            && self.subclass.is_none_or(|s| s == interface.subclass)
            && self.protocol.is_none_or(|p| p == interface.protocol)
    }
}

/// What a policy decided, and about what.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Authorization {
    /// Every interface the device presents is on the list.
    Allowed,
    /// One is not. Carries what the device claimed for it, so the refusal can
    /// be **recorded** — a device turned away silently is a support call, and
    /// a device turned away without saying what it claimed to be is a security
    /// event nobody can read.
    Refused {
        interface: u8,
        alternate: u8,
        class: u8,
        subclass: u8,
        protocol: u8,
    },
}

/// The classes this system will give a driver to.
///
/// Bounded and copied by value, so a host can hold one per policy domain
/// without an allocator.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Policy {
    entries: [Option<Allowed>; MAX_POLICY],
    len: usize,
}

impl Policy {
    /// A policy that admits nothing. The default on purpose: a policy that
    /// started open would admit whatever arrived before anyone configured it,
    /// which is exactly the window a hotplug attack wants.
    pub const fn new() -> Policy {
        Policy {
            entries: [None; MAX_POLICY],
            len: 0,
        }
    }

    /// Admits one class entirely.
    pub fn allow_class(&mut self, class: u8) -> Result<(), Error> {
        self.allow(Allowed {
            class,
            subclass: None,
            protocol: None,
        })
    }

    /// Admits one entry. A policy that is full refuses rather than drops the
    /// entry, because a policy silently missing a line is one that turns away
    /// a device the administrator meant to permit.
    pub fn allow(&mut self, entry: Allowed) -> Result<(), Error> {
        if self.len == MAX_POLICY {
            return Err(Error::TooMany);
        }
        self.entries[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Judges one interface.
    pub fn authorize(&self, interface: &Interface) -> Authorization {
        if self.entries[..self.len]
            .iter()
            .flatten()
            .any(|e| e.admits(interface))
        {
            return Authorization::Allowed;
        }
        Authorization::Refused {
            interface: interface.number,
            alternate: interface.alternate,
            class: interface.class,
            subclass: interface.subclass,
            protocol: interface.protocol,
        }
    }

    /// Judges a whole configuration, and admits it only if **every** interface
    /// is admitted.
    ///
    /// Not "any": a device presenting a keyboard and something else alongside
    /// it would otherwise be admitted on the strength of the keyboard, and the
    /// something else is the entire point of the attack. A composite device
    /// with one refused interface is refused, and the refusal names which.
    pub fn authorize_device(&self, config: &Configuration) -> Authorization {
        for interface in config.interfaces() {
            let decision = self.authorize(interface);
            if decision != Authorization::Allowed {
                return decision;
            }
        }
        Authorization::Allowed
    }
}

/// One descriptor as it sits in a byte string: its type, and its body with the
/// two-byte header removed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Raw<'a> {
    pub kind: u8,
    pub body: &'a [u8],
}

/// A walk over a descriptor chain.
///
/// Its own type because the bounds check is the whole job, and a `while` loop
/// over an index written afresh in each driver is a bounds check written afresh
/// in each driver.
pub struct Walk<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Walk<'a> {
    pub fn new(bytes: &'a [u8]) -> Walk<'a> {
        Walk { bytes, at: 0 }
    }

    /// The next descriptor, or `None` at the end of the chain.
    ///
    /// **A length below two is refused, not skipped.** It is the one input that
    /// turns a parser into a hang rather than a wrong answer: a walk that
    /// advanced by the length it read would sit on the same byte forever, and
    /// enumeration of the device would never return.
    pub fn next_descriptor(&mut self) -> Result<Option<Raw<'a>>, Error> {
        if self.at >= self.bytes.len() {
            return Ok(None);
        }
        let remaining = self.bytes.len() - self.at;
        if remaining < 2 {
            return Err(Error::Truncated);
        }
        let length = usize::from(self.bytes[self.at]);
        if length < 2 {
            return Err(Error::ZeroLength);
        }
        if length > remaining {
            return Err(Error::Truncated);
        }
        let kind = self.bytes[self.at + 1];
        let body = &self.bytes[self.at + 2..self.at + length];
        self.at += length;
        Ok(Some(Raw { kind, body }))
    }
}

/// Standard device requests, as the eight bytes of a control transfer's setup
/// stage.
///
/// Built here rather than in each driver because the request type byte encodes
/// direction, and a request whose direction disagrees with its data stage
/// stalls the endpoint — a mistake that is invisible in the constant and
/// obvious in one place.
pub mod request {
    /// Request type: device to host, standard, to the device.
    pub const IN_STANDARD_DEVICE: u8 = 0x80;
    /// Host to device, standard, to the device.
    pub const OUT_STANDARD_DEVICE: u8 = 0x00;
    /// Device to host, class, to the device — a hub's own requests.
    pub const IN_CLASS_DEVICE: u8 = 0xa0;
    /// Host to device, class, to another device — a hub's port requests.
    pub const OUT_CLASS_OTHER: u8 = 0x23;
    /// Device to host, class, from another device — a hub's port status.
    pub const IN_CLASS_OTHER: u8 = 0xa3;

    const GET_DESCRIPTOR: u8 = 6;
    const SET_ADDRESS: u8 = 5;
    const SET_CONFIGURATION: u8 = 9;
    const GET_STATUS: u8 = 0;
    const SET_FEATURE: u8 = 3;
    const CLEAR_FEATURE: u8 = 1;

    fn setup(kind: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
        let value = value.to_le_bytes();
        let index = index.to_le_bytes();
        let length = length.to_le_bytes();
        [
            kind, request, value[0], value[1], index[0], index[1], length[0], length[1],
        ]
    }

    /// Reads a standard descriptor: the type in the high half of the value, the
    /// index in the low.
    pub fn get_descriptor(descriptor_type: u8, index: u8, length: u16) -> [u8; 8] {
        setup(
            IN_STANDARD_DEVICE,
            GET_DESCRIPTOR,
            (u16::from(descriptor_type) << 8) | u16::from(index),
            0,
            length,
        )
    }

    /// Reads a hub's own descriptor, which is a class request rather than a
    /// standard one even though it looks like a descriptor read.
    pub fn get_hub_descriptor(length: u16) -> [u8; 8] {
        setup(
            IN_CLASS_DEVICE,
            GET_DESCRIPTOR,
            u16::from(super::descriptor::HUB) << 8,
            0,
            length,
        )
    }

    pub fn set_address(address: u8) -> [u8; 8] {
        setup(OUT_STANDARD_DEVICE, SET_ADDRESS, u16::from(address), 0, 0)
    }

    pub fn set_configuration(value: u8) -> [u8; 8] {
        setup(
            OUT_STANDARD_DEVICE,
            SET_CONFIGURATION,
            u16::from(value),
            0,
            0,
        )
    }

    /// A hub port's status and change bits — four bytes, the second half of
    /// which is write-one-to-clear through [`clear_port_feature`].
    pub fn get_port_status(port: u8) -> [u8; 8] {
        setup(IN_CLASS_OTHER, GET_STATUS, 0, u16::from(port), 4)
    }

    pub fn set_port_feature(port: u8, feature: u16) -> [u8; 8] {
        setup(OUT_CLASS_OTHER, SET_FEATURE, feature, u16::from(port), 0)
    }

    pub fn clear_port_feature(port: u8, feature: u16) -> [u8; 8] {
        setup(OUT_CLASS_OTHER, CLEAR_FEATURE, feature, u16::from(port), 0)
    }
}

/// Hub port features and the bits `GET_STATUS` returns for them.
pub mod hub_port {
    /// Features, named by the selector a `SET_FEATURE` carries.
    pub const FEATURE_POWER: u16 = 8;
    pub const FEATURE_RESET: u16 = 4;
    pub const FEATURE_C_CONNECTION: u16 = 16;
    pub const FEATURE_C_RESET: u16 = 20;

    /// Status bits, in the first half-word `GET_STATUS` returns.
    pub const CONNECTED: u16 = 1;
    pub const ENABLED: u16 = 1 << 1;
    pub const RESET: u16 = 1 << 4;
    pub const POWER: u16 = 1 << 8;
    pub const LOW_SPEED: u16 = 1 << 9;
    pub const HIGH_SPEED: u16 = 1 << 10;

    /// Change bits, in the second half-word. Cleared one at a time by feature
    /// selector rather than by writing a mask — a hub has no register a host
    /// can write, so "acknowledge exactly what was handled" is the only form
    /// available, and it is the same discipline a root port's change bits need.
    pub const C_CONNECTION: u16 = 1;
    pub const C_RESET: u16 = 1 << 4;
}
