<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Embedded Buses, Power Supply, Thermal, Watchdog, And Timekeeping Drivers

## Purpose

The driver classes in `drivers/02-storage-networking-usb-pcie.md` and
`drivers/03-graphics-display-media-sensors-ai.md` cover desktop and mobile
device classes but omit the low-level buses and platform devices that the
embedded, wearable, automotive, and appliance profiles depend on. This document
defines those driver classes. They follow the same framework as all other
drivers: user-space driver hosts by default, stable class contracts, resource
leases, DMA and IOMMU rules, power votes, and certification.

## Low-Level Bus And Controller Classes

Clocks, resets, and regulators appear as nodes in the resource graph
(`hardware/02-hardware-description-and-discovery.md`); the classes below are the
driver contracts that own those nodes, plus the serial and general-purpose
control buses that SoC peripherals hang off.

### Clock Controller

Exposes clock trees to the framework:

- Enumerate clocks, parents, and mux options.
- Get and set rate within declared ranges.
- Enable and disable with reference counting.
- Report accuracy and whether a clock is critical for correctness.

Consumers request rates through bounded APIs; only the clock controller driver
touches controller registers, as stated in `hardware/03`.

### Reset Controller

- Assert, deassert, and pulse reset lines.
- Declare shared versus exclusive reset domains.
- Participate in the device-manager-owned reset sequencing plan.

### Regulator / PMIC

- Enumerate supplies with voltage and current ranges.
- Set voltage within declared limits, enable and disable with reference
  counting, and report constraints that must not be violated.
- Expose regulator dependencies to the power manager's vote arbitration.

### GPIO And Pin Control

- GPIO: direction, level, drive strength, bias, and interrupt-capable lines
  delivered as interrupt objects.
- Pin control: pin muxing and electrical configuration, declared in data and
  scoped to hardware revisions per the quirk-management rules.

### PWM

- Configure period and duty cycle within declared ranges.
- Used by backlight, haptics, fan, and simple actuator drivers rather than those
  drivers poking timers directly.

### I2C And SPI Controllers

- Transfer primitives with speed, addressing, and chip-select parameters.
- Bus arbitration and multi-master handling where the hardware supports it.
- Child devices bind through the resource graph, not by scanning.

### I2S / Audio Serial

- Frame format, sample rate, and clock-domain description feeding the audio
  graph service in `drivers/03`.

### UART / Serial

- Byte-stream transport with baud, framing, and flow-control configuration.
- Backs early console, debug serial, and simple peripheral links; exposes a
  byte-stream endpoint per `kernel/04-synchronization-and-ipc-guarantees.md`.

### SDIO

- Command and data transfer for SD-interface peripherals, shared by storage and
  some radio modules.

### CAN And Automotive Buses

- Frame transmit and receive, filtering, error state, and bus-off recovery.
- Deadline metadata for the real-time scheduling classes used by automotive and
  industrial profiles.

## Power Supply Class

The power framework in `hardware/03-component-interaction-model.md` arbitrates
votes but has no class for the devices that report energy state. This class
fills that gap.

### Battery And Fuel Gauge

- State of charge, voltage, current, temperature, capacity, and cycle count.
- Health estimate and wear metrics for the health service.
- Charge and discharge rate and time-to-full or time-to-empty estimates.

### Charger

- Input source detection and negotiated input limits.
- Charge state, charge current control within safe limits, and thermal
  throttling of charging.
- Coordination with USB and USB4 power negotiation in `drivers/02`.

The driver exposes controls only; charging policy — battery-health
preservation, adaptive charging, charge limits — is owned by the power and
thermal manager per product profile
(`../power/01-power-management.md`).

### PMIC Aggregation

- Where a PMIC integrates regulators, charger, and fuel gauge, the driver
  exposes each function through the relevant class contract so consumers see
  stable interfaces regardless of integration.

Battery, charger, and thermal data are the inputs behind the battery-first and
always-on-low-power priorities in the mobile and wearable profiles.

## Thermal And Cooling Class

Thermal zones drive scheduling and power decisions but need driver contracts for
the sensors and cooling devices.

### Thermal Sensor

- Report temperature for named thermal zones.
- Declare trip points and support threshold interrupts where available.

### Cooling Device

- Fans, throttle states, and other actuators expressed as bounded cooling
  levels.
- The power and thermal manager maps zone readings and trip points to cooling
  levels and to the thermal-aware scheduling inputs in `kernel/02`.

## Watchdog Class And Kernel Watchdog

The embedded profile in `platforms/01` promises hardware watchdog integration;
this defines it.

### Hardware Watchdog Driver

- Configure timeout, start, stop where permitted, and pet the watchdog.
- Report last-reset cause including watchdog-induced resets.
- Declare whether the watchdog is non-stoppable once started.

### Kernel Watchdog Primitive

- A software watchdog supervises liveness of critical services and driver hosts.
- Missed deadlines escalate through the failure model: capture crash dump and
  trace tail, restart the component, and on repeated failure trigger rollback or
  hardware-watchdog-backed reboot.
- Watchdog petting is tied to actual progress signals, not a bare timer, so a
  hung-but-alive component is still caught.

## Real-Time Clock Class

The time service in `kernel/01-kernel-model.md` owns wall-clock policy; this is
the backing device class.

- Read and set the hardware real-time clock.
- Alarm and wake capability delivered as wake-capable interrupt objects.
- Report battery-backed persistence and accuracy.
- The time service consumes this class to seed wall-clock time; the kernel does
  not embed RTC hardware knowledge.

## Input Device Class

`drivers/03` covers USB HID and there is an input service and broker in
`platforms/01`, but embedded and touch-first devices need a first-class input
driver contract independent of USB.

- Touchscreen and touch controller: multitouch contacts, pressure, and
  coordinate space, with calibration from the platform manifest.
- Buttons, rotary encoders, crowns, and switches.
- Report events into the input broker, which owns focus, privacy, accessibility,
  and injection policy. Drivers expose events and capabilities only, not
  application-level routing.

## Secure Element And TPM Class

`hardware/03-component-interaction-model.md` lists TPMs, secure elements,
and biometric coprocessors as secure components mediated by security
services; this is their driver contract:

- Command/response transport to the device (TPM command interface,
  secure-element APDUs, vendor TEE mailboxes) with session framing and
  bounded message sizes.
- Locality and session state where the hardware models them; measured-boot
  PCR access exposed as operations, not raw register pokes.
- The class binds only to the security services (key service, attestation,
  identity); no application or general service may open it, and the driver
  exposes transport, never policy — which keys exist and who may use them
  is the key service's business.

## Short-Range And Emerging Radios

Radios named in the mobile profile and radio policy but lacking a driver class:

- NFC: field detection, tag and card emulation modes, and secure-element routing
  through the security services.
- UWB: ranging and angle-of-arrival measurements with privacy-sensitive
  metadata.
- Thread and low-power mesh: join, routing, and commissioning primitives.

Radio drivers expose device operations. Selection, pairing, identity rotation,
and regulatory policy remain in the radio policy service per `drivers/02`.

## Common Requirements

Every class in this document conforms to the shared driver framework:

- Runs in a user-space driver host by default; in-kernel fast paths only under
  the documented exception rules.
- Uses kernel-mediated DMA and IOMMU leasing where it moves data.
- Participates in the lifecycle state machine, power votes, hotplug, and
  crash-recovery flows in `drivers/01-driver-framework.md`.
- Ships a class contract with required and optional methods, event types, error
  codes, trace events, and conformance tests before it is considered stable.
