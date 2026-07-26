<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Driver Design Documents

Driver details are split by level:

- [Driver Framework](01-driver-framework.md) covers driver hosting, binding,
  lifecycle, security, DMA, power, tracing, and certification.
- [Storage, Networking, USB, And PCIe Drivers](02-storage-networking-usb-pcie.md)
  covers core I/O buses and high-throughput infrastructure.
- [Graphics, Display, Media, Sensors, And AI Drivers](03-graphics-display-media-sensors-ai.md)
  covers interactive, multimedia, sensor, and accelerator devices.
- [Embedded Buses, Power, And Timekeeping Drivers](04-embedded-buses-power-and-timekeeping.md)
  covers low-level buses, power supply, thermal, watchdogs, RTC, input, and
  short-range radios for embedded and wearable profiles.

The default rule is user-space drivers with least privilege. In-kernel driver
code is limited to narrow fast paths that have explicit performance, safety, and
maintenance justification.

