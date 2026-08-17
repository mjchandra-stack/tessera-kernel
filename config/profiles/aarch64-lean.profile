# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# The AArch64 machine without its multimedia and USB stacks.
#
# This is the profile that makes "configurable" a thing that has been done
# rather than a thing the format allows: it is built, it is booted, and
# `//tools/qemu:profile_boot_aarch64_test` asserts what it changed. The
# default machine carries twenty-four ring-3 programs; this one carries
# seventeen, and the seven it drops take their bytes out of the image rather
# than only their names.
#
# What it keeps is what the rest of the tree checks: the device manager and the
# driver host, the block path end to end, PCIe and platform enumeration, GPIO,
# networking, crypto, certification and power. What it drops is the two device
# classes with no client outside their own demo (sound, GPU) and the USB tree.
#
# Note what is *not* said here. `usb_storage`, `usb_hid` and `input_client` are
# off because `usb_host` is, and the declaration says so — turning off the host
# alone is refused with the reason. Writing them out is this file agreeing with
# an invariant, not repeating one.
#
# The sizing change is deliberate and small: this machine's handle tables can be
# half the size because it runs seven fewer programs. It is here so the profile
# exercises both halves of the surface rather than only the interesting one.

MAX_HANDLES = 512

snd_driver = n
snd_client = n
gpu_driver = n
gpu_client = n
usb_host = n
usb_storage = n
usb_hid = n
input_client = n
