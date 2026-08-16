# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
#
# A machine sized for one driver and its client, not for the whole matrix.
#
# This exists so that "the sizing is configurable" is a thing that has been
# done rather than a thing the format allows. Every value is at or above the
# declaration's minimum, and the boot checks are NOT expected to pass under it:
# the AArch64 machine runs 24 ring-3 programs and this profile does not have
# room for them. What it demonstrates is that the surface is real and that a
# value outside its range is refused.

MAX_PROCESSES = 4
MAX_THREADS = 8
MAX_HANDLES = 128
MAX_OBJECTS = 64
MAX_CHANNELS = 8
MAX_DEVICES = 2
EVENT_RING_CAPACITY = 32
