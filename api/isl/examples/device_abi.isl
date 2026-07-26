// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The ring-3 driver-host device syscall ABI, defined in ISL: the structured
// arguments for MapDevice and DmaAlloc, retiring those syscalls' register-passed
// v0 ABI (build/README.md, D77/D78 -> D79). The device capability names the
// physical MMIO window; the caller supplies only the desired page-aligned user
// virtual address, so nothing wire-visible carries a physical address inward.

library tessera.kernel.device;

// MapDevice — map the MMIO register window named by `device` (which must carry
// Rights::MAP) into the caller's own address space at page-aligned `vaddr`.
// Returns the register base VA: the page VA plus the window's intra-page
// offset (virtio-mmio windows are 0x200-byte slots, not page-aligned).
@abi
struct MapDeviceArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    reserved: uint32;
    vaddr: uint64;
};

// DmaAlloc — allocate one zero-filled page in the caller's address space at
// page-aligned `vaddr`, authorized by `device` (which must carry Rights::MAP
// and resolve to a real MMIO-backed device capability). Returns the page's
// physical address — the device-visible name of the same memory.
@abi
struct DmaAllocArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    reserved: uint32;
    vaddr: uint64;
};

// IrqComplete — re-enable the interrupt line of the device named by `device`
// (which must carry Rights::MAP and have an INTID wired in the resource
// graph), after the driver has acknowledged the device itself. The second
// half of the mask-on-deliver interrupt protocol (D84): the kernel disables
// the line when it signals the driver's port; the driver acks the device
// through its mapped window, then calls this to re-arm.
@abi
struct IrqCompleteArgs {
    size: uint32;
    version: uint32;
    flags: uint64;
    device: handle<Object, {}>;
    reserved: uint32;
};
