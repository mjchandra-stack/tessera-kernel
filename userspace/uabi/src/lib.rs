// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! What every ring-3 program needs and nothing else: the syscall instruction,
//! the two idioms that cross the kernel boundary, and the address-space layout
//! a program is entitled to assume.
//!
//! It exists because five programs had grown identical copies of all of it.
//! That was tolerable while every one of them ran on a single architecture and
//! invisible while there was only one architecture to run on — but the driver
//! framework's claim is that it is *common*, and a claim like that is not made
//! by prose. Porting the manager and the probe to a second architecture meant
//! either a sixth and seventh copy of the syscall stub or this crate.
//!
//! **Two things here are genuinely per-architecture**, and they are the only
//! two. The syscall instruction and its register convention, obviously. Less
//! obviously, the *addresses* a program may map things at: a port's user half
//! is whatever its paging format makes it, and AArch64's is 2^48 while Sv39's
//! is 2^38 — so a window base that is ordinary on one is out of range on the
//! other. Both are `cfg`-selected in one place rather than restated in every
//! program.
//!
//! Everything else about a user program — the protocols it speaks, the
//! capabilities it holds, what it does with a device — is portable Rust and
//! stays in the program.
//!
//! Normative: docs/api/01-syscall-surface-and-object-model.md,
//! docs/hardware/03-component-interaction-model.md

#![no_std]
#![deny(clippy::unwrap_used, clippy::expect_used)]

/// Encodes a staged failure a program reports through `DebugWrite` before it
/// exits: `0xdead_0000_<stage>_<cause>`.
///
/// A program that reports only "it failed" costs an afternoon; one that says
/// which stage failed and why costs a grep. The stage numbers are each
/// program's own — this is only the encoding they share.
pub const fn fail(stage: u64, cause: u64) -> u64 {
    0xdead_0000_0000_0000 | (stage << 16) | (cause & 0xffff)
}

/// One syscall with two arguments. The result lands where the first argument
/// was, which is the convention on every port this kernel targets.
#[cfg(target_arch = "aarch64")]
pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: the `svc` traps to the kernel dispatcher, which saves and
    // restores the whole trap frame and writes back only `x0` — declared here
    // as `inout`. The instruction itself touches no memory.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inout("x0") arg0 => ret,
            in("x1") arg1,
            options(nostack),
        );
    }
    ret
}

/// One syscall with two arguments. See the AArch64 form above; the difference
/// is the instruction and which registers carry what.
#[cfg(target_arch = "riscv64")]
pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: the `ecall` traps to the kernel dispatcher, which saves and
    // restores the whole trap frame and writes back only `a0` — declared here
    // as `inout`. The instruction itself touches no memory.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") number,
            inout("a0") arg0 => ret,
            in("a1") arg1,
            options(nostack),
        );
    }
    ret
}

/// One syscall with two arguments, on x86-64.
///
/// The number is in `rax` and the result comes back in the *same* register,
/// which is the one place this port breaks the "the result lands where the
/// first argument was" convention the other two share — `SYSCALL` has no say
/// in the matter.
///
/// **`rcx` and `r11` are clobbered by the instruction itself**, which is the
/// real difference in kind rather than in spelling: the CPU puts the return
/// RIP in one and the saved RFLAGS in the other before the kernel sees
/// anything. Declaring them as outputs is what stops the compiler keeping a
/// live value in either across the call. The registers below are what
/// `karch-x86_64`'s entry stub reads.
#[cfg(target_arch = "x86_64")]
pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    // SAFETY: the `syscall` traps to the kernel dispatcher, which saves and
    // restores the whole trap frame and writes back only `rax` — declared here
    // as an output. The instruction itself touches no memory; `rcx` and `r11`
    // are declared clobbered because the CPU overwrites them unconditionally.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") number => ret,
            in("rdi") arg0,
            in("rsi") arg1,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret
}

/// One syscall with a single argument.
///
/// Gated with its two-argument siblings: on a host build — which is what
/// `bazel build //...` does to every crate — there is no kernel to call and no
/// instruction that would mean anything, so the syscall surface simply is not
/// there. The rest of the crate still compiles, which keeps it inside the
/// same lint and license gates as everything else.
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
))]
pub fn syscall1(number: u64, arg0: u64) -> i64 {
    syscall2(number, arg0, 0)
}

/// Reads bytes the **kernel** wrote into a buffer during a preceding syscall,
/// through volatile loads.
///
/// The volatility is the point: the compiler sees a local this program never
/// wrote to, and is entitled to conclude it still holds what it held before
/// the syscall. Nothing in the language says an `ecall` or an `svc` modified
/// it. This is where that gap is closed, and it is why it is one function
/// rather than an ordinary read at each site.
pub fn read_kernel_filled<const N: usize>(buf: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: `&buf[i]` is a bounds-checked, initialised byte; volatile
        // only forbids the compiler assuming a cached value.
        unsafe { *slot = core::ptr::read_volatile(&buf[i]) };
    }
    out
}

/// Lends a caller the bytes of a page the kernel mapped for DMA.
///
/// The one place a driver's DMA page becomes a slice. Every driver used to
/// write this line for itself, which is why the SDK could not offer a model of
/// it: an address is only memory on the machine that mapped it.
pub fn with_dma_page<R>(va: u64, len: usize, f: impl FnOnce(&mut [u8]) -> R) -> R {
    // SAFETY: `DmaAlloc` mapped exactly `len` readable and writable bytes at
    // `va` for this process, and the mapping outlives the call. Nothing else
    // forms a reference to the page while `f` runs: this is the only function
    // that makes one, and the scope is what keeps two from existing at once.
    let page = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };
    f(page)
}

/// Re-reads, in place, a buffer the kernel filled.
///
/// The fixed-size sibling of [`read_kernel_filled`], for the buffers whose
/// length is only known at run time: the message a channel receive delivered,
/// the reply a call brought back. The hazard is identical — the compiler did
/// not see those bytes written and a plain load is entitled to hand back
/// whatever this program last stored there, which for a reply buffer is the
/// request that went out.
///
/// **Not proven load-bearing.** Removing it leaves both boot checks passing,
/// because `syscall2`'s inline asm clobbers memory and the compiler reloads on
/// its own. It stays because that is a property of one asm block's constraints
/// rather than a promise, and it is what the rest of this tree already does.
///
/// Chunked rather than sized, so one function serves a 40-byte record and a
/// message buffer of any length.
pub fn refresh_kernel_filled(buf: &mut [u8]) {
    const CHUNK: usize = 64;
    let mut at = 0;
    while at < buf.len() {
        let end = (at + CHUNK).min(buf.len());
        let mut staged = [0u8; CHUNK];
        for (index, slot) in staged[..end - at].iter_mut().enumerate() {
            // SAFETY: `at + index` is below `buf.len()`, so this is a
            // bounds-checked, initialised byte of the caller's own buffer;
            // volatile only forbids the compiler assuming a cached value.
            unsafe { *slot = core::ptr::read_volatile(&buf[at + index]) };
        }
        buf[at..end].copy_from_slice(&staged[..end - at]);
        at = end;
    }
}

/// Where a program may map things in its own address space.
///
/// A program chooses its own layout — that is what an address space is for —
/// but it cannot choose an address the architecture does not have. These are
/// the values that satisfy every port's user half while staying clear of where
/// the loader puts a program's image and stack.
pub mod layout {
    /// Base of the window a device manager maps each device at while it probes
    /// for the device's class, and the stride between successive ones.
    #[cfg(target_arch = "aarch64")]
    pub const PROBE_WINDOW_BASE: u64 = 0x0000_1000_0080_0000;
    /// Sv39's user half ends at 2^38, so AArch64's base is not merely
    /// unfashionable here — it is unmappable, and `map_device` says so.
    #[cfg(target_arch = "riscv64")]
    pub const PROBE_WINDOW_BASE: u64 = 0x0000_0000_3000_0000;
    /// x86-64's four-level paging has a 47-bit user half, so AArch64's value
    /// is mappable here. Written out rather than shared with it: the next port
    /// that cannot use it should change one line, not discover that two ports
    /// were quietly the same.
    #[cfg(target_arch = "x86_64")]
    pub const PROBE_WINDOW_BASE: u64 = 0x0000_1000_0080_0000;

    pub const PROBE_WINDOW_STRIDE: u64 = 0x1_0000;

    /// Where a single-device driver maps the transport it was granted.
    #[cfg(target_arch = "aarch64")]
    pub const DEVICE_MMIO_VA: u64 = 0x0000_1000_0090_0000;
    #[cfg(target_arch = "riscv64")]
    pub const DEVICE_MMIO_VA: u64 = 0x0000_0000_3100_0000;
    #[cfg(target_arch = "x86_64")]
    pub const DEVICE_MMIO_VA: u64 = 0x0000_1000_0090_0000;

    /// Where a driver places the DMA buffer it asks its device for. Clear of
    /// [`DEVICE_MMIO_VA`], because the two are mapped at once and a driver that
    /// overlapped them would fault on whichever it touched second.
    #[cfg(target_arch = "aarch64")]
    pub const DEVICE_DMA_VA: u64 = 0x0000_1000_00a0_0000;
    #[cfg(target_arch = "riscv64")]
    pub const DEVICE_DMA_VA: u64 = 0x0000_0000_3200_0000;
    #[cfg(target_arch = "x86_64")]
    pub const DEVICE_DMA_VA: u64 = 0x0000_1000_00a0_0000;

    /// Where a **child driver** finds the rings of the one queue it was given.
    ///
    /// A queue's descriptor table and available ring are memory the *device*
    /// reads by DMA, so they are placed by whoever brought the controller up
    /// and mapped to the child rather than allocated by it: the child never
    /// learns their physical address and does not need to, because a descriptor
    /// names buffers and not rings.
    #[cfg(target_arch = "aarch64")]
    pub const QUEUE_RING_VA: u64 = 0x0000_1000_00b0_0000;
    #[cfg(target_arch = "riscv64")]
    pub const QUEUE_RING_VA: u64 = 0x0000_0000_3300_0000;
    #[cfg(target_arch = "x86_64")]
    pub const QUEUE_RING_VA: u64 = 0x0000_1000_00b0_0000;

    /// Offset of the available ring within that page.
    ///
    /// **Agreed with the controller, exactly as [`DEVICE_MMIO_VA`] is.** A
    /// split virtqueue's available ring follows its descriptor table, so this
    /// is `16 * queue_size` — a layout fact both sides have to hold the same
    /// value for, and one neither can discover from the other.
    pub const QUEUE_AVAIL_OFFSET: u64 = 128;

    /// Descriptors in that queue's ring — agreed with the controller for the
    /// same reason [`QUEUE_AVAIL_OFFSET`] is, and needed for the same
    /// arithmetic: the available ring is a circular buffer, so publishing at
    /// the right slot means knowing how many there are.
    pub const QUEUE_RING_SIZE: u16 = 8;
}
