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

/// The published ABI this program was compiled against.
///
/// A program built here and a consumer built against the released artifact are
/// only interchangeable if they agree about the surface, and the only way to
/// say so is to carry the number. `//tools/checks:abi_test` holds this equal to
/// `abi-version` in `api/abi/surface.lock`, so a tree cannot publish one
/// surface and compile against another (`build/README.md`, D296).
///
/// **2 adds `StartupArg`, `StartupArgs` and `ExitStatus`** (D302) — an argument
/// vector on the startup message, and a vocabulary for what a program exits
/// with. The change is **additive**: no existing declaration moved, `size` or
/// `version` changed, and `StartupHandles` is byte-identical, so a program
/// compiled against 1 is correct against 2. The number still moves, because
/// `docs/api/02` versions the surface and not the breakage — a consumer that
/// cannot find `StartupArgs` needs to know why, and "your artifact is older"
/// is a better answer than a missing symbol.
///
/// **3 adds `diagnostic.isl` and one field to `StartupArgs`** (D303): a
/// contract a program's output is addressed to, and the handle saying where its
/// own goes. Additive again — the new field is appended, `StartupHandles` is
/// still byte-identical, and `StartupArg` did not move.
pub const ABI_VERSION: u32 = 3;

/// Encodes a staged failure a program reports through `DebugWrite` before it
/// exits: `0xdead_0000_<stage>_<cause>`.
///
/// A program that reports only "it failed" costs an afternoon; one that says
/// which stage failed and why costs a grep. The stage numbers are each
/// program's own — this is only the encoding they share.
pub const fn fail(stage: u64, cause: u64) -> u64 {
    0xdead_0000_0000_0000 | (stage << 16) | (cause & 0xffff)
}

/// The result word a caller-side refusal answers with: the kernel domain's
/// `InvalidMapping` (`-((1 << 16) | 6)`), spelled here rather than imported
/// because a ring-3 program cannot name anything in `kcore`.
///
/// **Raised before the trap, not by the kernel.** It is the answer to an
/// argument this machine's registers cannot carry — see [`syscall_arg`] — and
/// it is a defined domain and code so that a caller decoding it gets a real
/// error rather than a negative word naming no domain (`docs/api/01`, "The
/// Result Word").
pub const EARGUMENTWIDTH: i64 = -((1 << 16) | 6);

/// One syscall argument, narrowed to what this machine's registers hold, or
/// `None` for a value that does not fit.
///
/// **Refused rather than truncated, and that is the whole of this function.**
/// Every uabi entry point takes `u64` because the ABI `docs/api/01` describes
/// is written in 64-bit words, and on a 32-bit machine an argument register is
/// half that. Silently narrowing would hand the kernel a different value than
/// the caller passed — a pointer with its high half gone is a pointer to
/// somebody else's memory, and nothing downstream could tell. This tree's rule
/// is that code which degrades says so (`docs/lifecycle/04`, "No silent
/// fallback"), and here saying so means not degrading at all.
///
/// On a 64-bit machine every value fits and this is the identity.
#[inline]
pub const fn syscall_arg(value: u64) -> Option<usize> {
    if value > usize::MAX as u64 {
        None
    } else {
        Some(value as usize)
    }
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

/// One syscall with two arguments, on ARM 32.
///
/// **The same `svc` and the same register roles as AArch64, narrowed.** The
/// number goes in `r7` where AArch64 uses `x8` — the register the kernel's
/// user-syscall handler reads — and `r0` is both the first argument and the
/// result, which is the convention every port here shares but x86-64.
///
/// Each argument is narrowed through [`syscall_arg`] for the reason the RISC-V
/// 32 form gives: a `u64` cannot be placed in a 32-bit register, and a compiler
/// asked to try would use a *pair* and shift every argument index the kernel
/// reads. One that does not fit is [`EARGUMENTWIDTH`] rather than a truncation.
///
/// **No `pc` adjustment on the kernel side, unlike RISC-V**: `LR` already
/// points after the `svc`. That is the architecture's difference and it lives
/// in the port, not here — but it is why this sequence has no counterpart to
/// the `sepc += 4` a RISC-V hook performs.
#[cfg(target_arch = "arm")]
pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let (Some(number), Some(arg0), Some(arg1)) =
        (syscall_arg(number), syscall_arg(arg0), syscall_arg(arg1))
    else {
        return EARGUMENTWIDTH;
    };
    let ret: isize;
    // SAFETY: the `svc` traps to the kernel's user-syscall handler, which saves
    // and restores the whole user frame and writes back only `r0` — declared
    // here as `inout`. The instruction itself touches no memory.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") number,
            inout("r0") arg0 => ret,
            in("r1") arg1,
            options(nostack),
        );
    }
    ret as i64
}

/// One syscall with three arguments, on ARM 32. See the two-argument form for
/// why the arguments are narrowed rather than passed.
#[cfg(target_arch = "arm")]
pub fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let (Some(number), Some(arg0), Some(arg1), Some(arg2)) = (
        syscall_arg(number),
        syscall_arg(arg0),
        syscall_arg(arg1),
        syscall_arg(arg2),
    ) else {
        return EARGUMENTWIDTH;
    };
    let ret: isize;
    // SAFETY: as `syscall2`.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") number,
            inout("r0") arg0 => ret,
            in("r1") arg1,
            in("r2") arg2,
            options(nostack),
        );
    }
    ret as i64
}

/// One syscall with two arguments, on RISC-V 32.
///
/// **The same `ecall` and the same registers as RISC-V 64, and a different
/// thing happening to the arguments.** `a0`..`a7` are 32 bits wide here, so a
/// `u64` cannot be placed in one: the compiler would put it in a *pair*, which
/// would shift every argument index the kernel reads by one and hand
/// `ChannelSend` a length where it expects a handle. Each argument is narrowed
/// through [`syscall_arg`] instead, and one that does not fit is
/// [`EARGUMENTWIDTH`] rather than a truncation.
///
/// The result comes back in a 32-bit `a0` and widens to `i64` by sign
/// extension, which is lossless: a failure is `-((domain << 16) | code)` over
/// six domains and small codes, and a success on a 32-bit machine is a handle,
/// a count, or an address — all of which this register held to begin with.
#[cfg(target_arch = "riscv32")]
pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let (Some(number), Some(arg0), Some(arg1)) =
        (syscall_arg(number), syscall_arg(arg0), syscall_arg(arg1))
    else {
        return EARGUMENTWIDTH;
    };
    let ret: isize;
    // SAFETY: as the 64-bit form — the `ecall` traps to the kernel dispatcher,
    // which saves and restores the whole trap frame and writes back only `a0`,
    // declared here as `inout`. The instruction itself touches no memory.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") number,
            inout("a0") arg0 => ret,
            in("a1") arg1,
            options(nostack),
        );
    }
    ret as i64
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
    // SAFETY: the `syscall` traps to the kernel entry stub, which pushes the
    // argument registers, dispatches, and pops them back before `sysretq` —
    // so `rdi` and `rsi` hold what they held here and are correctly declared
    // `in`, and only `rax` is written back. `rcx` and `r11` are declared
    // clobbered because the CPU overwrites them unconditionally. The
    // instruction itself touches no memory.
    //
    // The stub used to *discard* that frame rather than pop it, which made the
    // `in` declarations above a lie the compiler was entitled to act on — it
    // may keep a value live in `rsi` across this block — as well as handing six
    // kernel-valued registers to ring 3. Fixed in `karch-x86_64::syscall`; this
    // comment is the half of the contract that lives on the calling side.
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

/// One syscall with three arguments.
///
/// **The third register had no way to be written until now**, which is a
/// larger fact than it looks: `PortBind` takes a port, a source and a signal,
/// and `DeviceIoWrite` a device, an offset and a byte, so no ring-3 program on
/// any port could make either call — the helper every one of them uses stopped
/// at two (build/README.md, D254). What reached those arms was kernel-side
/// boot glue building the frame itself.
#[cfg(target_arch = "aarch64")]
pub fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    // SAFETY: as `syscall2` — the `svc` traps to the kernel dispatcher, which
    // saves and restores the whole trap frame and writes back only `x0`. The
    // instruction itself touches no memory.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inout("x0") arg0 => ret,
            in("x1") arg1,
            in("x2") arg2,
            options(nostack),
        );
    }
    ret
}

/// One syscall with three arguments. See the AArch64 form above.
#[cfg(target_arch = "riscv64")]
pub fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    // SAFETY: as `syscall2`.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") number,
            inout("a0") arg0 => ret,
            in("a1") arg1,
            in("a2") arg2,
            options(nostack),
        );
    }
    ret
}

/// One syscall with three arguments, on RISC-V 32. See the two-argument form
/// above for why the arguments are narrowed rather than passed.
#[cfg(target_arch = "riscv32")]
pub fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let (Some(number), Some(arg0), Some(arg1), Some(arg2)) = (
        syscall_arg(number),
        syscall_arg(arg0),
        syscall_arg(arg1),
        syscall_arg(arg2),
    ) else {
        return EARGUMENTWIDTH;
    };
    let ret: isize;
    // SAFETY: as `syscall2`.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") number,
            inout("a0") arg0 => ret,
            in("a1") arg1,
            in("a2") arg2,
            options(nostack),
        );
    }
    ret as i64
}

/// One syscall with three arguments, on x86-64. `rcx` and `r11` are clobbered
/// by the instruction itself, for the reason `syscall2` gives.
#[cfg(target_arch = "x86_64")]
pub fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    // SAFETY: as `syscall2`.
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") number => ret,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
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
    target_arch = "arm",
    target_arch = "riscv32",
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

    /// Where a program that allocates puts its heap.
    ///
    /// **A region rather than an address**, which is what makes it different
    /// from everything above: the constants before this name one mapping
    /// apiece, made once, of a size the program knows. A heap is mapped
    /// repeatedly and grows towards a ceiling, so what is reserved here is the
    /// span between [`HEAP_BASE`] and `HEAP_BASE + HEAP_MAX_BYTES` and nothing
    /// else may be placed inside it (`docs/roadmap/04`, Phase 0).
    ///
    /// Clear of the device windows above by a wide margin rather than by one
    /// page: those are placed by a driver that knows how many devices it has,
    /// and a heap that grew into them would fail at whatever size the machine
    /// happened to make it reach.
    #[cfg(target_arch = "aarch64")]
    pub const HEAP_BASE: u64 = 0x0000_1000_0100_0000;
    /// Sv39's user half ends at 2^38, so this sits below it for the same
    /// reason [`PROBE_WINDOW_BASE`] does, and is written out rather than
    /// shared for the same reason.
    #[cfg(target_arch = "riscv64")]
    pub const HEAP_BASE: u64 = 0x0000_0000_4000_0000;
    #[cfg(target_arch = "x86_64")]
    pub const HEAP_BASE: u64 = 0x0000_1000_0100_0000;

    /// How far the heap may grow before a program is told it cannot have more.
    ///
    /// **A ceiling rather than a policy.** What a program *should* be allowed
    /// is a question this system has never been asked and cannot answer from
    /// here — it needs the pager and the reclaim path to have an opinion, which
    /// `docs/roadmap/04` predicts is where Phase 0's real cost is. This is the
    /// bound that keeps a runaway program from walking into an address it was
    /// never given, which is a different and much smaller claim.
    pub const HEAP_MAX_BYTES: u64 = 64 * 1024 * 1024;
}

#[cfg(test)]
mod tests {
    use super::{EARGUMENTWIDTH, syscall_arg};

    /// A value the machine's registers hold comes through unchanged.
    #[test]
    fn a_value_that_fits_is_the_identity() {
        for value in [0u64, 1, 0xffff, 0x7fff_ffff, usize::MAX as u64] {
            assert_eq!(syscall_arg(value), Some(value as usize));
        }
    }

    /// One that does not is refused, not narrowed.
    ///
    /// **Vacuous on a 64-bit host, and deliberately kept.** There is no `u64`
    /// a 64-bit register cannot hold, so this asserts the shape of the rule
    /// rather than exercising it here; what makes it worth having is that the
    /// same source is what a 32-bit build compiles, and a change that replaced
    /// the refusal with a cast would fail on that build with nothing here to
    /// notice. The `usize::MAX` boundary above is the part that discriminates
    /// on both.
    #[test]
    fn a_value_too_wide_for_a_register_is_refused() {
        if let Some(over) = (usize::MAX as u64).checked_add(1) {
            assert_eq!(syscall_arg(over), None);
        }
    }

    /// The refusal decodes to a real domain and code, which `docs/api/01`
    /// requires of every negative result word — a value naming no domain is a
    /// kernel defect to its caller rather than a failure to report.
    #[test]
    fn the_refusal_is_a_decodable_error() {
        let encoded = -EARGUMENTWIDTH;
        assert!(encoded > 0, "the refusal must carry the failure sign");
        let (domain, code) = (encoded >> 16, encoded & 0xffff);
        assert!(
            (1..=6).contains(&domain),
            "domain {domain} is not one of six"
        );
        assert_eq!(code, 6, "kernel-domain InvalidMapping");
    }
}
