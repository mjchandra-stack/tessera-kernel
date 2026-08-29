// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! U-mode: the port's first unprivileged execution.
//!
//! A program runs with `sstatus.SPP` clear, calls back through `ecall`, and its
//! faults are contained. `sscratch` is zero while the kernel runs, which is the
//! invariant the trap path reads to know which stack it is on.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---------------------------------------------------------------------------
// U-mode: the port's first unprivileged execution
// ---------------------------------------------------------------------------

/// Where the user program is mapped. Anywhere in the low half would do — the
/// point of the higher-half split is that the whole of `[0, 2^38)` is now
/// unclaimed — so this is chosen only to be obviously not a kernel address.
pub(crate) const USER_CODE_VA: u64 = 0x1000_0000;
/// The user stack, one page, deliberately not adjacent to the code page: a
/// stack that overflowed into executable memory would be a mapping bug this
/// layout cannot express.
pub(crate) const USER_STACK_VA: u64 = 0x2000_0000;
/// A data page every process maps at the *same* address and fills differently.
/// Identical addresses holding different bytes is what per-process translation
/// means; anything else would be reachable by agreeing on a layout.
pub(crate) const USER_DATA_VA: u64 = 0x3000_0000;
/// A page only one process maps at all.
pub(crate) const USER_PRIVATE_VA: u64 = 0x4000_0000;

/// The value the user program hands the kernel, and the rotation the kernel
/// hands back. Distinctive enough that finding it in a register is not a
/// coincidence, and asymmetric so that a round trip proves direction.
pub(crate) const USER_MAGIC: u64 = 0x5e17_c0de;

/// The two calls the user program can make. Not an ABI — this port is not yet
/// on kcore's syscall substrate — just the smallest pair that proves a syscall
/// carries a value in and a value out, and that the second one is reached.
pub(crate) const SYS_LOG: u64 = 0;
pub(crate) const SYS_EXIT: u64 = 1;

/// Selectors the program's `arg` chooses between.
pub(crate) const CHECK_SYSCALL: usize = 0;
pub(crate) const CHECK_WRITE_TO_CODE: usize = 1;
pub(crate) const CHECK_READ_KERNEL: usize = 2;
pub(crate) const CHECK_READ_DATA: usize = 3;
pub(crate) const CHECK_READ_PRIVATE: usize = 4;

/// Architectural causes the containment checks expect.
pub(crate) const EXCEPTION_LOAD_PAGE_FAULT: u64 = 13;
pub(crate) const EXCEPTION_STORE_PAGE_FAULT: u64 = 15;

/// Size of the user thread's kernel stack.
pub(crate) const USER_KSTACK_BYTES: usize = 8192;

/// The kernel stack the user thread's traps land on. One per user thread; the
/// checks run one at a time and each abandons its predecessor, so one stack
/// serves all three.
#[repr(align(16))]
// The bytes are reached only as an address — the stack pointer a trap from
// U-mode lands on — which is what makes the field dead to the compiler and
// load-bearing to the machine. The x86-64 port's fault stacks carry the same
// annotation for the same reason.
#[allow(dead_code)]
pub(crate) struct UserKernelStack([u8; USER_KSTACK_BYTES]);
pub(crate) static mut USER_KSTACK: UserKernelStack = UserKernelStack([0; USER_KSTACK_BYTES]);

/// Where the kernel resumes when a user thread stops being one — by exiting,
/// or by faulting. The user thread is abandoned mid-trap, on its own kernel
/// stack, which is exactly what containment means here.
pub(crate) static mut KERNEL_RETURN: Context = Context::zeroed();
/// Scratch the abandoned thread's state is saved into and never read from.
/// `switch` has nowhere else to put it.
pub(crate) static mut ABANDONED: Context = Context::zeroed();

/// What the last user thread did. Read only after control is back in the
/// kernel, so `Relaxed` carries no ordering weight it needs to earn.
pub(crate) static USER_EXIT_VALUE: AtomicU64 = AtomicU64::new(0);
pub(crate) static USER_TRAP_CAUSE: AtomicU64 = AtomicU64::new(0);
pub(crate) static USER_TRAP_ADDRESS: AtomicU64 = AtomicU64::new(0);
pub(crate) static USER_SYSCALLS: AtomicU64 = AtomicU64::new(0);

// The user program. Three behaviours selected by `a0`, all of them
// position-independent — `auipc` reads the *runtime* PC, which is a user
// virtual address, so the blob never needs to know where it was mapped and
// never refers to a kernel-linked symbol.
core::arch::global_asm!(
    r#"
.section .rodata
.balign 4
.globl user_blob_start
user_blob_start:
    li      t0, 1
    beq     a0, t0, 10f
    li      t0, 2
    beq     a0, t0, 20f
    li      t0, 3
    beq     a0, t0, 30f
    li      t0, 4
    beq     a0, t0, 40f

    // Syscall check: hand the kernel a value, get one back, park it on the
    // user stack, and hand it to a second syscall. Two calls, because one
    // proves entry and only the second proves the kernel put U-mode back
    // where it found it. The stack round trip is not decoration — it is what
    // makes the stack mapping and the `sp` the trampoline installed
    // load-bearing, and the clobber in between means a stale register cannot
    // stand in for either.
    li      a7, 0
    li      a0, 0x5e17c0de
    ecall
    addi    sp, sp, -16
    sd      a0, 0(sp)
    li      a0, 0
    ld      a0, 0(sp)
    addi    sp, sp, 16
    li      a7, 1
    ecall
    unimp

10: // W^X: store into the page this instruction was fetched from.
    auipc   t0, 0
    sd      zero, 0(t0)
    unimp

20: // The privilege boundary: read the base of the kernel's direct map.
    li      t0, -1
    slli    t0, t0, 38
    ld      t1, 0(t0)
    unimp

30: // Read this process's own data page and exit with what was there. The
    // address is a constant, identical in every process — which is the point.
    li      t0, 0x30000000
    ld      a0, 0(t0)
    li      a7, 1
    ecall
    unimp

40: // Read the page only one of the processes has.
    li      t0, 0x40000000
    ld      a0, 0(t0)
    li      a7, 1
    ecall
    unimp
.globl user_blob_end
user_blob_end:
"#
);

// SAFETY: declares the blob's bounding symbols, defined by the `global_asm!`
// block above; the declaration itself performs no operation.
unsafe extern "C" {
    pub(crate) static user_blob_start: u8;
    pub(crate) static user_blob_end: u8;
}

/// Handles every exception taken from U-mode: two syscalls, and everything
/// else as a contained fault.
///
/// Returning resumes U-mode. Not returning — which is what `leave_user` does —
/// gives the kernel back control on the stack it started the user thread from.
pub(crate) fn user_trap(frame: &mut TrapFrame) {
    if frame.scause == EXCEPTION_ECALL_FROM_USER {
        USER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
        match frame.a7 {
            SYS_LOG => {
                frame.a0 = user_transform(frame.a0);
                // `ecall` leaves `sepc` on the instruction itself. Resuming
                // without advancing it would re-execute the syscall forever —
                // the architecture does not do this for us, deliberately, so
                // that a handler can restart an instruction when it wants to.
                frame.sepc += 4;
                return;
            }
            SYS_EXIT => {
                USER_EXIT_VALUE.store(frame.a0, Ordering::Relaxed);
                leave_user()
            }
            _ => {
                USER_TRAP_CAUSE.store(u64::MAX, Ordering::Relaxed);
                leave_user()
            }
        }
    }

    USER_TRAP_CAUSE.store(frame.scause, Ordering::Relaxed);
    USER_TRAP_ADDRESS.store(frame.stval, Ordering::Relaxed);
    leave_user()
}

/// Abandons the running user thread and resumes the kernel.
pub(crate) fn leave_user() -> ! {
    use tessera_karch::ContextOps;
    // SAFETY: the boot CPU alone. `KERNEL_RETURN` was written by the
    // `switch` in `run_user` that started this thread, so it names a live
    // kernel stack frame; `ABANDONED` is write-only scratch. This switch does
    // not return, because nothing ever switches back into `ABANDONED`.
    unsafe { ContextSwitch::switch(&raw mut ABANDONED, &raw const KERNEL_RETURN) };
    // Not reachable: the switch above never comes back.
    loop {
        <Cpu as tessera_karch::CpuOps>::halt_until_interrupt();
    }
}

/// Runs the user program once, with `arg` selecting its behaviour, and returns
/// when it has stopped being a user program.
///
/// # Safety
///
/// The user code and stack must be mapped user-accessible in the active
/// address space, and no other user thread may be running.
pub(crate) unsafe fn run_user(arg: usize) {
    use tessera_karch::{ContextOps, UserContextOps};
    USER_EXIT_VALUE.store(0, Ordering::Relaxed);
    USER_TRAP_CAUSE.store(0, Ordering::Relaxed);
    USER_TRAP_ADDRESS.store(0, Ordering::Relaxed);

    let kstack_top =
        (&raw const USER_KSTACK) as u64 + core::mem::size_of::<UserKernelStack>() as u64;
    // SAFETY: `USER_KSTACK` is a live, 16-byte-aligned static owned by this
    // path alone, and the caller guarantees the user mappings. `init_user`
    // writes only the initial frame below its top.
    let user = unsafe {
        ContextSwitch::init_user(
            VirtAddr::new(kstack_top),
            VirtAddr::new(USER_CODE_VA),
            VirtAddr::new(USER_STACK_VA + FRAME_SIZE),
            arg,
        )
    };
    // SAFETY: `KERNEL_RETURN` is this boot path's own continuation and `user`
    // was just built by `init_user`. Control comes back here when the user
    // thread exits or faults.
    unsafe { ContextSwitch::switch(&raw mut KERNEL_RETURN, &user) };
}

/// The user program's bytes, as the linker laid them down.
pub(crate) fn user_blob() -> &'static [u8] {
    // SAFETY: both are linker-provided bounds of the read-only blob above, and
    // the region between them is initialised, immutable and never freed.
    unsafe {
        core::slice::from_raw_parts(
            &raw const user_blob_start,
            (&raw const user_blob_end as usize) - (&raw const user_blob_start as usize),
        )
    }
}

/// Maps the user program and a fresh stack into `space`.
///
/// `code` lets a caller hand in a frame another space is already using, which
/// is not an optimisation but the point being made: two processes running the
/// same program share its *frames* and share nothing else. Isolation is a
/// property of the tables.
pub(crate) fn map_user_image(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
    code: Option<tessera_karch::PhysFrame>,
) -> Result<tessera_karch::PhysFrame, u32> {
    let code = match code {
        Some(frame) => frame,
        None => {
            let blob = user_blob();
            if blob.is_empty() || blob.len() as u64 > FRAME_SIZE {
                return Err(1);
            }
            let frame = frames.alloc_frame().ok_or(2u32)?;
            space.zero_frame(frame);
            space.write_bytes_to_frame(frame, 0, blob);
            frame
        }
    };
    space
        .map(
            VirtAddr::new(USER_CODE_VA),
            code,
            PageFlags::rx().user(),
            frames,
        )
        .map_err(|_| 3u32)?;
    space.sync_instruction_cache(VirtAddr::new(USER_CODE_VA), FRAME_SIZE);

    let stack = frames.alloc_frame().ok_or(4u32)?;
    space.zero_frame(stack);
    space
        .map(
            VirtAddr::new(USER_STACK_VA),
            stack,
            PageFlags::rw().user(),
            frames,
        )
        .map_err(|_| 5u32)?;
    Ok(code)
}

/// The port's first ring-3 execution, asserted rather than announced.
///
/// Three properties, in the order that each depends on the one before it: that
/// U-mode can be entered and returned from at all, that the page table's `U`
/// bit means what it says in the executable direction, and that it means what
/// it says in the kernel direction. A port that could enter U-mode but could
/// not contain it would pass the first alone.
pub(crate) fn umode_check(
    space: &mut impl tessera_karch::AddressSpaceOps,
    frames: &mut impl tessera_karch::FrameSource,
) -> Result<tessera_karch::PhysFrame, u32> {
    let code = map_user_image(space, frames, None)?;

    tessera_karch_riscv64::set_user_trap_hook(user_trap);

    // 1. Enter U-mode, make two syscalls, exit. The value that comes back is
    //    the kernel's transform of the one the program sent, so a zero or an
    //    echo would both fail.
    // SAFETY: the code and stack pages are mapped user-accessible above, and
    // no other user thread exists.
    unsafe { run_user(CHECK_SYSCALL) };
    if USER_TRAP_CAUSE.load(Ordering::Relaxed) != 0 {
        return Err(6);
    }
    if USER_EXIT_VALUE.load(Ordering::Relaxed) != user_transform(USER_MAGIC) {
        return Err(7);
    }
    if USER_SYSCALLS.load(Ordering::Relaxed) != 2 {
        return Err(8);
    }
    kprintln!(
        "umode: entered U-mode and returned — syscall round-tripped {:#x} as {:#x}",
        USER_MAGIC,
        user_transform(USER_MAGIC)
    );

    // 2. W^X at the unprivileged level: the code page is mapped read-execute,
    //    so the program's store into it must fault rather than land.
    // SAFETY: as above.
    unsafe { run_user(CHECK_WRITE_TO_CODE) };
    let cause = USER_TRAP_CAUSE.load(Ordering::Relaxed);
    if cause != EXCEPTION_STORE_PAGE_FAULT {
        return Err(9);
    }
    // The program stores through `auipc`, so the faulting address is the
    // storing instruction's own address — somewhere inside the code page, not
    // its base. Checking the page is the claim being made.
    let fault = USER_TRAP_ADDRESS.load(Ordering::Relaxed);
    if fault & !(FRAME_SIZE - 1) != USER_CODE_VA {
        return Err(10);
    }
    kprintln!(
        "umode: W^X held — a store into the code page took a {} at {:#x}",
        exception_name(cause),
        fault
    );

    // 3. The privilege boundary itself: every kernel page is mapped without
    //    `U`, so a user load from one must fault. This is the check the higher
    //    half exists to make meaningful — the kernel is not merely elsewhere,
    //    it is unreachable.
    // SAFETY: as above.
    unsafe { run_user(CHECK_READ_KERNEL) };
    let cause = USER_TRAP_CAUSE.load(Ordering::Relaxed);
    if cause != EXCEPTION_LOAD_PAGE_FAULT {
        return Err(11);
    }
    if USER_TRAP_ADDRESS.load(Ordering::Relaxed) != DIRECT_MAP_BASE {
        return Err(12);
    }
    kprintln!(
        "umode: kernel unreachable from U-mode — a load of {:#018x} took a {}",
        DIRECT_MAP_BASE,
        exception_name(cause)
    );
    kcore::verdict::claims(&["umode.ok"]);

    Ok(code)
}
