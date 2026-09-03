// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Ports: asynchronous event delivery.
//!
//! Signals coalesce while nothing is listening, and the queued state survives
//! until something reads it.
//!
//! Split out of `main.rs` by area (build/README.md, D265). **The split is
//! organisational.** This module opens with `use crate::*` and the crate root
//! re-exports it, so the namespace is the flat one it was when this was one
//! file; what it buys is a name and a header per area, not a boundary.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/architecture/01-system-architecture.md

use crate::*;

// ---- Ports (async event delivery) kernel demo -------------------------------

/// The demo's abstract event source and signal. In v0 a source is an opaque id
/// (not yet a channel/sync/cancellation binding — build/README.md, D38).
pub(crate) const PORT_DEMO_SOURCE: u64 = 0x5011;
pub(crate) const PORT_DEMO_SIGNAL: u8 = 1;
/// Observations, published by the consumer and checked on boot.
pub(crate) static PORT_DEMO_COALESCED_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static PORT_DEMO_TRAILING_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static PORT_DEMO_WOKEN_PENDING: AtomicU64 = AtomicU64::new(u64::MAX);
pub(crate) static PORT_DEMO_COALESCE_COUNT: AtomicU64 = AtomicU64::new(u64::MAX);

/// The consumer: creates and binds a port, proves coalescing (three edges before
/// a drain collapse into one event carrying a pending count of 3), proves a
/// trailing edge after the drain is not lost, then blocks on an empty drain to
/// be woken by the producer's cross-thread signal.
pub(crate) extern "C" fn port_demo_consumer(_arg: usize) -> ! {
    let exec = exec_ref();
    let port = match exec.port_create() {
        Ok(port) => port,
        Err(_) => {
            exec.scheduler().yield_to_boot();
            loop {
                core::hint::spin_loop();
            }
        }
    };
    if exec
        .port_bind(port, PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL)
        .is_err()
    {
        exec.scheduler().yield_to_boot();
        loop {
            core::hint::spin_loop();
        }
    }
    // Phase 1 — three edges before a drain coalesce into one event.
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    if let Ok(event) = exec.port_wait(port) {
        PORT_DEMO_COALESCED_PENDING.store(event.pending as u64, Ordering::Relaxed);
    }
    // Phase 2 — a fresh edge after the drain is a separate, un-lost event.
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 1);
    if let Ok(event) = exec.port_wait(port) {
        PORT_DEMO_TRAILING_PENDING.store(event.pending as u64, Ordering::Relaxed);
    }
    PORT_DEMO_COALESCE_COUNT.store(exec.port_coalesced(port), Ordering::Relaxed);
    // Phase 3 — block on an empty port; the producer wakes us cross-thread.
    if let Ok(event) = exec.port_wait(port) {
        PORT_DEMO_WOKEN_PENDING.store(event.pending as u64, Ordering::Relaxed);
    }
    exec.scheduler().yield_to_boot();
    loop {
        core::hint::spin_loop();
    }
}

/// The producer: signals the bound source (waking the blocked consumer), then
/// parks so the woken consumer runs.
pub(crate) extern "C" fn port_demo_producer(_arg: usize) -> ! {
    let exec = exec_ref();
    exec.port_signal(PORT_DEMO_SOURCE, PORT_DEMO_SIGNAL, 5);
    exec.scheduler().block_current();
    loop {
        core::hint::spin_loop();
    }
}

/// Ports: async event delivery that cannot lose events or overflow. A consumer
/// binds a port to a source and proves the load-bearing semantics — coalescing
/// with a pending count, drain-reads-current-state, no lost edge — then a
/// producer thread signals the source and wakes the blocked drainer
/// (docs/kernel/04 "Port Delivery Semantics"). Both are kernel threads, so the
/// demo runs entirely under the kernel address space.
pub(crate) fn ports_demo(
    kernel_vm: &mut AddressSpace<KernelAddressSpace>,
    frames: &mut kcore::pmem::BumpFrameAllocator<'static>,
) {
    // SAFETY: the boot CPU alone; re-initializing the shared executive.
    unsafe { exec_restart(1) };
    let exec = exec_ref();
    let mut spawn_kernel_thread = |entry: extern "C" fn(usize) -> !, kstack: u64| {
        let thread = Thread::<ContextSwitch>::spawn(
            entry,
            0,
            VirtAddr::new(kstack),
            USER_KSTACK_PAGES,
            kernel_vm,
            frames,
        )
        .ok()?;
        exec.add_thread(thread).ok()
    };
    // Consumer first so it sets up the port and reaches its blocking drain
    // before the producer runs.
    if spawn_kernel_thread(port_demo_consumer, alloc_kstack(USER_KSTACK_PAGES).as_u64()).is_none() {
        return kprintln!("ports-demo: setup failed (consumer)");
    }
    if spawn_kernel_thread(port_demo_producer, alloc_kstack(USER_KSTACK_PAGES).as_u64()).is_none() {
        return kprintln!("ports-demo: setup failed (producer)");
    }
    exec.run();

    let coalesced = PORT_DEMO_COALESCED_PENDING.load(Ordering::Relaxed);
    let trailing = PORT_DEMO_TRAILING_PENDING.load(Ordering::Relaxed);
    let woken = PORT_DEMO_WOKEN_PENDING.load(Ordering::Relaxed);
    let collapses = PORT_DEMO_COALESCE_COUNT.load(Ordering::Relaxed);
    let pass = coalesced == 3 && trailing == 1 && woken == 5 && collapses == 2;
    report(&verdict(
        DemoId::Ports,
        pass,
        [collapses, 0, 0, 0, 0, 0, 0, 0],
    ));
    if !pass {
        kprintln!(
            "ports-demo: FAIL coalesced={coalesced} trailing={trailing} woken={woken} collapses={collapses}"
        );
    }
}
