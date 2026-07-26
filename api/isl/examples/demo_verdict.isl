// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The boot harness's demo-verdict ABI, defined in ISL.
// `docs/observability/01-debugging-monitoring-tracing-logging.md` states the rule
// this schema exists to satisfy: "Plain text rendering is generated from
// structured records." Each boot demo produces a `DemoVerdict` record; the
// harness renderer turns it into the verdict line, so the text is a view over the
// record rather than the primary artifact.
//
// The `outcome` field is what lets a failing demo fail the build: the harness
// aggregates it and selects the exit code, closing the long-standing hole where a
// demo could print FAIL and the boot still exited success (build/README.md, D58).
//
// This is a harness record, distinct from the kernel's observability events
// (`kernel_event.isl`): it carries eight payload slots because a verdict line
// interpolates more values than a kernel event, and inflating every kernel event
// to match would be the wrong trade. Only the pass-path prose is rendered from
// this record; a failing demo's diagnostic dump stays a direct print (D58).

library tessera.kernel.harness;

// Whether the demo's predicate held. `outcome` is the field the harness
// aggregates to decide the boot's exit code.
strict enum Outcome : uint32 {
    PASS = 1;
    FAIL = 2;
};

// The boot demos, each a stable id. Values are ABI: append only, never renumber
// or reuse — a recorded verdict must stay interpretable.
strict enum DemoId : uint32 {
    LOADER = 1;
    COMPONENT_MANAGER = 2;
    COMPONENT_MANAGER_BUDGET = 3;
    COMPONENT_MANAGER_RECLAIM = 4;
    DRIVER_CRASH = 5;
    DRIVER_RESTART = 6;
    DRIVER_RESTART_BUDGET = 7;
    CHANNEL_IPC = 8;
    COM2_DRIVER_STEP0 = 9;
    COM2_DRIVER_STEP1 = 10;
    COM2_DRIVER_STEP2 = 11;
    COM2_DRIVER_STEP3 = 12;
    COM2_DRIVER_STEP4 = 13;
    COM2_DRIVER_SERVICE = 14;
    DEVICE_MANAGER = 15;
    FS_SUPPLY = 16;
    FS_SERVICE = 17;
    WAIT_ON_ADDRESS = 18;
    PORTS = 19;
    JOBS = 20;
    PAGER_DIRTY_FLOOD = 21;
    PAGER_DIRTY_QUERY = 22;
    PAGER_DURABILITY = 23;
    PAGER_DEATH = 24;
    PAGER_RECLAIM_DEADLOCK = 25;
    PAGER_SELF_PAGING_CYCLE = 26;
    PAGER_DEADLINE_SUPERVISION = 27;
    OBSERVABILITY_EVENTS = 28;
    CORRELATION = 29;
    // Architecture-conformance battery: the porting-layer contract, run
    // identically by every architecture port so a port's claim to implement
    // the layer is checked rather than asserted (docs/hardware/01, "Porting
    // Rules" 5, "Pass kernel architecture tests").
    ARCH_MAP_TRANSLATE = 30;
    ARCH_WX_REFUSED = 31;
    ARCH_REMAP_REJECTED = 32;
    ARCH_PROTECT = 33;
    ARCH_UNMAP = 34;
    ARCH_FRAME_OPS = 35;
    ARCH_DIRECT_MAP = 36;
    ARCH_ICACHE_COHERENCE = 37;
    ARCH_CONTEXT_SWITCH = 38;
};

// One demo's verdict. `arg0..arg7` are the values its rendered line interpolates,
// positionally per demo (the renderer knows each demo's arity and types); eight
// slots covers the widest verdict with headroom. Signed values (exit codes, frame
// deltas) are carried as `uint64` and rendered back through the arm that knows
// their type.
@abi
struct DemoVerdict {
    size: uint32;
    version: uint32;
    flags: uint64;
    demo: DemoId;
    outcome: Outcome;
    arg0: uint64;
    arg1: uint64;
    arg2: uint64;
    arg3: uint64;
    arg4: uint64;
    arg5: uint64;
    arg6: uint64;
    arg7: uint64;
};
