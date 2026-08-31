// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// What a program says when something goes wrong, and who it says it to.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and has no opinion about what is in it, exactly as `fs_service` and
// `flow_service` are.
//
// **Why a contract and not a syscall.** `DebugWrite` is the kernel's console,
// and a kernel's console exists for the kernel's benefit — it is how a machine
// that cannot yet run programs says what happened. A program emitting a
// diagnostic is not talking to the machine; it is talking to whatever is
// collecting its output, which may be its parent, a log service, a build system
// two layers up, or nothing at all. That is a relationship between two
// components, and this tree writes those in ISL (`docs/roadmap/04`, Phase 1).
//
// **What using `DebugWrite` for this actually costs.** A diagnostic sent to the
// kernel cannot be routed, cannot be attributed to the program that sent it
// once more than one program is running, and cannot be collected by anything
// that is not the kernel. None of those is a limitation of the console; they
// are what happens when output has no addressee.
//
// **And the console cannot carry text anyway.** `syscall_abi.isl` declares
// `DebugWrite` as a buffer and a length; every port implements the length-zero
// case alone, recording the argument register as a *value* — riscv32's handler
// says so out loud ("this port has no console for a user string anyway"). So a
// ring-3 program in this tree cannot emit a byte of text by any means. That is
// not fixed here: what is fixed is that the text now has somewhere to go that
// is not the kernel, and the one program that has to change when a console
// arrives is the service rather than every program that reports.

library tessera.diagnostic;

// How much a reader should care.
//
// Three levels and no more. A vocabulary a caller has to look up is one it will
// pick from at random, and the distinctions that matter to a supervisor are
// "this run failed", "this run is suspect" and "this is narration".
strict enum Severity : uint32 {
    // The program could not do what it was asked. Pairs with a non-zero
    // `ExitStatus`, and a reader that sees one without the other has found a
    // program that is lying in one of the two places.
    ERROR = 1;
    // The program did what it was asked and something about it was wrong.
    WARNING = 2;
    // Narration. A reader may drop these without losing a verdict.
    INFO = 3;
};

@abi
struct DiagnosticRecord {
    size: uint32;
    version: uint32;
    flags: uint64;
    severity: Severity;
    // How many of `text` carry the message. Greater than the array's bound is a
    // malformed record and is refused, not clamped.
    //
    // **The bound is short on purpose.** A diagnostic that does not fit is one
    // that should have been several, and a message long enough to need a memory
    // object would put an allocation on the failure path — which is exactly
    // where a program has least to spend.
    len: uint32;
    // Set when the sender had more to say than would fit. **The sender says so
    // rather than the reader guessing**: a message that ends mid-word is
    // indistinguishable from one that meant to, and a log that silently drops
    // the end of a line is the silent degradation `docs/lifecycle/04` forbids.
    truncated: uint32;
    reserved: uint32;
    // Bytes, not a string: a path can appear in a diagnostic and a path is not
    // required to be UTF-8 — the same reason `FsOpenRequest.path` is bytes.
    text: array<uint8, 192>;
};

protocol Diagnostic {
    // **One-way, and that is the whole design.** A program reporting that it
    // failed must not then block on whoever is collecting the report: a service
    // that stopped would turn every diagnostic into a hang, and the programs
    // most likely to emit one are the ones least able to wait. The sender
    // learns nothing about delivery, which is the price and is worth it.
    1: Report(DiagnosticRecord);
    // The stream is over and the collector may stop.
    //
    // Sent by whoever composed the run rather than by a reporter — a program
    // that could end everybody's log by exiting would be one bug away from
    // silencing the others. A service that only ever received records would run
    // until something killed it, and nothing in this composition kills.
    2: Close();
};
