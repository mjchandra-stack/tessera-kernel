// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
//
// The **power vote protocol**: how a driver, a service or a user-facing
// program tells the power manager what it needs, and what it is told back.
//
// `docs/hardware/03-component-interaction-model.md` ("Power Domains") says
// drivers express their requirements as votes and that the power manager
// arbitrates them "with user intent, battery state, thermal state, policy, and
// real-time deadlines". Every class contract in the tree already declares its
// half — `block_driver.isl` names four device power states and reports the
// resume latency of the deepest one — and until this file there was nothing to
// send a vote *to*. `SetPower` existed and was called by a test client because
// the two lines were next to each other in a transcript, which is a device
// changing state, not a system deciding it should.
//
// This is a user<->user contract: the kernel transports the payload opaquely
// and never decodes it, exactly like `block_driver.isl` and `driver_bind.isl`.
//
// **What a vote names, and why it is not a device.** A vote names a *power
// domain* — the identifier `binding::ManifestEntry.power_domain` assigns and
// `driver_bind.isl`'s `BindReply` already delivers to every driver at bind
// time. Naming a device instead would mean a voter holding a kernel object
// id, which is a thing ring 3 has no business knowing and no way to have been
// given; and it would make it impossible to vote on a rail shared by two
// devices, which is the case the word "domain" exists for.
//
// **What is deliberately not here.** No frequency, no residency counters, no
// battery percentage. Frequency selection is a kernel-resident mechanism
// (`docs/power/01`, "CPU Power Governing") and the rest have no producer on
// any port yet; a protocol that carried them would be describing a system that
// does not exist.

library tessera.power;

// --- Levels -----------------------------------------------------------------

// The power levels a domain can be driven to, in the vocabulary
// `docs/hardware/03` defines.
//
// **Ordered, and the ordering is the arbitration rule**: the highest vote
// wins, so these values are compared and not merely matched. Numbered from 1
// so that zero stays "no level recorded", which a decoder can tell apart from
// a real level — the same convention `driver_lifecycle.isl` uses, and for the
// same reason: a reply whose `clamped_from` is absent must be distinguishable
// from one that was clamped from `Off`.
//
// Five rather than the block class's four. These are *system* levels shared by
// every device class, and `BlockPowerState` is one class's mapping onto them —
// a mapping the driver owns, because only the driver knows whether its
// medium's `STANDBY` is retention or off.
strict enum PowerLevel : uint32 {
    // Powered down. Whatever was not flushed is gone.
    OFF = 1;
    // Powered down with state retained; resuming restores rather than
    // re-initializes.
    RETENTION = 2;
    // Running, at the lowest rate that still serves.
    LOW_POWER_ACTIVE = 3;
    // Running at the ordinary rate.
    FULL_ACTIVE = 4;
    // Running above the ordinary rate. A level rather than a flag because it
    // must be refusable: a boost nothing could decline would be a floor
    // nobody agreed to.
    PERFORMANCE_BOOST = 5;
};

// Who is voting.
//
// The class is not decoration, and two of these do not vote in the ordinary
// sense at all. A `THERMAL` entry's level is the highest level currently
// *permitted* rather than one required, and `POLICY` never appears in a
// request — it is the attribution the manager uses when the installation's own
// limits are what bound the answer, so a clamp always names something.
strict enum VoterClass : uint32 {
    // A user-facing program, voting on behalf of somebody's intent.
    USER = 1;
    // A system service.
    SERVICE = 2;
    // The driver bound to the device, voting for what it needs to serve.
    DRIVER = 3;
    // A thermal zone. Its level is a ceiling.
    THERMAL = 4;
    // The installation itself. Never sent; only reported in `clamped_by`.
    POLICY = 5;
};

// --- Errors -----------------------------------------------------------------

// What a vote can fail with. A closed set, like every other class contract's,
// so a voter can enumerate the ways its request can be refused.
strict enum PowerError : uint32 {
    // The vote was recorded and the reply carries the resolution.
    OK = 0;
    // The request was malformed: an unknown method, a level or class outside
    // this contract.
    PROTOCOL = 1;
    // The manager has no such power domain. An answer rather than a silent
    // no-op: a voter shouting into a domain that does not exist would
    // otherwise look exactly like one whose vote is always outvoted.
    NO_SUCH_DOMAIN = 2;
    // The manager's vote table is full. Reported rather than dropping a vote,
    // because a dropped vote is a device held at the wrong level with nothing
    // anywhere saying why.
    NO_SPACE = 3;
    // The domain resolved, and the driver refused to move to the resolved
    // level. The resolution stands and the reply reports it; what failed is
    // the application, and the two are different situations.
    DEVICE_REFUSED = 4;
};

// --- Messages ---------------------------------------------------------------

// A vote, a withdrawal, or a request for a domain's current resolution.
//
// One request struct for all three methods rather than three, for the reason
// `BlockControlRequest` is one struct for four: the envelope is what the
// decoder needs, and structs distinguishable only by name are that many ways
// to get the same thing wrong.
@abi
struct PowerVoteRequest {
    size: uint32;
    version: uint32;
    flags: uint64;
    // Which power domain this is about.
    domain: uint32;
    // The level being asked for. Meaningful for `Vote`; ignored by `Withdraw`
    // and `Describe`.
    level: PowerLevel;
    // What kind of voter this is. A `THERMAL` sender's level is a ceiling.
    class: VoterClass;
    reserved: uint32;
};

// What the domain resolved to, and who lost.
//
// **`clamped_from` is the whole reason this is a reply and not an
// acknowledgement.** A voter that asked for `FULL_ACTIVE` and is running at
// `RETENTION` because a thermal zone said so is in a completely different
// situation from one whose vote was simply outvoted downward — which cannot
// happen, since the highest vote wins — or one whose device is broken. The
// system degraded it, and `docs/lifecycle/04` ("No silent fallback") requires
// that be said rather than discovered.
//
// The fields are only meaningful together: `clamped_from` is `0` — not a level
// — when nothing was taken away, which is why `PowerLevel` starts at 1.
@abi
struct PowerVoteReply {
    size: uint32;
    version: uint32;
    flags: uint64;
    // A `PowerError` value. Typed `uint32` rather than the enum so a
    // non-conformant value can be *observed* rather than failing to decode —
    // the same choice `BlockReadReply.status` makes.
    status: uint32;
    // What the domain is being driven to now.
    resolved: PowerLevel;
    // The level the winning voter asked for, when that is higher than
    // `resolved`; zero when nothing was clamped.
    clamped_from: uint32;
    // What took it away: `THERMAL` for heat, `POLICY` for the installation's
    // own limits. Zero when nothing was clamped.
    clamped_by: uint32;
    // Which voter won the domain, or zero when nothing demanded anything and
    // `resolved` is the policy floor. The distinction matters: an idle domain
    // and a busy one that needs very little resolve to the same level.
    winner: uint32;
    reserved: uint32;
};

// --- The protocol -----------------------------------------------------------

// The power manager, as seen by anything that votes.
//
// **Withdrawal is a method and not a vote of `OFF`.** They are different
// facts: `OFF` says "I need this powered down", which is a requirement like
// any other and competes with the rest; withdrawing says "I no longer have an
// opinion", which is what lets a domain fall to the policy floor. A protocol
// with only the first would make a program that finished its work hold the
// domain at whatever it last asked for, for ever.
protocol PowerManager {
    // Cast or replace this voter's vote on a domain. A voter has at most one
    // vote per domain; voting again replaces it, which is why there is no
    // separate "change" method.
    1: Vote(PowerVoteRequest) -> (PowerVoteReply);
    // Withdraw this voter's vote on a domain. Answers with the resolution the
    // withdrawal produced, so a voter learns whether it was the one holding
    // the domain up.
    2: Withdraw(PowerVoteRequest) -> (PowerVoteReply);
    // What is this domain resolved to right now, without changing anything.
    3: Describe(PowerVoteRequest) -> (PowerVoteReply);

    // Ordinals 4..=19 remain reserved for methods this contract has not needed
    // yet — system suspend and wake-hold brokering among them.

    // Events. The manager raises these; no voter asked.
    //
    // A domain's resolution changed because of somebody *else's* vote. Every
    // voter on a domain gets one, which is what lets a driver that was
    // clamped find out without polling.
    20: -> OnResolutionChanged(PowerVoteReply);
};
