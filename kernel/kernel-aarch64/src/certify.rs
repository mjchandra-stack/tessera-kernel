// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The certification check and what it measures.
//!
//! A boot records which checks *ran* as well as which passed, so a check
//! nobody ran can never look like a check that passed; this is the half that
//! reads those records back and encodes the certificate `//tools/certify`
//! admits or refuses a driver on.
//!
//! Normative: docs/lifecycle/02-build-and-test-infrastructure.md

// The crate root holds the machine's statics and its layout constants; a
// module of this crate can see them, and naming them one by one would be a
// list to maintain rather than a boundary.
use crate::*;
// `components` is a module rather than an item, so the root glob does not
// carry it here; named directly.
use crate::host::components;

/// What one run of `certification_check` looked at.
///
/// Counts rather than a verdict, because the verdict is in the certificate and
/// the counts are what make it readable: "the records were well formed" and
/// "the driver held only what it was allowed" are both unfalsifiable from a log
/// that does not say how many of each there were.
pub(crate) struct CertificationCounts {
    pub(crate) trace_records: u32,
    pub(crate) capabilities: u32,
    pub(crate) unscoped_grants: u32,
    /// Ticks that looked at the slot while ring 3 was still running.
    pub(crate) slot_polls: u64,
    /// The certificate itself, encoded, so the verdict can leave this machine.
    ///
    /// Everything else here is a number a human reads in a log. This is the
    /// record a later boot on a different machine has to act on, and prose is
    /// not something a signed channel can admit a driver on.
    pub(crate) certificate: [u8; certification::Certificate::WIRE_SIZE],
}

/// Puts the certificate on the wire, as one line of hex.
///
/// **A verdict that cannot leave the machine that reached it is not evidence
/// for anything.** Every other line this boot prints is prose for a person; a
/// signed channel admits a driver on a record, and this is the only form of
/// this run's answer that a later boot on a different machine can act on.
/// Hex on the console because the console is the one channel a boot check
/// already has, and because a reader can see that nothing was added to it.
pub(crate) fn print_certificate(encoded: &[u8; certification::Certificate::WIRE_SIZE]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = [0u8; certification::Certificate::WIRE_SIZE * 2];
    for (index, byte) in encoded.iter().enumerate() {
        hex[index * 2] = DIGITS[usize::from(byte >> 4)];
        hex[index * 2 + 1] = DIGITS[usize::from(byte & 0xf)];
    }
    match core::str::from_utf8(&hex) {
        Ok(text) => kprintln!("certificate: {text}"),
        // Unreachable, every byte being an ASCII hex digit — but a kernel whose
        // verdict silently stopped travelling is worse than one that says the
        // rendering failed.
        Err(_) => kprintln!("certificate: FATAL: the record did not render"),
    }
}

/// Encodes the certificate a run produced, measuring the artifact it is about.
///
/// **The digest is what makes it evidence about bytes.** A certificate naming
/// only a driver is evidence about a name, and a name is what an attacker
/// substituting an image keeps. `api/update-channel` refuses an entry whose
/// image is all zero for exactly that reason, so the measurement is taken here
/// — where the bytes that ran are the bytes in hand — rather than being
/// attached later by whoever is assembling a manifest.
pub(crate) fn encoded_certificate(
    certificate: &tessera_certification::Certificate,
) -> Result<[u8; certification::Certificate::WIRE_SIZE], u32> {
    // An absent image is refused rather than measured. This used to name the
    // image crate directly, so a build without it did not compile — loud, but
    // only by accident. Going through the manifest makes such a build possible,
    // and `sha256(&[])` is a digest of nothing wearing a certificate that says
    // it measured a driver, which is precisely the substitution the comment
    // above says this exists to stop.
    let image = components::crypto_driver();
    if image.is_empty() {
        return Err(1456);
    }
    let digest = tessera_hash::sha256(image);
    let record = certification::Certificate {
        size: certification::Certificate::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        driver: certificate.subject().driver,
        device_class: certificate.subject().class,
        contract_version: certificate.subject().contract_version,
        ran: certificate.ran(),
        passed: certificate.passed(),
        digest_algorithm: certification::CertificateDigest::Sha256,
        image: digest,
    };
    let mut out = [0u8; certification::Certificate::WIRE_SIZE];
    match tessera_isl_runtime::encode(&record, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(1455),
    }
}

/// What the binding manifest's crypto entry declares about a driver bound by
/// it, restated here because boot is where the comparison happens and the
/// manifest lives in a ring-3 manager.
///
/// **Restating it is the weak seam and it is stated rather than hidden.** The
/// honest arrangement is for the manager to report the entry it matched, which
/// needs a protocol that does not exist yet (build/README.md, D165). Until then
/// a disagreement between these two lines and the manager's table would make
/// this check compare a driver against a policy nobody applied.
pub(crate) const CERTIFIED_POLICY: tessera_policy_compliance::Declared = tessera_policy_compliance::Declared {
    configure: true,
    derive: false,
    domain: 1,
};

/// What the driver process actually holds, compared against that.
///
/// Read from the **process's own handle table** rather than from boot's memory
/// of what it installed. Those differ by exactly the thing worth finding: a
/// capability that arrived by transfer, from the manager, carrying rights
/// nobody at this end chose.
pub(crate) fn policy_compliance_of(process: usize) -> tessera_policy_compliance::Verdict {
    use tessera_policy_compliance::Held;
    const SLOTS: usize = 32;

    let mut audit = [(
        kcore::object::ObjectId::from_raw(0),
        kcore::rights::Rights::none(),
    ); SLOTS];
    // SAFETY: transient raw access to the static process table; a read, and
    // every thread is off-CPU.
    let count = unsafe {
        (*(&raw const KCORE_PROCESSES))
            .get(process)
            .map(|p| p.handles().audit(&mut audit))
            .unwrap_or(0)
    };
    let mut held = [Held {
        object: 0,
        rights: 0,
    }; SLOTS];
    for (slot, (object, rights)) in held.iter_mut().zip(audit.iter()).take(count) {
        *slot = Held {
            object: object.raw(),
            rights: rights.bits(),
        };
    }
    tessera_policy_compliance::check(&CERTIFIED_POLICY, &held[..count])
}

/// Whether the fuzz record this kernel was compiled with says anything.
///
/// **The outcome itself is entailed by this binary existing.** The evidence
/// record is a genrule output produced by a runner that exits non-zero on a
/// finding, and the kernel links it — so a kernel that fuzzed badly is a kernel
/// that did not build. Recording `Passed` here is reading a fact off the
/// artifact rather than asserting one.
///
/// What is still worth checking is that the record is *substantive*. A stubbed
/// evidence file would compile and link and say nothing, and "the fuzzing ran"
/// over zero targets is the same empty claim this whole facility exists to
/// refuse. So: targets exist, they got more inputs than there were targets, and
/// the run was two-sided — some inputs decoded and some were refused.
pub(crate) fn fuzz_evidence_is_substantive() -> bool {
    fuzz_evidence::TARGETS > 0
        && fuzz_evidence::INPUTS > fuzz_evidence::TARGETS
        && fuzz_evidence::ACCEPTED > 0
        && fuzz_evidence::ACCEPTED < fuzz_evidence::INPUTS
}

/// What this driver's own records say about its DMA.
///
/// **The certification question is prior to fault handling, and is not the same
/// one.** Every SMMU check in this tree proves the hardware refuses what it
/// should; none of them asks whether *this driver's* memory goes through an
/// aperture at all. A driver handed a physical address has no fault to handle,
/// because there is nothing for a fault to be raised against — so a driver
/// "certified for DMA-fault handling" on a machine that cannot contain it has
/// been certified for nothing.
///
/// `kernel_event.isl` already keeps the two apart, deliberately: a scoped grant
/// is a positive record rather than the absence of a warning.
#[derive(Clone, Copy, Default)]
pub(crate) struct DmaSummary {
    /// Grants that returned an IOVA the unit resolves for this device alone.
    scoped: u32,
    /// Grants that returned a physical address, because nothing translates for
    /// this device.
    unscoped: u32,
    /// Transactions the unit refused and attributed to this driver.
    faults: u32,
}

impl DmaSummary {
    /// Whether this driver's DMA is containable, and was contained.
    ///
    /// Requires at least one scoped grant. A driver that never asked for DMA
    /// has not shown that its DMA is scoped, and reading "no unscoped grants"
    /// off a driver that made none is the empty claim this facility refuses
    /// everywhere else.
    fn is_contained(&self) -> bool {
        self.scoped > 0 && self.unscoped == 0 && self.faults == 0
    }
}

/// Validates the trace records this driver caused, as `kernel_event.isl`
/// defines them.
///
/// **`tail` and not `drain`.** The ring is drained once per boot, by
/// `device_events_check`, and a reader that consumed it here would leave that
/// check nothing to read — the records would be judged and then be gone, which
/// is a worse trade than reading them twice.
///
/// Scoped to one process, because the question is what *this driver* emitted.
/// The machine's whole ring would fold in every earlier check's records and
/// answer a question nobody asked about a driver nobody is certifying.
pub(crate) fn trace_schema_of(process: u64) -> (tessera_trace_schema::Verdict, DmaSummary) {
    use kcore::event::{self, Component, EventKind, Severity};
    const SEEN: usize = 64;

    let blank = event::record(
        EventKind::EventsDropped,
        Severity::Debug,
        Component::Observability,
        0,
        kcore::trace::TraceContext::NONE,
        [0; 4],
    );
    let mut seen = [blank; SEEN];
    let n = event::tail(&mut seen);

    let mut records = [tessera_trace_schema::Record::default(); SEEN];
    let mut count = 0;
    for emitted in &seen[..n] {
        if emitted.process_id != process {
            continue;
        }
        records[count] = tessera_trace_schema::Record {
            size: emitted.size,
            version: emitted.version,
            kind: emitted.kind as u32,
            severity: emitted.severity as u32,
            component: emitted.component as u32,
            classification: emitted.classification as u32,
            timestamp: emitted.timestamp,
            process_id: emitted.process_id,
            correlation_lo: emitted.correlation_lo,
            correlation_hi: emitted.correlation_hi,
            args: [emitted.arg0, emitted.arg1, emitted.arg2, emitted.arg3],
        };
        count += 1;
    }

    // The same records read for a different question, from this one pass rather
    // than a second — for the reason `device_events_check` takes both its
    // summaries off one drain: the two readings are about the same run, and a
    // second pass could describe a machine that had moved on.
    let mut dma = DmaSummary::default();
    for record in &records[..count] {
        match record.kind {
            19 => dma.scoped += 1,
            18 => dma.unscoped += 1,
            22 => dma.faults += 1,
            _ => {}
        }
    }
    (tessera_trace_schema::validate(&records[..count]), dma)
}

/// What the certifier reports: the two checks it can make from inside a channel
/// both held, it refused to certify on them, the refusal named nine, and the
/// rules refused a forged record and a stale contract version in ring 3.
pub(crate) const CERTIFIER_EXPECTED: u64 = (0xc1 << 56)
    | (1 << 39)
    | (1 << 38)
    | (1 << 37)
    | (1 << 36)
    | (1 << 35)
    | (1 << 34)
    | (1 << 33)
    | (1 << 32)
    // AbiConformance, ClassConformance, Power and SuspendResume, and nothing
    // else.
    | 0b110
    | (1 << 7)
    | (1 << 4);

/// Proves **a runner that will not certify what it did not check**.
///
/// Every other check in this machine ends by reporting that something worked.
/// This one ends by reporting what was never asked. A ring-3 certifier runs the
/// two of the eleven checks a peer can make against a driver — the seven class
/// rules, and whether the driver's replies declare the shapes the reader
/// assumed — and both hold. It then refuses to issue a certificate, because
/// nine checks need a machine somebody is interfering with from outside, a
/// fuzzing engine, or a measurement rig, and none of those is here.
///
/// **The refusal is the property.** A runner that certified on two passing
/// checks would be hiding a failure that is not a driver bug: a rig that
/// stopped asking. The checks in this tree are scripts registered by hand, and
/// nothing notices a registration going missing except something built to.
pub(crate) fn certification_check(
    high: &KernelAddressSpace,
    boot_low: &KernelAddressSpace,
    frames: &mut kcore::pmem::BumpFrameAllocator<'_>,
    function: &tessera_pci::Function,
    layout: kcore::devmgr::DeviceLayout,
    bar_base: u64,
    bar_len: u64,
    pci: &tessera_devicetree::PciHost,
    functions: &[tessera_pci::Function],
    recovered: bool,
) -> Result<CertificationCounts, u32> {
    use kcore::rights::Rights;
    use kcore::vm::{AddressSpace, Asid};
    use tessera_karch::{AddressSpaceOps, TimerControl};

    // SAFETY: single-threaded boot; initialized before any thread runs.
    unsafe {
        (&raw mut KCORE_EXEC).write(Some(kcore::exec::Executive::new(1, 0)));
    }
    // SAFETY: transient raw access to the static executive.
    unsafe {
        let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1301u32)?;
        exec.device_register_identified(
            CERT_DEVICE_OBJ,
            bar_base,
            bar_len,
            Rights::READ | Rights::MAP | Rights::TRANSFER,
            kcore::devmgr::DeviceIdentity {
                class_code: function.class_code,
                vendor: function.vendor,
                device: function.device,
                bdf: (u16::from(function.bdf.bus) << 8)
                    | (u16::from(function.bdf.device) << 3)
                    | u16::from(function.bdf.function),
                revision: function.revision,
                bus: kcore::devmgr::DeviceBus::Pci,
            },
        )
        .map_err(|_| 1302u32)?;
        exec.device_set_layout(CERT_DEVICE_OBJ, layout)
            .map_err(|_| 1303u32)?;

        let manager = exec.channel_create().map_err(|_| 1304u32)?;
        exec.bind_endpoint_object(manager.0, CERT_MANAGER_SERVER_OBJ);
        exec.bind_endpoint_object(manager.1, CERT_MANAGER_CLIENT_OBJ);
        let service = exec.channel_create().map_err(|_| 1305u32)?;
        exec.bind_endpoint_object(service.0, CERT_SERVER_OBJ);
        exec.bind_endpoint_object(service.1, CERT_CLIENT_OBJ);
    }

    // SAFETY: `high` is the active kernel high-half; the alias is never torn
    // down.
    let kernel_arch = unsafe { KernelAddressSpace::from_root(high.root_phys(), DIRECT_MAP_BASE) };
    let mut kernel_space = AddressSpace::from_arch(kernel_arch, Asid(0), 0);

    let (manager_idx, manager_proc) = ring3_host_spawn(
        components::device_manager(),
        CERT_MANAGER_KSTACK_VA,
        1,
        CERT_MANAGER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1310,
    )?;
    let (driver_idx, driver_proc) = ring3_host_spawn(
        components::crypto_driver(),
        CERT_DRIVER_KSTACK_VA,
        0,
        CERT_DRIVER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1320,
    )?;
    // The certifier is told which driver this run is about, because it cannot
    // find out.
    let (certifier_idx, certifier_proc) = ring3_host_spawn(
        components::certifier(),
        CERT_CERTIFIER_KSTACK_VA,
        CERTIFIED_DRIVER_ID,
        CERT_CERTIFIER_PROC_OBJ,
        &mut kernel_space,
        frames,
        1330,
    )?;

    // SAFETY: transient raw access to the static process table.
    unsafe {
        let processes = &mut *(&raw mut KCORE_PROCESSES);
        {
            let manager = processes.get_mut(manager_proc).ok_or(1301u32)?;
            manager
                .handles_mut()
                .install(CERT_MANAGER_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1311u32)?;
            manager
                .handles_mut()
                .install(
                    CERT_DEVICE_OBJ,
                    Rights::READ | Rights::MAP | Rights::TRANSFER,
                )
                .map_err(|_| 1311u32)?;
        }
        {
            let driver = processes.get_mut(driver_proc).ok_or(1321u32)?;
            driver
                .handles_mut()
                .install(CERT_MANAGER_CLIENT_OBJ, Rights::WRITE)
                .map_err(|_| 1321u32)?;
            driver
                .handles_mut()
                .install(CERT_SERVER_OBJ, Rights::READ)
                .map_err(|_| 1321u32)?;
        }
        processes
            .get_mut(certifier_proc)
            .ok_or(1331u32)?
            .handles_mut()
            .install(CERT_CLIENT_OBJ, Rights::WRITE)
            .map_err(|_| 1331u32)?;
    }

    // Taken before the run, because the trace check reads it after the process
    // it names has been reaped.
    // SAFETY: transient raw access to the static process table; nothing else
    // holds a reference across this read.
    let driver_pid = unsafe {
        (*(&raw const KCORE_PROCESSES))
            .get(driver_proc)
            .map(|process| process.id().raw() as u64)
    }
    .ok_or(1322u32)?;

    EL0_SINK_LOG.store(0, Ordering::SeqCst);
    EL0_SINK_EXITED.store(false, Ordering::SeqCst);
    EL0_SINK_FAULT.store(0, Ordering::SeqCst);
    EL0_REPORT_COUNT.store(0, Ordering::SeqCst);
    for report in &EL0_REPORTS {
        report.store(0, Ordering::SeqCst);
    }

    // **Something to pull while ring 3 runs.** A PCI-to-PCI bridge behind a
    // root port, registered in the graph and held by nobody: the certification
    // subject is the crypto driver, and pulling *its* device is the next step
    // rather than this one. What is being shown here is only that a slot can be
    // answered and a device removed from inside a run — with a victim whose
    // going disturbs nothing else, so a failure here is about the mechanism.
    let host = tessera_pci::Host {
        ecam_base: pci.ecam_base,
        ecam_len: pci.ecam_len,
        first_bus: pci.first_bus,
        last_bus: pci.last_bus,
    };
    let watched = pullable_switch(host.first_bus, functions);
    if let Some((port, switch)) = watched {
        // SAFETY: transient raw access to the static executive.
        unsafe {
            let exec = (*(&raw mut KCORE_EXEC)).as_mut().ok_or(1307u32)?;
            exec.device_register_identified(
                CERT_VICTIM_OBJ,
                0,
                0,
                Rights::READ,
                kcore::devmgr::DeviceIdentity {
                    class_code: switch.class_code,
                    vendor: switch.vendor,
                    device: switch.device,
                    bdf: (u16::from(switch.bdf.bus) << 8)
                        | (u16::from(switch.bdf.device) << 3)
                        | u16::from(switch.bdf.function),
                    revision: switch.revision,
                    bus: kcore::devmgr::DeviceBus::Pci,
                },
            )
            .map_err(|_| 1308u32)?;
        }
        arm_slot_watch(&host, port.bdf, switch.bdf, CERT_VICTIM_OBJ);
        kprintln!(
            "certification-hotplug: armed — bridge {:02x}:{:02x}.{} in slot {:02x}:{:02x}.{}, awaiting a pull while ring 3 runs",
            switch.bdf.bus,
            switch.bdf.device,
            switch.bdf.function,
            port.bdf.bus,
            port.bdf.device,
            port.bdf.function
        );
        kcore::verdict::claims(&["cert.hotplug-armed"]);
    }

    // SAFETY: `frames` outlives the run; the pointer is cleared before
    // returning.
    let frames_ptr: *mut kcore::pmem::BumpFrameAllocator<'_> = frames;
    unsafe {
        EL0_DISPATCH_FRAMES = core::mem::transmute::<
            *mut kcore::pmem::BumpFrameAllocator<'_>,
            *mut kcore::pmem::BumpFrameAllocator<'static>,
        >(frames_ptr);
    }
    tessera_karch_aarch64::set_el0_sync_hook(el0_dispatch_hook);
    // The tick watches the slot for the whole run. Restored afterwards, so no
    // later check inherits a hook looking at hardware it does not know about.
    tessera_karch_aarch64::set_tick_hook(on_tick_watching_a_slot);
    tessera_karch_aarch64::GenericTimer::start_periodic(TICK_HZ);
    // SAFETY: transient raw access; `run` returns when nothing is runnable.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().run();
        }
    }
    // How much the tick saw **while ring 3 was still running**, read before
    // anything below can add to it. A removal that only landed afterwards is a
    // different and weaker claim, and the two must not be reported as one.
    let polls_during_run = SLOT_WATCH_POLLS.load(Ordering::SeqCst);

    // The pull is driven from outside and does not wait for this machine's
    // scheduler to run out of work, so the run ending is not the removal
    // failing. The timer is still going and the hook still looks; this gives it
    // a bounded window with interrupts open.
    if watched.is_some() {
        for _ in 0..SLOT_WATCH_SETTLE {
            if SLOT_WATCH_STATE.load(Ordering::SeqCst) == slot_watch::REMOVED {
                break;
            }
            // SAFETY: unmasking and re-masking at EL1 is a PSTATE write on the
            // boot CPU, which owns the machine here. `wfi` returns on the next
            // tick, and a masked one would never arrive at all.
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
                core::arch::asm!("wfi", options(nomem, nostack));
                core::arch::asm!("msr daifset, #2", options(nomem, nostack));
            }
        }
    }

    tessera_karch_aarch64::stop_timer();
    // **Back to doing nothing, not back to `on_tick`.** No hook is installed
    // when this check runs — `timer_check` installs the counting one later, and
    // its counter is never reset — so leaving a counting hook behind would have
    // every ring-3 run after this one increment it, and that check would find
    // its threshold already crossed before its own timer had ticked once.
    tessera_karch_aarch64::set_tick_hook(on_tick_idle);
    // SAFETY: single-threaded; the hook is done (every thread is off-CPU).
    unsafe { EL0_DISPATCH_FRAMES = core::ptr::null_mut() };
    // SAFETY: `boot_low` is the boot low-half space, active before this check.
    unsafe { boot_low.activate() };

    if EL0_SINK_FAULT.load(Ordering::SeqCst) != 0 {
        return Err(1340);
    }
    let report = EL0_REPORTS[0].load(Ordering::SeqCst);
    // Six separable claims, checked apart so a failure names which one.
    for (bit, which) in [
        (32u32, 1341u32),
        (33, 1342),
        (34, 1343),
        (35, 1344),
        (36, 1345),
        (37, 1346),
        (38, 1347),
        (39, 1349),
    ] {
        if report & (1 << bit) == 0 {
            return Err(which);
        }
    }
    // And exactly those two checks ran. A run that quietly recorded a third
    // would be the failure this whole facility is shaped against, so the mask
    // is compared rather than merely inspected for the two that matter.
    if report & 0xffff != CERTIFIER_EXPECTED & 0xffff {
        return Err(1348);
    }

    // **The check the certifier could not have made.** It holds one channel and
    // no view of the kernel's event ring, so the records this driver caused are
    // not something it could ever read — and a runner that only recorded what
    // one vantage could observe would be capped at that vantage forever. A
    // certificate aggregates outcomes from wherever they can be seen, so this
    // one is assembled here, from the certifier's two and boot's third.
    let (verdict, dma) = trace_schema_of(driver_pid);
    let mut runner = tessera_certification::Runner::new(tessera_certification::Subject {
        driver: CERTIFIED_DRIVER_ID as u32,
        class: CERTIFIED_DEVICE_CLASS,
        contract_version: CERTIFIED_CONTRACT_VERSION,
    });
    runner.record(
        tessera_certification::Check::AbiConformance,
        tessera_certification::Outcome::ran(report & (1 << 32) != 0),
    );
    runner.record(
        tessera_certification::Check::ClassConformance,
        tessera_certification::Outcome::ran(report & (1 << 33) != 0),
    );
    // Also the certifier's: power is a question a peer can ask, because it
    // holds the driver to its own `Describe` reply rather than to a wattmeter.
    runner.record(
        tessera_certification::Check::Power,
        tessera_certification::Outcome::ran(report & (1 << 38) != 0),
    );
    runner.record(
        tessera_certification::Check::SuspendResume,
        tessera_certification::Outcome::ran(report & (1 << 39) != 0),
    );
    runner.record(
        tessera_certification::Check::TraceSchema,
        tessera_certification::Outcome::ran(verdict.is_complete()),
    );
    runner.record(
        tessera_certification::Check::Fuzz,
        tessera_certification::Outcome::ran(fuzz_evidence_is_substantive()),
    );
    let policy = policy_compliance_of(driver_proc);
    runner.record(
        tessera_certification::Check::SecurityPolicy,
        tessera_certification::Outcome::ran(policy.is_compliant()),
    );
    runner.record(
        tessera_certification::Check::DmaFault,
        tessera_certification::Outcome::ran(dma.is_contained()),
    );
    runner.record(
        tessera_certification::Check::CrashRecovery,
        tessera_certification::Outcome::ran(recovered),
    );
    let certificate = runner.certificate();
    // A run that examined nothing must never read as a run that found nothing
    // wrong, so the count is a claim of its own and travels to the verdict line
    // — a reader who cannot see how much was looked at cannot weigh what was
    // found.
    if verdict.examined == 0 {
        return Err(1360);
    }
    if certificate.failures() != CERTIFIED_CHECKS_FAILED {
        // Which kind, so a failure names an event rather than the run.
        return Err(1349 + verdict.offending_kind.min(99));
    }
    if certificate.ran() != CERTIFIED_CHECKS_RAN {
        return Err(1449);
    }
    if certificate.is_certified() || certificate.missing().count_ones() != 2 {
        return Err(1450);
    }
    let encoded = encoded_certificate(&certificate)?;

    // The slot watch, as three separable facts. A machine with no pullable
    // bridge skips them, which a boot on a topology without one legitimately
    // is — and the script that drives the pull is what makes the difference
    // visible rather than this check assuming either way.
    if watched.is_some() {
        // The hook looked while ring 3 was still running. Without this the
        // whole mechanism could be a post-run poll wearing a tick's name.
        if polls_during_run == 0 {
            return Err(1451);
        }
        // The eject was answered by this guest. A device that left without the
        // slot ever asking would mean the watch was on the wrong port.
        if SLOT_WATCH_STATE.load(Ordering::SeqCst) == slot_watch::ARMED {
            return Err(1452);
        }
        if SLOT_WATCH_STATE.load(Ordering::SeqCst) != slot_watch::REMOVED {
            return Err(1453);
        }
        // And the graph acted rather than merely being told.
        if SLOT_WATCH_SUBTREE.load(Ordering::SeqCst) == 0 {
            return Err(1454);
        }
    }
    disarm_slot_watch();

    // SAFETY: transient raw access; all threads are off-CPU, removed once.
    unsafe {
        if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
            exec.scheduler().reap(certifier_idx);
            exec.scheduler().reap(driver_idx);
            exec.scheduler().reap(manager_idx);
        }
    }
    use tessera_karch::FrameSource;
    for kstack in [
        CERT_CERTIFIER_KSTACK_VA,
        CERT_DRIVER_KSTACK_VA,
        CERT_MANAGER_KSTACK_VA,
    ] {
        for page in 0..RING3_HOST_KSTACK_PAGES {
            if let Ok(frame) = kernel_space
                .arch_mut()
                .unmap(VirtAddr::new(kstack + page * FRAME_SIZE))
            {
                frames.free_frame(frame);
            }
        }
    }
    // SAFETY: transient raw access; each process is removed and torn down once.
    unsafe {
        for proc_idx in [certifier_proc, driver_proc, manager_proc] {
            if let Some(mut process) = (*(&raw mut KCORE_PROCESSES)).remove(proc_idx) {
                if let Some(exec) = (*(&raw mut KCORE_EXEC)).as_mut() {
                    exec.release_memory_of(process.id(), frames, None);
                }
                process.space_mut().teardown(frames);
            }
        }
    }
    Ok(CertificationCounts {
        trace_records: verdict.examined,
        capabilities: policy.examined,
        unscoped_grants: dma.unscoped,
        slot_polls: polls_during_run,
        certificate: encoded,
    })
}

// --- GPIO: one interrupt line becoming eight, and a button pressed from
// outside the machine (D156) ---

pub(crate) const GPIO_DEVICE_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x160);
pub(crate) const GPIO_MANAGER_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x161);
pub(crate) const GPIO_MANAGER_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x162);
pub(crate) const GPIO_MANAGER_SERVER2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x163);
pub(crate) const GPIO_MANAGER_CLIENT2_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x164);
pub(crate) const GPIO_IRQ_PORT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x165);
pub(crate) const GPIO_MANAGER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x166);
pub(crate) const GPIO_DRIVER_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x167);
pub(crate) const GPIO_CLIENT_A_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x168);
pub(crate) const GPIO_CLIENT_B_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x169);
/// The two service channels the driver serves, one per client.
pub(crate) const GPIO_SERVICE_A_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16a);
pub(crate) const GPIO_SERVICE_A_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16b);
pub(crate) const GPIO_SERVICE_B_SERVER_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16c);
pub(crate) const GPIO_SERVICE_B_CLIENT_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16d);
/// One port per line, at consecutive object ids.
pub(crate) const GPIO_LINE_PORT_BASE: u32 = 0x170;
/// The platform bus, and the process that walks it.
pub(crate) const PLATFORM_BUS_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16e);
pub(crate) const PLATFORM_BUS_PROC_OBJ: kcore::object::ObjectId = kcore::object::ObjectId::from_raw(0x16f);
pub(crate) const PLATFORM_BUS_KSTACK_VA: u64 = 0xffff_0009_e000_0000;

/// **What this bus forwards**, and therefore what it may declare devices in.
/// The `virt` machine's peripheral region: the console, the RTC, the GPIO
/// controller and the firmware configuration port. Deliberately not the
/// virtio-mmio transports a megabyte further up — a bus is granted a range and
/// a controller that wanted more would have to be given more, which is the
/// whole point of the range being on the capability.
pub(crate) const PLATFORM_FORWARD_BASE: u64 = 0x0900_0000;
pub(crate) const PLATFORM_FORWARD_LEN: u64 = 0x0004_0000;
/// The interrupt lines it may declare from: the first sixteen shared
/// peripheral interrupts, which is where this machine's peripherals sit.
pub(crate) const PLATFORM_FIRST_INTID: u32 = 32;
pub(crate) const PLATFORM_INTID_COUNT: u32 = 16;

/// The class code the bus controller declares a GPIO controller with — how
/// boot recognises which of the devices it declared is the one to route,
/// without knowing what a PL061 is or where it lives.
pub(crate) const PLATFORM_CLASS_GPIO: u32 = 0x08_8000;

pub(crate) const GPIO_MANAGER_KSTACK_VA: u64 = 0xffff_0009_a000_0000;
pub(crate) const GPIO_DRIVER_KSTACK_VA: u64 = 0xffff_0009_b000_0000;
pub(crate) const GPIO_CLIENT_A_KSTACK_VA: u64 = 0xffff_0009_c000_0000;
pub(crate) const GPIO_CLIENT_B_KSTACK_VA: u64 = 0xffff_0009_d000_0000;

/// The line QEMU's `virt` wires its power button to, and the one client A
/// watches. Read from the machine's own device tree — `gpio-keys/poweroff`
/// names `<&pl061 3 0>` — rather than chosen.
pub(crate) const GPIO_BUTTON_LINE: u32 = 3;
/// The line client B watches, which nothing is wired to. **The load-bearing
/// half of the check**: it must not wake.
pub(crate) const GPIO_QUIET_LINE: u32 = 5;

/// What a client reports: a tag, the line it watched, whether it was granted an
/// interrupt object, and whether that object fired naming its own line.
pub(crate) const GPIO_CLIENT_TAG: u64 = 0x91 << 56;
pub(crate) const GPIO_REPORT_WOKEN: u64 = 1 << 32;
pub(crate) const GPIO_REPORT_GRANTED: u64 = 1 << 33;
pub(crate) const GPIO_A_EXPECTED: u64 =
    GPIO_CLIENT_TAG | ((GPIO_BUTTON_LINE as u64) << 40) | GPIO_REPORT_GRANTED | GPIO_REPORT_WOKEN;

