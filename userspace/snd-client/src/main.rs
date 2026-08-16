// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ring-3 **audio client**: a `no_std` Rust program that plays into one
//! stream and deliberately abandons another.
//!
//! **The abandoned stream is the load-bearing half.** A check that played a
//! tone and asserted nothing else would pass against a driver that dropped
//! every period on the floor, because silence is what a broken audio path
//! produces too. So this program keeps one stream fed and requires it to have
//! consumed periods with no gap, and starts a second, hands it one period, and
//! requires the driver to notice that nothing followed.
//!
//! It also runs the class conformance suite over the driver, as `blk-client`
//! and `input-client` do — the same seven rules, a sixth contract.
//!
//! Normative: docs/drivers/03-graphics-display-media-sensors-ai.md ("Audio")

#![no_std]
#![no_main]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use audio_output::{
    AudioConfigRequest, AudioControlReply, AudioControlRequest, AudioDescribeReply, AudioError,
    AudioFormat, AudioOutput, AudioPowerState, AudioStatusReply, AudioVolumeRequest,
    AudioWriteReply, AudioWriteRequest,
};
use channel_msg::ChannelMsgArgs;
use tessera_class_conformance::{AUDIO, Described, Exchange, check};
use tessera_isl_runtime::{decode, encode};
use tessera_uabi::{fail, read_kernel_filled, syscall2};

/// Syscall numbers (kcore `SyscallNumber` ordinals — the stable ABI).
const SYS_DEBUG_WRITE: u64 = 1;
const SYS_PROCESS_EXIT: u64 = 5;
const SYS_CHANNEL_CALL: u64 = 14;

/// The one capability boot installs: the driver's service endpoint.
const DRIVER_ENDPOINT_HANDLE: u64 = 0;

/// The symmetric request/reply buffer.
const MSG_BUF_LEN: usize = 128;

/// The stream kept fed, and the one started and abandoned.
const FED_STREAM: u32 = 0;
const STARVED_STREAM: u32 = 1;

/// Bytes one write carries — what the contract's inline payload holds.
const CHUNK: usize = 64;

/// How many periods the fed stream must get through before this program is
/// satisfied. Small, because what is being proved is that the device consumes
/// at all and reports honestly, not how long it can keep going.
const PERIODS_TO_PLAY: u32 = 3;

/// How many times the starved stream is asked about before giving up on it
/// gapping. Bounded: a device that never consumes the one period it was given
/// is a device, not a hang, and this program says so rather than waiting.
const STARVE_POLLS: u32 = 200_000;

/// Ordinals at or above this belong to a vendor extension namespace.
const VENDOR_ORDINAL_BASE: u32 = 0x8000_0000;

/// Exchanges the conformance transcript holds.
const TRANSCRIPT_LEN: usize = 10;

/// What this program reports: a tag, and what it found.
const REPORT_TAG: u64 = 0xa0 << 56;
/// The conformance suite came back complete.
const REPORT_CONFORMANT: u64 = 1 << 32;
/// The fed stream played the periods it was given.
const REPORT_PLAYED_CLEAN: u64 = 1 << 33;
/// The abandoned stream reported one. **The half that cannot be faked by
/// silence.**
const REPORT_UNDERRAN: u64 = 1 << 34;

/// Writes a `ChannelMsgArgs` naming a method.
fn channel_args(buf_ptr: u64, method: u32) -> Result<[u8; ChannelMsgArgs::WIRE_SIZE], u64> {
    let args = ChannelMsgArgs {
        size: ChannelMsgArgs::WIRE_SIZE as u32,
        version: 4,
        flags: 0,
        interface_id: 0,
        txn_id: 0,
        method_id: method,
        msg_flags: 0,
        inline_ptr: buf_ptr,
        inline_len: MSG_BUF_LEN as u64,
        handles_ptr: 0,
        handle_count: 0,
        installed_ptr: 0,
        installed_cap: 0,
    };
    let mut out = [0u8; ChannelMsgArgs::WIRE_SIZE];
    match encode(&args, &mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(fail(0xa0, 0xe)),
    }
}

/// One call to the driver. The reply lands back in the same buffer.
fn call(buf: &mut [u8; MSG_BUF_LEN], method: u32) -> Result<(), u64> {
    let args = channel_args(buf.as_ptr() as u64, method)?;
    let n = syscall2(
        SYS_CHANNEL_CALL,
        args.as_ptr() as u64,
        DRIVER_ENDPOINT_HANDLE,
    );
    if n < 0 {
        return Err(fail(0xa1, (-n) as u64));
    }
    Ok(())
}

/// A control request, which is what five of this contract's methods take.
fn control_request(stream: u32, state: AudioPowerState) -> AudioControlRequest {
    AudioControlRequest {
        size: AudioControlRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream,
        state,
    }
}

/// An exchange the driver did not answer at all.
///
/// Recorded rather than skipped: a method that produced no reply is a different
/// failure from one that replied badly, and a transcript that omitted it would
/// let the suite report every rule as passing.
fn unanswered(ordinal: u32) -> Exchange {
    Exchange {
        ordinal,
        status: 0,
        answered: false,
        detail: 0,
    }
}

/// Calls a method taking a control request.
fn control(msg_buf: &mut [u8; MSG_BUF_LEN], method: u32, stream: u32) -> Exchange {
    let request = control_request(stream, AudioPowerState::Active);
    if encode(&request, &mut msg_buf[..AudioControlRequest::WIRE_SIZE]).is_err() {
        return unanswered(method);
    }
    if call(msg_buf, method).is_err() {
        return unanswered(method);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<AudioControlReply>(&bytes[..AudioControlReply::WIRE_SIZE]) {
        Ok(reply) => Exchange {
            ordinal: method,
            status: reply.status as u32,
            answered: true,
            // The power state a reset left, which is the one thing the suite
            // checks beyond the status.
            detail: reply.state as u32,
        },
        Err(_) => unanswered(method),
    }
}

/// Configures a stream for what this driver plays.
fn configure(msg_buf: &mut [u8; MSG_BUF_LEN], stream: u32, rate: u32) -> Exchange {
    let request = AudioConfigRequest {
        size: AudioConfigRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream,
        channels: 2,
        format: AudioFormat::S16,
        rate,
    };
    if encode(&request, &mut msg_buf[..AudioConfigRequest::WIRE_SIZE]).is_err() {
        return unanswered(AudioOutput::CONFIGURE);
    }
    if call(msg_buf, AudioOutput::CONFIGURE).is_err() {
        return unanswered(AudioOutput::CONFIGURE);
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    match decode::<AudioControlReply>(&bytes[..AudioControlReply::WIRE_SIZE]) {
        Ok(reply) => Exchange {
            ordinal: AudioOutput::CONFIGURE,
            status: reply.status as u32,
            answered: true,
            detail: 0,
        },
        Err(_) => unanswered(AudioOutput::CONFIGURE),
    }
}

/// Hands one chunk of samples over, and says what came back.
fn write(msg_buf: &mut [u8; MSG_BUF_LEN], stream: u32, seed: u8) -> Option<AudioWriteReply> {
    let mut samples = [0u8; CHUNK];
    // A ramp rather than zeros, so what is handed over is distinguishable from
    // the silence a device plays when nothing is.
    for (index, byte) in samples.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    let request = AudioWriteRequest {
        size: AudioWriteRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream,
        length: CHUNK as u32,
        samples,
    };
    if encode(&request, &mut msg_buf[..AudioWriteRequest::WIRE_SIZE]).is_err() {
        return None;
    }
    if call(msg_buf, AudioOutput::WRITE).is_err() {
        return None;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    decode::<AudioWriteReply>(&bytes[..AudioWriteReply::WIRE_SIZE]).ok()
}

/// Asks a stream what it has done.
fn status(msg_buf: &mut [u8; MSG_BUF_LEN], stream: u32) -> Option<AudioStatusReply> {
    let request = control_request(stream, AudioPowerState::Active);
    if encode(&request, &mut msg_buf[..AudioControlRequest::WIRE_SIZE]).is_err() {
        return None;
    }
    if call(msg_buf, AudioOutput::STATUS).is_err() {
        return None;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(msg_buf);
    decode::<AudioStatusReply>(&bytes[..AudioStatusReply::WIRE_SIZE]).ok()
}

/// The whole program.
fn run() -> u64 {
    let mut found = REPORT_TAG;
    let mut msg_buf = [0u8; MSG_BUF_LEN];

    // Describe first: the period and how many the device holds are what a
    // client needs before it can keep up, and guessing them is the failure this
    // contract reports rather than suffers.
    let request = control_request(0, AudioPowerState::Active);
    if encode(&request, &mut msg_buf[..AudioControlRequest::WIRE_SIZE]).is_err() {
        return fail(0xa2, 0);
    }
    if let Err(code) = call(&mut msg_buf, AudioOutput::DESCRIBE) {
        return code;
    }
    let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
    let described: AudioDescribeReply = match decode(&bytes[..AudioDescribeReply::WIRE_SIZE]) {
        Ok(described) => described,
        Err(_) => return fail(0xa2, 1),
    };
    if described.status != AudioError::Ok || described.streams < 2 {
        return fail(0xa2, 2);
    }
    if described.period_bytes == 0 || described.periods == 0 {
        return fail(0xa2, 3);
    }
    let mut transcript = [unanswered(0); TRANSCRIPT_LEN];
    transcript[0] = Exchange {
        ordinal: AudioOutput::DESCRIBE,
        status: described.status as u32,
        answered: true,
        detail: 0,
    };

    // **A rate this driver does not do, refused rather than converted.** A
    // client that asked for one rate and silently got another would hear its
    // audio at the wrong speed and have nothing to check — so the refusal is
    // asked for before the stream that works.
    let refused = configure(&mut msg_buf, FED_STREAM, 48_000);
    if refused.status != AudioError::BadFormat as u32 {
        return fail(0xa3, refused.status as u64);
    }

    transcript[1] = configure(&mut msg_buf, FED_STREAM, 44_100);
    if transcript[1].status != AudioError::Ok as u32 {
        return fail(0xa4, transcript[1].status as u64);
    }
    transcript[2] = control(&mut msg_buf, AudioOutput::START, FED_STREAM);

    // Keep it fed. Every write is a chunk; the driver assembles periods out of
    // them and hands each one over as it completes.
    let chunks_per_period = described.period_bytes / CHUNK as u32;
    let mut wrote = 0u32;
    let mut seed = 1u8;
    let mut write_exchange = unanswered(AudioOutput::WRITE);
    while wrote < chunks_per_period * (PERIODS_TO_PLAY + described.periods) {
        let Some(reply) = write(&mut msg_buf, FED_STREAM, seed) else {
            return fail(0xa5, 0);
        };
        write_exchange = Exchange {
            ordinal: AudioOutput::WRITE,
            status: reply.status as u32,
            answered: true,
            detail: 0,
        };
        // The device is holding all it can, which is the stream working: wait
        // rather than buffer without bound.
        if reply.status == AudioError::Busy {
            continue;
        }
        if reply.status != AudioError::Ok && reply.status != AudioError::Underrun {
            return fail(0xa5, reply.status as u64);
        }
        wrote += 1;
        seed = seed.wrapping_add(7);
    }
    transcript[3] = write_exchange;

    let Some(played) = status(&mut msg_buf, FED_STREAM) else {
        return fail(0xa6, 0);
    };
    // The numbers, not just the verdict: a checker outside this program can see
    // *how* a stream did rather than only whether it satisfied a threshold, and
    // a run that fell one period short reads differently from one that gapped.
    found |= u64::from(played.played) & 0xffff;
    found |= (u64::from(played.underruns) & 0xffff) << 16;
    // **What is claimed is that the periods it was given were played**, and not
    // that it never gapped while playing them.
    //
    // Requiring no underrun asserted a real-time property: that this client
    // wins a race against a device consuming in real time, on a host that
    // promises nothing about when this program runs. It held on an idle machine
    // and failed on a busy one — three times in five when the boot matrix ran
    // its other twenty-three QEMUs alongside — reporting six periods played and
    // one gap. Nothing about the driver differed between those runs.
    //
    // It also contradicted this check's own verdict, which says keeping a
    // stream fed is *not* proven here, for exactly this reason. The count stays
    // in the report above, where a reader can see a stream that hiccupped and a
    // stream that ran dry are not the same thing; what distinguishes an
    // attentive client from a negligent one is the starved stream below, which
    // needs no timing to be true.
    if played.played >= PERIODS_TO_PLAY {
        found |= REPORT_PLAYED_CLEAN;
    }

    // **And now the half that silence cannot fake.** A second stream is
    // configured, primed and started exactly as the first one was, and then
    // abandoned. The device drains what it was given, asks for the next period,
    // and there is none — which nothing in the machine records except the
    // driver.
    if configure(&mut msg_buf, STARVED_STREAM, 44_100).status != AudioError::Ok as u32 {
        return fail(0xa7, 0);
    }
    // **Primed exactly as the fed one was, and then abandoned.** Starting it
    // empty would have it gap immediately whatever this program did next, and
    // the check would pass even against a client that kept feeding it — so the
    // two streams begin identically and differ only in what happens after.
    for index in 0..chunks_per_period * described.periods {
        if write(&mut msg_buf, STARVED_STREAM, index as u8).is_none() {
            return fail(0xa7, 1);
        }
    }
    control(&mut msg_buf, AudioOutput::START, STARVED_STREAM);
    let mut starved = None;
    for _ in 0..STARVE_POLLS {
        let Some(reply) = status(&mut msg_buf, STARVED_STREAM) else {
            return fail(0xa7, 2);
        };
        if reply.underruns > 0 {
            starved = Some(reply);
            break;
        }
    }
    if starved.is_some() {
        found |= REPORT_UNDERRAN;
    }

    // The rest of the transcript: the optional this driver has, the optional it
    // does not, a reset, a power change and a vendor ordinal nobody negotiated.
    transcript[4] = control(&mut msg_buf, AudioOutput::STOP, FED_STREAM);
    let volume = AudioVolumeRequest {
        size: AudioVolumeRequest::WIRE_SIZE as u32,
        version: 1,
        flags: 0,
        stream: FED_STREAM,
        attenuation_centibels: 600,
    };
    transcript[5] = if encode(&volume, &mut msg_buf[..AudioVolumeRequest::WIRE_SIZE]).is_ok()
        && call(&mut msg_buf, AudioOutput::SET_VOLUME).is_ok()
    {
        let bytes = read_kernel_filled::<MSG_BUF_LEN>(&msg_buf);
        match decode::<AudioControlReply>(&bytes[..AudioControlReply::WIRE_SIZE]) {
            Ok(reply) => Exchange {
                ordinal: AudioOutput::SET_VOLUME,
                status: reply.status as u32,
                answered: true,
                detail: 0,
            },
            Err(_) => unanswered(AudioOutput::SET_VOLUME),
        }
    } else {
        unanswered(AudioOutput::SET_VOLUME)
    };
    transcript[6] = control(&mut msg_buf, AudioOutput::RESET, 0);
    transcript[7] = control(&mut msg_buf, AudioOutput::SET_POWER, 0);
    // Status again after the reset, so the required method is in the transcript
    // in a state the contract defines.
    transcript[8] = match status(&mut msg_buf, FED_STREAM) {
        Some(reply) => Exchange {
            ordinal: AudioOutput::STATUS,
            status: reply.status as u32,
            answered: true,
            detail: 0,
        },
        None => unanswered(AudioOutput::STATUS),
    };
    transcript[9] = control(&mut msg_buf, VENDOR_ORDINAL_BASE, 0);

    let report = check(
        &AUDIO,
        &Described {
            contract_version: described.contract_version,
            features: described.features,
            vendor: described.vendor_namespace,
        },
        &transcript,
    );
    if report.is_complete() {
        found |= REPORT_CONFORMANT;
    }
    found
}

/// Reports a value to the kernel's sink and never returns.
fn exit_reporting(value: u64) -> ! {
    let _ = syscall2(SYS_DEBUG_WRITE, value, 0);
    let _ = syscall2(SYS_PROCESS_EXIT, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// Entry point; the kernel starts this thread at the ELF's entry address.
///
// SAFETY: `no_mangle` gives this function the name the linker script's ENTRY
// resolves, which is what makes it the ELF's entry point. Nothing else in the
// program is exported, so there is no symbol to collide with.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_arg: u64) -> ! {
    exit_reporting(run())
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit_reporting(fail(0xff, 0))
}
