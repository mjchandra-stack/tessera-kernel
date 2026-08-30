// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! TCP: the segment, and the connection state a client needs to open one,
//! carry bytes over it, and close it.
//!
//! **What is here, and what is deliberately not.** This opens a connection,
//! sends and receives data in order, and closes both directions. It has **no
//! retransmission timer**, no congestion control, no reassembly of
//! out-of-order segments, and no window scaling. Those are not oversights and
//! they are not small: the first of them needs a clock, and a ring-3 program
//! in this tree has none — `docs/api/01`'s clock family is *designed* and
//! unimplemented, so a stack here cannot know that an acknowledgement is late.
//!
//! **So the honest claim is narrow.** Over a link that does not lose segments
//! this completes a connection and moves bytes correctly; over one that does,
//! it stalls rather than recovers, and it stalls silently. `docs/roadmap/03`
//! Phase 3 asks that *"the machine completes a TCP connection to the host"*,
//! and that is what this does — the connection, not a transport a service
//! should be built on. What turns it into one is a timer, and the timer is a
//! syscall that does not exist yet.
//!
//! **The state machine lives here rather than in the service**, so it can be
//! exercised on the host — the `api/ext2` argument: the protocol logic is
//! testable without a machine, and the ring-3 program that drives it only
//! moves bytes. A state machine reachable only through QEMU is one whose
//! corner cases nobody tests.
//!
//! Normative: docs/network/01-network-stack.md

use crate::udp::Peers;

/// TCP's protocol number, in both families.
pub const PROTOCOL: u8 = 6;

/// A header with no options, which is all this module writes.
pub const HEADER_LEN: usize = 20;

/// Header flags.
pub mod flag {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

/// The window this end advertises.
///
/// **One segment's worth, and fixed.** A window that never changes is a window
/// that cannot deadlock a peer through a mistake in updating it, and this end
/// consumes everything it is sent the moment it arrives. A real window moves
/// with the receive buffer, which is a thing this stack does not have.
pub const WINDOW: u16 = 4096;

/// A parsed segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
}

impl Segment<'_> {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// How much of the sequence space this segment occupies: its payload, plus
    /// one for each of SYN and FIN.
    ///
    /// **SYN and FIN consume a sequence number**, which is the arithmetic
    /// everything else depends on: an acknowledgement that did not count them
    /// would be one short forever, and the connection would hang on the first
    /// handshake rather than fail in a way anyone could read.
    pub fn sequence_len(&self) -> u32 {
        let mut n = self.payload.len() as u32;
        if self.has(flag::SYN) {
            n += 1;
        }
        if self.has(flag::FIN) {
            n += 1;
        }
        n
    }
}

/// Writes a segment and its payload, checksum included.
#[allow(clippy::too_many_arguments)]
pub fn write(
    out: &mut [u8],
    peers: Peers,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Option<usize> {
    let len = HEADER_LEN.checked_add(payload.len())?;
    let segment = out.get_mut(..len)?;
    segment[0..2].copy_from_slice(&src_port.to_be_bytes());
    segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
    segment[4..8].copy_from_slice(&seq.to_be_bytes());
    segment[8..12].copy_from_slice(&ack.to_be_bytes());
    // Data offset in 32-bit words, in the high nibble. No options, so five.
    segment[12] = ((HEADER_LEN / 4) as u8) << 4;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&WINDOW.to_be_bytes());
    segment[16..18].copy_from_slice(&0u16.to_be_bytes()); // zeroed while summed
    segment[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer
    segment[HEADER_LEN..].copy_from_slice(payload);

    let sum = peers
        .pseudo_header(PROTOCOL, u16::try_from(len).ok()?)
        .add(segment)
        .fold();
    // **Never zero.** TCP has no "not computed" encoding — unlike UDP over
    // IPv4, where zero means exactly that — so a folded zero goes out as all
    // ones and a received zero is a segment to refuse.
    let on_wire = if sum == 0 { 0xffff } else { sum };
    segment[16..18].copy_from_slice(&on_wire.to_be_bytes());
    Some(len)
}

/// Parses a segment, verifying the checksum against the addresses it arrived
/// on.
///
/// Refuses a segment too short for a header, one whose data offset lies
/// outside it, and one whose checksum does not verify — including a zero,
/// which TCP never means as "not computed".
pub fn parse(segment: &[u8], peers: Peers) -> Option<Segment<'_>> {
    let header = segment.get(..HEADER_LEN)?;
    let offset = (header[12] >> 4) as usize * 4;
    if offset < HEADER_LEN || offset > segment.len() {
        return None;
    }
    let len = u16::try_from(segment.len()).ok()?;
    if peers.pseudo_header(PROTOCOL, len).add(segment).fold() != 0 {
        return None;
    }
    Some(Segment {
        src_port: u16::from_be_bytes([header[0], header[1]]),
        dst_port: u16::from_be_bytes([header[2], header[3]]),
        seq: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        ack: u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
        flags: header[13],
        window: u16::from_be_bytes([header[14], header[15]]),
        // Options are skipped rather than read: none of the ones a peer may
        // send changes what this module does with the bytes after them.
        payload: segment.get(offset..)?,
    })
}

/// Where a connection is.
///
/// **The states this stack can be in, and no more.** RFC 793 has eleven; the
/// ones absent here are the passive-open half (`LISTEN`, `SYN-RECEIVED`) and
/// the simultaneous-close corner (`CLOSING`), because nothing here listens and
/// nothing closes at the same instant as its peer on a link with one of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing sent.
    Closed,
    /// A SYN is out and its acknowledgement has not come back.
    SynSent,
    /// Both directions are open.
    Established,
    /// This end sent a FIN and is waiting for it to be acknowledged.
    FinWait,
    /// Both ends have sent FIN and this one has acknowledged its peer's.
    Done,
    /// The peer refused, or the connection was reset.
    Reset,
}

/// One connection's sequence state.
///
/// **No buffers.** A caller hands bytes to [`Connection::send`] and takes them
/// from [`Connection::deliver`] as they arrive; nothing is held for
/// retransmission because nothing can retransmit. That makes this a state
/// machine rather than a transport, which is the honest description.
#[derive(Debug, Clone, Copy)]
pub struct Connection {
    pub state: State,
    pub local_port: u16,
    pub remote_port: u16,
    /// The next sequence number this end will send.
    pub snd_nxt: u32,
    /// The oldest sequence number this end has sent and not seen acknowledged.
    pub snd_una: u32,
    /// The next sequence number this end expects to receive.
    pub rcv_nxt: u32,
    /// Whether the peer's FIN has been seen.
    pub peer_finished: bool,
}

impl Connection {
    /// Opens a connection from `local_port` to `remote_port`, starting at
    /// `isn`.
    ///
    /// **The initial sequence number is the caller's**, for the reason the
    /// DHCP transaction id is: it should be unpredictable, the kernel CSPRNG
    /// is the only randomness a program here may use, and a state machine does
    /// not get to call one. A predictable ISN lets an off-path attacker inject
    /// into the stream, which is worth stating rather than hiding.
    pub fn connect(local_port: u16, remote_port: u16, isn: u32) -> Self {
        Connection {
            state: State::SynSent,
            local_port,
            remote_port,
            snd_nxt: isn.wrapping_add(1),
            snd_una: isn,
            rcv_nxt: 0,
            peer_finished: false,
        }
    }

    /// The SYN that opens it.
    pub fn syn(&self, out: &mut [u8], peers: Peers) -> Option<usize> {
        write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            self.snd_una,
            0,
            flag::SYN,
            &[],
        )
    }

    /// A bare acknowledgement of everything received so far.
    pub fn ack(&self, out: &mut [u8], peers: Peers) -> Option<usize> {
        write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            self.snd_nxt,
            self.rcv_nxt,
            flag::ACK,
            &[],
        )
    }

    /// Sends `payload`, advancing the send sequence.
    ///
    /// The segment carries `PSH` because this stack has no send buffer to
    /// coalesce into: every write is a segment, and telling the peer to hand
    /// it up immediately is the truth about what happened.
    pub fn send(&mut self, out: &mut [u8], peers: Peers, payload: &[u8]) -> Option<usize> {
        if self.state != State::Established {
            return None;
        }
        let len = write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            self.snd_nxt,
            self.rcv_nxt,
            flag::ACK | flag::PSH,
            payload,
        )?;
        self.snd_nxt = self.snd_nxt.wrapping_add(payload.len() as u32);
        Some(len)
    }

    /// Closes this end, sending a FIN.
    pub fn close(&mut self, out: &mut [u8], peers: Peers) -> Option<usize> {
        if self.state != State::Established {
            return None;
        }
        let len = write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            self.snd_nxt,
            self.rcv_nxt,
            flag::ACK | flag::FIN,
            &[],
        )?;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = State::FinWait;
        Some(len)
    }

    /// Takes a segment addressed to this connection and advances the state.
    ///
    /// Returns how many bytes of `segment`'s payload are new data for the
    /// caller — always a prefix, because anything out of order is dropped
    /// rather than held. `reply` is filled with the acknowledgement this end
    /// owes, if it owes one.
    ///
    /// **Out-of-order segments are dropped, not queued**, and the drop is why
    /// this needs a lossless link: a real receiver holds them until the gap
    /// fills, and holding them is the reassembly queue this does not have.
    pub fn on_segment(
        &mut self,
        segment: &Segment<'_>,
        out: &mut [u8],
        peers: Peers,
    ) -> (usize, Option<usize>) {
        if segment.dst_port != self.local_port || segment.src_port != self.remote_port {
            return (0, None);
        }
        if segment.has(flag::RST) {
            self.state = State::Reset;
            return (0, None);
        }
        match self.state {
            State::SynSent => {
                if segment.has(flag::SYN) && segment.has(flag::ACK) {
                    // The peer's ISN, and its SYN occupies one number.
                    self.rcv_nxt = segment.seq.wrapping_add(1);
                    self.snd_una = segment.ack;
                    self.state = State::Established;
                    let len = self.ack(out, peers);
                    return (0, len);
                }
                (0, None)
            }
            State::Established | State::FinWait => {
                // Only the segment that starts exactly where this end is
                // expecting is taken; anything else is a gap or a repeat.
                if segment.seq != self.rcv_nxt {
                    // Re-acknowledge, which is what tells a peer it has to
                    // send again — the closest this stack comes to recovery.
                    return (0, self.ack(out, peers));
                }
                if segment.has(flag::ACK) {
                    self.snd_una = segment.ack;
                }
                let data = segment.payload.len();
                self.rcv_nxt = self.rcv_nxt.wrapping_add(segment.sequence_len());
                if segment.has(flag::FIN) {
                    self.peer_finished = true;
                    if self.state == State::FinWait && self.snd_una == self.snd_nxt {
                        self.state = State::Done;
                    }
                }
                let owes_ack = data > 0 || segment.has(flag::FIN);
                let reply = if owes_ack { self.ack(out, peers) } else { None };
                (data, reply)
            }
            _ => (0, None),
        }
    }
}
