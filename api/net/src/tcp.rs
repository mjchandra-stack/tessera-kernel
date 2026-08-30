// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! TCP: the segment, and the connection state a client needs to open one,
//! carry bytes over it, and close it.
//!
//! **What is here, and what is deliberately not.** This opens a connection,
//! sends and receives data in order, retransmits what is not acknowledged, and
//! closes both directions. It has no congestion control, no reassembly of
//! out-of-order segments, and no window scaling.
//!
//! **The retransmission timer is RFC 6298**, and it is what stopped this being
//! a state machine and made it a transport. A segment that is sent is held
//! until it is acknowledged; the round-trip time is measured and the timeout
//! derived from it rather than fixed; a timeout that fires doubles the next
//! one; and a segment that goes unacknowledged past the attempt limit gives
//! up loudly, in [`State::Aborted`], rather than leaving the caller waiting
//! for a byte that is never coming. It needed a clock, which is why it could
//! not be written until there was one (`build/README.md`, D281).
//!
//! **The time is the caller's, not this module's**, for the reason the initial
//! sequence number is: a `no_std` protocol module that read a clock would be
//! one that could only be tested at the speed the host happened to run at.
//! Every entry point that can arm or disarm the timer takes `now` in monotonic
//! nanoseconds, so a test drives a retransmission by naming a moment.
//!
//! **The send buffer is [`MAX_UNACKED`] segments deep**, held oldest first. A
//! write goes out immediately and stays held until it is acknowledged; an
//! acknowledgement is cumulative and releases a prefix; a timeout retransmits
//! the front of the queue and nothing else, because sending the whole buffer
//! again turns one loss into a burst. What may be in flight is bounded by the
//! buffer and by the window the peer advertises, and a write past either is
//! refused rather than sent unrecoverably.
//!
//! **What that buys is the round trip.** With a single held segment every
//! write waited for the previous one to be acknowledged, so a connection moved
//! one segment per RTT however fast the link was. What it does not buy is a
//! cheaper retransmission: the segment is rebuilt from what is held, and the
//! frame around it is built again from scratch by whoever sends it.
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

/// Writes a segment and its payload, checksum included, advertising this end's
/// fixed [`WINDOW`].
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
    write_with_window(out, peers, src_port, dst_port, seq, ack, flags, payload, WINDOW)
}

/// As [`write`], with the advertised receive window chosen.
///
/// **Separate because this end's window does not move and a peer's does.**
/// [`WINDOW`] is fixed here for the reason its own note gives — there is no
/// receive buffer for it to track — so every segment this stack sends carries
/// the same number, and [`write`] is the right entry point for all of them.
/// What needs the other one is anything modelling a peer: a receiver filling
/// up says so by shrinking its window, and a sender that could not be shown a
/// shrinking window is a sender whose handling of one is untested. It becomes
/// this module's own entry point the day the receive window moves.
#[allow(clippy::too_many_arguments)]
pub fn write_with_window(
    out: &mut [u8],
    peers: Peers,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    window: u16,
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
    segment[14..16].copy_from_slice(&window.to_be_bytes());
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

/// The retransmission timeout before any round trip has been measured, in
/// nanoseconds — RFC 6298 (2.1).
pub const INITIAL_RTO_NANOS: u64 = 1_000_000_000;

/// The floor under a computed timeout.
///
/// **200 ms, where RFC 6298 (2.4) says one second, and the deviation is
/// deliberate.** That rule is a SHOULD whose stated purpose is to keep a
/// sender from retransmitting spuriously across the open internet, where the
/// round-trip time this arithmetic estimates can be wrong by a lot. Linux has
/// used 200 ms (`TCP_RTO_MIN`) for the same reason it is used here: on a link
/// whose round trip is measured in microseconds, a one-second floor is not
/// conservatism but a second of doing nothing after a loss. Stated rather than
/// silently chosen, because it is the one place this module knowingly departs
/// from the RFC it names.
pub const MIN_RTO_NANOS: u64 = 200_000_000;

/// The ceiling, RFC 6298 (2.5)'s "may be used to provide an upper bound".
pub const MAX_RTO_NANOS: u64 = 60_000_000_000;

/// The clock granularity this arithmetic assumes, RFC 6298's `G`.
///
/// It appears only in `RTO = SRTT + max(G, 4 * RTTVAR)`, where it keeps the
/// timeout from collapsing onto the smoothed round trip when the variance
/// estimate reaches zero — which it does on a link as regular as an emulated
/// one.
pub const CLOCK_GRANULARITY_NANOS: u64 = 1_000_000;

/// How many times a segment is sent again before the connection is given up
/// on.
///
/// **RFC 1122 (4.2.3.5)'s `R1`, as a count**: how many times a segment is sent
/// again before this end stops trying that way.
///
/// Three, which is what that section asks for. It is a backstop rather than
/// the usual reason a connection ends — [`GIVE_UP_NANOS`] below almost always
/// reaches first — and it is here because a bound that depends only on a clock
/// is a bound that disappears on a machine whose clock stops.
pub const MAX_RETRANSMISSIONS: u8 = 3;

/// **RFC 1122's `R2`, as a time**: how long a segment may go unacknowledged
/// before the connection is given up on, measured from when it was *first*
/// sent.
///
/// **A time and not a count, because that is what the specification says**,
/// and because a count means something different at every round-trip time. It
/// also lands where a reader expects: from a fresh connection the attempts
/// fall at 1, 3 and 7 seconds — one initial timeout, then doubling — and the
/// connection ends at 8. A pure count of three would end it at 15, waiting out
/// a fourth timeout that has already been decided.
///
/// **Eight seconds, where RFC 1122 asks for at least 100.** The third and last
/// deliberate departure in this module, and the same reasoning as
/// [`MIN_RTO_NANOS`]: that number is sized for the open internet, and every
/// link this stack has ever run on is local. A client here is better served
/// learning in eight seconds that its peer is not answering than in a minute
/// and a half.
pub const GIVE_UP_NANOS: u64 = 8_000_000_000;

/// The largest payload a single segment may carry here, and so the largest
/// this end can hold for retransmission.
///
/// **A write larger than this is refused, not truncated and not sent.** A
/// segment that cannot be held cannot be retransmitted, and a transport that
/// silently sent one would be back to stalling on the first loss — with the
/// stall now hidden behind a timer that appears to work.
///
/// **256, and the number is a copying cost rather than a protocol limit.** A
/// real send window is as large as the receiver advertises; this one is
/// bounded by the fact that [`Connection`] is `Copy` and a service holding it
/// by value copies the whole thing on every segment. Growing it is a decision
/// about that, not about TCP.
pub const MAX_SEGMENT_PAYLOAD: usize = 256;

/// How many segments may be in flight at once.
///
/// **Four, which with [`MAX_SEGMENT_PAYLOAD`] is a kilobyte of send buffer.**
/// The number that matters is that it is more than one: a window of one
/// segment makes every write wait a round trip, so a connection moves one
/// segment per RTT no matter how fast the link is. Four is chosen to be small
/// enough that the buffer is a fixed array in a `no_std` module with no
/// allocator, and the real ceiling on it is the peer's advertised window,
/// which is read and honoured (`Connection::snd_wnd`).
pub const MAX_UNACKED: usize = 4;

/// A segment this end has sent and not seen acknowledged.
///
/// **Held by value, because there is nowhere else to hold it.** A `no_std`
/// protocol module has no allocator, and the caller's buffer is gone the
/// moment the caller returns — so what is retransmitted has to be rebuilt from
/// what is kept here, not from a pointer to what was sent.
#[derive(Debug, Clone, Copy)]
struct Unacked {
    /// The sequence number the segment starts at.
    seq: u32,
    flags: u8,
    len: usize,
    payload: [u8; MAX_SEGMENT_PAYLOAD],
    /// How much of the sequence space it occupies — its payload, plus one for
    /// each of SYN and FIN.
    span: u32,
    /// When it was **first** sent. The round-trip sample is measured from
    /// here, and only when it has never been retransmitted.
    sent_at: u64,
    /// When to give up waiting and send it again.
    deadline: u64,
    retransmits: u8,
}

/// Whether `a` is at or before `b` in the sequence space, which wraps.
///
/// **Subtract and look at the sign, never compare directly.** Sequence numbers
/// are 32 bits and wrap; `a <= b` on the raw values is wrong for exactly the
/// half of the space that matters, and the failure is a connection that stops
/// acknowledging four gigabytes in.
fn seq_leq(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
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
    /// A segment went unacknowledged through every retransmission this end
    /// will make, and the connection was given up on.
    ///
    /// **Distinct from [`Reset`](State::Reset)**, which is the peer saying no.
    /// This is the peer saying nothing, and the two call for different things
    /// from a caller: a reset connection was refused and will be refused
    /// again, while an aborted one met a link or a peer that stopped and may
    /// work on a second attempt.
    Aborted,
}

/// One connection's sequence state, its send buffer, and its retransmission
/// timer.
///
/// **Not `Copy`, deliberately.** It holds [`MAX_UNACKED`] segments of up to
/// [`MAX_SEGMENT_PAYLOAD`] bytes each, which is about a kilobyte — small for a
/// send buffer and far too large to copy on a per-packet path. A service holds
/// one and borrows it; the version of this with a single held segment was
/// `Copy` and was copied in and out of the stack instance twice per frame.
#[derive(Debug, Clone)]
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
    /// The smoothed round-trip time, RFC 6298's `SRTT`. `None` until the first
    /// sample, which is what selects between the RFC's (2.2) and (2.3) rules.
    pub srtt: Option<u64>,
    /// The round-trip variation, RFC 6298's `RTTVAR`.
    pub rttvar: u64,
    /// The current retransmission timeout, RFC 6298's `RTO`.
    ///
    /// Public because it is the thing worth watching: a timer whose timeout
    /// never moves is one that measured nothing.
    pub rto: u64,
    /// How many segments this end has sent again. A count rather than a flag,
    /// because "it retransmitted" and "it retransmitted eleven times" are
    /// different reports about a link.
    pub retransmissions: u32,
    /// The segments sent and not yet acknowledged, **oldest first**.
    ///
    /// The order is the whole of the structure: RFC 6298 (5.4) retransmits the
    /// earliest unacknowledged segment and nothing else, an acknowledgement is
    /// cumulative and so releases a prefix, and the timer belongs to whatever
    /// is at the front. A queue that was not kept in order would need a search
    /// for each of those and would get a different answer for the third.
    unacked: [Option<Unacked>; MAX_UNACKED],
    /// The peer's advertised receive window, in bytes.
    ///
    /// **Read from every acknowledgement, and it bounds what may be in
    /// flight.** With one segment outstanding this could be ignored, because
    /// one segment is under any window a peer would advertise; with a buffer
    /// it cannot, and sending past a receiver's window is how a sender makes a
    /// receiver drop what it asked for.
    pub snd_wnd: u16,
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
            srtt: None,
            rttvar: 0,
            rto: INITIAL_RTO_NANOS,
            retransmissions: 0,
            unacked: [None; MAX_UNACKED],
            // **One segment's worth until the peer says otherwise.** The
            // handshake's SYN-ACK carries the peer's real window and the
            // acknowledgement path installs it; starting at anything larger
            // would be sending into a window nobody advertised.
            snd_wnd: MAX_SEGMENT_PAYLOAD as u16,
        }
    }

    /// The SYN that opens it, armed for retransmission at `now`.
    ///
    /// **The handshake is where the timer matters most**, and where a stack
    /// without one fails most visibly: a lost SYN is a connection that never
    /// opens and never says why.
    pub fn syn(&mut self, out: &mut [u8], peers: Peers, now: u64) -> Option<usize> {
        let len = write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            self.snd_una,
            0,
            flag::SYN,
            &[],
        )?;
        self.queue(self.snd_una, flag::SYN, &[], 1, now);
        Some(len)
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
    pub fn send(
        &mut self,
        out: &mut [u8],
        peers: Peers,
        payload: &[u8],
        now: u64,
    ) -> Option<usize> {
        if self.state != State::Established {
            return None;
        }
        // **Two refusals, and both are about what can be sent again.** A
        // payload larger than one segment could not be held at all; a write
        // that would overflow the send buffer, or push past the window the
        // peer advertised, has nowhere to go until something is acknowledged.
        // Refusing is what a full send buffer means — the alternative is
        // sending what cannot be retransmitted, which is the silent stall
        // with a working timer standing in front of it.
        if payload.len() > MAX_SEGMENT_PAYLOAD || !self.has_room_for(payload.len()) {
            return None;
        }
        let seq = self.snd_nxt;
        let len = write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            seq,
            self.rcv_nxt,
            flag::ACK | flag::PSH,
            payload,
        )?;
        self.snd_nxt = self.snd_nxt.wrapping_add(payload.len() as u32);
        self.queue(seq, flag::ACK | flag::PSH, payload, payload.len() as u32, now);
        Some(len)
    }

    /// Closes this end, sending a FIN.
    pub fn close(&mut self, out: &mut [u8], peers: Peers, now: u64) -> Option<usize> {
        // A FIN is queued behind whatever is still in flight, like any other
        // segment: closing does not cancel data the peer has not taken.
        if self.state != State::Established || !self.has_room_for(1) {
            return None;
        }
        let seq = self.snd_nxt;
        let len = write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            seq,
            self.rcv_nxt,
            flag::ACK | flag::FIN,
            &[],
        )?;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = State::FinWait;
        self.queue(seq, flag::ACK | flag::FIN, &[], 1, now);
        Some(len)
    }

    /// Puts a segment at the back of the send buffer and, if it is now the
    /// only one, starts its timer.
    ///
    /// **The timer belongs to the front of the queue, not to each segment**
    /// (RFC 6298 (5.1)): one timer runs for the oldest thing outstanding, and
    /// a segment queued behind it inherits that timer rather than starting a
    /// second one. Its own `deadline` is filled in when it reaches the front.
    fn queue(&mut self, seq: u32, flags: u8, payload: &[u8], span: u32, now: u64) {
        let Some(slot) = self.unacked.iter().position(|u| u.is_none()) else {
            return;
        };
        let mut held = [0u8; MAX_SEGMENT_PAYLOAD];
        let len = payload.len().min(MAX_SEGMENT_PAYLOAD);
        held[..len].copy_from_slice(&payload[..len]);
        self.unacked[slot] = Some(Unacked {
            seq,
            flags,
            len,
            payload: held,
            span,
            sent_at: now,
            deadline: now.saturating_add(self.rto),
            retransmits: 0,
        });
    }

    /// Whether the send buffer can take another segment of `bytes` bytes.
    ///
    /// Two limits, and they answer different questions: the buffer is what
    /// this end can hold for retransmission, and the window is what the peer
    /// said it can receive. Either one full means the write waits.
    fn has_room_for(&self, bytes: usize) -> bool {
        if self.unacked.iter().all(|u| u.is_some()) {
            return false;
        }
        self.in_flight().saturating_add(bytes) <= usize::from(self.snd_wnd)
    }

    /// How many bytes of sequence space are outstanding.
    pub fn in_flight(&self) -> usize {
        self.unacked
            .iter()
            .flatten()
            .map(|u| u.span as usize)
            .sum()
    }

    /// How many segments are outstanding.
    pub fn segments_in_flight(&self) -> usize {
        self.unacked.iter().flatten().count()
    }

    /// When the oldest unacknowledged segment must be sent again, or `None`
    /// when nothing is outstanding.
    ///
    /// **What a caller waits on.** A service holding this connection has a
    /// blocking receive with a deadline (`build/README.md`, D282); this is the
    /// deadline it must not sleep past, and a service that waits on its
    /// client's deadline alone will sleep through every loss.
    pub fn retransmit_at(&self) -> Option<u64> {
        self.unacked[0].map(|u| u.deadline)
    }

    /// Whether anything is outstanding — sent, and not yet acknowledged.
    pub fn awaiting_ack(&self) -> bool {
        self.unacked[0].is_some()
    }

    /// The timer fired: rebuild the unacknowledged segment into `out` and say
    /// how long it is, or `None` when there is nothing outstanding or this end
    /// has given up.
    ///
    /// **Giving up is a state, not a silence.** Past
    /// [`MAX_RETRANSMISSIONS`] the connection moves to [`State::Aborted`] and
    /// what is held is dropped, so a caller sees a connection that failed
    /// rather than one that is still trying.
    ///
    /// **The acknowledgement carried is the current one**, not the one the
    /// original segment carried. A retransmission is a fresh statement of
    /// where this end is, and repeating a stale `rcv_nxt` would tell a peer
    /// that data it has since sent was never received.
    pub fn on_timeout(&mut self, out: &mut [u8], peers: Peers, now: u64) -> Option<usize> {
        // **The earliest unacknowledged segment, and only that one** (RFC 6298
        // (5.4)). Sending the whole buffer again on one timeout is the
        // behaviour that turns a single loss into a burst, and a burst into
        // the next loss.
        let mut held = self.unacked[0]?;
        if now < held.deadline {
            return None;
        }
        if held.retransmits >= MAX_RETRANSMISSIONS
            || now.saturating_sub(held.sent_at) >= GIVE_UP_NANOS
        {
            // The whole buffer goes, not just the segment that ran out: the
            // connection is over, and everything behind it is owed to a peer
            // that will never take it.
            self.unacked = [None; MAX_UNACKED];
            self.state = State::Aborted;
            return None;
        }
        // **Exponential backoff, RFC 6298 (5.5).** The doubling is on the
        // connection's timeout and not on a local copy: the next segment this
        // connection sends inherits it, which is the point — a link that has
        // just shown itself slow enough to lose one segment is not a link to
        // start the next timer optimistically on.
        self.rto = (self.rto.saturating_mul(2)).min(MAX_RTO_NANOS);
        held.retransmits += 1;
        // **Clamped to the moment this connection gives up.** Without the
        // clamp the next wake is a whole doubled timeout away, so a connection
        // whose budget runs out at eight seconds would not notice until
        // fifteen — the give-up would be decided on time and delivered on a
        // count, which is the worst of both.
        held.deadline = now
            .saturating_add(self.rto)
            .min(held.sent_at.saturating_add(GIVE_UP_NANOS));
        self.retransmissions += 1;
        let len = write(
            out,
            peers,
            self.local_port,
            self.remote_port,
            held.seq,
            self.rcv_nxt,
            held.flags,
            &held.payload[..held.len],
        )?;
        self.unacked[0] = Some(held);
        Some(len)
    }

    /// Takes an acknowledgement: releases everything it covers, measures the
    /// round trip if it may be measured, and restarts the timer for whatever
    /// is left.
    ///
    /// **An acknowledgement is cumulative, so it releases a prefix.** One
    /// segment's worth of `ack` can retire several — that is the ordinary case
    /// once more than one is in flight, and a release that only ever looked at
    /// the front would leave the rest outstanding forever.
    fn acknowledge(&mut self, ack: u32, now: u64) {
        let mut released = 0;
        let mut sample = None;
        for slot in 0..MAX_UNACKED {
            let Some(held) = self.unacked[slot] else {
                break;
            };
            if !seq_leq(held.seq.wrapping_add(held.span), ack) {
                break;
            }
            // **Karn's algorithm (RFC 6298 (3), rule 5).** A segment that was
            // sent more than once cannot be measured: there is no way to tell
            // whether the acknowledgement answers the original or the
            // retransmission, and guessing wrong on a link that is losing
            // segments drags the estimate in exactly the direction that makes
            // the next timeout too short.
            //
            // The *newest* unambiguous segment released, because RFC 6298 (3)
            // asks for one measurement per round trip and that is the one this
            // acknowledgement most nearly measures.
            if held.retransmits == 0 {
                sample = Some(now.saturating_sub(held.sent_at));
            }
            released += 1;
        }
        if released == 0 {
            return;
        }
        self.unacked.rotate_left(released);
        for slot in (MAX_UNACKED - released)..MAX_UNACKED {
            self.unacked[slot] = None;
        }
        if let Some(measured) = sample {
            self.sample_rtt(measured);
        }
        // **The timer restarts for what is left** (RFC 6298 (5.3)), and stops
        // when nothing is (5.2). A deadline carried over from the segment that
        // was just acknowledged would fire against data that has been in
        // flight for a fraction of its timeout.
        if let Some(front) = self.unacked[0].as_mut() {
            front.deadline = now.saturating_add(self.rto);
        }
    }

    /// RFC 6298 (2.2) and (2.3): fold one round-trip measurement into the
    /// timeout.
    ///
    /// **The first sample is not smoothed with anything**, because there is
    /// nothing to smooth it with — `SRTT = R`, `RTTVAR = R/2`. Every sample
    /// after it moves the estimate by an eighth and the variation by a
    /// quarter, which is what makes the timeout follow a link that changes
    /// without chasing a single slow reply.
    fn sample_rtt(&mut self, measured: u64) {
        match self.srtt {
            None => {
                self.srtt = Some(measured);
                self.rttvar = measured / 2;
            }
            Some(srtt) => {
                // **`srtt` here is the value from before this sample**, and
                // that is the whole of the ordering rule: RFC 6298 defines
                // `RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R|` against the smoothed
                // value as it stood, then updates it. Taking the difference
                // first, from the binding rather than from the field, is what
                // makes the two assignments below order-independent instead of
                // a trap for whoever moves them.
                let difference = srtt.abs_diff(measured);
                self.rttvar = (self.rttvar * 3 + difference) / 4;
                self.srtt = Some((srtt * 7 + measured) / 8);
            }
        }
        let srtt = self.srtt.unwrap_or(measured);
        let slack = (4 * self.rttvar).max(CLOCK_GRANULARITY_NANOS);
        self.rto = srtt
            .saturating_add(slack)
            .clamp(MIN_RTO_NANOS, MAX_RTO_NANOS);
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
        now: u64,
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
                    // **The window arrives with the handshake**, which is the
                    // first thing this end learns about how much the peer can
                    // take — and the first moment sending more than one
                    // segment becomes a decision rather than a guess.
                    self.snd_wnd = segment.window;
                    // **The handshake is the first round-trip measurement**,
                    // and it is the only one available before any data moves —
                    // so a connection that sends one segment and closes still
                    // has a timeout derived from the link rather than from the
                    // one-second guess it started with.
                    self.acknowledge(segment.ack, now);
                    let len = self.ack(out, peers);
                    return (0, len);
                }
                (0, None)
            }
            State::Established | State::FinWait => {
                // Only the segment that starts exactly where this end is
                // expecting is taken; anything else is a gap or a repeat.
                if segment.seq != self.rcv_nxt {
                    // A gap or a repeat in the peer's direction. Its
                    // acknowledgement of *this* end's data is still good and
                    // still releases what it covers — the two directions are
                    // independent, and refusing the whole segment would leave
                    // this end retransmitting something the peer already has.
                    if segment.has(flag::ACK) {
                        self.snd_wnd = segment.window;
                        self.acknowledge(segment.ack, now);
                    }
                    // Re-acknowledge, which is what tells the peer where this
                    // end actually is.
                    return (0, self.ack(out, peers));
                }
                if segment.has(flag::ACK) {
                    self.snd_una = segment.ack;
                    // Updated from every acknowledgement, because a receiver
                    // that is filling up says so by shrinking it — and a
                    // sender still working from the handshake's number would
                    // keep sending into a window that has closed.
                    self.snd_wnd = segment.window;
                    self.acknowledge(segment.ack, now);
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
