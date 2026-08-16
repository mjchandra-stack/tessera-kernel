// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A mock NVMe controller, so the enable handshake, the doorbell arithmetic,
//! the command encodings and the phase tag are exercised end to end on the host
//! without any hardware.
//!
//! The mock owns a flat "guest memory" the driver and the controller both
//! address by offset — exactly the DMA relationship a real controller has — and
//! executes whatever it finds in a submission queue when the driver rings its
//! doorbell.
//!
//! Core-only (fixed arrays and `RefCell`), so it needs no allocator and matches
//! the crate's `no_std` stance.

use super::*;
use core::cell::RefCell;

const MEM_LEN: usize = 16384;

const ASQ: u64 = 0x0000;
const ACQ: u64 = 0x0400;
const IO_SQ: u64 = 0x0800;
const IO_CQ: u64 = 0x0c00;
const IO_SQ_B: u64 = 0x1000;
const IO_CQ_B: u64 = 0x1400;
const PRP: u64 = 0x2000;

// Larger than any test's outstanding command count. A submission ring of N
// entries holds N-1 outstanding commands — the tail catching the head is how a
// ring says "empty", so a full one is indistinguishable from an idle one.
const ADMIN_ENTRIES: u16 = 8;
const IO_ENTRIES: u16 = 4;

/// What the mock's one namespace holds at block 0, so a read that reached the
/// right place is distinguishable from a read that reached anywhere else.
const DISK_MAGIC: [u8; 8] = *b"TESSERAN";
/// What `Identify` writes, for the same reason.
const IDENTIFY_MAGIC: [u8; 8] = *b"TESSCTRL";
const BLOCK_SIZE: u64 = 512;

/// Flat guest physical memory the driver writes and the controller DMAs.
struct Guest {
    mem: RefCell<[u8; MEM_LEN]>,
}

/// One queue pair the mock knows about.
#[derive(Clone, Copy, Default)]
struct MockQueue {
    submission: u64,
    completion: u64,
    entries: u16,
    /// How far the mock has consumed the submission ring.
    sq_head: u16,
    /// Where its next completion goes, and the phase bit it carries.
    cq_tail: u16,
    phase: bool,
    vector: u16,
    live: bool,
}

#[derive(Default)]
struct MockState {
    cc: u32,
    csts: u32,
    aqa: u32,
    asq: u64,
    acq: u64,
    queues: [MockQueue; 3],
}

/// A mock NVMe controller: an admin queue, up to two I/O queue pairs, an
/// `Identify` that fills a page, and a namespace whose block zero is
/// recognisable.
struct MockNvme<'g> {
    guest: &'g Guest,
    /// `CAP.MQES + 1`, the largest queue this controller accepts.
    max_entries: u16,
    doorbell_stride: u32,
    /// Whether the controller ever becomes ready, and whether it declares a
    /// fatal status instead. Both are how a machine fails, and a driver must
    /// tell them apart.
    becomes_ready: bool,
    fatal: bool,
    /// The smallest memory page the controller supports, as `CAP.MPSMIN`.
    page_size_min: u32,
    state: RefCell<MockState>,
}

impl<'g> MockNvme<'g> {
    fn new(guest: &'g Guest) -> Self {
        Self {
            guest,
            max_entries: 64,
            doorbell_stride: 0,
            becomes_ready: true,
            fatal: false,
            page_size_min: 0,
            state: RefCell::new(MockState::default()),
        }
    }

    fn doorbell(&self, qid: u16, completion: bool) -> usize {
        let index = usize::from(qid) * 2 + usize::from(completion);
        reg::DOORBELL_BASE + index * (4usize << self.doorbell_stride)
    }

    /// The queue pair `qid` names, as the mock currently knows it.
    fn queue_of(&self, st: &MockState, qid: u16) -> MockQueue {
        if qid == 0 {
            MockQueue {
                submission: st.asq,
                completion: st.acq,
                entries: ((st.aqa & 0xfff) as u16) + 1,
                sq_head: st.queues[0].sq_head,
                cq_tail: st.queues[0].cq_tail,
                phase: st.queues[0].phase,
                vector: 0,
                live: true,
            }
        } else {
            st.queues[usize::from(qid)]
        }
    }

    /// Posts one completion on `qid`'s completion queue.
    fn complete(&self, st: &mut MockState, qid: u16, cid: u16, sqid: u16, status: u16) {
        let queue = self.queue_of(st, qid);
        let at = (queue.completion + u64::from(queue.cq_tail) * COMPLETION_LEN as u64) as usize;
        let mut mem = self.guest.mem.borrow_mut();
        for byte in mem[at..at + COMPLETION_LEN].iter_mut() {
            *byte = 0;
        }
        let head = self.queue_of(st, sqid).sq_head;
        let queues = u32::from(head) | (u32::from(sqid) << 16);
        mem[at + 8..at + 12].copy_from_slice(&queues.to_le_bytes());
        let phase = u32::from(queue.phase) << 16;
        let word = u32::from(cid) | phase | (u32::from(status) << 17);
        mem[at + 12..at + 16].copy_from_slice(&word.to_le_bytes());
        drop(mem);

        let slot = &mut st.queues[usize::from(qid)];
        slot.cq_tail += 1;
        if slot.cq_tail == queue.entries {
            slot.cq_tail = 0;
            slot.phase = !slot.phase;
        }
    }

    /// Runs whatever the driver just published on `qid`'s submission queue.
    fn process(&self, qid: u16, tail: u16) {
        let mut st = self.state.borrow_mut();
        let queue = self.queue_of(&st, qid);
        if !queue.live {
            return;
        }
        let mut head = queue.sq_head;
        // Bounded by the ring's length. A tail the driver could not
        // legitimately have published — past the end, or equal to the head
        // after a wrap it did not make — would otherwise walk the ring
        // forever, and a mock that hangs is a worse test than one that stops.
        let mut remaining = queue.entries;
        while head != tail && remaining > 0 {
            remaining -= 1;
            let at = (queue.submission + u64::from(head) * COMMAND_LEN as u64) as usize;
            let mut command = [0u8; COMMAND_LEN];
            command.copy_from_slice(&self.guest.mem.borrow()[at..at + COMMAND_LEN]);
            head += 1;
            if head == queue.entries {
                head = 0;
            }
            st.queues[usize::from(qid)].sq_head = head;

            let dword0 = get_u32(&command, 0);
            let opcode = (dword0 & 0xff) as u8;
            let cid = (dword0 >> 16) as u16;
            let prp1 = {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&command[24..32]);
                u64::from_le_bytes(bytes)
            };
            let cdw10 = get_u32(&command, 40);
            let cdw11 = get_u32(&command, 44);

            let status = match opcode {
                ADMIN_IDENTIFY => {
                    let at = prp1 as usize;
                    self.guest.mem.borrow_mut()[at..at + IDENTIFY_MAGIC.len()]
                        .copy_from_slice(&IDENTIFY_MAGIC);
                    // The CNS the driver asked for, echoed where a test can
                    // see it: a controller identify and a namespace identify
                    // are different structures, and a driver that got the
                    // wrong one would misread every field.
                    self.guest.mem.borrow_mut()[at + 8] = (cdw10 & 0xff) as u8;
                    0
                }
                ADMIN_CREATE_IO_CQ => {
                    let new = (cdw10 & 0xffff) as u16;
                    if usize::from(new) >= st.queues.len() {
                        1
                    } else {
                        let slot = &mut st.queues[usize::from(new)];
                        slot.completion = prp1;
                        slot.entries = ((cdw10 >> 16) as u16) + 1;
                        slot.vector = (cdw11 >> 16) as u16;
                        slot.phase = true;
                        slot.cq_tail = 0;
                        0
                    }
                }
                ADMIN_CREATE_IO_SQ => {
                    let new = (cdw10 & 0xffff) as u16;
                    if usize::from(new) >= st.queues.len() {
                        1
                    } else {
                        let slot = &mut st.queues[usize::from(new)];
                        slot.submission = prp1;
                        slot.sq_head = 0;
                        slot.live = true;
                        0
                    }
                }
                NVM_READ => {
                    let at = prp1 as usize;
                    self.guest.mem.borrow_mut()[at..at + DISK_MAGIC.len()]
                        .copy_from_slice(&DISK_MAGIC);
                    0
                }
                // An opcode this controller does not implement, answered the
                // way a real one does rather than ignored.
                _ => 1,
            };
            // An admin command's completion goes on the admin completion
            // queue; an I/O command's goes on the completion queue its
            // submission queue was bound to, which here is the same index.
            self.complete(&mut st, qid, cid, qid, status);
        }
    }
}

impl Registers for MockNvme<'_> {
    fn read32(&self, offset: usize) -> u32 {
        let st = self.state.borrow();
        match offset {
            reg::CAP => u32::from(self.max_entries - 1),
            reg::CAP_HIGH => self.doorbell_stride | (self.page_size_min << 16),
            reg::VS => 0x0001_0400,
            reg::CC => st.cc,
            reg::CSTS => st.csts,
            reg::AQA => st.aqa,
            _ => 0,
        }
    }

    fn write32(&self, offset: usize, value: u32) {
        // A doorbell write is the only register write with an effect beyond
        // recording a value, so it is matched first and by computed address.
        if offset >= reg::DOORBELL_BASE {
            for qid in 0..3u16 {
                if offset == self.doorbell(qid, false) {
                    self.process(qid, value as u16);
                    return;
                }
                if offset == self.doorbell(qid, true) {
                    return; // the driver freeing completion slots
                }
            }
            return;
        }
        let mut st = self.state.borrow_mut();
        match offset {
            reg::CC => {
                st.cc = value;
                if value & cc::ENABLE != 0 {
                    if self.fatal {
                        st.csts = csts::FATAL;
                    } else if self.becomes_ready {
                        st.csts = csts::READY;
                        st.queues[0].phase = true;
                    }
                } else {
                    st.csts = 0;
                }
            }
            reg::AQA => st.aqa = value,
            reg::ASQ => st.asq = (st.asq & !0xffff_ffff) | u64::from(value),
            reg::ASQ_HIGH => st.asq = (st.asq & 0xffff_ffff) | (u64::from(value) << 32),
            reg::ACQ => st.acq = (st.acq & !0xffff_ffff) | u64::from(value),
            reg::ACQ_HIGH => st.acq = (st.acq & 0xffff_ffff) | (u64::from(value) << 32),
            _ => {}
        }
    }
}

fn guest() -> Guest {
    Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    }
}

fn admin() -> QueuePair {
    QueuePair {
        submission: ASQ,
        completion: ACQ,
        entries: ADMIN_ENTRIES,
    }
}

/// Publishes `command` at `slot` of the submission ring based at `base`.
fn submit(guest: &Guest, base: u64, slot: u16, command: &[u8; COMMAND_LEN]) {
    let at = (base + u64::from(slot) * COMMAND_LEN as u64) as usize;
    guest.mem.borrow_mut()[at..at + COMMAND_LEN].copy_from_slice(command);
}

#[test]
fn bring_up_programs_the_admin_queue_and_leaves_the_controller_ready() {
    let guest = guest();
    let device = MockNvme::new(&guest);
    let controller = Controller::reset_and_enable(&device, admin()).expect("enable");
    assert_eq!(controller.max_queue_entries(), 64);
    assert_eq!(controller.version(), 0x0001_0400);

    let st = device.state.borrow();
    assert_eq!(st.csts & csts::READY, csts::READY);
    assert_eq!(st.asq, ASQ, "the admin submission base the driver chose");
    assert_eq!(st.acq, ACQ);
    assert_eq!(
        st.aqa,
        u32::from(ADMIN_ENTRIES - 1) | (u32::from(ADMIN_ENTRIES - 1) << 16),
        "both sizes are entries minus one",
    );
    // 64-byte commands and 16-byte completions, as powers of two.
    assert_eq!((st.cc >> cc::IOSQES_SHIFT) & 0xf, 6);
    assert_eq!((st.cc >> cc::IOCQES_SHIFT) & 0xf, 4);
}

/// **A controller that never answers and one that says it failed are different
/// machines.** A driver that reported them the same way would send somebody
/// looking for a hang when the controller had already explained itself.
#[test]
fn a_controller_that_never_readies_and_one_that_faults_are_told_apart() {
    let guest = guest();
    let mut silent = MockNvme::new(&guest);
    silent.becomes_ready = false;
    assert_eq!(
        Controller::reset_and_enable(&silent, admin()).map(|_| ()),
        Err(Error::NotReady),
    );

    let mut broken = MockNvme::new(&guest);
    broken.fatal = true;
    assert_eq!(
        Controller::reset_and_enable(&broken, admin()).map(|_| ()),
        Err(Error::ControllerFatal),
    );
}

/// A queue larger than `CAP.MQES` allows is refused, not clamped: a driver
/// that asked for more entries than it got would submit past the end of a ring
/// the controller is reading.
#[test]
fn an_oversized_admin_queue_is_refused() {
    let guest = guest();
    let device = MockNvme::new(&guest);
    let too_big = QueuePair {
        entries: 65,
        ..admin()
    };
    assert_eq!(
        Controller::reset_and_enable(&device, too_big).map(|_| ()),
        Err(Error::QueueSize),
    );
}

/// A controller whose smallest page is larger than this driver works in is
/// refused at bring-up rather than driven with PRP entries of the wrong size.
#[test]
fn a_controller_needing_bigger_pages_is_refused() {
    let guest = guest();
    let mut device = MockNvme::new(&guest);
    device.page_size_min = 1; // 8 KiB
    assert_eq!(
        Controller::reset_and_enable(&device, admin()).map(|_| ()),
        Err(Error::UnsupportedPageSize),
    );
}

#[test]
fn an_identify_completes_on_the_admin_queue() {
    let guest = guest();
    let device = MockNvme::new(&guest);
    let controller = Controller::reset_and_enable(&device, admin()).expect("enable");

    let mut command = [0u8; COMMAND_LEN];
    write_identify(&mut command, 0x1234, PRP, CNS_CONTROLLER, 0).expect("identify");
    submit(&guest, ASQ, 0, &command);
    controller.ring_submission(0, 1);

    let mut ring = CompletionRing::new(ADMIN_ENTRIES).expect("ring");
    let mem = guest.mem.borrow();
    let completion = ring
        .poll(&mem[ACQ as usize..])
        .expect("poll")
        .expect("a completion");
    assert_eq!(completion.cid, 0x1234);
    assert_eq!(completion.sqid, 0);
    assert!(completion.is_success());
    assert_eq!(&mem[PRP as usize..PRP as usize + 8], &IDENTIFY_MAGIC);
    assert_eq!(mem[PRP as usize + 8], CNS_CONTROLLER, "the CNS asked for");
    assert_eq!(ring.head(), 1);
}

/// **Two I/O queues, each with its own vector.** The vectors are what makes
/// per-queue completion interrupts possible at all: a controller told to raise
/// the same one for both would leave a driver unable to say which queue
/// finished without reading both.
#[test]
fn two_io_queues_are_created_with_distinct_vectors_and_serve_separately() {
    let guest = guest();
    let device = MockNvme::new(&guest);
    let controller = Controller::reset_and_enable(&device, admin()).expect("enable");
    controller.check_queue_size(IO_ENTRIES).expect("size");

    let mut command = [0u8; COMMAND_LEN];
    let mut slot = 0u16;
    let publish = |command: &[u8; COMMAND_LEN], slot: &mut u16| {
        submit(&guest, ASQ, *slot, command);
        *slot += 1;
        controller.ring_submission(0, *slot);
    };
    for (qid, cq, sq, vector) in [(1u16, IO_CQ, IO_SQ, 1u16), (2, IO_CQ_B, IO_SQ_B, 2)] {
        write_create_completion_queue(&mut command, qid, cq, qid, IO_ENTRIES, vector)
            .expect("create cq");
        publish(&command, &mut slot);
        write_create_submission_queue(&mut command, qid + 8, sq, qid, IO_ENTRIES, qid)
            .expect("create sq");
        publish(&command, &mut slot);
    }
    {
        let st = device.state.borrow();
        assert_eq!(st.queues[1].vector, 1);
        assert_eq!(st.queues[2].vector, 2, "each queue raises its own");
        assert_eq!(st.queues[1].submission, IO_SQ);
        assert_eq!(st.queues[2].submission, IO_SQ_B);
    }

    // A read on the *second* I/O queue, and the completion says so.
    write_read(&mut command, 0x77, 1, PRP, 0, 1, BLOCK_SIZE).expect("read");
    submit(&guest, IO_SQ_B, 0, &command);
    controller.ring_submission(2, 1);

    let mut ring = CompletionRing::new(IO_ENTRIES).expect("ring");
    let mem = guest.mem.borrow();
    let completion = ring
        .poll(&mem[IO_CQ_B as usize..])
        .expect("poll")
        .expect("a completion");
    assert_eq!(completion.cid, 0x77);
    assert_eq!(completion.sqid, 2, "the queue it was submitted on");
    assert!(completion.is_success());
    assert_eq!(&mem[PRP as usize..PRP as usize + 8], &DISK_MAGIC);
    // The first queue was never asked for anything, and its ring is untouched.
    let mut idle = CompletionRing::new(IO_ENTRIES).expect("ring");
    assert_eq!(idle.poll(&mem[IO_CQ as usize..]), Ok(None));
}

/// **The phase tag, which is the whole reason this is a type.** Nothing in a
/// completion says it is new. A reader that ignored the phase would see the
/// previous pass's entries again on every wrap — indistinguishable from a
/// controller completing work twice, and the one bug here a test can provoke on
/// demand and a machine almost never will.
#[test]
fn a_wrapped_ring_does_not_replay_the_previous_pass() {
    let guest = guest();
    let device = MockNvme::new(&guest);
    let controller = Controller::reset_and_enable(&device, admin()).expect("enable");
    let mut ring = CompletionRing::new(ADMIN_ENTRIES).expect("ring");

    // Fill the admin completion ring exactly once round.
    let mut command = [0u8; COMMAND_LEN];
    for i in 0..ADMIN_ENTRIES {
        write_identify(&mut command, 0x100 + i, PRP, CNS_CONTROLLER, 0).expect("identify");
        submit(&guest, ASQ, i, &command);
        controller.ring_submission(0, (i + 1) % ADMIN_ENTRIES);
    }
    for i in 0..ADMIN_ENTRIES {
        let mem = guest.mem.borrow();
        let completion = ring
            .poll(&mem[ACQ as usize..])
            .expect("poll")
            .expect("a completion");
        assert_eq!(completion.cid, 0x100 + i);
    }
    // Back at the start, on the other phase. The entries are still there, and
    // must not be read again.
    assert_eq!(ring.head(), 0);
    {
        let mem = guest.mem.borrow();
        assert_eq!(
            ring.poll(&mem[ACQ as usize..]),
            Ok(None),
            "the previous pass is not new work",
        );
    }

    // One more command, which the controller writes over slot zero with the
    // flipped phase — and that one *is* new.
    write_identify(&mut command, 0x200, PRP, CNS_CONTROLLER, 0).expect("identify");
    submit(&guest, ASQ, 0, &command);
    controller.ring_submission(0, 1);
    let mem = guest.mem.borrow();
    let completion = ring
        .poll(&mem[ACQ as usize..])
        .expect("poll")
        .expect("a completion");
    assert_eq!(completion.cid, 0x200);
}

/// A completion whose submission-queue head points past the end of the ring is
/// a controller describing a queue that cannot exist. Refused rather than used:
/// the head is what a driver frees slots against, and acting on this one would
/// free slots that still hold outstanding commands.
#[test]
fn a_completion_naming_an_impossible_head_is_refused() {
    let mut ring_bytes = [0u8; COMPLETION_LEN * 2];
    // sqid 0, head 99 — past a four-entry ring.
    ring_bytes[8..12].copy_from_slice(&99u32.to_le_bytes());
    ring_bytes[12..16].copy_from_slice(&(1u32 << 16).to_le_bytes());
    let mut ring = CompletionRing::new(4).expect("ring");
    assert_eq!(ring.poll(&ring_bytes), Err(Error::BadCompletion));
}

/// A ring shorter than one entry is a buffer nobody can read a completion out
/// of, and saying so beats reading past its end.
#[test]
fn a_ring_too_short_for_an_entry_is_refused() {
    let mut ring = CompletionRing::new(4).expect("ring");
    assert_eq!(ring.poll(&[0u8; 8]), Err(Error::ShortBuffer));
}

/// **Doorbells can be a page apart, and that is a capability property.** A
/// controller may space them by its `CAP.DSTRD` so each queue's doorbell lands
/// on its own page — which is what lets one queue be granted to one process
/// without granting the rest, since a page is the unit of granting.
#[test]
fn the_doorbell_stride_can_put_every_queue_on_its_own_page() {
    let guest = guest();
    let mut device = MockNvme::new(&guest);
    // 2^10 * 4 = 4096 bytes between doorbells.
    device.doorbell_stride = 10;
    let controller = Controller::reset_and_enable(&device, admin()).expect("enable");
    let first = controller.doorbell_offset(1, false);
    let second = controller.doorbell_offset(2, false);
    assert_eq!(second - first, 2 * 4096, "a page each, submission and head");
    assert_eq!(
        controller.doorbell_offset(0, false),
        reg::DOORBELL_BASE,
        "the admin queue's is the first",
    );
}

/// A read is refused rather than truncated when one PRP entry cannot describe
/// it: a driver told it read more than it did would hand back a buffer with a
/// stale tail and no way to know.
#[test]
fn a_read_one_prp_entry_cannot_cover_is_refused() {
    let mut command = [0u8; COMMAND_LEN];
    // Nine 512-byte blocks is 4608 bytes — past the end of the page.
    assert_eq!(
        write_read(&mut command, 1, 1, PRP, 0, 9, BLOCK_SIZE),
        Err(Error::ShortBuffer),
    );
    // And an unaligned buffer, which the specification does not allow here.
    assert_eq!(
        write_read(&mut command, 1, 1, PRP + 8, 0, 1, BLOCK_SIZE),
        Err(Error::ShortBuffer),
    );
    assert_eq!(
        write_read(&mut command, 1, 1, PRP, 0, 0, BLOCK_SIZE),
        Err(Error::ShortBuffer),
    );
}

/// **A submission slot is reused, so building a command clears it.** A builder
/// that wrote only the fields it cared about would leave the previous
/// command's namespace and PRP entries in place, and the controller would act
/// on them — a read of the wrong namespace into the wrong buffer, from a
/// command that looks correct in every field anybody thought to set.
#[test]
fn building_a_command_clears_what_the_slot_held() {
    let mut slot = [0xffu8; COMMAND_LEN];
    write_identify(&mut slot, 1, PRP, CNS_NAMESPACE, 7).expect("identify");
    // The namespace is what was asked for, not what was there.
    assert_eq!(get_u32(&slot, 4), 7);
    // The second PRP entry, which `Identify` does not use, is not the 0xff the
    // slot held.
    assert_eq!(get_u32(&slot, 32), 0);
    assert_eq!(get_u32(&slot, 36), 0);

    // And a command that uses fewer dwords still leaves nothing behind.
    write_read(&mut slot, 2, 1, PRP, 0x1234, 1, BLOCK_SIZE).expect("read");
    assert_eq!(get_u32(&slot, 0) & 0xff, u32::from(NVM_READ));
    assert_eq!(get_u32(&slot, 40), 0x1234, "the LBA's low half");
    assert_eq!(get_u32(&slot, 44), 0, "and its high half");
    assert_eq!(get_u32(&slot, 48), 0, "one block, encoded as zero");
}

/// A write is the same command with one opcode changed, and the mock proves
/// the driver can tell the controller which it meant: an opcode it does not
/// implement comes back as a failure rather than as a silent success.
#[test]
fn a_write_is_a_read_with_a_different_opcode_and_the_controller_can_tell() {
    let mut command = [0u8; COMMAND_LEN];
    write_write(&mut command, 5, 1, PRP, 9, 1, BLOCK_SIZE).expect("write");
    assert_eq!(get_u32(&command, 0) & 0xff, u32::from(NVM_WRITE));
    assert_eq!(get_u32(&command, 40), 9, "the LBA");

    let guest = guest();
    let device = MockNvme::new(&guest);
    let controller = Controller::reset_and_enable(&device, admin()).expect("enable");
    submit(&guest, ASQ, 0, &command);
    controller.ring_submission(0, 1);
    let mut ring = CompletionRing::new(ADMIN_ENTRIES).expect("ring");
    let mem = guest.mem.borrow();
    let completion = ring
        .poll(&mem[ACQ as usize..])
        .expect("poll")
        .expect("a completion");
    // This mock implements reads and not writes, so the write is declined —
    // and a declined command is an answer, which is the point: a driver that
    // could not tell a refusal from a success would report data written that
    // never left.
    assert!(!completion.is_success());
    assert_eq!(completion.cid, 5);
}

/// Attaching to a controller somebody else enabled gives the doorbell
/// arithmetic without taking the controller through reset — which would
/// destroy the queues the caller is holding.
#[test]
fn attaching_does_not_disturb_a_running_controller() {
    let guest = guest();
    let device = MockNvme::new(&guest);
    let enabled = Controller::reset_and_enable(&device, admin()).expect("enable");
    let before = device.state.borrow().cc;
    let attached = Controller::attach(&device);
    assert_eq!(device.state.borrow().cc, before, "CC is untouched");
    assert_eq!(device.state.borrow().csts & csts::READY, csts::READY);
    assert_eq!(
        attached.doorbell_offset(1, false),
        enabled.doorbell_offset(1, false),
    );
    assert_eq!(attached.max_queue_entries(), enabled.max_queue_entries());
}

/// A command buffer smaller than a command is refused rather than partially
/// written.
#[test]
fn a_short_command_buffer_is_refused() {
    let mut short = [0u8; COMMAND_LEN - 1];
    assert_eq!(
        write_identify(&mut short, 1, PRP, CNS_CONTROLLER, 0),
        Err(Error::ShortBuffer),
    );
}
