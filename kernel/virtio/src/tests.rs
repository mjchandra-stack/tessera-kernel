// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! A mock virtio-mmio block device, so the handshake and the descriptor/
//! available/used ring logic are exercised end to end on the host without any
//! hardware. The mock owns a flat "guest physical memory" the driver and the
//! device both address by offset — exactly the DMA relationship the real
//! transport has — and processes the queue when the driver rings the doorbell.
//!
//! Core-only (fixed arrays + `RefCell`), so it needs no allocator and matches
//! the crate's `no_std` stance.

use super::*;
use core::cell::RefCell;

const MEM_LEN: usize = 8192;
const DESC_PHYS: u64 = 0x0100;
const HEADER_PHYS: u64 = 0x0400;
const DATA_PHYS: u64 = 0x0600;
const STATUS_PHYS: u64 = 0x0800;
const QUEUE_SIZE: u16 = 8;
const DEVICE_MAX_QUEUE: u32 = 8;

/// Flat guest physical memory the driver writes and the device DMAs.
struct Guest {
    mem: RefCell<[u8; MEM_LEN]>,
}

/// The mock device's mutable register/queue state.
#[derive(Default)]
struct State {
    status: u32,
    device_features_sel: u32,
    q_desc: u64,
    q_avail: u64,
    q_used: u64,
    q_num: u32,
    interrupt_status: u32,
}

/// A mock virtio-mmio block device serving one 512-byte sector of `disk`.
struct MockBlk<'g> {
    guest: &'g Guest,
    device_id: u32,
    offers_version_1: bool,
    disk: [u8; SECTOR_LEN],
    state: RefCell<State>,
}

impl<'g> MockBlk<'g> {
    fn new(guest: &'g Guest, disk: [u8; SECTOR_LEN]) -> Self {
        Self {
            guest,
            device_id: DEVICE_ID_BLOCK,
            offers_version_1: true,
            disk,
            state: RefCell::new(State::default()),
        }
    }

    /// The device's side of the doorbell: consume every newly available entry,
    /// perform the block read it describes, and post a used-ring completion.
    fn process_queue(&self) {
        serve_block_queue(self.guest, &self.state, &self.disk);
    }
}

/// The device half of a block queue, shared by both transports' mocks.
///
/// It is transport-independent because the queue is: what a doorbell write
/// means — walk the descriptor chain, do the read, post the completion — is the
/// same whether the doorbell was a 32-bit register at a fixed offset or a
/// 16-bit write to a computed address. Sharing it is what makes the virtio-pci
/// test a test of the *transport* rather than a second copy of the ring logic.
fn serve_block_queue(guest: &Guest, state: &RefCell<State>, disk: &[u8; SECTOR_LEN]) {
    {
        let (desc_base, avail_base, used_base, n) = {
            let st = state.borrow();
            (st.q_desc, st.q_avail, st.q_used, st.q_num as usize)
        };
        if n == 0 {
            return;
        }
        let mut mem = guest.mem.borrow_mut();

        loop {
            let avail_idx = ld16(&mem, avail_base + 2);
            let used_idx = ld16(&mem, used_base + 2);
            if avail_idx == used_idx {
                break; // caught up
            }
            let slot = (used_idx as usize) % n;
            let head = u64::from(ld16(&mem, avail_base + 4 + slot as u64 * 2));

            // Descriptor chain: header -> data -> status. All addresses stay
            // u64 (guest physical), narrowed to usize only at the point of use.
            let d0 = desc_base + head * 16;
            let header_addr = ld64(&mem, d0);
            let next0 = u64::from(ld16(&mem, d0 + 14));
            let d1 = desc_base + next0 * 16;
            let data_addr = ld64(&mem, d1);
            let data_len = ld32(&mem, d1 + 8);
            let next1 = u64::from(ld16(&mem, d1 + 14));
            let d2 = desc_base + next1 * 16;
            let status_addr = ld64(&mem, d2);

            let req_type = ld32(&mem, header_addr);
            let sector = ld64(&mem, header_addr + 8);
            if req_type == BLK_T_IN && sector == 0 {
                for i in 0..SECTOR_LEN {
                    mem[data_addr as usize + i] = disk[i];
                }
            }
            mem[status_addr as usize] = BLK_S_OK;

            // Post the completion and advance the used index.
            let used_at = used_base + 4 + slot as u64 * 8;
            st32(&mut mem, used_at, head as u32);
            st32(&mut mem, used_at + 4, data_len + 1);
            st16(&mut mem, used_base + 2, used_idx.wrapping_add(1));
        }
        drop(mem);
        state.borrow_mut().interrupt_status = 1;
    }
}

impl Mmio for MockBlk<'_> {
    fn read(&self, offset: usize) -> u32 {
        let st = self.state.borrow();
        match offset {
            reg::MAGIC_VALUE => MAGIC,
            reg::VERSION => VERSION,
            reg::DEVICE_ID => self.device_id,
            reg::DEVICE_FEATURES => {
                // Selector 1 is the high feature word, where VERSION_1 lives.
                if st.device_features_sel == 1 && self.offers_version_1 {
                    FEATURE_VERSION_1_BIT
                } else {
                    0
                }
            }
            reg::QUEUE_NUM_MAX => DEVICE_MAX_QUEUE,
            reg::STATUS => st.status,
            reg::INTERRUPT_STATUS => st.interrupt_status,
            _ => 0,
        }
    }

    fn write(&self, offset: usize, value: u32) {
        if offset == reg::QUEUE_NOTIFY {
            self.process_queue();
            return;
        }
        let mut st = self.state.borrow_mut();
        match offset {
            reg::STATUS => st.status = value,
            reg::DEVICE_FEATURES_SEL => st.device_features_sel = value,
            reg::QUEUE_NUM => st.q_num = value,
            reg::QUEUE_DESC_LOW => st.q_desc = (st.q_desc & !0xffff_ffff) | u64::from(value),
            reg::QUEUE_DESC_HIGH => {
                st.q_desc = (st.q_desc & 0xffff_ffff) | (u64::from(value) << 32)
            }
            reg::QUEUE_DRIVER_LOW => st.q_avail = (st.q_avail & !0xffff_ffff) | u64::from(value),
            reg::QUEUE_DRIVER_HIGH => {
                st.q_avail = (st.q_avail & 0xffff_ffff) | (u64::from(value) << 32)
            }
            reg::QUEUE_DEVICE_LOW => st.q_used = (st.q_used & !0xffff_ffff) | u64::from(value),
            reg::QUEUE_DEVICE_HIGH => {
                st.q_used = (st.q_used & 0xffff_ffff) | (u64::from(value) << 32)
            }
            reg::INTERRUPT_ACK => st.interrupt_status &= !value,
            _ => {}
        }
    }
}

// Little-endian accessors over the flat guest memory.
fn ld16(mem: &[u8; MEM_LEN], at: u64) -> u16 {
    u16::from_le_bytes([mem[at as usize], mem[at as usize + 1]])
}
fn ld32(mem: &[u8; MEM_LEN], at: u64) -> u32 {
    let a = at as usize;
    u32::from_le_bytes([mem[a], mem[a + 1], mem[a + 2], mem[a + 3]])
}
fn ld64(mem: &[u8; MEM_LEN], at: u64) -> u64 {
    let a = at as usize;
    let mut b = [0u8; 8];
    b.copy_from_slice(&mem[a..a + 8]);
    u64::from_le_bytes(b)
}
fn st16(mem: &mut [u8; MEM_LEN], at: u64, v: u16) {
    mem[at as usize..at as usize + 2].copy_from_slice(&v.to_le_bytes());
}
fn st32(mem: &mut [u8; MEM_LEN], at: u64, v: u32) {
    mem[at as usize..at as usize + 4].copy_from_slice(&v.to_le_bytes());
}

/// Runs one full sector-0 read against a mock device and returns the 512 bytes
/// the driver received, plus the completion the device posted.
fn read_sector_0(guest: &Guest, device: &MockBlk<'_>) -> ([u8; SECTOR_LEN], (u16, u32), u8) {
    let layout = Layout::for_size(QUEUE_SIZE);
    let avail_phys = DESC_PHYS + layout.avail_offset as u64;
    let used_phys = DESC_PHYS + layout.used_offset as u64;

    let blk = Blk::init(device, QUEUE_SIZE, DESC_PHYS, avail_phys, used_phys)
        .expect("handshake succeeds");

    // Driver writes the request header, then the descriptor/available rings.
    {
        let mut mem = guest.mem.borrow_mut();
        let header = blk_read_header(0);
        mem[HEADER_PHYS as usize..HEADER_PHYS as usize + BLK_HEADER_LEN].copy_from_slice(&header);

        let region = DESC_PHYS as usize;
        let (desc, rest) = mem[region..].split_at_mut(layout.avail_offset);
        let avail = &mut rest[..layout.used_offset - layout.avail_offset];
        blk.write_read_request(desc, avail, HEADER_PHYS, DATA_PHYS, STATUS_PHYS, 0);
    }

    blk.notify(); // device processes synchronously

    let mem = guest.mem.borrow();
    let used = &mem[used_phys as usize..];
    let completion = blk
        .completion(used, 0)
        .expect("valid used element")
        .expect("device advanced the used ring");
    let status = mem[STATUS_PHYS as usize];
    let mut data = [0u8; SECTOR_LEN];
    data.copy_from_slice(&mem[DATA_PHYS as usize..DATA_PHYS as usize + SECTOR_LEN]);
    (data, completion, status)
}

#[test]
fn a_full_sector_read_round_trips_through_the_rings() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    // A disk whose sector 0 is a recognisable pattern.
    let mut disk = [0u8; SECTOR_LEN];
    for (i, byte) in disk.iter_mut().enumerate() {
        *byte = (i as u8) ^ 0xa5;
    }
    let device = MockBlk::new(&guest, disk);

    let (data, (id, len), status) = read_sector_0(&guest, &device);
    assert_eq!(status, BLK_S_OK);
    assert_eq!(id, 0); // head descriptor
    assert_eq!(len, SECTOR_LEN as u32 + 1); // 512 data + 1 status byte
    assert_eq!(
        data, disk,
        "the driver received the disk's sector 0 verbatim"
    );
}

#[test]
fn the_completion_is_absent_until_the_device_advances() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockBlk::new(&guest, [7u8; SECTOR_LEN]);
    let layout = Layout::for_size(QUEUE_SIZE);
    let avail_phys = DESC_PHYS + layout.avail_offset as u64;
    let used_phys = DESC_PHYS + layout.used_offset as u64;
    let blk = Blk::init(&device, QUEUE_SIZE, DESC_PHYS, avail_phys, used_phys).unwrap();

    // Before any request the used ring is empty, so completion() sees nothing.
    let mem = guest.mem.borrow();
    assert_eq!(blk.completion(&mem[used_phys as usize..], 0), Ok(None));
}

#[test]
fn a_non_block_transport_is_rejected() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let mut device = MockBlk::new(&guest, [0u8; SECTOR_LEN]);
    device.device_id = 1; // a network device, say
    assert_eq!(
        Blk::init(&device, QUEUE_SIZE, DESC_PHYS, 0, 0).map(|_| ()),
        Err(Error::NotBlockDevice)
    );
}

#[test]
fn a_legacy_only_device_is_rejected() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let mut device = MockBlk::new(&guest, [0u8; SECTOR_LEN]);
    device.offers_version_1 = false;
    assert_eq!(
        Blk::init(&device, QUEUE_SIZE, DESC_PHYS, 0, 0).map(|_| ()),
        Err(Error::NoModernFeature)
    );
}

#[test]
fn an_oversized_queue_is_rejected() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockBlk::new(&guest, [0u8; SECTOR_LEN]);
    // The mock device's QueueNumMax is 8; ask for 16.
    assert_eq!(
        Blk::init(&device, 16, DESC_PHYS, 0, 0).map(|_| ()),
        Err(Error::QueueSize)
    );
}

// --- virtio-net: a mock device + a SLIRP-like ARP responder ---

const NET_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const GW_IP: [u8; 4] = [10, 0, 2, 2];
const OUR_IP: [u8; 4] = [10, 0, 2, 15];

// Guest-memory layout for the net test: two queue regions and two buffers.
const RX_Q: u64 = 0x0100;
const TX_Q: u64 = 0x0400;
const RX_BUF: u64 = 0x1000;
const RX_BUF_LEN: u32 = 2048;
const TX_BUF: u64 = 0x1800;

#[derive(Default, Clone, Copy)]
struct QueueCfg {
    desc: u64,
    avail: u64,
    used: u64,
    num: u32,
}

#[derive(Default)]
struct NetState {
    status: u32,
    device_features_sel: u32,
    queue_sel: usize,
    queues: [QueueCfg; 2],
    interrupt_status: u32,
}

/// A mock virtio-net device: two queues (rx=0, tx=1), a MAC in config space,
/// and an ARP responder that, on a transmit doorbell, answers a request for the
/// gateway by delivering a reply into a posted receive buffer — QEMU's SLIRP in
/// miniature.
struct MockNet<'g> {
    guest: &'g Guest,
    device_id: u32,
    /// Whether this device offers `VIRTIO_NET_F_STATUS`, and what its link
    /// state field says if it does. Two fields rather than one, because "no
    /// status field" and "a status field reading down" are exactly the two
    /// cases a driver must not confuse.
    offers_status: bool,
    link_up: bool,
    state: RefCell<NetState>,
}

impl<'g> MockNet<'g> {
    fn new(guest: &'g Guest) -> Self {
        Self {
            guest,
            device_id: DEVICE_ID_NET,
            offers_status: false,
            link_up: false,
            state: RefCell::new(NetState::default()),
        }
    }

    /// The gateway's ARP reply to our request.
    fn arp_reply() -> [u8; arp::FRAME_LEN] {
        let mut f = [0u8; arp::FRAME_LEN];
        f[0..6].copy_from_slice(&NET_MAC); // dst: us
        f[6..12].copy_from_slice(&GW_MAC); // src: gateway
        f[12..14].copy_from_slice(&arp::ETHERTYPE_ARP.to_be_bytes());
        f[14..16].copy_from_slice(&1u16.to_be_bytes());
        f[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        f[18] = 6;
        f[19] = 4;
        f[20..22].copy_from_slice(&arp::OP_REPLY.to_be_bytes());
        f[22..28].copy_from_slice(&GW_MAC); // sender: gateway
        f[28..32].copy_from_slice(&GW_IP);
        f[32..38].copy_from_slice(&NET_MAC);
        f[38..42].copy_from_slice(&OUR_IP);
        f
    }

    fn process_tx(&self) {
        let (tx, rx) = {
            let st = self.state.borrow();
            (st.queues[1], st.queues[0])
        };
        if tx.num == 0 {
            return;
        }
        let mut mem = self.guest.mem.borrow_mut();

        let tx_avail = ld16(&mem, tx.avail + 2);
        let tx_used = ld16(&mem, tx.used + 2);
        if tx_avail == tx_used {
            return;
        }
        let tx_slot = (tx_used as usize) % (tx.num as usize);
        let tx_head = u64::from(ld16(&mem, tx.avail + 4 + tx_slot as u64 * 2));
        let td = tx.desc + tx_head * 16;
        let frame_addr = ld64(&mem, td) as usize;
        let frame_len = ld32(&mem, td + 8) as usize;

        // The frame is [net header | ethernet]; parse the ARP past the header.
        let arp_at = frame_addr + NET_HDR_LEN;
        let is_arp_request_for_gateway = frame_len >= NET_HDR_LEN + arp::FRAME_LEN
            && u16::from_be_bytes([mem[arp_at + 12], mem[arp_at + 13]]) == arp::ETHERTYPE_ARP
            && u16::from_be_bytes([mem[arp_at + 20], mem[arp_at + 21]]) == arp::OP_REQUEST
            && mem[arp_at + 38..arp_at + 42] == GW_IP;

        if is_arp_request_for_gateway && rx.num != 0 {
            let rx_avail = ld16(&mem, rx.avail + 2);
            let rx_used = ld16(&mem, rx.used + 2);
            if rx_avail != rx_used {
                let rx_slot = (rx_used as usize) % (rx.num as usize);
                let rx_head = u64::from(ld16(&mem, rx.avail + 4 + rx_slot as u64 * 2));
                let rd = rx.desc + rx_head * 16;
                let rx_buf = ld64(&mem, rd) as usize;
                for i in 0..NET_HDR_LEN {
                    mem[rx_buf + i] = 0; // zero net header
                }
                // **The chain is followed, not assumed.** A driver may post
                // the header and the frame as two descriptors so the frame
                // starts at its buffer's first byte; a mock that always wrote
                // both into the head would agree with a driver that got the
                // split wrong.
                let flags = ld16(&mem, rd + 12);
                let frame_at = if flags & 1 != 0 {
                    let next = u64::from(ld16(&mem, rd + 14));
                    ld64(&mem, rx.desc + next * 16) as usize
                } else {
                    rx_buf + NET_HDR_LEN
                };
                let reply = Self::arp_reply();
                for (i, byte) in reply.iter().enumerate() {
                    mem[frame_at + i] = *byte;
                }
                let rx_used_at = rx.used + 4 + rx_slot as u64 * 8;
                st32(&mut mem, rx_used_at, rx_head as u32);
                st32(
                    &mut mem,
                    rx_used_at + 4,
                    (NET_HDR_LEN + arp::FRAME_LEN) as u32,
                );
                st16(&mut mem, rx.used + 2, rx_used.wrapping_add(1));
            }
        }

        let tx_used_at = tx.used + 4 + tx_slot as u64 * 8;
        st32(&mut mem, tx_used_at, tx_head as u32);
        st32(&mut mem, tx_used_at + 4, frame_len as u32);
        st16(&mut mem, tx.used + 2, tx_used.wrapping_add(1));
        drop(mem);
        self.state.borrow_mut().interrupt_status = 1;
    }
}

impl Mmio for MockNet<'_> {
    fn read(&self, offset: usize) -> u32 {
        let st = self.state.borrow();
        match offset {
            reg::MAGIC_VALUE => MAGIC,
            reg::VERSION => VERSION,
            reg::DEVICE_ID => self.device_id,
            reg::DEVICE_FEATURES => {
                if st.device_features_sel == 1 {
                    FEATURE_VERSION_1_BIT // VERSION_1 in the high word
                } else if self.offers_status {
                    NET_F_MAC | NET_F_STATUS
                } else {
                    NET_F_MAC // MAC offered in the low word
                }
            }
            reg::QUEUE_NUM_MAX => DEVICE_MAX_QUEUE,
            reg::STATUS => st.status,
            reg::INTERRUPT_STATUS => st.interrupt_status,
            // Config space: the MAC, little-endian across two words.
            o if o == reg::CONFIG => {
                u32::from_le_bytes([NET_MAC[0], NET_MAC[1], NET_MAC[2], NET_MAC[3]])
            }
            // The second word is the MAC's last two bytes and, at offset 6,
            // the link-status field. Written out here as the device lays it
            // out, so a driver reading the wrong half of the word fails the
            // test rather than agreeing with a mock that shares its mistake.
            o if o == reg::CONFIG + 4 => {
                let status = if self.link_up { NET_S_LINK_UP } else { 0 };
                u32::from_le_bytes([
                    NET_MAC[4],
                    NET_MAC[5],
                    status.to_le_bytes()[0],
                    status.to_le_bytes()[1],
                ])
            }
            _ => 0,
        }
    }

    fn write(&self, offset: usize, value: u32) {
        if offset == reg::QUEUE_NOTIFY {
            if value == 1 {
                self.process_tx();
            }
            return;
        }
        let mut st = self.state.borrow_mut();
        let q = st.queue_sel;
        match offset {
            reg::STATUS => st.status = value,
            reg::DEVICE_FEATURES_SEL => st.device_features_sel = value,
            reg::QUEUE_SEL => st.queue_sel = value as usize,
            reg::QUEUE_NUM => st.queues[q].num = value,
            reg::QUEUE_DESC_LOW => {
                st.queues[q].desc = (st.queues[q].desc & !0xffff_ffff) | u64::from(value)
            }
            reg::QUEUE_DESC_HIGH => {
                st.queues[q].desc = (st.queues[q].desc & 0xffff_ffff) | (u64::from(value) << 32)
            }
            reg::QUEUE_DRIVER_LOW => {
                st.queues[q].avail = (st.queues[q].avail & !0xffff_ffff) | u64::from(value)
            }
            reg::QUEUE_DRIVER_HIGH => {
                st.queues[q].avail = (st.queues[q].avail & 0xffff_ffff) | (u64::from(value) << 32)
            }
            reg::QUEUE_DEVICE_LOW => {
                st.queues[q].used = (st.queues[q].used & !0xffff_ffff) | u64::from(value)
            }
            reg::QUEUE_DEVICE_HIGH => {
                st.queues[q].used = (st.queues[q].used & 0xffff_ffff) | (u64::from(value) << 32)
            }
            reg::INTERRUPT_ACK => st.interrupt_status &= !value,
            _ => {}
        }
    }
}

fn net_queue(base: u64, layout: Layout) -> QueueAddrs {
    QueueAddrs {
        desc: base,
        avail: base + layout.avail_offset as u64,
        used: base + layout.used_offset as u64,
    }
}

#[test]
fn a_net_arp_round_trip_completes_both_queues() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockNet::new(&guest);
    let layout = Layout::for_size(QUEUE_SIZE);
    let rx = net_queue(RX_Q, layout);
    let tx = net_queue(TX_Q, layout);

    let net = Net::init(&device, rx, tx, QUEUE_SIZE).expect("net handshake");
    assert_eq!(net.mac(), NET_MAC, "MAC read from config space");

    // Post a receive buffer so the device has somewhere to deliver the reply.
    {
        let mut mem = guest.mem.borrow_mut();
        let (desc, rest) = mem[RX_Q as usize..].split_at_mut(layout.avail_offset);
        let avail = &mut rest[..layout.used_offset - layout.avail_offset];
        net.post_rx(desc, avail, RX_BUF, RX_BUF_LEN, 0);
    }
    net.notify_rx();

    // Build the ARP request into [net header | frame] and transmit it.
    {
        let mut mem = guest.mem.borrow_mut();
        let frame = arp::build_request(NET_MAC, OUR_IP, GW_IP);
        for (i, byte) in frame.iter().enumerate() {
            mem[TX_BUF as usize + NET_HDR_LEN + i] = *byte;
        }
        let (desc, rest) = mem[TX_Q as usize..].split_at_mut(layout.avail_offset);
        let avail = &mut rest[..layout.used_offset - layout.avail_offset];
        net.post_tx(
            desc,
            avail,
            TX_BUF,
            (NET_HDR_LEN + arp::FRAME_LEN) as u32,
            0,
        );
    }
    net.notify_tx(); // the device processes synchronously

    let mem = guest.mem.borrow();
    // The transmit completed, and the reply landed on the receive queue.
    assert!(
        net.tx_completion(&mem[tx.used as usize..], 0)
            .unwrap()
            .is_some(),
        "transmit completed"
    );
    let (_id, len) = net
        .rx_completion(&mem[rx.used as usize..], 0)
        .unwrap()
        .expect("a frame was received");
    assert_eq!(len as usize, NET_HDR_LEN + arp::FRAME_LEN);

    let received =
        &mem[RX_BUF as usize + NET_HDR_LEN..RX_BUF as usize + NET_HDR_LEN + arp::FRAME_LEN];
    let reply = arp::parse_reply(received).expect("a valid ARP reply");
    assert_eq!(reply.sender_ip, GW_IP, "reply came from the gateway");
    assert_eq!(reply.sender_mac, GW_MAC);
}

/// A split receive post puts the frame at its buffer's **first byte**, with
/// the transport header in memory of the driver's own.
///
/// That is what lets a driver give a received frame away: the buffer it hands
/// over holds the frame and nothing else, so the client is not told to skip
/// twelve bytes of a transport it never negotiated.
#[test]
fn a_split_receive_leaves_the_frame_at_the_start_of_its_own_buffer() {
    const HDR_AT: u64 = 0x0700;
    const FRAME_AT: u64 = 0x1000;
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockNet::new(&guest);
    let layout = Layout::for_size(QUEUE_SIZE);
    let rx = net_queue(RX_Q, layout);
    let tx = net_queue(TX_Q, layout);
    let net = Net::init(&device, rx, tx, QUEUE_SIZE).expect("net handshake");

    {
        let mut mem = guest.mem.borrow_mut();
        let (desc, rest) = mem[RX_Q as usize..].split_at_mut(layout.avail_offset);
        let avail = &mut rest[..layout.used_offset - layout.avail_offset];
        net.post_rx_split(desc, avail, HDR_AT, FRAME_AT, RX_BUF_LEN, 0);
    }
    net.notify_rx();
    {
        let mut mem = guest.mem.borrow_mut();
        let frame = arp::build_request(NET_MAC, OUR_IP, GW_IP);
        for (i, byte) in frame.iter().enumerate() {
            mem[TX_BUF as usize + NET_HDR_LEN + i] = *byte;
        }
        let (desc, rest) = mem[TX_Q as usize..].split_at_mut(layout.avail_offset);
        let avail = &mut rest[..layout.used_offset - layout.avail_offset];
        net.post_tx(
            desc,
            avail,
            TX_BUF,
            (NET_HDR_LEN + arp::FRAME_LEN) as u32,
            0,
        );
    }
    net.notify_tx();

    let mem = guest.mem.borrow();
    let (_id, len) = net
        .rx_completion(&mem[rx.used as usize..], 0)
        .unwrap()
        .expect("a frame was received");
    // The used ring counts everything the device wrote, header included; the
    // frame is what is left after it.
    assert_eq!(len as usize - NET_HDR_LEN, arp::FRAME_LEN);
    let received = &mem[FRAME_AT as usize..FRAME_AT as usize + arp::FRAME_LEN];
    let reply = arp::parse_reply(received).expect("the frame starts at byte zero");
    assert_eq!(reply.sender_mac, GW_MAC);
    assert_eq!(
        &mem[HDR_AT as usize..HDR_AT as usize + NET_HDR_LEN],
        &[0u8; NET_HDR_LEN],
        "the transport header went to the driver's own page",
    );
}

/// **Link state is only a link state when the device said it has one.** A
/// device offering `VIRTIO_NET_F_STATUS` is read; one that does not is up by
/// definition, because a field that was never negotiated holds whatever the
/// device happened to leave there — and a driver taking an interface out of
/// service over that would be acting on noise.
#[test]
fn link_state_is_read_only_from_a_device_that_offers_it() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let layout = Layout::for_size(QUEUE_SIZE);
    let (rx, tx) = (net_queue(RX_Q, layout), net_queue(TX_Q, layout));

    // No status feature: nothing to read, and the link is up by definition.
    let silent = MockNet::new(&guest);
    let net = Net::init(&silent, rx, tx, QUEUE_SIZE).expect("handshake");
    assert!(!net.reports_link());
    assert!(
        net.link_up(),
        "a device with no status field has a live link"
    );

    // Offered and down — the case the default would get wrong.
    let mut down = MockNet::new(&guest);
    down.offers_status = true;
    let net = Net::init(&down, rx, tx, QUEUE_SIZE).expect("handshake");
    assert!(net.reports_link());
    assert!(!net.link_up());
    assert_eq!(net.mac(), NET_MAC, "the MAC shares that word and is intact");

    // Offered and up.
    let mut up = MockNet::new(&guest);
    up.offers_status = true;
    up.link_up = true;
    let net = Net::init(&up, rx, tx, QUEUE_SIZE).expect("handshake");
    assert!(net.link_up());
    assert_eq!(net.mac(), NET_MAC);
}

/// Bringing the link down puts the device back where `init` found it. Checked
/// through the status register because that is the only thing a driver and a
/// device agree about here: queues configured against a reset device are gone,
/// which is what makes this a link going down rather than a flag being set.
#[test]
fn shutting_the_link_down_returns_the_device_to_reset() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockNet::new(&guest);
    let layout = Layout::for_size(QUEUE_SIZE);
    let net = Net::init(
        &device,
        net_queue(RX_Q, layout),
        net_queue(TX_Q, layout),
        QUEUE_SIZE,
    )
    .expect("handshake");
    assert_ne!(device.read(reg::STATUS), 0, "running");
    net.shutdown();
    assert_eq!(device.read(reg::STATUS), 0, "back to reset");
    // And it comes back up through the whole handshake, not a resumption.
    let net = Net::init(
        &device,
        net_queue(RX_Q, layout),
        net_queue(TX_Q, layout),
        QUEUE_SIZE,
    )
    .expect("re-handshake");
    assert_eq!(net.mac(), NET_MAC);
}

#[test]
fn a_non_net_transport_is_rejected() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let mut device = MockNet::new(&guest);
    device.device_id = DEVICE_ID_BLOCK;
    let layout = Layout::for_size(QUEUE_SIZE);
    assert_eq!(
        Net::init(
            &device,
            net_queue(RX_Q, layout),
            net_queue(TX_Q, layout),
            QUEUE_SIZE
        )
        .map(|_| ()),
        Err(Error::NotNetDevice)
    );
}

#[test]
fn an_arp_request_does_not_parse_as_a_reply() {
    let request = arp::build_request(NET_MAC, OUR_IP, GW_IP);
    assert_eq!(arp::parse_reply(&request), None);
    assert_eq!(arp::parse_reply(&[0u8; 8]), None); // too short
}

// --- virtio-pci ---

use crate::pci::{Cap, PciTransport, Regs, cfg_type, common, decode_cap};

/// Where the mock places its notify structure's doorbells: one per queue, so a
/// wrong multiplier lands on the wrong one and the queue never runs.
const NOTIFY_MULTIPLIER: u32 = 4;

/// A mock virtio-pci block device. Its queue behaviour is
/// [`serve_block_queue`] — the same code the virtio-mmio mock runs — so what
/// these tests exercise is the transport and nothing else.
struct MockPciBlk<'g> {
    guest: &'g Guest,
    device_id: u32,
    offers_version_1: bool,
    disk: [u8; SECTOR_LEN],
    state: RefCell<State>,
    pci: RefCell<PciState>,
}

/// The parts of the common configuration structure the mock keeps.
#[derive(Default)]
struct PciState {
    device_feature_select: u32,
    driver_feature_select: u32,
    queue_select: u16,
    /// Set by the driver; reads back the device maximum until then.
    queue_size: u16,
    queue_enable: u16,
    /// Non-zero if a doorbell landed on a queue this device does not have.
    stray_notify: u32,
}

impl<'g> MockPciBlk<'g> {
    fn new(guest: &'g Guest, disk: [u8; SECTOR_LEN]) -> Self {
        Self {
            guest,
            device_id: DEVICE_ID_BLOCK,
            offers_version_1: true,
            disk,
            state: RefCell::new(State::default()),
            pci: RefCell::new(PciState {
                queue_size: QUEUE_SIZE,
                ..PciState::default()
            }),
        }
    }
}

/// Which structure a [`Regs`] handle reaches. One mock device answers for all
/// of them, because on real hardware they are regions of the same BAR.
#[derive(Clone, Copy)]
enum Region {
    Common,
    Notify,
    Isr,
    DeviceCfg,
}

struct MockRegs<'d, 'g> {
    dev: &'d MockPciBlk<'g>,
    region: Region,
}

impl MockRegs<'_, '_> {
    /// Rejects an access whose width is not the field's. A real device would
    /// see a 32-bit write to `device_status` as a write to three fields at
    /// once; a mock that quietly accepted it would let that bug ship.
    fn common_field_width(offset: usize, width: usize) {
        let expected = match offset {
            common::DEVICE_STATUS | common::CONFIG_GENERATION => 1,
            common::CONFIG_MSIX_VECTOR
            | common::NUM_QUEUES
            | common::QUEUE_SELECT
            | common::QUEUE_SIZE
            | common::QUEUE_MSIX_VECTOR
            | common::QUEUE_ENABLE
            | common::QUEUE_NOTIFY_OFF => 2,
            _ => 4,
        };
        assert_eq!(
            width, expected,
            "field at {offset:#x} must be accessed {expected} bytes at a time",
        );
    }
}

impl Regs for MockRegs<'_, '_> {
    fn read8(&self, offset: usize) -> u8 {
        match self.region {
            Region::Isr => 1,
            Region::Common => {
                Self::common_field_width(offset, 1);
                match offset {
                    common::DEVICE_STATUS => self.dev.state.borrow().status as u8,
                    common::CONFIG_GENERATION => 0,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    fn read16(&self, offset: usize) -> u16 {
        match self.region {
            Region::Common => {
                Self::common_field_width(offset, 2);
                let pci = self.dev.pci.borrow();
                match offset {
                    common::NUM_QUEUES => 1,
                    common::QUEUE_SELECT => pci.queue_select,
                    common::QUEUE_SIZE => pci.queue_size,
                    common::QUEUE_ENABLE => pci.queue_enable,
                    // Each queue's doorbell sits one multiplier apart.
                    common::QUEUE_NOTIFY_OFF => pci.queue_select,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    fn read32(&self, offset: usize) -> u32 {
        match self.region {
            // A recognisable pattern per dword, so a driver reading the wrong
            // offset gets the wrong answer rather than a plausible zero.
            Region::DeviceCfg => 0xc0f0_0000 | offset as u32,
            Region::Common => {
                Self::common_field_width(offset, 4);
                let pci = self.dev.pci.borrow();
                match offset {
                    common::DEVICE_FEATURE
                        if pci.device_feature_select == 1 && self.dev.offers_version_1 =>
                    {
                        FEATURE_VERSION_1_BIT
                    }
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    fn write8(&self, offset: usize, value: u8) {
        if let Region::Common = self.region {
            Self::common_field_width(offset, 1);
            if offset == common::DEVICE_STATUS {
                self.dev.state.borrow_mut().status = u32::from(value);
            }
        }
    }

    fn write16(&self, offset: usize, value: u16) {
        match self.region {
            Region::Notify => {
                // The doorbell address encodes the queue; check the driver
                // computed it from the multiplier rather than assuming zero.
                let expected = u32::from(value) * NOTIFY_MULTIPLIER;
                if offset as u32 != expected {
                    self.dev.pci.borrow_mut().stray_notify += 1;
                    return;
                }
                serve_block_queue(self.dev.guest, &self.dev.state, &self.dev.disk);
            }
            Region::Common => {
                Self::common_field_width(offset, 2);
                let mut pci = self.dev.pci.borrow_mut();
                match offset {
                    common::QUEUE_SELECT => pci.queue_select = value,
                    common::QUEUE_SIZE => {
                        pci.queue_size = value;
                        self.dev.state.borrow_mut().q_num = u32::from(value);
                    }
                    common::QUEUE_ENABLE => pci.queue_enable = value,
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn write32(&self, offset: usize, value: u32) {
        if let Region::Common = self.region {
            Self::common_field_width(offset, 4);
            let mut pci = self.dev.pci.borrow_mut();
            let mut st = self.dev.state.borrow_mut();
            match offset {
                common::DEVICE_FEATURE_SELECT => pci.device_feature_select = value,
                common::DRIVER_FEATURE_SELECT => pci.driver_feature_select = value,
                common::QUEUE_DESC => st.q_desc = (st.q_desc & !0xffff_ffff) | u64::from(value),
                QUEUE_DESC_HIGH => {
                    st.q_desc = (st.q_desc & 0xffff_ffff) | (u64::from(value) << 32);
                }
                common::QUEUE_DRIVER => st.q_avail = (st.q_avail & !0xffff_ffff) | u64::from(value),
                QUEUE_DRIVER_HIGH => {
                    st.q_avail = (st.q_avail & 0xffff_ffff) | (u64::from(value) << 32);
                }
                common::QUEUE_DEVICE => st.q_used = (st.q_used & !0xffff_ffff) | u64::from(value),
                QUEUE_DEVICE_HIGH => {
                    st.q_used = (st.q_used & 0xffff_ffff) | (u64::from(value) << 32);
                }
                _ => {}
            }
        }
    }
}

/// The high halves of the 64-bit common-config fields, which the transport
/// writes as two 32-bit accesses.
const QUEUE_DESC_HIGH: usize = common::QUEUE_DESC + 4;
const QUEUE_DRIVER_HIGH: usize = common::QUEUE_DRIVER + 4;
const QUEUE_DEVICE_HIGH: usize = common::QUEUE_DEVICE + 4;

/// A capability's four dwords are decoded, not guessed: `cfg_type` is the high
/// byte of the first word and `bar` the low byte of the second, which is easy
/// to get one field out of step.
#[test]
fn a_vendor_capability_decodes_to_the_structure_it_describes() {
    // cap_vndr 0x09, cap_next 0x50, cap_len 16, cfg_type COMMON | bar 4
    let words = [
        0x09 | (0x50 << 8) | (16 << 16) | (u32::from(cfg_type::COMMON) << 24),
        0x0000_0004,
        0x0000_3000,
        0x0000_1000,
    ];
    assert_eq!(
        decode_cap(words),
        Cap {
            cfg_type: cfg_type::COMMON,
            bar: 4,
            offset: 0x3000,
            length: 0x1000,
        }
    );
}

/// The claim: a full sector read through the **PCI** transport, over the same
/// rings and the same device-side queue logic the mmio transport uses.
#[test]
fn a_sector_reads_through_the_pci_transport() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let mut disk = [0u8; SECTOR_LEN];
    disk[0..8].copy_from_slice(b"TESSERAV");
    let device = MockPciBlk::new(&guest, disk);
    let common = MockRegs {
        dev: &device,
        region: Region::Common,
    };
    let notify = MockRegs {
        dev: &device,
        region: Region::Notify,
    };
    let isr = MockRegs {
        dev: &device,
        region: Region::Isr,
    };
    let transport = PciTransport::new(
        &common,
        &notify,
        NOTIFY_MULTIPLIER,
        Some(&isr),
        None,
        DEVICE_ID_BLOCK,
    );

    let layout = Layout::for_size(QUEUE_SIZE);
    let avail_phys = DESC_PHYS + layout.avail_offset as u64;
    let used_phys = DESC_PHYS + layout.used_offset as u64;
    let blk = Blk::init(&transport, QUEUE_SIZE, DESC_PHYS, avail_phys, used_phys)
        .expect("bring-up over pci");

    {
        let mut mem = guest.mem.borrow_mut();
        let header = blk_read_header(0);
        mem[HEADER_PHYS as usize..HEADER_PHYS as usize + BLK_HEADER_LEN].copy_from_slice(&header);
        mem[STATUS_PHYS as usize] = 0xff;
        let region = DESC_PHYS as usize;
        let (desc, rest) = mem[region..].split_at_mut(layout.avail_offset);
        let avail = &mut rest[..layout.used_offset - layout.avail_offset];
        blk.write_read_request(desc, avail, HEADER_PHYS, DATA_PHYS, STATUS_PHYS, 0);
    }
    blk.notify();

    assert_eq!(
        device.pci.borrow().stray_notify,
        0,
        "the doorbell address must be computed from the multiplier",
    );
    let mem = guest.mem.borrow();
    let (head, len) = blk
        .completion(&mem[used_phys as usize..], 0)
        .expect("well-formed completion")
        .expect("the device completed the request");
    assert_eq!(head, 0);
    assert_eq!(len as usize, SECTOR_LEN + 1);
    assert_eq!(mem[STATUS_PHYS as usize], BLK_S_OK);
    assert_eq!(
        &mem[DATA_PHYS as usize..DATA_PHYS as usize + 8],
        b"TESSERAV"
    );
}

/// A device that does not offer `VIRTIO_F_VERSION_1` is refused on this
/// transport too. virtio-pci has no version register to check, so this is the
/// *only* thing standing between the driver and a legacy device.
#[test]
fn a_legacy_only_device_is_rejected_over_pci() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let mut device = MockPciBlk::new(&guest, [0u8; SECTOR_LEN]);
    device.offers_version_1 = false;
    let common = MockRegs {
        dev: &device,
        region: Region::Common,
    };
    let notify = MockRegs {
        dev: &device,
        region: Region::Notify,
    };
    let transport = PciTransport::new(
        &common,
        &notify,
        NOTIFY_MULTIPLIER,
        None,
        None,
        DEVICE_ID_BLOCK,
    );
    let layout = Layout::for_size(QUEUE_SIZE);
    assert_eq!(
        Blk::init(
            &transport,
            QUEUE_SIZE,
            DESC_PHYS,
            DESC_PHYS + layout.avail_offset as u64,
            DESC_PHYS + layout.used_offset as u64,
        )
        .err(),
        Some(Error::NoModernFeature)
    );
}

/// A device of the wrong kind is refused before any of its state is touched.
#[test]
fn a_non_block_pci_device_is_rejected() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let mut device = MockPciBlk::new(&guest, [0u8; SECTOR_LEN]);
    device.device_id = DEVICE_ID_NET;
    let common = MockRegs {
        dev: &device,
        region: Region::Common,
    };
    let notify = MockRegs {
        dev: &device,
        region: Region::Notify,
    };
    let transport = PciTransport::new(
        &common,
        &notify,
        NOTIFY_MULTIPLIER,
        None,
        None,
        DEVICE_ID_NET,
    );
    let layout = Layout::for_size(QUEUE_SIZE);
    assert_eq!(
        Blk::init(
            &transport,
            QUEUE_SIZE,
            DESC_PHYS,
            DESC_PHYS + layout.avail_offset as u64,
            DESC_PHYS + layout.used_offset as u64,
        )
        .err(),
        Some(Error::NotBlockDevice)
    );
}

/// A transitional device id is not the modern one minus a constant. QEMU's
/// `virtio-blk-pci` is `1af4:1001`, and a driver that only knew the modern rule
/// would compute a device type of 0xffc1 and refuse a working disk.
#[test]
fn both_pci_device_id_encodings_name_the_same_device_type() {
    use crate::pci::device_type;
    assert_eq!(device_type(0x1001), Some(2), "transitional block");
    assert_eq!(device_type(0x1042), Some(2), "modern block");
    assert_eq!(device_type(0x1000), Some(1), "transitional network");
    assert_eq!(device_type(0x1041), Some(1), "modern network");
    // Not a virtio id at all — the `edu` device, which shares no encoding.
    assert_eq!(device_type(0x11e8), None);
}

/// Device-specific configuration is its own structure on this transport, not
/// an offset inside the common one — a driver reading the virtio-net MAC would
/// otherwise read the tail of the queue fields. And a device that has no such
/// structure answers zero rather than reading address zero.
#[test]
fn device_configuration_comes_from_its_own_region() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockPciBlk::new(&guest, [0u8; SECTOR_LEN]);
    let common = MockRegs {
        dev: &device,
        region: Region::Common,
    };
    let notify = MockRegs {
        dev: &device,
        region: Region::Notify,
    };
    let device_cfg = MockRegs {
        dev: &device,
        region: Region::DeviceCfg,
    };

    let with = PciTransport::new(
        &common,
        &notify,
        NOTIFY_MULTIPLIER,
        None,
        Some(&device_cfg),
        DEVICE_ID_BLOCK,
    );
    assert_eq!(with.config_u32(0), 0xc0f0_0000);
    assert_eq!(
        with.config_u32(4),
        0xc0f0_0004,
        "offset is within that region"
    );

    let without = PciTransport::new(
        &common,
        &notify,
        NOTIFY_MULTIPLIER,
        None,
        None,
        DEVICE_ID_BLOCK,
    );
    assert_eq!(
        without.config_u32(0),
        0,
        "absent structure, not address zero"
    );
}

/// A read marks the data descriptor device-writable and a write must not.
///
/// This is the whole difference between the two request shapes, and getting it
/// wrong is silent: a write whose buffer is marked writable hands the device
/// permission to scribble on the driver's data, and the transfer still reports
/// success. The flags are checked bit for bit because there is no later symptom
/// that would name this as the cause.
#[test]
fn a_write_does_not_mark_the_drivers_data_device_writable() {
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockBlk::new(&guest, [7u8; SECTOR_LEN]);
    let layout = Layout::for_size(QUEUE_SIZE);
    let blk = Blk::init(
        &device,
        QUEUE_SIZE,
        DESC_PHYS,
        DESC_PHYS + layout.avail_offset as u64,
        DESC_PHYS + layout.used_offset as u64,
    )
    .unwrap();
    let mut desc = [0u8; 3 * 16];
    let mut avail = [0u8; 64];

    blk.write_read_request(&mut desc, &mut avail, 0x1000, 0x2000, 0x3000, 0);
    let read_data_flags = u16::from_le_bytes([desc[16 + 12], desc[16 + 13]]);
    assert_eq!(
        read_data_flags & 2,
        2,
        "a read's data buffer is filled by the device",
    );

    blk.write_write_request(&mut desc, &mut avail, 0x1000, 0x2000, 0x3000, 0);
    let write_data_flags = u16::from_le_bytes([desc[16 + 12], desc[16 + 13]]);
    assert_eq!(
        write_data_flags & 2,
        0,
        "a write's data buffer is read by the device, never written",
    );
    // The chain is otherwise identical: header readable and chained, status
    // writable and terminal.
    assert_eq!(u16::from_le_bytes([desc[12], desc[13]]) & 2, 0, "header");
    assert_eq!(
        u16::from_le_bytes([desc[32 + 12], desc[32 + 13]]) & 2,
        2,
        "status is written by the device on both",
    );
}

/// The request type is the only thing that tells the device which way the data
/// travels, and each direction gets its own encoder so a caller cannot pass the
/// wrong one by passing the wrong integer.
#[test]
fn each_request_header_carries_its_own_direction() {
    let read = blk_read_header(9);
    let write = blk_write_header(9);
    assert_eq!(u32::from_le_bytes([read[0], read[1], read[2], read[3]]), 0);
    assert_eq!(
        u32::from_le_bytes([write[0], write[1], write[2], write[3]]),
        1,
    );
    // Same sector, opposite directions.
    assert_eq!(read[8..16], write[8..16]);
    assert_eq!(u64::from_le_bytes(read[8..16].try_into().unwrap()), 9);

    // A flush names no sector, and says so with a zero rather than with
    // whatever the caller's buffer held.
    let flush = blk_flush_header();
    assert_eq!(
        u32::from_le_bytes([flush[0], flush[1], flush[2], flush[3]]),
        4,
    );
    assert_eq!(flush[8..16], [0u8; 8]);
}

// ---------------------------------------------------------------------------
// Multiqueue: the parts a mock cannot vouch for.
//
// The bring-up itself is proven against a real device in the boot check — a
// mock would agree with whatever this crate did. What is tested here is the
// refusals, which are the difference between a driver that hands a child its
// own queue and one that quietly hands it the controller's.
// ---------------------------------------------------------------------------

#[test]
fn num_queues_is_read_from_the_high_half_of_its_word() {
    // The field is a u16 at byte 34, so it is the high half of the aligned word
    // at 32. Taking the low half reads `writeback` and an unused byte, which on
    // a device with write-back caching enabled is 1 — a plausible queue count,
    // and the reason this is worth a test rather than a comment.
    assert_eq!(blk_num_queues(0x0004_0001), 4);
    assert_eq!(blk_num_queues(0x0001_0001), 1);
    assert_eq!(blk_num_queues(0), 0);
}

#[test]
fn a_device_offering_no_multiqueue_is_refused_rather_than_brought_up_singly() {
    // MockBlk offers no feature bits, so it has one queue. Falling back would
    // give a child driver the controller's own queue under the name of its own.
    let guest = Guest {
        mem: RefCell::new([0u8; MEM_LEN]),
    };
    let device = MockBlk::new(&guest, [0u8; 512]);
    let blank = QueueAddrs {
        desc: 0,
        avail: 0,
        used: 0,
    };
    assert_eq!(
        Blk::init_multiqueue(&device, &[blank; 2], QUEUE_SIZE).err(),
        Some(Error::NotBlockDevice)
    );
    assert_eq!(
        Blk::init_multiqueue(&device, &[], QUEUE_SIZE).err(),
        Some(Error::QueueSize)
    );
}

// --- virtio-sound ------------------------------------------------------------

use crate::snd;

/// **A period that does not divide the buffer is refused.** The device consumes
/// whole periods, so the remainder is a piece of buffer that is never played
/// and never returned — the stream would lose a little of its latency budget
/// every time round and nothing would say why.
#[test]
fn stream_parameters_must_describe_something_playable() {
    let good = snd::Params {
        stream: 0,
        buffer_bytes: 4096,
        period_bytes: 1024,
        channels: 2,
        format: snd::FORMAT_S16,
        rate: snd::RATE_44100,
    };
    assert!(good.check().is_ok());
    assert_eq!(
        good.periods(),
        4,
        "four periods in flight, and a client is told"
    );

    let ragged = snd::Params {
        period_bytes: 1000,
        ..good
    };
    assert_eq!(ragged.check(), Err(Error::BadStreamParams));

    // A period larger than the buffer, and a buffer of nothing: both are a
    // stream that cannot hold what it says it will.
    assert_eq!(
        snd::Params {
            period_bytes: 8192,
            ..good
        }
        .check(),
        Err(Error::BadStreamParams),
    );
    assert_eq!(
        snd::Params {
            buffer_bytes: 0,
            ..good
        }
        .check(),
        Err(Error::BadStreamParams),
    );
    assert_eq!(
        snd::Params {
            channels: 0,
            ..good
        }
        .check(),
        Err(Error::BadStreamParams),
    );

    // And the encoder refuses what the check refuses, so a bad set of
    // parameters never reaches the wire.
    let mut out = [0u8; snd::SET_PARAMS_LEN];
    assert_eq!(
        snd::set_params(&ragged, &mut out),
        Err(Error::BadStreamParams),
    );
    assert_eq!(snd::set_params(&good, &mut out), Ok(snd::Queue::Control));
    assert_eq!(
        u32::from_le_bytes([out[0], out[1], out[2], out[3]]),
        snd::request::PCM_SET_PARAMS,
    );
    assert_eq!(u32::from_le_bytes([out[8], out[9], out[10], out[11]]), 4096);
    assert_eq!(
        u32::from_le_bytes([out[12], out[13], out[14], out[15]]),
        1024
    );
    assert_eq!(out[20], 2);
    assert_eq!(out[21], snd::FORMAT_S16);
    assert_eq!(out[22], snd::RATE_44100);
}

/// **Which queue a message belongs on is part of the message.** The four queues
/// are not interchangeable the way NVMe's pairs are: a control request put on
/// the transmit queue is not a slow request, it is noise played to somebody.
#[test]
fn the_queue_a_message_belongs_on_comes_back_with_it() {
    let mut out = [0u8; 32];
    assert_eq!(
        snd::stream_request(snd::request::PCM_START, 0, &mut out),
        Ok(snd::Queue::Control),
    );
    assert_eq!(
        u32::from_le_bytes([out[0], out[1], out[2], out[3]]),
        snd::request::PCM_START,
    );
    assert_eq!(snd::xfer_header(0, &mut out), Ok(snd::Queue::Transmit));
    assert_eq!(snd::Queue::Control as u16, 0);
    assert_eq!(snd::Queue::Transmit as u16, 2);
}

/// **Success is 0x8000, not zero.** A driver testing a control status for zero
/// would read every success as a failure, which is the opposite of the usual
/// convention and exactly what a second reader assumes.
#[test]
fn a_control_status_succeeds_at_a_value_that_is_not_zero() {
    assert!(snd::accepted(snd::status::OK));
    assert!(!snd::accepted(0));
    assert!(!snd::accepted(snd::status::NOT_SUPPORTED));
    assert_eq!(
        snd::control_status(&snd::status::OK.to_le_bytes()),
        Ok(snd::status::OK),
    );
    assert_eq!(snd::control_status(&[0u8; 2]), Err(Error::ShortResponse));
}

/// **The status is at the end of the buffer, and the used ring's length is
/// not.** A used element's length is what the device wrote, which here is the
/// status — so taking it for bytes played reads eight where a period is a
/// thousand, and a driver would keep handing over periods believing it had
/// barely started.
#[test]
fn a_transfer_status_is_read_from_the_buffer_and_not_from_a_length() {
    let mut buffer = [0u8; snd::XFER_STATUS_LEN];
    buffer[0..4].copy_from_slice(&snd::status::OK.to_le_bytes());
    buffer[4..8].copy_from_slice(&64u32.to_le_bytes());
    let status = snd::XferStatus::parse(&buffer).expect("status");
    assert!(status.is_ok());
    assert_eq!(status.latency_bytes, 64);

    buffer[0..4].copy_from_slice(&snd::status::IO_ERROR.to_le_bytes());
    assert!(!snd::XferStatus::parse(&buffer).expect("status").is_ok());
    assert_eq!(
        snd::XferStatus::parse(&buffer[..4]),
        Err(Error::ShortResponse),
    );
}

/// A device with no streams is refused rather than driven: every request names
/// one, and there is nothing useful to do with a sound card that has none.
#[test]
fn a_device_with_no_streams_is_refused() {
    assert_eq!(
        snd::Config::parse([1, 1, 1]),
        Ok(snd::Config {
            jacks: 1,
            streams: 1,
            channel_maps: 1,
        }),
    );
    assert_eq!(snd::Config::parse([1, 0, 1]), Err(Error::NotSoundDevice));
}

/// A stream is asked what it can do before it is told what to do. A device that
/// refuses `PCM_SET_PARAMS` answers "bad message" for every possible reason, so
/// a driver that had not asked could not tell an unsupported rate from a
/// malformed request.
#[test]
fn a_streams_capabilities_are_read_before_it_is_configured() {
    let mut bytes = [0u8; snd::PCM_INFO_LEN];
    bytes[12..16].copy_from_slice(&(1u32 << snd::FORMAT_S16).to_le_bytes());
    bytes[20..24].copy_from_slice(&(1u32 << snd::RATE_44100).to_le_bytes());
    bytes[28] = 0; // playback
    bytes[29] = 1;
    bytes[30] = 2;
    let info = snd::PcmInfo::parse(&bytes).expect("info");
    assert!(info.is_playback());
    assert_eq!(info.channels_max, 2);
    assert!(info.supports(snd::FORMAT_S16, snd::RATE_44100));
    // A rate it does not offer, which is what the ask exists to catch.
    assert!(!info.supports(snd::FORMAT_S16, snd::RATE_44100 + 1));

    bytes[28] = 1;
    assert!(!snd::PcmInfo::parse(&bytes).expect("info").is_playback());
    assert_eq!(snd::PcmInfo::parse(&bytes[..8]), Err(Error::ShortResponse));
}

/// **Underrun is the driver's observation and nothing else's.** The device does
/// not fault when it runs dry — it plays silence and carries on — so no
/// register anywhere says a gap was heard. What says it is that the driver had
/// nothing ready when a period came back.
#[test]
fn a_stream_that_ran_dry_says_so_and_one_that_did_not_says_that() {
    let mut fed = snd::Stream::new(4);
    for _ in 0..4 {
        fed.submitted().expect("room");
    }
    assert!(!fed.has_room(), "the device is holding all it can");
    assert_eq!(fed.submitted(), Err(Error::StreamFull));

    // Each period comes back and is replaced.
    for _ in 0..4 {
        fed.completed(true);
        fed.submitted().expect("room");
    }
    assert_eq!(fed.played(), 4);
    assert_eq!(fed.outstanding(), 4);
    assert_eq!(fed.underruns(), 0, "and zero is an answer, not a silence");

    // A stream nobody fed. It is still running, the device did not fail, and
    // the only thing that knows is this.
    let mut starved = snd::Stream::new(2);
    starved.submitted().expect("room");
    starved.submitted().expect("room");
    starved.completed(false);
    starved.completed(false);
    assert_eq!(starved.played(), 2);
    assert_eq!(starved.outstanding(), 0);
    assert_eq!(starved.underruns(), 2);
}

// --- virtio-gpu 2D -----------------------------------------------------------

use crate::gpu;

/// **The check the device does not do for you.** A flush naming a rectangle
/// past a resource's edge is not refused by the hardware — it reads whatever
/// follows the backing and puts it on the screen — so the arithmetic is done
/// here, where it needs no device to get wrong.
#[test]
fn a_rectangle_past_the_resource_is_refused_before_it_is_sent() {
    let full = gpu::Rect {
        x: 0,
        y: 0,
        width: 640,
        height: 480,
    };
    assert!(full.within(640, 480));

    // One pixel too wide, and one too tall.
    assert!(!gpu::Rect { width: 641, ..full }.within(640, 480));
    assert!(
        !gpu::Rect {
            height: 481,
            ..full
        }
        .within(640, 480)
    );
    // In range on its own, and out of range where it starts.
    assert!(
        !gpu::Rect {
            x: 1,
            width: 640,
            ..full
        }
        .within(640, 480)
    );
    // Empty is not a rectangle: a device asked to flush nothing reports success
    // and shows nothing, which is indistinguishable from a driver that worked.
    assert!(!gpu::Rect { width: 0, ..full }.within(640, 480));

    // **The wrap.** The sum of an offset and a width is exactly where 32-bit
    // arithmetic turns an obviously wrong rectangle into a plausible one: this
    // one's right edge is zero in 32 bits and enormous in truth.
    assert!(
        !gpu::Rect {
            x: u32::MAX,
            width: 1,
            ..full
        }
        .within(640, 480)
    );

    // And the encoders refuse what the check refuses, so a bad rectangle never
    // reaches the wire.
    let mut out = [0u8; 256];
    let bad = gpu::Rect { width: 641, ..full };
    assert_eq!(
        gpu::resource_flush(1, bad, 640, 480, &mut out),
        Err(Error::BadRect),
    );
    assert_eq!(
        gpu::transfer_to_host_2d(1, bad, 0, 640, 480, &mut out),
        Err(Error::BadRect),
    );
    assert_eq!(
        gpu::set_scanout(0, 1, bad, 640, 480, &mut out),
        Err(Error::BadRect),
    );
    assert_eq!(
        gpu::resource_flush(1, full, 640, 480, &mut out),
        Ok(gpu::FLUSH_LEN)
    );
}

/// **Success is a range, not a value.** A display-info answer and an empty
/// acknowledgement are both success, so a driver comparing against one of them
/// would read the other as a failure.
#[test]
fn both_kinds_of_success_are_success() {
    assert!(gpu::accepted(gpu::response::OK_NODATA));
    assert!(gpu::accepted(gpu::response::OK_DISPLAY_INFO));
    assert!(!gpu::accepted(gpu::response::ERR_INVALID_RESOURCE_ID));
    assert!(!gpu::accepted(0));

    let mut bytes = [0u8; gpu::HEADER_LEN];
    bytes[0..4].copy_from_slice(&gpu::response::OK_DISPLAY_INFO.to_le_bytes());
    assert_eq!(
        gpu::response_type(&bytes),
        Ok(gpu::response::OK_DISPLAY_INFO)
    );
    assert_eq!(gpu::response_type(&bytes[..4]), Err(Error::ShortResponse));
}

/// **A display with nothing attached is a state, not a fault.** A machine with
/// no monitor is an ordinary machine, and a driver that could not tell it from
/// a broken device would report a fault for something nobody plugged in.
#[test]
fn a_scanout_says_what_it_is_and_whether_anything_is_there() {
    let mut bytes = [0u8; gpu::DISPLAY_INFO_LEN];
    bytes[0..4].copy_from_slice(&gpu::response::OK_DISPLAY_INFO.to_le_bytes());
    let put = |bytes: &mut [u8], at: usize, value: u32| {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    put(&mut bytes, gpu::HEADER_LEN + 8, 1280);
    put(&mut bytes, gpu::HEADER_LEN + 12, 800);
    put(&mut bytes, gpu::HEADER_LEN + 16, 1);
    let scanout = gpu::Scanout::parse_first(&bytes).expect("scanout");
    assert_eq!(scanout.width, 1280);
    assert_eq!(scanout.height, 800);
    assert!(scanout.enabled);
    assert_eq!(scanout.framebuffer_bytes(), Some(1280 * 800 * 4));

    put(&mut bytes, gpu::HEADER_LEN + 16, 0);
    assert!(!gpu::Scanout::parse_first(&bytes).expect("scanout").enabled);

    // A resolution whose framebuffer does not fit in the arithmetic is one this
    // driver cannot back, rather than one it should try to.
    let huge = gpu::Scanout {
        width: u32::MAX,
        height: u32::MAX,
        ..scanout
    };
    assert_eq!(huge.framebuffer_bytes(), None);
    assert_eq!(
        gpu::Scanout::parse_first(&bytes[..8]),
        Err(Error::ShortResponse),
    );
}

/// A backing is a **list**, and the device reads every byte of every entry — so
/// an empty one is a resource with nowhere to read from, which the device would
/// accept and then read nothing out of.
#[test]
fn a_backing_describes_every_region_and_refuses_to_describe_none() {
    let mut out = [0u8; 256];
    assert_eq!(
        gpu::resource_attach_backing(1, &[], &mut out),
        Err(Error::BadRect),
    );
    let entries = [(0x4000_0000u64, 4096u32), (0x4000_2000, 4096)];
    let len = gpu::resource_attach_backing(1, &entries, &mut out).expect("attach");
    assert_eq!(len, gpu::ATTACH_HEADER_LEN + 2 * gpu::ATTACH_ENTRY_LEN);
    assert_eq!(gpu_word(&out, 0), gpu::command::RESOURCE_ATTACH_BACKING);
    assert_eq!(gpu_word(&out, gpu::HEADER_LEN), 1, "the resource");
    assert_eq!(
        gpu_word(&out, gpu::HEADER_LEN + 4),
        2,
        "and how many regions"
    );
    assert_eq!(gpu_long(&out, gpu::ATTACH_HEADER_LEN), 0x4000_0000);
    assert_eq!(
        gpu_long(&out, gpu::ATTACH_HEADER_LEN + gpu::ATTACH_ENTRY_LEN),
        0x4000_2000,
        "the second region, at its own address rather than the first's",
    );
}

/// Resource zero is what `SET_SCANOUT` means by "no resource", so creating one
/// would give a driver a resource it cannot tell from having none.
#[test]
fn resource_zero_cannot_be_created() {
    let mut out = [0u8; 256];
    assert_eq!(
        gpu::resource_create_2d(0, 64, 64, gpu::FORMAT_B8G8R8A8, &mut out),
        Err(Error::BadRect),
    );
    assert_eq!(
        gpu::resource_create_2d(1, 0, 64, gpu::FORMAT_B8G8R8A8, &mut out),
        Err(Error::BadRect),
    );
    let len = gpu::resource_create_2d(1, 64, 32, gpu::FORMAT_B8G8R8A8, &mut out).expect("create");
    assert_eq!(len, gpu::CREATE_2D_LEN);
    assert_eq!(gpu_word(&out, 0), gpu::command::RESOURCE_CREATE_2D);
    assert_eq!(gpu_word(&out, gpu::HEADER_LEN), 1);
    assert_eq!(gpu_word(&out, gpu::HEADER_LEN + 4), gpu::FORMAT_B8G8R8A8);
    assert_eq!(gpu_word(&out, gpu::HEADER_LEN + 8), 64);
    assert_eq!(gpu_word(&out, gpu::HEADER_LEN + 12), 32);
}

/// A transfer carries the offset into the backing its first row starts at,
/// because only the caller knows the stride it wrote at — and a flush carries
/// none, because it moves nothing.
#[test]
fn a_transfer_carries_the_offset_a_flush_does_not() {
    let mut out = [0u8; 256];
    let rect = gpu::Rect {
        x: 0,
        y: 4,
        width: 16,
        height: 8,
    };
    gpu::transfer_to_host_2d(1, rect, 4 * 64 * 4, 64, 64, &mut out).expect("transfer");
    assert_eq!(gpu_word(&out, 0), gpu::command::TRANSFER_TO_HOST_2D);
    assert_eq!(
        gpu_word(&out, gpu::HEADER_LEN + 4),
        4,
        "the rectangle's row"
    );
    let offset = u64::from(gpu_word(&out, gpu::HEADER_LEN + 16))
        | (u64::from(gpu_word(&out, gpu::HEADER_LEN + 20)) << 32);
    assert_eq!(offset, 4 * 64 * 4);
    assert_eq!(gpu_word(&out, gpu::HEADER_LEN + 24), 1, "and the resource");

    gpu::resource_flush(1, rect, 64, 64, &mut out).expect("flush");
    assert_eq!(gpu_word(&out, 0), gpu::command::RESOURCE_FLUSH);
    assert_eq!(gpu_word(&out, gpu::HEADER_LEN + 16), 1);
}

use crate::crypto;

/// A transport that answers only for configuration space, which is all the
/// crypto configuration reader touches.
struct CryptoConfig {
    words: [u32; 16],
}

impl Transport for CryptoConfig {
    fn probe(&self, _device_id: u32, _wrong: Error) -> Result<(), Error> {
        Ok(())
    }
    fn reset(&self) {}
    fn begin(&self) {}
    fn device_features_low(&self) -> u32 {
        crypto::FEATURE_REVISION_1
    }
    fn negotiate(&self, _low: u32, _high: u32) -> Result<(), Error> {
        Ok(())
    }
    fn set_features_ok(&self) -> Result<u32, Error> {
        Ok(0)
    }
    fn driver_ok(&self, _state: u32) -> Result<(), Error> {
        Ok(())
    }
    fn configure_queue(
        &self,
        _index: u32,
        size: u16,
        _desc: u64,
        _avail: u64,
        _used: u64,
    ) -> Result<u16, Error> {
        Ok(size)
    }
    fn notify(&self, _queue: u16) {}
    fn ack_interrupt(&self) {}
    fn config_u32(&self, offset: usize) -> u32 {
        self.words.get(offset / 4).copied().unwrap_or(0)
    }
}

/// A device offering one data queue, the cipher service and AES-CBC.
fn crypto_config() -> CryptoConfig {
    let mut words = [0u32; 16];
    words[1] = 1; // max_dataqueues
    words[2] = crypto::service::CIPHER;
    words[3] = crypto::Algorithm::AesCbc.bit() | crypto::Algorithm::AesEcb.bit();
    words[9] = 64; // max_cipher_key_len
    words[12] = 4096; // max_size, low word
    CryptoConfig { words }
}

/// **The control queue is after the data queues, not before them.** Every other
/// virtio device here puts its control queue first, and a driver that carried
/// that assumption over would create its sessions on the queue it then sends
/// operations to.
#[test]
fn the_control_queue_comes_after_the_data_queues() {
    let mut regs = crypto_config();
    regs.words[1] = 3;
    let config = crypto::Config::read(&regs).expect("a cipher device");
    assert_eq!(crypto::DATA_QUEUE, 0);
    assert_eq!(config.control_queue(), 3, "past the last data queue");

    // A device with no cipher service is refused here rather than at the first
    // request, which would be a session created on a queue nothing serves.
    let mut hashes_only = crypto_config();
    hashes_only.words[2] = crypto::service::HASH;
    assert_eq!(
        crypto::Config::read(&hashes_only),
        Err(Error::NotCryptoDevice)
    );
}

/// **An algorithm the device does not offer is refused, never substituted.**
/// The one failure this whole module is shaped against: bytes encrypted with
/// something other than what was asked for are indistinguishable from correct
/// ones until somebody tries to decrypt them somewhere else.
#[test]
fn an_algorithm_the_device_does_not_offer_is_refused() {
    let config = crypto::Config::read(&crypto_config()).expect("a cipher device");
    let mut out = [0u8; 128];
    assert!(config.offers(crypto::Algorithm::AesCbc));
    assert!(!config.offers(crypto::Algorithm::AesCtr));
    assert_eq!(
        crypto::create_session(
            &mut out,
            crypto::Algorithm::AesCtr,
            crypto::Direction::Encrypt,
            &[0u8; 16],
            &config,
        ),
        Err(Error::AlgorithmNotOffered),
    );
}

/// A key length the algorithm does not have, and one the device will not take,
/// are both refused — and they are different questions.
#[test]
fn a_key_the_algorithm_or_the_device_will_not_take_is_refused() {
    let mut regs = crypto_config();
    regs.words[9] = 16;
    let config = crypto::Config::read(&regs).expect("a cipher device");
    let mut out = [0u8; 128];
    for len in [15usize, 17, 20] {
        assert_eq!(
            crypto::create_session(
                &mut out,
                crypto::Algorithm::AesCbc,
                crypto::Direction::Encrypt,
                &[0u8; 32][..len],
                &config,
            ),
            Err(Error::BadKeyLength),
            "{len} is not an AES key length",
        );
    }
    // A real AES key length, and still longer than this device will take.
    assert_eq!(
        crypto::create_session(
            &mut out,
            crypto::Algorithm::AesCbc,
            crypto::Direction::Encrypt,
            &[0u8; 32],
            &config,
        ),
        Err(Error::BadKeyLength),
    );
}

/// The session names the algorithm and the direction, and the key follows the
/// request — its length is a field, not a delimiter.
#[test]
fn a_session_carries_its_key_after_the_request() {
    let config = crypto::Config::read(&crypto_config()).expect("a cipher device");
    let key = [0xa5u8; 16];
    let mut out = [0u8; 128];
    let len = crypto::create_session(
        &mut out,
        crypto::Algorithm::AesCbc,
        crypto::Direction::Decrypt,
        &key,
        &config,
    )
    .expect("a session");
    assert_eq!(len, crypto::CTRL_REQ_LEN + key.len());
    assert_eq!(gpu_word(&out, 0), crypto::opcode::CIPHER_CREATE_SESSION);
    assert_eq!(gpu_word(&out, 16), crypto::Algorithm::AesCbc as u32);
    assert_eq!(gpu_word(&out, 20), 16, "the key length is a field");
    assert_eq!(gpu_word(&out, 24), crypto::Direction::Decrypt as u32);
    assert_eq!(&out[crypto::CTRL_REQ_LEN..len], &key[..]);

    // Sixteen bytes back for a session, and **one** for its destruction.
    let mut input = [0u8; crypto::SESSION_INPUT_LEN];
    input[..8].copy_from_slice(&7u64.to_le_bytes());
    input[8..12].copy_from_slice(&crypto::status::OK.to_le_bytes());
    assert_eq!(crypto::session_reply(&input), Ok((7, crypto::status::OK)),);
    assert_eq!(crypto::destroy_status(&[0, 0xff, 0xff, 0xff]), Ok(0));
}

/// **An operation cannot disagree with its session.** The algorithm is written
/// from the session rather than passed alongside it, so the two copies the
/// protocol carries are one value here; and a direction the session was not
/// created for is refused.
#[test]
fn an_operation_cannot_disagree_with_its_session() {
    let config = crypto::Config::read(&crypto_config()).expect("a cipher device");
    let session = crypto::Session {
        id: 0x1234_5678_9abc_def0,
        algorithm: crypto::Algorithm::AesCbc,
        direction: crypto::Direction::Encrypt,
    };
    let mut out = [0u8; 128];
    assert_eq!(
        crypto::cipher_request(
            &mut out,
            &session,
            crypto::Direction::Decrypt,
            16,
            32,
            &config,
        ),
        Err(Error::SessionMismatch),
    );

    crypto::cipher_request(
        &mut out,
        &session,
        crypto::Direction::Encrypt,
        16,
        32,
        &config,
    )
    .expect("an operation");
    assert_eq!(gpu_word(&out, 0), crypto::opcode::CIPHER_ENCRYPT);
    assert_eq!(
        gpu_word(&out, 4),
        crypto::Algorithm::AesCbc as u32,
        "the session's algorithm, not one passed in beside it"
    );
    assert_eq!(gpu_long(&out, 8), session.id);
}

/// **The IV is its own region and the data length does not count it**, and the
/// destination is written from the same number as the source.
#[test]
fn the_lengths_an_operation_carries_are_the_data_alone() {
    let config = crypto::Config::read(&crypto_config()).expect("a cipher device");
    let session = crypto::Session {
        id: 1,
        algorithm: crypto::Algorithm::AesCbc,
        direction: crypto::Direction::Encrypt,
    };
    let mut out = [0u8; 128];
    let len = crypto::cipher_request(
        &mut out,
        &session,
        crypto::Direction::Encrypt,
        16,
        32,
        &config,
    )
    .expect("an operation");
    assert_eq!(len, crypto::DATA_REQ_LEN, "the IV and data come after it");
    assert_eq!(gpu_word(&out, 24), 16, "iv_len");
    assert_eq!(gpu_word(&out, 28), 32, "src_data_len — the data alone");
    assert_eq!(
        gpu_word(&out, 32),
        gpu_word(&out, 28),
        "a cipher's destination is exactly as long as its source"
    );
}

/// A length the mode cannot work in is refused, and the modes differ: CBC needs
/// whole blocks and CTR does not, because a stream cipher's last block is
/// allowed to be short.
#[test]
fn a_length_the_mode_cannot_work_in_is_refused() {
    let mut regs = crypto_config();
    regs.words[3] |= crypto::Algorithm::AesCtr.bit();
    let config = crypto::Config::read(&regs).expect("a cipher device");
    let mut out = [0u8; 128];

    let cbc = crypto::Session {
        id: 1,
        algorithm: crypto::Algorithm::AesCbc,
        direction: crypto::Direction::Encrypt,
    };
    assert_eq!(
        crypto::cipher_request(&mut out, &cbc, crypto::Direction::Encrypt, 16, 17, &config),
        Err(Error::BadDataLength),
    );
    assert_eq!(
        crypto::cipher_request(&mut out, &cbc, crypto::Direction::Encrypt, 16, 0, &config),
        Err(Error::BadDataLength),
        "nothing to encrypt is not an operation",
    );
    assert_eq!(
        crypto::cipher_request(
            &mut out,
            &cbc,
            crypto::Direction::Encrypt,
            16,
            8192,
            &config
        ),
        Err(Error::BadDataLength),
        "more than the device said it takes",
    );
    // The IV's length belongs to the mode, and ECB's is zero: an IV sent to it
    // would shift every byte of the data behind it.
    assert_eq!(
        crypto::cipher_request(&mut out, &cbc, crypto::Direction::Encrypt, 0, 32, &config),
        Err(Error::BadDataLength),
    );
    let ecb = crypto::Session {
        id: 2,
        algorithm: crypto::Algorithm::AesEcb,
        direction: crypto::Direction::Encrypt,
    };
    assert_eq!(
        crypto::cipher_request(&mut out, &ecb, crypto::Direction::Encrypt, 16, 32, &config),
        Err(Error::BadDataLength),
    );
    assert!(
        crypto::cipher_request(&mut out, &ecb, crypto::Direction::Encrypt, 0, 32, &config).is_ok()
    );

    let ctr = crypto::Session {
        id: 3,
        algorithm: crypto::Algorithm::AesCtr,
        direction: crypto::Direction::Encrypt,
    };
    assert!(
        crypto::cipher_request(&mut out, &ctr, crypto::Direction::Encrypt, 16, 17, &config).is_ok(),
        "a stream cipher's last block may be short"
    );
}

/// Two little-endian words of an encoded command, as one 64-bit value.
fn gpu_long(bytes: &[u8], at: usize) -> u64 {
    u64::from(gpu_word(bytes, at)) | (u64::from(gpu_word(bytes, at + 4)) << 32)
}

/// One little-endian word of an encoded command.
fn gpu_word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
