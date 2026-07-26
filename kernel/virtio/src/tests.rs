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
        let (desc_base, avail_base, used_base, n) = {
            let st = self.state.borrow();
            (st.q_desc, st.q_avail, st.q_used, st.q_num as usize)
        };
        if n == 0 {
            return;
        }
        let mut mem = self.guest.mem.borrow_mut();

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
                    mem[data_addr as usize + i] = self.disk[i];
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
        self.state.borrow_mut().interrupt_status = 1;
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
    state: RefCell<NetState>,
}

impl<'g> MockNet<'g> {
    fn new(guest: &'g Guest) -> Self {
        Self {
            guest,
            device_id: DEVICE_ID_NET,
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
                let reply = Self::arp_reply();
                for (i, byte) in reply.iter().enumerate() {
                    mem[rx_buf + NET_HDR_LEN + i] = *byte;
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
            o if o == reg::CONFIG + 4 => u32::from_le_bytes([NET_MAC[4], NET_MAC[5], 0, 0]),
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
