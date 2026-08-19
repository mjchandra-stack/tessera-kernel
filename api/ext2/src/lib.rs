// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! ext2, read path: mount a volume, walk a path, read a file.
//!
//! **A ported format rather than an invented one.** The roadmap
//! (`docs/roadmap/01-sequencing-and-mvp.md`) calls for "a ported memory-safe
//! filesystem implementation as v0", and the reason to port rather than invent
//! is testability: `mke2fs` lays out the image these tests read, so a test can
//! be wrong about this crate and cannot be wrong about ext2. A format of our
//! own would only ever prove that our writer and our reader agree.
//!
//! **Memory-safe and allocation-free, like every other parser here.** The
//! model is `kernel/virtio` and `api/image-store`: the format logic forbids
//! `unsafe`, knows nothing about a kernel or a driver, and is exercised on the
//! host; the ring-3 program that will drive it only supplies sectors. Bounded
//! pools, no allocator (D15/D29) — the two scratch buffers below are the whole
//! of this crate's working memory.
//!
//! **On-disk bytes are hostile input.** Every field that indexes anything is
//! range-checked before use, and a structure that does not make sense is a
//! refusal rather than a clamp. A filesystem is the first thing in this tree
//! that parses attacker-supplied layout.
//!
//! What this does **not** do yet: writing (M5), extents (an ext4 feature this
//! deliberately refuses), and the double- and triple-indirect blocks are
//! reached by the same single-pointer walk as the single-indirect one but are
//! covered only by the crafted tests, since `mke2fs` on a 4 MiB image has no
//! file large enough to need them.
//!
//! Normative: docs/storage/02-file-io-and-caching.md,
//! docs/drivers/02-storage-networking-usb-pcie.md

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(test)]
extern crate std;

/// One device sector. The block class moves exactly this much per call
/// (`dma_max_transfer_sectors` is 1 on every driver in this tree), so it is
/// the unit a filesystem can actually ask for.
pub const SECTOR: usize = 512;

/// The largest ext2 block this crate will mount.
///
/// ext2 allows 1 KiB, 2 KiB and 4 KiB. Fixing the ceiling here is what lets
/// the scratch buffers be arrays instead of allocations, and a volume above it
/// is refused rather than read with a buffer that cannot hold a block.
pub const MAX_BLOCK: usize = 4096;

/// The longest name ext2 can store, from the 8-bit `name_len` field.
pub const MAX_NAME: usize = 255;

/// Where the superblock always sits, whatever the block size.
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_MAGIC: u16 = 0xef53;

/// `filetype` — the only incompatible feature this crate understands.
///
/// It widens a directory entry's padding into a type byte. Every other
/// incompatible bit means a layout this code would misread, so anything else
/// is refused: that is what "incompatible" is defined to mean, and guessing
/// past it is how a reader invents data.
const INCOMPAT_FILETYPE: u32 = 0x0002;

/// Direct block pointers in an inode, before the indirect ones.
const DIRECT_BLOCKS: usize = 12;

/// What went wrong, as a value. Never a parsed string (docs/lifecycle/04).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The superblock is not an ext2 superblock.
    BadMagic,
    /// A block size this crate does not implement, or one that is not a power
    /// of two multiple of a sector.
    BlockSize,
    /// An incompatible feature bit that would change the layout.
    Incompatible,
    /// A field indexes past what the volume declares.
    Corrupt,
    /// The path names nothing.
    NotFound,
    /// A component of the path is not a directory.
    NotDirectory,
    /// The name is longer than ext2 can store.
    NameTooLong,
    /// The device refused a read or a write.
    Io,
    /// The volume, or the device under it, will not take writes.
    ReadOnly,
    /// The volume has no free block or inode left.
    Full,
    /// A name that is already there.
    Exists,
    /// A file large enough to need a growth this write path does not do.
    TooLarge,
}

/// A source of sectors. The whole of what this crate needs from a device.
///
/// Sectors rather than blocks because that is the unit the block class
/// delivers; assembling a block from sectors is this crate's job and not the
/// caller's.
pub trait BlockIo {
    /// Fills `into` with the 512-byte sector at `lba`.
    fn read_sector(&mut self, lba: u64, into: &mut [u8; SECTOR]) -> Result<(), Error>;

    /// Writes `from` to the 512-byte sector at `lba`.
    ///
    /// Refusing by default, so a device that only reads is a device that says
    /// so rather than one that silently drops writes — and so the read-only
    /// callers that already exist keep compiling unchanged.
    fn write_sector(&mut self, lba: u64, from: &[u8; SECTOR]) -> Result<(), Error> {
        let _ = (lba, from);
        Err(Error::ReadOnly)
    }
}

fn le16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let end = at.checked_add(2).ok_or(Error::Corrupt)?;
    let slice = bytes.get(at..end).ok_or(Error::Corrupt)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn le32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let end = at.checked_add(4).ok_or(Error::Corrupt)?;
    let slice = bytes.get(at..end).ok_or(Error::Corrupt)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// What the superblock says about the volume, in the fields a reader needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub first_data_block: u32,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub first_inode: u32,
    pub inode_size: u16,
    /// Free counts, which a writer must keep true.
    ///
    /// **`e2fsck` checks these against the bitmaps**, so an allocator that set
    /// a bit and left the counters alone produces a filesystem that mounts,
    /// reads correctly, and is reported corrupt by the first tool that looks.
    /// They are part of the write, not bookkeeping after it.
    pub free_blocks: u32,
    pub free_inodes: u32,
}

impl Superblock {
    /// Parses and **validates** a superblock image.
    ///
    /// The validation is not decoration. Every one of these fields is later
    /// used to index the device, and a zero `blocks_per_group` or an
    /// `inode_size` that is not a divisor of a block turns an ordinary read
    /// into a division by zero or an out-of-bounds index.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if le16(bytes, 56)? != SUPERBLOCK_MAGIC {
            return Err(Error::BadMagic);
        }
        let incompatible = le32(bytes, 96)?;
        if incompatible & !INCOMPAT_FILETYPE != 0 {
            return Err(Error::Incompatible);
        }
        let log_block_size = le32(bytes, 24)?;
        if log_block_size > 2 {
            return Err(Error::BlockSize);
        }
        let block_size = 1024u32 << log_block_size;

        // Revision 0 has no inode-size field and a fixed 128-byte inode; the
        // field only exists from revision 1 and reading it on an older volume
        // would read whatever follows.
        let revision = le32(bytes, 76)?;
        let (first_inode, inode_size) = if revision >= 1 {
            (le32(bytes, 84)?, le16(bytes, 88)?)
        } else {
            (11, 128)
        };

        let sb = Superblock {
            inodes_count: le32(bytes, 0)?,
            blocks_count: le32(bytes, 4)?,
            first_data_block: le32(bytes, 20)?,
            block_size,
            blocks_per_group: le32(bytes, 32)?,
            inodes_per_group: le32(bytes, 40)?,
            first_inode,
            inode_size,
            free_blocks: le32(bytes, 12)?,
            free_inodes: le32(bytes, 16)?,
        };

        if sb.blocks_per_group == 0 || sb.inodes_per_group == 0 || sb.blocks_count == 0 {
            return Err(Error::Corrupt);
        }
        // An inode must fit a block a whole number of times, and must be at
        // least the 128 bytes the structure occupies.
        if u32::from(sb.inode_size) < 128
            || !sb.inode_size.is_power_of_two()
            || u32::from(sb.inode_size) > block_size
        {
            return Err(Error::Corrupt);
        }
        if sb.first_data_block >= sb.blocks_count {
            return Err(Error::Corrupt);
        }
        Ok(sb)
    }
}

/// What kind of thing a directory entry names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Regular,
    Directory,
    Other,
}

/// One inode, in the fields this crate reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Inode {
    pub number: u32,
    pub kind: Kind,
    pub size: u64,
    pub links: u16,
    /// `i_blocks`: how many **512-byte sectors** this file occupies, counting
    /// the indirect blocks as well as the data.
    ///
    /// Not derivable from the size, which is why it is a field and not a
    /// calculation: a sparse file occupies fewer, and an indirect block
    /// occupies one that no offset in the file maps to. `e2fsck` recomputes it
    /// and reports a mismatch.
    pub sectors: u32,
    /// The fifteen block pointers: twelve direct, then single, double and
    /// triple indirect.
    blocks: [u32; 15],
}

impl Inode {
    fn parse(number: u32, bytes: &[u8]) -> Result<Self, Error> {
        let mode = le16(bytes, 0)?;
        let kind = match mode & 0xf000 {
            0x8000 => Kind::Regular,
            0x4000 => Kind::Directory,
            _ => Kind::Other,
        };
        let low = u64::from(le32(bytes, 4)?);
        // For a regular file on a revision-1 volume the high half of the size
        // lives in what revision 0 called `i_dir_acl`. A directory's size is
        // always the low half.
        let size = match kind {
            Kind::Regular => low | (u64::from(le32(bytes, 108)?) << 32),
            _ => low,
        };
        let mut blocks = [0u32; 15];
        for (index, slot) in blocks.iter_mut().enumerate() {
            *slot = le32(bytes, 40 + index * 4)?;
        }
        Ok(Inode {
            number,
            kind,
            size,
            links: le16(bytes, 26)?,
            sectors: le32(bytes, 28)?,
            blocks,
        })
    }
}

/// One directory entry, copied out rather than borrowed.
///
/// By value because the name lives in the same scratch buffer the next read
/// overwrites; handing out a reference would tie the caller's lifetime to a
/// buffer that is about to change. 255 bytes is what the format allows and is
/// therefore what this costs.
#[derive(Clone, Copy)]
pub struct Entry {
    pub inode: u32,
    pub kind: Kind,
    name: [u8; MAX_NAME],
    name_len: u8,
}

impl Entry {
    /// The entry's name. Bytes, not `str`: ext2 names are not required to be
    /// UTF-8, and deciding they are is how a reader loses a file.
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }
}

/// A mounted volume.
pub struct Fs<D: BlockIo> {
    device: D,
    sb: Superblock,
    /// One block of whatever is being read now.
    block: [u8; MAX_BLOCK],
    /// One block of pointers, for the indirect walk. Separate from `block`
    /// because resolving a data block reads a pointer block first; one buffer
    /// serves every indirect level because each level yields a single pointer
    /// before the next is read.
    pointers: [u8; MAX_BLOCK],
}

impl<D: BlockIo> Fs<D> {
    /// Reads and validates the superblock.
    pub fn mount(mut device: D) -> Result<Self, Error> {
        let mut head = [0u8; MAX_BLOCK];
        let base = SUPERBLOCK_OFFSET / SECTOR as u64;
        for index in 0..2 {
            let mut sector = [0u8; SECTOR];
            device.read_sector(base + index as u64, &mut sector)?;
            let at = index * SECTOR;
            head[at..at + SECTOR].copy_from_slice(&sector);
        }
        let sb = Superblock::parse(&head)?;
        Ok(Fs {
            device,
            sb,
            block: [0u8; MAX_BLOCK],
            pointers: [0u8; MAX_BLOCK],
        })
    }

    /// What the volume declared.
    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// Gives the device back, for a caller that mounts and then needs it.
    pub fn into_device(self) -> D {
        self.device
    }

    fn block_size(&self) -> usize {
        self.sb.block_size as usize
    }

    /// Reads block `number` into `into`.
    ///
    /// An associated function over the fields it needs rather than a method:
    /// every caller wants to fill one of this struct's scratch buffers while
    /// the device is borrowed, and `&mut self` would make those the same
    /// borrow. Named fields at the call site are disjoint and the borrow
    /// checker knows it.
    fn read_block(
        device: &mut D,
        sb: &Superblock,
        number: u32,
        into: &mut [u8; MAX_BLOCK],
    ) -> Result<(), Error> {
        if number >= sb.blocks_count {
            return Err(Error::Corrupt);
        }
        let per_block = sb.block_size as u64 / SECTOR as u64;
        let first = u64::from(number) * per_block;
        for index in 0..per_block {
            let mut sector = [0u8; SECTOR];
            device.read_sector(first + index, &mut sector)?;
            let at = (index as usize) * SECTOR;
            into[at..at + SECTOR].copy_from_slice(&sector);
        }
        Ok(())
    }

    /// Writes `from` to block `number`.
    fn write_block(
        device: &mut D,
        sb: &Superblock,
        number: u32,
        from: &[u8; MAX_BLOCK],
    ) -> Result<(), Error> {
        if number >= sb.blocks_count {
            return Err(Error::Corrupt);
        }
        let per_block = sb.block_size as u64 / SECTOR as u64;
        let first = u64::from(number) * per_block;
        for index in 0..per_block {
            let at = (index as usize) * SECTOR;
            let mut sector = [0u8; SECTOR];
            sector.copy_from_slice(&from[at..at + SECTOR]);
            device.write_sector(first + index, &sector)?;
        }
        Ok(())
    }

    /// Where a group's descriptor sits, and what it says.
    ///
    /// Returns `(descriptor block, offset within it)` so a caller can read a
    /// field or write one back without recomputing the location — the two go
    /// together, and computing it twice is how a writer updates a different
    /// group from the one it allocated in.
    fn group_descriptor(&self, group: u32) -> (u32, usize) {
        let per_block = (self.block_size() / 32) as u32;
        let block = self.sb.first_data_block + 1 + group / per_block;
        (block, ((group % per_block) * 32) as usize)
    }

    /// Marks bit `index` in the bitmap at `bitmap_block`, refusing if it was
    /// already set.
    ///
    /// The refusal matters: a bitmap bit that was already set means this
    /// allocator and something else both believe they own the block, and
    /// carrying on hands two files the same storage.
    fn claim_bit(&mut self, bitmap_block: u32, index: u32) -> Result<(), Error> {
        let byte = (index / 8) as usize;
        let mask = 1u8 << (index % 8);
        Self::read_block(&mut self.device, &self.sb, bitmap_block, &mut self.block)?;
        if byte >= self.block_size() {
            return Err(Error::Corrupt);
        }
        if self.block[byte] & mask != 0 {
            return Err(Error::Corrupt);
        }
        self.block[byte] |= mask;
        let buffer = self.block;
        Self::write_block(&mut self.device, &self.sb, bitmap_block, &buffer)
    }

    /// Clears bit `index`, for a free.
    fn release_bit(&mut self, bitmap_block: u32, index: u32) -> Result<(), Error> {
        let byte = (index / 8) as usize;
        let mask = 1u8 << (index % 8);
        Self::read_block(&mut self.device, &self.sb, bitmap_block, &mut self.block)?;
        if byte >= self.block_size() {
            return Err(Error::Corrupt);
        }
        self.block[byte] &= !mask;
        let buffer = self.block;
        Self::write_block(&mut self.device, &self.sb, bitmap_block, &buffer)
    }

    /// The first clear bit below `limit` in the bitmap at `bitmap_block`.
    fn first_free_bit(&mut self, bitmap_block: u32, limit: u32) -> Result<Option<u32>, Error> {
        Self::read_block(&mut self.device, &self.sb, bitmap_block, &mut self.block)?;
        for index in 0..limit {
            let byte = (index / 8) as usize;
            if byte >= self.block_size() {
                break;
            }
            if self.block[byte] & (1u8 << (index % 8)) == 0 {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    /// Adjusts a group descriptor's free counts and the superblock's, together.
    ///
    /// One function because they are one fact counted twice, and `e2fsck`
    /// compares both against the bitmaps: updating either alone produces a
    /// volume that reads correctly and is reported corrupt.
    fn account(&mut self, group: u32, blocks: i32, inodes: i32, dirs: i32) -> Result<(), Error> {
        let (block, at) = self.group_descriptor(group);
        Self::read_block(&mut self.device, &self.sb, block, &mut self.block)?;
        for (offset, delta) in [(12usize, blocks), (14, inodes), (16, dirs)] {
            if delta == 0 {
                continue;
            }
            let now = le16(&self.block, at + offset)?;
            let next = i32::from(now) + delta;
            let next = u16::try_from(next).map_err(|_| Error::Corrupt)?;
            self.block[at + offset..at + offset + 2].copy_from_slice(&next.to_le_bytes());
        }
        let buffer = self.block;
        Self::write_block(&mut self.device, &self.sb, block, &buffer)?;

        if blocks != 0 {
            self.sb.free_blocks = u32::try_from(self.sb.free_blocks as i64 + i64::from(blocks))
                .map_err(|_| Error::Corrupt)?;
        }
        if inodes != 0 {
            self.sb.free_inodes = u32::try_from(self.sb.free_inodes as i64 + i64::from(inodes))
                .map_err(|_| Error::Corrupt)?;
        }
        self.flush_superblock()
    }

    /// Writes the two counters back into the superblock on the medium.
    fn flush_superblock(&mut self) -> Result<(), Error> {
        let base = SUPERBLOCK_OFFSET / SECTOR as u64;
        let mut sector = [0u8; SECTOR];
        self.device.read_sector(base, &mut sector)?;
        sector[12..16].copy_from_slice(&self.sb.free_blocks.to_le_bytes());
        sector[16..20].copy_from_slice(&self.sb.free_inodes.to_le_bytes());
        self.device.write_sector(base, &sector)
    }

    /// Allocates one block, zeroed, and returns its number.
    fn alloc_block(&mut self) -> Result<u32, Error> {
        let groups = self.sb.blocks_count.div_ceil(self.sb.blocks_per_group);
        for group in 0..groups {
            let (descriptor, at) = self.group_descriptor(group);
            Self::read_block(&mut self.device, &self.sb, descriptor, &mut self.block)?;
            let bitmap = le32(&self.block, at)?;
            // The last group is short, so the limit is what this group holds
            // rather than the nominal size — allocating past it hands out a
            // block the volume does not have.
            let first = group * self.sb.blocks_per_group + self.sb.first_data_block;
            let limit = self.sb.blocks_per_group.min(self.sb.blocks_count - first);
            let Some(index) = self.first_free_bit(bitmap, limit)? else {
                continue;
            };
            self.claim_bit(bitmap, index)?;
            self.account(group, -1, 0, 0)?;
            let number = first + index;
            // Zeroed before it is anybody's: a block handed out with the last
            // file's bytes in it is that file's data leaking into this one.
            let zero = [0u8; MAX_BLOCK];
            Self::write_block(&mut self.device, &self.sb, number, &zero)?;
            return Ok(number);
        }
        Err(Error::Full)
    }

    /// Writes `inode` back to its slot on the medium.
    pub fn flush_inode(&mut self, inode: &Inode) -> Result<(), Error> {
        let (block, offset) = self.inode_location(inode.number)?;
        Self::read_block(&mut self.device, &self.sb, block, &mut self.block)?;
        let size = usize::from(self.sb.inode_size);
        let end = offset.checked_add(size).ok_or(Error::Corrupt)?;
        if end > self.block_size() {
            return Err(Error::Corrupt);
        }
        let slot = &mut self.block[offset..end];
        slot[4..8].copy_from_slice(&((inode.size & 0xffff_ffff) as u32).to_le_bytes());
        if inode.kind == Kind::Regular {
            slot[108..112].copy_from_slice(&((inode.size >> 32) as u32).to_le_bytes());
        }
        slot[26..28].copy_from_slice(&inode.links.to_le_bytes());
        slot[28..32].copy_from_slice(&inode.sectors.to_le_bytes());
        for (index, pointer) in inode.blocks.iter().enumerate() {
            slot[40 + index * 4..44 + index * 4].copy_from_slice(&pointer.to_le_bytes());
        }
        let buffer = self.block;
        Self::write_block(&mut self.device, &self.sb, block, &buffer)
    }

    /// Resolves a file-relative block index to a device block, or `None` for a
    /// hole.
    ///
    /// A sparse file's missing block is a zero pointer, which is a legitimate
    /// answer meaning "read zeroes" and not a corrupt one. Confusing the two
    /// would either invent an error or read block zero, which is the
    /// superblock.
    fn resolve(&mut self, inode: &Inode, index: u64) -> Result<Option<u32>, Error> {
        let per_block = (self.block_size() / 4) as u64;
        let direct = DIRECT_BLOCKS as u64;

        // Which pointer of the inode starts the walk, and how deep it goes.
        let (mut slot, depth, mut within) = if index < direct {
            (inode.blocks[index as usize], 0u32, 0u64)
        } else if index < direct + per_block {
            (inode.blocks[12], 1, index - direct)
        } else if index < direct + per_block + per_block * per_block {
            (inode.blocks[13], 2, index - direct - per_block)
        } else {
            let base = direct + per_block + per_block * per_block;
            let span = per_block
                .checked_mul(per_block)
                .and_then(|v| v.checked_mul(per_block))
                .ok_or(Error::Corrupt)?;
            if index >= base + span {
                return Err(Error::Corrupt);
            }
            (inode.blocks[14], 3, index - base)
        };

        let block_size = self.block_size();
        for level in (0..depth).rev() {
            if slot == 0 {
                return Ok(None);
            }
            Self::read_block(&mut self.device, &self.sb, slot, &mut self.pointers)?;
            let stride = per_block.pow(level);
            let entry = within / stride;
            within %= stride;
            let at = usize::try_from(entry).map_err(|_| Error::Corrupt)? * 4;
            slot = le32(&self.pointers[..block_size], at)?;
        }
        Ok(if slot == 0 { None } else { Some(slot) })
    }

    /// Where inode `number` lives: `(block, offset within it)`.
    ///
    /// Shared by the reader and the writer, so an inode is never written to a
    /// different slot from the one it was read out of.
    fn inode_location(&mut self, number: u32) -> Result<(u32, usize), Error> {
        if number == 0 || number > self.sb.inodes_count {
            return Err(Error::Corrupt);
        }
        let index = number - 1;
        let group = index / self.sb.inodes_per_group;
        let within = index % self.sb.inodes_per_group;
        let (descriptor, at) = self.group_descriptor(group);
        Self::read_block(&mut self.device, &self.sb, descriptor, &mut self.block)?;
        let table = le32(&self.block, at + 8)?;
        let size = u32::from(self.sb.inode_size);
        let per_inode_block = self.sb.block_size / size;
        if per_inode_block == 0 {
            return Err(Error::Corrupt);
        }
        let block = table
            .checked_add(within / per_inode_block)
            .ok_or(Error::Corrupt)?;
        Ok((block, ((within % per_inode_block) * size) as usize))
    }

    /// Reads inode `number`.
    pub fn inode(&mut self, number: u32) -> Result<Inode, Error> {
        if number == 0 || number > self.sb.inodes_count {
            return Err(Error::Corrupt);
        }
        let index = number - 1;
        let group = index / self.sb.inodes_per_group;
        let within = index % self.sb.inodes_per_group;

        // The group descriptor table follows the superblock's block.
        let descriptors = self.sb.first_data_block + 1;
        let per_block = (self.block_size() / 32) as u32;
        let table_block = descriptors + group / per_block;
        let block_size = self.block_size();
        Self::read_block(&mut self.device, &self.sb, table_block, &mut self.block)?;
        let table = le32(
            &self.block[..block_size],
            ((group % per_block) * 32 + 8) as usize,
        )?;

        let size = u32::from(self.sb.inode_size);
        let per_inode_block = self.sb.block_size / size;
        if per_inode_block == 0 {
            return Err(Error::Corrupt);
        }
        let block = table
            .checked_add(within / per_inode_block)
            .ok_or(Error::Corrupt)?;
        let offset = ((within % per_inode_block) * size) as usize;

        Self::read_block(&mut self.device, &self.sb, block, &mut self.block)?;
        let end = offset.checked_add(size as usize).ok_or(Error::Corrupt)?;
        let bytes = self.block.get(offset..end).ok_or(Error::Corrupt)?;
        Inode::parse(number, bytes)
    }

    /// The root directory, which ext2 fixes at inode 2.
    pub fn root(&mut self) -> Result<Inode, Error> {
        self.inode(2)
    }

    /// Calls `visit` for each entry of `directory` until it returns `false`.
    pub fn for_each_entry(
        &mut self,
        directory: &Inode,
        mut visit: impl FnMut(&Entry) -> bool,
    ) -> Result<(), Error> {
        if directory.kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        let block_size = self.block_size();
        let blocks = directory.size.div_ceil(block_size as u64);
        for index in 0..blocks {
            let Some(number) = self.resolve(directory, index)? else {
                continue;
            };
            Self::read_block(&mut self.device, &self.sb, number, &mut self.block)?;
            let buffer: &[u8] = &self.block;
            {
                let mut at = 0usize;
                while at + 8 <= block_size {
                    let inode = le32(buffer, at)?;
                    let record = le16(buffer, at + 4)? as usize;
                    let name_len = *buffer.get(at + 6).ok_or(Error::Corrupt)?;
                    // A record that does not advance is a loop, and a record
                    // that runs past the block is a read of the next one.
                    if record < 8 || at + record > block_size {
                        return Err(Error::Corrupt);
                    }
                    let end = at + 8 + usize::from(name_len);
                    if end > at + record {
                        return Err(Error::Corrupt);
                    }
                    // Inode 0 marks a slot whose entry was removed; the record
                    // still has to be stepped over.
                    if inode != 0 {
                        let mut entry = Entry {
                            inode,
                            kind: match *buffer.get(at + 7).ok_or(Error::Corrupt)? {
                                1 => Kind::Regular,
                                2 => Kind::Directory,
                                _ => Kind::Other,
                            },
                            name: [0u8; MAX_NAME],
                            name_len,
                        };
                        entry.name[..usize::from(name_len)].copy_from_slice(&buffer[at + 8..end]);
                        if !visit(&entry) {
                            return Ok(());
                        }
                    }
                    at += record;
                }
            }
        }
        Ok(())
    }

    /// Finds `name` in `directory`.
    pub fn lookup_in(&mut self, directory: &Inode, name: &[u8]) -> Result<Inode, Error> {
        if name.len() > MAX_NAME {
            return Err(Error::NameTooLong);
        }
        let mut found = 0u32;
        self.for_each_entry(directory, |entry| {
            if entry.name() == name {
                found = entry.inode;
                false
            } else {
                true
            }
        })?;
        if found == 0 {
            return Err(Error::NotFound);
        }
        self.inode(found)
    }

    /// Walks an absolute path.
    ///
    /// Empty components are skipped, so `/a//b` and `/a/b` name the same file
    /// and a trailing slash is not an error — the shapes a path picks up from
    /// being concatenated.
    pub fn lookup(&mut self, path: &[u8]) -> Result<Inode, Error> {
        let mut current = self.root()?;
        for component in path.split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." {
                continue;
            }
            current = self.lookup_in(&current, component)?;
        }
        Ok(current)
    }

    /// Reads from `inode` at `offset` into `out`, returning how many bytes
    /// were read.
    ///
    /// Short at end of file, and short is not an error: the caller learns the
    /// length from the return value, which is the only thing that composes
    /// with a file whose size is not a multiple of anything.
    pub fn read_at(&mut self, inode: &Inode, offset: u64, out: &mut [u8]) -> Result<usize, Error> {
        if offset >= inode.size {
            return Ok(0);
        }
        let block_size = self.block_size() as u64;
        let remaining = inode.size - offset;
        let want = out
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let mut done = 0usize;
        while done < want {
            let at = offset + done as u64;
            let index = at / block_size;
            let within = (at % block_size) as usize;
            let take = (self.block_size() - within).min(want - done);
            match self.resolve(inode, index)? {
                // A hole reads as zeroes, which is what the format says it
                // holds — not an error and not a short read.
                None => out[done..done + take].fill(0),
                Some(number) => {
                    Self::read_block(&mut self.device, &self.sb, number, &mut self.block)?;
                    out[done..done + take].copy_from_slice(&self.block[within..within + take]);
                }
            }
            done += take;
        }
        Ok(done)
    }
}

impl<D: BlockIo> Fs<D> {
    /// Resolves a file-relative block index, allocating what is missing.
    ///
    /// The write-side counterpart of [`Fs::resolve`]. Where that returns
    /// `None` for a hole, this fills it — including the indirect block itself,
    /// which is storage the file occupies but no offset in it maps to, and is
    /// why `i_blocks` is counted here rather than derived from the size.
    fn resolve_or_alloc(&mut self, inode: &mut Inode, index: u64) -> Result<u32, Error> {
        let per_block = (self.block_size() / 4) as u64;
        let direct = DIRECT_BLOCKS as u64;

        if index < direct {
            let slot = index as usize;
            if inode.blocks[slot] == 0 {
                inode.blocks[slot] = self.alloc_block()?;
                inode.sectors += self.sb.block_size / SECTOR as u32;
            }
            return Ok(inode.blocks[slot]);
        }

        // Single indirect only. Double and triple are read but not grown: a
        // file large enough to need them is one this write path has never
        // been asked for, and an allocator nobody has run is worse than a
        // refusal that says so.
        if index >= direct + per_block {
            return Err(Error::TooLarge);
        }
        if inode.blocks[12] == 0 {
            inode.blocks[12] = self.alloc_block()?;
            inode.sectors += self.sb.block_size / SECTOR as u32;
        }
        let indirect = inode.blocks[12];
        let at = ((index - direct) as usize) * 4;
        Self::read_block(&mut self.device, &self.sb, indirect, &mut self.pointers)?;
        let existing = le32(&self.pointers, at)?;
        if existing != 0 {
            return Ok(existing);
        }
        let fresh = self.alloc_block()?;
        inode.sectors += self.sb.block_size / SECTOR as u32;
        // Re-read: allocating went through the same scratch buffer.
        Self::read_block(&mut self.device, &self.sb, indirect, &mut self.pointers)?;
        self.pointers[at..at + 4].copy_from_slice(&fresh.to_le_bytes());
        let buffer = self.pointers;
        Self::write_block(&mut self.device, &self.sb, indirect, &buffer)?;
        Ok(fresh)
    }

    /// Writes `bytes` at `offset`, growing the file if it needs to.
    ///
    /// Returns how many bytes were written, which is all of them or an error —
    /// a short write here would be a caller left guessing which half landed.
    /// The inode is updated in memory and written back, so the size and the
    /// block count on the medium describe what is actually there.
    pub fn write_at(
        &mut self,
        inode: &mut Inode,
        offset: u64,
        bytes: &[u8],
    ) -> Result<usize, Error> {
        if inode.kind != Kind::Regular {
            return Err(Error::NotDirectory);
        }
        let block_size = self.block_size() as u64;
        let mut done = 0usize;
        while done < bytes.len() {
            let at = offset + done as u64;
            let index = at / block_size;
            let within = (at % block_size) as usize;
            let take = (self.block_size() - within).min(bytes.len() - done);
            let number = self.resolve_or_alloc(inode, index)?;
            // Read-modify-write: a partial block written whole would zero the
            // bytes either side of it, which is a write to somebody else's
            // part of the same file.
            Self::read_block(&mut self.device, &self.sb, number, &mut self.block)?;
            self.block[within..within + take].copy_from_slice(&bytes[done..done + take]);
            let buffer = self.block;
            Self::write_block(&mut self.device, &self.sb, number, &buffer)?;
            done += take;
        }
        let end = offset + done as u64;
        if end > inode.size {
            inode.size = end;
        }
        self.flush_inode(inode)?;
        Ok(done)
    }

    /// Frees block `number`, clearing its bitmap bit and giving the count back.
    fn free_block(&mut self, number: u32) -> Result<(), Error> {
        if number < self.sb.first_data_block || number >= self.sb.blocks_count {
            return Err(Error::Corrupt);
        }
        let group = (number - self.sb.first_data_block) / self.sb.blocks_per_group;
        let index = (number - self.sb.first_data_block) % self.sb.blocks_per_group;
        let (descriptor, at) = self.group_descriptor(group);
        Self::read_block(&mut self.device, &self.sb, descriptor, &mut self.block)?;
        let bitmap = le32(&self.block, at)?;
        self.release_bit(bitmap, index)?;
        self.account(group, 1, 0, 0)
    }

    /// Shortens `inode` to `length`, freeing what falls off the end.
    ///
    /// **Freeing is where a filesystem loses data twice.** A block released
    /// but still pointed at is one the next allocation hands to another file,
    /// which then shares storage with this one; a block forgotten but not
    /// released is space nothing will ever use again. So the pointer is
    /// cleared and the bit is cleared, and `i_blocks` follows both — which is
    /// exactly what `e2fsck` recomputes.
    ///
    /// Growing is [`Fs::write_at`]'s job; a length above the current size is
    /// refused rather than quietly doing nothing.
    pub fn truncate(&mut self, inode: &mut Inode, length: u64) -> Result<(), Error> {
        if inode.kind != Kind::Regular {
            return Err(Error::NotDirectory);
        }
        if length > inode.size {
            return Err(Error::TooLarge);
        }
        let block_size = self.block_size() as u64;
        let keep = length.div_ceil(block_size);
        let had = inode.size.div_ceil(block_size);
        let per_block = (self.block_size() / 4) as u64;
        let sectors_per_block = self.sb.block_size / SECTOR as u32;

        for index in keep..had {
            if index < DIRECT_BLOCKS as u64 {
                let slot = index as usize;
                if inode.blocks[slot] != 0 {
                    self.free_block(inode.blocks[slot])?;
                    inode.blocks[slot] = 0;
                    inode.sectors = inode.sectors.saturating_sub(sectors_per_block);
                }
                continue;
            }
            if index >= DIRECT_BLOCKS as u64 + per_block {
                // Beyond what this write path grows, so beyond what it can
                // have allocated.
                return Err(Error::TooLarge);
            }
            let indirect = inode.blocks[12];
            if indirect == 0 {
                continue;
            }
            let at = ((index - DIRECT_BLOCKS as u64) as usize) * 4;
            Self::read_block(&mut self.device, &self.sb, indirect, &mut self.pointers)?;
            let number = le32(&self.pointers, at)?;
            if number == 0 {
                continue;
            }
            self.pointers[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
            let buffer = self.pointers;
            Self::write_block(&mut self.device, &self.sb, indirect, &buffer)?;
            self.free_block(number)?;
            inode.sectors = inode.sectors.saturating_sub(sectors_per_block);
        }

        // The indirect block itself, once nothing in the file reaches through
        // it. Kept until then, because a file truncated to eleven blocks and
        // grown again would otherwise allocate it twice.
        if keep <= DIRECT_BLOCKS as u64 && inode.blocks[12] != 0 {
            let indirect = inode.blocks[12];
            inode.blocks[12] = 0;
            self.free_block(indirect)?;
            inode.sectors = inode.sectors.saturating_sub(sectors_per_block);
        }

        inode.size = length;
        self.flush_inode(inode)
    }

    /// Allocates a free inode and returns its number.
    fn alloc_inode(&mut self, directory: bool) -> Result<u32, Error> {
        let groups = self.sb.inodes_count.div_ceil(self.sb.inodes_per_group);
        for group in 0..groups {
            let (descriptor, at) = self.group_descriptor(group);
            Self::read_block(&mut self.device, &self.sb, descriptor, &mut self.block)?;
            let bitmap = le32(&self.block, at + 4)?;
            let Some(index) = self.first_free_bit(bitmap, self.sb.inodes_per_group)? else {
                continue;
            };
            let number = group * self.sb.inodes_per_group + index + 1;
            // The first few inodes are the filesystem's own; handing one out
            // would overwrite the root directory or the journal.
            if number < self.sb.first_inode {
                continue;
            }
            self.claim_bit(bitmap, index)?;
            self.account(group, 0, -1, i32::from(directory))?;
            return Ok(number);
        }
        Err(Error::Full)
    }

    /// Adds `name` to `directory`, pointing at `inode`.
    ///
    /// ext2 directories are a chain of records whose lengths must exactly fill
    /// each block, so a new name goes into the slack of an existing record
    /// rather than being appended: the last record in a block always claims
    /// the rest of it, and splitting that slack is how the chain stays exact.
    fn link(
        &mut self,
        directory: &mut Inode,
        name: &[u8],
        inode: u32,
        kind: Kind,
    ) -> Result<(), Error> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::NameTooLong);
        }
        let needed = (8 + name.len()).div_ceil(4) * 4;
        let block_size = self.block_size();
        let blocks = directory.size.div_ceil(block_size as u64);
        for index in 0..blocks {
            let number = self.resolve_or_alloc(directory, index)?;
            Self::read_block(&mut self.device, &self.sb, number, &mut self.block)?;
            let mut at = 0usize;
            while at + 8 <= block_size {
                let used = le32(&self.block, at)?;
                let record = le16(&self.block, at + 4)? as usize;
                let name_len = usize::from(*self.block.get(at + 6).ok_or(Error::Corrupt)?);
                if record < 8 || at + record > block_size {
                    return Err(Error::Corrupt);
                }
                let occupied = if used == 0 {
                    0
                } else {
                    (8 + name_len).div_ceil(4) * 4
                };
                if record - occupied >= needed {
                    // Split: the existing record shrinks to what it uses, and
                    // the new one takes the rest so the chain still ends
                    // exactly at the block's end.
                    let fresh = at + occupied;
                    let rest = record - occupied;
                    if used != 0 {
                        self.block[at + 4..at + 6]
                            .copy_from_slice(&(occupied as u16).to_le_bytes());
                    }
                    let start = if used == 0 { at } else { fresh };
                    let length = if used == 0 { record } else { rest };
                    self.block[start..start + 4].copy_from_slice(&inode.to_le_bytes());
                    self.block[start + 4..start + 6]
                        .copy_from_slice(&(length as u16).to_le_bytes());
                    self.block[start + 6] = name.len() as u8;
                    self.block[start + 7] = match kind {
                        Kind::Regular => 1,
                        Kind::Directory => 2,
                        Kind::Other => 0,
                    };
                    self.block[start + 8..start + 8 + name.len()].copy_from_slice(name);
                    let buffer = self.block;
                    return Self::write_block(&mut self.device, &self.sb, number, &buffer);
                }
                at += record;
            }
        }
        // Growing a directory by a block needs the last record to stop
        // claiming the end of the old one, which this does not do yet.
        Err(Error::Full)
    }

    /// Frees inode `number`, clearing its bitmap bit and giving the count back.
    fn free_inode(&mut self, number: u32, directory: bool) -> Result<(), Error> {
        if number == 0 || number > self.sb.inodes_count {
            return Err(Error::Corrupt);
        }
        let index = number - 1;
        let group = index / self.sb.inodes_per_group;
        let within = index % self.sb.inodes_per_group;
        let (descriptor, at) = self.group_descriptor(group);
        Self::read_block(&mut self.device, &self.sb, descriptor, &mut self.block)?;
        let bitmap = le32(&self.block, at + 4)?;
        self.release_bit(bitmap, within)?;
        self.account(group, 0, 1, -i32::from(directory))
    }

    /// Stamps an inode's `i_dtime`, which a freed inode must carry.
    fn set_dtime(&mut self, number: u32, when: u32) -> Result<(), Error> {
        let (block, offset) = self.inode_location(number)?;
        Self::read_block(&mut self.device, &self.sb, block, &mut self.block)?;
        self.block[offset + 20..offset + 24].copy_from_slice(&when.to_le_bytes());
        let buffer = self.block;
        Self::write_block(&mut self.device, &self.sb, block, &buffer)
    }

    /// Removes `name` from `directory`.
    ///
    /// **The record is absorbed, not blanked.** ext2 directory records chain
    /// by length and must fill each block exactly, so a removed entry's space
    /// goes to the record before it; the first record in a block has nothing
    /// before it and instead keeps its length with inode zero, which is what
    /// the reader already skips. Blanking a record in the middle would break
    /// the chain at that point and lose every name after it.
    ///
    /// The inode goes when its last name does: link count to zero means the
    /// blocks are freed and the inode returned, because a file nothing names
    /// and nothing freed is space no tool will ever reclaim.
    /// `deleted_at` is written into the inode's `i_dtime`, which ext2 requires
    /// to be **non-zero** on a freed inode — `e2fsck` reports "deleted inode
    /// has zero dtime" otherwise, and it is the one field a reader cannot
    /// derive. A parameter rather than a constant because this crate has no
    /// clock and inventing one would put a wrong time on the medium rather
    /// than making the caller supply a right one.
    pub fn unlink(
        &mut self,
        directory: &mut Inode,
        name: &[u8],
        deleted_at: u32,
    ) -> Result<(), Error> {
        if deleted_at == 0 {
            return Err(Error::Corrupt);
        }
        if directory.kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::NameTooLong);
        }
        let block_size = self.block_size();
        let blocks = directory.size.div_ceil(block_size as u64);
        for index in 0..blocks {
            let Some(number) = self.resolve(directory, index)? else {
                continue;
            };
            Self::read_block(&mut self.device, &self.sb, number, &mut self.block)?;
            let mut at = 0usize;
            let mut previous: Option<usize> = None;
            while at + 8 <= block_size {
                let inode = le32(&self.block, at)?;
                let record = le16(&self.block, at + 4)? as usize;
                let name_len = usize::from(*self.block.get(at + 6).ok_or(Error::Corrupt)?);
                if record < 8 || at + record > block_size {
                    return Err(Error::Corrupt);
                }
                let end = at + 8 + name_len;
                if end > at + record {
                    return Err(Error::Corrupt);
                }
                if inode != 0 && &self.block[at + 8..end] == name {
                    // **A directory is not unlinked, it is removed.** Its `..`
                    // is a reference to the parent, so dropping the name must
                    // also drop the parent's link count, and a directory with
                    // anything in it must not go at all. Neither is done here,
                    // and doing half of it leaves an unconnected directory —
                    // which is what `e2fsck` reported when this refused
                    // nothing. `rmdir` is its own operation and is not written.
                    if self.inode(inode)?.kind == Kind::Directory {
                        return Err(Error::NotDirectory);
                    }
                    // Re-read: checking the kind went through this buffer.
                    Self::read_block(&mut self.device, &self.sb, number, &mut self.block)?;
                    match previous {
                        Some(before) => {
                            let grown = le16(&self.block, before + 4)? as usize + record;
                            self.block[before + 4..before + 6]
                                .copy_from_slice(&(grown as u16).to_le_bytes());
                        }
                        // Nothing before it: keep the length, drop the name.
                        None => {
                            self.block[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
                        }
                    }
                    let buffer = self.block;
                    Self::write_block(&mut self.device, &self.sb, number, &buffer)?;

                    let mut target = self.inode(inode)?;
                    target.links = target.links.saturating_sub(1);
                    if target.links == 0 {
                        if target.kind == Kind::Regular {
                            self.truncate(&mut target, 0)?;
                        }
                        self.flush_inode(&target)?;
                        self.set_dtime(inode, deleted_at)?;
                        self.free_inode(inode, target.kind == Kind::Directory)?;
                    } else {
                        self.flush_inode(&target)?;
                    }
                    return Ok(());
                }
                previous = Some(at);
                at += record;
            }
        }
        Err(Error::NotFound)
    }

    /// Creates an empty regular file called `name` in `directory`.
    pub fn create(&mut self, directory: &mut Inode, name: &[u8]) -> Result<Inode, Error> {
        if directory.kind != Kind::Directory {
            return Err(Error::NotDirectory);
        }
        if self.lookup_in(directory, name).is_ok() {
            return Err(Error::Exists);
        }
        let number = self.alloc_inode(false)?;
        let inode = Inode {
            number,
            kind: Kind::Regular,
            size: 0,
            links: 1,
            sectors: 0,
            blocks: [0u32; 15],
        };
        // The mode is written here rather than in `flush_inode`, which only
        // ever updates a file that already has one: a fresh slot may hold
        // anything the last owner left.
        let (block, offset) = self.inode_location(number)?;
        Self::read_block(&mut self.device, &self.sb, block, &mut self.block)?;
        let size = usize::from(self.sb.inode_size);
        for byte in &mut self.block[offset..offset + size] {
            *byte = 0;
        }
        // 0o100644: a regular file, readable by all and writable by its owner.
        self.block[offset..offset + 2].copy_from_slice(&0x81a4u16.to_le_bytes());
        self.block[offset + 26..offset + 28].copy_from_slice(&1u16.to_le_bytes());
        let buffer = self.block;
        Self::write_block(&mut self.device, &self.sb, block, &buffer)?;

        self.link(directory, name, number, Kind::Regular)?;
        Ok(inode)
    }
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
