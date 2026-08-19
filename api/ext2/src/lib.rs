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
    /// The device refused a read.
    Io,
}

/// A source of sectors. The whole of what this crate needs from a device.
///
/// Sectors rather than blocks because that is the unit the block class
/// delivers; assembling a block from sectors is this crate's job and not the
/// caller's.
pub trait BlockIo {
    /// Fills `into` with the 512-byte sector at `lba`.
    fn read_sector(&mut self, lba: u64, into: &mut [u8; SECTOR]) -> Result<(), Error>;
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

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
