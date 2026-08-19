// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for the ext2 read path.
//!
//! Two kinds, and the split is deliberate. Most run against an image `mke2fs`
//! built, so what they assert is ext2 rather than this crate's opinion of it.
//! The rest run against crafted bytes, because the failures worth checking —
//! a record length of zero, a name running past its record, a pointer past
//! the volume — are ones no correct tool will produce on request.

use super::*;
use std::vec;
use std::vec::Vec;

/// The image, read whole. Its path comes from the build: a `genrule` under
/// Bazel, `build.rs` under cargo, both running `testdata/mkimage.sh`.
fn image() -> Vec<u8> {
    // Bazel hands the genrule's output over in the environment; cargo's build
    // script writes it into OUT_DIR, which does not exist under Bazel — so
    // `option_env!`, which is absent rather than a compile error.
    let path = std::env::var("TESSERA_EXT2_IMAGE")
        .ok()
        .or_else(|| option_env!("OUT_DIR").map(|dir| std::format!("{dir}/ext2_test.img")))
        .unwrap_or_else(|| panic!("neither TESSERA_EXT2_IMAGE nor OUT_DIR is set"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// A device over a byte slice.
struct Ram {
    bytes: Vec<u8>,
    reads: usize,
}

impl Ram {
    fn new(bytes: Vec<u8>) -> Self {
        Ram { bytes, reads: 0 }
    }
}

impl BlockIo for Ram {
    fn read_sector(&mut self, lba: u64, into: &mut [u8; SECTOR]) -> Result<(), Error> {
        self.reads += 1;
        let at = usize::try_from(lba).map_err(|_| Error::Io)? * SECTOR;
        let end = at.checked_add(SECTOR).ok_or(Error::Io)?;
        let slice = self.bytes.get(at..end).ok_or(Error::Io)?;
        into.copy_from_slice(slice);
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, from: &[u8; SECTOR]) -> Result<(), Error> {
        let at = usize::try_from(lba).map_err(|_| Error::Io)? * SECTOR;
        let end = at.checked_add(SECTOR).ok_or(Error::Io)?;
        let slice = self.bytes.get_mut(at..end).ok_or(Error::Io)?;
        slice.copy_from_slice(from);
        Ok(())
    }
}

fn mounted() -> Fs<Ram> {
    Fs::mount(Ram::new(image())).expect("mount the mke2fs image")
}

fn read_whole(fs: &mut Fs<Ram>, inode: &Inode) -> Vec<u8> {
    let mut out = vec![0u8; usize::try_from(inode.size).expect("size fits")];
    let n = fs.read_at(inode, 0, &mut out).expect("read");
    assert_eq!(n, out.len(), "read short of the declared size");
    out
}

#[test]
fn the_superblock_is_what_mke2fs_was_asked_for() {
    let fs = mounted();
    let sb = fs.superblock();
    assert_eq!(sb.block_size, 1024, "mkimage.sh asks for -b 1024");
    assert_eq!(sb.inode_size, 256);
    assert_eq!(sb.first_inode, 11);
    assert_eq!(sb.blocks_count, 4096, "a 4 MiB image at 1 KiB blocks");
    assert_eq!(
        sb.first_data_block, 1,
        "1 KiB blocks put the superblock in 1"
    );
}

#[test]
fn the_root_is_a_directory_at_inode_two() {
    let mut fs = mounted();
    let root = fs.root().expect("root");
    assert_eq!(root.number, 2);
    assert_eq!(root.kind, Kind::Directory);
    assert!(root.links >= 3, "., .. and dir/ link to it");
}

#[test]
fn a_short_file_reads_back_exactly() {
    let mut fs = mounted();
    let inode = fs.lookup(b"/hello.txt").expect("lookup");
    assert_eq!(inode.kind, Kind::Regular);
    assert_eq!(inode.size, 16);
    assert_eq!(read_whole(&mut fs, &inode), b"hello from ext2\n");
}

#[test]
fn a_path_walks_through_a_directory() {
    let mut fs = mounted();
    let inode = fs.lookup(b"/dir/nested.txt").expect("lookup");
    assert_eq!(read_whole(&mut fs, &inode), b"nested\n");
}

/// The path shapes concatenation produces, which a reader meets before it
/// meets a tidy one.
#[test]
fn empty_and_dot_components_are_skipped() {
    let mut fs = mounted();
    let plain = fs.lookup(b"/dir/nested.txt").expect("plain");
    for path in [
        &b"//dir//nested.txt"[..],
        b"/./dir/./nested.txt",
        b"dir/nested.txt",
    ] {
        assert_eq!(
            fs.lookup(path).expect("odd path").number,
            plain.number,
            "{path:?}"
        );
    }
}

/// 70 000 bytes at 1 KiB blocks is 69 blocks, so 57 of them are reached
/// through the single-indirect block rather than the inode's direct list.
/// The content varies per byte, so a reader returning the right length full of
/// zeroes — or repeating one block — fails.
#[test]
fn a_file_past_the_direct_blocks_reads_through_the_indirect_block() {
    let mut fs = mounted();
    let inode = fs.lookup(b"/big.bin").expect("lookup");
    assert_eq!(inode.size, 70_000);
    let bytes = read_whole(&mut fs, &inode);
    let expected: Vec<u8> = (0..70_000u32).map(|i| ((i * 7 + 3) % 256) as u8).collect();
    let first_wrong = bytes.iter().zip(&expected).position(|(a, b)| a != b);
    assert_eq!(first_wrong, None, "first wrong byte");
}

#[test]
fn a_read_at_an_offset_starts_there_and_stops_at_the_end() {
    let mut fs = mounted();
    let inode = fs.lookup(b"/big.bin").expect("lookup");
    let mut out = [0u8; 32];

    // An offset inside the indirect range, not aligned to a block.
    let at = 20_001u64;
    assert_eq!(fs.read_at(&inode, at, &mut out).expect("read"), 32);
    for (index, byte) in out.iter().enumerate() {
        let i = at as u32 + index as u32;
        assert_eq!(*byte, ((i * 7 + 3) % 256) as u8, "byte {i}");
    }

    // Straddling the end: short, and short is not an error.
    let mut tail = [0xabu8; 32];
    let read = fs
        .read_at(&inode, inode.size - 10, &mut tail)
        .expect("tail");
    assert_eq!(read, 10);
    assert_eq!(tail[10..], [0xab; 22], "past the end must be untouched");
    assert_eq!(fs.read_at(&inode, inode.size, &mut tail).expect("eof"), 0);
}

#[test]
fn the_root_lists_what_the_builder_put_there() {
    let mut fs = mounted();
    let root = fs.root().expect("root");
    let mut names: Vec<Vec<u8>> = Vec::new();
    fs.for_each_entry(&root, |entry| {
        names.push(entry.name().to_vec());
        true
    })
    .expect("iterate");
    for wanted in [&b"hello.txt"[..], b"big.bin", b"dir", b".", b".."] {
        assert!(
            names.iter().any(|n| n == wanted),
            "missing {wanted:?} in {names:?}"
        );
    }
}

#[test]
fn a_missing_name_is_not_found_and_a_file_is_not_a_directory() {
    let mut fs = mounted();
    assert_eq!(fs.lookup(b"/nope.txt"), Err(Error::NotFound));
    assert_eq!(fs.lookup(b"/hello.txt/deeper"), Err(Error::NotDirectory));
    assert_eq!(fs.lookup(&[b'x'; MAX_NAME + 1]), Err(Error::NameTooLong));
}

// --- crafted bytes: the refusals no correct tool will produce on request ---

fn corrupt(patch: impl FnOnce(&mut Vec<u8>)) -> Result<Fs<Ram>, Error> {
    let mut bytes = image();
    patch(&mut bytes);
    Fs::mount(Ram::new(bytes))
}

#[test]
fn a_volume_that_is_not_ext2_is_refused() {
    assert_eq!(
        corrupt(|b| b[1024 + 56..1024 + 58].copy_from_slice(&0u16.to_le_bytes())).err(),
        Some(Error::BadMagic)
    );
}

/// The bit that matters most: an ext4 volume with extents has an inode whose
/// `i_block` is not a list of pointers at all. Reading it as one would return
/// whatever the extent header happens to encode, which is the failure mode
/// "incompatible" exists to name.
#[test]
fn an_incompatible_feature_is_refused_rather_than_read_past() {
    const INCOMPAT_EXTENTS: u32 = 0x0040;
    assert_eq!(
        corrupt(|b| {
            let at = 1024 + 96;
            let now = u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
            b[at..at + 4].copy_from_slice(&(now | INCOMPAT_EXTENTS).to_le_bytes());
        })
        .err(),
        Some(Error::Incompatible)
    );
}

#[test]
fn an_unreadable_block_size_is_refused() {
    assert_eq!(
        corrupt(|b| b[1024 + 24..1024 + 28].copy_from_slice(&3u32.to_le_bytes())).err(),
        Some(Error::BlockSize)
    );
}

#[test]
fn a_zero_group_size_is_refused_rather_than_dividing_by_it() {
    assert_eq!(
        corrupt(|b| b[1024 + 32..1024 + 36].copy_from_slice(&0u32.to_le_bytes())).err(),
        Some(Error::Corrupt)
    );
    assert_eq!(
        corrupt(|b| b[1024 + 40..1024 + 44].copy_from_slice(&0u32.to_le_bytes())).err(),
        Some(Error::Corrupt)
    );
}

#[test]
fn an_inode_size_that_cannot_tile_a_block_is_refused() {
    for bad in [0u16, 64, 96, 8192] {
        assert_eq!(
            corrupt(|b| b[1024 + 88..1024 + 90].copy_from_slice(&bad.to_le_bytes())).err(),
            Some(Error::Corrupt),
            "inode_size {bad}"
        );
    }
}

/// A record length of zero would leave the walk on the same entry for ever.
/// The refusal is what makes a directory read terminate on hostile input.
///
/// Two guards catch this — the explicit `record < 8` and the name-past-record
/// check, which fires for any record under eight bytes. Removing either alone
/// leaves the other holding; removing both hangs, which is how the property
/// was confirmed to be pinned by the code rather than by one line of it.
#[test]
fn a_directory_record_that_does_not_advance_is_refused() {
    let mut bytes = image();
    let root_block = {
        let mut fs = Fs::mount(Ram::new(bytes.clone())).expect("mount");
        let root = fs.root().expect("root");
        fs.resolve(&root, 0).expect("resolve").expect("root block")
    };
    let at = root_block as usize * 1024;
    bytes[at + 4..at + 6].copy_from_slice(&0u16.to_le_bytes());
    let mut fs = Fs::mount(Ram::new(bytes)).expect("mount");
    let root = fs.root().expect("root");
    assert_eq!(fs.for_each_entry(&root, |_| true), Err(Error::Corrupt));
}

/// A name declared longer than its record reads the bytes of the next entry.
#[test]
fn a_name_running_past_its_record_is_refused() {
    let mut bytes = image();
    let root_block = {
        let mut fs = Fs::mount(Ram::new(bytes.clone())).expect("mount");
        let root = fs.root().expect("root");
        fs.resolve(&root, 0).expect("resolve").expect("root block")
    };
    let at = root_block as usize * 1024;
    bytes[at + 6] = 255;
    let mut fs = Fs::mount(Ram::new(bytes)).expect("mount");
    let root = fs.root().expect("root");
    assert_eq!(fs.for_each_entry(&root, |_| true), Err(Error::Corrupt));
}

#[test]
fn an_inode_number_outside_the_volume_is_refused() {
    let mut fs = mounted();
    let count = fs.superblock().inodes_count;
    assert_eq!(fs.inode(0), Err(Error::Corrupt));
    assert_eq!(fs.inode(count + 1), Err(Error::Corrupt));
}

/// A hole is a zero pointer and reads as zeroes — a legitimate answer, not an
/// error and not a short read. Confusing the two would make a sparse file
/// either fail or read the superblock, which is block zero.
#[test]
fn a_hole_reads_as_zeroes() {
    let mut bytes = image();
    let (inode_number, size) = {
        let mut fs = Fs::mount(Ram::new(bytes.clone())).expect("mount");
        let inode = fs.lookup(b"/big.bin").expect("lookup");
        (inode.number, inode.size)
    };
    // Punch the first direct pointer of big.bin, which is inode `inode_number`.
    let (table, inode_size, per_block) = {
        let fs = Fs::mount(Ram::new(bytes.clone())).expect("mount");
        let sb = *fs.superblock();
        let descriptors = (sb.first_data_block + 1) as usize * 1024;
        let table = u32::from_le_bytes([
            bytes[descriptors + 8],
            bytes[descriptors + 9],
            bytes[descriptors + 10],
            bytes[descriptors + 11],
        ]);
        (
            table,
            sb.inode_size as usize,
            sb.block_size as usize / sb.inode_size as usize,
        )
    };
    let within = (inode_number - 1) as usize;
    let at = (table as usize + within / per_block) * 1024 + (within % per_block) * inode_size;
    bytes[at + 40..at + 44].copy_from_slice(&0u32.to_le_bytes());

    // Poison block zero. Without this the test cannot tell "a hole reads as
    // zeroes" from "a zero pointer was followed and block zero was read",
    // because block zero of an mke2fs image is itself all zeroes — an
    // inversion that followed the pointer passed this test until the
    // poisoning was added.
    bytes[..1024].fill(0x5a);

    let mut fs = Fs::mount(Ram::new(bytes)).expect("mount");
    let inode = fs.inode(inode_number).expect("inode");
    assert_eq!(
        inode.size, size,
        "punching a pointer must not change the size"
    );
    let mut out = [0xffu8; 64];
    assert_eq!(fs.read_at(&inode, 0, &mut out).expect("read"), 64);
    assert_eq!(out, [0u8; 64], "a hole reads as zeroes");
}

// --- the write path ---

/// A device over a byte vector that takes writes, and can be handed back so a
/// test can put the mutated image in front of `e2fsck`.
impl Ram {
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Runs `e2fsck -fn` over an image and returns its output.
///
/// **The oracle for every test below.** This crate's own reader agreeing with
/// this crate's own writer would prove only that they were written by the same
/// hand; `e2fsck` recomputes the bitmaps, the free counts, the link counts and
/// `i_blocks` from the structures themselves and says whether the volume is
/// one ext2 would recognise. That is what porting a real format buys, and it
/// is the whole reason the write path is tested this way.
fn fsck(bytes: &[u8]) -> (bool, std::string::String) {
    use std::io::Write;
    use std::string::String;
    // A name per call, not per image. The length is the same for every test
    // here, so a name derived from it collides — and the harness runs tests
    // concurrently, so one test truncated the file another was reading and
    // `e2fsck` reported a short read on a perfectly good volume.
    static NEXT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let unique = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(std::format!(
        "tessera-ext2-fsck-{}-{unique}.img",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&path).expect("scratch image");
    file.write_all(bytes).expect("write scratch image");
    drop(file);
    let out = std::process::Command::new("e2fsck")
        .args(["-fn"])
        .arg(&path)
        .env(
            "PATH",
            std::format!(
                "/usr/sbin:/sbin:{}",
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        // Absent `e2fsck` is a failure, never a skip. A suite that quietly
        // stopped checking would report the same green as one that checked —
        // and the whole argument for porting a real format is that something
        // outside this repository judges the result.
        .expect("e2fsck must be installed: the write path is verified by it, not by this crate");
    let _ = std::fs::remove_file(&path);
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

#[test]
fn the_image_the_builder_produced_is_already_clean() {
    // The premise of every test below: if `e2fsck` disliked the *unmodified*
    // image, a clean result after a write would mean nothing.
    let (ok, text) = fsck(&image());
    assert!(ok, "e2fsck on the pristine image: {text}");
}

#[test]
fn overwriting_inside_an_existing_block_keeps_the_volume_clean() {
    let mut fs = mounted();
    let mut inode = fs.lookup(b"/hello.txt").expect("lookup");
    let written = fs.write_at(&mut inode, 0, b"HELLO").expect("write");
    assert_eq!(written, 5);

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after an overwrite: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let inode = fs.lookup(b"/hello.txt").expect("lookup");
    assert_eq!(inode.size, 16, "an overwrite must not change the size");
    assert_eq!(read_whole(&mut fs, &inode), b"HELLO from ext2\n");
}

#[test]
fn extending_a_file_allocates_and_stays_clean() {
    let mut fs = mounted();
    let mut inode = fs.lookup(b"/hello.txt").expect("lookup");
    let free_before = fs.superblock().free_blocks;

    // Past the end of the one block it occupies, so this must allocate.
    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    fs.write_at(&mut inode, 16, &payload).expect("extend");
    assert_eq!(inode.size, 16 + 3000);

    let free_after = fs.superblock().free_blocks;
    assert!(free_after < free_before, "extending must consume blocks");

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after extending: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let inode = fs.lookup(b"/hello.txt").expect("lookup");
    assert_eq!(inode.size, 16 + 3000);
    let mut out = vec![0u8; 3000];
    assert_eq!(fs.read_at(&inode, 16, &mut out).expect("read"), 3000);
    assert_eq!(out, payload, "what was written is what comes back");
}

/// Past twelve blocks the file needs an indirect block, which is storage it
/// occupies that no offset in it maps to — the case `i_blocks` exists for, and
/// the one `e2fsck` recomputes.
#[test]
fn growing_past_the_direct_blocks_allocates_the_indirect_one() {
    let mut fs = mounted();
    let mut root = fs.root().expect("root");
    let mut inode = fs.create(&mut root, b"grown.bin").expect("create");
    let payload: Vec<u8> = (0..20_000u32).map(|i| ((i * 3 + 1) % 256) as u8).collect();
    fs.write_at(&mut inode, 0, &payload).expect("write");

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after growing past the direct blocks: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let inode = fs.lookup(b"/grown.bin").expect("lookup");
    assert_eq!(inode.size, 20_000);
    assert_eq!(read_whole(&mut fs, &inode), payload);
}

#[test]
fn a_created_file_is_found_by_name_and_the_volume_stays_clean() {
    let mut fs = mounted();
    let mut root = fs.root().expect("root");
    let mut inode = fs.create(&mut root, b"fresh.txt").expect("create");
    assert_eq!(inode.kind, Kind::Regular);
    assert_eq!(inode.size, 0);
    fs.write_at(&mut inode, 0, b"written by tessera\n")
        .expect("write");

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after creating a file: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let found = fs.lookup(b"/fresh.txt").expect("the new name resolves");
    assert_eq!(read_whole(&mut fs, &found), b"written by tessera\n");
}

#[test]
fn a_name_that_is_already_there_is_refused() {
    let mut fs = mounted();
    let mut root = fs.root().expect("root");
    assert_eq!(
        fs.create(&mut root, b"hello.txt").err(),
        Some(Error::Exists)
    );
}

#[test]
fn a_directory_is_not_written_as_a_file() {
    let mut fs = mounted();
    let mut dir = fs.lookup(b"/dir").expect("lookup");
    assert_eq!(
        fs.write_at(&mut dir, 0, b"x").err(),
        Some(Error::NotDirectory)
    );
}

/// A device that refuses writes must produce a refusal, not a silent success —
/// which is what the trait's default does and what a driver that only reads
/// will hand this crate.
#[test]
fn a_read_only_device_refuses_rather_than_dropping_the_write() {
    struct ReadOnly(Vec<u8>);
    impl BlockIo for ReadOnly {
        fn read_sector(&mut self, lba: u64, into: &mut [u8; SECTOR]) -> Result<(), Error> {
            let at = usize::try_from(lba).map_err(|_| Error::Io)? * SECTOR;
            into.copy_from_slice(self.0.get(at..at + SECTOR).ok_or(Error::Io)?);
            Ok(())
        }
    }
    let mut fs = Fs::mount(ReadOnly(image())).expect("mount");
    let mut inode = fs.lookup(b"/hello.txt").expect("lookup");
    assert_eq!(
        fs.write_at(&mut inode, 0, b"x").err(),
        Some(Error::ReadOnly)
    );
}

/// Truncating must give the blocks back — both the count and the bits, which
/// `e2fsck` compares against each other.
#[test]
fn truncating_frees_the_blocks_and_stays_clean() {
    let mut fs = mounted();
    let free_at_rest = fs.superblock().free_blocks;
    let mut inode = fs.lookup(b"/big.bin").expect("lookup");

    fs.truncate(&mut inode, 0).expect("truncate");
    assert_eq!(inode.size, 0);
    assert_eq!(inode.sectors, 0, "a file of nothing occupies nothing");
    assert!(
        fs.superblock().free_blocks > free_at_rest,
        "truncating must return blocks"
    );

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after truncating: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let inode = fs.lookup(b"/big.bin").expect("lookup");
    assert_eq!(inode.size, 0);
    let mut out = [0u8; 8];
    assert_eq!(fs.read_at(&inode, 0, &mut out).expect("read"), 0);
}

/// Truncate to a length that keeps some blocks, so the freed set is a suffix
/// rather than everything — the case where an off-by-one frees a block the
/// file still points at.
#[test]
fn a_partial_truncate_keeps_what_is_below_it() {
    let mut fs = mounted();
    let mut inode = fs.lookup(b"/big.bin").expect("lookup");
    let head: Vec<u8> = (0..3000u32).map(|i| ((i * 7 + 3) % 256) as u8).collect();

    fs.truncate(&mut inode, 3000).expect("truncate");
    assert_eq!(inode.size, 3000);

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after a partial truncate: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let inode = fs.lookup(b"/big.bin").expect("lookup");
    assert_eq!(
        read_whole(&mut fs, &inode),
        head,
        "the kept prefix is intact"
    );
}

#[test]
fn truncating_upwards_is_refused_rather_than_ignored() {
    let mut fs = mounted();
    let mut inode = fs.lookup(b"/hello.txt").expect("lookup");
    assert_eq!(
        fs.truncate(&mut inode, 4096).err(),
        Some(Error::TooLarge),
        "growing is write_at's job, and silence here would look like success"
    );
}

/// Truncate then write again: the blocks come back from the allocator, and the
/// file reads as what was written second rather than a mixture.
#[test]
fn a_file_rewritten_after_truncation_holds_only_the_new_bytes() {
    let mut fs = mounted();
    let mut inode = fs.lookup(b"/big.bin").expect("lookup");
    fs.truncate(&mut inode, 0).expect("truncate");
    fs.write_at(&mut inode, 0, b"second\n").expect("rewrite");

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after truncate and rewrite: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let inode = fs.lookup(b"/big.bin").expect("lookup");
    assert_eq!(inode.size, 7);
    assert_eq!(read_whole(&mut fs, &inode), b"second\n");
}

/// Removing a name gives the inode and its blocks back, and leaves a directory
/// whose record chain still fills every block exactly — which is what `e2fsck`
/// walks and what a blanked record in the middle would break.
#[test]
fn unlinking_returns_the_inode_and_its_blocks() {
    let mut fs = mounted();
    let free_blocks = fs.superblock().free_blocks;
    let free_inodes = fs.superblock().free_inodes;
    let mut root = fs.root().expect("root");

    fs.unlink(&mut root, b"big.bin", 1_700_000_000)
        .expect("unlink");
    assert!(fs.superblock().free_blocks > free_blocks, "blocks returned");
    assert_eq!(
        fs.superblock().free_inodes,
        free_inodes + 1,
        "exactly one inode returned"
    );

    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after unlinking: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    assert_eq!(fs.lookup(b"/big.bin"), Err(Error::NotFound));
    // The names either side of it must still resolve: absorbing a record into
    // the one before it is what keeps the rest of the chain reachable.
    assert!(fs.lookup(b"/hello.txt").is_ok());
    assert!(fs.lookup(b"/dir/nested.txt").is_ok());
}

#[test]
fn unlinking_the_first_name_in_a_block_keeps_the_rest_reachable() {
    let mut fs = mounted();
    let mut root = fs.root().expect("root");
    // Collect the names in order so the test removes whichever is genuinely
    // first, rather than one this test assumed was.
    // Files only, and selected by **kind** rather than by name: a directory is
    // `rmdir`'s business and this `unlink` refuses it. Naming the directories
    // to skip missed `lost+found`, which every `mke2fs` volume has and this
    // test did not think of.
    let mut real: Vec<Vec<u8>> = Vec::new();
    fs.for_each_entry(&root, |entry| {
        if entry.kind == Kind::Regular {
            real.push(entry.name().to_vec());
        }
        true
    })
    .expect("iterate");
    let first = real.first().expect("a name to remove").clone();

    fs.unlink(&mut root, &first, 1_700_000_000).expect("unlink");
    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after unlinking the first name: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    for name in real.iter().skip(1) {
        let mut path = vec![b'/'];
        path.extend_from_slice(name);
        assert!(fs.lookup(&path).is_ok(), "{name:?} must still resolve");
    }
}

/// A directory is refused rather than half-removed: dropping the name without
/// dropping the parent's link count leaves a directory nothing reaches, which
/// is what `e2fsck` reported the first time this did not check.
#[test]
fn unlinking_a_directory_is_refused() {
    let mut fs = mounted();
    let mut root = fs.root().expect("root");
    assert_eq!(
        fs.unlink(&mut root, b"dir", 1_700_000_000),
        Err(Error::NotDirectory)
    );
}

#[test]
fn unlinking_a_name_that_is_not_there_is_not_found() {
    let mut fs = mounted();
    let mut root = fs.root().expect("root");
    assert_eq!(
        fs.unlink(&mut root, b"nope.txt", 1_700_000_000),
        Err(Error::NotFound)
    );
}

/// Create, write, unlink, create again: the allocator must hand the same
/// resources out cleanly rather than leaking or double-issuing them.
#[test]
fn a_name_can_be_created_removed_and_created_again() {
    let mut fs = mounted();
    let mut root = fs.root().expect("root");
    let free_inodes = fs.superblock().free_inodes;

    let mut inode = fs.create(&mut root, b"cycle.txt").expect("create");
    fs.write_at(&mut inode, 0, b"first\n").expect("write");
    fs.unlink(&mut root, b"cycle.txt", 1_700_000_000)
        .expect("unlink");
    let mut again = fs.create(&mut root, b"cycle.txt").expect("create again");
    fs.write_at(&mut again, 0, b"second\n")
        .expect("write again");

    assert_eq!(
        fs.superblock().free_inodes,
        free_inodes - 1,
        "one cycle must consume exactly one inode"
    );
    let bytes = fs.into_device().into_bytes();
    let (ok, text) = fsck(&bytes);
    assert!(ok, "e2fsck after a create/unlink/create cycle: {text}");

    let mut fs = Fs::mount(Ram::new(bytes)).expect("remount");
    let found = fs.lookup(b"/cycle.txt").expect("lookup");
    assert_eq!(read_whole(&mut fs, &found), b"second\n");
}
