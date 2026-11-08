//! Directory walker that measures allocated size.

use crate::fs::Fs;
use std::collections::HashSet;
use std::io;
use std::path::Path;

/// Size of one `st_blocks` unit, regardless of the filesystem block size.
const BLOCK_SIZE: u64 = 512;

/// Totals for one measured root.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Measure {
    /// Bytes actually allocated on disk (`st_blocks * 512`).
    pub allocated_bytes: u64,
    /// Regular files counted (each hardlinked inode once).
    pub file_count: u64,
}

/// Sequential walker. Keeps the set of seen `(dev, ino)` pairs across calls,
/// so a hardlink shared between two roots of one scan is counted once.
pub struct Walker<'a> {
    fs: &'a dyn Fs,
    seen: HashSet<(u64, u64)>,
}

impl<'a> Walker<'a> {
    pub fn new(fs: &'a dyn Fs) -> Self {
        Self {
            fs,
            seen: HashSet::new(),
        }
    }

    /// Measures `root` and everything below it.
    ///
    /// Symlinks are never followed nor counted. Directory blocks are counted
    /// like `du` does. Errors are propagated for now; the caller decides.
    pub fn measure(&mut self, root: &Path) -> io::Result<Measure> {
        let mut total = Measure::default();
        // Explicit stack: deep trees must not overflow the call stack.
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let meta = self.fs.symlink_metadata(&path)?;
            if meta.is_symlink {
                continue;
            }
            if meta.nlink > 1 && !self.seen.insert((meta.dev, meta.ino)) {
                continue;
            }
            total.allocated_bytes = total
                .allocated_bytes
                .saturating_add(meta.blocks.saturating_mul(BLOCK_SIZE));
            if meta.is_dir {
                pending.extend(self.fs.read_dir(&path)?.into_iter().map(|e| e.path));
            } else {
                total.file_count += 1;
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FakeFs, Metadata};
    use std::time::SystemTime;

    fn entry(is_dir: bool, ino: u64, nlink: u64, blocks: u64, len: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink,
            blocks,
            len,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    // FR-003: allocated size is st_blocks * 512, never the logical length.
    #[test]
    fn allocated_size_uses_blocks() {
        let mut fs = FakeFs::new();
        fs.insert("/r", entry(true, 1, 1, 0, 0))
            .insert("/r/sparse", entry(false, 2, 1, 8, 1_000_000))
            .insert("/r/sub", entry(true, 3, 1, 0, 0))
            .insert("/r/sub/tiny", entry(false, 4, 1, 8, 10));
        let m = Walker::new(&fs).measure(Path::new("/r")).unwrap();
        assert_eq!(m.allocated_bytes, 16 * 512);
        assert_eq!(m.file_count, 2);
    }

    // FR-003: an inode with several links counts once, also across roots.
    #[test]
    fn hardlink_counted_once() {
        let mut fs = FakeFs::new();
        fs.insert("/r", entry(true, 1, 1, 0, 0))
            .insert("/r/a", entry(false, 9, 3, 8, 4096))
            .insert("/r/b", entry(false, 9, 3, 8, 4096))
            .insert("/s", entry(true, 5, 1, 0, 0))
            .insert("/s/c", entry(false, 9, 3, 8, 4096));
        let mut w = Walker::new(&fs);
        let first = w.measure(Path::new("/r")).unwrap();
        let second = w.measure(Path::new("/s")).unwrap();
        assert_eq!(
            first,
            Measure {
                allocated_bytes: 8 * 512,
                file_count: 1
            }
        );
        assert_eq!(second, Measure::default());
    }

    // FR-003: the same inode number on another device is a different file.
    #[test]
    fn same_ino_on_other_dev_is_distinct() {
        let mut fs = FakeFs::new();
        let mut other = entry(false, 9, 2, 8, 4096);
        other.dev = 2;
        fs.insert("/r", entry(true, 1, 1, 0, 0))
            .insert("/r/a", entry(false, 9, 2, 8, 4096))
            .insert("/r/b", other);
        let m = Walker::new(&fs).measure(Path::new("/r")).unwrap();
        assert_eq!(m.file_count, 2);
        assert_eq!(m.allocated_bytes, 16 * 512);
    }

    // FR-005 (minimal, conservative): a symlink is neither followed nor counted.
    #[test]
    fn symlink_is_not_followed_or_counted() {
        let mut fs = FakeFs::new();
        let mut link = entry(true, 7, 1, 8, 20);
        link.is_symlink = true;
        fs.insert("/r", entry(true, 1, 1, 0, 0))
            .insert("/r/l", link)
            .insert("/r/l/inside", entry(false, 8, 1, 8, 20));
        let m = Walker::new(&fs).measure(Path::new("/r")).unwrap();
        assert_eq!(m, Measure::default());
    }
}
