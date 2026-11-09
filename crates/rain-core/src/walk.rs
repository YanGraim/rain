//! Directory walker that measures allocated size.

use crate::fs::{Fs, Metadata};
use crate::protect::ProtectList;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Size of one `st_blocks` unit, regardless of the filesystem block size.
const BLOCK_SIZE: u64 = 512;

/// Directories listed per parallel batch. Bounds how many listings are held
/// in memory at once; merge order is unchanged, so results stay
/// deterministic.
const LEVEL_BATCH: usize = 256;

/// Why an entry was left out of the totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    /// `EACCES`/`EPERM`, including what macOS denies without Full Disk Access.
    PermissionDenied,
    Protected,
    Symlink,
    OtherVolume,
    NotFound,
    /// Any other read error, kept with its kind so it is never silent.
    Io(io::ErrorKind),
}

impl From<&io::Error> for SkipReason {
    fn from(e: &io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::NotFound => Self::NotFound,
            kind => Self::Io(kind),
        }
    }
}

/// An entry left out of the totals, and why.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: SkipReason,
}

/// Totals for one measured root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Measure {
    /// Bytes actually allocated on disk (`st_blocks * 512`).
    pub allocated_bytes: u64,
    /// Non-directory entries counted (each hardlinked inode once).
    pub file_count: u64,
    /// Entries not counted nor descended, sorted by path.
    pub skipped: Vec<Skipped>,
    /// FR-011: the walk stopped early; totals are partial and must never be
    /// shown as final.
    pub cancelled: bool,
}

/// Sequential walker. Keeps the set of seen `(dev, ino)` pairs across calls,
/// so a hardlink shared between two roots of one scan is counted once.
pub struct Walker<'a> {
    fs: &'a dyn Fs,
    protect: &'a ProtectList,
    seen: HashSet<(u64, u64)>,
    threads: usize,
    cancel: Option<&'a AtomicBool>,
}

impl<'a> Walker<'a> {
    /// `protect` should already carry identities
    /// ([`ProtectList::with_identities`]), built once per scan.
    pub fn new(fs: &'a dyn Fs, protect: &'a ProtectList) -> Self {
        Self {
            fs,
            protect,
            seen: HashSet::new(),
            threads: 1,
            cancel: None,
        }
    }

    /// Number of worker threads (at least 1).
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }

    /// FR-011: flag checked for every entry; once set the walk stops and the
    /// result is marked [`Measure::cancelled`].
    pub fn with_cancel(mut self, cancel: &'a AtomicBool) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Measures `root` and everything below it. Never fails: whatever cannot
    /// be read, is protected, is a symlink or lives on another volume ends up
    /// in [`Measure::skipped`], is not counted and is not descended.
    ///
    /// `root` must be canonical (as returned by `Platform::resolve`); a root
    /// that is or goes through a symlink is skipped as [`SkipReason::Symlink`].
    pub fn measure(&mut self, root: &Path) -> Measure {
        let mut out = Measure::default();
        if self.is_cancelled() {
            out.cancelled = true;
            return out;
        }
        match self.open_root(root) {
            Ok(meta) => self.walk(root, meta, &mut out),
            Err(reason) => out.skip(root, reason),
        }
        out.skipped.sort();
        out
    }

    /// Validates the root and reads its metadata exactly once. That single
    /// read fixes the reference device and identity for the whole walk, so
    /// a root swapped afterwards cannot change which volume counts as "ours".
    fn open_root(&self, root: &Path) -> Result<Metadata, SkipReason> {
        let meta = self.fs.symlink_metadata(root);
        // Checked before canonicalizing: a dangling link is still a link.
        if matches!(&meta, Ok(m) if m.is_symlink) {
            return Err(SkipReason::Symlink);
        }
        // A symlinked ancestor makes `root` resolve elsewhere: the "never
        // leave the root" check would then be relative to the wrong place.
        if self
            .fs
            .canonicalize(root)
            .map_err(|e| SkipReason::from(&e))?
            != root
        {
            return Err(SkipReason::Symlink);
        }
        let meta = meta.map_err(|e| SkipReason::from(&e))?;
        if self.protect.is_protected_on(self.fs, root) {
            return Err(SkipReason::Protected);
        }
        Ok(meta)
    }

    /// Level-synchronous walk: each level's directories are read in
    /// parallel (the slow I/O), then merged on this thread in a fixed order.
    /// Every decision with shared state (directory cycles, which link of a
    /// hardlinked inode counts, FR-003/FR-010) happens only in the merge, so
    /// the result never depends on thread scheduling or thread count.
    fn walk(&mut self, root: &Path, root_meta: Metadata, out: &mut Measure) {
        // Directories are tracked per root, whatever their nlink, so a
        // hard-linked directory cycle ends; nlink cannot be trusted for that.
        let mut dirs = HashSet::new();
        let mut level = Vec::new();
        self.accept(root.to_path_buf(), root_meta, &mut dirs, &mut level, out);
        while !level.is_empty() {
            if self.is_cancelled() {
                out.cancelled = true;
                return;
            }
            let mut next = Vec::new();
            for batch in level.chunks(LEVEL_BATCH) {
                let listed = self.read_level(batch, root_meta.dev);
                for (dir, listing) in batch.iter().zip(listed) {
                    match listing {
                        Listing::Cancelled => {
                            out.cancelled = true;
                            return;
                        }
                        Listing::Failed(reason) => out.skip(dir, reason),
                        Listing::Children(children) => {
                            for (path, admitted) in children {
                                match admitted {
                                    Ok(meta) => self.accept(path, meta, &mut dirs, &mut next, out),
                                    Err(reason) => out.skip(&path, reason),
                                }
                            }
                        }
                    }
                }
            }
            level = next;
        }
    }

    /// Counts an admitted entry and queues it for descent if it is a
    /// directory not seen yet in this root.
    fn accept(
        &mut self,
        path: PathBuf,
        meta: Metadata,
        dirs: &mut HashSet<(u64, u64)>,
        next: &mut Vec<PathBuf>,
        out: &mut Measure,
    ) {
        if meta.is_dir {
            if !dirs.insert((meta.dev, meta.ino)) {
                return;
            }
            next.push(path);
        } else {
            if meta.nlink > 1 && !self.seen.insert((meta.dev, meta.ino)) {
                return;
            }
            out.file_count = out.file_count.saturating_add(1);
        }
        out.add_blocks(meta.blocks);
    }

    /// Lists and admits the children of every directory in `level`, using up
    /// to `threads` workers. Results come back in `level` order.
    fn read_level(&self, level: &[PathBuf], root_dev: u64) -> Vec<Listing> {
        let workers = self.threads.min(level.len());
        if workers <= 1 {
            return level.iter().map(|d| self.list(d, root_dev)).collect();
        }
        let next = AtomicUsize::new(0);
        let mut slots: Vec<Option<Listing>> = Vec::new();
        slots.resize_with(level.len(), || None);
        let done: Vec<Vec<(usize, Listing)>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    s.spawn(|| {
                        let mut mine = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(dir) = level.get(i) else { break };
                            mine.push((i, self.list(dir, root_dev)));
                        }
                        mine
                    })
                })
                .collect();
            // A worker panic is a bug: re-raise it on this thread rather
            // than reporting a partial result as cancelled or complete.
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
                .collect()
        });
        for (i, listing) in done.into_iter().flatten() {
            if let Some(slot) = slots.get_mut(i) {
                *slot = Some(listing);
            }
        }
        // Every index was claimed by a worker that finished, so no slot is
        // empty. Should one ever be, it stays aligned with its directory and
        // is reported as skipped: never dropped, never "cancelled".
        slots
            .into_iter()
            .map(|l| l.unwrap_or(Listing::Failed(SkipReason::Io(io::ErrorKind::Other))))
            .collect()
    }

    /// Reads one directory and admits each child, checking the cancel flag
    /// before every entry (FR-011: a huge directory must not delay the stop).
    fn list(&self, dir: &Path, root_dev: u64) -> Listing {
        if self.is_cancelled() {
            return Listing::Cancelled;
        }
        let mut entries = match self.fs.read_dir(dir) {
            Ok(c) => c,
            Err(e) => return Listing::Failed(SkipReason::from(&e)),
        };
        // read_dir order is filesystem-defined; sort for a stable merge.
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let mut children = Vec::with_capacity(entries.len());
        for child in entries {
            if self.is_cancelled() {
                return Listing::Cancelled;
            }
            let admitted = self.admit(&child.path, root_dev);
            children.push((child.path, admitted));
        }
        Listing::Children(children)
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.is_some_and(|c| c.load(Ordering::Relaxed))
    }

    /// Reads a child once and decides whether it may be counted or descended.
    /// Its parent was already cleared, so the protection check only needs
    /// the child's own name and identity.
    fn admit(&self, path: &Path, root_dev: u64) -> Result<Metadata, SkipReason> {
        let meta = self
            .fs
            .symlink_metadata(path)
            .map_err(|e| SkipReason::from(&e))?;
        if meta.is_symlink {
            return Err(SkipReason::Symlink);
        }
        // FR-006: same st_dev as the root is the main barrier against
        // other volumes and network mounts.
        if meta.dev != root_dev {
            return Err(SkipReason::OtherVolume);
        }
        if self.protect.is_protected_entry(path, &meta) {
            return Err(SkipReason::Protected);
        }
        Ok(meta)
    }
}

/// Outcome of reading one directory on a worker thread.
enum Listing {
    Children(Vec<(PathBuf, Result<Metadata, SkipReason>)>),
    Failed(SkipReason),
    Cancelled,
}

impl Measure {
    fn skip(&mut self, path: &Path, reason: SkipReason) {
        self.skipped.push(Skipped {
            path: path.to_path_buf(),
            reason,
        });
    }

    fn add_blocks(&mut self, blocks: u64) {
        self.allocated_bytes = self
            .allocated_bytes
            .saturating_add(blocks.saturating_mul(BLOCK_SIZE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FakeFs;
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::time::SystemTime;

    const HOME: &str = "/Users/Tester";
    const R: &str = "/Users/Tester/Library/Caches";

    /// Fixed, already canonical home (`FakePlatform` does not canonicalize).
    struct HomeAt;

    impl Platform for HomeAt {
        fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
            Ok(PathBuf::from(HOME))
        }
        fn is_root_user(&self) -> bool {
            false
        }
        fn os(&self) -> Os {
            Os::Macos
        }
    }

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

    /// Real directories have `nlink >= 2`.
    fn dir(ino: u64) -> Metadata {
        entry(true, ino, 2, 0, 0)
    }

    fn file(ino: u64, blocks: u64) -> Metadata {
        entry(false, ino, 1, blocks, blocks * 512)
    }

    fn at(rel: &str) -> PathBuf {
        if rel.is_empty() {
            PathBuf::from(R)
        } else {
            Path::new(R).join(rel)
        }
    }

    /// Ancestors of `R` plus `R` itself, all on dev 1.
    fn base() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", dir(100))
            .insert(HOME, dir(101))
            .insert("/Users/Tester/Library", dir(102))
            .insert(R, dir(103));
        fs
    }

    fn protect(fs: &FakeFs) -> ProtectList {
        match ProtectList::builtin(&HomeAt) {
            Ok(list) => list.with_identities(fs),
            Err(e) => panic!("builtin failed: {e}"),
        }
    }

    fn run(fs: &FakeFs, root: &Path) -> Measure {
        let list = protect(fs);
        Walker::new(fs, &list).measure(root)
    }

    fn skip(rel: &str, reason: SkipReason) -> Skipped {
        Skipped {
            path: at(rel),
            reason,
        }
    }

    fn sums(m: &Measure) -> (u64, u64) {
        (m.allocated_bytes, m.file_count)
    }

    // FR-003: allocated size is st_blocks * 512, never the logical length.
    #[test]
    fn allocated_size_uses_blocks() {
        let mut fs = base();
        fs.insert(at("sparse"), entry(false, 2, 1, 8, 1_000_000))
            .insert(at("sub"), dir(3))
            .insert(at("sub/tiny"), entry(false, 4, 1, 8, 10));
        let m = run(&fs, &at(""));
        assert_eq!(sums(&m), (16 * 512, 2));
        assert!(m.skipped.is_empty());
    }

    // FR-003: an inode with several links counts once, also across roots.
    #[test]
    fn hardlink_counted_once() {
        let mut fs = base();
        fs.insert(at("r"), dir(10))
            .insert(at("r/a"), entry(false, 9, 3, 8, 4096))
            .insert(at("r/b"), entry(false, 9, 3, 8, 4096))
            .insert(at("s"), dir(11))
            .insert(at("s/c"), entry(false, 9, 3, 8, 4096));
        let list = protect(&fs);
        let mut w = Walker::new(&fs, &list);
        assert_eq!(sums(&w.measure(&at("r"))), (8 * 512, 1));
        assert_eq!(sums(&w.measure(&at("s"))), (0, 0));
    }

    // FR-003: the seen set is keyed by (dev, ino): the same ino already seen
    // on another device does not hide this one.
    #[test]
    fn same_ino_on_other_dev_is_distinct() {
        let mut fs = base();
        fs.insert(at("a"), entry(false, 9, 2, 8, 4096))
            .insert(at("b"), entry(false, 9, 2, 8, 4096));
        let list = protect(&fs);
        let mut w = Walker::new(&fs, &list);
        w.seen.insert((2, 9));
        assert_eq!(sums(&w.measure(&at(""))), (8 * 512, 1));
    }

    // FR-005: a symlink is reported as skipped, never followed nor counted.
    #[test]
    fn symlink_is_skipped_not_followed() {
        let mut fs = base();
        fs.insert("/Big", dir(50))
            .insert("/Big/blob", file(51, 2_000_000))
            .insert_symlink(at("l"), "/Big")
            .insert(at("kept"), file(4, 8));
        let m = run(&fs, &at(""));
        assert_eq!(sums(&m), (8 * 512, 1));
        assert_eq!(m.skipped, vec![skip("l", SkipReason::Symlink)]);
    }

    // FR-005: a root that is itself a symlink is reported, not a silent 0.
    #[test]
    fn symlink_root_is_skipped_with_reason() {
        let mut fs = base();
        fs.insert("/Big", dir(50))
            .insert("/Big/blob", file(51, 8))
            .insert_symlink(at("l"), "/Big");
        let m = run(&fs, &at("l"));
        assert_eq!(sums(&m), (0, 0));
        assert_eq!(m.skipped, vec![skip("l", SkipReason::Symlink)]);
    }

    // FR-005: a dangling symlink root is a symlink, not "not found".
    #[test]
    fn dangling_symlink_root_is_skipped_as_symlink() {
        let mut fs = base();
        fs.insert_symlink(at("l"), "/nowhere");
        assert_eq!(
            run(&fs, &at("l")).skipped,
            vec![skip("l", SkipReason::Symlink)]
        );
    }

    // FR-005: a root reached through a symlinked ancestor is not canonical.
    #[test]
    fn root_through_symlinked_ancestor_is_skipped() {
        let mut fs = base();
        fs.insert("/Big", dir(50))
            .insert("/Big/sub", dir(52))
            .insert("/Big/sub/blob", file(51, 8))
            .insert_symlink(at("l"), "/Big");
        let m = run(&fs, &at("l/sub"));
        assert_eq!(sums(&m), (0, 0));
        assert_eq!(m.skipped, vec![skip("l/sub", SkipReason::Symlink)]);
    }

    // FR-006: an entry on another device is skipped and not descended.
    #[test]
    fn other_dev_is_skipped() {
        let mut fs = base();
        let mut mount = dir(5);
        mount.dev = 2;
        let mut inside = file(6, 8);
        inside.dev = 2;
        fs.insert(at("mnt"), mount)
            .insert(at("mnt/inside"), inside)
            .insert(at("kept"), file(4, 8));
        let m = run(&fs, &at(""));
        assert_eq!(sums(&m), (8 * 512, 1));
        assert_eq!(m.skipped, vec![skip("mnt", SkipReason::OtherVolume)]);
    }

    // FR-006: the reference device is the root's own, not its parent's.
    #[test]
    fn root_on_its_own_volume_is_walked_on_that_dev() {
        let mut fs = base();
        let mut d = dir(5);
        d.dev = 7;
        let mut f = file(6, 8);
        f.dev = 7;
        fs.insert(at("vol"), d).insert(at("vol/f"), f);
        assert_eq!(sums(&run(&fs, &at("vol"))), (8 * 512, 1));
    }

    // FR-004, NFR-008: denied entries are skipped with a reason, are not
    // counted nor descended, and the rest of the tree is still counted.
    #[test]
    fn eacces_and_eperm_are_skipped_with_reason() {
        let mut fs = base();
        fs.insert(at("denied"), entry(true, 5, 2, 8, 0))
            .insert(at("denied/x"), file(6, 8))
            .insert(at("eperm"), file(7, 8))
            .insert(at("kept"), file(4, 8))
            .fail_with(at("denied"), io::ErrorKind::PermissionDenied)
            .fail_with(at("eperm"), io::ErrorKind::PermissionDenied);
        let m = run(&fs, &at(""));
        assert_eq!(sums(&m), (8 * 512, 1));
        assert_eq!(
            m.skipped,
            vec![
                skip("denied", SkipReason::PermissionDenied),
                skip("eperm", SkipReason::PermissionDenied),
            ]
        );
    }

    // FR-004, NFR-008: the raw errnos the OS returns map to PermissionDenied.
    #[cfg(unix)]
    #[test]
    fn eacces_and_eperm_errnos_map_to_permission_denied() {
        const EPERM: i32 = 1;
        const EACCES: i32 = 13;
        for errno in [EPERM, EACCES] {
            let reason = SkipReason::from(&io::Error::from_raw_os_error(errno));
            assert_eq!(reason, SkipReason::PermissionDenied, "errno {errno}");
        }
    }

    // FR-004: any other read error is a skip with its kind, never a stop.
    #[test]
    fn other_errors_are_skipped_with_kind() {
        let mut fs = base();
        fs.insert(at("odd"), file(5, 8))
            .insert(at("kept"), file(4, 8))
            .fail_with(at("odd"), io::ErrorKind::InvalidData);
        let m = run(&fs, &at(""));
        assert_eq!(sums(&m), (8 * 512, 1));
        assert_eq!(
            m.skipped,
            vec![skip("odd", SkipReason::Io(io::ErrorKind::InvalidData))]
        );
    }

    // FR-004: a denied root is reported, not an error.
    #[test]
    fn denied_root_is_skipped() {
        let mut fs = base();
        fs.insert(at("f"), file(5, 8))
            .fail_with(R, io::ErrorKind::PermissionDenied);
        let m = run(&fs, &at(""));
        assert_eq!(sums(&m), (0, 0));
        assert_eq!(m.skipped, vec![skip("", SkipReason::PermissionDenied)]);
    }

    // FR-004: a missing root is reported, not an error.
    #[test]
    fn missing_root_is_skipped_not_found() {
        let m = run(&base(), &at("nope"));
        assert_eq!(sums(&m), (0, 0));
        assert_eq!(m.skipped, vec![skip("nope", SkipReason::NotFound)]);
    }

    // FR-007: a protected root is skipped before anything below is read.
    #[test]
    fn protected_root_is_skipped() {
        let mut fs = base();
        fs.insert("/Users/Tester/.ssh", dir(60))
            .insert("/Users/Tester/.ssh/id", file(61, 8));
        let m = run(&fs, Path::new("/Users/Tester/.ssh"));
        assert_eq!(sums(&m), (0, 0));
        assert_eq!(
            m.skipped,
            vec![Skipped {
                path: PathBuf::from("/Users/Tester/.ssh"),
                reason: SkipReason::Protected,
            }]
        );
    }

    // FR-007: a protected child, by name or by identity, is skipped whole.
    #[test]
    fn protected_child_is_skipped_by_name_and_identity() {
        let mut fs = base();
        fs.insert("/Users/Tester/.ssh", dir(60))
            .insert("/Users/Tester/.ssh/id", file(61, 8))
            .insert(at("alias"), dir(60))
            .insert(at("alias/id"), file(61, 8))
            .insert(at("kept"), file(4, 8));
        let m = run(&fs, Path::new(HOME));
        assert_eq!(sums(&m), (8 * 512, 1));
        assert_eq!(
            m.skipped,
            vec![
                Skipped {
                    path: PathBuf::from("/Users/Tester/.ssh"),
                    reason: SkipReason::Protected,
                },
                skip("alias", SkipReason::Protected),
            ]
        );
    }

    // FR-003: a root that is a file measures just that file.
    #[test]
    fn root_that_is_a_file_counts_itself() {
        let mut fs = base();
        fs.insert(at("f"), file(5, 8));
        assert_eq!(sums(&run(&fs, &at("f"))), (8 * 512, 1));
    }

    // FR-003: an empty directory contributes only its own blocks, like du.
    #[test]
    fn empty_dir_counts_only_its_blocks() {
        let mut fs = base();
        fs.insert(at("e"), entry(true, 5, 2, 8, 0));
        let m = run(&fs, &at("e"));
        assert_eq!(sums(&m), (8 * 512, 0));
        assert!(m.skipped.is_empty());
    }

    // FR-003: a file with zero blocks counts as a file with no bytes.
    #[test]
    fn zero_block_file_counts_file_not_bytes() {
        let mut fs = base();
        fs.insert(at("z"), entry(false, 5, 1, 0, 4096));
        assert_eq!(sums(&run(&fs, &at(""))), (0, 1));
    }

    // FR-003: huge block counts saturate instead of wrapping.
    #[test]
    fn block_overflow_saturates() {
        let mut fs = base();
        fs.insert(at("a"), entry(false, 5, 1, u64::MAX, 0))
            .insert(at("b"), entry(false, 6, 1, u64::MAX / 512, 0));
        assert_eq!(sums(&run(&fs, &at(""))), (u64::MAX, 2));
    }

    // FR-003: a hard-linked directory cycle is walked once, not forever.
    #[test]
    fn directory_hardlink_cycle_terminates() {
        let mut fs = base();
        fs.insert(at("a"), entry(true, 5, 3, 8, 0))
            .insert(at("a/f"), file(6, 8))
            .insert(at("a/loop"), entry(true, 5, 3, 8, 0))
            .insert(at("a/loop/f"), file(6, 8));
        assert_eq!(sums(&run(&fs, &at(""))), (16 * 512, 1));
    }

    // FR-003: a directory with nlink = 1 and a repeated ino is still a cycle.
    #[test]
    fn directory_with_nlink_1_and_repeated_ino_is_walked_once() {
        let mut fs = base();
        fs.insert(at("a"), entry(true, 5, 1, 8, 0))
            .insert(at("a/b"), entry(true, 5, 1, 8, 0))
            .insert(at("a/b/f"), file(6, 8));
        assert_eq!(sums(&run(&fs, &at(""))), (8 * 512, 0));
    }

    // FR-003: files with nlink = 1 are not deduplicated even if the ino
    // repeats (a filesystem quirk): with one link there is nothing to share.
    #[test]
    fn files_with_nlink_1_and_repeated_ino_count_each() {
        let mut fs = base();
        fs.insert(at("a"), file(5, 8)).insert(at("b"), file(5, 8));
        assert_eq!(sums(&run(&fs, &at(""))), (16 * 512, 2));
    }

    // FR-003: real directories have nlink >= 2; each still counts once and
    // the same directories measured again in a new root count again
    // (cross-root attribution is the planner's decision).
    #[test]
    fn directories_with_nlink_2_or_more_all_count() {
        let mut fs = base();
        fs.insert(at("a"), entry(true, 5, 3, 8, 0))
            .insert(at("a/b"), entry(true, 6, 2, 8, 0))
            .insert(at("c"), entry(true, 7, 2, 8, 0))
            .insert(at("c/f"), entry(false, 8, 2, 8, 0));
        let list = protect(&fs);
        let mut w = Walker::new(&fs, &list);
        assert_eq!(sums(&w.measure(&at(""))), (32 * 512, 1));
        assert_eq!(sums(&w.measure(&at("a"))), (16 * 512, 0));
    }

    /// Wraps a `FakeFs` and makes every metadata read slow.
    struct SlowFs(FakeFs, std::time::Duration);

    impl Fs for SlowFs {
        fn symlink_metadata(&self, p: &Path) -> io::Result<Metadata> {
            std::thread::sleep(self.1);
            self.0.symlink_metadata(p)
        }
        fn read_dir(&self, p: &Path) -> io::Result<Vec<crate::fs::DirEntryInfo>> {
            self.0.read_dir(p)
        }
        fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
            self.0.canonicalize(p)
        }
    }

    /// Wide and deep tree with hardlinks spread across far-apart
    /// directories (so different threads meet the same inode), plus
    /// symlinks, denied entries, other-volume mounts and dir cycles.
    fn busy_tree() -> FakeFs {
        let mut fs = base();
        let mut ino = 1_000;
        for d in 0..12 {
            fs.insert(at(&format!("d{d}")), dir(ino));
            ino += 1;
            for s in 0..6 {
                let sub = format!("d{d}/s{s}");
                fs.insert(at(&sub), dir(ino));
                ino += 1;
                for f in 0..8 {
                    fs.insert(at(&format!("{sub}/f{f}")), file(ino, (f + 1) * 8));
                    ino += 1;
                }
                // Shared inodes 1..=5, linked from every subdirectory.
                fs.insert(
                    at(&format!("{sub}/h{}", (d + s) % 5)),
                    entry(false, (d + s) % 5 + 1, 72, 16, 8192),
                );
            }
            fs.insert_symlink(at(&format!("d{d}/link")), "/Big");
            fs.insert(at(&format!("d{d}/denied")), dir(ino))
                .fail_with(at(&format!("d{d}/denied")), io::ErrorKind::PermissionDenied);
            ino += 1;
            let mut mnt = dir(ino);
            mnt.dev = 9;
            fs.insert(at(&format!("d{d}/mnt")), mnt);
            ino += 1;
        }
        // Hard-linked directory cycle reachable from two places.
        fs.insert(at("d0/cyc"), entry(true, 900, 3, 8, 0))
            .insert(at("d0/cyc/f"), file(901, 8))
            .insert(at("d0/cyc/odd"), file(902, 8))
            .fail_with(at("d0/cyc/odd"), io::ErrorKind::InvalidData)
            .insert(at("d7/cyc"), entry(true, 900, 3, 8, 0))
            .insert(at("d7/cyc/f"), file(901, 8))
            .insert(at("d7/cyc/odd"), file(902, 8))
            .fail_with(at("d7/cyc/odd"), io::ErrorKind::InvalidData);
        fs
    }

    fn measure_roots(
        fs: &dyn Fs,
        list: &ProtectList,
        threads: usize,
        roots: &[PathBuf],
    ) -> Vec<Measure> {
        let mut w = Walker::new(fs, list).with_threads(threads);
        roots.iter().map(|r| w.measure(r)).collect()
    }

    // FR-010, FR-003: the parallel walker gives the same totals, the same
    // hardlink attribution across roots and the same skipped list as the
    // sequential one, run after run.
    #[test]
    fn same_result_parallel_and_sequential() {
        let fs = busy_tree();
        let list = protect(&fs);
        let roots = [at(""), at("d3"), at("d0/cyc")];
        let seq = measure_roots(&fs, &list, 1, &roots);
        assert!(seq[0].file_count > 0 && !seq[0].skipped.is_empty());
        for threads in [2, 3, 8, 16] {
            for _ in 0..20 {
                assert_eq!(
                    measure_roots(&fs, &list, threads, &roots),
                    seq,
                    "threads {threads}"
                );
            }
        }
    }

    // FR-003: an inode linked from many subtrees walked by different threads
    // is counted exactly once, and in a later root not at all.
    #[test]
    fn hardlinks_across_threads_counted_once() {
        let mut fs = base();
        for d in 0..32 {
            fs.insert(at(&format!("d{d}")), dir(10 + d))
                .insert(at(&format!("d{d}/h")), entry(false, 9, 32, 8, 4096));
        }
        fs.insert(at("later"), dir(99))
            .insert(at("later/h"), entry(false, 9, 33, 8, 4096));
        let list = protect(&fs);
        for _ in 0..20 {
            let mut w = Walker::new(&fs, &list).with_threads(8);
            assert_eq!(sums(&w.measure(&at(""))).1, 1);
            assert_eq!(sums(&w.measure(&at("later"))), (0, 0));
        }
    }

    // FR-011: cancelling a slow walk stops it within 1 s and marks the
    // partial result as cancelled.
    #[test]
    fn cancel_returns_cancelled_within_1s() {
        let mut fake = base();
        for d in 0..40 {
            fake.insert(at(&format!("d{d}")), dir(10_000 + d));
            for f in 0..100 {
                fake.insert(at(&format!("d{d}/f{f}")), file(d * 1_000 + f + 1, 8));
            }
        }
        // 4000 entries * 5 ms is far beyond 1 s even with 8 threads.
        let fs = SlowFs(fake, std::time::Duration::from_millis(5));
        let list = protect(&fs.0);
        let cancel = AtomicBool::new(false);
        let (m, elapsed) = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                cancel.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            let start = std::time::Instant::now();
            let m = Walker::new(&fs, &list)
                .with_threads(8)
                .with_cancel(&cancel)
                .measure(&at(""));
            (m, start.elapsed())
        });
        assert!(m.cancelled);
        assert!(m.file_count < 4_000);
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
    }

    // FR-011: a flag already set stops before reading anything below root.
    #[test]
    fn cancel_before_start_reads_nothing() {
        let mut fs = base();
        fs.insert(at("f"), file(5, 8));
        let list = protect(&fs);
        let cancel = AtomicBool::new(true);
        let m = Walker::new(&fs, &list)
            .with_cancel(&cancel)
            .measure(&at(""));
        assert!(m.cancelled);
        assert_eq!(sums(&m), (0, 0));
    }

    // FR-011: an uncancelled walk is never marked cancelled.
    #[test]
    fn complete_walk_is_not_cancelled() {
        let fs = busy_tree();
        let list = protect(&fs);
        let cancel = AtomicBool::new(false);
        let m = Walker::new(&fs, &list)
            .with_threads(4)
            .with_cancel(&cancel)
            .measure(&at(""));
        assert!(!m.cancelled);
    }

    /// Panics when asked about one path, to test worker panic handling.
    struct PanicFs(FakeFs, PathBuf);

    impl Fs for PanicFs {
        fn symlink_metadata(&self, p: &Path) -> io::Result<Metadata> {
            if p == self.1 {
                panic!("boom");
            }
            self.0.symlink_metadata(p)
        }
        fn read_dir(&self, p: &Path) -> io::Result<Vec<crate::fs::DirEntryInfo>> {
            self.0.read_dir(p)
        }
        fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
            self.0.canonicalize(p)
        }
    }

    // FR-011: a worker panic is a bug and propagates; it is never reported
    // as a cancelled (or complete) partial result.
    #[test]
    fn worker_panic_propagates_not_cancelled() {
        let mut fake = base();
        for d in 0..8 {
            fake.insert(at(&format!("d{d}")), dir(10 + d))
                .insert(at(&format!("d{d}/f")), file(100 + d, 8));
        }
        let fs = PanicFs(fake, at("d5/f"));
        let list = protect(&fs.0);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Walker::new(&fs, &list).with_threads(4).measure(&at(""))
        }));
        match r {
            Err(_) => {}
            Ok(m) => panic!("expected panic, got {m:?}"),
        }
    }

    // FR-011: cancelling inside one huge directory stops within 1 s.
    #[test]
    fn cancel_inside_single_huge_dir_within_1s() {
        let mut fake = base();
        fake.insert(at("big"), dir(50));
        for f in 0..5_000 {
            fake.insert(at(&format!("big/f{f:05}")), file(1_000 + f, 8));
        }
        let fs = SlowFs(fake, std::time::Duration::from_millis(2));
        let list = protect(&fs.0);
        let cancel = AtomicBool::new(false);
        let (m, elapsed) = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                cancel.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            let start = std::time::Instant::now();
            let m = Walker::new(&fs, &list)
                .with_threads(4)
                .with_cancel(&cancel)
                .measure(&at("big"));
            (m, start.elapsed())
        });
        assert!(m.cancelled);
        assert!(elapsed < std::time::Duration::from_secs(1), "{elapsed:?}");
    }

    // FR-010: a level wider than one batch still merges in the same order.
    #[test]
    fn level_wider_than_batch_matches_sequential() {
        let mut fs = base();
        for d in 0..(LEVEL_BATCH as u64 * 2 + 7) {
            fs.insert(at(&format!("d{d:04}")), dir(10_000 + d))
                .insert(at(&format!("d{d:04}/h")), entry(false, 9, 500, 8, 4096))
                .insert_symlink(at(&format!("d{d:04}/l")), "/x");
        }
        let list = protect(&fs);
        let seq = Walker::new(&fs, &list).measure(&at(""));
        for _ in 0..5 {
            assert_eq!(
                Walker::new(&fs, &list).with_threads(8).measure(&at("")),
                seq
            );
        }
        assert_eq!(seq.file_count, 1);
    }
}
