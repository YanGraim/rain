//! #116 on a real filesystem: a folder that is swapped for a symlink between
//! the moment the walker admits it and the moment it lists it is not listed.
//! Everything lives in a tempdir under `CARGO_TARGET_TMPDIR`; nothing outside
//! it is touched. The swap is made at the exact instant of the listing by a
//! wrapper around the real filesystem, so the race is deterministic.

// Building the tree and swapping the folder need create_dir/write/rename and
// symlink, which clippy.toml bans for the read-only scan code. Only the
// tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{DirEntryInfo, Fs, StdFs};
use rain_core::model::SkipReason;
use rain_core::protect::ProtectList;
use rain_core::walk::Walker;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// The tempdir is the home, so nothing in it is protected.
struct HomeAt(PathBuf);

impl Platform for HomeAt {
    fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
        Ok(self.0.clone())
    }
    fn is_root_user(&self) -> bool {
        false
    }
    fn os(&self) -> Os {
        Os::Macos
    }
}

/// The real filesystem, except that just before `target` is listed it is
/// replaced by a symlink to `outside` (the folder is moved aside).
struct SwapOnList {
    target: PathBuf,
    outside: PathBuf,
    armed: AtomicBool,
}

impl SwapOnList {
    fn swap(&self, p: &Path) {
        if p == self.target && self.armed.swap(false, Ordering::SeqCst) {
            fs::rename(&self.target, self.target.with_extension("moved")).unwrap();
            symlink(&self.outside, &self.target).unwrap();
        }
    }
}

impl Fs for SwapOnList {
    fn symlink_metadata(&self, p: &Path) -> io::Result<rain_core::fs::Metadata> {
        StdFs.symlink_metadata(p)
    }
    fn read_dir(&self, p: &Path) -> io::Result<Vec<DirEntryInfo>> {
        self.swap(p);
        StdFs.read_dir(p)
    }
    fn read_dir_verified(&self, p: &Path, expected: (u64, u64)) -> io::Result<Vec<DirEntryInfo>> {
        self.swap(p);
        StdFs.read_dir_verified(p, expected)
    }
    fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
        StdFs.canonicalize(p)
    }
    fn read_to_string(&self, p: &Path, max_bytes: u64) -> io::Result<String> {
        StdFs.read_to_string(p, max_bytes)
    }
}

struct Tree {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    swapped: PathBuf,
    outside: PathBuf,
}

/// `root/swapped` holds 2 files, `root/plain` holds 1, and `outside` (not
/// below the root) holds 5.
fn tree() -> Tree {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let root = base.join("root");
    let swapped = root.join("swapped");
    let outside = base.join("outside");
    for (dir, n) in [(&swapped, 2), (&root.join("plain"), 1), (&outside, 5)] {
        fs::create_dir_all(dir).unwrap();
        for i in 0..n {
            fs::write(dir.join(format!("f{i}")), b"x").unwrap();
        }
    }
    Tree {
        _tmp: tmp,
        root,
        swapped,
        outside,
    }
}

fn walker<'a>(fs: &'a dyn Fs, protect: &'a ProtectList) -> Walker<'a> {
    Walker::new(fs, protect).with_threads(1)
}

fn protect(t: &Tree) -> ProtectList {
    ProtectList::builtin(&HomeAt(t.root.clone()))
        .unwrap()
        .with_identities(&StdFs)
}

// Control: without a swap the walker counts every file below the root.
#[test]
fn without_a_swap_every_file_is_counted() {
    let t = tree();
    let p = protect(&t);
    let m = walker(&StdFs, &p).measure(&t.root);
    assert_eq!(m.file_count, 3);
    assert!(m.skipped.is_empty(), "{:?}", m.skipped);
}

// The folder becomes a symlink to `outside` right before it is listed: its
// files are not listed, `outside` is never read, and the folder is skipped
// with the reason the walker already uses for a symlink.
#[test]
fn a_folder_swapped_for_a_symlink_is_not_listed_while_measuring() {
    let t = tree();
    let p = protect(&t);
    let fs = SwapOnList {
        target: t.swapped.clone(),
        outside: t.outside.clone(),
        armed: AtomicBool::new(true),
    };
    let m = walker(&fs, &p).measure(&t.root);
    // Only `plain/f0` is counted; none of the 5 files of `outside`.
    assert_eq!(m.file_count, 1, "{m:?}");
    assert!(
        m.skipped
            .iter()
            .any(|s| s.path == t.swapped && s.reason == SkipReason::Symlink),
        "{:?}",
        m.skipped
    );
}

// The same during discovery, which also walks and descends folders.
#[test]
fn a_folder_swapped_for_a_symlink_is_not_listed_while_discovering() {
    let t = tree();
    let p = protect(&t);
    let fs = SwapOnList {
        target: t.swapped.clone(),
        outside: t.outside.clone(),
        armed: AtomicBool::new(true),
    };
    let mut seen: Vec<PathBuf> = Vec::new();
    let d = walker(&fs, &p).discover(&t.root, &mut |path, _, _| {
        seen.push(path.to_path_buf());
        rain_core::rule::Visit::Descend
    });
    assert!(
        seen.iter()
            .all(|s| !s.starts_with(&t.outside) && !s.starts_with(t.swapped.join("f0"))),
        "{seen:?}"
    );
    assert!(
        d.skipped
            .iter()
            .any(|s| s.path == t.swapped && s.reason == SkipReason::Symlink),
        "{:?}",
        d.skipped
    );
}
