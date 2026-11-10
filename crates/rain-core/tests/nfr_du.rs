//! Compares the walker's total against `du -k` on a tempdir fixture under
//! `CARGO_TARGET_TMPDIR`. Nothing outside that tempdir is touched.

// Building the fixture needs create_dir/write, which clippy.toml bans for the
// read-only scan code. Spawning `du` lives only in this test.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::StdFs;
use rain_core::protect::ProtectList;
use rain_core::walk::Walker;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Home that cannot contain the tempdir (the worktree may be under a
/// protected `~/Documents`).
struct UnrelatedHome;

impl Platform for UnrelatedHome {
    fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from("/nonexistent-rain-test-home"))
    }
    fn is_root_user(&self) -> bool {
        false
    }
    fn os(&self) -> Os {
        Os::Macos
    }
}

fn build_fixture(root: &Path) {
    let sizes = [0usize, 1, 511, 4096, 4097, 65_536, 1_000_003];
    for d in 0..8 {
        let dir = root.join(format!("d{d}")).join("nested").join("deeper");
        fs::create_dir_all(&dir).unwrap();
        for (i, size) in sizes.iter().enumerate() {
            fs::write(dir.join(format!("f{i}")), vec![7u8; *size]).unwrap();
        }
        for i in 0..50 {
            fs::write(root.join(format!("d{d}")).join(format!("s{i}")), b"x").unwrap();
        }
    }
    fs::write(root.join("big"), vec![1u8; 8 * 1024 * 1024]).unwrap();
}

fn du_bytes(root: &Path) -> u64 {
    let out = Command::new("du").arg("-sk").arg(root).output().unwrap();
    assert!(out.status.success(), "du failed: {out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    let kib: u64 = text.split_whitespace().next().unwrap().parse().unwrap();
    kib * 1024
}

// NFR-004
#[test]
fn matches_du_within_5_percent() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = fs::canonicalize(tmp.path()).unwrap().join("root");
    fs::create_dir(&root).unwrap();
    build_fixture(&root);

    let list = ProtectList::builtin(&UnrelatedHome)
        .unwrap()
        .with_identities(&StdFs);
    let ours = Walker::new(&StdFs, &list).measure(&root).allocated_bytes;
    let reference = du_bytes(&root);

    assert!(reference > 0);
    let diff = ours.abs_diff(reference) as f64 / reference as f64;
    assert!(
        diff <= 0.05,
        "walker {ours} B vs du {reference} B: {:.2}% apart",
        diff * 100.0
    );
}
