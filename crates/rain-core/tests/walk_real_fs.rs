//! Walker against the real filesystem, confined to a tempdir under
//! `CARGO_TARGET_TMPDIR`. Nothing outside that tempdir is touched.

// Building fixtures needs create_dir/write/symlink/set_permissions, which
// clippy.toml bans for the read-only scan code. This test only writes inside
// its own tempdir; the scan under test still goes through the read-only `Fs`.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::protect::ProtectList;
use rain_core::walk::{SkipReason, Skipped, Walker};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

/// Built-in list with a home that cannot contain the tempdir. The worktree
/// may live under the real `~/Documents`, which is protected and would hide
/// the whole fixture; every system entry of the built-in list still applies.
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

/// Restores the permission even if an assertion fails, so the tempdir can
/// be removed.
struct Restore(PathBuf);

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

// FR-004, FR-005, NFR-008
#[test]
fn real_fs_skips_symlink_and_denied_dir_and_counts_file() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let root = base.join("root");
    let outside = base.join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("big"), vec![1u8; 256 * 1024]).unwrap();
    fs::write(root.join("kept"), vec![1u8; 8192]).unwrap();
    symlink(&outside, root.join("link")).unwrap();
    let denied = root.join("denied");
    fs::create_dir(&denied).unwrap();
    fs::write(denied.join("hidden"), vec![1u8; 8192]).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = Restore(denied.clone());

    if fs::read_dir(&denied).is_ok() {
        eprintln!("skipped: running with privileges that bypass mode 000 (root?)");
        return;
    }

    let list = ProtectList::builtin(&UnrelatedHome)
        .unwrap()
        .with_identities(&StdFs);
    let m = Walker::new(&StdFs, &list).measure(&root);

    let kept_blocks = StdFs.symlink_metadata(&root.join("kept")).unwrap().blocks;
    let root_blocks = StdFs.symlink_metadata(&root).unwrap().blocks;
    assert_eq!(m.file_count, 1, "only `kept` is a counted file");
    assert_eq!(m.allocated_bytes, (kept_blocks + root_blocks) * 512);
    assert_eq!(
        m.skipped,
        vec![
            Skipped {
                path: denied,
                reason: SkipReason::PermissionDenied,
            },
            Skipped {
                path: root.join("link"),
                reason: SkipReason::Symlink,
            },
        ]
    );
}
