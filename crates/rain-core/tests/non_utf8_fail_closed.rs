//! #119 on a real filesystem: a name that is not UTF-8 under a rule root is
//! reported as protected and never offered. Everything lives in a tempdir
//! under `CARGO_TARGET_TMPDIR`. Some filesystems (APFS on macOS) refuse to
//! create such names; then the test says so and stops, and the same behaviour
//! is covered by the in-memory tests in the crate.

// Building the fixture needs create_dir/write, which clippy.toml bans for the
// read-only scan code. Only the tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::model::SkipReason;
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

/// The tempdir is the home, so its `Library/Caches` is the rule root.
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

#[test]
fn non_utf8_name_under_a_rule_root_is_reported_as_protected() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    let caches = home.join("Library/Caches");
    fs::create_dir_all(caches.join("ok")).unwrap();
    fs::write(caches.join("free"), b"cache").unwrap();
    fs::write(caches.join("ok/x"), b"cache").unwrap();

    let bad = caches.join(OsStr::from_bytes(b"bad\xff\xfename"));
    if let Err(e) = fs::write(&bad, b"cache") {
        println!("SKIPPED: this filesystem refuses non-UTF-8 names ({e})");
        return;
    }

    let protect = ProtectList::builtin(&HomeAt(home.clone()))
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: home.clone(),
        caches: caches.clone(),
        logs: home.join("Library/Logs"),
    };
    let ctx = ScanContext {
        fs: &StdFs as &dyn Fs,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: 0,
            user_paths: Vec::new(),
            now: SystemTime::now(),
        },
        threads: None,
        tools: &rain_core::tools::NoTools,
    };
    let selected = rules::select(&["sys.user-caches"]).unwrap();
    let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();

    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path == bad && s.reason == SkipReason::Protected),
        "{:?}",
        report.skipped
    );
    assert!(report.items.iter().all(|i| i.path != bad));
    let mut offered: Vec<PathBuf> = report.items.iter().map(|i| i.path.clone()).collect();
    offered.sort();
    assert_eq!(offered, vec![caches.join("free"), caches.join("ok")]);
}
