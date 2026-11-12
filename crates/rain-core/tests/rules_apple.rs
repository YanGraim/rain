//! Xcode rules (D1) against the real filesystem. The fixture
//! `fixtures/apple` (a fake home) is copied into a tempdir
//! under `CARGO_TARGET_TMPDIR`; nothing outside it is touched.

// Copying the fixture needs create_dir/copy, which clippy.toml bans for the
// read-only scan code. Only the tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::model::{Risk, ScanReport};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

const X: &str = "Library/Developer/Xcode";

/// Built-in list with a home that cannot contain the tempdir (the worktree
/// may live under the real, protected `~/Documents`).
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

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// Scans a copy of the fixture home with `ids`; returns (rule, rel path).
fn scan_fixture(ids: &[&str]) -> (Vec<(String, PathBuf)>, ScanReport) {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let home = base.join("home");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/apple");
    copy_tree(&fixture, &home);

    let protect = ProtectList::builtin(&UnrelatedHome)
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: home.clone(),
        caches: home.join("Library/Caches"),
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
    let selected = rules::select(ids).unwrap();
    let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();
    let got = report
        .items
        .iter()
        .map(|i| {
            (
                i.rule.as_str().to_string(),
                i.path.strip_prefix(&home).unwrap().to_path_buf(),
            )
        })
        .collect();
    (got, report)
}

fn meta(id: &str) -> rain_core::rule::RuleMeta {
    rules::select(&[id]).unwrap()[0].meta().clone()
}

fn found(id: &str) -> Vec<PathBuf> {
    scan_fixture(&[id])
        .0
        .into_iter()
        .map(|(r, p)| {
            assert_eq!(r, id);
            p.strip_prefix(X).unwrap().to_path_buf()
        })
        .collect()
}

// FR-001: one item per archive, not per date folder.
#[test]
fn archives_found_in_fixture() {
    assert_eq!(
        found("apple.archives"),
        [
            PathBuf::from("Archives/2026-01-02/App 1.xcarchive"),
            PathBuf::from("Archives/2026-03-04/App 2.xcarchive"),
        ]
    );
}

// FR-014: archives are needed to symbolicate published builds.
#[test]
fn archives_high_not_default() {
    let m = meta("apple.archives");
    assert_eq!(m.risk, Risk::High);
    assert!(!m.default_selected);
}

// FR-001: one item per OS version, iOS and watchOS.
#[test]
fn device_support_lists_each_version() {
    assert_eq!(
        found("apple.device-support"),
        [
            PathBuf::from("iOS DeviceSupport/17.5 (21F79)"),
            PathBuf::from("iOS DeviceSupport/18.0 (22A3354)"),
            PathBuf::from("watchOS DeviceSupport/10.5 (21T576)"),
        ]
    );
    let m = meta("apple.device-support");
    assert_eq!(m.risk, Risk::Medium);
    assert!(!m.default_selected);
}

// FR-001: only Previews; other UserData (key bindings, themes) is untouched.
#[test]
fn previews_found_in_fixture() {
    assert_eq!(
        found("apple.previews"),
        [PathBuf::from("UserData/Previews/Simulator Devices")]
    );
    let m = meta("apple.previews");
    assert_eq!(m.risk, Risk::Low);
    assert!(m.default_selected);
}

// FR-015: every Xcode rule requires Xcode closed.
#[test]
fn apple_rules_require_xcode_closed() {
    for id in ["apple.archives", "apple.device-support", "apple.previews"] {
        assert_eq!(
            meta(id).requires_app_closed,
            Some("com.apple.dt.Xcode"),
            "{id}"
        );
    }
}
