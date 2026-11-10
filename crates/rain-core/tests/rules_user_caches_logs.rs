//! `sys.user-caches` and `sys.logs` against the real filesystem.
//! The checked-in fixture `fixtures/user-library` is copied into a tempdir
//! under `CARGO_TARGET_TMPDIR`; nothing outside that tempdir is touched.

// Copying the fixture needs create_dir/copy, which clippy.toml bans for the
// read-only scan code. Only the tempdir is written; the scan under test still
// goes through the read-only `Fs`.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

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

// FR-002, FR-003, acceptance criterion 1: the direct children of Caches and
// Logs are the items, with their whole subtree counted.
#[test]
fn fixture_children_are_items() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let library = base.join("Library");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/user-library");
    copy_tree(&fixture, &library);

    let protect = ProtectList::builtin(&UnrelatedHome)
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: base.clone(),
        caches: library.join("Caches"),
        logs: library.join("Logs"),
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
        tools: &rain_core::tools::NoTools,
        threads: None,
    };
    let selected = rules::select(&["sys.user-caches", "sys.logs"]).unwrap();
    let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();

    let got: Vec<(&str, PathBuf, u64)> = report
        .items
        .iter()
        .map(|i| {
            (
                i.rule.as_str(),
                i.path.strip_prefix(&library).unwrap().to_path_buf(),
                i.file_count,
            )
        })
        .collect();
    let want: Vec<(&str, PathBuf, u64)> = [
        ("sys.logs", "Logs/DiagnosticReports", 1),
        ("sys.logs", "Logs/app.log", 1),
        ("sys.user-caches", "Caches/a.db", 1),
        ("sys.user-caches", "Caches/b.bin", 1),
        ("sys.user-caches", "Caches/c.tmp", 1),
        ("sys.user-caches", "Caches/com.example.app", 2),
    ]
    .into_iter()
    .map(|(r, p, n)| (r, PathBuf::from(p), n))
    .collect();
    assert_eq!(got, want);
    assert!(report.items.iter().all(|i| i.allocated_bytes > 0));
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    let sum: u64 = report.items.iter().map(|i| i.allocated_bytes).sum();
    assert_eq!(report.total_bytes, sum);
}
