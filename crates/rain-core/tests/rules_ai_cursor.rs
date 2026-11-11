//! `ai.cursor.cache` and `ai.windsurf.cache` against the real filesystem.
//! The fixture `fixtures/ai/cursor` (a fake home) is copied into a tempdir
//! under `CARGO_TARGET_TMPDIR`; nothing outside it is touched.

// Copying the fixture needs create_dir/copy, which clippy.toml bans for the
// read-only scan code. Only the tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::model::ScanReport;
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

const AS: &str = "Library/Application Support";

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
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ai/cursor");
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

// FR-001: only the named cache dirs; each child is one item.
#[test]
fn cursor_cache_lists_only_named_dirs() {
    let (got, report) = scan_fixture(&["ai.cursor.cache", "ai.windsurf.cache"]);
    let (c, w) = ("ai.cursor.cache", "ai.windsurf.cache");
    let want: Vec<(String, PathBuf)> = [
        (c, "Cursor/Cache/f"),
        (c, "Cursor/CachedData/f"),
        (c, "Cursor/GPUCache/f"),
        (c, "Cursor/logs/f"),
        (w, "Windsurf/Cache/f"),
        (w, "Windsurf/CachedData/f"),
        (w, "Windsurf/logs/f"),
    ]
    .iter()
    .map(|(r, p)| ((*r).to_string(), Path::new(AS).join(p)))
    .collect();
    assert_eq!(got, want);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

// FR-001, FR-004: `User` (settings, workspace state, chat) is never listed.
#[test]
fn cursor_user_dir_not_listed() {
    let (got, _) = scan_fixture(&["ai.cursor.cache", "ai.windsurf.cache"]);
    for app in ["Cursor", "Windsurf"] {
        let user = Path::new(AS).join(app).join("User");
        assert!(
            got.iter().all(|(_, p)| !p.starts_with(&user)),
            "{app}/User listed: {got:?}"
        );
    }
}

// FR-015, acceptance criterion 4: both rules require the app closed.
#[test]
fn cursor_requires_app_closed() {
    let selected = rules::select(&["ai.cursor.cache", "ai.windsurf.cache"]).unwrap();
    let apps: Vec<_> = selected
        .iter()
        .map(|r| r.meta().requires_app_closed)
        .collect();
    assert_eq!(
        apps,
        [
            Some("com.todesktop.230313mzl4w4u92"),
            Some("com.exafunction.windsurf"),
        ]
    );
}
