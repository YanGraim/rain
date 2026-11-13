//! AI2f rules against the real filesystem. The fixture
//! `fixtures/pkg` (a fake home) is copied into a tempdir
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
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pkg");
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

fn found(ids: &[&str]) -> Vec<(String, PathBuf)> {
    scan_fixture(ids).0
}

fn want(list: &[(&str, &str)]) -> Vec<(String, PathBuf)> {
    list.iter()
        .map(|(r, p)| ((*r).to_string(), PathBuf::from(p)))
        .collect()
}

// AI2f: npx install cache; one item per cached package set.
#[test]
fn npx_found_in_fixture() {
    assert_eq!(
        found(&["pkg.npx"]),
        want(&[
            ("pkg.npx", ".npm/_npx/1415fee7"),
            ("pkg.npx", ".npm/_npx/16e1988c"),
        ])
    );
    let m = meta("pkg.npx");
    assert_eq!(m.risk, Risk::Low);
    assert!(m.default_selected);
}

// AI2f: only revisions with a newer one of the same browser; .links,
// single revisions and unparseable names are kept.
#[test]
fn playwright_lists_only_older_revisions() {
    let pw = "Library/Caches/ms-playwright";
    let got = found(&["pkg.playwright"]);
    assert_eq!(
        got,
        want(&[
            ("pkg.playwright", &format!("{pw}/chromium-1140")),
            (
                "pkg.playwright",
                &format!("{pw}/chromium_headless_shell-1140")
            ),
            ("pkg.playwright", &format!("{pw}/webkit-2083")),
        ])
    );
    let m = meta("pkg.playwright");
    assert_eq!(m.risk, Risk::Medium);
    assert!(!m.default_selected);
}

// ADR 0005: the old revisions belong to pkg.playwright, not sys.user-caches.
#[test]
fn playwright_wins_over_user_caches() {
    let got = found(&["pkg.playwright", "sys.user-caches"]);
    let old = PathBuf::from("Library/Caches/ms-playwright/chromium-1140");
    let owners: Vec<_> = got
        .iter()
        .filter(|(_, p)| p == &old)
        .map(|(r, _)| r.as_str())
        .collect();
    assert_eq!(owners, ["pkg.playwright"]);
}
