//! `ai.claude-code.cache` and `ai.claude-code.logs` against the real
//! filesystem. The fixture `fixtures/ai/claude` (a fake home) is copied into
//! a tempdir under `CARGO_TARGET_TMPDIR`; nothing outside it is touched.

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
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ai/claude");
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

fn want(rows: &[(&str, &str)]) -> Vec<(String, PathBuf)> {
    rows.iter()
        .map(|(r, p)| ((*r).to_string(), PathBuf::from(p)))
        .collect()
}

// FR-001, FR-004: snapshots, caches, paste cache, telemetry, ~/.cache/claude
// and the CLI's Library cache; each child is one item.
#[test]
fn claude_cache_lists_snapshots_and_cache_dirs() {
    let (got, report) = scan_fixture(&["ai.claude-code.cache", "ai.claude-code.logs"]);
    let c = "ai.claude-code.cache";
    assert_eq!(
        got,
        want(&[
            (c, ".cache/claude/x"),
            (c, ".claude/cache/changelog.md"),
            (c, ".claude/paste-cache/p1.txt"),
            (c, ".claude/shell-snapshots/snap-1.sh"),
            (c, ".claude/shell-snapshots/snap-2.sh"),
            (c, ".claude/telemetry/t.json"),
            (c, "Library/Caches/claude-cli-nodejs/v1"),
            ("ai.claude-code.logs", ".claude/debug/d1.txt"),
        ])
    );
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

// Acceptance criterion 12: the CLI cache content goes to the Claude rule.
// As with Homebrew (ADR 0005), `sys.user-caches` keeps at most the emptied
// folder itself, with no file of the Claude cache in it.
#[test]
fn claude_cli_nodejs_not_in_user_caches() {
    let (_, report) = scan_fixture(&["ai.claude-code.cache", "sys.user-caches"]);
    let cli = Path::new("Library/Caches/claude-cli-nodejs");
    let mut claude_files = 0;
    let mut other_seen = false;
    for item in &report.items {
        match item.rule.as_str() {
            "ai.claude-code.cache" if item.path.ends_with("claude-cli-nodejs/v1") => {
                claude_files += item.file_count;
            }
            "sys.user-caches" if item.path.ends_with(cli) => {
                assert_eq!(item.file_count, 0, "{:?} keeps Claude files", item.path);
            }
            "sys.user-caches" => other_seen |= item.path.ends_with("com.other"),
            _ => {}
        }
    }
    assert_eq!(claude_files, 1);
    assert!(other_seen, "{:?}", report.items);
}

// FR-004, acceptance criterion 5: sessions and history are never items.
#[test]
fn claude_projects_never_candidate() {
    let (got, _) = scan_fixture(&["ai.claude-code.cache", "ai.claude-code.logs"]);
    for user_data in [
        "projects",
        "history.jsonl",
        "file-history",
        "sessions",
        "plans",
        "backups",
        ".credentials.json",
        "settings.json",
        "settings.local.json",
        "todos",
    ] {
        let p = Path::new(".claude").join(user_data);
        assert!(
            got.iter().all(|(_, item)| !item.starts_with(&p)),
            "{user_data} listed: {got:?}"
        );
    }
    assert!(
        got.iter()
            .all(|(_, item)| !item.starts_with(".claude.json")),
        ".claude.json listed: {got:?}"
    );
}
