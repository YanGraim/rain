//! A3/A4 AI tool rules against the real filesystem. The fixtures
//! `fixtures/ai/{cursor,tools}` (fake homes) is copied into a tempdir
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
fn scan_fixture(name: &str, ids: &[&str]) -> (Vec<(String, PathBuf)>, ScanReport) {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let home = base.join("home");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ai")
        .join(name);
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

fn rel(p: &str) -> PathBuf {
    PathBuf::from(p)
}

fn only(rule: &str) -> Vec<(String, PathBuf)> {
    scan_fixture("tools", &[rule]).0
}

fn meta(id: &str) -> rain_core::rule::RuleMeta {
    rules::select(&[id]).unwrap()[0].meta().clone()
}

// FR-014: chat history of the agent lives here; high and never preselected.
#[test]
fn workspace_storage_is_high_and_not_default() {
    let m = meta("ai.cursor.workspace-storage");
    assert_eq!(m.risk, Risk::High);
    assert!(!m.default_selected);
    assert_eq!(m.requires_app_closed, Some("com.todesktop.230313mzl4w4u92"));
    let (got, _) = scan_fixture("cursor", &["ai.cursor.workspace-storage"]);
    let want = Path::new(AS).join("Cursor/User/workspaceStorage/ws1");
    assert_eq!(got, [("ai.cursor.workspace-storage".to_string(), want)]);
}

// FR-001: Codex logs only.
#[test]
fn codex_cache_found_in_fixture() {
    let got = only("ai.codex.cache");
    assert_eq!(
        got,
        [(
            "ai.codex.cache".to_string(),
            rel(".codex/log/codex-tui.log")
        )]
    );
}

// FR-004: sessions and auth are user data, never candidates.
#[test]
fn codex_sessions_never_candidate() {
    let (got, _) = scan_fixture(
        "tools",
        &[
            "ai.codex.cache",
            "ai.gemini.cache",
            "ai.continue.cache",
            "ai.aider.cache",
            "ai.copilot.cache",
        ],
    );
    for (_, p) in &got {
        assert!(!p.starts_with(".codex/sessions"), "{p:?}");
        assert_ne!(p, Path::new(".codex/auth.json"));
        assert!(!p.ends_with(".aider.chat.history.md"), "{p:?}");
    }
}

// FR-001: Gemini tmp may hold checkpoints: medium, not preselected.
#[test]
fn gemini_cache_found_in_fixture() {
    assert_eq!(
        only("ai.gemini.cache"),
        [("ai.gemini.cache".to_string(), rel(".gemini/tmp/abc"))]
    );
    let m = meta("ai.gemini.cache");
    assert_eq!(m.risk, Risk::Medium);
    assert!(!m.default_selected);
}

// FR-001: Continue index rebuilds itself.
#[test]
fn continue_cache_found_in_fixture() {
    assert_eq!(
        only("ai.continue.cache"),
        [(
            "ai.continue.cache".to_string(),
            rel(".continue/index/lancedb")
        )]
    );
    let m = meta("ai.continue.cache");
    assert_eq!(m.risk, Risk::Low);
    assert!(m.default_selected);
}

// FR-001: only the global Aider cache; chat history in projects is untouched.
#[test]
fn aider_cache_found_in_fixture() {
    assert_eq!(
        only("ai.aider.cache"),
        [("ai.aider.cache".to_string(), rel(".aider/caches/c1"))]
    );
}

// FR-001: Copilot cache dirs only; top-level files hold OAuth tokens.
#[test]
fn copilot_cache_found_in_fixture() {
    assert_eq!(
        only("ai.copilot.cache"),
        [(
            "ai.copilot.cache".to_string(),
            rel(".config/github-copilot/cache")
        )]
    );
    let m = meta("ai.copilot.cache");
    assert_eq!(m.risk, Risk::Medium);
    assert!(!m.default_selected);
}

// FR-001, FR-004: only the backup copies; the live `state.vscdb` (chat
// history), its WAL and folders are never listed.
#[test]
fn cursor_state_backups_found_in_fixture() {
    let (got, _) = scan_fixture("cursor", &["ai.cursor.state-backups"]);
    let g = Path::new(AS).join("Cursor/User/globalStorage");
    let id = "ai.cursor.state-backups".to_string();
    assert_eq!(
        got,
        [
            (id.clone(), g.join("state.vscdb.backup")),
            (id, g.join("state.vscdb.bak-20260101")),
        ]
    );
    let m = meta("ai.cursor.state-backups");
    assert_eq!(m.risk, Risk::Medium);
    assert!(!m.default_selected);
    assert_eq!(m.requires_app_closed, Some("com.todesktop.230313mzl4w4u92"));
}

// FR-001, FR-015: Claude desktop Chromium caches only.
#[test]
fn claude_desktop_cache_found_in_fixture() {
    let c = Path::new(AS).join("Claude");
    let id = "ai.claude-desktop.cache".to_string();
    assert_eq!(
        only("ai.claude-desktop.cache"),
        [
            (id.clone(), c.join("Cache/c")),
            (id.clone(), c.join("Code Cache/js")),
            (id, c.join("GPUCache/c")),
        ]
    );
    let m = meta("ai.claude-desktop.cache");
    assert_eq!(m.risk, Risk::Low);
    assert!(m.default_selected);
    assert_eq!(
        m.requires_app_closed,
        Some("com.anthropic.claudefordesktop")
    );
}
