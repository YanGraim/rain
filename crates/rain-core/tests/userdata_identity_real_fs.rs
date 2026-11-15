//! FR-004 on the real filesystem: user data is also recognised by file
//! identity, not only by name. Every tree lives in a tempdir under
//! `CARGO_TARGET_TMPDIR`; nothing outside it is touched.

// Building the fixtures needs create_dir/write/hard_link/symlink, which
// clippy.toml bans for the read-only scan code. Only the tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::model::{Category, Risk, RuleId, ScanReport, SkipReason};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::{
    EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit,
};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

/// The tempdir is the home, so `~/.codeium` and friends are inside it.
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

/// Offers every child of its roots (or the root itself when it is a file).
struct Children {
    meta: RuleMeta,
    roots: Vec<RootedPath>,
}

impl Rule for Children {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for Children {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        self.roots.clone()
    }
    fn visit(&self, _: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        if depth == 0 {
            Visit::Descend
        } else {
            Visit::Candidate
        }
    }
}

fn children(roots: Vec<RootedPath>) -> Children {
    Children {
        meta: RuleMeta {
            id: RuleId::new("test.children"),
            category: Category::SystemCaches,
            risk: Risk::Low,
            name_key: "rule.test",
            consequence_key: "rule.test.consequence",
            default_selected: true,
            requires_app_closed: None,
            os: &[Os::Macos],
        },
        roots,
    }
}

struct Home {
    _tmp: tempfile::TempDir,
    path: PathBuf,
}

impl Home {
    fn new() -> Home {
        let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let path = fs::canonicalize(tmp.path()).unwrap().join("home");
        fs::create_dir(&path).unwrap();
        Home { _tmp: tmp, path }
    }
    fn dir(&self, rel: &str) -> PathBuf {
        let p = self.path.join(rel);
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("data.txt"), b"user data").unwrap();
        p
    }
    fn file(&self, rel: &str) -> PathBuf {
        let p = self.path.join(rel);
        fs::write(&p, b"user data").unwrap();
        p
    }
    /// Scans `roots` with the built-in lists whose home is this tempdir.
    fn scan(&self, roots: Vec<RootedPath>) -> ScanReport {
        let protect = ProtectList::builtin(&HomeAt(self.path.clone()))
            .unwrap()
            .with_identities(&StdFs);
        let resolved = ResolvedRoots {
            home: self.path.clone(),
            caches: self.path.join("Library/Caches"),
            logs: self.path.join("Library/Logs"),
        };
        let ctx = ScanContext {
            fs: &StdFs as &dyn Fs,
            protect: &protect,
            roots: &resolved,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::now(),
            },
            threads: None,
            tools: &rain_core::tools::NoTools,
        };
        let rule = children(roots);
        scan(&[&rule as &dyn Rule], &ctx, &AtomicBool::new(false)).unwrap()
    }
    fn under_home(&self) -> Vec<RootedPath> {
        vec![RootedPath::Under(Root::Home, "")]
    }
}

/// Nothing may be offered; the reason, when there is one, is a refusal.
fn assert_never_offered(report: &ScanReport, what: &Path) {
    assert!(
        report.items.iter().all(|i| !i.path.starts_with(what)),
        "{what:?} was offered: {:?}",
        report.items
    );
    assert!(
        report.skipped.iter().all(|s| matches!(
            s.reason,
            SkipReason::UserData | SkipReason::Protected | SkipReason::Symlink
        )),
        "{:?}",
        report.skipped
    );
}

// (a) A symlink to `~/.codeium` in the folder being scanned.
#[test]
fn symlink_to_user_data_is_never_offered() {
    let h = Home::new();
    let target = h.dir(".codeium");
    let link = h.path.join("shortcut");
    symlink(&target, &link).unwrap();
    let report = h.scan(h.under_home());
    assert_never_offered(&report, &link);
    assert_never_offered(&report, &target);
}

// (b) A user supplied root that is a symlink to user data.
#[test]
fn user_root_symlinked_to_user_data_is_refused() {
    let h = Home::new();
    h.dir(".codex/sessions");
    let link = h.path.join("shortcut");
    symlink(h.path.join(".codex/sessions"), &link).unwrap();
    let report = h.scan(vec![RootedPath::User(link.clone())]);
    assert!(report.items.is_empty(), "{:?}", report.items);
    assert!(!report.skipped.is_empty());
    assert_never_offered(&report, &link);
}

// (c) A hard link: same device and inode as the user data file, other
// name. Found while walking a folder.
#[test]
fn hard_link_alias_of_user_data_is_never_offered() {
    let h = Home::new();
    let original = h.file(".aider.chat.history.md");
    let alias = h.path.join("notes-copy.md");
    fs::hard_link(&original, &alias).unwrap();
    let report = h.scan(h.under_home());
    assert_never_offered(&report, &alias);
    assert_never_offered(&report, &original);
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path == alias && s.reason == SkipReason::UserData),
        "{:?}",
        report.skipped
    );
}

// (c) The same alias handed in as a user supplied root.
#[test]
fn hard_link_alias_as_user_root_is_refused() {
    let h = Home::new();
    let original = h.file(".aider.chat.history.md");
    let alias = h.path.join("notes-copy.md");
    fs::hard_link(&original, &alias).unwrap();
    let report = h.scan(vec![RootedPath::User(alias.clone())]);
    assert!(report.items.is_empty(), "{:?}", report.items);
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path == alias && s.reason == SkipReason::UserData),
        "{:?}",
        report.skipped
    );
}

// A neighbour that only looks similar stays a normal candidate.
#[test]
fn unrelated_neighbour_is_still_offered() {
    let h = Home::new();
    h.file(".aider.chat.history.md");
    let other = h.file("other.md");
    let report = h.scan(h.under_home());
    assert!(report.items.iter().any(|i| i.path == other));
}

// (c) A folder that holds an alias of user data deeper inside would take it
// to the Trash, so the whole folder is refused, not just the alias.
#[test]
fn folder_holding_an_alias_of_user_data_is_refused() {
    let h = Home::new();
    let original = h.file(".aider.chat.history.md");
    let holder = h.path.join("box");
    fs::create_dir(&holder).unwrap();
    fs::hard_link(&original, holder.join("copy.md")).unwrap();
    let report = h.scan(h.under_home());
    assert!(
        report.items.iter().all(|i| i.path != holder),
        "{:?}",
        report.items
    );
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path == holder && s.reason == SkipReason::UserData),
        "{:?}",
        report.skipped
    );
}

// FR-004 (U2): on a real filesystem the user data that exists is measured
// and informed, even where the built-in protection list also names it
// (`~/.claude/projects`); the protected credentials next to it are not.
#[test]
fn existing_user_data_is_reported_as_unmanaged() {
    let h = Home::new();
    h.dir(".claude/projects/p1");
    h.dir(".codex/sessions");
    h.file(".codex/auth.json");
    h.file(".aider.chat.history.md");
    let report = h.scan(Vec::new());
    let got: Vec<(&str, PathBuf, u64)> = report
        .unmanaged
        .iter()
        .map(|u| (u.id, u.path.clone(), u.file_count))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "aider.chat-history",
                h.path.join(".aider.chat.history.md"),
                1
            ),
            ("claude-code.history", h.path.join(".claude/projects"), 1),
            ("codex.sessions", h.path.join(".codex/sessions"), 1),
        ]
    );
    assert!(report.unmanaged.iter().all(|u| u.allocated_bytes > 0));
    assert!(report.items.is_empty());
    assert_eq!(report.total_bytes, 0);
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
}

fn mentions(report: &ScanReport, under: &Path) -> bool {
    report.items.iter().any(|i| i.path.starts_with(under))
        || report.unmanaged.iter().any(|u| u.path.starts_with(under))
        || report.skipped.iter().any(|s| s.path.starts_with(under))
}

// FR-004 (U2): a hard link to a protected file inside a user data entry is
// refused while measuring and its bytes are not counted.
#[test]
fn protected_hard_link_inside_user_data_is_not_measured() {
    let h = Home::new();
    h.dir(".claude/projects/p1");
    let secret = h.file(".claude/.credentials.json");
    let link = h.path.join(".claude/projects/p1/creds-link");
    fs::hard_link(&secret, &link).unwrap();
    let report = h.scan(Vec::new());
    let entry = report
        .unmanaged
        .iter()
        .find(|u| u.id == "claude-code.history")
        .unwrap();
    assert_eq!(entry.file_count, 1, "{entry:?}");
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path == link && s.reason == SkipReason::Protected),
        "{:?}",
        report.skipped
    );
}

// FR-004 (U2): a symlink inside an entry that points to a protected folder
// is not followed; nothing under the protected folder shows up.
#[test]
fn symlink_to_protected_inside_user_data_is_not_followed() {
    let h = Home::new();
    let ssh = h.dir(".ssh");
    h.dir(".codex/sessions");
    let link = h.path.join(".codex/sessions/shortcut");
    symlink(&ssh, &link).unwrap();
    let report = h.scan(Vec::new());
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path == link && s.reason == SkipReason::Symlink),
        "{:?}",
        report.skipped
    );
    assert!(!mentions(&report, &ssh), "{report:?}");
    let entry = report
        .unmanaged
        .iter()
        .find(|u| u.id == "codex.sessions")
        .unwrap();
    assert_eq!(entry.file_count, 1, "{entry:?}");
}

// FR-004 (U2): an entry that is itself a symlink to a protected folder is
// refused: not reported as unmanaged, and nothing under the target shows up.
#[test]
fn user_data_entry_symlinked_to_protected_is_refused() {
    let h = Home::new();
    let ssh = h.dir(".ssh");
    let entry = h.path.join(".codeium");
    symlink(&ssh, &entry).unwrap();
    let report = h.scan(Vec::new());
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path == entry && s.reason == SkipReason::Symlink),
        "{:?}",
        report.skipped
    );
    assert!(report
        .unmanaged
        .iter()
        .all(|u| u.id != "codeium.conversations"));
    assert!(!mentions(&report, &ssh), "{report:?}");
}

// #159: whatever rule takes a user supplied root, one equal to or inside
// `~/.claude` is refused with the protection reason and nothing is offered;
// a neighbour folder still is.
#[test]
fn user_root_in_claude_home_is_refused_on_a_real_filesystem() {
    let h = Home::new();
    h.dir(".claude/futuro");
    let neighbour = h.dir("projeto");
    for rel in [".claude", ".claude/futuro"] {
        let root = h.path.join(rel);
        let report = h.scan(vec![RootedPath::User(root.clone())]);
        assert!(report.items.is_empty(), "{rel}: {:?}", report.items);
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path == root && s.reason == SkipReason::Protected),
            "{rel}: {:?}",
            report.skipped
        );
    }
    let report = h.scan(vec![RootedPath::User(neighbour.clone())]);
    assert!(report.items.iter().any(|i| i.path.starts_with(&neighbour)));
}
