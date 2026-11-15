//! Guard: no rule may be rooted at `~/.claude` or above it, so folders Claude
//! Code adds there later are never exposed. Only named subfolders are fine.
//! The two project rules walk the whole home looking for named artifact
//! folders; they are the explicit exception and must prune `~/.claude`.

use super::{builtin, Rule};
use crate::fs::{FakeFs, Metadata};
use crate::model::{Category, Risk, RuleId, SkipReason};
use crate::planner::{scan, ResolvedRoots, ScanContext};
use crate::protect::{normalize, ProtectList};
use crate::rule::{EntryInfo, FileRule, RootedPath, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

const HOME: &str = "/Users/Tester";

/// Rules that walk the home for named artifact folders (`node_modules`,
/// `target`). They only offer those folders, and they must prune
/// `~/.claude` (hidden folders are never entered).
const HOME_WALKERS: &[&str] = &["proj.node-modules", "proj.rust-target"];

struct HomeAt;

impl Platform for HomeAt {
    fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from(HOME))
    }
    fn is_root_user(&self) -> bool {
        false
    }
    fn os(&self) -> Os {
        Os::Macos
    }
}

fn base(root: Root) -> PathBuf {
    let home = Path::new(HOME);
    match root {
        Root::Home => home.to_path_buf(),
        Root::Caches => home.join("Library/Caches"),
        Root::Logs => home.join("Library/Logs"),
    }
}

fn dir_meta() -> Metadata {
    Metadata {
        is_dir: true,
        is_symlink: false,
        dev: 1,
        ino: 1,
        nlink: 2,
        blocks: 0,
        len: 0,
        mtime: SystemTime::UNIX_EPOCH,
    }
}

fn ctx() -> RuleContext {
    RuleContext {
        min_age_days: 0,
        user_paths: Vec::new(),
        now: SystemTime::UNIX_EPOCH,
    }
}

/// Declared roots of a rule, whatever its family.
fn roots_of(rule: &dyn Rule) -> Vec<RootedPath> {
    match rule.kind() {
        RuleKind::Files(f) => f.roots(&ctx()),
        RuleKind::Provider(p) => p.roots(),
    }
}

/// What `visit` answers for `path` as a direct child of the home.
fn visit_home_child(rule: &dyn Rule, name: &str) -> Option<Visit> {
    let RuleKind::Files(f) = rule.kind() else {
        return None;
    };
    let protect = ProtectList::builtin(&HomeAt).ok()?;
    let path = Path::new(HOME).join(name);
    let meta = dir_meta();
    let cancel = AtomicBool::new(false);
    let entry = EntryInfo {
        path: &path,
        meta: &meta,
        protect: &protect,
        cancel: &cancel,
    };
    Some(f.visit(&entry, 1, &ctx(), &FakeFs::new()))
}

/// Components compared as the protection list does, so case and Unicode
/// spellings count; a path is `~/.claude` or above when the folder lies
/// below it.
fn covers_claude(effective: &Path) -> bool {
    let claude = Path::new(HOME).join(".claude");
    claude.starts_with(effective) || normalize(&claude).starts_with(normalize(effective))
}

/// Every way a rule breaks the guard, as readable lines.
fn violations(rules: &[&dyn Rule], home_walkers: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for rule in rules {
        let id = rule.meta().id.as_str();
        let allowed = home_walkers.contains(&id);
        let roots = roots_of(*rule);
        for root in &roots {
            let RootedPath::Under(base_root, rel) = root else {
                continue;
            };
            let effective = base(*base_root).join(rel);
            if !covers_claude(&effective) {
                continue;
            }
            let is_home = effective == base(Root::Home);
            if !(allowed && is_home) {
                out.push(format!("{id}: root {effective:?} is ~/.claude or above"));
            }
        }
        if allowed {
            // The exception holds only while the rule prunes ~/.claude and
            // still looks at ordinary folders.
            for spelling in [".claude", ".CLAUDE", ".Claude"] {
                if visit_home_child(*rule, spelling) != Some(Visit::Skip) {
                    out.push(format!("{id}: does not prune ~/{spelling}"));
                }
            }
            if visit_home_child(*rule, "projects-dir") != Some(Visit::Descend) {
                out.push(format!("{id}: no longer walks ordinary folders"));
            }
        }
    }
    out
}

/// A rule with chosen roots and an optional pruning of hidden folders.
struct Synthetic {
    meta: RuleMeta,
    roots: Vec<RootedPath>,
    prunes_hidden: bool,
}

impl Rule for Synthetic {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for Synthetic {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        self.roots.clone()
    }
    fn visit(
        &self,
        entry: &EntryInfo,
        depth: usize,
        _: &RuleContext,
        _: &dyn crate::fs::Fs,
    ) -> Visit {
        let hidden = entry
            .path
            .file_name()
            .is_some_and(|n| n.as_encoded_bytes().starts_with(b"."));
        if depth > 0 && self.prunes_hidden && hidden {
            Visit::Skip
        } else {
            Visit::Descend
        }
    }
}

fn synthetic(id: &'static str, roots: Vec<RootedPath>, prunes_hidden: bool) -> Synthetic {
    Synthetic {
        meta: RuleMeta {
            id: RuleId::new(id),
            category: Category::SystemCaches,
            risk: Risk::Low,
            name_key: "rule.test",
            consequence_key: "rule.test.consequence",
            default_selected: false,
            requires_app_closed: None,
            os: &[Os::Macos],
        },
        roots,
        prunes_hidden,
    }
}

fn under(root: Root, rel: &'static str) -> Vec<RootedPath> {
    vec![RootedPath::Under(root, rel)]
}

// FR-004, #118: nothing in the registry is rooted at ~/.claude or above,
// except the two home walkers, which only look for named folders.
#[test]
fn no_builtin_rule_is_rooted_at_claude_or_above() {
    assert_eq!(violations(builtin(), HOME_WALKERS), Vec::<String>::new());
}

// The exception list is exactly what needs it: each id exists and is rooted
// at the home (so it is not a stale entry), and no other rule is.
#[test]
fn home_walkers_are_exactly_the_rules_rooted_at_the_home() {
    let rooted_at_home: Vec<&str> = builtin()
        .iter()
        .filter(|r| {
            roots_of(**r)
                .iter()
                .any(|root| *root == RootedPath::Under(Root::Home, ""))
        })
        .map(|r| r.meta().id.as_str())
        .collect();
    let mut want = HOME_WALKERS.to_vec();
    want.sort_unstable();
    let mut got = rooted_at_home;
    got.sort_unstable();
    assert_eq!(got, want);
}

// Red proof: a rule rooted at ~/.claude itself is flagged, also through
// another spelling, and so is one rooted at the home or above it.
#[test]
fn guard_flags_roots_at_or_above_claude() {
    for rel in [".claude", ".CLAUDE", ".claude/", ""] {
        let rule = synthetic("x.bad", under(Root::Home, rel), true);
        let found = violations(&[&rule as &dyn Rule], HOME_WALKERS);
        assert_eq!(found.len(), 1, "{rel:?}: {found:?}");
    }
}

// An ancestor of the home in the declared roots is not expressible (roots
// are below Home/Caches/Logs), but the Logs and Caches bases are checked
// with the same rule.
#[test]
fn guard_ignores_caches_and_logs_roots() {
    let a = synthetic("x.caches", under(Root::Caches, ""), false);
    let b = synthetic("x.logs", under(Root::Logs, "claude"), false);
    assert!(violations(&[&a as &dyn Rule, &b], HOME_WALKERS).is_empty());
}

// Named subfolders and look-alike neighbours are fine.
#[test]
fn guard_accepts_named_subfolders_and_neighbours() {
    for rel in [
        ".claude/cache",
        ".claude/shell-snapshots",
        ".claudex",
        ".cache/claude",
        ".config/claude",
        "claude",
    ] {
        let rule = synthetic("x.ok", under(Root::Home, rel), false);
        assert!(
            violations(&[&rule as &dyn Rule], HOME_WALKERS).is_empty(),
            "{rel}"
        );
    }
}

// Red proof: a home wide rule that is not an allowed home walker fails,
// and so does one that is allowed but does not prune ~/.claude.
#[test]
fn guard_flags_home_rule_outside_the_exception_or_without_pruning() {
    let outsider = synthetic("x.walker", under(Root::Home, ""), true);
    let found = violations(&[&outsider as &dyn Rule], HOME_WALKERS);
    assert_eq!(found.len(), 1, "{found:?}");

    let lazy = synthetic("proj.node-modules", under(Root::Home, ""), false);
    let found = violations(&[&lazy as &dyn Rule], HOME_WALKERS);
    assert!(
        found.iter().any(|l| l.contains("does not prune")),
        "{found:?}"
    );

    let fine = synthetic("proj.node-modules", under(Root::Home, ""), true);
    // A synthetic that prunes hidden folders but visits others the same way.
    assert!(violations(&[&fine as &dyn Rule], HOME_WALKERS).is_empty());
}

// Roots with several entries are all checked (ChildrenOf-like rules).
#[test]
fn guard_checks_every_root_of_a_rule() {
    let rule = synthetic(
        "x.many",
        vec![
            RootedPath::Under(Root::Home, ".claude/cache"),
            RootedPath::Under(Root::Home, ".claude"),
        ],
        true,
    );
    assert_eq!(violations(&[&rule as &dyn Rule], HOME_WALKERS).len(), 1);
}

// --- behaviour of the two home walkers on a fixture -------------------

const DAY: u64 = 86_400;

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000 * DAY)
}

fn entry(is_dir: bool, ino: u64, days: u64) -> Metadata {
    Metadata {
        is_dir,
        is_symlink: false,
        dev: 1,
        ino,
        nlink: if is_dir { 2 } else { 1 },
        blocks: if is_dir { 0 } else { 8 },
        len: if is_dir { 0 } else { 4096 },
        mtime: now() - Duration::from_secs(days * DAY),
    }
}

/// Home with inactive projects (90 days) inside and outside `~/.claude`.
fn walkers_fixture() -> FakeFs {
    let mut fs = FakeFs::new();
    let mut ino = 10;
    let mut add = |fs: &mut FakeFs, rel: &str, is_dir: bool| {
        ino += 1;
        fs.insert(Path::new(HOME).join(rel), entry(is_dir, ino, 90));
    };
    fs.insert("/Users", entry(true, 1, 900))
        .insert(HOME, entry(true, 2, 900));
    for rel in [
        ".claude",
        ".claude/futuro",
        ".claude/futuro/node_modules",
        ".claude/x",
        ".claude/x/target",
        "projeto",
        "projeto/node_modules",
        "rustproj",
        "rustproj/target",
    ] {
        add(&mut fs, rel, true);
    }
    for rel in [
        ".claude/futuro/package.json",
        ".claude/futuro/node_modules/a.js",
        ".claude/x/Cargo.toml",
        ".claude/x/target/b",
        "projeto/package.json",
        "projeto/node_modules/c.js",
        "rustproj/Cargo.toml",
        "rustproj/target/d",
    ] {
        add(&mut fs, rel, false);
    }
    fs
}

fn scan_walkers(fs: &FakeFs) -> Vec<PathBuf> {
    let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
    let roots = ResolvedRoots {
        home: PathBuf::from(HOME),
        caches: base(Root::Caches),
        logs: base(Root::Logs),
    };
    let ctx = ScanContext {
        fs,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: 30,
            user_paths: Vec::new(),
            now: now(),
        },
        tools: &crate::tools::NoTools,
        threads: Some(2),
    };
    let rules = super::select(HOME_WALKERS).unwrap();
    let report = scan(&rules, &ctx, &AtomicBool::new(false)).unwrap();
    // Nothing under ~/.claude is read, so it is not even a skip.
    assert!(
        report
            .skipped
            .iter()
            .all(|s| s.reason != SkipReason::UserData
                && !s.path.starts_with(Path::new(HOME).join(".claude"))),
        "{:?}",
        report.skipped
    );
    report.items.iter().map(|i| i.path.clone()).collect()
}

// #118: artifact folders of projects below ~/.claude are never offered, a
// project next to it still is.
#[test]
fn home_walkers_do_not_enter_claude() {
    let got = scan_walkers(&walkers_fixture());
    let home = Path::new(HOME);
    assert_eq!(
        got,
        vec![
            home.join("projeto/node_modules"),
            home.join("rustproj/target")
        ]
    );
}
