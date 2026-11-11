// FR-007, NFR-005: edge cases for refusing an item whose measurement
// skipped a protected entry (H1c). In-memory FakeFs only: no real disk.
#![cfg(unix)]

use rain_core::fs::{FakeFs, Fs, Metadata};
use rain_core::model::{Category, Risk, RuleId, ScanReport, SkipReason, Skipped};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::{
    EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit,
};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

const HOME: &str = "/Users/Tester";
const CACHES: &str = "/Users/Tester/Library/Caches";

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

struct Children(RuleMeta, &'static str);
impl Rule for Children {
    fn meta(&self) -> &RuleMeta {
        &self.0
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}
impl FileRule for Children {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        vec![RootedPath::Under(Root::Caches, self.1)]
    }
    fn visit(&self, _: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        if depth == 0 {
            Visit::Descend
        } else {
            Visit::Candidate
        }
    }
}

fn rule(id: &'static str, rel: &'static str) -> Children {
    Children(
        RuleMeta {
            id: RuleId::new(id),
            category: Category::SystemCaches,
            risk: Risk::Low,
            name_key: "rule.test",
            consequence_key: "rule.test.consequence",
            default_selected: true,
            requires_app_closed: None,
            os: &[Os::Macos],
        },
        rel,
    )
}

fn meta(is_dir: bool, ino: u64, nlink: u64, blocks: u64) -> Metadata {
    Metadata {
        is_dir,
        is_symlink: false,
        dev: 1,
        ino,
        nlink,
        blocks,
        len: blocks * 512,
        mtime: SystemTime::UNIX_EPOCH,
    }
}
fn dir(ino: u64) -> Metadata {
    meta(true, ino, 2, 0)
}
fn file(ino: u64, blocks: u64) -> Metadata {
    meta(false, ino, 1, blocks)
}
fn c(rel: &str) -> PathBuf {
    Path::new(CACHES).join(rel)
}

fn base() -> FakeFs {
    let mut fs = FakeFs::new();
    fs.insert("/Users", dir(100))
        .insert(HOME, dir(101))
        .insert("/Users/Tester/Library", dir(102))
        .insert(CACHES, dir(103))
        .insert("/Users/Tester/Library/Logs", dir(104))
        .insert("/Users/Tester/.ssh", dir(10))
        .insert("/Users/Tester/.ssh/id_ed25519", meta(false, 11, 2, 8));
    fs
}

fn run(fs: &FakeFs, rules: &[&dyn Rule]) -> ScanReport {
    let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
    let roots = ResolvedRoots {
        home: HOME.into(),
        caches: CACHES.into(),
        logs: "/Users/Tester/Library/Logs".into(),
    };
    let ctx = ScanContext {
        fs,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: 0,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH,
        },
        threads: None,
        tools: &rain_core::tools::NoTools,
    };
    scan(rules, &ctx, &AtomicBool::new(false)).unwrap()
}

fn paths(r: &ScanReport) -> Vec<PathBuf> {
    r.items.iter().map(|i| i.path.clone()).collect()
}
fn refused(r: &ScanReport, p: PathBuf) -> bool {
    r.skipped.contains(&Skipped {
        path: p,
        reason: SkipReason::Protected,
    })
}

// FR-007: alias buried several levels deep still refuses the top item.
#[test]
fn deep_protected_alias_refuses_item() {
    let mut fs = base();
    fs.insert(c("app"), dir(220))
        .insert(c("app/a"), dir(221))
        .insert(c("app/a/b"), dir(222))
        .insert(c("app/a/b/keys"), dir(10))
        .insert(c("app/a/b/keys/id_ed25519"), meta(false, 11, 2, 8))
        .insert(c("app/a/x"), file(223, 4))
        .insert(c("ok"), file(230, 2));
    let r = run(&fs, &[&rule("t.caches", "")]);
    assert_eq!(paths(&r), vec![c("ok")]);
    assert!(refused(&r, c("app")));
    assert_eq!(r.total_bytes, 2 * 512);
}

// FR-007: an item that is itself an alias of a protected dir is refused.
#[test]
fn item_that_is_protected_alias_is_refused() {
    let mut fs = base();
    fs.insert(c("app"), dir(10))
        .insert(c("app/id_ed25519"), meta(false, 11, 2, 8));
    let r = run(&fs, &[&rule("t.caches", "")]);
    assert!(r.items.is_empty());
    assert!(r
        .skipped
        .iter()
        .any(|s| s.reason == SkipReason::Protected && s.path.starts_with(c("app"))));
}

// A single-file item with no protected identity stays an item.
#[test]
fn single_file_item_is_kept() {
    let mut fs = base();
    fs.insert(c("f"), file(240, 3));
    let r = run(&fs, &[&rule("t.caches", "")]);
    assert_eq!(paths(&r), vec![c("f")]);
    assert_eq!(r.total_bytes, 3 * 512);
}

// Observation: a hardlink of a file *inside* ~/.ssh is not a protected
// identity (only protected roots are recorded). Documents current behavior.
#[test]
fn hardlinked_file_alias_behavior() {
    let mut fs = base();
    fs.insert(c("app"), dir(250))
        .insert(c("app/k"), meta(false, 11, 2, 8));
    let r = run(&fs, &[&rule("t.caches", "")]);
    eprintln!("items={:?} skipped={:?}", paths(&r), r.skipped);
}

// Non-protected skips must not refuse the item.
#[test]
fn symlink_other_dev_and_eacces_do_not_refuse_item() {
    let mut fs = base();
    let mut other = dir(260);
    other.dev = 2;
    fs.insert(c("app"), dir(250))
        .insert(c("app/x"), file(251, 4))
        .insert_symlink(c("app/link"), "/Users/Tester/.ssh")
        .insert(c("app/mnt"), other)
        .insert(c("app/locked"), dir(252))
        .fail_with(c("app/locked"), ErrorKind::PermissionDenied);
    let r = run(&fs, &[&rule("t.caches", "")]);
    assert_eq!(paths(&r), vec![c("app")]);
    assert!(!refused(&r, c("app")));
    assert!(
        r.skipped.iter().all(|s| s.reason != SkipReason::Protected),
        "{:?}",
        r.skipped
    );
    assert!(r.skipped.len() >= 2, "{:?}", r.skipped);
}

// Nested item of another rule holding the alias: the outer item must not
// be accepted either, since trashing it takes the nested folder along.
#[test]
fn outer_item_with_nested_item_holding_alias_is_not_accepted() {
    let mut fs = base();
    fs.insert(c("app"), dir(270))
        .insert(c("app/inner"), dir(271))
        .insert(c("app/inner/keys"), dir(10))
        .insert(c("app/inner/keys/id_ed25519"), meta(false, 11, 2, 8))
        .insert(c("app/y"), file(272, 2));
    let outer = rule("a.outer", "");
    let inner = rule("b.inner", "app");
    let r = run(&fs, &[&outer, &inner]);
    eprintln!("items={:?} skipped={:?}", paths(&r), r.skipped);
    for p in paths(&r) {
        assert!(
            !c("app/inner/keys").starts_with(&p),
            "item {p:?} would take the alias"
        );
    }
}
