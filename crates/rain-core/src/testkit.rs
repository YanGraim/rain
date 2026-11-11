//! Rule protection testkit (NFR-005): every rule gets a `protects_*` test
//! by calling [`assert_rule_protects`].

use crate::fs::{FakeFs, Fs, Metadata};
use crate::model::{ScanReport, SkipReason};
use crate::planner::{scan, ResolvedRoots, ScanContext};
use crate::protect::ProtectList;
use crate::rule::{RootedPath, Rule, RuleContext, RuleKind};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

/// A way a rule reached protected data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The rule starts its walk at or below a protected path.
    ProtectedRoot(PathBuf),
    /// The scan reported a protected item, or one holding protected data
    /// (by name, or a folder sharing a protected folder's identity).
    ProtectedItem(PathBuf),
    /// The scan reported an item reached through a symlink.
    FollowedSymlink(PathBuf),
    /// A root the planner refuses: a `rel` that is absolute, has `.`/`..`,
    /// an empty part or a trailing `/`.
    InvalidRoot(PathBuf),
    /// The fixture itself could not be built.
    Setup(String),
}

/// Home of the fake user the bait is planted for.
pub const HOME: &str = "/Users/rain";
/// User root (`--path`) given to rules that read `user_paths`.
pub const USER_PATH: &str = "/Users/rain/Projects";

const DEV: u64 = 1;
const SSH_INO: u64 = 2;
const DOCS_INO: u64 = 3;
const ESCAPE: &str = "escape-to-ssh";

struct FakeHome;

impl Platform for FakeHome {
    fn resolve(&self, root: Root) -> Result<PathBuf, PlatformError> {
        let home = PathBuf::from(HOME);
        Ok(match root {
            Root::Home => home,
            Root::Caches => home.join("Library/Caches"),
            Root::Logs => home.join("Library/Logs"),
        })
    }
    fn is_root_user(&self) -> bool {
        false
    }
    fn os(&self) -> Os {
        Os::Macos
    }
}

struct Bait {
    fs: FakeFs,
    next_ino: u64,
}

impl Bait {
    fn meta(&mut self, is_dir: bool, ino: Option<u64>) -> Metadata {
        let ino = ino.unwrap_or_else(|| {
            self.next_ino += 1;
            self.next_ino
        });
        Metadata {
            is_dir,
            is_symlink: false,
            dev: DEV,
            ino,
            nlink: 1,
            blocks: 8,
            len: 4096,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    fn dir(&mut self, p: &Path, ino: Option<u64>) {
        for a in p.ancestors().collect::<Vec<_>>().into_iter().rev().skip(1) {
            if self.fs.symlink_metadata(a).is_err() {
                let m = self.meta(true, if a == p { ino } else { None });
                self.fs.insert(a, m);
            }
        }
    }

    fn file(&mut self, p: &Path) {
        if let Some(parent) = p.parent() {
            self.dir(parent, None);
        }
        let m = self.meta(false, None);
        self.fs.insert(p, m);
    }

    /// FR-004, FR-007: inside `root`, a symlink out to `~/.ssh`, folders
    /// sharing the identity of `~/.ssh` and `~/Documents`, and plain files.
    fn plant(&mut self, root: &Path) {
        let home = Path::new(HOME);
        self.dir(root, None);
        for (name, ino) in [(".ssh", SSH_INO), ("Documents", DOCS_INO)] {
            let alias = root.join(name);
            if self.fs.symlink_metadata(&alias).is_err() {
                self.dir(&alias, Some(ino));
                self.file(&alias.join("secret"));
            }
        }
        let escape = root.join(ESCAPE);
        if self.fs.symlink_metadata(&escape).is_err() {
            self.fs.insert_symlink(escape, home.join(".ssh"));
        }
        self.file(&root.join("old.cache"));
        self.file(&root.join("node_modules/package.json"));
        self.file(&root.join("package.json"));
    }
}

fn base(rooted: &RootedPath, roots: &ResolvedRoots) -> Result<PathBuf, PathBuf> {
    match rooted {
        RootedPath::Under(root, rel) => {
            let base = match root {
                Root::Home => &roots.home,
                Root::Caches => &roots.caches,
                Root::Logs => &roots.logs,
            };
            if rel.is_empty() {
                return Ok(base.clone());
            }
            let rel_path = Path::new(rel);
            let plain = !rel.ends_with('/')
                && !rel.split('/').any(|part| part.is_empty() || part == ".")
                && rel_path
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)));
            if plain {
                Ok(base.join(rel_path))
            } else {
                Err(base.join(rel_path))
            }
        }
        RootedPath::User(p) => Ok(p.clone()),
    }
}

/// Scans `rule` over a fake home seeded with protected bait and returns
/// every violation found.
pub fn check_rule_protects(rule: &dyn Rule) -> Result<(), Vec<Violation>> {
    let (violations, _) = run(rule);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn run(rule: &dyn Rule) -> (Vec<Violation>, Option<ScanReport>) {
    let home = PathBuf::from(HOME);
    let roots = ResolvedRoots {
        home: home.clone(),
        caches: home.join("Library/Caches"),
        logs: home.join("Library/Logs"),
    };
    let rule_ctx = RuleContext {
        min_age_days: 0,
        user_paths: vec![PathBuf::from(USER_PATH)],
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(10 * 365 * 86_400),
    };
    let names = match ProtectList::builtin(&FakeHome) {
        Ok(list) => list,
        Err(e) => return (vec![Violation::Setup(e.to_string())], None),
    };

    let mut bait = Bait {
        fs: FakeFs::new(),
        next_ino: 100,
    };
    bait.dir(&home.join(".ssh"), Some(SSH_INO));
    bait.file(&home.join(".ssh/id_ed25519"));
    bait.dir(&home.join("Documents"), Some(DOCS_INO));
    bait.file(&home.join("Documents/notes.txt"));
    bait.dir(&home.join("Library/Keychains"), None);
    bait.file(&home.join("Library/Keychains/login.keychain-db"));

    let rule_roots = match rule.kind() {
        RuleKind::Files(files) => files.roots(&rule_ctx),
        RuleKind::Provider(provider) => provider.roots(),
    };
    let mut violations = Vec::new();
    let mut planted = Vec::new();
    for rooted in rule_roots {
        let root = match base(&rooted, &roots) {
            Ok(root) => root,
            Err(invalid) => {
                violations.push(Violation::InvalidRoot(invalid));
                continue;
            }
        };
        if names.is_protected(&root) {
            violations.push(Violation::ProtectedRoot(root));
        } else {
            planted.push(root);
        }
    }
    for root in &planted {
        bait.plant(root);
    }
    let fs = bait.fs;
    let protect = names.with_identities(&fs);
    for root in planted {
        if protect.is_protected_on(&fs, &root) {
            violations.push(Violation::ProtectedRoot(root));
        }
    }

    let ctx = ScanContext {
        fs: &fs,
        protect: &protect,
        roots: &roots,
        rule_ctx,
        tools: &crate::tools::NoTools,
        threads: Some(1),
    };
    let report = scan(&[rule], &ctx, &AtomicBool::new(false)).ok();
    if let Some(r) = &report {
        let refused: Vec<&Path> = r
            .skipped
            .iter()
            .filter(|s| s.reason == SkipReason::Protected)
            .map(|s| s.path.as_path())
            .collect();
        for item in &r.items {
            let path = item.path.clone();
            let holds_refused = refused.iter().any(|p| p.starts_with(&path));
            if path.ancestors().skip(1).any(|a| a.ends_with(ESCAPE)) {
                violations.push(Violation::FollowedSymlink(path));
            } else if holds_refused
                || protect.is_protected_on(&fs, &path)
                || protect.contains_protected(&path)
            {
                violations.push(Violation::ProtectedItem(path));
            }
        }
    }
    (violations, report)
}

/// Panics with the violations if `rule` reaches protected data.
pub fn assert_rule_protects(rule: &dyn Rule) {
    if let Err(violations) = check_rule_protects(rule) {
        panic!(
            "rule {} reaches protected data: {violations:?}",
            rule.meta().id
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Fs;
    use crate::model::{Category, Risk, RuleId};
    use crate::rule::{EntryInfo, FileRule, RootedPath, RuleContext, RuleKind, RuleMeta, Visit};
    use rain_platform::Root;

    struct Takes {
        meta: RuleMeta,
        root: Root,
        rel: &'static str,
        children_only: bool,
    }

    fn takes(rel: &'static str) -> Takes {
        Takes {
            meta: RuleMeta {
                id: RuleId::new("test.bad"),
                category: Category::SystemCaches,
                risk: Risk::Low,
                name_key: "test",
                consequence_key: "test",
                default_selected: true,
                requires_app_closed: None,
                os: &[],
            },
            root: Root::Home,
            rel,
            children_only: false,
        }
    }

    fn children_of(rel: &'static str) -> Takes {
        Takes {
            children_only: true,
            ..takes(rel)
        }
    }

    impl Rule for Takes {
        fn meta(&self) -> &RuleMeta {
            &self.meta
        }
        fn kind(&self) -> RuleKind<'_> {
            RuleKind::Files(self)
        }
    }

    impl FileRule for Takes {
        fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
            vec![RootedPath::Under(self.root, self.rel)]
        }
        fn visit(&self, _: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
            if self.children_only && depth == 0 {
                Visit::Descend
            } else {
                Visit::Candidate
            }
        }
    }

    // NFR-005, FR-007: a rule rooted in a protected folder fails the helper.
    #[test]
    fn testkit_catches_rule_that_lists_protected() {
        for rel in [".ssh", "Documents", "Documents/Work", "Library/Keychains"] {
            let err = check_rule_protects(&takes(rel)).unwrap_err();
            assert!(
                err.iter().any(|v| matches!(v, Violation::ProtectedRoot(_))),
                "{rel}: {err:?}"
            );
        }
    }

    // NFR-005: the panicking form names the rule.
    #[test]
    #[should_panic(expected = "test.bad")]
    fn assert_rule_protects_panics_on_bad_rule() {
        assert_rule_protects(&takes(".ssh"));
    }

    // NFR-005: a rule that only lists a cache folder's children passes.
    #[test]
    fn testkit_accepts_cache_children_rule() {
        assert_eq!(
            check_rule_protects(&children_of("Library/Caches/App")),
            Ok(())
        );
    }

    // NFR-005, FR-004, FR-007: the bait is really offered to the scan and
    // refused: the symlink out and both identity aliases are skipped.
    #[test]
    fn testkit_bait_is_refused_by_scan() {
        let (violations, report) = run(&children_of("Library/Caches/App"));
        assert_eq!(violations, []);
        let report = report.unwrap();
        let root = Path::new(HOME).join("Library/Caches/App");
        let skipped: Vec<_> = report.skipped.iter().map(|s| s.path.clone()).collect();
        for bait in [ESCAPE, ".ssh", "Documents"] {
            assert!(skipped.contains(&root.join(bait)), "{bait}: {skipped:?}");
        }
        assert!(
            report
                .items
                .iter()
                .any(|i| i.path == root.join("old.cache")),
            "{report:?}"
        );
    }

    // NFR-005, FR-007: a root the planner would refuse is reported, never
    // silently dropped.
    #[test]
    fn testkit_reports_invalid_root() {
        for rel in [
            "..",
            "../x",
            "./x",
            "x/./y",
            "x/",
            "/etc",
            "/Users/rain/.ssh",
        ] {
            let err = check_rule_protects(&children_of(rel)).unwrap_err();
            assert!(
                err.iter().any(|v| matches!(v, Violation::InvalidRoot(_))),
                "{rel}: {err:?}"
            );
        }
    }

    struct NoteReadDir<'a> {
        inner: &'a FakeFs,
        on_symlink: std::sync::Mutex<Vec<PathBuf>>,
    }

    impl Fs for NoteReadDir<'_> {
        fn symlink_metadata(&self, p: &Path) -> std::io::Result<Metadata> {
            self.inner.symlink_metadata(p)
        }
        fn read_dir(&self, p: &Path) -> std::io::Result<Vec<crate::fs::DirEntryInfo>> {
            if self.inner.symlink_metadata(p).is_ok_and(|m| m.is_symlink) {
                if let Ok(mut seen) = self.on_symlink.lock() {
                    seen.push(p.to_path_buf());
                }
            }
            self.inner.read_dir(p)
        }
        fn canonicalize(&self, p: &Path) -> std::io::Result<PathBuf> {
            self.inner.canonicalize(p)
        }
    }

    // NFR-005, FR-004: the walker never lists a symlink, so FakeFs's
    // `NotADirectory` there never differs from the real filesystem in a scan.
    #[test]
    fn walker_never_reads_dir_of_symlink() {
        let home = PathBuf::from(HOME);
        let root = home.join("Library/Caches/App");
        let mut bait = Bait {
            fs: FakeFs::new(),
            next_ino: 100,
        };
        bait.dir(&home.join(".ssh"), Some(SSH_INO));
        bait.plant(&root);
        bait.fs
            .insert_symlink(root.join("to-dir"), home.join("Library"));
        let fs = NoteReadDir {
            inner: &bait.fs,
            on_symlink: std::sync::Mutex::new(Vec::new()),
        };
        let protect = ProtectList::builtin(&FakeHome)
            .unwrap()
            .with_identities(&fs);
        let roots = ResolvedRoots {
            home: home.clone(),
            caches: home.join("Library/Caches"),
            logs: home.join("Library/Logs"),
        };
        let ctx = ScanContext {
            fs: &fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::UNIX_EPOCH,
            },
            tools: &crate::tools::NoTools,
            threads: Some(2),
        };
        for rule in [
            takes("Library/Caches/App"),
            children_of("Library/Caches/App"),
        ] {
            scan(&[&rule], &ctx, &AtomicBool::new(false)).unwrap();
        }
        assert_eq!(*fs.on_symlink.lock().unwrap(), Vec::<PathBuf>::new());
    }

    // NFR-005, FR-007: a folder that holds an alias of a protected folder
    // is refused whole by the planner, so the testkit sees no violation.
    #[test]
    fn testkit_bait_alias_item_is_refused_by_planner() {
        let root = Path::new(HOME).join("Library/Caches/App");
        let rule = takes("Library/Caches/App");
        assert_eq!(check_rule_protects(&rule), Ok(()));
        let (_, report) = run(&rule);
        let report = report.unwrap();
        assert!(report.items.is_empty());
        assert!(report.skipped.contains(&crate::model::Skipped {
            path: root,
            reason: SkipReason::Protected,
        }));
    }

    // NFR-005, FR-004, FR-007: every built-in rule passes.
    #[test]
    fn protects_every_builtin_rule() {
        for rule in crate::rules::builtin() {
            assert_rule_protects(*rule);
        }
    }
}
