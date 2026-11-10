//! Shared rule shapes: the items are the entries at a fixed depth below
//! some folders, or the folders themselves.

use crate::fs::Fs;
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::Root;

/// A rule that lists the entries `depth` levels below each `Under(root, rel)`
/// as items (`depth: 1` = direct children). A missing folder simply yields
/// 0 items (the planner keeps it silent).
pub struct ChildrenOf {
    pub(super) meta: RuleMeta,
    pub(super) root: Root,
    /// Paths under `root`; an empty one means `root` itself.
    pub(super) rels: &'static [&'static str],
    pub(super) depth: usize,
}

impl Rule for ChildrenOf {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for ChildrenOf {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        rooted(self.root, self.rels)
    }
    fn visit(&self, entry: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        // FR-002: the folder itself is never an item, only what it holds.
        let target = self.depth.max(1);
        if depth >= target {
            Visit::Candidate
        } else if depth == 0 || entry.meta.is_dir {
            Visit::Descend
        } else {
            Visit::Skip
        }
    }
}

/// A rule whose items are the folders `Under(root, rel)` themselves.
#[allow(dead_code)]
pub struct DirItself {
    pub(super) meta: RuleMeta,
    pub(super) root: Root,
    /// Paths under `root`; an empty one means `root` itself.
    pub(super) rels: &'static [&'static str],
}

impl Rule for DirItself {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for DirItself {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        rooted(self.root, self.rels)
    }
    fn visit(&self, _: &EntryInfo, _: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        Visit::Candidate
    }
}

fn rooted(root: Root, rels: &'static [&'static str]) -> Vec<RootedPath> {
    rels.iter()
        .map(|rel| RootedPath::Under(root, rel))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{Category, Risk, RuleId, ScanReport, SkipReason};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::protect::ProtectList;
    use crate::rule::RuleContext;
    use rain_platform::{Os, Platform, PlatformError};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, SystemTime};

    const HOME: &str = "/Users/Tester";
    const DAY: u64 = 86_400;

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

    const fn meta(id: &'static str) -> RuleMeta {
        RuleMeta {
            id: RuleId::new(id),
            category: Category::SystemCaches,
            risk: Risk::Low,
            name_key: "rule.sys.user-caches",
            consequence_key: "rule.sys.user-caches.consequence",
            default_selected: false,
            requires_app_closed: None,
            os: &[Os::Macos],
        }
    }

    fn md(is_dir: bool, ino: u64, blocks: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink: if is_dir { 2 } else { 1 },
            blocks,
            len: blocks * 512,
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(100 * DAY),
        }
    }

    fn h(rel: &str) -> PathBuf {
        Path::new(HOME).join(rel)
    }

    fn base() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", md(true, 100, 0))
            .insert(HOME, md(true, 101, 0));
        fs
    }

    fn run(fs: &FakeFs, rule: &dyn Rule) -> ScanReport {
        let protect = match ProtectList::builtin(&HomeAt) {
            Ok(list) => list.with_identities(fs),
            Err(e) => panic!("builtin failed: {e}"),
        };
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: h("Library/Caches"),
            logs: h("Library/Logs"),
        };
        let ctx = ScanContext {
            fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(101 * DAY),
            },
            threads: Some(1),
        };
        match scan(&[rule], &ctx, &AtomicBool::new(false)) {
            Ok(report) => report,
            Err(e) => panic!("scan failed: {e}"),
        }
    }

    fn items(report: &ScanReport) -> Vec<PathBuf> {
        report.items.iter().map(|i| i.path.clone()).collect()
    }

    fn skips(report: &ScanReport) -> Vec<(PathBuf, SkipReason)> {
        report
            .skipped
            .iter()
            .map(|s| (s.path.clone(), s.reason))
            .collect()
    }

    // FR-001: every folder in `rels` contributes its children.
    #[test]
    fn children_of_many_rels_lists_each() {
        static RULE: ChildrenOf = ChildrenOf {
            meta: meta("test.many"),
            root: Root::Home,
            rels: &[".a/cache", ".b"],
            depth: 1,
        };
        let mut fs = base();
        fs.insert(h(".a"), md(true, 1, 0))
            .insert(h(".a/cache"), md(true, 2, 0))
            .insert(h(".a/cache/x"), md(false, 3, 8))
            .insert(h(".b"), md(true, 4, 0))
            .insert(h(".b/y"), md(true, 5, 0))
            .insert(h(".b/y/z"), md(false, 6, 8));
        let report = run(&fs, &RULE);
        assert_eq!(items(&report), vec![h(".a/cache/x"), h(".b/y")]);
        assert!(report.skipped.is_empty());
    }

    // FR-001: depth 2 makes the grandchildren the items; files at depth 1
    // are not items and folders at depth 1 are only crossed.
    #[test]
    fn children_at_depth_2_lists_grandchildren() {
        static RULE: ChildrenOf = ChildrenOf {
            meta: meta("test.depth2"),
            root: Root::Home,
            rels: &["models"],
            depth: 2,
        };
        let mut fs = base();
        fs.insert(h("models"), md(true, 1, 0))
            .insert(h("models/readme"), md(false, 2, 8))
            .insert(h("models/org"), md(true, 3, 0))
            .insert(h("models/org/m1"), md(true, 4, 0))
            .insert(h("models/org/m1/w"), md(false, 5, 16))
            .insert(h("models/org/m2"), md(false, 6, 8));
        let report = run(&fs, &RULE);
        assert_eq!(items(&report), vec![h("models/org/m1"), h("models/org/m2")]);
        assert_eq!(report.items[0].allocated_bytes, 16 * 512);
    }

    // FR-001: the folder itself is a single item with its whole size.
    #[test]
    fn dir_itself_is_one_item() {
        static RULE: DirItself = DirItself {
            meta: meta("test.itself"),
            root: Root::Home,
            rels: &[".tool/cache"],
        };
        let mut fs = base();
        fs.insert(h(".tool"), md(true, 1, 0))
            .insert(h(".tool/cache"), md(true, 2, 0))
            .insert(h(".tool/cache/a"), md(false, 3, 8))
            .insert(h(".tool/cache/b"), md(true, 4, 0))
            .insert(h(".tool/cache/b/c"), md(false, 5, 8));
        let report = run(&fs, &RULE);
        assert_eq!(items(&report), vec![h(".tool/cache")]);
        assert_eq!(report.items[0].allocated_bytes, 16 * 512);
        assert_eq!(report.items[0].file_count, 2);
    }

    // FR-005: a folder that does not exist yields nothing and no skip.
    #[test]
    fn missing_rel_is_silent() {
        static KIDS: ChildrenOf = ChildrenOf {
            meta: meta("test.missing"),
            root: Root::Home,
            rels: &[".nope", ".here"],
            depth: 2,
        };
        static SELF: DirItself = DirItself {
            meta: meta("test.missing-self"),
            root: Root::Home,
            rels: &[".nope", ".here"],
        };
        let mut fs = base();
        fs.insert(h(".here"), md(true, 1, 0))
            .insert(h(".here/a"), md(true, 2, 0))
            .insert(h(".here/a/b"), md(false, 3, 8));
        let kids = run(&fs, &KIDS);
        assert_eq!(items(&kids), vec![h(".here/a/b")]);
        assert!(kids.skipped.is_empty());
        let itself = run(&fs, &SELF);
        assert_eq!(items(&itself), vec![h(".here")]);
        assert!(itself.skipped.is_empty());
    }

    // FR-005: every `rel` must be plain names; a bad one is refused alone.
    #[test]
    fn invalid_rel_in_list_is_refused() {
        static KIDS: ChildrenOf = ChildrenOf {
            meta: meta("test.bad"),
            root: Root::Home,
            rels: &["../other", ".ok"],
            depth: 1,
        };
        static SELF: DirItself = DirItself {
            meta: meta("test.bad-self"),
            root: Root::Home,
            rels: &[".ok", "/etc"],
        };
        let mut fs = base();
        fs.insert(h(".ok"), md(true, 1, 0))
            .insert(h(".ok/a"), md(false, 2, 8));
        let kids = run(&fs, &KIDS);
        assert_eq!(items(&kids), vec![h(".ok/a")]);
        assert_eq!(skips(&kids), vec![(h("../other"), SkipReason::InvalidRoot)]);
        let itself = run(&fs, &SELF);
        assert_eq!(items(&itself), vec![h(".ok")]);
        assert_eq!(
            itself.skipped.iter().map(|s| s.reason).collect::<Vec<_>>(),
            vec![SkipReason::InvalidRoot]
        );
    }

    // FR-005: protection applies to each item, at any depth and for the
    // whole folder: a protected item or one holding protected data is refused.
    #[test]
    fn protection_applies_to_every_item() {
        static KIDS: ChildrenOf = ChildrenOf {
            meta: meta("test.prot"),
            root: Root::Home,
            rels: &[""],
            depth: 2,
        };
        static SELF: DirItself = DirItself {
            meta: meta("test.prot-self"),
            root: Root::Home,
            rels: &[".ssh", "box"],
        };
        static HOME_SELF: DirItself = DirItself {
            meta: meta("test.prot-home"),
            root: Root::Home,
            rels: &[""],
        };
        let mut fs = base();
        fs.insert(h(".ssh"), md(true, 1, 0))
            .insert(h(".ssh/id"), md(false, 2, 8))
            .insert(h("box"), md(true, 3, 0))
            .insert(h("box/Documents"), md(true, 4, 0))
            .insert(h("box/junk"), md(false, 5, 8));
        let kids = run(&fs, &KIDS);
        assert!(!items(&kids).contains(&h(".ssh/id")));
        assert_eq!(items(&kids), vec![h("box/Documents"), h("box/junk")]);
        let itself = run(&fs, &SELF);
        assert_eq!(items(&itself), vec![h("box")]);
        assert_eq!(skips(&itself), vec![(h(".ssh"), SkipReason::Protected)]);
        let home = run(&fs, &HOME_SELF);
        assert!(items(&home).is_empty());
        assert_eq!(skips(&home), vec![(h(""), SkipReason::Protected)]);
    }
}
