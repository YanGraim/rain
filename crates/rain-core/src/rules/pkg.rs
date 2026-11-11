//! Package manager caches (catalogue 6.4).

use super::children::ChildrenOf;
use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};

pub(super) static RULES: &[&dyn Rule] = &[&NPM, &YARN, &BUN, &PNPM];

// --- JS -------------------------------------------------------------------

const fn js_meta(
    id: &'static str,
    name_key: &'static str,
    consequence_key: &'static str,
    risk: Risk,
) -> RuleMeta {
    RuleMeta {
        id: RuleId::new(id),
        category: Category::PackageManagers,
        risk,
        name_key,
        consequence_key,
        // FR-014: only low risk caches are preselected.
        default_selected: matches!(risk, Risk::Low),
        requires_app_closed: None,
        os: &[Os::Macos],
    }
}

/// FR-001 (6.4): npm content cache; each child of `_cacache` is one item.
pub static NPM: ChildrenOf = ChildrenOf {
    meta: js_meta(
        "pkg.npm",
        "rule.pkg.npm",
        "rule.pkg.npm.consequence",
        Risk::Low,
    ),
    root: Root::Home,
    rels: &[".npm/_cacache"],
    depth: 1,
};

/// FR-001 (6.4): Yarn classic (in `{caches}`) and Yarn Berry caches.
/// Listed before the user caches rule so it keeps those bytes (ADR 0005).
pub static YARN: ChildrenOfRoots = ChildrenOfRoots {
    meta: js_meta(
        "pkg.yarn",
        "rule.pkg.yarn",
        "rule.pkg.yarn.consequence",
        Risk::Low,
    ),
    roots: &[(Root::Caches, "Yarn"), (Root::Home, ".yarn/berry/cache")],
};

/// FR-001 (6.4): Bun install cache.
pub static BUN: ChildrenOf = ChildrenOf {
    meta: js_meta(
        "pkg.bun",
        "rule.pkg.bun",
        "rule.pkg.bun.consequence",
        Risk::Low,
    ),
    root: Root::Home,
    rels: &[".bun/install/cache"],
    depth: 1,
};

/// FR-001 (6.4): pnpm content store. Projects hard link into it, so it is
/// medium risk and not preselected.
pub static PNPM: ChildrenOf = ChildrenOf {
    meta: js_meta(
        "pkg.pnpm",
        "rule.pkg.pnpm",
        "rule.pkg.pnpm.consequence",
        Risk::Medium,
    ),
    root: Root::Home,
    rels: &["Library/pnpm/store"],
    depth: 1,
};

/// Like [`ChildrenOf`] at depth 1, but over folders under different roots.
pub struct ChildrenOfRoots {
    meta: RuleMeta,
    roots: &'static [(Root, &'static str)],
}

impl Rule for ChildrenOfRoots {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for ChildrenOfRoots {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        self.roots
            .iter()
            .map(|(root, rel)| RootedPath::Under(*root, rel))
            .collect()
    }
    fn visit(&self, _: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        // FR-002: the folder itself is never an item, only what it holds.
        if depth == 0 {
            Visit::Descend
        } else {
            Visit::Candidate
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::fs::{FakeFs, Fs, Metadata};
    use crate::model::{Risk, ScanReport};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::protect::ProtectList;
    use crate::rule::RuleContext;
    use rain_platform::{Os, Platform, PlatformError, Root};
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

    fn md(is_dir: bool, ino: u64, blocks: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink: if is_dir { 2 } else { 1 },
            blocks,
            len: blocks * 512,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    fn h(rel: &str) -> PathBuf {
        Path::new(HOME).join(rel)
    }

    /// Inserts `rel` below the home and every missing parent folder.
    fn put(fs: &mut FakeFs, rel: &str, blocks: Option<u64>, ino: &mut u64) {
        let mut cur = PathBuf::from(HOME);
        let parts: Vec<&str> = rel.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            cur.push(part);
            let last = i + 1 == parts.len();
            if fs.symlink_metadata(&cur).is_ok() && !last {
                continue;
            }
            *ino += 1;
            let meta = match (last, blocks) {
                (true, Some(b)) => md(false, *ino, b),
                _ => md(true, *ino, 0),
            };
            fs.insert(&cur, meta);
        }
    }

    fn fixture(files: &[&str]) -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", md(true, 100, 0))
            .insert(HOME, md(true, 101, 0));
        let mut ino = 1000;
        put(&mut fs, "Library/Caches", None, &mut ino);
        put(&mut fs, "Documents/notes.txt", Some(8), &mut ino);
        for f in files {
            put(&mut fs, f, Some(8), &mut ino);
        }
        fs
    }

    fn run(fs: &FakeFs, id: &str) -> ScanReport {
        let rule = super::super::select(&[id]).unwrap();
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from(CACHES),
            logs: h("Library/Logs"),
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
            threads: Some(1),
            tools: &crate::tools::NoTools,
        };
        scan(&rule, &ctx, &AtomicBool::new(false)).unwrap()
    }

    fn items(report: &ScanReport) -> Vec<PathBuf> {
        report.items.iter().map(|i| i.path.clone()).collect()
    }

    fn meta(id: &str) -> crate::rule::RuleMeta {
        super::super::select(&[id]).unwrap()[0].meta().clone()
    }

    // FR-001 (6.4): npm content cache, one item per child of `_cacache`.
    #[test]
    fn npm_found_in_fixture() {
        let fs = fixture(&[
            ".npm/_cacache/content-v2/sha512/ab",
            ".npm/_cacache/index-v5/00/x",
            ".npm/_logs/debug.log",
        ]);
        let report = run(&fs, "pkg.npm");
        assert_eq!(
            items(&report),
            vec![h(".npm/_cacache/content-v2"), h(".npm/_cacache/index-v5")]
        );
    }

    // FR-001 (6.4): Yarn classic in `{caches}/Yarn` and Berry in
    // `~/.yarn/berry/cache`.
    #[test]
    fn yarn_found_in_fixture() {
        let fs = fixture(&[
            "Library/Caches/Yarn/v6/npm-lodash",
            ".yarn/berry/cache/lodash.zip",
            ".yarn/berry/install-state.gz",
        ]);
        let report = run(&fs, "pkg.yarn");
        assert_eq!(
            items(&report),
            vec![
                h(".yarn/berry/cache/lodash.zip"),
                h("Library/Caches/Yarn/v6"),
            ]
        );
    }

    // FR-001 (6.4): Bun install cache.
    #[test]
    fn bun_found_in_fixture() {
        let fs = fixture(&[".bun/install/cache/lodash@4", ".bun/bin/bun"]);
        let report = run(&fs, "pkg.bun");
        assert_eq!(items(&report), vec![h(".bun/install/cache/lodash@4")]);
    }

    // FR-001 (6.4): pnpm store.
    #[test]
    fn pnpm_found_in_fixture() {
        let fs = fixture(&["Library/pnpm/store/v3/files/00/a", "Library/pnpm/pnpm"]);
        let report = run(&fs, "pkg.pnpm");
        assert_eq!(items(&report), vec![h("Library/pnpm/store/v3")]);
    }

    // FR-001 (6.4), FR-014: projects link to the pnpm store, so it is
    // medium risk and never preselected.
    #[test]
    fn pnpm_is_medium_not_default() {
        let m = meta("pkg.pnpm");
        assert_eq!(m.risk, Risk::Medium);
        assert!(!m.default_selected);
    }

    // FR-001 (6.4): npm, yarn and bun caches are low risk and preselected.
    #[test]
    fn npm_yarn_bun_are_low_and_default() {
        for id in ["pkg.npm", "pkg.yarn", "pkg.bun"] {
            let m = meta(id);
            assert_eq!(m.risk, Risk::Low, "{id}");
            assert!(m.default_selected, "{id}");
            assert_eq!(m.category, crate::model::Category::PackageManagers);
            assert_eq!(m.requires_app_closed, None);
        }
    }

    // FR-005: a missing tool is silent.
    #[test]
    fn missing_js_tools_are_silent() {
        let fs = fixture(&[]);
        for id in ["pkg.npm", "pkg.yarn", "pkg.bun", "pkg.pnpm"] {
            let report = run(&fs, id);
            assert!(report.items.is_empty(), "{id}");
            assert!(report.skipped.is_empty(), "{id}");
        }
    }

    // ADR 0005: the bytes of the Yarn cache inside `{caches}` belong to
    // pkg.yarn; the user caches item for the folder excludes them.
    #[test]
    fn yarn_inside_caches_goes_to_yarn() {
        let fs = fixture(&["Library/Caches/Yarn/v6/npm-lodash"]);
        let rules = super::super::select(&["pkg.yarn", "sys.user-caches"]).unwrap();
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from(CACHES),
            logs: h("Library/Logs"),
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
            threads: Some(1),
            tools: &crate::tools::NoTools,
        };
        let report = scan(&rules, &ctx, &AtomicBool::new(false)).unwrap();
        let bytes: Vec<_> = report
            .items
            .iter()
            .map(|i| (i.rule.as_str(), i.path.clone(), i.allocated_bytes))
            .collect();
        assert_eq!(
            bytes,
            vec![
                ("pkg.yarn", h("Library/Caches/Yarn/v6"), 8 * 512),
                ("sys.user-caches", h("Library/Caches/Yarn"), 0),
            ]
        );
    }
}
