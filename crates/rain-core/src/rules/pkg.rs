//! Package manager caches (catalogue 6.4).

use super::children::ChildrenOf;
use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};

pub(super) static RULES: &[&dyn Rule] = &[
    &NPM,
    &NPX,
    &PLAYWRIGHT,
    &YARN,
    &BUN,
    &PNPM,
    &PIP,
    &UV,
    &POETRY,
];

// --- JS and shared -------------------------------------------------------------------

const fn pkg_meta(
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
    meta: pkg_meta(
        "pkg.npm",
        "rule.pkg.npm",
        "rule.pkg.npm.consequence",
        Risk::Low,
    ),
    root: Root::Home,
    rels: &[".npm/_cacache"],
    depth: 1,
};

/// AI2f: npx install cache (`~/.npm/_npx/<hash>`: package.json and
/// node_modules). npx downloads them again on the next run.
pub static NPX: ChildrenOf = ChildrenOf {
    meta: pkg_meta(
        "pkg.npx",
        "rule.pkg.npx",
        "rule.pkg.npx.consequence",
        Risk::Low,
    ),
    root: Root::Home,
    rels: &[".npm/_npx"],
    depth: 1,
};

/// AI2f: Playwright browsers in `{caches}/ms-playwright`, named
/// `<browser>-<revision>`. Only revisions with a newer one of the same
/// browser are items; the newest stays. Listed before the user caches rule
/// so it keeps those bytes (ADR 0005).
pub static PLAYWRIGHT: OldRevisions = OldRevisions {
    meta: pkg_meta(
        "pkg.playwright",
        "rule.pkg.playwright",
        "rule.pkg.playwright.consequence",
        Risk::Medium,
    ),
    root: Root::Caches,
    rel: "ms-playwright",
};

pub struct OldRevisions {
    meta: RuleMeta,
    root: Root,
    rel: &'static str,
}

impl Rule for OldRevisions {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

/// `chromium_headless_shell-1148` -> (`chromium_headless_shell`, 1148).
fn revision(name: &str) -> Option<(&str, u64)> {
    let (browser, rev) = name.rsplit_once('-')?;
    let ok_browser = !browser.is_empty()
        && browser
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if !ok_browser || rev.is_empty() || !rev.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((browser, rev.parse().ok()?))
}

/// `true` only if a strictly newer revision of the same browser exists and
/// no sibling of that browser is unparseable (fail closed).
fn is_old_revision(name: &str, siblings: &[String]) -> bool {
    let Some((browser, rev)) = revision(name) else {
        return false;
    };
    let prefix = format!("{browser}-");
    let mut newer = false;
    for other in siblings.iter().filter(|s| s.as_str() != name) {
        match revision(other) {
            Some((b, r)) if b == browser => newer |= r > rev,
            Some(_) => {}
            None if other.starts_with(&prefix) => return false,
            None => {}
        }
    }
    newer
}

impl FileRule for OldRevisions {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        vec![RootedPath::Under(self.root, self.rel)]
    }
    fn visit(&self, entry: &EntryInfo, depth: usize, _: &RuleContext, fs: &dyn Fs) -> Visit {
        if depth == 0 {
            return Visit::Descend;
        }
        let (Some(name), Some(parent)) = (
            entry.path.file_name().and_then(|n| n.to_str()),
            entry.path.parent(),
        ) else {
            return Visit::Skip;
        };
        if !entry.meta.is_dir {
            return Visit::Skip;
        }
        let siblings: Option<Vec<String>> = fs.read_dir(parent).ok().and_then(|es| {
            es.iter()
                .map(|e| e.path.file_name()?.to_str().map(str::to_owned))
                .collect()
        });
        match siblings {
            Some(siblings) if is_old_revision(name, &siblings) => Visit::Candidate,
            _ => Visit::Skip,
        }
    }
}

/// FR-001 (6.4): Yarn classic (in `{caches}`) and Yarn Berry caches.
/// Listed before the user caches rule so it keeps those bytes (ADR 0005).
pub static YARN: ChildrenOfRoots = ChildrenOfRoots {
    meta: pkg_meta(
        "pkg.yarn",
        "rule.pkg.yarn",
        "rule.pkg.yarn.consequence",
        Risk::Low,
    ),
    roots: &[(Root::Caches, "Yarn"), (Root::Home, ".yarn/berry/cache")],
};

/// FR-001 (6.4): Bun install cache.
pub static BUN: ChildrenOf = ChildrenOf {
    meta: pkg_meta(
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
    meta: pkg_meta(
        "pkg.pnpm",
        "rule.pkg.pnpm",
        "rule.pkg.pnpm.consequence",
        Risk::Medium,
    ),
    root: Root::Home,
    rels: &["Library/pnpm/store"],
    depth: 1,
};

// --- Python ---------------------------------------------------------------

/// FR-001 (6.4): pip cache. Listed before the user caches rule so it keeps
/// those bytes (ADR 0005).
pub static PIP: ChildrenOf = ChildrenOf {
    meta: pkg_meta(
        "pkg.pip",
        "rule.pkg.pip",
        "rule.pkg.pip.consequence",
        Risk::Low,
    ),
    root: Root::Caches,
    rels: &["pip"],
    depth: 1,
};

/// FR-001 (6.4): uv cache.
pub static UV: ChildrenOf = ChildrenOf {
    meta: pkg_meta(
        "pkg.uv",
        "rule.pkg.uv",
        "rule.pkg.uv.consequence",
        Risk::Low,
    ),
    root: Root::Home,
    rels: &[".cache/uv"],
    depth: 1,
};

/// FR-001 (6.4): Poetry cache and artifacts. Only those two folders: the
/// sibling `virtualenvs` holds project environments (medium risk).
pub static POETRY: ChildrenOfRoots = ChildrenOfRoots {
    meta: pkg_meta(
        "pkg.poetry",
        "rule.pkg.poetry",
        "rule.pkg.poetry.consequence",
        Risk::Low,
    ),
    roots: &[
        (Root::Caches, "pypoetry/cache"),
        (Root::Caches, "pypoetry/artifacts"),
    ],
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

    // FR-001 (6.4), FR-043: Poetry virtualenvs are project environments.
    // With `sys.user-caches` also selected, nothing under
    // `{caches}/pypoetry/virtualenvs` is a candidate or counted in any item.
    #[test]
    fn poetry_virtualenvs_never_candidate() {
        let fs = fixture(&[
            "Library/Caches/pypoetry/cache/x/a",
            "Library/Caches/pypoetry/virtualenvs/p/bin/python",
        ]);
        let rules = super::super::select(&["pkg.poetry", "sys.user-caches"]).unwrap();
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
        let venvs = h("Library/Caches/pypoetry/virtualenvs");
        for item in &report.items {
            assert!(!item.path.starts_with(&venvs), "{item:?}");
            assert!(!venvs.starts_with(&item.path), "{item:?} counts the venvs");
        }
        assert!(report
            .items
            .iter()
            .any(|i| i.path == h("Library/Caches/pypoetry/cache/x")));
    }

    // FR-001 (6.4): pip cache in `{caches}/pip`, one item per child.
    #[test]
    fn pip_found_in_fixture() {
        let fs = fixture(&[
            "Library/Caches/pip/http-v2/a/b",
            "Library/Caches/pip/wheels/x/y.whl",
        ]);
        let report = run(&fs, "pkg.pip");
        assert_eq!(
            items(&report),
            vec![
                h("Library/Caches/pip/http-v2"),
                h("Library/Caches/pip/wheels"),
            ]
        );
    }

    // FR-001 (6.4): uv cache in `~/.cache/uv`.
    #[test]
    fn uv_found_in_fixture() {
        let fs = fixture(&[".cache/uv/wheels-v5/x", ".cache/other/y"]);
        let report = run(&fs, "pkg.uv");
        assert_eq!(items(&report), vec![h(".cache/uv/wheels-v5")]);
    }

    // FR-001 (6.4): Poetry cache and artifacts. Poetry virtualenvs are
    // medium risk in the catalogue, so this low rule never lists them.
    #[test]
    fn poetry_found_in_fixture() {
        let fs = fixture(&[
            "Library/Caches/pypoetry/cache/repositories/pypi/x",
            "Library/Caches/pypoetry/artifacts/00/a.whl",
            "Library/Caches/pypoetry/virtualenvs/proj-py3.12/bin/python",
        ]);
        let report = run(&fs, "pkg.poetry");
        assert_eq!(
            items(&report),
            vec![
                h("Library/Caches/pypoetry/artifacts/00"),
                h("Library/Caches/pypoetry/cache/repositories"),
            ]
        );
    }

    // FR-001 (6.4), FR-014: Python caches are low risk and preselected.
    #[test]
    fn python_caches_are_low_and_default() {
        for id in ["pkg.pip", "pkg.uv", "pkg.poetry"] {
            let m = meta(id);
            assert_eq!(m.risk, Risk::Low, "{id}");
            assert!(m.default_selected, "{id}");
            assert_eq!(m.category, crate::model::Category::PackageManagers);
            assert_eq!(m.requires_app_closed, None);
        }
    }

    // FR-005: a missing tool is silent.
    #[test]
    fn missing_python_tools_are_silent() {
        let fs = fixture(&[]);
        for id in ["pkg.pip", "pkg.uv", "pkg.poetry"] {
            let report = run(&fs, id);
            assert!(report.items.is_empty(), "{id}");
            assert!(report.skipped.is_empty(), "{id}");
        }
    }

    // ADR 0005: the pip bytes inside `{caches}` belong to pkg.pip; the user
    // caches item for the folder excludes them.
    #[test]
    fn pip_inside_caches_goes_to_pip() {
        let fs = fixture(&["Library/Caches/pip/http-v2/a"]);
        let rules = super::super::select(&["pkg.pip", "sys.user-caches"]).unwrap();
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
                ("pkg.pip", h("Library/Caches/pip/http-v2"), 8 * 512),
                ("sys.user-caches", h("Library/Caches/pip"), 0),
            ]
        );
    }
}
