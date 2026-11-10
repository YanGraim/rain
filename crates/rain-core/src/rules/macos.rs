//! macOS developer-tool rules whose items are the direct children of one
//! fixed folder.

use super::children::ChildrenOf;
use crate::model::{Category, Risk, RuleId};
use crate::rule::RuleMeta;
use rain_platform::{Os, Root};

/// FR-002: Xcode build products; each project folder is one item.
pub static XCODE_DERIVED_DATA: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("apple.derived-data"),
        category: Category::AppleDev,
        risk: Risk::Low,
        name_key: "rule.apple.derived-data",
        consequence_key: "rule.apple.derived-data.consequence",
        default_selected: true,
        requires_app_closed: Some("com.apple.dt.Xcode"),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &["Library/Developer/Xcode/DerivedData"],
    depth: 1,
};

/// FR-002: Homebrew download cache inside `{caches}`. Listed before the
/// user caches rule so it keeps these bytes (ADR 0005).
pub static HOMEBREW_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("pkg.homebrew"),
        category: Category::PackageManagers,
        risk: Risk::Low,
        name_key: "rule.pkg.homebrew",
        consequence_key: "rule.pkg.homebrew.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Caches,
    rels: &["Homebrew"],
    depth: 1,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{ScanReport, SkipReason};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::protect::ProtectList;
    use crate::rule::{Rule, RuleContext};
    use rain_platform::{Platform, PlatformError};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::time::SystemTime;

    const HOME: &str = "/Users/Tester";
    const CACHES: &str = "/Users/Tester/Library/Caches";
    const DD: &str = "/Users/Tester/Library/Developer/Xcode/DerivedData";
    const BREW: &str = "/Users/Tester/Library/Caches/Homebrew";

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

    fn meta(is_dir: bool, ino: u64, blocks: u64) -> Metadata {
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

    fn dir(ino: u64) -> Metadata {
        meta(true, ino, 0)
    }

    fn file(ino: u64, blocks: u64) -> Metadata {
        meta(false, ino, blocks)
    }

    /// Home with Library/Caches only: no Developer folder, no Homebrew.
    fn base() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", dir(100))
            .insert(HOME, dir(101))
            .insert("/Users/Tester/Library", dir(102))
            .insert(CACHES, dir(103))
            .insert("/Users/Tester/Library/Developer", dir(104))
            .insert("/Users/Tester/Library/Developer/Xcode", dir(105));
        fs
    }

    fn run(fs: &FakeFs, rules: &[&dyn Rule]) -> ScanReport {
        let protect = match ProtectList::builtin(&HomeAt) {
            Ok(list) => list.with_identities(fs),
            Err(e) => panic!("builtin failed: {e}"),
        };
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from(CACHES),
            logs: PathBuf::from("/Users/Tester/Library/Logs"),
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
        };
        match scan(rules, &ctx, &AtomicBool::new(false)) {
            Ok(r) => r,
            Err(e) => panic!("scan failed: {e}"),
        }
    }

    fn items(report: &ScanReport) -> Vec<(&'static str, PathBuf, u64, u64)> {
        report
            .items
            .iter()
            .map(|i| {
                (
                    i.rule.as_str(),
                    i.path.clone(),
                    i.allocated_bytes,
                    i.file_count,
                )
            })
            .collect()
    }

    fn at(base: &str, rel: &str) -> PathBuf {
        Path::new(base).join(rel)
    }

    // FR-002, FR-003: each child of DerivedData (project folder or stray
    // file) is one item with its whole subtree.
    #[test]
    fn derived_data_children_are_items() {
        let mut fs = base();
        fs.insert(DD, dir(106))
            .insert(at(DD, "App-abc"), dir(1))
            .insert(at(DD, "App-abc/Build"), dir(2))
            .insert(at(DD, "App-abc/Build/out.o"), file(3, 16))
            .insert(at(DD, "App-abc/info.plist"), file(4, 8))
            .insert(at(DD, "Lib-def"), dir(5))
            .insert(at(DD, "Lib-def/Index"), file(6, 4))
            .insert(at(DD, "ModuleCache.noindex"), file(7, 2));
        let report = run(&fs, &[&XCODE_DERIVED_DATA]);
        let id = "apple.derived-data";
        assert_eq!(
            items(&report),
            vec![
                (id, at(DD, "App-abc"), 24 * 512, 2),
                (id, at(DD, "Lib-def"), 4 * 512, 1),
                (id, at(DD, "ModuleCache.noindex"), 2 * 512, 1),
            ]
        );
        assert_eq!(report.total_bytes, 30 * 512);
        assert!(report.skipped.is_empty());
    }

    // FR-002: the Homebrew download cache below `{caches}` is found, one
    // item per child; sibling caches are not Homebrew's.
    #[test]
    fn homebrew_cache_found() {
        let mut fs = base();
        fs.insert(BREW, dir(10))
            .insert(at(BREW, "downloads"), dir(11))
            .insert(at(BREW, "downloads/abc--wget.bottle.tar.gz"), file(12, 40))
            .insert(at(BREW, "Cask"), dir(13))
            .insert(at(BREW, "Cask/app.dmg"), file(14, 80))
            .insert(at(BREW, "git--2.4.bottle.tar.gz"), file(15, 10))
            .insert(at(CACHES, "com.other.app"), file(16, 99));
        let report = run(&fs, &[&HOMEBREW_CACHE]);
        let id = "pkg.homebrew";
        assert_eq!(
            items(&report),
            vec![
                (id, at(BREW, "Cask"), 80 * 512, 1),
                (id, at(BREW, "downloads"), 40 * 512, 1),
                (id, at(BREW, "git--2.4.bottle.tar.gz"), 10 * 512, 1),
            ]
        );
        assert_eq!(report.total_bytes, 130 * 512);
    }

    // FR-002, FR-012: no Xcode and no Homebrew is not an error: both rules
    // show 0 items and nothing is skipped.
    #[test]
    fn missing_root_is_not_error() {
        let fs = base();
        let report = run(&fs, &[&HOMEBREW_CACHE, &XCODE_DERIVED_DATA]);
        assert!(report.items.is_empty());
        assert!(report.skipped.is_empty());
        let totals: Vec<_> = report
            .rules
            .iter()
            .map(|r| (r.rule.as_str(), r.allocated_bytes, r.items))
            .collect();
        assert_eq!(
            totals,
            vec![("apple.derived-data", 0, 0), ("pkg.homebrew", 0, 0)]
        );
    }

    // FR-005, FR-007: a DerivedData that is a symlink to `~/.ssh`, and a
    // Homebrew child that links there, never bring protected data in.
    #[test]
    fn symlink_to_protected_is_never_an_item() {
        let mut fs = base();
        fs.insert("/Users/Tester/.ssh", dir(20))
            .insert("/Users/Tester/.ssh/id_ed25519", file(21, 8))
            .insert_symlink(DD, "/Users/Tester/.ssh")
            .insert(BREW, dir(10))
            .insert_symlink(at(BREW, "keys"), "/Users/Tester/.ssh");
        let report = run(&fs, &[&HOMEBREW_CACHE, &XCODE_DERIVED_DATA]);
        assert!(report.items.is_empty());
        assert_eq!(report.total_bytes, 0);
        assert!(report
            .skipped
            .iter()
            .all(|s| s.reason == SkipReason::Symlink && !s.path.starts_with("/Users/Tester/.ssh")));
    }

    // FR-007: an entry that is `~/.ssh` itself (same inode, e.g. reached by a
    // firmlink) is refused by identity even under DerivedData.
    #[test]
    fn protected_identity_child_is_skipped() {
        let mut fs = base();
        fs.insert("/Users/Tester/.ssh", dir(20))
            .insert(DD, dir(106))
            .insert(at(DD, "App"), file(1, 4))
            .insert(at(DD, "keys"), dir(20));
        let report = run(&fs, &[&XCODE_DERIVED_DATA]);
        assert_eq!(
            items(&report),
            vec![("apple.derived-data", at(DD, "App"), 4 * 512, 1)]
        );
        assert!(report
            .skipped
            .iter()
            .any(|s| s.path == at(DD, "keys") && s.reason == SkipReason::Protected));
    }
}
