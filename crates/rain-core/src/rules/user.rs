//! User-level caches and logs: every direct child of the root is an item.

use super::children::ChildrenOf;
use crate::model::{Category, Risk, RuleId};
use crate::rule::RuleMeta;
use rain_platform::{Os, Root};

// FR-002: no age filter on these rules; the spec only ages `proj.node-modules`.

/// `sys.user-caches`: contents of `~/Library/Caches`.
pub static USER_CACHES: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("sys.user-caches"),
        category: Category::SystemCaches,
        risk: Risk::Low,
        name_key: "rule.sys.user-caches",
        consequence_key: "rule.sys.user-caches.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Caches,
    rel: "",
};

/// `sys.logs`: contents of `~/Library/Logs`.
pub static USER_LOGS: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("sys.logs"),
        category: Category::Logs,
        risk: Risk::Low,
        name_key: "rule.sys.logs",
        consequence_key: "rule.sys.logs.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Logs,
    rel: "",
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{ScanReport, SkipReason};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::protect::ProtectList;
    use crate::rule::{FileRule, RootedPath, Rule, RuleContext};
    use rain_platform::{Platform, PlatformError};
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, SystemTime};

    const HOME: &str = "/Users/Tester";
    const CACHES: &str = "/Users/Tester/Library/Caches";
    const LOGS: &str = "/Users/Tester/Library/Logs";
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

    fn meta(is_dir: bool, ino: u64, nlink: u64, blocks: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink,
            blocks,
            len: blocks * 512,
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(100 * DAY),
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

    fn l(rel: &str) -> PathBuf {
        Path::new(LOGS).join(rel)
    }

    fn base() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", dir(100))
            .insert(HOME, dir(101))
            .insert("/Users/Tester/Library", dir(102))
            .insert(CACHES, dir(103))
            .insert(LOGS, dir(104));
        fs
    }

    fn run_aged(fs: &FakeFs, rules: &[&dyn Rule], min_age_days: u32) -> ScanReport {
        let protect = match ProtectList::builtin(&HomeAt) {
            Ok(list) => list.with_identities(fs),
            Err(e) => panic!("builtin failed: {e}"),
        };
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from(CACHES),
            logs: PathBuf::from(LOGS),
        };
        let ctx = ScanContext {
            fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days,
                user_paths: Vec::new(),
                // Every fixture entry was modified at day 100.
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(101 * DAY),
            },
            threads: Some(1),
        };
        match scan(rules, &ctx, &AtomicBool::new(false)) {
            Ok(report) => report,
            Err(e) => panic!("scan failed: {e}"),
        }
    }

    fn run(fs: &FakeFs, rules: &[&dyn Rule]) -> ScanReport {
        run_aged(fs, rules, 0)
    }

    /// Stable text form of the report, compared as a whole.
    fn render(report: &ScanReport) -> String {
        let mut out = String::new();
        for r in &report.rules {
            let _ = writeln!(
                out,
                "rule {} {:?} {:?} items={} bytes={}",
                r.rule, r.category, r.risk, r.items, r.allocated_bytes
            );
        }
        for i in &report.items {
            let _ = writeln!(
                out,
                "item {} {} bytes={} files={}",
                i.rule,
                i.path.display(),
                i.allocated_bytes,
                i.file_count
            );
        }
        for s in &report.skipped {
            let _ = writeln!(out, "skip {} {:?}", s.path.display(), s.reason);
        }
        let _ = writeln!(out, "total {}", report.total_bytes);
        out
    }

    /// Caches with three files (acceptance criterion 1), a nested app folder
    /// and a symlink to a big folder outside; Logs with a file and a folder.
    fn fixture() -> FakeFs {
        let mut fs = base();
        fs.insert(c("a.db"), file(1, 8))
            .insert(c("b.bin"), file(2, 16))
            .insert(c("c.tmp"), file(3, 4))
            .insert(c("com.example.app"), dir(4))
            .insert(c("com.example.app/blob"), file(5, 32))
            .insert(c("com.example.app/sub"), dir(6))
            .insert(c("com.example.app/sub/deep"), file(7, 2))
            .insert_symlink(c("link"), "/Users/Tester/big")
            .insert("/Users/Tester/big", dir(8))
            .insert("/Users/Tester/big/huge", file(9, 2_000_000))
            .insert(l("app.log"), file(10, 6))
            .insert(l("DiagnosticReports"), dir(11))
            .insert(l("DiagnosticReports/x.ips"), file(12, 10));
        fs
    }

    // FR-002, FR-003, FR-005: direct children are the items, nested entries
    // are inside their parent's size, the symlink target is never counted.
    #[test]
    fn caches_and_logs_report_snapshot() {
        let report = run(&fixture(), &[&USER_LOGS, &USER_CACHES]);
        let expected = "\
rule sys.logs Logs Low items=2 bytes=8192
rule sys.user-caches SystemCaches Low items=4 bytes=31744
item sys.logs /Users/Tester/Library/Logs/DiagnosticReports bytes=5120 files=1
item sys.logs /Users/Tester/Library/Logs/app.log bytes=3072 files=1
item sys.user-caches /Users/Tester/Library/Caches/a.db bytes=4096 files=1
item sys.user-caches /Users/Tester/Library/Caches/b.bin bytes=8192 files=1
item sys.user-caches /Users/Tester/Library/Caches/c.tmp bytes=2048 files=1
item sys.user-caches /Users/Tester/Library/Caches/com.example.app bytes=17408 files=2
skip /Users/Tester/Library/Caches/link Symlink
total 39936
";
        assert_eq!(render(&report), expected);
    }

    // Acceptance criterion 1 (FR-002, FR-003): 3 files in Caches = 3 items.
    #[test]
    fn three_cache_files_are_three_items() {
        let mut fs = base();
        fs.insert(c("a"), file(1, 8))
            .insert(c("b"), file(2, 8))
            .insert(c("c"), file(3, 8));
        let report = run(&fs, &[&USER_CACHES]);
        assert_eq!(report.items.len(), 3);
        assert_eq!(report.total_bytes, 24 * 512);
        assert!(report.skipped.is_empty());
    }

    // FR-008: `--rule sys.logs` alone reports only Logs.
    #[test]
    fn logs_alone_ignore_caches() {
        let report = run(&fixture(), &[&USER_LOGS]);
        assert!(report.items.iter().all(|i| i.path.starts_with(LOGS)));
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.rules.len(), 1);
    }

    // FR-002: the spec sets no minimum age for caches or logs, so a large
    // `min_age_days` hides nothing.
    #[test]
    fn min_age_days_does_not_filter() {
        let fs = fixture();
        let young = run_aged(&fs, &[&USER_LOGS, &USER_CACHES], 0);
        let old = run_aged(&fs, &[&USER_LOGS, &USER_CACHES], 365);
        assert_eq!(young, old);
    }

    // FR-007: a cache or log entry that is the same inode as protected data
    // (another name for the `.ssh` or the Keychains folder, e.g. a firmlink)
    // never becomes an item and is not counted.
    #[test]
    fn protected_entry_inside_caches_or_logs_is_never_an_item() {
        let mut fs = base();
        fs.insert("/Users/Tester/.ssh", dir(49))
            .insert("/Users/Tester/.ssh/id_ed25519", file(50, 8))
            .insert(c("ssh_alias"), dir(49))
            .insert(c("ssh_alias/id_ed25519"), file(50, 8))
            .insert("/Users/Tester/Library/Keychains", dir(51))
            .insert(l("kc"), dir(51))
            .insert(c("free"), file(52, 4));
        let report = run(&fs, &[&USER_LOGS, &USER_CACHES]);

        let paths: Vec<&Path> = report.items.iter().map(|i| i.path.as_path()).collect();
        assert_eq!(paths, vec![c("free").as_path()]);
        assert_eq!(report.total_bytes, 4 * 512);
        for p in [c("ssh_alias"), l("kc")] {
            assert!(
                report
                    .skipped
                    .iter()
                    .any(|s| s.path == p && s.reason == SkipReason::Protected),
                "{} not skipped as protected",
                p.display()
            );
        }
    }

    // FR-009 (silent missing root): no Logs folder means 0 items, no error.
    #[test]
    fn missing_root_gives_zero_items() {
        let mut fs = FakeFs::new();
        fs.insert("/Users", dir(100))
            .insert(HOME, dir(101))
            .insert("/Users/Tester/Library", dir(102));
        let report = run(&fs, &[&USER_LOGS, &USER_CACHES]);
        assert!(report.items.is_empty());
        assert!(report.skipped.is_empty());
        assert_eq!(report.rules.len(), 2);
    }

    // FR-002: ids, category, risk and roots as declared in the spec.
    #[test]
    fn metadata_matches_spec() {
        let ctx = RuleContext {
            min_age_days: 0,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH,
        };
        assert_eq!(USER_CACHES.meta().id.as_str(), "sys.user-caches");
        assert_eq!(USER_CACHES.meta().risk, Risk::Low);
        assert_eq!(USER_CACHES.meta().os, &[Os::Macos]);
        assert_eq!(
            USER_CACHES.roots(&ctx),
            vec![RootedPath::Under(Root::Caches, "")]
        );
        assert_eq!(USER_LOGS.meta().id.as_str(), "sys.logs");
        assert_eq!(USER_LOGS.meta().risk, Risk::Low);
        assert_eq!(USER_LOGS.meta().category, Category::Logs);
        assert_eq!(
            USER_LOGS.roots(&ctx),
            vec![RootedPath::Under(Root::Logs, "")]
        );
    }

    // FR-002, NFR-004, ADR 0005: with the whole registry, the bytes under
    // `~/Library/Caches/Homebrew` belong to the Homebrew rule only. The caches
    // rule keeps the outer folder as an item, measured without that subtree.
    #[test]
    fn homebrew_cache_is_not_counted_twice() {
        let mut fs = base();
        fs.insert(c("Homebrew"), meta(true, 20, 2, 8))
            .insert(c("Homebrew/bottle.tar.gz"), file(21, 64))
            .insert(c("other"), file(22, 16));
        let report = run(&fs, super::super::builtin());

        let owners: Vec<(&str, PathBuf, u64)> = report
            .items
            .iter()
            .map(|i| (i.rule.as_str(), i.path.clone(), i.allocated_bytes))
            .collect();
        assert_eq!(
            owners,
            vec![
                ("pkg.homebrew", c("Homebrew/bottle.tar.gz"), 64 * 512),
                ("sys.user-caches", c("Homebrew"), 8 * 512),
                ("sys.user-caches", c("other"), 16 * 512),
            ]
        );
        assert_eq!(report.total_bytes, (64 + 8 + 16) * 512);
    }
}
