//! Build artifacts of inactive projects (FR-016).

use super::project::ProjectArtifact;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{Rule, RuleMeta};
use rain_platform::Os;

/// `proj.rust-target`: a Cargo `target/` beside a regular `Cargo.toml`.
pub static RUST_TARGET: ProjectArtifact = ProjectArtifact {
    meta: RuleMeta {
        id: RuleId::new("proj.rust-target"),
        category: Category::Projects,
        risk: Risk::Low,
        name_key: "rule.proj.rust-target",
        consequence_key: "rule.proj.rust-target.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    dir_name: "target",
    marker: "Cargo.toml",
    // FR-016: takes `--min-age-days` (30 by default).
    min_age_days: None,
    age_walk_budget: 200_000,
};

pub(super) static RULES: &[&dyn Rule] = &[&RUST_TARGET];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FakeFs, Fs, Metadata};
    use crate::protect::ProtectList;
    use crate::rule::{EntryInfo, FileRule, RuleContext, Visit};
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, SystemTime};

    const DAY: u64 = 86_400;

    struct HomeAt;

    impl Platform for HomeAt {
        fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
            Ok(PathBuf::from("/h"))
        }
        fn is_root_user(&self) -> bool {
            false
        }
        fn os(&self) -> Os {
            Os::Macos
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000 * DAY)
    }

    fn aged(is_dir: bool, ino: u64, days: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink: 1,
            blocks: 0,
            len: 0,
            mtime: now() - Duration::from_secs(days * DAY),
        }
    }

    fn project(days: u64) -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/h", aged(true, 1, 200))
            .insert("/h/p", aged(true, 2, days))
            .insert("/h/p/target", aged(true, 3, 0))
            .insert("/h/p/target/debug", aged(false, 4, 0))
            .insert("/h/p/src.rs", aged(false, 5, days));
        fs
    }

    fn visit(fs: &FakeFs) -> Visit {
        let protect = ProtectList::builtin(&HomeAt).unwrap();
        let cancel = AtomicBool::new(false);
        let path = Path::new("/h/p/target");
        let meta = fs.symlink_metadata(path).unwrap();
        let entry = EntryInfo {
            path,
            meta: &meta,
            protect: &protect,
            cancel: &cancel,
        };
        // FR-016: the default inactivity limit is 30 days.
        let ctx = RuleContext {
            min_age_days: 30,
            user_paths: Vec::new(),
            now: now(),
        };
        RUST_TARGET.visit(&entry, 1, &ctx, fs)
    }

    // FR-016
    #[test]
    fn target_without_cargo_toml_ignored() {
        assert_eq!(visit(&project(90)), Visit::Skip);
    }

    // FR-016
    #[test]
    fn recent_rust_project_ignored() {
        let mut fs = project(5);
        fs.insert("/h/p/Cargo.toml", aged(false, 6, 5));
        assert_eq!(visit(&fs), Visit::Skip);
    }

    // FR-016, section 6.7
    #[test]
    fn project_90_days_listed() {
        let mut fs = project(90);
        fs.insert("/h/p/Cargo.toml", aged(false, 6, 90));
        assert_eq!(visit(&fs), Visit::Candidate);
        let meta = RUST_TARGET.meta();
        assert_eq!(meta.risk, Risk::Low);
        assert!(meta.default_selected);
        assert!(RULES
            .iter()
            .any(|r| r.meta().id.as_str() == "proj.rust-target"));
    }

    mod fixture {
        use super::super::RUST_TARGET;
        use super::{now, DAY};
        use crate::fs::{FakeFs, Metadata};
        use crate::model::{SkipReason, Skipped};
        use crate::planner::{scan, ResolvedRoots, ScanContext};
        use crate::protect::ProtectList;
        use crate::rule::RuleContext;
        use rain_platform::{Os, Platform, PlatformError, Root};
        use std::path::{Path, PathBuf};
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        const HOME: &str = "/Users/Tester";
        const FIXTURE: &str = include_str!("../../tests/fixtures/dev_rust_target.txt");

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

        fn h(rel: &str) -> PathBuf {
            Path::new(HOME).join(rel)
        }

        fn entry(kind: &str, ino: u64, days: u64) -> Metadata {
            let is_dir = kind == "d";
            Metadata {
                is_dir,
                is_symlink: kind == "l",
                dev: 1,
                ino,
                nlink: if is_dir { 2 } else { 1 },
                blocks: if kind == "f" { 8 } else { 0 },
                len: if kind == "f" { 4096 } else { 0 },
                mtime: now() - Duration::from_secs(days * DAY),
            }
        }

        fn load() -> FakeFs {
            let mut fs = FakeFs::new();
            fs.insert("/Users", entry("d", 1, 900))
                .insert(HOME, entry("d", 2, 900));
            for (n, line) in FIXTURE.lines().map(str::trim).enumerate() {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.splitn(3, ' ');
                let (kind, days, rel) = (
                    parts.next().unwrap(),
                    parts.next().unwrap().parse().unwrap(),
                    parts.next().unwrap(),
                );
                assert!(matches!(kind, "d" | "f" | "l"), "bad line: {line}");
                fs.insert(h(rel), entry(kind, 10 + n as u64, days));
            }
            fs
        }

        // FR-016, FR-005, FR-007: of the whole fixture, only the inactive
        // project's outer target is listed.
        #[test]
        fn full_scan_lists_only_inactive_project_target() {
            let fs = load();
            let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
            let roots = ResolvedRoots {
                home: h(""),
                caches: h("Library/Caches"),
                logs: h("Library/Logs"),
            };
            let ctx = ScanContext {
                fs: &fs,
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
            let report = scan(&[&RUST_TARGET], &ctx, &AtomicBool::new(false)).unwrap();
            let listed: Vec<PathBuf> = report.items.iter().map(|i| i.path.clone()).collect();
            assert_eq!(listed, vec![h("code/old/target")]);
            // Outer target holds 3 files of 8 blocks, nested one included once.
            assert_eq!(report.items[0].allocated_bytes, 3 * 8 * 512);
            assert!(report.skipped.contains(&Skipped {
                path: h("Documents"),
                reason: SkipReason::Protected,
            }));
        }
    }
}
