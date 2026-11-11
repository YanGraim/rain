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
}
