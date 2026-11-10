//! A build or dependency folder of an inactive project: the artifact named
//! `dir_name` beside a regular `marker` file, when nothing else in the
//! project changed for the inactivity age.

use crate::fs::Fs;
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::Root;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct ProjectArtifact {
    pub meta: RuleMeta,
    pub dir_name: &'static str,
    pub marker: &'static str,
    /// FR-009: `None` takes `--min-age-days` from the context.
    pub min_age_days: Option<u32>,
    pub age_walk_budget: usize,
}

const SECONDS_PER_DAY: u64 = 86_400;

impl Rule for ProjectArtifact {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for ProjectArtifact {
    /// FR-009: the `--path` roots, or the home when there are none.
    fn roots(&self, ctx: &RuleContext) -> Vec<RootedPath> {
        if ctx.user_paths.is_empty() {
            vec![RootedPath::Under(Root::Home, "")]
        } else {
            ctx.user_paths
                .iter()
                .cloned()
                .map(RootedPath::User)
                .collect()
        }
    }

    fn visit(&self, entry: &EntryInfo, depth: usize, ctx: &RuleContext, fs: &dyn Fs) -> Visit {
        if !entry.meta.is_dir {
            return Visit::Skip;
        }
        if depth == 0 {
            // A root inside an artifact could only offer nested ones.
            let inside = entry
                .path
                .components()
                .any(|c| c.as_os_str() == self.dir_name);
            return if inside { Visit::Skip } else { Visit::Descend };
        }
        let Some(name) = entry.path.file_name() else {
            return Visit::Skip;
        };
        if never_entered(name.as_encoded_bytes()) {
            return Visit::Skip;
        }
        if name != self.dir_name {
            return Visit::Descend;
        }
        // Never descend into an artifact: nested ones are already inside
        // the size of the outer one.
        match entry.path.parent() {
            Some(project)
                if self.has_marker(fs, project) && self.is_inactive(entry, project, ctx, fs) =>
            {
                Visit::Candidate
            }
            _ => Visit::Skip,
        }
    }
}

impl ProjectArtifact {
    /// A regular marker beside the artifact (not a link, not a folder).
    fn has_marker(&self, fs: &dyn Fs, project: &Path) -> bool {
        fs.symlink_metadata(&project.join(self.marker))
            .is_ok_and(|m| !m.is_dir && !m.is_symlink)
    }

    /// No entry of the project outside its artifacts was modified within
    /// the inactivity age. Anything that cannot be checked (unreadable,
    /// protected, future mtime) counts as active: a wrong answer must cost a
    /// candidate, never add one.
    /// A cancelled check is not a candidate either; the planner then sees the
    /// flag and drops the whole scan (FR-011).
    fn is_inactive(
        &self,
        entry: &EntryInfo,
        project: &Path,
        ctx: &RuleContext,
        fs: &dyn Fs,
    ) -> bool {
        let Age::Newest(newest) =
            newest_mtime(entry, project, fs, self.dir_name, self.age_walk_budget)
        else {
            return false;
        };
        let days = self.min_age_days.unwrap_or(ctx.min_age_days);
        let min_age = Duration::from_secs(u64::from(days) * SECONDS_PER_DAY);
        ctx.now
            .duration_since(newest)
            .is_ok_and(|age| age >= min_age)
    }
}

/// Hidden folders, `Library` and app bundles hold tool and app internals,
/// whose artifacts are not projects of the user.
fn never_entered(name: &[u8]) -> bool {
    name.starts_with(b".") || name == b"Library" || name.ends_with(b".app")
}

/// Outcome of the age check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Age {
    Newest(SystemTime),
    /// Could not be proven (read error, protected folder, over budget).
    Unknown,
    Cancelled,
}

/// Newest mtime in `project`, outside every folder named `dir_name` (their
/// content is generated, not project activity). Never follows symlinks
/// (FR-005), never leaves the volume (FR-006) and never enters a protected
/// folder (FR-007); meeting a protected folder, a read error or more than
/// `budget` entries gives [`Age::Unknown`]. Checks the cancel flag before
/// every listing (FR-011).
pub(super) fn newest_mtime(
    entry: &EntryInfo,
    project: &Path,
    fs: &dyn Fs,
    dir_name: &str,
    budget: usize,
) -> Age {
    let dev = entry.meta.dev;
    let Ok(root) = fs.symlink_metadata(project) else {
        return Age::Unknown;
    };
    let mut newest = root.mtime;
    let mut read = 0usize;
    let mut pending: Vec<PathBuf> = vec![project.to_path_buf()];
    while let Some(dir) = pending.pop() {
        if entry.cancel.load(Ordering::SeqCst) {
            return Age::Cancelled;
        }
        let Ok(children) = fs.read_dir(&dir) else {
            return Age::Unknown;
        };
        for child in children {
            if child.path.file_name().is_some_and(|n| n == dir_name) {
                continue;
            }
            read += 1;
            if read > budget {
                return Age::Unknown;
            }
            let Ok(meta) = fs.symlink_metadata(&child.path) else {
                return Age::Unknown;
            };
            newest = newest.max(meta.mtime);
            if !meta.is_dir || meta.is_symlink || meta.dev != dev {
                continue;
            }
            if entry.protect.is_protected_entry(&child.path, &meta) {
                return Age::Unknown;
            }
            pending.push(child.path);
        }
    }
    Age::Newest(newest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FakeFs, Fs, Metadata};
    use crate::model::{Category, Risk, RuleId};
    use crate::protect::ProtectList;
    use crate::rule::{EntryInfo, FileRule, RuleContext, RuleMeta, Visit};
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

    static TARGET: ProjectArtifact = ProjectArtifact {
        meta: RuleMeta {
            id: RuleId::new("test.target"),
            category: Category::Projects,
            risk: Risk::Medium,
            name_key: "rule.proj.node-modules",
            consequence_key: "rule.proj.node-modules.consequence",
            default_selected: false,
            requires_app_closed: None,
            os: &[Os::Macos],
        },
        dir_name: "target",
        marker: "Cargo.toml",
        min_age_days: Some(90),
        age_walk_budget: 1_000,
    };

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

    fn visit_target(fs: &FakeFs, ctx_days: u32, budget_rule: &ProjectArtifact) -> Visit {
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
        let ctx = RuleContext {
            min_age_days: ctx_days,
            user_paths: Vec::new(),
            now: now(),
        };
        budget_rule.visit(&entry, 1, &ctx, fs)
    }

    // FR-009: the artifact name, marker, own inactivity age and budget are data.
    #[test]
    fn artifact_uses_its_own_name_marker_age_and_budget() {
        let mut fs = FakeFs::new();
        fs.insert("/h", aged(true, 1, 200))
            .insert("/h/p", aged(true, 2, 100))
            .insert("/h/p/target", aged(true, 3, 0))
            .insert("/h/p/target/fresh", aged(false, 4, 0));
        assert_eq!(visit_target(&fs, 0, &TARGET), Visit::Skip);
        fs.insert("/h/p/Cargo.toml", aged(false, 5, 100));
        assert_eq!(visit_target(&fs, 0, &TARGET), Visit::Candidate);
        let tight = ProjectArtifact {
            age_walk_budget: 1,
            ..TARGET.clone()
        };
        fs.insert("/h/p/lib.rs", aged(false, 7, 100));
        assert_eq!(visit_target(&fs, 0, &tight), Visit::Skip);
        fs.insert("/h/p/src.rs", aged(false, 6, 60));
        assert_eq!(visit_target(&fs, 0, &TARGET), Visit::Skip);
    }
}
