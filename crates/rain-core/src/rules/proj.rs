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
    dir_names: &["target"],
    marker: Some("Cargo.toml"),
    inner_marker: None,
    // FR-016: takes `--min-age-days` (30 by default).
    min_age_days: None,
    age_walk_budget: 200_000,
};

/// `proj.venv`: a `.venv` or `venv` (the names the Python docs call
/// conventional) that holds a regular `pyvenv.cfg`, the file `python -m venv`
/// places in the environment. Without it the folder is not an environment.
pub static VENV: ProjectArtifact = ProjectArtifact {
    meta: RuleMeta {
        id: RuleId::new("proj.venv"),
        category: Category::Projects,
        risk: Risk::Medium,
        name_key: "rule.proj.venv",
        consequence_key: "rule.proj.venv.consequence",
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    dir_names: &[".venv", "venv"],
    marker: None,
    inner_marker: Some("pyvenv.cfg"),
    min_age_days: None,
    age_walk_budget: 200_000,
};

/// `proj.build-dist`: a `dist/` (Vite's default output folder) beside a
/// regular `package.json`. Other build folders (`build`, `.next`, `.turbo`)
/// wait for a source.
pub static BUILD_DIST: ProjectArtifact = ProjectArtifact {
    meta: RuleMeta {
        id: RuleId::new("proj.build-dist"),
        category: Category::Projects,
        risk: Risk::Medium,
        name_key: "rule.proj.build-dist",
        consequence_key: "rule.proj.build-dist.consequence",
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    dir_names: &["dist"],
    marker: Some("package.json"),
    inner_marker: None,
    min_age_days: None,
    age_walk_budget: 200_000,
};

pub(super) static RULES: &[&dyn Rule] = &[&RUST_TARGET, &VENV, &BUILD_DIST];

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

    mod venv_dist {
        use super::super::{BUILD_DIST, RULES, VENV};
        use super::{now, DAY};
        use crate::fs::{FakeFs, Metadata};
        use crate::model::Risk;
        use crate::planner::{scan, ResolvedRoots, ScanContext};
        use crate::protect::ProtectList;
        use crate::rule::{Rule, RuleContext};
        use rain_platform::{Os, Platform, PlatformError, Root};
        use std::path::{Path, PathBuf};
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        const HOME: &str = "/Users/Tester";

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

        /// `d` folder, `f` file, `l` symlink; the age is in days.
        fn load(lines: &[(&str, u64, &str)]) -> FakeFs {
            let md = |kind: &str, ino: u64, days: u64| Metadata {
                is_dir: kind == "d",
                is_symlink: kind == "l",
                dev: 1,
                ino,
                nlink: if kind == "d" { 2 } else { 1 },
                blocks: u64::from(kind == "f") * 8,
                len: 0,
                mtime: now() - Duration::from_secs(days * DAY),
            };
            let mut fs = FakeFs::new();
            fs.insert("/Users", md("d", 1, 900))
                .insert(HOME, md("d", 2, 900));
            for (n, (kind, days, rel)) in lines.iter().enumerate() {
                fs.insert(Path::new(HOME).join(rel), md(kind, 10 + n as u64, *days));
            }
            fs
        }

        fn listed(fs: &FakeFs, rule: &'static dyn Rule) -> Vec<String> {
            let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
            let roots = ResolvedRoots {
                home: PathBuf::from(HOME),
                caches: Path::new(HOME).join("Library/Caches"),
                logs: Path::new(HOME).join("Library/Logs"),
            };
            let ctx = ScanContext {
                fs,
                protect: &protect,
                roots: &roots,
                rule_ctx: RuleContext {
                    min_age_days: 30,
                    user_paths: Vec::new(),
                    now: now(),
                },
                tools: &crate::tools::NoTools,
                threads: Some(1),
            };
            let report = scan(&[rule], &ctx, &AtomicBool::new(false)).unwrap();
            let mut out: Vec<String> = report
                .items
                .iter()
                .filter_map(|i| i.path.strip_prefix(HOME).ok()?.to_str().map(str::to_owned))
                .collect();
            out.sort();
            out
        }

        fn dist_project(marker: bool, days: u64) -> FakeFs {
            let mut lines = vec![
                ("d", days, "p"),
                ("d", 0, "p/dist"),
                ("f", 0, "p/dist/index.js"),
                ("f", days, "p/src.ts"),
            ];
            if marker {
                lines.push(("f", days, "p/package.json"));
            }
            load(&lines)
        }

        // FR-016
        #[test]
        fn dist_without_package_json_ignored() {
            assert!(listed(&dist_project(false, 90), &BUILD_DIST).is_empty());
        }

        // FR-016
        #[test]
        fn dist_of_an_inactive_js_project_listed_and_recent_one_ignored() {
            assert_eq!(listed(&dist_project(true, 90), &BUILD_DIST), ["p/dist"]);
            assert!(listed(&dist_project(true, 5), &BUILD_DIST).is_empty());
        }

        // Every npm package has a `package.json` and many a `dist/`: the
        // dependencies of a project are never projects of their own.
        #[test]
        fn dist_inside_node_modules_is_not_listed() {
            let fs = load(&[
                ("d", 90, "p"),
                ("d", 0, "p/node_modules"),
                ("d", 400, "p/node_modules/lib"),
                ("f", 400, "p/node_modules/lib/package.json"),
                ("d", 400, "p/node_modules/lib/dist"),
                ("d", 90, "q"),
                ("f", 90, "q/package.json"),
                ("d", 0, "q/dist"),
            ]);
            assert_eq!(listed(&fs, &BUILD_DIST), ["q/dist"]);
        }

        // Only `dist` is named: other build folders have no source yet.
        #[test]
        fn build_dist_lists_only_dist() {
            let fs = load(&[
                ("d", 90, "p"),
                ("f", 90, "p/package.json"),
                ("d", 90, "p/dist"),
                ("d", 90, "p/build"),
                ("d", 90, "p/.next"),
                ("d", 90, "p/.turbo"),
                ("d", 90, "p/out"),
            ]);
            assert_eq!(listed(&fs, &BUILD_DIST), ["p/dist"]);
        }

        // FR-014, FR-016
        #[test]
        fn venv_is_medium() {
            for rule in [&VENV as &dyn Rule, &BUILD_DIST] {
                let m = rule.meta();
                assert_eq!(m.risk, Risk::Medium, "{}", m.id.as_str());
                assert!(!m.default_selected, "{}", m.id.as_str());
                assert_eq!(m.os, &[Os::Macos]);
            }
            for id in ["proj.venv", "proj.build-dist"] {
                assert!(RULES.iter().any(|r| r.meta().id.as_str() == id), "{id}");
            }
        }

        // FR-016: a `.venv` or `venv` that holds a regular `pyvenv.cfg`.
        #[test]
        fn venv_of_an_inactive_project_listed_by_either_name() {
            for name in [".venv", "venv"] {
                let fs = load(&[
                    ("d", 90, "p"),
                    ("f", 90, "p/app.py"),
                    ("d", 0, &format!("p/{name}")),
                    ("f", 0, &format!("p/{name}/pyvenv.cfg")),
                    ("d", 0, &format!("p/{name}/lib")),
                ]);
                assert_eq!(listed(&fs, &VENV), [format!("p/{name}")], "{name}");
            }
        }

        #[test]
        fn venv_needs_a_regular_pyvenv_cfg() {
            for cfg in [None, Some("d"), Some("l")] {
                let mut lines = vec![
                    ("d", 90, "p"),
                    ("f", 90, "p/app.py"),
                    ("d", 0, "p/venv"),
                    ("f", 0, "p/venv/bin-python"),
                ];
                if let Some(kind) = cfg {
                    lines.push((kind, 0, "p/venv/pyvenv.cfg"));
                }
                assert!(listed(&load(&lines), &VENV).is_empty(), "{cfg:?}");
            }
        }

        #[test]
        fn recent_project_venv_ignored() {
            let fs = load(&[
                ("d", 5, "p"),
                ("f", 5, "p/app.py"),
                ("d", 0, "p/.venv"),
                ("f", 0, "p/.venv/pyvenv.cfg"),
            ]);
            assert!(listed(&fs, &VENV).is_empty());
        }

        // Hidden folders are tool internals: only the artifact name itself is
        // let through, and a venv inside a venv is part of the outer one.
        #[test]
        fn hidden_folders_are_not_entered_and_nested_venvs_not_listed() {
            let fs = load(&[
                ("d", 900, ".cache"),
                ("d", 90, ".cache/p"),
                ("d", 0, ".cache/p/.venv"),
                ("f", 0, ".cache/p/.venv/pyvenv.cfg"),
                ("d", 90, "p"),
                ("d", 0, "p/.venv"),
                ("f", 0, "p/.venv/pyvenv.cfg"),
                ("d", 0, "p/.venv/inner"),
                ("d", 0, "p/.venv/inner/venv"),
                ("f", 0, "p/.venv/inner/venv/pyvenv.cfg"),
            ]);
            assert_eq!(listed(&fs, &VENV), ["p/.venv"]);
        }

        // FR-004: a project is active while any file outside the artifact is
        // recent, e.g. a notebook beside the venv.
        #[test]
        fn recent_file_beside_the_venv_keeps_the_project_active() {
            let fs = load(&[
                ("d", 90, "p"),
                ("f", 2, "p/notes.ipynb"),
                ("d", 0, "p/.venv"),
                ("f", 0, "p/.venv/pyvenv.cfg"),
            ]);
            assert!(listed(&fs, &VENV).is_empty());
        }
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
