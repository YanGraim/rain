//! `ai.claude-code.old-versions` against the real filesystem. Every
//! tree is built inside a tempdir under `CARGO_TARGET_TMPDIR`; nothing
//! outside it is touched.

// Building the fixtures needs create_dir/write/hard_link/symlink, which
// clippy.toml bans for the read-only scan code. Only the tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

const ID: &str = "ai.claude-code.old-versions";
const VERSIONS: &str = ".local/share/claude/versions";
const BIN: &str = ".local/bin/claude";

/// Built-in list with a home that cannot contain the tempdir.
struct UnrelatedHome;

impl Platform for UnrelatedHome {
    fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from("/nonexistent-rain-test-home"))
    }
    fn is_root_user(&self) -> bool {
        false
    }
    fn os(&self) -> Os {
        Os::Macos
    }
}

struct Home {
    _tmp: tempfile::TempDir,
    path: PathBuf,
}

impl Home {
    fn new() -> Home {
        let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let path = fs::canonicalize(tmp.path()).unwrap().join("home");
        fs::create_dir_all(path.join(VERSIONS)).unwrap();
        fs::create_dir_all(path.join(".local/bin")).unwrap();
        Home { _tmp: tmp, path }
    }
    fn version(&self, name: &str) {
        fs::write(self.path.join(VERSIONS).join(name), b"binary").unwrap();
    }
    fn versions(&self, names: &[&str]) {
        for n in names {
            self.version(n);
        }
    }
    /// `~/.local/bin/claude` -> `target` (as written, may be relative).
    fn link_bin(&self, target: impl AsRef<Path>) {
        symlink(target, self.path.join(BIN)).unwrap();
    }
    fn link_bin_to_version(&self, name: &str) {
        self.link_bin(self.path.join(VERSIONS).join(name));
    }
    fn found(&self) -> Vec<String> {
        let protect = ProtectList::builtin(&UnrelatedHome)
            .unwrap()
            .with_identities(&StdFs);
        let roots = ResolvedRoots {
            home: self.path.clone(),
            caches: self.path.join("Library/Caches"),
            logs: self.path.join("Library/Logs"),
        };
        let ctx = ScanContext {
            fs: &StdFs as &dyn Fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::now(),
            },
            threads: None,
            tools: &rain_core::tools::NoTools,
        };
        let selected = rules::select(&[ID]).unwrap();
        let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();
        let mut names: Vec<String> = report
            .items
            .iter()
            .map(|i| {
                assert_eq!(i.rule.as_str(), ID);
                i.path
                    .strip_prefix(self.path.join(VERSIONS))
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

// Spec 1: the target of the symlink and the highest version stay.
#[test]
fn lists_all_but_the_current_version() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.319", "2.1.321"]);
    h.link_bin_to_version("2.1.321");
    assert_eq!(h.found(), strs(&["2.1.318", "2.1.319"]));
}

// Spec 2: after a rollback the current one and the highest both stay.
#[test]
fn rollback_keeps_current_and_highest() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.319", "2.1.321"]);
    h.link_bin_to_version("2.1.319");
    assert_eq!(h.found(), strs(&["2.1.318"]));
}

// A relative symlink target resolves the same way.
#[test]
fn relative_symlink_target_is_resolved() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.321"]);
    h.link_bin("../share/claude/versions/2.1.321");
    assert_eq!(h.found(), strs(&["2.1.318"]));
}

// Spec 3: fail closed without a valid symlink.
#[test]
fn no_symlink_lists_nothing() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.319", "2.1.321"]);
    assert!(h.found().is_empty());
}

#[test]
fn broken_symlink_lists_nothing() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.321"]);
    h.link_bin_to_version("2.1.999");
    assert!(h.found().is_empty());
}

#[test]
fn symlink_outside_the_root_lists_nothing() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.321"]);
    let outside = h.path.join("elsewhere");
    fs::write(&outside, b"x").unwrap();
    h.link_bin(&outside);
    assert!(h.found().is_empty());
}

#[test]
fn symlink_to_the_root_itself_lists_nothing() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.321"]);
    h.link_bin(h.path.join(VERSIONS));
    assert!(h.found().is_empty());
}

#[test]
fn bin_that_is_not_a_symlink_lists_nothing() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.321"]);
    fs::write(h.path.join(BIN), b"binary").unwrap();
    assert!(h.found().is_empty());
}

// Symlink to a symlink in the root that points at an old binary: the
// resolved target is the one kept.
#[test]
fn chained_symlink_keeps_the_resolved_target() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.319", "2.1.321"]);
    symlink("2.1.319", h.path.join(VERSIONS).join("current")).unwrap();
    h.link_bin_to_version("current");
    assert_eq!(h.found(), strs(&["2.1.318"]));
}

// Spec 4: numeric comparison per component.
#[test]
fn compares_numerically_not_lexically() {
    let h = Home::new();
    h.versions(&["2.1.99", "2.1.100", "2.1.9"]);
    h.link_bin_to_version("2.1.9");
    assert_eq!(h.found(), strs(&["2.1.99"]));
}

// Spec 5: everything that is not a plain semver file is ignored.
#[test]
fn ignores_everything_but_plain_semver_files() {
    let h = Home::new();
    h.versions(&["2.1.319", "2.1.321"]);
    h.link_bin_to_version("2.1.321");
    let root = h.path.join(VERSIONS);
    // folder, hidden file, non semver names, partial downloads, lock
    fs::create_dir(root.join("2.1.317")).unwrap();
    h.versions(&[
        ".2.1.316",
        "2.1.315.tmp",
        "2.1.314.lock",
        "2.1",
        "2.1.x",
        "v2.1.313",
        "2.1.3-beta",
        "2.1.312.",
    ]);
    // symlink to a file with a valid name, and one pointing outside
    let outside = h.path.join("elsewhere");
    fs::write(&outside, b"x").unwrap();
    symlink(&outside, root.join("2.1.310")).unwrap();
    symlink("2.1.319", root.join("2.1.311")).unwrap();
    // hard link: nlink > 1, on both names
    h.version("2.1.308");
    fs::hard_link(root.join("2.1.308"), root.join("2.1.309")).unwrap();
    // only the plain old file is listed
    assert_eq!(h.found(), strs(&["2.1.319"]));
}

// A symlink or a folder with a high version does not count as "highest".
#[test]
fn non_files_do_not_become_the_highest_version() {
    let h = Home::new();
    h.versions(&["2.1.318", "2.1.319", "2.1.321"]);
    h.link_bin_to_version("2.1.321");
    let root = h.path.join(VERSIONS);
    fs::create_dir(root.join("9.9.9")).unwrap();
    symlink("2.1.321", root.join("8.8.8")).unwrap();
    assert_eq!(h.found(), strs(&["2.1.318", "2.1.319"]));
}

// Leading zeros give the same numeric version: both spellings of the
// highest one stay, and neither is ever listed in place of the other.
#[test]
fn leading_zero_spelling_of_the_highest_is_kept() {
    let h = Home::new();
    h.versions(&["2.1.4", "02.1.5", "2.1.5"]);
    h.link_bin_to_version("2.1.4");
    assert!(h.found().is_empty());
    let h = Home::new();
    h.versions(&["2.1.4", "02.1.5", "2.1.5"]);
    h.link_bin_to_version("02.1.5");
    assert_eq!(h.found(), strs(&["2.1.4"]));
}

// A single installed version is never listed.
#[test]
fn single_version_is_kept() {
    let h = Home::new();
    h.version("2.1.321");
    h.link_bin_to_version("2.1.321");
    assert!(h.found().is_empty());
}

// Missing root: silent.
#[test]
fn missing_root_is_silent() {
    let h = Home::new();
    fs::remove_dir_all(h.path.join(".local")).unwrap();
    assert!(h.found().is_empty());
}

// Medium, never preselected, no app to close, same category as the
// other Claude Code rules.
#[test]
fn meta_is_medium_not_default() {
    let m = rules::select(&[ID]).unwrap()[0].meta().clone();
    assert_eq!(m.risk, rain_core::model::Risk::Medium);
    assert!(!m.default_selected);
    assert_eq!(m.requires_app_closed, None);
    let cache = rules::select(&["ai.claude-code.cache"]).unwrap()[0]
        .meta()
        .clone();
    assert_eq!(m.category, cache.category);
}
