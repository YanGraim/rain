//! The rustup rule against the real filesystem: its settings file is read
//! through the real, bounded reader, and a settings file that is a symlink is
//! not read. Everything lives in a tempdir under `CARGO_TARGET_TMPDIR`;
//! nothing outside it is touched.

// Building the tree needs create_dir/write/symlink, which clippy.toml bans for
// the read-only scan code. Only the tempdir is written.
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

const ARM: &str = "aarch64-apple-darwin";

struct HomeAt(PathBuf);

impl Platform for HomeAt {
    fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
        Ok(self.0.clone())
    }
    fn is_root_user(&self) -> bool {
        false
    }
    fn os(&self) -> Os {
        Os::Macos
    }
}

/// A home with the toolchains of a developer, `stable` being the default.
fn home() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    for name in [
        format!("stable-{ARM}"),
        format!("1.75.0-{ARM}"),
        format!("1.90.0-{ARM}"),
    ] {
        let dir = home.join(".rustup/toolchains").join(name);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin/rustc"), b"x").unwrap();
    }
    (tmp, home)
}

fn settings(home: &Path, text: &str) {
    fs::write(home.join(".rustup/settings.toml"), text).unwrap();
}

fn listed(home: &Path) -> Vec<String> {
    let protect = ProtectList::builtin(&HomeAt(home.to_path_buf()))
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: home.to_path_buf(),
        caches: home.join("Library/Caches"),
        logs: home.join("Library/Logs"),
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
    let selected = rules::select(&["pkg.rustup"]).unwrap();
    let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();
    let mut names: Vec<String> = report
        .items
        .iter()
        .filter_map(|i| i.path.file_name()?.to_str().map(str::to_owned))
        .collect();
    names.sort();
    names
}

// The default is kept and the rest is listed.
#[test]
fn toolchains_other_than_the_default_are_listed() {
    let (_tmp, home) = home();
    settings(
        &home,
        &format!("version = \"12\"\ndefault_toolchain = \"stable-{ARM}\"\nprofile = \"default\"\n\n[overrides]\n\"/work\" = \"1.75.0-{ARM}\"\n"),
    );
    assert_eq!(listed(&home), [format!("1.90.0-{ARM}")]);
}

// Without a settings file nothing is known to be in use: nothing is listed.
#[test]
fn no_settings_file_lists_nothing() {
    let (_tmp, home) = home();
    assert!(listed(&home).is_empty());
}

// A settings file that is a symlink is not followed, even to a good file.
#[test]
fn a_symlinked_settings_file_lists_nothing() {
    let (_tmp, home) = home();
    let real = home.join("settings-elsewhere.toml");
    fs::write(
        &real,
        format!("default_toolchain = \"stable-{ARM}\"\n[overrides]\n"),
    )
    .unwrap();
    symlink(&real, home.join(".rustup/settings.toml")).unwrap();
    assert!(listed(&home).is_empty());
}

// A settings file larger than the limit is not used.
#[test]
fn an_oversized_settings_file_lists_nothing() {
    let (_tmp, home) = home();
    let mut text = format!("default_toolchain = \"stable-{ARM}\"\n[overrides]\n");
    text.push_str(&"# padding\n".repeat(10_000));
    settings(&home, &text);
    assert!(listed(&home).is_empty());
}
