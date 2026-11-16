//! #139 against the real filesystem: the version an editor has registered in
//! `extensions.json` stays, and an `extensions.json` that cannot be trusted
//! (a symlink, too large) changes nothing. Everything lives in a tempdir under
//! `CARGO_TARGET_TMPDIR`; nothing outside it is touched.

// Building the fixture needs create_dir/write/symlink, which clippy.toml bans
// for the read-only scan code. Only the tempdir is written.
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

const ID: &str = "ai.vscode.old-extensions";

/// The tempdir is the home.
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

struct Editor {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    root: PathBuf,
}

impl Editor {
    /// `p.e` at 1.0.0, 1.1.0 and 2.0.0 under `~/.vscode/extensions`.
    fn new() -> Editor {
        let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let home = fs::canonicalize(tmp.path()).unwrap().join("home");
        let root = home.join(".vscode/extensions");
        for v in ["1.0.0", "1.1.0", "2.0.0"] {
            let dir = root.join(format!("p.e-{v}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("a.js"), b"x").unwrap();
        }
        Editor {
            _tmp: tmp,
            home,
            root,
        }
    }

    fn json(&self, content: &[u8]) {
        fs::write(self.root.join("extensions.json"), content).unwrap();
    }

    fn pin(folder: &str) -> Vec<u8> {
        format!(r#"[{{"relativeLocation":"{folder}"}}]"#).into_bytes()
    }

    /// The old versions the rule lists.
    fn listed(&self) -> Vec<String> {
        let protect = ProtectList::builtin(&HomeAt(self.home.clone()))
            .unwrap()
            .with_identities(&StdFs);
        let roots = ResolvedRoots {
            home: self.home.clone(),
            caches: self.home.join("Library/Caches"),
            logs: self.home.join("Library/Logs"),
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
            .filter_map(|i| {
                i.path
                    .strip_prefix(&self.root)
                    .ok()?
                    .to_str()
                    .map(str::to_owned)
            })
            .collect();
        names.sort();
        names
    }
}

const TODAY: &[&str] = &["p.e-1.0.0", "p.e-1.1.0"];

// The pinned older version stays; without the file the rule is as before.
#[test]
fn pinned_version_stays_on_a_real_filesystem() {
    let e = Editor::new();
    assert_eq!(e.listed(), TODAY);
    e.json(&Editor::pin("p.e-1.1.0"));
    assert_eq!(e.listed(), ["p.e-1.0.0"]);
    e.json(&Editor::pin("p.e-1.0.0"));
    assert_eq!(e.listed(), ["p.e-1.1.0"]);
}

// A symlinked `extensions.json` is not followed, even to a file that would
// keep a version.
#[test]
fn symlinked_extensions_json_is_ignored() {
    let e = Editor::new();
    let elsewhere: &Path = &e.home.join("elsewhere.json");
    fs::write(elsewhere, Editor::pin("p.e-1.1.0")).unwrap();
    symlink(elsewhere, e.root.join("extensions.json")).unwrap();
    assert_eq!(e.listed(), TODAY);
}

// A file over 1 MiB is not used (and not cut): the rule is as before, even
// if a pin sits at its start.
#[test]
fn oversized_extensions_json_is_ignored() {
    let e = Editor::new();
    let mut big = Editor::pin("p.e-1.1.0");
    big.extend(std::iter::repeat_n(b' ', 1024 * 1024));
    e.json(&big);
    assert_eq!(e.listed(), TODAY);
}

// A broken file and a folder with that name change nothing.
#[test]
fn broken_extensions_json_is_ignored() {
    let e = Editor::new();
    e.json(b"[{ not json");
    assert_eq!(e.listed(), TODAY);
    fs::remove_file(e.root.join("extensions.json")).unwrap();
    fs::create_dir(e.root.join("extensions.json")).unwrap();
    assert_eq!(e.listed(), TODAY);
}
