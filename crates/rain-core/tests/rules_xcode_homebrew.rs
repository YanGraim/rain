//! Xcode DerivedData and Homebrew cache rules against the real filesystem,
//! with a fake home built from `fixtures/xcode_homebrew.txt` inside a
//! tempdir under `CARGO_TARGET_TMPDIR`. Nothing outside it is touched.

// Building the fixture needs create_dir/write, which clippy.toml bans for the
// read-only scan code. Writes stay in the tempdir; the scan goes through `Fs`.
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

const FIXTURE: &str = include_str!("fixtures/xcode_homebrew.txt");

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

fn build(home: &Path) {
    for line in FIXTURE
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (rel, size) = line.rsplit_once(' ').unwrap();
        let path = home.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, vec![1u8; size.parse().unwrap()]).unwrap();
    }
}

fn allocated(fs: &StdFs, path: &Path) -> u64 {
    fs.symlink_metadata(path).unwrap().blocks * 512
}

// FR-002, FR-003, FR-005, FR-007, ADR 0005: with the builtin registry, each
// DerivedData and Homebrew child is one item, sibling caches and `~/.ssh` are
// not, and a symlink to `~/.ssh` inside DerivedData is never followed.
#[test]
fn fixture_items_for_xcode_and_homebrew() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    build(&home);
    let dd = home.join("Library/Developer/Xcode/DerivedData");
    let brew = home.join("Library/Caches/Homebrew");
    symlink(home.join(".ssh"), dd.join("keys")).unwrap();

    let real = StdFs;
    let protect = ProtectList::builtin(&HomeAt(home.clone()))
        .unwrap()
        .with_identities(&real);
    let roots = ResolvedRoots {
        home: home.clone(),
        caches: home.join("Library/Caches"),
        logs: home.join("Library/Logs"),
    };
    let ctx = ScanContext {
        fs: &real,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: 0,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH,
        },
        threads: Some(2),
    };
    let selected = rules::select(&["apple.derived-data", "pkg.homebrew"]).unwrap();
    let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();

    let got: Vec<_> = report
        .items
        .iter()
        .map(|i| (i.rule.as_str(), i.path.clone(), i.file_count))
        .collect();
    assert_eq!(
        got,
        vec![
            ("apple.derived-data", dd.join("App-abc"), 2),
            ("apple.derived-data", dd.join("Lib-def"), 1),
            ("pkg.homebrew", brew.join("downloads"), 1),
            ("pkg.homebrew", brew.join("git--2.4.bottle.tar.gz"), 1),
        ]
    );
    let expected: u64 = [
        brew.join("downloads/abc--wget.bottle.tar.gz"),
        brew.join("git--2.4.bottle.tar.gz"),
        dd.join("App-abc/Build/Products/app.o"),
        dd.join("App-abc/info.plist"),
        dd.join("Lib-def/Index/store"),
    ]
    .iter()
    .map(|p| allocated(&real, p))
    .sum();
    // Directory blocks are counted too, so the files set a lower bound.
    assert!(report.total_bytes >= expected);
    assert_eq!(
        report.total_bytes,
        report.items.iter().map(|i| i.allocated_bytes).sum::<u64>()
    );
    assert!(report.skipped.iter().any(|s| s.path == dd.join("keys")));
    assert!(!report
        .skipped
        .iter()
        .any(|s| s.path.starts_with(home.join(".ssh"))));
}
