//! #83, NFR-002: the full catalogue scan of a large synthetic home finishes
//! well inside the limit. The tree is built in a tempdir under
//! `CARGO_TARGET_TMPDIR` and nothing outside it is touched. The limit is the
//! NFR's 60 s while the scan takes a few seconds, so the margin is wide and
//! the test only fails for a real blow-up (a quadratic walk, a loop), not for
//! a slow CI runner. The real-machine measurement is in the handoff.

// Building the tree needs create_dir/write, which clippy.toml bans for the
// read-only scan code. Only the tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime};

/// NFR-002.
const LIMIT: Duration = Duration::from_secs(60);

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

/// `count` small files named `f0..` in `dir`.
fn files(dir: &Path, count: usize) {
    fs::create_dir_all(dir).unwrap();
    for i in 0..count {
        fs::write(dir.join(format!("f{i}")), b"x").unwrap();
    }
}

/// A home shaped like a developer's: many app caches and logs, package
/// manager caches, projects with `node_modules` and `target`, editor
/// extensions and AI tool folders. About 12,000 files.
fn build_home(home: &Path) -> usize {
    let mut total = 0;
    let mut add = |dir: PathBuf, n: usize| {
        files(&dir, n);
        total += n;
    };
    for app in 0..250 {
        add(
            home.join(format!("Library/Caches/com.example.app{app}/data")),
            25,
        );
    }
    for log in 0..60 {
        add(home.join(format!("Library/Logs/app{log}")), 10);
    }
    for shard in 0..40 {
        add(
            home.join(format!(".npm/_cacache/content-v2/sha512/{shard:02x}")),
            30,
        );
    }
    for p in 0..60 {
        let project = home.join(format!("code/proj{p}"));
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("package.json"), b"{}").unwrap();
        fs::write(project.join("Cargo.toml"), b"").unwrap();
        add(project.join("node_modules/dep/lib"), 30);
        add(project.join("target/debug/deps"), 30);
    }
    for v in 0..20 {
        add(home.join(format!(".vscode/extensions/pub.ext-1.{v}.0")), 10);
    }
    add(home.join(".claude/cache"), 50);
    add(home.join(".cache/uv/wheels"), 100);
    add(
        home.join("Library/Developer/Xcode/DerivedData/App-abc/Build"),
        100,
    );
    total
}

#[test]
fn full_scan_of_a_large_home_is_well_inside_the_limit() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap().join("home");
    let built = build_home(&home);

    let protect = ProtectList::builtin(&HomeAt(home.clone()))
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: home.clone(),
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

    let started = Instant::now();
    let report = scan(rules::builtin(), &ctx, &AtomicBool::new(false)).unwrap();
    let took = started.elapsed();
    println!(
        "full scan of {built} files: {took:?} ({} items)",
        report.items.len()
    );

    // The scan really did the work: caches, logs and package caches were found.
    assert!(report.items.len() > 300, "{} items", report.items.len());
    assert!(report.total_bytes > 0);
    assert!(
        took < LIMIT,
        "full scan took {took:?}, the limit is {LIMIT:?}"
    );
}
