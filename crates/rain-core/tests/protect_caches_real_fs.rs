// FR-043
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::model::SkipReason;
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

const NAMES: [&str; 3] = ["CloudKit", "com.apple.bird", "docker-secrets-engine"];

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

// FR-043
#[test]
fn user_caches_skips_protected_caches_on_real_fs() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap();
    let caches = home.join("Library").join("Caches");
    for name in NAMES {
        fs::create_dir_all(caches.join(name)).unwrap();
        fs::write(caches.join(name).join("secret.db"), b"secret").unwrap();
    }
    fs::write(caches.join("free"), b"free").unwrap();

    let protect = ProtectList::builtin(&HomeAt(home.clone()))
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: home.clone(),
        caches: caches.clone(),
        logs: home.join("Library").join("Logs"),
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
    };
    let selected = rules::select(&["sys.user-caches"]).unwrap();
    let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();

    let paths: Vec<&Path> = report.items.iter().map(|i| i.path.as_path()).collect();
    assert_eq!(paths, vec![caches.join("free").as_path()]);
    let sum: u64 = report.items.iter().map(|i| i.allocated_bytes).sum();
    assert_eq!(report.total_bytes, sum);
    for name in NAMES {
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path == caches.join(name) && s.reason == SkipReason::Protected),
            "{name} not skipped as protected"
        );
    }
}
