//! `sys.sensitive-caches` against the real filesystem. The fixture
//! `fixtures/sys/sensitive` (a fake home) is copied into a tempdir under
//! `CARGO_TARGET_TMPDIR`; nothing outside it is touched.

// Copying the fixture needs create_dir/copy, which clippy.toml bans for the
// read-only scan code. Only the tempdir is written.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::model::{Risk, ScanReport};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::{Rule, RuleContext};
use rain_core::rules;
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

const SENSITIVE: &str = "sys.sensitive-caches";
const USER: &str = "sys.user-caches";

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

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// Scans a copy of the fixture home with `ids`; returns sorted
/// (rule, path under Caches) and the report.
fn scan_fixture(ids: &[&str]) -> (Vec<(String, String)>, ScanReport) {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let base = fs::canonicalize(tmp.path()).unwrap();
    let home = base.join("home");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys/sensitive");
    copy_tree(&fixture, &home);
    let caches = home.join("Library/Caches");

    let protect = ProtectList::builtin(&UnrelatedHome)
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: home.clone(),
        caches: caches.clone(),
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
    let selected = rules::select(ids).unwrap();
    let report = scan(&selected, &ctx, &AtomicBool::new(false)).unwrap();
    let mut got: Vec<(String, String)> = report
        .items
        .iter()
        .map(|i| {
            let rel = i.path.strip_prefix(&caches).unwrap();
            (
                i.rule.as_str().to_string(),
                rel.to_string_lossy().into_owned(),
            )
        })
        .collect();
    got.sort();
    (got, report)
}

fn sensitive_rule() -> &'static dyn Rule {
    rules::select(&[SENSITIVE]).unwrap()[0]
}

// FR-014, FR-044, acceptance criterion 14a: PassKit is listed by the
// sensitive rule as high and never by the generic caches rule.
#[test]
fn passkit_cache_is_high_not_in_user_caches() {
    let (got, _) = scan_fixture(&[SENSITIVE, USER]);
    assert!(
        got.contains(&(SENSITIVE.into(), "PassKit".into())),
        "{got:?}"
    );
    assert!(!got
        .iter()
        .any(|(r, p)| r == USER && p.starts_with("PassKit")));
    assert_eq!(sensitive_rule().meta().risk, Risk::High);
}

// FR-014, FR-044: high risk and never preselected.
#[test]
fn sensitive_caches_never_default_selected() {
    let meta = sensitive_rule().meta();
    assert!(!meta.default_selected);
    assert_eq!(meta.risk, Risk::High);
}

// FR-044: the list reviewed by `seguranca`. Every entry goes to the
// sensitive rule as one item; the generic rule keeps only ordinary caches.
#[test]
fn sensitive_list_reviewed() {
    let (got, _) = scan_fixture(&[SENSITIVE, USER]);
    let mut want: Vec<(String, String)> = [
        (SENSITIVE, "FamilyCircle"),
        (SENSITIVE, "PassKit"),
        (SENSITIVE, "com.apple.HomeKit"),
        (SENSITIVE, "com.apple.akd"),
        (SENSITIVE, "com.apple.amsaccountsd"),
        (SENSITIVE, "com.apple.appleaccountd"),
        (SENSITIVE, "com.apple.icloudmailagent"),
        (SENSITIVE, "com.apple.passd"),
        (USER, "com.example.app"),
    ]
    .iter()
    .map(|(r, p)| ((*r).to_string(), (*p).to_string()))
    .collect();
    want.sort();
    assert_eq!(got, want);
}

// NFR-005: the rule never lists what the protect list protects.
#[test]
fn sensitive_caches_passes_testkit() {
    rain_core::testkit::assert_rule_protects(sensitive_rule());
}
