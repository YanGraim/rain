//! Audit of `~/Library/Caches`: `sys.user-caches` lists every child, so each
//! child that holds state rather than cache must be kept out of it, either
//! protected or owned by the high, never preselected sensitive rule. The
//! table below is fixed on purpose: adding state to either list without
//! adding it here, or the other way round, fails the audit.

use super::select;
use crate::fs::{FakeFs, Metadata};
use crate::model::{ScanReport, SkipReason};
use crate::planner::{scan, ResolvedRoots, ScanContext};
use crate::protect::ProtectList;
use crate::rule::{RootedPath, RuleContext, RuleKind};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

const HOME: &str = "/Users/Tester";
const CACHES: &str = "/Users/Tester/Library/Caches";

/// Children of `~/Library/Caches` that hold state and are protected: the
/// scan reports them as skipped, never as candidates. The second field is a
/// path below the child that makes the fixture realistic.
const PROTECTED_STATE: &[(&str, &str)] = &[
    // iCloud and Docker.
    ("CloudKit", "CloudKit/db"),
    ("com.apple.bird", "com.apple.bird/db"),
    ("docker-secrets-engine", "docker-secrets-engine/key"),
    // Environments, not cache: the child is refused whole because it holds
    // a protected folder.
    ("pypoetry", "pypoetry/virtualenvs/proj/bin"),
    // hatch and pdm environments can be pointed at Caches by their config;
    // the child is refused whole, with or without an environment (see below).
    ("hatch", "hatch/env/proj/bin"),
    ("pdm", "pdm/venvs/proj/bin"),
    // Downloads in flight, kept by the system until they finish.
    (
        "com.apple.nsurlsessiond",
        "com.apple.nsurlsessiond/Downloads/part",
    ),
    // Password managers and wallets.
    ("com.1password.1password", "com.1password.1password/db"),
    (
        "com.agilebits.onepassword7",
        "com.agilebits.onepassword7/db",
    ),
    ("2BUA8C4S2C.com.1password", "2BUA8C4S2C.com.1password/db"),
    ("com.bitwarden.desktop", "com.bitwarden.desktop/db"),
    ("com.lastpass.LastPass", "com.lastpass.LastPass/db"),
    ("com.dashlane.Dashlane", "com.dashlane.Dashlane/db"),
    ("in.sinew.Enpass-Desktop", "in.sinew.Enpass-Desktop/db"),
    ("org.keepassxc.keepassxc", "org.keepassxc.keepassxc/db"),
    // More managers, with exact bundle ids from a source (see the handoff).
    ("me.proton.pass.electron", "me.proton.pass.electron/db"),
    (
        "com.markmcguill.strongbox.mac",
        "com.markmcguill.strongbox.mac/db",
    ),
    (
        "com.hicknhacksoftware.MacPass",
        "com.hicknhacksoftware.MacPass/db",
    ),
    ("com.keepassium.ios", "com.keepassium.ios/db"),
    (
        "com.keepersecurity.passwordmanager",
        "com.keepersecurity.passwordmanager/db",
    ),
    (
        "com.callpod.keepermac.lite",
        "com.callpod.keepermac.lite/db",
    ),
];

/// Children owned by `sys.sensitive-caches` (high, not preselected): sign-in
/// and sync state that `sys.user-caches` must not offer as low.
const SENSITIVE_STATE: &[&str] = &[
    "PassKit",
    "com.apple.passd",
    "com.apple.appleaccountd",
    "com.apple.amsaccountsd",
    "com.apple.akd",
    "FamilyCircle",
    "com.apple.icloudmailagent",
    "com.apple.HomeKit",
];

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

fn md(is_dir: bool, ino: u64) -> Metadata {
    Metadata {
        is_dir,
        is_symlink: false,
        dev: 1,
        ino,
        nlink: if is_dir { 2 } else { 1 },
        blocks: if is_dir { 0 } else { 8 },
        len: if is_dir { 0 } else { 4096 },
        mtime: SystemTime::UNIX_EPOCH,
    }
}

/// Inserts `rel` below the caches with every missing folder on the way.
fn put(fs: &mut FakeFs, rel: &str, ino: &mut u64) {
    let mut cur = PathBuf::from(CACHES);
    let parts: Vec<&str> = rel.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        cur.push(part);
        *ino += 1;
        let last = i + 1 == parts.len();
        if !last {
            if crate::fs::Fs::symlink_metadata(fs, &cur).is_err() {
                fs.insert(&cur, md(true, *ino));
            }
        } else {
            fs.insert(&cur, md(false, *ino));
        }
    }
}

/// Caches with every audited child, an ordinary neighbour and the extra
/// children given in `ordinary`.
fn fixture(ordinary: &[&str]) -> FakeFs {
    let mut fs = FakeFs::new();
    fs.insert("/Users", md(true, 1))
        .insert(HOME, md(true, 2))
        .insert("/Users/Tester/Library", md(true, 3))
        .insert(CACHES, md(true, 4));
    let mut ino = 1000;
    for (_, inside) in PROTECTED_STATE {
        put(&mut fs, inside, &mut ino);
    }
    for name in SENSITIVE_STATE {
        put(&mut fs, &format!("{name}/state"), &mut ino);
    }
    for name in ordinary {
        put(&mut fs, &format!("{name}/blob"), &mut ino);
    }
    fs
}

fn run(fs: &FakeFs) -> ScanReport {
    let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
    let roots = ResolvedRoots {
        home: PathBuf::from(HOME),
        caches: PathBuf::from(CACHES),
        logs: Path::new(HOME).join("Library/Logs"),
    };
    let ctx = ScanContext {
        fs,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: 0,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH,
        },
        tools: &crate::tools::NoTools,
        threads: Some(1),
    };
    // Registry order: the sensitive rule comes before the generic one.
    let rules = select(&["sys.sensitive-caches", "sys.user-caches"]).unwrap();
    scan(&rules, &ctx, &AtomicBool::new(false)).unwrap()
}

fn child(name: &str) -> PathBuf {
    Path::new(CACHES).join(name)
}

// #117: no protected state child is a candidate; each is a protected skip,
// and nothing inside it is measured or offered.
#[test]
fn protected_state_is_never_offered() {
    let report = run(&fixture(&["com.example.app"]));
    for (name, _) in PROTECTED_STATE {
        assert!(
            report
                .items
                .iter()
                .all(|i| !i.path.starts_with(child(name))),
            "{name} was offered: {:?}",
            report.items
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path == child(name) && s.reason == SkipReason::Protected),
            "{name} is not a protected skip: {:?}",
            report.skipped
        );
    }
}

// #117: sign-in and sync state is owned by the sensitive rule (high, not
// preselected), never by `sys.user-caches`.
#[test]
fn sensitive_state_belongs_to_the_sensitive_rule() {
    let report = run(&fixture(&["com.example.app"]));
    for name in SENSITIVE_STATE {
        let owners: Vec<&str> = report
            .items
            .iter()
            .filter(|i| i.path == child(name))
            .map(|i| i.rule.as_str())
            .collect();
        assert_eq!(owners, vec!["sys.sensitive-caches"], "{name}");
    }
    let meta = select(&["sys.sensitive-caches"]).unwrap()[0].meta().clone();
    assert_eq!(meta.risk, crate::model::Risk::High);
    assert!(!meta.default_selected);
}

// #117: an ordinary neighbour stays a normal low candidate, and it is the
// only thing `sys.user-caches` offers.
#[test]
fn ordinary_neighbours_stay_candidates() {
    let report = run(&fixture(&["com.example.app", "com.example.other"]));
    let generic: Vec<PathBuf> = report
        .items
        .iter()
        .filter(|i| i.rule.as_str() == "sys.user-caches")
        .map(|i| i.path.clone())
        .collect();
    assert_eq!(
        generic,
        vec![child("com.example.app"), child("com.example.other")]
    );
}

// #117 (decision B): `hatch` and `pdm` are refused whole whether or not an
// environment exists in them, because protection of what a candidate holds
// is by path, not by existence (as for `pypoetry`). Their real cache is not
// offered either; that is intentional and cheap: neither tool keeps its
// environments there by default, and an environment pointed at Caches would
// lose the user's data.
#[test]
fn hatch_and_pdm_are_refused_with_or_without_an_environment() {
    for (name, env_dir) in [("hatch", "env"), ("pdm", "venvs")] {
        let mut ino = 9000;

        // With an environment: refused whole, the cache beside it too.
        let mut fs = fixture(&["com.example.app"]);
        put(&mut fs, &format!("{name}/wheels/a"), &mut ino);
        put(&mut fs, &format!("{name}/{env_dir}/proj/bin"), &mut ino);
        let report = run(&fs);
        assert!(
            report
                .items
                .iter()
                .all(|i| !i.path.starts_with(child(name))),
            "{name} with env was offered: {:?}",
            report.items
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path == child(name) && s.reason == SkipReason::Protected),
            "{name} with env: {:?}",
            report.skipped
        );

        // Without an environment: the same, by path.
        let mut fs = FakeFs::new();
        fs.insert("/Users", md(true, 1))
            .insert(HOME, md(true, 2))
            .insert("/Users/Tester/Library", md(true, 3))
            .insert(CACHES, md(true, 4));
        put(&mut fs, &format!("{name}/wheels/a"), &mut ino);
        put(&mut fs, "com.example.app/blob", &mut ino);
        let report = run(&fs);
        assert!(
            report
                .items
                .iter()
                .all(|i| !i.path.starts_with(child(name))),
            "{name} without env was offered: {:?}",
            report.items
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.path == child(name) && s.reason == SkipReason::Protected),
            "{name} without env: {:?}",
            report.skipped
        );
        // An ordinary neighbour is still a normal candidate.
        assert!(report
            .items
            .iter()
            .any(|i| i.path == child("com.example.app") && i.rule.as_str() == "sys.user-caches"));
    }
}

// The audit table and the lists say the same: every `~/Library/Caches/<x>`
// entry of the protection list is in the table, and the table has nothing
// the list does not protect; the sensitive rule owns exactly the others.
#[test]
fn table_matches_the_protection_list_and_the_sensitive_rule() {
    let listed: BTreeSet<String> = include_str!("../protected.list")
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("~/Library/Caches/"))
        .filter_map(|rest| rest.split('/').next())
        .map(str::to_owned)
        .collect();
    let table: BTreeSet<String> = PROTECTED_STATE
        .iter()
        .map(|(n, _)| (*n).to_owned())
        .collect();
    assert_eq!(listed, table);

    let rule = select(&["sys.sensitive-caches"]).unwrap();
    let RuleKind::Files(files) = rule[0].kind() else {
        panic!("sensitive caches is a file rule");
    };
    let ctx = RuleContext {
        min_age_days: 0,
        user_paths: Vec::new(),
        now: SystemTime::UNIX_EPOCH,
    };
    let owned: BTreeSet<String> = files
        .roots(&ctx)
        .into_iter()
        .filter_map(|r| match r {
            RootedPath::Under(Root::Caches, rel) => Some(rel.to_owned()),
            _ => None,
        })
        .collect();
    let sensitive: BTreeSet<String> = SENSITIVE_STATE.iter().map(|n| (*n).to_owned()).collect();
    assert_eq!(owned, sensitive);
    // No child is both protected and sensitive.
    assert!(table.is_disjoint(&sensitive));
}
