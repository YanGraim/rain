//! Simulator provider rules through the planner with `FakeToolRunner` and a
//! document in the format `xcrun simctl list -j` prints. `simctl` is never run.

use rain_core::fs::{FakeFs, Fs};
use rain_core::model::{Risk, ScanReport, ToolStatus, Unavailable};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::rules;
use rain_core::tools::{
    ExitStatusKind, FakeReply, FakeToolRunner, ToolError, ToolId, ToolOutput, ToolRunner,
};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

const ARGS: &[&str] = &["simctl", "list", "-j"];
const LIST: &str = include_str!("fixtures/simctl/list.json");
const IDS: [&str; 2] = ["apple.sim-unavailable", "apple.sim-runtimes"];

struct Home;

impl Platform for Home {
    fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from("/Users/u"))
    }
    fn is_root_user(&self) -> bool {
        false
    }
    fn os(&self) -> Os {
        Os::Macos
    }
}

fn run(tools: &dyn ToolRunner) -> ScanReport {
    let fs = FakeFs::new();
    let protect = ProtectList::builtin(&Home).unwrap();
    let roots = ResolvedRoots {
        home: PathBuf::from("/Users/u"),
        caches: PathBuf::from("/Users/u/Library/Caches"),
        logs: PathBuf::from("/Users/u/Library/Logs"),
    };
    let ctx = ScanContext {
        fs: &fs as &dyn Fs,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: 0,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH,
        },
        tools,
        threads: Some(1),
    };
    scan(&rules::select(&IDS).unwrap(), &ctx, &AtomicBool::new(false)).unwrap()
}

fn fake(reply: FakeReply) -> FakeToolRunner {
    let mut fake = FakeToolRunner::new();
    fake.reply(ToolId::Xcrun, ARGS, reply);
    fake
}

fn ok(s: &str) -> FakeReply {
    FakeReply::Output(ToolOutput::success(s))
}

fn statuses(report: &ScanReport) -> Vec<ToolStatus> {
    report.providers.iter().map(|p| p.status).collect()
}

fn items(report: &ScanReport, rule: &str) -> Vec<(String, u64)> {
    report
        .tool_items
        .iter()
        .filter(|i| i.rule.as_str() == rule)
        .map(|i| (i.key.clone(), i.reported_bytes))
        .collect()
}

// FR-021: simulators whose runtime is gone, with the size the tool reports.
#[test]
fn unavailable_simulators_listed() {
    let report = run(&fake(ok(LIST)));
    assert_eq!(
        items(&report, "apple.sim-unavailable"),
        [
            (
                "1A2B3C4D-0000-4000-8000-000000000003".to_owned(),
                12_345_678
            ),
            ("1A2B3C4D-0000-4000-8000-000000000004".to_owned(), 0),
        ]
    );
    assert_eq!(statuses(&report), [ToolStatus::Ok; 2]);
    // Reported by the tool, not measured on disk (FR-020, ADR of providers).
    assert!(report.items.is_empty());
    assert_eq!(report.total_bytes, 0);
    assert_eq!(report.tool_total_bytes, 12_345_678);
}

// FR-014: a runtime is a download of gigabytes.
#[test]
fn runtimes_high_not_default() {
    let r = rules::select(&["apple.sim-runtimes"]).unwrap();
    assert_eq!(r[0].meta().risk, Risk::High);
    assert!(!r[0].meta().default_selected);
    let report = run(&fake(ok(LIST)));
    assert_eq!(
        items(&report, "apple.sim-runtimes"),
        // The report sorts items by key.
        [
            ("com.apple.CoreSimulator.SimRuntime.iOS-15-5".to_owned(), 0),
            ("com.apple.CoreSimulator.SimRuntime.iOS-17-0".to_owned(), 0),
        ]
    );
}

// FR-014: unavailable simulators are low risk.
#[test]
fn unavailable_simulators_are_low_risk() {
    let r = rules::select(&["apple.sim-unavailable"]).unwrap();
    assert_eq!(r[0].meta().risk, Risk::Low);
    assert_eq!(r[0].meta().category, rain_core::model::Category::AppleDev);
}

// Only the one fixed read-only argv is ever asked for, and once.
#[test]
fn one_fixed_read_only_probe_for_both_rules() {
    let tools = fake(ok(LIST));
    run(&tools);
    assert_eq!(tools.calls(), vec![(ToolId::Xcrun, ARGS.to_vec())]);
    for id in IDS {
        let r = rules::select(&[id]).unwrap();
        let rain_core::rule::RuleKind::Provider(p) = r[0].kind() else {
            panic!("{id} is not a provider");
        };
        let call = p.probe();
        assert_eq!(call.tool, ToolId::Xcrun, "{id}");
        assert_eq!(call.args, ARGS, "{id}");
        assert!(call.item_args.is_empty(), "{id}");
        assert!(p
            .act(&rain_core::tools::ProviderItem {
                key: "k".into(),
                label: "l".into(),
                reported_bytes: 0,
                paths: Vec::new(),
            })
            .is_none());
    }
}

// FR-022: no `xcrun` at all.
#[test]
fn simctl_missing_is_unavailable() {
    let report = run(&FakeToolRunner::new());
    assert!(report.tool_items.is_empty());
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Tool(ToolError::NotInstalled)); 2]
    );
}

// The case on a Mac with only the Command Line Tools: `xcrun` exists and
// exits 72 ("unable to find utility simctl"). Never fails the scan.
#[test]
fn xcrun_without_simctl_is_unavailable() {
    let report = run(&fake(FakeReply::Output(ToolOutput {
        status: ExitStatusKind::Code(72),
        stdout: String::new(),
        stderr_len: 80,
    })));
    assert!(report.tool_items.is_empty());
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Failed); 2]
    );
}

#[test]
fn timeout_and_corrupt_output_are_unavailable() {
    let report = run(&fake(FakeReply::Error(ToolError::Timeout)));
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Tool(ToolError::Timeout)); 2]
    );
    for bad in ["", "{\"devices\":", "[]", "not json"] {
        let report = run(&fake(ok(bad)));
        assert!(report.tool_items.is_empty(), "{bad}");
        assert_eq!(
            statuses(&report),
            [ToolStatus::Unavailable(Unavailable::Parse); 2],
            "{bad}"
        );
    }
}

// Two entries with the same key are not told apart: unavailable, not guessed.
#[test]
fn duplicate_keys_are_unavailable() {
    let dup = r#"{"runtimes":[],"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-1-0":[
        {"udid":"1A2B3C4D-0000-4000-8000-000000000001","isAvailable":false,"name":"a"},
        {"udid":"1A2B3C4D-0000-4000-8000-000000000001","isAvailable":false,"name":"b"}]}}"#;
    let report = run(&fake(ok(dup)));
    assert!(items(&report, "apple.sim-unavailable").is_empty());
    let status = report
        .providers
        .iter()
        .find(|p| p.rule.as_str() == "apple.sim-unavailable")
        .map(|p| p.status);
    assert_eq!(status, Some(ToolStatus::Unavailable(Unavailable::Parse)));
}

// The probe is bounded.
#[test]
fn simulator_probe_is_bounded() {
    for id in IDS {
        let r = rules::select(&[id]).unwrap();
        let rain_core::rule::RuleKind::Provider(p) = r[0].kind() else {
            panic!("{id} is not a provider");
        };
        assert!(p.probe().timeout <= Duration::from_secs(30), "{id}");
    }
}
