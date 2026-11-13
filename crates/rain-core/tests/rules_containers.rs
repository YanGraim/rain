//! E3: Docker provider rules through the planner with `FakeToolRunner` and
//! output recorded from the real CLI. Docker is never run.

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
use std::time::SystemTime;

const DF_ARGS: &[&str] = &["system", "df", "--format", "{{json .}}"];
const IMAGES_ARGS: &[&str] = &[
    "images",
    "--filter",
    "dangling=true",
    "--format",
    "{{json .}}",
];
const DF: &str = include_str!("fixtures/docker/system_df.jsonl");
const DANGLING: &str = include_str!("fixtures/docker/images_dangling_synthetic.jsonl");

const IDS: [&str; 5] = [
    "containers.build-cache",
    "containers.dangling-images",
    "containers.stopped",
    "containers.unused-images",
    "containers.volumes",
];

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
    run_ids(tools, &IDS)
}

fn run_ids(tools: &dyn ToolRunner, ids: &[&str]) -> ScanReport {
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
    scan(&rules::select(ids).unwrap(), &ctx, &AtomicBool::new(false)).unwrap()
}

fn fake(df: FakeReply, images: FakeReply) -> FakeToolRunner {
    let mut fake = FakeToolRunner::new();
    fake.reply(ToolId::Docker, DF_ARGS, df)
        .reply(ToolId::Docker, IMAGES_ARGS, images);
    fake
}

fn ok(s: &str) -> FakeReply {
    FakeReply::Output(ToolOutput::success(s))
}

fn items(report: &ScanReport) -> Vec<(&'static str, String, u64)> {
    report
        .tool_items
        .iter()
        .map(|i| (i.rule.as_str(), i.key.clone(), i.reported_bytes))
        .collect()
}

fn statuses(report: &ScanReport) -> Vec<ToolStatus> {
    report.providers.iter().map(|p| p.status).collect()
}

// FR-021, acceptance criterion 6: sizes come from the tool, one item per
// reclaimable row and per unused dangling image.
#[test]
fn docker_rules_report_recorded_output() {
    let tools = fake(ok(DF), ok(DANGLING));
    let report = run(&tools);
    assert_eq!(
        items(&report),
        [
            ("containers.build-cache", "build-cache".into(), 305_700_000),
            (
                "containers.dangling-images",
                "0a1b2c3d4e5f".into(),
                1_250_000_000
            ),
            ("containers.stopped", "stopped".into(), 31_350_000),
            (
                "containers.unused-images",
                "unused-images".into(),
                4_630_000_000
            ),
            ("containers.volumes", "unused-volumes".into(), 1_660_000_000),
        ]
    );
    assert_eq!(statuses(&report), [ToolStatus::Ok; 5]);
    // Dangling images are already inside unused-images: counted once.
    assert_eq!(
        report.tool_total_bytes,
        305_700_000 + 31_350_000 + 4_630_000_000 + 1_660_000_000
    );
    // FR-020: nothing on disk is measured or listed.
    assert!(report.items.is_empty());
    assert_eq!(report.total_bytes, 0);
}

// ADR 0004 §3: only the two fixed read-only argv are ever asked for.
#[test]
fn probes_are_fixed_read_only_commands() {
    let tools = fake(ok(DF), ok(DANGLING));
    run(&tools);
    let mut calls = tools.calls();
    calls.sort();
    calls.dedup();
    assert_eq!(
        calls,
        [
            (ToolId::Docker, IMAGES_ARGS.to_vec()),
            (ToolId::Docker, DF_ARGS.to_vec()),
        ]
    );
}

// FR-021: running containers are never items; with all running, the
// reclaimable container bytes are 0 and no item appears.
#[test]
fn running_containers_are_never_items() {
    let all_running = DF.replace("31.35MB (100%)", "0B (0%)");
    let report = run(&fake(ok(&all_running), ok("")));
    assert!(report
        .tool_items
        .iter()
        .all(|i| i.rule.as_str() != "containers.stopped"));
}

// FR-014: volumes may hold databases.
#[test]
fn volumes_high_not_default() {
    let r = rules::select(&["containers.volumes"]).unwrap();
    assert_eq!(r[0].meta().risk, Risk::High);
    assert!(!r[0].meta().default_selected);
}

// FR-014: the other container rules are medium and not preselected.
#[test]
fn other_container_rules_medium_not_default() {
    for id in &IDS[..4] {
        let r = rules::select(&[id]).unwrap();
        assert_eq!(r[0].meta().risk, Risk::Medium, "{id}");
        assert!(!r[0].meta().default_selected, "{id}");
    }
}

// FR-022, acceptance criterion 7: a stopped daemon never fails the scan.
#[test]
fn docker_not_running_is_unavailable() {
    let failed = FakeReply::Output(ToolOutput {
        status: ExitStatusKind::Code(1),
        stdout: String::new(),
        stderr_len: 60,
    });
    let report = run(&fake(failed.clone(), failed));
    assert!(report.tool_items.is_empty());
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Failed); 5]
    );

    let down = FakeReply::Error(ToolError::NotRunning);
    let report = run(&fake(down.clone(), down));
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Tool(ToolError::NotRunning)); 5]
    );
}

// ADR 0004 §3: corrupt output is unavailable, never guessed around.
#[test]
fn corrupt_output_is_unavailable() {
    let report = run(&fake(ok("{\"Type\":"), ok("garbage")));
    assert!(report.tool_items.is_empty());
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Parse); 5]
    );
}

// Dangling bytes leave the total only when unused-images is in this scan
// and reported them; selected alone they count.
#[test]
fn dangling_alone_counts_in_total() {
    let report = run_ids(&fake(ok(DF), ok(DANGLING)), &["containers.dangling-images"]);
    assert_eq!(report.tool_total_bytes, 1_250_000_000);
}

// If `system df` fails, unused-images reports nothing: dangling bytes count.
#[test]
fn dangling_counts_when_system_df_fails() {
    let report = run(&fake(FakeReply::Error(ToolError::Timeout), ok(DANGLING)));
    assert_eq!(report.tool_total_bytes, 1_250_000_000);
}
