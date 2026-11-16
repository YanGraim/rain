//! Podman and Ollama provider rules through the planner with
//! `FakeToolRunner` and documents in the format each tool prints. Neither tool
//! is ever run.

use rain_core::fs::{FakeFs, Fs};
use rain_core::model::{Category, Risk, ScanReport, ToolStatus, Unavailable};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::{RuleContext, RuleKind};
use rain_core::rules;
use rain_core::tools::{
    ExitStatusKind, FakeReply, FakeToolRunner, ProviderItem, ToolError, ToolId, ToolOutput,
    ToolRunner,
};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

const PODMAN_ARGS: &[&str] = &["system", "df", "--format", "json"];
const OLLAMA_ARGS: &[&str] = &["list"];
const DF: &str = include_str!("fixtures/podman/system_df.json");
const LIST: &str = include_str!("fixtures/ollama/list.txt");

const PODMAN: [&str; 3] = [
    "containers.podman-unused-images",
    "containers.podman-stopped",
    "containers.podman-volumes",
];
const OLLAMA: &str = "models.ollama";

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

fn run(tools: &dyn ToolRunner, ids: &[&str]) -> ScanReport {
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

fn podman(reply: FakeReply) -> FakeToolRunner {
    let mut fake = FakeToolRunner::new();
    fake.reply(ToolId::Podman, PODMAN_ARGS, reply);
    fake
}

fn ollama(reply: FakeReply) -> FakeToolRunner {
    let mut fake = FakeToolRunner::new();
    fake.reply(ToolId::Ollama, OLLAMA_ARGS, reply);
    fake
}

fn ok(s: &str) -> FakeReply {
    FakeReply::Output(ToolOutput::success(s))
}

fn failed(code: i32) -> FakeReply {
    FakeReply::Output(ToolOutput {
        status: ExitStatusKind::Code(code),
        stdout: String::new(),
        stderr_len: 60,
    })
}

fn statuses(report: &ScanReport) -> Vec<ToolStatus> {
    report.providers.iter().map(|p| p.status).collect()
}

fn items(report: &ScanReport) -> Vec<(&'static str, String, u64)> {
    report
        .tool_items
        .iter()
        .map(|i| (i.rule.as_str(), i.key.clone(), i.reported_bytes))
        .collect()
}

// --- Podman (#74) -----------------------------------------------------------

// FR-021: one item per reclaimable row, with the bytes the tool counts.
#[test]
fn parses_podman_fixture() {
    let report = run(&podman(ok(DF)), &PODMAN);
    assert_eq!(
        items(&report),
        [
            ("containers.podman-stopped", "stopped".to_owned(), 1_800_000),
            (
                "containers.podman-unused-images",
                "unused-images".to_owned(),
                922_956_674
            ),
            (
                "containers.podman-volumes",
                "unused-volumes".to_owned(),
                300_000_000
            ),
        ]
    );
    assert_eq!(statuses(&report), [ToolStatus::Ok; 3]);
    // FR-020: nothing on disk is measured or listed.
    assert!(report.items.is_empty());
    assert_eq!(report.total_bytes, 0);
    assert_eq!(
        report.tool_total_bytes,
        922_956_674 + 1_800_000 + 300_000_000
    );
}

// FR-022: no `podman` binary.
#[test]
fn podman_missing_is_unavailable() {
    let report = run(&FakeToolRunner::new(), &PODMAN);
    assert!(report.tool_items.is_empty());
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Tool(ToolError::NotInstalled)); 3]
    );
}

// FR-022: a stopped machine, a bad exit, a timeout or corrupt output never
// fails the scan.
#[test]
fn podman_failures_are_unavailable() {
    let cases = [
        (failed(125), Unavailable::Failed),
        (
            FakeReply::Error(ToolError::NotRunning),
            Unavailable::Tool(ToolError::NotRunning),
        ),
        (
            FakeReply::Error(ToolError::Timeout),
            Unavailable::Tool(ToolError::Timeout),
        ),
        (ok("[{\"Type\":"), Unavailable::Parse),
        (ok(""), Unavailable::Parse),
    ];
    for (reply, why) in cases {
        let report = run(&podman(reply), &PODMAN);
        assert!(report.tool_items.is_empty());
        assert_eq!(statuses(&report), [ToolStatus::Unavailable(why); 3]);
    }
}

// A row with nothing reclaimable is no item.
#[test]
fn nothing_reclaimable_is_no_item() {
    let none = DF
        .replace("922956674", "0")
        .replace("1800000", "0")
        .replace("300000000", "0");
    let report = run(&podman(ok(&none)), &PODMAN);
    assert!(report.tool_items.is_empty());
    assert_eq!(statuses(&report), [ToolStatus::Ok; 3]);
}

// FR-014: volumes may hold databases; the others are medium; none selected.
#[test]
fn podman_rules_are_medium_or_high_and_never_default() {
    for id in PODMAN {
        let m = rules::select(&[id]).unwrap()[0].meta().clone();
        let expected = if id.ends_with("volumes") {
            Risk::High
        } else {
            Risk::Medium
        };
        assert_eq!(m.risk, expected, "{id}");
        assert!(!m.default_selected, "{id}");
        assert_eq!(m.category, Category::Containers, "{id}");
    }
}

// One fixed read-only argv, asked once for the three rules.
#[test]
fn podman_probe_is_one_fixed_read_only_command() {
    let tools = podman(ok(DF));
    run(&tools, &PODMAN);
    assert_eq!(tools.calls(), vec![(ToolId::Podman, PODMAN_ARGS.to_vec())]);
    for id in PODMAN {
        let r = rules::select(&[id]).unwrap();
        let RuleKind::Provider(p) = r[0].kind() else {
            panic!("{id} is not a provider");
        };
        let call = p.probe();
        assert_eq!(call.tool, ToolId::Podman, "{id}");
        assert_eq!(call.args, PODMAN_ARGS, "{id}");
        assert!(call.item_args.is_empty(), "{id}");
        assert!(call.timeout <= Duration::from_secs(30), "{id}");
        assert!(p.act(&item()).is_none(), "{id}");
    }
}

// --- Ollama (#75) -----------------------------------------------------------

fn item() -> ProviderItem {
    ProviderItem {
        key: "k".into(),
        label: "l".into(),
        reported_bytes: 0,
        paths: Vec::new(),
    }
}

// FR-005, FR-021: each model is its own item, with the size the tool prints.
#[test]
fn ollama_lists_each_model_with_size() {
    let report = run(&ollama(ok(LIST)), &[OLLAMA]);
    assert_eq!(
        items(&report),
        [
            ("models.ollama", "llama3.2:latest".to_owned(), 2_000_000_000),
            (
                "models.ollama",
                "nomic-embed-text:latest".to_owned(),
                274_000_000
            ),
            (
                "models.ollama",
                "qwen2.5-coder:7b".to_owned(),
                4_700_000_000
            ),
            ("models.ollama", "user/custom-model:q4_0".to_owned(), 1_500),
        ]
    );
    assert_eq!(statuses(&report), [ToolStatus::Ok]);
    assert!(report.items.is_empty());
    assert_eq!(
        report.tool_total_bytes,
        2_000_000_000 + 274_000_000 + 4_700_000_000 + 1_500
    );
}

// FR-022: the server is not running (the tool says so and exits with 1), or
// there is no binary.
#[test]
fn ollama_server_down_is_unavailable() {
    let report = run(&ollama(failed(1)), &[OLLAMA]);
    assert!(report.tool_items.is_empty());
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Failed)]
    );
    let report = run(&ollama(FakeReply::Error(ToolError::NotRunning)), &[OLLAMA]);
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Tool(
            ToolError::NotRunning
        ))]
    );
    let report = run(&FakeToolRunner::new(), &[OLLAMA]);
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Tool(
            ToolError::NotInstalled
        ))]
    );
    // The same words in the output of a run that exited 0 are corrupt output.
    let report = run(
        &ollama(ok(
            "Error: could not connect to ollama app, is it running?\n",
        )),
        &[OLLAMA],
    );
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Parse)]
    );
}

// FR-005: a name that could not be passed to the tool as one argument is no
// item, and the other models are still listed.
#[test]
fn invalid_model_key_dropped() {
    let text = "NAME    ID    SIZE    MODIFIED\n\
                good:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
                -rf:latest    a80c4f17acd5    9.0 GB    1 day ago\n\
                ../../etc:latest    a80c4f17acd5    9.0 GB    1 day ago\n";
    let report = run(&ollama(ok(text)), &[OLLAMA]);
    assert_eq!(
        items(&report),
        [("models.ollama", "good:latest".to_owned(), 1_000_000_000)]
    );
    assert_eq!(report.tool_total_bytes, 1_000_000_000);
}

// Two entries with the same name are not told apart: unavailable.
#[test]
fn duplicate_model_names_are_unavailable() {
    let text = "NAME ID SIZE MODIFIED\n\
                a:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
                a:latest    b80c4f17acd5    2.0 GB    1 day ago\n";
    let report = run(&ollama(ok(text)), &[OLLAMA]);
    assert!(report.tool_items.is_empty());
    assert_eq!(
        statuses(&report),
        [ToolStatus::Unavailable(Unavailable::Parse)]
    );
}

// FR-014: a model is a download of gigabytes, and may not be fetched again.
#[test]
fn ollama_is_high_never_default() {
    let r = rules::select(&[OLLAMA]).unwrap();
    assert_eq!(r[0].meta().risk, Risk::High);
    assert!(!r[0].meta().default_selected);
    assert_eq!(r[0].meta().category, Category::AiModels);
    let RuleKind::Provider(p) = r[0].kind() else {
        panic!("not a provider");
    };
    let call = p.probe();
    assert_eq!(call.tool, ToolId::Ollama);
    assert_eq!(call.args, OLLAMA_ARGS);
    assert!(call.item_args.is_empty());
    assert!(call.timeout <= Duration::from_secs(30));
    assert!(p.act(&item()).is_none());
}

// Only the one fixed read-only argv is ever asked for.
#[test]
fn ollama_probe_is_fixed_and_runs_once() {
    let tools = ollama(ok(LIST));
    run(&tools, &[OLLAMA]);
    assert_eq!(tools.calls(), vec![(ToolId::Ollama, OLLAMA_ARGS.to_vec())]);
}
