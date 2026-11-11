// FR-007, ADR 0004 §5: paths named by a tool, checked on a real (temp) FS.
#![cfg(unix)]
#![allow(clippy::disallowed_methods)]

use rain_core::fs::{Fs, StdFs};
use rain_core::model::{Category, Risk, RuleId, SkipReason};
use rain_core::planner::{scan, ResolvedRoots, ScanContext};
use rain_core::protect::ProtectList;
use rain_core::rule::{ProviderRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta};
use rain_core::tools::{
    ParseError, ProviderItem, ToolCall, ToolError, ToolId, ToolOutput, ToolRunner,
};
use rain_platform::{Os, Platform, PlatformError, Root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

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

/// One item per line; the line is the single path it names.
struct LinesProvider {
    meta: RuleMeta,
    roots: Vec<RootedPath>,
}

impl Rule for LinesProvider {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Provider(self)
    }
}

impl ProviderRule for LinesProvider {
    fn probe(&self) -> ToolCall {
        ToolCall::read(ToolId::Docker, &["system", "df"])
    }
    fn parse(&self, out: &ToolOutput) -> Result<Vec<ProviderItem>, ParseError> {
        Ok(out
            .stdout
            .lines()
            .enumerate()
            .map(|(i, line)| ProviderItem {
                key: format!("k{i}"),
                label: format!("k{i}"),
                reported_bytes: 1,
                paths: vec![PathBuf::from(line)],
            })
            .collect())
    }
    fn act(&self, _: &ProviderItem) -> Option<ToolCall> {
        None
    }
    fn roots(&self) -> Vec<RootedPath> {
        self.roots.clone()
    }
}

struct Says(String);

impl ToolRunner for Says {
    fn run(&self, _: &ToolCall, _: &AtomicBool) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::success(self.0.clone()))
    }
}

fn provider(roots: Vec<RootedPath>) -> LinesProvider {
    LinesProvider {
        meta: RuleMeta {
            id: RuleId::new("containers.docker"),
            category: Category::DevArtifacts,
            risk: Risk::Low,
            name_key: "x",
            consequence_key: "x",
            default_selected: false,
            requires_app_closed: None,
            os: &[Os::Macos],
        },
        roots,
    }
}

fn run(home: &Path, rule: &LinesProvider, stdout: String) -> rain_core::model::ScanReport {
    let protect = ProtectList::builtin(&HomeAt(home.to_path_buf()))
        .unwrap()
        .with_identities(&StdFs);
    let roots = ResolvedRoots {
        home: home.to_path_buf(),
        caches: home.join("Library").join("Caches"),
        logs: home.join("Library").join("Logs"),
    };
    let tools = Says(stdout);
    let ctx = ScanContext {
        fs: &StdFs as &dyn Fs,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: 0,
            user_paths: Vec::new(),
            now: SystemTime::now(),
        },
        tools: &tools,
        threads: Some(1),
    };
    scan(&[rule as &dyn Rule], &ctx, &AtomicBool::new(false)).unwrap()
}

fn home() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = fs::canonicalize(tmp.path()).unwrap();
    (tmp, home)
}

// FR-007: an ancestor of a protected path, strictly inside the rule's root,
// is refused even though it is not itself protected.
#[test]
fn tool_path_that_contains_protected_is_refused() {
    let (_tmp, home) = home();
    let caches = home.join("Library").join("Caches");
    fs::create_dir_all(caches.join("CloudKit")).unwrap();
    fs::write(caches.join("CloudKit").join("secret.db"), b"s").unwrap();
    let rule = provider(vec![RootedPath::Under(Root::Home, "Library")]);
    let report = run(&home, &rule, format!("{}", caches.display()));
    assert!(report.tool_items.is_empty(), "{:?}", report.tool_items);
    assert!(report
        .skipped
        .iter()
        .any(|s| s.path == caches && s.reason == SkipReason::Protected));
}

// FR-007: the rule's root itself is never an item path.
#[test]
fn tool_path_equal_to_root_is_refused() {
    let (_tmp, home) = home();
    let root = home.join("Library").join("Caches").join("tool");
    fs::create_dir_all(root.join("blob")).unwrap();
    let rule = provider(vec![RootedPath::Under(Root::Caches, "tool")]);
    let out = format!("{}\n{}", root.display(), root.join("blob").display());
    let report = run(&home, &rule, out);
    let kept: Vec<_> = report
        .tool_items
        .iter()
        .flat_map(|i| i.paths.clone())
        .collect();
    assert_eq!(kept, vec![root.join("blob")]);
    assert!(report
        .skipped
        .iter()
        .any(|s| s.path == root && s.reason == SkipReason::OutsideRoot));
}

// FR-007: a real symlink inside the root pointing outside it (not protected)
// is judged by its target.
#[test]
fn tool_symlink_leaving_root_is_refused() {
    let (_tmp, home) = home();
    let root = home.join("Library").join("Caches").join("tool");
    fs::create_dir_all(&root).unwrap();
    let outside = home.join("elsewhere");
    fs::write(&outside, b"x").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let rule = provider(vec![RootedPath::Under(Root::Caches, "tool")]);
    let out = format!(
        "{}\n{}/../tool/../../Caches/tool/link",
        root.join("link").display(),
        root.display()
    );
    let report = run(&home, &rule, out);
    assert!(report.tool_items.is_empty(), "{:?}", report.tool_items);
    assert!(report
        .skipped
        .iter()
        .any(|s| s.path == outside && s.reason == SkipReason::OutsideRoot));
}
