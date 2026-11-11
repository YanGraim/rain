//! Deterministic planner: runs the selected rules and builds the report.

use crate::fs::Fs;
use crate::model::{
    ItemId, ProviderStatus, RuleId, RuleTotal, ScanItem, ScanReport, SkipReason, Skipped, ToolItem,
    ToolStatus, Unavailable, SCHEMA_VERSION,
};
use crate::protect::ProtectList;
use crate::rule::{EntryInfo, ProviderRule, RootedPath, Rule, RuleContext, RuleKind};
use crate::tools::{ExitStatusKind, ProviderItem, ToolError, ToolRunner};
use crate::walk::Walker;
use rain_platform::Root;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Canonical platform roots, resolved by the caller (the planner never
/// talks to `Platform`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoots {
    pub home: PathBuf,
    pub caches: PathBuf,
    pub logs: PathBuf,
}

/// Everything a scan reads. `protect` must already carry identities
/// ([`ProtectList::with_identities`]).
pub struct ScanContext<'a> {
    pub fs: &'a dyn Fs,
    pub protect: &'a ProtectList,
    pub roots: &'a ResolvedRoots,
    pub rule_ctx: RuleContext,
    /// Runs provider probes (ADR 0004).
    pub tools: &'a dyn ToolRunner,
    /// Worker threads; `None` uses `available_parallelism`. The report is
    /// the same for any value.
    pub threads: Option<usize>,
}

/// Why a scan produced no report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// FR-011: stopped by the user; no partial total is kept.
    #[error("scan cancelled")]
    Cancelled,
}

/// Runs `rules` (in priority order, as returned by `rules::select`) and
/// builds a deterministic report, or nothing at all if cancelled (FR-011).
///
/// Two phases (ADR 0005): discovery collects candidates without measuring;
/// then the surviving, disjoint items are measured by one walker, in
/// `(rule id, path)` order, so a shared hardlink lands in the first item.
pub fn scan(
    rules: &[&dyn Rule],
    ctx: &ScanContext,
    cancel: &AtomicBool,
) -> Result<ScanReport, ScanError> {
    if cancel.load(Ordering::SeqCst) {
        return Err(ScanError::Cancelled);
    }
    std::thread::scope(|s| {
        let probes = s.spawn(|| probe_all(rules, ctx.tools, cancel));
        let files = scan_files(rules, ctx, cancel);
        let probes = match probes.join() {
            Ok(probes) => probes,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        let (items, mut skipped) = files?;
        let (tool_items, providers) = check_tool_paths(probes?, ctx, &mut skipped);
        Ok(report(rules, items, skipped, tool_items, providers))
    })
}

/// Discovery and measurement of the file rules.
fn scan_files(
    rules: &[&dyn Rule],
    ctx: &ScanContext,
    cancel: &AtomicBool,
) -> Result<(Vec<ScanItem>, BTreeSet<Skipped>), ScanError> {
    let threads = ctx
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from));
    let mut walker = Walker::new(ctx.fs, ctx.protect)
        .with_threads(threads)
        .with_cancel(cancel);
    let mut skipped = BTreeSet::new();

    let found = discover(rules, ctx, &mut walker, &mut skipped, cancel)?;
    let accepted = accept(found, ctx.protect, &mut skipped);

    let mut order: Vec<(RuleId, &PathBuf, usize)> = accepted
        .iter()
        .filter_map(|(path, &idx)| rules.get(idx).map(|r| (r.meta().id, path, idx)))
        .collect();
    order.sort();

    let mut items = Vec::with_capacity(order.len());
    for (rule, path, idx) in order {
        let excluded = nested_in(&accepted, path, idx);
        let m = walker.measure_excluding(path, &excluded);
        if m.cancelled {
            return Err(ScanError::Cancelled);
        }
        // A root that could not be opened or listed is not an item.
        let unmeasured = m.skipped.iter().any(|s| &s.path == path);
        skipped.extend(m.skipped);
        if !unmeasured {
            items.push(ScanItem {
                id: ItemId::of(rule, path),
                rule,
                path: path.clone(),
                allocated_bytes: m.allocated_bytes,
                file_count: m.file_count,
            });
        }
    }
    let items = refuse_holders_of_protected(items, &mut skipped);
    Ok((items, skipped))
}

/// FR-007: an item that is or contains a protected hit (e.g. a dev+ino
/// alias skipped while measuring, even one inside a nested item of another
/// rule) would take it to the Trash, so it is refused whole. Containment is
/// transitive, so one pass over every hit covers outer items too.
fn refuse_holders_of_protected(
    items: Vec<ScanItem>,
    skipped: &mut BTreeSet<Skipped>,
) -> Vec<ScanItem> {
    let hits: Vec<PathBuf> = skipped
        .iter()
        .filter(|s| s.reason == SkipReason::Protected)
        .map(|s| s.path.clone())
        .collect();
    let (refused, kept): (Vec<_>, Vec<_>) = items
        .into_iter()
        .partition(|item| hits.iter().any(|h| h.starts_with(&item.path)));
    skipped.extend(refused.into_iter().map(|item| Skipped {
        path: item.path,
        reason: SkipReason::Protected,
    }));
    kept
}

/// Phase 1: candidate path -> index of the highest-priority rule that found
/// it (ADR 0005: equal paths go to the earlier rule).
fn discover(
    rules: &[&dyn Rule],
    ctx: &ScanContext,
    walker: &mut Walker,
    skipped: &mut BTreeSet<Skipped>,
    cancel: &AtomicBool,
) -> Result<BTreeMap<PathBuf, usize>, ScanError> {
    let mut found: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for (idx, rule) in rules.iter().enumerate() {
        let RuleKind::Files(files) = rule.kind() else {
            continue;
        };
        let mut candidates: BTreeSet<PathBuf> = BTreeSet::new();
        for rooted in files.roots(&ctx.rule_ctx) {
            let (root, silent_if_missing) = match resolve(&rooted, ctx.roots) {
                Ok(resolved) => resolved,
                Err(refused) => {
                    skipped.insert(refused);
                    continue;
                }
            };
            let d = walker.discover(&root, &mut |path, meta, depth| {
                files.visit(
                    &EntryInfo {
                        path,
                        meta,
                        protect: ctx.protect,
                        cancel,
                    },
                    depth,
                    &ctx.rule_ctx,
                    ctx.fs,
                )
            });
            // FR-011: a rule may stop on the flag after the walker last looked.
            if d.cancelled || cancel.load(Ordering::SeqCst) {
                return Err(ScanError::Cancelled);
            }
            skipped.extend(d.skipped.into_iter().filter(|s| {
                // FR-009: a missing rule root just means 0 items.
                !(silent_if_missing && s.path == root && s.reason == SkipReason::NotFound)
            }));
            candidates.extend(d.candidates);
        }
        for path in without_nested(candidates) {
            found.entry(path).or_insert(idx);
        }
    }
    Ok(found)
}

/// FR-007: a candidate that would take protected data with it is refused
/// before it is measured. Done before nesting, so no item is ever measured
/// "around" a refused one.
fn accept(
    found: BTreeMap<PathBuf, usize>,
    protect: &ProtectList,
    skipped: &mut BTreeSet<Skipped>,
) -> BTreeMap<PathBuf, usize> {
    found
        .into_iter()
        .filter(|(path, _)| {
            let refused = protect.contains_protected(path);
            if refused {
                skipped.insert(Skipped {
                    path: path.clone(),
                    reason: SkipReason::Protected,
                });
            }
            !refused
        })
        .collect()
}

/// ADR 0005: one rule never yields nested items. Discovery does not descend
/// into a candidate, so this only happens with overlapping roots of one
/// rule (e.g. two `--path` inside each other); the outer one keeps all.
fn without_nested(candidates: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut kept: Vec<PathBuf> = Vec::new();
    // Sorted: an ancestor always comes before its descendants.
    for path in candidates {
        if !kept.last().is_some_and(|outer| path.starts_with(outer)) {
            kept.push(path);
        }
    }
    kept
}

/// Items of other rules strictly below `outer`: they keep their own bytes.
fn nested_in(accepted: &BTreeMap<PathBuf, usize>, outer: &Path, idx: usize) -> BTreeSet<PathBuf> {
    // Paths order by component, so descendants follow `outer` contiguously.
    accepted
        .range::<Path, _>((Bound::Excluded(outer), Bound::Unbounded))
        .take_while(|(path, _)| path.starts_with(outer))
        .filter(|(_, &other)| other != idx)
        .map(|(path, _)| path.clone())
        .collect()
}

/// Where a root lives, and whether its absence is silent (rule roots) or
/// reported (user roots). A rule `rel` must be `""` or only plain names:
/// `join` with an absolute `rel` would drop the base, and `.`/`..` could
/// leave it, so anything else is refused as [`SkipReason::InvalidRoot`].
/// A symlink inside a valid `rel` is caught by the walker, which never
/// follows it and reports it as [`SkipReason::Symlink`].
fn resolve(rooted: &RootedPath, roots: &ResolvedRoots) -> Result<(PathBuf, bool), Skipped> {
    match rooted {
        RootedPath::Under(root, rel) => {
            let base = match root {
                Root::Home => &roots.home,
                Root::Caches => &roots.caches,
                Root::Logs => &roots.logs,
            };
            if rel.is_empty() {
                return Ok((base.clone(), true));
            }
            let rel_path = Path::new(rel);
            // `components()` hides a trailing `/` and interior `.`, so the
            // raw text is checked too.
            let plain = !rel.ends_with('/')
                && !rel.split('/').any(|part| part.is_empty() || part == ".")
                && rel_path
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)));
            if !plain {
                return Err(Skipped {
                    path: base.join(rel_path),
                    reason: SkipReason::InvalidRoot,
                });
            }
            Ok((base.join(rel_path), true))
        }
        RootedPath::User(path) => Ok((path.clone(), false)),
    }
}

/// What one provider rule's probe gave.
type Probe<'r> = (
    &'r dyn Rule,
    &'r dyn ProviderRule,
    Result<Vec<ProviderItem>, Unavailable>,
);

/// Runs every provider probe in registry order. Only a cancel stops it;
/// any other failure makes that one provider unavailable (FR-022).
fn probe_all<'r>(
    rules: &[&'r dyn Rule],
    tools: &dyn ToolRunner,
    cancel: &AtomicBool,
) -> Result<Vec<Probe<'r>>, ScanError> {
    let mut probes = Vec::new();
    for &rule in rules {
        let RuleKind::Provider(provider) = rule.kind() else {
            continue;
        };
        if cancel.load(Ordering::SeqCst) {
            return Err(ScanError::Cancelled);
        }
        let result = match tools.run(&provider.probe(), cancel) {
            Err(ToolError::Cancelled) => return Err(ScanError::Cancelled),
            Err(e) => Err(Unavailable::Tool(e)),
            Ok(out) if out.status != ExitStatusKind::Success => Err(Unavailable::Failed),
            Ok(out) => provider
                .parse(&out)
                .map_err(|_| Unavailable::Parse)
                .and_then(unique_keys),
        };
        probes.push((rule, provider, result));
    }
    if cancel.load(Ordering::SeqCst) {
        return Err(ScanError::Cancelled);
    }
    Ok(probes)
}

fn unique_keys(items: Vec<ProviderItem>) -> Result<Vec<ProviderItem>, Unavailable> {
    let mut seen = BTreeSet::new();
    if items.iter().all(|i| seen.insert(i.key.as_str())) {
        Ok(items)
    } else {
        Err(Unavailable::Parse)
    }
}

/// FR-007, ADR 0004 §5: every path a tool names is canonicalized and kept
/// only if unprotected and strictly inside one of the rule's roots. An item
/// that named paths and kept none is dropped.
fn check_tool_paths(
    probes: Vec<Probe>,
    ctx: &ScanContext,
    skipped: &mut BTreeSet<Skipped>,
) -> (Vec<ToolItem>, Vec<ProviderStatus>) {
    let mut items = Vec::new();
    let mut statuses = Vec::new();
    for (rule, provider, result) in probes {
        let id = rule.meta().id;
        let found = match result {
            Ok(found) => found,
            Err(why) => {
                statuses.push(ProviderStatus {
                    rule: id,
                    status: ToolStatus::Unavailable(why),
                });
                continue;
            }
        };
        statuses.push(ProviderStatus {
            rule: id,
            status: ToolStatus::Ok,
        });
        let roots = provider_roots(provider, ctx, skipped);
        for item in found {
            let named = !item.paths.is_empty();
            let paths: BTreeSet<PathBuf> = item
                .paths
                .iter()
                .filter_map(|p| checked_path(p, &roots, ctx, skipped))
                .collect();
            if named && paths.is_empty() {
                continue;
            }
            items.push(ToolItem {
                id: ItemId::of_key(id, &item.key),
                rule: id,
                key: item.key,
                label: item.label,
                reported_bytes: item.reported_bytes,
                paths: paths.into_iter().collect(),
            });
        }
    }
    items.sort_by(|a, b| (a.rule, &a.key).cmp(&(b.rule, &b.key)));
    statuses.sort();
    statuses.dedup_by_key(|s| s.rule);
    (items, statuses)
}

fn provider_roots(
    provider: &dyn ProviderRule,
    ctx: &ScanContext,
    skipped: &mut BTreeSet<Skipped>,
) -> Vec<PathBuf> {
    provider
        .roots()
        .iter()
        .filter_map(|rooted| match resolve(rooted, ctx.roots) {
            Ok((root, _)) => ctx.fs.canonicalize(&root).ok(),
            Err(refused) => {
                skipped.insert(refused);
                None
            }
        })
        .collect()
}

fn checked_path(
    path: &Path,
    roots: &[PathBuf],
    ctx: &ScanContext,
    skipped: &mut BTreeSet<Skipped>,
) -> Option<PathBuf> {
    let refuse = |path: PathBuf, reason| Skipped { path, reason };
    if !path.is_absolute() {
        skipped.insert(refuse(path.to_path_buf(), SkipReason::OutsideRoot));
        return None;
    }
    let canonical = match ctx.fs.canonicalize(path) {
        Ok(canonical) => canonical,
        Err(e) => {
            skipped.insert(refuse(path.to_path_buf(), SkipReason::from(&e)));
            return None;
        }
    };
    if ctx.protect.is_protected_on(ctx.fs, &canonical) || ctx.protect.contains_protected(&canonical)
    {
        skipped.insert(refuse(canonical, SkipReason::Protected));
        return None;
    }
    if !roots
        .iter()
        .any(|root| canonical.starts_with(root) && &canonical != root)
    {
        skipped.insert(refuse(canonical, SkipReason::OutsideRoot));
        return None;
    }
    Some(canonical)
}

fn report(
    rules: &[&dyn Rule],
    items: Vec<ScanItem>,
    skipped: BTreeSet<Skipped>,
    tool_items: Vec<ToolItem>,
    providers: Vec<ProviderStatus>,
) -> ScanReport {
    let mut totals: Vec<RuleTotal> = rules
        .iter()
        .map(|r| {
            let meta = r.meta();
            let mine = items.iter().filter(|i| i.rule == meta.id);
            let tools = tool_items.iter().filter(|i| i.rule == meta.id).count();
            RuleTotal {
                rule: meta.id,
                category: meta.category,
                risk: meta.risk,
                allocated_bytes: mine
                    .clone()
                    .fold(0u64, |acc, i| acc.saturating_add(i.allocated_bytes)),
                items: (mine.count() + tools) as u64,
            }
        })
        .collect();
    totals.sort_by_key(|t| t.rule);
    totals.dedup_by_key(|t| t.rule);
    let total_bytes = items
        .iter()
        .fold(0u64, |acc, i| acc.saturating_add(i.allocated_bytes));
    let tool_total_bytes = tool_items
        .iter()
        .fold(0u64, |acc, i| acc.saturating_add(i.reported_bytes));
    ScanReport {
        schema_version: SCHEMA_VERSION,
        rules: totals,
        items,
        skipped: skipped.into_iter().collect(),
        total_bytes,
        tool_items,
        providers,
        tool_total_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{DirEntryInfo, FakeFs, Metadata};
    use crate::model::{Category, ItemId, Risk, RuleId, ScanItem, SkipReason, Skipped};
    use crate::rule::{EntryInfo, FileRule, RootedPath, RuleKind, RuleMeta, Visit};
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::io;
    use std::path::Path;
    use std::time::SystemTime;

    const HOME: &str = "/Users/Tester";
    const CACHES: &str = "/Users/Tester/Library/Caches";
    const LOGS: &str = "/Users/Tester/Library/Logs";

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

    /// How a test rule picks candidates below each root.
    #[derive(Clone, Copy)]
    enum Pick {
        /// Direct children of the root are the items.
        Children,
        /// Children of the root's children are the items.
        Grandchildren,
    }

    struct TestRule {
        meta: RuleMeta,
        roots: Vec<RootedPath>,
        pick: Pick,
    }

    impl Rule for TestRule {
        fn meta(&self) -> &RuleMeta {
            &self.meta
        }
        fn kind(&self) -> RuleKind<'_> {
            RuleKind::Files(self)
        }
    }

    impl FileRule for TestRule {
        fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
            self.roots.clone()
        }
        fn visit(&self, _: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
            match (self.pick, depth) {
                (Pick::Children, 0) => Visit::Descend,
                (Pick::Children, _) => Visit::Candidate,
                (Pick::Grandchildren, 0 | 1) => Visit::Descend,
                (Pick::Grandchildren, _) => Visit::Candidate,
            }
        }
    }

    fn rule(id: &'static str, roots: Vec<RootedPath>) -> TestRule {
        TestRule {
            meta: RuleMeta {
                id: RuleId::new(id),
                category: Category::SystemCaches,
                risk: Risk::Low,
                name_key: "rule.test",
                consequence_key: "rule.test.consequence",
                default_selected: true,
                requires_app_closed: None,
                os: &[Os::Macos],
            },
            roots,
            pick: Pick::Children,
        }
    }

    fn under(root: Root, rel: &'static str) -> Vec<RootedPath> {
        vec![RootedPath::Under(root, rel)]
    }

    fn meta(is_dir: bool, ino: u64, nlink: u64, blocks: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink,
            blocks,
            len: blocks * 512,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    fn dir(ino: u64) -> Metadata {
        meta(true, ino, 2, 0)
    }

    fn file(ino: u64, blocks: u64) -> Metadata {
        meta(false, ino, 1, blocks)
    }

    fn c(rel: &str) -> PathBuf {
        Path::new(CACHES).join(rel)
    }

    fn l(rel: &str) -> PathBuf {
        Path::new(LOGS).join(rel)
    }

    /// Home, Library, Caches and Logs on dev 1.
    fn base() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", dir(100))
            .insert(HOME, dir(101))
            .insert("/Users/Tester/Library", dir(102))
            .insert(CACHES, dir(103))
            .insert(LOGS, dir(104));
        fs
    }

    fn roots() -> ResolvedRoots {
        ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from(CACHES),
            logs: PathBuf::from(LOGS),
        }
    }

    fn run_on(
        fs: &dyn Fs,
        rules: &[&dyn Rule],
        cancel: &AtomicBool,
    ) -> Result<ScanReport, ScanError> {
        run_with(fs, rules, cancel, None)
    }

    fn run_with(
        fs: &dyn Fs,
        rules: &[&dyn Rule],
        cancel: &AtomicBool,
        threads: Option<usize>,
    ) -> Result<ScanReport, ScanError> {
        run_full(fs, rules, cancel, threads, &crate::tools::NoTools)
    }

    fn run_full(
        fs: &dyn Fs,
        rules: &[&dyn Rule],
        cancel: &AtomicBool,
        threads: Option<usize>,
        tools: &dyn ToolRunner,
    ) -> Result<ScanReport, ScanError> {
        let protect = match ProtectList::builtin(&HomeAt) {
            Ok(list) => list.with_identities(fs),
            Err(e) => panic!("builtin failed: {e}"),
        };
        let roots = roots();
        let ctx = ScanContext {
            fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::UNIX_EPOCH,
            },
            tools,
            threads,
        };
        scan(rules, &ctx, cancel)
    }

    fn run(fs: &FakeFs, rules: &[&dyn Rule]) -> ScanReport {
        match run_on(fs, rules, &AtomicBool::new(false)) {
            Ok(report) => report,
            Err(e) => panic!("scan failed: {e}"),
        }
    }

    /// `(rule, path, bytes, files)` of every item, in report order.
    fn items(report: &ScanReport) -> Vec<(&'static str, PathBuf, u64, u64)> {
        report
            .items
            .iter()
            .map(|i| {
                (
                    i.rule.as_str(),
                    i.path.clone(),
                    i.allocated_bytes,
                    i.file_count,
                )
            })
            .collect()
    }

    /// `(rule, bytes, items)` of every rule total, in report order.
    fn totals(report: &ScanReport) -> Vec<(&'static str, u64, u64)> {
        report
            .rules
            .iter()
            .map(|r| (r.rule.as_str(), r.allocated_bytes, r.items))
            .collect()
    }

    // FR-002: rules sorted by id, items by (rule, path); total = sum of items
    // = sum of rules; every item has a stable id.
    #[test]
    fn report_is_sorted_and_totals_match() {
        let mut fs = base();
        fs.insert(c("b"), file(1, 8))
            .insert(c("a"), dir(2))
            .insert(c("a/x"), file(3, 16))
            .insert(c("a/y"), file(4, 8))
            .insert(l("l1"), file(5, 4));
        // Registry order is deliberately not id order.
        let logs = rule("macos.user.logs", under(Root::Logs, ""));
        let caches = rule("macos.user.caches", under(Root::Caches, ""));
        let report = run(&fs, &[&logs, &caches]);

        assert_eq!(report.schema_version, 1);
        assert_eq!(
            items(&report),
            vec![
                ("macos.user.caches", c("a"), 24 * 512, 2),
                ("macos.user.caches", c("b"), 8 * 512, 1),
                ("macos.user.logs", l("l1"), 4 * 512, 1),
            ]
        );
        assert_eq!(
            totals(&report),
            vec![
                ("macos.user.caches", 32 * 512, 2),
                ("macos.user.logs", 4 * 512, 1),
            ]
        );
        let item_sum: u64 = report.items.iter().map(|i| i.allocated_bytes).sum();
        let rule_sum: u64 = report.rules.iter().map(|r| r.allocated_bytes).sum();
        assert_eq!(report.total_bytes, 36 * 512);
        assert_eq!(
            (item_sum, rule_sum),
            (report.total_bytes, report.total_bytes)
        );
        assert!(report.skipped.is_empty());
        let first: &ScanItem = &report.items[0];
        assert_eq!(
            first.id,
            ItemId::of(RuleId::new("macos.user.caches"), &c("a"))
        );
        // FR-010: same input, same report.
        assert_eq!(run(&fs, &[&logs, &caches]), report);
    }

    // FR-007: a rule root that is protected, and a candidate that contains
    // something protected, become Skipped(Protected) and are not measured.
    #[test]
    fn protection_wins_over_rule() {
        let mut fs = base();
        fs.insert("/Users/Tester/.ssh", dir(10))
            .insert("/Users/Tester/.ssh/id_ed25519", file(11, 8))
            .insert("/Users/Tester/Library/Keychains", dir(12))
            .insert(
                "/Users/Tester/Library/Keychains/login.keychain-db",
                file(13, 8),
            )
            .insert("/Users/Tester/junk", file(14, 2));
        let ssh = rule(
            "test.ssh",
            vec![RootedPath::User(PathBuf::from("/Users/Tester/.ssh"))],
        );
        let home = rule("test.home", under(Root::Home, ""));
        let report = run(&fs, &[&ssh, &home]);

        assert_eq!(
            items(&report),
            vec![("test.home", PathBuf::from("/Users/Tester/junk"), 2 * 512, 1)]
        );
        // `.ssh` is reached by both rules but listed once.
        assert_eq!(
            report.skipped,
            vec![
                Skipped {
                    path: PathBuf::from("/Users/Tester/.ssh"),
                    reason: SkipReason::Protected,
                },
                Skipped {
                    path: PathBuf::from("/Users/Tester/Library"),
                    reason: SkipReason::Protected,
                },
            ]
        );
        assert_eq!(report.total_bytes, 2 * 512);
        assert_eq!(
            totals(&report),
            vec![("test.home", 2 * 512, 1), ("test.ssh", 0, 0)]
        );
    }

    // ADR 0005: the innermost item keeps its bytes; the outer item of another
    // rule is measured without that subtree. Alone, the outer rule gets all.
    #[test]
    fn overlapping_rules_count_bytes_once() {
        let mut fs = base();
        fs.insert(c("Homebrew"), meta(true, 20, 2, 2))
            .insert(c("Homebrew/pkg1"), file(21, 8))
            .insert(c("Homebrew/pkg2"), dir(22))
            .insert(c("Homebrew/pkg2/f"), file(23, 16))
            .insert(c("other"), file(24, 4));
        let brew = rule("macos.homebrew.cache", under(Root::Caches, "Homebrew"));
        let caches = rule("macos.user.caches", under(Root::Caches, ""));

        let both = run(&fs, &[&brew, &caches]);
        assert_eq!(
            items(&both),
            vec![
                ("macos.homebrew.cache", c("Homebrew/pkg1"), 8 * 512, 1),
                ("macos.homebrew.cache", c("Homebrew/pkg2"), 16 * 512, 1),
                ("macos.user.caches", c("Homebrew"), 2 * 512, 0),
                ("macos.user.caches", c("other"), 4 * 512, 1),
            ]
        );
        assert_eq!(both.total_bytes, 30 * 512);
        assert!(both.skipped.is_empty());

        let alone = run(&fs, &[&caches]);
        assert_eq!(
            items(&alone),
            vec![
                ("macos.user.caches", c("Homebrew"), 26 * 512, 2),
                ("macos.user.caches", c("other"), 4 * 512, 1),
            ]
        );
        assert_eq!(alone.total_bytes, both.total_bytes);
    }

    // ADR 0005: the same path found by two rules goes to the one earlier in
    // the registry, even when its id sorts later; the loser still appears.
    #[test]
    fn equal_path_goes_to_higher_priority_rule() {
        let mut fs = base();
        fs.insert(c("x"), file(30, 8));
        let specific = rule("z.specific", under(Root::Caches, ""));
        let generic = rule("a.generic", under(Root::Caches, ""));
        let report = run(&fs, &[&specific, &generic]);
        assert_eq!(items(&report), vec![("z.specific", c("x"), 8 * 512, 1)]);
        assert_eq!(
            totals(&report),
            vec![("a.generic", 0, 0), ("z.specific", 8 * 512, 1)]
        );
    }

    // FR-003 / ADR 0005: a hardlinked inode shared by items counts once, in
    // the first item in (rule, path) order, whatever the registry order.
    #[test]
    fn shared_hardlink_goes_to_first_item_in_order() {
        let mut fs = base();
        fs.insert(c("k"), meta(false, 50, 2, 8))
            .insert(l("k"), meta(false, 50, 2, 8))
            .insert(c("c"), meta(false, 60, 2, 4))
            .insert(c("b"), meta(false, 60, 2, 4));
        let z = rule("z.rule", under(Root::Caches, ""));
        let a = rule("a.rule", under(Root::Logs, ""));
        let report = run(&fs, &[&z, &a]);
        assert_eq!(
            items(&report),
            vec![
                ("a.rule", l("k"), 8 * 512, 1),
                ("z.rule", c("b"), 4 * 512, 1),
                ("z.rule", c("c"), 0, 0),
                ("z.rule", c("k"), 0, 0),
            ]
        );
        assert_eq!(report.total_bytes, 12 * 512);
    }

    // FR-009: a rule root that does not exist is not an error and
    // not a skip; the rule just shows 0 items.
    #[test]
    fn missing_rule_root_is_silent() {
        let fs = base();
        let brew = rule("macos.homebrew.cache", under(Root::Caches, "Homebrew"));
        let report = run(&fs, &[&brew]);
        assert!(report.items.is_empty());
        assert!(report.skipped.is_empty());
        assert_eq!(totals(&report), vec![("macos.homebrew.cache", 0, 0)]);
    }

    // FR-009: a missing user root is never silent (the CLI validates first,
    // this is the fallback).
    #[test]
    fn missing_user_root_is_reported() {
        let fs = base();
        let gone = PathBuf::from("/Users/Tester/gone");
        let r = rule("test.user", vec![RootedPath::User(gone.clone())]);
        let report = run(&fs, &[&r]);
        assert_eq!(
            report.skipped,
            vec![Skipped {
                path: gone,
                reason: SkipReason::NotFound,
            }]
        );
    }

    // ADR 0005: one rule never yields nested items; with overlapping roots
    // the outer candidate keeps everything.
    #[test]
    fn same_rule_nested_candidates_keep_outer() {
        let mut fs = base();
        fs.insert(c("a"), dir(70))
            .insert(c("a/x"), file(71, 8))
            .insert(c("a/y"), file(72, 4));
        let r = rule(
            "test.nested",
            vec![
                RootedPath::User(PathBuf::from(CACHES)),
                RootedPath::User(c("a")),
            ],
        );
        let report = run(&fs, &[&r]);
        assert_eq!(items(&report), vec![("test.nested", c("a"), 12 * 512, 2)]);
    }

    // FR-011: a scan cancelled before it starts returns Cancelled.
    #[test]
    fn cancelled_before_start_is_error() {
        let mut fs = base();
        fs.insert(c("x"), file(80, 8));
        let caches = rule("macos.user.caches", under(Root::Caches, ""));
        let result = run_on(&fs, &[&caches], &AtomicBool::new(true));
        assert_eq!(result, Err(ScanError::Cancelled));
    }

    /// Raises the cancel flag when `trigger` is listed, i.e. once
    /// measurement reaches that item (discovery never lists a candidate).
    struct TripFs<'a> {
        inner: FakeFs,
        trigger: PathBuf,
        flag: &'a AtomicBool,
    }

    impl Fs for TripFs<'_> {
        fn symlink_metadata(&self, p: &Path) -> io::Result<Metadata> {
            self.inner.symlink_metadata(p)
        }
        fn read_dir(&self, p: &Path) -> io::Result<Vec<DirEntryInfo>> {
            if p == self.trigger {
                self.flag.store(true, Ordering::Relaxed);
            }
            self.inner.read_dir(p)
        }
        fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
            self.inner.canonicalize(p)
        }
    }

    // FR-011: cancelling during measurement returns Cancelled, never a
    // report with partial totals.
    #[test]
    fn cancel_during_measurement_is_error() {
        let mut inner = base();
        inner
            .insert(c("a"), dir(90))
            .insert(c("a/x"), file(91, 8))
            .insert(c("b"), file(92, 8));
        let flag = AtomicBool::new(false);
        let fs = TripFs {
            inner,
            trigger: c("a"),
            flag: &flag,
        };
        let caches = rule("macos.user.caches", under(Root::Caches, ""));
        assert_eq!(run_on(&fs, &[&caches], &flag), Err(ScanError::Cancelled));
    }

    fn grand(id: &'static str, roots: Vec<RootedPath>) -> TestRule {
        TestRule {
            pick: Pick::Grandchildren,
            ..rule(id, roots)
        }
    }

    fn reasons(report: &ScanReport) -> Vec<SkipReason> {
        report.skipped.iter().map(|s| s.reason).collect()
    }

    /// Content outside Caches that an escaping `rel` would reach.
    fn with_outside() -> FakeFs {
        let mut fs = base();
        fs.insert(l("secret"), file(200, 8))
            .insert("/Users/Tester/out", dir(201))
            .insert("/Users/Tester/out/f", file(202, 8));
        fs
    }

    // FR-007: an absolute `rel` would replace the base in
    // `join`; it is refused explicitly, never walked nor silent.
    #[test]
    fn under_absolute_rel_is_rejected() {
        let fs = with_outside();
        let r = rule("test.abs", under(Root::Caches, "/Users/Tester/out"));
        let report = run(&fs, &[&r]);
        assert!(report.items.is_empty());
        assert_eq!(reasons(&report), vec![SkipReason::InvalidRoot]);
    }

    // FR-007: `..` or `.` in `rel` is refused explicitly.
    #[test]
    fn under_dotdot_rel_is_rejected() {
        let fs = with_outside();
        for rel in ["../Logs", "x/../..", "./x", "x/"] {
            let r = rule("test.dotdot", under(Root::Caches, rel));
            let report = run(&fs, &[&r]);
            assert!(report.items.is_empty(), "{rel}");
            assert_eq!(reasons(&report), vec![SkipReason::InvalidRoot], "{rel}");
        }
    }

    // FR-004/FR-007: a `rel` that is a symlink is not
    // followed and is reported, not silent.
    #[test]
    fn under_symlinked_rel_is_rejected() {
        let mut fs = with_outside();
        fs.insert_symlink(c("link"), LOGS);
        let r = rule("test.link", under(Root::Caches, "link"));
        let report = run(&fs, &[&r]);
        assert!(report.items.is_empty());
        assert_eq!(
            report.skipped,
            vec![Skipped {
                path: c("link"),
                reason: SkipReason::Symlink,
            }]
        );
    }

    // FR-010: ItemId is a fixed function of (rule, path), checked against a
    // value computed outside Rust (FNV-1a 64 of "macos.user.caches\0<path>").
    #[test]
    fn item_id_has_fixed_value() {
        let id = ItemId::of(RuleId::new("macos.user.caches"), &c("a"));
        assert_eq!(id, ItemId(0x4189_a2b2_9eda_e167));
    }

    /// Fails `read_dir` on one path with `PermissionDenied`.
    struct DenyDir(FakeFs, PathBuf);

    impl Fs for DenyDir {
        fn symlink_metadata(&self, p: &Path) -> io::Result<Metadata> {
            self.0.symlink_metadata(p)
        }
        fn read_dir(&self, p: &Path) -> io::Result<Vec<DirEntryInfo>> {
            if p == self.1 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.0.read_dir(p)
        }
        fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
            self.0.canonicalize(p)
        }
    }

    // FR-007, NFR-005: an item whose measurement skipped a protected entry
    // (here an alias with the same dev+ino as `~/.ssh`) is refused whole and
    // shows up as Skipped(Protected); its other files are not taken either.
    #[test]
    fn item_holding_protected_alias_is_refused() {
        let mut fs = base();
        fs.insert("/Users/Tester/.ssh", dir(10))
            .insert("/Users/Tester/.ssh/id_ed25519", file(11, 8))
            .insert(c("app"), dir(220))
            .insert(c("app/x"), file(221, 8))
            .insert(c("app/.ssh"), dir(10))
            .insert(c("app/.ssh/id_ed25519"), file(11, 8))
            .insert(c("other"), file(222, 2));
        let caches = rule("macos.user.caches", under(Root::Caches, ""));
        let report = run(&fs, &[&caches]);

        assert_eq!(
            items(&report),
            vec![("macos.user.caches", c("other"), 2 * 512, 1)]
        );
        assert!(report.skipped.contains(&Skipped {
            path: c("app"),
            reason: SkipReason::Protected,
        }));
        assert_eq!(report.total_bytes, 2 * 512);
    }

    // FR-004: a candidate that cannot be listed is not an item; it shows up
    // only in skipped, and its rule has 0 items.
    #[test]
    fn unmeasured_item_is_only_skipped() {
        let mut inner = base();
        inner
            .insert(c("d"), meta(true, 210, 2, 8))
            .insert(c("d/x"), file(211, 8));
        let fs = DenyDir(inner, c("d"));
        let caches = rule("macos.user.caches", under(Root::Caches, ""));
        let report = match run_on(&fs, &[&caches], &AtomicBool::new(false)) {
            Ok(r) => r,
            Err(e) => panic!("scan failed: {e}"),
        };
        assert!(report.items.is_empty());
        assert_eq!(
            report.skipped,
            vec![Skipped {
                path: c("d"),
                reason: SkipReason::PermissionDenied,
            }]
        );
        assert_eq!(totals(&report), vec![("macos.user.caches", 0, 0)]);
        assert_eq!(report.total_bytes, 0);
    }

    // ADR 0005: three nested levels from three rules; every byte in exactly
    // one item, and the total equals the outer rule alone.
    #[test]
    fn three_level_nesting_counts_bytes_once() {
        let mut fs = base();
        fs.insert(c("A"), meta(true, 220, 2, 1))
            .insert(c("A/a1"), file(221, 2))
            .insert(c("A/B"), meta(true, 222, 2, 4))
            .insert(c("A/B/b1"), file(223, 8))
            .insert(c("A/B/C"), dir(224))
            .insert(c("A/B/C/c1"), file(225, 16));
        let r3 = rule("r3.inner", vec![RootedPath::User(c("A/B"))]);
        let r2 = rule("r2.middle", vec![RootedPath::User(c("A"))]);
        let r1 = rule("r1.outer", under(Root::Caches, ""));
        let report = run(&fs, &[&r3, &r2, &r1]);
        assert_eq!(
            items(&report),
            vec![
                ("r1.outer", c("A"), 512, 0),
                ("r2.middle", c("A/B"), 4 * 512, 0),
                ("r2.middle", c("A/a1"), 2 * 512, 1),
                ("r3.inner", c("A/B/C"), 16 * 512, 1),
                ("r3.inner", c("A/B/b1"), 8 * 512, 1),
            ]
        );
        assert_eq!(report.total_bytes, 31 * 512);
        assert_eq!(run(&fs, &[&r1]).total_bytes, report.total_bytes);
    }

    // FR-011: cancelling during discovery returns Cancelled.
    #[test]
    fn cancel_during_discovery_is_error() {
        let mut inner = base();
        inner.insert(c("x"), file(230, 8));
        let flag = AtomicBool::new(false);
        let fs = TripFs {
            inner,
            trigger: PathBuf::from(CACHES),
            flag: &flag,
        };
        let caches = rule("macos.user.caches", under(Root::Caches, ""));
        assert_eq!(run_on(&fs, &[&caches], &flag), Err(ScanError::Cancelled));
    }

    /// Trips the cancel flag on the root's children and gives up on them,
    /// as a rule with its own reads does on Ctrl+C.
    struct CancelsInVisit(TestRule);

    impl Rule for CancelsInVisit {
        fn meta(&self) -> &RuleMeta {
            &self.0.meta
        }
        fn kind(&self) -> RuleKind<'_> {
            RuleKind::Files(self)
        }
    }

    impl FileRule for CancelsInVisit {
        fn roots(&self, ctx: &RuleContext) -> Vec<RootedPath> {
            self.0.roots(ctx)
        }
        fn visit(&self, entry: &EntryInfo, depth: usize, ctx: &RuleContext, fs: &dyn Fs) -> Visit {
            if depth > 0 {
                entry.cancel.store(true, Ordering::SeqCst);
                return Visit::Skip;
            }
            self.0.visit(entry, depth, ctx, fs)
        }
    }

    // FR-011: a rule that stops on the flag after the walker's last check
    // (nothing left to list, no candidate) still cancels the scan.
    #[test]
    fn cancel_seen_by_rule_is_error() {
        let mut fs = base();
        fs.insert(c("x"), file(240, 8));
        let caches = CancelsInVisit(rule("macos.user.caches", under(Root::Caches, "")));
        let flag = AtomicBool::new(false);
        assert_eq!(run_on(&fs, &[&caches], &flag), Err(ScanError::Cancelled));
    }

    // FR-010: the report does not depend on the thread count.
    #[test]
    fn report_same_with_1_and_n_threads() {
        let mut fs = base();
        let mut ino = 1_000;
        for d in 0..8 {
            fs.insert(c(&format!("d{d}")), dir(ino));
            ino += 1;
            for f in 0..6 {
                fs.insert(c(&format!("d{d}/f{f}")), file(ino, f + 1));
                ino += 1;
            }
            // One inode shared by every directory.
            fs.insert(c(&format!("d{d}/h")), meta(false, 999, 8, 32));
        }
        fs.insert_symlink(c("link"), LOGS);
        let caches = rule("macos.user.caches", under(Root::Caches, ""));
        let nested = rule("test.nested", under(Root::Caches, "d3"));
        let rules: [&dyn Rule; 2] = [&nested, &caches];
        let go = |threads| match run_with(&fs, &rules, &AtomicBool::new(false), Some(threads)) {
            Ok(r) => r,
            Err(e) => panic!("scan failed: {e}"),
        };
        let one = go(1);
        assert_eq!(one.items.len(), 8 + 7);
        for threads in [2, 8] {
            assert_eq!(go(threads), one, "threads {threads}");
        }
    }

    // FR-002: a rule root that exists but is empty gives 0 items, no skip.
    #[test]
    fn empty_rule_root_gives_zero_items() {
        let mut fs = base();
        fs.insert(c("Empty"), dir(240));
        let r = rule("test.empty", under(Root::Caches, "Empty"));
        let report = run(&fs, &[&r]);
        assert!(report.items.is_empty());
        assert!(report.skipped.is_empty());
        assert_eq!(totals(&report), vec![("test.empty", 0, 0)]);
    }

    // ADR 0005: two rules sharing one root, one picking items nested in the
    // other's; bytes counted once and the shared skip listed once.
    #[test]
    fn equal_roots_with_nested_candidates() {
        let mut fs = base();
        fs.insert(c("A"), meta(true, 250, 2, 2))
            .insert(c("A/x"), file(251, 8))
            .insert(c("A/y"), file(252, 4))
            .insert(c("top"), file(253, 1))
            .insert_symlink(c("link"), LOGS);
        let outer = rule("a.outer", under(Root::Caches, ""));
        let inner = grand("z.inner", under(Root::Caches, ""));
        let report = run(&fs, &[&outer, &inner]);
        assert_eq!(
            items(&report),
            vec![
                ("a.outer", c("A"), 2 * 512, 0),
                ("a.outer", c("top"), 512, 1),
                ("z.inner", c("A/x"), 8 * 512, 1),
                ("z.inner", c("A/y"), 4 * 512, 1),
            ]
        );
        assert_eq!(report.total_bytes, 15 * 512);
        assert_eq!(
            report.skipped,
            vec![Skipped {
                path: c("link"),
                reason: SkipReason::Symlink,
            }]
        );
    }

    mod providers {
        use super::*;
        use crate::model::{ProviderStatus, ToolItem, ToolStatus, Unavailable};
        use crate::rule::ProviderRule;
        use crate::tools::{
            ExitStatusKind, FakeReply, FakeToolRunner, ParseError, ProviderItem, ToolCall,
            ToolError, ToolId, ToolOutput,
        };
        use std::sync::Mutex;
        use std::thread::ThreadId;

        const DF: &[&str] = &["system", "df"];

        /// Parses lines `key bytes [path...]`; anything else is an error.
        struct TestProvider {
            meta: RuleMeta,
            tool: ToolId,
            roots: Vec<RootedPath>,
        }

        impl Rule for TestProvider {
            fn meta(&self) -> &RuleMeta {
                &self.meta
            }
            fn kind(&self) -> RuleKind<'_> {
                RuleKind::Provider(self)
            }
        }

        impl ProviderRule for TestProvider {
            fn probe(&self) -> ToolCall {
                ToolCall::read(self.tool, DF)
            }
            fn parse(&self, out: &ToolOutput) -> Result<Vec<ProviderItem>, ParseError> {
                out.stdout
                    .lines()
                    .map(|line| {
                        let mut parts = line.split(' ');
                        let key = parts.next().ok_or(ParseError("key"))?;
                        let bytes = parts
                            .next()
                            .and_then(|b| b.parse().ok())
                            .ok_or(ParseError("bytes"))?;
                        Ok(ProviderItem {
                            key: key.to_owned(),
                            label: format!("label {key}"),
                            reported_bytes: bytes,
                            paths: parts.map(PathBuf::from).collect(),
                        })
                    })
                    .collect()
            }
            fn act(&self, _: &ProviderItem) -> Option<ToolCall> {
                None
            }
            fn roots(&self) -> Vec<RootedPath> {
                self.roots.clone()
            }
        }

        fn provider(id: &'static str, tool: ToolId) -> TestProvider {
            TestProvider {
                meta: rule(id, Vec::new()).meta,
                tool,
                roots: under(Root::Caches, "Homebrew"),
            }
        }

        fn replying(tool: ToolId, reply: FakeReply) -> FakeToolRunner {
            let mut fake = FakeToolRunner::new();
            fake.reply(tool, DF, reply);
            fake
        }

        fn ok(stdout: &str) -> FakeReply {
            FakeReply::Output(ToolOutput::success(stdout))
        }

        fn scan_with(fs: &FakeFs, rules: &[&dyn Rule], tools: &dyn ToolRunner) -> ScanReport {
            match run_full(fs, rules, &AtomicBool::new(false), Some(2), tools) {
                Ok(report) => report,
                Err(e) => panic!("scan failed: {e}"),
            }
        }

        fn status(report: &ScanReport) -> Vec<(&'static str, ToolStatus)> {
            report
                .providers
                .iter()
                .map(|p: &ProviderStatus| (p.rule.as_str(), p.status))
                .collect()
        }

        fn keys(report: &ScanReport) -> Vec<(&'static str, String, u64)> {
            report
                .tool_items
                .iter()
                .map(|i| (i.rule.as_str(), i.key.clone(), i.reported_bytes))
                .collect()
        }

        fn unavailable(e: ToolError) -> ToolStatus {
            ToolStatus::Unavailable(Unavailable::Tool(e))
        }

        // FR-005, FR-021
        #[test]
        fn provider_items_are_reported_with_key_ids() {
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, ok("b 20\na 10"));
            let report = scan_with(&base(), &[&docker], &tools);
            assert_eq!(
                keys(&report),
                vec![
                    ("containers.docker", "a".to_owned(), 10),
                    ("containers.docker", "b".to_owned(), 20),
                ]
            );
            assert_eq!(status(&report), vec![("containers.docker", ToolStatus::Ok)]);
            let first: &ToolItem = &report.tool_items[0];
            assert_eq!(
                first.id,
                ItemId::of_key(RuleId::new("containers.docker"), "a")
            );
            assert_eq!(first.label, "label a");
            assert_eq!(totals(&report), vec![("containers.docker", 0, 2)]);
            assert_eq!(tools.calls(), vec![(ToolId::Docker, DF.to_vec())]);
        }

        // FR-005
        #[test]
        fn provider_item_id_is_hash_of_key() {
            let rule = RuleId::new("containers.docker");
            assert_eq!(
                ItemId::of_key(rule, "sha256:ab"),
                ItemId(0xf968_1575_5be5_81cb)
            );
            assert_ne!(
                ItemId::of_key(rule, "/x"),
                ItemId::of(rule, Path::new("/x"))
            );
            assert_ne!(
                ItemId::of_key(rule, "a"),
                ItemId::of_key(RuleId::new("other"), "a")
            );
        }

        // FR-021
        #[test]
        fn tool_bytes_not_in_total_bytes() {
            let mut fs = base();
            fs.insert(c("f"), file(1, 8));
            let caches = rule("sys.user-caches", under(Root::Caches, ""));
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, ok("a 1000\nb 24"));
            let report = scan_with(&fs, &[&caches, &docker], &tools);
            assert_eq!(report.total_bytes, 8 * 512);
            assert_eq!(report.tool_total_bytes, 1024);
            let rule_sum: u64 = report.rules.iter().map(|r| r.allocated_bytes).sum();
            assert_eq!(rule_sum, report.total_bytes);
        }

        // FR-022
        #[test]
        fn unavailable_tool_does_not_fail_scan() {
            let mut fs = base();
            fs.insert(c("f"), file(1, 8));
            let caches = rule("sys.user-caches", under(Root::Caches, ""));
            let docker = provider("containers.docker", ToolId::Docker);
            let podman = provider("containers.podman", ToolId::Podman);
            let tools = replying(ToolId::Podman, ok("p 5"));
            let report = scan_with(&fs, &[&caches, &docker, &podman], &tools);
            assert_eq!(
                items(&report),
                vec![("sys.user-caches", c("f"), 8 * 512, 1)]
            );
            assert_eq!(
                status(&report),
                vec![
                    ("containers.docker", unavailable(ToolError::NotInstalled)),
                    ("containers.podman", ToolStatus::Ok),
                ]
            );
            assert_eq!(
                keys(&report),
                vec![("containers.podman", "p".to_owned(), 5)]
            );
        }

        // FR-022
        #[test]
        fn runner_errors_are_unavailable() {
            for error in [
                ToolError::NotRunning,
                ToolError::Timeout,
                ToolError::OutputTooLarge,
                ToolError::Denied,
                ToolError::Io(io::ErrorKind::Other),
            ] {
                let docker = provider("containers.docker", ToolId::Docker);
                let tools = replying(ToolId::Docker, FakeReply::Error(error));
                let report = scan_with(&base(), &[&docker], &tools);
                assert_eq!(
                    status(&report),
                    vec![("containers.docker", unavailable(error))],
                    "{error:?}"
                );
                assert!(report.tool_items.is_empty());
            }
        }

        // FR-022
        #[test]
        fn timeout_is_unavailable() {
            let mut fs = base();
            fs.insert(c("f"), file(1, 8));
            let caches = rule("sys.user-caches", under(Root::Caches, ""));
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, FakeReply::Error(ToolError::Timeout));
            let report = scan_with(&fs, &[&caches, &docker], &tools);
            assert_eq!(
                status(&report),
                vec![("containers.docker", unavailable(ToolError::Timeout))]
            );
            assert_eq!(report.items.len(), 1);
        }

        // FR-022
        #[test]
        fn parse_error_is_unavailable() {
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, ok("a 10\nb lots"));
            let report = scan_with(&base(), &[&docker], &tools);
            assert_eq!(
                status(&report),
                vec![(
                    "containers.docker",
                    ToolStatus::Unavailable(Unavailable::Parse)
                )]
            );
            assert!(report.tool_items.is_empty());
            assert_eq!(report.tool_total_bytes, 0);
        }

        // FR-005
        #[test]
        fn duplicate_keys_are_parse_error() {
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, ok("a 10\na 20"));
            let report = scan_with(&base(), &[&docker], &tools);
            assert_eq!(
                status(&report),
                vec![(
                    "containers.docker",
                    ToolStatus::Unavailable(Unavailable::Parse)
                )]
            );
            assert!(report.tool_items.is_empty());
        }

        // FR-022
        #[test]
        fn failed_exit_is_unavailable() {
            let docker = provider("containers.docker", ToolId::Docker);
            let out = ToolOutput {
                status: ExitStatusKind::Code(1),
                stdout: "a 10".to_owned(),
                stderr_len: 3,
            };
            let tools = replying(ToolId::Docker, FakeReply::Output(out));
            let report = scan_with(&base(), &[&docker], &tools);
            assert_eq!(
                status(&report),
                vec![(
                    "containers.docker",
                    ToolStatus::Unavailable(Unavailable::Failed)
                )]
            );
            assert!(report.tool_items.is_empty());
        }

        // FR-007
        #[test]
        fn protected_path_reported_by_tool_is_dropped() {
            let mut fs = base();
            fs.insert(c("Homebrew"), dir(10))
                .insert(c("Homebrew/old.tgz"), file(11, 8))
                .insert(c("other"), file(12, 8))
                .insert("/Users/Tester/.ssh", dir(13))
                .insert("/Users/Tester/.ssh/id_ed25519", file(14, 8))
                .insert_symlink(c("Homebrew/key"), "/Users/Tester/.ssh/id_ed25519");
            let brew = provider("pkg.homebrew", ToolId::Brew);
            let line = format!(
                "x 100 {} {} /Users/Tester/.ssh/id_ed25519 {} {} relative/x",
                c("Homebrew/old.tgz").display(),
                c("other").display(),
                c("Homebrew/key").display(),
                c("Homebrew/../Homebrew/old.tgz").display(),
            );
            let tools = replying(ToolId::Brew, ok(&line));
            let report = scan_with(&fs, &[&brew], &tools);
            assert_eq!(report.tool_items.len(), 1);
            assert_eq!(report.tool_items[0].paths, vec![c("Homebrew/old.tgz")]);
            assert_eq!(
                report.skipped,
                vec![
                    Skipped {
                        path: PathBuf::from("/Users/Tester/.ssh/id_ed25519"),
                        reason: SkipReason::Protected,
                    },
                    Skipped {
                        path: c("other"),
                        reason: SkipReason::OutsideRoot,
                    },
                    Skipped {
                        path: PathBuf::from("relative/x"),
                        reason: SkipReason::OutsideRoot,
                    },
                ]
            );
        }

        // FR-007
        #[test]
        fn item_with_only_refused_paths_is_dropped() {
            let mut fs = base();
            fs.insert(c("Homebrew"), dir(10))
                .insert("/Users/Tester/.ssh", dir(13))
                .insert("/Users/Tester/.ssh/id_ed25519", file(14, 8));
            let brew = provider("pkg.homebrew", ToolId::Brew);
            let out = format!(
                "x 100 /Users/Tester/.ssh/id_ed25519\ny 5 {}\nz 7",
                c("Homebrew/gone").display()
            );
            let tools = replying(ToolId::Brew, ok(&out));
            let report = scan_with(&fs, &[&brew], &tools);
            assert_eq!(keys(&report), vec![("pkg.homebrew", "z".to_owned(), 7)]);
            assert_eq!(report.tool_total_bytes, 7);
            assert_eq!(
                report.skipped,
                vec![
                    Skipped {
                        path: PathBuf::from("/Users/Tester/.ssh/id_ed25519"),
                        reason: SkipReason::Protected,
                    },
                    Skipped {
                        path: c("Homebrew/gone"),
                        reason: SkipReason::NotFound,
                    },
                ]
            );
        }

        // FR-007
        #[test]
        fn provider_without_roots_keeps_no_path() {
            let mut fs = base();
            fs.insert(c("Homebrew"), dir(10))
                .insert(c("Homebrew/old.tgz"), file(11, 8));
            let mut brew = provider("pkg.homebrew", ToolId::Brew);
            brew.roots = Vec::new();
            let out = format!("x 100 {}", c("Homebrew/old.tgz").display());
            let tools = replying(ToolId::Brew, ok(&out));
            let report = scan_with(&fs, &[&brew], &tools);
            assert!(report.tool_items.is_empty());
            assert_eq!(
                report.skipped,
                vec![Skipped {
                    path: c("Homebrew/old.tgz"),
                    reason: SkipReason::OutsideRoot,
                }]
            );
        }

        // FR-011
        #[test]
        fn cancel_while_tool_runs_is_error() {
            let mut fs = base();
            fs.insert(c("x"), file(240, 8));
            let caches = CancelsInVisit(rule("sys.user-caches", under(Root::Caches, "")));
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, FakeReply::WaitForCancel);
            let flag = AtomicBool::new(false);
            assert_eq!(
                run_full(&fs, &[&caches, &docker], &flag, Some(2), &tools),
                Err(ScanError::Cancelled)
            );
        }

        // FR-011
        #[test]
        fn tool_cancelled_is_error() {
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, FakeReply::Error(ToolError::Cancelled));
            assert_eq!(
                run_full(&base(), &[&docker], &AtomicBool::new(false), None, &tools),
                Err(ScanError::Cancelled)
            );
        }

        // FR-011
        #[test]
        fn cancelled_before_start_runs_no_tool() {
            let docker = provider("containers.docker", ToolId::Docker);
            let tools = replying(ToolId::Docker, ok("a 1"));
            assert_eq!(
                run_full(&base(), &[&docker], &AtomicBool::new(true), None, &tools),
                Err(ScanError::Cancelled)
            );
            assert!(tools.calls().is_empty());
        }

        #[derive(Default)]
        struct ThreadSpy(Mutex<Vec<ThreadId>>);

        impl ToolRunner for ThreadSpy {
            fn run(&self, _: &ToolCall, _: &AtomicBool) -> Result<ToolOutput, ToolError> {
                if let Ok(mut seen) = self.0.lock() {
                    seen.push(std::thread::current().id());
                }
                Ok(ToolOutput::success(""))
            }
        }

        // FR-022
        #[test]
        fn providers_run_on_separate_thread() {
            let docker = provider("containers.docker", ToolId::Docker);
            let spy = ThreadSpy::default();
            let report = scan_with(&base(), &[&docker], &spy);
            assert_eq!(status(&report), vec![("containers.docker", ToolStatus::Ok)]);
            let seen = spy.0.lock().map(|s| s.clone()).unwrap_or_default();
            assert_eq!(seen.len(), 1);
            assert_ne!(seen[0], std::thread::current().id());
        }

        // FR-010
        #[test]
        fn providers_sorted_by_rule() {
            let z = provider("z.tool", ToolId::Docker);
            let a = provider("a.tool", ToolId::Ollama);
            let tools = replying(ToolId::Docker, ok("k 1"));
            let report = scan_with(&base(), &[&z, &a], &tools);
            assert_eq!(
                status(&report),
                vec![
                    ("a.tool", unavailable(ToolError::NotInstalled)),
                    ("z.tool", ToolStatus::Ok),
                ]
            );
            assert_eq!(scan_with(&base(), &[&z, &a], &tools), report);
        }

        // FR-022
        #[test]
        fn provider_does_not_act() {
            let docker = provider("containers.docker", ToolId::Docker);
            let item = ProviderItem {
                key: "a".to_owned(),
                label: String::new(),
                reported_bytes: 0,
                paths: Vec::new(),
            };
            assert_eq!(docker.act(&item), None);
        }
    }
}
