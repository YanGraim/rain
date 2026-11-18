//! Running a cleaning plan: move each item to the Trash, one at a time
//! (ADR 0006 §4).
//!
//! Everything that touches the world is injected: the Trash, the cleaning
//! log, the app check, the file system and the clock. Nothing in this module
//! deletes anything, copies anything or opens a file.
//!
//! The rules it keeps:
//! - **No log, no action.** If the log cannot take `run_started` or an
//!   `item_started`, nothing is moved.
//! - **Revalidate right before each move**, never from an earlier answer:
//!   what the disk looked like for the previous item says nothing about this one.
//! - **A skip is not a stop.** An item that changed, is busy or is not
//!   allowed is left where it is and the run goes on; a swapped folder,
//!   protected data or a failing Trash ends the run.
//! - The run only stops **between** items. An item in progress is moved or
//!   fails whole.

use crate::clock::Clock;
use crate::fs::Fs;
use crate::model::{ItemId, Risk, RuleId};
use crate::plan::{Confirmation, Plan, PlanError, PlanItem};
use crate::planner::ResolvedRoots;
use crate::protect::ProtectList;
use crate::revalidate::{self, Outcome, Revalidation, Skip, Stop};
use crate::rule::{RuleContext, RuleKind};
use crate::rules;
use crate::trash::{Trash, TrashError, TrashTarget};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// What the log is told, in order. The real log (a file) writes each one as
/// a line; the executor only needs it to accept them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogEvent {
    RunStarted {
        plan_hash: u64,
        items: usize,
    },
    ItemStarted {
        id: ItemId,
        rule: RuleId,
        path: PathBuf,
        bytes: u64,
    },
    ItemTrashed {
        id: ItemId,
        path: PathBuf,
        trash_name: OsString,
        bytes: u64,
    },
    ItemSkipped {
        id: ItemId,
        path: PathBuf,
        reason: SkipReason,
    },
    ItemMisplaced {
        id: ItemId,
        path: PathBuf,
        trash_name: OsString,
        restored: bool,
    },
    TrashFailed {
        id: ItemId,
        path: PathBuf,
        kind: TrashFailure,
    },
    RunFinished {
        moved: usize,
        skipped: usize,
        bytes: u64,
        exit: ExitCode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogError;

/// Where the executor writes what it does.
///
/// Contract (the real log keeps it): `record` returns `Ok` only when the event
/// is written; an `Err` means it may not be, and the executor then moves
/// nothing more. `sync` returns `Ok` only when everything recorded so far is
/// on disk; the executor calls it after `ItemStarted` and before the move.
pub trait CleanLog: Send + Sync {
    fn record(&self, event: &LogEvent) -> Result<(), LogError>;
    fn sync(&self) -> Result<(), LogError>;
}

/// Whether the app that owns an item is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    Closed,
    Running,
    /// The check could not tell. Treated as running.
    Unknown,
}

/// Contract: `Closed` only when the app is known not to run. Anything else,
/// an error included, is `Unknown`.
pub trait AppProbe: Send + Sync {
    fn state(&self, bundle_id: &str) -> AppState;
}

/// Why an item was left where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Gone,
    ChangedSincePlan,
    RuleNoLongerClaims,
    OtherVolume,
    Unverifiable,
    AppRunning,
    PermissionDenied,
    NotConfirmed,
}

/// Why the Trash stopped the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashFailure {
    Unavailable,
    NameExhausted,
    Io,
}

/// Exit codes (ADR 0006 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Done = 0,
    /// Before acting: an invalid or expired plan, no log, root.
    NotRun = 1,
    /// Finished, with items left where they were.
    Skips = 3,
    /// Stopped for safety.
    SafetyStop = 4,
    /// Stopped because the Trash failed.
    TrashFailure = 5,
    Cancelled = 130,
}

/// Why the run ended before the end of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    Safety {
        id: ItemId,
        why: Stop,
    },
    /// Another entry was moved: where it is in the Trash, and whether it was put back
    /// (`false` is also "not known").
    Misplaced {
        id: ItemId,
        trash_name: OsString,
        restored: bool,
    },
    Trash {
        id: ItemId,
        why: TrashFailure,
    },
    Log,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub id: ItemId,
    pub path: PathBuf,
    pub trash_name: OsString,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Left {
    pub id: ItemId,
    pub path: PathBuf,
    pub reason: SkipReason,
}

/// What happened. Paths are kept as paths: whoever prints them escapes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub moved: Vec<Moved>,
    pub left: Vec<Left>,
    pub stopped: Option<Stopped>,
    pub exit: ExitCode,
}

impl RunReport {
    pub fn bytes_moved(&self) -> u64 {
        self.moved
            .iter()
            .map(|m| m.bytes)
            .fold(0, u64::saturating_add)
    }
}

/// The plan was refused before anything was done.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunRefused {
    #[error("running as root")]
    Root,
    #[error("the plan is not usable: {0}")]
    Plan(PlanError),
    #[error("the plan is for another home folder")]
    OtherHome,
    #[error("the plan has an item that is not confirmed")]
    NotConfirmed,
    #[error("the log cannot be written")]
    Log,
}

/// Everything a run reads from, and writes to, the world.
pub struct Executor<'a> {
    pub fs: &'a dyn Fs,
    pub protect: &'a ProtectList,
    pub roots: &'a ResolvedRoots,
    pub rule_ctx: &'a RuleContext,
    pub trash: &'a dyn Trash,
    pub log: &'a dyn CleanLog,
    pub apps: &'a dyn AppProbe,
    pub clock: &'a dyn Clock,
    pub cancel: &'a AtomicBool,
    pub running_as_root: bool,
    pub max_entries: usize,
}

impl Executor<'_> {
    /// Runs `plan`. `Err` means nothing was done; `Ok` is what happened, even
    /// when the run stopped on the way (see [`RunReport::stopped`]).
    pub fn run(&self, plan: &Plan) -> Result<RunReport, RunRefused> {
        self.admit(plan)?;
        self.log
            .record(&LogEvent::RunStarted {
                plan_hash: plan.plan_hash,
                items: plan.items.len(),
            })
            .map_err(|_| RunRefused::Log)?;
        let mut report = RunReport {
            moved: Vec::new(),
            left: Vec::new(),
            stopped: None,
            exit: ExitCode::Done,
        };
        // What the log refused to take, to be tried once more before the end.
        let mut pending: Option<LogEvent> = None;
        for item in &plan.items {
            // Only between items: one in progress is moved or fails whole.
            if self.cancel.load(Ordering::SeqCst) {
                report.stopped = Some(Stopped::Cancelled);
                break;
            }
            if let Some(stop) = self.item(item, &mut report, &mut pending) {
                report.stopped = Some(stop);
                break;
            }
        }
        report.exit = exit_of(&report);
        // The end is written even after a stop, but never over a gap: if the
        // log refused a line and still refuses it, "finished" is left out so
        // the missing line shows instead of being covered by a clean ending.
        let gap = pending
            .as_ref()
            .is_some_and(|event| self.log.record(event).is_err());
        if !gap {
            let _ = self.log.record(&LogEvent::RunFinished {
                moved: report.moved.len(),
                skipped: report.left.len(),
                bytes: report.bytes_moved(),
                exit: report.exit,
            });
            let _ = self.log.sync();
        }
        Ok(report)
    }

    /// Whether the plan may be run at all. Nothing is read from the disk.
    fn admit(&self, plan: &Plan) -> Result<(), RunRefused> {
        if self.running_as_root {
            return Err(RunRefused::Root);
        }
        if plan.version != crate::plan::PLAN_VERSION {
            return Err(RunRefused::Plan(PlanError::Malformed("version")));
        }
        plan.check_fresh(self.clock.now())
            .map_err(RunRefused::Plan)?;
        if plan.home != self.roots.home {
            return Err(RunRefused::OtherHome);
        }
        if plan.items.is_empty() {
            return Err(RunRefused::Plan(PlanError::Malformed("items")));
        }
        let mut seen = std::collections::BTreeSet::new();
        if !plan.items.iter().all(|i| seen.insert(i.id)) {
            return Err(RunRefused::Plan(PlanError::Malformed("repeated item")));
        }
        // The plan is a document anyone can edit, hash included. What decides
        // how an item is treated, its risk and the app to close, is the live
        // rule's, and the plan has to agree with it; the confirmation has to
        // be the one that risk asks for.
        let mut unconfirmed = false;
        for item in &plan.items {
            let meta = live_meta(item).ok_or(RunRefused::Plan(PlanError::Malformed("rule")))?;
            if meta.risk != item.risk {
                return Err(RunRefused::Plan(PlanError::Malformed("risk")));
            }
            if meta.requires_app_closed != item.requires_app_closed.as_deref() {
                return Err(RunRefused::Plan(PlanError::Malformed("app")));
            }
            unconfirmed |= !confirmed_enough(meta.risk, item.confirmation);
        }
        // A preview is not a plan to run, and a medium or high item needs its own yes.
        if unconfirmed {
            return Err(RunRefused::NotConfirmed);
        }
        Ok(())
    }

    /// One item. `Some` ends the run.
    fn item(
        &self,
        item: &PlanItem,
        report: &mut RunReport,
        pending: &mut Option<LogEvent>,
    ) -> Option<Stopped> {
        // Write-ahead, on disk before the move: no log, no action.
        let started = LogEvent::ItemStarted {
            id: item.id,
            rule: item.rule,
            path: item.path.clone(),
            bytes: item.bytes,
        };
        if self.log.record(&started).is_err() || self.log.sync().is_err() {
            return Some(Stopped::Log);
        }
        // The disk as it is now, right before this move; no earlier answer is reused.
        let outcome = revalidate::revalidate(
            item,
            &Revalidation {
                fs: self.fs,
                protect: self.protect,
                roots: self.roots,
                rule_ctx: self.rule_ctx,
                cancel: self.cancel,
                max_entries: self.max_entries,
            },
        );
        match outcome {
            Outcome::Clear => {}
            Outcome::Skip(skip) => return self.leave(item, skip_reason(skip), report),
            Outcome::Stop(why) => return Some(Stopped::Safety { id: item.id, why }),
            Outcome::Cancelled => return Some(Stopped::Cancelled),
        }
        // The rule's app, not the plan's (`admit` made sure they agree).
        if let Some(app) = live_meta(item).and_then(|m| m.requires_app_closed) {
            if self.apps.state(app) != AppState::Closed {
                return self.leave(item, SkipReason::AppRunning, report);
            }
        }
        match self.trash.trash(&TrashTarget::of(item), self.cancel) {
            Ok(done) => {
                if done.identity_after != item.identity {
                    return self.misplaced(item, done.trash_name, false);
                }
                report.moved.push(Moved {
                    id: item.id,
                    path: item.path.clone(),
                    trash_name: done.trash_name.clone(),
                    bytes: item.bytes,
                });
                let trashed = LogEvent::ItemTrashed {
                    id: item.id,
                    path: item.path.clone(),
                    trash_name: done.trash_name,
                    bytes: item.bytes,
                };
                // The entry is in the Trash and cannot be put back from here:
                // if the log cannot say so, the run ends and reports it.
                if self.log.record(&trashed).is_err() {
                    *pending = Some(trashed);
                    return Some(Stopped::Log);
                }
                None
            }
            Err(TrashError::Gone) => self.leave(item, SkipReason::Gone, report),
            Err(TrashError::OtherVolume) => self.leave(item, SkipReason::OtherVolume, report),
            Err(TrashError::PermissionDenied) => {
                self.leave(item, SkipReason::PermissionDenied, report)
            }
            Err(TrashError::IdentityChanged) => {
                self.leave(item, SkipReason::ChangedSincePlan, report)
            }
            Err(TrashError::SymlinkInPath) => Some(Stopped::Safety {
                id: item.id,
                why: Stop::SymlinkInPath,
            }),
            Err(TrashError::Misplaced {
                trash_name,
                restored,
            }) => self.misplaced(item, trash_name, restored),
            Err(TrashError::Cancelled) => Some(Stopped::Cancelled),
            Err(TrashError::TrashUnavailable(_)) => {
                self.trash_failed(item, TrashFailure::Unavailable)
            }
            Err(TrashError::NameExhausted) => self.trash_failed(item, TrashFailure::NameExhausted),
            Err(TrashError::Io(_)) => self.trash_failed(item, TrashFailure::Io),
        }
    }

    /// The item stays where it is; the run goes on unless the log cannot say so.
    fn leave(
        &self,
        item: &PlanItem,
        reason: SkipReason,
        report: &mut RunReport,
    ) -> Option<Stopped> {
        report.left.push(Left {
            id: item.id,
            path: item.path.clone(),
            reason,
        });
        self.log
            .record(&LogEvent::ItemSkipped {
                id: item.id,
                path: item.path.clone(),
                reason,
            })
            .err()
            .map(|_| Stopped::Log)
    }

    fn misplaced(&self, item: &PlanItem, trash_name: OsString, restored: bool) -> Option<Stopped> {
        let _ = self.log.record(&LogEvent::ItemMisplaced {
            id: item.id,
            path: item.path.clone(),
            trash_name: trash_name.clone(),
            restored,
        });
        Some(Stopped::Misplaced {
            id: item.id,
            trash_name,
            restored,
        })
    }

    fn trash_failed(&self, item: &PlanItem, kind: TrashFailure) -> Option<Stopped> {
        let _ = self.log.record(&LogEvent::TrashFailed {
            id: item.id,
            path: item.path.clone(),
            kind,
        });
        Some(Stopped::Trash {
            id: item.id,
            why: kind,
        })
    }
}

/// The metadata of the rule that lists the item, today's, for a rule that
/// finds files.
fn live_meta(item: &PlanItem) -> Option<&'static crate::rule::RuleMeta> {
    rules::builtin()
        .iter()
        .find(|r| r.meta().id == item.rule)
        .and_then(|r| match r.kind() {
            RuleKind::Files(_) => Some(r.meta()),
            RuleKind::Provider(_) => None,
        })
}

/// Low needs nothing, medium a yes, high its own yes. A pending item is none.
fn confirmed_enough(risk: Risk, given: Confirmation) -> bool {
    match (risk, given) {
        (_, Confirmation::Pending) => false,
        (Risk::Low, _) => true,
        (Risk::Medium, Confirmation::Confirmed | Confirmation::ConfirmedHigh) => true,
        (Risk::High, Confirmation::ConfirmedHigh) => true,
        _ => false,
    }
}

fn skip_reason(skip: Skip) -> SkipReason {
    match skip {
        Skip::Gone => SkipReason::Gone,
        Skip::ChangedSincePlan => SkipReason::ChangedSincePlan,
        Skip::RuleNoLongerClaims => SkipReason::RuleNoLongerClaims,
        Skip::OtherVolume => SkipReason::OtherVolume,
        Skip::Unverifiable => SkipReason::Unverifiable,
    }
}

fn exit_of(report: &RunReport) -> ExitCode {
    match &report.stopped {
        Some(Stopped::Cancelled) => ExitCode::Cancelled,
        Some(Stopped::Trash { .. }) => ExitCode::TrashFailure,
        Some(Stopped::Safety { .. } | Stopped::Misplaced { .. } | Stopped::Log) => {
            ExitCode::SafetyStop
        }
        None if report.left.is_empty() => ExitCode::Done,
        None => ExitCode::Skips,
    }
}

#[cfg(any(test, feature = "testing"))]
pub use fakes::{FakeAppProbe, FakeLog};

#[cfg(any(test, feature = "testing"))]
mod fakes {
    use super::{AppProbe, AppState, CleanLog, LogError, LogEvent};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// A log in memory. It can fail on purpose at the n-th `record` or `sync`.
    #[derive(Debug, Default)]
    pub struct FakeLog {
        events: Mutex<Vec<LogEvent>>,
        syncs: Mutex<Vec<usize>>,
        fail_record_at: Vec<usize>,
        fail_sync_at: Option<usize>,
        record_calls: Mutex<usize>,
        sync_calls: Mutex<usize>,
    }

    impl FakeLog {
        pub fn new() -> Self {
            Self::default()
        }
        /// The `n`-th `record` (from 0) fails, and nothing is stored for it. May be
        /// called more than once to fail several.
        pub fn fail_record_at(mut self, n: usize) -> Self {
            self.fail_record_at.push(n);
            self
        }
        /// The `n`-th `sync` (from 0) fails.
        pub fn fail_sync_at(mut self, n: usize) -> Self {
            self.fail_sync_at = Some(n);
            self
        }
        pub fn events(&self) -> Vec<LogEvent> {
            self.events.lock().map(|e| e.clone()).unwrap_or_default()
        }
        /// For each `sync`, how many events had been recorded by then.
        pub fn syncs(&self) -> Vec<usize> {
            self.syncs.lock().map(|e| e.clone()).unwrap_or_default()
        }
    }

    impl CleanLog for FakeLog {
        fn record(&self, event: &LogEvent) -> Result<(), LogError> {
            let n = self
                .record_calls
                .lock()
                .map(|mut c| {
                    let n = *c;
                    *c += 1;
                    n
                })
                .unwrap_or(0);
            if self.fail_record_at.contains(&n) {
                return Err(LogError);
            }
            if let Ok(mut events) = self.events.lock() {
                events.push(event.clone());
            }
            Ok(())
        }
        fn sync(&self) -> Result<(), LogError> {
            let n = self
                .sync_calls
                .lock()
                .map(|mut c| {
                    let n = *c;
                    *c += 1;
                    n
                })
                .unwrap_or(0);
            if self.fail_sync_at == Some(n) {
                return Err(LogError);
            }
            let recorded = self.events.lock().map(|e| e.len()).unwrap_or(0);
            if let Ok(mut syncs) = self.syncs.lock() {
                syncs.push(recorded);
            }
            Ok(())
        }
    }

    /// Apps by bundle id; anything not listed is `Unknown`.
    #[derive(Debug, Default)]
    pub struct FakeAppProbe {
        apps: BTreeMap<String, AppState>,
    }

    impl FakeAppProbe {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn with(mut self, bundle_id: &str, state: AppState) -> Self {
            self.apps.insert(bundle_id.to_owned(), state);
            self
        }
    }

    impl AppProbe for FakeAppProbe {
        fn state(&self, bundle_id: &str) -> AppState {
            self.apps
                .get(bundle_id)
                .copied()
                .unwrap_or(AppState::Unknown)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{
        Category, ItemSource, Risk, RuleTotal, ScanItem, ScanReport, SCHEMA_VERSION,
    };
    use crate::plan::{BuildContext, Confirmations, Plan, Selection};
    use crate::trash::FakeTrash;
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    const HOME: &str = "/Users/t";
    const NOW: u64 = 1_700_000_000;
    const CACHES: RuleId = RuleId::new("sys.user-caches");
    const LOGS: RuleId = RuleId::new("sys.logs");
    const ARCHIVES: RuleId = RuleId::new("apple.archives");
    const XCODE: &str = "com.apple.dt.Xcode";

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
            dev: 7,
            ino,
            nlink: if is_dir { 2 } else { 1 },
            blocks: 8,
            len: 0,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    const A: &str = "/Users/t/Library/Caches/com.a";
    const B: &str = "/Users/t/Library/Caches/com.b";
    const C: &str = "/Users/t/Library/Caches/com.c";
    const LOG: &str = "/Users/t/Library/Logs/old.log";
    const ARCHIVE: &str = "/Users/t/Library/Developer/Xcode/Archives/2024/App.xcarchive";
    const GO_MOD_ITEM: &str = "/Users/t/go/pkg/mod/golang.org";
    const GO_MOD: RuleId = RuleId::new("pkg.go-mod");

    fn world() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", md(true, 1))
            .insert(HOME, md(true, 2))
            .insert("/Users/t/Library", md(true, 3))
            .insert("/Users/t/Library/Caches", md(true, 4))
            .insert(A, md(true, 10))
            .insert(format!("{A}/blob"), md(false, 11))
            .insert(B, md(true, 12))
            .insert(C, md(true, 13))
            .insert("/Users/t/Library/Logs", md(true, 20))
            .insert(LOG, md(false, 21))
            .insert("/Users/t/.ssh", md(true, 30))
            .insert("/Users/t/Library/Developer", md(true, 40))
            .insert("/Users/t/Library/Developer/Xcode", md(true, 41))
            .insert("/Users/t/Library/Developer/Xcode/Archives", md(true, 42))
            .insert(
                "/Users/t/Library/Developer/Xcode/Archives/2024",
                md(true, 43),
            )
            .insert(ARCHIVE, md(true, 44))
            .insert("/Users/t/go", md(true, 60))
            .insert("/Users/t/go/pkg", md(true, 61))
            .insert("/Users/t/go/pkg/mod", md(true, 62))
            .insert(GO_MOD_ITEM, md(true, 63));
        fs
    }

    fn rule_total(rule: RuleId, risk: Risk, app: Option<&'static str>) -> RuleTotal {
        RuleTotal {
            rule,
            category: Category::SystemCaches,
            risk,
            allocated_bytes: 0,
            items: 0,
            name_key: "rule.test",
            consequence_key: "rule.test.consequence",
            default_selected: risk == Risk::Low,
            requires_app_closed: app,
            source: ItemSource::Files,
        }
    }

    fn scan_item(rule: RuleId, path: &str, bytes: u64) -> ScanItem {
        let path = PathBuf::from(path);
        ScanItem {
            id: ItemId::of(rule, &path),
            rule,
            path,
            allocated_bytes: bytes,
            file_count: 1,
        }
    }

    fn id(rule: RuleId, path: &str) -> ItemId {
        ItemId::of(rule, Path::new(path))
    }

    fn report(extra: &[ScanItem]) -> ScanReport {
        let mut items = vec![
            scan_item(CACHES, A, 100),
            scan_item(CACHES, B, 200),
            scan_item(CACHES, C, 400),
            scan_item(LOGS, LOG, 50),
            scan_item(ARCHIVES, ARCHIVE, 9_000),
            scan_item(GO_MOD, GO_MOD_ITEM, 3_000),
        ];
        items.extend(extra.iter().cloned());
        items.sort_by(|a, b| (a.rule, &a.path).cmp(&(b.rule, &b.path)));
        ScanReport {
            schema_version: SCHEMA_VERSION,
            rules: vec![
                rule_total(ARCHIVES, Risk::High, Some(XCODE)),
                rule_total(GO_MOD, Risk::Medium, None),
                rule_total(LOGS, Risk::Low, None),
                rule_total(CACHES, Risk::Low, None),
            ],
            items,
            skipped: Vec::new(),
            total_bytes: 0,
            tool_items: Vec::new(),
            providers: Vec::new(),
            tool_total_bytes: 0,
            unmanaged: Vec::new(),
            excluded: Vec::new(),
        }
    }

    fn make_plan(fs: &FakeFs, report: &ScanReport, ids: &[ItemId], high: &[ItemId]) -> Plan {
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
        let clock = FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW));
        let ctx = BuildContext {
            fs,
            protect: &protect,
            clock: &clock,
            home: Path::new(HOME),
        };
        let sel = Selection {
            ids: ids.to_vec(),
            confirmed: Vec::new(),
            confirmed_high: high.to_vec(),
        };
        Plan::build(report, &sel, Confirmations::Required, &ctx).expect("a plan")
    }

    fn low_plan(fs: &FakeFs) -> Plan {
        make_plan(
            fs,
            &report(&[]),
            &[id(CACHES, A), id(CACHES, B), id(CACHES, C)],
            &[],
        )
    }

    struct Rig {
        trash: FakeTrash,
        log: FakeLog,
        apps: FakeAppProbe,
        cancel: AtomicBool,
        root: bool,
        now: u64,
    }

    impl Rig {
        fn new() -> Rig {
            Rig {
                trash: FakeTrash::new(),
                log: FakeLog::new(),
                apps: FakeAppProbe::new(),
                cancel: AtomicBool::new(false),
                root: false,
                now: NOW + 5,
            }
        }
    }

    fn run_on(fs: &FakeFs, rig: &Rig, plan: &Plan) -> Result<RunReport, RunRefused> {
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from("/Users/t/Library/Caches"),
            logs: PathBuf::from("/Users/t/Library/Logs"),
        };
        let rule_ctx = RuleContext {
            min_age_days: 30,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(rig.now),
        };
        let clock = FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(rig.now));
        Executor {
            fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: &rule_ctx,
            trash: &rig.trash,
            log: &rig.log,
            apps: &rig.apps,
            clock: &clock,
            cancel: &rig.cancel,
            running_as_root: rig.root,
            max_entries: 1_000,
        }
        .run(plan)
    }

    fn paths(calls: &[PathBuf]) -> Vec<&str> {
        calls.iter().map(|p| p.to_str().unwrap()).collect()
    }

    // The ordinary case: every item moves, in the order of the plan, and the
    // log says so.
    #[test]
    fn every_item_is_moved_in_order_and_logged() {
        let fs = world();
        let rig = Rig::new();
        let plan = low_plan(&fs);
        let out = run_on(&fs, &rig, &plan).unwrap();
        assert_eq!(out.exit, ExitCode::Done);
        assert_eq!(out.stopped, None);
        assert!(out.left.is_empty());
        assert_eq!(paths(&rig.trash.calls()), [A, B, C]);
        assert_eq!(out.moved.len(), 3);
        assert_eq!(out.bytes_moved(), 700);
        assert_eq!(out.moved[0].trash_name, "com.a");
        let events = rig.log.events();
        assert!(matches!(events[0], LogEvent::RunStarted { items: 3, .. }));
        // started, trashed for each item, then the end.
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| match e {
                LogEvent::RunStarted { .. } => "run",
                LogEvent::ItemStarted { .. } => "start",
                LogEvent::ItemTrashed { .. } => "done",
                LogEvent::RunFinished { .. } => "end",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds,
            ["run", "start", "done", "start", "done", "start", "done", "end"]
        );
        assert!(matches!(
            events.last(),
            Some(LogEvent::RunFinished {
                moved: 3,
                skipped: 0,
                bytes: 700,
                exit: ExitCode::Done
            })
        ));
    }

    // Refused before anything is done.
    #[test]
    fn root_a_stale_plan_and_a_foreign_home_are_refused_before_acting() {
        let fs = world();
        let plan = low_plan(&fs);
        let mut rig = Rig::new();
        rig.root = true;
        assert_eq!(run_on(&fs, &rig, &plan), Err(RunRefused::Root));
        let mut rig = Rig::new();
        rig.now = NOW + 901;
        assert_eq!(
            run_on(&fs, &rig, &plan),
            Err(RunRefused::Plan(PlanError::Expired))
        );
        let mut rig = Rig::new();
        rig.now = NOW - 61;
        assert_eq!(
            run_on(&fs, &rig, &plan),
            Err(RunRefused::Plan(PlanError::FromTheFuture))
        );
        let mut other = plan.clone();
        other.home = PathBuf::from("/Users/someone");
        let rig = Rig::new();
        assert_eq!(run_on(&fs, &rig, &other), Err(RunRefused::OtherHome));
        // None of them moved or logged anything.
        assert!(rig.trash.calls().is_empty());
        assert!(rig.log.events().is_empty());
    }

    // Every item that needs a decision must carry it: a preview is not a plan
    // to run.
    #[test]
    fn a_plan_with_an_unconfirmed_item_is_refused() {
        let fs = world();
        let mut plan = low_plan(&fs);
        plan.items[1].confirmation = Confirmation::Pending;
        let rig = Rig::new();
        assert_eq!(run_on(&fs, &rig, &plan), Err(RunRefused::NotConfirmed));
        assert!(rig.trash.calls().is_empty());
    }

    // A plan can be written by hand: it needs an id per item, once, and a
    // version the program knows.
    #[test]
    fn a_plan_that_repeats_an_item_or_has_none_is_refused() {
        let fs = world();
        let rig = Rig::new();
        let mut twice = low_plan(&fs);
        let again = twice.items[0].clone();
        twice.items.push(again);
        assert!(matches!(
            run_on(&fs, &rig, &twice),
            Err(RunRefused::Plan(PlanError::Malformed(_)))
        ));
        let mut empty = low_plan(&fs);
        empty.items.clear();
        assert!(matches!(
            run_on(&fs, &rig, &empty),
            Err(RunRefused::Plan(PlanError::Malformed(_)))
        ));
        let mut future = low_plan(&fs);
        future.version = 99;
        assert!(matches!(
            run_on(&fs, &rig, &future),
            Err(RunRefused::Plan(PlanError::Malformed(_)))
        ));
        assert!(rig.trash.calls().is_empty());
    }

    // No log, no action: at each point where the log can fail, nothing more is
    // moved.
    #[test]
    fn if_the_log_cannot_be_written_nothing_is_moved() {
        let fs = world();
        let plan = low_plan(&fs);
        // record #0 is run_started, #1 the first item_started.
        for (label, log, moved) in [
            ("run_started", FakeLog::new().fail_record_at(0), 0),
            ("first item_started", FakeLog::new().fail_record_at(1), 0),
            ("first sync", FakeLog::new().fail_sync_at(0), 0),
            // run, start1, done1, start2: the second item is never moved.
            ("second item_started", FakeLog::new().fail_record_at(3), 1),
            ("second sync", FakeLog::new().fail_sync_at(1), 1),
        ] {
            let mut rig = Rig::new();
            rig.log = log;
            let out = run_on(&fs, &rig, &plan);
            let calls = rig.trash.calls().len();
            assert_eq!(calls, moved, "{label}");
            match out {
                Err(RunRefused::Log) => assert_eq!(moved, 0, "{label}"),
                Ok(report) => {
                    assert_eq!(report.stopped, Some(Stopped::Log), "{label}");
                    assert_eq!(report.moved.len(), moved, "{label}");
                    assert_eq!(report.exit, ExitCode::SafetyStop, "{label}");
                }
                other => panic!("{label}: {other:?}"),
            }
        }
    }

    // The move is written to the log only after the entry went, and the log is
    // synced between "started" and the move.
    #[test]
    fn the_start_is_on_disk_before_each_move() {
        let fs = world();
        let rig = Rig::new();
        run_on(&fs, &rig, &low_plan(&fs)).unwrap();
        // run_started, item_started #1 -> sync(2); then done #1, item_started #2 -> sync(4), ...
        let syncs = rig.log.syncs();
        assert_eq!(&syncs[..3], &[2, 4, 6]);
    }

    // The log refused the line that says an item was moved. If the run then
    // wrote "finished", the log would claim a clean ending with a move missing
    // from it. It tries that line once more; if the log still refuses, it
    // does not write "finished" at all, so the gap shows.
    #[test]
    fn a_log_that_lost_the_trashed_line_never_claims_the_run_finished() {
        let fs = world();
        // run(0) start1(1) done1(2 fails) done1-again(3 fails too).
        let mut rig = Rig::new();
        rig.log = FakeLog::new().fail_record_at(2).fail_record_at(3);
        let out = run_on(&fs, &rig, &low_plan(&fs)).unwrap();
        assert_eq!(out.stopped, Some(Stopped::Log));
        assert_eq!(out.moved.len(), 1);
        assert!(
            !rig.log
                .events()
                .iter()
                .any(|e| matches!(e, LogEvent::RunFinished { .. })),
            "{:?}",
            rig.log.events()
        );
        // One failure only: the line is written on the second try, and the
        // run's end is written after it.
        let mut rig = Rig::new();
        rig.log = FakeLog::new().fail_record_at(2);
        let out = run_on(&fs, &rig, &low_plan(&fs)).unwrap();
        assert_eq!(out.stopped, Some(Stopped::Log));
        let events = rig.log.events();
        let trashed = events
            .iter()
            .position(|e| matches!(e, LogEvent::ItemTrashed { .. }))
            .expect("the line was written on the retry");
        let finished = events
            .iter()
            .position(|e| matches!(e, LogEvent::RunFinished { .. }))
            .expect("the end is written once nothing is missing");
        assert!(trashed < finished);
    }

    // A failing log after a move that worked: stop and say so; what moved is reported.
    #[test]
    fn a_log_that_fails_after_a_move_stops_the_run_and_reports_it() {
        let fs = world();
        let mut rig = Rig::new();
        // run(0) start1(1) done1(2 fails).
        rig.log = FakeLog::new().fail_record_at(2);
        let out = run_on(&fs, &rig, &low_plan(&fs)).unwrap();
        assert_eq!(out.stopped, Some(Stopped::Log));
        assert_eq!(out.moved.len(), 1);
        assert_eq!(paths(&rig.trash.calls()), [A]);
    }

    // The core of the layer: the disk is looked at again right before EACH
    // move, not once for the whole plan.
    #[test]
    fn each_item_is_revalidated_right_before_its_own_move() {
        let fs = world();
        let plan = low_plan(&fs);
        // A swapped entry: `com.b` is another folder than the plan saw.
        let mut changed = world();
        changed.insert(B, md(true, 99));
        let rig = Rig::new();
        let out = run_on(&changed, &rig, &plan).unwrap();
        assert_eq!(paths(&rig.trash.calls()), [A, C]);
        assert_eq!(
            out.left,
            [Left {
                id: id(CACHES, B),
                path: PathBuf::from(B),
                reason: SkipReason::ChangedSincePlan
            }]
        );
        assert_eq!(out.exit, ExitCode::Skips);
        assert_eq!(out.stopped, None);
    }

    // What the first item's move changed on the disk is seen by the second
    // item's check: an ancestor swapped between two items stops the run.
    #[test]
    fn a_folder_swapped_between_two_items_is_seen_by_the_second() {
        use std::sync::Mutex;
        struct SharedFs<'a>(&'a Mutex<FakeFs>);
        impl Fs for SharedFs<'_> {
            fn symlink_metadata(&self, p: &Path) -> std::io::Result<Metadata> {
                self.0.lock().unwrap().symlink_metadata(p)
            }
            fn read_dir(&self, p: &Path) -> std::io::Result<Vec<crate::fs::DirEntryInfo>> {
                self.0.lock().unwrap().read_dir(p)
            }
            fn canonicalize(&self, p: &Path) -> std::io::Result<PathBuf> {
                self.0.lock().unwrap().canonicalize(p)
            }
            fn read_to_string(&self, p: &Path, max: u64) -> std::io::Result<String> {
                self.0.lock().unwrap().read_to_string(p, max)
            }
        }
        // Moving the first item swaps the folder that holds the others.
        struct Swapping<'a> {
            fake: FakeTrash,
            fs: &'a Mutex<FakeFs>,
        }
        impl Trash for Swapping<'_> {
            fn trash(
                &self,
                target: &TrashTarget,
                cancel: &AtomicBool,
            ) -> Result<crate::trash::Trashed, TrashError> {
                let moved = self.fake.trash(target, cancel);
                self.fs
                    .lock()
                    .unwrap()
                    .insert("/Users/t/Library/Caches", md(true, 777));
                moved
            }
        }
        let shared = Mutex::new(world());
        let plan = low_plan(&shared.lock().unwrap());
        let fs = SharedFs(&shared);
        let swapping = Swapping {
            fake: FakeTrash::new(),
            fs: &shared,
        };
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from("/Users/t/Library/Caches"),
            logs: PathBuf::from("/Users/t/Library/Logs"),
        };
        let rule_ctx = RuleContext {
            min_age_days: 30,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 5),
        };
        let clock = FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 5));
        let log = FakeLog::new();
        let apps = FakeAppProbe::new();
        let cancel = AtomicBool::new(false);
        let out = Executor {
            fs: &fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: &rule_ctx,
            trash: &swapping,
            log: &log,
            apps: &apps,
            clock: &clock,
            cancel: &cancel,
            running_as_root: false,
            max_entries: 1_000,
        }
        .run(&plan)
        .unwrap();
        // The first item went; the second saw the swapped folder and the run stopped.
        assert_eq!(paths(&swapping.fake.calls()), [A]);
        assert_eq!(
            out.stopped,
            Some(Stopped::Safety {
                id: id(CACHES, B),
                why: Stop::AncestorChanged
            })
        );
        assert_eq!(out.exit, ExitCode::SafetyStop);
        assert_eq!(out.moved.len(), 1);
    }

    // A stop for safety ends the run; what was already moved is reported.
    #[test]
    fn a_link_where_an_item_was_stops_the_run() {
        let fs = world();
        let plan = low_plan(&fs);
        let mut linked = world();
        linked.insert_symlink(B, "/Users/t/.ssh");
        let rig = Rig::new();
        let out = run_on(&linked, &rig, &plan).unwrap();
        assert_eq!(paths(&rig.trash.calls()), [A]);
        assert_eq!(
            out.stopped,
            Some(Stopped::Safety {
                id: id(CACHES, B),
                why: Stop::SymlinkInPath
            })
        );
        assert_eq!(out.exit, ExitCode::SafetyStop);
        assert_eq!(out.moved.len(), 1);
    }

    #[test]
    fn items_that_are_gone_or_that_changed_volume_are_left_and_the_run_goes_on() {
        let fs = world();
        let plan = low_plan(&fs);
        let mut gone = world();
        let mut other_volume = md(true, 13);
        other_volume.dev = 9;
        gone.insert(C, other_volume);
        let mut e = FakeFs::new();
        // `com.a` is gone altogether.
        for (path, meta) in [
            ("/Users", md(true, 1)),
            (HOME, md(true, 2)),
            ("/Users/t/Library", md(true, 3)),
            ("/Users/t/Library/Caches", md(true, 4)),
            (B, md(true, 12)),
        ] {
            e.insert(path, meta);
        }
        e.insert(C, other_volume);
        let rig = Rig::new();
        let out = run_on(&e, &rig, &plan).unwrap();
        assert_eq!(paths(&rig.trash.calls()), [B]);
        let reasons: Vec<_> = out.left.iter().map(|l| l.reason).collect();
        // The volume is part of an entry's identity: another one is another entry.
        assert_eq!(reasons, [SkipReason::Gone, SkipReason::ChangedSincePlan]);
        assert_eq!(out.exit, ExitCode::Skips);
    }

    // An app that is open, or whose state is unknown, is never acted on.
    #[test]
    fn an_item_whose_app_is_open_or_unknown_is_left_alone() {
        let fs = world();
        let report = report(&[]);
        let plan = make_plan(
            &fs,
            &report,
            &[id(CACHES, A), id(ARCHIVES, ARCHIVE)],
            &[id(ARCHIVES, ARCHIVE)],
        );
        for (label, apps) in [
            (
                "running",
                FakeAppProbe::new().with(XCODE, AppState::Running),
            ),
            (
                "unknown",
                FakeAppProbe::new().with(XCODE, AppState::Unknown),
            ),
            ("not asked about", FakeAppProbe::new()),
        ] {
            let mut rig = Rig::new();
            rig.apps = apps;
            let out = run_on(&fs, &rig, &plan).unwrap();
            assert_eq!(paths(&rig.trash.calls()), [A], "{label}");
            assert_eq!(out.left.len(), 1, "{label}");
            assert_eq!(out.left[0].reason, SkipReason::AppRunning, "{label}");
            assert_eq!(out.exit, ExitCode::Skips, "{label}");
        }
        // Closed: it goes.
        let mut rig = Rig::new();
        rig.apps = FakeAppProbe::new().with(XCODE, AppState::Closed);
        let out = run_on(&fs, &rig, &plan).unwrap();
        // The plan is in order of rule: `apple.archives` before `sys.user-caches`.
        assert_eq!(paths(&rig.trash.calls()), [ARCHIVE, A]);
        assert_eq!(out.exit, ExitCode::Done);
    }

    // What the Trash says decides whether the run goes on.
    #[test]
    fn a_permission_problem_on_one_item_is_a_skip_and_a_missing_trash_is_a_stop() {
        let fs = world();
        let plan = low_plan(&fs);
        // Permission, gone and another volume, reported by the Trash itself.
        let mut rig = Rig::new();
        rig.trash
            .fail(A, TrashError::PermissionDenied)
            .fail(B, TrashError::Gone)
            .fail(C, TrashError::OtherVolume);
        let out = run_on(&fs, &rig, &plan).unwrap();
        let reasons: Vec<_> = out.left.iter().map(|l| l.reason).collect();
        assert_eq!(
            reasons,
            [
                SkipReason::PermissionDenied,
                SkipReason::Gone,
                SkipReason::OtherVolume
            ]
        );
        assert_eq!(out.exit, ExitCode::Skips);
        assert_eq!(out.stopped, None);
        // A Trash that cannot be used: stop at the first, nothing else is tried.
        for (why, failure) in [
            (
                TrashError::TrashUnavailable(std::io::ErrorKind::NotFound),
                TrashFailure::Unavailable,
            ),
            (TrashError::NameExhausted, TrashFailure::NameExhausted),
            (TrashError::Io(std::io::ErrorKind::Other), TrashFailure::Io),
        ] {
            let mut rig = Rig::new();
            rig.trash.fail(B, why);
            let out = run_on(&fs, &rig, &plan).unwrap();
            assert_eq!(paths(&rig.trash.calls()), [A, B], "{failure:?}");
            assert_eq!(
                out.stopped,
                Some(Stopped::Trash {
                    id: id(CACHES, B),
                    why: failure
                })
            );
            assert_eq!(out.exit, ExitCode::TrashFailure);
            assert_eq!(out.moved.len(), 1);
            assert!(rig
                .log
                .events()
                .iter()
                .any(|e| matches!(e, LogEvent::TrashFailed { kind, .. } if *kind == failure)));
        }
    }

    // A Trash that says it moved the item but reports another entry at the
    // destination: not accepted as done.
    #[test]
    fn a_move_that_reports_another_entry_is_not_counted_as_done() {
        struct Other(FakeTrash);
        impl Trash for Other {
            fn trash(
                &self,
                target: &TrashTarget,
                cancel: &AtomicBool,
            ) -> Result<crate::trash::Trashed, TrashError> {
                let mut done = self.0.trash(target, cancel)?;
                done.identity_after.ino += 1;
                Ok(done)
            }
        }
        let fs = world();
        let plan = low_plan(&fs);
        let other = Other(FakeTrash::new());
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from("/Users/t/Library/Caches"),
            logs: PathBuf::from("/Users/t/Library/Logs"),
        };
        let rule_ctx = RuleContext {
            min_age_days: 30,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 5),
        };
        let clock = FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 5));
        let log = FakeLog::new();
        let apps = FakeAppProbe::new();
        let cancel = AtomicBool::new(false);
        let out = Executor {
            fs: &fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: &rule_ctx,
            trash: &other,
            log: &log,
            apps: &apps,
            clock: &clock,
            cancel: &cancel,
            running_as_root: false,
            max_entries: 1_000,
        }
        .run(&plan)
        .unwrap();
        assert!(out.moved.is_empty());
        assert_eq!(
            out.stopped,
            Some(Stopped::Misplaced {
                id: id(CACHES, A),
                trash_name: "com.a".into(),
                restored: false
            })
        );
        assert_eq!(out.exit, ExitCode::SafetyStop);
        // It was asked once and the run ended there.
        assert_eq!(paths(&other.0.calls()), [A]);
    }

    // The plan is a document anyone can edit, and its hash can be recomputed:
    // risk, confirmation and the app to close are the rule's, not the plan's.
    fn archive_plan(fs: &FakeFs) -> Plan {
        make_plan(
            fs,
            &report(&[]),
            &[id(ARCHIVES, ARCHIVE)],
            &[id(ARCHIVES, ARCHIVE)],
        )
    }

    #[test]
    fn a_plan_with_a_forged_low_risk_for_a_high_rule_is_refused() {
        let fs = world();
        let mut plan = archive_plan(&fs);
        plan.items[0].risk = Risk::Low;
        plan.items[0].requires_app_closed = None;
        plan.items[0].confirmation = Confirmation::NotNeeded;
        plan.plan_hash = crate::plan::plan_hash(&plan.items);
        let mut rig = Rig::new();
        rig.apps = FakeAppProbe::new().with(XCODE, AppState::Closed);
        let out = run_on(&fs, &rig, &plan);
        assert!(
            matches!(out, Err(RunRefused::Plan(PlanError::Malformed(_)))),
            "{out:?}"
        );
        assert!(rig.trash.calls().is_empty());
        assert!(rig.log.events().is_empty());
    }

    #[test]
    fn a_high_item_without_its_own_confirmation_is_refused() {
        let fs = world();
        let honest = archive_plan(&fs);
        // Only a medium confirmation, or none at all, stands for nothing here.
        for confirmation in [Confirmation::NotNeeded, Confirmation::Confirmed] {
            let mut plan = honest.clone();
            plan.items[0].confirmation = confirmation;
            let mut rig = Rig::new();
            rig.apps = FakeAppProbe::new().with(XCODE, AppState::Closed);
            assert_eq!(
                run_on(&fs, &rig, &plan),
                Err(RunRefused::NotConfirmed),
                "{confirmation:?}"
            );
            assert!(rig.trash.calls().is_empty());
        }
        // Medium risk takes either confirmation; low takes any.
        let mut rig = Rig::new();
        rig.apps = FakeAppProbe::new().with(XCODE, AppState::Closed);
        assert!(run_on(&fs, &rig, &honest).is_ok());
    }

    #[test]
    fn a_forged_plan_without_the_app_requirement_still_asks_the_probe() {
        let fs = world();
        let mut plan = archive_plan(&fs);
        plan.items[0].requires_app_closed = None;
        plan.plan_hash = crate::plan::plan_hash(&plan.items);
        // The plan disagrees with the rule about the app: refused before acting.
        let mut rig = Rig::new();
        rig.apps = FakeAppProbe::new().with(XCODE, AppState::Running);
        let out = run_on(&fs, &rig, &plan);
        assert!(
            matches!(out, Err(RunRefused::Plan(PlanError::Malformed(_)))),
            "{out:?}"
        );
        assert!(rig.trash.calls().is_empty());
    }

    // The risk alone is forged: the rule is high, the plan says low, and the
    // confirmation and the app match the lie as well as the truth allows.
    #[test]
    fn a_plan_that_only_lowers_the_risk_is_refused() {
        let fs = world();
        let mut plan = archive_plan(&fs);
        plan.items[0].risk = Risk::Low;
        plan.plan_hash = crate::plan::plan_hash(&plan.items);
        let mut rig = Rig::new();
        rig.apps = FakeAppProbe::new().with(XCODE, AppState::Closed);
        let out = run_on(&fs, &rig, &plan);
        assert!(
            matches!(out, Err(RunRefused::Plan(PlanError::Malformed(_)))),
            "{out:?}"
        );
        assert!(rig.trash.calls().is_empty());
    }

    // A medium item needs a yes, either kind; a high one needs its own.
    #[test]
    fn a_medium_item_takes_either_confirmation_and_nothing_less() {
        let fs = world();
        let medium = |confirmation| {
            // Built with a yes, as `rain clean` would; the field is then set
            // to what the test needs.
            let mut plan = make_plan(
                &fs,
                &report(&[]),
                &[id(GO_MOD, GO_MOD_ITEM)],
                &[id(GO_MOD, GO_MOD_ITEM)],
            );
            plan.items[0].confirmation = confirmation;
            plan
        };
        for ok in [Confirmation::Confirmed, Confirmation::ConfirmedHigh] {
            let rig = Rig::new();
            let out = run_on(&fs, &rig, &medium(ok)).unwrap();
            assert_eq!(out.moved.len(), 1, "{ok:?}");
        }
        for refused in [Confirmation::NotNeeded, Confirmation::Pending] {
            let rig = Rig::new();
            assert_eq!(
                run_on(&fs, &rig, &medium(refused)),
                Err(RunRefused::NotConfirmed),
                "{refused:?}"
            );
            assert!(rig.trash.calls().is_empty());
        }
    }

    #[test]
    fn a_plan_that_names_a_rule_the_program_does_not_know_is_refused() {
        let fs = world();
        let mut plan = low_plan(&fs);
        plan.items[0].rule = RuleId::new("made.up");
        let rig = Rig::new();
        let out = run_on(&fs, &rig, &plan);
        assert!(
            matches!(out, Err(RunRefused::Plan(PlanError::Malformed(_)))),
            "{out:?}"
        );
        assert!(rig.trash.calls().is_empty());
    }

    // The wrong entry was moved: stop, with its own code and log line.
    #[test]
    fn a_misplaced_entry_stops_the_run_with_a_safety_code() {
        let fs = world();
        let mut rig = Rig::new();
        rig.trash.move_the_wrong_entry(B);
        let out = run_on(&fs, &rig, &low_plan(&fs)).unwrap();
        assert_eq!(paths(&rig.trash.calls()), [A, B]);
        assert_eq!(
            out.stopped,
            Some(Stopped::Misplaced {
                id: id(CACHES, B),
                trash_name: "com.b".into(),
                restored: false
            })
        );
        assert_eq!(out.exit, ExitCode::SafetyStop);
        assert!(rig.log.events().iter().any(|e| matches!(
            e,
            LogEvent::ItemMisplaced {
                restored: false,
                ..
            }
        )));
    }

    // Ctrl+C is looked at between items; the item in progress is not cut.
    #[test]
    fn the_cancel_flag_is_honored_between_items() {
        let fs = world();
        // Raised before the run: nothing is moved.
        let rig = Rig::new();
        rig.cancel.store(true, Ordering::SeqCst);
        let out = run_on(&fs, &rig, &low_plan(&fs)).unwrap();
        assert!(rig.trash.calls().is_empty());
        assert_eq!(out.stopped, Some(Stopped::Cancelled));
        assert_eq!(out.exit, ExitCode::Cancelled);
        // The check between items comes first: no item was even started.
        assert!(
            !rig.log
                .events()
                .iter()
                .any(|e| matches!(e, LogEvent::ItemStarted { .. })),
            "{:?}",
            rig.log.events()
        );
        // Raised during the first move: that item still ends, the next does not start.
        struct Cancelling<'a>(FakeTrash, &'a AtomicBool);
        impl Trash for Cancelling<'_> {
            fn trash(
                &self,
                target: &TrashTarget,
                _cancel: &AtomicBool,
            ) -> Result<crate::trash::Trashed, TrashError> {
                // The flag is up while this move runs: the move itself ignores it.
                self.1.store(true, Ordering::SeqCst);
                self.0.trash(target, &AtomicBool::new(false))
            }
        }
        let plan = low_plan(&fs);
        let flag = AtomicBool::new(false);
        let cancelling = Cancelling(FakeTrash::new(), &flag);
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from("/Users/t/Library/Caches"),
            logs: PathBuf::from("/Users/t/Library/Logs"),
        };
        let rule_ctx = RuleContext {
            min_age_days: 30,
            user_paths: Vec::new(),
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 5),
        };
        let clock = FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 5));
        let log = FakeLog::new();
        let apps = FakeAppProbe::new();
        let out = Executor {
            fs: &fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: &rule_ctx,
            trash: &cancelling,
            log: &log,
            apps: &apps,
            clock: &clock,
            cancel: &flag,
            running_as_root: false,
            max_entries: 1_000,
        }
        .run(&plan)
        .unwrap();
        assert_eq!(out.moved.len(), 1, "the item in progress ended");
        assert_eq!(out.stopped, Some(Stopped::Cancelled));
        assert_eq!(out.exit, ExitCode::Cancelled);
        assert!(matches!(
            log.events().last(),
            Some(LogEvent::RunFinished {
                exit: ExitCode::Cancelled,
                ..
            })
        ));
    }

    // The report keeps paths as paths: no text ready for a terminal.
    #[test]
    fn the_report_keeps_raw_paths_for_the_caller_to_escape() {
        let mut fs = world();
        let hostile = "/Users/t/Library/Caches/ev\u{1b}[31mil";
        fs.insert(hostile, md(true, 50));
        let report = report(&[scan_item(CACHES, hostile, 10)]);
        let plan = make_plan(&fs, &report, &[id(CACHES, hostile)], &[]);
        let rig = Rig::new();
        let out = run_on(&fs, &rig, &plan).unwrap();
        assert_eq!(out.moved[0].path, PathBuf::from(hostile));
    }

    // The log gets what the executor did, item by item, and says how it ended.
    #[test]
    fn the_log_ends_with_the_counts_and_the_exit_code() {
        let fs = world();
        let mut rig = Rig::new();
        rig.trash.fail(B, TrashError::PermissionDenied);
        run_on(&fs, &rig, &low_plan(&fs)).unwrap();
        assert!(matches!(
            rig.log.events().last(),
            Some(LogEvent::RunFinished {
                moved: 2,
                skipped: 1,
                bytes: 500,
                exit: ExitCode::Skips
            })
        ));
        assert!(rig.log.events().iter().any(|e| matches!(
            e,
            LogEvent::ItemSkipped {
                reason: SkipReason::PermissionDenied,
                ..
            }
        )));
    }

    // ADR 0006 §9 (property): whatever name a forged plan gives an item that is
    // or holds protected data, the executor never asks the Trash to move it.
    mod hostile {
        use super::*;
        use crate::plan::Identity;
        use proptest::prelude::*;
        use unicode_normalization::UnicodeNormalization;

        /// Protected folders and files of the real list, and their parents.
        const PROTECTED: &[&str] = &[
            ".ssh",
            ".gnupg",
            ".aws",
            "Library/Keychains",
            "Library/Safari",
            "Library/Mail",
            "Documents",
            ".claude/projects",
            ".Trash",
        ];

        /// Case, Unicode form and an added slash or dot on a protected path,
        /// or one of its parents or children.
        fn hostile_path() -> impl Strategy<Value = String> {
            (
                0..PROTECTED.len(),
                any::<bool>(),
                any::<bool>(),
                0..4usize,
                "[a-z]{1,6}",
            )
                .prop_map(|(i, upper, nfd, shape, tail)| {
                    let mut rel = PROTECTED[i].to_owned();
                    if upper {
                        rel = rel.to_uppercase();
                    }
                    if nfd {
                        rel = rel.nfd().collect();
                    }
                    match shape {
                        0 => format!("{HOME}/{rel}"),
                        1 => format!("{HOME}/{rel}/{tail}"),
                        2 => {
                            // The parent of the protected folder.
                            let parent = rel.rsplit_once('/').map_or("", |(p, _)| p).to_owned();
                            if parent.is_empty() {
                                HOME.to_owned()
                            } else {
                                format!("{HOME}/{parent}")
                            }
                        }
                        _ => format!("{HOME}/{rel}/{tail}/{tail}"),
                    }
                })
        }

        fn forged(path: &str) -> PlanItem {
            let path = PathBuf::from(path);
            let dir = Identity {
                dev: 7,
                ino: 5,
                kind: crate::plan::EntryKind::Dir,
                nlink: None,
            };
            PlanItem {
                id: ItemId::of(CACHES, &path),
                rule: CACHES,
                path,
                risk: Risk::Low,
                bytes: 1,
                file_count: 1,
                identity: dir,
                ancestors: vec![dir],
                requires_app_closed: None,
                confirmation: Confirmation::NotNeeded,
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn no_protected_item_ever_reaches_the_trash(path in hostile_path()) {
                // The disk has every protected folder, so names and identities both exist.
                let mut fs = world();
                for rel in PROTECTED {
                    let mut here = PathBuf::from(HOME);
                    for part in rel.split('/') {
                        here.push(part);
                        fs.insert(&here, md(true, 1_000 + here.to_string_lossy().len() as u64));
                    }
                }
                let hostile = PathBuf::from(&path);
                fs.insert(&hostile, md(true, 5_000));
                let plan = Plan {
                    version: crate::plan::PLAN_VERSION,
                    created_at: NOW,
                    expires_at: NOW + crate::plan::PLAN_TTL_SECS,
                    report_hash: 0,
                    plan_hash: 0,
                    home: PathBuf::from(HOME),
                    items: vec![forged(&path)],
                };
                let rig = Rig::new();
                let out = run_on(&fs, &rig, &plan);
                prop_assert!(rig.trash.calls().is_empty(), "{path:?}: {:?}", rig.trash.calls());
                if let Ok(report) = out {
                    prop_assert!(report.moved.is_empty(), "{path:?}");
                }
            }
        }
    }
}
