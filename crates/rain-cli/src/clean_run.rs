//! `rain clean` for real (ADR 0006 §4 to §7): probe the Trash, ask for each
//! item that needs it, build the final plan, check the dry-run gate on that
//! plan, run the executor and report what moved. Off until the Finder check
//! (`REAL_CLEAN_ENABLED`): `clean_output` refuses the real run before this.

use crate::clean_log::{gate_at, plan_created_line, FileCleanLog, Gate};
use crate::output::escape_for_terminal;
use crate::trash::PlatformTrash;
use crate::{CliError, Env};
use rain_core::executor::{AppProbe, AppState, Executor, RunRefused, RunReport, Stopped};
use rain_core::messages::{Catalog, MessageKey};
use rain_core::model::{ItemId, Risk, ScanReport};
use rain_core::plan::{BuildContext, Confirmations, Plan, Selection};
use rain_core::planner::ResolvedRoots;
use rain_core::protect::ProtectList;
use rain_core::rule::RuleContext;
use rain_core::trash::TrashError;
use rain_platform::Root;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

/// The real run stays off until the Finder check of the Trash is done (the
/// Yan decides when it is turned on, in its own PR).
pub const REAL_CLEAN_ENABLED: bool = false;

/// The executor's budget for the entries it reads in one folder.
const MAX_ENTRIES: usize = 1_000_000;

/// Apps that must be closed are not known yet (the app probe is PR 8), so
/// every such item is left in place.
struct NoAppProbe;

impl AppProbe for NoAppProbe {
    fn state(&self, _bundle_id: &str) -> AppState {
        AppState::Unknown
    }
}

/// The program that runs Rain, named in the messages a denied Trash gives.
pub fn running_app() -> String {
    std::env::var("TERM_PROGRAM")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        })
        .unwrap_or_else(|| "rain".to_string())
}

/// `~/Library/Logs/Rain`, created 0700 if it is missing.
fn log_folder(logs_root: &Path) -> PathBuf {
    let folder = logs_root.join("Rain");
    let _ = rain_platform::clean_log::create_private_folder(&folder);
    folder.join("clean.jsonl")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes the dry run's plan to the log, so a real run of the same plan is
/// allowed (ADR 0006 §6). A log that cannot be written only means the real
/// run will ask for a dry run again; nothing is moved by this.
pub fn record_dry_run(env: &Env, plan: &Plan) {
    let Ok(logs) = env.platform.resolve(Root::Logs) else {
        return;
    };
    let path = log_folder(&logs);
    if let Ok(file) = rain_platform::clean_log::CleanLogFile::open(&path) {
        let line = plan_created_line(&run_id(), now_secs(), plan.plan_hash, plan.items.len());
        if file.append(&line).is_ok() {
            let _ = file.sync();
        }
    }
}

fn run_id() -> String {
    format!("{:x}", now_secs())
}

/// The answer that accepts an item: `s` or `y`, in any case.
fn accepted(answer: &str) -> bool {
    matches!(answer.trim().chars().next(), Some('s' | 'S' | 'y' | 'Y'))
}

/// Asks, one by one, for each item that needs a confirmation. Returns the ids
/// the user accepted, and those accepted for medium and high risk.
fn ask(plan: &Plan, catalog: &Catalog) -> Result<(Vec<ItemId>, Selection), CliError> {
    let mut input = io::stdin().lock();
    let mut accepted_ids = Vec::new();
    let mut confirmed = Vec::new();
    let mut confirmed_high = Vec::new();
    for item in &plan.items {
        let key = match item.risk {
            Risk::Low => {
                accepted_ids.push(item.id);
                continue;
            }
            Risk::Medium => MessageKey::CleanConfirmItem,
            Risk::High => MessageKey::CleanConfirmHigh,
        };
        let path = escape_for_terminal(&item.path.display().to_string());
        print!("{}", catalog.get(key).replace("{path}", &path));
        print!(" ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        input
            .read_line(&mut line)
            .map_err(|e| CliError::Runtime(e.to_string()))?;
        if accepted(&line) {
            accepted_ids.push(item.id);
            if item.risk == Risk::High {
                confirmed_high.push(item.id);
            } else {
                confirmed.push(item.id);
            }
        }
    }
    let selection = Selection {
        ids: accepted_ids.clone(),
        confirmed,
        confirmed_high,
    };
    Ok((accepted_ids, selection))
}

/// The real run of `rain clean`. Returns the text to print on success;
/// a stop or a non-zero outcome is `CliError::Finished`.
#[allow(clippy::too_many_arguments)]
pub fn real_run(
    env: &Env,
    catalog: &Catalog,
    cancel: &AtomicBool,
    report: &ScanReport,
    protect: &ProtectList,
    home: &Path,
    preview: &Plan,
    min_age_days: u32,
    user_paths: Vec<PathBuf>,
) -> Result<String, CliError> {
    // 1. The Trash must open before anything is asked.
    let trash_path = home.join(".Trash");
    let trash = PlatformTrash::at(&trash_path);
    match trash.probe() {
        Ok(()) => {}
        Err(TrashError::TrashUnavailable(io::ErrorKind::PermissionDenied)) => {
            return Err(CliError::TrashDenied(crate::trash_denied_message(
                catalog,
                &running_app(),
            )));
        }
        Err(_) => {
            return Err(CliError::Runtime(
                catalog.get(MessageKey::CleanStoppedTrash).to_owned(),
            ));
        }
    }

    // 2. Ask for each item that needs a confirmation.
    let (accepted_ids, selection) = ask(preview, catalog)?;
    if accepted_ids.is_empty() {
        return Err(CliError::Runtime(
            catalog.get(MessageKey::CleanNoneConfirmed).to_owned(),
        ));
    }

    // 3. The final plan: the dry run gate is checked on this plan's hash.
    let ctx = BuildContext {
        fs: env.fs,
        protect,
        clock: env.clock,
        home,
    };
    let plan = Plan::build(report, &selection, Confirmations::Required, &ctx)
        .map_err(|e| CliError::Runtime(crate::plan_error_message(&e, catalog)))?;

    // 4. The gate: the dry run of this exact plan, or a finished real run.
    let logs = env
        .platform
        .resolve(Root::Logs)
        .map_err(|_| CliError::Runtime(catalog.get(MessageKey::CleanStoppedLog).to_owned()))?;
    let log_path = log_folder(&logs);
    let hash = format!("{:016x}", plan.plan_hash);
    match gate_at(&log_path, &hash) {
        Gate::Allowed => {}
        Gate::NeedsDryRun => {
            return Err(CliError::Runtime(
                catalog.get(MessageKey::CleanNeedDryRun).to_owned(),
            ));
        }
        Gate::Unreadable => {
            return Err(CliError::Runtime(
                catalog.get(MessageKey::CleanLogUnreadable).to_owned(),
            ));
        }
    }

    // 5. The executor, with the real Trash and the real log.
    let log = FileCleanLog::open(&log_path, run_id(), now_secs())
        .map_err(|_| CliError::Runtime(catalog.get(MessageKey::CleanStoppedLog).to_owned()))?;
    let caches = env
        .platform
        .resolve(Root::Caches)
        .map_err(|_| CliError::Runtime(catalog.get(MessageKey::CleanStoppedSafety).to_owned()))?;
    let roots = ResolvedRoots {
        home: home.to_path_buf(),
        caches,
        logs,
    };
    let rule_ctx = RuleContext {
        min_age_days,
        user_paths,
        now: env.clock.now(),
    };
    let apps = NoAppProbe;
    let executor = Executor {
        fs: env.fs,
        protect,
        roots: &roots,
        rule_ctx: &rule_ctx,
        trash: &trash,
        log: &log,
        apps: &apps,
        clock: env.clock,
        cancel,
        running_as_root: env.platform.is_root_user(),
        max_entries: MAX_ENTRIES,
    };
    let outcome = executor.run(&plan).map_err(|e| match e {
        RunRefused::Root => CliError::Runtime(catalog.get(MessageKey::RunningAsRoot).to_owned()),
        RunRefused::Log => CliError::Runtime(catalog.get(MessageKey::CleanStoppedLog).to_owned()),
        other => CliError::Runtime(other.to_string()),
    })?;
    finish(&outcome, catalog)
}

/// What the run did, as text, and the exit code it ends with.
fn finish(report: &RunReport, catalog: &Catalog) -> Result<String, CliError> {
    let mut text = String::new();
    for moved in &report.moved {
        let line = catalog
            .get(MessageKey::CleanMovedLine)
            .replace(
                "{path}",
                &escape_for_terminal(&moved.path.display().to_string()),
            )
            .replace(
                "{trash_name}",
                &escape_for_terminal(&moved.trash_name.to_string_lossy()),
            );
        text.push_str(&line);
        text.push('\n');
    }
    let summary = catalog
        .get(MessageKey::CleanRunSummary)
        .replace("{moved}", &report.moved.len().to_string())
        .replace("{skipped}", &report.left.len().to_string());
    text.push_str(&summary);
    text.push('\n');
    if !report.moved.is_empty() {
        text.push_str(catalog.get(MessageKey::CleanRestoreHint));
        text.push('\n');
    }
    let stop = match &report.stopped {
        None => None,
        Some(Stopped::Safety { .. }) => Some(MessageKey::CleanStoppedSafety),
        Some(Stopped::Trash { .. }) => Some(MessageKey::CleanStoppedTrash),
        Some(Stopped::Log) => Some(MessageKey::CleanStoppedLog),
        Some(Stopped::Cancelled) => Some(MessageKey::CleanStoppedCancelled),
        Some(Stopped::Misplaced { trash_name, .. }) => {
            text.push_str(&catalog.get(MessageKey::CleanStoppedMisplaced).replace(
                "{trash_name}",
                &escape_for_terminal(&trash_name.to_string_lossy()),
            ));
            text.push('\n');
            None
        }
    };
    if let Some(key) = stop {
        text.push_str(catalog.get(key));
        text.push('\n');
    }
    let code = report.exit as u8;
    if code == 0 {
        Ok(text)
    } else {
        Err(CliError::Finished { code, text })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rain_core::executor::{ExitCode, Stopped};
    use rain_core::messages::Locale;
    use std::ffi::OsString;

    #[test]
    fn only_an_explicit_yes_accepts_an_item() {
        for yes in ["s", "S", "y", "Y", " s\n", "sim"] {
            assert!(accepted(yes), "{yes:?}");
        }
        for no in ["", "n", "N", "x", "\n", "nao"] {
            assert!(!accepted(no), "{no:?}");
        }
    }

    fn report(moved: usize, stopped: Option<Stopped>, exit: ExitCode) -> RunReport {
        RunReport {
            moved: (0..moved)
                .map(|i| rain_core::executor::Moved {
                    id: ItemId(i as u64),
                    path: PathBuf::from(format!("/Users/t/Library/Caches/x{i}")),
                    trash_name: OsString::from(format!("x{i}")),
                    bytes: 1,
                })
                .collect(),
            left: Vec::new(),
            stopped,
            exit,
        }
    }

    #[test]
    fn a_clean_run_is_ok_and_a_stopped_one_carries_its_exit_code() {
        let catalog = Catalog::en().unwrap();
        let ok = finish(&report(1, None, ExitCode::Done), &catalog).unwrap();
        assert!(ok.contains("1 items") || ok.contains("1 item"), "{ok}");
        assert!(ok.contains("x0"), "the trash name is shown: {ok}");
        match finish(
            &report(
                0,
                Some(Stopped::Safety {
                    id: ItemId(1),
                    why: rain_core::revalidate::Stop::SymlinkInPath,
                }),
                ExitCode::SafetyStop,
            ),
            &catalog,
        ) {
            Err(CliError::Finished { code, .. }) => assert_eq!(code, 4),
            other => panic!("expected Finished 4, got {other:?}"),
        }
        match finish(
            &report(
                0,
                Some(Stopped::Trash {
                    id: ItemId(1),
                    why: rain_core::executor::TrashFailure::Unavailable,
                }),
                ExitCode::TrashFailure,
            ),
            &catalog,
        ) {
            Err(CliError::Finished { code, .. }) => assert_eq!(code, 5),
            other => panic!("expected Finished 5, got {other:?}"),
        }
    }

    #[test]
    fn a_misplaced_entry_is_named_in_the_summary_and_stops_with_4() {
        let catalog = Catalog::en().unwrap();
        let r = report(
            0,
            Some(Stopped::Misplaced {
                id: ItemId(9),
                trash_name: OsString::from("other"),
                restored: true,
            }),
            ExitCode::SafetyStop,
        );
        match finish(&r, &catalog) {
            Err(CliError::Finished { code, text }) => {
                assert_eq!(code, 4);
                assert!(text.contains("other"), "{text}");
            }
            other => panic!("expected Finished, got {other:?}"),
        }
    }

    #[test]
    fn the_run_messages_exist_in_every_language() {
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for key in [
                MessageKey::CleanRealDisabled,
                MessageKey::CleanNeedDryRun,
                MessageKey::CleanLogUnreadable,
                MessageKey::CleanConfirmItem,
                MessageKey::CleanConfirmHigh,
                MessageKey::CleanRunSummary,
                MessageKey::CleanRestoreHint,
                MessageKey::CleanStoppedSafety,
                MessageKey::CleanStoppedTrash,
                MessageKey::CleanStoppedLog,
                MessageKey::CleanNoneConfirmed,
            ] {
                assert!(!catalog.get(key).is_empty(), "{locale:?} {key:?}");
            }
        }
    }
}
