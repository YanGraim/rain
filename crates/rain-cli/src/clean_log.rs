//! The cleaning log (ADR 0006 §5 and §6): JSON lines written by the executor,
//! and the gate that decides whether a real run may start. The log is a
//! convenience gate, not a security boundary: whoever writes it can forge it.

use rain_core::executor::{CleanLog, LogError, LogEvent, SkipReason, TrashFailure};
use rain_platform::clean_log::{CleanLogFile, LogError as FileError};
use serde_json::{json, Value};
use std::path::Path;

/// Whether a real run may start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Allowed,
    /// No dry run of this plan is in the log.
    NeedsDryRun,
    /// The log exists but cannot be read: the gate fails closed.
    Unreadable,
}

/// The gate for `plan_hash` (hex), from the text of the log.
pub fn gate_from_text(text: &str, plan_hash: &str) -> Gate {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut dry_run_seen = false;
    let mut real_run_done = false;
    for (i, line) in lines.iter().enumerate() {
        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            // A last line cut by a crash is ignored; any other bad line is not.
            Err(_) if i + 1 == lines.len() => continue,
            Err(_) => return Gate::Unreadable,
        };
        match value.get("event").and_then(Value::as_str) {
            Some("plan_created")
                if value.get("dry_run") == Some(&Value::Bool(true))
                    && value.get("plan_hash").and_then(Value::as_str) == Some(plan_hash) =>
            {
                dry_run_seen = true;
            }
            Some("run_finished") if value.get("dry_run") == Some(&Value::Bool(false)) => {
                real_run_done = true;
            }
            _ => {}
        }
    }
    // Once a real run has finished, the dry-run gate no longer applies.
    if real_run_done || dry_run_seen {
        Gate::Allowed
    } else {
        Gate::NeedsDryRun
    }
}

/// The gate read from the log file at `path`. A missing log means no run
/// before: a dry run is needed.
pub fn gate_at(path: &Path, plan_hash: &str) -> Gate {
    if std::fs::symlink_metadata(path).is_err() {
        return Gate::NeedsDryRun;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => gate_from_text(&text, plan_hash),
        Err(_) => Gate::Unreadable,
    }
}

/// One line for the dry run's plan (`plan_created`).
pub fn plan_created_line(run: &str, ts: u64, plan_hash: u64, items: usize) -> String {
    json!({
        "v": 1, "ts": ts, "run": run, "event": "plan_created",
        "dry_run": true, "plan_hash": format!("{plan_hash:016x}"), "items": items,
    })
    .to_string()
}

/// One line for an executor event. Paths and names are escaped the way the
/// terminal escapes them (ADR 0006 §5).
pub fn encode(event: &LogEvent, run: &str, ts: u64) -> String {
    let p = |path: &Path| crate::output::escape_for_terminal(&path.display().to_string());
    let n = |name: &std::ffi::OsString| crate::output::escape_for_terminal(&name.to_string_lossy());
    let base = |name: &str| json!({ "v": 1, "ts": ts, "run": run, "event": name });
    let mut v = match event {
        LogEvent::RunStarted { plan_hash, items } => {
            let mut v = base("run_started");
            v["plan_hash"] = json!(format!("{plan_hash:016x}"));
            v["items"] = json!(items);
            v["dry_run"] = json!(false);
            v
        }
        LogEvent::ItemStarted {
            id,
            rule,
            path,
            bytes,
        } => {
            let mut v = base("item_started");
            v["id"] = json!(format!("{:016x}", id.0));
            v["rule"] = json!(rule.to_string());
            v["path"] = json!(p(path));
            v["bytes"] = json!(bytes);
            v
        }
        LogEvent::ItemTrashed {
            id,
            path,
            trash_name,
            bytes,
        } => {
            let mut v = base("item_trashed");
            v["id"] = json!(format!("{:016x}", id.0));
            v["path"] = json!(p(path));
            v["trash_name"] = json!(n(trash_name));
            v["bytes"] = json!(bytes);
            v
        }
        LogEvent::ItemSkipped { id, path, reason } => {
            let mut v = base("item_skipped");
            v["id"] = json!(format!("{:016x}", id.0));
            v["path"] = json!(p(path));
            v["reason"] = json!(skip_name(*reason));
            v
        }
        LogEvent::ItemMisplaced {
            id,
            path,
            trash_name,
            restored,
        } => {
            let mut v = base("item_misplaced");
            v["id"] = json!(format!("{:016x}", id.0));
            v["path"] = json!(p(path));
            v["trash_name"] = json!(n(trash_name));
            v["restored"] = json!(restored);
            v
        }
        LogEvent::TrashFailed { id, path, kind } => {
            let mut v = base("trash_failed");
            v["id"] = json!(format!("{:016x}", id.0));
            v["path"] = json!(p(path));
            v["kind"] = json!(failure_name(*kind));
            v
        }
        LogEvent::RunFinished {
            moved,
            skipped,
            bytes,
            exit,
        } => {
            let mut v = base("run_finished");
            v["moved"] = json!(moved);
            v["skipped"] = json!(skipped);
            v["bytes"] = json!(bytes);
            v["exit"] = json!(*exit as u8);
            v["dry_run"] = json!(false);
            v
        }
    };
    if v.get("dry_run").is_none() {
        v["dry_run"] = json!(false);
    }
    v.to_string()
}

fn skip_name(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::Gone => "gone",
        SkipReason::ChangedSincePlan => "changed",
        SkipReason::RuleNoLongerClaims => "rule-no-longer-claims",
        SkipReason::OtherVolume => "other-volume",
        SkipReason::Unverifiable => "unverifiable",
        SkipReason::AppRunning => "app-running",
        SkipReason::PermissionDenied => "permission-denied",
        SkipReason::NotConfirmed => "not-confirmed",
    }
}

fn failure_name(kind: TrashFailure) -> &'static str {
    match kind {
        TrashFailure::Unavailable => "unavailable",
        TrashFailure::NameExhausted => "name-exhausted",
        TrashFailure::Io => "io",
    }
}

/// The executor's log: one line per event, synced when asked.
pub struct FileCleanLog {
    file: CleanLogFile,
    run: String,
    ts: u64,
}

impl FileCleanLog {
    pub fn open(
        path: impl Into<std::path::PathBuf>,
        run: String,
        ts: u64,
    ) -> Result<Self, FileError> {
        Ok(FileCleanLog {
            file: CleanLogFile::open(path)?,
            run,
            ts,
        })
    }
}

impl CleanLog for FileCleanLog {
    fn record(&self, event: &LogEvent) -> Result<(), LogError> {
        self.file
            .append(&encode(event, &self.run, self.ts))
            .map_err(|_| LogError)
    }

    fn sync(&self) -> Result<(), LogError> {
        self.file.sync().map_err(|_| LogError)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use rain_core::executor::ExitCode;
    use rain_core::model::ItemId;
    use std::path::PathBuf;

    const HASH: &str = "00000000000000ab";

    fn created(hash: &str, dry: bool) -> String {
        format!(
            r#"{{"v":1,"ts":1,"run":"r","event":"plan_created","dry_run":{dry},"plan_hash":"{hash}"}}"#
        )
    }

    #[test]
    fn no_log_means_a_dry_run_is_needed() {
        assert_eq!(gate_from_text("", HASH), Gate::NeedsDryRun);
    }

    #[test]
    fn a_dry_run_of_the_same_plan_allows_the_real_run() {
        let text = format!("{}\n", created(HASH, true));
        assert_eq!(gate_from_text(&text, HASH), Gate::Allowed);
    }

    #[test]
    fn a_dry_run_of_another_plan_does_not_allow_it() {
        let text = format!("{}\n", created("0000000000000001", true));
        assert_eq!(gate_from_text(&text, HASH), Gate::NeedsDryRun);
    }

    #[test]
    fn a_real_plan_line_is_not_a_dry_run() {
        let text = format!("{}\n", created(HASH, false));
        assert_eq!(gate_from_text(&text, HASH), Gate::NeedsDryRun);
    }

    #[test]
    fn a_finished_real_run_lifts_the_gate() {
        let text = format!(
            "{}\n{}\n",
            created(HASH, false),
            r#"{"v":1,"ts":2,"run":"r","event":"run_finished","dry_run":false,"moved":1}"#
        );
        assert_eq!(gate_from_text(&text, "ffff"), Gate::Allowed);
    }

    #[test]
    fn a_bad_line_in_the_middle_fails_closed() {
        let text = format!(
            "{}\nnot json\n{}\n",
            created(HASH, true),
            created(HASH, true)
        );
        assert_eq!(gate_from_text(&text, HASH), Gate::Unreadable);
    }

    #[test]
    fn a_last_line_cut_by_a_crash_is_ignored() {
        let text = format!("{}\n{{\"v\":1,\"ev", created(HASH, true));
        assert_eq!(gate_from_text(&text, HASH), Gate::Allowed);
    }

    #[test]
    fn a_missing_file_needs_a_dry_run_and_an_unreadable_one_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(gate_at(&dir.path().join("none"), HASH), Gate::NeedsDryRun);
        let bad = dir.path().join("bad");
        std::fs::write(&bad, [0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(gate_at(&bad, HASH), Gate::Unreadable);
    }

    #[test]
    fn an_item_line_escapes_a_bidi_path_and_keeps_one_line() {
        let event = LogEvent::ItemTrashed {
            id: ItemId(0xab),
            path: PathBuf::from("/Users/t/a\u{202E}b\nc"),
            trash_name: std::ffi::OsString::from("x"),
            bytes: 3,
        };
        let line = encode(&event, "run1", 7);
        assert!(!line.contains('\n'));
        assert!(!line.contains('\u{202E}'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["event"], "item_trashed");
        assert_eq!(v["id"], "00000000000000ab");
        assert_eq!(v["dry_run"], false);
    }

    #[test]
    fn a_run_finished_line_carries_the_exit_code() {
        let event = LogEvent::RunFinished {
            moved: 2,
            skipped: 1,
            bytes: 9,
            exit: ExitCode::SafetyStop,
        };
        let v: Value = serde_json::from_str(&encode(&event, "r", 1)).unwrap();
        assert_eq!(v["exit"], 4);
        assert_eq!(v["dry_run"], false);
    }

    #[test]
    fn the_dry_run_line_is_read_back_by_the_gate() {
        let line = plan_created_line("r", 1, 0xab, 2);
        assert_eq!(gate_from_text(&line, HASH), Gate::Allowed);
    }
}
