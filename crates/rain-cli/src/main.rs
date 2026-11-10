//! `rain`: the command-line front end.

mod args;
mod output;

use args::{Command, InvalidPath, ScanArgs};
use output::escape_for_terminal;
use rain_core::clock::Clock;
use rain_core::fs::{Fs, StdFs};
use rain_core::messages::{Catalog, MessageKey};
use rain_core::model::ScanReport;
use rain_core::planner::{self, ResolvedRoots, ScanContext, ScanError};
use rain_core::protect::{ProtectError, ProtectList};
use rain_core::rule::{Rule, RuleContext};
use rain_core::rules;
use rain_platform::{Platform, PlatformError, Root};
use signal_hook::consts::SIGINT;
use signal_hook::flag;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;

/// FR-012 exit codes.
const EXIT_RUNTIME: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_CANCELLED: u8 = 130;

/// The real clock.
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Why `rain scan` stopped without a report; each maps to an exit code.
#[derive(Debug)]
enum CliError {
    /// FR-012: exit 2, the message already localized.
    Usage(String),
    /// FR-012: exit 1.
    Runtime(String),
    /// FR-011: exit 130.
    Cancelled,
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Runtime(_) => EXIT_RUNTIME,
            CliError::Cancelled => EXIT_CANCELLED,
        }
    }
}

/// What a scan reads from the outside world, injected so tests never
/// touch the real disk (NFR-009).
struct Env<'a> {
    platform: &'a dyn Platform,
    fs: &'a dyn Fs,
    clock: &'a dyn Clock,
    /// Base for relative `--path` values.
    cwd: PathBuf,
}

/// Validates `args` (FR-008, FR-009), builds the context and runs the
/// planner. Usage errors are checked before anything is read from disk
/// beyond the given paths.
fn run_scan(
    args: &ScanArgs,
    env: &Env,
    catalog: &Catalog,
    cancel: &AtomicBool,
) -> Result<ScanReport, CliError> {
    if env.platform.is_root_user() {
        return Err(CliError::Runtime(
            catalog.get(MessageKey::RunningAsRoot).to_owned(),
        ));
    }
    let selected = select_rules(&args.rules, catalog)?;
    let user_paths =
        args::resolve_paths(env.fs, &env.cwd, &args.paths).map_err(|InvalidPath(path)| {
            CliError::Usage(
                catalog
                    .get(MessageKey::InvalidPath)
                    .replace("{path}", &escape_for_terminal(&path.display().to_string())),
            )
        })?;

    let resolve = |root| {
        env.platform
            .resolve(root)
            .map_err(|e| CliError::Runtime(home_error_message(&e, catalog)))
    };
    let roots = ResolvedRoots {
        home: resolve(Root::Home)?,
        caches: resolve(Root::Caches)?,
        logs: resolve(Root::Logs)?,
    };
    let protect = ProtectList::builtin(env.platform)
        .map_err(|e| CliError::Runtime(protect_error_message(&e, catalog)))?
        .with_identities(env.fs);

    let ctx = ScanContext {
        fs: env.fs,
        protect: &protect,
        roots: &roots,
        rule_ctx: RuleContext {
            min_age_days: args.min_age_days,
            user_paths,
            now: env.clock.now(),
        },
        threads: None,
    };
    planner::scan(&selected, &ctx, cancel).map_err(|e| match e {
        ScanError::Cancelled => CliError::Cancelled,
    })
}

/// FR-015: one localized message per kind of unusable home, with any
/// path escaped (FR-010).
fn home_error_message(e: &PlatformError, catalog: &Catalog) -> String {
    let (key, path) = match e {
        PlatformError::HomeMissing => (MessageKey::HomeMissing, None),
        PlatformError::HomeEmpty => (MessageKey::HomeEmpty, None),
        PlatformError::HomeNotAbsolute(p) => (MessageKey::HomeNotAbsolute, Some(p)),
        PlatformError::HomeNotFound(p) => (MessageKey::HomeNotFound, Some(p)),
        PlatformError::HomeNotADirectory(p) => (MessageKey::HomeNotADirectory, Some(p)),
        PlatformError::HomeNotAccessible(p) => (MessageKey::HomeNotAccessible, Some(p)),
        PlatformError::HomeIsFilesystemRoot(p) => (MessageKey::HomeIsFilesystemRoot, Some(p)),
    };
    let text = catalog.get(key);
    match path {
        Some(p) => text.replace("{path}", &escape_for_terminal(&p.display().to_string())),
        None => text.to_owned(),
    }
}

/// FR-015: a bad home stops the scan; a broken built-in list is reported as is.
fn protect_error_message(e: &ProtectError, catalog: &Catalog) -> String {
    match e {
        ProtectError::Platform(p) => home_error_message(p, catalog),
        other => catalog
            .get(MessageKey::ProtectListInvalid)
            .replace("{reason}", &escape_for_terminal(&other.to_string())),
    }
}

/// FR-011: Ctrl+C sets the returned flag, which the walker polls. A second
/// Ctrl+C while the flag is already set exits at once with 130.
fn install_cancel_handler() -> std::io::Result<Arc<AtomicBool>> {
    let cancel = Arc::new(AtomicBool::new(false));
    flag::register_conditional_shutdown(SIGINT, i32::from(EXIT_CANCELLED), Arc::clone(&cancel))?;
    flag::register(SIGINT, Arc::clone(&cancel))?;
    Ok(cancel)
}

/// Runs the scan and renders it; nothing is rendered when cancelled (FR-011).
fn scan_output(
    args: &ScanArgs,
    env: &Env,
    catalog: &Catalog,
    cancel: &AtomicBool,
) -> Result<String, CliError> {
    run_scan(args, env, catalog, cancel).and_then(|r| report_text(&r, args.json, catalog))
}

/// FR-008: no `--rule` means every built-in rule.
fn select_rules(ids: &[String], catalog: &Catalog) -> Result<Vec<&'static dyn Rule>, CliError> {
    if ids.is_empty() {
        return Ok(rules::builtin().to_vec());
    }
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    rules::select(&ids).map_err(|e| {
        let valid: Vec<&str> = e.valid.iter().map(|id| id.as_str()).collect();
        CliError::Usage(
            catalog
                .get(MessageKey::UnknownRule)
                .replace("{rule}", &escape_for_terminal(&e.id))
                .replace("{valid}", &escape_for_terminal(&valid.join(", "))),
        )
    })
}

/// FR-010, FR-014: the JSON document with `--json`, the table otherwise.
fn report_text(report: &ScanReport, json: bool, catalog: &Catalog) -> Result<String, CliError> {
    if !json {
        return Ok(output::render_table(report, catalog));
    }
    output::render_json(report).map_err(|e| {
        CliError::Runtime(
            catalog
                .get(MessageKey::RenderJsonFailed)
                .replace("{reason}", &escape_for_terminal(&e.to_string())),
        )
    })
}

/// The text written to stderr for `e`. Anything taken from the command
/// line or the disk was escaped when the error was built (FR-010).
fn error_message(e: &CliError, catalog: &Catalog) -> String {
    match e {
        CliError::Usage(msg) | CliError::Runtime(msg) => msg.clone(),
        CliError::Cancelled => catalog.get(MessageKey::ScanCancelled).to_string(),
    }
}

#[cfg(target_os = "macos")]
fn real_platform(_catalog: &Catalog) -> Result<Box<dyn Platform>, CliError> {
    Ok(Box::new(rain_platform::MacPlatform::from_env()))
}

/// FR-015: only macOS has an adapter; elsewhere the scan refuses with 1.
#[cfg(not(target_os = "macos"))]
fn real_platform(catalog: &Catalog) -> Result<Box<dyn Platform>, CliError> {
    Err(CliError::Runtime(
        catalog.get(MessageKey::UnsupportedOs).to_owned(),
    ))
}

fn main() -> anyhow::Result<ExitCode> {
    // FR-011: installed before any work so an early Ctrl+C still yields 130.
    let cancel = install_cancel_handler()?;
    let catalog = Catalog::en()?;
    let cli = match args::parse(&catalog, std::env::args_os()) {
        Ok(cli) => cli,
        Err(e) => {
            // `--help`/`--version` exit 0, usage errors 2 (FR-012).
            let code = e.exit_code();
            e.print()?;
            return Ok(ExitCode::from(u8::try_from(code).unwrap_or(EXIT_USAGE)));
        }
    };
    let Some(Command::Scan(scan)) = cli.command else {
        print!("{}", args::help(&catalog));
        return Ok(ExitCode::SUCCESS);
    };
    let cwd = std::env::current_dir()?;
    let result = real_platform(&catalog).and_then(|platform| {
        let env = Env {
            platform: platform.as_ref(),
            fs: &StdFs,
            clock: &SystemClock,
            cwd,
        };
        scan_output(&scan, &env, &catalog, &cancel)
    });
    match result {
        Ok(text) => {
            print!("{text}");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("{}", error_message(&e, &catalog));
            Ok(ExitCode::from(e.exit_code()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rain_core::clock::FixedClock;
    use rain_core::fs::{FakeFs, Metadata};
    use rain_core::model::{SkipReason, Skipped};
    use rain_platform::{FakePlatform, Os};
    use std::time::Duration;

    const HOME: &str = "/Users/t";

    fn meta(is_dir: bool, ino: u64, blocks: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink: if is_dir { 2 } else { 1 },
            blocks,
            len: blocks * 512,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    fn h(rel: &str) -> PathBuf {
        PathBuf::from(HOME).join(rel)
    }

    /// A home with caches, logs, `~/.ssh` and a file, all on dev 1.
    fn home_fs() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/", meta(true, 1, 0))
            .insert("/Users", meta(true, 2, 0))
            .insert(HOME, meta(true, 3, 0))
            .insert(h("Library"), meta(true, 4, 0))
            .insert(h("Library/Caches"), meta(true, 5, 0))
            .insert(h("Library/Caches/app"), meta(true, 6, 0))
            .insert(h("Library/Caches/app/blob"), meta(false, 7, 8))
            .insert(h("Library/Logs"), meta(true, 8, 0))
            .insert(h("Library/Logs/old.log"), meta(false, 9, 2))
            .insert(h(".ssh"), meta(true, 10, 0))
            .insert(h(".ssh/id_ed25519"), meta(false, 11, 1))
            .insert(h("notes.txt"), meta(false, 12, 1));
        fs
    }

    fn platform(home: Option<&str>) -> FakePlatform {
        FakePlatform {
            home: home.map(PathBuf::from),
            root: false,
            os: Os::Macos,
        }
    }

    fn clock() -> FixedClock {
        FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000))
    }

    fn args(argv: &[&str]) -> ScanArgs {
        let catalog = Catalog::en().unwrap();
        let mut full = vec!["rain", "scan"];
        full.extend_from_slice(argv);
        match args::parse(&catalog, full).unwrap().command {
            Some(Command::Scan(a)) => a,
            None => panic!("no subcommand"),
        }
    }

    fn run_with(
        argv: &[&str],
        fs: &FakeFs,
        platform: &FakePlatform,
    ) -> Result<ScanReport, CliError> {
        let env = Env {
            platform,
            fs,
            clock: &clock(),
            cwd: PathBuf::from(HOME),
        };
        let catalog = Catalog::en().unwrap();
        run_scan(&args(argv), &env, &catalog, &AtomicBool::new(false))
    }

    fn run(argv: &[&str]) -> Result<ScanReport, CliError> {
        run_with(argv, &home_fs(), &platform(Some(HOME)))
    }

    // FR-008, FR-012: an unknown rule is a usage error naming every rule.
    #[test]
    fn unknown_rule_exits_2_and_lists_rules() {
        let err = run(&["--rule", "sys.logs", "--rule", "nope"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        let CliError::Usage(msg) = err else {
            panic!("not a usage error: {err:?}");
        };
        assert!(msg.contains("nope"), "{msg}");
        for rule in rules::builtin() {
            assert!(msg.contains(rule.meta().id.as_str()), "{msg}");
        }
    }

    // FR-009, FR-012: a missing path or a file is a usage error.
    #[test]
    fn invalid_path_exits_2() {
        for bad in ["missing", "notes.txt", "/Users/t/missing"] {
            let err = run(&["--path", bad]).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{bad}");
            let CliError::Usage(msg) = err else {
                panic!("not a usage error");
            };
            assert!(msg.contains(bad), "{msg}");
        }
    }

    // FR-007, acceptance 4: a protected `--path` is reported as skipped,
    // nothing below it is listed, and the scan still succeeds.
    #[test]
    fn protected_path_arg_is_skipped() {
        let report = run(&["--rule", "proj.node-modules", "--path", ".ssh"]).unwrap();
        assert!(report.items.is_empty(), "{:?}", report.items);
        assert_eq!(
            report.skipped,
            [Skipped {
                path: h(".ssh"),
                reason: SkipReason::Protected,
            }]
        );
        assert_eq!(report.total_bytes, 0);
    }

    // FR-008: only the named rules run.
    #[test]
    fn rule_filter_limits_report() {
        let report = run(&["--rule", "sys.logs"]).unwrap();
        let ids: Vec<_> = report.rules.iter().map(|r| r.rule.as_str()).collect();
        assert_eq!(ids, ["sys.logs"]);
        assert_eq!(report.total_bytes, 2 * 512);
    }

    // FR-002: without `--rule`, every built-in rule is in the report.
    #[test]
    fn no_rule_filter_runs_every_rule() {
        let report = run(&[]).unwrap();
        assert_eq!(report.rules.len(), rules::builtin().len());
        assert_eq!(report.total_bytes, (8 + 2) * 512);
    }

    // FR-012: an unusable home is a runtime error, exit 1.
    #[test]
    fn invalid_home_is_runtime_error() {
        let err = run_with(&[], &home_fs(), &platform(None)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    // FR-012: usage errors win over a bad home, so the user fixes the
    // command line first.
    #[test]
    fn unknown_rule_is_checked_before_home() {
        let err = run_with(&["--rule", "nope"], &home_fs(), &platform(None)).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    // FR-011, FR-012: a cancelled scan maps to exit 130.
    #[test]
    fn cancelled_scan_exits_130() {
        let fs = home_fs();
        let p = platform(Some(HOME));
        let env = Env {
            platform: &p,
            fs: &fs,
            clock: &clock(),
            cwd: PathBuf::from(HOME),
        };
        let catalog = Catalog::en().unwrap();
        let err = run_scan(&args(&[]), &env, &catalog, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(err.exit_code(), 130);
    }

    // FR-015, FR-012, NFR-007: root, `sudo` or real uid 0 is refused with
    // exit 1 before anything is read.
    #[test]
    fn root_user_exits_1() {
        let mut p = platform(Some(HOME));
        p.root = true;
        let err = run_with(&[], &home_fs(), &p).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        let catalog = Catalog::en().unwrap();
        assert_eq!(
            error_message(&err, &catalog),
            catalog.get(MessageKey::RunningAsRoot)
        );
    }

    // FR-015, FR-012: each kind of unusable home has its own message, exit 1.
    #[test]
    fn invalid_home_exits_1() {
        let catalog = Catalog::en().unwrap();
        let cases = [
            (None, MessageKey::HomeMissing),
            (Some(""), MessageKey::HomeEmpty),
            (Some("rel/home"), MessageKey::HomeNotAbsolute),
            (Some("/"), MessageKey::HomeIsFilesystemRoot),
        ];
        for (home, key) in cases {
            let err = run_with(&[], &home_fs(), &platform(home)).unwrap_err();
            assert_eq!(err.exit_code(), 1, "{home:?}");
            let expected = catalog
                .get(key)
                .replace("{path}", &escape_for_terminal(home.unwrap_or("")));
            assert_eq!(error_message(&err, &catalog), expected, "{home:?}");
        }
        for e in [
            PlatformError::HomeNotFound(PathBuf::from("/x")),
            PlatformError::HomeNotADirectory(PathBuf::from("/x")),
            PlatformError::HomeNotAccessible(PathBuf::from("/x")),
        ] {
            let msg = home_error_message(&e, &catalog);
            assert!(msg.contains("/x"), "{msg}");
            assert!(!msg.contains("{path}"), "{msg}");
        }
        let distinct: std::collections::BTreeSet<_> = [
            MessageKey::HomeMissing,
            MessageKey::HomeEmpty,
            MessageKey::HomeNotAbsolute,
            MessageKey::HomeNotFound,
            MessageKey::HomeNotADirectory,
            MessageKey::HomeNotAccessible,
            MessageKey::HomeIsFilesystemRoot,
        ]
        .iter()
        .map(|k| catalog.get(*k))
        .collect();
        assert_eq!(distinct.len(), 7);
    }

    // FR-011, FR-012: Ctrl+C sets the scan's cancel flag; the scan then
    // exits 130 and prints no report or total.
    #[test]
    fn sigint_exits_130_without_total() {
        let cancel = install_cancel_handler().unwrap();
        assert!(!cancel.load(std::sync::atomic::Ordering::SeqCst));
        signal_hook::low_level::raise(signal_hook::consts::SIGINT).unwrap();
        assert!(cancel.load(std::sync::atomic::Ordering::SeqCst));

        let fs = home_fs();
        let p = platform(Some(HOME));
        let env = Env {
            platform: &p,
            fs: &fs,
            clock: &clock(),
            cwd: PathBuf::from(HOME),
        };
        let catalog = Catalog::en().unwrap();
        let err = scan_output(&args(&[]), &env, &catalog, &cancel).unwrap_err();
        assert_eq!(err.exit_code(), 130);
        let msg = error_message(&err, &catalog);
        assert_eq!(msg, catalog.get(MessageKey::ScanCancelled));
        assert!(!msg.contains(catalog.get(MessageKey::TableTotal)), "{msg}");
    }

    /// Control, bidi and OSC 52 payloads an attacker could put in a name.
    const NASTY: &str = "a\x1b[2Kb\rc\nd\x1b]52;c;cHduZWQ=\x07e\u{202e}f";

    fn assert_no_raw_controls(msg: &str) {
        for bad in ['\x1b', '\r', '\n', '\x07', '\u{202e}'] {
            assert!(!msg.contains(bad), "raw {:?} in {msg:?}", bad);
        }
    }

    // FR-010, FR-012: a hostile `--path` is escaped in the stderr message.
    #[test]
    fn invalid_path_message_is_escaped() {
        let err = run(&["--path", NASTY]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        let msg = error_message(&err, &Catalog::en().unwrap());
        assert_no_raw_controls(&msg);
        assert!(msg.contains("\\x1b[2K"), "{msg}");
    }

    // FR-010, FR-012: a hostile home path is escaped in the stderr message.
    #[test]
    fn invalid_home_message_is_escaped() {
        let err = run_with(&[], &home_fs(), &platform(Some(NASTY))).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        let msg = error_message(&err, &Catalog::en().unwrap());
        assert_no_raw_controls(&msg);
        assert!(msg.contains("\\u{202e}"), "{msg}");
    }

    // FR-008, FR-010: a hostile `--rule` is escaped in the stderr message.
    #[test]
    fn unknown_rule_message_is_escaped() {
        let err = run(&["--rule", NASTY]).unwrap_err();
        let msg = error_message(&err, &Catalog::en().unwrap());
        assert_no_raw_controls(&msg);
    }

    // FR-014: without `--json` the report is the table.
    #[test]
    fn default_output_is_table() {
        let catalog = Catalog::en().unwrap();
        let report = run(&[]).unwrap();
        let out = report_text(&report, false, &catalog).unwrap();
        assert_eq!(out, output::render_table(&report, &catalog));
    }

    // FR-010: with `--json` the report is the JSON document.
    #[test]
    fn json_flag_outputs_json() {
        let catalog = Catalog::en().unwrap();
        let report = run(&["--json"]).unwrap();
        let out = report_text(&report, true, &catalog).unwrap();
        assert_eq!(out, output::render_json(&report).unwrap());
    }

    // FR-010, acceptance 7: the same fixture gives byte-identical JSON.
    #[test]
    fn json_output_is_deterministic() {
        let catalog = Catalog::en().unwrap();
        let once = || report_text(&run(&["--json"]).unwrap(), true, &catalog).unwrap();
        assert_eq!(once().into_bytes(), once().into_bytes());
    }

    // FR-007: a `--path` reached through a symlink to `~/.ssh` is still
    // protected, because the path is canonicalized first.
    #[test]
    fn path_through_symlink_to_ssh_is_protected() {
        let mut fs = home_fs();
        fs.insert(h(".ssh/keys"), meta(true, 13, 0))
            .insert_symlink(h("link"), h(".ssh"))
            // `lstat` follows symlinks in ancestors, so the real OS reports
            // `link/keys` as the directory; FakeFs only does exact lookups.
            .insert(h("link/keys"), meta(true, 13, 0));
        let report = run_with(
            &["--rule", "proj.node-modules", "--path", "link/keys"],
            &fs,
            &platform(Some(HOME)),
        )
        .unwrap();
        assert!(report.items.is_empty(), "{:?}", report.items);
        assert_eq!(
            report.skipped,
            [Skipped {
                path: h(".ssh/keys"),
                reason: SkipReason::Protected,
            }]
        );
    }
}
