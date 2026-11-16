//! `rain`: the command-line front end.

mod args;
mod output;
mod tools;

use args::{CleanArgs, Command, InvalidPath, OutsideHome, ScanArgs};
use output::escape_for_terminal;
use rain_core::clock::Clock;
use rain_core::fs::{Fs, StdFs};
use rain_core::messages::{Catalog, MessageKey};
use rain_core::model::{ItemId, RuleId, ScanReport};
use rain_core::plan::{BuildContext, Confirmations, Plan, PlanError, Selection};
use rain_core::planner::{self, ResolvedRoots, ScanContext, ScanError};
use rain_core::protect::{ProtectError, ProtectList};
use rain_core::rule::{Rule, RuleContext};
use rain_core::rules;
use rain_core::tools::ToolRunner;
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
    /// Runs external tools for provider rules.
    tools: &'a dyn ToolRunner,
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
    args::ensure_inside_home(env.fs, &roots.home, &args.paths, &user_paths).map_err(
        |OutsideHome(path)| {
            CliError::Usage(
                catalog
                    .get(MessageKey::PathOutsideHome)
                    .replace("{path}", &escape_for_terminal(&path.display().to_string())),
            )
        },
    )?;
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
        tools: env.tools,
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

/// `rain clean --dry-run` (ADR 0006): scans, makes the plan and shows it.
/// Nothing is moved or deleted: there is no executor yet.
fn clean_output(
    args: &CleanArgs,
    env: &Env,
    catalog: &Catalog,
    cancel: &AtomicBool,
) -> Result<String, CliError> {
    let ids = args
        .items
        .iter()
        .map(|raw| parse_item_id(raw, catalog))
        .collect::<Result<Vec<_>, _>>()?;
    let report = run_scan(&args.scan_args(), env, catalog, cancel)?;
    // No `--item`: what the preselected (low risk) rules found.
    let ids = if ids.is_empty() {
        let preselected: Vec<RuleId> = report
            .rules
            .iter()
            .filter(|r| r.default_selected)
            .map(|r| r.rule)
            .collect();
        report
            .items
            .iter()
            .filter(|i| preselected.contains(&i.rule))
            .map(|i| i.id)
            .collect()
    } else {
        ids
    };
    if ids.is_empty() {
        return Ok(format!("{}\n", catalog.get(MessageKey::CleanNothing)));
    }
    let home = env
        .platform
        .resolve(Root::Home)
        .map_err(|e| CliError::Runtime(home_error_message(&e, catalog)))?;
    let protect = ProtectList::builtin(env.platform)
        .map_err(|e| CliError::Runtime(protect_error_message(&e, catalog)))?
        .with_identities(env.fs);
    let ctx = BuildContext {
        fs: env.fs,
        protect: &protect,
        clock: env.clock,
        home: &home,
    };
    // A dry run: what needs a confirmation is marked, not asked for.
    let selection = Selection {
        ids,
        ..Selection::default()
    };
    let plan = Plan::build(&report, &selection, Confirmations::Preview, &ctx)
        .map_err(|e| CliError::Runtime(plan_error_message(&e, catalog)))?;
    if args.json {
        Ok(format!("{}\n", plan.to_json()))
    } else {
        Ok(output::render_plan_preview(&plan, catalog))
    }
}

/// An item id as the JSON report prints it: 16 hexadecimal digits.
fn parse_item_id(raw: &str, catalog: &Catalog) -> Result<ItemId, CliError> {
    if raw.len() == 16 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(n) = u64::from_str_radix(raw, 16) {
            return Ok(ItemId(n));
        }
    }
    Err(CliError::Usage(
        catalog
            .get(MessageKey::InvalidItem)
            .replace("{item}", &escape_for_terminal(raw)),
    ))
}

/// One localized message for each reason a plan was refused.
fn plan_error_message(e: &PlanError, catalog: &Catalog) -> String {
    let with_id =
        |key: MessageKey, id: u64| catalog.get(key).replace("{id}", &format!("{id:016x}"));
    match e {
        PlanError::UnknownItem(id) => with_id(MessageKey::CleanErrorUnknownItem, *id),
        PlanError::ToolItem(id) => with_id(MessageKey::CleanErrorToolItem, *id),
        PlanError::HasExcludedSubtree(id) => with_id(MessageKey::CleanErrorExcluded, *id),
        PlanError::Protected(id) => with_id(MessageKey::CleanErrorProtected, *id),
        PlanError::TrashInvolved(id) => with_id(MessageKey::CleanErrorTrash, *id),
        PlanError::NonUtf8Path(id) => with_id(MessageKey::CleanErrorNonUtf8, *id),
        PlanError::Gone(id) => with_id(MessageKey::CleanErrorGone, *id),
        PlanError::Symlink(id) => with_id(MessageKey::CleanErrorSymlink, *id),
        PlanError::OutsideHome(id) => with_id(MessageKey::CleanErrorOutsideHome, *id),
        PlanError::Unreadable(id) => with_id(MessageKey::CleanErrorUnreadable, *id),
        PlanError::ClockBeforeEpoch => catalog.get(MessageKey::CleanErrorClock).to_owned(),
        other => catalog
            .get(MessageKey::CleanErrorOther)
            .replace("{reason}", &escape_for_terminal(&other.to_string())),
    }
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
    let Some(command) = cli.command else {
        print!("{}", args::help(&catalog));
        return Ok(ExitCode::SUCCESS);
    };
    let cwd = std::env::current_dir()?;
    let result = real_platform(&catalog).and_then(|platform| {
        let home = platform
            .resolve(Root::Home)
            .map_err(|e| CliError::Runtime(home_error_message(&e, &catalog)))?;
        let tools = tools::PlatformTools::new(home);
        let env = Env {
            platform: platform.as_ref(),
            fs: &StdFs,
            clock: &SystemClock,
            tools: &tools,
            cwd,
        };
        match &command {
            Command::Scan(scan) => scan_output(scan, &env, &catalog, &cancel),
            Command::Clean(clean) => clean_output(clean, &env, &catalog, &cancel),
        }
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
            _ => panic!("not a scan"),
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
            tools: &rain_core::tools::NoTools,
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

    fn outside_home_fs() -> FakeFs {
        let mut fs = home_fs();
        fs.insert("/Users/other", meta(true, 20, 0))
            .insert("/Users/other/sub", meta(true, 21, 0))
            .insert("/Volumes", meta(true, 22, 0))
            .insert("/Volumes/x", meta(true, 23, 0))
            .insert_symlink(h("out"), "/Users/other")
            // `lstat` follows symlinks in ancestors; FakeFs only does exact lookups.
            .insert(h("out/sub"), meta(true, 21, 0))
            .insert(h("../other"), meta(true, 20, 0));
        fs
    }

    fn assert_outside_home(path: &str) {
        let err =
            run_with(&["--path", path], &outside_home_fs(), &platform(Some(HOME))).unwrap_err();
        assert_eq!(err.exit_code(), 2, "{path}");
        let catalog = Catalog::en().unwrap();
        let expected = catalog
            .get(MessageKey::PathOutsideHome)
            .replace("{path}", &escape_for_terminal(path));
        assert_eq!(error_message(&err, &catalog), expected, "{path}");
    }

    // FR-009, FR-012
    #[test]
    fn path_root_exits_2() {
        assert_outside_home("/");
    }

    // FR-009, FR-012
    #[test]
    fn path_volumes_exits_2() {
        assert_outside_home("/Volumes/x");
    }

    // FR-009, FR-012
    #[test]
    fn path_other_user_home_exits_2() {
        assert_outside_home("/Users/other");
    }

    // FR-009, FR-012
    #[test]
    fn path_dotdot_escape_exits_2() {
        assert_outside_home("../other");
    }

    // FR-007, FR-009
    #[test]
    fn path_symlink_to_outside_home_exits_2() {
        assert_outside_home("out/sub");
    }

    // FR-009
    #[test]
    fn path_inside_home_ok() {
        for ok in [HOME, ".", "Library"] {
            let got = run_with(
                &["--rule", "proj.node-modules", "--path", ok],
                &outside_home_fs(),
                &platform(Some(HOME)),
            );
            assert!(got.is_ok(), "{ok}: {got:?}");
        }
    }

    // FR-010, FR-012
    #[test]
    fn outside_home_message_is_escaped() {
        let mut fs = outside_home_fs();
        let nasty = format!("/Volumes/{NASTY}");
        fs.insert(nasty.as_str(), meta(true, 30, 0));
        let err = run_with(&["--path", &nasty], &fs, &platform(Some(HOME))).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        let msg = error_message(&err, &Catalog::en().unwrap());
        assert_no_raw_controls(&msg);
        assert!(msg.contains("\\x1b[2K"), "{msg}");
        let expected = Catalog::en()
            .unwrap()
            .get(MessageKey::PathOutsideHome)
            .replace("{path}", &escape_for_terminal(&nasty));
        assert_eq!(msg, expected);
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
            tools: &rain_core::tools::NoTools,
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
            tools: &rain_core::tools::NoTools,
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

    // `rain clean --dry-run` (ADR 0006): the plan, shown and not run.
    mod clean_dry_run {
        use super::*;
        use rain_core::messages::Locale;
        use rain_core::plan::{Confirmation, Plan};
        use std::path::Path;

        fn dir(fs: &mut FakeFs, rel: &str, ino: u64) {
            fs.insert(h(rel), meta(true, ino, 0));
        }

        /// The usual home plus a Go module cache (medium risk) and an Xcode
        /// archive (high risk, needs Xcode closed).
        fn fs_with_medium_and_high() -> FakeFs {
            let mut fs = home_fs();
            dir(&mut fs, "go", 20);
            dir(&mut fs, "go/pkg", 21);
            dir(&mut fs, "go/pkg/mod", 22);
            dir(&mut fs, "go/pkg/mod/cache", 23);
            fs.insert(h("go/pkg/mod/cache/x"), meta(false, 24, 4));
            dir(&mut fs, "Library/Developer", 30);
            dir(&mut fs, "Library/Developer/Xcode", 31);
            dir(&mut fs, "Library/Developer/Xcode/Archives", 32);
            dir(&mut fs, "Library/Developer/Xcode/Archives/2024-01-01", 33);
            dir(
                &mut fs,
                "Library/Developer/Xcode/Archives/2024-01-01/App.xcarchive",
                34,
            );
            fs.insert(
                h("Library/Developer/Xcode/Archives/2024-01-01/App.xcarchive/blob"),
                meta(false, 35, 16),
            );
            fs
        }

        fn clean_args(argv: &[&str]) -> CleanArgs {
            let catalog = Catalog::en().unwrap();
            let mut full = vec!["rain", "clean", "--dry-run"];
            full.extend_from_slice(argv);
            match args::parse(&catalog, full).unwrap().command {
                Some(Command::Clean(a)) => a,
                _ => panic!("not a clean"),
            }
        }

        fn clean_with(
            argv: &[&str],
            fs: &FakeFs,
            platform: &FakePlatform,
            catalog: &Catalog,
        ) -> Result<String, CliError> {
            let env = Env {
                platform,
                fs,
                clock: &clock(),
                tools: &rain_core::tools::NoTools,
                cwd: PathBuf::from(HOME),
            };
            clean_output(&clean_args(argv), &env, catalog, &AtomicBool::new(false))
        }

        fn clean(argv: &[&str]) -> Result<String, CliError> {
            clean_with(
                argv,
                &fs_with_medium_and_high(),
                &platform(Some(HOME)),
                &Catalog::en().unwrap(),
            )
        }

        fn id_of(rule: &str, tail: &str) -> String {
            let report = run_with(
                &["--rule", rule],
                &fs_with_medium_and_high(),
                &platform(Some(HOME)),
            )
            .unwrap();
            let item = report
                .items
                .iter()
                .find(|i| i.path.ends_with(tail))
                .unwrap_or_else(|| panic!("no {tail} under {rule}"));
            format!("{:016x}", item.id.0)
        }

        // The preselected rules (low risk) are planned; nothing else.
        #[test]
        fn dry_run_previews_the_preselected_items() {
            let out = clean(&["--rule", "sys.logs", "--rule", "sys.user-caches"]).unwrap();
            insta::assert_snapshot!(out);
        }

        // Medium and high items are not planned unless asked for by id, and
        // then they wait for a confirmation.
        #[test]
        fn items_that_need_a_decision_are_not_planned_unless_chosen() {
            let rules = ["--rule", "pkg.go-mod", "--rule", "sys.logs"];
            let out = clean(&rules).unwrap();
            assert!(out.contains("old.log"), "{out}");
            assert!(!out.contains("go/pkg/mod"), "{out}");
            assert!(!out.contains("needs your confirmation"), "{out}");

            let go = id_of("pkg.go-mod", "cache");
            let mut chosen = rules.to_vec();
            chosen.extend(["--item", go.as_str()]);
            let out = clean(&chosen).unwrap();
            assert!(out.contains("go/pkg/mod/cache"), "{out}");
            assert!(!out.contains("old.log"), "{out}");
            assert!(
                out.contains("1 item needs your confirmation before it can be cleaned"),
                "{out}"
            );
        }

        // An app that must be closed is announced, also in a dry run.
        #[test]
        fn items_that_need_an_app_closed_are_announced() {
            let archive = id_of("apple.archives", "App.xcarchive");
            let out = clean(&["--rule", "apple.archives", "--item", &archive]).unwrap();
            assert!(out.contains("1 item needs its app closed first"), "{out}");
            assert!(out.contains("1 item needs your confirmation"), "{out}");
        }

        // `--json` is the plan itself, and it reads back as the same plan.
        #[test]
        fn json_is_a_plan_that_reads_back_and_is_stable() {
            let argv = ["--rule", "sys.logs", "--rule", "pkg.go-mod", "--json"];
            let go = id_of("pkg.go-mod", "cache");
            let mut chosen = argv.to_vec();
            chosen.extend(["--item", go.as_str()]);
            let first = clean(&chosen).unwrap();
            let plan = Plan::from_json(&first).expect("a plan");
            assert_eq!(plan.items.len(), 1);
            assert_eq!(plan.items[0].confirmation, Confirmation::Pending);
            assert_eq!(plan.created_at, 1_800_000_000);
            assert_eq!(plan.home, Path::new(HOME));
            // Same disk, same clock: the same document.
            assert_eq!(clean(&chosen).unwrap(), first);
        }

        #[test]
        fn nothing_selected_says_so_and_succeeds() {
            let out = clean(&["--rule", "pkg.go-mod"]).unwrap();
            assert_eq!(out.trim_end(), "Nothing to clean: no item was selected.");
        }

        #[test]
        fn bad_item_ids_are_refused() {
            for bad in [
                "",
                "ff",
                "xyz",
                "00000000000000FG",
                "00000000000000000",
                "+0000000000000001",
            ] {
                match clean(&["--rule", "sys.logs", "--item", bad]) {
                    Err(CliError::Usage(msg)) => {
                        assert!(msg.contains("is not an item id"), "{bad}: {msg}")
                    }
                    other => panic!("{bad:?}: {other:?}"),
                }
            }
            match clean(&["--rule", "sys.logs", "--item", "00000000000000aa"]) {
                Err(CliError::Runtime(msg)) => assert!(msg.contains("is not in the scan"), "{msg}"),
                other => panic!("{other:?}"),
            }
        }

        // An item the user cannot choose: the protected `~/.ssh` is never in
        // the scan, so its id is not in the report either.
        #[test]
        fn a_protected_folder_cannot_be_planned_by_id() {
            let ssh = rain_core::model::ItemId::of(
                rain_core::model::RuleId::new("sys.user-caches"),
                &h(".ssh"),
            );
            let bad = format!("{:016x}", ssh.0);
            match clean(&["--rule", "sys.user-caches", "--item", &bad]) {
                Err(CliError::Runtime(msg)) => assert!(msg.contains("is not in the scan"), "{msg}"),
                other => panic!("{other:?}"),
            }
        }

        #[test]
        fn root_is_refused_like_a_scan() {
            let root = FakePlatform {
                home: Some(PathBuf::from(HOME)),
                root: true,
                os: Os::Macos,
            };
            let out = clean_with(
                &["--rule", "sys.logs"],
                &home_fs(),
                &root,
                &Catalog::en().unwrap(),
            );
            assert!(matches!(out, Err(CliError::Runtime(_))), "{out:?}");
        }

        #[test]
        fn the_preview_is_translated() {
            for (locale, note) in [
                (Locale::Es, "Simulación: no se movió ni se borró nada."),
                (Locale::PtBr, "Simulação: nada foi movido nem apagado."),
            ] {
                let catalog = Catalog::for_locale(locale).unwrap();
                let out = clean_with(
                    &["--rule", "sys.logs"],
                    &fs_with_medium_and_high(),
                    &platform(Some(HOME)),
                    &catalog,
                )
                .unwrap();
                assert!(out.contains(note), "{out}");
            }
        }

        // The path comes from the disk: controls and bidi are shown escaped.
        #[test]
        fn hostile_names_are_escaped_in_the_preview() {
            let mut fs = home_fs();
            let bidi = char::from_u32(0x202e).unwrap();
            let name = format!("Library/Logs/a{bidi}b\u{1b}[31m.log");
            fs.insert(h(&name), meta(false, 40, 2));
            let out = clean_with(
                &["--rule", "sys.logs"],
                &fs,
                &platform(Some(HOME)),
                &Catalog::en().unwrap(),
            )
            .unwrap();
            for bad in ['\x1b', bidi] {
                assert!(!out.contains(bad), "{out:?}");
            }
            assert!(out.contains("a\\u{202e}b\\x1b[31m.log"), "{out}");
        }
    }

    // The simulator, Podman and Ollama rules through the table, with fake
    // runners: names a user or a repository chose never reach the terminal raw.
    mod new_provider_tables {
        use super::*;
        use rain_core::tools::{
            ExitStatusKind, FakeReply, FakeToolRunner, ToolError, ToolId, ToolOutput,
        };

        const SIMCTL: &[&str] = &["simctl", "list", "-j"];
        const OLLAMA: &[&str] = &["list"];
        const PODMAN: &[&str] = &["system", "df", "--format", "json"];
        const SIM_LIST: &str = include_str!("../../rain-core/tests/fixtures/simctl/list.json");
        const OLLAMA_LIST: &str = include_str!("../../rain-core/tests/fixtures/ollama/list.txt");
        const RULES: [&str; 6] = [
            "apple.sim-unavailable",
            "apple.sim-runtimes",
            "models.ollama",
            "containers.podman-unused-images",
            "containers.podman-stopped",
            "containers.podman-volumes",
        ];

        fn table(tools: &FakeToolRunner) -> String {
            let fs = home_fs();
            let p = platform(Some(HOME));
            let env = Env {
                platform: &p,
                fs: &fs,
                clock: &clock(),
                tools,
                cwd: PathBuf::from(HOME),
            };
            let argv: Vec<&str> = RULES.iter().flat_map(|id| ["--rule", id]).collect();
            scan_output(
                &args(&argv),
                &env,
                &Catalog::en().unwrap(),
                &AtomicBool::new(false),
            )
            .unwrap()
        }

        fn ok(s: &str) -> FakeReply {
            FakeReply::Output(ToolOutput::success(s))
        }

        // Simulator names are free text. This one holds a bidi override and
        // a terminal escape sequence (written as JSON escapes).
        #[test]
        fn simulator_name_with_bidi_and_controls_is_escaped_in_the_table() {
            let hostile = SIM_LIST.replace(
                "\"name\" : \"iPhone 8\"",
                "\"name\" : \"iPhone\\u202eevil\\u001b[31m\"",
            );
            assert_ne!(hostile, SIM_LIST, "the fixture has the name to replace");
            let mut tools = FakeToolRunner::new();
            tools.reply(ToolId::Xcrun, SIMCTL, ok(&hostile));
            let out = table(&tools);
            for bad in ['\x1b', '\u{202e}', '\r', '\x07'] {
                assert!(!out.contains(bad), "{out:?}");
            }
            assert!(
                out.contains("iPhone\\u{202e}evil\\x1b[31m (iOS-15-5)"),
                "{out}"
            );
        }

        // Simulators and models show with the tool's sizes, and the tool that
        // is not installed says so; the scan still succeeds.
        #[test]
        fn table_with_new_providers_ok_and_unavailable() {
            let mut tools = FakeToolRunner::new();
            tools
                .reply(ToolId::Xcrun, SIMCTL, ok(SIM_LIST))
                .reply(ToolId::Ollama, OLLAMA, ok(OLLAMA_LIST))
                .reply(
                    ToolId::Podman,
                    PODMAN,
                    FakeReply::Error(ToolError::NotInstalled),
                );
            insta::assert_snapshot!(table(&tools));
        }

        // The Command Line Tools have `xcrun` but no `simctl`: it exits with
        // an error, and the table says what is missing.
        #[test]
        fn xcrun_without_simctl_says_what_is_missing_in_the_table() {
            let mut tools = FakeToolRunner::new();
            tools.reply(
                ToolId::Xcrun,
                SIMCTL,
                FakeReply::Output(ToolOutput {
                    status: ExitStatusKind::Code(72),
                    stdout: String::new(),
                    stderr_len: 80,
                }),
            );
            let out = table(&tools);
            assert!(
                out.lines().any(|l| l
                    == "simctl is not available (the full Xcode is needed, not only the Command Line Tools)"),
                "{out}"
            );
            assert!(!out.contains("is it running"), "{out}");
            assert!(out.contains("Ollama is not installed"), "{out}");
            assert!(out.contains("Podman is not installed"), "{out}");
            assert!(!out.contains("Docker"), "{out}");
        }
    }

    mod provider_table {
        use super::*;
        use rain_core::tools::{
            ExitStatusKind, FakeReply, FakeToolRunner, ToolError, ToolId, ToolOutput,
        };

        const DF_ARGS: &[&str] = &["system", "df", "--format", "{{json .}}"];
        const IMAGES_ARGS: &[&str] = &[
            "images",
            "--filter",
            "dangling=true",
            "--format",
            "{{json .}}",
        ];
        const DF: &str = include_str!("../../rain-core/tests/fixtures/docker/system_df.jsonl");
        const DANGLING: &str =
            include_str!("../../rain-core/tests/fixtures/docker/images_dangling_synthetic.jsonl");

        fn table(tools: &FakeToolRunner) -> String {
            let fs = home_fs();
            let p = platform(Some(HOME));
            let env = Env {
                platform: &p,
                fs: &fs,
                clock: &clock(),
                tools,
                cwd: PathBuf::from(HOME),
            };
            let argv = [
                "--rule",
                "sys.logs",
                "--rule",
                "containers.build-cache",
                "--rule",
                "containers.dangling-images",
                "--rule",
                "containers.stopped",
                "--rule",
                "containers.unused-images",
                "--rule",
                "containers.volumes",
            ];
            scan_output(
                &args(&argv),
                &env,
                &Catalog::en().unwrap(),
                &AtomicBool::new(false),
            )
            .unwrap()
        }

        fn fake(df: FakeReply, images: FakeReply) -> FakeToolRunner {
            let mut fake = FakeToolRunner::new();
            fake.reply(ToolId::Docker, DF_ARGS, df)
                .reply(ToolId::Docker, IMAGES_ARGS, images);
            fake
        }

        // Container items appear with the tool's sizes; their
        // total is separate from the disk total.
        #[test]
        fn table_with_docker_items() {
            let ok = |s: &str| FakeReply::Output(ToolOutput::success(s));
            insta::assert_snapshot!(table(&fake(ok(DF), ok(DANGLING))));
        }

        // FR-022, criterion 7: a stopped daemon shows "unavailable" and the
        // scan still succeeds.
        #[test]
        fn table_with_docker_unavailable() {
            let failed = FakeReply::Output(ToolOutput {
                status: ExitStatusKind::Code(1),
                stdout: String::new(),
                stderr_len: 40,
            });
            insta::assert_snapshot!(table(&fake(
                failed,
                FakeReply::Error(ToolError::NotInstalled)
            )));
        }
    }
}
