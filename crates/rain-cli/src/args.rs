//! Command-line arguments of `rain` and their validation.

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use rain_core::fs::Fs;
use rain_core::messages::{Catalog, MessageKey};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Default inactivity, in days, for age-based rules.
pub const DEFAULT_MIN_AGE_DAYS: u32 = 30;

#[derive(Debug, Parser)]
#[command(name = "rain", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Scan(ScanArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct ScanArgs {
    /// FR-008
    #[arg(long = "rule", value_name = "ID")]
    pub rules: Vec<String>,
    /// FR-009
    #[arg(long = "path", value_name = "DIR")]
    pub paths: Vec<PathBuf>,
    #[arg(long, value_name = "DAYS", default_value_t = DEFAULT_MIN_AGE_DAYS)]
    pub min_age_days: u32,
    /// FR-010
    #[arg(long)]
    pub json: bool,
}

/// Help texts come from the catalog (FR-013), never from the source.
fn command(catalog: &Catalog) -> clap::Command {
    let text = |key| catalog.get(key).to_owned();
    Cli::command()
        .about(text(MessageKey::HelpAbout))
        .mut_subcommand("scan", |scan| {
            scan.about(text(MessageKey::HelpScan))
                .mut_arg("rules", |a| a.help(text(MessageKey::HelpRule)))
                .mut_arg("paths", |a| a.help(text(MessageKey::HelpPath)))
                .mut_arg("min_age_days", |a| a.help(text(MessageKey::HelpMinAgeDays)))
                .mut_arg("json", |a| a.help(text(MessageKey::HelpJson)))
        })
}

/// Parses `argv`. On failure (or `--help`/`--version`) the clap error
/// carries the text and the exit code (2 for usage errors, FR-012).
pub fn parse<I, T>(catalog: &Catalog, argv: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = command(catalog).try_get_matches_from(argv)?;
    Cli::from_arg_matches(&matches)
}

/// Help shown when `rain` runs without a subcommand.
pub fn help(catalog: &Catalog) -> String {
    command(catalog).render_help().to_string()
}

/// FR-009: why a `--path` is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPath(pub PathBuf);

/// FR-009: turns each `--path` into the canonical directory it names.
///
/// The path must exist and be a directory itself, read without following
/// a final symlink (a link given as root would be followed otherwise).
/// Ancestors are resolved by canonicalizing, so a spelling whose case
/// differs from the disk (APFS is case-insensitive) becomes the on-disk
/// form instead of a root the walker sees as "not canonical" and reports
/// as a symlink. Protection is applied later, by the planner, on the
/// canonical path (FR-007).
pub fn resolve_paths(
    fs: &dyn Fs,
    cwd: &Path,
    paths: &[PathBuf],
) -> Result<Vec<PathBuf>, InvalidPath> {
    paths.iter().map(|p| resolve_path(fs, cwd, p)).collect()
}

fn resolve_path(fs: &dyn Fs, cwd: &Path, given: &Path) -> Result<PathBuf, InvalidPath> {
    let invalid = || InvalidPath(given.to_path_buf());
    let absolute = cwd.join(given);
    match fs.symlink_metadata(&absolute) {
        Ok(meta) if meta.is_dir && !meta.is_symlink => {}
        _ => return Err(invalid()),
    }
    let canonical = fs.canonicalize(&absolute).map_err(|_| invalid())?;
    match fs.symlink_metadata(&canonical) {
        Ok(meta) if meta.is_dir && !meta.is_symlink => Ok(canonical),
        _ => Err(invalid()),
    }
}

/// FR-009: a `--path` whose canonical form is not inside the home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutsideHome(pub PathBuf);

/// FR-009: every resolved `--path` must be the canonical home or below it.
/// `given` and `resolved` are parallel; the error names the path as given.
pub fn ensure_inside_home(
    fs: &dyn Fs,
    home: &Path,
    given: &[PathBuf],
    resolved: &[PathBuf],
) -> Result<(), OutsideHome> {
    let home = fs.canonicalize(home).ok();
    for (g, r) in given.iter().zip(resolved) {
        match &home {
            Some(h) if r.starts_with(h) => {}
            _ => return Err(OutsideHome(g.clone())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rain_core::fs::{FakeFs, Metadata};
    use std::time::SystemTime;

    fn en() -> Catalog {
        Catalog::en().unwrap()
    }

    fn scan_args(argv: &[&str]) -> ScanArgs {
        let mut full = vec!["rain", "scan"];
        full.extend_from_slice(argv);
        match parse(&en(), full).unwrap().command {
            Some(Command::Scan(args)) => args,
            None => panic!("no subcommand"),
        }
    }

    fn meta(is_dir: bool, ino: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 1,
            ino,
            nlink: if is_dir { 2 } else { 1 },
            blocks: 0,
            len: 0,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    fn fake() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/", meta(true, 1))
            .insert("/Users", meta(true, 2))
            .insert("/Users/t", meta(true, 3))
            .insert("/Users/t/code", meta(true, 4))
            .insert("/Users/t/file.txt", meta(false, 5))
            .insert_symlink("/Users/t/link", "/Users/t/code");
        fs
    }

    // FR-008, FR-009, FR-010
    #[test]
    fn parses_repeated_rules_paths_age_and_json() {
        let args = scan_args(&[
            "--rule",
            "sys.logs",
            "--rule",
            "proj.node-modules",
            "--path",
            "/a",
            "--path",
            "b",
            "--min-age-days",
            "7",
            "--json",
        ]);
        assert_eq!(args.rules, ["sys.logs", "proj.node-modules"]);
        assert_eq!(args.paths, [PathBuf::from("/a"), PathBuf::from("b")]);
        assert_eq!(args.min_age_days, 7);
        assert!(args.json);
    }

    // FR-009: 30 days by default, no rule filter, no paths, table output.
    #[test]
    fn defaults() {
        let args = scan_args(&[]);
        assert!(args.rules.is_empty() && args.paths.is_empty() && !args.json);
        assert_eq!(args.min_age_days, 30);
    }

    // FR-012: a malformed option is a usage error, exit code 2.
    #[test]
    fn bad_min_age_days_is_usage_error() {
        for bad in ["-1", "abc", ""] {
            let err = parse(&en(), ["rain", "scan", "--min-age-days", bad]).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{bad}");
        }
        let err = parse(&en(), ["rain", "scan", "--nope"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    // FR-013: help texts come from the catalog.
    #[test]
    fn help_uses_catalog_texts() {
        let catalog = en();
        let err = parse(&catalog, ["rain", "scan", "--help"]).unwrap_err();
        let help = err.to_string();
        for key in [
            MessageKey::HelpScan,
            MessageKey::HelpRule,
            MessageKey::HelpPath,
            MessageKey::HelpMinAgeDays,
            MessageKey::HelpJson,
        ] {
            assert!(help.contains(catalog.get(key)), "{help}");
        }
        assert!(help_text_contains_about(&catalog));
    }

    fn help_text_contains_about(catalog: &Catalog) -> bool {
        help(catalog).contains(catalog.get(MessageKey::HelpAbout))
    }

    // FR-009
    #[test]
    fn existing_directory_is_resolved() {
        let fs = fake();
        let got = resolve_paths(&fs, Path::new("/Users/t"), &[PathBuf::from("code")]);
        assert_eq!(got, Ok(vec![PathBuf::from("/Users/t/code")]));
    }

    // FR-009
    #[test]
    fn invalid_path_is_rejected() {
        let fs = fake();
        for bad in ["/Users/t/missing", "/Users/t/file.txt", "/Users/t/link"] {
            let got = resolve_paths(&fs, Path::new("/"), &[PathBuf::from(bad)]);
            assert_eq!(got, Err(InvalidPath(PathBuf::from(bad))), "{bad}");
        }
    }

    // FR-009
    #[test]
    fn unresolvable_home_refuses_every_path() {
        let fs = fake();
        let given = [PathBuf::from("code")];
        let resolved = [PathBuf::from("/Users/t/code")];
        let got = ensure_inside_home(&fs, Path::new("/Users/gone"), &given, &resolved);
        assert_eq!(got, Err(OutsideHome(PathBuf::from("code"))));
    }

    // FR-009
    #[test]
    fn sibling_with_home_prefix_is_outside() {
        let mut fs = fake();
        fs.insert("/Users/t2", meta(true, 9));
        let given = [PathBuf::from("/Users/t2")];
        let got = ensure_inside_home(&fs, Path::new("/Users/t"), &given, &given);
        assert_eq!(got, Err(OutsideHome(PathBuf::from("/Users/t2"))));
    }

    // FR-009: the first bad path is reported, as given by the user.
    #[test]
    fn first_invalid_path_is_reported_as_given() {
        let fs = fake();
        let paths = [PathBuf::from("code"), PathBuf::from("nope")];
        let got = resolve_paths(&fs, Path::new("/Users/t"), &paths);
        assert_eq!(got, Err(InvalidPath(PathBuf::from("nope"))));
    }

    // FR-007, FR-009: on a case-insensitive volume a root spelled with
    // another case is the on-disk directory, not a symlink-looking root.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixture inside a tempdir
    fn case_variant_path_resolves_to_disk_case() {
        use rain_core::fs::StdFs;
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(base.join("Proj")).unwrap();
        if !base.join("PROJ").exists() {
            return; // case-sensitive volume: nothing to fold
        }
        let got = resolve_paths(&StdFs, &base, &[PathBuf::from("pROJ")]);
        assert_eq!(got, Ok(vec![base.join("Proj")]));
    }
}
