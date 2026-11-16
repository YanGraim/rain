//! Developer tool caches and toolchains (catalogue 6.4): Rust toolchains and
//! the Cargo registry, Go, Maven and Gradle.
//!
//! Each rule names its folders. The rest of each tool's home is never taken:
//! not `~/.cargo/bin`, the Cargo configuration or credentials, not the Go
//! sum database or binaries, not the Maven settings, not the Gradle wrapper.

use super::children::ChildrenOf;
use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};
use std::path::Path;

pub(super) static RULES: &[&dyn Rule] = &[&RUSTUP, &CARGO, &GO_BUILD, &GO_MOD, &GRADLE, &MAVEN];

const fn meta(
    id: &'static str,
    name_key: &'static str,
    consequence_key: &'static str,
    risk: Risk,
) -> RuleMeta {
    RuleMeta {
        id: RuleId::new(id),
        category: Category::PackageManagers,
        risk,
        name_key,
        consequence_key,
        // Only low risk caches are preselected.
        default_selected: matches!(risk, Risk::Low),
        requires_app_closed: None,
        os: &[Os::Macos],
    }
}

/// The Cargo registry (`$CARGO_HOME/registry`, `~/.cargo` by default, per the
/// Cargo book): the downloaded `.crate` archives and the unpacked sources, one
/// item per registry. Cargo restores any of it on demand. The index, `bin`,
/// the configuration and the credentials are not touched.
static CARGO: ChildrenOf = ChildrenOf {
    meta: meta(
        "pkg.cargo",
        "rule.pkg.cargo",
        "rule.pkg.cargo.consequence",
        Risk::Low,
    ),
    root: Root::Home,
    rels: &[".cargo/registry/cache", ".cargo/registry/src"],
    depth: 1,
};

/// The Go build cache: `go-build` in the user cache directory (the default of
/// `GOCACHE`, per `go help cache`; `go env GOCACHE` is not run). Rebuilt on the
/// next build.
static GO_BUILD: ChildrenOf = ChildrenOf {
    meta: meta(
        "pkg.go-build",
        "rule.pkg.go-build",
        "rule.pkg.go-build.consequence",
        Risk::Low,
    ),
    root: Root::Caches,
    rels: &["go-build"],
    depth: 1,
};

/// The Go module cache: `$GOPATH/pkg/mod`, `~/go/pkg/mod` by default (the Go
/// modules reference). Medium: downloading again needs the network and the
/// modules to still be available. The sum database and `~/go/bin` are not
/// touched.
static GO_MOD: ChildrenOf = ChildrenOf {
    meta: meta(
        "pkg.go-mod",
        "rule.pkg.go-mod",
        "rule.pkg.go-mod.consequence",
        Risk::Medium,
    ),
    root: Root::Home,
    rels: &["go/pkg/mod"],
    depth: 1,
};

/// The Gradle caches: `caches` in the Gradle user home, `~/.gradle` by default
/// (the Gradle user guide). The wrapper distributions and
/// `gradle.properties` are not touched.
static GRADLE: ChildrenOf = ChildrenOf {
    meta: meta(
        "pkg.gradle",
        "rule.pkg.gradle",
        "rule.pkg.gradle.consequence",
        Risk::Medium,
    ),
    root: Root::Home,
    rels: &[".gradle/caches"],
    depth: 1,
};

/// The Maven local repository: `~/.m2/repository` by default (the Maven
/// settings reference). Medium: every dependency is downloaded again, and a
/// build of a project whose dependencies are gone from the network breaks.
/// `settings.xml` is not touched.
static MAVEN: ChildrenOf = ChildrenOf {
    meta: meta(
        "pkg.maven",
        "rule.pkg.maven",
        "rule.pkg.maven.consequence",
        Risk::Medium,
    ),
    root: Root::Home,
    rels: &[".m2/repository"],
    depth: 1,
};

// --- rustup ------------------------------------------------------------------------

/// Rust toolchains: each folder of `~/.rustup/toolchains` is an item, except
/// the ones in use. Which ones are in use is read from rustup's
/// `settings.toml`: the default toolchain and every toolchain a directory
/// override names. If the file cannot be read or is not understood, nothing is
/// listed. A toolchain that only a project's `rust-toolchain` file names is not
/// known here; rustup installs it again on demand.
pub static RUSTUP: Toolchains = Toolchains {
    meta: meta(
        "pkg.rustup",
        "rule.pkg.rustup",
        "rule.pkg.rustup.consequence",
        Risk::Medium,
    ),
};

pub struct Toolchains {
    meta: RuleMeta,
}

impl Rule for Toolchains {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

/// The largest settings file that is read: it is a handful of lines.
const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

/// The toolchain names in use, as written in the settings.
struct InUse(Vec<String>);

impl InUse {
    /// A setting may leave the host out (`stable`, `1.75.0`) while the folder
    /// has it (`stable-aarch64-apple-darwin`): the folder is in use when it is
    /// the name or starts with it and a dash. A dated nightly named `nightly`
    /// is kept too; keeping more than needed is the safe side.
    fn covers(&self, folder: &str) -> bool {
        self.0.iter().any(|name| {
            folder == name
                || folder
                    .strip_prefix(name.as_str())
                    .is_some_and(|rest| rest.starts_with('-'))
        })
    }
}

/// A basic double quoted string with nothing to unescape, and its content.
fn quoted(value: &str) -> Option<&str> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.is_empty() && !inner.contains(['"', '\\', '\n'])).then_some(inner)
}

/// Reads rustup's settings file strictly: only the forms rustup writes.
/// Anything else (another table, an inline table, an array, a multi-line or
/// literal string, a repeated default, no default) is `None`.
fn parse_settings(text: &str) -> Option<InUse> {
    let mut in_overrides = false;
    let mut default: Option<String> = None;
    let mut names: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if line == "[overrides]" && !in_overrides {
                in_overrides = true;
                continue;
            }
            return None;
        }
        let (key, value) = line.split_once('=')?;
        let (key, value) = (key.trim(), value.trim());
        if in_overrides {
            quoted(key)?;
            names.push(quoted(value)?.to_owned());
        } else if key == "default_toolchain" {
            if default.is_some() {
                return None;
            }
            default = Some(quoted(value)?.to_owned());
        } else {
            let bare =
                !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            let plain = quoted(value).is_some()
                || (!value.is_empty()
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')));
            if !bare || !plain {
                return None;
            }
        }
    }
    names.push(default?);
    Some(InUse(names))
}

fn in_use(fs: &dyn Fs, settings: &Path) -> Option<InUse> {
    parse_settings(&fs.read_to_string(settings, MAX_SETTINGS_BYTES).ok()?)
}

impl FileRule for Toolchains {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        vec![RootedPath::Under(Root::Home, ".rustup/toolchains")]
    }
    fn visit(&self, entry: &EntryInfo, depth: usize, _: &RuleContext, fs: &dyn Fs) -> Visit {
        if depth == 0 {
            return Visit::Descend;
        }
        let Some(name) = entry.path.file_name().and_then(|n| n.to_str()) else {
            return Visit::Skip;
        };
        // `<rustup home>/toolchains/<name>`: the settings sit next to
        // `toolchains`, in the same rustup home, and nowhere else is read.
        let Some(home) = entry.path.parent().and_then(Path::parent) else {
            return Visit::Skip;
        };
        if !entry.meta.is_dir {
            return Visit::Skip;
        }
        match in_use(fs, &home.join("settings.toml")) {
            Some(used) if !used.covers(name) => Visit::Candidate,
            _ => Visit::Skip,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{Risk, ScanReport};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::protect::ProtectList;
    use crate::rule::RuleContext;
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::time::SystemTime;

    const HOME: &str = "/Users/Tester";
    const ARM: &str = "aarch64-apple-darwin";

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
            dev: 1,
            ino,
            nlink: if is_dir { 2 } else { 1 },
            blocks: u64::from(!is_dir) * 8,
            len: 0,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    /// A fake home that grows by relative paths; every folder on the way is
    /// inserted.
    struct Tree {
        fs: FakeFs,
        ino: u64,
    }

    impl Tree {
        fn new() -> Tree {
            let mut fs = FakeFs::new();
            fs.insert("/Users", md(true, 1)).insert(HOME, md(true, 2));
            Tree { fs, ino: 100 }
        }
        fn parents(&mut self, rel: &str) -> PathBuf {
            let mut cur = PathBuf::from(HOME);
            let parts: Vec<&str> = rel.split('/').collect();
            for part in &parts[..parts.len() - 1] {
                cur.push(part);
                if crate::fs::Fs::symlink_metadata(&self.fs, &cur).is_err() {
                    self.ino += 1;
                    self.fs.insert(&cur, md(true, self.ino));
                }
            }
            cur.push(parts[parts.len() - 1]);
            cur
        }
        fn dir(&mut self, rel: &str) -> &mut Self {
            let p = self.parents(rel);
            self.ino += 1;
            self.fs.insert(p, md(true, self.ino));
            self
        }
        fn file(&mut self, rel: &str) -> &mut Self {
            let p = self.parents(rel);
            self.ino += 1;
            self.fs.insert(p, md(false, self.ino));
            self
        }
        fn text(&mut self, rel: &str, content: &[u8]) -> &mut Self {
            let p = self.parents(rel);
            self.ino += 1;
            self.fs
                .insert_file(p, md(false, self.ino), content.to_vec());
            self
        }
        fn link(&mut self, rel: &str, target: &str) -> &mut Self {
            let p = self.parents(rel);
            self.fs.insert_symlink(p, target);
            self
        }
    }

    fn run(fs: &FakeFs, ids: &[&str]) -> ScanReport {
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: Path::new(HOME).join("Library/Caches"),
            logs: Path::new(HOME).join("Library/Logs"),
        };
        let ctx = ScanContext {
            fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::UNIX_EPOCH,
            },
            tools: &crate::tools::NoTools,
            threads: Some(1),
        };
        let rules = super::super::select(ids).unwrap();
        scan(&rules, &ctx, &AtomicBool::new(false)).unwrap()
    }

    /// Items of `id`, as paths below the home.
    fn listed(report: &ScanReport, id: &str) -> Vec<String> {
        let mut out: Vec<String> = report
            .items
            .iter()
            .filter(|i| i.rule.as_str() == id)
            .filter_map(|i| i.path.strip_prefix(HOME).ok()?.to_str().map(str::to_owned))
            .collect();
        out.sort();
        out
    }

    fn meta(id: &str) -> crate::rule::RuleMeta {
        super::super::select(&[id]).unwrap()[0].meta().clone()
    }

    // --- rustup (#61) -----------------------------------------------------

    const TC: &str = ".rustup/toolchains";

    /// The `settings.toml` rustup writes: a default and the directory
    /// overrides.
    fn settings(default: Option<&str>, overrides: &[(&str, &str)]) -> String {
        let mut s = String::from("version = \"12\"\n");
        if let Some(d) = default {
            s.push_str(&format!("default_toolchain = \"{d}\"\n"));
        }
        s.push_str("profile = \"default\"\n\n[overrides]\n");
        for (dir, tc) in overrides {
            s.push_str(&format!("\"{dir}\" = \"{tc}\"\n"));
        }
        s
    }

    fn rustup_home(settings: Option<&str>, toolchains: &[&str]) -> Tree {
        let mut t = Tree::new();
        t.dir(".rustup/downloads")
            .dir(".rustup/tmp")
            .dir(".rustup/update-hashes");
        if let Some(text) = settings {
            t.text(".rustup/settings.toml", text.as_bytes());
        }
        for name in toolchains {
            t.dir(&format!("{TC}/{name}"));
            t.file(&format!("{TC}/{name}/bin-rustc"));
        }
        t
    }

    fn toolchains() -> Vec<String> {
        [
            format!("stable-{ARM}"),
            format!("1.75.0-{ARM}"),
            format!("1.90.0-{ARM}"),
            format!("nightly-2024-01-01-{ARM}"),
        ]
        .to_vec()
    }

    fn tc_refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    // #61: every installed toolchain is an item, except the default one.
    #[test]
    fn rustup_lists_each_toolchain() {
        let all = toolchains();
        let t = rustup_home(Some(&settings(Some(&all[0]), &[])), &tc_refs(&all));
        let report = run(&t.fs, &["pkg.rustup"]);
        assert_eq!(
            listed(&report, "pkg.rustup"),
            [
                format!("{TC}/1.75.0-{ARM}"),
                format!("{TC}/1.90.0-{ARM}"),
                format!("{TC}/nightly-2024-01-01-{ARM}"),
            ]
        );
    }

    // #61: the default toolchain and every toolchain a directory override
    // names are in use: they are never items.
    #[test]
    fn rustup_never_lists_the_default_or_an_overridden_toolchain() {
        let all = toolchains();
        let text = settings(Some(&all[0]), &[("/work/a", &all[1]), ("/work/b", &all[3])]);
        let t = rustup_home(Some(&text), &tc_refs(&all));
        let report = run(&t.fs, &["pkg.rustup"]);
        assert_eq!(
            listed(&report, "pkg.rustup"),
            [format!("{TC}/1.90.0-{ARM}")]
        );
    }

    // #61: rustup lets a setting name a toolchain without its host, and the
    // folder on disk has it; both spellings protect the folder.
    #[test]
    fn rustup_short_names_protect_the_full_folder_name() {
        let all = toolchains();
        let text = settings(
            Some("stable"),
            &[("/work/a", "1.75.0"), ("/work/b", "nightly")],
        );
        let t = rustup_home(Some(&text), &tc_refs(&all));
        let report = run(&t.fs, &["pkg.rustup"]);
        assert_eq!(
            listed(&report, "pkg.rustup"),
            [format!("{TC}/1.90.0-{ARM}")]
        );
    }

    // #61: fail closed. Whatever cannot be read, or is not understood, lists
    // nothing, because then it is not known which toolchain is in use.
    #[test]
    fn rustup_lists_nothing_without_a_settings_file_it_understands() {
        let all = toolchains();
        let good = settings(Some(&all[0]), &[]);
        let huge = format!("{good}{}", "# padding\n".repeat(10_000));
        let cases: Vec<(&str, Option<Vec<u8>>)> = vec![
            ("absent", None),
            ("empty", Some(Vec::new())),
            ("not utf-8", Some(vec![0xff, 0xfe, 0x00])),
            ("too large", Some(huge.into_bytes())),
            ("no default", Some(settings(None, &[]).into_bytes())),
            (
                "default twice",
                Some(format!("{good}default_toolchain = \"x\"\n").into_bytes()),
            ),
            (
                "default not quoted",
                Some(b"default_toolchain = stable\n[overrides]\n".to_vec()),
            ),
            (
                "unknown table",
                Some(format!("{good}[toolchains]\nx = \"y\"\n").into_bytes()),
            ),
            (
                "unknown table with entries that look like overrides",
                Some(format!("{good}[toolchains]\n\"/a\" = \"stable\"\n").into_bytes()),
            ),
            (
                "inline table",
                Some(b"default_toolchain = \"stable\"\nx = { a = 1 }\n".to_vec()),
            ),
            (
                "array",
                Some(b"default_toolchain = \"stable\"\nx = [1, 2]\n".to_vec()),
            ),
            (
                "multi-line string",
                Some(b"default_toolchain = \"\"\"stable\"\"\"\n".to_vec()),
            ),
            (
                "override without a toolchain",
                Some(b"default_toolchain = \"stable\"\n[overrides]\n\"/a\" = 3\n".to_vec()),
            ),
        ];
        for (what, content) in cases {
            let mut t = rustup_home(None, &tc_refs(&all));
            if let Some(bytes) = &content {
                t.text(".rustup/settings.toml", bytes);
            }
            let report = run(&t.fs, &["pkg.rustup"]);
            assert!(listed(&report, "pkg.rustup").is_empty(), "{what}");
        }
        // A symlink or a folder in place of the file is not read either.
        let mut t = rustup_home(None, &tc_refs(&all));
        t.link(".rustup/settings.toml", "/elsewhere");
        assert!(listed(&run(&t.fs, &["pkg.rustup"]), "pkg.rustup").is_empty());
        let mut t = rustup_home(None, &tc_refs(&all));
        t.dir(".rustup/settings.toml");
        assert!(listed(&run(&t.fs, &["pkg.rustup"]), "pkg.rustup").is_empty());
    }

    // #61: only the folders of `toolchains`: not the rest of `~/.rustup`, not
    // files, not links.
    #[test]
    fn rustup_lists_only_toolchain_folders() {
        let all = toolchains();
        let mut t = rustup_home(Some(&settings(Some(&all[0]), &[])), &tc_refs(&all));
        t.file(&format!("{TC}/stray-file"));
        t.link(&format!("{TC}/linked-{ARM}"), "/opt/toolchain");
        t.file(".rustup/downloads/x");
        let report = run(&t.fs, &["pkg.rustup"]);
        let got = listed(&report, "pkg.rustup");
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(
            got.iter().all(|p| p.starts_with(&format!("{TC}/"))),
            "{got:?}"
        );
        assert!(got
            .iter()
            .all(|p| !p.contains("stray-file") && !p.contains("linked-")));
    }

    // #61: medium, not preselected, no app to close; and the only file it
    // reads is the settings file of the same rustup home.
    #[test]
    fn rustup_is_medium_not_default_and_reads_only_its_settings() {
        let m = meta("pkg.rustup");
        assert_eq!(m.risk, Risk::Medium);
        assert!(!m.default_selected);
        assert_eq!(m.requires_app_closed, None);
        let all = toolchains();
        let t = rustup_home(Some(&settings(Some(&all[0]), &[])), &tc_refs(&all));
        let _ = run(&t.fs, &["pkg.rustup"]);
        let reads = t.fs.read_log();
        assert!(!reads.is_empty());
        assert!(
            reads
                .iter()
                .all(|p| *p == Path::new(HOME).join(".rustup/settings.toml")),
            "{reads:?}"
        );
    }

    // --- Cargo, Go, Maven and Gradle (#60) -------------------------------------

    // #60: the registry cache and the unpacked sources, one item per registry;
    // never the binaries, the configuration, the credentials or the index.
    #[test]
    fn cargo_found_in_fixture() {
        let mut t = Tree::new();
        t.file(".cargo/registry/cache/index.crates.io-aaaa/serde-1.0.0.crate")
            .file(".cargo/registry/cache/github.com-bbbb/x-0.1.0.crate")
            .file(".cargo/registry/src/index.crates.io-aaaa/serde-1.0.0/lib.rs")
            .file(".cargo/registry/index/index.crates.io-aaaa/config.json")
            .file(".cargo/git/db/repo/HEAD")
            .file(".cargo/bin/rustc")
            .text(".cargo/config.toml", b"[registry]\n")
            .text(
                ".cargo/credentials.toml",
                b"[registry]\ntoken = \"secret\"\n",
            );
        let report = run(&t.fs, &["pkg.cargo"]);
        assert_eq!(
            listed(&report, "pkg.cargo"),
            [
                ".cargo/registry/cache/github.com-bbbb",
                ".cargo/registry/cache/index.crates.io-aaaa",
                ".cargo/registry/src/index.crates.io-aaaa",
            ]
        );
        let m = meta("pkg.cargo");
        assert_eq!(m.risk, Risk::Low);
        assert!(m.default_selected);
    }

    // #60: Go build cache: low and preselected; module cache: medium and not.
    #[test]
    fn go_found_in_fixture() {
        let mut t = Tree::new();
        t.file("Library/Caches/go-build/00/aa-d")
            .file("Library/Caches/go-build/ff/bb-a")
            .file("Library/Caches/go-build/README")
            .file("go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go")
            .file("go/pkg/mod/cache/download/x")
            .file("go/pkg/sumdb/sum.golang.org/latest")
            .file("go/bin/tool");
        let report = run(&t.fs, &["pkg.go-build", "pkg.go-mod"]);
        assert_eq!(
            listed(&report, "pkg.go-build"),
            [
                "Library/Caches/go-build/00",
                "Library/Caches/go-build/README",
                "Library/Caches/go-build/ff",
            ]
        );
        assert_eq!(
            listed(&report, "pkg.go-mod"),
            ["go/pkg/mod/cache", "go/pkg/mod/github.com"]
        );
        let build = meta("pkg.go-build");
        assert_eq!(build.risk, Risk::Low);
        assert!(build.default_selected);
    }

    #[test]
    fn go_mod_is_medium_not_default() {
        let m = meta("pkg.go-mod");
        assert_eq!(m.risk, Risk::Medium);
        assert!(!m.default_selected);
        assert_eq!(m.requires_app_closed, None);
    }

    // #60: the Go build cache is `go-build` in the user caches; the more
    // specific rule keeps its bytes and `sys.user-caches` only keeps the folder.
    #[test]
    fn go_build_goes_to_go_build_not_user_caches() {
        let mut t = Tree::new();
        t.file("Library/Caches/go-build/00/aa-d")
            .file("Library/Caches/other/x");
        let report = run(&t.fs, &["pkg.go-build", "sys.user-caches"]);
        assert_eq!(
            listed(&report, "pkg.go-build"),
            ["Library/Caches/go-build/00"]
        );
        let user = report
            .items
            .iter()
            .find(|i| i.rule.as_str() == "sys.user-caches" && i.path.ends_with("go-build"))
            .map(|i| i.allocated_bytes);
        assert_eq!(user, Some(0));
    }

    // #60: Maven local repository and Gradle caches: medium, not preselected;
    // the settings, the credentials and the wrapper distributions stay out.
    #[test]
    fn maven_and_gradle_found_in_fixture() {
        let mut t = Tree::new();
        t.file(".m2/repository/org/apache/maven/x.jar")
            .file(".m2/repository/junit/junit/4.13/junit.jar")
            .text(".m2/settings.xml", b"<settings/>")
            .file(".gradle/caches/modules-2/files-2.1/x.jar")
            .file(".gradle/caches/jars-9/y.jar")
            .file(".gradle/wrapper/dists/gradle-8/x")
            .text(".gradle/gradle.properties", b"token=secret\n");
        let report = run(&t.fs, &["pkg.maven", "pkg.gradle"]);
        assert_eq!(
            listed(&report, "pkg.maven"),
            [".m2/repository/junit", ".m2/repository/org"]
        );
        assert_eq!(
            listed(&report, "pkg.gradle"),
            [".gradle/caches/jars-9", ".gradle/caches/modules-2"]
        );
        for id in ["pkg.maven", "pkg.gradle"] {
            let m = meta(id);
            assert_eq!(m.risk, Risk::Medium, "{id}");
            assert!(!m.default_selected, "{id}");
            assert_eq!(m.requires_app_closed, None, "{id}");
        }
    }

    // --- crash reports (#63) --------------------------------------------------

    // #63: the diagnostic reports go to the crash reports rule, which is
    // registered before the user logs, and not to the logs.
    #[test]
    fn diagnostic_reports_go_to_crash_reports_not_logs() {
        let mut t = Tree::new();
        t.file("Library/Logs/DiagnosticReports/app-2026.ips")
            .file("Library/Logs/DiagnosticReports/other.crash")
            .file("Library/Application Support/CrashReporter/report.plist")
            .file("Library/Logs/other.log");
        let report = run(&t.fs, &["sys.crash-reports", "sys.logs"]);
        assert_eq!(
            listed(&report, "sys.crash-reports"),
            [
                "Library/Application Support/CrashReporter/report.plist",
                "Library/Logs/DiagnosticReports/app-2026.ips",
                "Library/Logs/DiagnosticReports/other.crash",
            ]
        );
        // The logs rule only keeps the folder itself, without those bytes.
        let folder = report
            .items
            .iter()
            .find(|i| i.rule.as_str() == "sys.logs" && i.path.ends_with("DiagnosticReports"))
            .map(|i| i.allocated_bytes);
        assert_eq!(folder, Some(0));
        let m = meta("sys.crash-reports");
        assert_eq!(m.risk, Risk::Low);
        assert!(m.default_selected);
        let ids: Vec<&str> = super::super::builtin()
            .iter()
            .map(|r| r.meta().id.as_str())
            .collect();
        let at = |id: &str| ids.iter().position(|x| *x == id).unwrap();
        assert!(at("sys.crash-reports") < at("sys.logs"));
    }
}
