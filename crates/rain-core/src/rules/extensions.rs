//! Older versions of editor extensions. Each folder is
//! `publisher.name-MAJOR.MINOR.PATCH[-target]`; the newest one per
//! (extension, target) is kept. Anything not understood fails closed.

use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};
use std::collections::BTreeSet;
use std::path::Path;

/// Platform suffixes the VS Code marketplace uses.
const TARGETS: &[&str] = &[
    "darwin-x64",
    "darwin-arm64",
    "linux-x64",
    "linux-arm64",
    "linux-armhf",
    "alpine-x64",
    "alpine-arm64",
    "win32-x64",
    "win32-arm64",
    "win32-ia32",
    "web",
    "universal",
];

#[derive(Debug, PartialEq, Eq)]
struct Parsed<'a> {
    id: &'a str,
    version: [u64; 3],
    target: &'a str,
}

fn parse(name: &str) -> Option<Parsed<'_>> {
    let (rest, target) = TARGETS
        .iter()
        .find_map(|t| name.strip_suffix(t)?.strip_suffix('-').map(|r| (r, *t)))
        .unwrap_or((name, ""));
    let (id, version) = rest.rsplit_once('-')?;
    let (publisher, ext) = id.split_once('.')?;
    let ok_part = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
            })
    };
    if !ok_part(publisher) || !ok_part(ext) {
        return None;
    }
    let mut parts = version.split('.');
    let mut v = [0u64; 3];
    for slot in &mut v {
        let p = parts.next()?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = p.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(Parsed {
        id,
        version: v,
        target,
    })
}

/// `true` only when a strictly newer sibling of the same extension and
/// target exists and no sibling of that extension is unparseable.
fn is_older(name: &str, siblings: &[String]) -> bool {
    let Some(me) = parse(name) else {
        return false;
    };
    let prefix = format!("{}-", me.id);
    let mut newer = false;
    for other in siblings.iter().filter(|s| s.as_str() != name) {
        match parse(other) {
            Some(o) if o.id == me.id && o.target == me.target => {
                if o.version == me.version {
                    return false;
                }
                newer |= o.version > me.version;
            }
            Some(_) => {}
            None if other.starts_with(&prefix) => return false,
            None => {}
        }
    }
    newer
}

pub(super) struct OldExtensions {
    meta: RuleMeta,
    rel: &'static str,
}

impl Rule for OldExtensions {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

fn names(fs: &dyn Fs, dir: &Path) -> Option<Vec<String>> {
    let entries = fs.read_dir(dir).ok()?;
    entries
        .iter()
        .map(|e| e.path.file_name()?.to_str().map(str::to_owned))
        .collect()
}

/// Largest `extensions.json` that is read (the real ones are a few tens of
/// KB); a larger one is not cut, it is not used.
const MAX_JSON_BYTES: u64 = 1024 * 1024;

/// #139: the folder names the editor has registered in the `extensions.json`
/// of the rule's own folder. The one in use may be older than the newest (the
/// user pinned a version), so it must stay. `None` for anything unusable (no
/// file, a symlink, too large, not text, not a list): the rule then does what
/// it did before, never more. Entries without a text `relativeLocation` say
/// nothing and are skipped.
fn registered(fs: &dyn Fs, dir: &Path) -> Option<BTreeSet<String>> {
    let text = fs
        .read_to_string(&dir.join("extensions.json"), MAX_JSON_BYTES)
        .ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(
        value
            .as_array()?
            .iter()
            .filter_map(|e| e.get("relativeLocation")?.as_str().map(str::to_owned))
            .collect(),
    )
}

impl FileRule for OldExtensions {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        vec![RootedPath::Under(Root::Home, self.rel)]
    }
    fn visit(&self, entry: &EntryInfo, depth: usize, _: &RuleContext, fs: &dyn Fs) -> Visit {
        if depth == 0 {
            return Visit::Descend;
        }
        let (Some(name), Some(parent)) = (
            entry.path.file_name().and_then(|n| n.to_str()),
            entry.path.parent(),
        ) else {
            return Visit::Skip;
        };
        if !entry.meta.is_dir {
            return Visit::Skip;
        }
        // Fail closed: an unreadable folder or a non-UTF-8 sibling lists nothing.
        match names(fs, parent) {
            Some(siblings) if is_older(name, &siblings) => {
                // #139: the version registered by the editor is in use.
                if registered(fs, parent).is_some_and(|set| set.contains(name)) {
                    Visit::Skip
                } else {
                    Visit::Candidate
                }
            }
            _ => Visit::Skip,
        }
    }
}

const fn meta(
    id: &'static str,
    name: &'static str,
    consequence: &'static str,
    app: &'static str,
) -> RuleMeta {
    RuleMeta {
        id: RuleId::new(id),
        category: Category::AiTools,
        risk: Risk::Medium,
        name_key: name,
        consequence_key: consequence,
        default_selected: false,
        requires_app_closed: Some(app),
        os: &[Os::Macos],
    }
}

pub(super) static VSCODE_OLD_EXTENSIONS: OldExtensions = OldExtensions {
    meta: meta(
        "ai.vscode.old-extensions",
        "rule.ai.vscode.old-extensions",
        "rule.ai.vscode.old-extensions.consequence",
        "com.microsoft.VSCode",
    ),
    rel: ".vscode/extensions",
};

pub(super) static CURSOR_OLD_EXTENSIONS: OldExtensions = OldExtensions {
    meta: meta(
        "ai.cursor.old-extensions",
        "rule.ai.cursor.old-extensions",
        "rule.ai.cursor.old-extensions.consequence",
        "com.todesktop.230313mzl4w4u92",
    ),
    rel: ".cursor/extensions",
};

#[cfg(test)]
mod tests {
    use super::*;

    // Parsing is strict.
    #[test]
    fn parses_names() {
        assert_eq!(
            parse("ms-python.vscode-pylance-2024.1.1"),
            Some(Parsed {
                id: "ms-python.vscode-pylance",
                version: [2024, 1, 1],
                target: ""
            })
        );
        assert_eq!(
            parse("rust-lang.rust-analyzer-0.3.2-darwin-arm64").map(|p| p.target),
            Some("darwin-arm64")
        );
        for bad in [
            "extensions.json",
            ".obsolete",
            "bad-name",
            "a.b-1.0",
            "a.b-1.0.0.0",
            "a.b-1.0.0-beta",
            "a.b-v1.0.0",
            "A.b-1.0.0",
            "ab-1.0.0",
            "a.b-1..0",
            "a.b-1.0.0-darwin-arm64-x",
            "a.b-99999999999999999999.0.0",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    // --- #139: the version the editor has registered is kept -------------

    use crate::fs::{FakeFs, Metadata};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::protect::ProtectList;
    use rain_platform::{Platform, PlatformError};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::time::SystemTime;

    const HOME: &str = "/Users/Tester";
    const RULES: &[(&str, &str)] = &[
        ("ai.vscode.old-extensions", ".vscode/extensions"),
        ("ai.cursor.old-extensions", ".cursor/extensions"),
    ];

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

    /// What `extensions.json` is in a fixture.
    enum Json<'a> {
        Absent,
        Text(&'a [u8]),
        Symlink,
        Folder,
    }

    /// Home with `rel` holding `p.e` at 1.0.0, 1.1.0 and 2.0.0, `q.f` at 1.0.0
    /// and 2.0.0, and an `extensions.json` as given.
    fn editor(rel: &str, json: &Json) -> (FakeFs, PathBuf) {
        let root = Path::new(HOME).join(rel);
        let mut fs = FakeFs::new();
        fs.insert("/Users", md(true, 1))
            .insert(HOME, md(true, 2))
            .insert(
                Path::new(HOME).join(rel.split('/').next().unwrap_or_default()),
                md(true, 3),
            )
            .insert(&root, md(true, 4));
        let mut ino = 10;
        for name in [
            "p.e-1.0.0",
            "p.e-1.1.0",
            "p.e-2.0.0",
            "q.f-1.0.0",
            "q.f-2.0.0",
        ] {
            ino += 1;
            fs.insert(root.join(name), md(true, ino))
                .insert(root.join(name).join("a.js"), md(false, ino + 100));
        }
        let file = root.join("extensions.json");
        match json {
            Json::Absent => {}
            Json::Text(bytes) => {
                fs.insert_file(&file, md(false, 900), bytes.to_vec());
            }
            Json::Symlink => {
                fs.insert_file(root.join("real.json"), md(false, 901), pinned("p.e-1.1.0"))
                    .insert_symlink(&file, root.join("real.json"));
            }
            Json::Folder => {
                fs.insert(&file, md(true, 902));
            }
        }
        (fs, root)
    }

    fn pinned(folder: &str) -> Vec<u8> {
        format!(r#"[{{"identifier":{{"id":"x"}},"version":"0","relativeLocation":"{folder}"}}]"#)
            .into_bytes()
    }

    /// Folders listed by `id` and every path read through the filesystem.
    fn listed(id: &str, rel: &str, json: &Json) -> (Vec<String>, Vec<PathBuf>) {
        let (fs, root) = editor(rel, json);
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: Path::new(HOME).join("Library/Caches"),
            logs: Path::new(HOME).join("Library/Logs"),
        };
        let ctx = ScanContext {
            fs: &fs,
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
        let rules = super::super::select(&[id]).unwrap();
        let report = scan(&rules, &ctx, &AtomicBool::new(false)).unwrap();
        let names = report
            .items
            .iter()
            .filter_map(|i| i.path.strip_prefix(&root).ok()?.to_str().map(str::to_owned))
            .collect();
        (names, fs.read_log())
    }

    const TODAY: &[&str] = &["p.e-1.0.0", "p.e-1.1.0", "q.f-1.0.0"];

    // #139: the user pinned an older version; it is the one in use, so it
    // stays, next to the newest. Both editors share the code.
    #[test]
    fn pinned_older_version_is_kept() {
        for (id, rel) in RULES {
            let (got, _) = listed(id, rel, &Json::Text(&pinned("p.e-1.1.0")));
            assert_eq!(got, ["p.e-1.0.0", "q.f-1.0.0"], "{id}");
            let (got, _) = listed(id, rel, &Json::Text(&pinned("p.e-1.0.0")));
            assert_eq!(got, ["p.e-1.1.0", "q.f-1.0.0"], "{id}");
        }
    }

    // #139: what the editor registered for other extensions is kept too.
    #[test]
    fn every_registered_folder_is_kept() {
        let json = br#"[{"relativeLocation":"p.e-1.0.0"},{"relativeLocation":"p.e-1.1.0"},{"relativeLocation":"q.f-1.0.0"}]"#;
        for (id, rel) in RULES {
            assert!(listed(id, rel, &Json::Text(json)).0.is_empty(), "{id}");
        }
    }

    // #139: an extension the file does not mention keeps only the newest,
    // as today.
    #[test]
    fn extension_missing_from_the_file_behaves_as_today() {
        let json = pinned("q.f-2.0.0");
        for (id, rel) in RULES {
            assert_eq!(listed(id, rel, &Json::Text(&json)).0, TODAY, "{id}");
        }
    }

    // #139, fail closed: a file that is missing, unreadable as text, not JSON,
    // not a list, too large, a symlink or a folder, or entries without a
    // usable `relativeLocation`, change nothing: never worse than today.
    #[test]
    fn unusable_extensions_json_behaves_as_today() {
        let huge = vec![b' '; 1024 * 1024 + 1];
        let cases: Vec<(&str, Json)> = vec![
            ("absent", Json::Absent),
            ("empty", Json::Text(b"")),
            ("not json", Json::Text(b"[{")),
            (
                "not a list",
                Json::Text(br#"{"relativeLocation":"p.e-1.1.0"}"#),
            ),
            ("not utf-8", Json::Text(&[0xff, 0xfe, 0x5b, 0x5d])),
            (
                "no relativeLocation",
                Json::Text(br#"[{"version":"1.1.0"}]"#),
            ),
            (
                "not a string",
                Json::Text(br#"[{"relativeLocation":["p.e-1.1.0"]}]"#),
            ),
            ("too large", Json::Text(&huge)),
            ("symlink", Json::Symlink),
            ("folder", Json::Folder),
        ];
        for (id, rel) in RULES {
            for (what, json) in &cases {
                assert_eq!(listed(id, rel, json).0, TODAY, "{id}: {what}");
            }
        }
    }

    // #139: the only file read is `extensions.json` in the rule's own
    // folder, and a symlinked one is refused by the filesystem, not read.
    #[test]
    fn only_the_rules_own_extensions_json_is_read() {
        for (id, rel) in RULES {
            let root = Path::new(HOME).join(rel);
            let want = root.join("extensions.json");
            let (_, reads) = listed(id, rel, &Json::Text(&pinned("p.e-1.1.0")));
            assert!(!reads.is_empty(), "{id}: nothing was read");
            assert!(reads.iter().all(|p| *p == want), "{id}: {reads:?}");
            // With a symlink the read is attempted at the same path only.
            let (names, reads) = listed(id, rel, &Json::Symlink);
            assert_eq!(names, TODAY, "{id}");
            assert!(reads.iter().all(|p| *p == want), "{id}: {reads:?}");
        }
    }

    // Numeric, not lexical, comparison; single versions are kept.
    #[test]
    fn only_strictly_older_versions() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let sib = s(&["p.e-1.2.0", "p.e-1.10.0", "q.f-3.0.0"]);
        assert!(is_older("p.e-1.2.0", &sib));
        assert!(!is_older("p.e-1.10.0", &sib));
        assert!(!is_older("q.f-3.0.0", &sib));
        // Unparseable sibling of the same extension: keep everything.
        assert!(!is_older("p.e-1.2.0", &s(&["p.e-1.2.0", "p.e-2.0.0-rc"])));
        // Different targets are separate groups.
        assert!(!is_older(
            "p.e-1.0.0-darwin-x64",
            &s(&["p.e-1.0.0-darwin-x64", "p.e-2.0.0-darwin-arm64"])
        ));
        // Same version twice (different target spelling impossible): keep.
        assert!(!is_older("p.e-1.0.0", &s(&["p.e-1.0.0"])));
    }
}
