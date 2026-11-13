//! AI2e: older versions of editor extensions. Each folder is
//! `publisher.name-MAJOR.MINOR.PATCH[-target]`; the newest one per
//! (extension, target) is kept. Anything not understood fails closed.

use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};
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
            Some(siblings) if is_older(name, &siblings) => Visit::Candidate,
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

    // AI2e: parsing is strict.
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

    // AI2e: numeric, not lexical, comparison; single versions are kept.
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
