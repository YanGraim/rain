//! Browser caches (catalogue 6.5): Chrome and Brave.
//!
//! Each rule lists only the named cache folders (`Cache`, `Code Cache`) that
//! sit directly in a profile folder below the browser's cache root. The
//! profile data (cookies, saved logins, history, autofill, extensions, local
//! storage) lives under Application Support, which no rule here uses, and a
//! name that is not on the list is never an item even inside a cache root.

use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};

pub(super) static RULES: &[&dyn Rule] = &[&CHROME, &BRAVE];

/// The cache folders a Chromium browser keeps in each profile folder below
/// its cache root. Anything else, whatever its name, is left alone.
const CACHE_DIRS: &[&str] = &["Cache", "Code Cache"];

const fn meta(
    id: &'static str,
    name_key: &'static str,
    consequence_key: &'static str,
    bundle: &'static str,
) -> RuleMeta {
    RuleMeta {
        id: RuleId::new(id),
        category: Category::Browsers,
        risk: Risk::Low,
        name_key,
        consequence_key,
        default_selected: true,
        requires_app_closed: Some(bundle),
        os: &[Os::Macos],
    }
}

/// A rule over `<cache root>/<profile>/<cache folder>`.
pub struct ProfileCaches {
    meta: RuleMeta,
    /// The cache root below `{caches}`.
    root: &'static str,
}

impl Rule for ProfileCaches {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for ProfileCaches {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        vec![RootedPath::Under(Root::Caches, self.root)]
    }
    fn visit(&self, entry: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        match depth {
            0 => Visit::Descend,
            // A profile folder; plain files at the cache root are not items.
            1 if entry.meta.is_dir => Visit::Descend,
            2 if entry.meta.is_dir
                && entry
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| CACHE_DIRS.contains(&n)) =>
            {
                Visit::Candidate
            }
            _ => Visit::Skip,
        }
    }
}

/// Chrome: `~/Library/Caches/Google/Chrome/<profile>` (the Chromium user data
/// directory notes).
pub static CHROME: ProfileCaches = ProfileCaches {
    meta: meta(
        "browser.chrome",
        "rule.browser.chrome",
        "rule.browser.chrome.consequence",
        "com.google.Chrome",
    ),
    root: "Google/Chrome",
};

/// Brave: `~/Library/Caches/BraveSoftware/Brave-Browser/<profile>`.
pub static BRAVE: ProfileCaches = ProfileCaches {
    meta: meta(
        "browser.brave",
        "rule.browser.brave",
        "rule.browser.brave.consequence",
        "com.brave.Browser",
    ),
    root: "BraveSoftware/Brave-Browser",
};

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

    /// (rule id, cache root below the home, profile data root below the home,
    /// bundle id of the app).
    const BROWSERS: [(&str, &str, &str, &str); 2] = [
        (
            "browser.chrome",
            "Library/Caches/Google/Chrome",
            "Library/Application Support/Google/Chrome",
            "com.google.Chrome",
        ),
        (
            "browser.brave",
            "Library/Caches/BraveSoftware/Brave-Browser",
            "Library/Application Support/BraveSoftware/Brave-Browser",
            "com.brave.Browser",
        ),
    ];

    /// Names of profile data: never an item, in any profile.
    const USER_DATA: [&str; 8] = [
        "Cookies",
        "Login Data",
        "History",
        "Web Data",
        "Extensions",
        "Local Storage",
        "Bookmarks",
        "IndexedDB",
    ];

    #[test]
    fn chrome_profile_lists_only_cache_dirs() {
        let mut t = Tree::new();
        for profile in ["Default", "Profile 1", "System Profile"] {
            t.dir(&format!("Library/Caches/Google/Chrome/{profile}/Cache"))
                .file(&format!(
                    "Library/Caches/Google/Chrome/{profile}/Cache/data_0"
                ))
                .dir(&format!(
                    "Library/Caches/Google/Chrome/{profile}/Code Cache"
                ))
                .dir(&format!(
                    "Library/Caches/Google/Chrome/{profile}/Local Storage"
                ))
                .file(&format!("Library/Caches/Google/Chrome/{profile}/Cookies"))
                .file(&format!("Library/Caches/Google/Chrome/{profile}/notes.txt"));
        }
        // A plain file with a cache folder's name is not a cache folder.
        t.dir("Library/Caches/Google/Chrome/Profile 2")
            .file("Library/Caches/Google/Chrome/Profile 2/Code Cache");
        // A stray file and an unknown folder at the root of the cache.
        t.file("Library/Caches/Google/Chrome/Cache")
            .dir("Library/Caches/Google/Chrome/ShaderCache");
        let r = run(&t.fs, &["browser.chrome"]);
        let base = "Library/Caches/Google/Chrome";
        assert_eq!(
            listed(&r, "browser.chrome"),
            [
                format!("{base}/Default/Cache"),
                format!("{base}/Default/Code Cache"),
                format!("{base}/Profile 1/Cache"),
                format!("{base}/Profile 1/Code Cache"),
                format!("{base}/System Profile/Cache"),
                format!("{base}/System Profile/Code Cache"),
            ]
        );
    }

    #[test]
    fn cookies_and_login_data_protected_in_any_profile() {
        for (id, cache, data, _) in BROWSERS {
            let mut t = Tree::new();
            for profile in ["Default", "Profile 7"] {
                t.dir(&format!("{cache}/{profile}/Cache"));
                for name in USER_DATA {
                    // Inside the cache root and in the real profile folder.
                    t.dir(&format!("{cache}/{profile}/{name}"))
                        .file(&format!("{cache}/{profile}/{name}/x"))
                        .dir(&format!("{data}/{profile}/{name}"))
                        .file(&format!("{data}/{profile}/{name}/x"));
                }
            }
            let r = run(&t.fs, &[id]);
            assert_eq!(
                listed(&r, id),
                [
                    format!("{cache}/Default/Cache"),
                    format!("{cache}/Profile 7/Cache"),
                ],
                "{id}"
            );
            assert!(
                r.items
                    .iter()
                    .all(|i| !i.path.starts_with(Path::new(HOME).join(data))),
                "{id}: nothing from the profile data folder"
            );
        }
    }

    #[test]
    fn each_browser_lists_its_own_cache_root_only() {
        for (id, cache, _, _) in BROWSERS {
            let mut t = Tree::new();
            t.dir(&format!("{cache}/Default/Cache"))
                .dir(&format!("{cache}/Default/Code Cache"));
            for (other, other_cache, _, _) in BROWSERS {
                if other != id {
                    t.dir(&format!("{other_cache}/Default/Cache"));
                }
            }
            let r = run(&t.fs, &[id]);
            assert_eq!(
                listed(&r, id),
                [
                    format!("{cache}/Default/Cache"),
                    format!("{cache}/Default/Code Cache"),
                ],
                "{id}"
            );
        }
    }

    #[test]
    fn a_symlinked_cache_folder_is_not_an_item() {
        let mut t = Tree::new();
        t.dir("Library/Caches/Google/Chrome/Default/Code Cache");
        t.dir("Elsewhere");
        t.link(
            "Library/Caches/Google/Chrome/Default/Cache",
            "/Users/Tester/Elsewhere",
        );
        let r = run(&t.fs, &["browser.chrome"]);
        assert_eq!(
            listed(&r, "browser.chrome"),
            ["Library/Caches/Google/Chrome/Default/Code Cache"]
        );
    }

    #[test]
    fn browser_caches_are_low_and_ask_for_the_app_closed() {
        for (id, _, _, bundle) in BROWSERS {
            let m = meta(id);
            assert_eq!(m.risk, Risk::Low, "{id}");
            assert!(m.default_selected, "{id}");
            assert_eq!(m.requires_app_closed, Some(bundle), "{id}");
            assert_eq!(m.os, &[Os::Macos], "{id}");
        }
    }
}
