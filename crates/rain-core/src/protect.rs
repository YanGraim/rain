//! Protection list: built-in protected paths and path normalization.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use rain_platform::{Platform, PlatformError, Root};

use crate::fs::{Fs, Metadata};

use unicode_normalization::UnicodeNormalization;

/// Normalizes a path so that comparisons ignore Unicode form and letter case,
/// matching how APFS (case-insensitive, normalization-insensitive) resolves names.
///
/// Each normal component goes through NFD, full Unicode case folding
/// (CaseFolding.txt statuses C and F) and NFC. Full folding is required
/// because APFS resolves names such as `.ßh` to `.ssh`, `ſystem` to `System`,
/// `ﬁ` to `fi` and final `ς` to `σ`; plain lowercasing would miss those.
/// Folding is context-free, so a final sigma is not special. Turkic mappings
/// (status T) are not applied, so `İ` does not match `i`, and default
/// ignorable characters such as zero-width spaces are kept.
///
/// Roots, prefixes and `..` are kept: resolving them is the job of
/// canonicalization. Interior `.` components and redundant separators are
/// dropped by `Path::components`, which does not change what the path names;
/// a leading `.` is kept.
///
/// Components that are not valid UTF-8 are returned byte-for-byte. They are
/// not normalized, so callers that need fail-closed behaviour must handle
/// them explicitly.
pub fn normalize(path: &Path) -> PathBuf {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => normalize_component(name),
            other => other.as_os_str().to_os_string(),
        })
        .collect()
}

fn normalize_component(name: &std::ffi::OsStr) -> OsString {
    match name.to_str() {
        Some(text) => {
            let decomposed: String = text.nfd().collect();
            caseless::default_case_fold_str(&decomposed)
                .nfc()
                .collect::<String>()
                .into()
        }
        None => name.to_os_string(),
    }
}

/// Built-in protected paths, one per line; `~` stands for the home.
const BUILTIN: &str = include_str!("protected.list");

/// Why the protection list could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectError {
    /// The home could not be resolved, so home-relative entries cannot be
    /// placed and nothing may be scanned.
    Platform(PlatformError),
    /// A list entry is relative or not fully resolved.
    InvalidEntry(String),
    /// A list entry repeats an earlier one after normalization.
    DuplicateEntry(String),
}

impl fmt::Display for ProtectError {
    // Developer-facing text only; the CLI maps variants to localized messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(e) => write!(f, "cannot build protection list: {e}"),
            Self::InvalidEntry(l) => write!(f, "invalid protection list entry: {l}"),
            Self::DuplicateEntry(l) => write!(f, "duplicate protection list entry: {l}"),
        }
    }
}

impl std::error::Error for ProtectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(e) => Some(e),
            Self::InvalidEntry(_) | Self::DuplicateEntry(_) => None,
        }
    }
}

impl From<PlatformError> for ProtectError {
    fn from(e: PlatformError) -> Self {
        Self::Platform(e)
    }
}

/// A protected path in both its literal and normalized spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedPattern {
    literal: PathBuf,
    normalized: PathBuf,
}

/// Paths that must never be reported as candidates, whatever a rule or a
/// user-supplied root says.
///
/// Matching is by whole components against both the literal and the
/// normalized form, so `~/.SSH`, `~/.ßh` and an NFD spelling all hit `~/.ssh`
/// while `~/.sshx` does not. Inputs that cannot be compared reliably
/// (relative, non-UTF-8, or with `.`/`..` left over) are treated as protected.
#[derive(Debug, Clone)]
pub struct ProtectList {
    patterns: Vec<NormalizedPattern>,
    identities: BTreeSet<(u64, u64)>,
}

impl ProtectList {
    /// Builds the embedded list, placing `~` entries below the platform home.
    pub fn builtin(platform: &dyn Platform) -> Result<Self, ProtectError> {
        let home = platform.resolve(Root::Home)?;
        Ok(Self {
            patterns: parse_list(BUILTIN, &home)?,
            identities: BTreeSet::new(),
        })
    }

    /// Records the `(dev, ino)` of every protected path that exists, so a
    /// path that reaches one of them under another name (firmlink, hard
    /// link to a directory, a spelling folding misses) is still caught.
    /// Missing or unreadable entries are skipped: the name check covers them.
    pub fn with_identities(mut self, fs: &dyn Fs) -> Self {
        for pattern in &self.patterns {
            let Ok(canonical) = fs.canonicalize(&pattern.literal) else {
                continue;
            };
            if let Ok(meta) = fs.symlink_metadata(&canonical) {
                self.identities.insert((meta.dev, meta.ino));
            }
        }
        self
    }

    /// True if `canonical` is a protected path or lies below one.
    pub fn is_protected(&self, canonical: &Path) -> bool {
        let Some(normalized) = comparable(canonical) else {
            return true;
        };
        self.patterns
            .iter()
            .any(|p| canonical.starts_with(&p.literal) || normalized.starts_with(&p.normalized))
    }

    /// True if `canonical` is an ancestor of (or equal to) a protected path,
    /// so taking it whole would take protected data with it.
    pub fn contains_protected(&self, canonical: &Path) -> bool {
        let Some(normalized) = comparable(canonical) else {
            return true;
        };
        self.patterns
            .iter()
            .any(|p| p.literal.starts_with(canonical) || p.normalized.starts_with(&normalized))
    }

    /// Name check plus identity check of `canonical` alone, using metadata
    /// the caller already read. Only sound when every ancestor was already
    /// cleared (the walker clears the root with [`Self::is_protected_on`]
    /// and each directory before descending), so it avoids re-reading the
    /// whole ancestor chain for every entry.
    pub fn is_protected_entry(&self, canonical: &Path, meta: &Metadata) -> bool {
        self.is_protected(canonical) || self.identities.contains(&(meta.dev, meta.ino))
    }

    /// Name check plus identity check: `canonical` or any ancestor sharing
    /// the `(dev, ino)` of a protected root makes it protected. An ancestor
    /// that cannot be read fails closed.
    pub fn is_protected_on(&self, fs: &dyn Fs, canonical: &Path) -> bool {
        if self.is_protected(canonical) {
            return true;
        }
        if self.identities.is_empty() {
            return false;
        }
        canonical
            .ancestors()
            .any(|ancestor| match fs.symlink_metadata(ancestor) {
                Ok(meta) => self.identities.contains(&(meta.dev, meta.ino)),
                Err(_) => true,
            })
    }
}

/// Parses a protection list: one path per line, `#` comments and blank
/// lines ignored, `~/` placed below `home`.
///
/// Relative entries, `~` alone, `~user`, `.`/`..` components and entries
/// that normalize to an earlier one are rejected, so a malformed list stops
/// the scan instead of silently protecting less.
fn parse_list(text: &str, home: &Path) -> Result<Vec<NormalizedPattern>, ProtectError> {
    let mut patterns: Vec<NormalizedPattern> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let invalid = || ProtectError::InvalidEntry(line.to_string());
        let literal = match line.strip_prefix("~/") {
            Some(rest) if !rest.is_empty() && Path::new(rest).is_relative() => home.join(rest),
            Some(_) => return Err(invalid()),
            None if line.starts_with('/') => PathBuf::from(line),
            None => return Err(invalid()),
        };
        let normalized = comparable(&literal).ok_or_else(invalid)?;
        if patterns.iter().any(|p| p.normalized == normalized) {
            return Err(ProtectError::DuplicateEntry(line.to_string()));
        }
        patterns.push(NormalizedPattern {
            literal,
            normalized,
        });
    }
    Ok(patterns)
}

/// Normalized form of an absolute, fully resolved, UTF-8 path; `None` when
/// the path cannot be compared safely.
fn comparable(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let clean = path.components().all(|c| match c {
        Component::Normal(name) => name.to_str().is_some(),
        Component::RootDir | Component::Prefix(_) => true,
        Component::CurDir | Component::ParentDir => false,
    });
    clean.then(|| normalize(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    use unicode_normalization::UnicodeNormalization;

    fn n(s: &str) -> PathBuf {
        normalize(Path::new(s))
    }

    fn raw(s: &str) -> OsString {
        n(s).into_os_string()
    }

    /// Groups of spellings that a case- and normalization-insensitive
    /// filesystem treats as the same text.
    pub(super) const EQUIVALENT: &[&[&str]] = &[
        &["a", "A"],
        &["x", "X"],
        &["1"],
        &["-"],
        &[
            "ss",
            "SS",
            "sS",
            "Ss",
            "\u{df}",
            "\u{1e9e}",
            "\u{17f}s",
            "\u{17f}\u{17f}",
            "S\u{17f}",
        ],
        &["s", "S", "\u{17f}"],
        &["fi", "FI", "Fi", "fI", "\u{fb01}"],
        &["k", "K", "\u{212a}"],
        &["\u{3c9}", "\u{3a9}", "\u{2126}"],
        &["\u{3c3}", "\u{3a3}", "\u{3c2}"],
        &["\u{3b1}", "\u{391}"],
        &["\u{e9}", "\u{c9}", "e\u{301}", "E\u{301}"],
        // Combining marks with different canonical classes, in both orders.
        &[
            "a\u{323}\u{301}",
            "a\u{301}\u{323}",
            "A\u{301}\u{323}",
            "\u{1ea1}\u{301}",
            "\u{1ea0}\u{301}",
        ],
        // Precomposed Hangul syllable and its conjoining jamo.
        &["\u{d55c}", "\u{1112}\u{1161}\u{11ab}"],
        &["\u{1c6}", "\u{1c5}", "\u{1c4}"],
    ];

    /// Two names built from the same groups, with an independent spelling
    /// chosen per group on each side.
    fn equivalent_names() -> impl Strategy<Value = (String, String)> {
        let group = (0..EQUIVALENT.len()).prop_flat_map(|g| {
            let len = EQUIVALENT[g].len();
            (Just(g), 0..len, 0..len)
        });
        prop::collection::vec(group, 1..8).prop_map(|parts| {
            let mut left = String::new();
            let mut right = String::new();
            for (g, i, j) in parts {
                left.push_str(EQUIVALENT[g][i]);
                right.push_str(EQUIVALENT[g][j]);
            }
            (left, right)
        })
    }

    fn any_path() -> impl Strategy<Value = String> {
        let pool: Vec<&str> = EQUIVALENT.iter().flat_map(|g| g.iter().copied()).collect();
        let piece = prop_oneof![
            any::<char>().prop_map(String::from),
            prop::sample::select(pool).prop_map(String::from),
            Just("/".to_string()),
            Just(".".to_string()),
        ];
        prop::collection::vec(piece, 0..16).prop_map(|v| v.concat().replace('\0', ""))
    }

    proptest! {
        // FR-007
        #[test]
        fn nfd_and_nfc_normalize_equal((a, b) in equivalent_names()) {
            let nfc = format!("/Users/{}/{}", a.nfc(), b.nfc());
            let nfd = format!("/Users/{}/{}", a.nfd(), b.nfd());
            prop_assert_eq!(n(&nfc), n(&nfd));
        }

        // FR-007
        #[test]
        fn case_variants_normalize_equal((a, b) in equivalent_names()) {
            prop_assert_eq!(
                raw(&format!("/Users/{a}")),
                raw(&format!("/uSERs/{b}"))
            );
        }

        // FR-007
        #[test]
        fn normalize_is_idempotent(s in any_path()) {
            let once = n(&s);
            prop_assert_eq!(normalize(&once).into_os_string(), once.into_os_string());
        }
    }

    // FR-007
    #[test]
    fn full_case_folding_matches_protected_names() {
        assert_eq!(n("~/.\u{df}h"), n("~/.ssh"));
        assert_eq!(n("/\u{17f}ystem"), n("/System"));
        assert_eq!(n("~/Library/Me\u{df}ages"), n("~/Library/Messages"));
        assert_eq!(n("~/Library/Keychain\u{17f}"), n("~/Library/Keychains"));
        assert_eq!(n("/\u{fb01}"), n("/fi"));
        assert_eq!(n("/\u{212a}"), n("/k"));
        assert_eq!(n("/\u{3a3}\u{391}\u{3a3}"), n("/\u{3c3}\u{3b1}\u{3c3}"));
    }

    // FR-007
    #[test]
    fn dotted_capital_i_does_not_match_plain_i() {
        assert_ne!(n("/\u{130}"), n("/i"));
    }

    // FR-007
    #[test]
    fn zero_width_characters_are_not_ignored() {
        assert_ne!(n("/s\u{200b}sh"), n("/ssh"));
        assert_ne!(n("/ss\u{200d}h"), n("/ssh"));
    }

    // FR-007
    #[test]
    fn decomposed_uppercase_matches_composed_lowercase() {
        assert_eq!(
            normalize(Path::new("/Users/x/RE\u{301}SUME\u{301}")),
            normalize(Path::new("/users/X/r\u{e9}sum\u{e9}"))
        );
    }

    // FR-007
    #[test]
    fn root_parent_and_empty_are_preserved() {
        assert_eq!(raw(""), "");
        assert_eq!(raw("/"), "/");
        assert_eq!(raw("/A/B/../C"), "/a/b/../c");
        assert_eq!(raw("../A"), "../a");
        assert_eq!(raw("Rel/X"), "rel/x");
    }

    // FR-007
    #[test]
    fn leading_dot_is_kept_and_interior_dots_are_dropped() {
        assert_eq!(raw("./A"), "./a");
        assert_eq!(raw("/A/./B/."), "/a/b");
    }

    // FR-007
    #[test]
    fn redundant_separators_are_collapsed() {
        assert_eq!(raw("/A//B/"), "/a/b");
    }

    // FR-007
    #[cfg(unix)]
    #[test]
    fn non_utf8_component_is_kept_verbatim() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let raw = OsStr::from_bytes(b"\xff\xfeX");
        let input = Path::new("/ABC").join(raw).join("D\u{e9}");
        let expected = Path::new("/abc").join(raw).join("d\u{e9}");
        assert_eq!(normalize(&input), expected);
    }
}

#[cfg(test)]
mod list_tests {
    use super::tests::EQUIVALENT;
    use super::*;
    use crate::fs::{FakeFs, Metadata};
    use proptest::prelude::*;
    use rain_platform::Os;
    use std::io;
    use std::time::SystemTime;
    use unicode_normalization::UnicodeNormalization;

    const HOME: &str = "/Users/Tester";

    /// Returns a fixed, already canonical home. `FakePlatform` is not used
    /// because it does not canonicalize, so it cannot stand in for a real root.
    struct HomeAt(Result<PathBuf, PlatformError>);

    impl Platform for HomeAt {
        fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
            self.0.clone()
        }
        fn is_root_user(&self) -> bool {
            false
        }
        fn os(&self) -> Os {
            Os::Macos
        }
    }

    fn list_for(home: &str) -> ProtectList {
        match ProtectList::builtin(&HomeAt(Ok(PathBuf::from(home)))) {
            Ok(list) => list,
            Err(e) => panic!("builtin failed: {e}"),
        }
    }

    fn list() -> ProtectList {
        list_for(HOME)
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s.replace('~', HOME))
    }

    const REQUIRED: &[&str] = &[
        "~/.ssh",
        "~/.gnupg",
        "~/Library/Keychains",
        "/private",
        "~/Documents",
        "~/Desktop",
        "~/Downloads",
        "~/Pictures/Photos Library.photoslibrary",
        "~/Library/Photos",
        "~/Library/Mail",
        "~/Library/Messages",
        "/System",
        "/usr",
        "~/Library/Mobile Documents",
        "~/Library/CloudStorage",
        "~/Library/Application Support/MobileSync",
        "~/Library/Group Containers",
        "/Applications",
        "/Library",
        "~/Applications",
        "/Volumes",
        "/opt",
        "~/Library/Safari",
        "~/Library/Cookies",
        "~/Library/Notes",
        "~/Library/Application Support/AddressBook",
        "~/Library/Application Support/Calendars",
        "~/Library/Application Support/1Password",
        "~/Library/Application Support/Bitwarden",
        "~/.aws",
        "~/.kube",
        "~/.config/gcloud",
        "~/.docker",
        "~/.password-store",
        // FR-043
        "~/Library/Caches/CloudKit",
        "~/Library/Caches/com.apple.bird",
        "~/Library/Caches/docker-secrets-engine",
    ];

    /// Splits text into tokens that each match one spelling in `EQUIVALENT`
    /// (multi-letter spellings first), or a literal character.
    fn tokens(text: &str) -> Vec<Result<usize, char>> {
        let lower = text.to_lowercase();
        let mut out = Vec::new();
        let mut rest = lower.as_str();
        while let Some(c) = rest.chars().next() {
            let single = &rest[..c.len_utf8()];
            let hit = ["ss", "fi", single]
                .into_iter()
                .filter(|t| rest.starts_with(t))
                .find_map(|t| {
                    EQUIVALENT
                        .iter()
                        .position(|g| g.contains(&t))
                        .map(|g| (g, t.len()))
                });
            match hit {
                Some((g, len)) => {
                    out.push(Ok(g));
                    rest = &rest[len..];
                }
                None => {
                    out.push(Err(c));
                    rest = &rest[c.len_utf8()..];
                }
            }
        }
        out
    }

    /// A spelling of `path` that APFS treats as the same name: every
    /// foldable token is replaced by a random equivalent (ß/ss, ſ/s, Kelvin
    /// K, ligatures, Greek, mixed case) and the result is NFC or NFD.
    fn spelling_of(path: String) -> impl Strategy<Value = String> {
        let toks = tokens(&path);
        let n = toks.len();
        (
            prop::collection::vec(any::<usize>(), n),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(move |(picks, upper_literal, nfd)| {
                let mut out = String::new();
                for (tok, pick) in toks.iter().zip(picks) {
                    match tok {
                        Ok(g) => out.push_str(EQUIVALENT[*g][pick % EQUIVALENT[*g].len()]),
                        Err(c) if upper_literal => out.extend(c.to_uppercase()),
                        Err(c) => out.push(*c),
                    }
                }
                if nfd {
                    out.nfd().collect()
                } else {
                    out.nfc().collect()
                }
            })
    }

    fn protected_variant() -> impl Strategy<Value = String> {
        let suffix = prop_oneof![
            Just(String::new()),
            Just("/id_ed25519".to_string()),
            Just("/a/b".to_string()),
        ];
        (prop::sample::select(REQUIRED), suffix)
            .prop_flat_map(|(base, suffix)| spelling_of(format!("{}{suffix}", p(base).display())))
    }

    /// Every ancestor of a required entry, as a string.
    fn required_ancestors() -> Vec<String> {
        let mut out: Vec<String> = REQUIRED
            .iter()
            .flat_map(|base| {
                p(base)
                    .ancestors()
                    .skip(1)
                    .map(|a| a.display().to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        // FR-007
        #[test]
        fn protected_under_any_case_or_normalization(path in protected_variant()) {
            prop_assert!(list().is_protected(Path::new(&path)), "{path:?}");
        }

        // FR-007: any spelling of an ancestor still contains protected data.
        #[test]
        fn ancestor_spelling_contains_protected(
            path in prop::sample::select(required_ancestors()).prop_flat_map(spelling_of)
        ) {
            prop_assert!(list().contains_protected(Path::new(&path)), "{path:?}");
        }
    }

    // FR-007
    #[test]
    fn literal_form_is_protected() {
        let list = list();
        for base in REQUIRED {
            assert!(list.is_protected(&p(base)), "{base}");
            assert!(list.is_protected(&p(base).join("child")), "{base}");
        }
        // Covered by a broader entry rather than listed on their own.
        for covered in ["/private/var", "/Library/Keychains", "/private/var/folders"] {
            assert!(list.is_protected(Path::new(covered)), "{covered}");
        }
    }

    // FR-007: a home spelling that folding does not map to itself (dotted
    // capital I) still matches literally and in other cases below it.
    #[test]
    fn literal_home_spelling_is_matched() {
        let home = "/Users/\u{130}stanbul";
        let list = list_for(home);
        assert!(list.is_protected(&Path::new(home).join(".ssh")));
        assert!(list.is_protected(&Path::new(home).join(".SSH/config")));
    }

    // FR-007
    #[test]
    fn matching_is_by_whole_components() {
        let list = list();
        for free in [
            "~/.sshx",
            "~/.ssh-old",
            "~/Documentsx",
            "/Systemx",
            "/usrlocal",
            "~/Library/Caches/com.example",
            "~/Library/Logs/x.log",
            "~/Library/MailData",
            "/Applicationsx",
            "/Volumesx",
            "~/Library/CloudStorageOld",
            "~/.config/other",
        ] {
            assert!(!list.is_protected(&p(free)), "{free}");
        }
    }

    // FR-007
    #[test]
    fn parent_of_protected_is_not_candidate() {
        let list = list();
        for parent in [
            "/",
            "/Users",
            HOME,
            "~/Library",
            "~/Pictures",
            "~/.config",
            "~/Library/Caches",
        ] {
            let parent = p(parent);
            assert!(list.contains_protected(&parent), "{}", parent.display());
            assert!(!list.is_protected(&parent), "{}", parent.display());
        }
        assert!(list.contains_protected(&p("/USERS/tester/LIBRARY")));
        assert!(!list.contains_protected(&p("~/Library/Caches/com.example")));
        assert!(!list.contains_protected(&p("~/Projects/node_modules")));
    }

    // FR-007: the M1 rules scan these, so they must stay unprotected.
    #[test]
    fn rule_roots_are_not_protected() {
        let list = list();
        for free in [
            "~/Library/Caches",
            "~/Library/Logs",
            "~/Library/Developer/Xcode/DerivedData",
            "~/Library/Developer/Xcode/DerivedData/App-abc",
        ] {
            assert!(!list.is_protected(&p(free)), "{free}");
            if free != "~/Library/Caches" {
                assert!(!list.contains_protected(&p(free)), "{free}");
            }
        }
    }

    // FR-007
    #[test]
    fn trailing_slash_does_not_change_the_answer() {
        let list = list();
        assert!(list.is_protected(&p("~/.ssh/")));
        assert!(list.contains_protected(Path::new("/Users/")));
        assert!(!list.is_protected(Path::new("/Users/")));
    }

    // FR-007
    #[test]
    fn home_equal_to_users_protects_below_but_not_itself() {
        let list = list_for("/Users");
        assert!(list.contains_protected(Path::new("/Users")));
        assert!(!list.is_protected(Path::new("/Users")));
        assert!(list.is_protected(Path::new("/Users/.ssh")));
    }

    fn literals(text: &str) -> Result<Vec<PathBuf>, ProtectError> {
        parse_list(text, Path::new(HOME)).map(|v| v.into_iter().map(|p| p.literal).collect())
    }

    // FR-007
    #[test]
    fn builtin_entries_are_absolute_and_unique() {
        let entries = match literals(BUILTIN) {
            Ok(e) => e,
            Err(e) => panic!("builtin list is invalid: {e}"),
        };
        assert!(entries.iter().all(|e| e.is_absolute()));
        let mut normalized: Vec<_> = entries.iter().map(|e| normalize(e)).collect();
        normalized.sort();
        normalized.dedup();
        assert_eq!(normalized.len(), entries.len());
        for base in REQUIRED {
            assert!(entries.contains(&p(base)), "{base} missing from the list");
        }
    }

    // FR-007
    #[test]
    fn parse_skips_comments_and_blank_lines() {
        assert_eq!(
            literals("# c\n\n  /System  \n~/.ssh\n"),
            Ok(vec![PathBuf::from("/System"), p("~/.ssh")])
        );
    }

    // FR-007
    #[test]
    fn parse_rejects_invalid_entries() {
        for bad in [
            "System",
            "~",
            "~/",
            "~user/x",
            "./x",
            "/a/../b",
            "~/a/../../etc",
            "/a\n/A",
            "~/.SSH\n~/.ssh",
        ] {
            assert!(literals(bad).is_err(), "{bad:?}");
        }
    }

    // FR-007
    #[test]
    fn residual_dot_components_fail_closed() {
        let list = list();
        for odd in [
            "~/Library/Caches/../../.ssh",
            "~/Library/Caches/..",
            "./x",
            "x/y",
            "",
        ] {
            let path = p(odd);
            assert!(list.is_protected(&path), "{odd}");
            assert!(list.contains_protected(&path), "{odd}");
        }
    }

    // FR-007
    #[cfg(unix)]
    #[test]
    fn non_utf8_component_fails_closed() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let list = list();
        let path = p("~/Library/Caches").join(OsStr::from_bytes(b"\xffx"));
        assert!(list.is_protected(&path));
        assert!(list.contains_protected(&path));
    }

    // FR-007: the platform accepts these homes; the protection list must not.
    #[test]
    fn home_inside_system_locations_is_protected() {
        for home in [
            "/System",
            "/usr",
            "/private/var",
            "/private/var/root",
            "/usr/local/u",
        ] {
            let list = list_for(home);
            let home = Path::new(home);
            assert!(list.is_protected(home), "{}", home.display());
            assert!(list.is_protected(&home.join("Library/Caches/x")));
        }
    }

    // FR-007
    #[test]
    fn unresolvable_home_is_an_error() {
        let err = ProtectList::builtin(&HomeAt(Err(PlatformError::HomeMissing)));
        assert_eq!(
            err.map(|_| ()),
            Err(ProtectError::Platform(PlatformError::HomeMissing))
        );
    }

    fn dir(dev: u64, ino: u64) -> Metadata {
        Metadata {
            is_dir: true,
            is_symlink: false,
            dev,
            ino,
            nlink: 2,
            blocks: 0,
            len: 0,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    /// `~/.ssh` also reachable as `/Users/Shared/Alias`, as a firmlink or a
    /// hard-linked directory would make it.
    fn aliased_fs() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/", dir(1, 2))
            .insert("/Users", dir(1, 3))
            .insert(HOME, dir(1, 4))
            .insert(p("~/.ssh"), dir(1, 50))
            .insert("/Users/Shared", dir(1, 5))
            .insert("/Users/Shared/Alias", dir(1, 50))
            .insert("/Users/Shared/Alias/keys", dir(1, 51))
            .insert("/Users/Shared/Other", dir(1, 60))
            .insert("/Users/Shared/Other/f", dir(1, 61));
        fs
    }

    // FR-007
    #[test]
    fn ancestor_with_protected_identity_is_protected() {
        let fs = aliased_fs();
        let list = list().with_identities(&fs);
        let alias = Path::new("/Users/Shared/Alias/keys");
        assert!(!list.is_protected(alias), "name check alone misses it");
        assert!(list.is_protected_on(&fs, alias));
        assert!(list.is_protected_on(&fs, Path::new("/Users/Shared/Alias")));
        assert!(!list.is_protected_on(&fs, Path::new("/Users/Shared/Other/f")));
    }

    // FR-007
    #[test]
    fn identity_check_still_applies_names() {
        let fs = aliased_fs();
        let list = list().with_identities(&fs);
        assert!(list.is_protected_on(&fs, &p("~/.SSH/config")));
    }

    // FR-007
    #[test]
    fn unreadable_ancestor_fails_closed() {
        let mut fs = aliased_fs();
        fs.fail_with("/Users/Shared/Other", io::ErrorKind::PermissionDenied);
        let list = list().with_identities(&fs);
        assert!(list.is_protected_on(&fs, Path::new("/Users/Shared/Other/f")));
    }

    // FR-007: the walker checks each entry with the metadata it already has,
    // since its ancestors were checked on the way down.
    #[test]
    fn entry_check_uses_name_and_given_identity() {
        let fs = aliased_fs();
        let list = list().with_identities(&fs);
        let alias = Path::new("/Users/Shared/Alias");
        let other = Path::new("/Users/Shared/Other");
        let meta = |ino| match fs.symlink_metadata(if ino == 50 { alias } else { other }) {
            Ok(m) => m,
            Err(e) => panic!("{e}"),
        };
        assert!(list.is_protected_entry(alias, &meta(50)));
        assert!(!list.is_protected_entry(other, &meta(60)));
        assert!(list.is_protected_entry(&p("~/.ssh"), &meta(60)));
    }
}

#[cfg(test)]
mod caches_tests {
    use super::*;
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{ScanReport, SkipReason};
    use crate::planner::{scan, ResolvedRoots, ScanContext};
    use crate::rule::RuleContext;
    use crate::rules;
    use rain_platform::Os;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, SystemTime};
    use unicode_normalization::UnicodeNormalization;

    const HOME: &str = "/Users/Tester";
    const CACHES: &str = "/Users/Tester/Library/Caches";
    const NAMES: [&str; 3] = ["CloudKit", "com.apple.bird", "docker-secrets-engine"];

    struct HomeAt(PathBuf);

    impl Platform for HomeAt {
        fn resolve(&self, _: Root) -> Result<PathBuf, PlatformError> {
            Ok(self.0.clone())
        }
        fn is_root_user(&self) -> bool {
            false
        }
        fn os(&self) -> Os {
            Os::Macos
        }
    }

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

    fn scan_caches(fs: &dyn Fs, home: &Path) -> ScanReport {
        let protect = match ProtectList::builtin(&HomeAt(home.to_path_buf())) {
            Ok(list) => list.with_identities(fs),
            Err(e) => panic!("builtin failed: {e}"),
        };
        let library = home.join("Library");
        let roots = ResolvedRoots {
            home: home.to_path_buf(),
            caches: library.join("Caches"),
            logs: library.join("Logs"),
        };
        let ctx = ScanContext {
            fs,
            protect: &protect,
            roots: &roots,
            rule_ctx: RuleContext {
                min_age_days: 0,
                user_paths: Vec::new(),
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(86_400),
            },
            threads: Some(1),
        };
        let selected = match rules::select(&["sys.user-caches"]) {
            Ok(selected) => selected,
            Err(e) => panic!("select failed: {e}"),
        };
        match scan(&selected, &ctx, &AtomicBool::new(false)) {
            Ok(report) => report,
            Err(e) => panic!("scan failed: {e}"),
        }
    }

    fn variants(name: &str) -> Vec<String> {
        let mut out = vec![
            name.to_string(),
            name.to_uppercase(),
            name.to_lowercase(),
            name.nfd().collect(),
            name.nfc().collect(),
        ];
        out.sort();
        out.dedup();
        out
    }

    fn assert_skipped(name: &str) {
        let caches = Path::new(CACHES);
        for spelling in variants(name) {
            let target = caches.join(&spelling);
            let mut fs = FakeFs::new();
            fs.insert("/Users", meta(true, 100, 0))
                .insert(HOME, meta(true, 101, 0))
                .insert("/Users/Tester/Library", meta(true, 102, 0))
                .insert(CACHES, meta(true, 103, 0))
                .insert(&target, meta(true, 200, 0))
                .insert(target.join("secret.db"), meta(false, 201, 64))
                .insert(caches.join("free"), meta(false, 300, 4));
            let report = scan_caches(&fs, Path::new(HOME));

            let paths: Vec<&Path> = report.items.iter().map(|i| i.path.as_path()).collect();
            assert_eq!(paths, vec![caches.join("free").as_path()], "{spelling}");
            assert_eq!(report.total_bytes, 4 * 512, "{spelling}");
            assert!(
                report
                    .skipped
                    .iter()
                    .any(|s| s.path == target && s.reason == SkipReason::Protected),
                "{spelling} not skipped as protected"
            );
        }
    }

    // FR-043
    #[test]
    fn user_caches_skips_cloudkit() {
        assert_skipped("CloudKit");
    }

    // FR-043
    #[test]
    fn user_caches_skips_com_apple_bird() {
        assert_skipped("com.apple.bird");
    }

    // FR-043
    #[test]
    fn user_caches_skips_docker_secrets_engine() {
        assert_skipped("docker-secrets-engine");
    }

    // FR-043
    #[test]
    fn decomposed_accented_spelling_matches_composed_entry() {
        let list = match ProtectList::builtin(&HomeAt(PathBuf::from(HOME))) {
            Ok(list) => list,
            Err(e) => panic!("builtin failed: {e}"),
        };
        for name in NAMES {
            for spelling in variants(name) {
                let path = Path::new(CACHES).join(&spelling);
                assert!(list.is_protected(&path), "{spelling}");
                assert!(list.is_protected(&path.join("child")), "{spelling}");
            }
        }
        let nfd_home: String = "/Users/Tést".nfd().collect();
        let list = match ProtectList::builtin(&HomeAt(PathBuf::from("/Users/Tést"))) {
            Ok(list) => list,
            Err(e) => panic!("builtin failed: {e}"),
        };
        for name in NAMES {
            let path = Path::new(&nfd_home).join("Library/Caches").join(name);
            assert!(list.is_protected(&path), "{name}");
        }
    }
}
