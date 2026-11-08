//! Protection list support: path normalization.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

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
    const EQUIVALENT: &[&[&str]] = &[
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
