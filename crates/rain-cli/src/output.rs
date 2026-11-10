//! Renders a finished scan report as a table or as JSON (FR-010, FR-014).
//!
//! Pure functions: no I/O, so the caller decides where the text goes.

use std::io::ErrorKind;

use rain_core::messages::{Catalog, MessageKey};
use rain_core::model::{Category, ItemId, Risk, ScanReport, SkipReason};
use rain_core::size::format_decimal;
use serde_json::{json, Value};

const COLUMN_GAP: &str = "  ";

/// Human-readable table (FR-014): one row per item, then the total and,
/// if any, the number of skipped entries (FR-013).
pub fn render_table(report: &ScanReport, catalog: &Catalog) -> String {
    let header = [
        catalog.get(MessageKey::TableHeaderRule).to_owned(),
        catalog.get(MessageKey::TableHeaderPath).to_owned(),
        catalog.get(MessageKey::TableHeaderSize).to_owned(),
    ];
    let mut rows = vec![header];
    for item in &report.items {
        rows.push([
            item.rule.as_str().to_owned(),
            // Escaped before measuring so widths match what is printed.
            escape_for_terminal(&item.path.to_string_lossy()),
            format_decimal(item.allocated_bytes),
        ]);
    }
    rows.push([
        catalog.get(MessageKey::TableTotal).to_owned(),
        String::new(),
        format_decimal(report.total_bytes),
    ]);

    let widths = column_widths(&rows);
    let mut out = String::new();
    for row in &rows {
        push_row(&mut out, row, &widths);
    }
    let skipped = u64::try_from(report.skipped.len()).unwrap_or(u64::MAX);
    if skipped > 0 {
        let line = catalog
            .get_plural(MessageKey::TableSkipped, skipped)
            .replace("{count}", &skipped.to_string());
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Makes text from disk safe to print on a terminal (FR-010): C0, DEL, C1
/// and bidi/format characters are written as visible escapes instead of
/// being dropped, and `\` itself is doubled, so two different inputs never
/// print the same.
pub(crate) fn escape_for_terminal(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{00}'..='\u{1f}' | '\u{7f}' => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if is_invisible_or_control(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            _ => out.push(c),
        }
    }
    out
}

// C1 plus the Unicode categories Cf (format), Zl and Zp (line/paragraph
// separators), written by hand to avoid a Unicode-tables dependency. These
// reorder, hide or break text on a terminal (FR-010). The list follows
// Unicode 16.0; recheck it when a new Unicode version adds Cf characters.
fn is_invisible_or_control(c: char) -> bool {
    matches!(
        c,
        '\u{80}'..='\u{9f}'
            | '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

fn column_widths(rows: &[[String; 3]]) -> [usize; 3] {
    let mut widths = [0; 3];
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    widths
}

// Size is right-aligned so magnitudes line up; the rest is left-aligned.
fn push_row(out: &mut String, row: &[String; 3], widths: &[usize; 3]) {
    let [rule, path, size] = row;
    let line = format!(
        "{rule:<rw$}{COLUMN_GAP}{path:<pw$}{COLUMN_GAP}{size:>sw$}",
        rw = widths[0],
        pw = widths[1],
        sw = widths[2],
    );
    out.push_str(line.trim_end());
    out.push('\n');
}

/// JSON document (FR-010). Locale-independent; sizes are raw `u64` bytes
/// (FR-014). Object keys are sorted and the report is already sorted, so
/// the same report always gives the same bytes. JSON string escaping already
/// neutralizes control characters in paths.
pub fn render_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    let rules: Vec<Value> = report
        .rules
        .iter()
        .map(|r| {
            json!({
                "id": r.rule.as_str(),
                "category": category_str(r.category),
                "risk": risk_str(r.risk),
                "allocated_bytes": r.allocated_bytes,
                "items": r.items,
            })
        })
        .collect();
    let items: Vec<Value> = report
        .items
        .iter()
        .map(|i| {
            json!({
                "id": item_id_str(i.id),
                "rule": i.rule.as_str(),
                "path": i.path.to_string_lossy(),
                "allocated_bytes": i.allocated_bytes,
                "file_count": i.file_count,
            })
        })
        .collect();
    let skipped: Vec<Value> = report
        .skipped
        .iter()
        .map(|s| {
            json!({
                "path": s.path.to_string_lossy(),
                "reason": reason_str(s.reason),
            })
        })
        .collect();
    let doc = json!({
        "schema_version": report.schema_version,
        "rules": rules,
        "items": items,
        "skipped": skipped,
        "total_bytes": report.total_bytes,
    });
    let mut out = serde_json::to_string_pretty(&doc)?;
    out.push('\n');
    Ok(out)
}

// Hex string: JSON consumers in JavaScript lose precision above 2^53.
fn item_id_str(id: ItemId) -> String {
    format!("{:016x}", id.0)
}

fn category_str(c: Category) -> &'static str {
    match c {
        Category::SystemCaches => "system-caches",
        Category::Logs => "logs",
        Category::DevArtifacts => "dev-artifacts",
        Category::PackageManagers => "package-managers",
        Category::Browsers => "browsers",
        Category::AiTools => "ai-tools",
        Category::Containers => "containers",
    }
}

fn risk_str(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

fn reason_str(r: SkipReason) -> String {
    let fixed = match r {
        SkipReason::PermissionDenied => "permission-denied",
        SkipReason::Protected => "protected",
        SkipReason::Symlink => "symlink",
        SkipReason::OtherVolume => "other-volume",
        SkipReason::NotFound => "not-found",
        SkipReason::InvalidRoot => "invalid-root",
        SkipReason::Io(kind) => return format!("io:{}", io_kind_str(kind)),
    };
    fixed.to_owned()
}

// `ErrorKind`'s `Debug`/`Display` are not stable across Rust releases, so
// each kind is spelled out; anything unlisted becomes `other` (FR-010).
fn io_kind_str(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::NotFound => "not-found",
        ErrorKind::PermissionDenied => "permission-denied",
        ErrorKind::AlreadyExists => "already-exists",
        ErrorKind::WouldBlock => "would-block",
        ErrorKind::InvalidInput => "invalid-input",
        ErrorKind::InvalidData => "invalid-data",
        ErrorKind::TimedOut => "timed-out",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::UnexpectedEof => "unexpected-eof",
        ErrorKind::OutOfMemory => "out-of-memory",
        ErrorKind::NotADirectory => "not-a-directory",
        ErrorKind::IsADirectory => "is-a-directory",
        ErrorKind::DirectoryNotEmpty => "directory-not-empty",
        ErrorKind::ReadOnlyFilesystem => "read-only-filesystem",
        ErrorKind::StorageFull => "storage-full",
        ErrorKind::ResourceBusy => "resource-busy",
        ErrorKind::Deadlock => "deadlock",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rain_core::messages::Locale;
    use rain_core::model::{
        Category, ItemId, Risk, RuleId, RuleTotal, ScanItem, SkipReason, Skipped, SCHEMA_VERSION,
    };
    use std::io::ErrorKind;
    use std::path::PathBuf;

    const CACHES: RuleId = RuleId::new("macos.user.caches");
    const LOGS: RuleId = RuleId::new("macos.user.logs");

    fn item(rule: RuleId, path: &str, bytes: u64, files: u64) -> ScanItem {
        let path = PathBuf::from(path);
        ScanItem {
            id: ItemId::of(rule, &path),
            rule,
            path,
            allocated_bytes: bytes,
            file_count: files,
        }
    }

    fn skipped(path: &str, reason: SkipReason) -> Skipped {
        Skipped {
            path: PathBuf::from(path),
            reason,
        }
    }

    fn report(skipped: Vec<Skipped>) -> ScanReport {
        let items = vec![
            item(CACHES, "/Users/u/Library/Caches/com.a", 1_200_000_000, 3),
            item(CACHES, "/Users/u/Library/Caches/com.b", 4_096, 1),
        ];
        ScanReport {
            schema_version: SCHEMA_VERSION,
            rules: vec![
                RuleTotal {
                    rule: CACHES,
                    category: Category::SystemCaches,
                    risk: Risk::Low,
                    allocated_bytes: 1_200_004_096,
                    items: 2,
                },
                RuleTotal {
                    rule: LOGS,
                    category: Category::Logs,
                    risk: Risk::Low,
                    allocated_bytes: 0,
                    items: 0,
                },
            ],
            items,
            skipped,
            total_bytes: 1_200_004_096,
        }
    }

    fn full_report() -> ScanReport {
        report(vec![
            skipped("/Users/u/Library/Caches/a", SkipReason::PermissionDenied),
            skipped("/Users/u/Library/Caches/b", SkipReason::Protected),
            skipped("/Users/u/Library/Caches/c", SkipReason::Symlink),
            skipped("/Users/u/Library/Caches/d", SkipReason::OtherVolume),
            skipped("/Users/u/Library/Caches/e", SkipReason::NotFound),
            skipped("/Users/u/Library/Caches/f", SkipReason::InvalidRoot),
            skipped(
                "/Users/u/Library/Caches/g",
                SkipReason::Io(ErrorKind::TimedOut),
            ),
            skipped(
                "/Users/u/Library/Caches/h",
                SkipReason::Io(ErrorKind::Other),
            ),
        ])
    }

    fn hostile_report() -> ScanReport {
        let mut r = report(vec![]);
        r.items = [
            "/c/a\x1b[2Kb",
            "/c/a\rb",
            "/c/a\nb",
            "/c/\x1b]52;c;ZXZpbA==\x07x",
            "/c/\u{202e}txt.exe",
            "/c/a\\x1bb",
        ]
        .into_iter()
        .map(|p| item(CACHES, p, 1_000, 1))
        .collect();
        r.total_bytes = 6_000;
        r
    }

    // FR-010: disk names cannot inject terminal control sequences.
    #[test]
    fn table_escapes_control_characters() {
        let out = render_table(&hostile_report(), &en());
        let body = out.trim_end_matches('\n');
        assert!(!out.contains('\x1b'), "{out}");
        assert!(!out.contains('\x07'), "{out}");
        assert!(!out.contains('\r'), "{out}");
        assert!(!out.contains('\u{202e}'), "{out}");
        // header + 6 items + total: LF only as row separator.
        assert_eq!(body.split('\n').count(), 8, "{out}");
        insta::assert_snapshot!(out);
    }

    // FR-010: escaping is injective, so distinct paths print differently.
    #[test]
    fn escape_is_visible_and_injective() {
        let cases = [
            ("a\x1bb", "a\\x1bb"),
            ("a\nb", "a\\nb"),
            ("a\rb", "a\\rb"),
            ("a\tb", "a\\tb"),
            ("a\x00b", "a\\x00b"),
            ("a\x7fb", "a\\x7fb"),
            ("a\u{9b}b", "a\\u{9b}b"),
            ("a\u{200e}\u{200f}b", "a\\u{200e}\\u{200f}b"),
            (
                "\u{202a}\u{202e}\u{2066}\u{2069}",
                "\\u{202a}\\u{202e}\\u{2066}\\u{2069}",
            ),
            ("a\\x1bb", "a\\\\x1bb"),
            ("a\u{61c}b", "a\\u{61c}b"),
            ("a\u{2028}b", "a\\u{2028}b"),
            ("a\u{2029}b", "a\\u{2029}b"),
            ("a\u{feff}b", "a\\u{feff}b"),
            ("a\u{200b}b", "a\\u{200b}b"),
            ("a\u{200c}b", "a\\u{200c}b"),
            ("a\u{200d}b", "a\\u{200d}b"),
            ("a\u{2060}b", "a\\u{2060}b"),
            ("a\u{2061}b", "a\\u{2061}b"),
            ("a\u{2062}b", "a\\u{2062}b"),
            ("a\u{2063}b", "a\\u{2063}b"),
            ("a\u{2064}b", "a\\u{2064}b"),
            ("a\u{ad}b", "a\\u{ad}b"),
            ("a\u{e0041}b", "a\\u{e0041}b"),
            ("ação/日本", "ação/日本"),
        ];
        for (raw, want) in cases {
            assert_eq!(escape_for_terminal(raw), want, "{raw:?}");
        }
        assert_ne!(
            escape_for_terminal("a\x1bb"),
            escape_for_terminal("a\\x1bb")
        );
    }

    fn en() -> Catalog {
        Catalog::en().unwrap()
    }

    fn json(report: &ScanReport) -> serde_json::Value {
        serde_json::from_str(&render_json(report).unwrap()).unwrap()
    }

    // FR-010
    #[test]
    fn json_snapshot() {
        insta::assert_snapshot!(render_json(&full_report()).unwrap());
    }

    // FR-014
    #[test]
    fn table_snapshot() {
        insta::assert_snapshot!(render_table(&full_report(), &en()));
    }

    // FR-013, FR-014
    #[test]
    fn table_snapshot_pt_br() {
        let pt = Catalog::for_locale(Locale::PtBr).unwrap();
        insta::assert_snapshot!(render_table(&full_report(), &pt));
    }

    // FR-010
    #[test]
    fn json_has_schema_version() {
        assert_eq!(json(&full_report())["schema_version"], SCHEMA_VERSION);
    }

    // FR-014: bytes are raw integers, never formatted text.
    #[test]
    fn json_bytes_are_integers() {
        let v = json(&full_report());
        assert_eq!(v["total_bytes"].as_u64(), Some(1_200_004_096));
        assert_eq!(
            v["items"][0]["allocated_bytes"].as_u64(),
            Some(1_200_000_000)
        );
        assert_eq!(v["items"][0]["file_count"].as_u64(), Some(3));
        assert_eq!(
            v["rules"][0]["allocated_bytes"].as_u64(),
            Some(1_200_004_096)
        );
        assert_eq!(v["rules"][1]["items"].as_u64(), Some(0));
    }

    // FR-014: values above 2^53 keep full precision.
    #[test]
    fn json_keeps_u64_max_exact() {
        let mut r = report(vec![]);
        r.total_bytes = u64::MAX;
        assert!(render_json(&r)
            .unwrap()
            .contains("\"total_bytes\": 18446744073709551615"));
    }

    // FR-010
    #[test]
    fn two_runs_identical_json() {
        assert_eq!(
            render_json(&full_report()).unwrap(),
            render_json(&full_report()).unwrap()
        );
    }

    // FR-010: every reason, including I/O kinds, has a stable string.
    #[test]
    fn skip_reasons_are_stable_strings() {
        let v = json(&full_report());
        let reasons: Vec<&str> = v["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["reason"].as_str().unwrap())
            .collect();
        assert_eq!(
            reasons,
            [
                "permission-denied",
                "protected",
                "symlink",
                "other-volume",
                "not-found",
                "invalid-root",
                "io:timed-out",
                "io:other",
            ]
        );
    }

    // FR-013: the skipped line uses the singular form for one item.
    #[test]
    fn table_skipped_line_singular_en() {
        let r = report(vec![skipped("/x", SkipReason::Protected)]);
        let out = render_table(&r, &en());
        assert!(out.contains("1 item skipped"), "{out}");
        assert!(!out.contains("1 items skipped"), "{out}");
    }

    // FR-013
    #[test]
    fn table_skipped_line_plural_en() {
        let out = render_table(&full_report(), &en());
        assert!(out.contains("8 items skipped"), "{out}");
    }

    // FR-013
    #[test]
    fn table_without_skipped_has_no_skipped_line() {
        let out = render_table(&report(vec![]), &en());
        assert!(!out.contains("skipped"), "{out}");
    }

    // FR-014
    #[test]
    fn table_shows_decimal_sizes() {
        let out = render_table(&full_report(), &en());
        assert!(out.contains("1.2 GB"), "{out}");
        assert!(out.contains("4.1 kB"), "{out}");
    }

    // Oracle for the clean-output property, kept apart from the production
    // table on purpose: Cc comes from std (`char::is_control`), and Cf, Zl
    // and Zp are listed here from Unicode 16.0 DerivedGeneralCategory.
    const CF_ZL_ZP: &[(u32, u32)] = &[
        (0xad, 0xad),
        (0x600, 0x605),
        (0x61c, 0x61c),
        (0x6dd, 0x6dd),
        (0x70f, 0x70f),
        (0x890, 0x891),
        (0x8e2, 0x8e2),
        (0x180e, 0x180e),
        (0x200b, 0x200f),
        (0x2028, 0x2029),
        (0x202a, 0x202e),
        (0x2060, 0x2064),
        (0x2066, 0x206f),
        (0xfeff, 0xfeff),
        (0xfff9, 0xfffb),
        (0x110bd, 0x110bd),
        (0x110cd, 0x110cd),
        (0x13430, 0x1343f),
        (0x1bca0, 0x1bca3),
        (0x1d173, 0x1d17a),
        (0xe0001, 0xe0001),
        (0xe0020, 0xe007f),
    ];

    fn is_cc_cf_zl_zp(c: char) -> bool {
        let n = u32::from(c);
        c.is_control() || CF_ZL_ZP.iter().any(|&(lo, hi)| (lo..=hi).contains(&n))
    }

    // Biased toward the dangerous ranges and the escape syntax itself, so
    // collisions like a literal "\\x1b" versus ESC are actually exercised.
    fn hostile_char() -> impl proptest::strategy::Strategy<Value = char> {
        use proptest::prelude::*;
        let from_table = proptest::sample::select(CF_ZL_ZP.to_vec())
            .prop_flat_map(|(lo, hi)| lo..=hi)
            .prop_filter_map("valid char", char::from_u32);
        prop_oneof![
            3 => proptest::char::range('\u{0}', '\u{9f}'),
            3 => from_table,
            2 => proptest::sample::select(vec!['\\', 'x', 'u', '{', '}', 'n', 'r', 't', '0', '1', 'b', 'f']),
            2 => any::<char>(),
        ]
    }

    fn hostile_string() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::strategy::Strategy;
        proptest::collection::vec(hostile_char(), 0..12).prop_map(|v| v.into_iter().collect())
    }

    proptest::proptest! {
        // FR-010: two different names must never print the same.
        #[test]
        fn escape_is_injective(a in hostile_string(), b in hostile_string()) {
            proptest::prop_assume!(a != b);
            proptest::prop_assert_ne!(escape_for_terminal(&a), escape_for_terminal(&b));
        }

        // FR-010: printed text never carries a Cc, Cf, Zl or Zp character.
        #[test]
        fn escape_output_has_no_control_or_format_chars(s in hostile_string()) {
            let out = escape_for_terminal(&s);
            let bad: Vec<char> = out.chars().filter(|&c| is_cc_cf_zl_zp(c)).collect();
            proptest::prop_assert!(bad.is_empty(), "{:?} -> {:?} has {:?}", s, out, bad);
        }
    }
}
