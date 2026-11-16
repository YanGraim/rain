//! Renders a finished scan report as a table or as JSON (FR-010, FR-014).
//!
//! Pure functions: no I/O, so the caller decides where the text goes.

use std::io::ErrorKind;

use rain_core::messages::{Catalog, MessageKey};
use rain_core::model::{
    Category, ExcludedReason, ItemId, ItemSource, Risk, RuleId, ScanReport, SkipReason, ToolStatus,
    Unavailable,
};
use rain_core::rule::RuleKind;
use rain_core::rules;
use rain_core::size::format_decimal;
use rain_core::tools::{ToolError, ToolId};
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
    for item in &report.tool_items {
        rows.push([
            item.rule.as_str().to_owned(),
            // The label comes from the tool: untrusted (FR-010).
            escape_for_terminal(&item.label),
            format_decimal(item.reported_bytes),
        ]);
    }
    rows.push([
        catalog.get(MessageKey::TableTotal).to_owned(),
        String::new(),
        format_decimal(report.total_bytes),
    ]);
    if !report.tool_items.is_empty() {
        rows.push([
            catalog.get(MessageKey::ReportToolTotal).to_owned(),
            String::new(),
            format_decimal(report.tool_total_bytes),
        ]);
    }

    let widths = column_widths(&rows);
    let mut out = String::new();
    for row in &rows {
        push_row(&mut out, row, &widths);
    }
    if !report.tool_items.is_empty() {
        out.push_str(catalog.get(MessageKey::ReportToolTotalNote));
        out.push('\n');
    }
    for line in unavailable_lines(report, catalog) {
        out.push_str(&line);
        out.push('\n');
    }
    push_unmanaged(&mut out, report, catalog);
    push_excluded(&mut out, report, catalog);
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

/// FR-004: the user data section: label, path and size, never selectable and
/// never part of the total above.
fn push_unmanaged(out: &mut String, report: &ScanReport, catalog: &Catalog) {
    if report.unmanaged.is_empty() {
        return;
    }
    out.push('\n');
    out.push_str(catalog.get(MessageKey::ReportUnmanaged));
    out.push('\n');
    out.push_str(catalog.get(MessageKey::ReportUnmanagedNote));
    out.push('\n');
    let rows: Vec<[String; 3]> = report
        .unmanaged
        .iter()
        .map(|u| {
            let label = catalog
                .text(&format!("userdata.{}", u.id))
                .unwrap_or(u.id)
                .to_owned();
            [
                label,
                escape_for_terminal(&u.path.to_string_lossy()),
                format_decimal(u.allocated_bytes),
            ]
        })
        .collect();
    let widths = column_widths(&rows);
    for row in &rows {
        push_row(out, row, &widths);
    }
}

/// #79: how many items each rule left to a more specific one. A count per
/// rule, in rule order; nothing when there is nothing to say.
fn push_excluded(out: &mut String, report: &ScanReport, catalog: &Catalog) {
    let mut per_rule: std::collections::BTreeMap<RuleId, u64> = std::collections::BTreeMap::new();
    for e in &report.excluded {
        *per_rule.entry(e.rule).or_insert(0) += 1;
    }
    if per_rule.is_empty() {
        return;
    }
    out.push('\n');
    for (rule, count) in per_rule {
        let line = catalog
            .get_plural(MessageKey::ReportExcluded, count)
            .replace("{rule}", rule.as_str())
            .replace("{count}", &count.to_string());
        out.push_str(&line);
        out.push('\n');
    }
}

/// FR-022: one line per distinct (tool, reason); several rules share a tool.
fn unavailable_lines(report: &ScanReport, catalog: &Catalog) -> Vec<String> {
    let mut lines: Vec<String> = report
        .providers
        .iter()
        .filter_map(|p| match p.status {
            ToolStatus::Ok => None,
            ToolStatus::Unavailable(why) => Some(
                catalog
                    .get(unavailable_key(why))
                    .replace("{tool}", tool_name(p.rule)),
            ),
        })
        .collect();
    lines.sort();
    lines.dedup();
    lines
}

fn unavailable_key(why: Unavailable) -> MessageKey {
    match why {
        Unavailable::Failed => MessageKey::ProviderUnavailableFailed,
        Unavailable::Parse => MessageKey::ProviderUnavailableParse,
        Unavailable::Tool(e) => match e {
            ToolError::NotInstalled => MessageKey::ProviderUnavailableNotInstalled,
            ToolError::NotRunning => MessageKey::ProviderUnavailableNotRunning,
            ToolError::Timeout => MessageKey::ProviderUnavailableTimeout,
            ToolError::Cancelled => MessageKey::ProviderUnavailableCancelled,
            ToolError::OutputTooLarge => MessageKey::ProviderUnavailableOutputTooLarge,
            ToolError::Denied => MessageKey::ProviderUnavailableDenied,
            ToolError::Io(_) => MessageKey::ProviderUnavailableIo,
        },
    }
}

/// Product names, not translated.
fn tool_name(rule: RuleId) -> &'static str {
    let tool = rules::builtin()
        .iter()
        .find(|r| r.meta().id == rule)
        .and_then(|r| match r.kind() {
            RuleKind::Provider(p) => Some(p.probe().tool),
            RuleKind::Files(_) => None,
        });
    match tool {
        Some(ToolId::Docker) => "Docker",
        Some(ToolId::Podman) => "Podman",
        Some(ToolId::Brew) => "Homebrew",
        Some(ToolId::Ollama) => "Ollama",
        Some(ToolId::Xcrun) => "Xcode",
        None => rule.as_str(),
    }
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
                "name_key": r.name_key,
                "consequence_key": r.consequence_key,
                "default_selected": r.default_selected,
                "requires_app_closed": r.requires_app_closed,
                "source": source_str(r.source),
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
    // FR-004: additive, no item id; `key` names the user data entry.
    let unmanaged: Vec<Value> = report
        .unmanaged
        .iter()
        .map(|u| {
            json!({
                "key": u.id,
                "path": u.path.to_string_lossy(),
                "allocated_bytes": u.allocated_bytes,
                "file_count": u.file_count,
            })
        })
        .collect();
    // FR-021: what a tool reported, with its own figures and no file path; the
    // bytes are the tool's, so they are in `tool_total_bytes` and never in
    // `total_bytes`. The label is untrusted text; JSON escapes it.
    let tool_items: Vec<Value> = report
        .tool_items
        .iter()
        .map(|t| {
            json!({
                "id": item_id_str(t.id),
                "rule": t.rule.as_str(),
                "key": t.key,
                "label": t.label,
                "reported_bytes": t.reported_bytes,
            })
        })
        .collect();
    // FR-022: `ok`, or why the tool gave nothing.
    let providers: Vec<Value> = report
        .providers
        .iter()
        .map(|p| {
            json!({
                "rule": p.rule.as_str(),
                "status": tool_status_str(p.status),
            })
        })
        .collect();
    // #79: what a rule left out because another one keeps it. No item id, and
    // in no total.
    let excluded: Vec<Value> = report
        .excluded
        .iter()
        .map(|e| {
            json!({
                "rule": e.rule.as_str(),
                "path": e.path.to_string_lossy(),
                "kept_by": e.kept_by.as_str(),
                "reason": excluded_reason_str(e.reason),
            })
        })
        .collect();
    let doc = json!({
        "schema_version": report.schema_version,
        "rules": rules,
        "items": items,
        "skipped": skipped,
        "total_bytes": report.total_bytes,
        "unmanaged": unmanaged,
        "tool_items": tool_items,
        "tool_total_bytes": report.tool_total_bytes,
        "providers": providers,
        "excluded": excluded,
    });
    let mut out = serde_json::to_string_pretty(&doc)?;
    out.push('\n');
    Ok(out)
}

// Hex string: JSON consumers in JavaScript lose precision above 2^53.
fn item_id_str(id: ItemId) -> String {
    format!("{:016x}", id.0)
}

fn excluded_reason_str(r: ExcludedReason) -> &'static str {
    match r {
        ExcludedReason::SamePath => "same-path",
        ExcludedReason::InsideItem => "inside-item",
        ExcludedReason::SharedHardlink => "shared-hardlink",
    }
}

fn source_str(s: ItemSource) -> &'static str {
    match s {
        ItemSource::Files => "fs",
        ItemSource::Tool => "tool",
    }
}

fn tool_status_str(s: ToolStatus) -> String {
    match s {
        ToolStatus::Ok => "ok".to_owned(),
        ToolStatus::Unavailable(Unavailable::Failed) => "failed".to_owned(),
        ToolStatus::Unavailable(Unavailable::Parse) => "parse".to_owned(),
        ToolStatus::Unavailable(Unavailable::Tool(e)) => match e {
            ToolError::NotInstalled => "not-installed".to_owned(),
            ToolError::NotRunning => "not-running".to_owned(),
            ToolError::Timeout => "timeout".to_owned(),
            ToolError::Cancelled => "cancelled".to_owned(),
            ToolError::OutputTooLarge => "output-too-large".to_owned(),
            ToolError::Denied => "denied".to_owned(),
            ToolError::Io(kind) => format!("io:{}", io_kind_str(kind)),
        },
    }
}

fn category_str(c: Category) -> &'static str {
    match c {
        Category::SystemCaches => "system-caches",
        Category::Logs => "logs",
        Category::DevArtifacts => "dev-artifacts",
        Category::PackageManagers => "package-managers",
        Category::Browsers => "browsers",
        Category::AiTools => "ai-tools",
        Category::AiModels => "ai-models",
        Category::Containers => "containers",
        Category::AppleDev => "apple-dev",
        Category::Projects => "projects",
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
        SkipReason::UserData => "user-data",
        SkipReason::Symlink => "symlink",
        SkipReason::OtherVolume => "other-volume",
        SkipReason::NotFound => "not-found",
        SkipReason::InvalidRoot => "invalid-root",
        SkipReason::OutsideRoot => "outside-root",
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
        Category, Excluded, ExcludedReason, ItemId, ItemSource, ProviderStatus, Risk, RuleId,
        RuleTotal, ScanItem, SkipReason, Skipped, ToolItem, ToolStatus, Unavailable, Unmanaged,
        SCHEMA_VERSION,
    };
    use std::io::ErrorKind;
    use std::path::PathBuf;

    const CACHES: RuleId = RuleId::new("sys.user-caches");
    const LOGS: RuleId = RuleId::new("sys.logs");

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
                    name_key: "rule.sys.user-caches",
                    consequence_key: "rule.sys.user-caches.consequence",
                    default_selected: true,
                    requires_app_closed: None,
                    source: ItemSource::Files,
                },
                RuleTotal {
                    rule: LOGS,
                    category: Category::Logs,
                    risk: Risk::Low,
                    allocated_bytes: 0,
                    items: 0,
                    name_key: "rule.sys.logs",
                    consequence_key: "rule.sys.logs.consequence",
                    default_selected: true,
                    requires_app_closed: None,
                    source: ItemSource::Files,
                },
            ],
            items,
            skipped,
            total_bytes: 1_200_004_096,
            tool_items: Vec::new(),
            providers: Vec::new(),
            tool_total_bytes: 0,
            unmanaged: Vec::new(),
            excluded: Vec::new(),
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

    // Labels come from the tool and are untrusted.
    #[test]
    fn label_from_tool_is_escaped() {
        let mut r = report(vec![]);
        r.tool_items = vec![rain_core::model::ToolItem {
            id: ItemId::of_key(RuleId::new("containers.dangling-images"), "k"),
            rule: RuleId::new("containers.dangling-images"),
            key: "k".into(),
            label: "img\x1b]52;c;cHduZWQ=\x07\u{202e}x".into(),
            reported_bytes: 5,
            paths: Vec::new(),
        }];
        r.tool_total_bytes = 5;
        let out = render_table(&r, &en());
        for bad in ['\x1b', '\x07', '\u{202e}'] {
            assert!(!out.contains(bad), "{out:?}");
        }
        assert!(out.contains("img\\x1b]52"), "{out}");
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

    // FR-004: user data skips have their own stable JSON reason.
    #[test]
    fn user_data_reason_is_user_data() {
        assert_eq!(reason_str(SkipReason::UserData), "user-data");
        // The JSON keeps its shape: same fields, only the value is new.
        let v = json(&report(vec![skipped(
            "/Users/u/.codeium",
            SkipReason::UserData,
        )]));
        let entry = &v["skipped"][0];
        assert_eq!(entry["reason"], "user-data");
        assert_eq!(entry["path"], "/Users/u/.codeium");
        assert_eq!(entry.as_object().unwrap().len(), 2);
    }

    fn with_unmanaged() -> ScanReport {
        let mut r = report(Vec::new());
        r.unmanaged = vec![
            Unmanaged {
                id: "claude-code.history",
                path: PathBuf::from("/Users/u/.claude/projects"),
                allocated_bytes: 2_500_000_000,
                file_count: 7,
            },
            Unmanaged {
                id: "codex.sessions",
                path: PathBuf::from("/Users/u/.codex/sessions"),
                allocated_bytes: 4_096,
                file_count: 1,
            },
        ];
        r
    }

    // FR-004: the table shows the user data apart, with its note, in every
    // language; the total row is the cleanable total and is unchanged.
    #[test]
    fn table_shows_unmanaged_in_all_locales() {
        for locale in [Locale::En, Locale::Es, Locale::PtBr] {
            let catalog = Catalog::for_locale(locale).unwrap();
            let out = render_table(&with_unmanaged(), &catalog);
            for key in [
                "report.unmanaged",
                "report.unmanaged-note",
                "userdata.claude-code.history",
                "userdata.codex.sessions",
            ] {
                let text = catalog.text(key).unwrap();
                assert!(
                    out.contains(text),
                    "{}: {key} missing in\n{out}",
                    locale.tag()
                );
            }
            assert!(out.contains("/Users/u/.claude/projects"), "{out}");
            // The cleanable total is the one of the items only.
            let total = catalog.get(MessageKey::TableTotal);
            let line = out.lines().find(|l| l.starts_with(total)).unwrap();
            assert!(line.contains(&format_decimal(1_200_004_096)), "{line}");
        }
    }

    // FR-004: without user data the table has no such section.
    #[test]
    fn table_without_unmanaged_has_no_section() {
        let out = render_table(&report(Vec::new()), &en());
        assert!(!out.contains(en().get(MessageKey::ReportUnmanaged)));
    }

    // FR-004, FR-010: JSON gets an additive top level `unmanaged` list with
    // raw bytes, and nothing there can be taken for an item id.
    #[test]
    fn json_has_unmanaged_without_item_id() {
        let v = json(&with_unmanaged());
        let list = v["unmanaged"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["key"], "claude-code.history");
        assert_eq!(list[0]["path"], "/Users/u/.claude/projects");
        assert_eq!(list[0]["allocated_bytes"], 2_500_000_000u64);
        assert_eq!(list[0]["file_count"], 7);
        assert!(list[0].get("id").is_none());
        assert_eq!(list[0].as_object().unwrap().len(), 4);
        // Existing fields and version are untouched.
        assert_eq!(v["schema_version"], 2);
        assert_eq!(v["total_bytes"], 1_200_004_096u64);
        assert_eq!(
            json(&report(Vec::new()))["unmanaged"],
            serde_json::json!([])
        );
    }

    // --- #82: schema version 2 ------------------------------------------------

    const DOCKER_DF: RuleId = RuleId::new("containers.build-cache");

    /// File items, tool items (one with a hostile label), providers in several
    /// states and unmanaged data: everything the v2 document carries.
    fn v2_report() -> ScanReport {
        let mut r = with_unmanaged();
        r.rules.push(RuleTotal {
            rule: DOCKER_DF,
            category: Category::Containers,
            risk: Risk::Medium,
            allocated_bytes: 0,
            items: 2,
            name_key: "rule.containers.build-cache",
            consequence_key: "rule.containers.build-cache.consequence",
            default_selected: false,
            requires_app_closed: Some("com.docker.docker"),
            source: ItemSource::Tool,
        });
        let tool = |key: &str, label: &str, bytes: u64| ToolItem {
            id: ItemId::of_key(DOCKER_DF, key),
            rule: DOCKER_DF,
            key: key.to_owned(),
            label: label.to_owned(),
            reported_bytes: bytes,
            paths: vec![PathBuf::from("/Users/u/never/in/json")],
        };
        r.tool_items = vec![
            tool("cache", "Build cache", 2_000_000_000),
            tool("old", "img\x1b]52;c;x\x07\u{202e}", 5),
        ];
        r.tool_total_bytes = 2_000_000_005;
        r.providers = vec![
            ProviderStatus {
                rule: DOCKER_DF,
                status: ToolStatus::Ok,
            },
            ProviderStatus {
                rule: RuleId::new("containers.volumes"),
                status: ToolStatus::Unavailable(Unavailable::Tool(
                    rain_core::tools::ToolError::Timeout,
                )),
            },
            ProviderStatus {
                rule: RuleId::new("containers.stopped"),
                status: ToolStatus::Unavailable(Unavailable::Failed),
            },
            ProviderStatus {
                rule: RuleId::new("containers.unused-images"),
                status: ToolStatus::Unavailable(Unavailable::Parse),
            },
        ];
        r
    }

    // FR-001, FR-004, FR-021: the document of the whole report, as the UI will
    // read it. Reviewed by hand: new fields are additive.
    #[test]
    fn json_v2_snapshot() {
        insta::assert_snapshot!(render_json(&v2_report()).unwrap());
    }

    #[test]
    fn schema_version_is_2() {
        assert_eq!(SCHEMA_VERSION, 2);
        assert_eq!(json(&v2_report())["schema_version"], 2);
    }

    // FR-010: the same report gives exactly the same bytes.
    #[test]
    fn two_runs_identical_json_v2() {
        assert_eq!(
            render_json(&v2_report()).unwrap(),
            render_json(&v2_report()).unwrap()
        );
    }

    fn is_hex16(s: &str) -> bool {
        s.len() == 16
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    // Item ids, for files and for tools, are lower case hex of 16 digits (a
    // `u64` is not safe in JavaScript).
    #[test]
    fn item_ids_are_hex16() {
        let v = json(&v2_report());
        for list in ["items", "tool_items"] {
            let entries = v[list].as_array().unwrap();
            assert!(!entries.is_empty(), "{list}");
            for e in entries {
                let id = e["id"].as_str().unwrap();
                assert!(is_hex16(id), "{list}: {id}");
            }
        }
    }

    // FR-004: user data has no id, so there is nothing to select.
    #[test]
    fn unmanaged_has_no_id() {
        let v = json(&v2_report());
        let list = v["unmanaged"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        for e in list {
            let keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(keys, ["allocated_bytes", "file_count", "key", "path"]);
        }
    }

    // Every field of the v1 document is still there with the same type.
    #[test]
    fn v2_keeps_every_v1_field_with_the_same_type() {
        use serde_json::Value;
        let v = json(&v2_report());
        let kind = |x: &Value| match x {
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Bool(_) => "bool",
            Value::Null => "null",
            Value::Object(_) => "object",
        };
        let top = [
            ("schema_version", "number"),
            ("rules", "array"),
            ("items", "array"),
            ("skipped", "array"),
            ("total_bytes", "number"),
            ("unmanaged", "array"),
        ];
        for (name, ty) in top {
            assert_eq!(kind(&v[name]), ty, "top level {name}");
        }
        let nested: [(&str, &[(&str, &str)]); 4] = [
            (
                "rules",
                &[
                    ("id", "string"),
                    ("category", "string"),
                    ("risk", "string"),
                    ("allocated_bytes", "number"),
                    ("items", "number"),
                ],
            ),
            (
                "items",
                &[
                    ("id", "string"),
                    ("rule", "string"),
                    ("path", "string"),
                    ("allocated_bytes", "number"),
                    ("file_count", "number"),
                ],
            ),
            ("skipped", &[("path", "string"), ("reason", "string")]),
            (
                "unmanaged",
                &[
                    ("key", "string"),
                    ("path", "string"),
                    ("allocated_bytes", "number"),
                    ("file_count", "number"),
                ],
            ),
        ];
        for (list, fields) in nested {
            for entry in v[list].as_array().unwrap() {
                for (name, ty) in fields {
                    assert_eq!(kind(&entry[*name]), *ty, "{list}[].{name}");
                }
            }
        }
    }

    // FR-001, FR-002, FR-015: each rule says how to show it and what it needs.
    #[test]
    fn rules_carry_their_metadata() {
        let v = json(&v2_report());
        let rules = v["rules"].as_array().unwrap();
        let by_id = |id: &str| rules.iter().find(|r| r["id"] == id).unwrap();
        let caches = by_id("sys.user-caches");
        assert_eq!(caches["name_key"], "rule.sys.user-caches");
        assert_eq!(
            caches["consequence_key"],
            "rule.sys.user-caches.consequence"
        );
        assert_eq!(caches["default_selected"], true);
        assert!(caches["requires_app_closed"].is_null());
        assert_eq!(caches["source"], "fs");
        let docker = by_id("containers.build-cache");
        assert_eq!(docker["default_selected"], false);
        assert_eq!(docker["requires_app_closed"], "com.docker.docker");
        assert_eq!(docker["source"], "tool");
    }

    // Tool items carry the tool's figures and no file path,
    // and their bytes are in `tool_total_bytes`, never in `total_bytes`.
    #[test]
    fn tool_items_have_no_path_and_stay_out_of_total_bytes() {
        let v = json(&v2_report());
        let items = v["tool_items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        for e in items {
            let keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(keys, ["id", "key", "label", "reported_bytes", "rule"]);
        }
        assert_eq!(items[0]["key"], "cache");
        assert_eq!(items[0]["reported_bytes"], 2_000_000_000u64);
        assert_eq!(v["tool_total_bytes"], 2_000_000_005u64);
        assert_eq!(v["total_bytes"], 1_200_004_096u64);
        let text = render_json(&v2_report()).unwrap();
        assert!(!text.contains("never/in/json"), "{text}");
    }

    // FR-022: a provider is `ok` or the reason it was unavailable, spelled as
    // the other enums (kebab-case).
    #[test]
    fn providers_use_kebab_case_statuses() {
        use rain_core::tools::ToolError;
        let mut r = v2_report();
        r.providers = [
            ToolStatus::Ok,
            ToolStatus::Unavailable(Unavailable::Failed),
            ToolStatus::Unavailable(Unavailable::Parse),
            ToolStatus::Unavailable(Unavailable::Tool(ToolError::NotInstalled)),
            ToolStatus::Unavailable(Unavailable::Tool(ToolError::NotRunning)),
            ToolStatus::Unavailable(Unavailable::Tool(ToolError::Timeout)),
            ToolStatus::Unavailable(Unavailable::Tool(ToolError::Cancelled)),
            ToolStatus::Unavailable(Unavailable::Tool(ToolError::OutputTooLarge)),
            ToolStatus::Unavailable(Unavailable::Tool(ToolError::Denied)),
            ToolStatus::Unavailable(Unavailable::Tool(ToolError::Io(ErrorKind::TimedOut))),
        ]
        .into_iter()
        .map(|status| ProviderStatus {
            rule: DOCKER_DF,
            status,
        })
        .collect();
        let v = json(&r);
        let got: Vec<&str> = v["providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["status"].as_str().unwrap())
            .collect();
        assert_eq!(
            got,
            [
                "ok",
                "failed",
                "parse",
                "not-installed",
                "not-running",
                "timeout",
                "cancelled",
                "output-too-large",
                "denied",
                "io:timed-out",
            ]
        );
        assert!(v["providers"][0].as_object().unwrap().contains_key("rule"));
    }

    // --- #79: what a more specific rule kept --------------------------------

    fn with_excluded() -> ScanReport {
        let mut r = v2_report();
        let sys = RuleId::new("sys.user-caches");
        let brew = RuleId::new("pkg.homebrew");
        let ex = |path: &str, rule: RuleId, kept_by: RuleId, reason: ExcludedReason| Excluded {
            path: PathBuf::from(path),
            rule,
            kept_by,
            reason,
        };
        r.excluded = vec![
            ex(
                "/Users/u/Library/Caches/Homebrew/a",
                sys,
                brew,
                ExcludedReason::InsideItem,
            ),
            ex(
                "/Users/u/Library/Caches/Homebrew/b",
                sys,
                brew,
                ExcludedReason::InsideItem,
            ),
            ex(
                "/Users/u/Library/Caches/x",
                sys,
                brew,
                ExcludedReason::SamePath,
            ),
            ex(
                "/Users/u/Library/Logs/k",
                LOGS,
                CACHES,
                ExcludedReason::SharedHardlink,
            ),
        ];
        r
    }

    // #79: additive `excluded` list: path, the rule that lost it, the rule
    // that kept it and the reason in kebab-case; `schema_version` stays 2.
    #[test]
    fn json_lists_excluded_items_without_ids_or_totals() {
        let v = json(&with_excluded());
        assert_eq!(v["schema_version"], 2);
        let list = v["excluded"].as_array().unwrap();
        assert_eq!(list.len(), 4);
        for e in list {
            let keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(keys, ["kept_by", "path", "reason", "rule"]);
        }
        assert_eq!(list[0]["reason"], "inside-item");
        assert_eq!(list[2]["reason"], "same-path");
        assert_eq!(list[3]["reason"], "shared-hardlink");
        assert_eq!(list[0]["kept_by"], "pkg.homebrew");
        assert_eq!(list[0]["rule"], "sys.user-caches");
        // In no total: the same as without it.
        assert_eq!(v["total_bytes"], json(&v2_report())["total_bytes"]);
        assert_eq!(v["total_bytes"], 1_200_004_096u64);
        // Every field of the earlier versions is still there.
        assert!(json(&v2_report())["excluded"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn json_v2_excluded_snapshot() {
        insta::assert_snapshot!(render_json(&with_excluded()).unwrap());
    }

    // #79: the table shows one count per rule, singular or plural, in every
    // language, and nothing when there is nothing.
    #[test]
    fn table_counts_excluded_items_per_rule_in_all_locales() {
        for locale in [Locale::En, Locale::Es, Locale::PtBr] {
            let catalog = Catalog::for_locale(locale).unwrap();
            let out = render_table(&with_excluded(), &catalog);
            let one = catalog
                .get_plural(MessageKey::ReportExcluded, 1)
                .replace("{rule}", "sys.logs")
                .replace("{count}", "1");
            let many = catalog
                .get_plural(MessageKey::ReportExcluded, 3)
                .replace("{rule}", "sys.user-caches")
                .replace("{count}", "3");
            assert!(
                out.contains(&one),
                "{}: {one:?} missing in\n{out}",
                locale.tag()
            );
            assert!(
                out.contains(&many),
                "{}: {many:?} missing in\n{out}",
                locale.tag()
            );
            // The paths are not listed in the table.
            assert!(!out.contains("Homebrew/a"), "{out}");
        }
        let out = render_table(&report(Vec::new()), &en());
        assert!(!out.contains("more specific"), "{out}");
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
