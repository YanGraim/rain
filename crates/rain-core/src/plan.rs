//! The cleaning plan (ADR 0006 §1): what `rain clean` would move to the
//! Trash, built from a finished scan and a selection of item ids.
//!
//! The plan only names items the report already holds. It records, for each,
//! the identity the item and each of its ancestors had when the plan was
//! made; the executor compares them with the live disk (ADR 0006 §2) and
//! trusts nothing else in it.

use crate::clock::Clock;
use crate::fs::{Fs, Metadata};
use crate::model::{fnv1a, ExcludedReason, ItemId, Risk, RuleId, ScanItem, ScanReport};
use crate::protect::ProtectList;
use crate::rules;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Version of the plan document; an unknown one is refused.
pub const PLAN_VERSION: u32 = 1;
/// How long a plan can be executed after it was made: 15 minutes.
pub const PLAN_TTL_SECS: u64 = 900;
/// How far in the future `created_at` may be before the clock is distrusted.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// What an entry is. A link is its own kind: it is never followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

/// Which entry a path named when the plan was made: `dev`, `ino` and kind,
/// and the link count only for entries that are not directories. On APFS the
/// link count of a folder is 2 plus the entries inside it, so it changes with
/// every file an app writes there and says nothing about identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
    pub kind: EntryKind,
    pub nlink: Option<u32>,
}

impl Identity {
    pub fn from_metadata(meta: &Metadata) -> Identity {
        let kind = if meta.is_symlink {
            EntryKind::Symlink
        } else if meta.is_dir {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let nlink = (kind != EntryKind::Dir).then(|| u32::try_from(meta.nlink).unwrap_or(u32::MAX));
        Identity {
            dev: meta.dev,
            ino: meta.ino,
            kind,
            nlink,
        }
    }
}

/// What the user confirmed for one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// Low risk: nothing to confirm.
    NotNeeded,
    /// Needed and not given yet (a preview); the executor refuses such a plan.
    Pending,
    /// Medium risk, confirmed.
    Confirmed,
    /// High risk, confirmed for this item on its own.
    ConfirmedHigh,
}

/// What the user chose: ids only (ADR 0002).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    pub ids: Vec<ItemId>,
    /// Ids the user confirmed (medium risk).
    pub confirmed: Vec<ItemId>,
    /// Ids the user confirmed one by one (high risk).
    pub confirmed_high: Vec<ItemId>,
}

/// Whether a missing confirmation refuses the plan or leaves it pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmations {
    /// The plan will be executed: every item that needs it must be confirmed.
    Required,
    /// A dry run: items that need a confirmation are marked pending.
    Preview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItem {
    pub id: ItemId,
    pub rule: RuleId,
    /// Canonical, valid UTF-8.
    pub path: PathBuf,
    pub risk: Risk,
    pub bytes: u64,
    pub file_count: u64,
    pub identity: Identity,
    /// From the home down to the parent of the item.
    pub ancestors: Vec<Identity>,
    /// Bundle id of the app that must be closed first.
    pub requires_app_closed: Option<String>,
    pub confirmation: Confirmation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub version: u32,
    /// Seconds since the epoch, from the injected clock.
    pub created_at: u64,
    pub expires_at: u64,
    /// FNV-1a of the report the plan came from: for tracing, not security.
    pub report_hash: u64,
    /// FNV-1a of what the user saw: `(id, rule, path, risk)` of each item. It
    /// leaves out identities, sizes, times and confirmations, so a cache that
    /// is rewritten, or a confirmation given after the preview, does not
    /// change it.
    pub plan_hash: u64,
    pub home: PathBuf,
    /// Sorted by `(rule, path)`, one per id.
    pub items: Vec<PlanItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("nothing was selected")]
    EmptySelection,
    #[error("item {0:016x} is not in the report")]
    UnknownItem(u64),
    #[error("item {0:016x} comes from a tool: tool items are read-only")]
    ToolItem(u64),
    #[error("item {0:016x} holds an item of another rule")]
    HasExcludedSubtree(u64),
    #[error("item {0:016x} is, or holds, protected data")]
    Protected(u64),
    #[error("item {0:016x} is, holds or sits inside the Trash")]
    TrashInvolved(u64),
    #[error("item {0:016x} has a path that is not valid UTF-8")]
    NonUtf8Path(u64),
    #[error("item {id:016x} needs a confirmation ({needed:?} risk)")]
    MissingConfirmation { id: u64, needed: Risk },
    #[error("item {0:016x} is gone")]
    Gone(u64),
    #[error("item {0:016x} is a link now")]
    Symlink(u64),
    #[error("item {0:016x} is not inside the home folder")]
    OutsideHome(u64),
    #[error("item {0:016x} could not be read")]
    Unreadable(u64),
    #[error("the clock is before 1970")]
    ClockBeforeEpoch,
    #[error("the plan expired")]
    Expired,
    #[error("the plan was made in the future")]
    FromTheFuture,
    #[error("malformed plan: {0}")]
    Malformed(&'static str),
}

/// What building a plan reads from the outside world.
pub struct BuildContext<'a> {
    pub fs: &'a dyn Fs,
    pub protect: &'a ProtectList,
    pub clock: &'a dyn Clock,
    /// Canonical home folder.
    pub home: &'a Path,
}

impl Plan {
    /// Builds the plan for `selection` out of a finished `report`.
    ///
    /// It refuses the whole plan if any chosen id is unknown or comes from a
    /// tool, if the item holds an item of another rule (ADR 0005), is or
    /// holds protected data, is or holds the Trash, is not inside the home,
    /// is not valid UTF-8, was replaced by a link or is gone, or needs a
    /// confirmation it was not given (unless this is a preview).
    pub fn build(
        report: &ScanReport,
        selection: &Selection,
        mode: Confirmations,
        ctx: &BuildContext,
    ) -> Result<Plan, PlanError> {
        let created_at = ctx
            .clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| PlanError::ClockBeforeEpoch)?
            .as_secs();
        let wanted: BTreeSet<ItemId> = selection.ids.iter().copied().collect();
        if wanted.is_empty() {
            return Err(PlanError::EmptySelection);
        }
        let by_id: HashMap<ItemId, &ScanItem> = report.items.iter().map(|i| (i.id, i)).collect();
        let trash = ctx.home.join(".Trash");
        let mut items = Vec::with_capacity(wanted.len());
        for id in &wanted {
            let Some(scan) = by_id.get(id) else {
                return Err(if report.tool_items.iter().any(|t| t.id == *id) {
                    PlanError::ToolItem(id.0)
                } else {
                    PlanError::UnknownItem(id.0)
                });
            };
            items.push(plan_item(scan, report, selection, mode, ctx, &trash)?);
        }
        items.sort_by(|a, b| (a.rule, &a.path).cmp(&(b.rule, &b.path)));
        Ok(Plan {
            version: PLAN_VERSION,
            created_at,
            expires_at: created_at.saturating_add(PLAN_TTL_SECS),
            report_hash: report_hash(report),
            plan_hash: plan_hash(&items),
            home: ctx.home.to_path_buf(),
            items,
        })
    }

    /// The executor refuses a plan that expired or that claims to come from
    /// the future (a clock set back).
    pub fn check_fresh(&self, now: SystemTime) -> Result<(), PlanError> {
        let now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| PlanError::ClockBeforeEpoch)?
            .as_secs();
        if now > self.expires_at {
            return Err(PlanError::Expired);
        }
        if self.created_at > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(PlanError::FromTheFuture);
        }
        Ok(())
    }

    /// The plan as a JSON document. Ids and hashes are 16 hex digits.
    pub fn to_json(&self) -> String {
        let items: Vec<Value> = self.items.iter().map(item_json).collect();
        let doc = json!({
            "version": self.version,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "report_hash": hex(self.report_hash),
            "plan_hash": hex(self.plan_hash),
            "home": self.home.to_str().unwrap_or_default(),
            "items": items,
        });
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    }

    /// Reads a plan back, strictly: every field with its type, the items
    /// sorted and each id the one of its rule and path, the window fixed, and
    /// the hash equal to the one of the items. Anything else is refused.
    pub fn from_json(text: &str) -> Result<Plan, PlanError> {
        let doc: Value = serde_json::from_str(text).map_err(|_| bad("json"))?;
        let doc = doc.as_object().ok_or(bad("document"))?;
        if doc.get("version").and_then(Value::as_u64) != Some(u64::from(PLAN_VERSION)) {
            return Err(bad("version"));
        }
        let created_at = num(doc, "created_at")?;
        let expires_at = num(doc, "expires_at")?;
        if created_at.checked_add(PLAN_TTL_SECS) != Some(expires_at) {
            return Err(bad("expires_at"));
        }
        let home = PathBuf::from(text_of(doc, "home")?);
        if !is_canonical_form(&home) {
            return Err(bad("home"));
        }
        let report_hash = hex_of(doc, "report_hash")?;
        let stored_hash = hex_of(doc, "plan_hash")?;
        let raw = doc
            .get("items")
            .and_then(Value::as_array)
            .ok_or(bad("items"))?;
        let items = raw
            .iter()
            .map(|v| parse_item(v, &home))
            .collect::<Result<Vec<_>, _>>()?;
        if items.is_empty() {
            return Err(bad("items"));
        }
        if items
            .windows(2)
            .any(|w| (w[0].rule, &w[0].path) >= (w[1].rule, &w[1].path))
        {
            return Err(bad("items order"));
        }
        if plan_hash(&items) != stored_hash {
            return Err(bad("plan_hash"));
        }
        Ok(Plan {
            version: PLAN_VERSION,
            created_at,
            expires_at,
            report_hash,
            plan_hash: stored_hash,
            home,
            items,
        })
    }
}

fn plan_item(
    scan: &ScanItem,
    report: &ScanReport,
    selection: &Selection,
    mode: Confirmations,
    ctx: &BuildContext,
    trash: &Path,
) -> Result<PlanItem, PlanError> {
    let id = scan.id;
    let path = &scan.path;
    if path.to_str().is_none() {
        return Err(PlanError::NonUtf8Path(id.0));
    }
    // Moving the Trash into itself, or what is in it again.
    if path.starts_with(trash) || trash.starts_with(path) {
        return Err(PlanError::TrashInvolved(id.0));
    }
    if !path.starts_with(ctx.home) || path == ctx.home {
        return Err(PlanError::OutsideHome(id.0));
    }
    // The inner item belongs to another rule: the outer one is not taken whole.
    if report.excluded.iter().any(|e| {
        e.reason == ExcludedReason::InsideItem
            && e.rule == scan.rule
            && e.path != *path
            && e.path.starts_with(path)
    }) {
        return Err(PlanError::HasExcludedSubtree(id.0));
    }
    let total = report
        .rules
        .iter()
        .find(|r| r.rule == scan.rule)
        .ok_or(PlanError::UnknownItem(id.0))?;

    let meta = look(ctx.fs, path, id)?;
    if ctx.protect.is_protected_entry(path, &meta) || ctx.protect.contains_protected(path) {
        return Err(PlanError::Protected(id.0));
    }
    // From the home down to the parent, each one a real folder.
    let rest = path
        .strip_prefix(ctx.home)
        .map_err(|_| PlanError::OutsideHome(id.0))?;
    let mut here = ctx.home.to_path_buf();
    let mut ancestors = vec![dir_identity(ctx.fs, &here, id)?];
    if let Some(parent) = rest.parent() {
        for part in parent.components() {
            here.push(part);
            ancestors.push(dir_identity(ctx.fs, &here, id)?);
        }
    }
    let confirmation = match total.risk {
        Risk::Low => Confirmation::NotNeeded,
        Risk::Medium
            if selection.confirmed.contains(&id) || selection.confirmed_high.contains(&id) =>
        {
            Confirmation::Confirmed
        }
        Risk::High if selection.confirmed_high.contains(&id) => Confirmation::ConfirmedHigh,
        needed => match mode {
            Confirmations::Preview => Confirmation::Pending,
            Confirmations::Required => {
                return Err(PlanError::MissingConfirmation { id: id.0, needed })
            }
        },
    };
    Ok(PlanItem {
        id,
        rule: scan.rule,
        path: path.clone(),
        risk: total.risk,
        bytes: scan.allocated_bytes,
        file_count: scan.file_count,
        identity: Identity::from_metadata(&meta),
        ancestors,
        requires_app_closed: total.requires_app_closed.map(str::to_owned),
        confirmation,
    })
}

/// `lstat` of `path`: a missing entry is gone, a link is refused.
fn look(fs: &dyn Fs, path: &Path, id: ItemId) -> Result<Metadata, PlanError> {
    let meta = fs.symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PlanError::Gone(id.0)
        } else {
            PlanError::Unreadable(id.0)
        }
    })?;
    if meta.is_symlink {
        return Err(PlanError::Symlink(id.0));
    }
    Ok(meta)
}

fn dir_identity(fs: &dyn Fs, path: &Path, id: ItemId) -> Result<Identity, PlanError> {
    let meta = look(fs, path, id)?;
    if !meta.is_dir {
        return Err(PlanError::Unreadable(id.0));
    }
    Ok(Identity::from_metadata(&meta))
}

/// FNV-1a of the file items of a report.
pub fn report_hash(report: &ScanReport) -> u64 {
    let mut buf = Vec::new();
    for i in &report.items {
        buf.extend_from_slice(&i.id.0.to_le_bytes());
        buf.extend_from_slice(i.rule.as_str().as_bytes());
        buf.push(0);
        buf.extend_from_slice(i.path.as_os_str().as_encoded_bytes());
        buf.push(0);
        buf.extend_from_slice(&i.allocated_bytes.to_le_bytes());
        buf.extend_from_slice(&i.file_count.to_le_bytes());
    }
    fnv1a(buf.iter())
}

/// The hash of what the user saw (see [`Plan::plan_hash`]).
pub fn plan_hash(items: &[PlanItem]) -> u64 {
    let mut buf = Vec::new();
    for i in items {
        buf.extend_from_slice(&i.id.0.to_le_bytes());
        buf.extend_from_slice(i.rule.as_str().as_bytes());
        buf.push(0);
        buf.extend_from_slice(i.path.as_os_str().as_encoded_bytes());
        buf.push(0);
        buf.push(match i.risk {
            Risk::Low => 0,
            Risk::Medium => 1,
            Risk::High => 2,
        });
    }
    fnv1a(buf.iter())
}

// --- the JSON form -------------------------------------------------------------------

fn hex(n: u64) -> String {
    format!("{n:016x}")
}

fn bad(what: &'static str) -> PlanError {
    PlanError::Malformed(what)
}

fn kind_str(k: EntryKind) -> &'static str {
    match k {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Symlink => "symlink",
    }
}

fn risk_str(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

fn confirmation_str(c: Confirmation) -> &'static str {
    match c {
        Confirmation::NotNeeded => "not-needed",
        Confirmation::Pending => "pending",
        Confirmation::Confirmed => "confirmed",
        Confirmation::ConfirmedHigh => "confirmed-high",
    }
}

fn identity_json(i: &Identity) -> Value {
    json!({ "dev": i.dev, "ino": i.ino, "kind": kind_str(i.kind), "nlink": i.nlink })
}

fn item_json(i: &PlanItem) -> Value {
    json!({
        "id": hex(i.id.0),
        "rule": i.rule.as_str(),
        "path": i.path.to_str().unwrap_or_default(),
        "risk": risk_str(i.risk),
        "bytes": i.bytes,
        "file_count": i.file_count,
        "identity": identity_json(&i.identity),
        "ancestors": i.ancestors.iter().map(identity_json).collect::<Vec<_>>(),
        "requires_app_closed": i.requires_app_closed,
        "confirmation": confirmation_str(i.confirmation),
    })
}

type Object = serde_json::Map<String, Value>;

fn num(o: &Object, key: &'static str) -> Result<u64, PlanError> {
    o.get(key).and_then(Value::as_u64).ok_or(bad(key))
}

fn text_of<'a>(o: &'a Object, key: &'static str) -> Result<&'a str, PlanError> {
    o.get(key).and_then(Value::as_str).ok_or(bad(key))
}

fn hex_of(o: &Object, key: &'static str) -> Result<u64, PlanError> {
    let t = text_of(o, key)?;
    if t.len() != 16 || !t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(bad(key));
    }
    u64::from_str_radix(t, 16).map_err(|_| bad(key))
}

/// An absolute path written the one way the scan writes it: no `..`, no `.`,
/// no doubled or trailing slash. `starts_with` compares components and
/// forgives all of those, so the text is checked too.
fn is_canonical_form(path: &Path) -> bool {
    use std::path::Component;
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

fn parse_identity(v: &Value) -> Result<Identity, PlanError> {
    let o = v.as_object().ok_or(bad("identity"))?;
    let kind = match text_of(o, "kind")? {
        "file" => EntryKind::File,
        "dir" => EntryKind::Dir,
        "symlink" => EntryKind::Symlink,
        _ => return Err(bad("kind")),
    };
    let nlink = match o.get("nlink") {
        Some(Value::Null) => None,
        Some(n) => Some(
            n.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(bad("nlink"))?,
        ),
        None => return Err(bad("nlink")),
    };
    // A folder has no link count; everything else has one.
    if nlink.is_some() == (kind == EntryKind::Dir) {
        return Err(bad("nlink"));
    }
    Ok(Identity {
        dev: num(o, "dev")?,
        ino: num(o, "ino")?,
        kind,
        nlink,
    })
}

fn parse_item(v: &Value, home: &Path) -> Result<PlanItem, PlanError> {
    let o = v.as_object().ok_or(bad("item"))?;
    let rule_name = text_of(o, "rule")?;
    let rule = rules::builtin()
        .iter()
        .map(|r| r.meta().id)
        .find(|id| id.as_str() == rule_name)
        .ok_or(bad("rule"))?;
    let path = PathBuf::from(text_of(o, "path")?);
    if !is_canonical_form(&path) || !path.starts_with(home) || path == home {
        return Err(bad("path"));
    }
    let id = ItemId(hex_of(o, "id")?);
    if id != ItemId::of(rule, &path) {
        return Err(bad("id"));
    }
    let risk = match text_of(o, "risk")? {
        "low" => Risk::Low,
        "medium" => Risk::Medium,
        "high" => Risk::High,
        _ => return Err(bad("risk")),
    };
    let confirmation = match text_of(o, "confirmation")? {
        "not-needed" => Confirmation::NotNeeded,
        "pending" => Confirmation::Pending,
        "confirmed" => Confirmation::Confirmed,
        "confirmed-high" => Confirmation::ConfirmedHigh,
        _ => return Err(bad("confirmation")),
    };
    let identity = parse_identity(o.get("identity").ok_or(bad("identity"))?)?;
    if identity.kind == EntryKind::Symlink {
        return Err(bad("identity"));
    }
    let ancestors = o
        .get("ancestors")
        .and_then(Value::as_array)
        .ok_or(bad("ancestors"))?
        .iter()
        .map(parse_identity)
        .collect::<Result<Vec<_>, _>>()?;
    if ancestors.is_empty() || ancestors.iter().any(|a| a.kind != EntryKind::Dir) {
        return Err(bad("ancestors"));
    }
    let requires_app_closed = match o.get("requires_app_closed") {
        Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return Err(bad("requires_app_closed")),
    };
    Ok(PlanItem {
        id,
        rule,
        path,
        risk,
        bytes: num(o, "bytes")?,
        file_count: num(o, "file_count")?,
        identity,
        ancestors,
        requires_app_closed,
        confirmation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::fs::{FakeFs, Metadata};
    use crate::model::{
        Category, Excluded, ExcludedReason, ItemSource, RuleTotal, ScanItem, ToolItem,
        SCHEMA_VERSION,
    };
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::time::Duration;

    const HOME: &str = "/Users/t";
    const NOW: u64 = 1_700_000_000;
    const CACHES: RuleId = RuleId::new("sys.user-caches");
    const RUSTUP: RuleId = RuleId::new("pkg.rustup");
    const ARCHIVES: RuleId = RuleId::new("apple.archives");
    const NPM: RuleId = RuleId::new("pkg.npm");

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

    fn md(is_dir: bool, ino: u64, nlink: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev: 7,
            ino,
            nlink,
            blocks: 8,
            len: 0,
            mtime: SystemTime::UNIX_EPOCH,
        }
    }

    /// `/Users/t/Library/Caches/{a,b}` and friends, every folder in place.
    fn disk() -> FakeFs {
        let mut fs = FakeFs::new();
        fs.insert("/Users", md(true, 1, 5))
            .insert(HOME, md(true, 2, 12))
            .insert("/Users/t/Library", md(true, 3, 9))
            .insert("/Users/t/Library/Caches", md(true, 4, 30))
            .insert("/Users/t/Library/Caches/com.a", md(true, 10, 4))
            .insert("/Users/t/Library/Caches/com.b", md(true, 11, 2))
            .insert("/Users/t/.rustup", md(true, 5, 6))
            .insert("/Users/t/.rustup/toolchains", md(true, 6, 3))
            .insert("/Users/t/.rustup/toolchains/old", md(true, 12, 4))
            .insert("/Users/t/Library/Developer", md(true, 7, 3))
            .insert("/Users/t/Library/Developer/Xcode", md(true, 8, 3))
            .insert("/Users/t/Library/Developer/Xcode/Archives", md(true, 9, 3))
            .insert(
                "/Users/t/Library/Developer/Xcode/Archives/App.xcarchive",
                md(true, 13, 3),
            )
            .insert("/Users/t/.npm", md(true, 14, 3))
            .insert("/Users/t/.npm/_cacache", md(true, 15, 3))
            .insert("/Users/t/.npm/_cacache/log.txt", md(false, 16, 2));
        fs
    }

    fn rule_total(rule: RuleId, risk: Risk, app: Option<&'static str>) -> RuleTotal {
        RuleTotal {
            rule,
            category: Category::SystemCaches,
            risk,
            allocated_bytes: 0,
            items: 0,
            name_key: "rule.test",
            consequence_key: "rule.test.consequence",
            default_selected: risk == Risk::Low,
            requires_app_closed: app,
            source: ItemSource::Files,
        }
    }

    fn scan_item(rule: RuleId, path: &str, bytes: u64) -> ScanItem {
        let path = PathBuf::from(path);
        ScanItem {
            id: ItemId::of(rule, &path),
            rule,
            path,
            allocated_bytes: bytes,
            file_count: 3,
        }
    }

    fn id(rule: RuleId, path: &str) -> ItemId {
        ItemId::of(rule, Path::new(path))
    }

    fn report() -> ScanReport {
        let mut items = vec![
            scan_item(CACHES, "/Users/t/Library/Caches/com.a", 1_000),
            scan_item(CACHES, "/Users/t/Library/Caches/com.b", 2_000),
            scan_item(RUSTUP, "/Users/t/.rustup/toolchains/old", 5_000),
            scan_item(
                ARCHIVES,
                "/Users/t/Library/Developer/Xcode/Archives/App.xcarchive",
                9_000,
            ),
            scan_item(NPM, "/Users/t/.npm/_cacache/log.txt", 100),
        ];
        items.sort_by(|a, b| (a.rule, &a.path).cmp(&(b.rule, &b.path)));
        ScanReport {
            schema_version: SCHEMA_VERSION,
            rules: vec![
                rule_total(ARCHIVES, Risk::High, Some("com.apple.dt.Xcode")),
                rule_total(NPM, Risk::Low, None),
                rule_total(RUSTUP, Risk::Medium, None),
                rule_total(CACHES, Risk::Low, None),
            ],
            items,
            skipped: Vec::new(),
            total_bytes: 17_100,
            tool_items: vec![ToolItem {
                id: ItemId::of_key(RuleId::new("models.ollama"), "llama3:latest"),
                rule: RuleId::new("models.ollama"),
                key: "llama3:latest".into(),
                label: "llama3:latest".into(),
                reported_bytes: 4_000_000_000,
                paths: Vec::new(),
            }],
            providers: Vec::new(),
            tool_total_bytes: 4_000_000_000,
            unmanaged: Vec::new(),
            excluded: Vec::new(),
        }
    }

    fn clock(secs: u64) -> FixedClock {
        FixedClock(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    struct Fixture {
        fs: FakeFs,
        protect: ProtectList,
        clock: FixedClock,
    }

    fn fixture() -> Fixture {
        let fs = disk();
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
        Fixture {
            fs,
            protect,
            clock: clock(NOW),
        }
    }

    fn build_with(
        fx: &Fixture,
        report: &ScanReport,
        selection: &Selection,
        mode: Confirmations,
    ) -> Result<Plan, PlanError> {
        let ctx = BuildContext {
            fs: &fx.fs,
            protect: &fx.protect,
            clock: &fx.clock,
            home: Path::new(HOME),
        };
        Plan::build(report, selection, mode, &ctx)
    }

    fn select(ids: &[ItemId]) -> Selection {
        Selection {
            ids: ids.to_vec(),
            ..Selection::default()
        }
    }

    fn low_plan() -> Plan {
        let fx = fixture();
        build_with(
            &fx,
            &report(),
            &select(&[id(CACHES, "/Users/t/Library/Caches/com.a")]),
            Confirmations::Required,
        )
        .unwrap()
    }

    // ADR 0006 §1: the plan holds what was chosen, with the identity of the
    // item and of every folder from the home down to it.
    #[test]
    fn build_records_the_item_its_identity_and_its_ancestors() {
        let plan = low_plan();
        assert_eq!(plan.version, PLAN_VERSION);
        assert_eq!(plan.created_at, NOW);
        assert_eq!(plan.expires_at, NOW + PLAN_TTL_SECS);
        assert_eq!(plan.home, Path::new(HOME));
        assert_eq!(plan.items.len(), 1);
        let item = &plan.items[0];
        assert_eq!(item.id, id(CACHES, "/Users/t/Library/Caches/com.a"));
        assert_eq!(item.rule, CACHES);
        assert_eq!(item.path, Path::new("/Users/t/Library/Caches/com.a"));
        assert_eq!(
            (item.risk, item.bytes, item.file_count),
            (Risk::Low, 1_000, 3)
        );
        assert_eq!(
            item.identity,
            Identity {
                dev: 7,
                ino: 10,
                kind: EntryKind::Dir,
                nlink: None
            }
        );
        // /Users/t, /Users/t/Library, /Users/t/Library/Caches: the home first.
        let inos: Vec<u64> = item.ancestors.iter().map(|a| a.ino).collect();
        assert_eq!(inos, [2, 3, 4]);
        assert!(item
            .ancestors
            .iter()
            .all(|a| a.kind == EntryKind::Dir && a.nlink.is_none()));
        assert_eq!(item.confirmation, Confirmation::NotNeeded);
        assert_eq!(item.requires_app_closed, None);
        assert_eq!(plan.report_hash, report_hash(&report()));
    }

    // The link count is part of a file's identity and not of a folder's.
    #[test]
    fn identity_keeps_nlink_for_files_and_drops_it_for_folders() {
        let file = Identity::from_metadata(&md(false, 5, 3));
        assert_eq!((file.kind, file.nlink), (EntryKind::File, Some(3)));
        let dir_a = Identity::from_metadata(&md(true, 5, 2));
        let dir_b = Identity::from_metadata(&md(true, 5, 9));
        assert_eq!(dir_a, dir_b);
        assert_eq!(dir_a.nlink, None);
        let link = Identity::from_metadata(&Metadata {
            is_symlink: true,
            ..md(false, 5, 1)
        });
        assert_eq!(link.kind, EntryKind::Symlink);
        let huge = Identity::from_metadata(&md(false, 5, u64::MAX));
        assert_eq!(huge.nlink, Some(u32::MAX));
        // A file hardlinked once more is not the same identity.
        assert_ne!(file, Identity::from_metadata(&md(false, 5, 4)));
    }

    #[test]
    fn items_are_sorted_by_rule_and_path_and_ids_are_not_repeated() {
        let fx = fixture();
        let a = id(CACHES, "/Users/t/Library/Caches/com.a");
        let b = id(CACHES, "/Users/t/Library/Caches/com.b");
        let n = id(NPM, "/Users/t/.npm/_cacache/log.txt");
        let plan = build_with(
            &fx,
            &report(),
            &select(&[b, n, a, b, a]),
            Confirmations::Required,
        )
        .unwrap();
        let got: Vec<ItemId> = plan.items.iter().map(|i| i.id).collect();
        assert_eq!(got, [n, a, b]);
        let again =
            build_with(&fx, &report(), &select(&[a, b, n]), Confirmations::Required).unwrap();
        assert_eq!(plan, again);
    }

    #[test]
    fn nothing_selected_is_refused() {
        let fx = fixture();
        assert_eq!(
            build_with(&fx, &report(), &select(&[]), Confirmations::Required),
            Err(PlanError::EmptySelection)
        );
    }

    #[test]
    fn an_id_that_is_not_in_the_report_is_refused() {
        let fx = fixture();
        let bogus = id(CACHES, "/Users/t/Library/Caches/nope");
        assert_eq!(
            build_with(&fx, &report(), &select(&[bogus]), Confirmations::Required),
            Err(PlanError::UnknownItem(bogus.0))
        );
    }

    // M2 only moves files: a tool item is read-only.
    #[test]
    fn a_tool_item_is_refused() {
        let fx = fixture();
        let r = report();
        let tool = r.tool_items[0].id;
        assert_eq!(
            build_with(&fx, &r, &select(&[tool]), Confirmations::Required),
            Err(PlanError::ToolItem(tool.0))
        );
    }

    // ADR 0005 / ADR 0006 §10.
    #[test]
    fn an_item_that_holds_an_item_of_another_rule_is_refused_whole() {
        let fx = fixture();
        let mut r = report();
        // The npm item sits inside the cache folder; another rule keeps it.
        r.excluded.push(Excluded {
            rule: CACHES,
            path: PathBuf::from("/Users/t/Library/Caches/com.a/inner"),
            kept_by: NPM,
            reason: ExcludedReason::InsideItem,
        });
        let a = id(CACHES, "/Users/t/Library/Caches/com.a");
        let b = id(CACHES, "/Users/t/Library/Caches/com.b");
        assert_eq!(
            build_with(&fx, &r, &select(&[a]), Confirmations::Required),
            Err(PlanError::HasExcludedSubtree(a.0))
        );
        // The neighbour and a shared hardlink are not affected.
        r.excluded.push(Excluded {
            rule: CACHES,
            path: PathBuf::from("/Users/t/Library/Caches/com.b"),
            kept_by: NPM,
            reason: ExcludedReason::SharedHardlink,
        });
        assert!(build_with(&fx, &r, &select(&[b]), Confirmations::Required).is_ok());
    }

    #[test]
    fn protected_items_and_items_that_hold_protected_data_are_refused() {
        let mut fx = fixture();
        fx.fs
            .insert("/Users/t/.ssh", md(true, 20, 2))
            .insert("/Users/t/Library/Keychains", md(true, 21, 2));
        let mut r = report();
        let ssh = scan_item(CACHES, "/Users/t/.ssh", 1);
        // `~/Library` holds `~/Library/Keychains`.
        let lib = scan_item(CACHES, "/Users/t/Library", 1);
        r.items.extend([ssh.clone(), lib.clone()]);
        for item in [ssh, lib] {
            assert_eq!(
                build_with(&fx, &r, &select(&[item.id]), Confirmations::Required),
                Err(PlanError::Protected(item.id.0)),
                "{:?}",
                item.path
            );
        }
    }

    // ADR 0006 §1: an item moved into itself, or trashed again.
    #[test]
    fn items_that_are_hold_or_sit_inside_the_trash_are_refused() {
        let mut fx = fixture();
        fx.fs
            .insert("/Users/t/.Trash", md(true, 30, 3))
            .insert("/Users/t/.Trash/old", md(true, 31, 2));
        let mut r = report();
        let inside = scan_item(CACHES, "/Users/t/.Trash/old", 1);
        let trash = scan_item(CACHES, "/Users/t/.Trash", 1);
        let home = scan_item(CACHES, "/Users/t", 1);
        r.items
            .extend([inside.clone(), trash.clone(), home.clone()]);
        for item in [inside, trash, home] {
            assert_eq!(
                build_with(&fx, &r, &select(&[item.id]), Confirmations::Required),
                Err(PlanError::TrashInvolved(item.id.0)),
                "{:?}",
                item.path
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_path_that_is_not_utf8_is_refused() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let mut fx = fixture();
        let raw: PathBuf = Path::new("/Users/t/Library/Caches").join(OsStr::from_bytes(b"caf\xe9"));
        fx.fs.insert(&raw, md(true, 40, 2));
        let mut r = report();
        let item = ScanItem {
            id: ItemId::of(CACHES, &raw),
            rule: CACHES,
            path: raw,
            allocated_bytes: 1,
            file_count: 1,
        };
        r.items.push(item.clone());
        assert_eq!(
            build_with(&fx, &r, &select(&[item.id]), Confirmations::Required),
            Err(PlanError::NonUtf8Path(item.id.0))
        );
    }

    // Low needs nothing; medium needs a confirmation; high needs its own.
    #[test]
    fn confirmations_follow_the_risk() {
        let fx = fixture();
        let r = report();
        let low = id(CACHES, "/Users/t/Library/Caches/com.a");
        let med = id(RUSTUP, "/Users/t/.rustup/toolchains/old");
        let high = id(
            ARCHIVES,
            "/Users/t/Library/Developer/Xcode/Archives/App.xcarchive",
        );
        let ids = [low, med, high];
        let only = |ids: &[ItemId]| Selection {
            ids: ids.to_vec(),
            ..Selection::default()
        };
        assert_eq!(
            build_with(&fx, &r, &only(&[med]), Confirmations::Required),
            Err(PlanError::MissingConfirmation {
                id: med.0,
                needed: Risk::Medium
            })
        );
        assert_eq!(
            build_with(&fx, &r, &only(&[high]), Confirmations::Required),
            Err(PlanError::MissingConfirmation {
                id: high.0,
                needed: Risk::High
            })
        );
        // A medium confirmation does not stand for a high item.
        let wrong = Selection {
            ids: vec![high],
            confirmed: vec![high],
            confirmed_high: vec![],
        };
        assert!(build_with(&fx, &r, &wrong, Confirmations::Required).is_err());
        let ok = Selection {
            ids: ids.to_vec(),
            confirmed: vec![med],
            confirmed_high: vec![high],
        };
        let plan = build_with(&fx, &r, &ok, Confirmations::Required).unwrap();
        let by_id = |i: ItemId| plan.items.iter().find(|p| p.id == i).unwrap().confirmation;
        assert_eq!(by_id(low), Confirmation::NotNeeded);
        assert_eq!(by_id(med), Confirmation::Confirmed);
        assert_eq!(by_id(high), Confirmation::ConfirmedHigh);
        // A preview marks what is still to confirm, and the hash is the same.
        let preview = build_with(&fx, &r, &only(&ids), Confirmations::Preview).unwrap();
        let by = |i: ItemId| {
            preview
                .items
                .iter()
                .find(|p| p.id == i)
                .unwrap()
                .confirmation
        };
        assert_eq!(by(low), Confirmation::NotNeeded);
        assert_eq!(by(med), Confirmation::Pending);
        assert_eq!(by(high), Confirmation::Pending);
        assert_eq!(preview.plan_hash, plan.plan_hash);
    }

    #[test]
    fn the_app_to_close_comes_from_the_rule() {
        let fx = fixture();
        let high = id(
            ARCHIVES,
            "/Users/t/Library/Developer/Xcode/Archives/App.xcarchive",
        );
        let sel = Selection {
            ids: vec![high],
            confirmed: vec![],
            confirmed_high: vec![high],
        };
        let plan = build_with(&fx, &report(), &sel, Confirmations::Required).unwrap();
        assert_eq!(
            plan.items[0].requires_app_closed.as_deref(),
            Some("com.apple.dt.Xcode")
        );
    }

    #[test]
    fn items_that_changed_since_the_scan_are_refused() {
        let mut fx = fixture();
        let a = id(CACHES, "/Users/t/Library/Caches/com.a");
        // Gone.
        let mut r = report();
        r.items.retain(|i| i.id != a);
        let gone = scan_item(CACHES, "/Users/t/Library/Caches/missing", 1);
        r.items.push(gone.clone());
        assert_eq!(
            build_with(&fx, &r, &select(&[gone.id]), Confirmations::Required),
            Err(PlanError::Gone(gone.id.0))
        );
        // A link now.
        let mut r = report();
        let link = scan_item(CACHES, "/Users/t/Library/Caches/link", 1);
        fx.fs
            .insert_symlink("/Users/t/Library/Caches/link", "/Users/t/.ssh");
        r.items.push(link.clone());
        assert_eq!(
            build_with(&fx, &r, &select(&[link.id]), Confirmations::Required),
            Err(PlanError::Symlink(link.id.0))
        );
        // An ancestor is a link now.
        let mut r = report();
        let deep = scan_item(CACHES, "/Users/t/Library/Caches/lnk/inner", 1);
        fx.fs
            .insert_symlink("/Users/t/Library/Caches/lnk", "/Users/t/.ssh");
        fx.fs
            .insert("/Users/t/Library/Caches/lnk/inner", md(true, 50, 2));
        r.items.push(deep.clone());
        assert_eq!(
            build_with(&fx, &r, &select(&[deep.id]), Confirmations::Required),
            Err(PlanError::Symlink(deep.id.0))
        );
    }

    #[test]
    fn an_item_outside_the_home_is_refused() {
        let mut fx = fixture();
        fx.fs
            .insert("/Volumes", md(true, 60, 3))
            .insert("/Volumes/x", md(true, 61, 2));
        let mut r = report();
        let out = scan_item(CACHES, "/Volumes/x", 1);
        r.items.push(out.clone());
        assert_eq!(
            build_with(&fx, &r, &select(&[out.id]), Confirmations::Required),
            Err(PlanError::OutsideHome(out.id.0))
        );
    }

    // The hash is what the user saw, not what the disk looks like.
    #[test]
    fn the_plan_hash_ignores_identity_sizes_times_and_confirmations() {
        let a = id(CACHES, "/Users/t/Library/Caches/com.a");
        let base = low_plan();
        let mut other = base.clone();
        other.created_at += 5;
        other.expires_at += 5;
        other.report_hash ^= 1;
        other.items[0].bytes += 1;
        other.items[0].file_count += 1;
        other.items[0].identity.ino += 1;
        other.items[0].identity.nlink = Some(9);
        other.items[0].ancestors[0].ino += 1;
        other.items[0].confirmation = Confirmation::Confirmed;
        other.items[0].requires_app_closed = Some("x".into());
        assert_eq!(plan_hash(&other.items), base.plan_hash);
        // What the user saw does change it.
        for change in 0..4 {
            let mut shown = base.clone();
            match change {
                0 => shown.items[0].path = PathBuf::from("/Users/t/Library/Caches/com.b"),
                1 => shown.items[0].rule = NPM,
                2 => shown.items[0].risk = Risk::High,
                _ => shown.items[0].id = ItemId(a.0 + 1),
            }
            assert_ne!(plan_hash(&shown.items), base.plan_hash, "{change}");
        }
        let mut two = base.clone();
        two.items.push(base.items[0].clone());
        assert_ne!(plan_hash(&two.items), base.plan_hash);
    }

    #[test]
    fn the_report_hash_follows_the_report() {
        let r = report();
        let h = report_hash(&r);
        assert_eq!(h, report_hash(&r.clone()));
        let mut bigger = r.clone();
        bigger.items[0].allocated_bytes += 1;
        assert_ne!(report_hash(&bigger), h);
        let mut fewer = r.clone();
        fewer.items.pop();
        assert_ne!(report_hash(&fewer), h);
        let mut tools = r.clone();
        tools.tool_items.clear();
        assert_eq!(report_hash(&tools), h, "tool items are not file items");
    }

    // ADR 0006 §6.
    #[test]
    fn a_plan_is_fresh_for_15_minutes_and_not_from_the_future() {
        let plan = low_plan();
        let at = |secs: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        assert_eq!(plan.check_fresh(at(NOW)), Ok(()));
        assert_eq!(plan.check_fresh(at(NOW + PLAN_TTL_SECS)), Ok(()));
        assert_eq!(
            plan.check_fresh(at(NOW + PLAN_TTL_SECS + 1)),
            Err(PlanError::Expired)
        );
        // The clock was set back: the plan claims to be from the future.
        assert_eq!(plan.check_fresh(at(NOW - CLOCK_SKEW_SECS)), Ok(()));
        assert_eq!(
            plan.check_fresh(at(NOW - CLOCK_SKEW_SECS - 1)),
            Err(PlanError::FromTheFuture)
        );
    }

    #[test]
    fn a_clock_before_1970_is_refused() {
        let mut fx = fixture();
        fx.clock = FixedClock(SystemTime::UNIX_EPOCH - Duration::from_secs(1));
        let a = id(CACHES, "/Users/t/Library/Caches/com.a");
        assert_eq!(
            build_with(&fx, &report(), &select(&[a]), Confirmations::Required),
            Err(PlanError::ClockBeforeEpoch)
        );
    }

    // The document round-trips, and anything that does not fit is refused.
    #[test]
    fn json_round_trips() {
        let fx = fixture();
        let sel = Selection {
            ids: vec![
                id(CACHES, "/Users/t/Library/Caches/com.a"),
                id(RUSTUP, "/Users/t/.rustup/toolchains/old"),
                id(NPM, "/Users/t/.npm/_cacache/log.txt"),
            ],
            confirmed: vec![id(RUSTUP, "/Users/t/.rustup/toolchains/old")],
            confirmed_high: vec![],
        };
        let plan = build_with(&fx, &report(), &sel, Confirmations::Required).unwrap();
        let text = plan.to_json();
        assert_eq!(Plan::from_json(&text), Ok(plan.clone()));
        // The file item has a link count; the folder items do not.
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["version"], 1);
        assert!(doc["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["identity"]["nlink"] == 2));
        assert!(doc["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["identity"]["nlink"].is_null()));
    }

    #[test]
    fn json_that_does_not_fit_is_refused() {
        let plan = low_plan();
        let good: serde_json::Value = serde_json::from_str(&plan.to_json()).unwrap();
        let edit = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            f(&mut v);
            Plan::from_json(&v.to_string())
        };
        assert!(Plan::from_json(&good.to_string()).is_ok());
        assert!(edit(&|v| v["version"] = 2.into()).is_err());
        assert!(edit(&|v| v["version"] = "1".into()).is_err());
        assert!(edit(&|v| {
            v.as_object_mut().unwrap().remove("home");
        })
        .is_err());
        assert!(edit(&|v| v["home"] = 5.into()).is_err());
        assert!(edit(&|v| v["home"] = "relative".into()).is_err());
        // A plan that was edited by hand no longer matches its hash.
        assert!(edit(&|v| v["plan_hash"] = "0000000000000001".into()).is_err());
        assert!(edit(&|v| v["items"][0]["path"] = "/Users/t/Library/Caches/com.b".into()).is_err());
        assert!(edit(&|v| v["items"][0]["risk"] = "high".into()).is_err());
        // The id has to be the one of the rule and the path.
        assert!(edit(&|v| v["items"][0]["id"] = "0000000000000001".into()).is_err());
        // The window is fixed.
        assert!(edit(&|v| v["expires_at"] = (NOW + PLAN_TTL_SECS + 1).into()).is_err());
        // A rule the program does not know.
        assert!(edit(&|v| v["items"][0]["rule"] = "made.up".into()).is_err());
        // An item outside the home, or without its ancestors.
        assert!(edit(&|v| v["items"][0]["path"] = "/etc/hosts".into()).is_err());
        assert!(edit(&|v| v["items"][0]["ancestors"] = serde_json::json!([])).is_err());
        assert!(edit(&|v| v["items"][0]["identity"]["kind"] = "pipe".into()).is_err());
        assert!(edit(&|v| v["items"][0]["confirmation"] = "maybe".into()).is_err());
        // Items out of order, repeated or none.
        assert!(edit(&|v| {
            let first = v["items"][0].clone();
            v["items"].as_array_mut().unwrap().push(first);
        })
        .is_err());
        assert!(edit(&|v| v["items"] = serde_json::json!([])).is_err());
        for bad in ["", "[]", "null", "{", "{}", "not json"] {
            assert!(Plan::from_json(bad).is_err(), "{bad:?}");
        }
        assert!(Plan::from_json(&format!("{} trailing", good)).is_err());
    }

    // A path that is not on the list but names the same inode as a protected
    // folder (a hardlink, a bind) is as protected as the folder.
    #[test]
    fn an_alias_of_a_protected_folder_is_refused() {
        let mut fx = fixture();
        fx.fs
            .insert("/Users/t/.ssh", md(true, 20, 2))
            .insert("/Users/t/Library/Caches/alias", md(true, 20, 2));
        fx.protect = ProtectList::builtin(&HomeAt)
            .unwrap()
            .with_identities(&fx.fs);
        let mut r = report();
        let alias = scan_item(CACHES, "/Users/t/Library/Caches/alias", 1);
        r.items.push(alias.clone());
        assert_eq!(
            build_with(&fx, &r, &select(&[alias.id]), Confirmations::Required),
            Err(PlanError::Protected(alias.id.0))
        );
    }

    // Only what a rule left out of ITS OWN item counts against that item.
    #[test]
    fn an_exclusion_of_another_rule_does_not_refuse_the_item() {
        let fx = fixture();
        let mut r = report();
        r.excluded.push(Excluded {
            rule: NPM,
            path: PathBuf::from("/Users/t/Library/Caches/com.a/inner"),
            kept_by: CACHES,
            reason: ExcludedReason::InsideItem,
        });
        let a = id(CACHES, "/Users/t/Library/Caches/com.a");
        assert!(build_with(&fx, &r, &select(&[a]), Confirmations::Required).is_ok());
    }

    #[test]
    fn a_file_in_the_middle_of_the_path_is_not_a_folder() {
        let mut fx = fixture();
        fx.fs
            .insert("/Users/t/Library/Caches/afile", md(false, 70, 1))
            .insert("/Users/t/Library/Caches/afile/inner", md(true, 71, 2));
        let mut r = report();
        let deep = scan_item(CACHES, "/Users/t/Library/Caches/afile/inner", 1);
        r.items.push(deep.clone());
        assert_eq!(
            build_with(&fx, &r, &select(&[deep.id]), Confirmations::Required),
            Err(PlanError::Unreadable(deep.id.0))
        );
    }

    /// A plan with a folder item, a folder item and a file item.
    fn rich_plan() -> Plan {
        let fx = fixture();
        let sel = Selection {
            ids: vec![
                id(CACHES, "/Users/t/Library/Caches/com.a"),
                id(CACHES, "/Users/t/Library/Caches/com.b"),
                id(NPM, "/Users/t/.npm/_cacache/log.txt"),
            ],
            ..Selection::default()
        };
        build_with(&fx, &report(), &sel, Confirmations::Required).unwrap()
    }

    /// The JSON of `plan` after `change`, with the hash made to match: only
    /// the change itself can make it refuse.
    fn rehashed_json(change: impl Fn(&mut Plan)) -> String {
        let mut plan = rich_plan();
        change(&mut plan);
        plan.plan_hash = plan_hash(&plan.items);
        plan.to_json()
    }

    #[test]
    fn json_with_a_matching_hash_is_still_refused_for_a_wrong_id_or_order() {
        assert!(Plan::from_json(&rehashed_json(|_| {})).is_ok());
        // An id that is not the one of the rule and the path.
        let wrong_id = rehashed_json(|p| p.items[0].id = ItemId(1));
        assert!(Plan::from_json(&wrong_id).is_err());
        // The same item twice.
        let twice = rehashed_json(|p| {
            let again = p.items[0].clone();
            p.items.insert(1, again);
        });
        assert!(Plan::from_json(&twice).is_err());
        // Items out of order.
        let swapped = rehashed_json(|p| p.items.swap(0, 1));
        assert!(Plan::from_json(&swapped).is_err());
    }

    // The link count belongs to files only; ancestors are folders.
    #[test]
    fn json_with_an_identity_that_does_not_fit_its_kind_is_refused() {
        let good: serde_json::Value = serde_json::from_str(&rich_plan().to_json()).unwrap();
        let edit = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            f(&mut v);
            Plan::from_json(&v.to_string())
        };
        let file = good["items"]
            .as_array()
            .unwrap()
            .iter()
            .position(|i| i["identity"]["kind"] == "file")
            .expect("a file item");
        let folder = good["items"]
            .as_array()
            .unwrap()
            .iter()
            .position(|i| i["identity"]["kind"] == "dir")
            .expect("a folder item");
        assert!(edit(&|_| {}).is_ok());
        // A folder with a link count, a file without one.
        assert!(edit(&|v| v["items"][folder]["identity"]["nlink"] = 3.into()).is_err());
        assert!(
            edit(&|v| v["items"][file]["identity"]["nlink"] = serde_json::Value::Null).is_err()
        );
        // An ancestor that is not a folder.
        assert!(edit(&|v| {
            v["items"][folder]["ancestors"][0]["kind"] = "file".into();
            v["items"][folder]["ancestors"][0]["nlink"] = 1.into();
        })
        .is_err());
    }

    // The paths in the document are compared by components, which forgive a
    // `..`, a `.`, a doubled or a trailing slash. A plan that carries one is
    // refused, even when its ids and hash were made to match.
    #[test]
    fn from_json_refuses_paths_that_are_not_in_canonical_form() {
        assert!(Plan::from_json(&rehashed_json(|_| {})).is_ok());
        for form in [
            "/Users/t/Library/Caches/../Caches/com.a",
            "/Users/t/./Library/Caches/com.a",
            "/Users/t/Library/Caches/com.a/",
            "/Users//t/Library/Caches/com.a",
            "/Users/t/Library/Caches/com.a/.",
        ] {
            let json = rehashed_json(|p| {
                let item = &mut p.items[0];
                item.path = PathBuf::from(form);
                item.id = ItemId::of(item.rule, &item.path);
            });
            assert!(Plan::from_json(&json).is_err(), "{form}");
        }
        for home in ["/Users//t", "/Users/t/", "/Users/./t", "/Users/t/."] {
            let json = rehashed_json(|p| p.home = PathBuf::from(home));
            assert!(Plan::from_json(&json).is_err(), "{home}");
        }
    }
}
