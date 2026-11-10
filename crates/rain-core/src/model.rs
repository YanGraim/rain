//! Scan report model: what a scan found, per rule and per item.

use std::fmt;
use std::path::{Path, PathBuf};

pub use crate::walk::{SkipReason, Skipped};

/// Version of the report layout; bumped on any breaking change (FR-010).
pub const SCHEMA_VERSION: u32 = 1;

/// Stable rule identifier, e.g. `sys.user-caches`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(&'static str);

impl RuleId {
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// What kind of data a rule cleans. Only the first three are used in M1;
/// the rest already exist for the catalogue and the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    SystemCaches,
    Logs,
    DevArtifacts,
    PackageManagers,
    Browsers,
    AiTools,
    AiModels,
    Containers,
    AppleDev,
    Projects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Risk {
    Low,
    Medium,
    High,
}

/// Stable identifier of an item: FNV-1a 64 of `(rule id, canonical path)`.
/// Hand-rolled because `std`'s hashers are not stable across releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemId(pub u64);

impl ItemId {
    pub fn of(rule: RuleId, path: &Path) -> Self {
        let bytes = rule
            .as_str()
            .as_bytes()
            .iter()
            // NUL separates the parts: it cannot occur in a path.
            .chain(std::iter::once(&0u8))
            .chain(path.as_os_str().as_encoded_bytes());
        Self(fnv1a(bytes))
    }

    /// Id of a tool item: `(rule id, tool key)`. A second NUL keeps it apart
    /// from every path id, since a path never starts with NUL.
    pub fn of_key(rule: RuleId, key: &str) -> Self {
        let bytes = rule
            .as_str()
            .as_bytes()
            .iter()
            .chain([0u8, 0u8].iter())
            .chain(key.as_bytes());
        Self(fnv1a(bytes))
    }
}

fn fnv1a<'a>(bytes: impl Iterator<Item = &'a u8>) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.fold(OFFSET, |h, b| (h ^ u64::from(*b)).wrapping_mul(PRIME))
}

/// Where an item comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemSource {
    Files,
    Tool,
}

/// One item reported by an external tool (ADR 0004). Its bytes are the
/// tool's figure and never enter `total_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolItem {
    pub id: ItemId,
    pub rule: RuleId,
    pub key: String,
    /// Untrusted text from the tool.
    pub label: String,
    pub reported_bytes: u64,
    /// Canonical, unprotected paths inside the rule's roots.
    pub paths: Vec<PathBuf>,
}

impl ToolItem {
    pub const SOURCE: ItemSource = ItemSource::Tool;
}

impl ScanItem {
    pub const SOURCE: ItemSource = ItemSource::Files;
}

/// Why a provider gave no items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unavailable {
    Tool(crate::tools::ToolError),
    /// The tool exited with a failure status.
    Failed,
    /// The output did not match the expected format.
    Parse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolStatus {
    Ok,
    Unavailable(Unavailable),
}

/// FR-022: one entry per provider rule that ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderStatus {
    pub rule: RuleId,
    pub status: ToolStatus,
}

/// One candidate found by a rule. Items are disjoint: no byte is counted in
/// two of them (ADR 0005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanItem {
    pub id: ItemId,
    pub rule: RuleId,
    /// Canonical path.
    pub path: PathBuf,
    /// `st_blocks * 512`, each hardlinked inode once per scan.
    pub allocated_bytes: u64,
    /// Non-directory, non-symlink entries (files, FIFOs, sockets, devices),
    /// each hardlinked inode once.
    pub file_count: u64,
}

/// FR-002: per-rule totals. Every selected rule appears, even with 0 items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTotal {
    pub rule: RuleId,
    pub category: Category,
    pub risk: Risk,
    pub allocated_bytes: u64,
    /// Number of items (candidates), not files.
    pub items: u64,
}

/// Result of a complete scan. Only ever built for a scan that finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub schema_version: u32,
    /// Sorted by rule id.
    pub rules: Vec<RuleTotal>,
    /// Sorted by `(rule, path)`.
    pub items: Vec<ScanItem>,
    /// Sorted by `(path, reason)`, no duplicates.
    pub skipped: Vec<Skipped>,
    /// Sum of all file items, equal to the sum of all rules.
    pub total_bytes: u64,
    /// Sorted by `(rule, key)`.
    pub tool_items: Vec<ToolItem>,
    /// Sorted by rule id.
    pub providers: Vec<ProviderStatus>,
    /// Sum of `reported_bytes` of all tool items.
    pub tool_total_bytes: u64,
}
