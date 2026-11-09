//! Rule contracts: what a rule declares and how it picks candidates.

use crate::fs::{Fs, Metadata};
use crate::model::{Category, Risk, RuleId};
use rain_platform::{Os, Root};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Static description of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: RuleId,
    pub category: Category,
    pub risk: Risk,
    /// Message catalogue key of the display name.
    pub name_key: &'static str,
    pub os: &'static [Os],
}

/// Extension point: rule families. `Provider` (act through an external
/// tool, e.g. Docker) is reserved for later (ADR 0004).
pub enum RuleKind<'a> {
    Files(&'a dyn FileRule),
}

pub trait Rule: Send + Sync {
    fn meta(&self) -> &RuleMeta;
    fn kind(&self) -> RuleKind<'_>;
}

/// Where a rule starts looking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootedPath {
    /// A relative path below a platform root; `""` is the root itself.
    Under(Root, &'static str),
    /// A user-supplied root (`--path`), already canonical.
    User(PathBuf),
}

/// What discovery does with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visit {
    /// Report it as an item and do not descend.
    Candidate,
    /// Not an item; look at its children.
    Descend,
    /// Not an item; ignore it and everything below, silently.
    Skip,
}

/// An entry offered to [`FileRule::visit`].
#[derive(Debug, Clone, Copy)]
pub struct EntryInfo<'a> {
    pub path: &'a Path,
    pub meta: &'a Metadata,
}

/// Inputs every rule sees. Time comes from here, never from a clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleContext {
    pub min_age_days: u32,
    pub user_paths: Vec<PathBuf>,
    pub now: SystemTime,
}

/// A rule that finds files and directories by walking roots.
///
/// Names must be matched exactly, never through `protect::normalize`: its
/// full case folding matches more than APFS, which is safe for protection
/// but would yield extra candidates here.
pub trait FileRule: Send + Sync {
    /// Explicit roots; no rule walks the whole home without a restriction.
    fn roots(&self, ctx: &RuleContext) -> Vec<RootedPath>;
    /// `depth` is 0 for the root itself.
    fn visit(&self, entry: &EntryInfo, depth: usize, ctx: &RuleContext, fs: &dyn Fs) -> Visit;
}
