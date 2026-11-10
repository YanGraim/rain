//! Rule contracts: what a rule declares and how it picks candidates.

use crate::fs::{Fs, Metadata};
use crate::model::{Category, Risk, RuleId};
use crate::protect::ProtectList;
use crate::tools::{ParseError, ProviderItem, ToolCall, ToolOutput};
use rain_platform::{Os, Root};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

/// Static description of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: RuleId,
    pub category: Category,
    pub risk: Risk,
    /// Message catalogue key of the display name.
    pub name_key: &'static str,
    /// FR-002: message key of what the user loses when the item goes.
    pub consequence_key: &'static str,
    /// FR-014: never `true` for `Risk::High`.
    pub default_selected: bool,
    /// FR-015: bundle id of the app that must not be running.
    pub requires_app_closed: Option<&'static str>,
    pub os: &'static [Os],
}

/// Rule families: files found by walking, or items reported by an
/// external tool (ADR 0004).
pub enum RuleKind<'a> {
    Files(&'a dyn FileRule),
    Provider(&'a dyn ProviderRule),
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
    /// FR-007: for rules that read beyond the entry (e.g. a project's age),
    /// so those reads never enter protected folders either.
    pub protect: &'a ProtectList,
    /// FR-011: the scan's cancel flag, for rules whose checks read further.
    /// A rule that stops on it reports nothing; the planner sees the flag.
    pub cancel: &'a AtomicBool,
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

/// A rule that asks an official tool what exists. It only describes
/// commands and reads their output; it never runs anything.
pub trait ProviderRule: Send + Sync {
    /// Read-only command with a fixed argv.
    fn probe(&self) -> ToolCall;
    /// Pure and strict: output it does not fully understand is an error.
    fn parse(&self, out: &ToolOutput) -> Result<Vec<ProviderItem>, ParseError>;
    /// M2: the command that removes one item; `None` only reports.
    fn act(&self, item: &ProviderItem) -> Option<ToolCall>;
    /// Where paths named by the tool must live; any other path is dropped.
    fn roots(&self) -> Vec<RootedPath> {
        Vec::new()
    }
}
