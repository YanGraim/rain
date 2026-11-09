//! Shared rule shape: the items are the direct children of one folder.

use crate::fs::Fs;
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::Root;

/// A rule that lists the direct children of `Under(root, rel)` as items.
/// A missing folder simply yields 0 items (the planner keeps it silent).
pub struct ChildrenOf {
    pub(super) meta: RuleMeta,
    pub(super) root: Root,
    /// Path under `root`; empty means `root` itself.
    pub(super) rel: &'static str,
}

impl Rule for ChildrenOf {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for ChildrenOf {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        vec![RootedPath::Under(self.root, self.rel)]
    }
    fn visit(&self, _: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        // FR-002: the folder itself is never an item, only what it holds.
        if depth == 0 {
            Visit::Descend
        } else {
            Visit::Candidate
        }
    }
}
