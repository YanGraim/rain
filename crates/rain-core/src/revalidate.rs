//! Revalidating one plan item right before it is moved (ADR 0006 §2, layer A).
//!
//! Pure: it only reads, through `Fs`. It does not trust the plan: it looks at
//! the live disk, applies the protection lists again and asks the rule if it
//! still claims the path. The move itself checks again, atomically, in the
//! `Trash` implementation (layer B).
//!
//! The answer says what to do next. A **skip** leaves the item where it is
//! and the run goes on (an app's cache that is busy again must not abort the
//! whole cleaning); a **stop** ends the run, because a folder was swapped,
//! a link appeared or protected data is involved.

use crate::fs::Fs;
use crate::plan::{Identity, PlanItem};
use crate::planner::{self, ResolvedRoots};
use crate::protect::ProtectList;
use crate::rule::{EntryInfo, FileRule, RootedPath, RuleContext, RuleKind, Visit};
use crate::rules;
use std::path::Path;
use std::sync::atomic::AtomicBool;

/// Entries of one item that are read before it is refused as too big to check.
pub const DEFAULT_MAX_ENTRIES: usize = 5_000_000;

/// The item stays where it is and the run goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// It is not there any more.
    Gone,
    /// The item itself was replaced or changed since the plan.
    ChangedSincePlan,
    /// The rule that listed it no longer does (a project is active again, a
    /// folder is not one the rule walks into).
    RuleNoLongerClaims,
    /// It, or something inside it, is on another volume.
    OtherVolume,
    /// It could not be read, or it is too big to check.
    Unverifiable,
}

/// The run ends here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// A folder on the way was replaced by another one.
    AncestorChanged,
    /// The item or a folder on the way is a link.
    SymlinkInPath,
    /// The item is, holds, or has the identity of protected data.
    Protected,
    /// The item is or holds user data (a chat history, `~/.claude`).
    UserData,
    /// Something inside the item is protected, or an alias of protected data.
    ProtectedInside,
    /// The plan does not fit what the program knows: an unknown rule, a tool
    /// rule, a path outside the home, ancestors that do not add up.
    InvalidPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Safe to move, as far as the pure check can tell.
    Clear,
    Skip(Skip),
    Stop(Stop),
    /// The cancel flag was raised while reading.
    Cancelled,
}

/// What the check reads from the outside world.
pub struct Revalidation<'a> {
    pub fs: &'a dyn Fs,
    /// Must carry identities ([`ProtectList::with_identities`]).
    pub protect: &'a ProtectList,
    pub roots: &'a ResolvedRoots,
    pub rule_ctx: &'a RuleContext,
    pub cancel: &'a AtomicBool,
    /// Entries read inside one item; more than this is [`Skip::Unverifiable`].
    pub max_entries: usize,
}

/// What to do with `item`, looking at the disk as it is now.
///
/// Order: names first (no disk), then the entry, then the folders on the way,
/// then identity, volume, protection by identity, what the rule says, and
/// last what is inside. A refusal for protection comes before any "it
/// changed": a changed protected thing is still protected.
pub fn revalidate(item: &PlanItem, ctx: &Revalidation) -> Outcome {
    match check(item, ctx) {
        Ok(()) => Outcome::Clear,
        Err(outcome) => outcome,
    }
}

fn check(item: &PlanItem, ctx: &Revalidation) -> Result<(), Outcome> {
    let stop = |s| Outcome::Stop(s);
    let skip = |s| Outcome::Skip(s);
    let rule = file_rule(item).ok_or(stop(Stop::InvalidPlan))?;
    let path = item.path.as_path();
    let home = ctx.roots.home.as_path();
    if !path.starts_with(home) || path == home {
        return Err(stop(Stop::InvalidPlan));
    }
    // Names: no disk needed.
    if ctx.protect.is_protected(path) || ctx.protect.contains_protected(path) {
        return Err(stop(Stop::Protected));
    }
    if ctx.protect.user_data_id(path).is_some() {
        return Err(stop(Stop::UserData));
    }
    // The entry.
    let meta = ctx.fs.symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            skip(Skip::Gone)
        } else {
            skip(Skip::Unverifiable)
        }
    })?;
    if meta.is_symlink {
        return Err(stop(Stop::SymlinkInPath));
    }
    // Identity: the entry itself, and each folder up the chain.
    if ctx.protect.is_protected_entry(path, &meta) || ctx.protect.is_protected_on(ctx.fs, path) {
        return Err(stop(Stop::Protected));
    }
    if ctx.protect.user_data_alias_on(ctx.fs, path).is_some() {
        return Err(stop(Stop::UserData));
    }
    // `~/.claude` holds the user's history, so nothing there is moved, with
    // one exception: what sits strictly below a folder the rule itself names
    // as a root (the Claude Code cache and log rules), which is what a scan
    // lists there.
    if ctx.protect.in_claude_home_on(ctx.fs, path) && !below_a_named_claude_root(rule, path, ctx) {
        return Err(stop(Stop::UserData));
    }
    check_ancestors(item, home, ctx)?;
    match ctx.fs.canonicalize(path) {
        Ok(canonical) if canonical == path => {}
        Ok(_) => return Err(stop(Stop::SymlinkInPath)),
        Err(_) => return Err(skip(Skip::Unverifiable)),
    }
    if Identity::from_metadata(&meta) != item.identity {
        return Err(skip(Skip::ChangedSincePlan));
    }
    // Same volume as the home (checked above to be the one in the plan).
    if item.ancestors.first().map(|home| home.dev) != Some(meta.dev) {
        return Err(skip(Skip::OtherVolume));
    }
    if !claims(rule, path, ctx) {
        return Err(skip(Skip::RuleNoLongerClaims));
    }
    read_inside(path, &meta, ctx)
}

/// True when `path` is strictly inside a root that `rule` declares and that
/// is itself inside `~/.claude`.
fn below_a_named_claude_root(rule: &dyn FileRule, path: &Path, ctx: &Revalidation) -> bool {
    rule.roots(ctx.rule_ctx).iter().any(|rooted| {
        planner::resolve(rooted, ctx.roots).is_ok_and(|(root, _)| {
            path.starts_with(&root)
                && path != root
                && ctx.protect.in_claude_home_on(ctx.fs, &root)
                && matches!(rooted, RootedPath::Under(..))
        })
    })
}

fn file_rule(item: &PlanItem) -> Option<&'static dyn FileRule> {
    rules::builtin()
        .iter()
        .find(|r| r.meta().id == item.rule)
        .and_then(|r| match r.kind() {
            RuleKind::Files(files) => Some(files),
            RuleKind::Provider(_) => None,
        })
}

/// Each folder from the home to the parent is a real folder and the one the
/// plan recorded.
fn check_ancestors(item: &PlanItem, home: &Path, ctx: &Revalidation) -> Result<(), Outcome> {
    let rest = item
        .path
        .strip_prefix(home)
        .map_err(|_| Outcome::Stop(Stop::InvalidPlan))?;
    let parts: Vec<_> = rest.components().collect();
    // The home, then one folder for each part but the last.
    if item.ancestors.len() != parts.len() {
        return Err(Outcome::Stop(Stop::InvalidPlan));
    }
    let mut here = home.to_path_buf();
    for (i, expected) in item.ancestors.iter().enumerate() {
        if i > 0 {
            here.push(parts[i - 1]);
        }
        let meta = ctx.fs.symlink_metadata(&here).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Outcome::Skip(Skip::Gone)
            } else {
                Outcome::Skip(Skip::Unverifiable)
            }
        })?;
        if meta.is_symlink {
            return Err(Outcome::Stop(Stop::SymlinkInPath));
        }
        if Identity::from_metadata(&meta) != *expected {
            return Err(Outcome::Stop(Stop::AncestorChanged));
        }
    }
    Ok(())
}

/// Replays what a scan does: from one of the rule's roots, every folder on
/// the way answers `Descend` at its depth and the item answers `Candidate`.
fn claims(rule: &dyn FileRule, path: &Path, ctx: &Revalidation) -> bool {
    rule.roots(ctx.rule_ctx).iter().any(|rooted| {
        let Ok((root, _)) = planner::resolve(rooted, ctx.roots) else {
            return false;
        };
        path.starts_with(&root) && path != root && replay(rule, &root, path, ctx)
    })
}

fn replay(rule: &dyn FileRule, root: &Path, path: &Path, ctx: &Revalidation) -> bool {
    let Ok(rest) = path.strip_prefix(root) else {
        return false;
    };
    let parts: Vec<_> = rest.components().collect();
    let mut here = root.to_path_buf();
    for depth in 0..=parts.len() {
        if depth > 0 {
            here.push(parts[depth - 1]);
        }
        let Ok(meta) = ctx.fs.symlink_metadata(&here) else {
            return false;
        };
        let entry = EntryInfo {
            path: &here,
            meta: &meta,
            protect: ctx.protect,
            cancel: ctx.cancel,
        };
        let wanted = if depth == parts.len() {
            Visit::Candidate
        } else {
            Visit::Descend
        };
        if rule.visit(&entry, depth, ctx.rule_ctx, ctx.fs) != wanted {
            return false;
        }
    }
    true
}

/// Reads what is inside the item without following a link: no protected
/// entry or alias of one, nothing on another volume, within the entry budget.
fn read_inside(path: &Path, meta: &crate::fs::Metadata, ctx: &Revalidation) -> Result<(), Outcome> {
    if !meta.is_dir {
        return Ok(());
    }
    let volume = meta.dev;
    let mut pending = vec![(path.to_path_buf(), (meta.dev, meta.ino))];
    let mut read = 0usize;
    while let Some((dir, identity)) = pending.pop() {
        if ctx.cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Outcome::Cancelled);
        }
        let children = ctx
            .fs
            .read_dir_verified(&dir, identity)
            .map_err(|_| Outcome::Skip(Skip::Unverifiable))?;
        for child in children {
            read += 1;
            if read > ctx.max_entries {
                return Err(Outcome::Skip(Skip::Unverifiable));
            }
            let meta = ctx
                .fs
                .symlink_metadata(&child.path)
                .map_err(|_| Outcome::Skip(Skip::Unverifiable))?;
            if ctx.protect.is_protected_entry(&child.path, &meta)
                || ctx.protect.user_data_alias(&child.path, &meta).is_some()
            {
                return Err(Outcome::Stop(Stop::ProtectedInside));
            }
            // A link is only a name, on the volume of the folder that holds it.
            if meta.dev != volume && !meta.is_symlink {
                return Err(Outcome::Skip(Skip::OtherVolume));
            }
            if meta.is_dir && !meta.is_symlink {
                pending.push((child.path, (meta.dev, meta.ino)));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{FakeFs, Metadata};
    use crate::model::RuleId;
    use crate::plan::{Identity, PlanItem};
    use rain_platform::{Os, Platform, PlatformError, Root};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    const HOME: &str = "/Users/t";
    const DAY: u64 = 86_400;
    const CACHES: RuleId = RuleId::new("sys.user-caches");
    const LOGS: RuleId = RuleId::new("sys.logs");
    const RUST_TARGET: RuleId = RuleId::new("proj.rust-target");
    const NODE_MODULES: RuleId = RuleId::new("proj.node-modules");
    const CLAUDE_CACHE: RuleId = RuleId::new("ai.claude-code.cache");
    const CLAUDE_LOGS: RuleId = RuleId::new("ai.claude-code.logs");

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

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000 * DAY)
    }

    fn md(is_dir: bool, ino: u64, nlink: u64, dev: u64, age_days: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev,
            ino,
            nlink,
            blocks: 8,
            len: 0,
            mtime: now() - Duration::from_secs(age_days * DAY),
        }
    }

    type Entries = Vec<(String, Metadata)>;

    /// A home on dev 7. Folders and files are old unless a test says otherwise.
    fn entries() -> Entries {
        let d = |p: &str, ino: u64| (p.to_owned(), md(true, ino, 2, 7, 200));
        let f = |p: &str, ino: u64| (p.to_owned(), md(false, ino, 1, 7, 200));
        vec![
            d("/Users", 1),
            d(HOME, 2),
            d("/Users/t/Library", 3),
            d("/Users/t/Library/Caches", 4),
            d("/Users/t/Library/Caches/com.a", 10),
            f("/Users/t/Library/Caches/com.a/blob", 11),
            d("/Users/t/Library/Caches/com.b", 12),
            d("/Users/t/Library/Logs", 13),
            f("/Users/t/Library/Logs/old.log", 14),
            d("/Users/t/.ssh", 20),
            f("/Users/t/.ssh/id", 21),
            d("/Users/t/Library/Keychains", 22),
            f("/Users/t/.claude.json", 60),
            d("/Users/t/.claude", 50),
            d("/Users/t/.claude/projects", 51),
            d("/Users/t/.claude/futuro", 52),
            d("/Users/t/.claude/cache", 55),
            d("/Users/t/.claude/cache/abc", 56),
            d("/Users/t/.claude/shell-snapshots", 57),
            d("/Users/t/.claude/shell-snapshots/s1", 58),
            d("/Users/t/.claude/debug", 59),
            d("/Users/t/.claude/debug/d1", 61),
            d("/Users/t/.claude/futuro/node_modules", 53),
            f("/Users/t/.claude/futuro/package.json", 54),
            f("/Users/t/.aider.chat.history.md", 62),
            d("/Users/t/.codex", 80),
            d("/Users/t/.codex/sessions", 81),
            d("/Users/t/proj", 30),
            f("/Users/t/proj/Cargo.toml", 31),
            f("/Users/t/proj/src.rs", 32),
            d("/Users/t/proj/target", 33),
            f("/Users/t/proj/target/x", 34),
            d("/Users/t/.cache", 40),
            d("/Users/t/.cache/p", 41),
            f("/Users/t/.cache/p/Cargo.toml", 42),
            f("/Users/t/.cache/p/src.rs", 44),
            d("/Users/t/.cache/p/target", 43),
        ]
    }

    fn fs_of(entries: &Entries, links: &[(&str, &str)]) -> FakeFs {
        let mut fs = FakeFs::new();
        for (path, meta) in entries {
            fs.insert(path, *meta);
        }
        for (path, target) in links {
            fs.insert_symlink(path, target);
        }
        fs
    }

    fn world() -> FakeFs {
        fs_of(&entries(), &[])
    }

    /// `entries()` with `path` (and what is below it) gone.
    fn without(prefix: &str) -> Entries {
        let mut e = entries();
        e.retain(|(p, _)| !Path::new(p).starts_with(prefix));
        e
    }

    /// `entries()` with `path` replaced by `meta` (or added).
    fn with(path: &str, meta: Metadata) -> Entries {
        let mut e = entries();
        e.retain(|(p, _)| p != path);
        e.push((path.to_owned(), meta));
        e
    }

    /// The item as the plan records it: identity of the entry and of each
    /// folder from the home down to its parent.
    fn item_of(fs: &FakeFs, rule: RuleId, path: &str) -> PlanItem {
        use crate::fs::Fs;
        let ident = |p: &Path| {
            let meta = fs
                .symlink_metadata(p)
                .unwrap_or_else(|_| panic!("{p:?} is not in the fixture"));
            Identity::from_metadata(&meta)
        };
        let path_buf = PathBuf::from(path);
        let rest = path_buf.strip_prefix(HOME).unwrap();
        let mut here = PathBuf::from(HOME);
        let mut ancestors = vec![ident(&here)];
        let comps: Vec<_> = rest.components().collect();
        for part in &comps[..comps.len() - 1] {
            here.push(part);
            ancestors.push(ident(&here));
        }
        PlanItem {
            id: crate::model::ItemId::of(rule, &path_buf),
            rule,
            path: path_buf.clone(),
            risk: crate::model::Risk::Low,
            bytes: 1,
            file_count: 1,
            identity: ident(&path_buf),
            ancestors,
            requires_app_closed: None,
            confirmation: crate::plan::Confirmation::NotNeeded,
        }
    }

    fn check(fs: &FakeFs, item: &PlanItem) -> Outcome {
        check_with(fs, item, DEFAULT_MAX_ENTRIES, &AtomicBool::new(false))
    }

    fn check_with(fs: &FakeFs, item: &PlanItem, max: usize, cancel: &AtomicBool) -> Outcome {
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from("/Users/t/Library/Caches"),
            logs: PathBuf::from("/Users/t/Library/Logs"),
        };
        let rule_ctx = RuleContext {
            min_age_days: 30,
            user_paths: Vec::new(),
            now: now(),
        };
        revalidate(
            item,
            &Revalidation {
                fs,
                protect: &protect,
                roots: &roots,
                rule_ctx: &rule_ctx,
                cancel,
                max_entries: max,
            },
        )
    }

    const COM_A: &str = "/Users/t/Library/Caches/com.a";

    // ADR 0006 §2: nothing changed, nothing to say.
    #[test]
    fn an_unchanged_item_is_clear() {
        let fs = world();
        assert_eq!(check(&fs, &item_of(&fs, CACHES, COM_A)), Outcome::Clear);
        assert_eq!(
            check(&fs, &item_of(&fs, LOGS, "/Users/t/Library/Logs/old.log")),
            Outcome::Clear
        );
    }

    // The item is gone, or it is another entry now: left alone, the run goes on.
    #[test]
    fn an_item_that_is_gone_or_was_replaced_is_skipped() {
        let item = item_of(&world(), CACHES, COM_A);
        assert_eq!(
            check(&fs_of(&without(COM_A), &[]), &item),
            Outcome::Skip(Skip::Gone)
        );
        // Another inode under the same name.
        let recreated = fs_of(&with(COM_A, md(true, 99, 2, 7, 1)), &[]);
        assert_eq!(
            check(&recreated, &item),
            Outcome::Skip(Skip::ChangedSincePlan)
        );
        // A file where the folder was.
        let turned = fs_of(&with(COM_A, md(false, 10, 1, 7, 1)), &[]);
        assert_eq!(check(&turned, &item), Outcome::Skip(Skip::ChangedSincePlan));
    }

    // A folder's link count moves with every file an app writes; a file's does not.
    #[test]
    fn the_link_count_counts_for_files_and_not_for_folders() {
        let fs = world();
        let folder = item_of(&fs, CACHES, COM_A);
        let busy = fs_of(&with(COM_A, md(true, 10, 9, 7, 1)), &[]);
        assert_eq!(check(&busy, &folder), Outcome::Clear);
        let log = "/Users/t/Library/Logs/old.log";
        let file = item_of(&fs, LOGS, log);
        let linked = fs_of(&with(log, md(false, 14, 2, 7, 200)), &[]);
        assert_eq!(check(&linked, &file), Outcome::Skip(Skip::ChangedSincePlan));
    }

    // A link where the item was, or on the way to it, is not followed: stop.
    #[test]
    fn a_link_in_the_path_stops_the_run() {
        let item = item_of(&world(), CACHES, COM_A);
        let link_item = fs_of(&without(COM_A), &[(COM_A, "/Users/t/.ssh")]);
        assert_eq!(check(&link_item, &item), Outcome::Stop(Stop::SymlinkInPath));
        // `Caches` itself is a link now.
        let mut e = without("/Users/t/Library/Caches");
        e.push(("/Users/t/elsewhere".to_owned(), md(true, 70, 2, 7, 5)));
        e.push((COM_A.to_owned(), md(true, 10, 2, 7, 200)));
        let linked_parent = fs_of(&e, &[("/Users/t/Library/Caches", "/Users/t/elsewhere")]);
        assert_eq!(
            check(&linked_parent, &item),
            Outcome::Stop(Stop::SymlinkInPath)
        );
    }

    // A folder on the way was swapped for another: the item is not where it was.
    #[test]
    fn a_swapped_ancestor_stops_the_run() {
        let item = item_of(&world(), CACHES, COM_A);
        let swapped_parent = fs_of(&with("/Users/t/Library/Caches", md(true, 88, 2, 7, 1)), &[]);
        assert_eq!(
            check(&swapped_parent, &item),
            Outcome::Stop(Stop::AncestorChanged)
        );
        let swapped_home = fs_of(&with(HOME, md(true, 89, 2, 7, 1)), &[]);
        assert_eq!(
            check(&swapped_home, &item),
            Outcome::Stop(Stop::AncestorChanged)
        );
    }

    #[test]
    fn a_plan_that_does_not_add_up_is_invalid() {
        let fs = world();
        let good = item_of(&fs, CACHES, COM_A);
        // Ancestors missing one folder.
        let mut short = good.clone();
        short.ancestors.pop();
        assert_eq!(check(&fs, &short), Outcome::Stop(Stop::InvalidPlan));
        // A path outside the home, and the home itself.
        for outside in ["/etc/hosts", HOME] {
            let mut out = good.clone();
            out.path = PathBuf::from(outside);
            assert_eq!(
                check(&fs, &out),
                Outcome::Stop(Stop::InvalidPlan),
                "{outside}"
            );
        }
        // A rule the program does not know, and one that asks a tool.
        for rule in ["made.up", "models.ollama"] {
            let mut odd = good.clone();
            odd.rule = RuleId::new(rule);
            assert_eq!(check(&fs, &odd), Outcome::Stop(Stop::InvalidPlan), "{rule}");
        }
    }

    // Something on another volume than the home: not moved, not an error.
    #[test]
    fn an_item_on_another_volume_is_skipped() {
        let fs = fs_of(&with(COM_A, md(true, 10, 2, 9, 200)), &[]);
        let item = item_of(&fs, CACHES, COM_A);
        assert_eq!(check(&fs, &item), Outcome::Skip(Skip::OtherVolume));
    }

    // The protection lists are applied again, by name and by identity.
    #[test]
    fn protected_items_are_refused_by_name_and_by_identity() {
        let fs = world();
        // By name: the folder itself and one that holds protected folders.
        let ssh = item_of(&fs, CACHES, "/Users/t/.ssh");
        assert_eq!(check(&fs, &ssh), Outcome::Stop(Stop::Protected));
        let library = item_of(&fs, CACHES, "/Users/t/Library");
        assert_eq!(check(&fs, &library), Outcome::Stop(Stop::Protected));
        // By identity: a folder that is not on the list but is the same inode.
        let alias = "/Users/t/Library/Caches/alias";
        let fs2 = fs_of(&with(alias, md(true, 20, 2, 7, 200)), &[]);
        assert_eq!(
            check(&fs2, &item_of(&fs2, CACHES, alias)),
            Outcome::Stop(Stop::Protected)
        );
        // By an ancestor that has the identity of a protected folder.
        let mut e = entries();
        e.push((alias.to_owned(), md(true, 20, 2, 7, 200)));
        e.push((format!("{alias}/inner"), md(true, 71, 2, 7, 200)));
        let fs3 = fs_of(&e, &[]);
        assert_eq!(
            check(&fs3, &item_of(&fs3, CACHES, &format!("{alias}/inner"))),
            Outcome::Stop(Stop::Protected)
        );
    }

    // User data is a list of its own, not part of the protection list.
    #[test]
    fn user_data_is_refused() {
        let fs = world();
        let history = item_of(&fs, CACHES, "/Users/t/.claude/projects");
        assert!(
            matches!(
                check(&fs, &history),
                Outcome::Stop(Stop::UserData) | Outcome::Stop(Stop::Protected)
            ),
            "{:?}",
            check(&fs, &history)
        );
    }

    // The Claude Code rules are low risk and preselected, and their roots are
    // named folders inside `~/.claude`: what they list there is theirs to move.
    #[test]
    fn a_claude_cache_item_under_a_named_claude_root_is_clear() {
        let fs = world();
        for (rule, path) in [
            (CLAUDE_CACHE, "/Users/t/.claude/cache/abc"),
            (CLAUDE_CACHE, "/Users/t/.claude/shell-snapshots/s1"),
            (CLAUDE_LOGS, "/Users/t/.claude/debug/d1"),
        ] {
            assert_eq!(
                check(&fs, &item_of(&fs, rule, path)),
                Outcome::Clear,
                "{path}"
            );
        }
    }

    // The exception is only for what is BELOW a root the rule names, and only
    // for that rule: not the root itself, not another rule, not another folder.
    #[test]
    fn the_claude_exception_is_narrow() {
        let fs = world();
        let stopped = |rule: RuleId, path: &str| {
            matches!(
                check(&fs, &item_of(&fs, rule, path)),
                Outcome::Stop(Stop::UserData) | Outcome::Stop(Stop::Protected)
            )
        };
        // The named root itself (it holds the rule's items, it is not one).
        assert!(stopped(CLAUDE_CACHE, "/Users/t/.claude/cache"));
        // A rule that does not name that folder.
        assert!(stopped(CLAUDE_LOGS, "/Users/t/.claude/cache/abc"));
        assert!(stopped(NODE_MODULES, "/Users/t/.claude/cache/abc"));
        // A folder of `~/.claude` that no rule names.
        assert!(stopped(CLAUDE_CACHE, "/Users/t/.claude/futuro"));
    }

    // A root the user typed (`--path`) inside `~/.claude` is not a named root
    // of the rule: the scan refuses it, and so does the check.
    #[test]
    fn a_user_root_inside_the_claude_home_does_not_open_the_exception() {
        let fs = world();
        let item = item_of(&fs, NODE_MODULES, "/Users/t/.claude/futuro/node_modules");
        let protect = ProtectList::builtin(&HomeAt).unwrap().with_identities(&fs);
        let roots = ResolvedRoots {
            home: PathBuf::from(HOME),
            caches: PathBuf::from("/Users/t/Library/Caches"),
            logs: PathBuf::from("/Users/t/Library/Logs"),
        };
        let rule_ctx = RuleContext {
            min_age_days: 30,
            user_paths: vec![PathBuf::from("/Users/t/.claude/futuro")],
            now: now(),
        };
        let cancel = AtomicBool::new(false);
        let outcome = revalidate(
            &item,
            &Revalidation {
                fs: &fs,
                protect: &protect,
                roots: &roots,
                rule_ctx: &rule_ctx,
                cancel: &cancel,
                max_entries: DEFAULT_MAX_ENTRIES,
            },
        );
        assert!(
            matches!(
                outcome,
                Outcome::Stop(Stop::UserData) | Outcome::Stop(Stop::Protected)
            ),
            "{outcome:?}"
        );
    }

    // User data outside `~/.claude` is on the list by name.
    #[test]
    fn user_data_outside_the_claude_folder_is_refused_by_name() {
        let fs = world();
        let sessions = item_of(&fs, CACHES, "/Users/t/.codex/sessions");
        assert_eq!(check(&fs, &sessions), Outcome::Stop(Stop::UserData));
    }

    // A scan never enters `~/.claude` for a project rule; a plan that names
    // a folder there (made by hand, or stale) is stopped, not just skipped.
    #[test]
    fn a_folder_under_the_claude_home_is_stopped_even_if_no_list_names_it() {
        let fs = world();
        let item = item_of(&fs, NODE_MODULES, "/Users/t/.claude/futuro/node_modules");
        assert!(
            matches!(
                check(&fs, &item),
                Outcome::Stop(Stop::UserData) | Outcome::Stop(Stop::Protected)
            ),
            "{:?}",
            check(&fs, &item)
        );
    }

    // The rule has to claim the path the way a scan would: the descent from
    // its root, folder by folder, then the item.
    #[test]
    fn the_rule_has_to_still_claim_the_item() {
        let fs = world();
        let target = "/Users/t/proj/target";
        let project = item_of(&fs, RUST_TARGET, target);
        assert_eq!(check(&fs, &project), Outcome::Clear);
        // The project has seen work again.
        let active = fs_of(&with("/Users/t/proj/src.rs", md(false, 32, 1, 7, 2)), &[]);
        assert_eq!(
            check(&active, &project),
            Outcome::Skip(Skip::RuleNoLongerClaims)
        );
        // A `target` under a hidden folder, which the walk never enters.
        let hidden = item_of(&fs, RUST_TARGET, "/Users/t/.cache/p/target");
        assert_eq!(check(&fs, &hidden), Outcome::Skip(Skip::RuleNoLongerClaims));
        // A rule that does not walk where the item is.
        let elsewhere = item_of(&fs, LOGS, COM_A);
        assert_eq!(
            check(&fs, &elsewhere),
            Outcome::Skip(Skip::RuleNoLongerClaims)
        );
        // Without its marker file it is not a Rust project any more.
        let no_marker = fs_of(&without("/Users/t/proj/Cargo.toml"), &[]);
        assert_eq!(
            check(&no_marker, &project),
            Outcome::Skip(Skip::RuleNoLongerClaims)
        );
    }

    // What is inside the item is read again, entry by entry.
    #[test]
    fn protected_data_inside_the_item_stops_the_run() {
        let item = item_of(&world(), CACHES, COM_A);
        // A hardlink to a protected file.
        let mut e = entries();
        e.push((format!("{COM_A}/cj"), md(false, 60, 2, 7, 200)));
        let hardlink = fs_of(&e, &[]);
        assert_eq!(
            check(&hardlink, &item),
            Outcome::Stop(Stop::ProtectedInside)
        );
        // Deeper in the tree.
        let mut e = entries();
        e.push((format!("{COM_A}/deep"), md(true, 72, 2, 7, 200)));
        e.push((format!("{COM_A}/deep/alias"), md(true, 20, 2, 7, 200)));
        let deep = fs_of(&e, &[]);
        assert_eq!(check(&deep, &item), Outcome::Stop(Stop::ProtectedInside));
    }

    // A name inside the item for a chat history kept elsewhere: the scan
    // refuses it by identity, so the check does too.
    #[test]
    fn a_hardlink_to_user_data_inside_the_item_stops_the_run() {
        let item = item_of(&world(), CACHES, COM_A);
        let mut e = entries();
        e.push((format!("{COM_A}/history"), md(false, 62, 2, 7, 200)));
        assert_eq!(
            check(&fs_of(&e, &[]), &item),
            Outcome::Stop(Stop::ProtectedInside)
        );
    }

    #[test]
    fn another_volume_inside_the_item_is_skipped_and_links_are_not_followed() {
        let item = item_of(&world(), CACHES, COM_A);
        let mut e = entries();
        e.push((format!("{COM_A}/mount"), md(true, 73, 2, 9, 200)));
        assert_eq!(
            check(&fs_of(&e, &[]), &item),
            Outcome::Skip(Skip::OtherVolume)
        );
        // A link inside, even to a protected folder, is a name: moved, not followed.
        let links = fs_of(&entries(), &[(&format!("{COM_A}/to-ssh"), "/Users/t/.ssh")]);
        assert_eq!(check(&links, &item), Outcome::Clear);
    }

    // A folder that is a link is a name inside the item: it is moved with it
    // and never read through.
    #[test]
    fn a_link_to_a_folder_inside_the_item_is_not_read_through() {
        let item = item_of(&world(), CACHES, COM_A);
        let mut e = entries();
        let link = Metadata {
            is_symlink: true,
            ..md(true, 90, 2, 7, 200)
        };
        e.push((format!("{COM_A}/dirlink"), link));
        // What the link would lead to, if it were followed.
        e.push((format!("{COM_A}/dirlink/alias"), md(true, 20, 2, 7, 200)));
        assert_eq!(check(&fs_of(&e, &[]), &item), Outcome::Clear);
    }

    #[test]
    fn a_big_item_is_skipped_and_the_cancel_flag_stops_the_read() {
        let mut e = entries();
        for n in 0..5 {
            e.push((format!("{COM_A}/f{n}"), md(false, 100 + n, 1, 7, 200)));
        }
        let fs = fs_of(&e, &[]);
        let item = item_of(&fs, CACHES, COM_A);
        let no = AtomicBool::new(false);
        // blob and f0..f4: 6 entries.
        assert_eq!(check_with(&fs, &item, 6, &no), Outcome::Clear);
        assert_eq!(
            check_with(&fs, &item, 5, &no),
            Outcome::Skip(Skip::Unverifiable)
        );
        let yes = AtomicBool::new(true);
        assert_eq!(check_with(&fs, &item, 100, &yes), Outcome::Cancelled);
    }
}
