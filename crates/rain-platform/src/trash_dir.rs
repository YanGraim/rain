//! The real Trash: moves one entry into a Trash folder with `renameat` and
//! `NOREPLACE`, relative to file descriptors (ADR 0006 §3, option B).
//!
//! Nothing here deletes or copies. The Trash folder is a parameter: the
//! production code hands in the user's `~/.Trash`, and the tests hand in a
//! tempdir. The Trash folder is never created; if it is missing, the move
//! is refused as `TrashUnavailable`.

use crate::entry_check::{entry_ident, open_parent_checked, EntryIdent, FolderId};
use rustix::fs::{
    fstat, openat, renameat_with, statat, AtFlags, Mode, OFlags, RawMode, RenameFlags,
};
use rustix::io::Errno;
use rustix::process::getuid;
use std::io::{self, ErrorKind};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

/// Why an entry could not be moved. Nothing is deleted or copied instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveError {
    /// The entry is not there any more.
    Gone,
    /// The Trash folder is missing or is not safe to write to.
    TrashUnavailable(ErrorKind),
    /// Another entry was moved into the Trash under the moved entry's name:
    /// it was put back when `restored`, and nothing was lost either way.
    Misplaced { trash_name: String, restored: bool },
    /// A folder on the way to the entry is a link: refused, never followed.
    SymlinkInPath,
    /// The Trash is on another volume than the entry: refused, never copied.
    OtherVolume,
    /// The system does not do a rename that refuses to replace.
    NoReplaceUnsupported,
    /// The entry itself cannot be moved (read-only folder, flag, privacy).
    PermissionDenied,
    /// Every name in the Trash is taken.
    NameExhausted,
    /// A folder on the way, or the entry, is not the one the plan recorded.
    IdentityChanged,
    /// Anything else the system said.
    Io(ErrorKind),
}

/// A Trash folder that entries can be moved into.
#[derive(Debug)]
pub struct TrashDir {
    path: PathBuf,
    /// Test seam: runs between the move and the check after it.
    #[cfg(test)]
    pub(crate) after_move: Option<fn(&Path, &str)>,
}

/// A checked move: the name in the Trash and the identity found there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub trash_name: String,
    pub identity_after: EntryIdent,
}

impl TrashDir {
    /// The Trash at `path`. Nothing is created and nothing is moved yet.
    pub fn at(path: impl Into<PathBuf>) -> TrashDir {
        TrashDir {
            path: path.into(),
            #[cfg(test)]
            after_move: None,
        }
    }

    /// Where this Trash is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Moves `entry` into this Trash after checking it as the plan recorded
    /// it (ADR 0006 §2, layer B): every folder from the top down to the parent
    /// (`folders`) and the entry itself (`item`). Nothing is moved when a
    /// check fails. After the move the identity found in the Trash is checked
    /// again; a different entry is put back and reported as `Misplaced`.
    pub fn move_checked(
        &self,
        entry: &Path,
        folders: &[FolderId],
        item: EntryIdent,
    ) -> Result<Moved, MoveError> {
        let parent = entry.parent().ok_or(MoveError::Gone)?;
        let name = entry.file_name().ok_or(MoveError::Gone)?;
        let from = open_parent_checked(parent, folders)?;
        if entry_ident(&from, name)? != item {
            return Err(MoveError::IdentityChanged);
        }
        let trash_name = self.move_from(&from, name)?;
        #[cfg(test)]
        if let Some(hook) = self.after_move {
            hook(&self.path, &trash_name);
        }
        let after = self.ident_in_trash(&trash_name)?;
        if after == item {
            return Ok(Moved {
                trash_name,
                identity_after: after,
            });
        }
        let restored = self.put_back(&trash_name, &from, name).is_ok();
        Err(MoveError::Misplaced {
            trash_name,
            restored,
        })
    }

    /// The identity of the entry `name` now in this Trash.
    pub fn ident_in_trash(&self, name: &str) -> Result<crate::entry_check::EntryIdent, MoveError> {
        let to = open_dir(&self.path).map_err(map_errno)?;
        crate::entry_check::entry_ident(&to, std::ffi::OsStr::new(name))
    }

    /// Puts the entry `trash_name` back into the folder `parent` as `name`,
    /// never replacing anything there (`NOREPLACE`).
    pub fn put_back(
        &self,
        trash_name: &str,
        parent: &OwnedFd,
        name: &std::ffi::OsStr,
    ) -> Result<(), MoveError> {
        let to = open_dir(&self.path).map_err(map_errno)?;
        renameat_with(&to, trash_name, parent, name, RenameFlags::NOREPLACE).map_err(map_rename)
    }

    /// Moves the entry `name` that lives in the folder `from` (a descriptor
    /// the caller has already checked). Everything is relative to `from`, so
    /// the parent cannot be swapped between the check and the move.
    pub fn move_from(&self, from: &OwnedFd, name: &std::ffi::OsStr) -> Result<String, MoveError> {
        let to = open_dir(&self.path).map_err(|e| match e {
            Errno::NOENT => MoveError::TrashUnavailable(ErrorKind::NotFound),
            Errno::LOOP | Errno::NOTDIR => MoveError::TrashUnavailable(ErrorKind::InvalidInput),
            other => MoveError::Io(io::Error::from(other).kind()),
        })?;
        // The Trash must be the user's and not writable by group or others.
        let trash = fstat(&to).map_err(map_errno)?;
        if !trash_is_safe(trash.st_mode, trash.st_uid, getuid().as_raw()) {
            return Err(MoveError::TrashUnavailable(ErrorKind::PermissionDenied));
        }
        // The entry itself: a link stays a link, and it must be on this volume.
        let st = statat(from, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        let trash_dev = trash.st_dev;
        check_same_volume(st.st_dev, trash_dev)?;
        // Try the entry's own name, then a name made unique from the time and
        // the inode, and only then a counter (ADR 0006 §3).
        let mut candidates = vec![name.to_string_lossy().into_owned()];
        candidates.push(unique_name(name, st.st_ino));
        for n in 2..=99u32 {
            candidates.push(format!("{} {n}", name.to_string_lossy()));
        }
        for candidate in candidates {
            if candidate.len() > 255 {
                continue;
            }
            match renameat_with(from, name, &to, candidate.as_str(), RenameFlags::NOREPLACE) {
                Ok(()) => return Ok(candidate),
                // A taken name: the Trash has it already (a folder that is not
                // empty reports ENOTEMPTY, not EXIST, on some systems).
                Err(e) if e == Errno::EXIST || e == Errno::NOTEMPTY => continue,
                Err(e) => return Err(map_rename(e)),
            }
        }
        Err(MoveError::NameExhausted)
    }
}

/// A folder opened without following a link, and checked to be a folder.
fn open_dir(path: &Path) -> Result<OwnedFd, Errno> {
    let fd = openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(fd)
}

/// The Trash is safe to move into only when the user owns it and neither
/// the group nor anyone else can write to it.
fn trash_is_safe(mode: RawMode, owner: u32, me: u32) -> bool {
    owner == me && mode & 0o022 == 0
}

/// An entry on another volume cannot be renamed into the Trash.
fn check_same_volume<T: PartialEq>(entry_dev: T, trash_dev: T) -> Result<(), MoveError> {
    if entry_dev == trash_dev {
        Ok(())
    } else {
        Err(MoveError::OtherVolume)
    }
}

/// A name that is not used by the others: the name, the hour and minute and
/// second, and the inode, so two equal names do not collide.
fn unique_name(name: &std::ffi::OsStr, ino: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (h, m, s) = ((now / 3600) % 24, (now / 60) % 60, now % 60);
    format!("{} {h:02}.{m:02}.{s:02} {ino:x}", name.to_string_lossy())
}

fn map_errno(e: Errno) -> MoveError {
    match e {
        Errno::NOENT => MoveError::Gone,
        Errno::ACCESS | Errno::PERM => MoveError::PermissionDenied,
        other => MoveError::Io(io::Error::from(other).kind()),
    }
}

fn map_rename(e: Errno) -> MoveError {
    match e {
        Errno::NOENT => MoveError::Gone,
        Errno::ACCESS | Errno::PERM | Errno::ROFS => MoveError::PermissionDenied,
        Errno::XDEV => MoveError::OtherVolume,
        Errno::INVAL | Errno::OPNOTSUPP => MoveError::NoReplaceUnsupported,
        // On macOS ENOTSUP and EOPNOTSUPP are different numbers; on Linux they
        // are the same one, so this arm exists only where it is a new value.
        #[cfg(target_os = "macos")]
        Errno::NOTSUP => MoveError::NoReplaceUnsupported,
        other => MoveError::Io(io::Error::from(other).kind()),
    }
}

#[cfg(test)]
mod tests {
    // Tests build throwaway folders inside a tempdir sandbox only.
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use crate::entry_check::Kind;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    /// A tempdir with `home/<rel>` for an entry and a Trash folder next to it.
    fn sandbox() -> (tempfile::TempDir, PathBuf, PathBuf) {
        // Canonical like a plan's paths: the temp dir sits behind `/var` on macOS.
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let trash = root.join("trash");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&trash).unwrap();
        (dir, home, trash)
    }

    /// The folders from the top down to `parent`, read now: what a plan
    /// records for them.
    fn folders_of(parent: &Path) -> Vec<FolderId> {
        let mut chain: Vec<&Path> = parent
            .ancestors()
            .filter(|p| !p.as_os_str().is_empty() && *p != Path::new("/"))
            .collect();
        chain.reverse();
        chain
            .into_iter()
            .map(|p| {
                let m = std::fs::metadata(p).unwrap();
                (m.dev(), m.ino())
            })
            .collect()
    }

    /// The identity of one folder, read now: a plan's expectation covers the
    /// folders from the home down, so a test that stops at `home` passes it.
    fn folder_id(folder: &Path) -> FolderId {
        let m = std::fs::metadata(folder).unwrap();
        (m.dev(), m.ino())
    }

    /// The entry as a plan records it, read now (`dev`, `ino`, kind, links).
    fn item_of(entry: &Path) -> EntryIdent {
        let m = std::fs::symlink_metadata(entry).unwrap();
        let kind = if m.file_type().is_symlink() {
            Kind::Symlink
        } else if m.is_dir() {
            Kind::Dir
        } else {
            Kind::File
        };
        EntryIdent {
            dev: m.dev(),
            ino: m.ino(),
            kind,
            nlink: (kind != Kind::Dir).then(|| m.nlink() as u32),
        }
    }

    /// A move checked against what the plan would have recorded for `entry`.
    fn move_planned(trash: &Path, entry: &Path) -> Result<Moved, MoveError> {
        let parent = entry.parent().unwrap();
        TrashDir::at(trash).move_checked(entry, &folders_of(parent), item_of(entry))
    }

    /// An identity that matches nothing: for entries that must be missing.
    fn no_item() -> EntryIdent {
        EntryIdent {
            dev: 0,
            ino: 0,
            kind: Kind::File,
            nlink: Some(1),
        }
    }

    #[test]
    fn an_entry_moves_into_the_trash_under_its_own_name() {
        let (_d, home, trash) = sandbox();
        let cache = home.join("com.example.app");
        std::fs::create_dir(&cache).unwrap();
        std::fs::write(cache.join("blob"), "data").unwrap();
        let ino = std::fs::metadata(&cache).unwrap().ino();
        let name = move_planned(&trash, &cache).unwrap().trash_name;
        assert_eq!(name, "com.example.app");
        assert!(!cache.exists(), "the entry left its place");
        let moved = trash.join(&name);
        assert_eq!(
            std::fs::metadata(&moved).unwrap().ino(),
            ino,
            "the same inode"
        );
        assert_eq!(std::fs::read_to_string(moved.join("blob")).unwrap(), "data");
    }

    #[test]
    fn a_name_already_taken_gets_a_different_one_and_nothing_is_replaced() {
        let (_d, home, trash) = sandbox();
        // An entry already in the Trash with the same name.
        std::fs::create_dir(trash.join("cache")).unwrap();
        std::fs::write(trash.join("cache/keep.txt"), "old").unwrap();
        let cache = home.join("cache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::write(cache.join("new.txt"), "new").unwrap();
        let name = move_planned(&trash, &cache).unwrap().trash_name;
        assert_ne!(name, "cache", "the taken name is not reused");
        assert_eq!(
            std::fs::read_to_string(trash.join("cache/keep.txt")).unwrap(),
            "old"
        );
        assert_eq!(
            std::fs::read_to_string(trash.join(&name).join("new.txt")).unwrap(),
            "new"
        );
    }

    /// The unique name is made from the time and the inode, so the second
    /// entry with the same name lands under a name that is not a counter.
    #[test]
    fn a_taken_name_is_made_unique_from_the_inode_before_any_counter() {
        let (_d, home, trash) = sandbox();
        std::fs::create_dir(trash.join("cache")).unwrap();
        let cache = home.join("cache");
        std::fs::create_dir(&cache).unwrap();
        let ino = std::fs::metadata(&cache).unwrap().ino();
        let name = move_planned(&trash, &cache).unwrap().trash_name;
        assert!(name.starts_with("cache "), "{name}");
        assert!(name.ends_with(&format!("{ino:x}")), "{name}");
        assert!(!name.ends_with(" 2"), "a counter was used first: {name}");
    }

    #[test]
    fn a_missing_entry_is_gone() {
        let (_d, home, trash) = sandbox();
        let nope = home.join("nope");
        assert_eq!(
            TrashDir::at(&trash).move_checked(&nope, &[folder_id(&home)], no_item()),
            Err(MoveError::Gone)
        );
    }

    #[test]
    fn a_missing_trash_is_unavailable_and_never_created() {
        let (_d, home, _trash) = sandbox();
        let cache = home.join("cache");
        std::fs::create_dir(&cache).unwrap();
        let gone = home.join("no-trash-here");
        assert!(matches!(
            move_planned(&gone, &cache),
            Err(MoveError::TrashUnavailable(_))
        ));
        assert!(!gone.exists(), "the Trash is never created by Rain");
        assert!(cache.exists(), "nothing was moved");
    }

    #[test]
    fn a_trash_that_others_can_write_to_is_unavailable_and_nothing_moves() {
        let (_d, home, trash) = sandbox();
        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o777)).unwrap();
        let cache = home.join("cache");
        std::fs::write(&cache, "x").unwrap();
        assert_eq!(
            move_planned(&trash, &cache),
            Err(MoveError::TrashUnavailable(ErrorKind::PermissionDenied))
        );
        assert!(cache.exists(), "nothing was moved");
    }

    #[test]
    fn a_trash_is_safe_only_when_owned_by_the_user_and_not_writable_by_others() {
        const DIR: RawMode = 0o040000;
        assert!(trash_is_safe(DIR | 0o700, 501, 501));
        assert!(trash_is_safe(DIR | 0o755, 501, 501));
        assert!(!trash_is_safe(DIR | 0o777, 501, 501));
        assert!(!trash_is_safe(DIR | 0o775, 501, 501));
        assert!(!trash_is_safe(DIR | 0o757, 501, 501));
        assert!(!trash_is_safe(DIR | 0o700, 0, 501));
    }

    #[test]
    fn a_parent_folder_that_is_a_link_is_a_symlink_in_path() {
        let (_d, home, _trash) = sandbox();
        let real = home.join("real");
        std::fs::create_dir(&real).unwrap();
        let linked = home.join("linked");
        symlink(&real, &linked).unwrap();
        assert_eq!(
            TrashDir::at(home.join("trash")).move_checked(
                &linked.join("x"),
                &[folder_id(&home)],
                no_item()
            ),
            Err(MoveError::SymlinkInPath)
        );
    }

    #[test]
    fn a_parent_folder_that_is_gone_means_the_entry_is_gone() {
        let (_d, home, trash) = sandbox();
        assert_eq!(
            TrashDir::at(&trash).move_checked(
                &home.join("nope").join("x"),
                &[folder_id(&home)],
                no_item()
            ),
            Err(MoveError::Gone)
        );
    }

    #[test]
    fn the_same_volume_is_the_only_one_accepted() {
        assert_eq!(check_same_volume(16777230u64, 16777230u64), Ok(()));
        assert_eq!(
            check_same_volume(16777230u64, 16777231u64),
            Err(MoveError::OtherVolume)
        );
    }

    #[test]
    fn a_taken_name_for_a_link_uses_the_links_own_inode_not_its_targets() {
        use std::os::unix::fs::MetadataExt;
        let (_d, home, trash) = sandbox();
        let target = home.join("target");
        std::fs::write(&target, "x").unwrap();
        let link = home.join("link");
        symlink(&target, &link).unwrap();
        let link_ino = std::fs::symlink_metadata(&link).unwrap().ino();
        let target_ino = std::fs::metadata(&target).unwrap().ino();
        assert_ne!(link_ino, target_ino);
        std::fs::write(trash.join("link"), "taken").unwrap();
        let name = move_planned(&trash, &link).unwrap().trash_name;
        assert!(
            name.ends_with(&format!("{link_ino:x}")),
            "name {name} should carry the link's inode"
        );
        assert!(!name.ends_with(&format!("{target_ino:x}")));
    }

    #[test]
    fn a_link_is_moved_as_a_link_and_its_target_is_untouched() {
        let (_d, home, trash) = sandbox();
        let target = home.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), "x").unwrap();
        let link = home.join("link");
        symlink(&target, &link).unwrap();
        let name = move_planned(&trash, &link).unwrap().trash_name;
        assert!(std::fs::symlink_metadata(trash.join(&name))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(target.join("keep")).unwrap(), "x");
    }

    /// `home/real/b/item`, with the plan's expectations for it.
    fn real_b_item(home: &Path) -> (PathBuf, Vec<FolderId>, EntryIdent) {
        let b = home.join("real").join("b");
        std::fs::create_dir_all(&b).unwrap();
        let item = b.join("item");
        std::fs::write(&item, "x").unwrap();
        let folders = vec![
            folder_id(home),
            folder_id(&home.join("real")),
            folder_id(&b),
        ];
        (item.clone(), folders, item_of(&item))
    }

    #[test]
    fn an_entry_reached_through_a_link_in_its_path_is_refused_and_not_moved() {
        let (_d, home, trash) = sandbox();
        let (item, folders, ident) = real_b_item(&home);
        symlink(home.join("real"), home.join("link")).unwrap();
        let through_link = home.join("link").join("b").join("item");
        assert_eq!(
            TrashDir::at(&trash).move_checked(&through_link, &folders, ident),
            Err(MoveError::SymlinkInPath)
        );
        assert!(item.exists(), "nothing was moved");
    }

    #[test]
    fn an_entry_that_is_not_the_planned_one_is_refused_and_not_moved() {
        let (_d, home, trash) = sandbox();
        let (item, folders, mut ident) = real_b_item(&home);
        ident.ino += 1;
        assert_eq!(
            TrashDir::at(&trash).move_checked(&item, &folders, ident),
            Err(MoveError::IdentityChanged)
        );
        assert!(item.exists(), "nothing was moved");
    }

    #[test]
    fn a_folder_on_the_way_that_is_not_the_planned_one_is_refused() {
        let (_d, home, trash) = sandbox();
        let (item, mut folders, ident) = real_b_item(&home);
        folders[1].1 += 1;
        assert_eq!(
            TrashDir::at(&trash).move_checked(&item, &folders, ident),
            Err(MoveError::IdentityChanged)
        );
        assert!(item.exists(), "nothing was moved");
    }

    #[test]
    fn a_parent_with_dot_dot_is_refused_and_not_moved() {
        let (_d, home, trash) = sandbox();
        let (item, folders, ident) = real_b_item(&home);
        let odd = home
            .join("..")
            .join("home")
            .join("real")
            .join("b")
            .join("item");
        assert_eq!(
            TrashDir::at(&trash).move_checked(&odd, &folders, ident),
            Err(MoveError::IdentityChanged)
        );
        assert!(item.exists(), "nothing was moved");
    }

    fn another_entry_lands_under_the_moved_name(dir: &Path, name: &str) {
        let moved = dir.join(name);
        std::fs::rename(&moved, dir.join("held-away")).unwrap();
        std::fs::write(&moved, "another entry").unwrap();
    }

    #[test]
    fn a_different_entry_under_the_moved_name_is_put_back_and_reported() {
        let (_d, home, trash) = sandbox();
        let (item, folders, ident) = real_b_item(&home);
        let mut t = TrashDir::at(&trash);
        t.after_move = Some(another_entry_lands_under_the_moved_name);
        match t.move_checked(&item, &folders, ident) {
            Err(MoveError::Misplaced {
                trash_name,
                restored,
            }) => {
                assert!(restored, "the wrong entry must be put back");
                assert_eq!(std::fs::read_to_string(&item).unwrap(), "another entry");
                assert!(!trash.join(trash_name).exists());
            }
            other => panic!("expected Misplaced, got {other:?}"),
        }
    }

    #[test]
    fn a_checked_move_reports_the_identity_found_in_the_trash() {
        let (_d, home, trash) = sandbox();
        let (item, folders, ident) = real_b_item(&home);
        let moved = TrashDir::at(&trash)
            .move_checked(&item, &folders, ident)
            .unwrap();
        assert_eq!(moved.identity_after, ident);
        assert!(trash.join(&moved.trash_name).exists());
    }

    #[test]
    fn a_read_only_folder_is_a_permission_problem_and_is_not_made_writable() {
        let (_d, home, trash) = sandbox();
        let locked = home.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("f"), "x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = move_planned(&trash, &locked).map(|m| m.trash_name);
        // Restore before any assertion so the tempdir can be removed.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(out, Err(MoveError::PermissionDenied));
    }
}
