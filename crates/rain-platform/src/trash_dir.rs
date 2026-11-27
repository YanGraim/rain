//! The real Trash: moves one entry into a Trash folder with `renameat` and
//! `NOREPLACE`, relative to file descriptors (ADR 0006 §3, option B).
//!
//! Nothing here deletes or copies. The Trash folder is a parameter: the
//! production code hands in the user's `~/.Trash`, and the tests hand in a
//! tempdir. The Trash folder is never created; if it is missing, the move
//! is refused as `TrashUnavailable`.

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
}

impl TrashDir {
    /// The Trash at `path`. Nothing is created and nothing is moved yet.
    pub fn at(path: impl Into<PathBuf>) -> TrashDir {
        TrashDir { path: path.into() }
    }

    /// Where this Trash is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Moves `entry` (an absolute path) into this Trash, under a name that is
    /// not taken. Returns the name it got.
    pub fn move_in(&self, entry: &Path) -> Result<String, MoveError> {
        let parent = entry.parent().ok_or(MoveError::Gone)?;
        let name = entry.file_name().ok_or(MoveError::Gone)?;
        let from = open_dir(parent).map_err(|e| match e {
            // A missing parent means the entry is gone with it.
            Errno::NOENT => MoveError::Gone,
            Errno::LOOP | Errno::NOTDIR => MoveError::SymlinkInPath,
            other => MoveError::Io(io::Error::from(other).kind()),
        })?;
        self.move_from(&from, name)
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
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    /// A tempdir with `home/<rel>` for an entry and a Trash folder next to it.
    fn sandbox() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let trash = dir.path().join("trash");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&trash).unwrap();
        (dir, home, trash)
    }

    #[test]
    fn an_entry_moves_into_the_trash_under_its_own_name() {
        let (_d, home, trash) = sandbox();
        let cache = home.join("com.example.app");
        std::fs::create_dir(&cache).unwrap();
        std::fs::write(cache.join("blob"), "data").unwrap();
        let ino = std::fs::metadata(&cache).unwrap().ino();
        let name = TrashDir::at(&trash).move_in(&cache).unwrap();
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
        let name = TrashDir::at(&trash).move_in(&cache).unwrap();
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
        let name = TrashDir::at(&trash).move_in(&cache).unwrap();
        assert!(name.starts_with("cache "), "{name}");
        assert!(name.ends_with(&format!("{ino:x}")), "{name}");
        assert!(!name.ends_with(" 2"), "a counter was used first: {name}");
    }

    #[test]
    fn a_missing_entry_is_gone() {
        let (_d, home, trash) = sandbox();
        assert_eq!(
            TrashDir::at(&trash).move_in(&home.join("nope")),
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
            TrashDir::at(&gone).move_in(&cache),
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
            TrashDir::at(&trash).move_in(&cache),
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
            TrashDir::at(home.join("trash")).move_in(&linked.join("x")),
            Err(MoveError::SymlinkInPath)
        );
    }

    #[test]
    fn a_parent_folder_that_is_gone_means_the_entry_is_gone() {
        let (_d, home, trash) = sandbox();
        assert_eq!(
            TrashDir::at(&trash).move_in(&home.join("nope").join("x")),
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
        let name = TrashDir::at(&trash).move_in(&link).unwrap();
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
        let name = TrashDir::at(&trash).move_in(&link).unwrap();
        assert!(std::fs::symlink_metadata(trash.join(&name))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(target.join("keep")).unwrap(), "x");
    }

    #[test]
    fn a_read_only_folder_is_a_permission_problem_and_is_not_made_writable() {
        let (_d, home, trash) = sandbox();
        let locked = home.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("f"), "x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = TrashDir::at(&trash).move_in(&locked);
        // Restore before any assertion so the tempdir can be removed.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(out, Err(MoveError::PermissionDenied));
    }
}
