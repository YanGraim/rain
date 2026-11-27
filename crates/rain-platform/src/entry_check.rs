//! Checks a planned entry by file descriptor, right before a move (ADR 0006
//! §2, layer B). Every folder from the top down to the entry's parent is
//! opened without following links and compared with the identities the plan
//! recorded; the entry itself is then read relative to that folder.

use crate::trash_dir::MoveError;
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

/// Device and inode of one folder.
pub type FolderId = (u64, u64);

/// What an entry is, read without following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

/// The identity of an entry as the system reports it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryIdent {
    pub dev: u64,
    pub ino: u64,
    pub kind: Kind,
    /// Only for entries that are not folders (a folder's link count says
    /// nothing about its identity).
    pub nlink: Option<u32>,
}

/// Opens the folder `parent` (an absolute path) without following links, and
/// checks that each folder from `expect` down to `parent` is the one the plan
/// recorded. `expect` lists those folders from the home down to `parent`.
pub fn open_parent_checked(parent: &Path, expect: &[FolderId]) -> Result<OwnedFd, MoveError> {
    if !parent.is_absolute() || expect.is_empty() {
        return Err(MoveError::IdentityChanged);
    }
    let names: Vec<&OsStr> = parent
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    let first_checked = names
        .len()
        .checked_sub(expect.len())
        .ok_or(MoveError::IdentityChanged)?;
    let mut fd = open_folder(rustix::fs::CWD, Path::new("/"))?;
    for (depth, name) in names.iter().enumerate() {
        fd = open_folder(&fd, Path::new(name))?;
        if depth >= first_checked {
            let st = fstat(&fd).map_err(map_open)?;
            let found = (st.st_dev as u64, st.st_ino as u64);
            if found != expect[depth - first_checked] {
                return Err(MoveError::IdentityChanged);
            }
        }
    }
    Ok(fd)
}

/// The entry `name` in the folder `parent`, read without following a link.
pub fn entry_ident(parent: &OwnedFd, name: &OsStr) -> Result<EntryIdent, MoveError> {
    let st = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_open)?;
    Ok(ident_of(&st))
}

// `st_dev` is i32 on macOS and u64 on Linux: the cast is needed on one.
#[allow(clippy::unnecessary_cast)]
fn ident_of(st: &Stat) -> EntryIdent {
    let kind = match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory => Kind::Dir,
        FileType::Symlink => Kind::Symlink,
        _ => Kind::File,
    };
    EntryIdent {
        dev: st.st_dev as u64,
        ino: st.st_ino,
        kind,
        nlink: (kind != Kind::Dir).then_some(st.st_nlink as u32),
    }
}

fn open_folder(dir: impl rustix::fd::AsFd, name: &Path) -> Result<OwnedFd, MoveError> {
    openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_open)
}

/// A missing folder means the entry is gone with it; a link where a folder
/// should be is a symlink in the path.
fn map_open(e: Errno) -> MoveError {
    match e {
        Errno::NOENT => MoveError::Gone,
        Errno::LOOP | Errno::NOTDIR => MoveError::SymlinkInPath,
        Errno::ACCESS | Errno::PERM => MoveError::PermissionDenied,
        other => MoveError::Io(io::Error::from(other).kind()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};

    /// home/Library/Caches/x.bin, with the identities a plan would record.
    fn layout() -> (tempfile::TempDir, std::path::PathBuf, Vec<FolderId>) {
        // Canonical like a plan's paths: on macOS the temp dir sits behind
        // the `/var` link, which a checked path must not contain.
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let caches = home.join("Library").join("Caches");
        std::fs::create_dir_all(&caches).unwrap();
        std::fs::write(caches.join("x.bin"), "x").unwrap();
        let id = |p: &Path| {
            let m = std::fs::metadata(p).unwrap();
            (m.dev(), m.ino())
        };
        let expect = vec![id(&home), id(&home.join("Library")), id(&caches)];
        (dir, home, expect)
    }

    #[test]
    fn a_folder_chain_that_matches_the_plan_opens() {
        let (_d, home, expect) = layout();
        let parent = home.join("Library").join("Caches");
        assert!(open_parent_checked(&parent, &expect).is_ok());
    }

    #[test]
    fn a_folder_that_was_swapped_is_refused() {
        let (_d, home, mut expect) = layout();
        expect.swap(1, 2);
        let parent = home.join("Library").join("Caches");
        assert_eq!(
            open_parent_checked(&parent, &expect).unwrap_err(),
            MoveError::IdentityChanged
        );
    }

    #[test]
    fn a_folder_replaced_by_a_link_is_a_symlink_in_path() {
        let (d, home, expect) = layout();
        let caches = home.join("Library").join("Caches");
        std::fs::rename(&caches, d.path().join("moved")).unwrap();
        symlink(d.path().join("moved"), &caches).unwrap();
        assert_eq!(
            open_parent_checked(&caches, &expect).unwrap_err(),
            MoveError::SymlinkInPath
        );
    }

    #[test]
    fn a_missing_folder_means_the_entry_is_gone() {
        let (_d, home, expect) = layout();
        let parent = home.join("Library").join("Gone");
        assert_eq!(
            open_parent_checked(&parent, &expect).unwrap_err(),
            MoveError::Gone
        );
    }

    #[test]
    fn an_entry_is_read_without_following_a_link() {
        let (d, home, expect) = layout();
        let caches = home.join("Library").join("Caches");
        symlink(caches.join("x.bin"), d.path().join("link")).unwrap();
        let fd = open_parent_checked(&caches, &expect).unwrap();
        let file = entry_ident(&fd, OsStr::new("x.bin")).unwrap();
        assert_eq!(file.kind, Kind::File);
        assert_eq!(file.nlink, Some(1));
        let folder = entry_ident(&fd, OsStr::new("..")).unwrap();
        assert_eq!(folder.kind, Kind::Dir);
        assert_eq!(folder.nlink, None);
    }

    #[test]
    fn a_link_entry_is_reported_as_a_link_not_its_target() {
        let (_d, home, expect) = layout();
        let caches = home.join("Library").join("Caches");
        symlink(caches.join("x.bin"), caches.join("alias")).unwrap();
        let fd = open_parent_checked(&caches, &expect).unwrap();
        assert_eq!(
            entry_ident(&fd, OsStr::new("alias")).unwrap().kind,
            Kind::Symlink
        );
    }
}
