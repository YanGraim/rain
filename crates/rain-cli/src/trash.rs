//! The real Trash behind the executor's `Trash` trait (ADR 0006 §2 and §3).
//! The checks and the move live in `rain-platform` (`move_checked`); this maps
//! them to the core's types. It is the only place where both meet.

use rain_core::plan::{EntryKind, Identity};
use rain_core::trash::{Trash, TrashError, TrashTarget, Trashed};
use rain_platform::entry_check::{EntryIdent, FolderId, Kind};
use rain_platform::trash_dir::{MoveError, TrashDir};
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// Moves planned entries into one Trash folder.
pub struct PlatformTrash {
    trash: TrashDir,
}

impl PlatformTrash {
    pub fn at(path: impl Into<PathBuf>) -> PlatformTrash {
        PlatformTrash {
            trash: TrashDir::at(path),
        }
    }

    /// Whether the Trash can be used at all (a denied Trash is reported before
    /// any item is touched).
    pub fn probe(&self) -> Result<(), TrashError> {
        self.trash.probe().map_err(map_move)
    }
}

impl Trash for PlatformTrash {
    fn trash(&self, target: &TrashTarget, cancel: &AtomicBool) -> Result<Trashed, TrashError> {
        if cancel.load(Ordering::SeqCst) {
            return Err(TrashError::Cancelled);
        }
        let folders: Vec<FolderId> = target.ancestors.iter().map(|a| (a.dev, a.ino)).collect();
        match self
            .trash
            .move_checked(&target.path, &folders, to_entry(&target.identity))
        {
            Ok(moved) => Ok(Trashed {
                trash_name: OsString::from(moved.trash_name),
                identity_after: to_core(&moved.identity_after),
            }),
            Err(MoveError::Misplaced {
                trash_name,
                restored,
            }) => Err(TrashError::Misplaced {
                trash_name: OsString::from(trash_name),
                restored,
            }),
            Err(e) => Err(map_move(e)),
        }
    }
}

fn kind_of(kind: EntryKind) -> Kind {
    match kind {
        EntryKind::File => Kind::File,
        EntryKind::Dir => Kind::Dir,
        EntryKind::Symlink => Kind::Symlink,
    }
}

fn to_entry(identity: &Identity) -> EntryIdent {
    EntryIdent {
        dev: identity.dev,
        ino: identity.ino,
        kind: kind_of(identity.kind),
        nlink: identity.nlink,
    }
}

fn to_core(ident: &EntryIdent) -> Identity {
    Identity {
        dev: ident.dev,
        ino: ident.ino,
        kind: match ident.kind {
            Kind::File => EntryKind::File,
            Kind::Dir => EntryKind::Dir,
            Kind::Symlink => EntryKind::Symlink,
        },
        nlink: ident.nlink,
    }
}

fn map_move(e: MoveError) -> TrashError {
    match e {
        MoveError::Gone => TrashError::Gone,
        MoveError::IdentityChanged => TrashError::IdentityChanged,
        MoveError::SymlinkInPath => TrashError::SymlinkInPath,
        MoveError::OtherVolume => TrashError::OtherVolume,
        MoveError::PermissionDenied => TrashError::PermissionDenied,
        MoveError::TrashUnavailable(kind) => TrashError::TrashUnavailable(kind),
        // The Trash has no way to replace without a flag: treated as unusable.
        MoveError::NoReplaceUnsupported => TrashError::TrashUnavailable(ErrorKind::Unsupported),
        MoveError::NameExhausted => TrashError::NameExhausted,
        // Reported by `move_checked` as `Misplaced`; mapped there, not here.
        MoveError::Misplaced { .. } => TrashError::Io(ErrorKind::Other),
        MoveError::Io(kind) => TrashError::Io(kind),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use rain_core::plan::EntryKind;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    struct Layout {
        _dir: tempfile::TempDir,
        home: PathBuf,
        trash: PathBuf,
    }

    /// home/Library/Caches/x.bin and an empty Trash, all in a tempdir.
    fn layout() -> Layout {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("Library/Caches")).unwrap();
        std::fs::write(home.join("Library/Caches/x.bin"), "x").unwrap();
        let trash = root.join("trash");
        std::fs::create_dir(&trash).unwrap();
        Layout {
            _dir: dir,
            home,
            trash,
        }
    }

    fn core_identity(p: &Path) -> Identity {
        let m = std::fs::symlink_metadata(p).unwrap();
        let kind = if m.file_type().is_symlink() {
            EntryKind::Symlink
        } else if m.is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        Identity {
            dev: m.dev(),
            ino: m.ino(),
            kind,
            nlink: (kind != EntryKind::Dir).then(|| m.nlink() as u32),
        }
    }

    fn target(l: &Layout) -> TrashTarget {
        let entry = l.home.join("Library/Caches/x.bin");
        TrashTarget {
            path: entry.clone(),
            identity: core_identity(&entry),
            ancestors: vec![
                core_identity(&l.home),
                core_identity(&l.home.join("Library")),
                core_identity(&l.home.join("Library/Caches")),
            ],
        }
    }

    #[test]
    fn a_planned_entry_moves_into_the_trash_and_its_identity_is_kept() {
        let l = layout();
        let t = target(&l);
        let cancel = AtomicBool::new(false);
        let trashed = PlatformTrash::at(&l.trash).trash(&t, &cancel).unwrap();
        assert!(!t.path.exists());
        assert_eq!(trashed.identity_after, t.identity);
        assert!(l.trash.join(&trashed.trash_name).exists());
    }

    #[test]
    fn an_entry_that_is_not_the_planned_one_is_refused_and_nothing_moves() {
        let l = layout();
        let mut t = target(&l);
        t.identity.ino += 1;
        let cancel = AtomicBool::new(false);
        assert_eq!(
            PlatformTrash::at(&l.trash).trash(&t, &cancel),
            Err(TrashError::IdentityChanged)
        );
        assert!(t.path.exists());
    }

    #[test]
    fn a_folder_on_the_way_that_changed_is_refused_and_nothing_moves() {
        let l = layout();
        let mut t = target(&l);
        t.ancestors[1].ino += 1;
        let cancel = AtomicBool::new(false);
        assert_eq!(
            PlatformTrash::at(&l.trash).trash(&t, &cancel),
            Err(TrashError::IdentityChanged)
        );
        assert!(t.path.exists());
    }

    #[test]
    fn a_cancel_before_the_move_moves_nothing() {
        let l = layout();
        let t = target(&l);
        let cancel = AtomicBool::new(true);
        assert_eq!(
            PlatformTrash::at(&l.trash).trash(&t, &cancel),
            Err(TrashError::Cancelled)
        );
        assert!(t.path.exists());
    }

    #[test]
    fn a_missing_entry_is_gone() {
        let l = layout();
        let mut t = target(&l);
        t.path = l.home.join("Library/Caches/nope");
        let cancel = AtomicBool::new(false);
        assert_eq!(
            PlatformTrash::at(&l.trash).trash(&t, &cancel),
            Err(TrashError::Gone)
        );
    }

    #[test]
    fn a_denied_trash_is_reported_by_the_probe_before_anything_moves() {
        use std::os::unix::fs::PermissionsExt;
        let l = layout();
        std::fs::set_permissions(&l.trash, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            PlatformTrash::at(&l.trash).probe(),
            Err(TrashError::TrashUnavailable(ErrorKind::PermissionDenied))
        );
        assert!(target(&l).path.exists());
    }
}
