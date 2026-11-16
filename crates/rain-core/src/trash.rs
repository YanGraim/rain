//! Moving one entry to the Trash (ADR 0006 §3).
//!
//! The core only describes the move; the implementation that does it lives
//! outside, like `Fs` and `ToolRunner`. `FakeTrash` stands in for it in tests.

use crate::plan::{Identity, PlanItem};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

/// What to move, and what it has to be: the entry and every folder from the
/// home down to it, as the plan recorded them. An implementation checks
/// them as close to the move as it can and never follows a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashTarget {
    pub path: PathBuf,
    pub identity: Identity,
    pub ancestors: Vec<Identity>,
}

impl TrashTarget {
    pub fn of(item: &PlanItem) -> TrashTarget {
        TrashTarget {
            path: item.path.clone(),
            identity: item.identity,
            ancestors: item.ancestors.clone(),
        }
    }
}

/// Where the entry went and which entry it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trashed {
    /// The name it has in the Trash (it may differ from the original).
    pub trash_name: OsString,
    /// The identity found at the destination: the same as the target's, or
    /// the wrong entry was moved.
    pub identity_after: Identity,
}

/// Why an entry was not moved. Nothing is ever deleted or copied instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrashError {
    #[error("the entry is gone")]
    Gone,
    #[error("the entry or one of its folders is not the one in the plan")]
    IdentityChanged,
    #[error("a link in the path")]
    SymlinkInPath,
    #[error("the entry is on another volume than the Trash")]
    OtherVolume,
    /// The entry itself cannot be moved (a read-only folder, an immutable
    /// flag, a privacy setting): skipped, never made writable.
    #[error("not allowed to move the entry")]
    PermissionDenied,
    /// The Trash is missing, cannot be written or lacks what is needed.
    #[error("the Trash is not usable: {0:?}")]
    TrashUnavailable(io::ErrorKind),
    #[error("no free name in the Trash")]
    NameExhausted,
    #[error("cancelled")]
    Cancelled,
    #[error("i/o error: {0:?}")]
    Io(io::ErrorKind),
    /// `identity_after` differs: another entry was moved. `restored` says if
    /// it was put back.
    #[error("another entry was moved ({trash_name:?}, restored: {restored})")]
    Misplaced {
        trash_name: OsString,
        restored: bool,
    },
}

/// Moves one entry to the Trash.
pub trait Trash: Send + Sync {
    /// Must stop before moving when `cancel` is raised ([`TrashError::Cancelled`]).
    fn trash(&self, target: &TrashTarget, cancel: &AtomicBool) -> Result<Trashed, TrashError>;
}

#[cfg(any(test, feature = "testing"))]
pub use fake::FakeTrash;

#[cfg(any(test, feature = "testing"))]
mod fake {
    use super::{Trash, TrashError, TrashTarget, Trashed};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A Trash in memory: records every call and can fail or move the wrong
    /// entry on purpose. It touches no disk.
    #[derive(Debug, Default)]
    pub struct FakeTrash {
        errors: BTreeMap<PathBuf, TrashError>,
        wrong_entry: BTreeSet<PathBuf>,
        calls: Mutex<Vec<PathBuf>>,
    }

    impl FakeTrash {
        pub fn new() -> Self {
            Self::default()
        }

        /// `path` fails with `error` (every time).
        pub fn fail(&mut self, path: impl Into<PathBuf>, error: TrashError) -> &mut Self {
            self.errors.insert(path.into(), error);
            self
        }

        /// `path` ends up as another entry: a `Misplaced` error, not restored.
        pub fn move_the_wrong_entry(&mut self, path: impl Into<PathBuf>) -> &mut Self {
            self.wrong_entry.insert(path.into());
            self
        }

        /// The paths asked for, in order.
        pub fn calls(&self) -> Vec<PathBuf> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }

        fn name_of(path: &Path) -> std::ffi::OsString {
            path.file_name().map(ToOwned::to_owned).unwrap_or_default()
        }
    }

    impl Trash for FakeTrash {
        fn trash(&self, target: &TrashTarget, cancel: &AtomicBool) -> Result<Trashed, TrashError> {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(target.path.clone());
            }
            if cancel.load(Ordering::SeqCst) {
                return Err(TrashError::Cancelled);
            }
            if let Some(error) = self.errors.get(&target.path) {
                return Err(error.clone());
            }
            if self.wrong_entry.contains(&target.path) {
                return Err(TrashError::Misplaced {
                    trash_name: Self::name_of(&target.path),
                    restored: false,
                });
            }
            Ok(Trashed {
                trash_name: Self::name_of(&target.path),
                identity_after: target.identity,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::plan::{EntryKind, Identity};
        use std::io::ErrorKind;

        fn target(path: &str) -> TrashTarget {
            TrashTarget {
                path: PathBuf::from(path),
                identity: Identity {
                    dev: 1,
                    ino: 2,
                    kind: EntryKind::Dir,
                    nlink: None,
                },
                ancestors: Vec::new(),
            }
        }

        fn no() -> AtomicBool {
            AtomicBool::new(false)
        }

        #[test]
        fn it_moves_without_touching_anything_and_records_the_calls() {
            let fake = FakeTrash::new();
            let t: &dyn Trash = &fake;
            let moved = t.trash(&target("/h/a/cache"), &no()).unwrap();
            assert_eq!(moved.trash_name, "cache");
            assert_eq!(moved.identity_after, target("/h/a/cache").identity);
            t.trash(&target("/h/b"), &no()).unwrap();
            assert_eq!(
                fake.calls(),
                [PathBuf::from("/h/a/cache"), PathBuf::from("/h/b")]
            );
        }

        #[test]
        fn it_fails_on_purpose_for_one_path_only() {
            let mut fake = FakeTrash::new();
            fake.fail("/h/ro", TrashError::PermissionDenied)
                .fail("/h/gone", TrashError::Gone)
                .fail(
                    "/h/trash",
                    TrashError::TrashUnavailable(ErrorKind::NotFound),
                );
            assert_eq!(
                fake.trash(&target("/h/ro"), &no()),
                Err(TrashError::PermissionDenied)
            );
            assert_eq!(fake.trash(&target("/h/gone"), &no()), Err(TrashError::Gone));
            assert_eq!(
                fake.trash(&target("/h/trash"), &no()),
                Err(TrashError::TrashUnavailable(ErrorKind::NotFound))
            );
            assert!(fake.trash(&target("/h/fine"), &no()).is_ok());
            // The failed paths were asked for too.
            assert_eq!(fake.calls().len(), 4);
        }

        #[test]
        fn it_can_move_the_wrong_entry() {
            let mut fake = FakeTrash::new();
            fake.move_the_wrong_entry("/h/swapped");
            assert_eq!(
                fake.trash(&target("/h/swapped"), &no()),
                Err(TrashError::Misplaced {
                    trash_name: "swapped".into(),
                    restored: false
                })
            );
        }

        #[test]
        fn it_stops_on_the_cancel_flag_before_moving() {
            let fake = FakeTrash::new();
            let cancelled = AtomicBool::new(true);
            assert_eq!(
                fake.trash(&target("/h/a"), &cancelled),
                Err(TrashError::Cancelled)
            );
        }
    }
}
