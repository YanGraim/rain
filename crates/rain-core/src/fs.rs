//! Read-only filesystem abstraction.
//!
//! The scan must never write to disk, so the trait deliberately has no
//! write, rename, remove or create methods: there is no write path to misuse.

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Metadata of an entry, read without following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub is_dir: bool,
    pub is_symlink: bool,
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    /// Allocated 512-byte blocks (`st_blocks`).
    pub blocks: u64,
    /// Logical size in bytes (`st_size`).
    pub len: u64,
    pub mtime: SystemTime,
}

/// A directory child as returned by [`Fs::read_dir`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirEntryInfo {
    pub path: PathBuf,
}

// FS-TRAIT-BEGIN
/// Read-only view of a filesystem.
pub trait Fs: Send + Sync {
    /// Never follows symlinks.
    fn symlink_metadata(&self, p: &Path) -> io::Result<Metadata>;
    fn read_dir(&self, p: &Path) -> io::Result<Vec<DirEntryInfo>>;
    fn canonicalize(&self, p: &Path) -> io::Result<PathBuf>;
}
// FS-TRAIT-END

#[cfg(any(test, feature = "testing"))]
pub use fake::FakeFs;

#[cfg(any(test, feature = "testing"))]
mod fake {
    use super::{DirEntryInfo, Fs, Metadata};
    use std::collections::BTreeMap;
    use std::io;
    use std::path::{Path, PathBuf};

    /// In-memory filesystem for tests. Paths are used verbatim (no
    /// canonicalization beyond an exact lookup), and errors can be injected
    /// per path to simulate `EACCES`/`EPERM`.
    #[derive(Debug, Default)]
    pub struct FakeFs {
        entries: BTreeMap<PathBuf, Metadata>,
        errors: BTreeMap<PathBuf, io::ErrorKind>,
    }

    impl FakeFs {
        pub fn new() -> Self {
            Self::default()
        }

        /// Registers an entry with the given metadata.
        pub fn insert(&mut self, path: impl Into<PathBuf>, meta: Metadata) -> &mut Self {
            self.entries.insert(path.into(), meta);
            self
        }

        /// Makes every access to `path` fail with `kind`.
        pub fn fail_with(&mut self, path: impl Into<PathBuf>, kind: io::ErrorKind) -> &mut Self {
            self.errors.insert(path.into(), kind);
            self
        }
    }

    impl FakeFs {
        fn lookup(&self, p: &Path) -> io::Result<&Metadata> {
            if let Some(kind) = self.errors.get(p) {
                return Err((*kind).into());
            }
            self.entries
                .get(p)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }

    impl Fs for FakeFs {
        fn symlink_metadata(&self, p: &Path) -> io::Result<Metadata> {
            self.lookup(p).copied()
        }

        fn read_dir(&self, p: &Path) -> io::Result<Vec<DirEntryInfo>> {
            if !self.lookup(p)?.is_dir {
                return Err(io::ErrorKind::NotADirectory.into());
            }
            // BTreeMap iteration is ordered, so children come out sorted.
            Ok(self
                .entries
                .keys()
                .filter(|k| k.parent() == Some(p))
                .map(|k| DirEntryInfo { path: k.clone() })
                .collect())
        }

        fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
            self.lookup(p).map(|_| p.to_path_buf())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn meta(is_dir: bool, dev: u64, ino: u64, nlink: u64, blocks: u64) -> Metadata {
        Metadata {
            is_dir,
            is_symlink: false,
            dev,
            ino,
            nlink,
            blocks,
            len: blocks * 400,
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        }
    }

    /// Method names declared in the `Fs` trait, read from this file's source.
    fn fs_trait_methods() -> Vec<String> {
        let src = include_str!("fs.rs");
        let begin = src.find("// FS-TRAIT-BEGIN").unwrap_or(0);
        let end = src.find("// FS-TRAIT-END").unwrap_or(0);
        src[begin..end]
            .split("fn ")
            .skip(1)
            .filter_map(|s| s.split('(').next())
            .map(|s| s.trim().to_string())
            .collect()
    }

    // NFR-005: the trait exposes exactly the read-only allowlist. Adding any
    // method (write or otherwise) fails here and forces a security review.
    #[test]
    fn fake_fs_has_no_write_api() {
        let mut methods = fs_trait_methods();
        methods.sort();
        assert_eq!(methods, ["canonicalize", "read_dir", "symlink_metadata"]);

        // Exhaustive impl: if the trait gained a method, this would not compile.
        struct Probe;
        impl Fs for Probe {
            fn symlink_metadata(&self, _: &Path) -> io::Result<Metadata> {
                Err(io::ErrorKind::Unsupported.into())
            }
            fn read_dir(&self, _: &Path) -> io::Result<Vec<DirEntryInfo>> {
                Err(io::ErrorKind::Unsupported.into())
            }
            fn canonicalize(&self, _: &Path) -> io::Result<PathBuf> {
                Err(io::ErrorKind::Unsupported.into())
            }
        }
        let _: &dyn Fs = &Probe;
        let _: &dyn Fs = &FakeFs::new();
    }

    // NFR-009
    #[test]
    fn fake_fs_returns_configured_blocks_ino_dev_nlink() {
        let mut fs = FakeFs::new();
        fs.insert("/home/u/a.bin", meta(false, 7, 42, 3, 16));
        let m = fs.symlink_metadata(Path::new("/home/u/a.bin")).unwrap();
        assert_eq!((m.blocks, m.ino, m.dev, m.nlink), (16, 42, 7, 3));
        assert_eq!(m.len, 16 * 400);
        assert!(!m.is_dir);
    }

    // NFR-009
    #[test]
    fn fake_fs_read_dir_lists_direct_children_sorted() {
        let mut fs = FakeFs::new();
        fs.insert("/r", meta(true, 1, 1, 1, 0))
            .insert("/r/b", meta(false, 1, 3, 1, 8))
            .insert("/r/a", meta(true, 1, 2, 1, 0))
            .insert("/r/a/deep", meta(false, 1, 4, 1, 8));
        let names: Vec<_> = fs
            .read_dir(Path::new("/r"))
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(names, [PathBuf::from("/r/a"), PathBuf::from("/r/b")]);
    }

    // NFR-009
    #[test]
    fn fake_fs_read_dir_on_file_is_not_a_directory() {
        let mut fs = FakeFs::new();
        fs.insert("/r/f", meta(false, 1, 6, 1, 8));
        let err = fs.read_dir(Path::new("/r/f")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory);
    }

    // NFR-009
    #[test]
    fn fake_fs_missing_path_is_not_found() {
        let fs = FakeFs::new();
        let err = fs.symlink_metadata(Path::new("/nope")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            fs.read_dir(Path::new("/nope")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    // NFR-009
    #[test]
    fn fake_fs_injected_error_is_returned() {
        let mut fs = FakeFs::new();
        fs.insert("/r/mail", meta(true, 1, 9, 1, 0))
            .fail_with("/r/mail", io::ErrorKind::PermissionDenied);
        for err in [
            fs.symlink_metadata(Path::new("/r/mail")).unwrap_err(),
            fs.read_dir(Path::new("/r/mail")).unwrap_err(),
            fs.canonicalize(Path::new("/r/mail")).unwrap_err(),
        ] {
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    // NFR-009
    #[test]
    fn fake_fs_canonicalize_returns_known_path() {
        let mut fs = FakeFs::new();
        fs.insert("/r/x", meta(false, 1, 5, 1, 1));
        assert_eq!(
            fs.canonicalize(Path::new("/r/x")).unwrap(),
            PathBuf::from("/r/x")
        );
    }
}
