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

/// The real filesystem, read-only.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdFs;

impl Fs for StdFs {
    fn symlink_metadata(&self, p: &Path) -> io::Result<Metadata> {
        from_std(&std::fs::symlink_metadata(p)?)
    }

    fn read_dir(&self, p: &Path) -> io::Result<Vec<DirEntryInfo>> {
        std::fs::read_dir(p)?
            .map(|e| e.map(|e| DirEntryInfo { path: e.path() }))
            .collect()
    }

    fn canonicalize(&self, p: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(p)
    }
}

#[cfg(unix)]
fn from_std(m: &std::fs::Metadata) -> io::Result<Metadata> {
    with_mtime(m, m.modified())
}

// Without a real device and inode, hard-link dedupe and the same-volume
// check cannot be trusted, so refuse instead of inventing an identity.
#[cfg(not(unix))]
fn from_std(_m: &std::fs::Metadata) -> io::Result<Metadata> {
    Err(io::ErrorKind::Unsupported.into())
}

/// An unreadable mtime is an error, never a default: a made-up date would
/// make age-based rules select files they should skip.
#[cfg(unix)]
fn with_mtime(m: &std::fs::Metadata, mtime: io::Result<SystemTime>) -> io::Result<Metadata> {
    use std::os::unix::fs::MetadataExt;
    Ok(Metadata {
        is_dir: m.is_dir(),
        is_symlink: m.file_type().is_symlink(),
        dev: m.dev(),
        ino: m.ino(),
        nlink: m.nlink(),
        blocks: m.blocks(),
        len: m.len(),
        mtime: mtime?,
    })
}

#[cfg(any(test, feature = "testing"))]
pub use fake::FakeFs;
#[cfg(test)]
use fake::Realpath;

#[cfg(any(test, feature = "testing"))]
mod fake {
    use super::{DirEntryInfo, Fs, Metadata};
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::io;
    use std::path::{Component, Path, PathBuf};
    use std::time::SystemTime;

    /// Which `realpath(3)` the fake imitates.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Realpath {
        /// Applies `.`, `..` and a trailing slash lexically, even after a
        /// file (`f/..` is the parent of `f`), and resolves at most
        /// `MAXSYMLINKS` (32) + 1 links, as measured on the real filesystem.
        Darwin,
        /// Demands a directory before `.`, `..` or a trailing slash
        /// (`ENOTDIR`) and stops at `MAXSYMLINKS` (40).
        Glibc,
    }

    impl Realpath {
        pub(crate) const HOST: Self = if cfg!(any(target_os = "macos", target_os = "ios")) {
            Self::Darwin
        } else {
            Self::Glibc
        };

        fn max_hops(self) -> usize {
            match self {
                Self::Darwin => 33,
                Self::Glibc => 40,
            }
        }
    }

    /// In-memory filesystem for tests. `symlink_metadata` and `read_dir` use
    /// exact lookups and never follow symlinks; `canonicalize` resolves
    /// symlinks, `.` and `..` like `realpath`. Every directory must be
    /// inserted explicitly, except the root, which always exists. Errors can be injected per
    /// path to simulate `EACCES`/`EPERM`.
    #[derive(Debug, Default)]
    pub struct FakeFs {
        entries: BTreeMap<PathBuf, Metadata>,
        symlinks: BTreeMap<PathBuf, PathBuf>,
        errors: BTreeMap<PathBuf, io::ErrorKind>,
    }

    enum Node<'a> {
        Dir,
        File,
        Link(&'a Path),
    }

    fn symlink_loop() -> io::Error {
        if cfg!(any(target_os = "linux", target_os = "android")) {
            io::Error::from_raw_os_error(40)
        } else if cfg!(unix) {
            io::Error::from_raw_os_error(62)
        } else {
            io::Error::other("too many levels of symbolic links")
        }
    }

    const ROOT_META: Metadata = Metadata {
        is_dir: true,
        is_symlink: false,
        dev: 0,
        ino: 0,
        nlink: 1,
        blocks: 0,
        len: 0,
        mtime: SystemTime::UNIX_EPOCH,
    };

    fn is_root(p: &Path) -> bool {
        p.has_root() && p.parent().is_none()
    }

    fn link_meta() -> Metadata {
        Metadata {
            is_dir: false,
            is_symlink: true,
            dev: 0,
            ino: 0,
            nlink: 1,
            blocks: 0,
            len: 0,
            mtime: SystemTime::UNIX_EPOCH,
        }
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

        /// Registers a symlink at `path` pointing to `target` (stored verbatim).
        pub fn insert_symlink(
            &mut self,
            path: impl Into<PathBuf>,
            target: impl Into<PathBuf>,
        ) -> &mut Self {
            let path = path.into();
            self.entries.insert(path.clone(), link_meta());
            self.symlinks.insert(path, target.into());
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
            match self.entries.get(p) {
                Some(m) => Ok(m),
                None if is_root(p) => Ok(&ROOT_META),
                None => Err(io::ErrorKind::NotFound.into()),
            }
        }

        fn node(&self, p: &Path) -> io::Result<Node<'_>> {
            let meta = self.lookup(p)?;
            if let Some(target) = self.symlinks.get(p) {
                return Ok(Node::Link(target));
            }
            Ok(if meta.is_dir { Node::Dir } else { Node::File })
        }

        /// `realpath`-style resolution over the in-memory tree.
        pub(crate) fn resolve_as(&self, p: &Path, dialect: Realpath) -> io::Result<PathBuf> {
            if !p.is_absolute() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut pending: VecDeque<OsString> = components(p);
            let mut resolved = PathBuf::new();
            let mut hops = 0;
            let mut at_file = false;
            while let Some(part) = pending.pop_front() {
                let dot = matches!(part.to_str(), Some("." | ".."));
                if at_file && !(dot && dialect == Realpath::Darwin) {
                    return Err(io::ErrorKind::NotADirectory.into());
                }
                match part.to_str() {
                    Some(".") => continue,
                    Some("..") => {
                        if resolved.parent().is_some() {
                            resolved.pop();
                        }
                        at_file = false;
                        continue;
                    }
                    _ => {}
                }
                if resolved.as_os_str().is_empty() || Path::new(&part).has_root() {
                    resolved = PathBuf::from(part);
                    self.node(&resolved)?;
                    continue;
                }
                let candidate = resolved.join(&part);
                match self.node(&candidate)? {
                    Node::Link(target) => {
                        hops += 1;
                        if hops > dialect.max_hops() {
                            return Err(symlink_loop());
                        }
                        for c in components(target).into_iter().rev() {
                            pending.push_front(c);
                        }
                        if target.has_root() {
                            resolved = PathBuf::new();
                        }
                    }
                    Node::Dir => resolved = candidate,
                    Node::File => {
                        resolved = candidate;
                        at_file = true;
                    }
                }
            }
            Ok(resolved)
        }
    }

    /// Splits a path keeping every `.` and `..` (which `Path::components`
    /// drops when not leading), with any prefix and root fused as the first
    /// element. A trailing separator, also dropped by `components`, becomes
    /// a final `.` so the last entry must be a directory.
    fn components(p: &Path) -> VecDeque<OsString> {
        let mut root = OsString::new();
        for c in p.components() {
            match c {
                Component::Prefix(_) | Component::RootDir => root.push(c.as_os_str()),
                _ => break,
            }
        }
        // Names come from `components` (no unsafe byte-to-OsStr conversion);
        // the raw segments only tell where the dropped `.` entries were.
        let mut names = p.components().filter_map(|c| match c {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => None,
            Component::ParentDir => Some(OsString::from("..")),
            Component::Normal(n) => Some(n.to_os_string()),
        });
        let raw = p.as_os_str().as_encoded_bytes();
        let rest = raw.strip_prefix(root.as_encoded_bytes()).unwrap_or(raw);
        let mut out = VecDeque::new();
        let segments = rest.split(|b| std::path::is_separator(char::from(*b)));
        for segment in segments.filter(|s| !s.is_empty()) {
            if segment == b"." {
                out.push_back(".".into());
            } else if let Some(name) = names.next() {
                out.push_back(name);
            }
        }
        // Checked before the root is added: a bare root has no last entry.
        let ends_with_separator = raw
            .last()
            .is_some_and(|b| std::path::is_separator(char::from(*b)));
        if ends_with_separator && !out.is_empty() {
            out.push_back(".".into());
        }
        if !root.is_empty() {
            out.push_front(root);
        }
        out
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
            self.resolve_as(p, Realpath::HOST)
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
        fs.insert("/r", meta(true, 1, 8, 1, 0))
            .insert("/r/mail", meta(true, 1, 9, 1, 0))
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
        fs.insert("/r", meta(true, 1, 4, 1, 0))
            .insert("/r/x", meta(false, 1, 5, 1, 1));
        assert_eq!(
            fs.canonicalize(Path::new("/r/x")).unwrap(),
            PathBuf::from("/r/x")
        );
    }

    fn dir() -> Metadata {
        meta(true, 1, 1, 1, 0)
    }

    // FR-004, FR-007: absolute, relative and chained symlinks are resolved.
    #[test]
    fn fake_canonicalize_resolves_symlink_target() {
        let mut fs = FakeFs::new();
        fs.insert("/r", dir())
            .insert("/r/a", dir())
            .insert("/r/a/f", meta(false, 1, 2, 1, 8))
            .insert("/out", dir())
            .insert_symlink("/r/abs", "/out")
            .insert_symlink("/r/rel", "a/f")
            .insert_symlink("/r/up", "../out")
            .insert_symlink("/r/chain", "rel")
            .insert_symlink("/r/via", "a")
            .insert_symlink("/r/dangling", "/missing");
        let c = |p: &str| fs.canonicalize(Path::new(p));
        assert_eq!(c("/r/abs").unwrap(), PathBuf::from("/out"));
        assert_eq!(c("/r/rel").unwrap(), PathBuf::from("/r/a/f"));
        assert_eq!(c("/r/up").unwrap(), PathBuf::from("/out"));
        assert_eq!(c("/r/chain").unwrap(), PathBuf::from("/r/a/f"));
        assert_eq!(c("/r/via/f").unwrap(), PathBuf::from("/r/a/f"));
        assert_eq!(
            c("/r/dangling").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        // The link itself is still reported, not followed.
        assert!(fs.symlink_metadata(Path::new("/r/abs")).unwrap().is_symlink);
    }

    // FR-004, FR-007: a symlink cycle fails like ELOOP instead of hanging.
    #[test]
    fn fake_canonicalize_symlink_loop_is_an_error() {
        let mut fs = FakeFs::new();
        fs.insert("/r", dir())
            .insert_symlink("/r/a", "b")
            .insert_symlink("/r/b", "a");
        let err = fs.canonicalize(Path::new("/r/a")).unwrap_err();
        assert_eq!(err.raw_os_error(), eloop_errno());
    }

    // FR-004, FR-007: `.` and `..` are resolved; `..` at the root stays there.
    #[test]
    fn fake_canonicalize_resolves_dotdot() {
        let mut fs = FakeFs::new();
        fs.insert("/r", dir())
            .insert("/r/a", dir())
            .insert("/r/b", meta(false, 1, 3, 1, 8));
        let c = |p: &str| fs.canonicalize(Path::new(p));
        assert_eq!(c("/r/a/../b").unwrap(), PathBuf::from("/r/b"));
        assert_eq!(c("/r/./a/.").unwrap(), PathBuf::from("/r/a"));
        assert_eq!(c("/../../r").unwrap(), PathBuf::from("/r"));
        assert_eq!(
            c("/r/a/../nope").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        // `..` after a file: lexical on Darwin, ENOTDIR on glibc.
        let after_file = c("/r/b/../a");
        if DARWIN {
            assert_eq!(after_file.unwrap(), PathBuf::from("/r/a"));
        } else {
            assert_eq!(after_file.unwrap_err().kind(), io::ErrorKind::NotADirectory);
        }
        assert_eq!(
            c("/r/b/x").unwrap_err().kind(),
            io::ErrorKind::NotADirectory
        );
    }

    // FR-004: read_dir lists the link itself, never the target's children.
    #[test]
    fn fake_read_dir_does_not_follow_symlinks() {
        let mut fs = FakeFs::new();
        fs.insert("/r", dir())
            .insert("/out", dir())
            .insert("/out/secret", meta(false, 1, 4, 1, 8))
            .insert_symlink("/r/link", "/out");
        let names: Vec<_> = fs
            .read_dir(Path::new("/r"))
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(names, [PathBuf::from("/r/link")]);
        assert_eq!(
            fs.read_dir(Path::new("/r/link")).unwrap_err().kind(),
            io::ErrorKind::NotADirectory
        );
    }

    // FR-004, NFR-009: a parent that was never inserted does not exist, and
    // all three operations agree on it.
    #[test]
    fn fake_uninserted_ancestor_is_not_found_everywhere() {
        let mut fs = FakeFs::new();
        fs.insert("/r/x", meta(false, 1, 5, 1, 1));
        let r = Path::new("/r");
        assert_eq!(
            fs.symlink_metadata(r).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(fs.read_dir(r).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(
            fs.canonicalize(r).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            fs.canonicalize(Path::new("/r/x")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    // FR-004, FR-007: an error injected on the root is honored too.
    #[test]
    fn fake_canonicalize_consults_root_errors() {
        let mut fs = FakeFs::new();
        fs.insert("/r", dir())
            .fail_with("/", io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs.canonicalize(Path::new("/r")).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    // FR-004, FR-007: a trailing slash demands a directory, as in realpath.
    #[test]
    fn fake_canonicalize_trailing_slash_follows_platform_realpath() {
        let mut fs = FakeFs::new();
        fs.insert("/r", dir())
            .insert("/r/a", dir())
            .insert("/r/b", meta(false, 1, 3, 1, 8));
        // Darwin ignores the slash; glibc demands a directory.
        let file = fs.canonicalize(Path::new("/r/b/"));
        if DARWIN {
            assert_eq!(file.unwrap(), PathBuf::from("/r/b"));
        } else {
            assert_eq!(file.unwrap_err().kind(), io::ErrorKind::NotADirectory);
        }
        assert_eq!(
            fs.canonicalize(Path::new("/r/a/")).unwrap(),
            PathBuf::from("/r/a")
        );
    }

    const DARWIN: bool = cfg!(any(target_os = "macos", target_os = "ios"));

    // FR-004, FR-007: with glibc semantics, `.` after a file (inside or at
    // the end of the path, through a link too) is ENOTDIR; Darwin keeps it
    // lexical. Both dialects run on every host.
    #[test]
    fn fake_dot_after_file_follows_each_realpath_dialect() {
        let mut fs = FakeFs::new();
        fs.insert("/r", dir())
            .insert("/r/b", meta(false, 1, 3, 1, 8))
            .insert("/r/w", dir())
            .insert("/r/w/pc", meta(false, 1, 4, 1, 8))
            .insert_symlink("/r/l", "w/pc/.")
            .insert_symlink("/r/slash", "b/");
        for p in [
            "/r/b/.",
            "/r/w/pc/.",
            "/r/w/pc/./",
            "/r/b/./..",
            "/r/b/",
            "/r/l",
            "/r/slash",
            "/r/w/../slash",
        ] {
            let glibc = fs.resolve_as(Path::new(p), Realpath::Glibc);
            assert_eq!(
                glibc.unwrap_err().kind(),
                io::ErrorKind::NotADirectory,
                "{p}"
            );
            assert!(fs.resolve_as(Path::new(p), Realpath::Darwin).is_ok(), "{p}");
        }
        assert_eq!(
            fs.resolve_as(Path::new("/r/w/./pc"), Realpath::Glibc)
                .unwrap(),
            PathBuf::from("/r/w/pc")
        );
    }

    fn eloop_errno() -> Option<i32> {
        if cfg!(any(target_os = "linux", target_os = "android")) {
            Some(40)
        } else if cfg!(unix) {
            Some(62)
        } else {
            None
        }
    }
}

// Fixtures need real directories, files and symlinks inside a `tempfile`
// sandbox, the only place these write calls are allowed.
#[cfg(all(test, unix))]
#[allow(clippy::disallowed_methods)]
mod real_fs_tests {
    use super::*;
    use proptest::prelude::*;
    use std::os::unix::fs::symlink;

    // Darwin's realpath(3) follows 33 links (measured); glibc follows 40.
    const HOP_LIMIT: usize = if cfg!(target_os = "macos") { 33 } else { 40 };

    /// A canonical tempdir and a FakeFs mirroring it and all its ancestors,
    /// each inserted explicitly with its real metadata.
    fn sandbox() -> (tempfile::TempDir, PathBuf, FakeFs) {
        let tmp = tempfile::tempdir().unwrap();
        let base = StdFs.canonicalize(tmp.path()).unwrap();
        let mut fake = FakeFs::new();
        for a in base.ancestors().filter(|a| a.parent().is_some()) {
            fake.insert(a, StdFs.symlink_metadata(a).unwrap());
        }
        (tmp, base, fake)
    }

    fn mkdir(fake: &mut FakeFs, p: PathBuf) {
        std::fs::create_dir(&p).unwrap();
        let m = StdFs.symlink_metadata(&p).unwrap();
        fake.insert(p, m);
    }

    fn mkfile(fake: &mut FakeFs, p: PathBuf) {
        std::fs::write(&p, b"x").unwrap();
        let m = StdFs.symlink_metadata(&p).unwrap();
        fake.insert(p, m);
    }

    fn mklink(fake: &mut FakeFs, p: PathBuf, target: &str) {
        symlink(target, &p).unwrap();
        fake.insert_symlink(p, target);
    }

    /// Same success path, or same error kind (and errno for ELOOP, which has
    /// no stable `ErrorKind`).
    fn assert_same(real: io::Result<PathBuf>, fake: io::Result<PathBuf>, what: &Path) {
        match (real, fake) {
            (Ok(r), Ok(f)) => assert_eq!(f, r, "{what:?}"),
            (Err(r), Err(f)) => {
                assert_eq!(f.kind(), r.kind(), "{what:?}: real {r}, fake {f}");
                if f.raw_os_error().is_some() {
                    assert_eq!(f.raw_os_error(), r.raw_os_error(), "{what:?}");
                }
            }
            (r, f) => panic!("{what:?}: real {r:?}, fake {f:?}"),
        }
    }

    // FR-004, FR-007: a link escaping the root canonicalizes outside it on the
    // real filesystem, and FakeFs gives the very same result.
    #[test]
    fn root_escape_detected_on_real_fs() {
        let (_tmp, base, mut fake) = sandbox();
        let root = base.join("root");
        mkdir(&mut fake, root.clone());
        mkdir(&mut fake, base.join("outside"));
        mklink(&mut fake, root.join("escape"), "../outside");
        mklink(&mut fake, root.join("abs"), "/");

        let real_escape = StdFs.canonicalize(&root.join("escape")).unwrap();
        let real_abs = StdFs.canonicalize(&root.join("abs")).unwrap();
        assert!(!real_escape.starts_with(&root));
        assert!(!real_abs.starts_with(&root));
        assert!(
            StdFs
                .symlink_metadata(&root.join("escape"))
                .unwrap()
                .is_symlink
        );
        assert_eq!(
            fake.canonicalize(&root.join("escape")).unwrap(),
            real_escape
        );
        assert_eq!(fake.canonicalize(&root.join("abs")).unwrap(), real_abs);
    }

    // FR-004, FR-007: dangling links and loops fail the same way on both.
    #[test]
    fn dangling_and_loop_errors_match_real_fs() {
        let (_tmp, root, mut fake) = sandbox();
        mklink(&mut fake, root.join("dangling"), "missing");
        mklink(&mut fake, root.join("a"), "b");
        mklink(&mut fake, root.join("b"), "a");

        let err = |fs: &dyn Fs, name: &str| fs.canonicalize(&root.join(name)).unwrap_err();
        assert_eq!(err(&StdFs, "dangling").kind(), io::ErrorKind::NotFound);
        assert_eq!(
            err(&fake, "dangling").kind(),
            err(&StdFs, "dangling").kind()
        );
        assert!(err(&fake, "a").raw_os_error().is_some());
        assert_eq!(
            err(&fake, "a").raw_os_error(),
            err(&StdFs, "a").raw_os_error()
        );
    }

    // FR-004, FR-007: a trailing slash, `.` and `..` after a file behave as
    // the platform's realpath does (lexical on Darwin, ENOTDIR on glibc).
    #[test]
    fn trailing_slash_matches_real_fs() {
        let (_tmp, root, mut fake) = sandbox();
        mkdir(&mut fake, root.join("a"));
        mkfile(&mut fake, root.join("b"));
        mklink(&mut fake, root.join("lb"), "b");
        mklink(&mut fake, root.join("la"), "a/");
        for name in ["b/", "lb/", "a/", "la", "la/", "b/.", "b/.."] {
            let p = PathBuf::from(format!("{}/{name}", root.display()));
            assert_same(StdFs.canonicalize(&p), fake.canonicalize(&p), &p);
        }
        let p = PathBuf::from(format!("{}/b/x", root.display()));
        assert_eq!(
            StdFs.canonicalize(&p).unwrap_err().kind(),
            io::ErrorKind::NotADirectory
        );
        assert_same(StdFs.canonicalize(&p), fake.canonicalize(&p), &p);
    }

    // FR-004, FR-007: the symlink hop budget is the platform's, exactly.
    #[test]
    fn symlink_hop_limit_matches_real_fs() {
        let (_tmp, root, mut fake) = sandbox();
        mkfile(&mut fake, root.join("f"));
        let n = HOP_LIMIT + 1;
        for i in 1..=n {
            let target = if i == n {
                "f".to_string()
            } else {
                format!("l{}", i + 1)
            };
            mklink(&mut fake, root.join(format!("l{i}")), &target);
        }
        // From l2 the chain is exactly the limit; from l1 one hop too many.
        let at_limit = root.join("l2");
        let over = root.join("l1");
        assert_eq!(StdFs.canonicalize(&at_limit).unwrap(), root.join("f"));
        assert_same(
            StdFs.canonicalize(&at_limit),
            fake.canonicalize(&at_limit),
            &at_limit,
        );
        assert!(StdFs.canonicalize(&over).is_err());
        assert_same(StdFs.canonicalize(&over), fake.canonicalize(&over), &over);
    }

    // FR-004: StdFs reads metadata and lists children without following links.
    #[test]
    fn std_fs_does_not_follow_symlinks() {
        let (_tmp, root, _fake) = sandbox();
        std::fs::create_dir(root.join("d")).unwrap();
        std::fs::write(root.join("d/f"), b"x").unwrap();
        symlink("d", root.join("link")).unwrap();

        let m = StdFs.symlink_metadata(&root.join("link")).unwrap();
        assert!(m.is_symlink && !m.is_dir);
        let mut names: Vec<_> = StdFs
            .read_dir(&root)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        names.sort();
        assert_eq!(names, [root.join("d"), root.join("link")]);
        let f = StdFs.symlink_metadata(&root.join("d/f")).unwrap();
        assert_eq!(f.len, 1);
        assert!(!f.is_dir && !f.is_symlink);
    }

    // FR-008: an unreadable mtime is an error, never a default date that age
    // rules could act on.
    #[test]
    fn std_fs_unreadable_mtime_is_an_error() {
        let (_tmp, root, _fake) = sandbox();
        std::fs::write(root.join("f"), b"x").unwrap();
        let m = std::fs::symlink_metadata(root.join("f")).unwrap();
        let err = with_mtime(&m, Err(io::ErrorKind::Unsupported.into())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(with_mtime(&m, m.modified()).is_ok());
    }

    const NAMES: [&str; 3] = ["pa", "pb", "pc"];
    const TARGETS: [&str; 12] = [
        "pa", "pb", "pc", "../pa", "../pb", "pa/pb", "..", ".", "missing", "pa/", "@/pa", "@/pb/pc",
    ];
    const QUERY_PARTS: [&str; 5] = ["pa", "pb", "pc", ".", ".."];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        // FR-004, FR-007: on random small trees of dirs, files and links
        // (relative, absolute, with `..`), FakeFs canonicalizes like the OS.
        #[test]
        fn real_and_fake_canonicalize_agree(
            ops in prop::collection::vec((0usize..8, 0usize..3, 0usize..3, 0usize..12), 1..12),
            queries in prop::collection::vec(
                (prop::collection::vec(0usize..5, 0..5), any::<bool>()),
                1..12,
            ),
        ) {
            let (_tmp, base, mut fake) = sandbox();
            let work = base.join("w");
            mkdir(&mut fake, work.clone());
            let mut dirs = vec![work.clone()];
            let mut taken = std::collections::BTreeSet::new();
            for (parent, name, kind, target) in ops {
                let p = dirs[parent % dirs.len()].join(NAMES[name]);
                if !taken.insert(p.clone()) {
                    continue;
                }
                match kind {
                    0 => {
                        mkdir(&mut fake, p.clone());
                        dirs.push(p);
                    }
                    1 => mkfile(&mut fake, p),
                    _ => {
                        let t = TARGETS[target].replace('@', &work.display().to_string());
                        mklink(&mut fake, p, &t);
                    }
                }
            }
            for (parts, trailing) in queries {
                let mut s = work.display().to_string();
                for i in parts {
                    s.push('/');
                    s.push_str(QUERY_PARTS[i]);
                }
                if trailing {
                    s.push('/');
                }
                let q = PathBuf::from(s);
                assert_same(StdFs.canonicalize(&q), fake.canonicalize(&q), &q);
            }
        }
    }
}
