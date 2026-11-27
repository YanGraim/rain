//! The cleaning log: an append-only file of JSON lines (ADR 0006 §5).
//!
//! The core decides what a line says and hands over the finished line; this
//! module only writes it. The file is created 0600 inside a folder that must
//! be 0700 and owned by the user, and opened without following a link. Every
//! write is one `write` call; a line counts as recorded only after the disk
//! has been told to flush (`F_FULLFSYNC` on macOS, which `fsync` does not do).

use rustix::fs::{fstat, openat, FileType, Mode, OFlags, RawMode};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

/// A log that is not safe to write to, or a line that could not be written.
#[derive(Debug, PartialEq, Eq)]
pub enum LogError {
    /// The folder is a link, belongs to someone else, or is not 0700.
    UnsafeFolder,
    /// The file is a link, not a regular file, not the user's, or not 0600.
    UnsafeFile,
    /// The line is not one line of text (it has a newline in it).
    NotOneLine,
    /// The system refused.
    Io(io::ErrorKind),
}

/// The append-only log file.
#[derive(Debug)]
pub struct CleanLogFile {
    path: PathBuf,
}

impl CleanLogFile {
    /// The log at `path`. The folder must exist and be safe; nothing is
    /// created here (the first write creates the file).
    pub fn open(path: impl Into<PathBuf>) -> Result<CleanLogFile, LogError> {
        let path = path.into();
        let dir = path.parent().ok_or(LogError::UnsafeFolder)?;
        open_dir(dir)?;
        Ok(CleanLogFile { path })
    }

    /// Appends one line with one `write` call. The caller syncs (see
    /// [`Self::sync`]) when the line has to be on disk.
    pub fn append(&self, line: &str) -> Result<(), LogError> {
        if line.contains('\n') || line.contains('\r') {
            return Err(LogError::NotOneLine);
        }
        let mut file = self.open_file()?;
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        file.write_all(buf.as_bytes())
            .map_err(|e| LogError::Io(e.kind()))
    }

    /// Flushes everything written so far to the disk (`F_FULLFSYNC`, which
    /// `fsync` does not do on macOS).
    pub fn sync(&self) -> Result<(), LogError> {
        self.sync_with(flush_to_disk)
    }

    /// Opens the file and hands its descriptor to `flush`; the real flush is
    /// the only caller-facing piece that cannot be observed in a test.
    fn sync_with<F>(&self, flush: F) -> Result<(), LogError>
    where
        F: FnOnce(std::os::fd::BorrowedFd<'_>) -> rustix::io::Result<()>,
    {
        let file = self.open_file()?;
        flush(file.as_fd()).map_err(|e| LogError::Io(io::Error::from(e).kind()))
    }

    /// Opens the file for appending, creating it 0600 if it is missing, never
    /// following a link, and refusing anything that is not a plain file the
    /// user owns with exactly 0600.
    fn open_file(&self) -> Result<File, LogError> {
        let dir = self.path.parent().ok_or(LogError::UnsafeFolder)?;
        let name = self.path.file_name().ok_or(LogError::UnsafeFolder)?;
        let dirfd = open_dir(dir)?;
        let fd: OwnedFd = openat(
            &dirfd,
            name,
            OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| match e {
            rustix::io::Errno::LOOP | rustix::io::Errno::MLINK => LogError::UnsafeFile,
            other => LogError::Io(io::Error::from(other).kind()),
        })?;
        let st = fstat(&fd).map_err(|e| LogError::Io(io::Error::from(e).kind()))?;
        if !log_file_is_safe(st.st_mode, st.st_uid, rustix::process::getuid().as_raw()) {
            return Err(LogError::UnsafeFile);
        }
        Ok(File::from(fd))
    }

    /// The file this log writes.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Asks the system to put the bytes on disk. macOS needs `F_FULLFSYNC`
/// (`fsync` only reaches the drive cache); other systems use `fsync`.
#[cfg(target_os = "macos")]
fn flush_to_disk(fd: std::os::fd::BorrowedFd<'_>) -> rustix::io::Result<()> {
    rustix::fs::fcntl_fullfsync(fd)
}

#[cfg(not(target_os = "macos"))]
fn flush_to_disk(fd: std::os::fd::BorrowedFd<'_>) -> rustix::io::Result<()> {
    rustix::fs::fsync(fd)
}

/// The rule for the log file: a regular file, the user's, exactly 0600.
fn log_file_is_safe(mode: RawMode, owner: u32, me: u32) -> bool {
    FileType::from_raw_mode(mode) == FileType::RegularFile && owner == me && mode & 0o777 == 0o600
}

/// The folder: a real directory the user owns, with exactly 0700, opened
/// without following a link.
fn open_dir(dir: &Path) -> Result<OwnedFd, LogError> {
    let fd = openat(
        rustix::fs::CWD,
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| LogError::UnsafeFolder)?;
    let st = fstat(&fd).map_err(|_| LogError::UnsafeFolder)?;
    if st.st_uid != rustix::process::getuid().as_raw() || st.st_mode & 0o777 != 0o700 {
        return Err(LogError::UnsafeFolder);
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    // Tests build throwaway folders inside a tempdir sandbox only.
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// A folder for the log in a throwaway tempdir, with the mode given.
    fn folder(mode: u32) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("Rain");
        std::fs::create_dir(&logs).unwrap();
        std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(mode)).unwrap();
        (dir, logs.join("clean.jsonl"))
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_line_is_appended_and_the_file_is_0600() {
        let (_dir, path) = folder(0o700);
        let log = CleanLogFile::open(&path).unwrap();
        log.append(r#"{"v":1,"event":"run_started"}"#).unwrap();
        log.sync().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"v\":1,\"event\":\"run_started\"}\n"
        );
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn lines_only_grow_and_keep_their_order() {
        let (_dir, path) = folder(0o700);
        let log = CleanLogFile::open(&path).unwrap();
        for n in 0..5 {
            log.append(&format!("{{\"n\":{n}}}")).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            [
                "{\"n\":0}",
                "{\"n\":1}",
                "{\"n\":2}",
                "{\"n\":3}",
                "{\"n\":4}"
            ]
        );
        // A second handle appends to the same file, never truncates it.
        CleanLogFile::open(&path)
            .unwrap()
            .append("{\"n\":5}")
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 6);
    }

    #[test]
    fn a_newline_inside_a_line_is_refused() {
        let (_dir, path) = folder(0o700);
        let log = CleanLogFile::open(&path).unwrap();
        assert_eq!(
            log.append("{\"a\":1}\n{\"b\":2}"),
            Err(LogError::NotOneLine)
        );
        assert!(!path.exists() || std::fs::read_to_string(&path).unwrap().is_empty());
    }

    #[test]
    fn a_folder_that_is_not_0700_is_refused_before_anything_is_written() {
        for mode in [0o755, 0o750, 0o777] {
            let (_dir, path) = folder(mode);
            assert_eq!(
                CleanLogFile::open(&path).unwrap_err(),
                LogError::UnsafeFolder,
                "{mode:o}"
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn a_folder_that_is_a_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("Rain");
        symlink(&real, &link).unwrap();
        assert_eq!(
            CleanLogFile::open(link.join("clean.jsonl")).unwrap_err(),
            LogError::UnsafeFolder
        );
    }

    #[test]
    fn a_file_that_is_a_link_is_never_followed() {
        let (dir, path) = folder(0o700);
        let victim = dir.path().join("elsewhere.txt");
        std::fs::write(&victim, "keep me\n").unwrap();
        // Owned by the user and 0600: only the no-follow flag can refuse it.
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&victim, &path).unwrap();
        let log = CleanLogFile::open(&path).unwrap();
        assert_eq!(log.append("{\"a\":1}"), Err(LogError::UnsafeFile));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me\n");
    }

    #[test]
    fn a_log_file_is_only_one_the_user_owns_as_a_regular_file_with_0600() {
        const REGULAR: RawMode = 0o100000;
        const DIR: RawMode = 0o040000;
        const LINK: RawMode = 0o120000;
        assert!(log_file_is_safe(REGULAR | 0o600, 501, 501));
        // Someone else's file: refused even with the right mode.
        assert!(!log_file_is_safe(REGULAR | 0o600, 0, 501));
        assert!(!log_file_is_safe(REGULAR | 0o600, 502, 501));
        // Not a regular file, whatever the mode.
        assert!(!log_file_is_safe(DIR | 0o600, 501, 501));
        assert!(!log_file_is_safe(LINK | 0o600, 501, 501));
        // Right owner and type, wrong mode.
        assert!(!log_file_is_safe(REGULAR | 0o644, 501, 501));
        assert!(!log_file_is_safe(REGULAR | 0o660, 501, 501));
    }

    #[test]
    fn sync_asks_the_system_to_flush_the_file_it_writes() {
        let (_dir, path) = folder(0o700);
        let log = CleanLogFile::open(&path).unwrap();
        log.append("{\"a\":1}").unwrap();
        let mut asked = false;
        log.sync_with(|fd| {
            asked = true;
            assert_eq!(fstat(fd).unwrap().st_size, 8);
            Ok(())
        })
        .unwrap();
        assert!(asked, "the flush was never requested");
    }

    #[test]
    fn a_failed_flush_is_reported_not_hidden() {
        let (_dir, path) = folder(0o700);
        let log = CleanLogFile::open(&path).unwrap();
        log.append("{\"a\":1}").unwrap();
        let err = log.sync_with(|_| Err(rustix::io::Errno::IO)).unwrap_err();
        assert_eq!(
            err,
            LogError::Io(io::Error::from(rustix::io::Errno::IO).kind())
        );
    }

    #[test]
    fn a_folder_with_group_or_other_access_or_no_owner_access_is_refused() {
        for mode in [0o600, 0o500, 0o650] {
            let (_dir, path) = folder(mode);
            assert_eq!(
                CleanLogFile::open(&path).unwrap_err(),
                LogError::UnsafeFolder,
                "{mode:o}"
            );
        }
    }

    #[test]
    fn a_file_with_group_or_other_access_or_executable_is_refused() {
        for mode in [0o644, 0o700, 0o660] {
            let (_dir, path) = folder(0o700);
            std::fs::write(&path, "x\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let log = CleanLogFile::open(&path).unwrap();
            assert_eq!(
                log.append("{\"a\":1}"),
                Err(LogError::UnsafeFile),
                "{mode:o}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "x\n");
        }
    }

    #[test]
    fn a_file_with_another_mode_is_refused() {
        let (_dir, path) = folder(0o700);
        std::fs::write(&path, "x\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let log = CleanLogFile::open(&path).unwrap();
        assert_eq!(log.append("{\"a\":1}"), Err(LogError::UnsafeFile));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x\n");
    }
}
