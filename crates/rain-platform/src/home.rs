//! Home validation shared by every adapter.

use std::ffi::OsStr;
#[cfg(any(test, target_os = "macos"))]
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::{PlatformError, Root};

/// Checks the shape of a home value without touching the disk.
pub(crate) fn validate_shape(raw: Option<&OsStr>) -> Result<PathBuf, PlatformError> {
    let raw = raw.ok_or(PlatformError::HomeMissing)?;
    if raw.is_empty() {
        return Err(PlatformError::HomeEmpty);
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(PlatformError::HomeNotAbsolute(path));
    }
    if is_filesystem_root(&path) {
        return Err(PlatformError::HomeIsFilesystemRoot(path));
    }
    Ok(path)
}

/// A path with no named component is a filesystem root (`/`, `C:\`), and a
/// scan rooted there would cover the whole disk.
fn is_filesystem_root(path: &Path) -> bool {
    !path.components().any(|c| matches!(c, Component::Normal(_)))
}

#[cfg(any(test, target_os = "macos"))]
/// Checks shape, then that the home exists and is a directory, and returns
/// its canonical form so `..`, trailing slashes and links cannot widen the scan.
pub(crate) fn validate_on_disk(raw: Option<&OsStr>) -> Result<PathBuf, PlatformError> {
    let path = validate_shape(raw)?;
    // Follows a symlinked home on purpose: the home itself is the user's choice;
    // the walker is what must never follow links below it.
    let canonical = match std::fs::canonicalize(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Err(PlatformError::HomeNotAccessible(path))
        }
        Err(_) => return Err(PlatformError::HomeNotFound(path)),
    };
    if is_filesystem_root(&canonical) {
        return Err(PlatformError::HomeIsFilesystemRoot(path));
    }
    match std::fs::metadata(&canonical) {
        Ok(m) if m.is_dir() => Ok(canonical),
        Ok(_) => Err(PlatformError::HomeNotADirectory(path)),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            Err(PlatformError::HomeNotAccessible(path))
        }
        Err(_) => Err(PlatformError::HomeNotFound(path)),
    }
}

/// Maps a root onto the macOS layout below a validated home.
pub(crate) fn macos_root(home: PathBuf, root: Root) -> PathBuf {
    match root {
        Root::Home => home,
        Root::Caches => home.join("Library").join("Caches"),
        Root::Logs => home.join("Library").join("Logs"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    // FR-015
    #[test]
    fn invalid_home_is_error() {
        assert_eq!(validate_shape(None), Err(PlatformError::HomeMissing));
        assert_eq!(
            validate_shape(Some(OsStr::new(""))),
            Err(PlatformError::HomeEmpty)
        );
        assert_eq!(
            validate_shape(Some(OsStr::new("relative/home"))),
            Err(PlatformError::HomeNotAbsolute(PathBuf::from(
                "relative/home"
            )))
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope");
        assert_eq!(
            validate_on_disk(Some(missing.as_os_str())),
            Err(PlatformError::HomeNotFound(missing.clone()))
        );
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        assert_eq!(
            validate_on_disk(Some(file.as_os_str())),
            Err(PlatformError::HomeNotADirectory(file.clone()))
        );
        let ok = OsString::from(dir.path());
        assert_eq!(validate_on_disk(Some(&ok)), Ok(canonical(dir.path())));
    }

    fn canonical(p: &std::path::Path) -> PathBuf {
        std::fs::canonicalize(p).expect("canonicalize")
    }

    // FR-015
    #[test]
    fn tilde_is_not_absolute() {
        assert_eq!(
            validate_shape(Some(OsStr::new("~"))),
            Err(PlatformError::HomeNotAbsolute(PathBuf::from("~")))
        );
    }

    // FR-015
    #[test]
    fn filesystem_root_home_is_error() {
        assert_eq!(
            validate_shape(Some(OsStr::new("/"))),
            Err(PlatformError::HomeIsFilesystemRoot(PathBuf::from("/")))
        );
        assert_eq!(
            validate_on_disk(Some(OsStr::new("/"))),
            Err(PlatformError::HomeIsFilesystemRoot(PathBuf::from("/")))
        );
    }

    // FR-015
    #[cfg(unix)]
    #[test]
    fn symlink_to_filesystem_root_is_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("home");
        std::os::unix::fs::symlink("/", &link).expect("symlink");
        assert_eq!(
            validate_on_disk(Some(link.as_os_str())),
            Err(PlatformError::HomeIsFilesystemRoot(link.clone()))
        );
        let dotted = dir.path().join("a/../../../../../../../../../../..");
        std::fs::create_dir(dir.path().join("a")).expect("mkdir");
        assert_eq!(
            validate_on_disk(Some(dotted.as_os_str())),
            Err(PlatformError::HomeIsFilesystemRoot(dotted.clone()))
        );
    }

    // FR-015
    #[test]
    fn home_resolves_to_canonical_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("user");
        std::fs::create_dir_all(real.join("sub")).expect("mkdir");
        let expected = canonical(&real);

        let dotted = real.join("sub").join("..");
        assert_eq!(
            validate_on_disk(Some(dotted.as_os_str())),
            Ok(expected.clone())
        );

        let mut slash = real.clone().into_os_string();
        slash.push("/");
        assert_eq!(validate_on_disk(Some(&slash)), Ok(expected.clone()));
    }

    // FR-015
    #[cfg(unix)]
    #[test]
    fn symlinked_home_resolves_to_canonical_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert_eq!(
            validate_on_disk(Some(link.as_os_str())),
            Ok(canonical(&real))
        );
    }

    // FR-015
    #[cfg(unix)]
    #[test]
    fn permission_denied_is_not_accessible() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let locked = dir.path().join("locked");
        let home = locked.join("home");
        std::fs::create_dir_all(&home).expect("mkdir");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        // Root ignores permission bits; the scenario cannot be reproduced then.
        let as_root = std::fs::read_dir(&locked).is_ok();
        let got = validate_on_disk(Some(home.as_os_str()));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("chmod back");
        if as_root {
            return;
        }
        assert_eq!(got, Err(PlatformError::HomeNotAccessible(home.clone())));
    }
}
