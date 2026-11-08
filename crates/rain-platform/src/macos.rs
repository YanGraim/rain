//! macOS adapter.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::{home, Os, Platform, PlatformError, Root};

/// Real macOS platform. The home value and effective uid are injected so the
/// adapter can be tested without depending on the developer's environment.
#[derive(Debug, Clone)]
pub struct MacPlatform {
    home: Option<OsString>,
    effective_uid: u32,
}

impl MacPlatform {
    pub fn new(home: Option<OsString>, effective_uid: u32) -> Self {
        Self {
            home,
            effective_uid,
        }
    }
}

impl Platform for MacPlatform {
    fn resolve(&self, root: Root) -> Result<PathBuf, PlatformError> {
        let home = home::validate_on_disk(self.home.as_deref())?;
        Ok(home::macos_root(home, root))
    }

    fn is_root_user(&self) -> bool {
        self.effective_uid == 0
    }

    fn os(&self) -> Os {
        Os::Macos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FR-015
    #[test]
    fn resolves_home_caches_logs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = std::fs::canonicalize(dir.path()).expect("canonicalize");
        let p = MacPlatform::new(Some(dir.path().as_os_str().to_owned()), 501);
        assert_eq!(p.resolve(Root::Home), Ok(home.clone()));
        assert_eq!(
            p.resolve(Root::Caches),
            Ok(home.join("Library").join("Caches"))
        );
        assert_eq!(p.resolve(Root::Logs), Ok(home.join("Library").join("Logs")));
        assert_eq!(p.os(), Os::Macos);
        assert!(!p.is_root_user());
    }

    // FR-015
    #[test]
    fn invalid_home_is_error_for_every_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("gone");
        let p = MacPlatform::new(Some(missing.clone().into_os_string()), 501);
        for root in [Root::Home, Root::Caches, Root::Logs] {
            assert_eq!(
                p.resolve(root),
                Err(PlatformError::HomeNotFound(missing.clone()))
            );
        }
        let p = MacPlatform::new(None, 501);
        assert_eq!(p.resolve(Root::Caches), Err(PlatformError::HomeMissing));
    }

    // NFR-007
    #[test]
    fn uid_zero_is_root() {
        assert!(MacPlatform::new(None, 0).is_root_user());
    }
}
