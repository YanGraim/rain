//! In-memory platform for tests: never touches the disk.

use std::path::PathBuf;

use crate::{home, Os, Platform, PlatformError, Root};

/// Test platform with a configurable home, root flag and OS.
#[derive(Debug, Clone)]
pub struct FakePlatform {
    pub home: Option<PathBuf>,
    pub root: bool,
    pub os: Os,
}

impl Platform for FakePlatform {
    fn resolve(&self, root: Root) -> Result<PathBuf, PlatformError> {
        let home = home::validate_shape(self.home.as_deref().map(|p| p.as_os_str()))?;
        Ok(home::macos_root(home, root))
    }

    fn is_root_user(&self) -> bool {
        self.root
    }

    fn os(&self) -> Os {
        self.os
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(home: Option<&str>) -> FakePlatform {
        FakePlatform {
            home: home.map(PathBuf::from),
            root: false,
            os: Os::Macos,
        }
    }

    // FR-015
    #[test]
    fn fake_resolves_home_caches_logs() {
        let p = fake(Some("/Users/test"));
        assert_eq!(p.resolve(Root::Home), Ok(PathBuf::from("/Users/test")));
        assert_eq!(
            p.resolve(Root::Caches),
            Ok(PathBuf::from("/Users/test/Library/Caches"))
        );
        assert_eq!(
            p.resolve(Root::Logs),
            Ok(PathBuf::from("/Users/test/Library/Logs"))
        );
        assert_eq!(p.os(), Os::Macos);
    }

    // FR-015
    #[test]
    fn fake_invalid_home_is_error() {
        assert_eq!(
            fake(None).resolve(Root::Logs),
            Err(PlatformError::HomeMissing)
        );
        assert_eq!(
            fake(Some("")).resolve(Root::Home),
            Err(PlatformError::HomeEmpty)
        );
        assert_eq!(
            fake(Some("rel")).resolve(Root::Caches),
            Err(PlatformError::HomeNotAbsolute(PathBuf::from("rel")))
        );
        assert_eq!(
            fake(Some("/")).resolve(Root::Home),
            Err(PlatformError::HomeIsFilesystemRoot(PathBuf::from("/")))
        );
    }

    // NFR-007
    #[test]
    fn fake_root_flag_is_reported() {
        let p = FakePlatform {
            root: true,
            ..fake(Some("/Users/test"))
        };
        assert!(p.is_root_user());
    }
}
