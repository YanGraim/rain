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
    real_uid: u32,
    under_sudo: bool,
}

/// Where the process facts come from, so logic can be tested without the
/// real environment or the real uid.
pub trait ProcessEnv {
    fn var_os(&self, name: &str) -> Option<OsString>;
    fn effective_uid(&self) -> u32;
    fn real_uid(&self) -> u32;
}

/// The current process's environment and uids.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealProcessEnv;

impl ProcessEnv for RealProcessEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }

    fn effective_uid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn real_uid(&self) -> u32 {
        rustix::process::getuid().as_raw()
    }
}

impl MacPlatform {
    // Ignores the real uid and `SUDO_UID`, so it must never build a production adapter.
    #[cfg(test)]
    fn new(home: Option<OsString>, effective_uid: u32) -> Self {
        Self {
            home,
            effective_uid,
            real_uid: effective_uid,
            under_sudo: false,
        }
    }

    /// Builds the adapter from the running process.
    pub fn from_env() -> Self {
        Self::from_source(&RealProcessEnv)
    }

    /// Builds the adapter from an injected source. Production code uses
    /// [`MacPlatform::from_env`]; this exists so tests control every fact.
    pub fn from_source(env: &dyn ProcessEnv) -> Self {
        Self {
            home: env.var_os("HOME"),
            effective_uid: env.effective_uid(),
            real_uid: env.real_uid(),
            // `sudo` may keep the caller's HOME, so its marker alone is enough
            // to treat the run as privileged.
            under_sudo: env.var_os("SUDO_UID").is_some(),
        }
    }
}

impl Platform for MacPlatform {
    fn resolve(&self, root: Root) -> Result<PathBuf, PlatformError> {
        let home = home::validate_on_disk(self.home.as_deref())?;
        Ok(home::macos_root(home, root))
    }

    fn is_root_user(&self) -> bool {
        self.effective_uid == 0 || self.real_uid == 0 || self.under_sudo
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

    struct FakeEnv {
        home: Option<OsString>,
        sudo_uid: Option<OsString>,
        effective_uid: u32,
        real_uid: u32,
    }

    impl ProcessEnv for FakeEnv {
        fn var_os(&self, name: &str) -> Option<OsString> {
            match name {
                "HOME" => self.home.clone(),
                "SUDO_UID" => self.sudo_uid.clone(),
                _ => None,
            }
        }
        fn effective_uid(&self) -> u32 {
            self.effective_uid
        }
        fn real_uid(&self) -> u32 {
            self.real_uid
        }
    }

    fn user_env() -> FakeEnv {
        FakeEnv {
            home: None,
            sudo_uid: None,
            effective_uid: 501,
            real_uid: 501,
        }
    }

    // FR-015, NFR-007
    #[test]
    fn from_env_reads_home_and_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = MacPlatform::from_source(&FakeEnv {
            home: Some(dir.path().as_os_str().to_owned()),
            ..user_env()
        });
        let canonical = std::fs::canonicalize(dir.path()).expect("canonicalize");
        assert_eq!(p.resolve(Root::Home), Ok(canonical));
        assert!(!p.is_root_user());

        let p = MacPlatform::from_source(&FakeEnv {
            effective_uid: 0,
            ..user_env()
        });
        assert!(p.is_root_user());
        assert_eq!(p.resolve(Root::Home), Err(PlatformError::HomeMissing));
    }

    // NFR-007
    #[test]
    fn sudo_uid_counts_as_root() {
        let p = MacPlatform::from_source(&FakeEnv {
            sudo_uid: Some("501".into()),
            ..user_env()
        });
        assert!(p.is_root_user());
        // Presence is what matters, even when the value is empty.
        let p = MacPlatform::from_source(&FakeEnv {
            sudo_uid: Some(OsString::new()),
            ..user_env()
        });
        assert!(p.is_root_user());
    }

    // NFR-007
    #[test]
    fn sudo_uid_non_numeric_counts_as_root() {
        let p = MacPlatform::from_source(&FakeEnv {
            sudo_uid: Some("abc".into()),
            ..user_env()
        });
        assert!(p.is_root_user());
    }

    // FR-015: non-UTF-8 HOME is handled as raw bytes; a relative one is a
    // typed error, an absolute missing one is reported as not found. Never a panic.
    #[test]
    fn home_non_utf8_is_typed_error_not_panic() {
        use std::os::unix::ffi::OsStringExt;
        let p = MacPlatform::from_source(&FakeEnv {
            home: Some(OsString::from_vec(b"\xff".to_vec())),
            ..user_env()
        });
        assert_eq!(
            p.resolve(Root::Home),
            Err(PlatformError::HomeNotAbsolute(PathBuf::from(
                OsString::from_vec(b"\xff".to_vec())
            )))
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let mut raw = dir.path().as_os_str().to_owned().into_vec();
        raw.extend_from_slice(b"/\xff");
        let missing = OsString::from_vec(raw);
        let p = MacPlatform::from_source(&FakeEnv {
            home: Some(missing.clone()),
            ..user_env()
        });
        assert_eq!(
            p.resolve(Root::Home),
            Err(PlatformError::HomeNotFound(PathBuf::from(missing)))
        );
    }

    // NFR-007
    #[test]
    fn real_uid_zero_counts_as_root() {
        let p = MacPlatform::from_source(&FakeEnv {
            real_uid: 0,
            ..user_env()
        });
        assert!(p.is_root_user());
    }

    // NFR-007: only checks the real source agrees with the OS; no logic depends on it.
    #[test]
    fn real_process_env_reports_uids() {
        let env = RealProcessEnv;
        assert_eq!(env.effective_uid(), rustix::process::geteuid().as_raw());
        assert_eq!(env.real_uid(), rustix::process::getuid().as_raw());
    }

    // NFR-007
    #[test]
    fn uid_zero_is_root() {
        assert!(MacPlatform::new(None, 0).is_root_user());
    }
}
