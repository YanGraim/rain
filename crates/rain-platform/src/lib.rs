//! Rain platform adapters (macOS, Linux for CI).

use std::fmt;
use std::path::PathBuf;

// Only the macOS layout and the fake use it; other OSes have no adapter yet.
#[cfg(any(test, feature = "testing", target_os = "macos"))]
mod home;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod tools;

#[cfg(any(test, feature = "testing"))]
mod fake;

#[cfg(any(test, feature = "testing"))]
pub use fake::FakePlatform;
#[cfg(target_os = "macos")]
pub use macos::{MacPlatform, ProcessEnv, RealProcessEnv};
#[cfg(unix)]
pub use tools::{ProcessToolRunner, RunError, RunOutput, RunRequest, Tool, MAX_STDOUT_BYTES};

/// Crate version, shared across the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Operating systems Rain knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Macos,
    Linux,
    Windows,
}

/// Well-known roots that rules are expressed against (`{home}`, `{caches}`, `{logs}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Root {
    Home,
    Caches,
    Logs,
}

/// Why the home directory could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    HomeMissing,
    HomeEmpty,
    HomeNotAbsolute(PathBuf),
    HomeNotFound(PathBuf),
    HomeNotADirectory(PathBuf),
    HomeNotAccessible(PathBuf),
    HomeIsFilesystemRoot(PathBuf),
}

impl fmt::Display for PlatformError {
    // Developer-facing text only; the CLI maps variants to localized messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HomeMissing => write!(f, "home directory is not set"),
            Self::HomeEmpty => write!(f, "home directory is empty"),
            Self::HomeNotAbsolute(p) => {
                write!(f, "home directory is not absolute: {}", p.display())
            }
            Self::HomeNotFound(p) => write!(f, "home directory does not exist: {}", p.display()),
            Self::HomeNotADirectory(p) => {
                write!(f, "home directory is not a directory: {}", p.display())
            }
            Self::HomeNotAccessible(p) => {
                write!(f, "home directory is not accessible: {}", p.display())
            }
            Self::HomeIsFilesystemRoot(p) => {
                write!(f, "home directory is the filesystem root: {}", p.display())
            }
        }
    }
}

impl std::error::Error for PlatformError {}

/// OS adapter: resolves roots and reports process facts.
pub trait Platform: Send + Sync {
    /// Resolves a root. An unusable home is an error, never a fallback.
    fn resolve(&self, root: Root) -> Result<PathBuf, PlatformError>;
    fn is_root_user(&self) -> bool;
    fn os(&self) -> Os;
}
