//! Rain core: scanner, rules and protection list.

pub mod clock;
pub mod fs;
pub mod messages;
pub mod protect;
pub mod size;
pub mod walk;

/// Crate version, shared across the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
