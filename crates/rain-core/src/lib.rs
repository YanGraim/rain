//! Rain core: scanner, rules and protection list.

pub mod clock;
pub mod fs;
pub mod messages;
pub mod model;
pub mod plan;
pub mod planner;
pub mod protect;
mod providers;
pub mod revalidate;
pub mod rule;
pub mod rules;
pub mod size;
#[cfg(any(test, feature = "testing"))]
pub mod testkit;
pub mod tools;
pub mod trash;
pub mod walk;

/// Crate version, shared across the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
