//! The workspace compiles and its crates link together.

use std::process::Command;

#[test]
// Spawns only the freshly built `rain` binary, which does nothing yet.
#[allow(clippy::disallowed_methods)]
fn workspace_builds() {
    // Library crates are linkable from the binary's test harness.
    assert_eq!(rain_core::VERSION, env!("CARGO_PKG_VERSION"));
    assert_eq!(rain_platform::VERSION, env!("CARGO_PKG_VERSION"));

    // The `rain` binary was built and runs.
    let status = Command::new(env!("CARGO_BIN_EXE_rain"))
        .status()
        .expect("rain binary should run");
    assert!(status.success());
}
