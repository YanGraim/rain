//! The real `rain` binary, built from `MacPlatform::from_env`, refuses an
//! unusable home and `sudo` with exit 1 and scans nothing.
#![cfg(target_os = "macos")]

use std::process::Command;

// Spawns only the freshly built `rain` binary with a sandboxed environment.
#[allow(clippy::disallowed_methods)]
fn rain_scan(home: &std::path::Path, sudo: bool) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rain"));
    cmd.arg("scan").env("HOME", home).env_remove("SUDO_UID");
    if sudo {
        cmd.env("SUDO_UID", "501");
    }
    cmd.output().expect("rain binary should run")
}

// FR-015, FR-012
#[test]
fn missing_home_exits_1_without_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = rain_scan(&dir.path().join("gone"), false);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not exist"), "{err}");
}

// FR-015, NFR-007
#[test]
fn sudo_exits_1_without_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = rain_scan(dir.path(), true);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("root"), "{err}");
}
