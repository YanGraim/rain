//! FR-009: on a case-insensitive APFS volume, a `--path` that differs from
//! the home only by letter case is still inside the home (not exit 2).
#![cfg(target_os = "macos")]

use std::process::Command;

#[allow(clippy::disallowed_methods)]
fn is_case_insensitive(dir: &std::path::Path) -> bool {
    std::fs::write(dir.join("probe"), b"").expect("write");
    dir.join("PROBE").exists()
}

// FR-009
#[test]
#[allow(clippy::disallowed_methods)]
fn path_with_different_case_is_inside_home() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("tempdir");
    if !is_case_insensitive(dir.path()) {
        eprintln!("case-sensitive volume, skipping");
        return;
    }
    let home = dir.path().join("Home");
    std::fs::create_dir_all(home.join("Code")).expect("mkdir");
    for p in [dir.path().join("home"), dir.path().join("HOME/code")] {
        let out = Command::new(env!("CARGO_BIN_EXE_rain"))
            // File rules only: tests never run real Docker (ADR 0004).
            .args(["scan", "--rule", "proj.node-modules", "--path"])
            .arg(&p)
            .env("HOME", &home)
            .env_remove("SUDO_UID")
            .output()
            .expect("run");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_ne!(out.status.code(), Some(2), "{}: {err}", p.display());
        assert_eq!(out.status.code(), Some(0), "{}: {err}", p.display());
    }
}
