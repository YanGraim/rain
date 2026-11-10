//! FR-011, FR-012: a real Ctrl+C on the real `rain` binary, in the middle
//! of a scan of a large sandboxed home, exits 130 and prints no report.
#![cfg(target_os = "macos")]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Fixture writes stay inside the tempdir; the binary under test only reads.
#[allow(clippy::disallowed_methods)]
/// Wide, deep tree under `~/Library/Caches` so the walk takes well over the
/// delay before SIGINT, even in release builds.
fn big_home(root: &Path) {
    let caches = root.join("Library/Caches");
    for a in 0..20 {
        for b in 0..25 {
            let d = caches.join(format!("app{a}/d{b}"));
            std::fs::create_dir_all(&d).expect("mkdir");
            for f in 0..20 {
                std::fs::write(d.join(format!("f{f}")), b"x").expect("write");
            }
        }
    }
}

#[allow(clippy::disallowed_methods)]
fn kill_int(pid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-INT", &pid.to_string()])
        .status();
}

// FR-011, FR-012
#[test]
#[allow(clippy::disallowed_methods)]
fn real_sigint_mid_scan_exits_130_with_empty_stdout() {
    // The system temp dir lives under `/private/var`, which the protect list
    // refuses, so the sandbox sits in Cargo's per-target scratch dir instead.
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("tempdir");
    big_home(dir.path());

    // Baseline: the scan itself must take long enough to be interrupted.
    let t = Instant::now();
    let full = Command::new(env!("CARGO_BIN_EXE_rain"))
        .arg("scan")
        .env("HOME", dir.path())
        .env_remove("SUDO_UID")
        .output()
        .expect("run");
    let full_time = t.elapsed();
    assert_eq!(full.status.code(), Some(0), "{full:?}");
    assert!(!full.stdout.is_empty());

    let child = Command::new(env!("CARGO_BIN_EXE_rain"))
        .arg("scan")
        .env("HOME", dir.path())
        .env_remove("SUDO_UID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    // Give main() time to install the handler, but stay well inside the scan.
    std::thread::sleep((full_time / 4).max(Duration::from_millis(20)));
    kill_int(child.id());
    let out = child.wait_with_output().expect("wait");

    assert!(
        full_time > Duration::from_millis(100),
        "fixture too small to be reliable: {full_time:?}"
    );
    assert_eq!(out.status.code(), Some(130), "{out:?}");
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
