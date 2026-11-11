//! Real external-tool runner (ADR 0004 §3, §4). The only place in Rain that
//! spawns processes. No shell, fixed argv, binary from a fixed allowlist,
//! clean environment, null stdin, timeout, bounded stdout, and the whole
//! process group is killed on timeout, cancel or overflow.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// stdout cap; past it the run fails with [`RunError::OutputTooLarge`].
pub const MAX_STDOUT_BYTES: usize = 4 * 1024 * 1024;

const POLL: Duration = Duration::from_millis(10);

/// Tools Rain knows how to find. Mirrors the core's closed `ToolId` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    Docker,
    Podman,
    Brew,
    Ollama,
    Xcrun,
}

impl Tool {
    /// Fixed install locations, never `PATH`: a fake `docker` in `~/bin`
    /// must not run.
    pub fn candidates(self, home: &Path) -> Vec<PathBuf> {
        let fixed: &[&str] = match self {
            Self::Docker => &[
                "/usr/local/bin/docker",
                "/opt/homebrew/bin/docker",
                "/Applications/Docker.app/Contents/Resources/bin/docker",
                "/usr/bin/docker",
            ],
            Self::Podman => &[
                "/opt/homebrew/bin/podman",
                "/usr/local/bin/podman",
                "/opt/podman/bin/podman",
                "/usr/bin/podman",
            ],
            Self::Brew => &[
                "/opt/homebrew/bin/brew",
                "/usr/local/bin/brew",
                "/home/linuxbrew/.linuxbrew/bin/brew",
            ],
            Self::Ollama => &[
                "/usr/local/bin/ollama",
                "/opt/homebrew/bin/ollama",
                "/Applications/Ollama.app/Contents/Resources/ollama",
                "/usr/bin/ollama",
            ],
            Self::Xcrun => &["/usr/bin/xcrun"],
        };
        let mut out: Vec<PathBuf> = fixed.iter().map(PathBuf::from).collect();
        if self == Self::Docker {
            out.push(home.join(".orbstack/bin/docker"));
        }
        out
    }
}

/// One run: candidates for the binary, literal argv, limits.
#[derive(Debug, Clone)]
pub struct RunRequest {
    pub candidates: Vec<PathBuf>,
    pub args: Vec<OsString>,
    pub timeout: Duration,
    pub max_stdout: usize,
}

impl RunRequest {
    pub fn new(candidates: Vec<PathBuf>, args: Vec<OsString>, timeout: Duration) -> Self {
        Self {
            candidates,
            args,
            timeout,
            max_stdout: MAX_STDOUT_BYTES,
        }
    }
}

/// What the tool printed. stderr is only counted, never kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    /// `None` when killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr_len: usize,
}

/// Why a run gave no usable output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError {
    NotInstalled,
    Timeout,
    Cancelled,
    OutputTooLarge,
    /// stdout was not UTF-8; parsers are strict, so this is fail-closed.
    InvalidOutput,
    Io(io::ErrorKind),
}

impl fmt::Display for RunError {
    // Developer-facing only; callers map variants to localized text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "tool not installed"),
            Self::Timeout => write!(f, "tool timed out"),
            Self::Cancelled => write!(f, "tool cancelled"),
            Self::OutputTooLarge => write!(f, "tool output too large"),
            Self::InvalidOutput => write!(f, "tool output is not utf-8"),
            Self::Io(k) => write!(f, "tool i/o error: {k:?}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Spawns allowlisted tools. Holds only the `HOME` handed to the child.
#[derive(Debug, Clone)]
pub struct ProcessToolRunner {
    home: PathBuf,
}

impl ProcessToolRunner {
    pub fn new(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn run(&self, req: &RunRequest, cancel: &AtomicBool) -> Result<RunOutput, RunError> {
        let bin = resolve(&req.candidates).ok_or(RunError::NotInstalled)?;
        let mut child = self.spawn(&bin, &req.args)?;
        let overflow = Arc::new(AtomicBool::new(false));
        let stdout = child
            .stdout
            .take()
            .map(|s| read_capped(s, req.max_stdout, Arc::clone(&overflow)));
        let stderr = child.stderr.take().map(count_bytes);
        let waited = wait(&mut child, req.timeout, cancel, &overflow);
        // Always reap the group: grandchildren may still hold the pipes open.
        kill_group(&mut child);
        let out = join(stdout);
        let err_len = join(stderr);
        let status = waited?;
        if overflow.load(Ordering::SeqCst) {
            return Err(RunError::OutputTooLarge);
        }
        let stdout = String::from_utf8(out?).map_err(|_| RunError::InvalidOutput)?;
        Ok(RunOutput {
            code: status.code(),
            stdout,
            stderr_len: err_len?,
        })
    }

    fn spawn(&self, bin: &Path, args: &[OsString]) -> Result<Child, RunError> {
        let mut path = OsString::from("/usr/bin:/bin");
        if let Some(dir) = bin.parent() {
            path.push(":");
            path.push(dir);
        }
        // The one sanctioned spawn in Rain (ADR 0004 §4): absolute,
        // allowlisted binary, literal argv, no shell.
        #[allow(clippy::disallowed_methods)]
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", path)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("HOMEBREW_NO_AUTO_UPDATE", "1")
            .env("HOMEBREW_NO_ANALYTICS", "1")
            .env("HOMEBREW_NO_INSTALL_FROM_API", "1")
            .env("DOCKER_CLI_HINTS", "false")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Own process group, so the whole tree can be killed at once.
            .process_group(0);
        cmd.spawn().map_err(|e| RunError::Io(e.kind()))
    }
}

/// First candidate that is absolute, canonicalizes to a regular file owned by
/// root or the current user, with no write bit for group or others.
fn resolve(candidates: &[PathBuf]) -> Option<PathBuf> {
    let me = rustix::process::getuid().as_raw();
    candidates.iter().find_map(|c| {
        if !c.is_absolute() {
            return None;
        }
        let real = std::fs::canonicalize(c).ok()?;
        let meta = std::fs::metadata(&real).ok()?;
        let owner_ok = meta.uid() == 0 || meta.uid() == me;
        let mode_ok = meta.mode() & 0o022 == 0;
        (meta.is_file() && owner_ok && mode_ok).then_some(real)
    })
}

fn wait(
    child: &mut Child,
    timeout: Duration,
    cancel: &AtomicBool,
    overflow: &AtomicBool,
) -> Result<ExitStatus, RunError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| RunError::Io(e.kind()))? {
            return Ok(status);
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(RunError::Cancelled);
        }
        if overflow.load(Ordering::SeqCst) {
            return Err(RunError::OutputTooLarge);
        }
        if Instant::now() >= deadline {
            return Err(RunError::Timeout);
        }
        thread::sleep(POLL);
    }
}

fn kill_group(child: &mut Child) {
    let pgid = rustix::process::Pid::from_child(child);
    // ESRCH just means the group is already gone.
    let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    let _ = child.wait();
}

fn read_capped(
    mut src: impl Read + Send + 'static,
    cap: usize,
    overflow: Arc<AtomicBool>,
) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = src.read(&mut chunk)?;
            if n == 0 {
                return Ok(buf);
            }
            if buf.len() + n > cap {
                overflow.store(true, Ordering::SeqCst);
                return Ok(Vec::new());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
}

fn count_bytes(mut src: impl Read + Send + 'static) -> JoinHandle<io::Result<usize>> {
    thread::spawn(move || {
        let mut total = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            let n = src.read(&mut chunk)?;
            if n == 0 {
                return Ok(total);
            }
            total = total.saturating_add(n);
        }
    })
}

fn join<T>(h: Option<JoinHandle<io::Result<T>>>) -> Result<T, RunError>
where
    T: Default,
{
    match h {
        None => Ok(T::default()),
        Some(h) => match h.join() {
            Ok(r) => r.map_err(|e| RunError::Io(e.kind())),
            Err(_) => Err(RunError::Io(io::ErrorKind::Other)),
        },
    }
}

#[cfg(test)]
mod tests {
    // Tests build throwaway scripts inside a tempdir sandbox only.
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn runner() -> ProcessToolRunner {
        ProcessToolRunner::new(PathBuf::from("/nonexistent-home"))
    }

    fn req(bin: PathBuf, args: &[&str], timeout: Duration) -> RunRequest {
        RunRequest::new(
            vec![bin],
            args.iter().map(OsString::from).collect(),
            timeout,
        )
    }

    fn go(r: &RunRequest) -> Result<RunOutput, RunError> {
        runner().run(r, &AtomicBool::new(false))
    }

    #[test]
    fn runs_allowlisted_binary_with_literal_args() {
        let out = go(&req("/bin/echo".into(), &["hi"], Duration::from_secs(5))).unwrap();
        assert_eq!(out.stdout, "hi\n");
        assert_eq!(out.code, Some(0));
    }

    #[test]
    fn binary_outside_allowlist_is_not_installed() {
        let dir = tempfile::tempdir().unwrap();
        let r = req(dir.path().join("docker"), &[], Duration::from_secs(5));
        assert_eq!(go(&r), Err(RunError::NotInstalled));
        let r = req(PathBuf::from("echo"), &["x"], Duration::from_secs(5));
        assert_eq!(
            go(&r),
            Err(RunError::NotInstalled),
            "relative path is refused"
        );
        let r = req(dir.path().to_path_buf(), &[], Duration::from_secs(5));
        assert_eq!(go(&r), Err(RunError::NotInstalled), "directory is refused");
    }

    #[test]
    fn first_usable_candidate_wins() {
        let dir = tempfile::tempdir().unwrap();
        let r = RunRequest::new(
            vec![dir.path().join("missing"), "/bin/echo".into()],
            vec!["ok".into()],
            Duration::from_secs(5),
        );
        assert_eq!(go(&r).unwrap().stdout, "ok\n");
    }

    #[test]
    fn group_writable_binary_refused() {
        let dir = tempfile::tempdir().unwrap();
        let g = script(dir.path(), "g", "echo x", 0o770);
        assert_eq!(
            go(&req(g, &[], Duration::from_secs(5))),
            Err(RunError::NotInstalled)
        );
        let o = script(dir.path(), "o", "echo x", 0o702);
        assert_eq!(
            go(&req(o, &[], Duration::from_secs(5))),
            Err(RunError::NotInstalled)
        );
        let ok = script(dir.path(), "ok", "echo x", 0o700);
        assert_eq!(
            go(&req(ok, &[], Duration::from_secs(5))).unwrap().stdout,
            "x\n"
        );
    }

    #[test]
    fn symlink_is_judged_by_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let bad = script(dir.path(), "bad", "echo x", 0o777);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&bad, &link).unwrap();
        assert_eq!(
            go(&req(link, &[], Duration::from_secs(5))),
            Err(RunError::NotInstalled)
        );
    }

    #[test]
    fn timeout_kills_child() {
        let start = Instant::now();
        let r = req("/bin/sleep".into(), &["30"], Duration::from_millis(200));
        assert_eq!(go(&r), Err(RunError::Timeout));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    fn alive(pid: i32) -> bool {
        rustix::process::Pid::from_raw(pid)
            .is_some_and(|p| rustix::process::test_kill_process(p).is_ok())
    }

    #[test]
    fn timeout_kills_the_whole_process_tree() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let s = script(
            dir.path(),
            "tree",
            &format!("/bin/sleep 30 &\necho $! > '{}'\nwait", pidfile.display()),
            0o700,
        );
        assert_eq!(
            go(&req(s, &[], Duration::from_millis(500))),
            Err(RunError::Timeout)
        );
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(pid) && Instant::now() < deadline {
            thread::sleep(POLL);
        }
        assert!(!alive(pid), "grandchild {pid} survived");
    }

    #[test]
    fn cancel_stops_the_child() {
        let cancel = AtomicBool::new(false);
        let start = Instant::now();
        let r = req("/bin/sleep".into(), &["30"], Duration::from_secs(30));
        let res = thread::scope(|s| {
            s.spawn(|| {
                thread::sleep(Duration::from_millis(200));
                cancel.store(true, Ordering::SeqCst);
            });
            runner().run(&r, &cancel)
        });
        assert_eq!(res, Err(RunError::Cancelled));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_over_limit_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let s = script(
            dir.path(),
            "big",
            "while :; do echo aaaaaaaaaaaaaaaa; done",
            0o700,
        );
        let mut r = req(s, &[], Duration::from_secs(10));
        r.max_stdout = 1024;
        assert_eq!(go(&r), Err(RunError::OutputTooLarge));
    }

    #[test]
    fn stderr_is_counted_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let s = script(dir.path(), "err", "echo secret 1>&2\necho out", 0o700);
        let out = go(&req(s, &[], Duration::from_secs(5))).unwrap();
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr_len, "secret\n".len());
    }

    #[test]
    fn env_is_cleared() {
        let out = go(&req("/usr/bin/env".into(), &[], Duration::from_secs(5))).unwrap();
        let mut keys: Vec<&str> = out
            .stdout
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            .collect();
        keys.sort_unstable();
        let mut want = vec![
            "DOCKER_CLI_HINTS",
            "HOME",
            "HOMEBREW_NO_ANALYTICS",
            "HOMEBREW_NO_AUTO_UPDATE",
            "HOMEBREW_NO_INSTALL_FROM_API",
            "LANG",
            "LC_ALL",
            "PATH",
        ];
        want.sort_unstable();
        // macOS may inject __CF_USER_TEXT_ENCODING into every process.
        keys.retain(|k| *k != "__CF_USER_TEXT_ENCODING");
        assert_eq!(keys, want);
        assert!(out.stdout.contains("HOME=/nonexistent-home\n"));
        assert!(out.stdout.contains("LC_ALL=C\n"));
        assert!(out.stdout.contains("PATH=/usr/bin:/bin"));
    }

    #[test]
    fn stdin_is_null_and_cwd_is_root() {
        let dir = tempfile::tempdir().unwrap();
        let s = script(dir.path(), "in", "cat\npwd", 0o700);
        let out = go(&req(s, &[], Duration::from_secs(5))).unwrap();
        assert_eq!(out.stdout, "/\n");
    }

    #[test]
    fn no_shell_metachar_expansion() {
        let out = go(&req(
            "/bin/echo".into(),
            &["$(touch x)", "; rm -rf ~", "`id`"],
            Duration::from_secs(5),
        ))
        .unwrap();
        assert_eq!(out.stdout, "$(touch x) ; rm -rf ~ `id`\n");
    }

    #[test]
    fn nonzero_exit_is_reported() {
        let out = go(&req("/usr/bin/false".into(), &[], Duration::from_secs(5)))
            .or_else(|_| go(&req("/bin/false".into(), &[], Duration::from_secs(5))))
            .unwrap();
        assert_eq!(out.code, Some(1));
    }

    #[test]
    fn non_utf8_stdout_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let s = script(dir.path(), "bin", "printf '\\377\\376'", 0o700);
        assert_eq!(
            go(&req(s, &[], Duration::from_secs(5))),
            Err(RunError::InvalidOutput)
        );
    }

    #[test]
    fn docker_candidates_are_absolute_and_include_orbstack() {
        let c = Tool::Docker.candidates(Path::new("/Users/u"));
        assert!(c.iter().all(|p| p.is_absolute()));
        assert!(c.contains(&PathBuf::from("/Users/u/.orbstack/bin/docker")));
        assert_eq!(
            Tool::Xcrun.candidates(Path::new("/h")),
            vec![PathBuf::from("/usr/bin/xcrun")]
        );
    }
}
