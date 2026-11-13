//! Bridges the core's [`ToolRunner`] to the real process runner in
//! `rain-platform` (ADR 0004 §4). Only maps types; all the safety lives in
//! `ProcessToolRunner`.

use rain_core::tools::{ExitStatusKind, ToolCall, ToolError, ToolId, ToolOutput, ToolRunner};
use rain_platform::{ProcessToolRunner, RunError, RunOutput, RunRequest, Tool};
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

pub struct PlatformTools {
    runner: ProcessToolRunner,
    home: PathBuf,
}

impl PlatformTools {
    pub fn new(home: PathBuf) -> Self {
        Self {
            runner: ProcessToolRunner::new(home.clone()),
            home,
        }
    }
}

impl ToolRunner for PlatformTools {
    fn run(&self, call: &ToolCall, cancel: &AtomicBool) -> Result<ToolOutput, ToolError> {
        let req = request(call, &self.home);
        self.runner.run(&req, cancel).map(output).map_err(error)
    }
}

fn tool(id: ToolId) -> Tool {
    match id {
        ToolId::Docker => Tool::Docker,
        ToolId::Podman => Tool::Podman,
        ToolId::Brew => Tool::Brew,
        ToolId::Ollama => Tool::Ollama,
        ToolId::Xcrun => Tool::Xcrun,
    }
}

fn request(call: &ToolCall, home: &std::path::Path) -> RunRequest {
    let args: Vec<OsString> = call
        .args
        .iter()
        .map(OsString::from)
        .chain(call.item_args.iter().map(|a| OsString::from(a.as_str())))
        .collect();
    RunRequest::new(tool(call.tool).candidates(home), args, call.timeout)
}

fn output(out: RunOutput) -> ToolOutput {
    ToolOutput {
        status: match out.code {
            Some(0) => ExitStatusKind::Success,
            Some(code) => ExitStatusKind::Code(code),
            None => ExitStatusKind::Signal,
        },
        stdout: out.stdout,
        stderr_len: out.stderr_len,
    }
}

fn error(e: RunError) -> ToolError {
    match e {
        RunError::NotInstalled => ToolError::NotInstalled,
        RunError::Timeout => ToolError::Timeout,
        RunError::Cancelled => ToolError::Cancelled,
        RunError::OutputTooLarge => ToolError::OutputTooLarge,
        // Strict parsers could not read it either: fail closed.
        RunError::InvalidOutput => ToolError::Io(io::ErrorKind::InvalidData),
        RunError::Io(kind) => ToolError::Io(kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ADR 0004 §3: argv is passed literally, binary from the fixed list.
    #[test]
    fn request_keeps_argv_and_fixed_candidates() {
        let call = ToolCall {
            timeout: Duration::from_secs(3),
            ..ToolCall::read(ToolId::Docker, &["system", "df", "--format", "{{json .}}"])
        };
        let home = PathBuf::from("/Users/t");
        let req = request(&call, &home);
        assert_eq!(req.args, ["system", "df", "--format", "{{json .}}"]);
        assert_eq!(req.candidates, Tool::Docker.candidates(&home));
        assert_eq!(req.timeout, Duration::from_secs(3));
    }

    // FR-022: exit codes and errors map one to one.
    #[test]
    fn outputs_and_errors_map() {
        let out = |code| RunOutput {
            code,
            stdout: "x".into(),
            stderr_len: 2,
        };
        assert_eq!(output(out(Some(0))).status, ExitStatusKind::Success);
        assert_eq!(output(out(Some(1))).status, ExitStatusKind::Code(1));
        assert_eq!(output(out(None)).status, ExitStatusKind::Signal);
        assert_eq!(output(out(Some(0))).stderr_len, 2);
        assert_eq!(error(RunError::NotInstalled), ToolError::NotInstalled);
        assert_eq!(error(RunError::Timeout), ToolError::Timeout);
        assert_eq!(error(RunError::Cancelled), ToolError::Cancelled);
        assert_eq!(error(RunError::OutputTooLarge), ToolError::OutputTooLarge);
        assert_eq!(
            error(RunError::InvalidOutput),
            ToolError::Io(io::ErrorKind::InvalidData)
        );
    }
}
