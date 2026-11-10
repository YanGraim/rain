//! External tool contracts (ADR 0004). The core only describes commands and
//! reads their output; running a process is the injected [`ToolRunner`]'s
//! job, which lives outside the core.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Default time a tool gets before it is killed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Closed list of tools the core may ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ToolId {
    Docker,
    Podman,
    Brew,
    Ollama,
    Xcrun,
}

/// A validated argument naming one item, for `act` (M2). It has no public
/// constructor yet: in M1 nothing builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemArg(String);

impl ItemArg {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One command: a fixed argv, never a shell line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub tool: ToolId,
    pub args: &'static [&'static str],
    pub item_args: Vec<ItemArg>,
    pub timeout: Duration,
}

impl ToolCall {
    /// A read-only call with the default timeout.
    pub const fn read(tool: ToolId, args: &'static [&'static str]) -> Self {
        Self {
            tool,
            args,
            item_args: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// How the tool exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatusKind {
    Success,
    Code(i32),
    Signal,
}

/// What the tool printed. stderr is only counted: it may hold paths or
/// secrets and is never shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub status: ExitStatusKind,
    pub stdout: String,
    pub stderr_len: usize,
}

impl ToolOutput {
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            status: ExitStatusKind::Success,
            stdout: stdout.into(),
            stderr_len: 0,
        }
    }
}

/// Why a tool gave no usable output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
pub enum ToolError {
    #[error("tool not installed")]
    NotInstalled,
    #[error("tool not running")]
    NotRunning,
    #[error("tool timed out")]
    Timeout,
    #[error("tool cancelled")]
    Cancelled,
    #[error("tool output too large")]
    OutputTooLarge,
    #[error("tool needs privileges")]
    Denied,
    #[error("tool i/o error: {0:?}")]
    Io(io::ErrorKind),
}

/// Output that does not match the expected format. Never guessed around.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unexpected tool output: {0}")]
pub struct ParseError(pub &'static str);

/// One thing the tool reports (an image, a model, a simulator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderItem {
    /// Id given by the tool (image digest, model name).
    pub key: String,
    /// Display name; untrusted text, escaped by whoever prints it.
    pub label: String,
    /// Size according to the tool, not measured on disk.
    pub reported_bytes: u64,
    /// Files the tool named, if any; checked by the planner before use.
    pub paths: Vec<PathBuf>,
}

/// Side effect injected into the planner, like `Fs`.
pub trait ToolRunner: Send + Sync {
    /// Must stop the tool and return [`ToolError::Cancelled`] soon after
    /// `cancel` is raised.
    fn run(&self, call: &ToolCall, cancel: &AtomicBool) -> Result<ToolOutput, ToolError>;
}

/// Runner for scans without tools: every tool is missing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTools;

impl ToolRunner for NoTools {
    fn run(&self, _: &ToolCall, _: &AtomicBool) -> Result<ToolOutput, ToolError> {
        Err(ToolError::NotInstalled)
    }
}

#[cfg(any(test, feature = "testing"))]
pub use fake::{FakeReply, FakeToolRunner};

#[cfg(any(test, feature = "testing"))]
mod fake {
    use super::{ToolCall, ToolError, ToolId, ToolOutput, ToolRunner};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    /// A recorded answer.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FakeReply {
        Output(ToolOutput),
        Error(ToolError),
        /// Blocks until the cancel flag is raised, then `Cancelled`.
        WaitForCancel,
    }

    /// Tool runner for tests: answers each `(tool, argv)` with a recorded
    /// reply; anything else is `NotInstalled`. Records every call.
    #[derive(Debug, Default)]
    pub struct FakeToolRunner {
        replies: BTreeMap<(ToolId, Vec<&'static str>), FakeReply>,
        calls: Mutex<Vec<(ToolId, Vec<&'static str>)>>,
    }

    impl FakeToolRunner {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn reply(
            &mut self,
            tool: ToolId,
            args: &[&'static str],
            reply: FakeReply,
        ) -> &mut Self {
            self.replies.insert((tool, args.to_vec()), reply);
            self
        }

        pub fn calls(&self) -> Vec<(ToolId, Vec<&'static str>)> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }
    }

    impl ToolRunner for FakeToolRunner {
        fn run(&self, call: &ToolCall, cancel: &AtomicBool) -> Result<ToolOutput, ToolError> {
            let key = (call.tool, call.args.to_vec());
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(key.clone());
            }
            match self.replies.get(&key) {
                Some(FakeReply::Output(out)) => Ok(out.clone()),
                Some(FakeReply::Error(e)) => Err(*e),
                Some(FakeReply::WaitForCancel) => {
                    while !cancel.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(ToolError::Cancelled)
                }
                None => Err(ToolError::NotInstalled),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tools::ToolCall;

        const PS: ToolCall = ToolCall::read(ToolId::Docker, &["ps"]);

        // FR-022
        #[test]
        fn unknown_call_is_not_installed_and_recorded() {
            let fake = FakeToolRunner::new();
            assert_eq!(
                fake.run(&PS, &AtomicBool::new(false)),
                Err(ToolError::NotInstalled)
            );
            assert_eq!(fake.calls(), vec![(ToolId::Docker, vec!["ps"])]);
        }

        // FR-022
        #[test]
        fn recorded_reply_is_returned() {
            let mut fake = FakeToolRunner::new();
            fake.reply(
                ToolId::Docker,
                &["ps"],
                FakeReply::Output(ToolOutput::success("x")),
            )
            .reply(
                ToolId::Podman,
                &["ps"],
                FakeReply::Error(ToolError::Timeout),
            );
            let no = AtomicBool::new(false);
            assert_eq!(fake.run(&PS, &no), Ok(ToolOutput::success("x")));
            let podman = ToolCall::read(ToolId::Podman, &["ps"]);
            assert_eq!(fake.run(&podman, &no), Err(ToolError::Timeout));
        }

        // FR-011
        #[test]
        fn wait_for_cancel_returns_cancelled() {
            let mut fake = FakeToolRunner::new();
            fake.reply(ToolId::Docker, &["ps"], FakeReply::WaitForCancel);
            assert_eq!(
                fake.run(&PS, &AtomicBool::new(true)),
                Err(ToolError::Cancelled)
            );
        }
    }
}
