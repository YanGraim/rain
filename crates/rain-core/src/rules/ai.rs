//! AI agents and tools. Only data the tool recreates on its own; sessions
//! and history are user data (FR-004) and never appear here.

use super::children::{ChildDirsOf, ChildrenOf};
use crate::fs::Fs;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{EntryInfo, FileRule, RootedPath, Rule, RuleContext, RuleKind, RuleMeta, Visit};
use rain_platform::{Os, Root};

// ADR 0005: listed before `sys.user-caches`, so `claude-cli-nodejs` in
// `~/Library/Caches` belongs to this rule.
pub(super) static RULES: &[&dyn Rule] = &[
    &CLAUDE_CODE_CACHE,
    &CLAUDE_CODE_LOGS,
    &CURSOR_CACHE,
    &WINDSURF_CACHE,
    &CURSOR_WORKSPACE_STORAGE,
    &CURSOR_STATE_BACKUPS,
    &CLAUDE_DESKTOP_CACHE,
    &CODEX_CACHE,
    &GEMINI_CACHE,
    &CONTINUE_CACHE,
    &AIDER_CACHE,
    &COPILOT_CACHE,
];

/// FR-001: Claude Code caches and shell snapshots. Every child is one item;
/// a whole folder would hide protected data planted inside it (NFR-005).
static CLAUDE_CODE_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.claude-code.cache"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.claude-code.cache",
        consequence_key: "rule.ai.claude-code.cache.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[
        ".claude/shell-snapshots",
        ".claude/cache",
        ".claude/paste-cache",
        ".claude/telemetry",
        ".cache/claude",
        "Library/Caches/claude-cli-nodejs",
    ],
    depth: 1,
};

/// FR-001: Claude Code debug logs.
static CLAUDE_CODE_LOGS: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.claude-code.logs"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.claude-code.logs",
        consequence_key: "rule.ai.claude-code.logs.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[".claude/debug"],
    depth: 1,
};

/// FR-001, FR-015: Cursor caches and logs. Only named dirs: `User` holds
/// settings and agent chat (FR-004). Cursor's bundle id is the ToDesktop one.
static CURSOR_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.cursor.cache"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.cursor.cache",
        consequence_key: "rule.ai.cursor.cache.consequence",
        default_selected: true,
        requires_app_closed: Some("com.todesktop.230313mzl4w4u92"),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[
        "Library/Application Support/Cursor/Cache",
        "Library/Application Support/Cursor/CachedData",
        "Library/Application Support/Cursor/GPUCache",
        "Library/Application Support/Cursor/logs",
    ],
    depth: 1,
};

/// FR-001, FR-015: Windsurf caches and logs. Conversations live in
/// `~/.codeium` and are user data.
static WINDSURF_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.windsurf.cache"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.windsurf.cache",
        consequence_key: "rule.ai.windsurf.cache.consequence",
        default_selected: true,
        requires_app_closed: Some("com.exafunction.windsurf"),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[
        "Library/Application Support/Windsurf/Cache",
        "Library/Application Support/Windsurf/CachedData",
        "Library/Application Support/Windsurf/logs",
    ],
    depth: 1,
};

/// FR-014: per-workspace state, including the agent chat. High, never preselected;
/// each workspace is one item.
static CURSOR_WORKSPACE_STORAGE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.cursor.workspace-storage"),
        category: Category::AiTools,
        risk: Risk::High,
        name_key: "rule.ai.cursor.workspace-storage",
        consequence_key: "rule.ai.cursor.workspace-storage.consequence",
        default_selected: false,
        requires_app_closed: Some("com.todesktop.230313mzl4w4u92"),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &["Library/Application Support/Cursor/User/workspaceStorage"],
    depth: 1,
};

/// FR-001: Codex CLI logs. `~/.codex/sessions` is user data (FR-004).
static CODEX_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.codex.cache"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.codex.cache",
        consequence_key: "rule.ai.codex.cache.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[".codex/log"],
    depth: 1,
};

/// FR-001: Gemini CLI temp files; may hold session checkpoints.
static GEMINI_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.gemini.cache"),
        category: Category::AiTools,
        risk: Risk::Medium,
        name_key: "rule.ai.gemini.cache",
        consequence_key: "rule.ai.gemini.cache.consequence",
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[".gemini/tmp"],
    depth: 1,
};

/// FR-001: Continue code index; rebuilt on its own.
static CONTINUE_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.continue.cache"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.continue.cache",
        consequence_key: "rule.ai.continue.cache.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[".continue/index"],
    depth: 1,
};

/// FR-001: Aider global caches only. Per-project tag caches sit next to
/// `.aider.chat.history.md` (user data) and are not scanned.
static AIDER_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.aider.cache"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.aider.cache",
        consequence_key: "rule.ai.aider.cache.consequence",
        default_selected: true,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[".aider/caches"],
    depth: 1,
};

/// FR-001: GitHub Copilot cache. Only sub-folders: the top-level files
/// (`hosts.json`, `apps.json`) hold OAuth tokens.
static COPILOT_CACHE: ChildDirsOf = ChildDirsOf {
    meta: RuleMeta {
        id: RuleId::new("ai.copilot.cache"),
        category: Category::AiTools,
        risk: Risk::Medium,
        name_key: "rule.ai.copilot.cache",
        consequence_key: "rule.ai.copilot.cache.consequence",
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[".config/github-copilot"],
};

const CURSOR_ID: &str = "com.todesktop.230313mzl4w4u92";

/// FR-001: backup copies of Cursor's state database, which grow large.
/// Only plain files named `state.vscdb.backup` or `state.vscdb.bak-*`; the
/// live `state.vscdb` (chat history) is also in the protect list (FR-004).
static CURSOR_STATE_BACKUPS: CursorStateBackups = CursorStateBackups {
    meta: RuleMeta {
        id: RuleId::new("ai.cursor.state-backups"),
        category: Category::AiTools,
        risk: Risk::Medium,
        name_key: "rule.ai.cursor.state-backups",
        consequence_key: "rule.ai.cursor.state-backups.consequence",
        default_selected: false,
        requires_app_closed: Some(CURSOR_ID),
        os: &[Os::Macos],
    },
};

struct CursorStateBackups {
    meta: RuleMeta,
}

impl CursorStateBackups {
    fn is_backup(name: &str) -> bool {
        name == "state.vscdb.backup" || name.starts_with("state.vscdb.bak-")
    }
}

impl Rule for CursorStateBackups {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Files(self)
    }
}

impl FileRule for CursorStateBackups {
    fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
        vec![RootedPath::Under(
            Root::Home,
            "Library/Application Support/Cursor/User/globalStorage",
        )]
    }
    fn visit(&self, entry: &EntryInfo, depth: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
        if depth == 0 {
            return Visit::Descend;
        }
        let name = entry.path.file_name().and_then(|n| n.to_str());
        if !entry.meta.is_dir && name.is_some_and(Self::is_backup) {
            Visit::Candidate
        } else {
            Visit::Skip
        }
    }
}

/// FR-001, FR-015: Claude desktop Chromium caches. Config and VM bundles
/// in the same folder are not listed.
static CLAUDE_DESKTOP_CACHE: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("ai.claude-desktop.cache"),
        category: Category::AiTools,
        risk: Risk::Low,
        name_key: "rule.ai.claude-desktop.cache",
        consequence_key: "rule.ai.claude-desktop.cache.consequence",
        default_selected: true,
        requires_app_closed: Some("com.anthropic.claudefordesktop"),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[
        "Library/Application Support/Claude/Cache",
        "Library/Application Support/Claude/Code Cache",
        "Library/Application Support/Claude/GPUCache",
    ],
    depth: 1,
};
