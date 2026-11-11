//! AI agents and tools. Only data the tool recreates on its own; sessions
//! and history are user data (FR-004) and never appear here.

use super::children::ChildrenOf;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{Rule, RuleMeta};
use rain_platform::{Os, Root};

// ADR 0005: listed before `sys.user-caches`, so `claude-cli-nodejs` in
// `~/Library/Caches` belongs to this rule.
pub(super) static RULES: &[&dyn Rule] = &[
    &CLAUDE_CODE_CACHE,
    &CLAUDE_CODE_LOGS,
    &CURSOR_CACHE,
    &WINDSURF_CACHE,
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
