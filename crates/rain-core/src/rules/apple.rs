//! Xcode developer data besides DerivedData. All need Xcode closed (FR-015).

use super::children::ChildrenOf;
use crate::model::{Category, Risk, RuleId};
use crate::providers::simctl::{parse_runtimes, parse_unavailable_simulators};
use crate::rule::{ProviderRule, Rule, RuleKind, RuleMeta};
use crate::tools::{ParseError, ProviderItem, ToolCall, ToolId, ToolOutput};
use rain_platform::{Os, Root};

const XCODE: &str = "com.apple.dt.Xcode";

pub(super) static RULES: &[&dyn Rule] = &[
    &ARCHIVES,
    &DEVICE_SUPPORT,
    &PREVIEWS,
    &SIM_UNAVAILABLE,
    &SIM_RUNTIMES,
];

/// FR-014: published builds' archives (needed to symbolicate). One item per
/// `.xcarchive` inside its date folder; high, never preselected.
static ARCHIVES: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("apple.archives"),
        category: Category::AppleDev,
        risk: Risk::High,
        name_key: "rule.apple.archives",
        consequence_key: "rule.apple.archives.consequence",
        default_selected: false,
        requires_app_closed: Some(XCODE),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &["Library/Developer/Xcode/Archives"],
    depth: 2,
};

/// FR-001: device symbols, one item per OS version.
static DEVICE_SUPPORT: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("apple.device-support"),
        category: Category::AppleDev,
        risk: Risk::Medium,
        name_key: "rule.apple.device-support",
        consequence_key: "rule.apple.device-support.consequence",
        default_selected: false,
        requires_app_closed: Some(XCODE),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &[
        "Library/Developer/Xcode/iOS DeviceSupport",
        "Library/Developer/Xcode/watchOS DeviceSupport",
    ],
    depth: 1,
};

/// FR-001: SwiftUI preview simulators; rebuilt on demand.
static PREVIEWS: ChildrenOf = ChildrenOf {
    meta: RuleMeta {
        id: RuleId::new("apple.previews"),
        category: Category::AppleDev,
        risk: Risk::Low,
        name_key: "rule.apple.previews",
        consequence_key: "rule.apple.previews.consequence",
        default_selected: true,
        requires_app_closed: Some(XCODE),
        os: &[Os::Macos],
    },
    root: Root::Home,
    rels: &["Library/Developer/Xcode/UserData/Previews"],
    depth: 1,
};

// --- Simulators, through `xcrun simctl list -j` ------------------------------------------

/// One fixed read-only command for both rules: it runs once per scan.
const SIMCTL_LIST: ToolCall = ToolCall::read(ToolId::Xcrun, &["simctl", "list", "-j"]);

/// Items the tool reports, not files: `act` stays `None` until the M2 spec.
struct Simulators {
    meta: RuleMeta,
    parse: fn(&str) -> Result<Vec<ProviderItem>, ParseError>,
}

impl Rule for Simulators {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        RuleKind::Provider(self)
    }
}

impl ProviderRule for Simulators {
    fn probe(&self) -> ToolCall {
        SIMCTL_LIST
    }
    fn parse(&self, out: &ToolOutput) -> Result<Vec<ProviderItem>, ParseError> {
        (self.parse)(&out.stdout)
    }
    fn act(&self, _: &ProviderItem) -> Option<ToolCall> {
        None
    }
}

/// Simulators whose runtime is gone. Low risk, but not preselected: their
/// apps and data are lost, and the bytes are the tool's, not measured.
static SIM_UNAVAILABLE: Simulators = Simulators {
    meta: RuleMeta {
        id: RuleId::new("apple.sim-unavailable"),
        category: Category::AppleDev,
        risk: Risk::Low,
        name_key: "rule.apple.sim-unavailable",
        consequence_key: "rule.apple.sim-unavailable.consequence",
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    parse: parse_unavailable_simulators,
};

/// Runtimes are downloads of gigabytes: high, never preselected.
static SIM_RUNTIMES: Simulators = Simulators {
    meta: RuleMeta {
        id: RuleId::new("apple.sim-runtimes"),
        category: Category::AppleDev,
        risk: Risk::High,
        name_key: "rule.apple.sim-runtimes",
        consequence_key: "rule.apple.sim-runtimes.consequence",
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    parse: parse_runtimes,
};
