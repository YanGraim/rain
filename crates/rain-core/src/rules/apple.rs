//! Xcode developer data besides DerivedData. All need Xcode closed (FR-015).

use super::children::ChildrenOf;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{Rule, RuleMeta};
use rain_platform::{Os, Root};

const XCODE: &str = "com.apple.dt.Xcode";

pub(super) static RULES: &[&dyn Rule] = &[&ARCHIVES, &DEVICE_SUPPORT, &PREVIEWS];

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
