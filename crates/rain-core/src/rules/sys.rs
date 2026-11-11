//! System caches that need more care than the generic caches rule.

use super::children::DirItself;
use crate::model::{Category, Risk, RuleId};
use crate::rule::{Rule, RuleMeta};
use rain_platform::{Os, Root};

// ADR 0005: listed before `sys.user-caches`, so these folders belong to
// this high-risk rule and never show up as ordinary, preselected caches.
pub(super) static RULES: &[&dyn Rule] = &[&SENSITIVE_CACHES];

/// FR-014, FR-044: Wallet, Apple Account, App Store, Family Sharing, iCloud
/// Mail and Home caches. Clearing them can sign the user out or force a
/// resync, so the rule is high and never preselected. iCloud (`bird`,
/// `CloudKit`) and `docker-secrets-engine` are protected instead.
static SENSITIVE_CACHES: DirItself = DirItself {
    meta: RuleMeta {
        id: RuleId::new("sys.sensitive-caches"),
        category: Category::SystemCaches,
        risk: Risk::High,
        name_key: "rule.sys.sensitive-caches",
        consequence_key: "rule.sys.sensitive-caches.consequence",
        default_selected: false,
        requires_app_closed: None,
        os: &[Os::Macos],
    },
    root: Root::Caches,
    rels: &[
        "PassKit",
        "com.apple.passd",
        "com.apple.appleaccountd",
        "com.apple.amsaccountsd",
        "com.apple.akd",
        "FamilyCircle",
        "com.apple.icloudmailagent",
        "com.apple.HomeKit",
    ],
};
