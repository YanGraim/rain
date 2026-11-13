//! Built-in rule registry. The order is the priority: when two rules find
//! the same path, the earlier one keeps it (ADR 0005), so more specific
//! rules come first.

mod ai;
mod apple;
mod browser;
mod children;
mod containers;
mod extensions;
mod macos;
mod models;
mod node_modules;
mod pkg;
mod proj;
mod project;
mod sys;
mod user;

use std::sync::OnceLock;

use crate::model::{Risk, RuleId};
use crate::rule::{Rule, RuleKind, RuleMeta};

// FR-001
static ORDER: &[&[&dyn Rule]] = &[
    ai::RULES,
    models::RULES,
    containers::RULES,
    pkg::RULES,
    &[&macos::HOMEBREW_CACHE],
    apple::RULES,
    &[&macos::XCODE_DERIVED_DATA],
    browser::RULES,
    sys::RULES,
    &[&user::USER_LOGS, &user::USER_CACHES],
    proj::RULES,
    &[&node_modules::NODE_MODULES],
];

pub fn builtin() -> &'static [&'static dyn Rule] {
    static BUILTIN: OnceLock<Vec<&'static dyn Rule>> = OnceLock::new();
    BUILTIN.get_or_init(|| assemble(ORDER))
}

// FR-014 / ADR 0005
fn assemble<'r>(slices: &[&[&'r dyn Rule]]) -> Vec<&'r dyn Rule> {
    slices
        .iter()
        .flat_map(|slice| slice.iter().copied())
        .map(|rule| {
            let meta = rule.meta();
            if meta.risk == Risk::High && meta.default_selected {
                debug_assert!(false, "{} is high and default selected", meta.id);
                demote(rule)
            } else {
                rule
            }
        })
        .collect()
}

// FR-014
struct Demoted<'r> {
    inner: &'r dyn Rule,
    meta: RuleMeta,
}

impl Rule for Demoted<'_> {
    fn meta(&self) -> &RuleMeta {
        &self.meta
    }
    fn kind(&self) -> RuleKind<'_> {
        self.inner.kind()
    }
}

// FR-014 / ADR 0005
fn demote(rule: &dyn Rule) -> &dyn Rule {
    let meta = RuleMeta {
        default_selected: false,
        ..rule.meta().clone()
    };
    Box::leak(Box::new(Demoted { inner: rule, meta }))
}

/// FR-008: an `--rule` id that does not exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown rule: {id}")]
pub struct UnknownRule {
    pub id: String,
    /// Every valid id, sorted.
    pub valid: Vec<RuleId>,
}

/// Picks the rules named in `ids` from the built-in registry, keeping the
/// registry order (the priority), whatever order `ids` came in.
pub fn select(ids: &[&str]) -> Result<Vec<&'static dyn Rule>, UnknownRule> {
    select_from(builtin(), ids)
}

fn select_from<'r>(
    registry: &[&'r dyn Rule],
    ids: &[&str],
) -> Result<Vec<&'r dyn Rule>, UnknownRule> {
    if let Some(unknown) = ids
        .iter()
        .find(|id| !registry.iter().any(|r| r.meta().id.as_str() == **id))
    {
        let mut valid: Vec<RuleId> = registry.iter().map(|r| r.meta().id).collect();
        valid.sort();
        return Err(UnknownRule {
            id: (*unknown).to_string(),
            valid,
        });
    }
    Ok(registry
        .iter()
        .copied()
        .filter(|r| ids.contains(&r.meta().id.as_str()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Fs;
    use crate::model::{Category, Risk};
    use crate::rule::{EntryInfo, FileRule, RootedPath, RuleContext, RuleKind, RuleMeta, Visit};

    struct Named(RuleMeta);

    impl Rule for Named {
        fn meta(&self) -> &RuleMeta {
            &self.0
        }
        fn kind(&self) -> RuleKind<'_> {
            RuleKind::Files(self)
        }
    }

    impl FileRule for Named {
        fn roots(&self, _: &RuleContext) -> Vec<RootedPath> {
            Vec::new()
        }
        fn visit(&self, _: &EntryInfo, _: usize, _: &RuleContext, _: &dyn Fs) -> Visit {
            Visit::Skip
        }
    }

    fn named(id: &'static str) -> Named {
        Named(RuleMeta {
            id: RuleId::new(id),
            category: Category::SystemCaches,
            risk: Risk::Low,
            name_key: "rule.test",
            consequence_key: "rule.test.consequence",
            default_selected: true,
            requires_app_closed: None,
            os: &[],
        })
    }

    fn ids(rules: &[&dyn Rule]) -> Vec<&'static str> {
        rules.iter().map(|r| r.meta().id.as_str()).collect()
    }

    // FR-008 / ADR 0005: selection keeps the registry (priority) order.
    #[test]
    fn select_keeps_registry_order() {
        let (z, a) = (named("z.first"), named("a.second"));
        let registry: [&dyn Rule; 2] = [&z, &a];
        let picked = select_from(&registry, &["a.second", "z.first"]).unwrap();
        assert_eq!(ids(&picked), ["z.first", "a.second"]);
    }

    // FR-008: an unknown id is an error listing every valid id, sorted.
    #[test]
    fn unknown_rule_lists_valid_ids_sorted() {
        let (z, a) = (named("z.first"), named("a.second"));
        let registry: [&dyn Rule; 2] = [&z, &a];
        let err = select_from(&registry, &["z.first", "nope"]).err().unwrap();
        assert_eq!(err.id, "nope");
        assert_eq!(err.valid, [RuleId::new("a.second"), RuleId::new("z.first")]);
    }

    // FR-002, ADR 0005: more specific rules come first, so the Homebrew
    // cache keeps its bytes when the user caches rule also sees them.
    #[test]
    fn homebrew_then_xcode_before_user_caches() {
        let all = ids(builtin());
        let at = |id: &str| all.iter().position(|x| *x == id);
        assert!(at("pkg.homebrew") < at("apple.derived-data"));
        assert!(at("apple.derived-data") < at("sys.user-caches"));
    }

    // FR-013: every builtin rule name is a catalogue key, so it exists in
    // all locales (checked by the catalogue tests).
    #[test]
    fn builtin_names_are_message_keys() {
        use crate::messages::{catalogue_keys, MessageKey};
        let catalogue = catalogue_keys();
        for rule in builtin() {
            let key = rule.meta().name_key;
            assert!(
                MessageKey::ALL.iter().any(|k| k.as_str() == key)
                    || catalogue.iter().any(|k| k == key),
                "missing message key {key}"
            );
        }
    }

    // FR-008: builtin ids are unique, so selection by id is unambiguous.
    #[test]
    fn builtin_ids_are_unique() {
        let mut all = ids(builtin());
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
    }

    // FR-014
    #[test]
    fn high_rules_are_never_default_selected() {
        for rule in builtin() {
            let meta = rule.meta();
            assert!(
                !(meta.risk == Risk::High && meta.default_selected),
                "{} is high and default selected",
                meta.id
            );
        }
    }

    // FR-001
    #[test]
    fn rules_from_scan_macos_are_default_selected() {
        let scan_macos = [
            "pkg.homebrew",
            "apple.derived-data",
            "sys.logs",
            "sys.user-caches",
            "proj.node-modules",
        ];
        for rule in select(&scan_macos).unwrap() {
            let meta = rule.meta();
            if meta.id.as_str() == "proj.node-modules" {
                assert!(!meta.default_selected, "{}", meta.id);
            } else {
                assert!(meta.default_selected, "{}", meta.id);
            }
        }
    }

    // FR-010
    #[test]
    fn medium_and_high_rules_are_never_default_selected() {
        for rule in builtin() {
            let meta = rule.meta();
            assert!(
                meta.risk == Risk::Low || !meta.default_selected,
                "{} is {:?} and default selected",
                meta.id,
                meta.risk
            );
        }
    }

    // FR-015
    #[test]
    fn derived_data_requires_xcode_closed() {
        let pick = select(&["apple.derived-data"]).unwrap();
        assert_eq!(
            pick[0].meta().requires_app_closed,
            Some("com.apple.dt.Xcode")
        );
        let others = builtin()
            .iter()
            // FR-015: the Cursor and Windsurf rules are covered in
            // `tests/rules_ai_cursor.rs` and `tests/rules_ai_tools.rs`; the Xcode ones in `tests/rules_apple.rs`.
            .filter(|r| {
                !matches!(
                    r.meta().id.as_str(),
                    "apple.derived-data"
                        | "ai.cursor.cache"
                        | "ai.cursor.workspace-storage"
                        | "ai.cursor.state-backups"
                        | "ai.claude-desktop.cache"
                        | "ai.vscode.old-extensions"
                        | "ai.cursor.old-extensions"
                        | "ai.windsurf.cache"
                        | "apple.archives"
                        | "apple.device-support"
                        | "apple.previews"
                )
            });
        for rule in others {
            assert_eq!(rule.meta().requires_app_closed, None, "{}", rule.meta().id);
        }
    }

    // FR-002
    #[test]
    fn every_rule_has_consequence_key() {
        for rule in builtin() {
            let meta = rule.meta();
            assert_eq!(
                meta.consequence_key,
                format!("rule.{}.consequence", meta.id),
                "{}",
                meta.id
            );
        }
    }

    // FR-001
    #[test]
    fn rules_from_scan_macos_use_their_catalogue_category() {
        let category = |id: &str| select(&[id]).unwrap()[0].meta().category;
        assert_eq!(category("apple.derived-data"), Category::AppleDev);
        assert_eq!(category("proj.node-modules"), Category::Projects);
        assert_eq!(category("pkg.homebrew"), Category::PackageManagers);
        assert_eq!(category("sys.user-caches"), Category::SystemCaches);
        assert_eq!(category("sys.logs"), Category::Logs);
    }

    // FR-001 / ADR 0005: slices are joined in the given order, keeping each
    // slice's own order.
    #[test]
    fn category_slices_concatenate_in_fixed_order() {
        let (a, b, c) = (named("a.one"), named("b.two"), named("c.three"));
        let first: [&dyn Rule; 2] = [&a, &b];
        let second: [&dyn Rule; 1] = [&c];
        let joined = assemble(&[&second, &[], &first]);
        assert_eq!(ids(&joined), ["c.three", "a.one", "b.two"]);
    }

    // FR-014: no rule in the real order is high risk and default selected.
    #[test]
    fn order_has_no_high_risk_default_selected() {
        for rule in ORDER.iter().flat_map(|s| s.iter()) {
            let meta = rule.meta();
            assert!(
                !(meta.risk == Risk::High && meta.default_selected),
                "{} is high and default selected",
                meta.id
            );
        }
    }

    // FR-014 / ADR 0005: nothing is dropped, so no item falls to a lower
    // risk rule.
    #[test]
    fn builtin_keeps_every_rule_in_order() {
        let total: usize = ORDER.iter().map(|s| s.len()).sum();
        assert_eq!(builtin().len(), total);
    }

    // FR-014 / ADR 0005: a high risk default selected rule stays in place,
    // keeps its kind and id, and is no longer default selected.
    #[test]
    fn demote_keeps_rule_but_unselects_it() {
        let mut bad = named("x.bad");
        bad.0.risk = Risk::High;
        let demoted = demote(&bad);
        assert_eq!(demoted.meta().id.as_str(), "x.bad");
        assert_eq!(demoted.meta().risk, Risk::High);
        assert!(!demoted.meta().default_selected);
        assert!(matches!(demoted.kind(), RuleKind::Files(_)));
    }

    // FR-014
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "high and default selected")]
    fn assemble_panics_in_debug_on_high_risk_default_selected() {
        let mut bad = named("x.bad");
        bad.0.risk = Risk::High;
        let slice: [&dyn Rule; 1] = [&bad];
        let _ = assemble(&[&slice]);
    }

    // FR-002 / ADR 0005: the registry order is AI, JS and Python package
    // caches, homebrew, xcode, logs, caches.
    #[test]
    fn builtin_order_is_specific_first() {
        assert_eq!(
            ids(builtin()),
            [
                "ai.claude-code.cache",
                "ai.claude-code.logs",
                "ai.cursor.cache",
                "ai.windsurf.cache",
                "ai.cursor.workspace-storage",
                "ai.cursor.state-backups",
                "ai.claude-desktop.cache",
                "ai.vscode.old-extensions",
                "ai.cursor.old-extensions",
                "ai.codex.cache",
                "ai.gemini.cache",
                "ai.continue.cache",
                "ai.aider.cache",
                "ai.copilot.cache",
                "containers.build-cache",
                "containers.dangling-images",
                "containers.stopped",
                "containers.unused-images",
                "containers.volumes",
                "pkg.npm",
                "pkg.yarn",
                "pkg.bun",
                "pkg.pnpm",
                "pkg.pip",
                "pkg.uv",
                "pkg.poetry",
                "pkg.homebrew",
                "apple.archives",
                "apple.device-support",
                "apple.previews",
                "apple.derived-data",
                "sys.sensitive-caches",
                "sys.logs",
                "sys.user-caches",
                "proj.rust-target",
                "proj.node-modules",
            ]
        );
    }
}
