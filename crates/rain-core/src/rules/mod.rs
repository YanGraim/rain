//! Built-in rule registry. The order is the priority: when two rules find
//! the same path, the earlier one keeps it (ADR 0005), so more specific
//! rules come first.

mod children;
mod macos;
mod node_modules;
mod user;

use crate::model::RuleId;
use crate::rule::Rule;

/// Built-in rules, most specific first.
static BUILTIN: &[&dyn Rule] = &[
    &macos::HOMEBREW_CACHE,
    &macos::XCODE_DERIVED_DATA,
    &user::USER_LOGS,
    &user::USER_CACHES,
    &node_modules::NODE_MODULES,
];

pub fn builtin() -> &'static [&'static dyn Rule] {
    BUILTIN
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
    fn builtin_starts_with_homebrew_then_xcode() {
        assert_eq!(
            ids(builtin()).get(..2),
            Some(&["macos.homebrew.cache", "macos.xcode.derived-data"][..])
        );
    }

    // FR-013: every builtin rule name is a catalogue key, so it exists in
    // all locales (checked by the catalogue tests).
    #[test]
    fn builtin_names_are_message_keys() {
        use crate::messages::MessageKey;
        for rule in builtin() {
            let key = rule.meta().name_key;
            assert!(
                MessageKey::ALL.iter().any(|k| k.as_str() == key),
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

    // FR-002 / ADR 0005: the registry order is homebrew, xcode, logs, caches.
    #[test]
    fn builtin_order_is_specific_first() {
        assert_eq!(
            ids(builtin()),
            [
                "macos.homebrew.cache",
                "macos.xcode.derived-data",
                "macos.user.logs",
                "macos.user.caches",
                "dev.node-modules",
            ]
        );
    }
}
