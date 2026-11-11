//! NFR-005: one protection test per built-in rule, through the testkit.

use rain_core::rules;
use rain_core::testkit::assert_rule_protects;

fn protects(id: &str) {
    let rule = rules::select(&[id]).unwrap();
    assert_rule_protects(rule[0]);
}

// NFR-005, FR-007
#[test]
fn protects_apple_derived_data() {
    protects("apple.derived-data");
}

// NFR-005, FR-007
#[test]
fn protects_pkg_homebrew() {
    protects("pkg.homebrew");
}

// NFR-005, FR-007
#[test]
fn protects_pkg_js_caches() {
    for id in ["pkg.npm", "pkg.yarn", "pkg.bun", "pkg.pnpm"] {
        protects(id);
    }
}

// NFR-005, FR-007
#[test]
fn protects_ai_claude_code_cache() {
    protects("ai.claude-code.cache");
}

// NFR-005, FR-007
#[test]
fn protects_ai_claude_code_logs() {
    protects("ai.claude-code.logs");
}

// NFR-005, FR-007
#[test]
fn protects_registry_covers_every_rule() {
    for rule in rules::builtin() {
        assert_rule_protects(*rule);
    }
}
