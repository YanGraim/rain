//! The package `clippy.toml` replaces the workspace one (no merging), so
//! the core copy must keep every root ban and add the process ban.
//! Read-only: both files are embedded at compile time.

const ROOT: &str = include_str!("../../../clippy.toml");
const CORE: &str = include_str!("../clippy.toml");

/// `path = "..."` values of the entries of one top-level list, ignoring
/// comments.
fn paths(toml: &str, list: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = Vec::new();
    for line in toml.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with(&format!("{list} = [")) {
            inside = true;
            continue;
        }
        if inside && line.starts_with(']') {
            break;
        }
        if inside {
            if let Some(rest) = line.split("path = \"").nth(1) {
                if let Some(p) = rest.split('"').next() {
                    out.push(p.to_string());
                }
            }
        }
    }
    out
}

/// Top-level keys (`name = ...`) outside comments and list bodies.
fn keys(toml: &str) -> Vec<String> {
    toml.lines()
        .filter(|l| !l.starts_with([' ', '\t', '#', ']']) && l.contains(" = "))
        .filter_map(|l| l.split(" = ").next())
        .map(str::to_string)
        .collect()
}

#[test]
fn core_keeps_every_root_disallowed_method() {
    let root = paths(ROOT, "disallowed-methods");
    let core = paths(CORE, "disallowed-methods");
    assert!(!root.is_empty(), "parser found no root entries");
    let missing: Vec<_> = root.iter().filter(|p| !core.contains(p)).collect();
    assert!(
        missing.is_empty(),
        "missing in core clippy.toml: {missing:?}"
    );
}

#[test]
fn core_has_no_extra_methods_and_no_other_root_key_is_lost() {
    let root = paths(ROOT, "disallowed-methods");
    let core = paths(CORE, "disallowed-methods");
    assert_eq!(root.len(), core.len(), "core and root method lists differ");
    for key in keys(ROOT) {
        assert!(keys(CORE).contains(&key), "core lacks root key {key}");
    }
}

#[test]
fn core_bans_the_process_command_type() {
    assert_eq!(
        paths(CORE, "disallowed-types"),
        vec!["std::process::Command".to_string()]
    );
}
