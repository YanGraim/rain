//! Single message catalog. Every user-visible string is looked up here by
//! key; texts live in `locales/<lang>/cli.json`, embedded at build time so
//! the binary needs no files at runtime.
//!
//! A value is either a string or, for count-dependent messages, an object
//! with plural forms `one` and `other`.

use std::collections::HashMap;

const EN_JSON: &str = include_str!("../../../locales/en/cli.json");
const ES_JSON: &str = include_str!("../../../locales/es/cli.json");
const PT_BR_JSON: &str = include_str!("../../../locales/pt-BR/cli.json");

/// Supported languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    En,
    Es,
    PtBr,
}

impl Locale {
    pub const ALL: &'static [Locale] = &[Locale::En, Locale::Es, Locale::PtBr];

    /// Tag as used in the `locales/` directory.
    pub fn tag(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Es => "es",
            Locale::PtBr => "pt-BR",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Locale::En => EN_JSON,
            Locale::Es => ES_JSON,
            Locale::PtBr => PT_BR_JSON,
        }
    }

    // CLDR cardinal rules for integers; small enough to not need ICU.
    fn plural_form(self, count: u64) -> PluralForm {
        let one = match self {
            Locale::En | Locale::Es => count == 1,
            Locale::PtBr => count <= 1,
        };
        if one {
            PluralForm::One
        } else {
            PluralForm::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluralForm {
    One,
    Other,
}

/// Keys of every user-visible message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKey {
    ScanCancelled,
    RunningAsRoot,
    UnknownRule,
    InvalidPath,
    PathOutsideHome,
    TableHeaderRule,
    TableHeaderPath,
    TableHeaderSize,
    TableTotal,
    TableSkipped,
    RuleHomebrewCache,
    RuleXcodeDerivedData,
    RuleUserLogs,
    RuleUserCaches,
    RuleDevNodeModules,
    HelpAbout,
    HelpScan,
    HelpRule,
    HelpPath,
    HelpMinAgeDays,
    HelpJson,
    HomeMissing,
    HomeEmpty,
    HomeNotAbsolute,
    HomeNotFound,
    HomeNotADirectory,
    HomeNotAccessible,
    HomeIsFilesystemRoot,
    ProtectListInvalid,
    UnsupportedOs,
    RenderJsonFailed,
    ReportUnmanaged,
    ReportUnmanagedNote,
    ReportToolTotal,
    ReportToolTotalNote,
    ProviderUnavailableNotInstalled,
    ProviderUnavailableNotRunning,
    ProviderUnavailableTimeout,
    ProviderUnavailableCancelled,
    ProviderUnavailableOutputTooLarge,
    ProviderUnavailableDenied,
    ProviderUnavailableParse,
    ProviderUnavailableIo,
    ProviderUnavailableFailed,
}

impl MessageKey {
    pub const ALL: &'static [MessageKey] = &[
        MessageKey::ScanCancelled,
        MessageKey::RunningAsRoot,
        MessageKey::UnknownRule,
        MessageKey::InvalidPath,
        MessageKey::PathOutsideHome,
        MessageKey::TableHeaderRule,
        MessageKey::TableHeaderPath,
        MessageKey::TableHeaderSize,
        MessageKey::TableTotal,
        MessageKey::TableSkipped,
        MessageKey::RuleHomebrewCache,
        MessageKey::RuleXcodeDerivedData,
        MessageKey::RuleUserLogs,
        MessageKey::RuleUserCaches,
        MessageKey::RuleDevNodeModules,
        MessageKey::HelpAbout,
        MessageKey::HelpScan,
        MessageKey::HelpRule,
        MessageKey::HelpPath,
        MessageKey::HelpMinAgeDays,
        MessageKey::HelpJson,
        MessageKey::HomeMissing,
        MessageKey::HomeEmpty,
        MessageKey::HomeNotAbsolute,
        MessageKey::HomeNotFound,
        MessageKey::HomeNotADirectory,
        MessageKey::HomeNotAccessible,
        MessageKey::HomeIsFilesystemRoot,
        MessageKey::ProtectListInvalid,
        MessageKey::UnsupportedOs,
        MessageKey::RenderJsonFailed,
        MessageKey::ReportUnmanaged,
        MessageKey::ReportUnmanagedNote,
        MessageKey::ReportToolTotal,
        MessageKey::ReportToolTotalNote,
        MessageKey::ProviderUnavailableNotInstalled,
        MessageKey::ProviderUnavailableNotRunning,
        MessageKey::ProviderUnavailableTimeout,
        MessageKey::ProviderUnavailableCancelled,
        MessageKey::ProviderUnavailableOutputTooLarge,
        MessageKey::ProviderUnavailableDenied,
        MessageKey::ProviderUnavailableParse,
        MessageKey::ProviderUnavailableIo,
        MessageKey::ProviderUnavailableFailed,
    ];

    /// Key as written in the locale file.
    pub fn as_str(self) -> &'static str {
        match self {
            MessageKey::ScanCancelled => "scan.cancelled",
            MessageKey::RunningAsRoot => "error.running-as-root",
            MessageKey::UnknownRule => "error.unknown-rule",
            MessageKey::InvalidPath => "error.invalid-path",
            MessageKey::PathOutsideHome => "error.path-outside-home",
            MessageKey::TableHeaderRule => "table.header.rule",
            MessageKey::TableHeaderPath => "table.header.path",
            MessageKey::TableHeaderSize => "table.header.size",
            MessageKey::TableTotal => "table.total",
            MessageKey::TableSkipped => "table.skipped",
            MessageKey::RuleHomebrewCache => "rule.pkg.homebrew",
            MessageKey::RuleXcodeDerivedData => "rule.apple.derived-data",
            MessageKey::RuleUserLogs => "rule.sys.logs",
            MessageKey::RuleUserCaches => "rule.sys.user-caches",
            MessageKey::RuleDevNodeModules => "rule.proj.node-modules",
            MessageKey::HelpAbout => "help.about",
            MessageKey::HelpScan => "help.scan",
            MessageKey::HelpRule => "help.rule",
            MessageKey::HelpPath => "help.path",
            MessageKey::HelpMinAgeDays => "help.min-age-days",
            MessageKey::HelpJson => "help.json",
            MessageKey::HomeMissing => "error.home.missing",
            MessageKey::HomeEmpty => "error.home.empty",
            MessageKey::HomeNotAbsolute => "error.home.not-absolute",
            MessageKey::HomeNotFound => "error.home.not-found",
            MessageKey::HomeNotADirectory => "error.home.not-a-directory",
            MessageKey::HomeNotAccessible => "error.home.not-accessible",
            MessageKey::HomeIsFilesystemRoot => "error.home.filesystem-root",
            MessageKey::ProtectListInvalid => "error.protect-list",
            MessageKey::UnsupportedOs => "error.unsupported-os",
            MessageKey::RenderJsonFailed => "error.render-json",
            MessageKey::ReportUnmanaged => "report.unmanaged",
            MessageKey::ReportUnmanagedNote => "report.unmanaged-note",
            MessageKey::ReportToolTotal => "report.tool-total",
            MessageKey::ReportToolTotalNote => "report.tool-total-note",
            MessageKey::ProviderUnavailableNotInstalled => "provider.unavailable.not-installed",
            MessageKey::ProviderUnavailableNotRunning => "provider.unavailable.not-running",
            MessageKey::ProviderUnavailableTimeout => "provider.unavailable.timeout",
            MessageKey::ProviderUnavailableCancelled => "provider.unavailable.cancelled",
            MessageKey::ProviderUnavailableOutputTooLarge => {
                "provider.unavailable.output-too-large"
            }
            MessageKey::ProviderUnavailableDenied => "provider.unavailable.denied",
            MessageKey::ProviderUnavailableParse => "provider.unavailable.parse",
            MessageKey::ProviderUnavailableIo => "provider.unavailable.io",
            MessageKey::ProviderUnavailableFailed => "provider.unavailable.failed",
        }
    }
}

/// FR-002: ids of every catalogue rule whose name (`rule.<id>`) and
/// consequence (`rule.<id>.consequence`) must exist in every locale.
pub const CATALOGUE_RULE_IDS: &[&str] = &[
    "ai.claude-code.cache",
    "ai.claude-code.logs",
    "ai.cursor.cache",
    "ai.cursor.workspace-storage",
    "ai.windsurf.cache",
    "ai.cursor.state-backups",
    "ai.claude-desktop.cache",
    "ai.vscode.old-extensions",
    "ai.cursor.old-extensions",
    "ai.copilot.cache",
    "ai.codex.cache",
    "ai.gemini.cache",
    "ai.aider.cache",
    "ai.continue.cache",
    "models.ollama",
    "models.lmstudio",
    "models.huggingface",
    "models.torch-hub",
    "models.gpt4all",
    "models.whisper",
    "containers.build-cache",
    "containers.dangling-images",
    "containers.stopped",
    "containers.unused-images",
    "containers.volumes",
    "pkg.npm",
    "pkg.npx",
    "pkg.yarn",
    "pkg.bun",
    "pkg.pip",
    "pkg.uv",
    "pkg.poetry",
    "pkg.cargo",
    "pkg.gradle",
    "pkg.cocoapods",
    "pkg.homebrew",
    "pkg.pnpm",
    "pkg.conda",
    "pkg.rustup",
    "pkg.go",
    "pkg.maven",
    "pkg.playwright",
    "apple.derived-data",
    "apple.archives",
    "apple.device-support",
    "apple.sim-unavailable",
    "apple.sim-runtimes",
    "apple.previews",
    "sys.user-caches",
    "sys.sensitive-caches",
    "sys.logs",
    "sys.crash-reports",
    "browser.cache",
    "proj.node-modules",
    "proj.rust-target",
    "proj.venv",
    "proj.build-dist",
];

/// FR-004: user data reported as unmanaged; each has a name `userdata.<id>`.
pub const USERDATA_IDS: &[&str] = &[
    "claude-code.history",
    "codeium.conversations",
    "codex.sessions",
    "aider.chat-history",
];

/// Every string key the catalogue needs, besides the fixed [`MessageKey`]s.
pub fn catalogue_keys() -> Vec<String> {
    let mut keys = Vec::with_capacity(CATALOGUE_RULE_IDS.len() * 2 + USERDATA_IDS.len());
    for id in CATALOGUE_RULE_IDS {
        keys.push(format!("rule.{id}"));
        keys.push(format!("rule.{id}.consequence"));
    }
    for id in USERDATA_IDS {
        keys.push(format!("userdata.{id}"));
    }
    keys
}

/// Failure to load a locale file.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("locale file is not valid JSON")]
    Parse(#[from] serde_json::Error),
    #[error("locale file must be a JSON object")]
    NotAnObject,
    #[error("invalid value for message key {0}")]
    InvalidValue(String),
}

#[derive(Debug, Clone)]
enum Text {
    Simple(String),
    Plural { one: String, other: String },
}

/// Loaded message texts for one language.
#[derive(Debug, Clone)]
pub struct Catalog {
    locale: Locale,
    texts: HashMap<String, Text>,
}

impl Catalog {
    /// English catalog, the default and fallback language.
    pub fn en() -> Result<Self, CatalogError> {
        Self::for_locale(Locale::En)
    }

    /// Catalog for `locale`.
    pub fn for_locale(locale: Locale) -> Result<Self, CatalogError> {
        Self::from_json(locale, locale.source())
    }

    fn from_json(locale: Locale, json: &str) -> Result<Self, CatalogError> {
        let value: serde_json::Value = serde_json::from_str(json)?;
        let obj = value.as_object().ok_or(CatalogError::NotAnObject)?;
        let mut texts = HashMap::with_capacity(obj.len());
        for (key, v) in obj {
            texts.insert(key.clone(), parse_text(key, v)?);
        }
        Ok(Catalog { locale, texts })
    }

    pub fn locale(&self) -> Locale {
        self.locale
    }

    /// Text for `key`, or `None` if the locale file lacks it. Plural
    /// messages return their `other` form.
    pub fn try_get(&self, key: MessageKey) -> Option<&str> {
        self.texts.get(key.as_str()).map(|t| match t {
            Text::Simple(s) => s.as_str(),
            Text::Plural { other, .. } => other.as_str(),
        })
    }

    /// Text for a string key such as a rule's `name_key`; `None` if absent
    /// or plural.
    pub fn text(&self, key: &str) -> Option<&str> {
        match self.texts.get(key) {
            Some(Text::Simple(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Text for `key`; falls back to the key itself so a missing entry
    /// degrades visibly instead of crashing.
    pub fn get(&self, key: MessageKey) -> &str {
        // A plural message read here would always show the `other` form.
        debug_assert!(
            !matches!(self.texts.get(key.as_str()), Some(Text::Plural { .. })),
            "{} is plural; use get_plural",
            key.as_str()
        );
        self.try_get(key).unwrap_or(key.as_str())
    }

    /// Text for `key` in the plural form matching `count`. Simple messages
    /// ignore the count.
    pub fn get_plural(&self, key: MessageKey, count: u64) -> &str {
        match self.texts.get(key.as_str()) {
            Some(Text::Plural { one, other }) => match self.locale.plural_form(count) {
                PluralForm::One => one.as_str(),
                PluralForm::Other => other.as_str(),
            },
            Some(Text::Simple(s)) => s.as_str(),
            None => key.as_str(),
        }
    }
}

fn parse_text(key: &str, v: &serde_json::Value) -> Result<Text, CatalogError> {
    let invalid = || CatalogError::InvalidValue(key.to_owned());
    if let Some(s) = v.as_str() {
        return Ok(Text::Simple(s.to_owned()));
    }
    let obj = v.as_object().ok_or_else(invalid)?;
    if obj.len() != 2 {
        return Err(invalid());
    }
    let form = |name: &str| {
        obj.get(name)
            .and_then(|f| f.as_str())
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    Ok(Text::Plural {
        one: form("one")?,
        other: form("other")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn all_forms(catalog: &Catalog, key: MessageKey) -> Vec<&str> {
        match catalog.texts.get(key.as_str()) {
            Some(Text::Simple(s)) => vec![s.as_str()],
            Some(Text::Plural { one, other }) => vec![one.as_str(), other.as_str()],
            None => vec![],
        }
    }

    fn placeholders(text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut rest = text;
        while let Some(start) = rest.find('{') {
            let after = &rest[start + 1..];
            match after.find('}') {
                Some(end) => {
                    out.insert(after[..end].to_owned());
                    rest = &after[end + 1..];
                }
                None => break,
            }
        }
        out
    }

    // FR-013
    #[test]
    fn all_message_keys_exist_in_en() {
        let catalog = Catalog::en().unwrap();
        for key in MessageKey::ALL {
            let text = catalog.try_get(*key);
            assert!(
                text.is_some_and(|t| !t.is_empty()),
                "missing en text for {}",
                key.as_str()
            );
        }
    }

    // FR-013
    #[test]
    fn all_message_keys_exist_in_every_locale() {
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for key in MessageKey::ALL {
                let forms = all_forms(&catalog, *key);
                assert!(
                    !forms.is_empty() && forms.iter().all(|f| !f.is_empty()),
                    "missing {} text for {}",
                    locale.tag(),
                    key.as_str()
                );
            }
        }
    }

    // FR-013
    #[test]
    fn no_locale_has_unknown_keys() {
        let extra = catalogue_keys();
        let mut known: Vec<&str> = MessageKey::ALL.iter().map(|k| k.as_str()).collect();
        known.extend(extra.iter().map(String::as_str));
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for key in catalog.texts.keys() {
                assert!(
                    known.contains(&key.as_str()),
                    "unknown key {key} in {}",
                    locale.tag()
                );
            }
        }
    }

    // FR-013
    #[test]
    fn placeholders_match_across_locales() {
        let en = Catalog::en().unwrap();
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for key in MessageKey::ALL {
                let want: Vec<_> = all_forms(&en, *key).into_iter().map(placeholders).collect();
                let got: Vec<_> = all_forms(&catalog, *key)
                    .into_iter()
                    .map(placeholders)
                    .collect();
                assert_eq!(got, want, "{} {}", locale.tag(), key.as_str());
            }
        }
    }

    // FR-013
    #[test]
    fn skipped_uses_plural_forms() {
        let en = Catalog::en().unwrap();
        assert_ne!(
            en.get_plural(MessageKey::TableSkipped, 1),
            en.get_plural(MessageKey::TableSkipped, 2)
        );
        assert_eq!(
            en.get_plural(MessageKey::TableSkipped, 0),
            en.get_plural(MessageKey::TableSkipped, 2)
        );
        let pt = Catalog::for_locale(Locale::PtBr).unwrap();
        assert_eq!(
            pt.get_plural(MessageKey::TableSkipped, 0),
            pt.get_plural(MessageKey::TableSkipped, 1)
        );
    }

    // FR-013
    #[test]
    fn plural_form_table() {
        use PluralForm::{One, Other};
        let cases = [
            (Locale::En, [Other, One, Other, Other]),
            (Locale::Es, [Other, One, Other, Other]),
            (Locale::PtBr, [One, One, Other, Other]),
        ];
        for (locale, want) in cases {
            for (count, form) in [0, 1, 2, 1_000_000].into_iter().zip(want) {
                assert_eq!(locale.plural_form(count), form, "{} {count}", locale.tag());
            }
        }
    }

    // FR-013: plural messages must go through `get_plural`.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "get_plural")]
    fn get_on_plural_key_panics_in_debug() {
        let _ = Catalog::en().unwrap().get(MessageKey::TableSkipped);
    }

    // FR-013
    #[test]
    fn missing_key_falls_back_to_key() {
        let catalog = Catalog::from_json(Locale::En, "{}").unwrap();
        assert_eq!(catalog.get(MessageKey::TableTotal), "table.total");
        assert_eq!(
            catalog.get_plural(MessageKey::TableSkipped, 3),
            "table.skipped"
        );
    }

    // FR-013
    #[test]
    fn invalid_json_is_an_error() {
        assert!(Catalog::from_json(Locale::En, "[1]").is_err());
        assert!(Catalog::from_json(Locale::En, r#"{"a": 1}"#).is_err());
        assert!(Catalog::from_json(Locale::En, r#"{"a": {"one": "x"}}"#).is_err());
    }

    fn all_text_forms<'c>(catalog: &'c Catalog, key: &str) -> Vec<&'c str> {
        match catalog.texts.get(key) {
            Some(Text::Simple(s)) => vec![s.as_str()],
            Some(Text::Plural { one, other }) => vec![one.as_str(), other.as_str()],
            None => vec![],
        }
    }

    // FR-002, NFR-003
    #[test]
    fn every_key_in_all_locales() {
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for key in catalogue_keys() {
                let forms = all_text_forms(&catalog, &key);
                assert!(
                    !forms.is_empty() && forms.iter().all(|f| !f.trim().is_empty()),
                    "missing {} text for {key}",
                    locale.tag()
                );
            }
        }
    }

    // FR-002, NFR-003
    #[test]
    fn every_builtin_rule_has_name_and_consequence_in_all_locales() {
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for rule in crate::rules::builtin() {
                let meta = rule.meta();
                for key in [meta.name_key, meta.consequence_key] {
                    assert!(
                        catalog.text(key).is_some_and(|t| !t.trim().is_empty()),
                        "missing {} text for {key}",
                        locale.tag()
                    );
                }
            }
        }
    }

    // FR-002
    #[test]
    fn catalogue_placeholders_match_across_locales() {
        let en = Catalog::en().unwrap();
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for key in catalogue_keys() {
                let want: Vec<_> = all_text_forms(&en, &key)
                    .into_iter()
                    .map(placeholders)
                    .collect();
                let got: Vec<_> = all_text_forms(&catalog, &key)
                    .into_iter()
                    .map(placeholders)
                    .collect();
                assert_eq!(got, want, "{} {key}", locale.tag());
            }
        }
    }

    // FR-002
    #[test]
    fn consequence_mentions_size_placeholder() {
        for locale in Locale::ALL {
            let catalog = Catalog::for_locale(*locale).unwrap();
            for id in CATALOGUE_RULE_IDS
                .iter()
                .filter(|id| id.starts_with("models."))
            {
                let key = format!("rule.{id}.consequence");
                let text = catalog.text(&key).unwrap_or_default();
                assert!(
                    placeholders(text).contains("size"),
                    "{} {key} lacks {{size}}",
                    locale.tag()
                );
            }
        }
    }

    // FR-002
    #[test]
    fn catalogue_ids_are_unique() {
        let set: BTreeSet<_> = CATALOGUE_RULE_IDS.iter().collect();
        assert_eq!(set.len(), CATALOGUE_RULE_IDS.len());
    }

    // FR-014, FR-043
    #[test]
    fn sensitive_caches_consequence_names_what_it_covers() {
        let cases: [(Locale, &[&str]); 3] = [
            (
                Locale::En,
                &[
                    "Wallet",
                    "Apple Pay",
                    "Apple Account",
                    "App Store",
                    "Family Sharing",
                    "iCloud Mail",
                    "Home",
                ],
            ),
            (
                Locale::Es,
                &[
                    "Wallet",
                    "Apple Pay",
                    "cuenta de Apple",
                    "App Store",
                    "En familia",
                    "Mail de iCloud",
                    "Casa",
                ],
            ),
            (
                Locale::PtBr,
                &[
                    "Wallet",
                    "Apple Pay",
                    "conta Apple",
                    "App Store",
                    "Compartilhamento Familiar",
                    "Mail do iCloud",
                    "Casa",
                ],
            ),
        ];
        for (locale, wants) in cases {
            let catalog = Catalog::for_locale(locale).unwrap();
            let text = catalog
                .text("rule.sys.sensitive-caches.consequence")
                .unwrap_or_default();
            for want in wants {
                assert!(text.contains(want), "{} missing {want}", locale.tag());
            }
            let lower = text.to_lowercase();
            for banned in [
                "password",
                "contraseña",
                "senha",
                "security",
                "seguridad",
                "segurança",
                "icloud drive",
            ] {
                assert!(
                    !lower.contains(banned),
                    "{} mentions {banned}",
                    locale.tag()
                );
            }
        }
    }

    // FR-002
    #[test]
    fn playwright_consequence_mentions_next_install_and_size() {
        let en = Catalog::en().unwrap();
        let text = en
            .text("rule.pkg.playwright.consequence")
            .unwrap_or_default();
        assert!(placeholders(text).contains("size"), "lacks {{size}}");
        assert!(text.contains("next install"), "lacks next install");
    }

    // FR-002: losing the paste cache matters when resuming old chats.
    #[test]
    fn claude_cache_consequence_mentions_pasted_content_in_all_locales() {
        for (locale, word) in [
            (Locale::En, "pasted"),
            (Locale::Es, "pegado"),
            (Locale::PtBr, "colado"),
        ] {
            let catalog = Catalog::for_locale(locale).unwrap();
            let text = catalog
                .text("rule.ai.claude-code.cache.consequence")
                .unwrap_or_default();
            assert!(
                text.to_lowercase().contains(word),
                "{}: {text}",
                locale.tag()
            );
        }
    }
}
