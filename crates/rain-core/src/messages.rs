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
    TableHeaderRule,
    TableHeaderPath,
    TableHeaderSize,
    TableTotal,
    TableSkipped,
    RuleHomebrewCache,
    RuleXcodeDerivedData,
}

impl MessageKey {
    pub const ALL: &'static [MessageKey] = &[
        MessageKey::ScanCancelled,
        MessageKey::RunningAsRoot,
        MessageKey::UnknownRule,
        MessageKey::InvalidPath,
        MessageKey::TableHeaderRule,
        MessageKey::TableHeaderPath,
        MessageKey::TableHeaderSize,
        MessageKey::TableTotal,
        MessageKey::TableSkipped,
        MessageKey::RuleHomebrewCache,
        MessageKey::RuleXcodeDerivedData,
    ];

    /// Key as written in the locale file.
    pub fn as_str(self) -> &'static str {
        match self {
            MessageKey::ScanCancelled => "scan.cancelled",
            MessageKey::RunningAsRoot => "error.running-as-root",
            MessageKey::UnknownRule => "error.unknown-rule",
            MessageKey::InvalidPath => "error.invalid-path",
            MessageKey::TableHeaderRule => "table.header.rule",
            MessageKey::TableHeaderPath => "table.header.path",
            MessageKey::TableHeaderSize => "table.header.size",
            MessageKey::TableTotal => "table.total",
            MessageKey::TableSkipped => "table.skipped",
            MessageKey::RuleHomebrewCache => "rule.macos.homebrew.cache",
            MessageKey::RuleXcodeDerivedData => "rule.macos.xcode.derived-data",
        }
    }
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

    /// Text for `key`; falls back to the key itself so a missing entry
    /// degrades visibly instead of crashing.
    pub fn get(&self, key: MessageKey) -> &str {
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
        let known: Vec<&str> = MessageKey::ALL.iter().map(|k| k.as_str()).collect();
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
}
