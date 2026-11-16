//! Ollama CLI output: `ollama list`.

use super::size_text::parse_decimal_size;
use crate::tools::{ParseError, ProviderItem};

/// `model:tag`, the model with an optional namespace (`user/model`). Every
/// part starts with a letter or digit, so the name can never read as an
/// option or as a path; names use lower case, tags may use upper case
/// (`q4_K_M`).
fn is_model_name(name: &str) -> bool {
    let part = |s: &str, upper: bool| {
        s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && s.bytes().all(|b| {
                b.is_ascii_digit()
                    || b.is_ascii_lowercase()
                    || (upper && b.is_ascii_uppercase())
                    || matches!(b, b'.' | b'_' | b'-')
            })
    };
    name.split_once(':')
        .is_some_and(|(model, tag)| model.split('/').all(|p| part(p, false)) && part(tag, true))
}

/// The id column: 12 lower-case hex digits.
fn is_short_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `1.5 KB`, `4.7 GB`: decimal units, a space between number and unit.
fn size(number: &str, unit: &str) -> Result<u64, ParseError> {
    let unit = match unit {
        "B" | "MB" | "GB" | "TB" => unit,
        "KB" => "kB",
        _ => return Err(ParseError("size")),
    };
    parse_decimal_size(&format!("{number}{unit}"))
}

/// FR-005: the table `ollama list` prints (`NAME ID SIZE MODIFIED`, one model
/// per row, the columns separated by spaces; the last one is free text of
/// several words). The header and every column are checked; a model whose
/// name does not validate is left out, the rest of the list stays.
pub(crate) fn parse_list(stdout: &str) -> Result<Vec<ProviderItem>, ParseError> {
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    let header: Vec<&str> = lines
        .next()
        .ok_or(ParseError("header"))?
        .split_whitespace()
        .collect();
    if header != ["NAME", "ID", "SIZE", "MODIFIED"] {
        return Err(ParseError("header"));
    }
    let mut items = Vec::new();
    for line in lines {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // name, id, number, unit and at least one word of the time.
        let [name, id, number, unit, _modified, ..] = cols[..] else {
            return Err(ParseError("row"));
        };
        if !is_short_id(id) {
            return Err(ParseError("ID"));
        }
        let bytes = size(number, unit)?;
        if is_model_name(name) {
            items.push(ProviderItem {
                key: name.to_owned(),
                label: name.to_owned(),
                reported_bytes: bytes,
                paths: Vec::new(),
            });
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = include_str!("../../tests/fixtures/ollama/list.txt");
    const HEADER: &str = "NAME    ID    SIZE    MODIFIED\n";

    fn rows(items: Vec<ProviderItem>) -> Vec<(String, u64)> {
        items
            .into_iter()
            .map(|i| (i.key, i.reported_bytes))
            .collect()
    }

    // FR-005: one item per model, with the size the tool prints.
    #[test]
    fn ollama_lists_each_model_with_size() {
        assert_eq!(
            rows(parse_list(LIST).unwrap()),
            [
                ("llama3.2:latest".to_owned(), 2_000_000_000),
                ("qwen2.5-coder:7b".to_owned(), 4_700_000_000),
                ("nomic-embed-text:latest".to_owned(), 274_000_000),
                ("user/custom-model:q4_0".to_owned(), 1_500),
            ]
        );
        let items = parse_list(LIST).unwrap();
        assert_eq!(items[0].label, "llama3.2:latest");
        assert!(items.iter().all(|i| i.paths.is_empty()));
    }

    // No models is a list, not an error.
    #[test]
    fn header_only_is_an_empty_list() {
        assert_eq!(parse_list(HEADER), Ok(vec![]));
        assert_eq!(parse_list("NAME ID SIZE MODIFIED"), Ok(vec![]));
    }

    // A name that could not be handed to the tool as one plain argument is
    // no item; the rest of the list still counts.
    #[test]
    fn invalid_model_key_dropped() {
        let text = format!(
            "{HEADER}\
             good:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             UPPER:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             notag    a80c4f17acd5    1.0 GB    1 day ago\n\
             -rf:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             ../../x:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             a//b:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             a/./b:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             a:tag:more    a80c4f17acd5    1.0 GB    1 day ago\n\
             a:    a80c4f17acd5    1.0 GB    1 day ago\n\
             :tag    a80c4f17acd5    1.0 GB    1 day ago\n\
             $(rm):latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             a;b:latest    a80c4f17acd5    1.0 GB    1 day ago\n\
             also/ok:7b-q4_K_M    a80c4f17acd5    2.0 GB    1 day ago\n"
        );
        // Tags may use upper-case letters (`q4_K_M`); names may not.
        assert_eq!(
            rows(parse_list(&text).unwrap()),
            [
                ("good:latest".to_owned(), 1_000_000_000),
                ("also/ok:7b-q4_K_M".to_owned(), 2_000_000_000),
            ]
        );
    }

    // Output that does not fully match is an error, never guessed around.
    #[test]
    fn unexpected_output_is_an_error() {
        let ok = "a:latest    a80c4f17acd5    1.0 GB    1 day ago\n";
        let bad = [
            String::new(),
            "\n".to_owned(),
            "Error: could not connect to ollama app, is it running?\n".to_owned(),
            // header
            format!("NAME ID SIZE\n{ok}"),
            format!("NAME ID SIZE MODIFIED EXTRA\n{ok}"),
            format!("name id size modified\n{ok}"),
            ok.to_owned(),
            // rows
            format!("{HEADER}a:latest\n"),
            format!("{HEADER}a:latest a80c4f17acd5 1.0 GB\n"),
            format!("{HEADER}a:latest a80c4f17acd5 1.0 XB 1 day ago\n"),
            format!("{HEADER}a:latest a80c4f17acd5 1.0GB 1 day ago extra\n"),
            format!("{HEADER}a:latest a80c4f17acd5 - - -\n"),
            format!("{HEADER}a:latest a80c4f17acd5 -1.0 GB 1 day ago\n"),
            format!("{HEADER}a:latest a80c4f17acd5 1.0.0 GB 1 day ago\n"),
            format!("{HEADER}a:latest A80C4F17ACD5 1.0 GB 1 day ago\n"),
            format!("{HEADER}a:latest a80c4f17acd 1.0 GB 1 day ago\n"),
            format!("{HEADER}a:latest a80c4f17acd5z 1.0 GB 1 day ago\n"),
        ];
        for text in &bad {
            assert!(parse_list(text).is_err(), "{text:?}");
        }
    }

    // Decimal units, as the tool prints them.
    #[test]
    fn units_are_decimal_and_exact() {
        let text = format!(
            "{HEADER}\
             a:b    a80c4f17acd5    0 B    now\n\
             b:b    a80c4f17acd5    512 B    now\n\
             c:b    a80c4f17acd5    1.5 KB    now\n\
             d:b    a80c4f17acd5    2.3 MB    now\n\
             e:b    a80c4f17acd5    13.2 GB    now\n\
             f:b    a80c4f17acd5    1.1 TB    now\n"
        );
        assert_eq!(
            rows(parse_list(&text).unwrap())
                .into_iter()
                .map(|(_, b)| b)
                .collect::<Vec<_>>(),
            [0, 512, 1_500, 2_300_000, 13_200_000_000, 1_100_000_000_000]
        );
    }
}
