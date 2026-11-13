//! Docker CLI output (Docker Desktop, OrbStack and Colima share it).

use super::size_text::parse_decimal_size;
use crate::tools::{ParseError, ProviderItem};
use serde_json::{Map, Value};

/// One JSON object per non-empty line.
fn objects(stdout: &str) -> Result<Vec<Map<String, Value>>, ParseError> {
    stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| match serde_json::from_str(line) {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(ParseError("json line")),
        })
        .collect()
}

fn text<'a>(obj: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, ParseError> {
    obj.get(field)
        .and_then(Value::as_str)
        .ok_or(ParseError(field))
}

/// `4.63GB (59%)` or `305.7MB`: the size, then an optional percentage.
fn reclaimable(text: &str) -> Result<u64, ParseError> {
    let size = match text.split_once(' ') {
        None => text,
        Some((size, pct)) => {
            let n = pct
                .strip_prefix('(')
                .and_then(|p| p.strip_suffix("%)"))
                .ok_or(ParseError("reclaimable"))?;
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError("reclaimable"));
            }
            size
        }
    };
    parse_decimal_size(size)
}

/// Short (12) or full (`sha256:` + 64) lower-case hex image id.
fn is_image_id(id: &str) -> bool {
    let hex = |s: &str, n: usize| {
        s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    hex(id, 12) || id.strip_prefix("sha256:").is_some_and(|h| hex(h, 64))
}

/// Reclaimable bytes per `docker system df` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SystemDf {
    pub images: u64,
    pub containers: u64,
    pub volumes: u64,
    pub build_cache: u64,
}

/// FR-021: `docker system df --format '{{json .}}'`, one JSON object per
/// line. Every one of the 4 rows must appear exactly once.
pub(crate) fn parse_system_df(stdout: &str) -> Result<SystemDf, ParseError> {
    let mut rows: [Option<u64>; 4] = [None; 4];
    for obj in objects(stdout)? {
        let slot = match text(&obj, "Type")? {
            "Images" => 0,
            "Containers" => 1,
            "Local Volumes" => 2,
            "Build Cache" => 3,
            _ => return Err(ParseError("Type")),
        };
        let bytes = reclaimable(text(&obj, "Reclaimable")?)?;
        if rows[slot].replace(bytes).is_some() {
            return Err(ParseError("repeated Type"));
        }
    }
    match rows {
        [Some(images), Some(containers), Some(volumes), Some(build_cache)] => Ok(SystemDf {
            images,
            containers,
            volumes,
            build_cache,
        }),
        _ => Err(ParseError("missing Type")),
    }
}

/// FR-021: `docker images --filter dangling=true --format '{{json .}}'`.
/// Images some container still uses are not items.
pub(crate) fn parse_dangling_images(stdout: &str) -> Result<Vec<ProviderItem>, ParseError> {
    let mut items = Vec::new();
    for obj in objects(stdout)? {
        let id = text(&obj, "ID")?;
        if !is_image_id(id) {
            return Err(ParseError("ID"));
        }
        let size = parse_decimal_size(text(&obj, "Size")?)?;
        let in_use = match text(&obj, "Containers")? {
            "N/A" => false,
            n if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
                n.bytes().any(|b| b != b'0')
            }
            _ => return Err(ParseError("Containers")),
        };
        if !in_use {
            items.push(ProviderItem {
                key: id.to_owned(),
                label: id.to_owned(),
                reported_bytes: size,
                paths: Vec::new(),
            });
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DF: &str = include_str!("../../tests/fixtures/docker/system_df.jsonl");
    const DANGLING: &str = include_str!("../../tests/fixtures/docker/images_dangling.jsonl");
    const DANGLING_SYN: &str =
        include_str!("../../tests/fixtures/docker/images_dangling_synthetic.jsonl");

    // FR-021, acceptance criterion 6 (output recorded on the owner's Mac)
    #[test]
    fn parses_system_df_fixture() {
        assert_eq!(
            parse_system_df(DF),
            Ok(SystemDf {
                images: 4_630_000_000,
                containers: 31_350_000,
                volumes: 1_660_000_000,
                build_cache: 305_700_000,
            })
        );
    }

    // ADR 0004 §3: one bad line makes the whole output unusable.
    #[test]
    fn corrupt_line_is_unavailable() {
        let mut lines: Vec<&str> = DF.lines().collect();
        lines[1] = "{\"Type\":\"Containers\",\"Reclaimable\":";
        assert!(parse_system_df(&lines.join("\n")).is_err());
        assert!(parse_system_df("Cannot connect to the Docker daemon").is_err());
    }

    // ADR 0004 §3: fail closed on missing, repeated or unknown rows and on
    // reclaimable text that does not match.
    #[test]
    fn system_df_rows_are_strict() {
        let lines: Vec<&str> = DF.lines().collect();
        assert!(parse_system_df("").is_err());
        assert!(parse_system_df(&lines[..3].join("\n")).is_err());
        let twice = format!("{DF}{}", lines[0]);
        assert!(parse_system_df(&twice).is_err());
        let unknown = DF.replace("\"Build Cache\"", "\"Snapshots\"");
        assert!(parse_system_df(&unknown).is_err());
        let bad_pct = DF.replace("4.63GB (59%)", "4.63GB (59");
        assert!(parse_system_df(&bad_pct).is_err());
        let not_str = DF.replace("\"305.7MB\"", "305");
        assert!(parse_system_df(&not_str).is_err());
        assert!(parse_system_df("[1]").is_err());
    }

    // FR-021: recorded image is still used by 2 containers: not an item.
    #[test]
    fn dangling_image_in_use_is_not_an_item() {
        assert_eq!(parse_dangling_images(DANGLING), Ok(Vec::new()));
        assert_eq!(parse_dangling_images(""), Ok(Vec::new()));
    }

    // FR-021: one item per unused dangling image, keyed by its id.
    #[test]
    fn parses_dangling_images() {
        let items = parse_dangling_images(DANGLING_SYN).unwrap();
        let got: Vec<_> = items
            .iter()
            .map(|i| {
                (
                    i.key.as_str(),
                    i.label.as_str(),
                    i.reported_bytes,
                    i.paths.len(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("0a1b2c3d4e5f", "0a1b2c3d4e5f", 1_250_000_000, 0),
                ("ffeeddccbbaa", "ffeeddccbbaa", 12_300, 0),
            ]
        );
    }

    // ADR 0004 §3: ids must be 12 or 64 lower-case hex; anything else fails.
    #[test]
    fn dangling_image_bad_fields_fail_closed() {
        let line = DANGLING_SYN.lines().next().unwrap();
        for bad in [
            line.replace("0a1b2c3d4e5f", "../etc"),
            line.replace("0a1b2c3d4e5f", "0A1B2C3D4E5F"),
            line.replace("0a1b2c3d4e5f", "--force"),
            line.replace("\"Containers\":\"0\"", "\"Containers\":\"x\""),
            line.replace("1.25GB", "lots"),
            line.replace("\"ID\"", "\"Id\""),
            "not json".to_string(),
        ] {
            assert!(parse_dangling_images(&bad).is_err(), "{bad}");
        }
        let long = line.replace("0a1b2c3d4e5f", &format!("sha256:{}", "a".repeat(64)));
        assert!(parse_dangling_images(&long).is_ok());
    }
}
