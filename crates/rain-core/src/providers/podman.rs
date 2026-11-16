//! Podman CLI output: `podman system df --format json`.

use crate::tools::ParseError;
use serde_json::Value;

/// Reclaimable bytes per `podman system df` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PodmanDf {
    pub images: u64,
    pub containers: u64,
    pub volumes: u64,
}

/// FR-021: a JSON array with one object per row (`Images`, `Containers`,
/// `Local Volumes`), each with its reclaimable size in bytes as the whole
/// number `RawReclaimable`. Every row must appear exactly once; the text
/// fields (`Size`, `Reclaimable`) are not read.
pub(crate) fn parse_system_df(stdout: &str) -> Result<PodmanDf, ParseError> {
    let doc: Value = serde_json::from_str(stdout).map_err(|_| ParseError("json"))?;
    let rows = doc.as_array().ok_or(ParseError("document"))?;
    let mut found: [Option<u64>; 3] = [None; 3];
    for row in rows {
        let obj = row.as_object().ok_or(ParseError("row"))?;
        let slot = match obj.get("Type").and_then(Value::as_str) {
            Some("Images") => 0,
            Some("Containers") => 1,
            Some("Local Volumes") => 2,
            _ => return Err(ParseError("Type")),
        };
        let bytes = obj
            .get("RawReclaimable")
            .and_then(Value::as_u64)
            .ok_or(ParseError("RawReclaimable"))?;
        if found[slot].replace(bytes).is_some() {
            return Err(ParseError("repeated Type"));
        }
    }
    match found {
        [Some(images), Some(containers), Some(volumes)] => Ok(PodmanDf {
            images,
            containers,
            volumes,
        }),
        _ => Err(ParseError("missing Type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DF: &str = include_str!("../../tests/fixtures/podman/system_df.json");

    fn row(kind: &str, reclaimable: &str) -> String {
        format!(
            r#"{{"Type":"{kind}","Total":1,"Active":0,"RawSize":9,"RawReclaimable":{reclaimable}}}"#
        )
    }

    fn doc(rows: &[String]) -> String {
        format!("[{}]", rows.join(","))
    }

    fn all(images: &str, containers: &str, volumes: &str) -> String {
        doc(&[
            row("Images", images),
            row("Containers", containers),
            row("Local Volumes", volumes),
        ])
    }

    // FR-021: the three rows, reclaimable bytes as the tool counts them.
    #[test]
    fn parses_podman_fixture() {
        assert_eq!(
            parse_system_df(DF),
            Ok(PodmanDf {
                images: 922_956_674,
                containers: 1_800_000,
                volumes: 300_000_000,
            })
        );
    }

    #[test]
    fn row_order_does_not_matter_and_zero_is_valid() {
        let json = doc(&[
            row("Local Volumes", "0"),
            row("Images", "5"),
            row("Containers", "7"),
        ]);
        assert_eq!(
            parse_system_df(&json),
            Ok(PodmanDf {
                images: 5,
                containers: 7,
                volumes: 0
            })
        );
    }

    // Output that does not fully match is an error, never guessed around.
    #[test]
    fn unexpected_output_is_an_error() {
        let bad = [
            String::new(),
            "not json".to_owned(),
            "{}".to_owned(),
            "[]".to_owned(),
            "[1]".to_owned(),
            format!("{} trailing", all("1", "2", "3")),
            // a row missing, repeated or unknown
            doc(&[row("Images", "1"), row("Containers", "2")]),
            doc(&[
                row("Images", "1"),
                row("Images", "1"),
                row("Containers", "2"),
                row("Local Volumes", "3"),
            ]),
            doc(&[
                row("Images", "1"),
                row("Containers", "2"),
                row("Local Volumes", "3"),
                row("Build Cache", "4"),
            ]),
            // the size is a whole number
            all("\"1\"", "2", "3"),
            all("-1", "2", "3"),
            all("1.5", "2", "3"),
            all("null", "2", "3"),
            doc(&[
                r#"{"Type":"Images","Total":1}"#.to_owned(),
                row("Containers", "2"),
                row("Local Volumes", "3"),
            ]),
            doc(&[
                r#"{"RawReclaimable":1}"#.to_owned(),
                row("Containers", "2"),
                row("Local Volumes", "3"),
            ]),
        ];
        for json in &bad {
            assert!(parse_system_df(json).is_err(), "{json}");
        }
    }
}
