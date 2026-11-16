//! `xcrun simctl list -j`: the Xcode simulators and runtimes.
//!
//! The document is read strictly and as a whole by both parsers: a shape this
//! code does not know is a [`ParseError`], never a guess. Every field that is
//! read has to be there with its type (`isAvailable` and `isInternal` as
//! booleans, names and ids as text, `dataPathSize` as a whole number when
//! present). Only the key of an item is checked more closely, and an item
//! whose key could not be handed to the tool as one plain argument is left
//! out instead of failing the whole list.

use crate::tools::{ParseError, ProviderItem};
use serde_json::{Map, Value};

const RUNTIME_PREFIX: &str = "com.apple.CoreSimulator.SimRuntime.";

struct Device {
    /// Key of the `devices` entry: the identifier of the runtime it belongs to.
    runtime: String,
    udid: String,
    available: bool,
    name: String,
    /// What the tool reports for the device data; 0 when it reports none.
    bytes: u64,
}

struct Runtime {
    identifier: String,
    internal: bool,
    name: String,
}

struct Document {
    devices: Vec<Device>,
    runtimes: Vec<Runtime>,
}

fn text(obj: &Map<String, Value>, field: &'static str) -> Result<String, ParseError> {
    obj.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ParseError(field))
}

fn flag(obj: &Map<String, Value>, field: &'static str) -> Result<bool, ParseError> {
    obj.get(field)
        .and_then(Value::as_bool)
        .ok_or(ParseError(field))
}

fn object<'a>(value: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>, ParseError> {
    value.as_object().ok_or(ParseError(what))
}

fn document(stdout: &str) -> Result<Document, ParseError> {
    let root: Value = serde_json::from_str(stdout).map_err(|_| ParseError("json"))?;
    let root = object(&root, "document")?;
    let by_runtime = root
        .get("devices")
        .and_then(Value::as_object)
        .ok_or(ParseError("devices"))?;
    let listed = root
        .get("runtimes")
        .and_then(Value::as_array)
        .ok_or(ParseError("runtimes"))?;

    let mut devices = Vec::new();
    for (runtime, list) in by_runtime {
        for entry in list.as_array().ok_or(ParseError("devices"))? {
            let obj = object(entry, "device")?;
            let bytes = match obj.get("dataPathSize") {
                None => 0,
                Some(size) => size.as_u64().ok_or(ParseError("dataPathSize"))?,
            };
            devices.push(Device {
                runtime: runtime.clone(),
                udid: text(obj, "udid")?,
                available: flag(obj, "isAvailable")?,
                name: text(obj, "name")?,
                bytes,
            });
        }
    }
    let mut runtimes = Vec::new();
    for entry in listed {
        let obj = object(entry, "runtime")?;
        // Read although unused: the format is checked, not assumed.
        flag(obj, "isAvailable")?;
        runtimes.push(Runtime {
            identifier: text(obj, "identifier")?,
            internal: flag(obj, "isInternal")?,
            name: text(obj, "name")?,
        });
    }
    Ok(Document { devices, runtimes })
}

/// `8-4-4-4-12` hex digits.
fn is_udid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The runtime prefix and then letters, digits, `-`, `.` and `_`, starting
/// with a letter or digit.
fn is_runtime_id(id: &str) -> bool {
    id.strip_prefix(RUNTIME_PREFIX).is_some_and(|rest| {
        rest.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    })
}

/// Simulators the tool marks unavailable.
pub(crate) fn parse_unavailable_simulators(stdout: &str) -> Result<Vec<ProviderItem>, ParseError> {
    let doc = document(stdout)?;
    Ok(doc
        .devices
        .into_iter()
        .filter(|d| !d.available && is_udid(&d.udid))
        .map(|d| ProviderItem {
            label: format!(
                "{} ({})",
                d.name,
                d.runtime.strip_prefix(RUNTIME_PREFIX).unwrap_or(&d.runtime)
            ),
            key: d.udid,
            reported_bytes: d.bytes,
            paths: Vec::new(),
        })
        .collect())
}

/// Installed simulator runtimes the tool does not mark internal. The list
/// gives no size, so they report 0.
pub(crate) fn parse_runtimes(stdout: &str) -> Result<Vec<ProviderItem>, ParseError> {
    let doc = document(stdout)?;
    Ok(doc
        .runtimes
        .into_iter()
        .filter(|r| !r.internal && is_runtime_id(&r.identifier))
        .map(|r| ProviderItem {
            key: r.identifier,
            label: r.name,
            reported_bytes: 0,
            paths: Vec::new(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = include_str!("../../tests/fixtures/simctl/list.json");
    const UDID: &str = "1A2B3C4D-0000-4000-8000-000000000001";
    const RT: &str = "com.apple.CoreSimulator.SimRuntime.iOS-17-0";

    fn rows(items: Vec<ProviderItem>) -> Vec<(String, String, u64)> {
        items
            .into_iter()
            .map(|i| (i.key, i.label, i.reported_bytes))
            .collect()
    }

    fn devices(body: &str) -> String {
        format!(
            r#"{{"runtimes":[],"devices":{{"com.apple.CoreSimulator.SimRuntime.iOS-1-0":[{body}]}}}}"#
        )
    }

    fn runtimes(body: &str) -> String {
        format!(r#"{{"devices":{{}},"runtimes":[{body}]}}"#)
    }

    // FR-021: only what the tool says is unavailable; the size is the one the
    // tool reports for the device data, 0 when it reports none.
    #[test]
    fn unavailable_simulators_listed() {
        assert_eq!(
            rows(parse_unavailable_simulators(LIST).unwrap()),
            [
                (
                    "1A2B3C4D-0000-4000-8000-000000000003".to_owned(),
                    "iPhone 8 (iOS-15-5)".to_owned(),
                    12_345_678
                ),
                (
                    "1A2B3C4D-0000-4000-8000-000000000004".to_owned(),
                    "iPad Air (iOS-15-5)".to_owned(),
                    0
                ),
            ]
        );
    }

    // Available simulators, booted or not, are never items; none unavailable
    // is an empty list, not an error.
    #[test]
    fn available_simulators_are_never_items() {
        let json = devices(&format!(
            r#"{{"udid":"{UDID}","isAvailable":true,"state":"Booted","name":"A"}},
               {{"udid":"1A2B3C4D-0000-4000-8000-000000000002","isAvailable":true,"name":"B"}}"#
        ));
        assert_eq!(parse_unavailable_simulators(&json), Ok(vec![]));
        let empty = r#"{"runtimes":[],"devices":{}}"#;
        assert_eq!(parse_unavailable_simulators(empty), Ok(vec![]));
    }

    // FR-021: every runtime that is not internal; the list gives no size.
    #[test]
    fn runtimes_listed_without_internal_ones() {
        assert_eq!(
            rows(parse_runtimes(LIST).unwrap()),
            [
                (RT.to_owned(), "iOS 17.0".to_owned(), 0),
                (
                    "com.apple.CoreSimulator.SimRuntime.iOS-15-5".to_owned(),
                    "iOS 15.5".to_owned(),
                    0
                ),
            ]
        );
    }

    // A key that could not be passed to the tool as one argument is no item.
    #[test]
    fn keys_that_do_not_validate_are_dropped() {
        for udid in [
            "",
            "../../etc",
            "1A2B3C4D-0000-4000-8000-00000000000",
            "1A2B3C4D-0000-4000-8000-0000000000012",
            "1A2B3C4D-0000-4000-8000-00000000000G",
            "-1A2B3C4D-0000-4000-8000-000000000001",
            "1A2B3C4D 0000 4000 8000 000000000001",
            "1A2B3C4D-0000-4000-8000-000000000001\n",
            "--all",
        ] {
            let json = devices(&format!(
                r#"{{"udid":{udid:?},"isAvailable":false,"name":"x"}}"#
            ));
            assert_eq!(parse_unavailable_simulators(&json), Ok(vec![]), "{udid:?}");
        }
        for id in [
            "",
            "iOS-17-0",
            "com.apple.CoreSimulator.SimRuntime.",
            "com.apple.CoreSimulator.SimRuntime.iOS 17",
            "com.apple.CoreSimulator.SimRuntime.-flag",
            "com.apple.CoreSimulator.SimRuntime..hidden",
            "com.apple.CoreSimulator.SimRuntime.../x",
            "-com.apple.CoreSimulator.SimRuntime.iOS-17-0",
            "com.apple.CoreSimulator.SimRuntime.iOS-17-0\n",
        ] {
            let json = runtimes(&format!(
                r#"{{"identifier":{id:?},"isInternal":false,"isAvailable":true,"name":"x"}}"#
            ));
            assert_eq!(parse_runtimes(&json), Ok(vec![]), "{id:?}");
        }
    }

    // Output that does not fully match is an error, never guessed around.
    #[test]
    fn unexpected_shapes_are_errors() {
        let dev = |extra: &str| {
            devices(&format!(
                r#"{{"udid":"{UDID}","isAvailable":false,"name":"x"{extra}}}"#
            ))
        };
        let whole = [
            String::new(),
            "not json".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            r#"{"runtimes":[]}"#.to_owned(),
            r#"{"devices":{}}"#.to_owned(),
            r#"{"devices":[],"runtimes":[]}"#.to_owned(),
            r#"{"devices":{},"runtimes":{}}"#.to_owned(),
            r#"{"devices":{"r":{}},"runtimes":[]}"#.to_owned(),
            r#"{"devices":{},"runtimes":[]} trailing"#.to_owned(),
        ];
        let bad_devices = [
            devices("1"),
            devices(r#"{"isAvailable":false,"name":"x"}"#),
            devices(&format!(r#"{{"udid":"{UDID}","name":"x"}}"#)),
            devices(&format!(
                r#"{{"udid":"{UDID}","isAvailable":"false","name":"x"}}"#
            )),
            devices(&format!(r#"{{"udid":"{UDID}","isAvailable":false}}"#)),
            devices(&format!(
                r#"{{"udid":"{UDID}","isAvailable":false,"name":3}}"#
            )),
            dev(r#","dataPathSize":"9""#),
            dev(r#","dataPathSize":-1"#),
            dev(r#","dataPathSize":1.5"#),
        ];
        for json in whole.iter().chain(&bad_devices) {
            assert!(parse_unavailable_simulators(json).is_err(), "{json}");
        }
        let bad_runtimes = [
            runtimes("1"),
            runtimes(r#"{"isInternal":false,"isAvailable":true,"name":"x"}"#),
            runtimes(&format!(
                r#"{{"identifier":"{RT}","isAvailable":true,"name":"x"}}"#
            )),
            runtimes(&format!(
                r#"{{"identifier":"{RT}","isInternal":"no","isAvailable":true,"name":"x"}}"#
            )),
            runtimes(&format!(
                r#"{{"identifier":"{RT}","isInternal":false,"name":"x"}}"#
            )),
            runtimes(&format!(
                r#"{{"identifier":"{RT}","isInternal":false,"isAvailable":true}}"#
            )),
        ];
        for json in whole.iter().chain(&bad_runtimes) {
            assert!(parse_runtimes(json).is_err(), "{json}");
        }
    }

    // The two parsers read the same document: a runtime problem does not
    // hide behind a good device list, and the other way round.
    #[test]
    fn both_parsers_check_the_whole_document() {
        let bad_runtime = r#"{"devices":{},"runtimes":[{"identifier":3}]}"#;
        assert!(parse_unavailable_simulators(bad_runtime).is_err());
        let bad_device = r#"{"runtimes":[],"devices":{"r":[{"udid":1}]}}"#;
        assert!(parse_runtimes(bad_device).is_err());
    }

    // The name is untrusted text: kept as is, escaped by whoever prints it.
    #[test]
    fn labels_keep_the_name_untouched() {
        // Built here: the compiler rejects the bidi character in a literal.
        let bidi = char::from_u32(0x202e).unwrap();
        let json = devices(&format!(
            r#"{{"udid":"{UDID}","isAvailable":false,"name":"a{bidi}b\u001b[31m"}}"#
        ));
        let items = parse_unavailable_simulators(&json).unwrap();
        assert_eq!(items[0].label, format!("a{bidi}b\u{1b}[31m (iOS-1-0)"));
    }
}
