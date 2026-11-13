//! Sizes printed by Go's `units.HumanSize` (Docker, Podman): decimal units.

use crate::tools::ParseError;

/// FR-021: parses `0B`, `12.3kB`, `4.63GB`; rounds down to whole bytes.
pub(crate) fn parse_decimal_size(text: &str) -> Result<u64, ParseError> {
    const BAD: ParseError = ParseError("size");
    let split = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .ok_or(BAD)?;
    let (number, unit) = text.split_at(split);
    let scale: u128 = match unit {
        "B" => 1,
        "kB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        "PB" => 1_000_000_000_000_000,
        _ => return Err(BAD),
    };
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    let digits = |s: &str| !s.is_empty() && s.len() <= 18 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || (number.contains('.') && !digits(frac)) {
        return Err(BAD);
    }
    let whole: u128 = whole.parse().map_err(|_| BAD)?;
    let frac_bytes = if frac.is_empty() {
        0
    } else {
        let len = u32::try_from(frac.len()).map_err(|_| BAD)?;
        let frac: u128 = frac.parse().map_err(|_| BAD)?;
        frac * scale / 10u128.pow(len)
    };
    u64::try_from(whole * scale + frac_bytes).map_err(|_| BAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    // FR-021
    #[test]
    fn parses_docker_units() {
        assert_eq!(parse_decimal_size("0B"), Ok(0));
        assert_eq!(parse_decimal_size("512B"), Ok(512));
        assert_eq!(parse_decimal_size("12.3kB"), Ok(12_300));
        assert_eq!(parse_decimal_size("31.35MB"), Ok(31_350_000));
        assert_eq!(parse_decimal_size("4.63GB"), Ok(4_630_000_000));
        assert_eq!(parse_decimal_size("7.803GB"), Ok(7_803_000_000));
        assert_eq!(parse_decimal_size("1.5TB"), Ok(1_500_000_000_000));
        assert_eq!(parse_decimal_size("2PB"), Ok(2_000_000_000_000_000));
        assert_eq!(parse_decimal_size("1.0005kB"), Ok(1_000));
    }

    // ADR 0004 §3: fail closed on anything else.
    #[test]
    fn rejects_unknown_size_text() {
        for bad in [
            "",
            "B",
            "GB",
            "1",
            "1 GB",
            "1gb",
            "1GiB",
            "-1B",
            "+1B",
            "1.B",
            ".5GB",
            "1..2GB",
            "1e3B",
            "1,5GB",
            " 1B",
            "1B ",
            "N/A",
            "99999999999999999999PB",
        ] {
            assert!(parse_decimal_size(bad).is_err(), "{bad:?}");
        }
    }
}
