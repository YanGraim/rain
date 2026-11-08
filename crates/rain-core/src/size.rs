//! Human-readable sizes in decimal (SI) units.

// SI symbols are locale-invariant, so they are not part of the message catalog.
const UNITS: [&str; 4] = ["kB", "MB", "GB", "TB"];

/// Formats a byte count with one decimal (half-up), e.g.
/// `1_200_000_000` -> `1.2 GB`. Integer math avoids float rounding drift.
pub fn format_decimal(bytes: u64) -> String {
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let bytes = u128::from(bytes);
    let mut divisor: u128 = 1000;
    let mut unit = 0;
    loop {
        let tenths = (bytes * 10 + divisor / 2) / divisor;
        // Promote when rounding reaches 1000.0 (e.g. 999_950 B -> 1.0 MB).
        if tenths < 10_000 || unit == UNITS.len() - 1 {
            return format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit]);
        }
        divisor *= 1000;
        unit += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FR-014
    #[test]
    fn formats_decimal_units() {
        let cases = [
            (0, "0 B"),
            (1, "1 B"),
            (999, "999 B"),
            (1_000, "1.0 kB"),
            (1_500, "1.5 kB"),
            (999_949, "999.9 kB"),
            (999_950, "1.0 MB"),
            (1_200_000_000, "1.2 GB"),
            (1_250_000_000, "1.3 GB"),
            (5_000_000_000_000, "5.0 TB"),
            (u64::MAX, "18446744.1 TB"),
        ];
        for (bytes, want) in cases {
            assert_eq!(format_decimal(bytes), want, "bytes = {bytes}");
        }
    }
}
