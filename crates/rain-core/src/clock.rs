//! Time source, injected so age checks are deterministic in tests.

use std::time::SystemTime;

/// Source of the current time.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Clock that always returns the same instant.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub SystemTime);

#[cfg(any(test, feature = "testing"))]
impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // NFR-009
    #[test]
    fn fixed_clock_returns_configured_instant() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock: &dyn Clock = &FixedClock(t);
        assert_eq!(clock.now(), t);
        assert_eq!(clock.now(), t);
    }
}
