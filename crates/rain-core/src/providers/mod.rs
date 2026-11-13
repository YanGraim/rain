//! Pure parsers for external tool output (ADR 0004). Strict: anything not
//! fully understood is a [`crate::tools::ParseError`].

pub(crate) mod docker;
pub(crate) mod size_text;
