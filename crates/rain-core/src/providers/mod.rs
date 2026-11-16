//! Pure parsers for external tool output. Strict: anything not
//! fully understood is a [`crate::tools::ParseError`].

pub(crate) mod docker;
pub(crate) mod size_text;
