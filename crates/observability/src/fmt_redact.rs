//! Address redaction for the `fmt` (stdout) layer.
//!
//! # Why this exists at the sink rather than at the call sites
//!
//! `turna-relay` redacts through `loggable_addr`, which works and is not enough:
//! it only reaches lines that crate writes. `turna-session` logs `%client_addr`
//! and `%peer_ip` in eight places of its own — including `allocation created`
//! and `allocation removed`, the same events the relay logs redacted. The same
//! address therefore appeared twice, once as a hash and once verbatim, and the
//! verbatim one is the only one that matters to whoever holds the log.
//!
//! Session cannot call the relay's function: relay depends on session, not the
//! other way round. Pushing the check to the formatter is what makes the switch
//! mean what an operator reads it to mean, and it covers call sites nobody has
//! audited yet — including ones written after this.
//!
//! # What it does not do
//!
//! It matches on the FIELD NAME (`src`, `peer_ip`, `client_addr`, …), the same
//! list the syslog exporter uses. An address logged under a name outside that
//! list, or interpolated into the message text, passes through. Scanning every
//! value for something address-shaped was considered and rejected: it runs on
//! every field of every line, and it would redact node ids, cluster addresses
//! and listen addresses, which are not personal data and are exactly what an
//! operator needs to read the line.

use std::fmt;

use tracing::field::{Field, Visit};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::FormatFields;

use crate::syslog::{hash_address, looks_like_address, process_salt};

/// Whether the `fmt` layer redacts. Set once at startup.
static REDACT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Turn stdout redaction on or off. Called by `init_telemetry` from
/// `[turn.observability] log_allocation_addresses`.
pub fn set_redact_addresses(on: bool) {
    REDACT.store(on, std::sync::atomic::Ordering::Relaxed);
}

fn redacting() -> bool {
    REDACT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Replace a value with its salted label when the field name names an address.
fn value_for(name: &str, raw: &str) -> String {
    if redacting() && looks_like_address(name) {
        match process_salt() {
            Some(salt) => hash_address(salt, raw),
            // No salt means redaction was disabled at startup with a logged
            // reason. Writing the address is the honest outcome; a label derived
            // from something predictable would look like a hash and protect
            // nothing.
            None => raw.to_string(),
        }
    } else {
        raw.to_string()
    }
}

/// `FormatFields` for the human-readable formatter: `key=value`, space separated,
/// message field first and unkeyed, which is what the default does.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedactingFields;

struct TextVisitor<'a, 'w> {
    writer: &'a mut Writer<'w>,
    result: fmt::Result,
    first: bool,
}

impl TextVisitor<'_, '_> {
    fn write(&mut self, name: &str, raw: &str) {
        if self.result.is_err() {
            return;
        }
        let sep = if self.first { "" } else { " " };
        self.first = false;
        let value = value_for(name, raw);
        self.result = if name == "message" {
            write!(self.writer, "{sep}{value}")
        } else {
            write!(self.writer, "{sep}{name}={value}")
        };
    }
}

impl Visit for TextVisitor<'_, '_> {
    // `%src` and `?peer` both arrive here: tracing records Display and Debug
    // values through `record_debug`, with `format_args!` already applied for
    // Display. `{:?}` on `Arguments` prints the formatted text without quotes,
    // so an address reads the same either way.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.write(field.name(), &format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.write(field.name(), value);
    }
}

impl<'writer> FormatFields<'writer> for RedactingFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut visitor = TextVisitor {
            writer: &mut writer,
            result: Ok(()),
            first: true,
        };
        fields.record(&mut visitor);
        visitor.result
    }
}

/// `FormatFields` for `json_logs = true`.
///
/// Separate because the JSON event formatter embeds this output inside an object
/// and expects `"key":value` fragments. Emitting the text form there would
/// produce a line that is not JSON — and a malformed line is usually dropped by
/// the collector without a word, which loses exactly the event worth keeping.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedactingJsonFields;

struct JsonVisitor<'a, 'w> {
    writer: &'a mut Writer<'w>,
    result: fmt::Result,
    first: bool,
}

/// Escape per RFC 8259 §7. Hand-written rather than pulled from `serde_json`,
/// which this crate does not depend on: the input is a field name or an
/// already-formatted value, and the seven cases below are the whole grammar.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

impl JsonVisitor<'_, '_> {
    fn write(&mut self, name: &str, raw: &str) {
        if self.result.is_err() {
            return;
        }
        let sep = if self.first { "" } else { "," };
        self.first = false;
        let value = value_for(name, raw);
        // Every value is emitted as a JSON string, including numbers and bools.
        // That differs from the stock JsonFields, which types them — and it is
        // the safe direction: a consumer that expects a number reads a string
        // and says so, whereas a malformed line disappears.
        self.result = write!(
            self.writer,
            "{sep}\"{}\":\"{}\"",
            json_escape(name),
            json_escape(&value)
        );
    }
}

impl Visit for JsonVisitor<'_, '_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.write(field.name(), &format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.write(field.name(), value);
    }
}

impl<'writer> FormatFields<'writer> for RedactingJsonFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut visitor = JsonVisitor {
            writer: &mut writer,
            result: Ok(()),
            first: true,
        };
        fields.record(&mut visitor);
        visitor.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_covers_the_cases_that_break_a_line() {
        assert_eq!(json_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(json_escape(r"a\b"), r"a\\b");
        assert_eq!(json_escape("a\nb"), r"a\nb");
        assert_eq!(json_escape("a\u{1}b"), r"a\u0001b");
        assert_eq!(json_escape("192.0.2.1:5000"), "192.0.2.1:5000");
    }

    #[test]
    fn only_address_named_fields_are_redacted() {
        set_redact_addresses(true);
        // A field that is not an address passes through even while redacting.
        assert_eq!(value_for("node_id", "turna-1"), "turna-1");
        // An address-named field is replaced, and the label is stable.
        let a = value_for("src", "192.0.2.1:5000");
        let b = value_for("src", "192.0.2.1:5000");
        assert_eq!(a, b, "the label must be stable within a process");
        if process_salt().is_some() {
            assert_ne!(a, "192.0.2.1:5000");
            assert!(a.starts_with("ip-"), "unexpected label: {a}");
        }
        set_redact_addresses(false);
        assert_eq!(value_for("src", "192.0.2.1:5000"), "192.0.2.1:5000");
    }
}
