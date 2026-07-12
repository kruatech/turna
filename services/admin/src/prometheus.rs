//! Minimal Prometheus text-format parser -> normalized JSON.
//!
//! The frontend must NOT parse Prometheus itself; this turns the node's
//! `/metrics` output into `{ counters, gauges, labeled }`:
//!   - `counters`: unlabeled samples whose TYPE is `counter` (or name ends
//!     with `_total` when TYPE is absent).
//!   - `gauges`:   other unlabeled samples.
//!   - `labeled`:  samples carrying labels, grouped by metric name, each entry
//!     `{ labels: {..}, value: f64 }`.
//!
//! We read `# TYPE name kind` comment lines to classify; all other `#` lines
//! are ignored. Metric names are taken verbatim from the node (never invented).

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct LabeledSample {
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

#[derive(Serialize, Default)]
pub struct Normalized {
    pub counters: BTreeMap<String, f64>,
    pub gauges: BTreeMap<String, f64>,
    pub labeled: BTreeMap<String, Vec<LabeledSample>>,
}

pub fn parse(input: &str) -> Normalized {
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    let mut out = Normalized::default();

    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            // Only "# TYPE <name> <kind>" is meaningful; ignore HELP/other.
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "TYPE" {
                types.insert(parts[1].to_string(), parts[2].to_string());
            }
            continue;
        }

        // Sample line: "name{labels} value [timestamp]" or "name value".
        // Determine the value token: the last whitespace-delimited token, or the
        // one before it when the last token is a trailing timestamp.
        let mut it = line.rsplitn(3, char::is_whitespace);
        let last = it.next().unwrap_or("");
        let mid = it.next();

        let value_str = if last.parse::<f64>().is_ok() {
            last
        } else if let Some(m) = mid {
            // `last` is likely a timestamp; the value is `mid`.
            if m.parse::<f64>().is_ok() {
                m
            } else {
                continue;
            }
        } else {
            continue;
        };

        // Re-derive `name{labels}` from the original line (robust to spaces
        // inside `{...}`, which a naive whitespace split would mishandle).
        let name_labels = strip_value_suffix(line, value_str);
        let value: f64 = match value_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let (name, labels) = split_name_labels(&name_labels);
        if name.is_empty() {
            continue;
        }
        if labels.is_empty() {
            let is_counter = matches!(types.get(&name).map(String::as_str), Some("counter"))
                || name.ends_with("_total");
            if is_counter {
                out.counters.insert(name, value);
            } else {
                out.gauges.insert(name, value);
            }
        } else {
            out.labeled
                .entry(name)
                .or_default()
                .push(LabeledSample { labels, value });
        }
    }

    out
}

/// Remove the trailing value (and optional timestamp) from a sample line,
/// leaving `name{labels}` or `name`.
fn strip_value_suffix(line: &str, value: &str) -> String {
    // Find the last occurrence of a whitespace-delimited `value` token.
    if let Some(pos) = line.rfind(value) {
        line[..pos].trim_end().to_string()
    } else {
        line.trim_end().to_string()
    }
}

fn split_name_labels(s: &str) -> (String, BTreeMap<String, String>) {
    let mut labels = BTreeMap::new();
    match s.find('{') {
        Some(idx) => {
            let name = s[..idx].trim().to_string();
            if let Some(end) = s.rfind('}') {
                let inner = &s[idx + 1..end];
                for pair in split_labels(inner) {
                    if let Some((k, v)) = pair.split_once('=') {
                        let v = v.trim().trim_matches('"');
                        labels.insert(k.trim().to_string(), v.to_string());
                    }
                }
            }
            (name, labels)
        }
        None => (s.trim().to_string(), labels),
    }
}

/// Split label pairs on commas that are not inside quotes.
fn split_labels(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in inner.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ',' if !in_quotes => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_counter_gauge_labeled() {
        let input = "\
# HELP turna_backend_readiness readiness
# TYPE turna_backend_readiness gauge
turna_backend_readiness 1
# TYPE turna_parser_rejections_total counter
turna_parser_rejections_total 0
failover_claimed_total 3
turna_auth_failures_by_reason_total{reason=\"bad_mac\"} 5
turna_auth_failures_by_reason_total{reason=\"expired\"} 2
";
        let n = parse(input);
        assert_eq!(n.gauges.get("turna_backend_readiness"), Some(&1.0));
        assert_eq!(n.counters.get("turna_parser_rejections_total"), Some(&0.0));
        // no TYPE line, but ends with _total -> counter
        assert_eq!(n.counters.get("failover_claimed_total"), Some(&3.0));
        let auth = n
            .labeled
            .get("turna_auth_failures_by_reason_total")
            .unwrap();
        assert_eq!(auth.len(), 2);
        assert!(auth.iter().any(
            |s| s.labels.get("reason").map(String::as_str) == Some("bad_mac") && s.value == 5.0
        ));
    }
}
