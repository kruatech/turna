//! Optional config parser smoke test for generated artifacts.
//!
//! CI sets `TURNA_CONFIG_TEST_FILE` to a Helm-rendered `turn.toml` extracted
//! from the chart. When the variable is absent the test is a no-op, so normal
//! local `cargo test -p turna-config` remains unchanged.

use turna_config::TurnaConfig;

#[test]
fn external_config_file_parses_when_requested() {
    let Ok(path) = std::env::var("TURNA_CONFIG_TEST_FILE") else {
        return;
    };

    TurnaConfig::load(&path).unwrap_or_else(|err| {
        panic!("generated config did not parse/validate: {path}: {err}");
    });
}
