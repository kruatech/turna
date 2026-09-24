//! The optional sinks through the real `init_with_config` path.
//!
//! Its own test binary because `init` installs the process-global subscriber,
//! which can happen once per process.

use turna_observability::log_file::{LogFileConfig, Rotation};
use turna_observability::{FileSink, TelemetryConfig};

#[test]
fn file_sink_receives_redacted_lines_and_stdout_can_be_off() {
    let dir = std::env::temp_dir().join(format!("turna-sinks-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("turna.log");

    let _guard = turna_observability::init_with_config(TelemetryConfig {
        log_filter: "info".into(),
        log_to_stdout: false,
        redact_stdout_addresses: true,
        log_file: Some(FileSink {
            file: LogFileConfig {
                path: path.clone(),
                rotation: Rotation::Size(1 << 20),
                max_files: 2,
            },
            level: tracing::level_filters::LevelFilter::INFO,
        }),
        ..Default::default()
    })
    .expect("telemetry with a file sink");

    tracing::debug!("filtered out by the global filter");
    tracing::info!(
        src = "192.0.2.7:4000",
        shared_secret = "s3cr3t",
        "allocation created"
    );

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("allocation created"), "{text}");
    assert!(!text.contains("filtered out"), "{text}");
    // Same redaction as stdout: the address switch and the credential backstop.
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(text.contains("shared_secret=[redacted]"), "{text}");
    assert!(
        !text.contains("192.0.2.7"),
        "address must be hashed: {text}"
    );
    // No colour codes in a file.
    assert!(!text.contains('\u{1b}'), "ANSI escape in file: {text:?}");

    // SIGHUP path: move the file away, reopen, and the next line lands at the path.
    std::fs::rename(&path, dir.join("moved.log")).unwrap();
    assert!(turna_observability::log_file::reopen());
    tracing::info!("after reopen");
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("after reopen"));

    let stats = turna_observability::log_sink_stats();
    assert_eq!(stats.file_write_errors, 0);
    let _ = std::fs::remove_dir_all(&dir);
}
