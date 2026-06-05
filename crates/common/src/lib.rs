//! turna-common — shared utilities used across the workspace.
//!
//! Single home for helpers that several crates need:
//! - `now_ms()` — epoch milliseconds
//! - `hex_encode()`
//! - `base64_encode/decode()`
//! - `constant_time_eq()` — timing-safe comparison

pub mod drain;

use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Current time in milliseconds since UNIX epoch.
#[inline]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Current time in microseconds since UNIX epoch.
#[inline]
pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// Current time in seconds since UNIX epoch.
#[inline]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Simple ISO-8601 timestamp (without chrono dependency).
pub fn now_iso8601() -> String {
    let secs = now_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Approximate date (good enough for filenames and logs)
    let y = 1970 + days / 365;
    let d = days % 365;
    let month = d / 30 + 1;
    let day = d % 30 + 1;

    format!("{y:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Hex-encode bytes.
pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex-decode string to bytes. Returns None on invalid hex.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Constant-time byte comparison (prevents timing attacks).
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Type aliases (used everywhere)
// ---------------------------------------------------------------------------

pub type TrackId = String;
pub type AllocationId = String;

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

/// Generate a random ID with prefix.
pub fn generate_id(prefix: &str) -> String {
    format!("{prefix}-{:08x}", rand_u32())
}

/// Simple random u32 (no external dependency).
fn rand_u32() -> u32 {
    // Use address of stack variable as entropy source + timestamp
    let mut x = now_us() as u32;
    x ^= (&x as *const u32 as u64 & 0xFFFFFFFF) as u32;
    // xorshift32
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

/// Check if a port is in valid range for relay.
pub fn is_valid_relay_port(port: u16) -> bool {
    port >= 49152
}

/// Check if a port is in valid channel number range.
pub fn is_valid_channel(channel: u16) -> bool {
    channel >= 0x4000 && channel <= 0x7FFF
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ms_reasonable() {
        let ms = now_ms();
        assert!(ms > 1_700_000_000_000); // After 2023
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"hello";
        let hex = hex_encode(data);
        assert_eq!(hex, "68656c6c6f");
        assert_eq!(hex_decode(&hex).unwrap(), data);
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("xyz").is_none());
        assert!(hex_decode("0").is_none()); // odd length
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn generate_id_format() {
        let id = generate_id("alloc");
        assert!(id.starts_with("alloc-"));
        assert!(id.len() > 6);
    }

    #[test]
    fn port_validation() {
        assert!(!is_valid_relay_port(80));
        assert!(!is_valid_relay_port(3478));
        assert!(is_valid_relay_port(49152));
        assert!(is_valid_relay_port(65535));
    }

    #[test]
    fn channel_validation() {
        assert!(!is_valid_channel(0x3FFF));
        assert!(is_valid_channel(0x4000));
        assert!(is_valid_channel(0x7FFF));
        assert!(!is_valid_channel(0x8000));
    }

    #[test]
    fn iso8601_format() {
        let ts = now_iso8601();
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
    }
}
