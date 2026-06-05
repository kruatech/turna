//! MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC32) computation

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const FINGERPRINT_XOR: u32 = 0x5354554E;

/// Compute HMAC-SHA1 for MESSAGE-INTEGRITY.
///
/// `message_bytes` — STUN message up to (but not including) the MESSAGE-INTEGRITY attribute,
/// with the length field adjusted to include MESSAGE-INTEGRITY (24 bytes: 4 header + 20 value).
pub fn compute_message_integrity(message_bytes: &[u8], key: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message_bytes);
    let result = mac.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Verify MESSAGE-INTEGRITY.
pub fn verify_message_integrity(message_bytes: &[u8], key: &[u8], expected: &[u8; 20]) -> bool {
    let computed = compute_message_integrity(message_bytes, key);
    constant_time_eq(&computed, expected)
}

/// Compute CRC32 fingerprint (XOR with 0x5354554E).
pub fn compute_fingerprint(message_bytes: &[u8]) -> u32 {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    crc.checksum(message_bytes) ^ FINGERPRINT_XOR
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Build the long-term credential key: MD5(username:realm:password)
pub fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{username}:{realm}:{password}");
    let digest = md5::compute(input.as_bytes());
    digest.0.to_vec()
}
