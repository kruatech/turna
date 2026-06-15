//! MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC32) computation

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

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

/// Verify MESSAGE-INTEGRITY in constant time.
///
/// Uses `hmac`'s built-in `verify_slice`, which performs a constant-time tag
/// comparison via the vetted `subtle`/`crypto-common` machinery — we no longer
/// hand-roll the comparison (A3-Q5).
pub fn verify_message_integrity(message_bytes: &[u8], key: &[u8], expected: &[u8; 20]) -> bool {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message_bytes);
    mac.verify_slice(expected).is_ok()
}

/// Compute HMAC-SHA-256 for MESSAGE-INTEGRITY-SHA256 (RFC 8489). Returns the
/// full 32-byte tag; callers may left-truncate to a multiple of 4 (>= 16).
pub fn compute_message_integrity_sha256(message_bytes: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Verify MESSAGE-INTEGRITY-SHA256 in constant time. `expected` may be a
/// left-truncated tag (16..=32 bytes, a multiple of 4) or the full 32 bytes.
pub fn verify_message_integrity_sha256(message_bytes: &[u8], key: &[u8], expected: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message_bytes);
    if expected.len() == 32 {
        mac.verify_slice(expected).is_ok()
    } else {
        mac.verify_truncated_left(expected).is_ok()
    }
}

/// Compute CRC32 fingerprint (XOR with 0x5354554E).
pub fn compute_fingerprint(message_bytes: &[u8]) -> u32 {
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    crc.checksum(message_bytes) ^ FINGERPRINT_XOR
}

// NOTE (A3-Q3): the long-term credential key — MD5(username:realm:password) —
// lives in a single place, `turna_crypto::long_term_key`. The duplicate that
// used to sit here was dead (the key is always passed into compute/verify as a
// parameter) and has been removed to keep one source of truth.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_correct_and_rejects_tampered() {
        let key = b"a-test-key";
        let msg = b"stun message body bytes";
        let tag = compute_message_integrity(msg, key);

        assert!(verify_message_integrity(msg, key, &tag));

        // A single flipped bit in the tag is rejected.
        let mut tampered = tag;
        tampered[0] ^= 0xff;
        assert!(!verify_message_integrity(msg, key, &tampered));

        // A wrong key is rejected.
        assert!(!verify_message_integrity(msg, b"wrong-key", &tag));
    }

    #[test]
    fn sha256_verify_accepts_correct_and_rejects_tampered() {
        let key = b"a-test-key";
        let msg = b"stun message body bytes";
        let tag = compute_message_integrity_sha256(msg, key);

        assert!(verify_message_integrity_sha256(msg, key, &tag));

        let mut tampered = tag;
        tampered[0] ^= 0xff;
        assert!(!verify_message_integrity_sha256(msg, key, &tampered));

        assert!(!verify_message_integrity_sha256(msg, b"wrong-key", &tag));

        // A left-truncated 16-byte tag still verifies.
        assert!(verify_message_integrity_sha256(msg, key, &tag[..16]));
        // ...but a tampered truncated tag does not.
        let mut t16 = tag[..16].to_vec();
        t16[0] ^= 0xff;
        assert!(!verify_message_integrity_sha256(msg, key, &t16));
    }
}
