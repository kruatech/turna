//! Cryptographic primitives for TURN auth

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Generate a random nonce string.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Length of the truncated HMAC tag embedded in a stateless client nonce.
const NONCE_MAC_LEN: usize = 16;

/// Generate a random 32-byte key, e.g. a per-process key for stateless nonces.
pub fn random_key_32() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Issue a stateless, per-client TURN nonce bound to `client` and `ts_ms`.
///
/// Format: `hex(ts_ms) ":" base64url(HMAC-SHA1(server_key, ts_ms_be || client)[..16])`.
/// The nonce carries no server-side state; [`verify_client_nonce`] recomputes
/// the MAC to authenticate it. `client` should be the client's full address
/// string (IP:port) so a nonce issued to one peer cannot be replayed by another.
pub fn issue_client_nonce(server_key: &[u8], client: &str, ts_ms: u64) -> String {
    let mut mac = HmacSha1::new_from_slice(server_key).expect("HMAC accepts any key length");
    mac.update(&ts_ms.to_be_bytes());
    mac.update(client.as_bytes());
    let tag = mac.finalize().into_bytes();
    let tag_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &tag[..NONCE_MAC_LEN],
    );
    format!("{ts_ms:x}:{tag_b64}")
}

/// Verify a nonce produced by [`issue_client_nonce`] for `client`. Returns the
/// embedded timestamp (`ts_ms`) when the MAC matches in constant time, else
/// `None` (bad format, wrong client, or forged tag). Freshness (age vs the
/// nonce lifetime) is the caller's policy.
pub fn verify_client_nonce(server_key: &[u8], client: &str, nonce: &str) -> Option<u64> {
    let (ts_hex, tag_b64) = nonce.split_once(':')?;
    let ts_ms = u64::from_str_radix(ts_hex, 16).ok()?;
    let tag =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, tag_b64).ok()?;
    let mut mac = HmacSha1::new_from_slice(server_key).expect("HMAC accepts any key length");
    mac.update(&ts_ms.to_be_bytes());
    mac.update(client.as_bytes());
    mac.verify_truncated_left(&tag).ok().map(|()| ts_ms)
}

/// Compute long-term credential key: MD5(username:realm:password).
pub fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{username}:{realm}:{password}");
    md5::compute(input.as_bytes()).0.to_vec()
}

/// RFC 8489 long-term credential key for the SHA-256 password algorithm:
/// `SHA-256(username ":" realm ":" password)` (32 bytes). No SASLprep — parity
/// with [`long_term_key`], which also skips it.
pub fn long_term_key_sha256(username: &str, realm: &str, password: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let input = format!("{username}:{realm}:{password}");
    Sha256::digest(input.as_bytes()).to_vec()
}

/// Generate time-limited TURN credentials (REST API style).
pub fn generate_turn_credentials(
    user_id: &str,
    shared_secret: &[u8],
    ttl_secs: u64,
) -> (String, String) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the UNIX epoch")
        .as_secs()
        + ttl_secs;

    let username = format!("{timestamp}:{user_id}");
    let mut mac = HmacSha1::new_from_slice(shared_secret).expect("HMAC accepts any key size");
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let password = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        result.into_bytes(),
    );
    (username, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_nonce_roundtrips_and_is_client_bound() {
        let key = random_key_32();
        let n = issue_client_nonce(&key, "203.0.113.7:51000", 1234);
        // Same client + key verifies and recovers the timestamp.
        assert_eq!(
            verify_client_nonce(&key, "203.0.113.7:51000", &n),
            Some(1234)
        );
        // A different client must not validate the same nonce.
        assert_eq!(verify_client_nonce(&key, "203.0.113.8:51000", &n), None);
        // A different key must not validate it.
        assert_eq!(
            verify_client_nonce(&random_key_32(), "203.0.113.7:51000", &n),
            None
        );
    }

    #[test]
    fn client_nonce_rejects_garbage() {
        let key = random_key_32();
        assert_eq!(verify_client_nonce(&key, "c", "not-a-nonce"), None);
        assert_eq!(verify_client_nonce(&key, "c", "zz:zz"), None);
        assert_eq!(verify_client_nonce(&key, "c", ""), None);
    }

    #[test]
    fn long_term_key_sha256_is_32_bytes_and_matches_sha256() {
        let k = long_term_key_sha256("user", "realm", "pass");
        assert_eq!(k.len(), 32);
        use sha2::{Digest, Sha256};
        assert_eq!(k, Sha256::digest(b"user:realm:pass").to_vec());
        // Distinct from the MD5 long-term key.
        assert_ne!(k, long_term_key("user", "realm", "pass"));
    }
}
