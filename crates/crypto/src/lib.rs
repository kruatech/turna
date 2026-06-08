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

/// Compute long-term credential key: MD5(username:realm:password).
pub fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{username}:{realm}:{password}");
    md5::compute(input.as_bytes()).0.to_vec()
}

/// Generate time-limited TURN credentials (REST API style).
pub fn generate_turn_credentials(
    user_id: &str,
    shared_secret: &[u8],
    ttl_secs: u64,
) -> (String, String) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + ttl_secs;

    let username = format!("{timestamp}:{user_id}");
    let mut mac = HmacSha1::new_from_slice(shared_secret).unwrap();
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let password = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        result.into_bytes(),
    );
    (username, password)
}

/// Verify time-limited TURN credentials.
pub fn verify_turn_credentials(username: &str, password: &str, shared_secret: &[u8]) -> bool {
    let Some(ts_str) = username.split(':').next() else {
        return false;
    };
    let Ok(timestamp) = ts_str.parse::<u64>() else {
        return false;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > timestamp {
        return false;
    }

    let mut mac = HmacSha1::new_from_slice(shared_secret).unwrap();
    mac.update(username.as_bytes());
    let result = mac.finalize();
    let expected = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        result.into_bytes(),
    );
    expected == password
}
