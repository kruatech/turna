//! STUN error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StunError {
    #[error("buffer too short: need {need}, have {have}")]
    BufferTooShort { need: usize, have: usize },

    #[error("invalid magic cookie")]
    InvalidMagicCookie,

    #[error("invalid message length (not multiple of 4)")]
    InvalidLength,

    #[error("unknown attribute type: 0x{0:04x}")]
    UnknownAttribute(u16),

    #[error("attribute parse error: {0}")]
    AttributeParse(String),

    #[error("integrity check failed")]
    IntegrityFailed,

    #[error("fingerprint mismatch")]
    FingerprintMismatch,

    // ── DoS / abuse guards ────────────────────────────────────────────────
    /// A single attribute's declared value length exceeds our cap. STUN's wire
    /// format allows up to 65535 bytes per attribute (u16 length field); we
    /// cap much lower because real attributes (USERNAME, REALM, NONCE,
    /// SOFTWARE, DATA, etc.) are all far below MTU in normal use.
    #[error("attribute value too long: type=0x{attr_type:04x} len={len} max={max}")]
    AttributeValueTooLong {
        attr_type: u16,
        len: usize,
        max: usize,
    },

    /// A message contains more attributes than we accept. Real STUN/TURN
    /// messages have a handful (typically 3–8); a huge count is either a
    /// malformed packet or an abuse attempt.
    #[error("too many attributes: count={count} max={max}")]
    TooManyAttributes { count: usize, max: usize },

    /// The header's length field is larger than the maximum STUN message we
    /// accept. The wire allows up to 65535 (u16); we cap to MTU + reasonable
    /// TURN overhead so a single packet can't trick us into allocating tens
    /// of kilobytes per request.
    #[error("message length too large: declared={len} max={max}")]
    MessageTooLong { len: u16, max: u16 },
}

pub type Result<T> = std::result::Result<T, StunError>;
