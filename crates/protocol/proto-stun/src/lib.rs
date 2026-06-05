//! STUN protocol implementation (RFC 5389)
//!
//! Pure parsing and serialization — no I/O, no async.

pub mod attribute;
pub mod error;
pub mod header;
pub mod integrity;
pub mod message;
pub mod method;

pub use error::StunError;
pub use header::{MessageClass, MessageHeader, MAGIC_COOKIE};
pub use message::StunMessage;
pub use method::Method;
