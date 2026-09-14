//! STUN protocol implementation (RFC 5389)
//!
//! Pure parsing and serialization — no I/O, no async.

// This crate contains no `unsafe`. The attribute makes that checkable by
// the compiler instead of by `docs/unsafe-audit.md`: a future change that
// introduces `unsafe` here fails to build rather than quietly widening the
// audited surface, which is confined to turna-transport and turna-relay.
#![forbid(unsafe_code)]

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
