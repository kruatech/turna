//! DTLS 1.2 for the turna TURN datapath.
//!
//! # Origin
//!
//! Derived from `webrtc-dtls` 0.10.0 by Rain Liu <yuliu@webrtc.rs>
//! (<https://github.com/webrtc-rs/dtls>), which is itself a port of pion/dtls.
//! Dual-licensed MIT OR Apache-2.0; both texts are in this directory and the
//! copyright notice is preserved. Files changed since the copy say so at the
//! top, as Apache-2.0 §4(b) requires.
//!
//! This is not a fork tracked against upstream. The code is turna's now, and so
//! is the maintenance — including the security fixes upstream will make and
//! this copy will not, unless somebody watches for them. That obligation is
//! recorded in `docs/security/accepted-risks.md`.
//!
//! # Why a copy
//!
//! turna's DTLS listener validates the client's address before allocating
//! anything: a ClientHello without a cookie this node issued is answered with a
//! HelloVerifyRequest and no state is kept (RFC 6347 §4.2.1). A spoofed flood
//! then costs an HMAC and a datagram instead of a connection and a task.
//!
//! The upstream crate performs that exchange **inside** `DTLSConn`, after the
//! allocation, and offers no way to tell it the address is already proved:
//! `flight0` generates its own random cookie and `flight2` compares against it,
//! so an externally issued cookie can never match. Handing it the second
//! ClientHello without a cookie does not help either — that message carries
//! `message_seq = 1`, and `full_pull_map` requires an exact sequence match, so
//! the state machine waits for a message that will never arrive. Both were
//! observed on the wire before this copy was made.
//!
//! Reconciling the two needs a change to the handshake state machine, which
//! cannot be made from outside the crate. See `config::Config::
//! insecure_skip_verify_hello` and the modification notes in `flight/flight0.rs`.

#![warn(rust_2018_idioms)]
#![allow(dead_code)]

pub mod alert;
pub mod application_data;
pub mod change_cipher_spec;
pub mod cipher_suite;
pub mod client_certificate_type;
pub mod compression_methods;
pub mod config;
pub mod conn;
pub mod content;
pub mod crypto;
pub mod curve;
mod error;
pub mod extension;
pub mod flight;
pub mod fragment_buffer;
pub mod handshake;
pub mod handshaker;
pub mod listener;
pub mod prf;
pub mod record_layer;
pub mod signature_hash_algorithm;
pub mod state;

use cipher_suite::*;
pub use error::Error;
use extension::extension_use_srtp::SrtpProtectionProfile;

pub(crate) fn find_matching_srtp_profile(
    a: &[SrtpProtectionProfile],
    b: &[SrtpProtectionProfile],
) -> Result<SrtpProtectionProfile, ()> {
    for a_profile in a {
        for b_profile in b {
            if a_profile == b_profile {
                return Ok(*a_profile);
            }
        }
    }
    Err(())
}

pub(crate) fn find_matching_cipher_suite(
    a: &[CipherSuiteId],
    b: &[CipherSuiteId],
) -> Result<CipherSuiteId, ()> {
    for a_suite in a {
        for b_suite in b {
            if a_suite == b_suite {
                return Ok(*a_suite);
            }
        }
    }
    Err(())
}
