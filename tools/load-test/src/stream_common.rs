//! A certificate verifier that accepts anything, shared by the verification
//! clients.
//!
//! Extracted so `tls_client` and `quic_client` do not each carry a copy. It is
//! named for what it does: this is a **test client**, pointed at a server whose
//! certificate is usually self-signed or issued by a local CA, and its job is to
//! exercise the TURN path rather than to validate a chain. Anything that links this
//! into a real client is wrong.

/// The certificate verifier needs rustls; the framing below needs nothing. They live
/// in one module because both are shared by the stream transports, but only this half
/// can be compiled without a TLS feature — and the AF_XDP lab builds the tool with no
/// features at all, which is how the missing gate surfaced.
#[cfg(any(feature = "tls", feature = "quic", feature = "dtls"))]
mod verifier {
    use std::sync::Arc;

    /// Accepts every server certificate presented. Test-only.
    #[derive(Debug)]
    pub struct AcceptAnyServerCert(pub Arc<rustls::crypto::CryptoProvider>);

    impl AcceptAnyServerCert {
        /// Shared provider for the rustls builders, which take an `Arc`.
        ///
        /// Only the TLS and QUIC clients construct a rustls config; DTLS installs a
        /// process default instead (`owned_provider`), so without this gate a
        /// `--features dtls` build carries it unused.
        #[cfg(any(feature = "tls", feature = "quic"))]
        pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
            Arc::new(rustls::crypto::ring::default_provider())
        }

        /// An **owned** provider, for `CryptoProvider::install_default`, which consumes
        /// one by value. Libraries that build their own crypto — `webrtc-dtls` among
        /// them — look up the process-wide default instead of accepting a provider, so
        /// something has to install it.
        ///
        /// Gated rather than `#[allow(dead_code)]`: only the DTLS client needs it, and the
        /// gate says so. A blanket allow would hide the next genuinely unused item here.
        #[cfg(feature = "dtls")]
        pub fn owned_provider() -> rustls::crypto::CryptoProvider {
            rustls::crypto::ring::default_provider()
        }
    }

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

#[cfg(any(feature = "tls", feature = "quic", feature = "dtls"))]
pub use verifier::AcceptAnyServerCert;

/// Frame one message out of a TURN-over-stream buffer, or `None` if more bytes are
/// needed.
///
/// Gated on the stream transports specifically. The module as a whole is compiled for
/// `dtls` too — that one needs the certificate verifier — but DTLS is datagram-oriented
/// and never frames, so without this gate the function is dead in a DTLS-only build.
///
/// Shared by every stream transport here — TLS, QUIC, and (once it exists) the
/// WebTransport client — because the framing is identical in all three: the stream
/// carries raw STUN messages delimited by the length in their own header, plus
/// ChannelData whose 4-byte header is followed by a payload padded to a 4-byte
/// boundary on the wire. Only the padding differs from a naive read, and it is the
/// detail a hand-rolled framer gets wrong.
///
/// Returns the message *without* the padding, so callers see exactly what was sent.
#[cfg(any(feature = "tls", feature = "quic", feature = "web-transport"))]
pub fn next_stream_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if buf.len() < 4 {
            return None;
        }
        let b0 = buf[0];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let (wire, logical) = if b0 & 0xC0 == 0x00 {
            // STUN: 20-byte header + length, already 4-byte aligned by the encoder.
            (20 + len, 20 + len)
        } else if (0x40..=0x7f).contains(&b0) {
            // ChannelData: 4-byte header + payload, padded to 4 bytes on a stream.
            let pad = (4 - (len % 4)) % 4;
            (4 + len + pad, 4 + len)
        } else {
            // Not a valid first byte for either. Drop it and resynchronise rather
            // than stalling forever on a stream we cannot interpret.
            buf.drain(0..1);
            continue;
        };
        if buf.len() < wire {
            return None;
        }
        let msg: Vec<u8> = buf.drain(0..wire).collect();
        return Some(msg[..logical].to_vec());
    }
}
