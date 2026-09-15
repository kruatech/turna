//! **Modified from webrtc-dtls 0.10.0.** An extension this implementation does
//! not parse is logged at `debug` rather than `warn`: ignoring unknown
//! extensions is what the protocol requires, so it is not a warning.

#[cfg(test)]
mod handshake_message_server_hello_test;

use std::fmt;
use std::io::{BufReader, BufWriter};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use super::handshake_random::*;
use super::*;
use crate::cipher_suite::*;
use crate::compression_methods::*;
use crate::extension::*;
use crate::record_layer::record_layer_header::*;

/*
The server will send this message in response to a ClientHello
message when it was able to find an acceptable set of algorithms.
If it cannot find such a match, it will respond with a handshake
failure alert.
https://tools.ietf.org/html/rfc5246#section-7.4.1.3
*/
#[derive(Clone)]
pub struct HandshakeMessageServerHello {
    pub(crate) version: ProtocolVersion,
    pub(crate) random: HandshakeRandom,

    pub(crate) cipher_suite: CipherSuiteId,
    pub(crate) compression_method: CompressionMethodId,
    pub(crate) extensions: Vec<Extension>,
}

impl PartialEq for HandshakeMessageServerHello {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.random == other.random
            && self.compression_method == other.compression_method
            && self.extensions == other.extensions
            && self.cipher_suite == other.cipher_suite
    }
}

impl fmt::Debug for HandshakeMessageServerHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = [
            format!("version: {:?} random: {:?}", self.version, self.random),
            format!("cipher_suites: {:?}", self.cipher_suite),
            format!("compression_method: {:?}", self.compression_method),
            format!("extensions: {:?}", self.extensions),
        ];
        write!(f, "{}", s.join(" "))
    }
}

impl HandshakeMessageServerHello {
    pub fn handshake_type(&self) -> HandshakeType {
        HandshakeType::ServerHello
    }

    pub fn size(&self) -> usize {
        let mut len = 2 + self.random.size();

        // SessionID
        len += 1;

        len += 2;

        len += 1;

        len += 2;
        for extension in &self.extensions {
            len += extension.size();
        }

        len
    }

    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version.major)?;
        writer.write_u8(self.version.minor)?;
        self.random.marshal(writer)?;

        // SessionID
        writer.write_u8(0x00)?;

        writer.write_u16::<BigEndian>(self.cipher_suite as u16)?;

        writer.write_u8(self.compression_method as u8)?;

        let mut extension_buffer = vec![];
        {
            let mut extension_writer = BufWriter::<&mut Vec<u8>>::new(extension_buffer.as_mut());
            for extension in &self.extensions {
                extension.marshal(&mut extension_writer)?;
            }
        }

        writer.write_u16::<BigEndian>(extension_buffer.len() as u16)?;
        writer.write_all(&extension_buffer)?;

        Ok(writer.flush()?)
    }

    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let major = reader.read_u8()?;
        let minor = reader.read_u8()?;
        let random = HandshakeRandom::unmarshal(reader)?;

        // Session ID
        let session_id_len = reader.read_u8()? as usize;
        let mut session_id_buffer = vec![0u8; session_id_len];
        reader.read_exact(&mut session_id_buffer)?;

        let cipher_suite: CipherSuiteId = reader.read_u16::<BigEndian>()?.into();

        let compression_method = reader.read_u8()?.into();
        let mut extensions = vec![];

        let extension_buffer_len = reader.read_u16::<BigEndian>()? as usize;
        let mut extension_buffer = vec![0u8; extension_buffer_len];
        reader.read_exact(&mut extension_buffer)?;

        let mut offset = 0;
        while offset < extension_buffer_len {
            let mut extension_reader = BufReader::new(&extension_buffer[offset..]);
            if let Ok(extension) = Extension::unmarshal(&mut extension_reader) {
                extensions.push(extension);
            } else {
                // Debug, not warn.
                //
                // An extension this implementation does not parse is ordinary
                // TLS: the peer advertises what it supports and the other side
                // ignores what it does not know (RFC 8446 §4.2, and the same
                // rule in TLS 1.2). Every OpenSSL client trips this two or three
                // times per handshake — session_ticket and encrypt_then_mac
                // among them — so at `warn` it is one to three lines of noise
                // per connection that report nothing wrong.
                //
                // A warning that fires on correct behaviour trains people to
                // stop reading warnings, which costs more than the information
                // it carries.
                log::debug!(
                    "unparsed extension type {} {}",
                    extension_buffer[offset],
                    extension_buffer[offset + 1]
                );
            }

            let extension_len =
                u16::from_be_bytes([extension_buffer[offset + 2], extension_buffer[offset + 3]])
                    as usize;
            offset += 4 + extension_len;
        }

        Ok(HandshakeMessageServerHello {
            version: ProtocolVersion { major, minor },
            random,

            cipher_suite,
            compression_method,
            extensions,
        })
    }
}
