// AES-CBC (Cipher Block Chaining)
// First historic block cipher for AES.
// CBC mode is insecure and must not be used. It’s been progressively deprecated and
// removed from SSL libraries.
// Introduced with TLS 1.0 year 2002. Superseded by GCM in TLS 1.2 year 2008.
// Removed in TLS 1.3 year 2018.
// RFC 3268 year 2002 https://tools.ietf.org/html/rfc3268

// https://github.com/RustCrypto/block-ciphers

use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use rand::Rng;
use std::io::Cursor;
use std::ops::Not;

use super::padding::DtlsPadding;
use crate::content::*;
use crate::error::*;
use crate::prf::*;
use crate::record_layer::record_layer_header::*;
type Aes256CbcEnc = cbc::Encryptor<aes_cbc::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes_cbc::Aes256>;

// State needed to handle encrypted input/output
#[derive(Clone)]
pub struct CryptoCbc {
    local_key: Vec<u8>,
    remote_key: Vec<u8>,
    write_mac: Vec<u8>,
    read_mac: Vec<u8>,
}

impl CryptoCbc {
    const BLOCK_SIZE: usize = 16;
    const MAC_SIZE: usize = 20;

    pub fn new(
        local_key: &[u8],
        local_mac: &[u8],
        remote_key: &[u8],
        remote_mac: &[u8],
    ) -> Result<Self> {
        Ok(CryptoCbc {
            local_key: local_key.to_vec(),
            write_mac: local_mac.to_vec(),

            remote_key: remote_key.to_vec(),
            read_mac: remote_mac.to_vec(),
        })
    }

    pub fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let mut payload = raw[RECORD_LAYER_HEADER_SIZE..].to_vec();
        let raw = &raw[..RECORD_LAYER_HEADER_SIZE];

        // Generate + Append MAC
        let h = pkt_rlh;

        let mac = prf_mac(
            h.epoch,
            h.sequence_number,
            h.content_type,
            h.protocol_version,
            &payload,
            &self.write_mac,
        )?;
        payload.extend_from_slice(&mac);

        let mut iv: Vec<u8> = vec![0; Self::BLOCK_SIZE];
        rand::rng().fill_bytes(iv.as_mut_slice());

        // cipher 0.5 has its own InvalidLength; report it as the same Error::Aes the
        // other suites (cipher 0.4) produce.
        let write_cbc = Aes256CbcEnc::new_from_slices(&self.local_key, &iv)
            .map_err(|_| Error::Aes(aes::cipher::InvalidLength))?;
        let encrypted = write_cbc.encrypt_padded_vec::<DtlsPadding>(&payload);

        // Prepend unencrypte header with encrypted payload
        let mut r = vec![];
        r.extend_from_slice(raw);
        r.extend_from_slice(&iv);
        r.extend_from_slice(&encrypted);

        let r_len = (r.len() - RECORD_LAYER_HEADER_SIZE) as u16;
        r[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
            .copy_from_slice(&r_len.to_be_bytes());

        Ok(r)
    }

    pub fn decrypt(&self, r: &[u8]) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(r);
        let h = RecordLayerHeader::unmarshal(&mut reader)?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(r.to_vec());
        }

        let body = &r[RECORD_LAYER_HEADER_SIZE..];
        let iv = &body[0..Self::BLOCK_SIZE];
        let body = &body[Self::BLOCK_SIZE..];
        //TODO: add body.len() check

        let read_cbc = Aes256CbcDec::new_from_slices(&self.remote_key, iv)
            .map_err(|_| Error::Aes(aes::cipher::InvalidLength))?;

        let decrypted = read_cbc
            .decrypt_padded_vec::<DtlsPadding>(body)
            .map_err(|_| Error::ErrInvalidPacketLength)?;

        let recv_mac = &decrypted[decrypted.len() - Self::MAC_SIZE..];
        let decrypted = &decrypted[0..decrypted.len() - Self::MAC_SIZE];
        let mac = prf_mac(
            h.epoch,
            h.sequence_number,
            h.content_type,
            h.protocol_version,
            decrypted,
            &self.read_mac,
        )?;

        if recv_mac.ct_eq(&mac).not().into() {
            return Err(Error::ErrInvalidMac);
        }

        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + decrypted.len());
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(decrypted);

        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"turna cbc known-answer payload, 37 b";

    /// A record produced by `encrypt` on the cbc 0.1 / cipher 0.4 stack (the
    /// implementation before the cbc 0.2 move), with the key, MAC key and
    /// header built by `fixture()`. Decrypting it pins wire compatibility
    /// across the cipher-crate upgrade: CBC chaining, DTLS padding and the MAC.
    const KAT_RECORD_CBC_0_1: &str = "17fefd0001000000000007005082bf9d6c929feac538549ed5be3396b16798965c264ab0a83a1d539025226167b0dbaee38c48f0a50b767b92b426837e99f833040ea80ed30ce80fee546d3364c502e24fe20184540e59e51b37b2bfc7";

    fn fixture() -> (CryptoCbc, RecordLayerHeader, Vec<u8>) {
        let key: Vec<u8> = (0u8..32).collect();
        let mac: Vec<u8> = (100u8..120).collect();
        let c = CryptoCbc::new(&key, &mac, &key, &mac).unwrap();
        let h = RecordLayerHeader {
            content_type: ContentType::ApplicationData,
            protocol_version: PROTOCOL_VERSION1_2,
            epoch: 1,
            sequence_number: 7,
            content_len: PAYLOAD.len() as u16,
        };
        let mut raw = Vec::new();
        h.marshal(&mut raw).unwrap();
        raw.extend_from_slice(PAYLOAD);
        (c, h, raw)
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decrypts_a_record_from_the_previous_cipher_stack() {
        let (c, _, raw) = fixture();
        let out = c.decrypt(&unhex(KAT_RECORD_CBC_0_1)).unwrap();
        // decrypt keeps the header as received (its length field is the
        // encrypted length), so compare the plaintext after it.
        assert_eq!(&out[RECORD_LAYER_HEADER_SIZE..], PAYLOAD);
        assert_eq!(out[..11], raw[..11]);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let (c, h, _) = fixture();
        let mut raw = Vec::new();
        h.marshal(&mut raw).unwrap();
        raw.extend_from_slice(PAYLOAD);
        let rec = c.encrypt(&h, &raw).unwrap();
        // header + IV + whole blocks of (payload + MAC + DTLS padding)
        assert_eq!(
            (rec.len() - RECORD_LAYER_HEADER_SIZE) % CryptoCbc::BLOCK_SIZE,
            0
        );
        let out = c.decrypt(&rec).unwrap();
        assert_eq!(&out[RECORD_LAYER_HEADER_SIZE..], PAYLOAD);
    }

    #[test]
    fn rejects_a_tampered_record() {
        let (c, _, _) = fixture();
        let mut rec = unhex(KAT_RECORD_CBC_0_1);
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
        assert!(c.decrypt(&rec).is_err());
    }
}
