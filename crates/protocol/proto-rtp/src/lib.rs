//! RTP header parser (RFC 3550) — read-only, for metrics/QoS.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RtpError {
    #[error("buffer too short for RTP header")]
    TooShort,
    #[error("invalid RTP version: {0}")]
    InvalidVersion(u8),
}

#[derive(Debug, Clone)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

impl RtpHeader {
    /// Parse RTP header from buffer (minimum 12 bytes).
    pub fn parse(buf: &[u8]) -> Result<Self, RtpError> {
        if buf.len() < 12 {
            return Err(RtpError::TooShort);
        }
        let version = (buf[0] >> 6) & 0x03;
        if version != 2 {
            return Err(RtpError::InvalidVersion(version));
        }
        Ok(Self {
            version,
            padding: (buf[0] >> 5) & 0x01 == 1,
            extension: (buf[0] >> 4) & 0x01 == 1,
            marker: (buf[1] >> 7) & 0x01 == 1,
            payload_type: buf[1] & 0x7F,
            sequence_number: u16::from_be_bytes([buf[2], buf[3]]),
            timestamp: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            ssrc: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }

    pub fn is_audio(&self) -> bool {
        // Common audio payload types (Opus=111 dynamic, PCMU=0, PCMA=8)
        matches!(self.payload_type, 0 | 8 | 111)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rtp() {
        // Version 2, no padding/ext, PT=111, seq=1, ts=160, ssrc=12345
        let buf = [
            0x80, 0x6F, 0x00, 0x01,
            0x00, 0x00, 0x00, 0xA0,
            0x00, 0x00, 0x30, 0x39,
        ];
        let hdr = RtpHeader::parse(&buf).unwrap();
        assert_eq!(hdr.version, 2);
        assert_eq!(hdr.payload_type, 111);
        assert_eq!(hdr.sequence_number, 1);
        assert_eq!(hdr.ssrc, 12345);
    }
}
