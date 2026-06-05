//! Lazy STUN Parser — двухстадийный разбор
//!
//! Stage 1: classify_packet() ~2-5ns — STUN vs ChannelData vs Unknown
//! Stage 2: LazyStunMessage — заголовок всегда, атрибуты on-demand
//!
//! 95% трафика — ChannelData: нулевой overhead, zero-copy ChannelDataView.

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_HEADER_SIZE: usize = 20;
const CHANNEL_MIN: u16 = 0x4000;
const CHANNEL_MAX: u16 = 0x7FFF;

// Re-use existing attribute type constants from proto-stun
pub mod attr_type {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
}

// ---------------------------------------------------------------------------
// Stage 1: Classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Stun,
    ChannelData { channel: u16, length: u16 },
    Unknown,
}

#[inline]
pub fn classify_packet(data: &[u8]) -> PacketKind {
    if data.len() < 4 { return PacketKind::Unknown; }
    let first = u16::from_be_bytes([data[0], data[1]]);
    if first >= CHANNEL_MIN && first <= CHANNEL_MAX {
        return PacketKind::ChannelData { channel: first, length: u16::from_be_bytes([data[2], data[3]]) };
    }
    if data.len() >= STUN_HEADER_SIZE && data[0] & 0xC0 == 0 {
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie == STUN_MAGIC_COOKIE { return PacketKind::Stun; }
    }
    PacketKind::Unknown
}

// ---------------------------------------------------------------------------
// STUN Header
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct StunHeader {
    pub message_type: u16,
    pub message_length: u16,
    pub transaction_id: [u8; 12],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass { Request, Indication, SuccessResponse, ErrorResponse }

impl StunHeader {
    #[inline]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < STUN_HEADER_SIZE { return None; }
        let mut txn = [0u8; 12];
        txn.copy_from_slice(&data[8..20]);
        Some(Self {
            message_type: u16::from_be_bytes([data[0], data[1]]),
            message_length: u16::from_be_bytes([data[2], data[3]]),
            transaction_id: txn,
        })
    }

    pub fn method(&self) -> u16 {
        let m = self.message_type;
        (m & 0x000F) | ((m & 0x00E0) >> 1) | ((m & 0x3E00) >> 2)
    }

    pub fn class(&self) -> StunClass {
        let c0 = (self.message_type >> 4) & 1;
        let c1 = (self.message_type >> 8) & 1;
        match (c1, c0) {
            (0, 0) => StunClass::Request,
            (0, 1) => StunClass::Indication,
            (1, 0) => StunClass::SuccessResponse,
            (1, 1) => StunClass::ErrorResponse,
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Stage 2: Lazy Message
// ---------------------------------------------------------------------------

pub struct LazyStunMessage<'a> {
    raw: &'a [u8],
    pub header: StunHeader,
}

impl<'a> LazyStunMessage<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let header = StunHeader::parse(data)?;
        if data.len() < STUN_HEADER_SIZE + header.message_length as usize { return None; }
        Some(Self { raw: data, header })
    }

    pub fn raw_bytes(&self) -> &'a [u8] { &self.raw[..STUN_HEADER_SIZE + self.header.message_length as usize] }
    fn body(&self) -> &'a [u8] { &self.raw[STUN_HEADER_SIZE..STUN_HEADER_SIZE + self.header.message_length as usize] }

    /// On-demand: ищет первый атрибут, останавливается при нахождении.
    pub fn find_attribute(&self, target: u16) -> Option<RawAttribute<'a>> {
        let body = self.body();
        let mut off = 0;
        while off + 4 <= body.len() {
            let at = u16::from_be_bytes([body[off], body[off + 1]]);
            let al = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
            let ve = off + 4 + al;
            if ve > body.len() { return None; }
            if at == target { return Some(RawAttribute { attr_type: at, value: &body[off + 4..ve], offset: STUN_HEADER_SIZE + off }); }
            off = ve + ((4 - (al % 4)) % 4);
        }
        None
    }

    /// Данные для проверки MESSAGE-INTEGRITY (RFC 5389 §15.4).
    pub fn integrity_input(&self) -> Option<(Vec<u8>, RawAttribute<'a>)> {
        let mi = self.find_attribute(attr_type::MESSAGE_INTEGRITY)?;
        let adj_len = (mi.offset + 4 + 20 - STUN_HEADER_SIZE) as u16;
        let mut input = self.raw[..mi.offset].to_vec();
        input[2] = (adj_len >> 8) as u8;
        input[3] = adj_len as u8;
        Some((input, mi))
    }

    pub fn username(&self) -> Option<&'a str> { self.find_attribute(attr_type::USERNAME).and_then(|a| std::str::from_utf8(a.value).ok()) }
    pub fn realm(&self) -> Option<&'a str> { self.find_attribute(attr_type::REALM).and_then(|a| std::str::from_utf8(a.value).ok()) }
    pub fn nonce(&self) -> Option<&'a str> { self.find_attribute(attr_type::NONCE).and_then(|a| std::str::from_utf8(a.value).ok()) }
    pub fn lifetime(&self) -> Option<u32> { self.find_attribute(attr_type::LIFETIME).and_then(|a| a.as_u32()) }
    pub fn requested_transport(&self) -> Option<u8> { self.find_attribute(attr_type::REQUESTED_TRANSPORT).map(|a| a.value.first().copied()).flatten() }
    pub fn dont_fragment(&self) -> bool { self.find_attribute(attr_type::DONT_FRAGMENT).is_some() }

    pub fn iter_attributes(&self) -> AttrIter<'a> { AttrIter { body: self.body(), off: 0, base: STUN_HEADER_SIZE } }
}

// ---------------------------------------------------------------------------
// Raw Attribute
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RawAttribute<'a> {
    pub attr_type: u16,
    pub value: &'a [u8],
    pub offset: usize,
}

impl<'a> RawAttribute<'a> {
    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() == 4 { Some(u32::from_be_bytes([self.value[0], self.value[1], self.value[2], self.value[3]])) } else { None }
    }
    pub fn as_str(&self) -> Option<&'a str> { std::str::from_utf8(self.value).ok() }
}

pub struct AttrIter<'a> { body: &'a [u8], off: usize, base: usize }

impl<'a> Iterator for AttrIter<'a> {
    type Item = RawAttribute<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.off + 4 > self.body.len() { return None; }
        let at = u16::from_be_bytes([self.body[self.off], self.body[self.off + 1]]);
        let al = u16::from_be_bytes([self.body[self.off + 2], self.body[self.off + 3]]) as usize;
        let ve = self.off + 4 + al;
        if ve > self.body.len() { return None; }
        let a = RawAttribute { attr_type: at, value: &self.body[self.off + 4..ve], offset: self.base + self.off };
        self.off = ve + ((4 - (al % 4)) % 4);
        Some(a)
    }
}

// ---------------------------------------------------------------------------
// ChannelData Zero-Copy View
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ChannelDataView<'a> {
    pub channel: u16,
    pub data_length: u16,
    pub data: &'a [u8],
}

impl<'a> ChannelDataView<'a> {
    #[inline]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 4 { return None; }
        let ch = u16::from_be_bytes([buf[0], buf[1]]);
        let dl = u16::from_be_bytes([buf[2], buf[3]]);
        if ch < CHANNEL_MIN || ch > CHANNEL_MAX { return None; }
        if buf.len() < 4 + dl as usize { return None; }
        Some(Self { channel: ch, data_length: dl, data: &buf[4..4 + dl as usize] })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_request() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x00; p[1] = 0x01;
        p[4] = 0x21; p[5] = 0x12; p[6] = 0xA4; p[7] = 0x42;
        for i in 8..20 { p[i] = i as u8; }
        p
    }

    fn with_attrs() -> Vec<u8> {
        let mut p = binding_request();
        p.extend_from_slice(&[0x00, 0x06, 0x00, 0x05]); // USERNAME, len=5
        p.extend_from_slice(b"alice\x00\x00\x00");        // padded
        p.extend_from_slice(&[0x00, 0x14, 0x00, 0x03]);   // REALM, len=3
        p.extend_from_slice(b"r.c\x00");                   // padded
        p.extend_from_slice(&[0x00, 0x0D, 0x00, 0x04]);   // LIFETIME
        p.extend_from_slice(&3600u32.to_be_bytes());
        let bl = (p.len() - 20) as u16;
        p[2] = (bl >> 8) as u8; p[3] = bl as u8;
        p
    }

    #[test] fn classify_stun()    { assert_eq!(classify_packet(&binding_request()), PacketKind::Stun); }
    #[test] fn classify_channel() { let mut d = vec![0x40, 0x01, 0x00, 0x05]; d.extend(b"hello"); match classify_packet(&d) { PacketKind::ChannelData { channel: 0x4001, length: 5 } => {} _ => panic!() } }
    #[test] fn classify_unknown() { assert_eq!(classify_packet(&[0xFF, 0xFF, 0, 0]), PacketKind::Unknown); }

    #[test] fn header_parse() {
        let h = StunHeader::parse(&binding_request()).unwrap();
        assert_eq!(h.method(), 0x0001);
        assert_eq!(h.class(), StunClass::Request);
    }

    #[test] fn lazy_find_attr() {
        let p = with_attrs();
        let m = LazyStunMessage::new(&p).unwrap();
        assert_eq!(m.username(), Some("alice"));
        assert_eq!(m.lifetime(), Some(3600));
        assert!(m.find_attribute(attr_type::SOFTWARE).is_none());
    }

    #[test] fn lazy_iter() {
        let p = with_attrs();
        let m = LazyStunMessage::new(&p).unwrap();
        assert_eq!(m.iter_attributes().count(), 3);
    }

    #[test] fn channel_data_view() {
        let mut d = vec![0x40, 0x01, 0x00, 0x04];
        d.extend(b"test");
        let v = ChannelDataView::parse(&d).unwrap();
        assert_eq!(v.channel, 0x4001);
        assert_eq!(v.data, b"test");
    }
}
