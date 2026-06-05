//! Semantic/structured STUN mutation fuzzer
//!
//! В отличие от `fuzz_stun` (случайные байты), этот таргет генерирует
//! **валидные STUN-фреймы** и применяет **семантические мутации**:
//!
//! - дублирующиеся атрибуты
//! - неверный MESSAGE-INTEGRITY (1 бит флип)
//! - неверный FINGERPRINT
//! - неверный порядок атрибутов (INTEGRITY до USERNAME)
//! - oversized значения ровно на границе MAX_ATTRIBUTE_VALUE_LEN
//! - невалидные transaction ID паттерны
//!
//! Контракт: ни один вход не вызывает panic, hang, OOM.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::attribute::Attribute;

const FUZZ_KEY: &[u8] = b"fuzz_integrity_key_32bytes_pad__";

#[derive(Debug, Arbitrary)]
enum StunMutation {
    /// Корректный Binding Request — baseline.
    ValidBinding,
    /// Дублирующийся USERNAME.
    DuplicateAttr,
    /// MESSAGE-INTEGRITY с битом-флипом в HMAC.
    CorruptedIntegrity { flip_byte: u8, flip_bit: u8 },
    /// FINGERPRINT с неверным CRC32.
    WrongFingerprint(u32),
    /// INTEGRITY стоит раньше USERNAME (нарушение RFC 5389 §15.4).
    IntegrityBeforeUsername,
    /// Атрибут длиной ровно MAX_ATTRIBUTE_VALUE_LEN (граничное значение).
    AttrAtMaxLen,
    /// Атрибут длиной MAX_ATTRIBUTE_VALUE_LEN + 1 (должен быть отклонён).
    AttrOverMaxLen,
    /// Transaction ID = все нули.
    ZeroTransactionId,
    /// Transaction ID = все 0xFF.
    MaxTransactionId,
    /// LIFETIME с максимальным u32.
    MaxLifetime,
    /// Невалидный family в XOR-MAPPED-ADDRESS (не 0x01 и не 0x02).
    UnknownAddressFamily(u8),
    /// Несколько XOR-PEER-ADDRESS подряд.
    RepeatedPeerAddress(u8),
    /// Пустой DATA атрибут.
    EmptyData,
}

fn build_mutated(mutation: &StunMutation) -> Vec<u8> {
    match mutation {
        StunMutation::ValidBinding => {
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Software("fuzz".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf);
            buf[..n].to_vec()
        }

        StunMutation::DuplicateAttr => {
            let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
            msg.add(Attribute::Username("user".into()));
            msg.add(Attribute::Username("user".into())); // дубль
            msg.add(Attribute::Realm("realm".into()));
            msg.add(Attribute::Nonce("nonce".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY);
            buf[..n].to_vec()
        }

        StunMutation::CorruptedIntegrity { flip_byte, flip_bit } => {
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Username("user".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY);
            let mut raw = buf[..n].to_vec();
            // Флипаем бит в последних 20 байтах (HMAC-SHA1)
            if n >= 20 {
                let idx = n - 20 + (*flip_byte as usize % 20);
                raw[idx] ^= 1 << (*flip_bit % 8);
            }
            raw
        }

        StunMutation::WrongFingerprint(fp) => {
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Fingerprint(*fp)); // произвольный CRC
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf);
            buf[..n].to_vec()
        }

        StunMutation::IntegrityBeforeUsername => {
            // Собираем сырой буфер вручную: INTEGRITY заголовок перед USERNAME
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            // Добавляем в «неправильном» порядке
            msg.add(Attribute::MessageIntegrity([0u8; 20]));
            msg.add(Attribute::Username("user".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf);
            buf[..n].to_vec()
        }

        StunMutation::AttrAtMaxLen => {
            // SOFTWARE длиной ровно 1500 байт — должен приниматься
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Software("X".repeat(1500)));
            let mut buf = vec![0u8; 4096];
            let n = msg.encode(&mut buf);
            buf[..n].to_vec()
        }

        StunMutation::AttrOverMaxLen => {
            // Вручную кодируем атрибут с длиной 1501 (нарушение лимита).
            // Парсер должен вернуть Err, не паниковать.
            let mut hdr = [0u8; 20];
            // Binding Request header
            hdr[0] = 0x00; hdr[1] = 0x01; // type
            hdr[2] = 0x05; hdr[3] = 0xE8; // length = 1504 (1501 + 3 padding), aligned
            hdr[4] = 0x21; hdr[5] = 0x12; hdr[6] = 0xA4; hdr[7] = 0x42; // magic
            let mut raw = hdr.to_vec();
            raw.extend_from_slice(&[0x80u8, 0x22]); // SOFTWARE type
            raw.extend_from_slice(&1501u16.to_be_bytes()); // declared len = 1501
            raw.extend(std::iter::repeat(b'X').take(1504)); // padded
            raw
        }

        StunMutation::ZeroTransactionId => {
            let mut msg = StunMessage::with_transaction_id(
                Method::Binding, MessageClass::Request, [0u8; 12],
            );
            msg.add(Attribute::Software("zero-tid".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf);
            buf[..n].to_vec()
        }

        StunMutation::MaxTransactionId => {
            let mut msg = StunMessage::with_transaction_id(
                Method::Binding, MessageClass::Request, [0xFFu8; 12],
            );
            msg.add(Attribute::Software("max-tid".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf);
            buf[..n].to_vec()
        }

        StunMutation::MaxLifetime => {
            let mut msg = StunMessage::new(Method::Refresh, MessageClass::Request);
            msg.add(Attribute::Lifetime(u32::MAX));
            msg.add(Attribute::Username("u".into()));
            msg.add(Attribute::Realm("r".into()));
            msg.add(Attribute::Nonce("n".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY);
            buf[..n].to_vec()
        }

        StunMutation::UnknownAddressFamily(family) => {
            // Вручную строим XOR-MAPPED-ADDRESS с неверным family
            let mut hdr = [0u8; 20];
            hdr[0] = 0x01; hdr[1] = 0x01; // Binding Success
            hdr[2] = 0x00; hdr[3] = 0x0C; // length = 12
            hdr[4] = 0x21; hdr[5] = 0x12; hdr[6] = 0xA4; hdr[7] = 0x42;
            let mut raw = hdr.to_vec();
            raw.extend_from_slice(&[0x00, 0x20]); // XOR-MAPPED-ADDRESS
            raw.extend_from_slice(&8u16.to_be_bytes()); // len = 8
            raw.push(0x00); raw.push(*family); // неверный family
            raw.extend_from_slice(&[0x00u8; 6]); // port + addr
            raw
        }

        StunMutation::RepeatedPeerAddress(count) => {
            let mut msg = StunMessage::new(Method::CreatePermission, MessageClass::Request);
            let peer: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
            for _ in 0..(*count as usize).min(30) {
                msg.add(Attribute::XorPeerAddress(peer));
            }
            msg.add(Attribute::Username("u".into()));
            msg.add(Attribute::Realm("r".into()));
            msg.add(Attribute::Nonce("n".into()));
            let mut buf = vec![0u8; 8192];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY);
            buf[..n].to_vec()
        }

        StunMutation::EmptyData => {
            let mut msg = StunMessage::new(Method::Send, MessageClass::Indication);
            let peer: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
            msg.add(Attribute::XorPeerAddress(peer));
            msg.add(Attribute::Data(vec![]));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf);
            buf[..n].to_vec()
        }
    }
}

fuzz_target!(|mutation: StunMutation| {
    let raw = build_mutated(&mutation);

    // Ни один путь не должен паниковать
    let _ = StunMessage::decode(&raw);
    let _ = turna_proto_stun::message::is_stun_message(&raw);
    let _ = turna_proto_stun::message::is_channel_data(&raw);
    let _ = turna_proto_stun::header::MessageHeader::decode(&raw);
    let _ = turna_proto_stun::attribute::parse_attributes(
        if raw.len() > 20 { &raw[20..] } else { &[] },
        &[0u8; 12],
    );

    if let Ok(msg) = StunMessage::decode(&raw) {
        let _ = msg.verify_integrity(&raw, FUZZ_KEY);
    }
});
