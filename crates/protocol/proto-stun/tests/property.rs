//! Property tests: decode(encode(x)) == x
//!
//! Проверяет что encode и decode являются взаимно обратными функциями
//! для всех валидных входных данных. Находит баги типа:
//! - потеря поля при roundtrip
//! - truncation строк
//! - неверная XOR-маска адресов
//! - padding ошибки

use proptest::prelude::*;
use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

// ── Стратегии генерации ───────────────────────────────────────────────────────

fn arb_method() -> impl Strategy<Value = Method> {
    prop_oneof![
        Just(Method::Binding),
        Just(Method::Allocate),
        Just(Method::Refresh),
        Just(Method::CreatePermission),
        Just(Method::ChannelBind),
    ]
}

fn arb_class() -> impl Strategy<Value = MessageClass> {
    prop_oneof![
        Just(MessageClass::Request),
        Just(MessageClass::Indication),
        Just(MessageClass::SuccessResponse),
        Just(MessageClass::ErrorResponse),
    ]
}

fn arb_tid() -> impl Strategy<Value = [u8; 12]> {
    any::<[u8; 12]>()
}

/// Генерирует ASCII строку длиной 1..=200 (валидный USERNAME/REALM/NONCE).
fn arb_short_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_.@:-]{1,200}".prop_map(|s| s)
}

fn arb_ipv4_addr() -> impl Strategy<Value = std::net::SocketAddr> {
    (any::<[u8; 4]>(), 1024u16..=65535)
        .prop_map(|(ip, port)| std::net::SocketAddr::new(std::net::Ipv4Addr::from(ip).into(), port))
}

fn arb_lifetime() -> impl Strategy<Value = u32> {
    // Реалистичные значения + граничные
    prop_oneof![
        Just(0u32),
        Just(1u32),
        Just(600u32),
        Just(3600u32),
        Just(u32::MAX),
        any::<u32>(),
    ]
}

fn arb_channel() -> impl Strategy<Value = u16> {
    prop_oneof![
        0x4000u16..=0x7FFEu16, // валидные
        Just(0x4000u16),
        Just(0x7FFEu16),
    ]
}

// ── Property: header roundtrip ────────────────────────────────────────────────

proptest! {
    /// Method + Class + TransactionID сохраняются при encode → decode.
    #[test]
    fn prop_header_roundtrip(
        method in arb_method(),
        class  in arb_class(),
        tid    in arb_tid(),
    ) {
        let msg = StunMessage::with_transaction_id(method, class, tid);
        let mut buf = [0u8; 512];
        let len = msg.encode(&mut buf).unwrap();

        let decoded = StunMessage::decode(&buf[..len])
            .expect("encode must produce decodable output");

        prop_assert_eq!(decoded.method, msg.method);
        prop_assert!(matches_class(&decoded.class, &msg.class));
        prop_assert_eq!(decoded.transaction_id, tid);
    }
}

fn matches_class(a: &MessageClass, b: &MessageClass) -> bool {
    matches!(
        (a, b),
        (MessageClass::Request, MessageClass::Request)
            | (MessageClass::Indication, MessageClass::Indication)
            | (MessageClass::SuccessResponse, MessageClass::SuccessResponse)
            | (MessageClass::ErrorResponse, MessageClass::ErrorResponse)
    )
}

// ── Property: Username roundtrip ──────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_username_roundtrip(s in arb_short_string()) {
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        msg.add(Attribute::Username(s.clone()));

        let mut buf = [0u8; 1024];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        let got = decoded.get_username().unwrap_or("").to_string();
        prop_assert_eq!(got, s);
    }

    #[test]
    fn prop_realm_roundtrip(s in arb_short_string()) {
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        msg.add(Attribute::Realm(s.clone()));

        let mut buf = [0u8; 1024];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        let got = decoded.attributes.iter().find_map(|a| match a {
            Attribute::Realm(r) => Some(r.clone()),
            _ => None,
        }).unwrap_or_default();
        prop_assert_eq!(got, s);
    }

    #[test]
    fn prop_nonce_roundtrip(s in arb_short_string()) {
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        msg.add(Attribute::Nonce(s.clone()));

        let mut buf = [0u8; 1024];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        let got = decoded.get_nonce().unwrap_or("").to_string();
        prop_assert_eq!(got, s);
    }
}

// ── Property: Lifetime roundtrip ──────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_lifetime_roundtrip(lifetime in arb_lifetime()) {
        let mut msg = StunMessage::new(Method::Refresh, MessageClass::Request);
        msg.add(Attribute::Lifetime(lifetime));

        let mut buf = [0u8; 256];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        prop_assert_eq!(decoded.get_lifetime(), Some(lifetime));
    }
}

// ── Property: ChannelNumber roundtrip ─────────────────────────────────────────

proptest! {
    #[test]
    fn prop_channel_number_roundtrip(channel in arb_channel()) {
        let mut msg = StunMessage::new(Method::ChannelBind, MessageClass::Request);
        msg.add(Attribute::ChannelNumber(channel));

        let mut buf = [0u8; 256];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        prop_assert_eq!(decoded.get_channel_number(), Some(channel));
    }
}

// ── Property: XOR address roundtrip ──────────────────────────────────────────

proptest! {
    /// XOR-MAPPED-ADDRESS: encode → decode должен вернуть точно тот же SocketAddr.
    /// Это проверяет правильность XOR-маски (MAGIC_COOKIE + TID).
    #[test]
    fn prop_xor_mapped_address_roundtrip(addr in arb_ipv4_addr()) {
        let mut msg = StunMessage::new(Method::Binding, MessageClass::SuccessResponse);
        msg.add(Attribute::XorMappedAddress(addr));

        let mut buf = [0u8; 256];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        let got = decoded.attributes.iter().find_map(|a| match a {
            Attribute::XorMappedAddress(a) => Some(*a),
            _ => None,
        });
        prop_assert_eq!(got, Some(addr));
    }

    #[test]
    fn prop_xor_peer_address_roundtrip(addr in arb_ipv4_addr()) {
        let mut msg = StunMessage::new(Method::CreatePermission, MessageClass::Request);
        msg.add(Attribute::XorPeerAddress(addr));

        let mut buf = [0u8; 256];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        let got = decoded.get_xor_peer_address();
        prop_assert_eq!(got, Some(addr));
    }
}

// ── Property: encode length == HEADER + attr_bytes (4-aligned) ───────────────

proptest! {
    #[test]
    fn prop_encoded_length_is_aligned(
        method  in arb_method(),
        class   in arb_class(),
        n_attrs in 0usize..8,
        s       in arb_short_string(),
    ) {
        let mut msg = StunMessage::new(method, class);
        for _ in 0..n_attrs {
            msg.add(Attribute::Username(s.clone()));
        }

        let mut buf = vec![0u8; 8192];
        let len = msg.encode(&mut buf).unwrap();

        // Длина должна быть кратна 4 (после header)
        let attr_len = len - 20; // HEADER_SIZE = 20
        prop_assert_eq!(attr_len % 4, 0, "attribute section must be 4-byte aligned");

        // Задекодированный заголовок должен совпадать с фактической длиной
        let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        prop_assert_eq!(declared, attr_len);
    }
}

// ── Property: integrity roundtrip ─────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_integrity_verify(
        s   in arb_short_string(),
        key in "[a-z]{8,32}",
    ) {
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        msg.add(Attribute::Username(s));

        let key = key.into_bytes();
        let mut buf = [0u8; 2048];
        let len = msg.encode_with_integrity(&mut buf, &key).unwrap();

        let decoded = StunMessage::decode(&buf[..len]).unwrap();

        // Верификация с правильным ключом
        prop_assert!(decoded.verify_integrity(&buf[..len], &key),
            "integrity must verify with correct key");

        // Верификация с неправильным ключом должна падать
        let bad_key = b"wrong_key_xxxxx";
        prop_assert!(!decoded.verify_integrity(&buf[..len], bad_key),
            "integrity must NOT verify with wrong key");
    }
}

// ── Property: raw ChannelData frame codec ────────────────────────────────────
//
// Взаимная обратимость encode_channel_data / decode_channel_data, корректность
// 4-байтового паддинга и согласованность классификатора is_channel_data с
// диапазоном номеров каналов 0x4000..=0x7FFE.

use turna_proto_stun::message::{decode_channel_data, encode_channel_data, is_channel_data};

fn arb_channel_data_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=2048)
}

proptest! {
    /// decode(encode(channel, data)) == (channel, data) для валидного канала.
    #[test]
    fn prop_channel_data_roundtrip(
        channel in arb_channel(),
        data    in arb_channel_data_payload(),
    ) {
        let mut buf = vec![0u8; 4 + data.len() + 4];
        let len = encode_channel_data(&mut buf, channel, &data)
            .expect("buffer is large enough for the padded frame");

        // Кадр кратен 4 и покрывает заголовок + данные, паддинг < 4 байт.
        prop_assert_eq!(len % 4, 0, "channel-data frame must be 4-byte aligned");
        prop_assert!(len >= 4 + data.len());
        prop_assert!(len - (4 + data.len()) < 4, "padding must be < 4 bytes");

        // Встроенная длина == длине данных (без паддинга).
        let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        prop_assert_eq!(declared, data.len());

        // Паддинг-байты нулевые.
        for &b in &buf[4 + data.len()..len] {
            prop_assert_eq!(b, 0u8, "padding bytes must be zero");
        }

        // Roundtrip: канал и данные восстанавливаются точно.
        let (got_channel, got_data) =
            decode_channel_data(&buf[..len]).expect("encoded frame must decode");
        prop_assert_eq!(got_channel, channel);
        prop_assert_eq!(got_data, &data[..]);
    }

    /// Классификатор принимает ровно валидный диапазон каналов 0x4000..=0x7FFE.
    #[test]
    fn prop_is_channel_data_matches_range(
        channel in any::<u16>(),
        data    in arb_channel_data_payload(),
    ) {
        let mut buf = vec![0u8; 4 + data.len() + 4];
        let len = encode_channel_data(&mut buf, channel, &data).unwrap();

        let in_range = (0x4000..=0x7FFE).contains(&channel);
        prop_assert_eq!(is_channel_data(&buf[..len]), in_range);
    }

    /// encode возвращает ошибку, если буфер меньше паддированного кадра.
    #[test]
    fn prop_channel_data_buffer_too_short(
        channel in arb_channel(),
        data    in prop::collection::vec(any::<u8>(), 1..=512),
    ) {
        let total = 4 + data.len();
        let padded = (total + 3) & !3;
        let mut small = vec![0u8; padded - 1];
        prop_assert!(encode_channel_data(&mut small, channel, &data).is_err());
    }
}
