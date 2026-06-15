//! Stateful fuzz target: TURN allocation lifecycle
//!
//! Вместо случайных байтов генерирует **семантически корректные** TURN
//! последовательности и мутирует их структурно:
//!
//!   ALLOCATE → CREATE_PERMISSION → CHANNEL_BIND → SEND → REFRESH → EXPIRE
//!
//! Цель: найти баги в state machine процессора, которые coverage-fuzzing
//! на случайных байтах не находит (нужно сначала пройти auth challenge).
//!
//! Контракт: ни один вариант входа не должен вызывать panic, hang или OOM.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::attribute::Attribute;
use turna_proto_turn as turn;

// ── Lifecycle stage enum ──────────────────────────────────────────────────────

/// Стадия жизненного цикла TURN-аллокации.
#[derive(Debug, Arbitrary)]
enum LifecycleStage {
    Allocate,
    CreatePermission,
    ChannelBind,
    Send,
    Refresh,
    RefreshZero,   // lifetime=0 → явное удаление аллокации
    ChannelData,
}

/// Мутации атрибутов для negative testing.
#[derive(Debug, Arbitrary)]
enum AttributeMutation {
    /// Нормальные атрибуты (happy path).
    Normal,
    /// Отсутствует LIFETIME.
    MissingLifetime,
    /// LIFETIME=0 в Allocate (не Refresh).
    ZeroLifetimeInAllocate,
    /// Неверный REQUESTED-TRANSPORT (не UDP=17).
    WrongTransport(u8),
    /// Несуществующий channel number (< 0x4000).
    InvalidChannelNumber(u16),
    /// XOR-PEER-ADDRESS — мультикастовый адрес.
    MulticastPeerAddress,
    /// Дублирующийся атрибут USERNAME.
    DuplicateUsername,
    /// Очень длинный NONCE (до MAX_ATTRIBUTE_VALUE_LEN).
    LongNonce(u8),          // длина = value * 6 (max ~1500)
    /// Отсутствует XOR-PEER-ADDRESS в CreatePermission.
    MissingPeerAddress,
}

/// Параметры одного шага последовательности.
#[derive(Debug, Arbitrary)]
struct Step {
    stage:    LifecycleStage,
    mutation: AttributeMutation,
    /// Случайная часть transaction ID — имитирует параллельные запросы.
    tid_seed: [u8; 12],
}

/// Вся фаззируемая последовательность.
#[derive(Debug, Arbitrary)]
struct Sequence {
    steps: Vec<Step>,
    /// Добавить ли ChannelData-фрейм в конце (exercise разбора заголовка).
    trailing_channel_data: bool,
    /// Число байт в payload ChannelData (0..=4000).
    channel_data_payload_len: u16,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const FUZZ_KEY:      &[u8] = b"fuzz_integrity_key_32bytes_pad__";
const FUZZ_USERNAME: &str  = "fuzz_user";
const FUZZ_REALM:    &str  = "fuzz.example";
const FUZZ_NONCE:    &str  = "fuzz_nonce_0000000000";

fn make_tid(seed: [u8; 12]) -> [u8; 12] { seed }

fn add_auth_attrs(msg: &mut StunMessage, mutation: &AttributeMutation) {
    match mutation {
        AttributeMutation::DuplicateUsername => {
            msg.add(Attribute::Username(FUZZ_USERNAME.into()));
            msg.add(Attribute::Username(FUZZ_USERNAME.into())); // дубль
        }
        _ => {
            msg.add(Attribute::Username(FUZZ_USERNAME.into()));
        }
    }
    msg.add(Attribute::Realm(FUZZ_REALM.into()));

    match mutation {
        AttributeMutation::LongNonce(factor) => {
            let len = (*factor as usize * 6).min(1490);
            msg.add(Attribute::Nonce("X".repeat(len)));
        }
        _ => {
            msg.add(Attribute::Nonce(FUZZ_NONCE.into()));
        }
    }
}

fn build_allocate(step: &Step) -> Vec<u8> {
    let mut msg = StunMessage::with_transaction_id(
        Method::Allocate, MessageClass::Request, make_tid(step.tid_seed),
    );

    let transport = match &step.mutation {
        AttributeMutation::WrongTransport(t) => *t,
        _ => turn::TRANSPORT_UDP,
    };
    msg.add(Attribute::RequestedTransport(transport));

    match &step.mutation {
        AttributeMutation::MissingLifetime => {}
        AttributeMutation::ZeroLifetimeInAllocate => {
            msg.add(Attribute::Lifetime(0));
        }
        _ => {
            msg.add(Attribute::Lifetime(600));
        }
    }

    add_auth_attrs(&mut msg, &step.mutation);

    let mut buf = [0u8; 4096];
    let len = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
    buf[..len].to_vec()
}

fn build_create_permission(step: &Step) -> Vec<u8> {
    let mut msg = StunMessage::with_transaction_id(
        Method::CreatePermission, MessageClass::Request, make_tid(step.tid_seed),
    );

    match &step.mutation {
        AttributeMutation::MissingPeerAddress => {}
        AttributeMutation::MulticastPeerAddress => {
            let mc: std::net::SocketAddr = "224.0.0.1:3478".parse().unwrap();
            msg.add(Attribute::XorPeerAddress(mc));
        }
        _ => {
            let peer: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
            msg.add(Attribute::XorPeerAddress(peer));
        }
    }

    add_auth_attrs(&mut msg, &step.mutation);

    let mut buf = [0u8; 4096];
    let len = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
    buf[..len].to_vec()
}

fn build_channel_bind(step: &Step) -> Vec<u8> {
    let mut msg = StunMessage::with_transaction_id(
        Method::ChannelBind, MessageClass::Request, make_tid(step.tid_seed),
    );

    let channel = match &step.mutation {
        AttributeMutation::InvalidChannelNumber(n) => *n,
        _ => 0x4000,
    };
    msg.add(Attribute::ChannelNumber(channel));

    let peer: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
    msg.add(Attribute::XorPeerAddress(peer));
    add_auth_attrs(&mut msg, &step.mutation);

    let mut buf = [0u8; 4096];
    let len = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
    buf[..len].to_vec()
}

fn build_send_indication(step: &Step) -> Vec<u8> {
    let mut msg = StunMessage::with_transaction_id(
        Method::Send, MessageClass::Indication, make_tid(step.tid_seed),
    );
    let peer: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
    msg.add(Attribute::XorPeerAddress(peer));
    msg.add(Attribute::Data(b"fuzz_payload".to_vec()));

    let mut buf = [0u8; 4096];
    let len = msg.encode(&mut buf).unwrap();
    buf[..len].to_vec()
}

fn build_refresh(step: &Step, lifetime: u32) -> Vec<u8> {
    let mut msg = StunMessage::with_transaction_id(
        Method::Refresh, MessageClass::Request, make_tid(step.tid_seed),
    );
    msg.add(Attribute::Lifetime(lifetime));
    add_auth_attrs(&mut msg, &step.mutation);

    let mut buf = [0u8; 4096];
    let len = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
    buf[..len].to_vec()
}

fn build_channel_data(channel: u16, payload_len: usize) -> Vec<u8> {
    let payload_len = payload_len.min(3900);
    let payload = vec![0xABu8; payload_len];
    let padded_len = (4 + payload_len + 3) & !3;
    let mut buf = vec![0u8; padded_len];
    turna_proto_stun::message::encode_channel_data(&mut buf, channel, &payload).unwrap();
    buf
}

// ── Fuzz target ───────────────────────────────────────────────────────────────

fuzz_target!(|seq: Sequence| {
    // Ограничиваем количество шагов чтобы не уходить в бесконечность
    let steps = seq.steps.iter().take(16);

    for step in steps {
        let raw = match &step.stage {
            LifecycleStage::Allocate =>
                build_allocate(step),
            LifecycleStage::CreatePermission =>
                build_create_permission(step),
            LifecycleStage::ChannelBind =>
                build_channel_bind(step),
            LifecycleStage::Send =>
                build_send_indication(step),
            LifecycleStage::Refresh =>
                build_refresh(step, 600),
            LifecycleStage::RefreshZero =>
                build_refresh(step, 0),
            LifecycleStage::ChannelData =>
                build_channel_data(0x4000, 200),
        };

        // Прогоняем через парсеры — ни один не должен паниковать
        let _ = StunMessage::decode(&raw);
        let _ = turna_proto_stun::message::decode_channel_data(&raw);
        let _ = turna_proto_stun::message::is_stun_message(&raw);
        let _ = turna_proto_stun::message::is_channel_data(&raw);

        if let Ok(msg) = StunMessage::decode(&raw) {
            let _ = msg.verify_integrity(&raw, FUZZ_KEY);
        }
    }

    // Trailing ChannelData с произвольным payload
    if seq.trailing_channel_data {
        let len = (seq.channel_data_payload_len as usize).min(4000);
        let raw = build_channel_data(0x4000, len);
        let _ = turna_proto_stun::message::decode_channel_data(&raw);
        let _ = turna_proto_stun::message::is_channel_data(&raw);
    }
});
