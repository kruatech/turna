# Security Invariants — turna

**Дата:** 2026-05-23  
**Версия:** 1.0

Данный документ формализует инварианты безопасности системы. Каждый инвариант должен выполняться при любых входных данных. Нарушение инварианта — security bug.

---

## 1. Аутентификация и авторизация

### INV-AUTH-01: MESSAGE-INTEGRITY до state mutation
> Проверка MESSAGE-INTEGRITY должна завершиться успешно **до** любого изменения состояния.

**Реализация:** `processor.rs` — `auth.validate(msg, raw)` вызывается до `store.create()`, `store.refresh()`, `store.add_permission()`, `store.add_channel()`.  
**Нарушение:** создание аллокации без валидного HMAC.

### INV-AUTH-02: TURN allocation не переживает аутентифицированную сессию
> TURN-аллокация не может существовать дольше credentials которыми она создана.

**Реализация:** `CredentialRotationManager::cleanup()` удаляет аллокации при истечении credentials + grace period.  
**Нарушение:** активная аллокация при отсутствии валидных credentials.

### INV-AUTH-03: Истёкшие permissions не переиспользуются
> Пакет от peer без активного permission должен быть отброшен.

**Реализация:** `alloc.has_permission(&peer_addr)` проверяется при каждом relay_recv.  
**Нарушение:** форвардинг пакета от peer которому permission не выдавался или истёк.

### INV-AUTH-04: JWT replay protection
> Каждый JWT имеет уникальный `jti`. Отозванный токен не принимается.

**Реализация:** `UserStore::verify_token()` проверяет `TokenBlacklist` по `jti` после верификации подписи.  
**Нарушение:** принятие токена после вызова `revoke_token()`.

### INV-AUTH-05: JWT issuer validation
> Токены с `iss != "turna-auth"` отклоняются независимо от подписи.

**Реализация:** `verify_jwt()` устанавливает `validation.set_issuer(&["turna-auth"])`.  
**Нарушение:** принятие токена с произвольным issuer.

---

## 2. Парсер и протокол

### INV-PARSE-01: Парсер не паникует на произвольном вводе
> `StunMessage::decode()`, `parse_compound()`, `decode_channel_data()` возвращают `Err` на любых входных данных. Panic запрещён.

**Реализация:** hard limits + exhaustive тесты + fuzzing corpus.  
**Верификация:** `cargo fuzz run fuzz_stun`, `fuzz_turn`, `fuzz_rtcp`, `fuzz_turn_lifecycle`, `fuzz_stun_semantic`.

### INV-PARSE-02: Размер пакета ограничен до выделения памяти
> Поле `length` в заголовке STUN не может вызвать аллокацию более `MAX_MESSAGE_LEN=4096` байт.

**Реализация:** `header.rs` — проверка `length > MAX_MESSAGE_LEN` до любых аллокаций.  
**Нарушение:** аллокация буфера размером из untrusted length field.

### INV-PARSE-03: Размер атрибута ограничен
> Значение одного атрибута не превышает `MAX_ATTRIBUTE_VALUE_LEN=1500` байт.

**Реализация:** `attribute.rs` — проверка до bounds check.  
**Нарушение:** аллокация Vec по untrusted attr_len.

### INV-PARSE-04: Количество атрибутов ограничено
> Одно STUN-сообщение содержит не более `MAX_ATTRIBUTES_PER_MESSAGE=32` атрибутов.

**Реализация:** `attribute.rs` — проверка `attrs.len() >= MAX_ATTRIBUTES_PER_MESSAGE` до `push`.  
**Нарушение:** unbounded Vec growth из одного пакета.

### INV-PARSE-05: ChannelData буфер включает padding
> Буфер переданный в `encode_channel_data` должен быть не менее `(4 + data.len() + 3) & !3` байт.

**Реализация:** `message.rs` — assert перед записью padding.  
**Нарушение:** OOB запись при unaligned payload.

---

## 3. Relay и квоты

### INV-RELAY-01: Квоты проверяются до форвардинга
> Bandwidth quota проверяется до передачи пакета peer.

**Реализация:** `processor.rs` — `alloc.check_bandwidth()` до `add_bytes()` и `Action::Forward`.  
**Нарушение:** форвардинг при превышении квоты.

### INV-RELAY-02: Replay transaction ID отклоняется
> Nonce с истёкшим или неверным значением возвращает 438 Stale Nonce.

**Реализация:** `NonceManager::validate()` с rotation interval 10 мин и grace period 30 сек.  
**Нарушение:** принятие старого nonce.

### INV-RELAY-03: Channel number валиден
> ChannelBind принимается только для channel 0x4000–0x7FFE.

**Реализация:** `turn::is_valid_channel(channel)` в `handle_channel_bind`.  
**Нарушение:** binding на channel вне допустимого диапазона.

---

## 4. Unsafe код

### INV-UNSAFE-01: HugePagePool — нет активных буферов при drop
> `HugePagePool` нельзя дропать пока существуют `PoolBuffer` из него.

**Реализация:** `drop()` паникует если `allocated > 0`.  
**Обеспечение:** держать pool в `Arc`, shared с воркерами.

### INV-UNSAFE-02: Umem::frame_slice — адрес в пределах UMEM
> `addr + len <= umem.size` перед любым доступом к mmap-региону.

**Реализация:** `assert!` в `frame_slice` и `frame_slice_mut` с диагностическим сообщением.  
**Нарушение:** OOB доступ к mmap региону (возможен при driver bug в AF_XDP).

### INV-UNSAFE-03: MsgHdrStorage — стабильный адрес
> `MsgHdrStorage` не перемещается после `setup_recv`/`setup_send`.

**Реализация:** хранение в `Box<[MsgHdrStorage]>` — heap-аллокация с фиксированным адресом.  
**Нарушение:** любой `Vec<MsgHdrStorage>` который может реаллоцироваться.

---

## 5. Верификация инвариантов

| Инвариант | Метод верификации |
|---|---|
| INV-AUTH-* | Unit tests в `crates/auth/`, integration tests |
| INV-PARSE-* | Fuzzing: `cargo fuzz run fuzz_stun / fuzz_turn / ...` |
| INV-RELAY-* | Unit tests в `crates/relay/src/processor.rs` |
| INV-UNSAFE-* | ASAN/UBSAN/TSAN sanitizer runs |
