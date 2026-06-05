# Threat Model — turna

**Дата:** 2026-05-23  
**Версия:** 1.0  
**Статус:** актуально

---

## 1. Область применения

Данный threat model описывает угрозы для realtime communication platform (TURN/STUN relay, SFU, signaling). Используется как основа для security review, НДВ-анализа и аудита ФСТЭК.

---

## 2. Защищаемые активы

| Актив | Описание | Критичность |
|---|---|---|
| TURN credentials | HMAC-ключи аллокаций, long-term/shared-secret | Критическая |
| TURN allocations | Relay-порты, состояние сессий | Высокая |
| DTLS sessions | Параметры handshake, session state | Высокая |
| SRTP keys | Ключи шифрования медиапотоков | Критическая |
| JWT/session tokens | Токены платформенной аутентификации | Высокая |
| Audit logs | Журналы событий безопасности | Высокая |
| Relay state | Таблицы разрешений, channel bindings | Средняя |
| Management API | gRPC управляющий интерфейс | Высокая |
| Node-to-node channels | Межузловые соединения кластера | Высокая |

---

## 3. Классы атакующих

### 3.1 Unauthenticated internet client
- **Возможности:** отправка произвольных UDP/TCP пакетов на публичный edge
- **Цели:** получить relay без аутентификации, вызвать DoS, исчерпать ресурсы
- **Меры:** MESSAGE-INTEGRITY перед любым state mutation, rate limiting per IP, parser hard limits

### 3.2 Malicious authenticated client
- **Возможности:** валидные credentials, легитимные TURN аллокации
- **Цели:** выйти за пределы своей аллокации, получить трафик других сессий, исчерпать relay квоты
- **Меры:** permission enforcement, bandwidth quotas, channel isolation

### 3.3 Replay attacker
- **Возможности:** перехват и повтор валидных STUN-запросов или JWT
- **Цели:** переиспользовать истёкшие credentials, повторить allocate/refresh
- **Меры:** nonce rotation (10 мин), jti blacklist для JWT, transaction ID tracking

### 3.4 Relay exhaustion attacker
- **Возможности:** массовое создание аллокаций с валидными credentials
- **Цели:** исчерпать порты relay, заблокировать легитимных клиентов
- **Меры:** allocation quotas в AllocationStore, port pool ограничение, rate limiter

### 3.5 Malformed packet sender
- **Возможности:** отправка намеренно сломанных STUN/RTCP/ChannelData пакетов
- **Цели:** вызвать panic, OOB access, бесконечный цикл в парсере
- **Меры:** MAX_MESSAGE_LEN=4096, MAX_ATTRIBUTE_VALUE_LEN=1500, MAX_ATTRIBUTES_PER_MESSAGE=32, fuzzing coverage

### 3.6 MITM attacker
- **Возможности:** перехват трафика на сетевом уровне
- **Цели:** подменить STUN ответы, перехватить ключи
- **Меры:** mTLS для management plane, MESSAGE-INTEGRITY на STUN, DTLS для медиа

### 3.7 Compromised node
- **Возможности:** полный контроль над одним узлом кластера
- **Цели:** получить данные других узлов, инжектировать фиктивные аллокации
- **Меры:** mTLS межузловые соединения, изолированный AllocationStore per-node

### 3.8 Compromised signaling service
- **Возможности:** выпуск произвольных JWT, управление room state
- **Цели:** создать привилегированные сессии, получить доступ к управлению
- **Меры:** JWT issuer validation (`iss=turna-auth`), jti blacklist, короткий TTL токенов

---

## 4. Границы доверия

```
┌─────────────────────────────────────────────────────┐
│                  PUBLIC INTERNET                     │
│  Unauthenticated UDP/TCP clients                     │
└──────────────────────┬──────────────────────────────┘
                       │ UDP 3478 / TCP 3478
              ╔════════▼════════╗
              ║  PUBLIC UDP EDGE ║  ← минимальное доверие
              ║  rate limiter    ║    только parser + auth challenge
              ║  parser limits   ║
              ╚════════╤════════╝
                       │ verified MESSAGE-INTEGRITY
              ╔════════▼════════╗
              ║   RELAY CORE    ║  ← аутентифицированные клиенты
              ║  allocation mgr  ║    permission enforcement
              ║  channel routing ║    bandwidth quotas
              ╚════════╤════════╝
                       │ mTLS
              ╔════════▼════════╗
              ║  CONTROL PLANE  ║  ← только внутренние узлы
              ║  gRPC management ║    mutual TLS required
              ║  cluster state   ║
              ╚════════╤════════╝
                       │ mTLS
              ╔════════▼════════╗
              ║ MANAGEMENT PLANE ║  ← административный доступ
              ║  admin API       ║    аутентификация + авторизация
              ║  config changes  ║
              ╚════════╤════════╝
                       │
              ╔════════▼════════╗
              ║  OBSERVABILITY  ║  ← read-only метрики
              ║  Prometheus      ║    без доступа к данным сессий
              ║  audit log       ║
              ╚════════╤════════╝
                       │
              ╔════════▼════════╗
              ║ STORAGE BACKEND ║  ← Tarantool, изолирован
              ║  allocation store ║   только через internal API
              ╚═════════════════╝
```

---

## 5. Поверхности атаки

### 5.1 STUN/TURN parser
- **Вектор:** любой UDP пакет на порт 3478
- **Риски:** OOB read/write, integer overflow в length fields, бесконечный цикл
- **Контроль:** hard limits на packet/attribute size и count, fuzzing

### 5.2 RTCP parser
- **Вектор:** медиапакеты от peer через relay
- **Риски:** OOB в reception report loop (rc field), REMB bitfield overflow
- **Контроль:** bounds checks, fuzzing corpus

### 5.3 DTLS handshake
- **Вектор:** DTLS ClientHello от любого IP
- **Риски:** handshake flood, invalid certificate processing
- **Контроль:** handshake rate limiting, retransmission abuse protection

### 5.4 Relay allocation lifecycle
- **Вектор:** последовательность ALLOCATE/REFRESH/EXPIRE запросов
- **Риски:** аллокация без аутентификации, permission bypass, lifetime manipulation
- **Контроль:** MESSAGE-INTEGRITY до state mutation, nonce validation, max lifetime cap

### 5.5 Auth endpoints (REST API)
- **Вектор:** POST /api/auth/login, /api/auth/register
- **Риски:** credential bruteforce, token replay, account enumeration
- **Контроль:** Argon2id hashing, JWT jti blacklist, rate limiting

### 5.6 Management gRPC
- **Вектор:** gRPC соединения на management порт
- **Риски:** unauthorized admin actions, config modification
- **Контроль:** mTLS mutual authentication, только из внутренней сети

### 5.7 Config loading
- **Вектор:** файл конфигурации, переменные окружения
- **Риски:** injection через параметры конфига, secret exposure в логах
- **Контроль:** валидация при загрузке, secrets только через env vars

---

## 6. Применимые стандарты

- ГОСТ Р 59548-2022 (события информационной безопасности)
- RFC 5389 (STUN), RFC 5766 (TURN), RFC 3550 (RTP/RTCP)
- Требования ФСТЭК к защите информации в ИС
