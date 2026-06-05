# Reproducible Builds

## Требования

- Rust 1.95.0 (зафиксирован в `rust-toolchain.toml`)
- Зависимости зафиксированы в `Cargo.lock`

## Сборка

```bash
# Установить правильную версию Rust
rustup toolchain install 1.95.0

# Верифицировать версию
rustc --version  # должно быть 1.95.0

# Собрать
cargo build --release -p turna-node

# Проверить зависимости на уязвимости
cargo deny check
```

## Верификация

```bash
# Хэш бинарника должен совпадать на одинаковом окружении
sha256sum target/release/turna-node
```

## Lockfile

`Cargo.lock` коммитится в репозиторий — гарантирует идентичные
версии зависимостей на всех машинах.

## cargo-deny

Проверка зависимостей:
```bash
cargo deny check
```

Конфиг: `deny.toml`
