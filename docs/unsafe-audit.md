# Unsafe Code Audit — first pass

**Дата:** 2026-05-16
**Скоуп:** все `unsafe` блоки в `crates/{transport,relay}/src/`.
**Примечание:** документ сокращён до крейтов, входящих в этот репозиторий; записи исходного прохода по не вошедшим крейтам удалены, нумерация пунктов сохранена (поэтому в ней есть пропуски), агрегированные счётчики ниже могут отражать исходный объём.
**Тип аудита:** first-pass — категоризация и фиксация инвариантов, не формальная верификация. Подробнее см. раздел «Методология».

---

## Сводка

| Категория | Кол-во блоков | Что это значит |
|---|---|---|
| ✓ **SAFETY** (обоснован) | ~75 | Инварианты ясны из контекста; задокументированы прямо в коде через `// SAFETY: ...`. |
| ⚠ **NEEDS-REVIEW** | 15 | Корректность зависит от инвариантов, которые из исходника не видны. Нужен экспертный взгляд или дополнительные тесты. |
| ✗ **SUSPECT** | 9 | Виден конкретный риск UB / data race / unbounded behaviour. Перед production-деплоем чинить. |

**Топ-3 находки, требующие немедленного внимания:**

1. **ABA race в `HugePagePool` Treiber stack** (`hugepages.rs:130, 137, 160`) — классический use-after-free под нагрузкой.
2. **`Umem::frame_slice/frame_slice_mut` без bounds-чека** (`af_xdp.rs:167-174`) — OOB чтение/запись из mmap'd региона.
3. **Self-referential `MsgHdrStorage` без гарантии стабильности места** (`uring.rs:65-100`) — работает только потому, что `Vec` пред-аллоцирован один раз; невидимый инвариант.

Остальные SUSPECT-находки описаны ниже.

---

## Методология

Прошёл по всем 17 файлам глазами, для каждого `unsafe` блока:

1. Определил, зачем он (FFI, raw pointer math, разделяемая память, lock-free, и т.д.).
2. Выписал требуемые инварианты (что должно быть истинным, чтобы блок был корректен).
3. Проверил, выполняются ли инварианты из контекста кода.
4. Если **да** — добавил `// SAFETY: <обоснование>` в код.
5. Если **частично** (зависит от внешнего инварианта) — добавил `// NEEDS-REVIEW: <что нужно проверить>`.
6. Если виден **конкретный риск** — добавил `// SUSPECT: <конкретный сценарий>`.

**Что не входит в этот раунд:**

- Доказательство soundness через [Miri](https://github.com/rust-lang/miri) (несовместимо с kernel API: mmap, io_uring, syscalls).
- Прогон под [ASan/TSan/MSan](https://github.com/google/sanitizers) — отдельная инфра, нужны интеграционные тесты с трафиком.
- Формальные модели для lock-free структур (TLA+, Loom).
- Рефакторинг unsound кода в safe эквиваленты.

Все эти штуки — отдельные большие задачи. Этот документ — **отправная точка**, а не финальный вердикт.

---

## SUSPECT — конкретные риски

### 1. ABA race в `HugePagePool::alloc/free` (HIGH)

**Файл:** `crates/transport/src/hugepages.rs:122-172`

```rust
pub fn alloc(&self) -> Option<PoolBuffer> {
    loop {
        let head = self.free_head.load(Ordering::Acquire);
        if head.is_null() { ... }
        let next = unsafe { (*head).next };   // ← (1) разыменование, потом
        if self.free_head
            .compare_exchange_weak(head, next, ..)    // ← (2) CAS
            .is_ok()
        {
            let slot_index = unsafe { (*head).slot_index };
            unsafe { drop(Box::from_raw(head)) };    // ← (3) free
            ...
        }
    }
}
```

**Проблема:** между (1) загрузкой `head` и (2) CAS другой поток может:
1. Сделать `alloc()` того же узла → `head` уже не на стеке.
2. Сделать `free()` другого узла → `Box::new(FreeNode)` может **переиспользовать тот же адрес**.
3. Теперь `head` указывает на «новый» узел с другим `.next`.
4. CAS видит «тот же» указатель и проходит. Но логически это другой узел.
5. Считываем `(*head).next` повторно → получаем мусор.

**Сценарий UB:** между шагом 1 и шагом 2 поток вытесняется, другой поток успевает сделать pop+push с тем же адресом. CAS проходит, но `(*head).slot_index` теперь читается из узла, который другой поток ещё держит в работе → race на чтение.

**Стандартный фикс:** epoch-based reclamation (`crossbeam_epoch`) или hazard pointers, либо отказ от Treiber stack в пользу `crossbeam_queue::SegQueue`. Самый прагматичный — заменить лок-фри логику на `Mutex<Vec<usize>>` (буферный пул не на hot path после прогрева).

**Impact:** под высокой concurrent-нагрузкой (несколько worker-потоков активно alloc/free) — реальный data race. Не воспроизводится в простых тестах из-за вероятностной природы, но в production проявится как редкие краши.

---

### 2. `Umem::frame_slice` без bounds-чека (HIGH)

**Файл:** `crates/transport/src/af_xdp.rs:166-174`

```rust
pub fn frame_slice(&self, addr: u64, len: usize) -> &[u8] {
    unsafe { std::slice::from_raw_parts(self.area.add(addr as usize), len) }
}

pub fn frame_slice_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(self.area.add(addr as usize), len) }
}
```

**Проблема:** функции принимают произвольные `addr` и `len` без проверки, что `addr + len <= self.size`. Вызываются с данными из RX-ring kernel'а. Если kernel выдаст некорректный `addr` (баг в драйвере, испорченный ring), или если кто-то в userspace ошибётся при пересчёте offset'ов — UB через OOB-чтение mmap'd региона.

**Фикс:** добавить `assert!(addr.checked_add(len as u64).map(|end| end <= self.size as u64).unwrap_or(false))` в начало обеих функций. На hot path это один cmp/jne, измеримо ноль на современном CPU.

---

### 3. Self-referential `MsgHdrStorage` (HIGH)

**Файл:** `crates/transport/src/uring.rs:45-106`

```rust
pub struct MsgHdrStorage {
    pub msgvec: libc::iovec,
    pub addr: libc::sockaddr_storage,
    pub addr_len: libc::socklen_t,
    pub msghdr: libc::msghdr,         // содержит указатели...
    send_buf: Vec<u8>,
}

pub fn setup_recv(&mut self, buf_ptr: *mut u8, buf_len: usize) {
    ...
    self.msghdr.msg_name = &mut self.addr as *mut _ as *mut _;   // ← в self
    self.msghdr.msg_iov  = &mut self.msgvec;                       // ← в self
    ...
}
```

**Проблема:** `msghdr` содержит указатели на `addr` и `msgvec`, лежащие в **том же** `MsgHdrStorage`. Структура **не Pin'нута**. Если её переместить — указатели задангилят.

**Текущая «спасительная» инвариантa:** `MsgHdrStorage` лежит в `Vec<MsgHdrStorage>` внутри `UringEngine`, и этот `Vec` создаётся с `with_capacity(N)` и заполняется ровно `N` элементами в `UringEngine::new`. Дальше — никаких `push`. Поэтому Vec не реаллоцируется → элементы не двигаются → указатели валидны.

**Почему это suspect, а не safety:** инвариант **невидим** из исходника. Любая будущая правка, которая добавит `push` или `extend` в эти Vec'и (например, динамическое добавление relay-сокетов с расширением пула msghdr'ов), молча сломает корректность без warning'а от компилятора.

**Связанная проблема:** `relay_pool_size = 512`, каждый relay тратит `2 * 32 = 64` слота → максимум **8 одновременных relay-сокетов**. На 9-м — паника при индексации в `submit_relay_recv`. Не UB, но silent limit без проверки в `add_relay`.

**Фикс:**
- Либо обернуть в `Box<MsgHdrStorage>` (один Box-allocation, адрес стабилен).
- Либо использовать `Pin<Box<...>>` явно.
- В `add_relay` добавить проверку capacity перед инкрементом `relay_msghdr_next`.

---

### 4. `PoolBuffer::as_mut_slice` отдаёт неинициализированные байты (MEDIUM)

**Файл:** `crates/transport/src/hugepages.rs:225-227`

```rust
pub fn as_mut_slice(&mut self) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.capacity) }
}
```

**Проблема:** возвращает slice на `capacity` байт, но память из mmap **не зануляется** (хотя `MAP_ANONYMOUS` обычно даёт нули, это поведение Linux, не Rust-инвариант). Если вызывающий читает байты до записи — UB по [«reading uninitialized memory»](https://rust-lang.github.io/unsafe-code-guidelines/glossary.html#uninitialized-memory).

`as_slice` (read-only) использует `self.len` — это OK, если `len` был корректно установлен через `set_len` после записи.

**Фикс:** возвращать `&mut [MaybeUninit<u8>]` вместо `&mut [u8]` для нерасчитанного хвоста, либо чётко контрактом запретить читать из as_mut_slice до записи (но это слабая гарантия).

---

### 5. Stacked borrows fragility в `batch.rs::sendmmsg_batch` (MEDIUM)

**Файл:** `crates/transport/src/batch.rs:75-113`

```rust
for pkt in packets.iter().take(count) {
    iovecs.push(libc::iovec { ... });
    addrs.push(addr);
    msgs.push(MmsgHdr { ... });
}

for i in 0..count {
    msgs[i].msg_hdr.msg_iov  = &mut iovecs[i] as *mut libc::iovec;   // ← raw ptr
    msgs[i].msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
    ...
}

let sent = unsafe { libc::syscall(SYS_sendmmsg, fd, msgs.as_mut_ptr(), ...) };
```

**Проблема:** все три Vec'а заранее `with_capacity(count)` — реаллокаций нет, адреса элементов стабильны до конца функции. Это OK.

Но: создание `&mut iovecs[i]` в цикле и каст в raw pointer перекрывается во времени с последующими `&mut iovecs[j]`. По stacked borrows это технически создаёт overlapping mutable borrows через raw pointers. Текущая компиляторная политика их не ловит, и фактически memory layout от этого не страдает, но **в строгом смысле UB**.

**Impact:** низкий — текущий код работает. Но если миграция на Tree Borrows / новые SB-правила сломается, начнётся UB-warning от Miri и потенциальные крэши под новыми оптимизациями.

**Фикс:** взять указатели в одном проходе через `as_mut_ptr()` + offset arithmetic.

---

### 6. `cmsghdr` parsing без alignment-чека (MEDIUM)

**Файл:** `crates/transport/src/gso.rs:155-178`

```rust
let hdr = unsafe {
    &*(cmsg_buf.as_ptr().add(offset) as *const libc::cmsghdr)
};
```

**Проблема:** `cmsghdr` имеет нативное выравнивание (8 байт на 64-bit Linux). `cmsg_buf` — это `&[u8]` без гарантий выравнивания. Если ptr не выровнен — UB при разыменовании.

На практике буферы под cmsg обычно идут от kernel'а с правильным выравниванием, и `cmsg_buf` приходит от `recvmsg`. Но user-controlled offset (`offset += aligned`) теоретически мог бы привести к смещённому указателю.

**Фикс:** использовать `std::ptr::read_unaligned` либо проверять `align_of_val`.

---

### 7. Drop of `HugePagePool` без синхронизации (MEDIUM)

**Файл:** `crates/transport/src/hugepages.rs:190-202`

```rust
impl Drop for HugePagePool {
    fn drop(&mut self) {
        let mut node = self.free_head.load(Ordering::Relaxed);
        while !node.is_null() {
            let next = unsafe { (*node).next };
            unsafe { drop(Box::from_raw(node)) };
            node = next;
        }
        free_memory(self.base, self.total_size);
    }
}
```

**Проблема:** munmap'ает `base` без какой-либо проверки, что нет outstanding `PoolBuffer`'ов, которые указывают в эту память. `PoolBuffer` не ссылается на pool через `Arc`, у него просто raw pointer. Если pool дропнут, а buffer'ы живы — UAF.

**Текущая защита:** никакая. Полагается на корректное использование (pool живёт дольше всех buffer'ов).

**Фикс:** `Arc<HugePagePool>` + хранение клона `Arc` в каждом `PoolBuffer`, либо `assert!(self.allocated == 0)` в Drop с паникой.

---


### 9. `recv_batch` / `send_to` в AfXdpTransport — stub-функции возвращают пустые результаты (INFO)

**Файл:** `crates/transport/src/af_xdp.rs:401-413`

```rust
pub fn recv_batch(&mut self, max: usize) -> Vec<ReceivedFrame> {
    Vec::new() // placeholder
}
pub fn send_to(&mut self, data: &[u8], target: SocketAddr) -> Result<()> {
    Ok(()) // placeholder
}
```

**Проблема:** не UB, но **функционал не работает**. Если кто-то поверит сигнатуре и подключит AfXdpTransport — пакеты тихо потеряются. Маркер «placeholder» в комментариях есть, но это не предотвратит ошибку использования.

**Фикс:** либо `unimplemented!()`, либо чётко стуб через cfg-gate с предупреждением при сборке.

---

## NEEDS-REVIEW — нужен экспертный взгляд

| # | Файл | Что | Почему NEEDS-REVIEW |
|---|---|---|---|
| 1 | `uring.rs:213,229,275,302` | `submission().push(&entry)` | Корректность зависит от того, живёт ли `msghdr` (на который указывает entry) до завершения операции. В коде это держится через `Vec` + slot-индекс, но нет механизма «slot busy». Если slot переиспользовать до completion — UB. |
| 2 | `splice.rs:155-237` | `splice_relay` через `spawn_blocking` | `client_fd` / `peer_fd` передаются в blocking-task. Если в это время родительский async-таск уронит сокет — fd валиден до конца blocking, но семантика «owner» неясна. |
| 3 | `graceful.rs:169,180` | `File::from_raw_fd(fd)` + `mem::forget(f)` | Идиома для «передать fd обратно вызывающему». Корректна, но `mem::forget` блокирует RAII — если позже забыть закрыть fd, leak. |
| 5 | `af_xdp.rs:105-106` | `unsafe impl Send/Sync for Umem` | Send OK (raw ptr принадлежит структуре). Sync через `&Umem.frame_slice` отдаёт `&[u8]` на mmap-область, которая параллельно может модифицироваться kernel'ом (DMA). По модели Rust это нарушение Sync. NEEDS-REVIEW: возможно нужно вообще убрать Sync. |
| 6 | `worker.rs:329-335` | `pin_to_core` через `sched_setaffinity` | Стандартный pattern, но `CPU_SET` — macro libc, в Rust обёртка делает write через `set_bit`. Если cpuset не достаточен (на машине больше CPU, чем размер `cpu_set_t`) — silent truncation. На современных Linux это >1024 CPU, маловероятно. |
| 7 | `hugepages.rs:71-72` | `unsafe impl Send/Sync for HugePagePool` | Если ABA-проблема (см. SUSPECT #1) реальна, lock-free свойство неверно — Sync impl становится ложным. |

---

## SAFETY — обоснованные блоки (укрупнённо)

Не перечисляю поштучно — таких ~75. Все попадают в одну из категорий:

1. **libc syscalls** (≈40): `mmap`, `munmap`, `close`, `setsockopt`, `if_nametoindex`, `sched_setaffinity`, `epoll_*`, `pipe2`, `bpf`, `set_mempolicy`, `socket`, `bind`, `poll`, `sendto`. Все — стандартный pattern: ptr + len, errno check. Аргументы либо stack-локальные структуры, либо валидные slice'ы. SAFETY: `libc syscall with valid local-struct pointer and size; errno checked`.

2. **`mem::zeroed::<libc::*>()`** (≈8): зануление C-структур через `MaybeUninit::zeroed().assume_init()` эквивалент. Корректно для `sockaddr_*`, `cmsghdr`, `epoll_event`, `cpu_set_t`, `iovec`, `msghdr` — все являются POD-структурами с валидным all-zero состоянием.

3. **Raw pointer cast `&T as *mut _ as *mut U`** для FFI structs (≈12): кастуем `&mut sockaddr_storage` к `&mut sockaddr_in` после установки `family`. Layout одинаковый (sockaddr_storage спроектирован как union для всех вариантов). SAFETY: standard sockaddr cast.

4. **`set_len` после `recv_from`** (1, в `server.rs:197`): инициализирует BytesMut до `MAX_UDP_PACKET`, затем `recv_from` пишет первые `n` байт, после чего `truncate(n)`. Между set_len и recv_from байты не читаются. Стандартный pattern для recv-буферов.

5. **`from_raw_parts` для mmap'd регионов** (4): `as_slice` / `as_mut_slice` на `PoolBuffer` использует `len`/`capacity`, что является валидной частью mmap-региона. (Исключение — `PoolBuffer::as_mut_slice` отдаёт `capacity` неинициализированных байт; см. SUSPECT #4.)

6. **`Box::from_raw` / `into_raw`** (4): идиома владения для FFI и lock-free структур. В FFI контракт документирован. В lock-free — см. SUSPECT #1 для известной проблемы.

---

## Per-file inventory

| Файл | Строки | unsafe-блоков | SAFETY | NEEDS-REVIEW | SUSPECT |
|---|---|---|---|---|---|
| transport/hugepages.rs | 421 | 18 | 13 | 1 | **4** |
| transport/af_xdp.rs | 533 | 17 | 13 | 2 | 2 |
| relay/splice.rs | 288 | 15 | 14 | 1 | 0 |
| transport/uring.rs | 354 | 9 | 7 | 1 | 1 |
| transport/gso.rs | 295 | 7 | 6 | 0 | 1 |
| transport/batch.rs | 296 | 4 | 3 | 0 | 1 |
| relay/graceful.rs | 296 | 3 | 2 | 1 | 0 |
| transport/numa.rs | 329 | 2 | 2 | 0 | 0 |
| transport/bpf_filter.rs | 225 | 2 | 2 | 0 | 0 |
| transport/worker.rs | 340 | 1 | 0 | 1 | 0 |
| transport/buffer.rs | 228 | 1 | 1 (doc only) | 0 | 0 |
| relay/server.rs | 268 | 1 | 1 | 0 | 0 |
| relay/processor.rs | 577 | 1 | 1 (doc only) | 0 | 0 |
| xdp/lib.rs | 228 | 1 | 1 | 0 | 0 |
| xdp/program.rs | 137 | 1 | 1 | 0 | 0 |
| **Итого** | **5337** | **99** | **~75** | **15** | **9** |

(Распределение приблизительное — multi-line блоки иногда содержат несколько отдельных unsafe-операций; точные числа в коде через комментарии `// SAFETY/NEEDS-REVIEW/SUSPECT:`.)

---

## Рекомендации

### Срочное (перед production)

1. **Заменить Treiber stack в `HugePagePool`** на `Mutex<Vec<usize>>` (буферный пул всё равно не на hot path после прогрева) или `crossbeam_queue::SegQueue`. Это закрывает SUSPECT #1.
2. **Добавить bounds-чеки в `Umem::frame_slice*`.** Однострочный assert, ~0 cost. Закрывает SUSPECT #2.
3. **Box-аллоцировать `MsgHdrStorage`** в `uring.rs` (или Pin'нуть Vec). Закрывает SUSPECT #3.
4. **`PoolBuffer::as_mut_slice` → MaybeUninit** или удалить (использовать только `as_mut_ptr` + явный `set_len`). Закрывает SUSPECT #4.

### Среднее (в течение квартала)

5. Прогнать `cargo geiger` в CI (informational job — есть в этом архиве).
6. Прогнать парсеры под Miri (отдельная задача — STUN/TURN парсеры без kernel-зависимостей, Miri-совместимы).
7. Добавить интеграционные тесты с `RUSTFLAGS=-Z sanitizer=address` (требует nightly).

### Постоянное

8. **Все новые `unsafe` блоки должны иметь `// SAFETY: ...` комментарий.** Включить clippy lint `clippy::undocumented_unsafe_blocks` (warn-level, потом deny).
9. Пере-генерировать инвентарь через `scripts/unsafe-inventory.sh` после каждого затрагивающего PR. В будущем — автоматически в CI.

---

## Что дальше

Этот документ — **отправная точка**. Чтобы продвинуться:

- **SUSPECT #1-4** реализуйте как отдельные PR. Каждый — 100-200 строк, легко ревьюится.
- **Miri-кампанию** для STUN/TURN парсеров запустите параллельно (`cargo +nightly miri test -p turna-proto-stun`).
- **Fuzzing** (отдельный TODO из критичного списка) логически продолжает этот аудит — найдённые fuzz-крэши скорее всего будут касаться этих же блоков.
