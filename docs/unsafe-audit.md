# Unsafe Code Audit — first pass

> AF_XDP update, 2026-09-19: the active XSK path now retains pending refill
> descriptors, quarantines ambiguous TX submissions, shares the program across
> queues within one thread, and removes XSK map entries before queue/UMEM teardown.
> XDP_OPTIONS checks the actual socket mode. These changes still require Rust and
> kernel verification; this note is not a completed soundness audit. See
> [the verification record](verification/af-xdp-hardening-2026-09-19.md).


**Date:** 2026-05-16
**Scope:** all `unsafe` blocks in `crates/{transport,relay}/src/`.
**Note:** the document has been trimmed to the crates included in this repository; entries from the original pass for crates not included have been removed, item numbering has been preserved (hence the gaps in it), and the aggregate counts below may reflect the original scope.
**Audit type:** first-pass — categorization and recording of invariants, not formal verification. See the "Methodology" section for details.

---

## Summary

| Category | Block count | What it means |
|---|---|---|
| ✓ **SAFETY** (justified) | ~76 | Invariants are clear from context; documented directly in the code via `// SAFETY: ...`. |
| ⚠ **NEEDS-REVIEW** | 14 | Correctness depends on invariants that are not visible from the source. Needs expert review or additional tests. |
| ✓ **SUSPECT (fixed)** | 9 | A concrete UB / data race risk was visible. **All 9 were fixed** before P0 (`summary.suspect_fixed = 9` in `unsafe-inventory.json`); this section is a historical record of findings, not an open list. |

> Status as of P0: 9 SUSPECT closed (see below), USF-008 (overflow in `Umem::new`) fixed, the `Sync` invariant of `Umem` documented. What remains open are NEEDS-REVIEW items that do not cause direct UB.

**Top 3 findings (all FIXED — historical record):**

1. ✓ **ABA race in the `HugePagePool` Treiber stack** (`hugepages.rs`) — *fixed (USF-001)*: the Treiber CAS stack was replaced with `Mutex<Vec<usize>>`; `Drop` asserts there are no active buffers before `munmap`.
2. ✓ **`Umem::frame_slice/frame_slice_mut` without a bounds check** (`af_xdp.rs`) — *fixed (USF-002/#2)*: `checked_add` + `assert` on the bounds before access.
3. ✓ **Self-referential `MsgHdrStorage` without a guarantee of address stability** (`uring.rs`) — *fixed (USF-003/#3)*: `Vec<MsgHdrStorage>` → `Box<[MsgHdrStorage]>`; addresses are stable for the whole lifetime of `UringEngine`.

The full list of SUSPECT items and their status is in `unsafe-inventory.json` (`suspect_fixed = 9`).

> **Current state (regeneration via `scripts/unsafe-inventory.sh`, 2026-06-15).**
> The reproducible count of `unsafe` lines in the `crates/{transport,relay}/src/` scope is **104**
> (transport 85, relay 19). Markers in the code: `// SAFETY:` 97, `// NEEDS-REVIEW:` 2,
> `// SUSPECT:` 0. All 104 are documented; `crates/transport/src/tokio_transport.rs` (6
> blocks) has been audited and added (USF-010/011, SAFETY_JUSTIFIED) — nothing is outside the audited
> set. The 76/14/9 counts below refer
> to the original 2026-05-16 pass, not to a recategorization of the current 104.

---

## Methodology

I went through all 17 files by eye; for each `unsafe` block I:

1. Determined why it exists (FFI, raw pointer math, shared memory, lock-free, etc.).
2. Wrote down the required invariants (what must be true for the block to be correct).
3. Checked whether the invariants hold from the code context.
4. If **yes** — added `// SAFETY: <justification>` in the code.
5. If **partially** (depends on an external invariant) — added `// NEEDS-REVIEW: <what needs checking>`.
6. If a **concrete risk** is visible — added `// SUSPECT: <concrete scenario>`.

**Out of scope for this round:**

- Proving soundness with [Miri](https://github.com/rust-lang/miri) (incompatible with kernel APIs: mmap, io_uring, syscalls).
- Running under [ASan/TSan/MSan](https://github.com/google/sanitizers) — separate infrastructure; requires integration tests with traffic.
- Formal models for lock-free structures (TLA+, Loom).
- Refactoring unsound code into safe equivalents.

Each of these is a separate large task. This document is a **starting point**, not a final verdict.

---

## SUSPECT — concrete risks

### 1. ABA race in `HugePagePool::alloc/free` (HIGH)

**File:** `crates/transport/src/hugepages.rs:122-172`

```rust
pub fn alloc(&self) -> Option<PoolBuffer> {
    loop {
        let head = self.free_head.load(Ordering::Acquire);
        if head.is_null() { ... }
        let next = unsafe { (*head).next };   // ← (1) dereference, then
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

**Problem:** between (1) loading `head` and (2) the CAS, another thread can:
1. `alloc()` the same node → `head` is no longer on the stack.
2. `free()` a different node → `Box::new(FreeNode)` may **reuse the same address**.
3. Now `head` points to a "new" node with a different `.next`.
4. The CAS sees the "same" pointer and succeeds. But logically it is a different node.
5. We read `(*head).next` again → we get garbage.

**UB scenario:** between step 1 and step 2 the thread is preempted, and another thread manages to do a pop+push with the same address. The CAS succeeds, but `(*head).slot_index` is now read from a node that the other thread is still using → read race.

**Standard fix:** epoch-based reclamation (`crossbeam_epoch`) or hazard pointers, or dropping the Treiber stack in favor of `crossbeam_queue::SegQueue`. The most pragmatic option is to replace the lock-free logic with `Mutex<Vec<usize>>` (the buffer pool is not on the hot path after warm-up).

**Impact:** under high concurrent load (several worker threads actively doing alloc/free) — a real data race. It does not reproduce in simple tests because of its probabilistic nature, but in production it will show up as rare crashes.

---

### 2. `Umem::frame_slice` without a bounds check (HIGH)

**File:** `crates/transport/src/af_xdp.rs:166-174`

```rust
pub fn frame_slice(&self, addr: u64, len: usize) -> &[u8] {
    unsafe { std::slice::from_raw_parts(self.area.add(addr as usize), len) }
}

pub fn frame_slice_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(self.area.add(addr as usize), len) }
}
```

**Problem:** the functions take arbitrary `addr` and `len` without checking that `addr + len <= self.size`. They are called with data from the kernel's RX ring. If the kernel hands out an invalid `addr` (a driver bug, a corrupted ring), or if something in userspace gets an offset calculation wrong — UB via an OOB read of the mmap'd region.

**Fix:** add `assert!(addr.checked_add(len as u64).map(|end| end <= self.size as u64).unwrap_or(false))` at the start of both functions. On the hot path this is a single cmp/jne, measurably zero on a modern CPU.

---

### 3. Self-referential `MsgHdrStorage` (HIGH)

**File:** `crates/transport/src/uring.rs:45-106`

```rust
pub struct MsgHdrStorage {
    pub msgvec: libc::iovec,
    pub addr: libc::sockaddr_storage,
    pub addr_len: libc::socklen_t,
    pub msghdr: libc::msghdr,         // contains pointers...
    send_buf: Vec<u8>,
}

pub fn setup_recv(&mut self, buf_ptr: *mut u8, buf_len: usize) {
    ...
    self.msghdr.msg_name = &mut self.addr as *mut _ as *mut _;   // ← into self
    self.msghdr.msg_iov  = &mut self.msgvec;                       // ← into self
    ...
}
```

**Problem:** `msghdr` contains pointers to `addr` and `msgvec`, which live in the **same** `MsgHdrStorage`. The struct is **not pinned**. If it is moved, the pointers will dangle.

**The current "saving" invariant:** `MsgHdrStorage` lives in a `Vec<MsgHdrStorage>` inside `UringEngine`, and that `Vec` is created with `with_capacity(N)` and filled with exactly `N` elements in `UringEngine::new`. After that, no `push`. So the Vec does not reallocate → elements do not move → pointers stay valid.

**Why this is suspect rather than safety:** the invariant is **invisible** from the source. Any future change that adds a `push` or `extend` to these Vecs (for example, dynamically adding relay sockets by growing the msghdr pool) will silently break correctness without any compiler warning.

**Related problem:** `relay_pool_size = 512`, and each relay uses `2 * 32 = 64` slots → at most **8 concurrent relay sockets**. On the 9th — a panic on indexing in `submit_relay_recv`. Not UB, but a silent limit with no check in `add_relay`.

**Fix:**
- Either wrap it in `Box<MsgHdrStorage>` (one Box allocation, stable address).
- Or use `Pin<Box<...>>` explicitly.
- In `add_relay`, add a capacity check before incrementing `relay_msghdr_next`.

---

### 4. `PoolBuffer::as_mut_slice` hands out uninitialized bytes (MEDIUM)

**File:** `crates/transport/src/hugepages.rs:225-227`

```rust
pub fn as_mut_slice(&mut self) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.capacity) }
}
```

**Problem:** it returns a slice of `capacity` bytes, but the mmap memory is **not zeroed** (although `MAP_ANONYMOUS` usually yields zeros, that is Linux behavior, not a Rust invariant). If the caller reads bytes before writing them — UB per ["reading uninitialized memory"](https://rust-lang.github.io/unsafe-code-guidelines/glossary.html#uninitialized-memory).

`as_slice` (read-only) uses `self.len` — this is OK as long as `len` was set correctly via `set_len` after writing.

**Fix:** return `&mut [MaybeUninit<u8>]` instead of `&mut [u8]` for the unaccounted tail, or explicitly forbid by contract reading from as_mut_slice before writing (but that is a weak guarantee).

---

### 5. Stacked borrows fragility in `batch.rs::sendmmsg_batch` (MEDIUM)

**File:** `crates/transport/src/batch.rs:75-113`

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

**Problem:** all three Vecs are preallocated with `with_capacity(count)` — no reallocations, element addresses are stable until the end of the function. This is OK.

But: creating `&mut iovecs[i]` in the loop and casting it to a raw pointer overlaps in time with the subsequent `&mut iovecs[j]`. Under stacked borrows this technically creates overlapping mutable borrows through raw pointers. Current compiler policy does not catch them, and in practice the memory layout is not affected, but it is **UB in the strict sense**.

**Impact:** low — the current code works. But if the migration to Tree Borrows / new SB rules breaks it, Miri will start reporting UB and there may be crashes under new optimizations.

**Fix:** take the pointers in a single pass via `as_mut_ptr()` + offset arithmetic.

---

### 6. `cmsghdr` parsing without an alignment check (MEDIUM)

**File:** `crates/transport/src/gso.rs:155-178`

```rust
let hdr = unsafe {
    &*(cmsg_buf.as_ptr().add(offset) as *const libc::cmsghdr)
};
```

**Problem:** `cmsghdr` has native alignment (8 bytes on 64-bit Linux). `cmsg_buf` is a `&[u8]` with no alignment guarantees. If the ptr is not aligned — UB on dereference.

In practice cmsg buffers usually come from the kernel with correct alignment, and `cmsg_buf` comes from `recvmsg`. But a user-controlled offset (`offset += aligned`) could theoretically produce a misaligned pointer.

**Fix:** use `std::ptr::read_unaligned` or check `align_of_val`.

---

### 7. Drop of `HugePagePool` without synchronization (MEDIUM)

**File:** `crates/transport/src/hugepages.rs:190-202`

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

**Problem:** it munmaps `base` without any check that there are no outstanding `PoolBuffer`s pointing into that memory. `PoolBuffer` does not reference the pool through an `Arc`; it just holds a raw pointer. If the pool is dropped while buffers are alive — UAF.

**Current protection:** none. It relies on correct usage (the pool outlives all buffers).

**Fix:** `Arc<HugePagePool>` + storing an `Arc` clone in each `PoolBuffer`, or `assert!(self.allocated == 0)` in Drop with a panic.

---


### 9. `recv_batch` / `send_to` in AfXdpTransport — stub functions return empty results (INFO)

**File:** `crates/transport/src/af_xdp.rs:401-413`

```rust
pub fn recv_batch(&mut self, max: usize) -> Vec<ReceivedFrame> {
    Vec::new() // placeholder
}
pub fn send_to(&mut self, data: &[u8], target: SocketAddr) -> Result<()> {
    Ok(()) // placeholder
}
```

**Problem:** not UB, but **the functionality does not work**. If someone trusts the signature and wires up AfXdpTransport, packets will be silently lost. There is a "placeholder" marker in the comments, but that will not prevent misuse.

**Fix:** either `unimplemented!()`, or an explicit stub behind a cfg gate with a build-time warning.

---

## NEEDS-REVIEW — needs expert review

| # | File | What | Why NEEDS-REVIEW |
|---|---|---|---|
| 1 | `uring.rs:213,229,275,302` | `submission().push(&entry)` | Correctness depends on whether the `msghdr` (pointed to by the entry) lives until the operation completes. In the code this is held via `Vec` + a slot index, but there is no "slot busy" mechanism. If a slot is reused before completion — UB. |
| 2 | `splice.rs:155-237` | `splice_relay` via `spawn_blocking` | `client_fd` / `peer_fd` are passed into a blocking task. If the parent async task drops the socket in the meantime, the fd stays valid until the blocking task ends, but the "owner" semantics are unclear. |
| 3 | `graceful.rs:169,180` | `File::from_raw_fd(fd)` + `mem::forget(f)` | Idiom for "hand the fd back to the caller". Correct, but `mem::forget` bypasses RAII — if the fd is later not closed, it leaks. |
| 5 | `af_xdp.rs` | `unsafe impl Send/Sync for Umem` | **RESOLVED (P0):** `Send` is justified (the struct exclusively owns the mmap region). `Sync` now has a strict SAFETY invariant (a frame is accessed only after dequeue from the RX ring and before refill, without aliasing — the AF_XDP frame ownership protocol). In addition, `Umem` is owned by value by a single socket and is not shared as `&Umem` between threads, so `Sync` could be removed altogether if desired. USF-008 (overflow in `Umem::new`) was also fixed. |
| 6 | `worker.rs:329-335` | `pin_to_core` via `sched_setaffinity` | Standard pattern, but `CPU_SET` is a libc macro; the Rust wrapper writes via `set_bit`. If the cpuset is not large enough (the machine has more CPUs than the size of `cpu_set_t`) — silent truncation. On modern Linux that is >1024 CPUs, unlikely. |
| 7 | `hugepages.rs:71-72` | `unsafe impl Send/Sync for HugePagePool` | If the ABA problem (see SUSPECT #1) is real, the lock-free property does not hold — the Sync impl becomes false. |

---

## SAFETY — justified blocks (aggregated)

Not listed one by one — there are ~75 of them. All fall into one of these categories:

1. **libc syscalls** (≈40): `mmap`, `munmap`, `close`, `setsockopt`, `if_nametoindex`, `sched_setaffinity`, `epoll_*`, `pipe2`, `bpf`, `set_mempolicy`, `socket`, `bind`, `poll`, `sendto`. All follow the standard pattern: ptr + len, errno check. The arguments are either stack-local structs or valid slices. SAFETY: `libc syscall with valid local-struct pointer and size; errno checked`.

2. **`mem::zeroed::<libc::*>()`** (≈8): zeroing C structs, equivalent to `MaybeUninit::zeroed().assume_init()`. Correct for `sockaddr_*`, `cmsghdr`, `epoll_event`, `cpu_set_t`, `iovec`, `msghdr` — all are POD structs with a valid all-zero state.

3. **Raw pointer cast `&T as *mut _ as *mut U`** for FFI structs (≈12): casting `&mut sockaddr_storage` to `&mut sockaddr_in` after setting `family`. The layout is the same (sockaddr_storage is designed as a union for all variants). SAFETY: standard sockaddr cast.

4. **`set_len` after `recv_from`** (1, in `server.rs:197`): initializes the BytesMut up to `MAX_UDP_PACKET`, then `recv_from` writes the first `n` bytes, followed by `truncate(n)`. No bytes are read between set_len and recv_from. Standard pattern for recv buffers.

5. **`from_raw_parts` for mmap'd regions** (4): `as_slice` / `as_mut_slice` on `PoolBuffer` use `len`/`capacity`, which is a valid part of the mmap region. (The exception is `PoolBuffer::as_mut_slice`, which hands out `capacity` uninitialized bytes; see SUSPECT #4.)

6. **`Box::from_raw` / `into_raw`** (4): ownership idiom for FFI and lock-free structures. For FFI the contract is documented. For lock-free, see SUSPECT #1 for a known issue.

---

## Per-file inventory

| File | Lines | unsafe blocks | SAFETY | NEEDS-REVIEW | SUSPECT |
|---|---|---|---|---|---|
| transport/hugepages.rs | 421 | 18 | 13 | 1 | **4** |
| transport/af_xdp.rs | 533 | 17 | 14 | 1 | 2 |
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
| **Total** | **5337** | **99** | **~76** | **14** | **9 (fixed)** |

(The distribution is approximate — multi-line blocks sometimes contain several separate unsafe operations; exact numbers are in the code via `// SAFETY/NEEDS-REVIEW/SUSPECT:` comments.)

---

## Recommendations

### Urgent (before production)

1. **Replace the Treiber stack in `HugePagePool`** with `Mutex<Vec<usize>>` (the buffer pool is not on the hot path after warm-up anyway) or `crossbeam_queue::SegQueue`. This closes SUSPECT #1.
2. **Add bounds checks to `Umem::frame_slice*`.** A one-line assert, ~0 cost. Closes SUSPECT #2.
3. **Box-allocate `MsgHdrStorage`** in `uring.rs` (or pin the Vec). Closes SUSPECT #3.
4. **`PoolBuffer::as_mut_slice` → MaybeUninit** or remove it (use only `as_mut_ptr` + an explicit `set_len`). Closes SUSPECT #4.

### Medium-term (within a quarter)

5. Run `cargo geiger` in CI (informational job — included in this archive).
6. Run the parsers under Miri (a separate task — the STUN/TURN parsers have no kernel dependencies and are Miri-compatible).
7. Add integration tests with `RUSTFLAGS=-Z sanitizer=address` (requires nightly).

### Ongoing

8. **All new `unsafe` blocks must have a `// SAFETY: ...` comment.** Enable the clippy lint `clippy::undocumented_unsafe_blocks` (warn level, later deny).
9. Regenerate the inventory via `scripts/unsafe-inventory.sh` after every PR that touches it. In the future — automatically in CI.

---

## What's next

This document is a **starting point**. To move forward:

- Implement **SUSPECT #1-4** as separate PRs. Each is 100-200 lines and easy to review.
- Run a **Miri campaign** for the STUN/TURN parsers in parallel (`cargo +nightly miri test -p turna-proto-stun`).
- **Fuzzing** (a separate TODO from the critical list) is the logical continuation of this audit — fuzz crashes found are most likely to involve these same blocks.

---

## USF-010/011 — `tokio_transport.rs` recvmmsg/sendmmsg FFI (SAFETY_JUSTIFIED)

**File:** `crates/transport/src/tokio_transport.rs` (Linux-only, `cfg(target_os = "linux")`)

6 `unsafe` blocks in the `recv_mmsg`/`send_mmsg` batch I/O paths:

- **USF-010 — `recv_mmsg()`** (4 blocks): `mem::zeroed()` for `sockaddr_storage`/`mmsghdr` (C POD, the all-zero pattern is valid), `libc::recvmmsg`, `socket2::SockAddr::new`. Invariants: `fd` is open for the lifetime of the socket (`Arc<UdpSocket>`); `iovecs`/`addrs` live for the duration of the call and are not reallocated after setup; only entries `[0, r)` are read, where `r` is the result of `recvmmsg`; `msg_namelen <= size_of::<sockaddr_storage>()`. Inline `// SAFETY:` comments are present and correct. No UB/OOB/aliasing found.
- **USF-011 — `send_mmsg()`** (2 blocks): `mem::zeroed()` for `mmsghdr`, `libc::sendmmsg`. Invariants: `fd` is open; the buffers (`bytes::Bytes` from `pkts`, borrowed for the whole function) and `addrs` outlive the call; `sendmmsg` only reads the buffers, so the `*const -> *mut` cast is safe. Inline `// SAFETY:` comments are correct.

Status: **SAFETY_JUSTIFIED**. The file has been added to `AUDITED_PATHS` (`scripts/unsafe-inventory.sh`) and to `docs/security/unsafe-inventory.json`.
