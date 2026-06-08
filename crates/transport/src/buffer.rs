//! Zero-copy buffer management.
//!
//! Two pools for two paths:
//! - `BufferRing`  — for io_uring workers (aligned, kernel-registered)
//! - `BytesPool`   — for tokio path (lock-free BytesMut recycling)

use std::collections::VecDeque;

// ── io_uring path ────────────────────────────────────────────────────────────

/// Maximum UDP packet size.
pub const MAX_UDP_PACKET: usize = 1500;

/// Cache-line aligned buffer for io_uring registered buffers.
/// Alignment prevents false sharing between adjacent buffers.
#[repr(align(64))]
pub struct AlignedBuf {
    data: [u8; MAX_UDP_PACKET],
}

impl AlignedBuf {
    pub fn new() -> Self {
        Self {
            data: [0u8; MAX_UDP_PACKET],
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

impl Default for AlignedBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool of pre-allocated, cache-aligned buffers for io_uring.
///
/// Buffers are registered with the kernel via `io_uring_register_buffers`,
/// enabling true zero-copy recv/send in the io_uring worker path.
pub struct BufferRing {
    buffers: Vec<AlignedBuf>,
    free: VecDeque<u16>,
}

impl BufferRing {
    /// Create a ring with `count` pre-allocated buffers.
    pub fn new(count: u16) -> Self {
        let mut buffers = Vec::with_capacity(count as usize);
        let mut free = VecDeque::with_capacity(count as usize);
        for i in 0..count {
            buffers.push(AlignedBuf::new());
            free.push_back(i);
        }
        tracing::info!(count, buf_size = MAX_UDP_PACKET, "buffer ring created");
        Self { buffers, free }
    }

    /// Acquire a buffer index. Returns `None` if the pool is exhausted.
    pub fn acquire(&mut self) -> Option<u16> {
        self.free.pop_front()
    }

    /// Release a buffer back to the pool.
    pub fn release(&mut self, idx: u16) {
        self.buffers[idx as usize].data[..4].fill(0);
        self.free.push_back(idx);
    }

    pub fn get(&self, idx: u16) -> &AlignedBuf {
        &self.buffers[idx as usize]
    }
    pub fn get_mut(&mut self, idx: u16) -> &mut AlignedBuf {
        &mut self.buffers[idx as usize]
    }

    pub fn registration_info(&self) -> (&[AlignedBuf], usize) {
        (&self.buffers, MAX_UDP_PACKET)
    }

    pub fn available(&self) -> usize {
        self.free.len()
    }
    pub fn capacity(&self) -> usize {
        self.buffers.len()
    }

    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    pub fn as_iovecs(&self) -> Vec<libc::iovec> {
        self.buffers
            .iter()
            .map(|buf| libc::iovec {
                iov_base: buf.data.as_ptr() as *mut _,
                iov_len: MAX_UDP_PACKET,
            })
            .collect()
    }
}

// ── tokio path ───────────────────────────────────────────────────────────────

use bytes::BytesMut;
use std::sync::{Arc, Mutex};

/// Lock-free-ish pool of `BytesMut` buffers for the tokio recv path.
///
/// # Why this matters
/// Without a pool, every UDP packet triggers a heap allocation for its buffer.
/// At 200k pps that is 200 000 allocations/second hitting the global allocator.
/// With a pool: acquire = pop from a Vec (O(1), no alloc), release = push back.
///
/// The `Mutex` here is std (not tokio) and is held for only a single
/// `Vec::pop` / `Vec::push` — contention is negligible compared to I/O.
/// If profiling shows lock contention, replace the inner `Mutex<Vec<...>>`
/// with `crossbeam::queue::ArrayQueue`.
///
/// # Usage pattern
/// ```ignore
/// let pool = BytesPool::new(4096, MAX_UDP_PACKET);
///
/// // recv side
/// let mut buf = pool.acquire();
/// // Safety: recv_from will fill exactly `n` bytes
/// unsafe { buf.set_len(MAX_UDP_PACKET); }
/// let (n, src) = socket.recv_from(&mut buf).await?;
/// buf.truncate(n);
/// let data: Bytes = buf.freeze();  // BytesMut → Bytes, zero-copy from here
///
/// // downstream: cheap clone = AtomicAdd, no memcpy
/// subscriber_a.send(data.clone());
/// subscriber_b.send(data.clone());
/// // data drops → memory returns to OS (pool does not reclaim frozen Bytes)
/// ```
///
/// When you need to reclaim the buffer *before* freezing (e.g. the packet
/// was dropped during rate-limiting), call `pool.release(buf)` instead.
#[derive(Clone)]
pub struct BytesPool {
    inner: Arc<Mutex<Vec<BytesMut>>>,
    buf_size: usize,
}

impl BytesPool {
    /// Create a pool pre-populated with `capacity` buffers.
    ///
    /// Recommended defaults:
    /// - `capacity`: 4 × (number of tokio worker threads). 4096 is safe for
    ///   most deployments; excess buffers are just heap allocations that sit
    ///   unused.
    /// - `buf_size`: `MAX_UDP_PACKET` (1500) for standard MTU.
    pub fn new(capacity: usize, buf_size: usize) -> Self {
        let bufs = (0..capacity)
            .map(|_| BytesMut::with_capacity(buf_size))
            .collect();
        tracing::info!(capacity, buf_size, "bytes pool created");
        Self {
            inner: Arc::new(Mutex::new(bufs)),
            buf_size,
        }
    }

    /// Acquire a buffer. Returns a pooled buffer if available, or allocates
    /// a fresh one. Never blocks.
    pub fn acquire(&self) -> BytesMut {
        let mut pool = self.inner.lock().unwrap();
        pool.pop().unwrap_or_else(|| {
            tracing::debug!(
                buf_size = self.buf_size,
                "bytes pool miss — allocating fresh buffer"
            );
            BytesMut::with_capacity(self.buf_size)
        })
    }

    /// Return a buffer to the pool. Call this when the buffer will NOT be
    /// frozen (e.g. packet was dropped). Do NOT call after `buf.freeze()`.
    pub fn release(&self, mut buf: BytesMut) {
        buf.clear();
        let mut pool = self.inner.lock().unwrap();
        // Cap pool size to avoid unbounded growth after traffic spikes.
        if pool.len() < 8192 {
            pool.push(buf);
        }
    }

    /// Current number of idle buffers in the pool.
    pub fn idle(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_ring_acquire_release() {
        let mut ring = BufferRing::new(4);
        assert_eq!(ring.available(), 4);
        let idx = ring.acquire().unwrap();
        assert_eq!(ring.available(), 3);
        ring.release(idx);
        assert_eq!(ring.available(), 4);
    }

    #[test]
    fn buffer_ring_exhaustion() {
        let mut ring = BufferRing::new(2);
        let a = ring.acquire().unwrap();
        let b = ring.acquire().unwrap();
        assert!(ring.acquire().is_none());
        ring.release(a);
        ring.release(b);
        assert_eq!(ring.available(), 2);
    }

    #[test]
    fn bytes_pool_acquire_release() {
        let pool = BytesPool::new(8, MAX_UDP_PACKET);
        assert_eq!(pool.idle(), 8);
        let buf = pool.acquire();
        assert_eq!(pool.idle(), 7);
        pool.release(buf);
        assert_eq!(pool.idle(), 8);
    }

    #[test]
    fn bytes_pool_miss_allocates() {
        let pool = BytesPool::new(0, MAX_UDP_PACKET);
        let buf = pool.acquire(); // no buffers pre-allocated → fresh alloc
        assert_eq!(buf.capacity(), MAX_UDP_PACKET);
    }

    #[test]
    fn bytes_freeze_is_zero_copy() {
        use bytes::Bytes;
        let pool = BytesPool::new(4, MAX_UDP_PACKET);
        let mut buf = pool.acquire();
        buf.extend_from_slice(b"hello world");
        let frozen: Bytes = buf.freeze();
        // Clone is AtomicAdd — no memcpy
        let clone_a = frozen.clone();
        let clone_b = frozen.clone();
        assert_eq!(&clone_a[..], b"hello world");
        assert_eq!(&clone_b[..], b"hello world");
        // Both point at the same memory
        assert_eq!(clone_a.as_ptr(), clone_b.as_ptr());
    }
}
