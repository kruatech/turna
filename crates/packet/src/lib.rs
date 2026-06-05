//! Packet buffer management — pools, zero-copy, reuse

use bytes::BytesMut;
use std::collections::VecDeque;

pub const MAX_PACKET_SIZE: usize = 1500;

/// Pre-allocated buffer pool to avoid runtime allocations on hot path.
pub struct BufferPool {
    pool: VecDeque<BytesMut>,
    buf_capacity: usize,
}

impl BufferPool {
    pub fn new(count: usize, buf_capacity: usize) -> Self {
        let mut pool = VecDeque::with_capacity(count);
        for _ in 0..count {
            pool.push_back(BytesMut::with_capacity(buf_capacity));
        }
        Self { pool, buf_capacity }
    }

    pub fn default_pool() -> Self {
        Self::new(1024, MAX_PACKET_SIZE)
    }

    /// Get a buffer from pool, or allocate new one if empty.
    pub fn get(&mut self) -> BytesMut {
        self.pool.pop_front().unwrap_or_else(|| BytesMut::with_capacity(self.buf_capacity))
    }

    /// Return a buffer to the pool for reuse.
    pub fn put(&mut self, mut buf: BytesMut) {
        buf.clear();
        if buf.capacity() >= self.buf_capacity {
            self.pool.push_back(buf);
        }
        // Drop oversized buffers
    }

    pub fn available(&self) -> usize {
        self.pool.len()
    }
}

/// A received packet with source address.
#[derive(Debug)]
pub struct Packet {
    pub data: BytesMut,
    pub len: usize,
    pub source: std::net::SocketAddr,
}

impl Packet {
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Encode helper: write data into a BytesMut and return it.
pub fn encode_to_buf(pool: &mut BufferPool, f: impl FnOnce(&mut [u8]) -> usize) -> BytesMut {
    let mut buf = pool.get();
    buf.resize(MAX_PACKET_SIZE, 0);
    let len = f(&mut buf);
    buf.truncate(len);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let mut pool = BufferPool::new(4, 1500);
        assert_eq!(pool.available(), 4);

        let buf = pool.get();
        assert_eq!(pool.available(), 3);

        pool.put(buf);
        assert_eq!(pool.available(), 4);
    }
}