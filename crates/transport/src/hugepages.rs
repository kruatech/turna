//! Huge Pages — буферный пул на huge pages для снижения TLB-промахов
//!
//! На Linux: mmap(MAP_HUGETLB) с fallback на обычные страницы.
//! На macOS/других: только обычные страницы (mmap без MAP_HUGETLB).
//!
//! # Изменения от оригинала (unsafe-audit PR1)
//!
//! 1. **ABA race устранена**: Treiber lock-free stack заменён на
//!    `Mutex<Vec<usize>>`. Pool не на горячем recv-пути (инициализируется
//!    один раз при старте), поэтому потеря throughput от мьютекса нулевая.
//!    Removed: `FreeNode`, `AtomicPtr`, CAS-цикл в alloc/free.
//!
//! 2. **MaybeUninit**: `as_mut_slice` теперь возвращает только
//!    инициализированные байты (до `self.len`). Для записи в сырой буфер
//!    используй `uninit_buf_mut() -> &mut [MaybeUninit<u8>]`.
//!
//! 3. **Drop guard**: `HugePagePool::drop` паникует если есть активные
//!    буферы — вместо тихого dangling pointer + munmap.

use std::io;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HugePagesConfig {
    /// Размер одного слота (байты). Default: 2048.
    pub slot_size: usize,
    /// Количество слотов. Default: 65536 (128 MiB при 2 KiB).
    pub slot_count: usize,
    /// Использовать huge pages на Linux (2 MiB).
    pub try_huge_pages: bool,
    /// Fallback на обычные страницы если huge pages недоступны.
    pub fallback_to_regular: bool,
    /// Prefault: touch all pages при создании.
    pub prefault: bool,
}

impl Default for HugePagesConfig {
    fn default() -> Self {
        Self {
            slot_size: 2048,
            slot_count: 65536,
            try_huge_pages: true,
            fallback_to_regular: true,
            prefault: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

pub struct HugePagePool {
    base: NonNull<u8>,
    total_size: usize,
    slot_size: usize,
    slot_count: usize,
    uses_huge_pages: bool,
    /// FIX (SUSPECT #1): was AtomicPtr<FreeNode> + Treiber CAS stack.
    /// Replaced with Mutex<Vec<usize>> — slot indices of free buffers.
    /// No ABA possible: pop/push on Vec under Mutex is trivially correct.
    free_slots: Mutex<Vec<usize>>,
    allocated: AtomicUsize,
    _dropped: AtomicBool,
    stats: PoolStats,
}

pub struct PoolStats {
    pub total_allocs: AtomicU64,
    pub total_frees: AtomicU64,
    pub failed_allocs: AtomicU64,
}

// SAFETY: HugePagePool is Send + Sync because:
// - `base` (NonNull<u8> into mmap region) is only accessed via alloc/free
//   which are now serialised by `free_slots: Mutex<Vec<usize>>`.
// - PoolBuffer carries disjoint slot offsets — no two PoolBuffers alias.
// - `allocated` / `stats` are AtomicU*/AtomicBool (inherently Sync).
// ABA concern that invalidated this claim previously has been removed.
unsafe impl Send for HugePagePool {}
unsafe impl Sync for HugePagePool {}

impl HugePagePool {
    pub fn new(config: HugePagesConfig) -> io::Result<Self> {
        let total_size = config.slot_size * config.slot_count;
        let aligned_size = (total_size + (2 * 1024 * 1024 - 1)) & !(2 * 1024 * 1024 - 1);

        let (base, uses_huge) = alloc_memory(aligned_size, &config)?;

        // Pre-populate free slot list: indices 0..slot_count
        let free_slots: Vec<usize> = (0..config.slot_count).collect();

        let pool = Self {
            base,
            total_size: aligned_size,
            slot_size: config.slot_size,
            slot_count: config.slot_count,
            uses_huge_pages: uses_huge,
            free_slots: Mutex::new(free_slots),
            allocated: AtomicUsize::new(0),
            _dropped: AtomicBool::new(false),
            stats: PoolStats {
                total_allocs: AtomicU64::new(0),
                total_frees: AtomicU64::new(0),
                failed_allocs: AtomicU64::new(0),
            },
        };

        if config.prefault {
            pool.prefault_pages();
        }

        info!(
            slots = config.slot_count,
            slot_size = config.slot_size,
            total_mib = aligned_size / (1024 * 1024),
            huge_pages = uses_huge,
            "buffer pool initialized"
        );

        Ok(pool)
    }

    /// Alloc a slot. Returns None if exhausted. O(1) amortised.
    ///
    /// Previously lock-free via Treiber stack — replaced with Mutex because
    /// the pool is not on the hot recv path (warm-up only) and Mutex is
    /// trivially correct under concurrent access.
    pub fn alloc(&self) -> Option<PoolBuffer> {
        let slot_index = self.free_slots.lock().unwrap().pop()?;

        self.allocated.fetch_add(1, Ordering::Relaxed);
        self.stats.total_allocs.fetch_add(1, Ordering::Relaxed);

        let offset = slot_index * self.slot_size;
        // SAFETY: slot_index < slot_count (invariant maintained by Mutex<Vec>),
        // so offset + slot_size <= total_size <= mmap region.
        let ptr = unsafe { self.base.as_ptr().add(offset) };
        Some(PoolBuffer {
            ptr: NonNull::new(ptr).unwrap(),
            len: 0,
            capacity: self.slot_size,
            slot_index,
        })
    }

    /// Return a slot to the pool. O(1) amortised.
    pub fn free(&self, buf: PoolBuffer) {
        let slot_index = buf.slot_index;
        // Forget buf so its (trivial) Drop doesn't run — the slot is returned
        // to the pool, not freed.
        std::mem::forget(buf);
        self.free_slots.lock().unwrap().push(slot_index);
        self.allocated.fetch_sub(1, Ordering::Relaxed);
        self.stats.total_frees.fetch_add(1, Ordering::Relaxed);
    }

    fn prefault_pages(&self) {
        let ptr = self.base.as_ptr();
        for i in (0..self.total_size).step_by(4096) {
            unsafe { std::ptr::write_volatile(ptr.add(i), 0u8) };
        }
        debug!(pages = self.total_size / 4096, "prefaulted pages");
    }

    pub fn capacity(&self) -> usize {
        self.slot_count
    }
    pub fn allocated_count(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }
    pub fn free_count(&self) -> usize {
        self.slot_count - self.allocated_count()
    }
    pub fn uses_huge_pages(&self) -> bool {
        self.uses_huge_pages
    }
    pub fn total_allocs(&self) -> u64 {
        self.stats.total_allocs.load(Ordering::Relaxed)
    }
    pub fn failed_allocs(&self) -> u64 {
        self.stats.failed_allocs.load(Ordering::Relaxed)
    }
}

impl Drop for HugePagePool {
    fn drop(&mut self) {
        // FIX (SUSPECT #7): assert no active PoolBuffers before munmap.
        // If any PoolBuffer is still alive its ptr points into the region
        // we are about to unmap → dangling pointer → UB on next access.
        // Panic is intentional: this is a programmer error, not a runtime
        // condition. In prod the pool must outlive all its buffers (typically
        // achieved by keeping HugePagePool in an Arc shared with PoolBuffer).
        let active = self.allocated.load(Ordering::Relaxed);
        assert_eq!(
            active, 0,
            "BUG: HugePagePool dropped with {active} active PoolBuffer(s) — \
             those pointers are now dangling. Ensure all PoolBuffers are \
             freed before dropping the pool (wrap in Arc if lifetimes are complex)."
        );

        // munmap — safe because no active buffers (asserted above).
        free_memory(self.base, self.total_size);
    }
}

// ---------------------------------------------------------------------------
// Pool Buffer
// ---------------------------------------------------------------------------

pub struct PoolBuffer {
    ptr: NonNull<u8>,
    len: usize,
    capacity: usize,
    slot_index: usize,
}

impl PoolBuffer {
    /// Write `data` into the buffer. Returns bytes written.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.capacity);
        // SAFETY: ptr is valid for `capacity` bytes (slot in mmap region).
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr(), n) };
        self.len = n;
        n
    }

    /// View the already-written bytes. Safe: only accesses [0, len).
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: len ≤ capacity ≤ slot_size ≤ mmap region.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Mutable view of the already-written bytes. Safe: only accesses [0, len).
    ///
    /// FIX (SUSPECT #4): was returning `capacity` bytes including uninitialised
    /// memory, which is UB to read. Now returns only the written portion.
    /// Use `uninit_buf_mut()` to obtain a writable slice for kernel I/O.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: len ≤ capacity; bytes [0, len) were written by `write()`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Full-capacity buffer as `MaybeUninit<u8>` for kernel writes (recvfrom,
    /// io_uring RecvMsg, etc.).
    ///
    /// # Safety contract
    /// The caller MUST write all bytes it later reads. After writing `n` bytes,
    /// call `set_len(n)` and then read via `as_slice()`.
    pub fn uninit_buf_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        // SAFETY: ptr is valid for `capacity` bytes. MaybeUninit<u8> has the
        // same layout as u8 and validity only requires the allocation be live.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut MaybeUninit<u8>, self.capacity)
        }
    }

    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.capacity,
            "set_len({len}) > capacity({})",
            self.capacity
        );
        self.len = len;
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

// SAFETY: PoolBuffer owns a disjoint slot in the mmap region — no aliasing.
unsafe impl Send for PoolBuffer {}

// ---------------------------------------------------------------------------
// Platform: memory allocation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn alloc_memory(size: usize, config: &HugePagesConfig) -> io::Result<(NonNull<u8>, bool)> {
    if config.try_huge_pages {
        let huge_flags = libc::MAP_PRIVATE
            | libc::MAP_ANONYMOUS
            | libc::MAP_HUGETLB
            | (21 << libc::MAP_HUGE_SHIFT);

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                huge_flags,
                -1,
                0,
            )
        };

        if ptr != libc::MAP_FAILED {
            info!(size_mib = size / (1024 * 1024), "huge pages mmap OK");
            return Ok((NonNull::new(ptr as *mut u8).unwrap(), true));
        }

        tracing::warn!(
            error = %io::Error::last_os_error(),
            "huge pages unavailable, falling back"
        );

        if !config.fallback_to_regular {
            return Err(io::Error::last_os_error());
        }
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    info!(size_mib = size / (1024 * 1024), "regular mmap");
    Ok((NonNull::new(ptr as *mut u8).unwrap(), false))
}

#[cfg(not(target_os = "linux"))]
fn alloc_memory(size: usize, _config: &HugePagesConfig) -> io::Result<(NonNull<u8>, bool)> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    info!(
        size_mib = size / (1024 * 1024),
        "mmap (no huge pages on this platform)"
    );
    Ok((NonNull::new(ptr as *mut u8).unwrap(), false))
}

fn free_memory(base: NonNull<u8>, size: usize) {
    unsafe { libc::munmap(base.as_ptr() as *mut libc::c_void, size) };
}

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HugePagesInfo {
    pub available: bool,
    pub total_pages: u64,
    pub free_pages: u64,
    pub page_size_kb: u64,
}

#[cfg(target_os = "linux")]
pub fn check_hugepages_available() -> HugePagesInfo {
    let read_val = |path: &str| -> u64 {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    let total = read_val("/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages");
    let free = read_val("/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages");
    HugePagesInfo {
        available: free > 0,
        total_pages: total,
        free_pages: free,
        page_size_kb: 2048,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn check_hugepages_available() -> HugePagesInfo {
    HugePagesInfo {
        available: false,
        total_pages: 0,
        free_pages: 0,
        page_size_kb: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn small_pool() -> HugePagePool {
        HugePagePool::new(HugePagesConfig {
            slot_count: 16,
            slot_size: 256,
            try_huge_pages: false,
            fallback_to_regular: true,
            prefault: false,
        })
        .unwrap()
    }

    #[test]
    fn alloc_free() {
        let pool = small_pool();
        assert_eq!(pool.capacity(), 16);
        assert_eq!(pool.free_count(), 16);

        let mut buf = pool.alloc().unwrap();
        assert_eq!(pool.allocated_count(), 1);
        assert_eq!(buf.capacity(), 256);

        buf.write(b"hello");
        assert_eq!(buf.as_slice(), b"hello");

        pool.free(buf);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn exhaust_and_recover() {
        let pool = HugePagePool::new(HugePagesConfig {
            slot_count: 4,
            slot_size: 64,
            try_huge_pages: false,
            fallback_to_regular: true,
            prefault: false,
        })
        .unwrap();

        let mut bufs: Vec<_> = (0..4).map(|_| pool.alloc().unwrap()).collect();
        assert!(pool.alloc().is_none());

        pool.free(bufs.pop().unwrap());
        let recovered = pool.alloc();
        assert!(recovered.is_some());

        // Free everything so the pool's Drop invariant (active == 0) holds.
        pool.free(recovered.unwrap());
        for b in bufs {
            pool.free(b);
        }
    }

    #[test]
    fn buffer_read_write() {
        let pool = small_pool();
        let mut buf = pool.alloc().unwrap();
        let data = b"STUN packet data here";
        buf.write(data);
        assert_eq!(buf.len(), data.len());
        assert_eq!(buf.as_slice(), data);
        assert!(!buf.is_empty());
        pool.free(buf);
    }

    #[test]
    fn as_mut_slice_only_len_bytes() {
        let pool = small_pool();
        let mut buf = pool.alloc().unwrap();
        buf.write(b"abc");
        // as_mut_slice must return only 3 bytes, not capacity
        assert_eq!(buf.as_mut_slice().len(), 3);
        pool.free(buf);
    }

    #[test]
    fn uninit_buf_mut_is_capacity() {
        let pool = small_pool();
        let mut buf = pool.alloc().unwrap();
        // uninit_buf_mut gives the full slot for writing
        assert_eq!(buf.uninit_buf_mut().len(), 256);
        // write via uninit, then set_len
        let uninit = buf.uninit_buf_mut();
        uninit[0] = MaybeUninit::new(b'X');
        buf.set_len(1);
        assert_eq!(buf.as_slice(), b"X");
        pool.free(buf);
    }

    #[test]
    fn drop_with_zero_active_does_not_panic() {
        let pool = small_pool();
        let buf = pool.alloc().unwrap();
        pool.free(buf);
        // Drop pool with zero active — should not panic
        drop(pool);
    }

    #[test]
    #[should_panic(expected = "BUG: HugePagePool dropped with 1 active")]
    fn drop_with_active_panics() {
        let pool = small_pool();
        let _buf = pool.alloc().unwrap(); // not freed
                                          // drop(pool) while buf is still alive — must panic
    }

    #[test]
    fn hugepages_info_no_panic() {
        let info = check_hugepages_available();
        let _ = info.available;
    }
}
