//! Backpressure + Priority Queues
//!
//! Проблема: медленный клиент → буферы растут → OOM или latency spike.
//!
//! Решение:
//! - 3 приоритета: Audio (высший) > Control (STUN) > Data (видео/прочее)
//! - Per-allocation очередь с ограничением
//! - Drop policy: при переполнении дропаем low-priority первым
//! - Метрики: dropped packets по приоритетам

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::{debug, trace, warn};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BackpressureConfig {
    /// Макс. пакетов в очереди Audio.
    pub audio_queue_limit: usize,
    /// Макс. пакетов в очереди Control (STUN/TURN).
    pub control_queue_limit: usize,
    /// Макс. пакетов в очереди Data (видео и прочее).
    pub data_queue_limit: usize,
    /// Макс. возраст пакета (старше — дропаем).
    pub max_packet_age: Duration,
    /// При какой заполненности data-очереди начинать дроп (0.0-1.0).
    pub data_drop_threshold: f64,
    /// Интервал cleanup старых пакетов.
    pub cleanup_interval: Duration,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            audio_queue_limit: 500,
            control_queue_limit: 100,
            data_queue_limit: 200,
            max_packet_age: Duration::from_millis(500),
            data_drop_threshold: 0.8,
            cleanup_interval: Duration::from_millis(50),
        }
    }
}

// ---------------------------------------------------------------------------
// Packet Priority
// ---------------------------------------------------------------------------

/// Приоритет пакета. Определяется по содержимому.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Audio RTP (PT 111 Opus, etc.) — никогда не дропается до переполнения.
    Audio = 2,
    /// STUN/TURN control messages — важны, но допускают задержку.
    Control = 1,
    /// Video RTP, DataChannel, прочее — дропается первым.
    Data = 0,
}

impl Priority {
    /// Определяет приоритет по payload.
    /// Вызывается на hot path — должен быть быстрым.
    pub fn classify(data: &[u8]) -> Self {
        if data.len() < 2 {
            return Self::Data;
        }

        let first_two = u16::from_be_bytes([data[0], data[1]]);

        // ChannelData (0x4000-0x7FFF) → нужно смотреть RTP внутри
        if first_two >= 0x4000 && first_two <= 0x7FFF {
            // ChannelData header = 4 bytes, потом RTP
            if data.len() >= 16 {
                return classify_rtp(&data[4..]);
            }
            return Self::Data;
        }

        // STUN (first 2 bits = 00, magic cookie at [4..8])
        if data[0] & 0xC0 == 0x00 && data.len() >= 8 {
            let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            if cookie == 0x2112A442 {
                return Self::Control;
            }
        }

        // Raw RTP (version = 2, first 2 bits = 10)
        if data[0] & 0xC0 == 0x80 {
            return classify_rtp(data);
        }

        Self::Data
    }
}

/// Классифицирует RTP-пакет как Audio или Data по payload type.
fn classify_rtp(data: &[u8]) -> Priority {
    if data.len() < 2 {
        return Priority::Data;
    }
    // Payload type = bits 1-7 of second byte
    let pt = data[1] & 0x7F;

    // Common audio payload types:
    // 0 = PCMU, 8 = PCMA, 9 = G722, 111 = Opus (dynamic, most common)
    // 96-127 = dynamic, but Opus is almost always 111
    match pt {
        0 | 8 | 9 => Priority::Audio,                // Static audio PTs
        111 => Priority::Audio,                        // Opus (conventional)
        96..=110 | 112..=127 => Priority::Data,       // Likely video (VP8/VP9/H264)
        _ => Priority::Data,
    }
}

// ---------------------------------------------------------------------------
// Queued Packet
// ---------------------------------------------------------------------------

struct QueuedPacket {
    data: Vec<u8>,
    enqueued_at: Instant,
}

// ---------------------------------------------------------------------------
// Priority Queue per allocation
// ---------------------------------------------------------------------------

/// Per-allocation priority queue с backpressure.
pub struct PriorityQueue {
    audio: VecDeque<QueuedPacket>,
    control: VecDeque<QueuedPacket>,
    data: VecDeque<QueuedPacket>,
    config: BackpressureConfig,
    stats: QueueStats,
    last_cleanup: Instant,
}

pub struct QueueStats {
    pub audio_enqueued: AtomicU64,
    pub control_enqueued: AtomicU64,
    pub data_enqueued: AtomicU64,
    pub audio_dropped: AtomicU64,
    pub control_dropped: AtomicU64,
    pub data_dropped: AtomicU64,
    pub expired_dropped: AtomicU64,
}

impl QueueStats {
    fn new() -> Self {
        Self {
            audio_enqueued: AtomicU64::new(0),
            control_enqueued: AtomicU64::new(0),
            data_enqueued: AtomicU64::new(0),
            audio_dropped: AtomicU64::new(0),
            control_dropped: AtomicU64::new(0),
            data_dropped: AtomicU64::new(0),
            expired_dropped: AtomicU64::new(0),
        }
    }
}

/// Результат enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueResult {
    /// Пакет добавлен.
    Accepted,
    /// Пакет дропнут — очередь полная.
    DroppedQueueFull,
    /// Пакет дропнут — backpressure на data при перегрузке.
    DroppedBackpressure,
}

impl PriorityQueue {
    pub fn new(config: BackpressureConfig) -> Self {
        Self {
            audio: VecDeque::with_capacity(config.audio_queue_limit),
            control: VecDeque::with_capacity(config.control_queue_limit),
            data: VecDeque::with_capacity(config.data_queue_limit),
            config,
            stats: QueueStats::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Добавляет пакет. Классифицирует приоритет автоматически.
    pub fn enqueue(&mut self, data: Vec<u8>) -> EnqueueResult {
        let priority = Priority::classify(&data);
        self.enqueue_with_priority(data, priority)
    }

    /// Добавляет пакет с заданным приоритетом.
    pub fn enqueue_with_priority(&mut self, data: Vec<u8>, priority: Priority) -> EnqueueResult {
        // Периодический cleanup
        if self.last_cleanup.elapsed() >= self.config.cleanup_interval {
            self.cleanup_expired();
            self.last_cleanup = Instant::now();
        }

        let pkt = QueuedPacket {
            data,
            enqueued_at: Instant::now(),
        };

        match priority {
            Priority::Audio => {
                if self.audio.len() >= self.config.audio_queue_limit {
                    // Audio full: дропаем старейший audio пакет, принимаем новый
                    self.audio.pop_front();
                    self.stats.audio_dropped.fetch_add(1, Ordering::Relaxed);
                }
                self.audio.push_back(pkt);
                self.stats.audio_enqueued.fetch_add(1, Ordering::Relaxed);
                EnqueueResult::Accepted
            }
            Priority::Control => {
                if self.control.len() >= self.config.control_queue_limit {
                    self.stats.control_dropped.fetch_add(1, Ordering::Relaxed);
                    return EnqueueResult::DroppedQueueFull;
                }
                self.control.push_back(pkt);
                self.stats.control_enqueued.fetch_add(1, Ordering::Relaxed);
                EnqueueResult::Accepted
            }
            Priority::Data => {
                // Backpressure: если data-очередь заполнена > threshold, дропаем
                let fill_ratio = self.data.len() as f64 / self.config.data_queue_limit as f64;
                if fill_ratio >= self.config.data_drop_threshold {
                    self.stats.data_dropped.fetch_add(1, Ordering::Relaxed);
                    return EnqueueResult::DroppedBackpressure;
                }
                if self.data.len() >= self.config.data_queue_limit {
                    self.stats.data_dropped.fetch_add(1, Ordering::Relaxed);
                    return EnqueueResult::DroppedQueueFull;
                }
                self.data.push_back(pkt);
                self.stats.data_enqueued.fetch_add(1, Ordering::Relaxed);
                EnqueueResult::Accepted
            }
        }
    }

    /// Извлекает следующий пакет для отправки (приоритет: Audio → Control → Data).
    pub fn dequeue(&mut self) -> Option<Vec<u8>> {
        // Audio first
        if let Some(pkt) = self.audio.pop_front() {
            if pkt.enqueued_at.elapsed() <= self.config.max_packet_age {
                return Some(pkt.data);
            }
            self.stats.expired_dropped.fetch_add(1, Ordering::Relaxed);
        }
        // Then control
        if let Some(pkt) = self.control.pop_front() {
            if pkt.enqueued_at.elapsed() <= self.config.max_packet_age {
                return Some(pkt.data);
            }
            self.stats.expired_dropped.fetch_add(1, Ordering::Relaxed);
        }
        // Then data
        if let Some(pkt) = self.data.pop_front() {
            if pkt.enqueued_at.elapsed() <= self.config.max_packet_age {
                return Some(pkt.data);
            }
            self.stats.expired_dropped.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    /// Извлекает batch пакетов (для sendmmsg).
    pub fn dequeue_batch(&mut self, max: usize) -> Vec<Vec<u8>> {
        let mut batch = Vec::with_capacity(max);
        for _ in 0..max {
            match self.dequeue() {
                Some(data) => batch.push(data),
                None => break,
            }
        }
        batch
    }

    /// Удаляет просроченные пакеты из всех очередей.
    fn cleanup_expired(&mut self) {
        let max_age = self.config.max_packet_age;
        let mut expired = 0u64;

        for queue in [&mut self.audio, &mut self.control, &mut self.data] {
            let before = queue.len();
            queue.retain(|pkt| pkt.enqueued_at.elapsed() <= max_age);
            expired += (before - queue.len()) as u64;
        }

        if expired > 0 {
            self.stats.expired_dropped.fetch_add(expired, Ordering::Relaxed);
            trace!(expired, "cleaned up expired packets");
        }
    }

    /// Общий размер всех очередей.
    pub fn total_queued(&self) -> usize {
        self.audio.len() + self.control.len() + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.audio.is_empty() && self.control.is_empty() && self.data.is_empty()
    }

    /// Snapshot метрик.
    pub fn metrics(&self) -> QueueMetrics {
        QueueMetrics {
            audio_queued: self.audio.len(),
            control_queued: self.control.len(),
            data_queued: self.data.len(),
            audio_dropped: self.stats.audio_dropped.load(Ordering::Relaxed),
            control_dropped: self.stats.control_dropped.load(Ordering::Relaxed),
            data_dropped: self.stats.data_dropped.load(Ordering::Relaxed),
            expired_dropped: self.stats.expired_dropped.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueueMetrics {
    pub audio_queued: usize,
    pub control_queued: usize,
    pub data_queued: usize,
    pub audio_dropped: u64,
    pub control_dropped: u64,
    pub data_dropped: u64,
    pub expired_dropped: u64,
}

impl QueueMetrics {
    pub fn total_dropped(&self) -> u64 {
        self.audio_dropped + self.control_dropped + self.data_dropped + self.expired_dropped
    }
}

// ---------------------------------------------------------------------------
// Congestion Detector
// ---------------------------------------------------------------------------

/// Детектор перегрузки на основе роста очереди.
pub struct CongestionDetector {
    /// Скользящее среднее размера очереди.
    avg_queue_size: f64,
    /// Порог: если avg > threshold → congestion.
    threshold: f64,
    /// Smoothing factor (EWMA alpha).
    alpha: f64,
    /// Текущее состояние.
    congested: bool,
}

impl CongestionDetector {
    pub fn new(threshold: f64) -> Self {
        Self {
            avg_queue_size: 0.0,
            threshold,
            alpha: 0.1,
            congested: false,
        }
    }

    /// Обновляет состояние. Вызывать периодически.
    pub fn update(&mut self, current_queue_size: usize) -> bool {
        self.avg_queue_size =
            self.alpha * current_queue_size as f64 + (1.0 - self.alpha) * self.avg_queue_size;

        let was = self.congested;
        self.congested = self.avg_queue_size > self.threshold;

        if self.congested != was {
            if self.congested {
                warn!(avg = self.avg_queue_size, threshold = self.threshold, "congestion detected");
            } else {
                debug!(avg = self.avg_queue_size, "congestion cleared");
            }
        }

        self.congested
    }

    pub fn is_congested(&self) -> bool {
        self.congested
    }

    pub fn avg_queue_size(&self) -> f64 {
        self.avg_queue_size
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stun_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x00; p[1] = 0x01; // Binding Request
        p[4] = 0x21; p[5] = 0x12; p[6] = 0xA4; p[7] = 0x42; // magic
        p
    }

    fn make_audio_rtp() -> Vec<u8> {
        let mut p = vec![0u8; 172]; // typical Opus packet
        p[0] = 0x80; // V=2
        p[1] = 111;  // PT=111 (Opus)
        p
    }

    fn make_video_rtp() -> Vec<u8> {
        let mut p = vec![0u8; 1200];
        p[0] = 0x80; // V=2
        p[1] = 96;   // PT=96 (VP8)
        p
    }

    fn make_channel_data_audio() -> Vec<u8> {
        let mut p = vec![0u8; 176];
        p[0] = 0x40; p[1] = 0x01; // Channel 0x4001
        p[2] = 0x00; p[3] = 0xAC; // Length 172
        p[4] = 0x80; // RTP V=2
        p[5] = 111;  // PT=111 Opus
        p
    }

    #[test]
    fn classify_stun() {
        assert_eq!(Priority::classify(&make_stun_packet()), Priority::Control);
    }

    #[test]
    fn classify_audio() {
        assert_eq!(Priority::classify(&make_audio_rtp()), Priority::Audio);
    }

    #[test]
    fn classify_video() {
        assert_eq!(Priority::classify(&make_video_rtp()), Priority::Data);
    }

    #[test]
    fn classify_channel_data_audio() {
        assert_eq!(Priority::classify(&make_channel_data_audio()), Priority::Audio);
    }

    #[test]
    fn enqueue_dequeue_priority() {
        let mut q = PriorityQueue::new(BackpressureConfig::default());

        q.enqueue(make_video_rtp());   // Data
        q.enqueue(make_stun_packet()); // Control
        q.enqueue(make_audio_rtp());   // Audio

        // Dequeue order: Audio → Control → Data
        let p1 = q.dequeue().unwrap();
        assert_eq!(p1[1] & 0x7F, 111); // Opus audio

        let p2 = q.dequeue().unwrap();
        assert_eq!(p2[0] & 0xC0, 0x00); // STUN

        let p3 = q.dequeue().unwrap();
        assert_eq!(p3[1] & 0x7F, 96); // VP8 video

        assert!(q.dequeue().is_none());
    }

    #[test]
    fn backpressure_drops_data() {
        let mut q = PriorityQueue::new(BackpressureConfig {
            data_queue_limit: 10,
            data_drop_threshold: 0.5, // drop at 50%
            ..Default::default()
        });

        // Fill 5 → 50% → threshold hit
        for _ in 0..5 {
            assert_eq!(q.enqueue(make_video_rtp()), EnqueueResult::Accepted);
        }

        // 6th should be dropped
        assert_eq!(q.enqueue(make_video_rtp()), EnqueueResult::DroppedBackpressure);

        // Audio still accepted
        assert_eq!(q.enqueue(make_audio_rtp()), EnqueueResult::Accepted);
    }

    #[test]
    fn audio_never_dropped_before_limit() {
        let mut q = PriorityQueue::new(BackpressureConfig {
            audio_queue_limit: 3,
            ..Default::default()
        });

        // Fill to limit
        for _ in 0..3 {
            assert_eq!(q.enqueue(make_audio_rtp()), EnqueueResult::Accepted);
        }

        // 4th: oldest is evicted, new is accepted (audio is precious)
        assert_eq!(q.enqueue(make_audio_rtp()), EnqueueResult::Accepted);
        assert_eq!(q.metrics().audio_dropped, 1);
    }

    #[test]
    fn expired_packets_dropped_on_dequeue() {
        let mut q = PriorityQueue::new(BackpressureConfig {
            max_packet_age: Duration::from_millis(1),
            ..Default::default()
        });

        q.enqueue(make_audio_rtp());
        std::thread::sleep(Duration::from_millis(5));

        // Packet expired
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn batch_dequeue() {
        let mut q = PriorityQueue::new(BackpressureConfig::default());
        for _ in 0..5 { q.enqueue(make_audio_rtp()); }
        for _ in 0..3 { q.enqueue(make_video_rtp()); }

        let batch = q.dequeue_batch(4);
        assert_eq!(batch.len(), 4);
    }

    #[test]
    fn congestion_detector() {
        let mut cd = CongestionDetector::new(50.0);
        assert!(!cd.is_congested());

        for _ in 0..100 { cd.update(200); }
        assert!(cd.is_congested());

        for _ in 0..100 { cd.update(0); }
        assert!(!cd.is_congested());
    }

    #[test]
    fn metrics() {
        let mut q = PriorityQueue::new(BackpressureConfig::default());
        q.enqueue(make_audio_rtp());
        q.enqueue(make_stun_packet());
        q.enqueue(make_video_rtp());

        let m = q.metrics();
        assert_eq!(m.audio_queued, 1);
        assert_eq!(m.control_queued, 1);
        assert_eq!(m.data_queued, 1);
        assert_eq!(m.total_dropped(), 0);
    }
}
