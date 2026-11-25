//! Lock-Free Priority Ring Partitioning for Telemetry Streams.
//!
//! Implements a four-tier non-blocking priority queue backed by independent atomic ring buffers,
//! enabling ultra-fast telemetry event dispatch without mutex contention or head-of-line blocking.
//!
//! Priority tiers (highest to lowest):
//!   - `Critical` : packet-loss alerts, SevereImpairment anomalies, mTLS attestation failures.
//!   - `High`     : BufferbloatOnset / RouteShift detections, threshold adaptation events.
//!   - `Normal`   : routine congestion samples, RTT measurements, session heartbeats.
//!   - `Debug`    : verbose trace samples, raw jitter windows, benchmark micro-events.
//!
//! Architecture:
//!   Each tier owns an independent `AtomicRingBuffer<TelemetryEvent>`, avoiding cross-tier
//!   contention entirely. The drainer polls tiers in strict priority order with work-stealing
//!   fallback: if `Critical` is empty it tries `High`, then `Normal`, then `Debug`.

use crate::fiber::AtomicRingBuffer;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Priority tier definition ───────────────────────────────────────────────

/// Priority tier for a telemetry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TelemetryPriority {
    /// Verbose diagnostics and raw sample data (lowest).
    Debug = 0,
    /// Routine measurements, session heartbeats.
    Normal = 1,
    /// Actionable anomaly detections requiring threshold adaptation.
    High = 2,
    /// Critical impairments: loss alerts, attestation failures (highest).
    Critical = 3,
}

impl TelemetryPriority {
    /// Number of priority tiers.
    pub const TIER_COUNT: usize = 4;

    /// Convert from raw discriminant. Returns `None` for out-of-range values.
    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Debug),
            1 => Some(Self::Normal),
            2 => Some(Self::High),
            3 => Some(Self::Critical),
            _ => None,
        }
    }

    /// Human-readable label (product-facing, no internal codes).
    pub fn label(self) -> &'static str {
        match self {
            Self::Debug => "verbose",
            Self::Normal => "routine",
            Self::High => "actionable",
            Self::Critical => "critical",
        }
    }
}

// ── Telemetry event envelope ───────────────────────────────────────────────

/// Lightweight telemetry event envelope stored in priority ring slots.
/// Sized to fit a single cache line (64 bytes) for minimal false-sharing.
#[derive(Clone)]
#[repr(C, align(64))]
pub struct TelemetryEvent {
    /// Monotonic nanosecond timestamp at event creation.
    pub timestamp_ns: u64,
    /// Event kind discriminant (application-defined tag).
    pub kind: u32,
    /// Priority tier this event was enqueued on.
    pub priority: TelemetryPriority,
    /// Arbitrary payload bytes (up to 51 bytes inline).
    pub payload: [u8; 51],
}

impl TelemetryEvent {
    /// Maximum inline payload length.
    pub const MAX_PAYLOAD: usize = 51;

    /// Construct an event with zero-padded payload.
    pub fn new(timestamp_ns: u64, kind: u32, priority: TelemetryPriority, payload: &[u8]) -> Self {
        let mut buf = [0u8; Self::MAX_PAYLOAD];
        let len = payload.len().min(Self::MAX_PAYLOAD);
        buf[..len].copy_from_slice(&payload[..len]);
        Self {
            timestamp_ns,
            kind,
            priority,
            payload: buf,
        }
    }
}

impl std::fmt::Debug for TelemetryEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryEvent")
            .field("timestamp_ns", &self.timestamp_ns)
            .field("kind", &self.kind)
            .field("priority", &self.priority)
            .field("payload_prefix", &&self.payload[..8])
            .finish()
    }
}

// ── Size assertions ────────────────────────────────────────────────────────

const _: () = {
    assert!(
        std::mem::size_of::<TelemetryEvent>() <= 64,
        "TelemetryEvent must fit within one cache line (64 bytes)"
    );
};

// ── Per-tier ring capacity constants ──────────────────────────────────────

/// Ring capacity for `Critical` tier (must be power-of-two).
pub const CRITICAL_RING_CAPACITY: usize = 256;
/// Ring capacity for `High` tier.
pub const HIGH_RING_CAPACITY: usize = 512;
/// Ring capacity for `Normal` tier.
pub const NORMAL_RING_CAPACITY: usize = 1024;
/// Ring capacity for `Debug` tier (largest; lossy under saturation).
pub const DEBUG_RING_CAPACITY: usize = 2048;

// ── Counters ───────────────────────────────────────────────────────────────

/// Per-tier atomic operation counters for observability.
#[repr(C, align(64))]
struct TierCounters {
    enqueued: AtomicU64,
    drained: AtomicU64,
    dropped: AtomicU64,
}

impl TierCounters {
    const fn new() -> Self {
        Self {
            enqueued: AtomicU64::new(0),
            drained: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }
}

// ── Priority telemetry ring ────────────────────────────────────────────────

/// Four-tier lock-free priority telemetry ring with independent per-tier MPMC ring buffers.
///
/// Producers call [`PriorityTelemetryRing::enqueue`] with the desired priority.
/// A single drain thread calls [`PriorityTelemetryRing::drain_next`] which yields
/// events in strict priority order (Critical first).
pub struct PriorityTelemetryRing {
    critical: AtomicRingBuffer<TelemetryEvent>,
    high: AtomicRingBuffer<TelemetryEvent>,
    normal: AtomicRingBuffer<TelemetryEvent>,
    debug: AtomicRingBuffer<TelemetryEvent>,
    counters: [TierCounters; TelemetryPriority::TIER_COUNT],
}

// SAFETY: `AtomicRingBuffer<T: Send>` is Send+Sync; `TelemetryEvent` is Send.
unsafe impl Send for PriorityTelemetryRing {}
unsafe impl Sync for PriorityTelemetryRing {}

impl PriorityTelemetryRing {
    /// Construct a new priority ring with per-tier capacities.
    pub fn new() -> Self {
        Self {
            critical: AtomicRingBuffer::new(CRITICAL_RING_CAPACITY),
            high: AtomicRingBuffer::new(HIGH_RING_CAPACITY),
            normal: AtomicRingBuffer::new(NORMAL_RING_CAPACITY),
            debug: AtomicRingBuffer::new(DEBUG_RING_CAPACITY),
            counters: [
                TierCounters::new(),
                TierCounters::new(),
                TierCounters::new(),
                TierCounters::new(),
            ],
        }
    }

    /// Enqueue an event into its designated priority tier.
    ///
    /// Returns `Ok(())` on success, `Err(event)` if the target ring is full (dropped).
    pub fn enqueue(&self, event: TelemetryEvent) -> Result<(), TelemetryEvent> {
        let tier = event.priority as usize;
        let ring = self.ring_for(event.priority);
        match ring.try_push(event) {
            Err(dropped) => {
                self.counters[tier].dropped.fetch_add(1, Ordering::Relaxed);
                Err(dropped)
            }
            Ok(()) => {
                self.counters[tier].enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    /// Drain the next highest-priority available event.
    ///
    /// Polls Critical → High → Normal → Debug. Returns `None` if all rings are empty.
    pub fn drain_next(&self) -> Option<TelemetryEvent> {
        for priority in [
            TelemetryPriority::Critical,
            TelemetryPriority::High,
            TelemetryPriority::Normal,
            TelemetryPriority::Debug,
        ] {
            if let Some(event) = self.ring_for(priority).try_pop() {
                self.counters[priority as usize]
                    .drained
                    .fetch_add(1, Ordering::Relaxed);
                return Some(event);
            }
        }
        None
    }

    /// Drain up to `max` events in priority order into `out`. Returns count drained.
    pub fn drain_batch(&self, out: &mut Vec<TelemetryEvent>, max: usize) -> usize {
        let mut count = 0;
        while count < max {
            match self.drain_next() {
                Some(ev) => {
                    out.push(ev);
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Snapshot statistics for a specific tier.
    pub fn tier_stats(&self, priority: TelemetryPriority) -> TierStats {
        let c = &self.counters[priority as usize];
        TierStats {
            priority,
            enqueued: c.enqueued.load(Ordering::Relaxed),
            drained: c.drained.load(Ordering::Relaxed),
            dropped: c.dropped.load(Ordering::Relaxed),
            ring_len: self.ring_for(priority).len(),
        }
    }

    /// Snapshot statistics for all tiers.
    pub fn all_tier_stats(&self) -> [TierStats; TelemetryPriority::TIER_COUNT] {
        [
            self.tier_stats(TelemetryPriority::Debug),
            self.tier_stats(TelemetryPriority::Normal),
            self.tier_stats(TelemetryPriority::High),
            self.tier_stats(TelemetryPriority::Critical),
        ]
    }

    /// Total events currently buffered across all tiers.
    pub fn total_buffered(&self) -> usize {
        self.critical.len() + self.high.len() + self.normal.len() + self.debug.len()
    }

    /// True if all tiers are empty.
    pub fn is_empty(&self) -> bool {
        self.critical.is_empty()
            && self.high.is_empty()
            && self.normal.is_empty()
            && self.debug.is_empty()
    }

    #[inline]
    fn ring_for(&self, priority: TelemetryPriority) -> &AtomicRingBuffer<TelemetryEvent> {
        match priority {
            TelemetryPriority::Critical => &self.critical,
            TelemetryPriority::High => &self.high,
            TelemetryPriority::Normal => &self.normal,
            TelemetryPriority::Debug => &self.debug,
        }
    }
}

impl Default for PriorityTelemetryRing {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tier statistics snapshot ───────────────────────────────────────────────

/// Point-in-time snapshot of one tier's operational counters.
#[derive(Debug, Clone, Copy)]
pub struct TierStats {
    pub priority: TelemetryPriority,
    pub enqueued: u64,
    pub drained: u64,
    pub dropped: u64,
    pub ring_len: usize,
}

impl TierStats {
    /// Net events still pending (enqueued - drained, ignoring drops).
    pub fn pending(&self) -> u64 {
        self.enqueued.saturating_sub(self.drained)
    }

    /// Drop rate as a fraction of total enqueued (0.0 = no drops).
    pub fn drop_rate(&self) -> f64 {
        if self.enqueued == 0 {
            0.0
        } else {
            self.dropped as f64 / self.enqueued as f64
        }
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> u64 {
        42_000_000_000
    }

    fn make_event(priority: TelemetryPriority, kind: u32) -> TelemetryEvent {
        TelemetryEvent::new(ts(), kind, priority, b"test-payload")
    }

    #[test]
    fn test_event_cache_line_size() {
        assert!(std::mem::size_of::<TelemetryEvent>() <= 64);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(TelemetryPriority::Critical > TelemetryPriority::High);
        assert!(TelemetryPriority::High > TelemetryPriority::Normal);
        assert!(TelemetryPriority::Normal > TelemetryPriority::Debug);
    }

    #[test]
    fn test_enqueue_drain_single_tier() {
        let ring = PriorityTelemetryRing::new();
        let ev = make_event(TelemetryPriority::Normal, 1);
        ring.enqueue(ev)
            .expect("enqueue must succeed on empty ring");
        let drained = ring.drain_next().expect("must drain one event");
        assert_eq!(drained.kind, 1);
        assert!(ring.is_empty());
    }

    #[test]
    fn test_priority_drain_order() {
        let ring = PriorityTelemetryRing::new();
        // Enqueue in reverse priority: Debug first, Critical last.
        ring.enqueue(make_event(TelemetryPriority::Debug, 10))
            .unwrap();
        ring.enqueue(make_event(TelemetryPriority::Normal, 20))
            .unwrap();
        ring.enqueue(make_event(TelemetryPriority::High, 30))
            .unwrap();
        ring.enqueue(make_event(TelemetryPriority::Critical, 40))
            .unwrap();

        // Drain must yield Critical first, then High, Normal, Debug.
        let ev1 = ring.drain_next().unwrap();
        assert_eq!(ev1.kind, 40, "Critical must be drained first");
        let ev2 = ring.drain_next().unwrap();
        assert_eq!(ev2.kind, 30, "High must be drained second");
        let ev3 = ring.drain_next().unwrap();
        assert_eq!(ev3.kind, 20, "Normal must be drained third");
        let ev4 = ring.drain_next().unwrap();
        assert_eq!(ev4.kind, 10, "Debug must be drained last");
        assert!(ring.drain_next().is_none());
    }

    #[test]
    fn test_drain_batch() {
        let ring = PriorityTelemetryRing::new();
        for i in 0..8u32 {
            ring.enqueue(make_event(TelemetryPriority::Normal, i))
                .unwrap();
        }
        let mut out = Vec::new();
        let count = ring.drain_batch(&mut out, 5);
        assert_eq!(count, 5);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn test_tier_stats() {
        let ring = PriorityTelemetryRing::new();
        ring.enqueue(make_event(TelemetryPriority::High, 1))
            .unwrap();
        ring.enqueue(make_event(TelemetryPriority::High, 2))
            .unwrap();
        ring.drain_next();
        let stats = ring.tier_stats(TelemetryPriority::High);
        assert_eq!(stats.enqueued, 2);
        assert_eq!(stats.drained, 1);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.ring_len, 1);
    }

    #[test]
    fn test_total_buffered() {
        let ring = PriorityTelemetryRing::new();
        ring.enqueue(make_event(TelemetryPriority::Critical, 1))
            .unwrap();
        ring.enqueue(make_event(TelemetryPriority::Debug, 2))
            .unwrap();
        assert_eq!(ring.total_buffered(), 2);
    }

    #[test]
    fn test_all_tier_stats_shape() {
        let ring = PriorityTelemetryRing::new();
        let stats = ring.all_tier_stats();
        assert_eq!(stats.len(), TelemetryPriority::TIER_COUNT);
    }

    #[test]
    fn test_priority_from_u8_roundtrip() {
        for v in 0u8..4 {
            let p = TelemetryPriority::from_u8(v).expect("valid tier");
            assert_eq!(p as u8, v);
        }
        assert!(TelemetryPriority::from_u8(4).is_none());
    }

    #[test]
    fn test_drop_rate_zero_enqueued() {
        let stats = TierStats {
            priority: TelemetryPriority::Normal,
            enqueued: 0,
            drained: 0,
            dropped: 0,
            ring_len: 0,
        };
        assert_eq!(stats.drop_rate(), 0.0);
    }

    #[test]
    fn test_event_payload_truncation() {
        let long_payload = [0xABu8; 100];
        let ev = TelemetryEvent::new(0, 0, TelemetryPriority::Debug, &long_payload);
        // Payload must be clamped to MAX_PAYLOAD with no panic.
        assert_eq!(&ev.payload[..8], &[0xABu8; 8]);
    }

    // Multi-threaded MPMC correctness: 4 producers × 4 priority tiers, 1 consumer.
    #[test]
    fn test_mpmc_concurrent_enqueue_drain() {
        use std::sync::Arc;
        use std::thread;

        const EVENTS_PER_THREAD: u32 = 200;
        let ring = Arc::new(PriorityTelemetryRing::new());

        let priorities = [
            TelemetryPriority::Debug,
            TelemetryPriority::Normal,
            TelemetryPriority::High,
            TelemetryPriority::Critical,
        ];

        let producers: Vec<_> = priorities
            .iter()
            .map(|&prio| {
                let ring = Arc::clone(&ring);
                thread::spawn(move || {
                    for i in 0..EVENTS_PER_THREAD {
                        // Spin on backpressure rather than hard-failing.
                        let ev = TelemetryEvent::new(i as u64, i, prio, b"mpmc");
                        loop {
                            if ring.enqueue(ev.clone()).is_ok() {
                                break;
                            }
                            std::hint::spin_loop();
                        }
                    }
                })
            })
            .collect();

        // Drain from the main thread until all producers finish and ring is empty.
        let mut drained = 0u64;
        loop {
            while ring.drain_next().is_some() {
                drained += 1;
            }
            // Check if all producer threads have finished.
            let all_done = producers.iter().all(|h| h.is_finished());
            if all_done && ring.is_empty() {
                break;
            }
            std::hint::spin_loop();
        }
        // Drain any residual.
        while ring.drain_next().is_some() {
            drained += 1;
        }

        let expected = (EVENTS_PER_THREAD as u64) * (priorities.len() as u64);
        assert_eq!(drained, expected, "all events must be drained with no loss");
    }
}
