//! Adaptive Multi-Slice Egress Traffic Shaper and Admission Controller (`SubpathSliceShaper`).
//!
//! Provides granular bandwidth shaping and policing per physical transport subpath across
//! heterogeneous QoS traffic classes (`UltraLowLatency`, `MissionCritical`, `HighThroughput`, `BestEffort`):
//! - **Token Bucket / Leaky Bucket Rate Limiting**: Independent bucket state and burst depth per slice.
//! - **Proportional Bandwidth Redistribution**: Automatically scales slice rate allocations when subpath
//!   bandwidth adapts dynamically (e.g. via BBR, PMTUD, or telemetry updates).
//! - **Priority Overdraft & Pacing**: Allows bounded overdraft bursts for `UltraLowLatency` and `MissionCritical`
//!   traffic to prevent Head-of-Line delays, while hard-policing bulk streams.
//! - **Dynamic Closed-Loop Backpressure**: Scales down slice quantum/rate under downstream congestion signals.
//! - **Transit Latency & OpenMetrics Observability**: Tracks policing metrics, token availability, and transit
//!   sojourn times for Prometheus export.

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;

use crate::traffic_slicing::FlowSliceClass;

/// Verdict returned when evaluating a packet against subpath slice shaping limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubpathAdmissionVerdict {
    /// Packet admitted immediately for transmission.
    Admitted,
    /// Packet admitted with required pacing delay in nanoseconds.
    Delayed { delay_ns: u64 },
    /// Packet throttled / dropped by shaper to protect link capacity and latency.
    Throttled { dropped_bytes: usize },
}

/// Individual rate limiter and token bucket governing a specific QoS traffic slice on a subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct SliceRateLimiter {
    pub slice_class: FlowSliceClass,
    pub weight_pct: u8,
    pub configured_rate_bps: u64,
    pub effective_rate_bps: u64,
    pub burst_bytes: u64,
    pub current_tokens_bytes: f64,
    pub last_replenish_timestamp_ns: u64,
    pub admitted_packets: u64,
    pub admitted_bytes: u64,
    pub throttled_packets: u64,
    pub throttled_bytes: u64,
    pub delayed_packets: u64,
    pub delayed_bytes: u64,
    pub total_transit_latency_ns: u64,
    pub transit_latency_samples: u64,
}

impl SliceRateLimiter {
    /// Create a new rate limiter for a specific slice.
    pub fn new(
        slice_class: FlowSliceClass,
        weight_pct: u8,
        rate_bps: u64,
        burst_bytes: u64,
        now_ns: u64,
    ) -> Self {
        Self {
            slice_class,
            weight_pct,
            configured_rate_bps: rate_bps,
            effective_rate_bps: rate_bps,
            burst_bytes,
            current_tokens_bytes: burst_bytes as f64,
            last_replenish_timestamp_ns: now_ns,
            admitted_packets: 0,
            admitted_bytes: 0,
            throttled_packets: 0,
            throttled_bytes: 0,
            delayed_packets: 0,
            delayed_bytes: 0,
            total_transit_latency_ns: 0,
            transit_latency_samples: 0,
        }
    }

    /// Replenish available tokens based on elapsed monotonic nanoseconds.
    pub fn replenish(&mut self, now_ns: u64) {
        if now_ns <= self.last_replenish_timestamp_ns {
            return;
        }

        let elapsed_ns = now_ns.saturating_sub(self.last_replenish_timestamp_ns);
        let elapsed_sec = (elapsed_ns as f64) / 1_000_000_000.0;
        let tokens_to_add = (self.effective_rate_bps as f64 / 8.0) * elapsed_sec;

        self.current_tokens_bytes =
            (self.current_tokens_bytes + tokens_to_add).min(self.burst_bytes as f64);
        self.last_replenish_timestamp_ns = now_ns;
    }

    /// Attempt to admit a packet of size `packet_bytes`.
    pub fn try_admit(&mut self, packet_bytes: usize, now_ns: u64) -> SubpathAdmissionVerdict {
        self.replenish(now_ns);

        let req = packet_bytes as f64;
        if self.current_tokens_bytes >= req {
            self.current_tokens_bytes -= req;
            self.admitted_packets = self.admitted_packets.saturating_add(1);
            self.admitted_bytes = self.admitted_bytes.saturating_add(packet_bytes as u64);
            SubpathAdmissionVerdict::Admitted
        } else {
            match self.slice_class {
                FlowSliceClass::UltraLowLatency => {
                    // URLLC allows overdraft burst credit up to 50% beyond bucket depth
                    let overdraft_limit = -(self.burst_bytes as f64 * 0.50);
                    if self.current_tokens_bytes - req >= overdraft_limit {
                        self.current_tokens_bytes -= req;
                        self.admitted_packets = self.admitted_packets.saturating_add(1);
                        self.admitted_bytes =
                            self.admitted_bytes.saturating_add(packet_bytes as u64);
                        SubpathAdmissionVerdict::Admitted
                    } else {
                        // Beyond overdraft: pacing delay calculation
                        let deficit_bytes = req - self.current_tokens_bytes;
                        let bytes_per_sec = (self.effective_rate_bps as f64) / 8.0;
                        let delay_ns = if bytes_per_sec > 0.0 {
                            ((deficit_bytes / bytes_per_sec) * 1_000_000_000.0) as u64
                        } else {
                            1_000_000 // 1ms fallback
                        };
                        self.delayed_packets = self.delayed_packets.saturating_add(1);
                        self.delayed_bytes = self.delayed_bytes.saturating_add(packet_bytes as u64);
                        SubpathAdmissionVerdict::Delayed { delay_ns }
                    }
                }
                FlowSliceClass::MissionCritical => {
                    // MissionCritical allows overdraft credit up to 25% of burst depth
                    let overdraft_limit = -(self.burst_bytes as f64 * 0.25);
                    if self.current_tokens_bytes - req >= overdraft_limit {
                        self.current_tokens_bytes -= req;
                        self.admitted_packets = self.admitted_packets.saturating_add(1);
                        self.admitted_bytes =
                            self.admitted_bytes.saturating_add(packet_bytes as u64);
                        SubpathAdmissionVerdict::Admitted
                    } else {
                        self.throttled_packets = self.throttled_packets.saturating_add(1);
                        self.throttled_bytes =
                            self.throttled_bytes.saturating_add(packet_bytes as u64);
                        SubpathAdmissionVerdict::Throttled {
                            dropped_bytes: packet_bytes,
                        }
                    }
                }
                FlowSliceClass::HighThroughput | FlowSliceClass::BestEffort => {
                    // Hard policing tail-drop for bulk flows when bucket is empty
                    self.throttled_packets = self.throttled_packets.saturating_add(1);
                    self.throttled_bytes = self.throttled_bytes.saturating_add(packet_bytes as u64);
                    SubpathAdmissionVerdict::Throttled {
                        dropped_bytes: packet_bytes,
                    }
                }
            }
        }
    }

    /// Record measured transit latency through the shaper/queue.
    pub fn record_transit_latency(&mut self, latency_ns: u64) {
        self.total_transit_latency_ns = self.total_transit_latency_ns.saturating_add(latency_ns);
        self.transit_latency_samples = self.transit_latency_samples.saturating_add(1);
    }

    /// Average transit latency in nanoseconds.
    pub fn avg_transit_latency_ns(&self) -> u64 {
        self.total_transit_latency_ns
            .checked_div(self.transit_latency_samples)
            .unwrap_or(0)
    }

    /// Dynamically update configured/effective rates, adjusting burst depth and clamping tokens.
    pub fn update_rate(&mut self, new_rate_bps: u64, burst_bytes: u64, now_ns: u64) {
        self.replenish(now_ns);
        self.configured_rate_bps = new_rate_bps;
        self.effective_rate_bps = new_rate_bps;
        self.burst_bytes = burst_bytes;
        self.current_tokens_bytes = self.current_tokens_bytes.min(burst_bytes as f64);
    }
}

/// Telemetry snapshot for a single slice rate limiter.
#[derive(Debug, Clone, PartialEq)]
pub struct SliceShaperTelemetry {
    pub slice_class: FlowSliceClass,
    pub weight_pct: u8,
    pub configured_rate_bps: u64,
    pub effective_rate_bps: u64,
    pub burst_bytes: u64,
    pub current_tokens_bytes: f64,
    pub admitted_packets: u64,
    pub admitted_bytes: u64,
    pub throttled_packets: u64,
    pub throttled_bytes: u64,
    pub delayed_packets: u64,
    pub delayed_bytes: u64,
    pub avg_transit_latency_ns: u64,
}

/// Comprehensive telemetry snapshot for a subpath's multi-slice shaper.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathShaperTelemetry {
    pub subpath_id: u8,
    pub subpath_bandwidth_bps: u64,
    pub slices: Vec<SliceShaperTelemetry>,
}

/// Adaptive multi-slice traffic shaper and admission controller for a physical subpath.
#[derive(Debug, Clone)]
pub struct SubpathSliceShaper {
    pub subpath_id: u8,
    pub subpath_bandwidth_bps: u64,
    pub burst_window_ms: u32,
    pub limiters: BTreeMap<FlowSliceClass, SliceRateLimiter>,
    pub min_guaranteed_bps: BTreeMap<FlowSliceClass, u64>,
}

impl SubpathSliceShaper {
    /// Default burst duration window in milliseconds (50ms).
    pub const DEFAULT_BURST_WINDOW_MS: u32 = 50;
    /// Minimum bucket burst size in bytes (8 KB) to allow wire-speed MTU frame bursts.
    pub const MIN_BURST_BYTES: u64 = 8_192;

    /// Create a new multi-slice traffic shaper with standard default allocations:
    /// - UltraLowLatency: 20%
    /// - MissionCritical: 35%
    /// - HighThroughput: 35%
    /// - BestEffort: 10%
    pub fn new(subpath_id: u8, bandwidth_bps: u64, now_ns: u64) -> Self {
        let weights = [
            (FlowSliceClass::UltraLowLatency, 20),
            (FlowSliceClass::MissionCritical, 35),
            (FlowSliceClass::HighThroughput, 35),
            (FlowSliceClass::BestEffort, 10),
        ];
        Self::with_weights(subpath_id, bandwidth_bps, &weights, now_ns)
    }

    /// Create a shaper with custom slice weight distribution.
    pub fn with_weights(
        subpath_id: u8,
        bandwidth_bps: u64,
        weights: &[(FlowSliceClass, u8)],
        now_ns: u64,
    ) -> Self {
        let burst_window_ms = Self::DEFAULT_BURST_WINDOW_MS;
        let mut limiters = BTreeMap::new();
        let mut min_guaranteed = BTreeMap::new();

        min_guaranteed.insert(FlowSliceClass::UltraLowLatency, 500_000); // 500 Kbps min
        min_guaranteed.insert(FlowSliceClass::MissionCritical, 1_000_000); // 1 Mbps min
        min_guaranteed.insert(FlowSliceClass::HighThroughput, 1_000_000); // 1 Mbps min
        min_guaranteed.insert(FlowSliceClass::BestEffort, 200_000); // 200 Kbps min

        let total_weight: u32 = weights.iter().map(|(_, w)| *w as u32).sum();
        let safe_total = if total_weight > 0 { total_weight } else { 100 };

        for &(slice, weight) in weights {
            let allocated_rate =
                ((bandwidth_bps as u128 * weight as u128) / safe_total as u128) as u64;
            let min_rate = min_guaranteed.get(&slice).copied().unwrap_or(100_000);
            let effective_rate = allocated_rate.max(min_rate.min(bandwidth_bps));

            let bytes_per_sec = effective_rate / 8;
            let burst_bytes =
                ((bytes_per_sec * burst_window_ms as u64) / 1000).max(Self::MIN_BURST_BYTES);

            let limiter = SliceRateLimiter::new(slice, weight, effective_rate, burst_bytes, now_ns);
            limiters.insert(slice, limiter);
        }

        Self {
            subpath_id,
            subpath_bandwidth_bps: bandwidth_bps,
            burst_window_ms,
            limiters,
            min_guaranteed_bps: min_guaranteed,
        }
    }

    /// Dynamically recalculates slice rates proportionally based on updated subpath bandwidth.
    pub fn rebalance(&mut self, new_bandwidth_bps: u64, now_ns: u64) {
        self.subpath_bandwidth_bps = new_bandwidth_bps;
        let total_weight: u32 = self.limiters.values().map(|l| l.weight_pct as u32).sum();
        let safe_total = if total_weight > 0 { total_weight } else { 100 };

        for (slice, limiter) in self.limiters.iter_mut() {
            let allocated_rate = ((new_bandwidth_bps as u128 * limiter.weight_pct as u128)
                / safe_total as u128) as u64;
            let min_rate = self
                .min_guaranteed_bps
                .get(slice)
                .copied()
                .unwrap_or(100_000);
            let effective_rate = allocated_rate.max(min_rate.min(new_bandwidth_bps));

            let bytes_per_sec = effective_rate / 8;
            let burst_bytes =
                ((bytes_per_sec * self.burst_window_ms as u64) / 1000).max(Self::MIN_BURST_BYTES);

            limiter.update_rate(effective_rate, burst_bytes, now_ns);
        }
    }

    /// Dynamically update slice weight and rebalance allocations.
    pub fn set_slice_weight(&mut self, slice: FlowSliceClass, weight_pct: u8, now_ns: u64) {
        if let Some(limiter) = self.limiters.get_mut(&slice) {
            limiter.weight_pct = weight_pct;
        }
        self.rebalance(self.subpath_bandwidth_bps, now_ns);
    }

    /// Apply dynamic backpressure reduction scaling to a specific slice.
    pub fn apply_backpressure_reduction(
        &mut self,
        slice: FlowSliceClass,
        scale_pct: u32,
        now_ns: u64,
    ) {
        if let Some(limiter) = self.limiters.get_mut(&slice) {
            limiter.replenish(now_ns);
            let scaled_rate =
                ((limiter.configured_rate_bps as u128 * scale_pct as u128) / 100) as u64;
            limiter.effective_rate_bps = scaled_rate.max(50_000); // 50 Kbps minimum floor
            let bytes_per_sec = limiter.effective_rate_bps / 8;
            limiter.burst_bytes =
                ((bytes_per_sec * self.burst_window_ms as u64) / 1000).max(Self::MIN_BURST_BYTES);
            limiter.current_tokens_bytes =
                limiter.current_tokens_bytes.min(limiter.burst_bytes as f64);
        }
    }

    /// Reset backpressure reduction for a specific slice back to configured rate.
    pub fn reset_backpressure_reduction(&mut self, slice: FlowSliceClass, now_ns: u64) {
        if let Some(limiter) = self.limiters.get_mut(&slice) {
            limiter.replenish(now_ns);
            limiter.effective_rate_bps = limiter.configured_rate_bps;
            let bytes_per_sec = limiter.effective_rate_bps / 8;
            limiter.burst_bytes =
                ((bytes_per_sec * self.burst_window_ms as u64) / 1000).max(Self::MIN_BURST_BYTES);
        }
    }

    /// Check admission and consume shaping tokens for a packet on a specific slice.
    pub fn try_admit(
        &mut self,
        slice: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> SubpathAdmissionVerdict {
        if let Some(limiter) = self.limiters.get_mut(&slice) {
            limiter.try_admit(packet_bytes, now_ns)
        } else {
            // Unregistered slice class admitted by default
            SubpathAdmissionVerdict::Admitted
        }
    }

    /// Record transit latency for a packet on a specific slice.
    pub fn record_transit_latency(&mut self, slice: FlowSliceClass, latency_ns: u64) {
        if let Some(limiter) = self.limiters.get_mut(&slice) {
            limiter.record_transit_latency(latency_ns);
        }
    }

    /// Generate an immutable snapshot of all slice limiter metrics.
    pub fn snapshot(&self) -> SubpathShaperTelemetry {
        let slices = self
            .limiters
            .values()
            .map(|l| SliceShaperTelemetry {
                slice_class: l.slice_class,
                weight_pct: l.weight_pct,
                configured_rate_bps: l.configured_rate_bps,
                effective_rate_bps: l.effective_rate_bps,
                burst_bytes: l.burst_bytes,
                current_tokens_bytes: l.current_tokens_bytes,
                admitted_packets: l.admitted_packets,
                admitted_bytes: l.admitted_bytes,
                throttled_packets: l.throttled_packets,
                throttled_bytes: l.throttled_bytes,
                delayed_packets: l.delayed_packets,
                delayed_bytes: l.delayed_bytes,
                avg_transit_latency_ns: l.avg_transit_latency_ns(),
            })
            .collect();

        SubpathShaperTelemetry {
            subpath_id: self.subpath_id,
            subpath_bandwidth_bps: self.subpath_bandwidth_bps,
            slices,
        }
    }

    /// Export OpenMetrics / Prometheus formatted lines for this subpath's shaper.
    pub fn export_prometheus_metrics(&self, subpath_name: &str) -> String {
        let mut out = String::new();
        let sid = self.subpath_id;

        for slice in self.limiters.values() {
            let slice_str = slice.slice_class.as_str();

            let _ = writeln!(
                out,
                "ifa_multipath_shaper_admitted_packets_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                sid, subpath_name, slice_str, slice.admitted_packets
            );
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_admitted_bytes_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                sid, subpath_name, slice_str, slice.admitted_bytes
            );
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_throttled_packets_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                sid, subpath_name, slice_str, slice.throttled_packets
            );
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_throttled_bytes_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                sid, subpath_name, slice_str, slice.throttled_bytes
            );
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_delayed_packets_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                sid, subpath_name, slice_str, slice.delayed_packets
            );
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_delayed_bytes_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                sid, subpath_name, slice_str, slice.delayed_bytes
            );
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_effective_rate_bps{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                sid, subpath_name, slice_str, slice.effective_rate_bps
            );
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_tokens_available_bytes{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {:.2}",
                sid, subpath_name, slice_str, slice.current_tokens_bytes
            );
            let transit_sec = (slice.avg_transit_latency_ns() as f64) / 1_000_000_000.0;
            let _ = writeln!(
                out,
                "ifa_multipath_shaper_transit_latency_seconds{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {:.6}",
                sid, subpath_name, slice_str, transit_sec
            );
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shaper_initialization_and_weights() {
        let shaper = SubpathSliceShaper::new(1, 10_000_000, 1_000_000_000); // 10 Mbps
        assert_eq!(shaper.subpath_id, 1);
        assert_eq!(shaper.subpath_bandwidth_bps, 10_000_000);

        let ull = shaper
            .limiters
            .get(&FlowSliceClass::UltraLowLatency)
            .unwrap();
        assert_eq!(ull.weight_pct, 20);
        assert_eq!(ull.configured_rate_bps, 2_000_000); // 20% of 10M

        let mc = shaper
            .limiters
            .get(&FlowSliceClass::MissionCritical)
            .unwrap();
        assert_eq!(mc.weight_pct, 35);
        assert_eq!(mc.configured_rate_bps, 3_500_000); // 35% of 10M

        let ht = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap();
        assert_eq!(ht.weight_pct, 35);
        assert_eq!(ht.configured_rate_bps, 3_500_000); // 35% of 10M

        let be = shaper.limiters.get(&FlowSliceClass::BestEffort).unwrap();
        assert_eq!(be.weight_pct, 10);
        assert_eq!(be.configured_rate_bps, 1_000_000); // 10% of 10M
    }

    #[test]
    fn test_dynamic_rebalance_bandwidth_scaling() {
        let mut shaper = SubpathSliceShaper::new(2, 10_000_000, 1_000_000_000);

        // Scale bandwidth up from 10 Mbps to 100 Mbps
        shaper.rebalance(100_000_000, 1_500_000_000);
        assert_eq!(shaper.subpath_bandwidth_bps, 100_000_000);

        let ull = shaper
            .limiters
            .get(&FlowSliceClass::UltraLowLatency)
            .unwrap();
        assert_eq!(ull.effective_rate_bps, 20_000_000); // 20% of 100M

        let mc = shaper
            .limiters
            .get(&FlowSliceClass::MissionCritical)
            .unwrap();
        assert_eq!(mc.effective_rate_bps, 35_000_000); // 35% of 100M

        let ht = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap();
        assert_eq!(ht.effective_rate_bps, 35_000_000); // 35% of 100M

        let be = shaper.limiters.get(&FlowSliceClass::BestEffort).unwrap();
        assert_eq!(be.effective_rate_bps, 10_000_000); // 10% of 100M
    }

    #[test]
    fn test_admission_and_policing_hard_drop_vs_urllc_overdraft() {
        let mut shaper = SubpathSliceShaper::new(1, 8_000_000, 1_000_000_000); // 8 Mbps
        let now_ns = 1_000_000_000;

        // Drain BestEffort bucket
        let be_burst = shaper
            .limiters
            .get(&FlowSliceClass::BestEffort)
            .unwrap()
            .burst_bytes;
        let v1 = shaper.try_admit(FlowSliceClass::BestEffort, be_burst as usize, now_ns);
        assert_eq!(v1, SubpathAdmissionVerdict::Admitted);

        // Immediate subsequent packet should be throttled (bucket empty)
        let v2 = shaper.try_admit(FlowSliceClass::BestEffort, 1500, now_ns);
        assert_eq!(
            v2,
            SubpathAdmissionVerdict::Throttled {
                dropped_bytes: 1500
            }
        );

        // Drain UltraLowLatency bucket
        let ull_burst = shaper
            .limiters
            .get(&FlowSliceClass::UltraLowLatency)
            .unwrap()
            .burst_bytes;
        let u1 = shaper.try_admit(FlowSliceClass::UltraLowLatency, ull_burst as usize, now_ns);
        assert_eq!(u1, SubpathAdmissionVerdict::Admitted);

        // Subsequent URLLC frame fits within 50% overdraft credit
        let u2 = shaper.try_admit(
            FlowSliceClass::UltraLowLatency,
            (ull_burst / 4) as usize,
            now_ns,
        );
        assert_eq!(u2, SubpathAdmissionVerdict::Admitted);
    }

    #[test]
    fn test_backpressure_reduction_and_reset() {
        let mut shaper = SubpathSliceShaper::new(1, 10_000_000, 1_000_000_000);

        let initial_rate = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap()
            .effective_rate_bps;
        assert_eq!(initial_rate, 3_500_000);

        // Reduce HighThroughput slice rate by 50% under backpressure
        shaper.apply_backpressure_reduction(FlowSliceClass::HighThroughput, 50, 1_100_000_000);
        let reduced = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap()
            .effective_rate_bps;
        assert_eq!(reduced, 1_750_000);

        // Reset back to configured rate
        shaper.reset_backpressure_reduction(FlowSliceClass::HighThroughput, 1_200_000_000);
        let restored = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap()
            .effective_rate_bps;
        assert_eq!(restored, 3_500_000);
    }

    #[test]
    fn test_transit_latency_and_openmetrics_export() {
        let mut shaper = SubpathSliceShaper::new(1, 10_000_000, 1_000_000_000);
        shaper.record_transit_latency(FlowSliceClass::UltraLowLatency, 1_500_000); // 1.5ms
        shaper.record_transit_latency(FlowSliceClass::UltraLowLatency, 2_500_000); // 2.5ms

        let snapshot = shaper.snapshot();
        let ull_snap = snapshot
            .slices
            .iter()
            .find(|s| s.slice_class == FlowSliceClass::UltraLowLatency)
            .unwrap();
        assert_eq!(ull_snap.avg_transit_latency_ns, 2_000_000); // 2.0ms avg

        let prom = shaper.export_prometheus_metrics("eth0");
        assert!(prom.contains("ifa_multipath_shaper_admitted_packets_total{subpath_id=\"1\",name=\"eth0\",slice=\"ultra_low_latency\"}"));
        assert!(prom.contains("ifa_multipath_shaper_effective_rate_bps{subpath_id=\"1\",name=\"eth0\",slice=\"mission_critical\"}"));
        assert!(prom.contains("ifa_multipath_shaper_transit_latency_seconds{subpath_id=\"1\",name=\"eth0\",slice=\"ultra_low_latency\"} 0.002000"));
    }
}
